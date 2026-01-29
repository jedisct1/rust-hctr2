#![allow(deprecated)]
//! HCTR2+FP (Format-Preserving) variant of HCTR2.
//!
//! While standard HCTR2 operates on arbitrary bytes, HCTR2+FP ensures that ciphertext
//! consists only of digits in a specified radix (e.g., decimal digits 0-9 for radix-10).
//!
//! Use cases:
//! - Encrypting credit card numbers (decimal)
//! - Encrypting alphanumeric identifiers (hexadecimal or custom radix)
//! - Systems requiring format-preserving encryption
//!
//! Security properties:
//! - Ciphertext length equals plaintext length
//! - All ciphertext digits are in range [0, radix)
//! - Requires unique (key, tweak) pairs for security
//! - No authentication - consider AEAD if integrity protection is needed
//! - Minimum message length depends on radix (e.g., 39 digits for decimal)

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt};
use aes::{Aes128, Aes256};
use polyval::{Polyval, universal_hash::UniversalHash};

use crate::common::{BLOCK_LENGTH, Direction, Error, absorb, xor_block, xor_blocks_3};
use crate::hctr2::AesCipher;

// Keep the old error type as an alias for backwards compatibility
#[allow(non_camel_case_types)]
#[deprecated(note = "Use common::Error instead")]
pub type Hctr2FpError = Error;

/// Check if a number is a power of two.
pub const fn is_power_of_two(n: u16) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

/// Compute bits per digit for power-of-2 radix.
pub const fn bits_per_digit(radix: u16) -> u32 {
    radix.trailing_zeros()
}

/// Compute the minimum number of base-radix digits needed to represent 128 bits.
/// This is: ceil(128 / log2(radix)) = smallest k where radix^k >= 2^128
pub const fn first_block_length(radix: u16) -> usize {
    assert!(radix >= 2 && radix <= 256);

    if radix == 256 {
        return 16;
    }

    if is_power_of_two(radix) {
        let bpd = bits_per_digit(radix);
        return 128_u32.div_ceil(bpd) as usize;
    }

    let mut k: usize = 1;
    let mut capacity: u128 = radix as u128;

    loop {
        k += 1;
        if let Some(next) = capacity.checked_mul(radix as u128) {
            capacity = next;
        } else {
            return k;
        }
    }
}

/// Encode a 128-bit value as base-radix digits (little-endian).
pub fn encode_base_radix(value: u128, radix: u16, output: &mut [u8]) {
    debug_assert!((2..=256).contains(&radix));
    let min_len = first_block_length(radix);
    debug_assert!(output.len() >= min_len);

    if radix == 256 {
        output[..16].copy_from_slice(&value.to_le_bytes());
        return;
    }

    if is_power_of_two(radix) {
        let bpd = bits_per_digit(radix);
        let mask: u128 = ((1u128) << bpd) - 1;
        let mut bits = value;

        for digit in output.iter_mut() {
            *digit = (bits & mask) as u8;
            bits >>= bpd;
        }
        return;
    }

    let mut remaining = value;
    for digit in output.iter_mut() {
        *digit = (remaining % radix as u128) as u8;
        remaining /= radix as u128;
    }
}

/// Decode base-radix digits (little-endian) to a 128-bit value.
pub fn decode_base_radix(digits: &[u8], radix: u16) -> Result<u128, Error> {
    debug_assert!((2..=256).contains(&radix));

    if radix == 256 {
        if digits.len() < 16 {
            return Err(Error::InputTooShort);
        }
        return Ok(u128::from_le_bytes(digits[..16].try_into().unwrap()));
    }

    for &d in digits {
        if d >= radix as u8 {
            return Err(Error::InvalidDigit);
        }
    }

    if is_power_of_two(radix) {
        let bpd = bits_per_digit(radix);
        let mut value: u128 = 0;

        for (i, &digit) in digits.iter().enumerate() {
            let shift = (i as u32) * bpd;
            if shift < 128 {
                value |= (digit as u128) << shift;
            }
        }
        return Ok(value);
    }

    let mut value: u128 = 0;
    for &digit in digits.iter().rev() {
        value = value
            .wrapping_mul(radix as u128)
            .wrapping_add(digit as u128);
    }

    Ok(value)
}

/// Generic HCTR2+FP cipher.
pub struct Hctr2Fp<Aes: AesCipher, const RADIX: u16> {
    ks_enc: Aes,
    ks_dec: Aes::Dec,
    h: [u8; BLOCK_LENGTH],
    l: [u8; BLOCK_LENGTH],
}

#[allow(non_camel_case_types)]
/// HCTR2+FP with AES-128 and decimal (radix-10) format preservation.
pub type Hctr2Fp_128_Decimal = Hctr2Fp<Aes128, 10>;

#[allow(non_camel_case_types)]
/// HCTR2+FP with AES-256 and decimal (radix-10) format preservation.
pub type Hctr2Fp_256_Decimal = Hctr2Fp<Aes256, 10>;

#[allow(non_camel_case_types)]
/// HCTR2+FP with AES-128 and hexadecimal (radix-16) format preservation.
pub type Hctr2Fp_128_Hex = Hctr2Fp<Aes128, 16>;

#[allow(non_camel_case_types)]
/// HCTR2+FP with AES-256 and hexadecimal (radix-16) format preservation.
pub type Hctr2Fp_256_Hex = Hctr2Fp<Aes256, 16>;

#[allow(non_camel_case_types)]
/// HCTR2+FP with AES-128 and base-64 (radix-64) format preservation.
pub type Hctr2Fp_128_Base64 = Hctr2Fp<Aes128, 64>;

#[allow(non_camel_case_types)]
/// HCTR2+FP with AES-256 and base-64 (radix-64) format preservation.
pub type Hctr2Fp_256_Base64 = Hctr2Fp<Aes256, 64>;

impl<Aes: AesCipher, const RADIX: u16> Hctr2Fp<Aes, RADIX> {
    /// First block length in digits (radix-dependent).
    pub const FIRST_BLOCK_LENGTH: usize = first_block_length(RADIX);

    /// Minimum message length in digits (same as first_block_length).
    pub const MIN_MESSAGE_LENGTH: usize = Self::FIRST_BLOCK_LENGTH;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR2+FP cipher state from an encryption key.
    pub fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Aes::KEY_LEN);

        let ks_enc = Aes::new(Array::from_slice(key));
        let ks_dec = Aes::new_dec(key);

        let mut h_block = Array::clone_from_slice(&[0u8; 16]);
        let mut l_block = Array::clone_from_slice(&{
            let mut b = [0u8; 16];
            b[0] = 1;
            b
        });
        ks_enc.encrypt_block(&mut h_block);
        ks_enc.encrypt_block(&mut l_block);

        let h: [u8; 16] = h_block.as_slice().try_into().unwrap();
        let l: [u8; 16] = l_block.as_slice().try_into().unwrap();
        Self {
            ks_enc,
            ks_dec,
            h,
            l,
        }
    }

    /// Encrypt plaintext digits to ciphertext digits using HCTR2+FP.
    ///
    /// All input digits must be in range [0, RADIX). Output will also be in this range.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr2fp(plaintext, tweak, ciphertext, Direction::Encrypt)
    }

    /// Decrypt ciphertext digits to plaintext digits using HCTR2+FP.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr2fp(ciphertext, tweak, plaintext, Direction::Decrypt)
    }

    fn hctr2fp(
        &self,
        src: &[u8],
        tweak: &[u8],
        dst: &mut [u8],
        direction: Direction,
    ) -> Result<(), Error> {
        debug_assert_eq!(dst.len(), src.len());

        let first_block_len = Self::FIRST_BLOCK_LENGTH;
        if src.len() < first_block_len {
            return Err(Error::InputTooShort);
        }

        for &digit in src {
            if digit >= RADIX as u8 {
                return Err(Error::InvalidDigit);
            }
        }

        let first_part = &src[..first_block_len];
        let tail = &src[first_block_len..];

        let mut block_bytes = [0u8; BLOCK_LENGTH];
        let tweak_len_bits = tweak.len() * 8;
        let tweak_len_bytes: u128 = if tail.len() % BLOCK_LENGTH == 0 {
            (2 * tweak_len_bits + 2) as u128
        } else {
            (2 * tweak_len_bits + 3) as u128
        };
        block_bytes.copy_from_slice(&tweak_len_bytes.to_le_bytes());

        let mut poly = Polyval::new(Array::from_slice(&self.h));
        poly.update(&[Array::clone_from_slice(&block_bytes)]);

        let full_tweak_blocks = tweak.len() / BLOCK_LENGTH;
        for i in 0..full_tweak_blocks {
            let block = Array::clone_from_slice(&tweak[i * BLOCK_LENGTH..(i + 1) * BLOCK_LENGTH]);
            poly.update(&[block]);
        }
        let tweak_remainder = tweak.len() % BLOCK_LENGTH;
        if tweak_remainder > 0 {
            let mut padded_tweak = [0u8; BLOCK_LENGTH];
            padded_tweak[..tweak_remainder]
                .copy_from_slice(&tweak[full_tweak_blocks * BLOCK_LENGTH..]);
            poly.update(&[Array::clone_from_slice(&padded_tweak)]);
        }

        let poly_after_tweak = poly.clone();

        match direction {
            Direction::Encrypt => {
                let hh = absorb(&mut poly, tail);
                let m_bits = decode_base_radix(first_part, RADIX)?;
                let mut mm: [u8; BLOCK_LENGTH] = m_bits.to_le_bytes();
                xor_block(&mut mm, &hh);

                let mut uu_block = Array::clone_from_slice(&mm);
                self.ks_enc.encrypt_block(&mut uu_block);
                let uu: [u8; BLOCK_LENGTH] = uu_block.as_slice().try_into().unwrap();

                let s = xor_blocks_3(&mm, &uu, &self.l);
                fp_xctr::<Aes, RADIX>(
                    &self.ks_enc,
                    &mut dst[first_block_len..],
                    tail,
                    &s,
                    Direction::Encrypt,
                );

                let mut poly = poly_after_tweak;
                let hh2 = absorb(&mut poly, &dst[first_block_len..]);
                let mut u_bytes = uu;
                xor_block(&mut u_bytes, &hh2);
                encode_base_radix(
                    u128::from_le_bytes(u_bytes),
                    RADIX,
                    &mut dst[..first_block_len],
                );
            }
            Direction::Decrypt => {
                let hh2 = absorb(&mut poly, tail);
                let u_bits = decode_base_radix(first_part, RADIX)?;
                let mut uu: [u8; BLOCK_LENGTH] = u_bits.to_le_bytes();
                xor_block(&mut uu, &hh2);

                let mut mm_block = Array::clone_from_slice(&uu);
                self.ks_dec.decrypt_block(&mut mm_block);
                let mm: [u8; BLOCK_LENGTH] = mm_block.as_slice().try_into().unwrap();

                let s = xor_blocks_3(&mm, &uu, &self.l);
                fp_xctr::<Aes, RADIX>(
                    &self.ks_enc,
                    &mut dst[first_block_len..],
                    tail,
                    &s,
                    Direction::Decrypt,
                );

                let mut poly = poly_after_tweak;
                let hh = absorb(&mut poly, &dst[first_block_len..]);
                let mut m_bytes = mm;
                xor_block(&mut m_bytes, &hh);
                encode_base_radix(
                    u128::from_le_bytes(m_bytes),
                    RADIX,
                    &mut dst[..first_block_len],
                );
            }
        }

        Ok(())
    }
}

fn fp_xctr<Aes: BlockCipherEncrypt, const RADIX: u16>(
    ks_enc: &Aes,
    dst: &mut [u8],
    src: &[u8],
    seed: &[u8; BLOCK_LENGTH],
    dir: Direction,
) {
    debug_assert_eq!(dst.len(), src.len());

    let mut counter: u64 = 1;
    let mut i = 0;

    if is_power_of_two(RADIX) {
        let bpd = bits_per_digit(RADIX);
        let digits_per_block = 128 / bpd as usize;
        let mask: u128 = (RADIX as u128) - 1;

        let mut block = [0u8; BLOCK_LENGTH];

        while i + digits_per_block <= src.len() {
            block[..8].copy_from_slice(&counter.to_le_bytes());
            block[8..].fill(0);
            for j in 0..BLOCK_LENGTH {
                block[j] ^= seed[j];
            }
            let mut ga_block = Array::clone_from_slice(&block);
            ks_enc.encrypt_block(&mut ga_block);
            let mut ks_bytes = [0u8; 16];
            ks_bytes.copy_from_slice(ga_block.as_slice());
            let keystream = u128::from_le_bytes(ks_bytes);

            let mut ks = keystream;
            for j in 0..digits_per_block {
                let ks_digit = (ks & mask) as u8;
                let adjustment = match dir {
                    Direction::Encrypt => ks_digit,
                    Direction::Decrypt => {
                        (RADIX as u8).wrapping_sub(ks_digit) & ((RADIX as u8) - 1)
                    }
                };
                dst[i + j] = ((src[i + j] as u16 + adjustment as u16) & (RADIX - 1)) as u8;
                ks >>= bpd;
            }

            counter += 1;
            i += digits_per_block;
        }

        if i < src.len() {
            block[..8].copy_from_slice(&counter.to_le_bytes());
            block[8..].fill(0);
            for j in 0..BLOCK_LENGTH {
                block[j] ^= seed[j];
            }
            let mut ga_block = Array::clone_from_slice(&block);
            ks_enc.encrypt_block(&mut ga_block);
            let mut ks_bytes = [0u8; 16];
            ks_bytes.copy_from_slice(ga_block.as_slice());
            let keystream = u128::from_le_bytes(ks_bytes);

            let mut ks = keystream;
            while i < src.len() {
                let ks_digit = (ks & mask) as u8;
                let adjustment = match dir {
                    Direction::Encrypt => ks_digit,
                    Direction::Decrypt => {
                        (RADIX as u8).wrapping_sub(ks_digit) & ((RADIX as u8) - 1)
                    }
                };
                dst[i] = ((src[i] as u16 + adjustment as u16) & (RADIX - 1)) as u8;
                ks >>= bpd;
                i += 1;
            }
        }

        return;
    }

    let mut block = [0u8; BLOCK_LENGTH];

    while i < src.len() {
        block[..8].copy_from_slice(&counter.to_le_bytes());
        block[8..].fill(0);
        for j in 0..BLOCK_LENGTH {
            block[j] ^= seed[j];
        }

        let mut ga_block = Array::clone_from_slice(&block);
        ks_enc.encrypt_block(&mut ga_block);
        let mut ks_bytes = [0u8; 16];
        ks_bytes.copy_from_slice(ga_block.as_slice());
        let keystream = u128::from_le_bytes(ks_bytes);

        let ks_digit = (keystream % (RADIX as u128)) as u8;
        match dir {
            Direction::Encrypt => {
                dst[i] = ((src[i] as u16 + ks_digit as u16) % RADIX) as u8;
            }
            Direction::Decrypt => {
                dst[i] = ((src[i] as u16 + RADIX - ks_digit as u16) % RADIX) as u8;
            }
        }

        counter += 1;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_block_length() {
        assert_eq!(first_block_length(2), 128);
        assert_eq!(first_block_length(10), 39);
        assert_eq!(first_block_length(16), 32);
        assert_eq!(first_block_length(64), 22);
        assert_eq!(first_block_length(256), 16);
    }

    #[test]
    fn test_encode_decode_decimal() {
        let value: u128 = 12345678901234567890;
        let mut digits = [0u8; 39];
        encode_base_radix(value, 10, &mut digits);

        let decoded = decode_base_radix(&digits, 10).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_encode_decode_hex() {
        let value: u128 = 0xDEADBEEFCAFEBABE_u128 << 64 | 0x123456789ABCDEF0_u128;
        let mut digits = [0u8; 32];
        encode_base_radix(value, 16, &mut digits);

        let decoded = decode_base_radix(&digits, 16).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_encode_decode_base64() {
        let value: u128 = u128::MAX / 2;
        let mut digits = [0u8; 22];
        encode_base_radix(value, 64, &mut digits);

        let decoded = decode_base_radix(&digits, 64).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_hctr2fp_decimal_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let mut plaintext = vec![0u8; 40];
        for i in 0..38 {
            plaintext[i] = (i % 10) as u8;
        }
        plaintext[38] = 2;
        plaintext[39] = 5;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        cipher
            .encrypt(&plaintext, b"tweak", &mut ciphertext)
            .unwrap();

        for &d in &ciphertext {
            assert!(d < 10);
        }

        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2fp_hex_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Hex::new(&key);

        let plaintext: Vec<u8> = (0..33).map(|i| (i % 16) as u8).collect();
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        cipher
            .encrypt(&plaintext, b"tweak", &mut ciphertext)
            .unwrap();

        for &d in &ciphertext {
            assert!(d < 16);
        }

        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2fp_decimal_nonzero_key() {
        let key: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let mut plaintext = vec![0u8; 40];
        for i in 0..38 {
            plaintext[i] = (i % 10) as u8;
        }
        plaintext[38] = 1;
        plaintext[39] = 7;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        cipher
            .encrypt(&plaintext, b"tweak", &mut ciphertext)
            .unwrap();
        assert_ne!(plaintext, ciphertext);

        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2fp_decimal_minimum_length() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let mut plaintext = [5u8; 39];
        plaintext[38] = 2;

        let mut ciphertext = [0u8; 39];
        let mut decrypted = [0u8; 39];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2fp_decimal_too_short() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let plaintext = [5u8; 38]; // One too short
        let mut ciphertext = [0u8; 38];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InputTooShort)
        );
    }

    #[test]
    fn test_hctr2fp_decimal_invalid_digit() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let mut plaintext = [5u8; 40];
        plaintext[0] = 10; // Invalid digit for decimal
        let mut ciphertext = [0u8; 40];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InvalidDigit)
        );
    }

    #[test]
    fn test_hctr2fp_different_tweaks() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let plaintext = [5u8; 40];
        let mut ciphertext1 = [0u8; 40];
        let mut ciphertext2 = [0u8; 40];

        cipher
            .encrypt(&plaintext, b"tweak1", &mut ciphertext1)
            .unwrap();
        cipher
            .encrypt(&plaintext, b"tweak2", &mut ciphertext2)
            .unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_hctr2fp_256_decimal_roundtrip() {
        let key = [0u8; 32];
        let cipher = Hctr2Fp_256_Decimal::new(&key);

        let mut plaintext = vec![0u8; 50];
        plaintext[0] = 5;
        plaintext[1] = 7;
        plaintext[2] = 9;
        plaintext[38] = 3;
        for i in 39..50 {
            plaintext[i] = ((i - 39) % 10) as u8;
        }

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        cipher
            .encrypt(&plaintext, b"tweak", &mut ciphertext)
            .unwrap();
        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_first_block_encode_decode_consistency() {
        let value: u128 = 0x123456789ABCDEF0_u128 << 64 | 0xFEDCBA9876543210_u128;

        let mut digits = [0u8; 39];
        encode_base_radix(value, 10, &mut digits);

        for &d in &digits {
            assert!(d < 10, "digit {} out of range", d);
        }

        let decoded = decode_base_radix(&digits, 10).unwrap();
        assert_eq!(value, decoded, "encode/decode roundtrip failed");
    }

    #[test]
    fn test_xor_and_encode_decode() {
        let a: u128 = 0x123456789ABCDEF0_u128 << 64 | 0xFEDCBA9876543210_u128;
        let b: u128 = 0xFFFFFFFFFFFFFFFF_u128 << 64 | 0xFFFFFFFFFFFFFFFF_u128;

        let c = a ^ b;

        let mut digits = [0u8; 39];
        encode_base_radix(c, 10, &mut digits);

        let decoded = decode_base_radix(&digits, 10).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn test_max_u128_encode_decode() {
        let value = u128::MAX;

        let mut digits = [0u8; 39];
        encode_base_radix(value, 10, &mut digits);

        assert!(digits[38] <= 3, "39th digit {} is too large", digits[38]);

        let decoded = decode_base_radix(&digits, 10).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        #[allow(deprecated)]
        use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
        use aes::{Aes128, Aes128Dec};

        let key = [0u8; 16];
        let ks_enc = Aes128::new(Array::from_slice(&key));
        let ks_dec = Aes128Dec::new(Array::from_slice(&key));

        let plaintext = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let mut block = Array::clone_from_slice(&plaintext);
        ks_enc.encrypt_block(&mut block);
        let ciphertext: [u8; 16] = block.as_slice().try_into().unwrap();

        let mut block2 = Array::clone_from_slice(&ciphertext);
        ks_dec.decrypt_block(&mut block2);
        let decrypted: [u8; 16] = block2.as_slice().try_into().unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2fp_decimal_debug() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let plaintext = [0u8; 39];
        let mut ciphertext = [0u8; 39];
        let mut decrypted = [0u8; 39];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();

        for &d in &ciphertext {
            assert!(d < 10, "ciphertext digit {} >= 10", d);
        }

        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2fp_decimal_nonzero_plain_empty_tweak() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let mut plaintext = vec![0u8; 40];
        for i in 0..38 {
            plaintext[i] = ((i + 1) % 10) as u8;
        }
        plaintext[38] = 2;
        plaintext[39] = 8;

        let mut ciphertext = vec![0u8; 40];
        let mut decrypted = vec![0u8; 40];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2fp_decimal_zeros_plain_with_tweak() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let plaintext = [0u8; 40];
        let mut ciphertext = [0u8; 40];
        let mut decrypted = [0u8; 40];

        cipher
            .encrypt(&plaintext, b"tweak", &mut ciphertext)
            .unwrap();
        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decode_specific_pattern() {
        let mut digits = [0u8; 39];
        digits[0] = 1;
        digits[1] = 2;
        digits[2] = 3;
        digits[38] = 3;

        let value = decode_base_radix(&digits, 10).unwrap();

        let mut reencoded = [0u8; 39];
        encode_base_radix(value, 10, &mut reencoded);

        assert_eq!(digits.as_slice(), reencoded.as_slice());
    }

    #[test]
    fn test_hctr2fp_decimal_single_digit_1() {
        let key = [0u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let plaintext = [1u8; 40];
        let mut ciphertext = [0u8; 40];
        let mut decrypted = [0u8; 40];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
