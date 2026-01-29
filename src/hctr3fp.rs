#![allow(deprecated)]
//! HCTR3+FP (Format-Preserving) variant of HCTR3.
//!
//! HCTR3+FP extends HCTR3's enhanced security with format preservation, ensuring that ciphertext
//! consists only of digits in a specified radix (e.g., decimal digits 0-9 for radix-10).
//!
//! Construction features:
//! - Two-key construction (encryption key + derived authentication key)
//! - SHA-256 hashing of tweaks for domain separation
//! - fpElk mode (Format-Preserving Encrypted LFSR Keystream)
//! - Base-radix encoding for first block
//! - Modular arithmetic with LFSR-based keystream
//! - Constant-time LFSR implementation
//!
//! Use cases:
//! - Encrypting credit card numbers with enhanced security (decimal)
//! - Encrypting sensitive alphanumeric identifiers (hexadecimal or custom radix)
//! - Systems requiring both format preservation and strong security bounds
//!
//! Security properties:
//! - Ciphertext length equals plaintext length
//! - All ciphertext digits are in range [0, radix)
//! - Stronger security bounds than HCTR2+FP
//! - Requires unique (key, tweak) pairs for security
//! - No authentication - consider AEAD if integrity protection is needed
//! - Minimum message length depends on radix (e.g., 39 digits for decimal)

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherDecrypt};
use aes::{Aes128, Aes256};
use polyval::{Polyval, universal_hash::UniversalHash};
use sha2::{Digest, Sha256};

use crate::common::{
    BLOCK_LENGTH, Direction, Error, absorb, lfsr_next_128, xor_block, xor_blocks_3,
};
use crate::hctr2::AesCipher;
use crate::hctr2fp::{
    bits_per_digit, decode_base_radix, encode_base_radix, first_block_length, is_power_of_two,
};

/// Generic HCTR3+FP cipher.
pub struct Hctr3Fp<Aes: AesCipher, const RADIX: u16> {
    ks_enc: Aes,
    ks_dec: Aes::Dec,
    ke_enc: Aes,
    h: [u8; BLOCK_LENGTH],
    l: [u8; BLOCK_LENGTH],
}

#[allow(non_camel_case_types)]
/// HCTR3+FP with AES-128, SHA-256 tweak hashing, and decimal (radix-10) format preservation.
pub type Hctr3Fp_128_Decimal = Hctr3Fp<Aes128, 10>;

#[allow(non_camel_case_types)]
/// HCTR3+FP with AES-256, SHA-256 tweak hashing, and decimal (radix-10) format preservation.
pub type Hctr3Fp_256_Decimal = Hctr3Fp<Aes256, 10>;

#[allow(non_camel_case_types)]
/// HCTR3+FP with AES-128, SHA-256 tweak hashing, and hexadecimal (radix-16) format preservation.
pub type Hctr3Fp_128_Hex = Hctr3Fp<Aes128, 16>;

#[allow(non_camel_case_types)]
/// HCTR3+FP with AES-256, SHA-256 tweak hashing, and hexadecimal (radix-16) format preservation.
pub type Hctr3Fp_256_Hex = Hctr3Fp<Aes256, 16>;

#[allow(non_camel_case_types)]
/// HCTR3+FP with AES-128, SHA-256 tweak hashing, and base-64 (radix-64) format preservation.
pub type Hctr3Fp_128_Base64 = Hctr3Fp<Aes128, 64>;

#[allow(non_camel_case_types)]
/// HCTR3+FP with AES-256, SHA-256 tweak hashing, and base-64 (radix-64) format preservation.
pub type Hctr3Fp_256_Base64 = Hctr3Fp<Aes256, 64>;

impl<Aes: AesCipher, const RADIX: u16> Hctr3Fp<Aes, RADIX> {
    /// First block length in digits (radix-dependent).
    pub const FIRST_BLOCK_LENGTH: usize = first_block_length(RADIX);

    /// Minimum message length in digits (same as first_block_length).
    pub const MIN_MESSAGE_LENGTH: usize = Self::FIRST_BLOCK_LENGTH;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR3+FP cipher state from an encryption key.
    ///
    /// Derives a secondary authentication key (Ke) from the encryption key for the two-key construction.
    pub fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Aes::KEY_LEN);

        let ks_enc = Aes::new(Array::from_slice(key));
        let ks_dec = Aes::new_dec(key);

        // Derive Ke (authentication key)
        let mut ke_block0 = Array::clone_from_slice(&[0u8; 16]);
        ks_enc.encrypt_block(&mut ke_block0);

        let ke_key: Vec<u8> = if Aes::KEY_LEN <= 16 {
            ke_block0[..Aes::KEY_LEN].to_vec()
        } else {
            // For AES-256, need 32 bytes - use [0x01; 16] for second block
            let mut ke_block1 = Array::clone_from_slice(&[0x01u8; 16]);
            ks_enc.encrypt_block(&mut ke_block1);
            let mut ke = vec![0u8; Aes::KEY_LEN];
            ke[..16].copy_from_slice(ke_block0.as_slice());
            ke[16..].copy_from_slice(&ke_block1[..(Aes::KEY_LEN - 16)]);
            ke
        };

        let ke_enc = Aes::new(Array::from_slice(&ke_key));

        let mut h_block = Array::clone_from_slice(&[0u8; 16]);
        let mut l_block = Array::clone_from_slice(&{
            let mut b = [0u8; 16];
            b[15] = 1;
            b
        });
        ke_enc.encrypt_block(&mut h_block);
        ke_enc.encrypt_block(&mut l_block);

        let h: [u8; 16] = h_block.as_slice().try_into().unwrap();
        let l: [u8; 16] = l_block.as_slice().try_into().unwrap();
        Self {
            ks_enc,
            ks_dec,
            ke_enc,
            h,
            l,
        }
    }

    /// Encrypt plaintext digits to ciphertext digits using HCTR3+FP.
    ///
    /// All input digits must be in range [0, RADIX). Output will also be in this range.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr3fp(plaintext, tweak, ciphertext, Direction::Encrypt)
    }

    /// Decrypt ciphertext digits to plaintext digits using HCTR3+FP.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr3fp(ciphertext, tweak, plaintext, Direction::Decrypt)
    }

    fn hctr3fp(
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

        let mut hasher = Sha256::new();
        hasher.update(tweak);
        let hash_out = hasher.finalize();
        let mut t = [0u8; BLOCK_LENGTH];
        t.copy_from_slice(&hash_out[..BLOCK_LENGTH]);

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

        poly.update(&[Array::clone_from_slice(&t)]);

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
                self.fp_elk(&mut dst[first_block_len..], tail, &s, Direction::Encrypt);

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
                self.fp_elk(&mut dst[first_block_len..], tail, &s, Direction::Decrypt);

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

    fn fp_elk(&self, dst: &mut [u8], src: &[u8], seed: &[u8; BLOCK_LENGTH], dir: Direction) {
        debug_assert_eq!(dst.len(), src.len());

        let mut lfsr = *seed;
        let mut i = 0;

        if is_power_of_two(RADIX) {
            let bpd = bits_per_digit(RADIX);
            let digits_per_block = 128 / bpd as usize;
            let mask: u128 = (RADIX as u128) - 1;

            let mut block = [0u8; BLOCK_LENGTH];

            while i + digits_per_block <= src.len() {
                block.copy_from_slice(&lfsr);
                lfsr = lfsr_next_128(&lfsr);
                let mut ga_block = Array::clone_from_slice(&block);
                self.ke_enc.encrypt_block(&mut ga_block);
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

                i += digits_per_block;
            }

            if i < src.len() {
                block.copy_from_slice(&lfsr);
                let mut ga_block = Array::clone_from_slice(&block);
                self.ke_enc.encrypt_block(&mut ga_block);
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
            block.copy_from_slice(&lfsr);
            lfsr = lfsr_next_128(&lfsr);

            let mut ga_block = Array::clone_from_slice(&block);
            self.ke_enc.encrypt_block(&mut ga_block);
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

            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hctr3fp_decimal_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Decimal::new(&key);

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
    fn test_hctr3fp_hex_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Hex::new(&key);

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
    fn test_hctr3fp_decimal_nonzero_key() {
        let key: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);
        let cipher = Hctr3Fp_128_Decimal::new(&key);

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
    fn test_hctr3fp_decimal_minimum_length() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Decimal::new(&key);

        // Exactly 39 digits (minimum for decimal)
        let mut plaintext = [5u8; 39];
        plaintext[38] = 2;

        let mut ciphertext = [0u8; 39];
        let mut decrypted = [0u8; 39];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr3fp_decimal_too_short() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Decimal::new(&key);

        let plaintext = [5u8; 38]; // One too short
        let mut ciphertext = [0u8; 38];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InputTooShort)
        );
    }

    #[test]
    fn test_hctr3fp_decimal_invalid_digit() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Decimal::new(&key);

        let mut plaintext = [5u8; 40];
        plaintext[0] = 10; // Invalid digit for decimal
        let mut ciphertext = [0u8; 40];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InvalidDigit)
        );
    }

    #[test]
    fn test_hctr3fp_different_tweaks() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Decimal::new(&key);

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
    fn test_hctr3fp_256_decimal_roundtrip() {
        let key = [0u8; 32];
        let cipher = Hctr3Fp_256_Decimal::new(&key);

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
    fn test_hctr3fp_decimal_zeros() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Decimal::new(&key);

        let plaintext = [0u8; 39];
        let mut ciphertext = [0u8; 39];
        let mut decrypted = [0u8; 39];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr3fp_base64_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Base64::new(&key);

        let mut plaintext = vec![0u8; 23];
        for i in 0..21 {
            plaintext[i] = (i % 64) as u8;
        }
        plaintext[21] = 3;
        plaintext[22] = 42;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        cipher
            .encrypt(&plaintext, b"tweak", &mut ciphertext)
            .unwrap();

        for &d in &ciphertext {
            assert!(d < 64);
        }

        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr3fp_vs_hctr2fp_different_output() {
        use crate::hctr2fp::Hctr2Fp_128_Decimal;

        let key = [0u8; 16];
        let hctr2fp = Hctr2Fp_128_Decimal::new(&key);
        let hctr3fp = Hctr3Fp_128_Decimal::new(&key);

        let plaintext = [0u8; 40];
        let mut ciphertext2 = [0u8; 40];
        let mut ciphertext3 = [0u8; 40];

        hctr2fp
            .encrypt(&plaintext, b"tweak", &mut ciphertext2)
            .unwrap();
        hctr3fp
            .encrypt(&plaintext, b"tweak", &mut ciphertext3)
            .unwrap();
        assert_ne!(ciphertext2, ciphertext3);
    }

    #[test]
    fn test_lfsr_next_produces_unique_states() {
        let initial = [0x01u8; 16];
        let mut state = initial;
        let mut seen = std::collections::HashSet::new();
        seen.insert(state);

        for _ in 0..1000 {
            state = lfsr_next_128(&state);
            assert!(seen.insert(state), "LFSR produced duplicate state");
        }
    }

    #[test]
    fn test_hctr3fp_large_message() {
        let key = [0u8; 16];
        let cipher = Hctr3Fp_128_Hex::new(&key);

        let plaintext: Vec<u8> = (0..256).map(|i| (i % 16) as u8).collect();
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        cipher
            .encrypt(&plaintext, b"large tweak", &mut ciphertext)
            .unwrap();
        cipher
            .decrypt(&ciphertext, b"large tweak", &mut decrypted)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
