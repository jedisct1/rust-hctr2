#![allow(deprecated)]
//! HCTR2 (Hash-CTR-Hash) length-preserving wide-block tweakable cipher.
//!
//! HCTR2 provides full-block diffusion: any change to plaintext affects the entire ciphertext.
//! It requires no nonce or authentication tag, making it suitable for constrained environments.
//!
//! Construction uses:
//! - Single encryption key
//! - Polyval universal hash function
//! - XCTR mode for wide-block encryption (counter-based)
//!
//! Security properties:
//! - Ciphertext length equals plaintext length (no expansion)
//! - Requires unique (key, tweak) pairs for security
//! - No authentication - consider AEAD if integrity protection is needed
//! - Minimum message length: 16 bytes (one AES block)

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use polyval::{Polyval, universal_hash::UniversalHash};

use crate::common::{BLOCK_LENGTH, Direction, Error, absorb, xctr, xor_blocks, xor_blocks_3};

/// Trait for AES ciphers used in HCTR2.
pub trait AesCipher: BlockCipherEncrypt + KeyInit + Clone {
    type Dec: BlockCipherDecrypt + KeyInit;
    const KEY_LEN: usize;

    fn new_dec(key: &[u8]) -> Self::Dec;
}

impl AesCipher for Aes128 {
    type Dec = aes::Aes128Dec;
    const KEY_LEN: usize = 16;

    fn new_dec(key: &[u8]) -> Self::Dec {
        aes::Aes128Dec::new(Array::from_slice(key))
    }
}

impl AesCipher for Aes256 {
    type Dec = aes::Aes256Dec;
    const KEY_LEN: usize = 32;

    fn new_dec(key: &[u8]) -> Self::Dec {
        aes::Aes256Dec::new(Array::from_slice(key))
    }
}

/// Generic HCTR2 cipher parameterized by AES key size.
pub struct Hctr2<Aes: AesCipher> {
    ks_enc: Aes,
    ks_dec: Aes::Dec,
    h: [u8; BLOCK_LENGTH],
    l: [u8; BLOCK_LENGTH],
}

/// HCTR2 with AES-128 encryption.
#[allow(non_camel_case_types)]
pub type Hctr2_128 = Hctr2<Aes128>;

/// HCTR2 with AES-256 encryption.
#[allow(non_camel_case_types)]
pub type Hctr2_256 = Hctr2<Aes256>;

// Keep the old error type as an alias for backwards compatibility
#[allow(non_camel_case_types)]
#[deprecated(note = "Use common::Error instead")]
pub type Hctr2Error = Error;

impl<Aes: AesCipher> Hctr2<Aes> {
    /// Encryption key length in bytes.
    pub const KEY_LENGTH: usize = Aes::KEY_LEN;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR2 cipher state from an encryption key.
    pub fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Aes::KEY_LEN);

        let ks_enc = Aes::new(Array::from_slice(key));
        let ks_dec = Aes::new_dec(key);

        let mut block0 = Array::clone_from_slice(&[0u8; 16]);
        let mut block1 = Array::clone_from_slice(&{
            let mut b = [0u8; 16];
            b[0] = 1;
            b
        });

        ks_enc.encrypt_block(&mut block0);
        ks_enc.encrypt_block(&mut block1);

        let h: [u8; 16] = block0.as_slice().try_into().unwrap();
        let l: [u8; 16] = block1.as_slice().try_into().unwrap();
        Self {
            ks_enc,
            ks_dec,
            h,
            l,
        }
    }

    /// Encrypt plaintext to ciphertext using HCTR2.
    ///
    /// # Arguments
    /// * `plaintext` - Input data to encrypt (minimum 16 bytes)
    /// * `tweak` - Tweak value for domain separation
    /// * `ciphertext` - Output buffer (must be same length as plaintext)
    ///
    /// # Errors
    /// Returns `Error::InputTooShort` if plaintext is less than 16 bytes.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr2(plaintext, tweak, ciphertext, Direction::Encrypt)
    }

    /// Decrypt ciphertext to plaintext using HCTR2.
    ///
    /// # Arguments
    /// * `ciphertext` - Input data to decrypt (minimum 16 bytes)
    /// * `tweak` - Tweak value used during encryption
    /// * `plaintext` - Output buffer (must be same length as ciphertext)
    ///
    /// # Errors
    /// Returns `Error::InputTooShort` if ciphertext is less than 16 bytes.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr2(ciphertext, tweak, plaintext, Direction::Decrypt)
    }

    fn hctr2(
        &self,
        src: &[u8],
        tweak: &[u8],
        dst: &mut [u8],
        direction: Direction,
    ) -> Result<(), Error> {
        debug_assert_eq!(dst.len(), src.len());
        if src.len() < BLOCK_LENGTH {
            return Err(Error::InputTooShort);
        }

        let m: [u8; BLOCK_LENGTH] = src[..BLOCK_LENGTH].try_into().unwrap();
        let n = &src[BLOCK_LENGTH..];

        let tweak_len_bits = tweak.len() * 8;
        let tweak_len_encoded: u128 = if n.len() % BLOCK_LENGTH == 0 {
            (2 * tweak_len_bits + 2) as u128
        } else {
            (2 * tweak_len_bits + 3) as u128
        };

        let mut poly = Polyval::new(Array::from_slice(&self.h));
        poly.update(&[Array::from(tweak_len_encoded.to_le_bytes())]);
        poly.update_padded(tweak);
        let poly_after_tweak = poly.clone();

        let hh = absorb(&mut poly, n);
        let mm = xor_blocks(&hh, &m);

        let uu: [u8; BLOCK_LENGTH] = match direction {
            Direction::Encrypt => {
                let mut block = Array::clone_from_slice(&mm);
                self.ks_enc.encrypt_block(&mut block);
                block.as_slice().try_into().unwrap()
            }
            Direction::Decrypt => {
                let mut block = Array::clone_from_slice(&mm);
                self.ks_dec.decrypt_block(&mut block);
                block.as_slice().try_into().unwrap()
            }
        };

        let s = xor_blocks_3(&mm, &uu, &self.l);
        let (u, v) = dst.split_at_mut(BLOCK_LENGTH);
        xctr(&self.ks_enc, v, n, &s);

        let mut poly = poly_after_tweak;
        let hh2 = absorb(&mut poly, v);
        u.copy_from_slice(&xor_blocks(&uu, &hh2));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hctr2_128_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr2_128::new(&key);

        let plaintext = b"Hello, HCTR2 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2_128_roundtrip_nonzero_key() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let cipher = Hctr2_128::new(&key);

        let plaintext = b"Hello, HCTR2 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2_128_minimum_length() {
        let key = [0u8; 16];
        let cipher = Hctr2_128::new(&key);

        let plaintext = [0x42u8; 16];
        let mut ciphertext = [0u8; 16];
        let mut decrypted = [0u8; 16];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2_128_input_too_short() {
        let key = [0u8; 16];
        let cipher = Hctr2_128::new(&key);

        let plaintext = [0x42u8; 15]; // Too short
        let mut ciphertext = [0u8; 15];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InputTooShort)
        );
    }

    #[test]
    fn test_hctr2_128_different_tweaks() {
        let key = [0u8; 16];
        let cipher = Hctr2_128::new(&key);

        let plaintext = [0x42u8; 32];
        let mut ciphertext1 = [0u8; 32];
        let mut ciphertext2 = [0u8; 32];

        cipher
            .encrypt(&plaintext, b"tweak1", &mut ciphertext1)
            .unwrap();
        cipher
            .encrypt(&plaintext, b"tweak2", &mut ciphertext2)
            .unwrap();
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_hctr2_128_large_message() {
        let key = [0u8; 16];
        let cipher = Hctr2_128::new(&key);

        let plaintext = [0xABu8; 1024];
        let mut ciphertext = [0u8; 1024];
        let mut decrypted = [0u8; 1024];

        cipher
            .encrypt(&plaintext, b"large tweak", &mut ciphertext)
            .unwrap();
        cipher
            .decrypt(&ciphertext, b"large tweak", &mut decrypted)
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2_256_roundtrip() {
        let key = [0u8; 32];
        let cipher = Hctr2_256::new(&key);

        let plaintext = b"Hello, HCTR2-256 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak 256";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
