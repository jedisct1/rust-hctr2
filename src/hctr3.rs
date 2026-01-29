#![allow(deprecated)]
//! HCTR3 (Hash-CTR-Hash version 3) length-preserving wide-block tweakable cipher.
//!
//! HCTR3 is an improved version of HCTR2 with enhanced security properties.
//! Like HCTR2, it requires no nonce or authentication tag.
//!
//! Construction differences from HCTR2:
//! - Two-key construction (encryption key + derived authentication key)
//! - SHA-256 hashing of tweaks for domain separation
//! - ELK mode (Encrypted LFSR Keystream) instead of XCTR
//! - Constant-time LFSR implementation
//!
//! Security properties:
//! - Ciphertext length equals plaintext length (no expansion)
//! - Stronger security bounds than HCTR2
//! - Requires unique (key, tweak) pairs for security
//! - No authentication - consider AEAD if integrity protection is needed
//! - Minimum message length: 16 bytes (one AES block)

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherDecrypt};
use aes::{Aes128, Aes256};
use polyval::{Polyval, universal_hash::UniversalHash};
use sha2::{Digest, Sha256};

use crate::common::{BLOCK_LENGTH, Direction, Error, absorb, elk, xor_blocks, xor_blocks_3};
use crate::hctr2::AesCipher;

// Keep the old error type as an alias for backwards compatibility
#[allow(non_camel_case_types)]
#[deprecated(note = "Use common::Error instead")]
pub type Hctr3Error = Error;

/// Generic HCTR3 cipher parameterized by AES key size.
pub struct Hctr3<Aes: AesCipher> {
    ks_enc: Aes,
    ks_dec: Aes::Dec,
    ke_enc: Aes,
    h: [u8; BLOCK_LENGTH],
    l: [u8; BLOCK_LENGTH],
}

/// HCTR3 with AES-128 encryption and SHA-256 tweak hashing.
#[allow(non_camel_case_types)]
pub type Hctr3_128 = Hctr3<Aes128>;

/// HCTR3 with AES-256 encryption and SHA-256 tweak hashing.
#[allow(non_camel_case_types)]
pub type Hctr3_256 = Hctr3<Aes256>;

impl<Aes: AesCipher> Hctr3<Aes> {
    /// Encryption key length in bytes.
    pub const KEY_LENGTH: usize = Aes::KEY_LEN;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR3 cipher state from an encryption key.
    ///
    /// Derives a secondary authentication key (Ke) from the encryption key for the two-key construction.
    pub fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Aes::KEY_LEN);

        let ks_enc = Aes::new(Array::from_slice(key));
        let ks_dec = Aes::new_dec(key);

        let ke_key: Vec<u8> = if Aes::KEY_LEN <= 16 {
            let mut ke_block = Array::clone_from_slice(&[0u8; 16]);
            ks_enc.encrypt_block(&mut ke_block);
            ke_block[..Aes::KEY_LEN].to_vec()
        } else {
            let mut ke_block0 = Array::clone_from_slice(&[0u8; 16]);
            let mut ke_block1 = Array::clone_from_slice(&[0x01u8; 16]);
            ks_enc.encrypt_block(&mut ke_block0);
            ks_enc.encrypt_block(&mut ke_block1);
            let mut ke = vec![0u8; Aes::KEY_LEN];
            ke[..16].copy_from_slice(ke_block0.as_slice());
            ke[16..].copy_from_slice(&ke_block1.as_slice()[..(Aes::KEY_LEN - 16)]);
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

    /// Encrypt plaintext to ciphertext using HCTR3.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr3(plaintext, tweak, ciphertext, Direction::Encrypt)
    }

    /// Decrypt ciphertext to plaintext using HCTR3.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr3(ciphertext, tweak, plaintext, Direction::Decrypt)
    }

    fn hctr3(
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

        let mut hasher = Sha256::new();
        hasher.update(tweak);
        let hash_out = hasher.finalize();
        let t: [u8; BLOCK_LENGTH] = hash_out[..BLOCK_LENGTH].try_into().unwrap();

        let tweak_len_bits = tweak.len() * 8;
        let tweak_len_encoded: u128 = if n.len() % BLOCK_LENGTH == 0 {
            (2 * tweak_len_bits + 2) as u128
        } else {
            (2 * tweak_len_bits + 3) as u128
        };

        let mut poly = Polyval::new(Array::from_slice(&self.h));
        poly.update(&[Array::from(tweak_len_encoded.to_le_bytes())]);
        poly.update(&[Array::from(t)]);
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
        elk(&self.ke_enc, v, n, &s);

        let mut poly = poly_after_tweak;
        let hh2 = absorb(&mut poly, v);
        u.copy_from_slice(&xor_blocks(&uu, &hh2));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::lfsr_next_128;

    #[test]
    fn test_hctr3_128_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr3_128::new(&key);

        let plaintext = b"Hello, HCTR3 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr3_128_roundtrip_nonzero_key() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let cipher = Hctr3_128::new(&key);

        let plaintext = b"Hello, HCTR3 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr3_128_minimum_length() {
        let key = [0u8; 16];
        let cipher = Hctr3_128::new(&key);

        let plaintext = [0x42u8; 16];
        let mut ciphertext = [0u8; 16];
        let mut decrypted = [0u8; 16];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr3_128_input_too_short() {
        let key = [0u8; 16];
        let cipher = Hctr3_128::new(&key);

        let plaintext = [0x42u8; 15];
        let mut ciphertext = [0u8; 15];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InputTooShort)
        );
    }

    #[test]
    fn test_hctr3_128_different_tweaks() {
        let key = [0u8; 16];
        let cipher = Hctr3_128::new(&key);

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
    fn test_hctr3_128_large_message() {
        let key = [0u8; 16];
        let cipher = Hctr3_128::new(&key);

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
    fn test_hctr3_256_roundtrip() {
        let key = [0u8; 32];
        let cipher = Hctr3_256::new(&key);

        let plaintext = b"Hello, HCTR3-256 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak 256";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_lfsr_128_produces_unique_states() {
        let initial = [0x01u8; 16];
        let mut state = initial;
        let mut seen = std::collections::HashSet::new();
        seen.insert(state);

        for _ in 0..1000 {
            state = lfsr_next_128(&state);
            assert!(seen.insert(state), "LFSR produced duplicate state");
        }
    }
}
