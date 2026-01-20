#![allow(deprecated)]
//! CHCTR2 (Cascaded HCTR2) beyond-birthday-bound secure wide-block tweakable cipher.
//!
//! CHCTR2 achieves 2n/3-bit multi-user security (approximately 85 bits with 128-bit blocks)
//! by cascading HCTR2 twice with two independent keys. This provides significantly higher
//! security than standard HCTR2's birthday-bound (64-bit) security.
//!
//! Construction (from "Beyond-Birthday-Bound Security with HCTR2", ASIACRYPT 2025):
//! - Uses two independent keys K1 and K2
//! - CHCTR2[K1,K2](T,M) = HCTR2[K2](T, HCTR2[K1](T, M))
//! - Optimized: middle hash layer combines H1 and H2: Z_{1,2} = H1(T,R) XOR H2(T,R)
//! - Cost per block: 2 BC calls + 3 field multiplications
//!
//! Security properties:
//! - Beyond-birthday-bound: ~85-bit security vs HCTR2's ~64-bit
//! - No restrictions on tweak usage
//! - Multi-user secure
//! - Ciphertext length equals plaintext length

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use polyval::{Polyval, universal_hash::UniversalHash};

use crate::common::{BLOCK_LENGTH, Direction, Error, absorb, xctr, xor_blocks, xor_blocks_3};
use crate::hctr2::AesCipher;

// Keep the old error type as an alias for backwards compatibility
#[allow(non_camel_case_types)]
#[deprecated(note = "Use common::Error instead")]
pub type Chctr2Error = Error;

/// Generic CHCTR2 cipher parameterized by AES key size.
pub struct Chctr2<Aes: AesCipher> {
    ks1_enc: Aes,
    ks1_dec: Aes::Dec,
    h1: [u8; BLOCK_LENGTH],
    l1: [u8; BLOCK_LENGTH],
    ks2_enc: Aes,
    ks2_dec: Aes::Dec,
    h2: [u8; BLOCK_LENGTH],
    l2: [u8; BLOCK_LENGTH],
}

/// CHCTR2 with AES-128 encryption (uses two AES-128 keys = 32 bytes total).
#[allow(non_camel_case_types)]
pub type Chctr2_128 = Chctr2<Aes128>;

/// CHCTR2 with AES-256 encryption (uses two AES-256 keys = 64 bytes total).
#[allow(non_camel_case_types)]
pub type Chctr2_256 = Chctr2<Aes256>;

impl<Aes: AesCipher> Chctr2<Aes> {
    /// Total key length in bytes (two AES keys).
    pub const KEY_LENGTH: usize = Aes::KEY_LEN * 2;

    /// Single AES key length.
    pub const SINGLE_KEY_LENGTH: usize = Aes::KEY_LEN;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize CHCTR2 from two separate keys.
    pub fn new_split(key1: &[u8], key2: &[u8]) -> Self {
        debug_assert_eq!(key1.len(), Aes::KEY_LEN);
        debug_assert_eq!(key2.len(), Aes::KEY_LEN);

        fn derive_hl<A: BlockCipherEncrypt>(ks: &A) -> ([u8; 16], [u8; 16]) {
            let mut h_block = Array::clone_from_slice(&[0u8; 16]);
            let mut l_block = Array::clone_from_slice(&{
                let mut b = [0u8; 16];
                b[0] = 1;
                b
            });
            ks.encrypt_block(&mut h_block);
            ks.encrypt_block(&mut l_block);
            (
                h_block.as_slice().try_into().unwrap(),
                l_block.as_slice().try_into().unwrap(),
            )
        }

        let ks1_enc = Aes::new(Array::from_slice(key1));
        let ks1_dec = Aes::new_dec(key1);
        let (h1, l1) = derive_hl(&ks1_enc);

        let ks2_enc = Aes::new(Array::from_slice(key2));
        let ks2_dec = Aes::new_dec(key2);
        let (h2, l2) = derive_hl(&ks2_enc);

        Self {
            ks1_enc,
            ks1_dec,
            h1,
            l1,
            ks2_enc,
            ks2_dec,
            h2,
            l2,
        }
    }

    /// Encrypt plaintext to ciphertext using CHCTR2.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.chctr2(plaintext, tweak, ciphertext, Direction::Encrypt)
    }

    /// Decrypt ciphertext to plaintext using CHCTR2.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        self.chctr2(ciphertext, tweak, plaintext, Direction::Decrypt)
    }

    /// Optimized CHCTR2 implementation.
    /// Structure: hash1-encrypt1-hash_{1,2}-encrypt2-hash2
    fn chctr2(
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

        let m0: [u8; BLOCK_LENGTH] = src[..BLOCK_LENGTH].try_into().unwrap();
        let m_star = &src[BLOCK_LENGTH..];

        let tweak_len_bits = tweak.len() * 8;
        let tweak_len_encoded: u128 = if m_star.len() % BLOCK_LENGTH == 0 {
            (2 * tweak_len_bits + 2) as u128
        } else {
            (2 * tweak_len_bits + 3) as u128
        };
        let len_block = Array::from(tweak_len_encoded.to_le_bytes());

        let mut poly1 = Polyval::new(Array::from_slice(&self.h1));
        poly1.update(&[len_block]);
        poly1.update_padded(tweak);
        let poly1_after_tweak = poly1.clone();

        let mut poly2 = Polyval::new(Array::from_slice(&self.h2));
        poly2.update(&[len_block]);
        poly2.update_padded(tweak);
        let poly2_after_tweak = poly2.clone();

        match direction {
            Direction::Encrypt => {
                let z1 = absorb(&mut poly1, m_star);
                let x1_0 = xor_blocks(&z1, &m0);

                let y1_0: [u8; 16] = {
                    let mut block = Array::clone_from_slice(&x1_0);
                    self.ks1_enc.encrypt_block(&mut block);
                    block.as_slice().try_into().unwrap()
                };

                let iv1 = xor_blocks_3(&x1_0, &y1_0, &self.l1);

                let (_, r_slice) = dst.split_at_mut(BLOCK_LENGTH);
                xctr(&self.ks1_enc, r_slice, m_star, &iv1);

                let mut poly1 = poly1_after_tweak.clone();
                let mut poly2 = poly2_after_tweak.clone();
                let h1_r = absorb(&mut poly1, r_slice);
                let h2_r = absorb(&mut poly2, r_slice);
                let z1_2 = xor_blocks(&h1_r, &h2_r);

                let x2_0 = xor_blocks(&y1_0, &z1_2);

                let y2_0: [u8; 16] = {
                    let mut block = Array::clone_from_slice(&x2_0);
                    self.ks2_enc.encrypt_block(&mut block);
                    block.as_slice().try_into().unwrap()
                };

                let iv2 = xor_blocks_3(&x2_0, &y2_0, &self.l2);

                let c_star_src: Vec<u8> = r_slice.to_vec();
                let (_, c_star) = dst.split_at_mut(BLOCK_LENGTH);
                xctr(&self.ks2_enc, c_star, &c_star_src, &iv2);

                let mut poly2 = poly2_after_tweak;
                let z2 = absorb(&mut poly2, c_star);
                dst[..BLOCK_LENGTH].copy_from_slice(&xor_blocks(&y2_0, &z2));
            }
            Direction::Decrypt => {
                let c0: [u8; BLOCK_LENGTH] = src[..BLOCK_LENGTH].try_into().unwrap();
                let c_star = &src[BLOCK_LENGTH..];

                let z2 = absorb(&mut poly2, c_star);
                let y2_0 = xor_blocks(&c0, &z2);

                let x2_0: [u8; 16] = {
                    let mut block = Array::clone_from_slice(&y2_0);
                    self.ks2_dec.decrypt_block(&mut block);
                    block.as_slice().try_into().unwrap()
                };

                let iv2 = xor_blocks_3(&x2_0, &y2_0, &self.l2);

                let (_, r_slice) = dst.split_at_mut(BLOCK_LENGTH);
                xctr(&self.ks2_enc, r_slice, c_star, &iv2);

                let mut poly1 = poly1_after_tweak.clone();
                let mut poly2 = poly2_after_tweak.clone();
                let h1_r = absorb(&mut poly1, r_slice);
                let h2_r = absorb(&mut poly2, r_slice);
                let z1_2 = xor_blocks(&h1_r, &h2_r);

                let y1_0 = xor_blocks(&x2_0, &z1_2);

                let x1_0: [u8; 16] = {
                    let mut block = Array::clone_from_slice(&y1_0);
                    self.ks1_dec.decrypt_block(&mut block);
                    block.as_slice().try_into().unwrap()
                };

                let iv1 = xor_blocks_3(&x1_0, &y1_0, &self.l1);

                let r_copy: Vec<u8> = r_slice.to_vec();
                let (_, m_star_out) = dst.split_at_mut(BLOCK_LENGTH);
                xctr(&self.ks1_enc, m_star_out, &r_copy, &iv1);

                let mut poly1 = poly1_after_tweak;
                let z1 = absorb(&mut poly1, m_star_out);
                dst[..BLOCK_LENGTH].copy_from_slice(&xor_blocks(&x1_0, &z1));
            }
        }

        Ok(())
    }
}

impl Chctr2_128 {
    /// Initialize CHCTR2-128 from a combined key (K1 || K2).
    pub fn new(key: &[u8; 32]) -> Self {
        let key1: [u8; 16] = key[..16].try_into().unwrap();
        let key2: [u8; 16] = key[16..].try_into().unwrap();
        Self::new_split(&key1, &key2)
    }
}

impl Chctr2_256 {
    /// Initialize CHCTR2-256 from a combined key (K1 || K2).
    pub fn new(key: &[u8; 64]) -> Self {
        let key1: [u8; 32] = key[..32].try_into().unwrap();
        let key2: [u8; 32] = key[32..].try_into().unwrap();
        Self::new_split(&key1, &key2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chctr2_128_roundtrip() {
        let key = [0u8; 32];
        let cipher = Chctr2_128::new(&key);

        let plaintext = b"Hello, CHCTR2 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chctr2_128_roundtrip_nonzero_key() {
        let key: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let cipher = Chctr2_128::new(&key);

        let plaintext = b"Hello, CHCTR2 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chctr2_128_minimum_length() {
        let key = [0u8; 32];
        let cipher = Chctr2_128::new(&key);

        let plaintext = [0x42u8; 16];
        let mut ciphertext = [0u8; 16];
        let mut decrypted = [0u8; 16];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_chctr2_128_input_too_short() {
        let key = [0u8; 32];
        let cipher = Chctr2_128::new(&key);

        let plaintext = [0x42u8; 15];
        let mut ciphertext = [0u8; 15];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InputTooShort)
        );
    }

    #[test]
    fn test_chctr2_128_different_tweaks() {
        let key = [0u8; 32];
        let cipher = Chctr2_128::new(&key);

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
    fn test_chctr2_128_split_init() {
        let key1 = [0x01u8; 16];
        let key2 = [0x02u8; 16];
        let cipher = Chctr2_128::new_split(&key1, &key2);

        let plaintext = b"Test split key init";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        cipher
            .encrypt(plaintext, b"tweak", &mut ciphertext)
            .unwrap();
        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chctr2_128_large_message() {
        let key = [0u8; 32];
        let cipher = Chctr2_128::new(&key);

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
    fn test_chctr2_256_roundtrip() {
        let key = [0u8; 64];
        let cipher = Chctr2_256::new(&key);

        let plaintext = b"Hello, CHCTR2-256 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak 256";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
