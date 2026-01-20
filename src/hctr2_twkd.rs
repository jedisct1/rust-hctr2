#![allow(deprecated)]
//! HCTR2-TwKD (HCTR2 with Tweak-Based Key Derivation) beyond-birthday-bound secure cipher.
//!
//! HCTR2-TwKD achieves 2n/3-bit multi-user security (approximately 85 bits with 128-bit blocks)
//! when the number of BC calls per tweak is bounded by 2^(n/3).
//!
//! Construction (from "Beyond-Birthday-Bound Security with HCTR2", ASIACRYPT 2025):
//! - Uses a KDF F to derive HCTR2's key from the tweak
//! - HCTR2-TwKD[F_L, E, H](T, M) = HCTR2[E_{F_L(T_0)}, H](T_*, M)
//! - Cost per block: 1 BC call + 2 field multiplications (same as HCTR2)
//! - Small overhead for key derivation per unique tweak
//!
//! Security properties:
//! - Beyond-birthday-bound: ~85-bit security when tweak repetition <= 2^(n/3)
//! - Multi-user secure
//! - Ciphertext length equals plaintext length
//! - Maintains backward compatibility with HCTR2 implementations

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use crate::common::{BLOCK_LENGTH, Error, xor_blocks};
use crate::hctr2::{Hctr2_128, Hctr2_256};

// Keep the old error type as an alias for backwards compatibility
#[allow(non_camel_case_types)]
#[deprecated(note = "Use common::Error instead")]
pub type Hctr2TwKDError = Error;

/// CENC-based Key Derivation Function for AES-128.
///
/// Derives an AES key from a master key and a tweak using CENC construction:
/// K = E_L(00||T) XOR E_L(01||T)
pub struct CencKdf128 {
    ks: Aes128,
}

impl CencKdf128 {
    /// Master key length (same as AES-128 key length).
    pub const MASTER_KEY_LENGTH: usize = 16;

    /// Derived key length (same as AES-128 key length).
    pub const KEY_LENGTH: usize = 16;

    /// Maximum tweak length (14 bytes).
    pub const MAX_TWEAK_LENGTH: usize = 14;

    /// Initialize the KDF with a master key.
    pub fn new(master_key: &[u8; 16]) -> Self {
        Self {
            ks: Aes128::new(Array::from_slice(master_key)),
        }
    }

    /// Derive a key from a tweak.
    ///
    /// # Panics
    /// Panics if tweak length exceeds MAX_TWEAK_LENGTH.
    pub fn derive_key(&self, tweak: &[u8]) -> [u8; 16] {
        debug_assert!(tweak.len() <= Self::MAX_TWEAK_LENGTH);

        let mut block0 = [0u8; BLOCK_LENGTH];
        let mut block1 = [0u8; BLOCK_LENGTH];
        block0[0] = 0x00;
        block1[0] = 0x01;
        block0[1..1 + tweak.len()].copy_from_slice(tweak);
        block1[1..1 + tweak.len()].copy_from_slice(tweak);

        let mut enc0 = Array::from(block0);
        let mut enc1 = Array::from(block1);
        self.ks.encrypt_block(&mut enc0);
        self.ks.encrypt_block(&mut enc1);

        xor_blocks(&enc0.into(), &enc1.into())
    }
}

/// CENC-based Key Derivation Function for AES-256.
///
/// Derives an AES-256 key from a master key and a tweak using CENC construction:
/// K = (E_L(00||T) XOR E_L(01||T)) || (E_L(00||T) XOR E_L(10||T))
pub struct CencKdf256 {
    ks: Aes256,
}

impl CencKdf256 {
    /// Master key length (same as AES-256 key length).
    pub const MASTER_KEY_LENGTH: usize = 32;

    /// Derived key length (same as AES-256 key length).
    pub const KEY_LENGTH: usize = 32;

    /// Maximum tweak length (14 bytes).
    pub const MAX_TWEAK_LENGTH: usize = 14;

    /// Initialize the KDF with a master key.
    pub fn new(master_key: &[u8; 32]) -> Self {
        Self {
            ks: Aes256::new(Array::from_slice(master_key)),
        }
    }

    /// Derive a key from a tweak.
    pub fn derive_key(&self, tweak: &[u8]) -> [u8; 32] {
        debug_assert!(tweak.len() <= Self::MAX_TWEAK_LENGTH);

        let mut block0 = [0u8; BLOCK_LENGTH];
        let mut block1 = [0u8; BLOCK_LENGTH];
        let mut block2 = [0u8; BLOCK_LENGTH];
        block0[0] = 0x00;
        block1[0] = 0x01;
        block2[0] = 0x02;
        block0[1..1 + tweak.len()].copy_from_slice(tweak);
        block1[1..1 + tweak.len()].copy_from_slice(tweak);
        block2[1..1 + tweak.len()].copy_from_slice(tweak);

        let mut enc0 = Array::from(block0);
        let mut enc1 = Array::from(block1);
        let mut enc2 = Array::from(block2);
        self.ks.encrypt_block(&mut enc0);
        self.ks.encrypt_block(&mut enc1);
        self.ks.encrypt_block(&mut enc2);

        let enc0_arr: [u8; 16] = enc0.into();
        let enc1_arr: [u8; 16] = enc1.into();
        let enc2_arr: [u8; 16] = enc2.into();

        let mut derived = [0u8; 32];
        derived[..16].copy_from_slice(&xor_blocks(&enc0_arr, &enc1_arr));
        derived[16..].copy_from_slice(&xor_blocks(&enc0_arr, &enc2_arr));
        derived
    }
}

/// HCTR2-TwKD with AES-128 and CENC KDF.
#[allow(non_camel_case_types)]
pub struct Hctr2TwKD_128 {
    kdf: CencKdf128,
}

impl Hctr2TwKD_128 {
    /// Master key length in bytes.
    pub const KEY_LENGTH: usize = 16;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Maximum tweak length for key derivation.
    pub const MAX_TWEAK_LENGTH: usize = CencKdf128::MAX_TWEAK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR2-TwKD-128 cipher state from a master key.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            kdf: CencKdf128::new(key),
        }
    }

    /// Encrypt plaintext to ciphertext using HCTR2-TwKD.
    ///
    /// The tweak is used for key derivation. Each unique tweak derives a unique
    /// HCTR2 key, providing beyond-birthday-bound security when the same tweak
    /// is not reused excessively (limit: ~2^42 encryptions per tweak).
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(tweak);
        let hctr2 = Hctr2_128::new(&derived_key);
        hctr2.encrypt(plaintext, &[], ciphertext)?;
        Ok(())
    }

    /// Decrypt ciphertext to plaintext using HCTR2-TwKD.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(tweak);
        let hctr2 = Hctr2_128::new(&derived_key);
        hctr2.decrypt(ciphertext, &[], plaintext)?;
        Ok(())
    }

    /// Encrypt with split tweak: part for key derivation, part for HCTR2.
    ///
    /// This allows using a longer tweak by splitting it into:
    /// - `kdf_tweak`: Used for key derivation (max 14 bytes)
    /// - `hctr2_tweak`: Passed to underlying HCTR2 (any length)
    pub fn encrypt_split(
        &self,
        plaintext: &[u8],
        kdf_tweak: &[u8],
        hctr2_tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if kdf_tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_128::new(&derived_key);
        hctr2.encrypt(plaintext, hctr2_tweak, ciphertext)?;
        Ok(())
    }

    /// Decrypt with split tweak.
    pub fn decrypt_split(
        &self,
        ciphertext: &[u8],
        kdf_tweak: &[u8],
        hctr2_tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if kdf_tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_128::new(&derived_key);
        hctr2.decrypt(ciphertext, hctr2_tweak, plaintext)?;
        Ok(())
    }
}

/// HCTR2-TwKD with AES-256 and CENC KDF.
#[allow(non_camel_case_types)]
pub struct Hctr2TwKD_256 {
    kdf: CencKdf256,
}

impl Hctr2TwKD_256 {
    /// Master key length in bytes.
    pub const KEY_LENGTH: usize = 32;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Maximum tweak length for key derivation.
    pub const MAX_TWEAK_LENGTH: usize = CencKdf256::MAX_TWEAK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR2-TwKD-256 cipher state from a master key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            kdf: CencKdf256::new(key),
        }
    }

    /// Encrypt plaintext to ciphertext using HCTR2-TwKD.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(tweak);
        let hctr2 = Hctr2_256::new(&derived_key);
        hctr2.encrypt(plaintext, &[], ciphertext)?;
        Ok(())
    }

    /// Decrypt ciphertext to plaintext using HCTR2-TwKD.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(tweak);
        let hctr2 = Hctr2_256::new(&derived_key);
        hctr2.decrypt(ciphertext, &[], plaintext)?;
        Ok(())
    }

    /// Encrypt with split tweak.
    pub fn encrypt_split(
        &self,
        plaintext: &[u8],
        kdf_tweak: &[u8],
        hctr2_tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if kdf_tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_256::new(&derived_key);
        hctr2.encrypt(plaintext, hctr2_tweak, ciphertext)?;
        Ok(())
    }

    /// Decrypt with split tweak.
    pub fn decrypt_split(
        &self,
        ciphertext: &[u8],
        kdf_tweak: &[u8],
        hctr2_tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if kdf_tweak.len() > Self::MAX_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_256::new(&derived_key);
        hctr2.decrypt(ciphertext, hctr2_tweak, plaintext)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hctr2_twkd_128_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr2TwKD_128::new(&key);

        let plaintext = b"Hello, HCTR2-TwKD!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2_twkd_128_roundtrip_nonzero_key() {
        let key: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);
        let cipher = Hctr2TwKD_128::new(&key);

        let plaintext = b"Hello, HCTR2-TwKD!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2_twkd_128_minimum_length() {
        let key = [0u8; 16];
        let cipher = Hctr2TwKD_128::new(&key);

        let plaintext = [0x42u8; 16];
        let mut ciphertext = [0u8; 16];
        let mut decrypted = [0u8; 16];

        cipher
            .encrypt(&plaintext, b"tweak", &mut ciphertext)
            .unwrap();
        cipher
            .decrypt(&ciphertext, b"tweak", &mut decrypted)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2_twkd_128_input_too_short() {
        let key = [0u8; 16];
        let cipher = Hctr2TwKD_128::new(&key);

        let plaintext = [0x42u8; 15];
        let mut ciphertext = [0u8; 15];

        assert_eq!(
            cipher.encrypt(&plaintext, b"tweak", &mut ciphertext),
            Err(Error::InputTooShort)
        );
    }

    #[test]
    fn test_hctr2_twkd_128_tweak_too_long() {
        let key = [0u8; 16];
        let cipher = Hctr2TwKD_128::new(&key);

        let plaintext = [0x42u8; 16];
        let mut ciphertext = [0u8; 16];

        let long_tweak = [0u8; 15];
        assert_eq!(
            cipher.encrypt(&plaintext, &long_tweak, &mut ciphertext),
            Err(Error::TweakTooLong)
        );
    }

    #[test]
    fn test_hctr2_twkd_128_different_tweaks() {
        let key = [0u8; 16];
        let cipher = Hctr2TwKD_128::new(&key);

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
    fn test_hctr2_twkd_128_split_tweak() {
        let key = [0u8; 16];
        let cipher = Hctr2TwKD_128::new(&key);

        let plaintext = b"Test split tweak mode";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let kdf_tweak = b"kdf part";
        let hctr2_tweak = b"hctr2 part - can be longer than 14 bytes!";

        cipher
            .encrypt_split(plaintext, kdf_tweak, hctr2_tweak, &mut ciphertext)
            .unwrap();
        cipher
            .decrypt_split(&ciphertext, kdf_tweak, hctr2_tweak, &mut decrypted)
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2_twkd_128_large_message() {
        let key = [0u8; 16];
        let cipher = Hctr2TwKD_128::new(&key);

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
    fn test_hctr2_twkd_256_roundtrip() {
        let key = [0u8; 32];
        let cipher = Hctr2TwKD_256::new(&key);

        let plaintext = b"Hello, HCTR2-TwKD-256!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_cenc_kdf_128_different_tweaks() {
        let master_key = [0u8; 16];
        let kdf = CencKdf128::new(&master_key);

        let key1 = kdf.derive_key(b"tweak1");
        let key2 = kdf.derive_key(b"tweak2");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cenc_kdf_128_deterministic() {
        let master_key = [0u8; 16];
        let kdf = CencKdf128::new(&master_key);

        let key1 = kdf.derive_key(b"same tweak");
        let key2 = kdf.derive_key(b"same tweak");

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cenc_kdf_256_key_derivation() {
        let master_key = [0u8; 32];
        let kdf = CencKdf256::new(&master_key);

        let key = kdf.derive_key(b"test");
        assert_eq!(key.len(), 32);

        let key2 = kdf.derive_key(b"test2");
        assert_ne!(key, key2);
    }
}
