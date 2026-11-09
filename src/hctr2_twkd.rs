#![allow(deprecated)]
//! HCTR2-TwKD: a length-preserving wide-block tweakable cipher that derives its HCTR2 key from the tweak.
//!
//! The first part of the tweak, T0, picks the HCTR2 key through a KDF.
//! The rest, T*, goes to a regular HCTR2.
//! From "Beyond-Birthday-Bound Security with HCTR2", ASIACRYPT 2025.
//!
//! Each block costs the same as HCTR2, plus one key derivation per message.
//!
//! You get about 85 bits of multi-user security as long as each user processes at most about 2^42 blocks with the same T0.
//! Tweak blocks and decryption count too.
//! Changing only T* does not help, because it does not affect the key.

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use crate::common::{BLOCK_LENGTH, Error, xor_blocks};
use crate::hctr2::{Hctr2_128, Hctr2_256};

// Keep the old error type as an alias for backwards compatibility
#[allow(non_camel_case_types)]
#[deprecated(note = "Use common::Error instead")]
pub type Hctr2TwKDError = Error;

/// CENC key derivation for AES-128.
///
/// Turns a master key and a 126-bit tweak T into an AES-128 key:
/// K = E_L(00||T) XOR E_L(01||T)
///
/// The paper only defines the AES-256 version.
/// This one is our own: same idea, using AES-128 and deriving 16 bytes instead of 32.
///
/// T is stored in 16 bytes, and the top two bits of the first byte must be zero.
/// Those two bits are where the 00/01/10 prefix goes.
pub struct CencKdf128 {
    ks: Aes128,
}

impl CencKdf128 {
    /// Master key length (same as AES-128 key length).
    pub const MASTER_KEY_LENGTH: usize = 16;

    /// Derived key length (same as AES-128 key length).
    pub const KEY_LENGTH: usize = 16;

    /// Tweak length in bytes (126 bits packed into 16 bytes).
    pub const TWEAK_LENGTH: usize = 16;

    /// Tweak bits (126 bits, top 2 bits of first byte must be zero).
    pub const TWEAK_BITS: usize = 126;

    /// Initialize the KDF with a master key.
    pub fn new(master_key: &[u8; 16]) -> Self {
        Self {
            ks: Aes128::new(Array::from_slice(master_key)),
        }
    }

    /// Derive a key from a tweak.
    ///
    /// # Panics
    /// Panics if tweak is not valid (use `validate_tweak` to check).
    pub fn derive_key(&self, tweak: &[u8]) -> [u8; 16] {
        debug_assert!(Self::validate_tweak(tweak));

        let block0 = Self::make_block(tweak, 0);
        let block1 = Self::make_block(tweak, 1);

        let mut enc0 = Array::from(block0);
        let mut enc1 = Array::from(block1);
        self.ks.encrypt_block(&mut enc0);
        self.ks.encrypt_block(&mut enc1);

        xor_blocks(&enc0.into(), &enc1.into())
    }

    /// Validate that a tweak has the correct format.
    ///
    /// Returns true if the tweak is exactly 16 bytes and the top 2 bits of
    /// the first byte are zero.
    pub fn validate_tweak(tweak: &[u8]) -> bool {
        tweak.len() == Self::TWEAK_LENGTH && (tweak[0] & 0xC0) == 0
    }

    /// Create a block from a tweak with the given prefix (0, 1, or 2).
    fn make_block(tweak: &[u8], prefix: u8) -> [u8; BLOCK_LENGTH] {
        debug_assert!(prefix <= 2);
        let mut block = [0u8; BLOCK_LENGTH];
        block.copy_from_slice(tweak);
        block[0] = (block[0] & 0x3F) | (prefix << 6);
        block
    }
}

/// CENC key derivation for AES-256.
///
/// Turns a master key and a 126-bit tweak T into an AES-256 key:
/// K = (E_L(00||T) XOR E_L(01||T)) || (E_L(00||T) XOR E_L(10||T))
///
/// T is stored in 16 bytes, and the top two bits of the first byte must be zero.
/// Those two bits are where the 00/01/10 prefix goes.
pub struct CencKdf256 {
    ks: Aes256,
}

impl CencKdf256 {
    /// Master key length (same as AES-256 key length).
    pub const MASTER_KEY_LENGTH: usize = 32;

    /// Derived key length (same as AES-256 key length).
    pub const KEY_LENGTH: usize = 32;

    /// Tweak length in bytes (126 bits packed into 16 bytes).
    pub const TWEAK_LENGTH: usize = 16;

    /// Tweak bits (126 bits, top 2 bits of first byte must be zero).
    pub const TWEAK_BITS: usize = 126;

    /// Initialize the KDF with a master key.
    pub fn new(master_key: &[u8; 32]) -> Self {
        Self {
            ks: Aes256::new(Array::from_slice(master_key)),
        }
    }

    /// Derive a key from a tweak.
    ///
    /// # Panics
    /// Panics if tweak is not valid (use `validate_tweak` to check).
    pub fn derive_key(&self, tweak: &[u8]) -> [u8; 32] {
        debug_assert!(Self::validate_tweak(tweak));

        let block0 = Self::make_block(tweak, 0);
        let block1 = Self::make_block(tweak, 1);
        let block2 = Self::make_block(tweak, 2);

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

    /// Validate that a tweak has the correct format.
    ///
    /// Returns true if the tweak is exactly 16 bytes and the top 2 bits of
    /// the first byte are zero.
    pub fn validate_tweak(tweak: &[u8]) -> bool {
        tweak.len() == Self::TWEAK_LENGTH && (tweak[0] & 0xC0) == 0
    }

    /// Create a block from a tweak with the given prefix (0, 1, or 2).
    fn make_block(tweak: &[u8], prefix: u8) -> [u8; BLOCK_LENGTH] {
        debug_assert!(prefix <= 2);
        let mut block = [0u8; BLOCK_LENGTH];
        block.copy_from_slice(tweak);
        block[0] = (block[0] & 0x3F) | (prefix << 6);
        block
    }
}

/// HCTR2-TwKD with AES-128 and CENC KDF.
///
/// Every new T0 is one more AES-128 key an attacker can go after.
/// Use the AES-256 version if you expect more than about 2^43 different T0 values.
#[allow(non_camel_case_types)]
pub struct Hctr2TwKD_128 {
    kdf: CencKdf128,
}

impl Hctr2TwKD_128 {
    /// Master key length in bytes.
    pub const KEY_LENGTH: usize = 16;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// How many bytes at the start of the tweak go to the KDF.
    pub const KDF_TWEAK_LENGTH: usize = CencKdf128::TWEAK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR2-TwKD-128 cipher state from a master key.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            kdf: CencKdf128::new(key),
        }
    }

    /// Encrypts `plaintext` with `tweak` into `ciphertext`.
    ///
    /// The first `KDF_TWEAK_LENGTH` bytes of the tweak are T0, which picks the key.
    /// The rest is T*, which goes to HCTR2.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }

        let kdf_tweak = &tweak[..Self::KDF_TWEAK_LENGTH];
        if !CencKdf128::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_128::new(&derived_key);
        hctr2.encrypt(plaintext, &tweak[Self::KDF_TWEAK_LENGTH..], ciphertext)?;
        Ok(())
    }

    /// Decrypt ciphertext to plaintext using HCTR2-TwKD.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }

        let kdf_tweak = &tweak[..Self::KDF_TWEAK_LENGTH];
        if !CencKdf128::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_128::new(&derived_key);
        hctr2.decrypt(ciphertext, &tweak[Self::KDF_TWEAK_LENGTH..], plaintext)?;
        Ok(())
    }

    /// Encrypt with split tweak: part for key derivation, part for HCTR2.
    ///
    /// This allows finer control over the tweak split:
    /// - `kdf_tweak`: Used for key derivation (must be exactly `KDF_TWEAK_LENGTH` bytes)
    /// - `hctr2_tweak`: Passed to underlying HCTR2 (any length)
    pub fn encrypt_split(
        &self,
        plaintext: &[u8],
        kdf_tweak: &[u8],
        hctr2_tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if kdf_tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }
        if kdf_tweak.len() > Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }
        if !CencKdf128::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
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
        if kdf_tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }
        if kdf_tweak.len() > Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }
        if !CencKdf128::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
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

    /// How many bytes at the start of the tweak go to the KDF.
    pub const KDF_TWEAK_LENGTH: usize = CencKdf256::TWEAK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR2-TwKD-256 cipher state from a master key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            kdf: CencKdf256::new(key),
        }
    }

    /// Encrypts `plaintext` with `tweak` into `ciphertext`.
    ///
    /// The first `KDF_TWEAK_LENGTH` bytes of the tweak are T0, which picks the key.
    /// The rest is T*, which goes to HCTR2.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }

        let kdf_tweak = &tweak[..Self::KDF_TWEAK_LENGTH];
        if !CencKdf256::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_256::new(&derived_key);
        hctr2.encrypt(plaintext, &tweak[Self::KDF_TWEAK_LENGTH..], ciphertext)?;
        Ok(())
    }

    /// Decrypt ciphertext to plaintext using HCTR2-TwKD.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }

        let kdf_tweak = &tweak[..Self::KDF_TWEAK_LENGTH];
        if !CencKdf256::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
        }

        let derived_key = self.kdf.derive_key(kdf_tweak);
        let hctr2 = Hctr2_256::new(&derived_key);
        hctr2.decrypt(ciphertext, &tweak[Self::KDF_TWEAK_LENGTH..], plaintext)?;
        Ok(())
    }

    /// Encrypt with split tweak.
    ///
    /// - `kdf_tweak`: Used for key derivation (must be exactly `KDF_TWEAK_LENGTH` bytes)
    /// - `hctr2_tweak`: Passed to underlying HCTR2 (any length)
    pub fn encrypt_split(
        &self,
        plaintext: &[u8],
        kdf_tweak: &[u8],
        hctr2_tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if kdf_tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }
        if kdf_tweak.len() > Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }
        if !CencKdf256::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
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
        if kdf_tweak.len() < Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooShort);
        }
        if kdf_tweak.len() > Self::KDF_TWEAK_LENGTH {
            return Err(Error::TweakTooLong);
        }
        if !CencKdf256::validate_tweak(kdf_tweak) {
            return Err(Error::InvalidTweak);
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
    use ct_codecs::{Decoder, Hex};

    fn sequence(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    macro_rules! assert_ciphertext {
        ($cipher:expr, $tweak:expr, $hex:expr) => {{
            let tweak: &[u8] = $tweak;
            let (t0, t_star) = tweak.split_at(16);
            let expected = Hex::decode_to_vec($hex, None).unwrap();
            let message = sequence(expected.len());
            let mut output = vec![0u8; expected.len()];

            $cipher.encrypt(&message, tweak, &mut output).unwrap();
            assert_eq!(expected, output);
            $cipher.decrypt(&expected, tweak, &mut output).unwrap();
            assert_eq!(message, output);

            $cipher
                .encrypt_split(&message, t0, t_star, &mut output)
                .unwrap();
            assert_eq!(expected, output);
            $cipher
                .decrypt_split(&expected, t0, t_star, &mut output)
                .unwrap();
            assert_eq!(message, output);
        }};
    }

    #[test]
    fn test_hctr2_twkd_known_answers() {
        // Expected values were computed separately, following the paper.
        let cipher128 = Hctr2TwKD_128::new(&core::array::from_fn(|i| i as u8));
        let cipher256 = Hctr2TwKD_256::new(&core::array::from_fn(|i| i as u8));

        let mut tweak128 = sequence(20);
        tweak128[0] = 0x3f;
        let mut tweak256 = [sequence(16), b"tail".to_vec()].concat();
        tweak256[0] = 0x2a;

        assert_ciphertext!(cipher128, &sequence(16), "69549f31b5a2e330c55a60989743ba99");
        assert_ciphertext!(
            cipher128,
            &tweak128,
            "510ef09ca748a7405eaaad65d1e6cf90d0ab39236a40034bc0c4feb4cc611ede17"
        );
        assert_ciphertext!(cipher256, &sequence(16), "c397e7293e00d50bcaaec448b0c247a1");
        assert_ciphertext!(
            cipher256,
            &tweak256,
            "4c8bfd522e0a059151ec81b8f341d2d9801446375cb59b25a195c1c55298c9e7b7e709538c33e9586b52f0fdbfa986b436148dc68c1017d2529627f684fbf9b5a3"
        );
    }

    #[test]
    fn test_hctr2_twkd_rejects_bad_input_and_tweaks() {
        let cipher = Hctr2TwKD_128::new(&[0u8; 16]);
        let input = [0x42u8; 16];
        let tweak = [0u8; 17];
        let mut output = [0u8; 16];
        let mut bad_tweak = tweak;
        bad_tweak[0] = 0xc0;

        assert_eq!(
            cipher.encrypt(&input[..15], &tweak[..16], &mut output[..15]),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            cipher.encrypt(&input, &tweak[..8], &mut output),
            Err(Error::TweakTooShort)
        );
        assert_eq!(
            cipher.encrypt_split(&input, &tweak, b"", &mut output),
            Err(Error::TweakTooLong)
        );
        assert_eq!(
            cipher.encrypt(&input, &bad_tweak, &mut output),
            Err(Error::InvalidTweak)
        );
    }
}
