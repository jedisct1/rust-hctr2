#![allow(deprecated)]
//! CACH-CHCTR2: CHCTR2 with a key-committing authentication tag.
//!
//! From "More Keys, Less Commitment: Key-Committing Attacks on BBB Accordions via Encode-then-Encipher and a Key-Committing Transform".
//!
//! It needs a single AES key.
//! Nobody can find a ciphertext and a tag that are valid under two different keys.
//! A tag of `TAG_LEN` bytes gives about `4 * TAG_LEN` bits of key-committing security.
//!
//! Put the nonce and the associated data in the tweak, with an unambiguous encoding.
//! Reusing a tweak only reveals whether two messages are equal.
//!
//! Messages must be at least 32 bytes long.
//! Each message costs one CHCTR2 call, five AES calls and one AES key schedule.

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherEncrypt};
use aes::{Aes128, Aes256};

use crate::chctr2::Chctr2;
use crate::common::{BLOCK_LENGTH, Error, xor_blocks};
use crate::hctr2::AesCipher;

/// Generic CACH-CHCTR2 cipher, parameterized by AES key size and tag length.
///
/// `TAG_LEN` can be anything from 16 to 32.
pub struct CachChctr2<Aes: AesCipher, const TAG_LEN: usize> {
    ks_enc: Aes,
    accordion: Chctr2<Aes>,
}

/// CACH-CHCTR2 with AES-128 and a 32-byte tag.
#[allow(non_camel_case_types)]
pub type CachChctr2_128 = CachChctr2<Aes128, 32>;

/// CACH-CHCTR2 with AES-256 and a 32-byte tag.
#[allow(non_camel_case_types)]
pub type CachChctr2_256 = CachChctr2<Aes256, 32>;

impl<Aes: AesCipher, const TAG_LEN: usize> CachChctr2<Aes, TAG_LEN> {
    /// Key length in bytes (a single AES key).
    pub const KEY_LENGTH: usize = Aes::KEY_LEN;

    /// Authentication tag length in bytes.
    pub const TAG_LENGTH: usize = TAG_LEN;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = 2 * BLOCK_LENGTH;

    /// Initialize the cipher from a single AES key.
    pub fn new(key: &[u8]) -> Self {
        const { assert!(TAG_LEN >= BLOCK_LENGTH && TAG_LEN <= 2 * BLOCK_LENGTH) };
        debug_assert_eq!(key.len(), Aes::KEY_LEN);

        let ks_enc = Aes::new(Array::from_slice(key));

        // The two low bits stay at zero, so these blocks never match the ones the tag encrypts.
        let mut derived = [[0u8; BLOCK_LENGTH]; 4];
        let derived = &mut derived[..2 * Aes::KEY_LEN / BLOCK_LENGTH];
        for (block, i) in derived.iter_mut().zip(0u128..) {
            *block = (i << 2).to_be_bytes();
        }
        encrypt_in_place(&ks_enc, derived);
        let (key1, key2) = derived.as_flattened().split_at(Aes::KEY_LEN);

        Self {
            ks_enc,
            accordion: Chctr2::new_split(key1, key2),
        }
    }

    /// Encrypt `plaintext` into `ciphertext` and return the tag.
    ///
    /// Returns `Error::InputTooShort` if the message is shorter than `MIN_INPUT_LENGTH`.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        if plaintext.len() < Self::MIN_INPUT_LENGTH {
            return Err(Error::InputTooShort);
        }
        self.accordion.encrypt(plaintext, tweak, ciphertext)?;
        Ok(self.compute_tag(plaintext, ciphertext))
    }

    /// Decrypt `ciphertext` into `plaintext` and verify the tag.
    ///
    /// Returns `Error::InputTooShort` if the message is shorter than `MIN_INPUT_LENGTH`.
    /// Returns `Error::AuthenticationFailed` if the tag is wrong, and clears `plaintext`.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if ciphertext.len() < Self::MIN_INPUT_LENGTH {
            return Err(Error::InputTooShort);
        }
        self.accordion.decrypt(ciphertext, tweak, plaintext)?;
        if !ct_codecs::verify(&self.compute_tag(plaintext, ciphertext), tag) {
            plaintext.fill(0);
            return Err(Error::AuthenticationFailed);
        }
        Ok(())
    }

    /// The tag only covers the first 32 bytes of plaintext XOR ciphertext.
    /// That is enough, because CHCTR2 spreads any change over the whole message.
    fn compute_tag(&self, plaintext: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
        let mut s = [[0u8; BLOCK_LENGTH]; 2];
        for ((byte, p), c) in s
            .as_flattened_mut()
            .iter_mut()
            .zip(plaintext)
            .zip(ciphertext)
        {
            *byte = p ^ c;
        }
        self.ceth(s)
    }

    /// CEtH from the paper, a collision-resistant PRF that turns `s` into the tag.
    ///
    /// The second half of `s` picks a one-time key.
    /// The first half is hashed under that key.
    /// The paper uses a few low bits of each half for domain separation, so these bits don't change the tag.
    fn ceth(&self, [s1, s2]: [[u8; BLOCK_LENGTH]; 2]) -> [u8; TAG_LEN] {
        let mut cenc = [s2; 3];
        for (block, domain) in cenc.iter_mut().zip(1u8..) {
            block[BLOCK_LENGTH - 1] = (block[BLOCK_LENGTH - 1] & 0xfc) | domain;
        }
        encrypt_in_place(&self.ks_enc, &mut cenc);
        let key_material = [
            xor_blocks(&cenc[0], &cenc[1]),
            xor_blocks(&cenc[0], &cenc[2]),
        ];
        let (hirose_key, leftover) = key_material.as_flattened().split_at(Aes::KEY_LEN);

        let mut x = [s1; 2];
        x[0][BLOCK_LENGTH - 1] &= 0xf8;
        x[1][BLOCK_LENGTH - 1] = (x[1][BLOCK_LENGTH - 1] & 0xf8) | 0x04;

        let mut z = x;
        encrypt_in_place(&Aes::new(Array::from_slice(hirose_key)), &mut z);
        let mut tag = [xor_blocks(&z[0], &x[0]), xor_blocks(&z[1], &x[1])];

        // With AES-128, the Hirose key only needs half of `key_material`.
        // The other half goes into the tag.
        for (byte, l) in tag[0].iter_mut().zip(leftover) {
            *byte ^= l;
        }

        tag.as_flattened()[..TAG_LEN].try_into().unwrap()
    }
}

fn encrypt_in_place(ks: &impl BlockCipherEncrypt, blocks: &mut [[u8; BLOCK_LENGTH]]) {
    for block in blocks {
        let mut encrypted = Array::clone_from_slice(block);
        ks.encrypt_block(&mut encrypted);
        block.copy_from_slice(&encrypted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Decoder, Hex};

    fn sequence(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    fn assert_vector<Aes: AesCipher, const TAG_LEN: usize>(
        cipher: &CachChctr2<Aes, TAG_LEN>,
        tweak: &[u8],
        ciphertext_hex: &str,
        tag_hex: &str,
    ) {
        let expected = Hex::decode_to_vec(ciphertext_hex, None).unwrap();
        let expected_tag = Hex::decode_to_vec(tag_hex, None).unwrap();
        let message = sequence(expected.len());
        let mut output = vec![0u8; message.len()];

        let tag = cipher.encrypt(&message, tweak, &mut output).unwrap();
        assert_eq!(expected, output);
        assert_eq!(expected_tag, tag);

        let mut decrypted = vec![0u8; message.len()];
        cipher
            .decrypt(&output, &tag, tweak, &mut decrypted)
            .unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_cach_chctr2_known_answers() {
        // Same vectors as zig-hctr2, checked against an independent Python implementation.
        let cipher128 = CachChctr2_128::new(&sequence(16));
        let cipher256 = CachChctr2_256::new(&sequence(32));
        let cipher256_short_tag = CachChctr2::<Aes256, 16>::new(&sequence(32));

        assert_vector(
            &cipher128,
            b"",
            "c9b34805f981180bb490278842f7abfafaf1f46bd3b56e34d97366f2d1b87586",
            "d189ce8a553521bc68fcad4095f84110429fdd1b5b0e1ad774ae1dca727dc434",
        );
        assert_vector(
            &cipher128,
            b"tweak",
            "0238a7b0151adb2436551a6c1551ed1a6a636c68aca6f8415777c3c8a190a2fbe2",
            "4faa7c99980f97120a4dd9422c4c50df9818fc0664aa6a8a522773817a342390",
        );
        assert_vector(
            &cipher256,
            b"tweak",
            "ad9c7c3b3a7c0b925c4534c4aae7e0e15db44fdd881eeac825608e6bfc5c6cd7494e00599e31597a529a93ecfe9e2316",
            "592df8fae784ff1312e230b6c3101877c9b91bb4fc418e53908b8905f28c924c",
        );
        // A 16-byte tag is the first half of the 32-byte tag.
        assert_vector(
            &cipher256_short_tag,
            b"tweak",
            "ad9c7c3b3a7c0b925c4534c4aae7e0e15db44fdd881eeac825608e6bfc5c6cd7494e00599e31597a529a93ecfe9e2316",
            "592df8fae784ff1312e230b6c3101877",
        );
        assert_vector(
            &cipher256,
            b"a tweak longer than one block",
            "64b1a9d9db813b15d88341051d3df82e02d436b66d2d408fb106812ac9607e191da3c2e0b70309280161db99197ff5aa5c985ad5fb1c288f57707ba94864d6978cd7df4e9e3b7159112fd80aefebdf5ba3f0efaccf385c0cb3198fef3171871f018b631b",
            "eb9c0b19138952d1a3e08bc789d6fd97abd2081b8a672e36a930f0630d3d7b44",
        );
    }

    fn assert_rejects_forgeries<Aes: AesCipher, const TAG_LEN: usize>() {
        let cipher = CachChctr2::<Aes, TAG_LEN>::new(&sequence(Aes::KEY_LEN));
        let mut ciphertext = [0u8; 48];
        let tag = cipher
            .encrypt(&sequence(48), b"tweak", &mut ciphertext)
            .unwrap();
        let mut output = [0xffu8; 48];

        let mut bad_tag = tag;
        bad_tag[TAG_LEN - 1] ^= 1;
        assert_eq!(
            cipher.decrypt(&ciphertext, &bad_tag, b"tweak", &mut output),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(output, [0u8; 48]);

        assert_eq!(
            cipher.decrypt(&ciphertext, &tag, b"tweaj", &mut output),
            Err(Error::AuthenticationFailed)
        );

        // The last byte doesn't go into the tag directly, but a change must still be detected.
        let mut bad_ciphertext = ciphertext;
        bad_ciphertext[bad_ciphertext.len() - 1] ^= 1;
        assert_eq!(
            cipher.decrypt(&bad_ciphertext, &tag, b"tweak", &mut output),
            Err(Error::AuthenticationFailed)
        );

        let other = CachChctr2::<Aes, TAG_LEN>::new(&vec![0u8; Aes::KEY_LEN]);
        assert_eq!(
            other.decrypt(&ciphertext, &tag, b"tweak", &mut output),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn test_cach_chctr2_rejects_forgeries() {
        assert_rejects_forgeries::<Aes128, 32>();
        assert_rejects_forgeries::<Aes256, 16>();
    }

    #[test]
    fn test_cach_chctr2_rejects_short_input() {
        let cipher = CachChctr2_128::new(&[0u8; 16]);
        let input = [0x42u8; CachChctr2_128::MIN_INPUT_LENGTH - 1];
        let mut output = [0u8; CachChctr2_128::MIN_INPUT_LENGTH - 1];

        assert_eq!(
            cipher.encrypt(&input, b"", &mut output),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            cipher.decrypt(&input, &[0u8; 32], b"", &mut output),
            Err(Error::InputTooShort)
        );
    }
}
