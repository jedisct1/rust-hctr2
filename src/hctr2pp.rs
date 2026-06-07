#![allow(deprecated)]
//! HCTR2++ (HCTR++) beyond-birthday-bound secure variant of HCTR2.
//!
//! HCTR2++ is the construction from "HCTR++: A Beyond Birthday Bound Secure HCTR2
//! Variant" by Ozturk, Kocak and Yayla. It keeps the Hash-Encrypt-Hash structure of
//! HCTR2 but replaces every static block cipher call with Mennink's R3 fresh re-keying
//! scheme and widens the universal hash function from n bits to 2n bits. The result is
//! O(2^n) SPRP security with unique tweaks, degrading gracefully with tweak reuse,
//! while still being built from a plain block cipher (AES).
//!
//! Construction (Figure 4 of the paper):
//! - Subkeys h1, h2 (2n-bit hash keys) and K (2n-bit re-keying key) are derived from
//!   the master key as E_K(bin(1))||E_K(bin(2)), E_K(bin(3))||E_K(bin(4)) and
//!   E_K(bin(5))||E_K(bin(6))
//! - The first block is masked with the top half of a 2n-bit hash of the bulk and the
//!   tweak, then encrypted under an R3-derived ephemeral key; the bottom half of the
//!   hash seeds the re-keying nonce
//! - The internal state r||J is the 2n-bit hash of CC and the tweak under h1 XOR h2
//! - CTR++ generates the keystream with a fresh R3-derived key per block
//! - The first output block goes through an inverse block cipher call so that the
//!   ciphertext depends on the complete hash digest, and encryption and decryption
//!   share the same code path with h1 and h2 swapped
//!
//! The 2n-bit hash is instantiated as a POLYVAL-style polynomial evaluation over
//! GF(2^256). Blocks are 32 bytes interpreted as little-endian polynomials, and the
//! field is defined by the irreducible pentanomial x^256 + x^10 + x^5 + x^2 + 1. The
//! input encoding mirrors the HCTR2 hash: a length block encoding 2*|T| + 2 (or + 3
//! when the message is not block-aligned), the zero-padded tweak, then the message
//! padded with a single 1 bit and zeros.
//!
//! Security properties:
//! - Beyond-birthday-bound SPRP security, approaching O(2^n) with unique tweaks
//! - Security degrades with the number of queries sharing the same tweak
//! - Ciphertext length equals plaintext length (no expansion)
//! - No authentication - consider AEAD if integrity protection is needed
//! - Minimum message length: 16 bytes (one AES block)
//!
//! The re-keying makes this mode noticeably slower than HCTR2: every message block
//! costs one AES key schedule, one AES call and two GF(2^256) multiplications.

#[allow(deprecated)]
use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use core::marker::PhantomData;

use crate::common::{BLOCK_LENGTH, Direction, Error, xor_blocks};
use crate::hctr2::AesCipher;

/// Hash block length in bytes (2n bits with n = 128).
pub const HASH_BLOCK_LENGTH: usize = 32;

type Elem = [u64; 4];

/// Carryless 64x64 -> 128 bit multiplication.
///
/// Uses the masked-multiplication technique (as in BearSSL's ghash_ctmul64) so the
/// running time does not depend on the operand values.
#[inline]
fn bmul64(x: u64, y: u64) -> u128 {
    const M0: u128 = 0x1111_1111_1111_1111_1111_1111_1111_1111;
    const M1: u128 = M0 << 1;
    const M2: u128 = M0 << 2;
    const M3: u128 = M0 << 3;

    let x0 = (x as u128) & M0;
    let x1 = (x as u128) & M1;
    let x2 = (x as u128) & M2;
    let x3 = (x as u128) & M3;
    let y0 = (y as u128) & M0;
    let y1 = (y as u128) & M1;
    let y2 = (y as u128) & M2;
    let y3 = (y as u128) & M3;

    let z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    let z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    let z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    let z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// Multiplication in GF(2^256) defined by x^256 + x^10 + x^5 + x^2 + 1.
///
/// Elements are little-endian: bit i of limb j is the coefficient of x^(64j + i).
fn gf_mul(a: &Elem, b: &Elem) -> Elem {
    let mut t = [0u64; 8];
    for i in 0..4 {
        for j in 0..4 {
            let p = bmul64(a[i], b[j]);
            t[i + j] ^= p as u64;
            t[i + j + 1] ^= (p >> 64) as u64;
        }
    }

    // Fold the upper 256 bits using x^256 = x^10 + x^5 + x^2 + 1.
    let hi = [t[4], t[5], t[6], t[7]];
    let mut res = [t[0], t[1], t[2], t[3]];
    let mut overflow: u64 = 0;
    for k in 0..4 {
        res[k] ^= hi[k];
    }
    for s in [2u32, 5, 10] {
        let mut prev: u64 = 0;
        for k in 0..4 {
            res[k] ^= (hi[k] << s) | (prev >> (64 - s));
            prev = hi[k];
        }
        overflow ^= hi[3] >> (64 - s);
    }
    // overflow < 2^10, so the second fold stays within the first limb.
    res[0] ^= overflow ^ (overflow << 2) ^ (overflow << 5) ^ (overflow << 10);
    res
}

#[inline]
fn elem_from_bytes(bytes: &[u8; HASH_BLOCK_LENGTH]) -> Elem {
    let mut e = [0u64; 4];
    for (i, limb) in e.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    e
}

#[inline]
fn elem_to_bytes(e: &Elem) -> [u8; HASH_BLOCK_LENGTH] {
    let mut bytes = [0u8; HASH_BLOCK_LENGTH];
    for (i, limb) in e.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

#[inline]
fn elem_xor(a: &Elem, b: &Elem) -> Elem {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

/// 2n-bit POLYVAL-style universal hash over GF(2^256).
///
/// Computes sum X_i * h^(l-i+1) by Horner evaluation, with the HCTR2 input encoding:
/// a length block, the zero-padded tweak, and the message padded with 1 || 0*.
fn hash2n(key: &Elem, tweak: &[u8], msg: &[u8]) -> [u8; HASH_BLOCK_LENGTH] {
    let tweak_len_bits = tweak.len() * 8;
    let len_code: u128 = if msg.len().is_multiple_of(HASH_BLOCK_LENGTH) {
        (2 * tweak_len_bits + 2) as u128
    } else {
        (2 * tweak_len_bits + 3) as u128
    };
    let mut len_block = [0u8; HASH_BLOCK_LENGTH];
    len_block[..16].copy_from_slice(&len_code.to_le_bytes());

    let mut acc = [0u64; 4];
    let mut update = |block: &[u8; HASH_BLOCK_LENGTH]| {
        acc = gf_mul(&elem_xor(&acc, &elem_from_bytes(block)), key);
    };

    update(&len_block);

    let mut chunks = tweak.chunks_exact(HASH_BLOCK_LENGTH);
    for chunk in chunks.by_ref() {
        update(chunk.try_into().unwrap());
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; HASH_BLOCK_LENGTH];
        block[..rem.len()].copy_from_slice(rem);
        update(&block);
    }

    let mut chunks = msg.chunks_exact(HASH_BLOCK_LENGTH);
    for chunk in chunks.by_ref() {
        update(chunk.try_into().unwrap());
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; HASH_BLOCK_LENGTH];
        block[..rem.len()].copy_from_slice(rem);
        block[rem.len()] = 1;
        update(&block);
    }

    elem_to_bytes(&acc)
}

/// Generic HCTR2++ cipher parameterized by the master AES key size.
///
/// The master cipher is only used to derive the hash and re-keying subkeys. The
/// re-keyed block cipher calls always use AES-128, since the R3 scheme produces n-bit
/// ephemeral keys; the effective key strength is therefore 128 bits regardless of the
/// master key size.
pub struct Hctr2pp<Aes: AesCipher> {
    h1: Elem,
    h2: Elem,
    h12: Elem,
    kk: Elem,
    _aes: PhantomData<Aes>,
}

/// HCTR2++ with an AES-128 master key.
#[allow(non_camel_case_types)]
pub type Hctr2pp_128 = Hctr2pp<Aes128>;

/// HCTR2++ with an AES-256 master key.
///
/// AES-256 is used only to derive the hash and re-keying subkeys from the master
/// key. The R3 re-keyed block cipher calls are always AES-128, because the R3
/// scheme produces n-bit ephemeral keys, so this variant does NOT provide
/// 256-bit security: the effective primitive strength is 128 bits, exactly as
/// with [`Hctr2pp_128`]. Choose it only when key management mandates a 256-bit
/// master key.
#[allow(non_camel_case_types)]
pub type Hctr2pp_256 = Hctr2pp<aes::Aes256>;

impl<Aes: AesCipher> Hctr2pp<Aes> {
    /// Master key length in bytes.
    pub const KEY_LENGTH: usize = Aes::KEY_LEN;

    /// AES block length in bytes (always 16).
    pub const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = BLOCK_LENGTH;

    /// Initialize HCTR2++ cipher state from a master key.
    pub fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), Aes::KEY_LEN);

        let ks = Aes::new(Array::from_slice(key));
        let mut subkeys = [[0u8; BLOCK_LENGTH]; 6];
        for (i, subkey) in subkeys.iter_mut().enumerate() {
            let mut block = [0u8; BLOCK_LENGTH];
            block[0] = (i + 1) as u8;
            let mut arr = Array::clone_from_slice(&block);
            ks.encrypt_block(&mut arr);
            *subkey = arr.as_slice().try_into().unwrap();
        }

        let pair = |a: &[u8; 16], b: &[u8; 16]| {
            let mut bytes = [0u8; HASH_BLOCK_LENGTH];
            bytes[..16].copy_from_slice(a);
            bytes[16..].copy_from_slice(b);
            elem_from_bytes(&bytes)
        };
        let h1 = pair(&subkeys[0], &subkeys[1]);
        let h2 = pair(&subkeys[2], &subkeys[3]);
        let kk = pair(&subkeys[4], &subkeys[5]);

        Self {
            h1,
            h2,
            h12: elem_xor(&h1, &h2),
            kk,
            _aes: PhantomData,
        }
    }

    /// Encrypt plaintext to ciphertext using HCTR2++.
    ///
    /// # Arguments
    /// * `plaintext` - Input data to encrypt (minimum 16 bytes)
    /// * `tweak` - Tweak value for domain separation
    /// * `ciphertext` - Output buffer (must be same length as plaintext)
    ///
    /// # Errors
    /// Returns `Error::InputTooShort` if plaintext is less than 16 bytes, and
    /// `Error::OutputLengthMismatch` if the buffer lengths differ.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr2pp(plaintext, tweak, ciphertext, Direction::Encrypt)
    }

    /// Decrypt ciphertext to plaintext using HCTR2++.
    ///
    /// # Arguments
    /// * `ciphertext` - Input data to decrypt (minimum 16 bytes)
    /// * `tweak` - Tweak value used during encryption
    /// * `plaintext` - Output buffer (must be same length as ciphertext)
    ///
    /// # Errors
    /// Returns `Error::InputTooShort` if ciphertext is less than 16 bytes, and
    /// `Error::OutputLengthMismatch` if the buffer lengths differ.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        self.hctr2pp(ciphertext, tweak, plaintext, Direction::Decrypt)
    }

    /// R3 re-keying: derive an ephemeral key and mask from a nonce.
    ///
    /// The paper leaves H_K(r) underspecified; this implementation hashes r as a
    /// message with an empty tweak, using the same hash as the rest of the mode.
    fn r3(&self, r: &[u8; BLOCK_LENGTH]) -> ([u8; BLOCK_LENGTH], [u8; BLOCK_LENGTH]) {
        let digest = hash2n(&self.kk, b"", r);
        (
            digest[..BLOCK_LENGTH].try_into().unwrap(),
            digest[BLOCK_LENGTH..].try_into().unwrap(),
        )
    }

    fn hctr2pp(
        &self,
        src: &[u8],
        tweak: &[u8],
        dst: &mut [u8],
        direction: Direction,
    ) -> Result<(), Error> {
        if dst.len() != src.len() {
            return Err(Error::OutputLengthMismatch);
        }
        if src.len() < BLOCK_LENGTH {
            return Err(Error::InputTooShort);
        }

        // Encryption hashes the input bulk with h1 and the output bulk with h2;
        // decryption swaps the two, which makes the code path self-inverse.
        let (hk_in, hk_out) = match direction {
            Direction::Encrypt => (&self.h1, &self.h2),
            Direction::Decrypt => (&self.h2, &self.h1),
        };

        let first: [u8; BLOCK_LENGTH] = src[..BLOCK_LENGTH].try_into().unwrap();
        let bulk = &src[BLOCK_LENGTH..];

        let x1 = hash2n(hk_in, tweak, bulk);
        let pp1 = xor_blocks(&first, &x1[..BLOCK_LENGTH].try_into().unwrap());
        let re: [u8; BLOCK_LENGTH] = x1[BLOCK_LENGTH..].try_into().unwrap();

        let (ue, ve) = self.r3(&re);
        let mut cc_block = Array::from(xor_blocks(&pp1, &ve));
        Aes128::new(Array::from_slice(&ue)).encrypt_block(&mut cc_block);
        let cc = xor_blocks(&cc_block.into(), &ve);

        let rj = hash2n(&self.h12, tweak, &cc);
        let r: [u8; BLOCK_LENGTH] = rj[..BLOCK_LENGTH].try_into().unwrap();
        let j: [u8; BLOCK_LENGTH] = rj[BLOCK_LENGTH..].try_into().unwrap();

        let (dst_first, dst_bulk) = dst.split_at_mut(BLOCK_LENGTH);
        self.ctr_pp(&r, &j, bulk, dst_bulk);

        let x2 = hash2n(hk_out, tweak, dst_bulk);
        let rd: [u8; BLOCK_LENGTH] = x2[BLOCK_LENGTH..].try_into().unwrap();

        let (ud, vd) = self.r3(&rd);
        let mut pp2_block = Array::from(xor_blocks(&cc, &vd));
        aes::Aes128Dec::new(Array::from_slice(&ud)).decrypt_block(&mut pp2_block);
        let pp2 = xor_blocks(&pp2_block.into(), &vd);

        dst_first.copy_from_slice(&xor_blocks(&pp2, &x2[..BLOCK_LENGTH].try_into().unwrap()));

        Ok(())
    }

    /// CTR++ mode: counter keystream where every block uses a fresh R3-derived key.
    fn ctr_pp(&self, r: &[u8; BLOCK_LENGTH], j: &[u8; BLOCK_LENGTH], src: &[u8], dst: &mut [u8]) {
        for (i, (src_chunk, dst_chunk)) in src
            .chunks(BLOCK_LENGTH)
            .zip(dst.chunks_mut(BLOCK_LENGTH))
            .enumerate()
        {
            let counter = ((i + 1) as u128).to_le_bytes();
            let ri = xor_blocks(r, &counter);
            let ji = xor_blocks(j, &counter);

            let (ui, vi) = self.r3(&ri);
            let mut block = Array::from(xor_blocks(&ji, &vi));
            Aes128::new(Array::from_slice(&ui)).encrypt_block(&mut block);
            let si = xor_blocks(&block.into(), &vi);

            for (k, (d, s)) in dst_chunk.iter_mut().zip(src_chunk.iter()).enumerate() {
                *d = s ^ si[k];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_elem(state: &mut u64) -> Elem {
        [
            xorshift(state),
            xorshift(state),
            xorshift(state),
            xorshift(state),
        ]
    }

    /// Bit-by-bit GF(2^256) multiplication used as a reference for gf_mul.
    fn slow_mul(a: &Elem, b: &Elem) -> Elem {
        let mut res = [0u64; 4];
        let mut cur = *a;
        for limb in b.iter() {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    res = elem_xor(&res, &cur);
                }
                // cur = cur * x mod x^256 + x^10 + x^5 + x^2 + 1
                let carry = cur[3] >> 63;
                cur[3] = (cur[3] << 1) | (cur[2] >> 63);
                cur[2] = (cur[2] << 1) | (cur[1] >> 63);
                cur[1] = (cur[1] << 1) | (cur[0] >> 63);
                cur[0] = (cur[0] << 1) ^ (carry * 0x425);
            }
        }
        res
    }

    #[test]
    fn test_gf_mul_matches_reference() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..50 {
            let a = random_elem(&mut state);
            let b = random_elem(&mut state);
            assert_eq!(gf_mul(&a, &b), slow_mul(&a, &b));
        }
    }

    #[test]
    fn test_gf_mul_identity_and_commutativity() {
        let one: Elem = [1, 0, 0, 0];
        let mut state = 0xdead_beef_cafe_f00du64;
        for _ in 0..20 {
            let a = random_elem(&mut state);
            let b = random_elem(&mut state);
            assert_eq!(gf_mul(&a, &one), a);
            assert_eq!(gf_mul(&a, &b), gf_mul(&b, &a));
        }
    }

    #[test]
    fn test_hash2n_separates_inputs() {
        let key: Elem = [2, 0, 0, 0];
        assert_ne!(hash2n(&key, b"", b"a"), hash2n(&key, b"a", b""));
        assert_ne!(hash2n(&key, b"t", b"m"), hash2n(&key, b"t", b"m\0"));
        assert_ne!(hash2n(&key, b"", &[0u8; 32]), hash2n(&key, b"", &[0u8; 64]));
    }

    #[test]
    fn test_hctr2pp_128_roundtrip() {
        let key = [0u8; 16];
        let cipher = Hctr2pp_128::new(&key);

        let plaintext = b"Hello, HCTR2++ World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hctr2pp_128_roundtrip_all_lengths() {
        let key: [u8; 16] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let cipher = Hctr2pp_128::new(&key);
        let tweak = b"length sweep";

        let plaintext: Vec<u8> = (0..100).map(|i| (i * 13 + 5) as u8).collect();
        for len in 16..=plaintext.len() {
            let mut ciphertext = vec![0u8; len];
            let mut decrypted = vec![0u8; len];
            cipher
                .encrypt(&plaintext[..len], tweak, &mut ciphertext)
                .unwrap();
            cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
            assert_eq!(&plaintext[..len], decrypted.as_slice(), "len = {len}");
        }
    }

    #[test]
    fn test_hctr2pp_128_minimum_length() {
        let key = [0u8; 16];
        let cipher = Hctr2pp_128::new(&key);

        let plaintext = [0x42u8; 16];
        let mut ciphertext = [0u8; 16];
        let mut decrypted = [0u8; 16];

        cipher.encrypt(&plaintext, b"", &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, b"", &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hctr2pp_128_input_too_short() {
        let key = [0u8; 16];
        let cipher = Hctr2pp_128::new(&key);

        let plaintext = [0x42u8; 15];
        let mut ciphertext = [0u8; 15];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut ciphertext),
            Err(Error::InputTooShort)
        );
    }

    #[test]
    fn test_hctr2pp_128_different_tweaks() {
        let key = [0u8; 16];
        let cipher = Hctr2pp_128::new(&key);

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
    fn test_hctr2pp_128_deterministic() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let cipher1 = Hctr2pp_128::new(&key);
        let cipher2 = Hctr2pp_128::new(&key);

        let plaintext = [0x55u8; 64];
        let mut ciphertext1 = [0u8; 64];
        let mut ciphertext2 = [0u8; 64];

        cipher1.encrypt(&plaintext, b"t", &mut ciphertext1).unwrap();
        cipher2.encrypt(&plaintext, b"t", &mut ciphertext2).unwrap();
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_hctr2pp_128_avalanche() {
        let key = [7u8; 16];
        let cipher = Hctr2pp_128::new(&key);

        let plaintext = [0u8; 64];
        let mut modified = plaintext;
        modified[63] ^= 1;

        let mut ciphertext1 = [0u8; 64];
        let mut ciphertext2 = [0u8; 64];
        cipher.encrypt(&plaintext, b"t", &mut ciphertext1).unwrap();
        cipher.encrypt(&modified, b"t", &mut ciphertext2).unwrap();

        // Flipping the last plaintext bit must change the first ciphertext block.
        assert_ne!(ciphertext1[..16], ciphertext2[..16]);
        // ... and the keystream over the bulk as well.
        assert_ne!(ciphertext1[16..48], ciphertext2[16..48]);
    }

    #[test]
    fn test_hctr2pp_128_large_message() {
        let key = [0u8; 16];
        let cipher = Hctr2pp_128::new(&key);

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
    fn test_hctr2pp_256_roundtrip() {
        let key = [0u8; 32];
        let cipher = Hctr2pp_256::new(&key);

        let plaintext = b"Hello, HCTR2++-256 World!";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let tweak = b"test tweak 256";

        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Known-answer vectors generated with an independent Python implementation
    // of the Figure 4 pseudocode (tmp/hctr2pp_ref.py): big-int GF(2^256)
    // arithmetic and AES from the cryptography library, no shared code.

    #[test]
    fn test_kat_subkeys() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let cipher = Hctr2pp_128::new(&key);

        let expect = |hex: &str| elem_from_bytes(&unhex(hex).try_into().unwrap());
        assert_eq!(
            cipher.h1,
            expect("e37cd363dd7c87a09aff0e3e60e09c82fb8ae31ba5db9cad97364d8722d47326")
        );
        assert_eq!(
            cipher.h2,
            expect("8cb899148f1fa8ff9132d0eb15a936f2f08c8d049312eac76f8fa05078178aa1")
        );
        assert_eq!(
            cipher.kk,
            expect("789dc76ccb52ce1c3db90ecb357af60eeb3ee851461107fec27297b27ad5e563")
        );
    }

    #[test]
    fn test_kat_hash2n() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let cipher = Hctr2pp_128::new(&key);

        let msg16: [u8; 16] = core::array::from_fn(|i| i as u8);
        let msg40: [u8; 40] = core::array::from_fn(|i| i as u8);
        let cases: [(&[u8], &[u8], &str); 4] = [
            (
                b"",
                b"",
                "c6f9a6c7baf90e4135ff1d7cc0c03905f715c7374ab7395b2f6d9a0e45a8e74c",
            ),
            (
                b"tweak",
                b"",
                "3c4414e8acf1f1bc7f9674c74043855751ef29e9513bdcf7fec97f76776ec5d6",
            ),
            (
                b"",
                &msg16,
                "6bcd860a4f8467fee40f2ae865cf74f010994a07f5c9b0248be2ffff87f29fad",
            ),
            (
                b"tweak",
                &msg40,
                "89e96782de662ce1592258b6abc040597d3abaea2e6c86ffee481ff7afb9b858",
            ),
        ];
        for (tweak, msg, expected) in cases {
            assert_eq!(hash2n(&cipher.h1, tweak, msg).to_vec(), unhex(expected));
        }
    }

    #[test]
    fn test_kat_r3() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let cipher = Hctr2pp_128::new(&key);

        let r: [u8; 16] = core::array::from_fn(|i| i as u8);
        let (u, v) = cipher.r3(&r);
        assert_eq!(u.to_vec(), unhex("cf53026c002409032271b44d2cfb76ae"));
        assert_eq!(v.to_vec(), unhex("cc0108efd8d927ec03a148f06bec9c38"));
    }

    #[test]
    fn test_kat_encrypt_128() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let cipher = Hctr2pp_128::new(&key);

        let cases: [(&[u8], &str, &str); 3] = [
            (
                b"",
                "000102030405060708090a0b0c0d0e0f",
                "02c3c1ea3033a092e21a16acaf88121b",
            ),
            (
                b"tweak",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "46feab9309b3e5826370ad00561963c698a293833efa5ce25c23786df2f4abad",
            ),
            (
                &unhex(
                    "0104070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e6164676a\
                     6d707376797c7f8285888b8e9194979a9da0a3a6a9acafb2b5b8bbbec1c4c7cacdd0",
                ),
                "050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa\
                 01080f161d242b323940474e55",
                "8ce2a701bc7547a38212d07087d365b4bf6b4bfe530436ec11f9087b813457a013fcfc18\
                 9b0ca9e172c2a3c148ab621beb",
            ),
        ];
        for (tweak, pt_hex, ct_hex) in cases {
            let pt = unhex(pt_hex);
            let expected_ct = unhex(ct_hex);
            let mut ct = vec![0u8; pt.len()];
            cipher.encrypt(&pt, tweak, &mut ct).unwrap();
            assert_eq!(ct, expected_ct);

            let mut decrypted = vec![0u8; ct.len()];
            cipher.decrypt(&ct, tweak, &mut decrypted).unwrap();
            assert_eq!(decrypted, pt);
        }
    }

    #[test]
    fn test_kat_encrypt_256() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let cipher = Hctr2pp_256::new(&key);

        let pt = unhex("03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3");
        let expected_ct =
            unhex("d885008594f696577cd7bf4478d27965d8741fd5eda96612e8ef397df08a4d0fec");
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&pt, b"tweak 256", &mut ct).unwrap();
        assert_eq!(ct, expected_ct);

        let mut decrypted = vec![0u8; ct.len()];
        cipher.decrypt(&ct, b"tweak 256", &mut decrypted).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_hctr2pp_128_output_length_mismatch() {
        let key = [0u8; 16];
        let cipher = Hctr2pp_128::new(&key);

        let plaintext = [0x42u8; 32];
        let mut too_short = [0u8; 16];
        let mut too_long = [0u8; 48];

        assert_eq!(
            cipher.encrypt(&plaintext, b"", &mut too_short),
            Err(Error::OutputLengthMismatch)
        );
        assert_eq!(
            cipher.decrypt(&plaintext, b"", &mut too_long),
            Err(Error::OutputLengthMismatch)
        );
    }

    #[test]
    fn test_hctr2pp_128_long_tweak() {
        let key = [3u8; 16];
        let cipher = Hctr2pp_128::new(&key);

        let plaintext = [0x11u8; 40];
        let tweak = [0x77u8; 100];
        let mut ciphertext = [0u8; 40];
        let mut decrypted = [0u8; 40];

        cipher.encrypt(&plaintext, &tweak, &mut ciphertext).unwrap();
        cipher.decrypt(&ciphertext, &tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
