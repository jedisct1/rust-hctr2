#![allow(deprecated)]
//! Common utilities shared across HCTR2/HCTR3 cipher implementations.

#[allow(deprecated)]
use aes::cipher::{Array, BlockCipherEncrypt};
use polyval::{Polyval, universal_hash::UniversalHash};

/// Unified error type for all HCTR cipher operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input is shorter than the minimum required length.
    InputTooShort,
    /// Tweak is longer than the maximum allowed.
    TweakTooLong,
    /// Tweak is shorter than the minimum required length.
    TweakTooShort,
    /// Tweak format is invalid (e.g., reserved bits are set).
    InvalidTweak,
    /// A digit value is out of range for the radix.
    InvalidDigit,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InputTooShort => write!(f, "input too short"),
            Error::TweakTooLong => write!(f, "tweak too long"),
            Error::TweakTooShort => write!(f, "tweak too short"),
            Error::InvalidTweak => write!(f, "invalid tweak format"),
            Error::InvalidDigit => write!(f, "digit out of range for radix"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// AES block length in bytes.
pub const BLOCK_LENGTH: usize = 16;

/// Direction of cipher operation.
#[derive(Clone, Copy)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// Absorb message into Polyval with HCTR2/HCTR3-style padding.
///
/// Pads incomplete blocks with a single 1 bit followed by zeros.
pub fn absorb(poly: &mut Polyval, msg: &[u8]) -> [u8; BLOCK_LENGTH] {
    let full_blocks = msg.len() / BLOCK_LENGTH;
    for i in 0..full_blocks {
        let block = Array::clone_from_slice(&msg[i * BLOCK_LENGTH..(i + 1) * BLOCK_LENGTH]);
        poly.update(&[block]);
    }

    let remainder = msg.len() % BLOCK_LENGTH;
    if remainder > 0 {
        let start = full_blocks * BLOCK_LENGTH;
        let remaining = &msg[start..];

        let mut padded_block = [0u8; BLOCK_LENGTH];
        padded_block[..remaining.len()].copy_from_slice(remaining);
        padded_block[remaining.len()] = 1;
        poly.update(&[Array::clone_from_slice(&padded_block)]);
    }

    let mut hh = [0u8; BLOCK_LENGTH];
    hh.copy_from_slice(poly.clone().finalize().as_slice());
    hh
}

/// XCTR mode: counter-based stream cipher using AES.
///
/// This is a self-inverse operation (encryption and decryption are identical).
pub fn xctr<Aes: BlockCipherEncrypt>(
    ks_enc: &Aes,
    dst: &mut [u8],
    src: &[u8],
    z: &[u8; BLOCK_LENGTH],
) {
    let mut counter: u64 = 1;
    let mut i = 0;

    while i + BLOCK_LENGTH <= src.len() {
        let mut counter_bytes = [0u8; BLOCK_LENGTH];
        counter_bytes[..8].copy_from_slice(&counter.to_le_bytes());

        for j in 0..BLOCK_LENGTH {
            counter_bytes[j] ^= z[j];
        }

        let mut block = Array::clone_from_slice(&counter_bytes);
        ks_enc.encrypt_block(&mut block);

        for j in 0..BLOCK_LENGTH {
            dst[i + j] = src[i + j] ^ block[j];
        }

        counter += 1;
        i += BLOCK_LENGTH;
    }

    let left = src.len() - i;
    if left > 0 {
        let mut counter_bytes = [0u8; BLOCK_LENGTH];
        counter_bytes[..8].copy_from_slice(&counter.to_le_bytes());

        for j in 0..BLOCK_LENGTH {
            counter_bytes[j] ^= z[j];
        }

        let mut block = Array::clone_from_slice(&counter_bytes);
        ks_enc.encrypt_block(&mut block);

        for j in 0..left {
            dst[i + j] = src[i + j] ^ block[j];
        }
    }
}

/// LFSR next state function for 128-bit state.
///
/// Uses primitive polynomial x^128 + x^7 + x^2 + x + 1 (Galois configuration).
/// Implementation is constant-time to prevent timing side-channel attacks.
#[inline]
pub fn lfsr_next_128(state: &[u8; 16]) -> [u8; 16] {
    let mut result = *state;

    let msb = result[15] >> 7;
    let mask = 0u8.wrapping_sub(msb);

    let mut carry: u8 = 0;
    for byte in result.iter_mut() {
        let new_carry = (*byte & 0x80) >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }

    result[0] ^= 0x87 & mask;

    result
}

/// LFSR next state function for 256-bit state.
///
/// Uses primitive polynomial x^256 + x^254 + x^251 + x^246 + 1 (Galois configuration).
/// Implementation is constant-time to prevent timing side-channel attacks.
#[inline]
#[allow(dead_code)]
pub fn lfsr_next_256(state: &[u8; 32]) -> [u8; 32] {
    let mut result = *state;

    let msb = result[31] >> 7;
    let mask = 0u8.wrapping_sub(msb);

    let mut carry: u8 = 0;
    for byte in result.iter_mut() {
        let new_carry = (*byte & 0x80) >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }

    result[0] ^= 0x01 & mask;
    result[30] ^= 0x40 & mask;
    result[31] ^= 0x08 & mask;
    result[31] ^= 0x40 & mask;

    result
}

/// XOR two 16-byte blocks, storing result in the first argument.
#[inline]
pub fn xor_block(dst: &mut [u8; BLOCK_LENGTH], src: &[u8; BLOCK_LENGTH]) {
    for i in 0..BLOCK_LENGTH {
        dst[i] ^= src[i];
    }
}

/// XOR two 16-byte blocks, returning a new block.
#[inline]
pub fn xor_blocks(a: &[u8; BLOCK_LENGTH], b: &[u8; BLOCK_LENGTH]) -> [u8; BLOCK_LENGTH] {
    let mut result = *a;
    xor_block(&mut result, b);
    result
}

/// XOR three 16-byte blocks, returning a new block.
#[inline]
pub fn xor_blocks_3(
    a: &[u8; BLOCK_LENGTH],
    b: &[u8; BLOCK_LENGTH],
    c: &[u8; BLOCK_LENGTH],
) -> [u8; BLOCK_LENGTH] {
    let mut result = [0u8; BLOCK_LENGTH];
    for i in 0..BLOCK_LENGTH {
        result[i] = a[i] ^ b[i] ^ c[i];
    }
    result
}

/// ELK mode: Encrypted LFSR Keystream.
///
/// This function XORs the source with an encrypted LFSR keystream.
/// Used by HCTR3 instead of XCTR.
pub fn elk<Aes: BlockCipherEncrypt>(
    ks: &Aes,
    dst: &mut [u8],
    src: &[u8],
    seed: &[u8; BLOCK_LENGTH],
) {
    let mut lfsr_state = *seed;
    let mut i = 0;

    while i + BLOCK_LENGTH <= src.len() {
        let mut block = Array::clone_from_slice(&lfsr_state);
        ks.encrypt_block(&mut block);

        for j in 0..BLOCK_LENGTH {
            dst[i + j] = src[i + j] ^ block[j];
        }

        lfsr_state = lfsr_next_128(&lfsr_state);
        i += BLOCK_LENGTH;
    }

    let left = src.len() - i;
    if left > 0 {
        let mut block = Array::clone_from_slice(&lfsr_state);
        ks.encrypt_block(&mut block);

        for j in 0..left {
            dst[i + j] = src[i + j] ^ block[j];
        }
    }
}
