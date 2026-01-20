//! HCTR2 and HCTR3 length-preserving encryption library.
//!
//! This crate provides implementations of HCTR2 and HCTR3 wide-block tweakable ciphers,
//! including their beyond-birthday-bound (BBB) secure variants and format-preserving modes.
//!
//! # Overview
//!
//! HCTR2 and HCTR3 are length-preserving encryption modes suitable for applications like:
//! - Full-disk encryption
//! - Filename encryption
//! - Database field encryption
//!
//! # Variants
//!
//! - **HCTR2**: Standard HCTR2 with birthday-bound (~64-bit) security
//! - **HCTR3**: Enhanced security with two-key construction and LFSR-based ELK mode
//! - **CHCTR2**: Cascaded HCTR2 with ~85-bit multi-user security
//! - **HCTR2-TwKD**: HCTR2 with tweak-based key derivation for BBB security
//! - **HCTR2-FP/HCTR3-FP**: Format-preserving variants for encrypting structured data
//!
//! # Quick Start
//!
//! ## Basic HCTR2 encryption
//!
//! ```rust
//! use hctr2::Hctr2_128;
//!
//! let key = [0u8; 16];
//! let cipher = Hctr2_128::new(&key);
//!
//! let plaintext = b"Hello, HCTR2 World!";
//! let tweak = b"unique tweak";
//!
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();
//!
//! let mut decrypted = vec![0u8; plaintext.len()];
//! cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```
//!
//! ## Format-preserving encryption (credit card numbers)
//!
//! ```rust
//! use hctr2::{Hctr2Fp_128_Decimal, encode_base_radix, first_block_length};
//!
//! let key = [0u8; 16];
//! let cipher = Hctr2Fp_128_Decimal::new(&key);
//!
//! // 16-digit credit card number represented as individual digits
//! // Note: minimum length for decimal is 39 digits (first_block_length(10))
//! // For shorter inputs, use a different radix or padding scheme
//! let first_len = first_block_length(10); // 39
//! let mut cc_digits = vec![0u8; first_len + 1]; // 40 digits
//! // Fill with some valid decimal digits (each must be 0-9)
//! cc_digits[0] = 4; cc_digits[1] = 1; cc_digits[2] = 2; cc_digits[3] = 3;
//!
//! let tweak = b"merchant_id_123";
//! let mut encrypted = vec![0u8; cc_digits.len()];
//! cipher.encrypt(&cc_digits, tweak, &mut encrypted).unwrap();
//!
//! // All encrypted digits are still in range [0, 9]
//! for &d in &encrypted {
//!     assert!(d < 10);
//! }
//! ```
//!
//! # Security Considerations
//!
//! - **Never reuse (key, tweak) pairs**: Each encryption must use a unique tweak
//! - **No authentication**: These are encryption-only modes; use AEAD for integrity
//! - **Minimum message length**: 16 bytes for HCTR2/HCTR3, varies by radix for FP modes
//!
//! # Feature Flags
//!
//! - `std` (default): Enable standard library support
//! - When disabled, the crate is `no_std` compatible

#![cfg_attr(not(feature = "std"), no_std)]

pub mod chctr2;
pub mod common;
pub mod hctr2;
pub mod hctr2_twkd;
pub mod hctr2fp;
pub mod hctr3;
pub mod hctr3fp;

#[cfg(test)]
mod cross_check;

#[allow(deprecated)]
pub use chctr2::Chctr2Error;
pub use chctr2::{Chctr2, Chctr2_128, Chctr2_256};
pub use common::Error;
#[allow(deprecated)]
pub use hctr2::Hctr2Error;
pub use hctr2::{AesCipher, Hctr2, Hctr2_128, Hctr2_256};
#[allow(deprecated)]
pub use hctr2_twkd::Hctr2TwKDError;
pub use hctr2_twkd::{CencKdf128, CencKdf256, Hctr2TwKD_128, Hctr2TwKD_256};
#[allow(deprecated)]
pub use hctr2fp::Hctr2FpError;
pub use hctr2fp::{
    Hctr2Fp, Hctr2Fp_128_Base64, Hctr2Fp_128_Decimal, Hctr2Fp_128_Hex, Hctr2Fp_256_Base64,
    Hctr2Fp_256_Decimal, Hctr2Fp_256_Hex, decode_base_radix, encode_base_radix, first_block_length,
};
#[allow(deprecated)]
pub use hctr3::Hctr3Error;
pub use hctr3::{Hctr3, Hctr3_128, Hctr3_256};
pub use hctr3fp::{
    Hctr3Fp, Hctr3Fp_128_Base64, Hctr3Fp_128_Decimal, Hctr3Fp_128_Hex, Hctr3Fp_256_Base64,
    Hctr3Fp_256_Decimal, Hctr3Fp_256_Hex,
};
