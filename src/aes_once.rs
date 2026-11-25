//! AES-128 for keys that are used only once, like the ones in the head of HCENC.
//!
//! Computing the round keys along the way is a lot faster than setting up a full AES context.
//! CPUs without AES instructions use the `aes` crate instead.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
use crate::common::has_crypto_extensions;

type Block = [u8; 16];

pub(crate) fn encrypt(key: &Block, block: &Block) -> Block {
    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little"),
        target_arch = "x86_64"
    ))]
    if has_crypto_extensions() {
        // SAFETY: the CPU supports the AES instructions.
        return unsafe { native::encrypt(key, block) };
    }
    let mut b = (*block).into();
    aes::Aes128Enc::new(&(*key).into()).encrypt_block(&mut b);
    b.into()
}

pub(crate) fn decrypt(key: &Block, block: &Block) -> Block {
    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little"),
        target_arch = "x86_64"
    ))]
    if has_crypto_extensions() {
        // SAFETY: the CPU supports the AES instructions.
        return unsafe { native::decrypt(key, block) };
    }
    let mut b = (*block).into();
    aes::Aes128Dec::new(&(*key).into()).decrypt_block(&mut b);
    b.into()
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod native {
    use super::Block;
    use core::arch::aarch64::*;

    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    #[inline(always)]
    unsafe fn next_key(k: uint8x16_t, rcon: u8) -> uint8x16_t {
        unsafe {
            let zero = vdupq_n_u8(0);
            let rot_word = vld1q_u8(
                [
                    13u8, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12,
                ]
                .as_ptr(),
            );
            // With four identical columns, ShiftRows does nothing, so AESE with a zero key only applies SubBytes.
            let sub = vaeseq_u8(vqtbl1q_u8(k, rot_word), zero);
            // Only the last XOR waits for AESE, which keeps the key schedule fast.
            let t = veorq_u8(k, vextq_u8(zero, k, 12));
            let t = veorq_u8(t, vextq_u8(zero, t, 8));
            let t = veorq_u8(t, vreinterpretq_u8_u32(vdupq_n_u32(u32::from(rcon))));
            veorq_u8(t, sub)
        }
    }

    #[target_feature(enable = "aes")]
    pub(super) unsafe fn encrypt(key: &Block, block: &Block) -> Block {
        unsafe {
            let mut k = vld1q_u8(key.as_ptr());
            let mut s = vld1q_u8(block.as_ptr());
            for &rcon in &RCON[..9] {
                s = vaesmcq_u8(vaeseq_u8(s, k));
                k = next_key(k, rcon);
            }
            s = vaeseq_u8(s, k);
            s = veorq_u8(s, next_key(k, RCON[9]));
            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), s);
            out
        }
    }

    #[target_feature(enable = "aes")]
    pub(super) unsafe fn decrypt(key: &Block, block: &Block) -> Block {
        unsafe {
            let mut keys = [vld1q_u8(key.as_ptr()); 11];
            for i in 0..10 {
                keys[i + 1] = next_key(keys[i], RCON[i]);
            }
            let mut s = vaesimcq_u8(vaesdq_u8(vld1q_u8(block.as_ptr()), keys[10]));
            for k in keys[2..10].iter().rev() {
                s = vaesimcq_u8(vaesdq_u8(s, vaesimcq_u8(*k)));
            }
            s = veorq_u8(vaesdq_u8(s, vaesimcq_u8(keys[1])), keys[0]);
            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), s);
            out
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod native {
    use super::Block;
    use core::arch::x86_64::*;

    #[inline(always)]
    unsafe fn expand<const RCON: i32>(k: __m128i) -> __m128i {
        unsafe {
            let t = _mm_shuffle_epi32(_mm_aeskeygenassist_si128::<RCON>(k), 0xff);
            let k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            let k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            let k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
            _mm_xor_si128(k, t)
        }
    }

    /// All the round keys, as AESKEYGENASSIST needs its round constant at compile time.
    #[inline(always)]
    unsafe fn round_keys(key: &Block) -> [__m128i; 11] {
        unsafe {
            let k0 = _mm_loadu_si128(key.as_ptr().cast());
            let k1 = expand::<0x01>(k0);
            let k2 = expand::<0x02>(k1);
            let k3 = expand::<0x04>(k2);
            let k4 = expand::<0x08>(k3);
            let k5 = expand::<0x10>(k4);
            let k6 = expand::<0x20>(k5);
            let k7 = expand::<0x40>(k6);
            let k8 = expand::<0x80>(k7);
            let k9 = expand::<0x1b>(k8);
            let k10 = expand::<0x36>(k9);
            [k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10]
        }
    }

    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn encrypt(key: &Block, block: &Block) -> Block {
        unsafe {
            let keys = round_keys(key);
            let mut s = _mm_xor_si128(_mm_loadu_si128(block.as_ptr().cast()), keys[0]);
            for k in &keys[1..10] {
                s = _mm_aesenc_si128(s, *k);
            }
            s = _mm_aesenclast_si128(s, keys[10]);
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr().cast(), s);
            out
        }
    }

    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn decrypt(key: &Block, block: &Block) -> Block {
        unsafe {
            let keys = round_keys(key);
            let mut s = _mm_xor_si128(_mm_loadu_si128(block.as_ptr().cast()), keys[10]);
            for k in keys[1..10].iter().rev() {
                s = _mm_aesdec_si128(s, _mm_aesimc_si128(*k));
            }
            s = _mm_aesdeclast_si128(s, keys[0]);
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr().cast(), s);
            out
        }
    }
}
