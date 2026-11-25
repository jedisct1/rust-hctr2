//! POLYVAL of the same input under two keys.
//!
//! On CPUs with carryless multiplication, both hashes are computed in one pass, which is a lot faster than two separate ones.

use polyval::hazmat::FieldElement;

use crate::common::{BLOCK_LENGTH, has_crypto_extensions};

const AGGREGATE: usize = 16;

#[cfg_attr(
    not(any(
        all(target_arch = "aarch64", target_endian = "little"),
        target_arch = "x86_64"
    )),
    allow(dead_code)
)]
pub(crate) struct DualPolyval {
    keys: [FieldElement; 2],
    /// `powers[k][i]` is key `k` to the power `16 - i`, so that 16 blocks can share one reduction.
    powers: [[[u8; BLOCK_LENGTH]; AGGREGATE]; 2],
    /// For each power, the XOR of the two halves of key 0 in the low lane, and of key 1 in the high lane.
    karatsuba: [[u8; BLOCK_LENGTH]; AGGREGATE],
    clmul: bool,
}

impl DualPolyval {
    pub(crate) fn new(key1: &[u8; BLOCK_LENGTH], key2: &[u8; BLOCK_LENGTH]) -> Self {
        Self::with_backend(key1, key2, has_crypto_extensions())
    }

    fn with_backend(key1: &[u8; BLOCK_LENGTH], key2: &[u8; BLOCK_LENGTH], clmul: bool) -> Self {
        let keys = [FieldElement::from(*key1), FieldElement::from(*key2)];
        let mut powers = [[[0u8; BLOCK_LENGTH]; AGGREGATE]; 2];
        for (powers, key) in powers.iter_mut().zip(keys) {
            let mut p = key;
            for power in powers.iter_mut().rev() {
                *power = p.into();
                p *= key;
            }
        }
        let fold = |h: &[u8; BLOCK_LENGTH]| {
            let h = u128::from_le_bytes(*h);
            u128::from(h as u64 ^ (h >> 64) as u64)
        };
        let karatsuba = core::array::from_fn(|i| {
            (fold(&powers[0][i]) | (fold(&powers[1][i]) << 64)).to_le_bytes()
        });
        Self {
            keys,
            powers,
            karatsuba,
            clmul,
        }
    }

    pub(crate) fn hasher(&self) -> Hasher<'_> {
        Hasher {
            keys: self,
            acc: [0; 2],
            buf: [0; BLOCK_LENGTH],
            buffered: 0,
        }
    }

    /// Absorbs between 1 and 16 blocks.
    fn absorb(&self, acc: &mut [u128; 2], blocks: &[[u8; BLOCK_LENGTH]]) {
        debug_assert!((1..=AGGREGATE).contains(&blocks.len()));
        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            target_arch = "x86_64"
        ))]
        if self.clmul {
            // SAFETY: `clmul` is only set when the CPU supports the instructions.
            unsafe { clmul::absorb(&self.powers, &self.karatsuba, acc, blocks) };
            return;
        }
        for block in blocks {
            for (acc, key) in acc.iter_mut().zip(self.keys) {
                *acc = (FieldElement::from(*acc ^ u128::from_le_bytes(*block)) * key).into();
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct Hasher<'a> {
    keys: &'a DualPolyval,
    acc: [u128; 2],
    buf: [u8; BLOCK_LENGTH],
    buffered: usize,
}

impl Hasher<'_> {
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let n = data.len().min(BLOCK_LENGTH - self.buffered);
            self.buf[self.buffered..][..n].copy_from_slice(&data[..n]);
            self.buffered += n;
            data = &data[n..];
            if self.buffered < BLOCK_LENGTH {
                return;
            }
            self.keys.absorb(&mut self.acc, &[self.buf]);
            self.buffered = 0;
        }
        let (blocks, rest) = data.as_chunks::<BLOCK_LENGTH>();
        for chunk in blocks.chunks(AGGREGATE) {
            self.keys.absorb(&mut self.acc, chunk);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Adds `first`, then zeros up to the end of the block.
    pub(crate) fn pad(&mut self, first: u8) {
        let mut pad = [0u8; BLOCK_LENGTH];
        pad[0] = first;
        self.update(&pad[..BLOCK_LENGTH - self.buffered]);
    }

    pub(crate) fn is_block_aligned(&self) -> bool {
        self.buffered == 0
    }

    /// Returns both hashes.
    /// The input must be a whole number of blocks.
    pub(crate) fn finalize(self) -> [u8; 2 * BLOCK_LENGTH] {
        debug_assert!(self.is_block_aligned());
        let mut out = [0u8; 2 * BLOCK_LENGTH];
        out[..BLOCK_LENGTH].copy_from_slice(&self.acc[0].to_le_bytes());
        out[BLOCK_LENGTH..].copy_from_slice(&self.acc[1].to_le_bytes());
        out
    }
}

/// Karatsuba with PMULL or PCLMULQDQ.
/// Each block is loaded once, and its share of the work is done once for both keys.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
mod clmul {
    use super::{AGGREGATE, BLOCK_LENGTH};

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    mod ops {
        use core::arch::aarch64::*;

        pub(super) type V = uint64x2_t;

        #[inline(always)]
        pub(super) unsafe fn load(bytes: &[u8; 16]) -> V {
            unsafe { vreinterpretq_u64_u8(vld1q_u8(bytes.as_ptr())) }
        }

        #[inline(always)]
        pub(super) unsafe fn store(v: V) -> [u8; 16] {
            let mut out = [0u8; 16];
            unsafe { vst1q_u8(out.as_mut_ptr(), vreinterpretq_u8_u64(v)) };
            out
        }

        #[inline(always)]
        pub(super) unsafe fn xor(a: V, b: V) -> V {
            unsafe { veorq_u64(a, b) }
        }

        #[inline(always)]
        pub(super) unsafe fn swap(a: V) -> V {
            unsafe { vextq_u64(a, a, 1) }
        }

        #[inline(always)]
        pub(super) unsafe fn clmul_lo(a: V, b: V) -> V {
            unsafe { vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64(a, 0), vgetq_lane_u64(b, 0))) }
        }

        #[inline(always)]
        pub(super) unsafe fn clmul_hi(a: V, b: V) -> V {
            unsafe {
                vreinterpretq_u64_p128(vmull_high_p64(
                    vreinterpretq_p64_u64(a),
                    vreinterpretq_p64_u64(b),
                ))
            }
        }

        /// Returns `(0, a.lo)`, which is `a << 64`.
        #[inline(always)]
        pub(super) unsafe fn shift_up(a: V) -> V {
            unsafe { vextq_u64(vdupq_n_u64(0), a, 1) }
        }

        /// Returns `(a.hi, 0)`, which is `a >> 64`.
        #[inline(always)]
        pub(super) unsafe fn shift_down(a: V) -> V {
            unsafe { vextq_u64(a, vdupq_n_u64(0), 1) }
        }
    }

    #[cfg(target_arch = "x86_64")]
    mod ops {
        use core::arch::x86_64::*;

        pub(super) type V = __m128i;

        #[inline(always)]
        pub(super) unsafe fn load(bytes: &[u8; 16]) -> V {
            unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
        }

        #[inline(always)]
        pub(super) unsafe fn store(v: V) -> [u8; 16] {
            let mut out = [0u8; 16];
            unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), v) };
            out
        }

        #[inline(always)]
        pub(super) unsafe fn xor(a: V, b: V) -> V {
            unsafe { _mm_xor_si128(a, b) }
        }

        #[inline(always)]
        pub(super) unsafe fn swap(a: V) -> V {
            unsafe { _mm_shuffle_epi32(a, 0x4e) }
        }

        #[inline(always)]
        pub(super) unsafe fn clmul_lo(a: V, b: V) -> V {
            unsafe { _mm_clmulepi64_si128(a, b, 0x00) }
        }

        #[inline(always)]
        pub(super) unsafe fn clmul_hi(a: V, b: V) -> V {
            unsafe { _mm_clmulepi64_si128(a, b, 0x11) }
        }

        #[inline(always)]
        pub(super) unsafe fn shift_up(a: V) -> V {
            unsafe { _mm_slli_si128(a, 8) }
        }

        #[inline(always)]
        pub(super) unsafe fn shift_down(a: V) -> V {
            unsafe { _mm_srli_si128(a, 8) }
        }
    }

    use ops::*;

    /// The low, high and middle Karatsuba terms of `x0` times key 0, then of `x1` times key 1.
    #[inline(always)]
    unsafe fn products(x0: V, x1: V, h0: &[u8; 16], h1: &[u8; 16], karatsuba: &[u8; 16]) -> [V; 6] {
        unsafe {
            let (h0, h1, k) = (load(h0), load(h1), load(karatsuba));
            let (xk0, xk1) = (xor(x0, swap(x0)), xor(x1, swap(x1)));
            [
                clmul_lo(x0, h0),
                clmul_hi(x0, h0),
                clmul_lo(xk0, k),
                clmul_lo(x1, h1),
                clmul_hi(x1, h1),
                clmul_hi(xk1, k),
            ]
        }
    }

    #[inline(always)]
    unsafe fn add(t: &mut [V; 6], p: [V; 6]) {
        unsafe {
            *t = [
                xor(t[0], p[0]),
                xor(t[1], p[1]),
                xor(t[2], p[2]),
                xor(t[3], p[3]),
                xor(t[4], p[4]),
                xor(t[5], p[5]),
            ];
        }
    }

    /// Reduces modulo the POLYVAL polynomial, including its division by x^128.
    #[inline(always)]
    unsafe fn reduce(lo: V, hi: V, mid: V) -> u128 {
        unsafe {
            let mid = xor(mid, xor(lo, hi));
            let lo = xor(lo, shift_up(mid));
            let hi = xor(hi, shift_down(mid));
            let poly = load(&0xc200_0000_0000_0000u128.to_le_bytes());
            let t = xor(swap(lo), clmul_lo(lo, poly));
            u128::from_le_bytes(store(xor(hi, xor(swap(t), clmul_lo(t, poly)))))
        }
    }

    #[cfg_attr(
        all(target_arch = "aarch64", target_endian = "little"),
        target_feature(enable = "neon,aes")
    )]
    #[cfg_attr(target_arch = "x86_64", target_feature(enable = "pclmulqdq,sse2"))]
    pub(super) unsafe fn absorb(
        powers: &[[[u8; BLOCK_LENGTH]; AGGREGATE]; 2],
        karatsuba: &[[u8; BLOCK_LENGTH]; AGGREGATE],
        acc: &mut [u128; 2],
        blocks: &[[u8; BLOCK_LENGTH]],
    ) {
        unsafe {
            let start = AGGREGATE - blocks.len();
            let (p0, p1, pk) = (
                &powers[0][start..],
                &powers[1][start..],
                &karatsuba[start..],
            );
            let x = load(&blocks[0]);
            let (x0, x1) = (
                xor(x, load(&acc[0].to_le_bytes())),
                xor(x, load(&acc[1].to_le_bytes())),
            );
            let mut t = products(x0, x1, &p0[0], &p1[0], &pk[0]);
            // Two products at a time, so that the additions don't form one long chain.
            let mut rest = blocks[1..].iter().zip(&p0[1..]).zip(&p1[1..]).zip(&pk[1..]);
            while let Some((((a, h0), h1), k)) = rest.next() {
                let a = load(a);
                let mut p = products(a, a, h0, h1, k);
                if let Some((((b, h0), h1), k)) = rest.next() {
                    let b = load(b);
                    add(&mut p, products(b, b, h0, h1, k));
                }
                add(&mut t, p);
            }
            acc[0] = reduce(t[0], t[1], t[2]);
            acc[1] = reduce(t[3], t[4], t[5]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyval::{Polyval, universal_hash::UniversalHash};

    #[test]
    fn test_dual_polyval_matches_polyval() {
        let key1: [u8; 16] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let key2: [u8; 16] = core::array::from_fn(|i| (i * 13 + 200) as u8);
        let data: Vec<u8> = (0..2000).map(|i| (i * 31 + 5) as u8).collect();
        let reference = |key: &[u8; 16], data: &[u8]| {
            let mut p = Polyval::new(key.into());
            p.update_padded(data);
            p.finalize()
        };

        for keys in [
            DualPolyval::with_backend(&key1, &key2, false),
            DualPolyval::new(&key1, &key2),
        ] {
            for len in [0, 16, 32, 240, 256, 272, 512, 2000] {
                let mut expected = reference(&key1, &data[..len]).to_vec();
                expected.extend_from_slice(&reference(&key2, &data[..len]));
                for step in [1, 7, 16, 1000] {
                    let mut hasher = keys.hasher();
                    for chunk in data[..len].chunks(step) {
                        hasher.update(chunk);
                    }
                    assert_eq!(
                        hasher.finalize().as_slice(),
                        expected.as_slice(),
                        "len {len} step {step}"
                    );
                }
            }
        }
    }
}
