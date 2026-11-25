//! HCENC, a wide-block tweakable cipher built on AES-128, with security well beyond the birthday bound.
//!
//! From "HCENC: How to Design an Efficient Committing Beyond-Birthday-Bound Accordion from a Block Cipher with n-Bit Blocks and Keys".
//!
//! [`Hcenc`] is the bare cipher: the ciphertext is as long as the plaintext, and nothing is authenticated.
//!
//! [`EtesHcenc`] and [`UcxHcenc`] add authentication and key commitment, with a slightly longer ciphertext.
//!
//! All of them need messages of at least 32 bytes.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128Enc, Aes256Enc};
use cshake::CShake256;
use cshake::digest::{ExtendableOutput, Update};

use crate::aes_once;
use crate::common::{BLOCK_LENGTH, Direction, Error, xor_blocks};
use crate::dual_polyval::{DualPolyval, Hasher};

type Block = [u8; BLOCK_LENGTH];

const HEAD_LENGTH: usize = 2 * BLOCK_LENGTH;

/// EtES adds this many zero bytes after the head, and checks them on decryption.
const TAG_LENGTH: usize = BLOCK_LENGTH;

/// The frame width the paper recommends.
///
/// Each frame of `w` blocks costs one extra AES call, and security goes up to about 2^128 / w blocks.
pub const DEFAULT_FRAME_WIDTH: u64 = 4096;

/// HCENC, parameterized by its frame width.
pub struct Hcenc<const FRAME_WIDTH: u64 = DEFAULT_FRAME_WIDTH> {
    hash_keys: DualPolyval,
    k1: Block,
    k2: Block,
    k3: Block,
    ks: Block,
}

/// HCENC with the recommended frame width.
#[allow(non_camel_case_types)]
pub type Hcenc_128 = Hcenc<DEFAULT_FRAME_WIDTH>;

impl<const FRAME_WIDTH: u64> Hcenc<FRAME_WIDTH> {
    /// Master key length in bytes.
    pub const KEY_LENGTH: usize = 32;

    /// Minimum input length in bytes.
    pub const MIN_INPUT_LENGTH: usize = HEAD_LENGTH;

    /// Creates a cipher with the one-call key derivation of the paper.
    ///
    /// It costs one AES call, and is all you need for plain encryption.
    pub fn new(key: &[u8]) -> Self {
        let (ka, kb) = split_key(key);
        let h2 = aes_once::encrypt(&ka, &kb);
        let k1 = mul_x(&ka);
        let k2 = mul_x(&k1);
        let k3 = mul_x(&k2);
        Self::from_keys(kb, h2, k1, k2, k3, mul_x(&k3))
    }

    /// Creates a cipher with the two-stage key derivation of the paper.
    ///
    /// It costs seven AES calls, and with [`EtesHcenc`] it also commits to the key, but only up to about 60 bits.
    pub fn new_two_stage(key: &[u8]) -> Self {
        let (ka, kb) = split_key(key);
        let l = xor_blocks(&aes_once::encrypt(&ka, &kb), &kb);
        let d: [Block; 6] = core::array::from_fn(|j| {
            let mut kj = l;
            kj[0] ^= j as u8;
            aes_once::encrypt(&kj, &ka)
        });
        Self::from_keys(d[0], d[1], d[2], d[3], d[4], d[5])
    }

    fn from_keys(h1: Block, h2: Block, k1: Block, k2: Block, k3: Block, ks: Block) -> Self {
        const { assert!(FRAME_WIDTH >= 1 && FRAME_WIDTH < u64::MAX) };
        Self {
            hash_keys: DualPolyval::new(&h1, &h2),
            k1,
            k2,
            k3,
            ks,
        }
    }

    /// Encrypts `plaintext` into `ciphertext`, which must have the same length.
    ///
    /// The same tweak and message always give the same ciphertext.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        tweak: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.encrypt_with_tag(plaintext, &[], [tweak, &[]], ciphertext)
    }

    /// Decrypts `ciphertext` into `plaintext`, which must have the same length.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tweak: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        if plaintext.len() != ciphertext.len() {
            return Err(Error::OutputLengthMismatch);
        }
        if ciphertext.len() < HEAD_LENGTH {
            return Err(Error::InputTooShort);
        }
        let (src_head, src_tail) = ciphertext.split_at(HEAD_LENGTH);
        let (dst_head, dst_tail) = plaintext.split_at_mut(HEAD_LENGTH);
        self.crypt(
            Direction::Decrypt,
            dst_head.try_into().unwrap(),
            [dst_tail, &mut []],
            src_head.try_into().unwrap(),
            [src_tail, &[]],
            [tweak, &[]],
        );
        Ok(())
    }

    /// Encrypts `plaintext` with `tag` inserted after its head, which is how EtES adds its zero bytes.
    fn encrypt_with_tag(
        &self,
        plaintext: &[u8],
        tag: &[u8],
        tweak: [&[u8]; 2],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if ciphertext.len() != plaintext.len() + tag.len() {
            return Err(Error::OutputLengthMismatch);
        }
        if plaintext.len() < HEAD_LENGTH {
            return Err(Error::InputTooShort);
        }
        let (src_head, src_tail) = plaintext.split_at(HEAD_LENGTH);
        let (dst_head, dst_tail) = ciphertext.split_at_mut(HEAD_LENGTH);
        self.crypt(
            Direction::Encrypt,
            dst_head.try_into().unwrap(),
            [dst_tail, &mut []],
            src_head.try_into().unwrap(),
            [tag, src_tail],
            tweak,
        );
        Ok(())
    }

    /// EtES decryption.
    /// Fails and clears `plaintext` unless the zero bytes come back.
    fn decrypt_with_tag(
        &self,
        src_head: &[u8; HEAD_LENGTH],
        src_tail: [&[u8]; 2],
        tweak: [&[u8]; 2],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        let mut tag = [0u8; TAG_LENGTH];
        let (dst_head, dst_tail) = plaintext.split_at_mut(HEAD_LENGTH);
        self.crypt(
            Direction::Decrypt,
            dst_head.try_into().unwrap(),
            [&mut tag, dst_tail],
            src_head,
            src_tail,
            tweak,
        );
        if !ct_codecs::verify(&tag, &[0; TAG_LENGTH]) {
            plaintext.fill(0);
            return Err(Error::AuthenticationFailed);
        }
        Ok(())
    }

    // The tail and the tweak can be split in two, so the AEAD modes can add their extra bytes without copying the message.
    fn crypt(
        &self,
        direction: Direction,
        dst_head: &mut [u8; HEAD_LENGTH],
        mut dst_tail: [&mut [u8]; 2],
        src_head: &[u8; HEAD_LENGTH],
        src_tail: [&[u8]; 2],
        tweak: [&[u8]; 2],
    ) {
        let tail_len = src_tail[0].len() + src_tail[1].len();
        let prefix = self.hash_prefix(tweak, tail_len);
        let (s_in, s_out) = match direction {
            Direction::Encrypt => (0, 1),
            Direction::Decrypt => (1, 0),
        };
        let input = xor_heads(src_head, &finish_hash(&prefix, s_in, src_tail));
        let output = match direction {
            Direction::Encrypt => self.head(&input),
            Direction::Decrypt => self.head_inverse(&input),
        };
        if tail_len > 0 {
            let (z1, z2) = split_head(&xor_heads(&input, &output));
            Keystream::<FRAME_WIDTH>::new(&xor_blocks(&self.ks, &z1), &z2)
                .apply_parts(&mut dst_tail, src_tail);
        }
        *dst_head = xor_heads(
            &output,
            &finish_hash(&prefix, s_out, dst_tail.map(|part| &*part)),
        );
    }

    // Both hashes start with the same length block and tweak, so that part is only hashed once.
    fn hash_prefix(&self, tweak: [&[u8]; 2], tail_len: usize) -> Hasher<'_> {
        let tweak_len = tweak[0].len() + tweak[1].len();
        let partial = u128::from(!tail_len.is_multiple_of(BLOCK_LENGTH));
        let mut hasher = self.hash_keys.hasher();
        hasher.update(&(16 * tweak_len as u128 + 4 + partial).to_le_bytes());
        hasher.update(tweak[0]);
        hasher.update(tweak[1]);
        hasher
    }

    fn head(&self, x: &[u8; HEAD_LENGTH]) -> [u8; HEAD_LENGTH] {
        let (a, b) = split_head(x);
        let g = aes_once::encrypt(&xor_blocks(&self.k1, &b), &a);
        let v = aes_once::encrypt(&xor_blocks(&self.k2, &g), &b);
        let u = aes_once::encrypt(&xor_blocks(&self.k3, &v), &g);
        join_head(&u, &v)
    }

    fn head_inverse(&self, y: &[u8; HEAD_LENGTH]) -> [u8; HEAD_LENGTH] {
        let (u, v) = split_head(y);
        let g = aes_once::decrypt(&xor_blocks(&self.k3, &v), &u);
        let b = aes_once::decrypt(&xor_blocks(&self.k2, &g), &v);
        let a = aes_once::decrypt(&xor_blocks(&self.k1, &b), &g);
        join_head(&a, &b)
    }
}

/// The paper's H^s for this tail, under both hash keys.
fn finish_hash(prefix: &Hasher<'_>, s: u8, tail: [&[u8]; 2]) -> [u8; HEAD_LENGTH] {
    let mut hasher = prefix.clone();
    hasher.pad(s);
    hasher.update(tail[0]);
    hasher.update(tail[1]);
    if !hasher.is_block_aligned() {
        hasher.pad(1);
    }
    hasher.finalize()
}

/// The CENC keystream of the paper.
///
/// Each frame encrypts w + 1 counters in a row.
/// The first one is the anchor, and each of the others gives a keystream block, XORed with the encrypted anchor.
struct Keystream<const W: u64> {
    aes: Aes128Enc,
    mask: u128,
    counter: u64,
    anchor: u128,
    leftover: Block,
    leftover_len: usize,
}

/// Number of blocks encrypted together, so that the AES pipeline stays full.
const KEYSTREAM_BATCH: usize = 32;

impl<const W: u64> Keystream<W> {
    fn new(key: &Block, mask: &Block) -> Self {
        Self {
            aes: Aes128Enc::new(&(*key).into()),
            mask: u128::from_le_bytes(*mask),
            counter: 0,
            anchor: 0,
            leftover: [0; BLOCK_LENGTH],
            leftover_len: 0,
        }
    }

    fn counter_block(&self, offset: usize) -> Block {
        (self.mask ^ u128::from(self.counter + offset as u64)).to_le_bytes()
    }

    fn next_encrypted_counter(&mut self) -> u128 {
        let block = aes_encrypt(&self.aes, &self.counter_block(0));
        self.counter += 1;
        u128::from_le_bytes(block)
    }

    fn update_anchor(&mut self) {
        if self.counter.is_multiple_of(W + 1) {
            self.anchor = self.next_encrypted_counter();
        }
    }

    /// XORs the next `src.len()` bytes of keystream into `src`, writing the result to `dst`.
    /// Can be called repeatedly with any lengths.
    fn apply(&mut self, dst: &mut [u8], src: &[u8]) {
        debug_assert_eq!(dst.len(), src.len());
        let mut i = self.leftover_len.min(src.len());
        let offset = BLOCK_LENGTH - self.leftover_len;
        for ((d, s), k) in dst[..i]
            .iter_mut()
            .zip(&src[..i])
            .zip(&self.leftover[offset..])
        {
            *d = s ^ k;
        }
        self.leftover_len -= i;

        // The counters are encrypted right in `dst`, so no scratch buffer is needed.
        while src.len() - i >= BLOCK_LENGTH {
            self.update_anchor();
            let frame_left = (W + 1 - self.counter % (W + 1)).min(KEYSTREAM_BATCH as u64) as usize;
            let n = frame_left.min((src.len() - i) / BLOCK_LENGTH);
            let (dst_blocks, _) = dst[i..i + n * BLOCK_LENGTH].as_chunks_mut::<BLOCK_LENGTH>();
            for (j, block) in dst_blocks.iter_mut().enumerate() {
                *block = self.counter_block(j);
            }
            self.aes
                .encrypt_blocks(aes::Block::cast_slice_from_core_mut(dst_blocks));
            self.counter += n as u64;
            let (src_blocks, _) = src[i..].as_chunks::<BLOCK_LENGTH>();
            for (d, s) in dst_blocks.iter_mut().zip(src_blocks) {
                *d =
                    (u128::from_le_bytes(*d) ^ self.anchor ^ u128::from_le_bytes(*s)).to_le_bytes();
            }
            i += n * BLOCK_LENGTH;
        }

        let rest = src.len() - i;
        if rest > 0 {
            self.update_anchor();
            let k = (self.next_encrypted_counter() ^ self.anchor).to_le_bytes();
            for ((d, s), k) in dst[i..].iter_mut().zip(&src[i..]).zip(&k) {
                *d = s ^ k;
            }
            self.leftover = k;
            self.leftover_len = BLOCK_LENGTH - rest;
        }
    }

    /// Same as `apply`, with the input and the output split in two, possibly at different places.
    fn apply_parts(&mut self, dst: &mut [&mut [u8]; 2], src: [&[u8]; 2]) {
        debug_assert_eq!(dst[0].len() + dst[1].len(), src[0].len() + src[1].len());
        let [mut d, mut d_next] = dst.each_mut().map(|part| &mut **part);
        let [mut s, mut s_next] = src;
        while !d.is_empty() || !d_next.is_empty() {
            if d.is_empty() {
                d = core::mem::take(&mut d_next);
            }
            if s.is_empty() {
                s = core::mem::take(&mut s_next);
            }
            let n = d.len().min(s.len());
            let (d_head, d_rest) = core::mem::take(&mut d).split_at_mut(n);
            let (s_head, s_rest) = s.split_at(n);
            self.apply(d_head, s_head);
            (d, s) = (d_rest, s_rest);
        }
    }
}

/// Rejects ciphertexts that are too short, which also clears `plaintext`, and output buffers of the wrong size.
fn check_decrypt_lengths(
    ciphertext: &[u8],
    plaintext: &mut [u8],
    expansion: usize,
) -> Result<(), Error> {
    if ciphertext.len() < HEAD_LENGTH + expansion {
        plaintext.fill(0);
        return Err(Error::AuthenticationFailed);
    }
    if plaintext.len() + expansion != ciphertext.len() {
        return Err(Error::OutputLengthMismatch);
    }
    Ok(())
}

/// EtES-HCENC, authenticated encryption built from HCENC with the two-stage key derivation.
///
/// It adds 16 zero bytes after the first 32 bytes of the message, and decryption checks that they are still zero.
/// The ciphertext is 16 bytes longer than the message.
///
/// It commits to the key, but only up to about 60 bits.
/// Use [`UcxHcenc`] for stronger commitment.
/// Reusing a nonce only reveals whether two messages with the same associated data are equal.
pub struct EtesHcenc<const FRAME_WIDTH: u64 = DEFAULT_FRAME_WIDTH, const NONCE_LENGTH: usize = 16> {
    mode: Hcenc<FRAME_WIDTH>,
}

/// EtES-HCENC with the recommended frame width and a 16-byte nonce.
#[allow(non_camel_case_types)]
pub type EtesHcenc_128 = EtesHcenc<DEFAULT_FRAME_WIDTH, 16>;

impl<const FRAME_WIDTH: u64, const NONCE_LENGTH: usize> EtesHcenc<FRAME_WIDTH, NONCE_LENGTH> {
    /// Master key length in bytes.
    pub const KEY_LENGTH: usize = 32;

    /// Nonce length in bytes.
    pub const NONCE_LENGTH: usize = NONCE_LENGTH;

    /// How much longer the ciphertext is than the message.
    pub const CIPHERTEXT_EXPANSION: usize = TAG_LENGTH;

    /// Minimum message length in bytes.
    pub const MIN_INPUT_LENGTH: usize = HEAD_LENGTH;

    /// Creates a cipher from a 32-byte key.
    pub fn new(key: &[u8]) -> Self {
        Self {
            mode: Hcenc::new_two_stage(key),
        }
    }

    /// Encrypts `plaintext` into `ciphertext`, which must be `CIPHERTEXT_EXPANSION` bytes longer.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        self.mode
            .encrypt_with_tag(plaintext, &[0; TAG_LENGTH], [nonce, ad], ciphertext)
    }

    /// Decrypts `ciphertext` into `plaintext`, which must be `CIPHERTEXT_EXPANSION` bytes shorter.
    ///
    /// Returns `Error::AuthenticationFailed` if the ciphertext is not valid, and clears `plaintext`.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        ad: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        check_decrypt_lengths(ciphertext, plaintext, Self::CIPHERTEXT_EXPANSION)?;
        let (head, tail) = ciphertext.split_at(HEAD_LENGTH);
        self.mode.decrypt_with_tag(
            head.try_into().unwrap(),
            [tail, &[]],
            [nonce, ad],
            plaintext,
        )
    }
}

/// UCX-HCENC, authenticated encryption that commits to the key, and with `COMMIT_ALL` to all the inputs.
///
/// It encrypts with EtES-HCENC, then runs the last 127 bits of the ciphertext through two AES-256 calls.
/// The master key is an AES-256 key, and the ciphertext is 32 bytes longer than the message.
///
/// Each message costs two AES-256 calls on top of HCENC, and with `COMMIT_ALL` also a KMAC256 and an AES-256 key schedule.
/// Reusing a nonce only reveals whether two messages with the same associated data are equal.
pub struct UcxHcenc<
    const COMMIT_ALL: bool,
    const FRAME_WIDTH: u64 = DEFAULT_FRAME_WIDTH,
    const NONCE_LENGTH: usize = 16,
> {
    mode: Hcenc<FRAME_WIDTH>,
    concealer: Concealer,
}

/// UCX-HCENC that commits to the key, with 116 bits of security.
#[allow(non_camel_case_types)]
pub type UcxHcenc_Cmt1 = UcxHcenc<false>;

/// UCX-HCENC that commits to the key, the nonce, the associated data and the message, with 116 bits of security.
#[allow(non_camel_case_types)]
pub type UcxHcenc_Cmt4 = UcxHcenc<true>;

enum Concealer {
    Fixed(Aes256Enc),
    /// KMAC256 with the key already absorbed.
    Kmac(CShake256),
}

impl<const COMMIT_ALL: bool, const FRAME_WIDTH: u64, const NONCE_LENGTH: usize>
    UcxHcenc<COMMIT_ALL, FRAME_WIDTH, NONCE_LENGTH>
{
    /// Master key length in bytes.
    pub const KEY_LENGTH: usize = 32;

    /// Nonce length in bytes.
    pub const NONCE_LENGTH: usize = NONCE_LENGTH;

    /// How much longer the ciphertext is than the message.
    pub const CIPHERTEXT_EXPANSION: usize = TAG_LENGTH + BLOCK_LENGTH;

    /// Minimum message length in bytes.
    pub const MIN_INPUT_LENGTH: usize = HEAD_LENGTH;

    /// Creates a cipher from a 32-byte AES-256 key.
    pub fn new(key: &[u8]) -> Self {
        let master = Aes256Enc::new_from_slice(key).expect("UCX-HCENC needs a 32-byte key");
        let derived: [Block; 4] = core::array::from_fn(|i| {
            let mut block = [0u8; BLOCK_LENGTH];
            block[0] = i as u8;
            aes_encrypt(&master, &block)
        });
        let kc = join_head(&derived[0], &derived[1]);
        let ke = join_head(&derived[2], &derived[3]);
        let concealer = if COMMIT_ALL {
            let mut kmac = CShake256::new_with_function_name(b"KMAC", b"");
            // bytepad(encode_string(KC), 136) from NIST SP 800-185, for a 32-byte key.
            let mut key_block = [0u8; 136];
            key_block[..5].copy_from_slice(&[1, 136, 2, 1, 0]);
            key_block[5..37].copy_from_slice(&kc);
            kmac.update(&key_block);
            Concealer::Kmac(kmac)
        } else {
            Concealer::Fixed(Aes256Enc::new(&kc.into()))
        };
        Self {
            mode: Hcenc::new(&ke),
            concealer,
        }
    }

    /// Encrypts `plaintext` into `ciphertext`, which must be `CIPHERTEXT_EXPANSION` bytes longer.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        if ciphertext.len() != plaintext.len() + Self::CIPHERTEXT_EXPANSION {
            return Err(Error::OutputLengthMismatch);
        }
        let (base, _) = ciphertext.split_at_mut(plaintext.len() + TAG_LENGTH);
        self.mode
            .encrypt_with_tag(plaintext, &[0; TAG_LENGTH], [nonce, ad], base)?;

        // The first bit of the last 16 bytes stays, and the 127 bits after it are replaced with the 255 bits of the concealer.
        let window = &mut ciphertext[plaintext.len()..];
        let last = u128::from_le_bytes(window[..BLOCK_LENGTH].try_into().unwrap());
        let (a, b) = feistel(&self.concealer_key(ad, nonce), last >> 1);
        window[..BLOCK_LENGTH].copy_from_slice(&((last & 1) | (a << 1)).to_le_bytes());
        window[BLOCK_LENGTH..].copy_from_slice(&((a >> 127) | (b << 1)).to_le_bytes());
        Ok(())
    }

    /// Decrypts `ciphertext` into `plaintext`, which must be `CIPHERTEXT_EXPANSION` bytes shorter.
    ///
    /// Returns `Error::AuthenticationFailed` if the ciphertext is not valid, and clears `plaintext`.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        ad: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        plaintext: &mut [u8],
    ) -> Result<(), Error> {
        check_decrypt_lengths(ciphertext, plaintext, Self::CIPHERTEXT_EXPANSION)?;
        let (body, window) = ciphertext.split_at(plaintext.len());
        let low = u128::from_le_bytes(window[..BLOCK_LENGTH].try_into().unwrap());
        let high = u128::from_le_bytes(window[BLOCK_LENGTH..].try_into().unwrap());
        let Some(d) = feistel_inverse(
            &self.concealer_key(ad, nonce),
            (low >> 1) | (high << 127),
            high >> 1,
        ) else {
            plaintext.fill(0);
            return Err(Error::AuthenticationFailed);
        };
        let last = ((low & 1) | (d << 1)).to_le_bytes();
        let (head, tail) = body.split_at(HEAD_LENGTH);
        self.mode.decrypt_with_tag(
            head.try_into().unwrap(),
            [tail, &last],
            [nonce, ad],
            plaintext,
        )
    }

    fn concealer_key(&self, ad: &[u8], nonce: &[u8; NONCE_LENGTH]) -> Aes256Enc {
        match &self.concealer {
            Concealer::Fixed(aes) => aes.clone(),
            Concealer::Kmac(kmac) => {
                let mut kmac = kmac.clone();
                kmac.update(nonce);
                kmac.update(ad);
                // right_encode(256), the output length in bits.
                kmac.update(&[1, 0, 2]);
                let mut kappa = [0u8; 32];
                kmac.finalize_xof_into(&mut kappa);
                Aes256Enc::new(&kappa.into())
            }
        }
    }
}

fn davies_meyer(aes: &Aes256Enc, x: u128) -> u128 {
    u128::from_le_bytes(aes_encrypt(aes, &x.to_le_bytes())) ^ x
}

const TOP_BIT: u128 = 1 << 127;

/// The paper's Feistel concealer, which turns 127 bits into A (128 bits) and B (127 bits).
fn feistel(aes: &Aes256Enc, d: u128) -> (u128, u128) {
    let b = davies_meyer(aes, d) & !TOP_BIT;
    let a = davies_meyer(aes, b | TOP_BIT) ^ d;
    (a, b)
}

/// Returns `None` if A and B didn't come from `feistel` under this key.
fn feistel_inverse(aes: &Aes256Enc, a: u128, b: u128) -> Option<u128> {
    let x = a ^ davies_meyer(aes, b | TOP_BIT);
    let r = (b ^ davies_meyer(aes, x & !TOP_BIT)) & !TOP_BIT;
    if (x & TOP_BIT) | r != 0 {
        return None;
    }
    Some(x)
}

fn split_key(key: &[u8]) -> (Block, Block) {
    split_head(key.try_into().expect("HCENC needs a 32-byte key"))
}

fn split_head(x: &[u8; HEAD_LENGTH]) -> (Block, Block) {
    (
        x[..BLOCK_LENGTH].try_into().unwrap(),
        x[BLOCK_LENGTH..].try_into().unwrap(),
    )
}

fn join_head(a: &Block, b: &Block) -> [u8; HEAD_LENGTH] {
    let mut out = [0u8; HEAD_LENGTH];
    out[..BLOCK_LENGTH].copy_from_slice(a);
    out[BLOCK_LENGTH..].copy_from_slice(b);
    out
}

fn xor_heads(a: &[u8; HEAD_LENGTH], b: &[u8; HEAD_LENGTH]) -> [u8; HEAD_LENGTH] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

fn aes_encrypt(
    aes: &impl BlockCipherEncrypt<BlockSize = aes::cipher::consts::U16>,
    block: &Block,
) -> Block {
    let mut b = (*block).into();
    aes.encrypt_block(&mut b);
    b.into()
}

/// Multiplication by x in the POLYVAL field.
fn mul_x(a: &Block) -> Block {
    polyval::hazmat::FieldElement::from(*a).mulx().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Decoder, Hex};

    fn sequence(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    /// Equation (2) of the paper, one block at a time.
    fn naive_keystream<const W: u64>(key: &Block, mask: &Block, out: &mut [u8]) {
        let aes = Aes128Enc::new(&(*key).into());
        let mask = u128::from_le_bytes(*mask);
        for (j, chunk) in out.chunks_mut(BLOCK_LENGTH).enumerate() {
            let j = j as u64;
            let anchor = aes_encrypt(&aes, &(mask ^ u128::from((W + 1) * (j / W))).to_le_bytes());
            let leaf = aes_encrypt(&aes, &(mask ^ u128::from(j + j / W + 1)).to_le_bytes());
            for ((o, a), l) in chunk.iter_mut().zip(anchor).zip(leaf) {
                *o = a ^ l;
            }
        }
    }

    fn check_keystream<const W: u64>() {
        let key: Block = core::array::from_fn(|i| i as u8);
        let mask: Block = core::array::from_fn(|i| if i < 8 { 0xa5 } else { 0x3c });
        let zeros = [0u8; 1000];
        for len in [1, 15, 16, 17, 96, 97, 200, 1000] {
            let mut expected = vec![0u8; len];
            naive_keystream::<W>(&key, &mask, &mut expected);
            for step in [1000, 1, 5, 16, 33, 100] {
                let mut keystream = Keystream::<W>::new(&key, &mask);
                let mut actual = vec![0u8; len];
                for (i, chunk) in actual.chunks_mut(step).enumerate() {
                    keystream.apply(chunk, &zeros[i * step..i * step + chunk.len()]);
                }
                assert_eq!(expected, actual, "w {W} len {len} step {step}");
            }
        }
    }

    #[test]
    fn test_hcenc_keystream_matches_the_paper() {
        check_keystream::<1>();
        check_keystream::<2>();
        check_keystream::<3>();
        check_keystream::<31>();
        check_keystream::<32>();
        check_keystream::<33>();
        check_keystream::<4096>();
    }

    trait Aead {
        const EXPANSION: usize;
        const NONCE: usize;
        fn seal(&self, m: &[u8], ad: &[u8], nonce: &[u8], c: &mut [u8]) -> Result<(), Error>;
        fn open(&self, c: &[u8], ad: &[u8], nonce: &[u8], m: &mut [u8]) -> Result<(), Error>;
    }

    impl<const W: u64, const N: usize> Aead for EtesHcenc<W, N> {
        const EXPANSION: usize = Self::CIPHERTEXT_EXPANSION;
        const NONCE: usize = N;
        fn seal(&self, m: &[u8], ad: &[u8], nonce: &[u8], c: &mut [u8]) -> Result<(), Error> {
            self.encrypt(m, ad, nonce.try_into().unwrap(), c)
        }
        fn open(&self, c: &[u8], ad: &[u8], nonce: &[u8], m: &mut [u8]) -> Result<(), Error> {
            self.decrypt(c, ad, nonce.try_into().unwrap(), m)
        }
    }

    impl<const C: bool, const W: u64, const N: usize> Aead for UcxHcenc<C, W, N> {
        const EXPANSION: usize = Self::CIPHERTEXT_EXPANSION;
        const NONCE: usize = N;
        fn seal(&self, m: &[u8], ad: &[u8], nonce: &[u8], c: &mut [u8]) -> Result<(), Error> {
            self.encrypt(m, ad, nonce.try_into().unwrap(), c)
        }
        fn open(&self, c: &[u8], ad: &[u8], nonce: &[u8], m: &mut [u8]) -> Result<(), Error> {
            self.decrypt(c, ad, nonce.try_into().unwrap(), m)
        }
    }

    fn check_rejects_forgeries<A: Aead>(aead: &A) {
        let nonce = sequence(A::NONCE);
        let mut other_nonce = nonce.clone();
        other_nonce[0] ^= 1;
        let message = sequence(300);
        let failed = Err(Error::AuthenticationFailed);
        for len in [32, 33, 63, 300] {
            let mut ct = vec![0u8; len + A::EXPANSION];
            let mut m = vec![0u8; len];
            aead.seal(&message[..len], b"ad", &nonce, &mut ct).unwrap();
            for pos in [0, 32, 47, ct.len() - 17, ct.len() - 16, ct.len() - 1] {
                ct[pos] ^= 0x80;
                assert_eq!(aead.open(&ct, b"ad", &nonce, &mut m), failed);
                assert!(m.iter().all(|&b| b == 0));
                ct[pos] ^= 0x80;
            }
            assert_eq!(aead.open(&ct, b"", &nonce, &mut m), failed);
            assert_eq!(aead.open(&ct, b"ad", &other_nonce, &mut m), failed);
        }
        let mut ct = vec![0u8; 31 + A::EXPANSION];
        assert_eq!(
            aead.seal(&message[..31], b"", &nonce, &mut ct),
            Err(Error::InputTooShort)
        );
        let mut m = [0xaau8; 31];
        assert_eq!(aead.open(&ct, b"", &nonce, &mut m), failed);
        assert_eq!(m, [0u8; 31]);
    }

    #[test]
    fn test_hcenc_rejects_bad_inputs() {
        let cipher = Hcenc_128::new(&sequence(32));
        let message = sequence(33);
        assert_eq!(
            cipher.encrypt(&message[..31], b"", &mut [0u8; 31]),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            cipher.decrypt(&message[..31], b"", &mut [0u8; 31]),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            cipher.encrypt(&message[..32], b"", &mut [0u8; 33]),
            Err(Error::OutputLengthMismatch)
        );

        check_rejects_forgeries(&EtesHcenc_128::new(&sequence(32)));
        check_rejects_forgeries(&EtesHcenc::<2, 12>::new(&sequence(32)));
        check_rejects_forgeries(&UcxHcenc_Cmt1::new(&sequence(32)));
        check_rejects_forgeries(&UcxHcenc_Cmt4::new(&sequence(32)));
    }

    fn assert_mode<const W: u64>(cipher: &Hcenc<W>, tweak: &[u8], ciphertext_hex: &str) {
        let expected = Hex::decode_to_vec(ciphertext_hex, None).unwrap();
        let message = sequence(expected.len());
        let mut output = vec![0u8; message.len()];
        cipher.encrypt(&message, tweak, &mut output).unwrap();
        assert_eq!(expected, output);
        let mut decrypted = vec![0u8; message.len()];
        cipher.decrypt(&output, tweak, &mut decrypted).unwrap();
        assert_eq!(message, decrypted);
    }

    fn assert_aead<A: Aead>(aead: &A, ad: &[u8], ciphertext_hex: &str) {
        let expected = Hex::decode_to_vec(ciphertext_hex, None).unwrap();
        let message = sequence(expected.len() - A::EXPANSION);
        let nonce: Vec<u8> = (0x40..0x50).collect();
        let mut output = vec![0u8; expected.len()];
        aead.seal(&message, ad, &nonce, &mut output).unwrap();
        assert_eq!(expected, output);
        let mut decrypted = vec![0u8; message.len()];
        aead.open(&output, ad, &nonce, &mut decrypted).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_hcenc_known_answers() {
        // Same vectors as zig-hctr2, checked against an independent Python implementation.
        // The key is 00 01 02 ... 1f, the message is 00 01 02 ..., and the AEAD nonce is 40 41 ... 4f.
        let tweak17: Vec<u8> = (100..117).collect();
        assert_mode(
            &Hcenc_128::new(&sequence(32)),
            b"",
            "398e436b918bad34189ed9393ab8de1ca6c878cb860b0fc44f2981c109bc571f",
        );
        assert_mode(
            &Hcenc_128::new(&sequence(32)),
            b"",
            "c97bb9ae0f5a06884715e3f7409008d425c336bd21f763f50b1aa936c48ddad640",
        );
        assert_mode(
            &Hcenc_128::new(&sequence(32)),
            b"",
            "885642823b4b2df9c7756abb8a0b3ca95a17aff851fb72b6e2e330279b146ee0a21f9d578e94f6a79474e52912717bc28b81bc98ffb94b7bf3f888003f3674b4291e6c8ade154b02a8cea10e0a6697ae56cdd111d0374d6cba43225ad7fa2a7c10d69642",
        );
        assert_mode(
            &Hcenc::<1>::new(&sequence(32)),
            &tweak17,
            "b343094e64706207a26c7163034f6e43fd5d0f366ad54e4a03d740717ecfdf91e1231f0d71fd7cdf9523b9e36742185b8820df78f48a7a4eca261e6f3fb13c1804c4d1049f57fb5a9de97740330627f67c37bb6cb6fc7b5e2f65ea35aad5282e4730c3d83c29d12496f18377d668aef25e47453f5e0814273324e6caaa614e8fc3e2ee49d20f27914f40bb7783eb858a381fb5d84faed61e115de9bda30525090c30d61df9d4e2492da08d174152717ea9faa3a011243228e63b4f0b4798ee053285f6a41747db61efb20079f60d259844166d0d8a921e5639bfbedc0abcd98a6cb36bc76624b221575bede5112d51e3c8cd03b36ff801ae6656cb518c9900",
        );
        assert_mode(
            &Hcenc_128::new_two_stage(&sequence(32)),
            b"tweak",
            "3e367781de0ce586a02275ae60b22ea264a3704704b8e6f4cd26e533f5547f5508a24d1a581668bdd05a586d6fe2094b7c9f30a6e548da896594c724a4e0ac",
        );
        assert_mode(
            &Hcenc::<3>::new_two_stage(&sequence(32)),
            b"tweak",
            "8cc07aa176898e307218b2a19b9d904159aa8e4219312b6001eaefff0132e19f0b950eeb1c74e227b83bd735af7687b5f79231cb44f4a5cf8da3407a395c763a310be69f89f6153056036a6f7e8f7f4e4d9870d97fa1d082014dc269442b8c449ad231a64d2c8ac226dbad38733f82007482cf34796bd741281aef26fbda935bdad407824f3ba37c7546ea506e816f899cc8ab41d56a6ebeff5565970936d918ad2ae9681bb7f3b698921b09262eaa72e5cf399b1b7fc1d75e16942a0af6af8b1bbea15561",
        );
        assert_aead(
            &EtesHcenc_128::new(&sequence(32)),
            b"",
            "aa8271dce4da49f52a74790add3ef96f43572fd4b3bc291b6f0059dc54dd0d6950e86292822d20ed49c171694e504fb7",
        );
        assert_aead(
            &EtesHcenc_128::new(&sequence(32)),
            b"ad",
            "231a3c6e669c870af54ade681b1dc208cf3bbb430754c47653c8ab52a818b8078ff462de3e8616950b07252f705bc4ae82d45919012cd569fa8b4b337a47b9959db6cd33cdf5009ce4a0f104d846cde9eeb5ff6f644d3e103e9f6c02bf494ec6bb5e9a2831b9abd3baefe2e0eb3cb0452ee6d787",
        );
        assert_aead(
            &UcxHcenc_Cmt1::new(&sequence(32)),
            b"",
            "d3b0528f62d1c20d620db67fcc6665e8d5c3da61bee744f982d6913ef7e6b0e5b8dda4c079ec735f0ff1ae834821d653423713e3206482f80fb43b1d9caa6088",
        );
        assert_aead(
            &UcxHcenc_Cmt1::new(&sequence(32)),
            b"associated data",
            "bef202ab397690c4611ff1c1e1facdd0f71e0a5844eb86ea569946beab1a5281a88971fa0ecfe24ed1c9e42b27c12cbfe733ef81da9669c30a590379f272d165b9de509d4971395a38b655a513fb3e66c99068078ca438bde85522ab559adafac78ae87e1a9c54bad560ad85157b1064f4284cb96de27321c30e5ea468f58ead51218e1261895e3b563876fba5b116576010cecacc7c420ec76955559682ae78cd82a36f76d964076ba6afbd50631c329d2438f314c8dd1ff801ffbabd9675f5f0bab03f6932c4412b6787314833f8b0ed40a75cc6fd2cf1dda40062482a3c6b6cc8e744be813177f2b13e4d4233d8fbd1e735acf691ec6e97db3abfe1eb9c420fe0944270376cb9b136661f0c9ac611b1c1de6e107e7150d4743da1df09e4",
        );
        assert_aead(
            &UcxHcenc_Cmt4::new(&sequence(32)),
            b"",
            "8a5cb7ee0cfd33cd3e320addaf5d40ee1d7707a08d2a81e4139ff6b3b92be15c5a345691c87bc9d5f4f673d6f17c641490a40814b28a5d0ed29a569bdc5e4e98b4",
        );
        assert_aead(
            &UcxHcenc_Cmt4::new(&sequence(32)),
            b"associated data",
            "3808405a13f34e40aeddeb862eeccc6108e264f317388802a92c4b0a909331540712b2033130952726ae000269dbc04f368169943babffb9593b91d7f9c274825867aefdca52b6b5569f52012ad35bbb19f76ec7c906d3de8b6fc61b110594f2f01bf9da05159a9663016f8e41e3b9da4b1324092134aea4369b1937a58f4a250f04a28e",
        );
    }
}
