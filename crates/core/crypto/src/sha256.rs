// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SHA-256 hash function (FIPS 180-4).
//!
//! Pure software, no_std, no allocations. Processes data in 64-byte blocks.

// ---------------------------------------------------------------------------
// Constants (FIPS 180-4 §4.2.2)
// ---------------------------------------------------------------------------

/// Round constants K[0..63].
static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash values H0 (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Block size in bytes (512 bits).
const BLOCK_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A partial block, 8-aligned so the word loads take their aligned path.
#[repr(C, align(8))]
struct Block([u8; BLOCK_SIZE]);

/// SHA-256 digest (32 bytes).
pub type Digest = [u8; 32];

/// Incremental SHA-256 hasher.
pub struct Sha256 {
    state: [u32; 8],
    buf:   Block,
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher.
    pub const fn new() -> Self {
        Self {
            state: H0,
            buf: Block([0u8; BLOCK_SIZE]),
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // Fill buffer first
        if self.buf_len > 0 {
            let space = BLOCK_SIZE - self.buf_len;
            let take = data.len().min(space);
            self.buf.0[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;

            if self.buf_len == BLOCK_SIZE {
                compress_blocks(&mut self.state, &self.buf.0);
                self.buf_len = 0;
            }
        }

        let whole = (data.len() - offset) / BLOCK_SIZE * BLOCK_SIZE;
        if whole > 0 {
            compress_blocks(&mut self.state, &data[offset..offset + whole]);
            offset += whole;
        }

        // Buffer remainder
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf.0[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the 32-byte digest.
    pub fn finalize(mut self) -> Digest {
        let bit_len = self.total_len * 8;

        // Pad in place: 0x80, zeros, then the 64-bit big-endian bit length,
        // in a second block when fewer than 8 bytes are left after 0x80.
        let n = self.buf_len;
        self.buf.0[n] = 0x80;
        self.buf.0[n + 1..].fill(0);
        if n >= BLOCK_SIZE - 8 {
            compress_blocks(&mut self.state, &self.buf.0);
            self.buf.0 = [0u8; BLOCK_SIZE];
        }
        self.buf.0[BLOCK_SIZE - 8..].copy_from_slice(&bit_len.to_be_bytes());
        compress_blocks(&mut self.state, &self.buf.0);

        // Produce output
        let mut digest = [0u8; 32];
        for i in 0..8 {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }
}

/// One-shot SHA-256: hash `data` and return the 32-byte digest.
pub fn sha256(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Block dispatch (wave 13): the CPU's SHA-2 instructions when it has them
// ---------------------------------------------------------------------------
//
// `select_*` runs once at boot on what the CPU reports (ID registers, device
// tree: the vDSO hwcap inputs), never on build flags, and keeps a path only
// after it reproduces the FIPS 180-4 "abc" digest and the generic code's
// digests over several lengths and both alignments.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

static MODE: AtomicU8 = AtomicU8::new(MODE_GENERIC);
const MODE_GENERIC: u8 = 0;
const MODE_ZBB: u8 = 1;
const MODE_ZKNH: u8 = 2;
const MODE_HOOK: u8 = 3;
/// `MODE_HOOK`'s function.
static HOOK: AtomicUsize = AtomicUsize::new(0);

/// A whole-blocks function a platform registers with [`select_hook`]:
/// `(state, blocks)`, `blocks.len()` a multiple of 64.
pub type BlocksFn = fn(&mut [u32; 8], &[u8]);

/// Name of the block function in use: `generic`, `zbb`, `zknh` or `hook`.
pub fn backend() -> &'static str {
    match MODE.load(Ordering::Relaxed) {
        MODE_ZBB => "zbb",
        MODE_ZKNH => "zknh",
        MODE_HOOK => "hook",
        _ => "generic",
    }
}

fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    match MODE.load(Ordering::Relaxed) {
        MODE_HOOK => {
            // SAFETY: only `select_hook` stores here, a `BlocksFn`, before it
            // publishes MODE_HOOK.
            let f: BlocksFn = unsafe { core::mem::transmute::<usize, BlocksFn>(HOOK.load(Ordering::Relaxed)) };
            f(state, blocks);
        }
        // SAFETY (both riscv arms): set only by `select_riscv`, after cpu@0
        // declared the extension and the path passed the self-test.
        #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
        MODE_ZBB => unsafe { rv::blocks_zbb(state, blocks) },
        #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
        MODE_ZKNH => unsafe { rv::blocks_zknh(state, blocks) },
        _ => blocks_generic(state, blocks),
    }
}

/// "abc", FIPS 180-4 B.1.
const ABC_DIGEST: Digest = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

/// FIPS 180-4 / NIST CAVP two-block messages (56 and 112 bytes) and 1,000
/// bytes of `(i * 31 + 7) mod 256`, with digests computed off-target
/// (Python hashlib): known answers that do not come from this file's
/// template, so a bug shared by the fast and the generic path still fails.
const KAT_56: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const KAT_56_DIGEST: Digest = [
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
];
const KAT_112: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
const KAT_112_DIGEST: Digest = [
    0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
    0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1,
];
const KAT_PATTERN_LEN: usize = 1000;
const KAT_PATTERN_DIGEST: Digest = [
    0x50, 0x97, 0xe7, 0xd5, 0x87, 0x35, 0x2f, 0x50, 0x97, 0x06, 0x2a, 0xe6, 0x79, 0xf3, 0x7b, 0xda,
    0x58, 0x02, 0xd9, 0xf8, 0x75, 0xab, 0xa1, 0x4c, 0x8c, 0xb4, 0xd1, 0xa1, 0x88, 0xad, 0xa1, 0x79,
];

/// The self-test buffer, 8-aligned so that offsets 0, 4 and 1 give an
/// 8-aligned, a 4-aligned and an odd start.
#[repr(align(8))]
struct TestMsg([u8; KAT_PATTERN_LEN + 8]);

/// `want` for `msg`, one-shot and fed in uneven `update` pieces (a partial
/// buffer fill, whole blocks from the input, a block straddling the buffer).
fn known_answer(msg: &[u8], want: &Digest) -> bool {
    if sha256(msg) != *want {
        return false;
    }
    const STEPS: [usize; 5] = [1, 63, 64, 65, 7];
    let mut h = Sha256::new();
    let mut rest = msg;
    let mut i = 0;
    while !rest.is_empty() {
        let k = STEPS[i % STEPS.len()].min(rest.len());
        h.update(&rest[..k]);
        rest = &rest[k..];
        i += 1;
    }
    h.finalize() == *want
}

/// The selected path against known answers ("abc"; the 56- and 112-byte
/// FIPS messages and a 1,000-byte message, each at an 8-aligned, a
/// 4-aligned and an odd start, one-shot and streamed), then against the
/// generic code on the padding boundaries (55/56: one or two final blocks;
/// 63/64/65: around a whole block) at the same three starts.
fn self_test() -> bool {
    if sha256(b"abc") != ABC_DIGEST {
        return false;
    }
    let mut msg = TestMsg([0u8; KAT_PATTERN_LEN + 8]);
    let pattern = |b: &mut [u8]| {
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
    };
    for off in [0usize, 4, 1] {
        for (m, want) in [(KAT_56, &KAT_56_DIGEST), (KAT_112, &KAT_112_DIGEST)] {
            msg.0[off..off + m.len()].copy_from_slice(m);
            if !known_answer(&msg.0[off..off + m.len()], want) {
                return false;
            }
        }
        pattern(&mut msg.0[off..off + KAT_PATTERN_LEN]);
        if !known_answer(&msg.0[off..off + KAT_PATTERN_LEN], &KAT_PATTERN_DIGEST) {
            return false;
        }
    }
    pattern(&mut msg.0);
    for len in [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 200] {
        for off in [0usize, 4, 1] {
            let m = &msg.0[off..off + len];
            let fast = sha256(m);
            let mode = MODE.swap(MODE_GENERIC, Ordering::Relaxed);
            let slow = sha256(m);
            MODE.store(mode, Ordering::Relaxed);
            if fast != slow {
                return false;
            }
        }
    }
    true
}

/// Install a platform block function (aarch64: the ARMv8 SHA-2
/// instructions, wrapped by the kernel so the SIMD registers are free). Kept
/// only if it passes the self-test; returns whether it did. Boot only,
/// before anything else hashes.
pub fn select_hook(f: BlocksFn) -> bool {
    HOOK.store(f as usize, Ordering::Relaxed);
    MODE.store(MODE_HOOK, Ordering::Release);
    if self_test() {
        return true;
    }
    MODE.store(MODE_GENERIC, Ordering::Release);
    false
}

/// riscv64: Zknh, else Zbb, else generic, from what cpu@0 declares. Returns
/// the backend kept. Boot only, before anything else hashes.
#[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
pub fn select_riscv(zbb: bool, zknh: bool) -> &'static str {
    // Zknh's path is compiled with Zbb on as well (rev8 word loads, and the
    // code generator may pick other Zbb forms), so it needs both.
    for (on, mode) in [(zknh && zbb, MODE_ZKNH), (zbb, MODE_ZBB)] {
        if on {
            MODE.store(mode, Ordering::Release);
            if self_test() {
                return backend();
            }
        }
    }
    MODE.store(MODE_GENERIC, Ordering::Release);
    backend()
}

/// `no-bitmanip` boards: no Zbb/Zknh code exists in the image; generic only.
#[cfg(all(target_arch = "riscv64", feature = "no-bitmanip"))]
pub fn select_riscv(_zbb: bool, _zknh: bool) -> &'static str {
    backend()
}

// ---------------------------------------------------------------------------
// Compression function (FIPS 180-4 §6.2.2)
// ---------------------------------------------------------------------------
//
// One template, `blocks_with`, instantiated per path. What makes it fast
// (wave 14, rv64 instructions a block: Zbb 3,006 -> 2,362, Zknh 2,431 ->
// 1,463, generic 4,188 -> 3,007):
// - fully unrolled with constant indices: no round counter, no bounds or
//   overflow checks;
// - two passes a block (see `blocks_with`), so neither pass spills;
// - the block loop runs inside the (target-feature) function, so the
//   prologue is paid once per call;
// - `maj` as `b ^ ((a ^ b) & (b ^ c))`, carrying this round's `a ^ b` as the
//   next round's `b ^ c`; `ch` as `g ^ (e & (f ^ g))`: three ops each;
// - word loads (a u64 at a time when 8-aligned, a u32 when 4-aligned);
// - K read through an opaque pointer: one load, not a two-instruction
//   immediate.

/// How the four sigma functions are computed.
const SIG_ROT: u8 = 0; // `rotate_right`: a native rotate (aarch64, x86, riscv64 Zbb)
const SIG_DUP: u8 = 1; // riscv64 without Zbb: 64-bit duplicate, see `dup`
#[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
const SIG_ZKNH: u8 = 2; // riscv64 Zknh: one instruction each

/// How message words are loaded.
const LOAD_BYTES: u8 = 0; // four bytes per word (any alignment)
const LOAD_WIDE: u8 = 1; // byte-swapped u64 (8-aligned) or u32 (4-aligned) loads
const LOAD_SWAR: u8 = 2; // u64 + two mask-shift swaps per two words, 8- or 4-aligned (no rev8)

/// The generic path: what runs without SHA-2 or rotate instructions, and on
/// `no-bitmanip` boards (VF2).
#[inline(never)]
fn blocks_generic(state: &mut [u32; 8], blocks: &[u8]) {
    #[cfg(target_arch = "riscv64")]
    blocks_with::<SIG_DUP, LOAD_SWAR>(state, blocks);
    #[cfg(not(target_arch = "riscv64"))]
    blocks_with::<SIG_ROT, LOAD_BYTES>(state, blocks);
}

/// The riscv64 generic sigma arithmetic (64-bit duplicate), callable on any
/// target so the host tests run it against the FIPS vectors (install it with
/// [`select_hook`]). Not an API.
#[doc(hidden)]
pub fn blocks_dup64(state: &mut [u32; 8], blocks: &[u8]) {
    blocks_with::<SIG_DUP, LOAD_SWAR>(state, blocks);
}

/// The Zbb/Zknh word loads (u64 + byte swap when aligned) with portable
/// rotates, for the same host tests. Not an API.
#[doc(hidden)]
pub fn blocks_wide(state: &mut [u32; 8], blocks: &[u8]) {
    blocks_with::<SIG_ROT, LOAD_WIDE>(state, blocks);
}

#[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
mod rv {
    use super::*;

    /// The template compiled with Zbb: each `rotate_right` is one `roriw`
    /// (rv64imac has no rotate), each aligned u64 swap one `rev8`.
    #[target_feature(enable = "zbb")]
    pub(super) unsafe fn blocks_zbb(state: &mut [u32; 8], blocks: &[u8]) {
        blocks_with::<SIG_ROT, LOAD_WIDE>(state, blocks)
    }

    /// Zknh: the four sigma functions are one instruction each.
    #[target_feature(enable = "zbb")]
    pub(super) unsafe fn blocks_zknh(state: &mut [u32; 8], blocks: &[u8]) {
        blocks_with::<SIG_ZKNH, LOAD_WIDE>(state, blocks)
    }

    macro_rules! zknh_op {
        ($name:ident, $insn:literal) => {
            #[inline(always)]
            pub(super) fn $name(x: u32) -> u32 {
                let r: u32;
                // SAFETY: a register-only Zknh instruction, reached only
                // after `select_riscv` saw the extension declared. It reads
                // bits 31:0 only, so `x` goes in as a 32-bit operand (no
                // zero-extension: two instructions per call saved).
                unsafe {
                    core::arch::asm!(".option push", ".option arch, +zknh", concat!($insn, " {0}, {1}"), ".option pop",
                        out(reg) r, in(reg) x, options(pure, nomem, nostack));
                }
                r
            }
        };
    }
    zknh_op!(sum0, "sha256sum0");
    zknh_op!(sum1, "sha256sum1");
    zknh_op!(sig0, "sha256sig0");
    zknh_op!(sig1, "sha256sig1");
}

/// The sixteen big-endian message words of `block`. `align` is the
/// block's address mod 8 (the same for every block of one call): 0 and 4
/// take word loads, anything else four byte loads a word.
#[inline(always)]
fn load_words<const LOAD: u8>(block: &[u8; BLOCK_SIZE], align: usize) -> [u32; 16] {
    let mut w = [0u32; 16];
    if LOAD == LOAD_BYTES || align & 3 != 0 {
        macro_rules! be {
            ($($i:literal)*) => {$(
                w[$i] = u32::from_be_bytes([block[$i * 4], block[$i * 4 + 1], block[$i * 4 + 2], block[$i * 4 + 3]]);
            )*};
        }
        be!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
        return w;
    }
    // SAFETY (every read below): `align` says `block` starts 8-aligned (0)
    // or 4-aligned (4), the read is of that width or narrower, and all 64
    // bytes are in bounds.
    if LOAD == LOAD_WIDE {
        if align == 0 {
            let p = block.as_ptr() as *const u64;
            for i in 0..8 {
                let v = u64::from_be(unsafe { p.add(i).read() });
                w[2 * i] = (v >> 32) as u32;
                w[2 * i + 1] = v as u32;
            }
        } else {
            let p = block.as_ptr() as *const u32;
            for (i, word) in w.iter_mut().enumerate() {
                *word = u32::from_be(unsafe { p.add(i).read() });
            }
        }
        return w;
    }
    // LOAD_SWAR, rv64 without rev8: byte-reverse both 32-bit lanes of a
    // little-endian u64 at once (6 instructions a word when 8-aligned, not
    // 10; a 4-aligned block assembles the u64 from two word loads first).
    const M8: u64 = 0x00ff_00ff_00ff_00ff;
    const M16: u64 = 0x0000_ffff_0000_ffff;
    for i in 0..8 {
        let v = if align == 0 {
            u64::from_le(unsafe { (block.as_ptr() as *const u64).add(i).read() })
        } else {
            let p = block.as_ptr() as *const u32;
            let lo = u32::from_le(unsafe { p.add(2 * i).read() }) as u64;
            let hi = u32::from_le(unsafe { p.add(2 * i + 1).read() }) as u64;
            lo | (hi << 32)
        };
        let v = ((v >> 8) & M8) | ((v & M8) << 8);
        let v = ((v >> 16) & M16) | ((v & M16) << 16);
        w[2 * i] = v as u32;
        w[2 * i + 1] = (v >> 32) as u32;
    }
    w
}

/// Whole blocks into `state`; `blocks.len()` a multiple of 64 (a tail is
/// ignored, as `chunks_exact` did).
///
/// Two passes a block. The message schedule runs first with its 16-word
/// window in registers and stores `W[t] + K[t]` for all 64 rounds; the
/// rounds then hold only the eight working variables and load one word
/// each. A single interleaved pass needs ~30 live values, more than rv64
/// has registers, and the spills cost more than the 64 stores and loads.
#[inline(always)]
fn blocks_with<const SIG: u8, const LOAD: u8>(state: &mut [u32; 8], blocks: &[u8]) {
    let align = blocks.as_ptr() as usize & 7;
    let (chunks, _) = blocks.as_chunks::<BLOCK_SIZE>();
    for block in chunks {
        // Every word is written by the schedule below before it is read; no
        // initialisation (a 256-byte memset a call).
        let mut wk = core::mem::MaybeUninit::<[u32; 64]>::uninit();
        let wp = wk.as_mut_ptr() as *mut u32;
        // Opaque per block: otherwise the 64 loads are hoisted out of the
        // block loop and spilled.
        let k: &[u32; 64] = core::hint::black_box(&K);
        let mut w = load_words::<LOAD>(block, align);
        macro_rules! sched {
            ($t:expr, $i:expr) => {
                if $t >= 16 {
                    w[$i] = sig1::<SIG>(w[($i + 14) & 15])
                        .wrapping_add(w[($i + 9) & 15])
                        .wrapping_add(sig0::<SIG>(w[($i + 1) & 15]))
                        .wrapping_add(w[$i]);
                }
                pin(&mut w[$i]);
                // SAFETY: `$t + $i` < 64, inside `wk`.
                unsafe { wp.add($t + $i).write(w[$i].wrapping_add(k[$t + $i])) };
            };
        }
        macro_rules! sched16 {
            ($t:expr) => {
                sched!($t, 0); sched!($t, 1); sched!($t, 2); sched!($t, 3);
                sched!($t, 4); sched!($t, 5); sched!($t, 6); sched!($t, 7);
                sched!($t, 8); sched!($t, 9); sched!($t, 10); sched!($t, 11);
                sched!($t, 12); sched!($t, 13); sched!($t, 14); sched!($t, 15);
            };
        }
        sched16!(0);
        sched16!(16);
        sched16!(32);
        sched16!(48);
        // The rounds below must load `wk` from memory, not take the stored
        // values from registers (that would be the one-pass shape again).
        barrier(wp);
        // SAFETY: the 64 steps above wrote all 64 words.
        let wk = unsafe { wk.assume_init_ref() };
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        // `x`/`y`: this round's `b ^ c`, written as the next round's.
        let mut x = b ^ c;
        let mut y;
        macro_rules! round {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident,
             $bc:ident, $ab:ident, $t:expr) => {
                let t1 = $h
                    .wrapping_add(sum1::<SIG>($e))
                    .wrapping_add($g ^ ($e & ($f ^ $g)))
                    .wrapping_add(wk[$t]);
                $ab = $a ^ $b;
                let t2 = sum0::<SIG>($a).wrapping_add($b ^ ($ab & $bc));
                $d = $d.wrapping_add(t1);
                $h = t1.wrapping_add(t2);
            };
        }
        macro_rules! rounds8 {
            ($t:expr) => {
                round!(a, b, c, d, e, f, g, h, x, y, $t);
                round!(h, a, b, c, d, e, f, g, y, x, $t + 1);
                round!(g, h, a, b, c, d, e, f, x, y, $t + 2);
                round!(f, g, h, a, b, c, d, e, y, x, $t + 3);
                round!(e, f, g, h, a, b, c, d, x, y, $t + 4);
                round!(d, e, f, g, h, a, b, c, y, x, $t + 5);
                round!(c, d, e, f, g, h, a, b, x, y, $t + 6);
                round!(b, c, d, e, f, g, h, a, y, x, $t + 7);
            };
        }
        rounds8!(0);
        rounds8!(8);
        rounds8!(16);
        rounds8!(24);
        rounds8!(32);
        rounds8!(40);
        rounds8!(48);
        rounds8!(56);
        let _ = y;
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// Keeps a message-schedule word's computation in its step: an empty asm
/// statement (no instruction) that the compiler must order. Without it the
/// unrolled schedule is hoisted and interleaved freely, and the extra live
/// words spill.
#[inline(always)]
fn pin(x: &mut u32) {
    // SAFETY (each arm): an empty template; it only claims to read and
    // write `x`.
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("/* {0} */", inout(reg) *x, options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("/* {0:w} */", inout(reg) *x, options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("/* {0:e} */", inout(reg) *x, options(nomem, nostack, preserves_flags));
    }
}

/// An empty asm statement that may read and write `*m`: the compiler must
/// complete the stores to it before and reload it after.
#[inline(always)]
fn barrier(m: *mut u32) {
    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))]
    // SAFETY: an empty template; the pointer is only named in a comment.
    unsafe {
        core::arch::asm!("/* {0} */", in(reg) m, options(nostack, preserves_flags));
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
    let _ = core::hint::black_box(m);
}

// ---------------------------------------------------------------------------
// SHA-256 sigma functions (FIPS 180-4 §4.1.2)
// ---------------------------------------------------------------------------
//
// SIG_DUP: riscv64 without Zbb has no rotate (each `rotate_right` is three
// instructions). With `y = x:x` (x in both halves of a u64), the low 32 bits
// of `y >> n` are `x` rotated right by `n`, and the three shifts factor into
// two plus one: Σ1 is 8 instructions instead of 11. Written factored so no
// sub-expression is a rotate the code generator would re-expand.

/// `x` in both halves of a u64, and `x` zero-extended.
#[inline(always)]
fn dup(x: u32) -> (u64, u64) {
    let hi = (x as u64) << 32;
    let lo = hi >> 32;
    (hi | lo, lo)
}

/// Σ0 = ROTR2 ^ ROTR13 ^ ROTR22.
#[inline(always)]
fn sum0<const S: u8>(x: u32) -> u32 {
    #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
    if S == SIG_ZKNH {
        return rv::sum0(x);
    }
    if S == SIG_DUP {
        let (y, _) = dup(x);
        return ((y ^ (y >> 11) ^ (y >> 20)) >> 2) as u32;
    }
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Σ1 = ROTR6 ^ ROTR11 ^ ROTR25.
#[inline(always)]
fn sum1<const S: u8>(x: u32) -> u32 {
    #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
    if S == SIG_ZKNH {
        return rv::sum1(x);
    }
    if S == SIG_DUP {
        let (y, _) = dup(x);
        return ((y ^ (y >> 5) ^ (y >> 19)) >> 6) as u32;
    }
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// σ0 = ROTR7 ^ ROTR18 ^ SHR3.
#[inline(always)]
fn sig0<const S: u8>(x: u32) -> u32 {
    #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
    if S == SIG_ZKNH {
        return rv::sig0(x);
    }
    if S == SIG_DUP {
        let (y, lo) = dup(x);
        return (((y ^ (y >> 11)) >> 7) ^ (lo >> 3)) as u32;
    }
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// σ1 = ROTR17 ^ ROTR19 ^ SHR10.
#[inline(always)]
fn sig1<const S: u8>(x: u32) -> u32 {
    #[cfg(all(target_arch = "riscv64", not(feature = "no-bitmanip")))]
    if S == SIG_ZKNH {
        return rv::sig1(x);
    }
    if S == SIG_DUP {
        let (y, lo) = dup(x);
        return (((y ^ (y >> 2)) >> 17) ^ (lo >> 10)) as u32;
    }
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
