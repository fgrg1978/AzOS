// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The allocator engine: Scudo's shape over a small [`Sys`] trait.
//!
//! * **Size classes.** A request up to [`MAX_SMALL`] bytes is served from a
//!   *slot* of one of [`NCLASS`] sizes. A class takes a block of anonymous
//!   memory from the kernel when it runs out (`Config::block_bytes`) and cuts
//!   it into slots; blocks are never returned. Bigger requests get a mapping
//!   of their own, unmapped on free.
//! * **Randomized placement** (`Config::randomize`, needs kernel entropy).
//!   Which free slot an allocation takes (a random one of the first [`HOPS`]
//!   of the class's free list, or one of the fresh slots of a shuffled
//!   window), where a large allocation sits inside its pages, and which
//!   quarantined chunk leaves first.
//! * **Chunk headers.** Every chunk is preceded by 16 bytes: size, class,
//!   state (allocated / quarantined / available), the distance back to the
//!   slot start, and a 32-bit checksum keyed with a secret cookie over the
//!   header and the chunk's own address. A free of a pointer that is not a
//!   chunk, of a chunk already freed (still quarantined, or free), of a
//!   chunk whose header was overwritten, or with the wrong size is a
//!   [`Fault`], reported through [`Sys::fault`], which does not return.
//! * **Quarantine** (`Config::quarantine_bytes`). A freed small chunk is held
//!   back, header in the quarantined state, until the byte budget or the
//!   table is full. With `Config::poison` its first [`POISON_SPAN`] bytes are
//!   filled and checked when it leaves: a write through a stale pointer is a
//!   fault. The free list links are masked with the cookie (safe-linking) and
//!   checked against the block table on every hop.
//! * **Guard pages** (`Config::guard`). Blocks and large allocations are
//!   mapped by [`Sys::map`] between two reserved, unmapped pages.
//!
//! The engine never touches memory it did not get from [`Sys::map`]: a
//! pointer handed to [`Heap::free`] is looked up in the mapping table before
//! anything is read through it.

use core::mem::size_of;

/// Chunk header size, and the allocator's minimum alignment.
pub const HDR: usize = 16;
/// Slot sizes (header included), ascending. Four steps per doubling above 128.
pub const SLOT: [usize; NCLASS] = [
    32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048,
];
pub const NCLASS: usize = 23;
/// Largest slot; a request needing more than this is a large allocation.
pub const MAX_SMALL: usize = 2048;
/// `class` value of a header (and a mapping) that is a large allocation.
pub const LARGE: u8 = 0xff;
/// Free-list hops a random pop chooses among.
pub const HOPS: usize = 8;
/// Fresh slots shuffled together.
pub const FRESH: usize = 16;
/// Bytes of a freed chunk that are filled and checked.
pub const POISON_SPAN: usize = 512;
/// The fill byte.
pub const POISON: u8 = 0xa5;

const ST_AVAIL: u8 = 0;
const ST_ALLOC: u8 = 1;
const ST_QUAR: u8 = 2;

/// What the engine detected. Every one of them is fatal to the program.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// A chunk freed while quarantined or already free.
    DoubleFree,
    /// A pointer that is not a chunk of this heap (foreign, misaligned,
    /// inside a block's tail, or into an unmapped large allocation).
    InvalidFree,
    /// A chunk header whose checksum does not match: overwritten by an
    /// overflow from the chunk before it, or forged.
    HeaderCorrupt,
    /// A freed chunk written through a stale pointer (the poison changed).
    UseAfterFree,
    /// A free list link that does not name a free slot of its class.
    FreelistCorrupt,
    /// `free` told a size that is not the one the chunk was allocated with.
    SizeMismatch,
    /// No kernel entropy and `Config::seed_required`.
    SeedMissing,
}

impl Fault {
    pub const fn name(self) -> &'static str {
        match self {
            Fault::DoubleFree => "double free",
            Fault::InvalidFree => "invalid free",
            Fault::HeaderCorrupt => "chunk header corrupted",
            Fault::UseAfterFree => "write after free",
            Fault::FreelistCorrupt => "free list corrupted",
            Fault::SizeMismatch => "size mismatch on free",
            Fault::SeedMissing => "no kernel entropy",
        }
    }
}

/// What the engine needs from the system. The AzOS implementation is
/// `native::NativeSys`; the host tests model it.
pub trait Sys {
    /// The kernel's page size.
    const PAGE: usize;
    /// `len` bytes (a page multiple) of zeroed read-write memory at a page
    /// aligned address. With `guards`, one reserved unmapped page lies before
    /// and one after it, so a touch there faults; `None` if the system
    /// cannot place them.
    fn map(&mut self, len: usize, guards: bool) -> Option<usize>;
    /// Give back what [`Sys::map`] returned (same `len`, same `guards`).
    fn unmap(&mut self, base: usize, len: usize, guards: bool);
    /// Fill `out` from the kernel entropy pool; `false` if it cannot.
    fn entropy(&mut self, out: &mut [u8]) -> bool;
    /// A one-line diagnostic.
    fn note(&mut self, msg: &[u8]);
    /// Stop the program with a recorded fault. Never returns.
    fn fault(&mut self, kind: Fault, addr: usize) -> !;
}

/// The knobs (Kconfig `USER_ALLOC_*`, read by `native.rs`).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Quarantine budget in slot bytes; 0 = no quarantine.
    pub quarantine_bytes: usize,
    /// Block taken from the system by a size class.
    pub block_bytes: usize,
    pub randomize: bool,
    pub poison: bool,
    pub guard: bool,
    pub seed_required: bool,
}

/// Counters, for the programs' own gates and the tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub allocs: u64,
    pub frees: u64,
    /// Chunks that left quarantine for the free lists.
    pub evictions: u64,
    /// Blocks taken for size classes / large mappings made and unmapped.
    pub blocks: u32,
    pub large_maps: u32,
    pub large_unmaps: u32,
    /// Chunks in quarantine now, and their slot bytes.
    pub quarantined: u32,
    pub quarantined_bytes: usize,
    /// The kernel entropy pool seeded the cookie and the placement.
    pub seeded: bool,
    /// The last fault, set just before [`Sys::fault`] is called.
    pub last_fault: Option<(Fault, usize)>,
}

#[derive(Clone, Copy)]
struct Map {
    base: usize,
    len: usize,
    class: u8,
}

#[derive(Clone, Copy)]
struct Class {
    /// Free list head (a slot start, 0 = empty) and length.
    head: usize,
    free_len: usize,
    /// The unused tail of the current block.
    cur: usize,
    end: usize,
    /// A shuffled window of fresh slots.
    fresh: [usize; FRESH],
    fresh_n: usize,
}

impl Class {
    const EMPTY: Class = Class { head: 0, free_len: 0, cur: 0, end: 0, fresh: [0; FRESH], fresh_n: 0 };
}

#[derive(Clone, Copy)]
struct Hdr {
    size: usize,
    class: u8,
    state: u8,
    front: u32,
}

#[inline]
fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

#[inline]
unsafe fn rd(a: usize) -> u64 {
    (a as *const u64).read()
}

#[inline]
unsafe fn wr(a: usize, v: u64) {
    (a as *mut u64).write(v)
}

/// The smallest class whose slot holds `need` bytes (header included).
fn class_for(need: usize) -> Option<usize> {
    if need > MAX_SMALL {
        return None;
    }
    Some(SLOT.partition_point(|&s| s < need))
}

pub struct Heap<S: Sys, const MAPS: usize, const QN: usize> {
    sys: S,
    cfg: Config,
    ready: bool,
    cookie: u64,
    rng: [u64; 4],
    have_entropy: bool,
    block: usize,
    maps: [Map; MAPS],
    nmaps: usize,
    classes: [Class; NCLASS],
    q: [usize; QN],
    qn: usize,
    qbytes: usize,
    stats: Stats,
}

impl<S: Sys, const MAPS: usize, const QN: usize> Heap<S, MAPS, QN> {
    pub const fn new(sys: S, cfg: Config) -> Self {
        Heap {
            sys,
            cfg,
            ready: false,
            cookie: 0,
            rng: [0; 4],
            have_entropy: false,
            block: 0,
            maps: [Map { base: 0, len: 0, class: 0 }; MAPS],
            nmaps: 0,
            classes: [Class::EMPTY; NCLASS],
            q: [0; QN],
            qn: 0,
            qbytes: 0,
            stats: Stats {
                allocs: 0,
                frees: 0,
                evictions: 0,
                blocks: 0,
                large_maps: 0,
                large_unmaps: 0,
                quarantined: 0,
                quarantined_bytes: 0,
                seeded: false,
                last_fault: None,
            },
        }
    }

    pub fn stats(&self) -> Stats {
        let mut s = self.stats;
        s.quarantined = self.qn as u32;
        s.quarantined_bytes = self.qbytes;
        s
    }

    pub fn sys(&mut self) -> &mut S {
        &mut self.sys
    }

    pub fn config(&self) -> Config {
        self.cfg
    }

    // ── fault, entropy ──────────────────────────────────────────────────────

    #[cold]
    fn raise(&mut self, kind: Fault, addr: usize) -> ! {
        self.stats.last_fault = Some((kind, addr));
        self.sys.fault(kind, addr)
    }

    fn ensure_init(&mut self) {
        if self.ready {
            return;
        }
        self.block = align_up(self.cfg.block_bytes.max(MAX_SMALL), S::PAGE);
        let mut seed = [0u8; 40];
        if self.sys.entropy(&mut seed) {
            let w = |i: usize| u64::from_le_bytes(seed[i * 8..i * 8 + 8].try_into().unwrap());
            self.cookie = w(0) | 1;
            self.rng = [w(1), w(2), w(3), w(4)];
            if self.rng == [0; 4] {
                self.rng[0] = 1;
            }
            self.have_entropy = true;
            self.stats.seeded = true;
        } else {
            if self.cfg.seed_required {
                self.raise(Fault::SeedMissing, 0);
            }
            // Not secret: the checksum still catches accidents.
            self.cookie = mix(self as *const Self as usize as u64 ^ 0x4157_4f53_414c_4c43) | 1;
            if self.cfg.randomize {
                self.sys.note(b"[ualloc] no kernel entropy: placement is not randomized");
            }
        }
        self.ready = true;
    }

    fn next_u64(&mut self) -> u64 {
        let s = &mut self.rng;
        let r = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        r
    }

    /// Placement is random: asked for, and the kernel seeded it.
    fn random(&self) -> bool {
        self.cfg.randomize && self.have_entropy
    }

    /// A number in `0..n`; 0 when placement is not randomized.
    fn rand(&mut self, n: usize) -> usize {
        if n <= 1 || !self.random() {
            return 0;
        }
        ((self.next_u64() >> 32) as u128 * n as u128 >> 32) as usize % n
    }

    // ── headers ─────────────────────────────────────────────────────────────

    fn csum(&self, p: usize, w0: u64, front: u32) -> u32 {
        let h = mix(mix(self.cookie ^ p as u64) ^ w0) ^ (front as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        ((h ^ (h >> 32)) as u32) | 1
    }

    fn put_hdr(&self, p: usize, size: usize, class: u8, state: u8, front: u32) {
        let w0 = size as u64 | (class as u64) << 48 | (state as u64) << 56;
        let w1 = front as u64 | (self.csum(p, w0, front) as u64) << 32;
        // SAFETY: `p - HDR .. p` lies in a mapping the caller found in the table
        // (or just mapped).
        unsafe {
            wr(p - HDR, w0);
            wr(p - HDR + 8, w1);
        }
    }

    fn get_hdr(&self, p: usize) -> Option<Hdr> {
        // SAFETY: as `put_hdr`.
        let (w0, w1) = unsafe { (rd(p - HDR), rd(p - HDR + 8)) };
        let front = w1 as u32;
        if (w1 >> 32) as u32 != self.csum(p, w0, front) {
            return None;
        }
        Some(Hdr { size: (w0 & 0xffff_ffff_ffff) as usize, class: (w0 >> 48) as u8, state: (w0 >> 56) as u8, front })
    }

    // ── the mapping table ───────────────────────────────────────────────────

    /// Index of the mapping holding `a`.
    fn find_map(&self, a: usize) -> Option<usize> {
        let i = self.maps[..self.nmaps].partition_point(|m| m.base <= a);
        let m = self.maps[i.checked_sub(1)?];
        (a < m.base + m.len).then_some(i - 1)
    }

    fn insert_map(&mut self, m: Map) -> bool {
        if self.nmaps == MAPS {
            return false;
        }
        let i = self.maps[..self.nmaps].partition_point(|x| x.base < m.base);
        self.maps.copy_within(i..self.nmaps, i + 1);
        self.maps[i] = m;
        self.nmaps += 1;
        true
    }

    fn remove_map(&mut self, i: usize) {
        self.maps.copy_within(i + 1..self.nmaps, i);
        self.nmaps -= 1;
    }

    /// Is `b` the start of a slot of class `c` in one of its blocks?
    fn slot_ok(&self, c: usize, b: usize) -> bool {
        match self.find_map(b) {
            Some(i) => {
                let m = self.maps[i];
                let s = SLOT[c];
                m.class == c as u8 && (b - m.base) % s == 0 && b + s <= m.base + m.len / s * s
            }
            None => false,
        }
    }

    // ── allocation ──────────────────────────────────────────────────────────

    /// `size` bytes aligned to `align` (a power of two, at most the page
    /// size), or null: out of memory, a mapping table full, or a request the
    /// system refuses. The memory is NOT zeroed (a recycled chunk holds the
    /// poison or old data).
    pub fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        self.ensure_init();
        if align == 0 || !align.is_power_of_two() || align > S::PAGE || size >= 1 << 47 {
            return core::ptr::null_mut();
        }
        let align = align.max(HDR);
        let extra = align - HDR;
        let need = match HDR.checked_add(size).and_then(|n| n.checked_add(extra)) {
            Some(n) => n,
            None => return core::ptr::null_mut(),
        };
        let p = match class_for(need) {
            Some(c) => self.alloc_small(c, size, align),
            None => self.alloc_large(size, align),
        };
        if p != 0 {
            self.stats.allocs += 1;
        }
        p as *mut u8
    }

    fn alloc_small(&mut self, c: usize, size: usize, align: usize) -> usize {
        let b = match self.take_slot(c) {
            Some(b) => b,
            None => return 0,
        };
        let p = align_up(b + HDR, align);
        self.put_hdr(p, size, c as u8, ST_ALLOC, (p - HDR - b) as u32);
        p
    }

    fn take_slot(&mut self, c: usize) -> Option<usize> {
        if self.classes[c].free_len == 0 && self.classes[c].fresh_n == 0 && !self.refill_fresh(c) {
            return None;
        }
        let (len, fresh) = (self.classes[c].free_len, self.classes[c].fresh_n);
        if self.rand(len + fresh) < len {
            return Some(self.pop_free(c));
        }
        let cl = &mut self.classes[c];
        cl.fresh_n -= 1;
        Some(cl.fresh[cl.fresh_n])
    }

    /// Cut up to [`FRESH`] slots off the class's block (a new block when it
    /// is used up) into its fresh window, shuffled.
    fn refill_fresh(&mut self, c: usize) -> bool {
        let s = SLOT[c];
        if self.classes[c].cur + s > self.classes[c].end {
            let guard = self.cfg.guard;
            let Some(base) = self.sys.map(self.block, guard) else { return false };
            if !self.insert_map(Map { base, len: self.block, class: c as u8 }) {
                self.sys.unmap(base, self.block, guard);
                return false;
            }
            self.stats.blocks += 1;
            let cl = &mut self.classes[c];
            cl.cur = base;
            cl.end = base + self.block / s * s;
        }
        let n = ((self.classes[c].end - self.classes[c].cur) / s).min(FRESH);
        let cur = self.classes[c].cur;
        // Descending, so the unshuffled pop order is ascending addresses.
        for k in 0..n {
            self.classes[c].fresh[k] = cur + (n - 1 - k) * s;
        }
        self.classes[c].cur = cur + n * s;
        self.classes[c].fresh_n = n;
        if self.random() {
            for k in (1..n).rev() {
                let j = self.rand(k + 1);
                self.classes[c].fresh.swap(k, j);
            }
        }
        true
    }

    fn link(&self, next: usize) -> u64 {
        next as u64 ^ self.cookie.rotate_left(29)
    }

    /// The slot `node` points to, checked.
    fn next_of(&mut self, c: usize, node: usize) -> usize {
        // SAFETY: `node` passed `slot_ok`: inside a block of the table.
        let next = (unsafe { rd(node + HDR) } ^ self.cookie.rotate_left(29)) as usize;
        if next != 0 && !self.slot_ok(c, next) {
            self.raise(Fault::FreelistCorrupt, node);
        }
        next
    }

    fn pop_free(&mut self, c: usize) -> usize {
        let len = self.classes[c].free_len;
        let k = self.rand(len.min(HOPS));
        let (mut prev, mut cur) = (0usize, self.classes[c].head);
        if !self.slot_ok(c, cur) {
            self.raise(Fault::FreelistCorrupt, cur);
        }
        for _ in 0..k {
            let next = self.next_of(c, cur);
            if next == 0 {
                self.raise(Fault::FreelistCorrupt, cur);
            }
            prev = cur;
            cur = next;
        }
        let next = self.next_of(c, cur);
        match self.get_hdr(cur + HDR) {
            Some(h) if h.state == ST_AVAIL && h.class == c as u8 => {}
            _ => self.raise(Fault::FreelistCorrupt, cur),
        }
        if self.cfg.poison {
            let n = (SLOT[c] - HDR - 8).min(POISON_SPAN);
            self.check_poison(cur + HDR + 8, n);
        }
        if prev == 0 {
            self.classes[c].head = next;
        } else {
            let l = self.link(next);
            // SAFETY: `prev` was checked by `slot_ok` on the way here.
            unsafe { wr(prev + HDR, l) };
        }
        self.classes[c].free_len -= 1;
        cur
    }

    fn alloc_large(&mut self, size: usize, align: usize) -> usize {
        let page = S::PAGE;
        // At least one payload byte inside the pages, so the pointer of a
        // zero-size chunk is still inside the mapping `free` looks it up in.
        let room = size.max(1);
        let Some(want) = HDR.checked_add(room) else { return 0 };
        let Some(mut len) = want.checked_add(page - 1).map(|n| n & !(page - 1)) else { return 0 };
        // `x` is the payload offset in the mapping: a multiple of `align`
        // (the base is page aligned), room for the header before and `size`
        // after.
        let x_min = align_up(HDR, align);
        let mut x_max = (len - room) & !(align - 1);
        if x_max < x_min {
            let Some(l) = len.checked_add(page) else { return 0 };
            len = l;
            x_max = (len - room) & !(align - 1);
        }
        let guard = self.cfg.guard;
        let Some(base) = self.sys.map(len, guard) else { return 0 };
        if !self.insert_map(Map { base, len, class: LARGE }) {
            self.sys.unmap(base, len, guard);
            return 0;
        }
        self.stats.large_maps += 1;
        let x = if self.random() {
            x_min + align * self.rand((x_max - x_min) / align + 1)
        } else {
            // Ends at the guard page: the tightest overflow detection.
            x_max
        };
        let p = base + x;
        self.put_hdr(p, size, LARGE, ST_ALLOC, (x - HDR) as u32);
        p
    }

    // ── free ────────────────────────────────────────────────────────────────

    /// Release a chunk. `size`, when known (a `Layout`), must be the one it
    /// was allocated with. A pointer this heap did not hand out, or hands out
    /// no more, is a [`Fault`].
    pub fn free(&mut self, p: *mut u8, size: Option<usize>) {
        let a = p as usize;
        if a == 0 {
            return;
        }
        self.ensure_init();
        if a % HDR != 0 {
            self.raise(Fault::InvalidFree, a);
        }
        let Some(mi) = self.find_map(a) else { self.raise(Fault::InvalidFree, a) };
        let m = self.maps[mi];
        if a - m.base < HDR {
            self.raise(Fault::InvalidFree, a);
        }
        let Some(h) = self.get_hdr(a) else { self.raise(Fault::HeaderCorrupt, a) };
        if h.state != ST_ALLOC {
            self.raise(Fault::DoubleFree, a);
        }
        if h.class != m.class {
            self.raise(Fault::HeaderCorrupt, a);
        }
        if size.is_some_and(|s| s != h.size) {
            self.raise(Fault::SizeMismatch, a);
        }
        self.stats.frees += 1;
        if m.class == LARGE {
            self.free_large(mi, a, h);
        } else {
            self.free_small(m, a, h);
        }
    }

    fn free_large(&mut self, mi: usize, a: usize, h: Hdr) {
        let m = self.maps[mi];
        if h.front as usize != a - HDR - m.base || h.size > m.len {
            self.raise(Fault::HeaderCorrupt, a);
        }
        self.remove_map(mi);
        self.stats.large_unmaps += 1;
        // The range is never mapped again (the kernel's mmap only moves the
        // break up): a stale pointer into it faults.
        self.sys.unmap(m.base, m.len, self.cfg.guard);
    }

    fn free_small(&mut self, m: Map, a: usize, h: Hdr) {
        let c = m.class as usize;
        let s = SLOT[c];
        let front = h.front as usize;
        let ok = front <= s
            && a >= m.base + HDR + front
            && (a - HDR - front - m.base) % s == 0
            && a - HDR - front + s <= m.base + m.len / s * s
            && h.size + HDR + front <= s;
        if !ok {
            self.raise(Fault::HeaderCorrupt, a);
        }
        let b = a - HDR - front;
        if self.cfg.quarantine_bytes < s || QN == 0 {
            if front != 0 {
                // `release` writes its header at the slot start; the one at
                // `a - HDR` would stay a validly checksummed ST_ALLOC and a
                // second free(a) would put the slot on the list twice.
                self.put_hdr(a, 0, c as u8, ST_AVAIL, h.front);
            }
            self.release(c, b);
            return;
        }
        if self.cfg.poison {
            let n = ((b + s - a).min(POISON_SPAN)) & !7;
            // SAFETY: inside the slot.
            unsafe { core::ptr::write_bytes(a as *mut u8, POISON, n) };
        }
        self.put_hdr(a, h.size, c as u8, ST_QUAR, h.front);
        while self.qn == QN || self.qbytes + s > self.cfg.quarantine_bytes {
            self.evict();
        }
        self.q[self.qn] = a;
        self.qn += 1;
        self.qbytes += s;
    }

    /// One chunk leaves quarantine for its class's free list.
    fn evict(&mut self) {
        let i = self.rand(self.qn);
        let a = self.q[i];
        if self.random() {
            self.q[i] = self.q[self.qn - 1];
        } else {
            self.q.copy_within(i + 1..self.qn, i);
        }
        self.qn -= 1;
        let h = match self.get_hdr(a) {
            Some(h) if h.state == ST_QUAR => h,
            _ => self.raise(Fault::HeaderCorrupt, a),
        };
        let c = h.class as usize;
        let s = SLOT[c];
        let b = a - HDR - h.front as usize;
        self.qbytes -= s;
        if self.cfg.poison {
            let n = ((b + s - a).min(POISON_SPAN)) & !7;
            self.check_poison(a, n);
        }
        self.stats.evictions += 1;
        self.release(c, b);
    }

    /// Put the slot at `b` on its class's free list.
    fn release(&mut self, c: usize, b: usize) {
        let p = b + HDR;
        self.put_hdr(p, 0, c as u8, ST_AVAIL, 0);
        if self.cfg.poison {
            let n = (SLOT[c] - HDR - 8).min(POISON_SPAN);
            // SAFETY: inside the slot.
            unsafe { core::ptr::write_bytes((p + 8) as *mut u8, POISON, n) };
        }
        let l = self.link(self.classes[c].head);
        // SAFETY: inside the slot.
        unsafe { wr(p, l) };
        self.classes[c].head = b;
        self.classes[c].free_len += 1;
    }

    fn check_poison(&mut self, from: usize, n: usize) {
        const W: u64 = u64::from_ne_bytes([POISON; size_of::<u64>()]);
        let mut o = 0;
        while o < n {
            // SAFETY: `from .. from + n` is inside one slot; 8-aligned.
            if unsafe { rd(from + o) } != W {
                self.raise(Fault::UseAfterFree, from + o);
            }
            o += 8;
        }
    }
}
