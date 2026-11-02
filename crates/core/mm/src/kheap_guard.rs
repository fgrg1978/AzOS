// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel heap guard (Kconfig `KHEAP_GUARD_*`, development builds): every
//! allocation of the global allocator is wrapped in red zones, and a freed
//! block sits poisoned in a quarantine before the allocator sees it again.
//!
//! ```text
//! base            body-RZ          body                  body+size        +RZ
//! | padding       | front red zone | the caller's bytes  | rear red zone  |
//! ```
//!
//! * **Overflow / underflow**: a write past either end of the body changes a
//!   red-zone byte; the free checks both zones byte by byte and names the
//!   first changed offset.
//! * **Use after free**: a freed block is filled with [`FREED`] and held in a
//!   FIFO quarantine (`KHEAP_GUARD_QUARANTINE_KB` bytes and
//!   `KHEAP_GUARD_QUARANTINE_SLOTS` blocks); leaving it, the block must still
//!   be all [`FREED`], or something wrote to it while it was free. A second
//!   free of a block still in quarantine finds its front zone poisoned.
//! * With `KHEAP_LEAKS` a record of the allocation sits at the start of the
//!   block and survives the free, so a finding names the allocation.
//! * A new body is filled with [`FRESH`], so a read of a byte nobody wrote
//!   does not see a freed object's old contents.
//!
//! **Not caught**: a read through a stale or out-of-bounds pointer (nothing
//! sees loads); a write that lands beyond the red zone, or in another live
//! object; a write that stores the poison byte itself; a use after the block
//! has left quarantine; memory that does not come from the global allocator
//! (frames, stacks, statics, DMA pools); a write to a size-class slab's own
//! bookkeeping. The check runs where the block is freed or leaves quarantine,
//! not where the bad access happened: the report names the block, the offset
//! and the byte.
//!
//! A finding panics, the panic message being the report. A test that commits
//! a bug on purpose runs it inside [`expect`], which counts the findings.

use core::alloc::Layout;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use azos_sync::SpinLock;

/// Whether the guard is compiled in: Kconfig `KHEAP_GUARD_Y`, or
/// `KHEAP_GUARD_KTEST` in a kernel built with the `ktest` feature.
pub const ENABLED: bool = azos_limits::KHEAP_GUARD_Y || (azos_limits::KHEAP_GUARD_KTEST && cfg!(feature = "ktest"));
/// Whether live blocks are tracked as well (Kconfig `KHEAP_LEAKS`,
/// `kheap_leaks.rs`).
pub const LEAKS: bool = ENABLED && azos_limits::KHEAP_LEAKS;
/// Bytes of a red zone: Kconfig `KHEAP_GUARD_REDZONE`.
pub const RZ: usize = azos_limits::KHEAP_GUARD_REDZONE as usize;
/// Fill of a red zone.
pub const ZONE: u8 = 0xfc;
/// Fill of a freed block.
pub const FREED: u8 = 0xdd;
/// Fill of a new body.
pub const FRESH: u8 = 0xcd;

/// Bytes in front of the red zone: the leak record.
const HDR: usize = if LEAKS { crate::kheap_leaks::HDR } else { 0 };
const SLOTS: usize = azos_limits::KHEAP_GUARD_QUARANTINE_SLOTS as usize;
const CAP_BYTES: usize = azos_limits::KHEAP_GUARD_QUARANTINE_KB as usize * 1024;

/// The allocator underneath: what the guard wraps.
#[derive(Clone, Copy)]
pub struct Raw {
    pub alloc: unsafe fn(Layout) -> *mut u8,
    pub free: unsafe fn(*mut u8, Layout),
}

/// What a finding is about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A red-zone byte past the body changed.
    Overflow,
    /// A red-zone byte before the body changed.
    Underflow,
    /// A freed block changed while it was in quarantine.
    UseAfterFree,
    /// A block freed while it was in quarantine.
    DoubleFree,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Overflow, Kind::Underflow, Kind::UseAfterFree, Kind::DoubleFree];
    const fn name(self) -> &'static str {
        match self {
            Kind::Overflow => "heap buffer overflow",
            Kind::Underflow => "heap buffer underflow",
            Kind::UseAfterFree => "use after free",
            Kind::DoubleFree => "double free",
        }
    }
}

/// A block in quarantine, as the raw allocator knows it.
#[derive(Clone, Copy)]
struct Held {
    base: usize,
    total: usize,
    align: usize,
}

struct Quarantine {
    ring: [Held; SLOTS],
    head: usize,
    len: usize,
    bytes: usize,
}

static Q: SpinLock<Quarantine> = SpinLock::new(Quarantine {
    ring: [Held { base: 0, total: 0, align: 0 }; SLOTS],
    head: 0,
    len: 0,
    bytes: 0,
});

/// Bytes the quarantine holds, readable without its lock.
static HELD: AtomicUsize = AtomicUsize::new(0);
/// Findings counted inside [`expect`], per [`Kind`].
static COUNTED: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
/// Nonzero while an [`expect`] scope is open.
static EXPECTING: AtomicUsize = AtomicUsize::new(0);

/// The raw allocation behind a request: its alignment, the offset of the body
/// in it, and its size.
#[inline(always)]
fn shape(layout: Layout) -> (usize, usize, usize) {
    let front = (HDR + RZ).next_multiple_of(layout.align().max(16));
    (layout.align(), front, front + layout.size() + RZ)
}

/// Make the body accessible and its red zones not (Kconfig `KASAN`).
#[cfg(feature = "kasan")]
fn arm(body: usize, size: usize) {
    use crate::kasan::{poison, unpoison, REDZONE};
    if body & 7 != 0 {
        return;
    }
    poison(body - RZ, RZ, REDZONE);
    unpoison(body, size);
    let end = body + size;
    let rear = (end + 7) & !7;
    poison(rear, (end + RZ - rear) & !7, REDZONE);
}

/// Everything the block's red zones poisoned accessible again, for the
/// guard's own checks of them.
#[cfg(feature = "kasan")]
fn disarm(body: usize, size: usize) {
    if body & 7 == 0 {
        crate::kasan::poison(body - RZ, (size + 2 * RZ) & !7, 0);
    }
}

/// First offset in `[p, p+n)` whose byte is not `byte`.
unsafe fn first_other(p: *const u8, byte: u8, n: usize) -> Option<usize> {
    (0..n).find(|&i| unsafe { *p.add(i) } != byte)
}

#[cold]
#[inline(never)]
fn report(kind: Kind, base: *const u8, body: usize, size: usize, off: isize, byte: u8) {
    if EXPECTING.load(Relaxed) != 0 {
        COUNTED[kind as usize].fetch_add(1, Relaxed);
        return;
    }
    if LEAKS {
        panic!("kheap guard: {} in the {}-byte block at {:#x}: offset {} holds {:#04x}{}",
            kind.name(), size, body, off, byte, crate::kheap_leaks::Site(base));
    }
    panic!("kheap guard: {} in the {}-byte block at {:#x}: offset {} holds {:#04x}", kind.name(), size, body, off, byte);
}

/// Allocate `layout` through `raw`, wrapped.
///
/// # Safety
/// `raw` is the global allocator, unwrapped.
#[inline(always)]
pub unsafe fn alloc(layout: Layout, raw: Raw) -> *mut u8 {
    let (align, front, total) = shape(layout);
    let outer = unsafe { Layout::from_size_align_unchecked(total, align) };
    let mut base = unsafe { (raw.alloc)(outer) };
    if base.is_null() {
        // A heap full of quarantined blocks gives them back, then one retry.
        if unsafe { drain(raw) } == 0 {
            return null_mut();
        }
        base = unsafe { (raw.alloc)(outer) };
        if base.is_null() {
            return null_mut();
        }
    }
    unsafe {
        let body = base.add(front);
        core::ptr::write_bytes(base.add(HDR), ZONE, front - HDR);
        core::ptr::write_bytes(body, FRESH, layout.size());
        core::ptr::write_bytes(body.add(layout.size()), ZONE, RZ);
        if LEAKS {
            crate::kheap_leaks::register(base, body as usize, layout.size());
        }
        #[cfg(feature = "kasan")]
        arm(body as usize, layout.size());
        body
    }
}

/// Free `ptr` (a body from [`alloc`]) through `raw`: check it, poison it, hold
/// it, and release the oldest held blocks that no longer fit.
///
/// # Safety
/// `ptr` and `layout` are those of an [`alloc`] result.
#[inline(always)]
pub unsafe fn dealloc(ptr: *mut u8, layout: Layout, raw: Raw) {
    let (align, front, total) = shape(layout);
    let size = layout.size();
    unsafe {
        let base = ptr.sub(front);
        let zone = ptr.sub(RZ);
        #[cfg(feature = "kasan")]
        disarm(ptr as usize, size);
        if first_other(zone, FREED, RZ).is_none() {
            report(Kind::DoubleFree, base, ptr as usize, size, 0, FREED);
            return;
        }
        if let Some(i) = first_other(zone, ZONE, RZ) {
            report(Kind::Underflow, base, ptr as usize, size, i as isize - RZ as isize, *zone.add(i));
        }
        if let Some(i) = first_other(ptr.add(size), ZONE, RZ) {
            report(Kind::Overflow, base, ptr as usize, size, (size + i) as isize, *ptr.add(size + i));
        }
        if LEAKS {
            crate::kheap_leaks::unregister(base);
        }
        core::ptr::write_bytes(base.add(HDR), FREED, total - HDR);
        #[cfg(feature = "kasan")]
        crate::kasan::poison((base as usize + HDR + 7) & !7, (total - HDR) & !7, crate::kasan::FREED);
        hold(Held { base: base as usize, total, align }, raw);
    }
}

/// Make room for `h`, release what that evicts, and hold it. The room check
/// and the push are one critical section: two CPUs that both found the ring
/// with a free slot would otherwise push into the same one.
unsafe fn hold(h: Held, raw: Raw) {
    loop {
        let t = crate::kheap::irq_off();
        let mut q = Q.lock();
        let old = q.evict_for(h.total);
        if cfg!(feature = "kheap-guard-hold-canary") && old.is_none() {
            drop(q);
            for _ in 0..200 {
                core::hint::spin_loop();
            }
            q = Q.lock();
        }
        if old.is_none() {
            q.push(h);
        }
        HELD.store(q.bytes, Relaxed);
        drop(q);
        crate::kheap::irq_restore(t);
        match old {
            Some(old) => unsafe { release(old, raw) },
            None => return,
        }
    }
}

impl Quarantine {
    /// The oldest held block, when `extra` more bytes (or one more block)
    /// would not fit; always one when `extra` is huge and any is held.
    fn evict_for(&mut self, extra: usize) -> Option<Held> {
        if self.len > 0 && (self.len == SLOTS || self.bytes + extra > CAP_BYTES) {
            let old = self.ring[self.head];
            self.head = (self.head + 1) % SLOTS;
            self.len -= 1;
            self.bytes -= old.total;
            Some(old)
        } else {
            None
        }
    }

    fn push(&mut self, h: Held) {
        let at = (self.head + self.len) % SLOTS;
        self.ring[at] = h;
        self.len += 1;
        self.bytes += h.total;
    }
}

/// The oldest held block, when `extra` more bytes (or one more block) would
/// not fit; always one when `extra` is zero and any is held.
fn evict(extra: usize) -> Option<Held> {
    let t = crate::kheap::irq_off();
    let mut q = Q.lock();
    let r = q.evict_for(extra);
    HELD.store(q.bytes, Relaxed);
    drop(q);
    crate::kheap::irq_restore(t);
    r
}

/// Blocks in quarantine now. Never more than the Kconfig slot count.
pub fn blocks_held() -> usize {
    let t = crate::kheap::irq_off();
    let n = Q.lock().len;
    crate::kheap::irq_restore(t);
    n
}

/// The slot count the quarantine is built with.
pub const MAX_BLOCKS: usize = SLOTS;

/// A block leaving quarantine: it must still be all [`FREED`].
unsafe fn release(h: Held, raw: Raw) {
    unsafe {
        let p = h.base as *mut u8;
        #[cfg(feature = "kasan")]
        crate::kasan::poison((h.base + HDR + 7) & !7, (h.total - HDR) & !7, 0);
        if let Some(i) = first_other(p.add(HDR), FREED, h.total - HDR) {
            let byte = *p.add(HDR + i);
            report(Kind::UseAfterFree, p, h.base, h.total, (HDR + i) as isize, byte);
        }
        (raw.free)(p, Layout::from_size_align_unchecked(h.total, h.align));
    }
}

/// Release every held block, checking each: how many.
///
/// # Safety
/// `raw` is the global allocator, unwrapped.
pub unsafe fn drain(raw: Raw) -> usize {
    let mut n = 0;
    while let Some(old) = evict(usize::MAX / 2) {
        unsafe { release(old, raw) };
        n += 1;
    }
    n
}

/// Bytes held in quarantine: heap that is in use only because a free is
/// delayed.
pub fn bytes_held() -> usize {
    HELD.load(Relaxed)
}

/// Run `f`, counting the guard's findings instead of panicking on them: the
/// count per [`Kind`], in [`Kind::ALL`] order.
pub fn expect<R>(f: impl FnOnce() -> R) -> (R, [usize; 4]) {
    let before = Kind::ALL.map(|k| COUNTED[k as usize].load(Relaxed));
    EXPECTING.fetch_add(1, Relaxed);
    // The deliberate bad accesses of a guard test are the sanitizer's too.
    #[cfg(feature = "kasan")]
    let r = crate::kasan::expect(f).0;
    #[cfg(not(feature = "kasan"))]
    let r = f();
    EXPECTING.fetch_sub(1, Relaxed);
    let after = Kind::ALL.map(|k| COUNTED[k as usize].load(Relaxed));
    (r, [0, 1, 2, 3].map(|i| after[i] - before[i]))
}
