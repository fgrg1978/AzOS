// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The structured kernel log: every `kerr!`/`kwarn!`/`kinfo!`/`kdebug!`/
//! `kprintln!` line, as a `{ts, level, module, msg}` record in a ring that
//! ring 3 maps and reads.
//!
//! The UART mirror is unchanged: [`uart::kernel_log`](crate::uart::kernel_log)
//! pushes the record, then prints the same bytes it always printed. The
//! record is what a durable sink reads instead of the console's bytes:
//! `userspace/services/logd` drains the ring into a file under its own
//! directory grant (Kconfig `LOGD_*`), and the toolbox's `log` reads the file.
//! Layout and protocol: [`wire`].
//!
//! # Two rings, one handover
//!
//! The first line is printed before the page allocator exists, so the ring
//! cannot be a kernel-owned memory object yet: until [`attach`] a small ring in
//! `.bss` (Kconfig `KLOG_EARLY_ENTRIES`) takes the records. `attach` is called
//! once from `kernel_main`, with the object's direct-map address; it copies
//! the early records into the new ring, in order and with their own
//! timestamps, and switches the producers over. A line older than the early
//! ring's depth is not in the log (the UART had it); `attach` returns how many,
//! and the boot prints it (`[KLOG] ...`).
//!
//! `attach` runs on the boot hart with interrupts masked and no other hart
//! started, so no producer is mid-push on either ring when the pointer
//! changes.

pub mod wire;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Does this build keep the log (Kconfig `KLOG`)?
pub const ENABLED: bool = azos_limits::KLOG;
/// Slots of the ring ring 3 maps (Kconfig `KLOG_ENTRIES`).
pub const ENTRIES: u32 = azos_limits::KLOG_ENTRIES as u32;
/// Slots of the pre-region ring (Kconfig `KLOG_EARLY_ENTRIES`).
pub const EARLY_ENTRIES: u32 = azos_limits::KLOG_EARLY_ENTRIES as u32;

const _: () = assert!(!ENABLED || ENTRIES.is_power_of_two(), "KLOG_ENTRIES must be a power of two");
const _: () = assert!(!ENABLED || EARLY_ENTRIES.is_power_of_two(), "KLOG_EARLY_ENTRIES must be a power of two");

/// Bytes of the pre-region ring (none with the log off).
const EARLY_BYTES: usize = if ENABLED { wire::region_bytes(EARLY_ENTRIES) } else { 0 };

/// The pre-region ring: its header built at compile time, its slots zero.
#[repr(C, align(64))]
struct Early(UnsafeCell<[u8; EARLY_BYTES]>);

// SAFETY: every access is through `wire`'s atomics.
unsafe impl Sync for Early {}

static EARLY: Early = Early(UnsafeCell::new(early_image()));

const fn early_image() -> [u8; EARLY_BYTES] {
    let mut img = [0u8; EARLY_BYTES];
    if ENABLED {
        let h = wire::header(EARLY_ENTRIES, 0);
        let mut i = 0;
        while i < wire::HDR_BYTES {
            img[i] = h[i];
            i += 1;
        }
    }
    img
}

/// Held, with interrupts masked, across [`attach`]'s handover.
static HANDOVER: azos_sync::SpinLock<()> = azos_sync::SpinLock::new(());

/// The ring producers push into; null until [`attach`] (then [`EARLY`]).
static CURRENT: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn current() -> *mut u8 {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() { EARLY.0.get() as *mut u8 } else { p }
}

/// Record one kernel line: `msg` is the formatted line without its newline,
/// `partial` that it had none (a `kprint!` fragment), `truncated` that
/// formatting stopped at the console's pre-format buffer.
#[inline]
pub fn record(level: usize, module: &'static str, msg: &[u8], partial: bool, truncated: bool) {
    if !ENABLED {
        return;
    }
    use azos_arch::Cpu;
    let mut flags = 0;
    if partial {
        flags |= wire::FLAG_PARTIAL;
    }
    if truncated {
        flags |= wire::FLAG_TRUNC;
    }
    let r = wire::New {
        ts: crate::timebase::now(),
        level: level as u8,
        flags,
        // percpu-hint: the cpu tag of a log line: display only
        cpu: azos_arch::ARCH.hart_id() as u8,
        module,
        msg,
    };
    // SAFETY: `current()` is a formatted ring that lives for the whole run.
    unsafe { wire::push(current(), &r) };
}

/// Hand the log over to the region at `base` (`bytes` long, zeroed, 8-aligned,
/// kernel-owned and never freed): format it, replay the early records into
/// it and switch the producers. Boot, once, on the boot hart, before any
/// other hart starts. Returns the early records the new ring could not take
/// because the early ring had already overwritten them.
///
/// # Safety
/// As [`wire::format`]; `base` is not used by anything else until this
/// returns.
pub unsafe fn attach(base: *mut u8, bytes: usize) -> Option<u32> {
    if !ENABLED || bytes < wire::region_bytes(ENTRIES) || !CURRENT.load(Ordering::Relaxed).is_null() {
        return None;
    }
    let _masked = HANDOVER.lock_irqsave();
    let early = EARLY.0.get() as *const u8;
    // SAFETY: the early ring is formatted by `early_image`; nothing else
    // runs on this hart, and no other hart exists yet.
    let rd = unsafe { wire::Reader::open(early, EARLY_BYTES) }?;
    // Lost: overwritten in the early ring, or too many for the new one.
    let kept = rd.head() - rd.oldest();
    let lost = (rd.oldest() + kept.saturating_sub(ENTRIES as u64)) as u32;
    // SAFETY: the caller's region, just formatted; the early ring is idle.
    unsafe {
        wire::format(base, ENTRIES, crate::timebase::TIMER_FREQ);
        wire::replay(&rd, base);
    }
    CURRENT.store(base, Ordering::Release);
    Some(lost)
}
