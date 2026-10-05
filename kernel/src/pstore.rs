// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Panic record in reserved RAM that survives a warm reboot (pstore/ramoops
//! shape). Kconfig `PSTORE_SIZE_KB`; 0 compiles the region out.
//!
//! **Where.** The top `PSTORE_SIZE_KB` KiB of the RAM range the boot found
//! (DTB `/memory`, or the fallback size), taken out of the page allocator
//! by [`reserve`] before anything else allocates. Not a linker section: on a
//! guest-initiated reset QEMU re-copies every loaded ELF segment (and the
//! riscv64 DTB), so a slot inside the image would be overwritten. Measured
//! on QEMU 11.0 with a bare-metal probe on both ISAs: a pattern written
//! outside those blobs survives SBI `SRST` (cold and warm types) and PSCI
//! `SYSTEM_RESET`; the riscv64 DTB page did not. The region stays inside the
//! kernel's linear map (`vmm::init` maps the whole range).
//!
//! **Write.** [`panic_record`] runs in the panic handler: no lock, no
//! allocation, one atomic claim so a second panicking hart (or a panic
//! inside the handler) cannot tear the first record. Format and checksum:
//! `azos_fs::pstore`.
//!
//! **Contained panics (RT7).** Under `PANIC_POLICY_CONTAIN` a panic that
//! passes the containment predicate keeps the machine running, so its record
//! must not hold the region for the rest of the boot: [`contained_record`]
//! stores it, and [`contained_record_persisted`] clears it again once
//! `/fat/CRASH.LOG` has the entry. A reset-path panic always wins the region:
//! it replaces a contained record still pending (one whose file write
//! failed), and waits — bounded — for a contained hart that is writing or
//! clearing the region, so the two never interleave inside it.
//!
//! **Read.** [`recover`] runs right after `/fat` mounts: a valid record is
//! appended to `/fat/CRASH.LOG` through the normal file path, a damaged one
//! is reported and noted there, and the region is cleared.
//!
//! **Boards.** The region needs a reset that keeps DRAM contents and
//! firmware that leaves the top of RAM alone. Default off outside
//! `BOARD_QEMU`.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use azos_drv_sys::kprintln;
use azos_drv_sys::uart;
use azos_fs::pstore::{self as fmt, Record};

/// Region size in bytes; 0 = off.
pub const SIZE: usize = azos_limits::PSTORE_SIZE_KB * 1024;
const PAGE: usize = 4096;
/// Longest line [`recover`] appends to `/fat/CRASH.LOG`. A panic entry is at
/// most 512 bytes (`CRASH_ENTRY_MAX` in panic.rs); the rest is the prefix.
const LINE_MAX: usize = 640;

/// Physical base, set by [`reserve`]. `.bss`: zero on every boot.
static REGION_PA: AtomicUsize = AtomicUsize::new(0);
/// Kernel virtual base, set by [`arm`]; the only address the panic path
/// uses. 0 = not armed (panic before `arm`, or no region).
static REGION_VA: AtomicUsize = AtomicUsize::new(0);
/// Who holds the region this boot: [`FREE`], [`HELD_CONTAINED`] (a contained
/// panic's record that `/fat/CRASH.LOG` does not have yet) or [`HELD_RESET`]
/// (the first reset-path panic's record, kept for the next boot).
static CLAIMED: AtomicU8 = AtomicU8::new(FREE);
const FREE: u8 = 0;
const HELD_CONTAINED: u8 = 1;
const HELD_RESET: u8 = 2;
/// A contained panic is writing or clearing the region (with this hart's
/// interrupts masked, so it cannot be halted half-way by the panic flag).
/// Raised BEFORE its claim changes, so a reset-path panic whose claim lands
/// after that change sees it and waits.
static CONTAINED_BUSY: AtomicBool = AtomicBool::new(false);
/// How long a reset-path panic waits for [`CONTAINED_BUSY`] to drop before
/// writing anyway. The contained section writes at most a few KiB; it can
/// only outlast this if it is this same hart, panicking inside it.
const BUSY_WAIT_MS: u64 = 10;
/// What [`recover`] found: 0 nothing, 1 a valid record, 2 a rejected one.
static FOUND: AtomicU8 = AtomicU8::new(0);

/// Take the region out of the page allocator. Call right after
/// `pmm::init` (and after any DTB reservation), before the heap.
/// `dtb` is the blob's `[start, end)`, when there is one.
pub fn reserve(mem_start: usize, mem_size: usize, kernel_end: usize, dtb: Option<(usize, usize)>) {
    if SIZE == 0 {
        kprintln!("[PSTORE] off (PSTORE_SIZE_KB = 0)");
        return;
    }
    let end = crate::mem_range_end(mem_start, mem_size) & !(PAGE - 1);
    let base = end.saturating_sub(SIZE) & !(PAGE - 1);
    if base < kernel_end || base < mem_start {
        azos_drv_sys::kwarn!("[PSTORE] off: region {:#x} would overlap the kernel image (ends {:#x})",
            base, kernel_end);
        return;
    }
    if let Some((ds, de)) = dtb {
        if ds < end && base < de {
            azos_drv_sys::kwarn!("[PSTORE] off: region {:#x}-{:#x} overlaps the DTB {:#x}-{:#x}",
                base, end, ds, de);
            return;
        }
    }
    let managed_end = mem_start + azos_mm::pmm::total_pages() * PAGE;
    if base >= managed_end {
        // Past the allocator's ceiling (MAX_PAGES / RAM_SIZE): nobody else
        // can be handed these pages.
    } else if azos_mm::pmm::range_is_free(base, SIZE) {
        azos_mm::pmm::reserve_range(base, SIZE);
    } else {
        azos_drv_sys::kwarn!("[PSTORE] off: region {:#x}-{:#x} is not free in the page allocator",
            base, end);
        return;
    }
    REGION_PA.store(base, Ordering::Release);
    kprintln!("[PSTORE] region reserved: {:#x} - {:#x} ({} KiB)", base, base + SIZE, SIZE / 1024);
}

/// Publish the region's kernel virtual address to the panic path. Call once
/// the kernel's own page table (which maps all RAM) is live.
pub fn arm() {
    let pa = REGION_PA.load(Ordering::Acquire);
    if pa != 0 {
        REGION_VA.store(azos_mm::addr::phys_to_virt(pa), Ordering::Release);
    }
}

/// The region, if armed.
///
/// # Safety
/// Two users only: the panic paths, after winning `CLAIMED`, and [`recover`],
/// once, at boot. A hart panicking while `recover` runs can overwrite the
/// record `recover` is reading; the magic is stored last, so the outcome is
/// a lost or duplicated old record, never a torn new one.
unsafe fn region() -> Option<&'static mut [u8]> {
    let va = REGION_VA.load(Ordering::Acquire);
    if va == 0 || SIZE == 0 {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts_mut(va as *mut u8, SIZE) })
}

/// Push the region out of this hart's data cache to memory, so a reset
/// that does not write back dirty lines still finds the record.
fn make_durable(r: &[u8]) {
    core::sync::atomic::fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    unsafe {
        azos_arch::cache::dcache_clean(r.as_ptr() as usize, r.len());
    }
    // riscv64: QEMU has no cache to clean; on a board with a write-back
    // cache this would be Zicbom `cbo.clean` or the SoC's own flush.
    #[cfg(not(target_arch = "aarch64"))]
    let _ = r;
}

fn put_hex(v: usize) {
    let mut b = [0u8; 18];
    b[0] = b'0';
    b[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> (60 - 4 * i)) & 0xF) as u8;
        b[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    uart::puts(unsafe { core::str::from_utf8_unchecked(&b) });
}

/// Panic path: store `entry` as this boot's record. Lock-free, no
/// allocation, UART output through the lock-free `uart::puts` only.
/// Returns true if THIS call wrote the record (only then may the caller
/// clear it with [`panic_record_persisted`]).
pub fn panic_record(entry: &[u8]) -> bool {
    if SIZE == 0 {
        return false;
    }
    let Some(r) = (unsafe { region() }) else {
        uart::puts("[PANIC] pstore not armed yet — no RAM record\n");
        return false;
    };
    let prev = CLAIMED.swap(HELD_RESET, Ordering::SeqCst);
    if prev == HELD_RESET {
        uart::puts("[PANIC] pstore already holds this boot's first panic — kept\n");
        return false;
    }
    // A contained panic on another hart may be inside the region right now.
    let start = azos_drv_sys::timebase::now();
    let limit = BUSY_WAIT_MS * (azos_drv_sys::timebase::TIMER_FREQ / 1000);
    while CONTAINED_BUSY.load(Ordering::SeqCst)
        && azos_drv_sys::timebase::now().wrapping_sub(start) < limit
    {
        core::hint::spin_loop();
    }
    if prev == HELD_CONTAINED {
        uart::puts("[PANIC] pstore: replacing a contained panic's record\n");
    }
    let n = fmt::encode(r, entry);
    // Canary for the gate row: damage the payload after the CRC was taken.
    #[cfg(feature = "pstore-corrupt-smoke")]
    {
        r[fmt::PSTORE_HEADER_LEN] ^= 0x01;
    }
    make_durable(r);
    uart::puts("[PANIC] pstore record written: ");
    let mut nb = [0u8; 20];
    uart::puts(fmt_usize(n, &mut nb));
    uart::puts(" bytes at PA ");
    put_hex(REGION_PA.load(Ordering::Relaxed));
    uart::puts("\n");
    true
}

/// Run `f` on the region as the contained-panic writer: interrupts masked on
/// this hart, [`CONTAINED_BUSY`] raised before the claim moves (see
/// [`panic_record`] for the reader of that order).
fn contained_section<R>(f: impl FnOnce() -> R) -> R {
    use azos_arch::Interrupts;
    let irq = azos_arch::ARCH.disable_all();
    CONTAINED_BUSY.store(true, Ordering::SeqCst);
    let out = f();
    CONTAINED_BUSY.store(false, Ordering::SeqCst);
    azos_arch::ARCH.restore(irq);
    out
}

/// Contained-panic path (task context, no lock held): store `entry` while
/// the region is free. Returns true if THIS call wrote it; only then may the
/// caller clear it with [`contained_record_persisted`].
pub fn contained_record(entry: &[u8]) -> bool {
    if SIZE == 0 {
        return false;
    }
    let Some(r) = (unsafe { region() }) else {
        azos_drv_sys::kconsoleln!("[PANIC] pstore not armed yet — no RAM record");
        return false;
    };
    let n = contained_section(|| {
        if CLAIMED
            .compare_exchange(FREE, HELD_CONTAINED, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return None;
        }
        let n = fmt::encode(r, entry);
        make_durable(r);
        Some(n)
    });
    match n {
        Some(n) => {
            azos_drv_sys::kconsoleln!("[PANIC] pstore record written (contained): {} bytes", n);
            true
        }
        None => {
            azos_drv_sys::kconsoleln!("[PANIC] pstore holds an earlier record — contained record not stored in RAM");
            false
        }
    }
}

/// Contained-panic path, after `/fat/CRASH.LOG` confirmed the entry: clear
/// the RAM copy and free the region for the next panic. A no-op if a
/// reset-path panic has taken the region over in the meantime.
pub fn contained_record_persisted() {
    let Some(r) = (unsafe { region() }) else { return };
    let cleared = contained_section(|| {
        if CLAIMED
            .compare_exchange(HELD_CONTAINED, FREE, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        fmt::clear(r);
        make_durable(r);
        true
    });
    if cleared {
        azos_drv_sys::kwarn!("[PANIC] pstore record cleared (CRASH.LOG has the entry); region free");
    }
}

/// Panic path, after `/fat/CRASH.LOG` confirmed the same entry: drop the RAM
/// copy so the next boot does not append it a second time.
pub fn panic_record_persisted() {
    if let Some(r) = unsafe { region() } {
        fmt::clear(r);
        make_durable(r);
        uart::puts("[PANIC] pstore record cleared (CRASH.LOG has the entry)\n");
    }
}

fn fmt_usize(mut v: usize, buf: &mut [u8; 20]) -> &str {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}

/// Boot path, with `/fat` mounted: copy a record left by the previous boot
/// into `/fat/CRASH.LOG` and clear it.
pub fn recover() {
    let Some(r) = (unsafe { region() }) else { return };
    let rec = fmt::decode(r);
    let mut line = [0u8; LINE_MAX];
    let n = fmt::recovery_line(&rec, &mut line);
    let text = core::str::from_utf8(&line[..n]).unwrap_or("<non-utf8>").trim_end();
    match rec {
        Record::Empty => {
            kprintln!("[PSTORE] no record from the previous boot");
            return;
        }
        Record::Valid(p) => {
            FOUND.store(1, Ordering::Release);
            if p.len() + fmt::PSTORE_LOG_PREFIX.len() > LINE_MAX {
                kprintln!("[PSTORE] record is {} bytes; CRASH.LOG gets the first {}",
                    p.len(), LINE_MAX);
            }
        }
        Record::Rejected(_) => {
            FOUND.store(2, Ordering::Release);
            azos_drv_sys::kwarn!("[PSTORE] record REJECTED: {}", text);
        }
    }
    let mut fds = azos_fs::ScratchFds::new();
    let out = azos_fs::record_entry(&mut fds, &line[..n]);
    let written = out.write == azos_fs::WriteResult::Written;
    match (rec, written) {
        (Record::Valid(_), true) => {
            azos_drv_sys::kwarn!("[PSTORE] recovered previous panic into /fat/CRASH.LOG: {}", text);
        }
        (Record::Valid(_), false) => {
            // Kept for the next boot: the RAM copy is the only one.
            azos_drv_sys::kerr!("[PSTORE] /fat/CRASH.LOG write failed ({:?}); record kept in RAM", out.write);
            return;
        }
        (_, true) => azos_drv_sys::kwarn!("[PSTORE] discarded; noted in /fat/CRASH.LOG"),
        (_, false) => azos_drv_sys::kerr!("[PSTORE] discarded; /fat/CRASH.LOG note failed ({:?})", out.write),
    }
    fmt::clear(r);
    make_durable(r);
}

/// What [`recover`] found this boot: 0 nothing, 1 valid, 2 rejected.
#[cfg(feature = "pstore-smoke")]
fn found_this_boot() -> u8 {
    FOUND.load(Ordering::Acquire)
}

/// Gate rows `pstore: ...`: panic with the VFS lock held, once. A boot that
/// found a record (valid or rejected) is the second boot and carries on.
/// Sets the panic reboot delay itself: `CONFIG.INI` is read after this.
#[cfg(feature = "pstore-smoke")]
pub fn smoke() {
    if found_this_boot() != 0 {
        kprintln!("[PSTORE-SMOKE] record found this boot ({}); no second panic",
            if found_this_boot() == 1 { "valid" } else { "rejected" });
        return;
    }
    azos_config::CFG_PANIC_REBOOT_DELAY_MS.store(200, Ordering::Release);
    kprintln!("[PSTORE-SMOKE] panicking with the VFS FS lock held");
    azos_fs::pstore_smoke_panic_holding_fs_lock();
}
