// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel tracer's region and its older entry points (wave 15, TRACE).
//!
//! The tracer itself is `azos_trace` (per-CPU lock-free rings, the runtime
//! class mask, the tracepoints). This module owns what needs the IPC layer:
//! the shared-memory region the rings live in (a kernel-owned contiguous
//! `Cap<Shm>`-pool region, as the sensor streams', so its mappings are
//! booked and torn down with every other region's), the mapping a reader
//! holding `Cap<Trace>` asks for, and the panic path's dump.
//!
//! Until wave 15 this was a 512-event ring of its own (AQ8), recorded into
//! with a shared `fetch_add` from every CPU and readable only through the
//! UART. [`trace_event`] keeps its signature for the two callers that still
//! use it (seccomp denials and Linux signal delivery) and forwards to the
//! typed tracepoints.

use crate::shm::{self, ShmPerms};
use core::sync::atomic::{AtomicU32, Ordering};

const _: () = assert!(azos_trace::MAX_CPUS == azos_sync::isr_depth::MAX_HARTS);

// The categories [`trace_event`] takes (AQ8 numbering, kept for its callers).

/// An interrupt (forwarded as an IRQ entry).
pub const TRACE_IRQ: u8 = 1;
/// A context switch.
pub const TRACE_SCHED: u8 = 2;
/// A syscall; `d1 == 0xDEAD` marks a seccomp denial.
pub const TRACE_SYSCALL: u8 = 3;
/// A page fault: `[addr, cause, tid, 0]`.
pub const TRACE_FAULT: u8 = 6;
/// A signal delivered to a Linux task: `[tid, signo, sender, action]`.
pub const TRACE_SIGNAL: u8 = 9;

/// `d1` of a [`TRACE_SYSCALL`] event that records a seccomp denial.
pub const TRACE_SYSCALL_DENIED: u32 = 0xDEAD;

/// The region's packed `Cap<Shm>`-pool reference, `u32::MAX` until created.
static REGION_REF: AtomicU32 = AtomicU32::new(u32::MAX);
static REGION_PAGES: AtomicU32 = AtomicU32::new(0);

/// Create the region for `ncpu` CPUs and install the tracer into it, at
/// boot, before any secondary CPU runs. `ts_hz` is the timebase rate the
/// clock vDSO publishes; `text` the kernel text `[start, end)` the static
/// keys live in. Nothing with `KTRACE` off. When `ncpu` rings of
/// `KTRACE_RING_ENTRIES` do not fit one region, the entries are halved
/// until they do, and the boot says so.
pub fn init(ncpu: usize, ts_hz: u64, text: (usize, usize)) {
    if !azos_trace::ENABLED {
        return;
    }
    let ncpu = ncpu.clamp(1, azos_trace::MAX_CPUS) as u32;
    let page = azos_arch::PAGE_SIZE;
    let cap_bytes = shm::MAX_SHM_PAGES * page;
    let mut entries = azos_trace::RING_ENTRIES;
    while entries > 64 && azos_spsc::trace::region_bytes(ncpu, entries) > cap_bytes {
        entries /= 2;
    }
    if entries != azos_trace::RING_ENTRIES {
        azos_drv_sys::kwarn!(
            "[TRACE] {} CPUs x {} records do not fit one {} KiB region: {} records per CPU",
            ncpu, azos_trace::RING_ENTRIES, cap_bytes / 1024, entries
        );
    }
    let bytes = azos_spsc::trace::region_bytes(ncpu, entries);
    let pages = bytes.div_ceil(page);
    let Some((region, phys)) = shm::shm_create_kernel_contig_ref(pages, ShmPerms::ReadWrite) else {
        azos_drv_sys::kerr!("[TRACE] no region ({} pages): the tracer stays off", pages);
        return;
    };
    let base = azos_mm::addr::phys_to_virt(phys);
    azos_trace::install(base, ncpu, entries, ts_hz);
    REGION_PAGES.store(pages as u32, Ordering::Relaxed);
    REGION_REF.store(region, Ordering::Release);
    if azos_trace::STATIC_KEYS {
        keys_init(text);
    }
    azos_drv_sys::kprintln!(
        "[TRACE] tracer on: {} CPUs x {} records ({} KiB), classes {:#x}, mask {:#x}, {}, timestamps {}",
        ncpu, entries, pages * page / 1024, azos_trace::CLASSES, azos_trace::mask(),
        if azos_trace::OVERWRITE { "overwrite" } else { "drop newest" },
        if azos_trace::TS_IS_CYCLES { "cycles" } else { "timebase" },
    );
}

/// The region's packed pool reference and its size in bytes, once created.
pub fn region_ref() -> Option<(u32, usize)> {
    let r = REGION_REF.load(Ordering::Acquire);
    (r != u32::MAX).then(|| (r, REGION_PAGES.load(Ordering::Relaxed) as usize * azos_arch::PAGE_SIZE))
}

/// Record an event in the AQ8 form. Forwards to the typed tracepoints; a
/// category with no class is ignored.
#[inline]
pub fn trace_event(category: u8, d0: u32, d1: u32, d2: u32, d3: u32) {
    match category {
        TRACE_SYSCALL if azos_trace::syscall_on() => {
            let tid = azos_sched::current_task_tid();
            if d1 == TRACE_SYSCALL_DENIED {
                azos_trace::raw::sys_deny(d0, tid);
            } else {
                azos_trace::raw::sys_enter(d0, tid, d1 as u64, d2 as u64);
            }
        }
        TRACE_SIGNAL => azos_trace::proc_signal(d0, d1, d2, d3),
        TRACE_IRQ => azos_trace::irq_entry(d0),
        TRACE_SCHED => azos_trace::sched_switch(d0, d1, d2, d3),
        TRACE_FAULT => azos_trace::page_fault(d0 as u64, d1, d2),
        _ => {}
    }
}

/// Print each CPU's last `last_n` records (the panic path, and
/// `SYS_TRACE_DUMP`), from the kernel's own view of each ring: what a
/// reader has or has not drained does not change it.
pub fn trace_dump(last_n: usize) {
    let region = if azos_trace::ENABLED { azos_trace::region() } else { None };
    let Some((_, ncpu, entries)) = region else {
        azos_drv_sys::kconsoleln!("[TRACE] no trace rings (KTRACE off, or no region)");
        return;
    };
    let n = (last_n as u32).min(entries);
    azos_drv_sys::kconsoleln!("[TRACE] last {} records per CPU, mask {:#x}", n, azos_trace::mask());
    for cpu in 0..ncpu as usize {
        let (written, drops) = azos_trace::cpu_stats(cpu);
        azos_drv_sys::kconsoleln!("[TRACE] cpu{}: {} written, {} dropped", cpu, written, drops);
        azos_trace::for_each_recent(cpu, n, |r| {
            azos_drv_sys::kconsoleln!(
                "  t={} cpu={} {} [{:#x}, {:#x}, {:#x}, {:#x}]",
                r.ts, r.cpu, azos_abi::trace::trace_event_name(r.event),
                r.args[0], r.args[1], r.args[2], r.args[3],
            );
        });
    }
}

/// Records written on every CPU so far (statistics).
pub fn trace_total() -> u32 {
    let ncpu = azos_trace::region().map(|(_, n, _)| n).unwrap_or(0) as usize;
    (0..ncpu).map(|c| azos_trace::cpu_stats(c).0).fold(0u32, u32::wrapping_add)
}

// ── Static keys (Kconfig `KTRACE_STATIC_KEYS`) ──────────────────────────────
//
// Every tracepoint is a site linked as a branch to its class's mask test
// (`azos_trace::jump`). Boot rewrites the sites of the classes the mask
// leaves off to nops, through `azos_mm::text_poke`; a mask change rewrites
// the changed classes' sites. Order, both ways: the mask first, the text
// after, so a site in either state at any instant runs correct code (a
// branch re-tests the mask). A kernel that could not set the patcher up
// leaves every site a branch: the mask test, correct and slower.

/// Serialises mask changes with their text rewrites.
static KEYS: azos_sync::SpinLock<()> = azos_sync::SpinLock::new(());

/// The word `site` holds now, read through its own (read-execute) mapping.
fn site_word(s: &azos_trace::jump::KeySite) -> u32 {
    // SAFETY: a site address from the linked table, inside the kernel text,
    // which is readable.
    unsafe { core::ptr::read_volatile(s.site as usize as *const u32) }
}

/// Rewrite the sites of the classes in `classes` to match `mask` (branch for
/// a class in it, nop otherwise). `(rewritten, refused)`.
fn apply(classes: u32, mask: u32) -> (usize, usize) {
    use azos_trace::jump::KeySite;
    const BATCH: usize = 16;
    let mut batch: [(usize, u32); BATCH] = [(0, 0); BATCH];
    let (mut n, mut done, mut refused) = (0usize, 0usize, 0usize);
    let flush = |b: &[(usize, u32)], done: &mut usize, refused: &mut usize| {
        if b.is_empty() {
            return;
        }
        #[cfg(feature = "text-poke-wx-canary")]
        {
            // Gate canary: the write through the EXECUTABLE mapping, which
            // W^X must refuse with a store fault.
            azos_drv_sys::kprintln!(
                "[TRACE] static-key W^X canary: writing {:#x} through the executable mapping", b[0].0);
            // SAFETY: none; this is the fault the canary exists to take.
            unsafe { core::ptr::write_volatile(b[0].0 as *mut u32, b[0].1) };
        }
        match azos_mm::text_poke::write_words(b) {
            Ok(k) => *done += k,
            Err(e) => {
                *refused += b.len();
                azos_drv_sys::kerr!("[TRACE] static keys: text write refused ({:?})", e);
            }
        }
    };
    for s in azos_trace::key_sites().iter().filter(|s: &&KeySite| s.key < 32 && classes & (1 << s.key) != 0) {
        let on = mask & (1 << s.key) != 0;
        let (cur, want) = match (s.state(site_word(s)), s.word(on)) {
            (Ok(cur), Ok(w)) => (cur, w),
            _ => {
                refused += 1;
                continue;
            }
        };
        if cur == on {
            continue;
        }
        batch[n] = (s.site as usize, want);
        n += 1;
        if n == BATCH {
            flush(&batch[..n], &mut done, &mut refused);
            n = 0;
        }
    }
    flush(&batch[..n], &mut done, &mut refused);
    (done, refused)
}

/// Set the patcher up and bring every site in line with the boot mask.
fn keys_init(text: (usize, usize)) {
    // The trace classes' sites only: keys >= 32 are other boot-once sites
    // (aarch64 PAN, `azos_trace::jump::KEY_A64_PAN`) with their own census.
    let sites = || azos_trace::key_sites().iter().filter(|s| s.key < 32);
    let Some(alias) = azos_mm::text_poke::init(text.0, text.1) else {
        azos_drv_sys::kwarn!(
            "[TRACE] static keys: no text alias, {} sites stay branches (the mask test)", sites().count());
        return;
    };
    let _g = KEYS.lock_irqsave();
    let (done, refused) = apply(azos_trace::CLASSES, azos_trace::mask());
    let (mut nop, mut branch, mut rx) = (0, 0, 0);
    for s in sites() {
        match s.state(site_word(s)) {
            Ok(true) => branch += 1,
            Ok(false) => nop += 1,
            Err(_) => {}
        }
        if azos_mm::text_poke::text_is_rx(s.site as usize).is_ok() {
            rx += 1;
        }
    }
    // Not printed under the lock (interrupts off): lockdep's hold bound.
    drop(_g);
    azos_drv_sys::kprintln!(
        "[TRACE] static keys: {} sites, {} rewritten, {} refused; now {} nop, {} branch; text RX at {}/{} sites; alias {:#x} mapped={}",
        sites().count(), done, refused, nop, branch, rx, sites().count(), alias,
        azos_mm::text_poke::alias_mapped(),
    );
}

/// Set the runtime class mask and, with static keys, rewrite the sites of
/// every class that changed. The one door for a mask change
/// (`SYS_TRACE_CTL_TYPED`'s `SET_MASK`, the cost probe). Returns the
/// previous mask.
pub fn set_mask(m: u32) -> u32 {
    if !azos_trace::STATIC_KEYS {
        return azos_trace::set_mask(m);
    }
    let _g = KEYS.lock_irqsave();
    let prev = azos_trace::set_mask(m);
    let now = azos_trace::mask();
    if azos_mm::text_poke::alias().is_some() && prev != now {
        apply(prev ^ now, now);
    }
    prev
}
