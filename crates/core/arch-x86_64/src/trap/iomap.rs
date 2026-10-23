// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 port I/O on x86_64: each CPU's TSS I/O permission bitmap, loaded
//! with the running thread's open ports (`azos_arch_api::ioport`).
//!
//! The CPU checks an `in`/`out` from ring 3 (IOPL is 0) against the bitmap
//! at `TSS + iomap_base`: one bit per port, a clear bit opens it, and a bit
//! past the TSS limit refuses it (SDM Vol. 1 19.5.2). So a CPU shows ring 3
//! one of two things:
//!
//! - **no port**: `iomap_base` past the limit ([`gdt::IO_BITMAP_OFF`]). Every
//!   port faults, whatever the bitmap holds. One 16-bit store turns it on.
//! - **one thread's ports**: `iomap_base` at the bitmap, whose clear bits are
//!   exactly that thread's ranges; every other bit is set.
//!
//! A switch is cheap where it can be (Linux does the same, `switch_to_bitmap`
//! and `tss_update_io_bitmap`): to a thread with no port, from a CPU showing
//! none, it is two loads and a test; to one, it turns the bitmap off. The
//! bitmap itself is rewritten only when the CPU's TSS holds another set than
//! the incoming thread's (each set has a key that is never reused,
//! `PortGrant::key`), and then only over the bytes the old set touched and
//! the new one needs: a thread that goes off and back on one CPU is one
//! 16-bit store each way.
//!
//! The decision and the bitmap writes are pure ([`step`], [`fill`]) so the
//! host tests check them (`tests/host/arch-stub-tests`).

use azos_arch_api::ioport::{PortGrant, RANGES};
use azos_arch_api::IoPorts;

use super::gdt;

/// What a switch does to a CPU's TSS.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Nothing: it already shows what the incoming thread needs.
    Keep,
    /// `iomap_base` past the limit: the incoming thread has no port.
    Off,
    /// `iomap_base` at the bitmap, which already holds the thread's set.
    On,
    /// Rewrite the bitmap with the thread's set ([`fill`]), then [`Step::On`].
    Load,
}

/// The step for a CPU whose bitmap holds the set `resident` (0: none),
/// shown to ring 3 when `on`, switching to a thread whose set is `next`.
pub const fn step(resident: u64, on: bool, next: u64) -> Step {
    match (next == 0, on) {
        (true, false) => Step::Keep,
        (true, true) => Step::Off,
        (false, _) if resident != next => Step::Load,
        (false, true) => Step::Keep,
        (false, false) => Step::On,
    }
}

/// Write `ranges` (inclusive `(first, last)`) into `bitmap`: bytes
/// `0..dirty` may hold the clear bits of the set before, so they are set
/// again first, then each range's bits are cleared. Returns the bytes the new
/// set touched (its `dirty`). A port past the bitmap is not written: it stays
/// past the TSS limit and refused.
pub fn fill(bitmap: &mut [u8], dirty: usize, ranges: &[(u16, u16)]) -> usize {
    let dirty = dirty.min(bitmap.len());
    bitmap[..dirty].fill(0xFF);
    let mut touched = 0;
    for &(first, last) in ranges {
        for port in first as usize..=last as usize {
            let Some(b) = bitmap.get_mut(port / 8) else { break };
            *b &= !(1u8 << (port % 8));
            touched = touched.max(port / 8 + 1);
        }
    }
    touched
}

/// What one CPU's TSS holds: the key of the set in its bitmap, the bytes
/// that set touched, and whether `iomap_base` shows the bitmap.
#[cfg(target_arch = "x86_64")]
struct Resident {
    key: core::sync::atomic::AtomicU64,
    dirty: core::sync::atomic::AtomicUsize,
    on: core::sync::atomic::AtomicBool,
}

/// Indexed by CPU id; each CPU reads and writes only its own, interrupts off.
#[cfg(target_arch = "x86_64")]
static RESIDENT: [Resident; azos_limits::NR_CPUS] = [const {
    Resident {
        key: core::sync::atomic::AtomicU64::new(0),
        dirty: core::sync::atomic::AtomicUsize::new(0),
        on: core::sync::atomic::AtomicBool::new(false),
    }
}; azos_limits::NR_CPUS];

/// Point CPU `cpu`'s `iomap_base` at `base`.
#[cfg(target_arch = "x86_64")]
fn set_base(cpu: usize, base: u16) {
    let area = crate::cpu::percpu_area(cpu);
    // SAFETY: `cpu` is the calling CPU (the trait's contract), whose area is
    // live from boot; the field is inside a packed struct, hence unaligned.
    unsafe { core::ptr::addr_of_mut!((*area).tss.iomap_base).write_unaligned(base) };
}

/// Every step but the port-less fast one; out of line so the switch path
/// that never sees a port does not carry it.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn apply(cpu: usize, r: &Resident, grant: &PortGrant, next: u64, on: bool) {
    use core::sync::atomic::Ordering::Relaxed;
    match step(r.key.load(Relaxed), on, next) {
        Step::Keep => return,
        Step::Off => {
            set_base(cpu, gdt::IO_BITMAP_OFF);
            r.on.store(false, Relaxed);
            return;
        }
        Step::On => {}
        Step::Load => {
            let mut set = [(0u16, 0u16); RANGES];
            let n = grant.ranges(&mut set);
            let area = crate::cpu::percpu_area(cpu);
            // SAFETY: as `set_base`; `io_bitmap` is bytes (alignment 1), and
            // the slice leaves out its closing all-ones byte.
            let bitmap = unsafe {
                core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!((*area).tss.io_bitmap) as *mut u8,
                    gdt::IO_BITMAP_BYTES,
                )
            };
            r.dirty.store(fill(bitmap, r.dirty.load(Relaxed), &set[..n]), Relaxed);
            r.key.store(next, Relaxed);
        }
    }
    set_base(cpu, gdt::IO_BITMAP_OFFSET);
    r.on.store(true, Relaxed);
}

impl IoPorts for crate::X86_64 {
    #[inline(always)]
    fn io_ports_load(&self, cpu: usize, grant: &PortGrant) {
        #[cfg(target_arch = "x86_64")]
        {
            use core::sync::atomic::Ordering::Relaxed;
            if gdt::IO_BITMAP_BYTES == 0 {
                return;
            }
            let Some(r) = RESIDENT.get(cpu) else { return };
            let next = grant.key();
            let on = r.on.load(Relaxed);
            // Neither the CPU nor the thread has a port: the switch every
            // port-less task pays.
            if next == 0 && !on {
                return;
            }
            apply(cpu, r, grant, next, on)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (cpu, grant);
            todo!("x86_64: io_ports_load: the TSS I/O permission bitmap")
        }
    }
}
