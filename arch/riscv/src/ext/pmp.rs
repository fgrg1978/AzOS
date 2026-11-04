// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V Physical Memory Protection (PMP) — Phase D.
//!
//! Defines the OS memory-isolation policy and provides helpers to encode and
//! program PMP registers.
//!
//! # Privilege context
//!
//! **PMP CSRs (`pmpcfg*`, `pmpaddr*`) are M-mode only.**
//! `pmp_configure()` must be called before dropping to S-mode (i.e. from
//! early M-mode boot, not from `kernel_main` which runs in S-mode).
//!
//! When the kernel boots under OpenSBI, `pmp_configure()` is NOT called
//! automatically — OpenSBI already sets up a permissive PMP allowing the
//! kernel full access.  To enforce the stricter AzOS policy, run
//! without OpenSBI (`-bios none`) and call `pmp_configure()` from your
//! M-mode boot stub before `mret` into S-mode.
//!
//! `pmp_regions()` is safe to call at any privilege level; it returns the
//! *intended* policy for display / audit.
//!
//! # AzOS PMP policy (audit finding, U10-10: 7 entries programmed, not
//! # "8" as an earlier version of this header claimed — `N_PMP_REGIONS`
//! # below is 6, plus one hard-coded catch-all `pmp_configure` appends)
//!
//! ```text
//! #  Range                         Perm   Purpose
//! 0  0x0000_0000 .. firmware_end   R      Firmware / OpenSBI (read-only)
//! 1  firmware_end .. kernel_end    R X    Kernel text + rodata (no write)
//! 2  kernel_end .. heap_start      R W    Kernel data + BSS
//! 3  heap_start .. rt_heap_end     R W X  RT task heap (code-in-data allowed)
//! 4  rt_heap_end .. ml_heap_end    R W    ML deliberative heap (NO execute)
//! 5  MMIO window                   R W    UART / PLIC / MMIO (no execute)
//! 6  everything else               ---    DENY (catches stray accesses)
//! ```
//!
//! **Known-broken as written (U10-10, audit) — `pmp_configure` has no
//! caller anywhere in this tree, so none of this is live policy today.**
//! PMP matching is lowest-index-wins: region 0's range `[0, firmware_end)`
//! covers this platform's MMIO window too (both start at physical `0`),
//! so a real activation would deny the UART/PLIC accesses region 5 means
//! to allow, before region 5 is ever consulted. Region 5 also computes its
//! TOR upper bound as `MMIO_BASE + MMIO_SIZE` (`0x2000_0000`), which lands
//! BELOW region 4's own upper bound in RAM whenever the heap is of any
//! real size — an empty match range. Fixing the ordering/overlap is a
//! policy redesign, not a doc fix, and is out of this pass's scope; this
//! header only corrects the entry count it used to get wrong too.
//!
//! Splitting the heap enforces that ML code cannot inject executable pages
//! into the RT task's memory space: even if the ML policy network is
//! compromised, it cannot overwrite or execute RT control code.

/// PMP address-matching mode (2-bit field `A` in pmpcfg).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PmpMode {
    Off   = 0b00,
    Tor   = 0b01,   // Top-of-Range: pmpaddr[i-1] ≤ addr < pmpaddr[i]
    Na4   = 0b10,   // Naturally aligned 4-byte region
    Napot = 0b11,   // Naturally aligned power-of-two region
}

/// Access permissions for one PMP entry.
#[derive(Clone, Copy)]
pub struct PmpPerm {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl PmpPerm {
    pub const NONE:  Self = Self { r: false, w: false, x: false };
    pub const RO:    Self = Self { r: true,  w: false, x: false };
    pub const RW:    Self = Self { r: true,  w: true,  x: false };
    pub const RX:    Self = Self { r: true,  w: false, x: true  };
    pub const RWX:   Self = Self { r: true,  w: true,  x: true  };
    pub const MMIO:  Self = Self { r: true,  w: true,  x: false }; // alias for RW

    /// Encode permission bits + address-matching mode into one pmpcfg byte.
    #[inline]
    pub fn cfg_with_mode(self, mode: PmpMode, locked: bool) -> u8 {
        let mut c = 0u8;
        if self.r { c |= 1 << 0; }
        if self.w { c |= 1 << 1; }
        if self.x { c |= 1 << 2; }
        c |= (mode as u8) << 3;
        if locked { c |= 1 << 7; }
        c
    }
}

/// One PMP region descriptor.
#[derive(Clone, Copy)]
pub struct PmpRegion {
    /// Human-readable name for diagnostic output.
    pub name:   &'static str,
    /// Physical base address of the region (TOR: exclusive upper bound of previous).
    pub base:   usize,
    /// Size in bytes.  For TOR regions this is the *span* (end = base + size).
    pub size:   usize,
    pub perm:   PmpPerm,
    pub mode:   PmpMode,
    /// Lock bit: prevents further changes without a reset.
    pub locked: bool,
}

impl PmpRegion {
    /// Compute the `pmpaddr` value for a TOR region (exclusive upper bound >> 2).
    #[inline]
    pub fn tor_addr(&self) -> usize {
        (self.base + self.size) >> 2
    }

    /// Compute the `pmpaddr` value for a NAPOT region.
    ///
    /// `self.size` must be a power of two ≥ 8 bytes and `self.base` must be
    /// naturally aligned to `self.size`.
    #[inline]
    pub fn napot_addr(&self) -> usize {
        (self.base >> 2) | ((self.size / 8) - 1)
    }

    /// Encode the 8-bit `pmpcfg` entry byte.
    pub fn cfg_byte(&self) -> u8 {
        let mut c = 0u8;
        if self.perm.r { c |= 1 << 0; }
        if self.perm.w { c |= 1 << 1; }
        if self.perm.x { c |= 1 << 2; }
        c |= (self.mode as u8) << 3;
        if self.locked { c |= 1 << 7; }
        c
    }
}

// ── Intended policy ───────────────────────────────────────────────────────────

/// MMIO window common to QEMU virt / VF2 / K1.
/// Covers UART, PLIC and peripheral registers.
const MMIO_BASE: usize = 0x0000_0000;
const MMIO_SIZE: usize = 0x2000_0000; // 512 MiB covers all peripheral ranges

/// Number of PMP regions in the AzOS policy.
pub const N_PMP_REGIONS: usize = 6;

/// Return the AzOS PMP policy for the given memory layout.
///
/// `firmware_end` — first byte past OpenSBI firmware (e.g. `platform::KERNEL_LOAD`).
/// `kernel_end`   — first byte past kernel `.bss` (from linker symbol `_kernel_end`).
/// `heap_start`   — first byte of the kernel heap.
/// `heap_size`    — total heap size in bytes.
///
/// The RT heap occupies the first half; the ML deliberative heap the second.
pub fn pmp_regions(
    firmware_end: usize,
    kernel_end:   usize,
    heap_start:   usize,
    heap_size:    usize,
) -> [PmpRegion; N_PMP_REGIONS] {
    let half      = heap_size / 2;
    let rt_end    = heap_start + half;
    let ml_end    = heap_start + heap_size;
    let mmio_end  = MMIO_BASE  + MMIO_SIZE;

    [
        PmpRegion { name: "firmware / ROM",  base: 0,            size: firmware_end,       perm: PmpPerm::RO,   mode: PmpMode::Tor, locked: false },
        PmpRegion { name: "kernel text/ro",  base: firmware_end, size: kernel_end - firmware_end,  perm: PmpPerm::RX,   mode: PmpMode::Tor, locked: false },
        PmpRegion { name: "kernel data/bss", base: kernel_end,   size: heap_start - kernel_end,    perm: PmpPerm::RW,   mode: PmpMode::Tor, locked: false },
        PmpRegion { name: "RT task heap",    base: heap_start,   size: half,               perm: PmpPerm::RWX,  mode: PmpMode::Tor, locked: false },
        PmpRegion { name: "ML task heap",    base: rt_end,       size: ml_end - rt_end,    perm: PmpPerm::RW,   mode: PmpMode::Tor, locked: false },
        PmpRegion { name: "MMIO (deny X)",   base: MMIO_BASE,    size: mmio_end,           perm: PmpPerm::MMIO, mode: PmpMode::Tor, locked: false },
    ]
}

// ── M-mode CSR writer ─────────────────────────────────────────────────────────

// ── M-mode CSR writers ────────────────────────────────────────────────────
//
// **`cfg(target_arch)`-gated so the pure half of this file is host-testable.**
// Everything above -- the region table and the TOR/NAPOT/cfg encoding -- is
// arithmetic whose mistakes are silent: a wrong `pmpaddr` leaves memory
// unprotected while the kernel boots and every test passes. It had no test at
// all, because `#[path]`-pulling this file into a host suite failed to
// assemble these three `csrw` instructions on aarch64.
//
// The gate is honest rather than convenient: these functions are RV64 CSR
// writes and cannot exist anywhere else. On a non-RISC-V host they are absent,
// not stubbed, so nothing can call them by accident and believe a PMP was
// programmed.
#[cfg(target_arch = "riscv64")]
/// Write one PMP address register (M-mode only; `idx` 0..15).
///
/// # Safety
/// Must be called from M-mode.  In S-mode this raises an illegal-instruction
/// exception and the write is silently discarded by the trap handler.
#[inline(always)]
pub unsafe fn write_pmpaddr(idx: usize, addr: usize) {
    // The pmpaddr CSRs are 0x3B0..0x3BF (indices 0..15).
    // We use a macro-like match since inline asm requires literal CSR numbers.
    macro_rules! wpa {
        ($n:literal) => {
            core::arch::asm!(concat!("csrw pmpaddr", $n, ", {}"), in(reg) addr)
        };
    }
    match idx {
        0  => wpa!("0"),   1  => wpa!("1"),   2  => wpa!("2"),   3  => wpa!("3"),
        4  => wpa!("4"),   5  => wpa!("5"),   6  => wpa!("6"),   7  => wpa!("7"),
        8  => wpa!("8"),   9  => wpa!("9"),   10 => wpa!("10"),  11 => wpa!("11"),
        12 => wpa!("12"),  13 => wpa!("13"),  14 => wpa!("14"),  15 => wpa!("15"),
        _  => {}
    }
}
#[cfg(target_arch = "riscv64")]

/// Write the packed `pmpcfg0` CSR (entries 0-7) from a byte array.
///
/// # Safety
/// Must be called from M-mode.
#[inline(always)]
pub unsafe fn write_pmpcfg0(cfg: u64) {
    core::arch::asm!("csrw pmpcfg0, {}", in(reg) cfg);
}
#[cfg(target_arch = "riscv64")]

/// Write the packed `pmpcfg2` CSR (entries 8-15) from a byte array.
///
/// # Safety
/// Must be called from M-mode.
#[inline(always)]
pub unsafe fn write_pmpcfg2(cfg: u64) {
    core::arch::asm!("csrw pmpcfg2, {}", in(reg) cfg);
}
#[cfg(target_arch = "riscv64")]

/// Configure PMP hardware from the AzOS policy.
///
/// Computes the TOR `pmpaddr` values and the packed `pmpcfg0` register, then
/// writes them using M-mode CSR instructions.
///
/// Call this from your M-mode boot stub, before `mret` into S-mode.
/// Calling from S-mode raises an illegal-instruction exception per the spec.
///
/// # Safety
/// Must be called from M-mode exactly once at boot.
pub unsafe fn pmp_configure(
    firmware_end: usize,
    kernel_end:   usize,
    heap_start:   usize,
    heap_size:    usize,
) {
    let regions = pmp_regions(firmware_end, kernel_end, heap_start, heap_size);

    // Write pmpaddr registers (TOR: upper bound >> 2 for each region).
    for (i, r) in regions.iter().enumerate() {
        write_pmpaddr(i, r.tor_addr());
    }
    // Entry 6: catch-all deny — set to max address.
    write_pmpaddr(6, usize::MAX >> 2);

    // Pack pmpcfg0: one byte per entry, entries 0-7 in a u64 (little-endian).
    let mut cfg0 = 0u64;
    for (i, r) in regions.iter().enumerate().take(6) {
        cfg0 |= (r.cfg_byte() as u64) << (i * 8);
    }
    // Entry 6: deny everything — A=TOR, R=W=X=0.
    cfg0 |= (PmpMode::Tor as u64) << (6 * 8 + 3);

    write_pmpcfg0(cfg0);
}
