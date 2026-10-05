// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Zicboz (`cbo.zero`, cache-block zero) fast path — RFC-0045 Tier 0 item 3.
//!
//! `cbo.zero` zeroes one cache block without first reading it into cache
//! (no read-for-ownership), which is the RISC-V answer to the same problem
//! ARM's `DC ZVA` and x86's `MOVNTI`-based zeroing solve. The page
//! allocator's zero-fill (`crates/core/mm/src/pmm.rs::alloc_page`, plus the
//! demand-fault and vDSO one-shot zero-fills) is the hot path this benefits:
//! a 4 KiB page is 64-128 cache blocks depending on implementation, each one
//! a single `cbo.zero` instead of 16-32 scalar stores.
//!
//! # Why this is not a `target-feature`
//!
//! `.cargo/config.toml` carries only `+zaamo,+zalrsc`. Adding `+zicboz`
//! there would let the compiler assume every hart the kernel ever boots on
//! has it — including in code that runs before [`zicboz_select`] has run,
//! on a board or QEMU CPU model that does not implement it. RFC-0045's own
//! standing rule (§1, "every extension above gets a runtime probe before
//! use, with a scalar fallback") and its Drawbacks section ("QEMU's default
//! CPU model and a board missing an extension must both still boot") both
//! rule that out. Instead `cbo.zero` is emitted from a local
//! `.option arch, +zicboz` directive inside an `asm!` block — the same
//! mechanism `rvv.rs` already uses for `+v,+f,+d` — so nothing outside this
//! module's own gated asm blocks is affected.
//!
//! # Two-step availability, mirroring `clint::timer_select`/Sstc exactly
//!
//! A device tree claiming an extension is not proof it is safe to execute,
//! and here that is not a general principle but the **same CSR-gating
//! mechanism** `clint.rs` already documents for Sstc: `menvcfg.STCE` can
//! mask `stimecmp` from S-mode even on a hart that implements it, and
//! `menvcfg.CBZE` does exactly that for `cbo.zero` (with `senvcfg.CBZE`
//! gating U-mode). Only M-mode can read or set it, so a board whose
//! firmware leaves CBZE clear traps on `cbo.zero` while its device tree
//! still advertises Zicboz — which is precisely the case the execution
//! probe below exists to catch, not merely an inherited pattern.
//!
//! On top of that, this project's standing rule is that **nothing** on the
//! RFC-0045 extension list is assumed to work under QEMU's default CPU
//! model or on real silicon without checking that it *runs*, not merely
//! that the device tree or the assembler accepts it. So:
//!
//! 1. [`DtbInfo::isa_zicboz`](azos_dtb) — does `cpu@0`'s device tree
//!    declare the extension at all?
//! 2. [`zicboz_select`] — a private-`stvec` probe (identical shape to
//!    `clint::smode_timer`'s `azos_stimecmp_probe`) actually **executes**
//!    `cbo.zero` once, on a scratch page, and — going one step further than
//!    the Sstc probe, which only checks for a trap — reads the scratch
//!    memory back and confirms every byte the probed block size claims to
//!    cover is genuinely zero. This closes the exact gap RFC-0045's own
//!    "Unresolved questions" section left open: "whether QEMU's TCG
//!    *executes* each instruction correctly rather than merely accepting
//!    the [CPU] property."
//!
//! Only when both hold does [`zero_memory`] ever emit `cbo.zero`; otherwise
//! it is `core::ptr::write_bytes`, unconditionally.
//!
//! # Block size is not assumed either
//!
//! Zicboz's block size is implementation-defined (RISC-V Cache Management
//! Operations spec, Zicboz chapter) and is not necessarily 64 bytes. The
//! standard discovery mechanism — mirrored by Linux's
//! `riscv,cboz-block-size` device-tree binding and by QEMU's own
//! `hw/riscv/virt.c`, which populates that exact property from the CPU's
//! `cboz_blocksize` property when `zicboz=true` (verified empirically against
//! this tree's pinned QEMU 11.0.0: `-M virt,dumpdtb=x.dtb -cpu rv64` emits
//! `riscv,cboz-block-size = <0x40>` by default, and `-cpu rv64,zicboz=false`
//! removes both that property and the `zicboz` token from
//! `riscv,isa-extensions`) — is read once by `azos_dtb` into
//! [`DtbInfo::cboz_block_size`] and validated here (nonzero, a power of two,
//! and a divisor of `PAGE_SIZE`) before any `cbo.zero` is ever issued.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use crate::mmu::PAGE_SIZE;

// ── Selection state, same shape as clint::TIMER_MODE ────────────────────────

const STATE_UNSET: u8 = 0;
const STATE_AVAILABLE: u8 = 1;
const STATE_ABSENT: u8 = 2;

/// Decided once by [`zicboz_select`]. Until then — and whenever the decision
/// is "absent" — every zero-fill goes through the scalar fallback, which
/// works on every RV64 hart regardless of Zicboz.
static ZICBOZ_STATE: AtomicU8 = AtomicU8::new(STATE_UNSET);

/// The validated block size in bytes, valid only when `ZICBOZ_STATE ==
/// STATE_AVAILABLE`. `0` otherwise.
static ZICBOZ_BLOCK: AtomicU32 = AtomicU32::new(0);

/// Is `n` a usable Zicboz block size for this kernel's zero-fill callers?
///
/// Every caller ([`zero_memory`]) zeroes a whole number of `PAGE_SIZE`
/// regions, so a block size that does not evenly divide `PAGE_SIZE` would
/// leave a partial block at the tail with no defined way to zero it via
/// `cbo.zero` alone — rather than special-case that tail, such a board (none
/// of the RISC-V CMO spec's typical 32/64/128-byte sizes trip this; it exists
/// to catch a malformed or unusual device tree) simply does not get the fast
/// path.
fn validated_block_size(n: u32) -> Option<u32> {
    if n == 0 || !n.is_power_of_two() {
        return None;
    }
    if PAGE_SIZE % (n as usize) != 0 {
        return None;
    }
    Some(n)
}

/// Decide, once, whether `cbo.zero` is safe and worthwhile to use.
///
/// `dt_zicboz`/`dt_block_size` are `DtbInfo::isa_zicboz` /
/// `DtbInfo::cboz_block_size` — and `(false, 0)` from a caller with no DTB
/// (the probe below only ever runs when the device tree already claims the
/// extension, exactly like `clint::timer_select`'s `dt_sstc &&
/// stimecmp_readable()` short-circuit).
///
/// Probed on the calling hart only (the boot hart). A SoC whose harts differ
/// in Zicboz support would be mis-selected on the others — the same
/// documented limitation `clint::timer_select` already carries for Sstc.
///
/// The first call decides; later calls return that decision without
/// re-probing (`cbo.zero` is only ever executed once by this function, at
/// boot, by design — see the probe's own doc comment for why more than one
/// call would not learn anything new).
pub fn zicboz_select(dt_zicboz: bool, dt_block_size: u32) -> bool {
    let current = ZICBOZ_STATE.load(Ordering::Acquire);
    if current != STATE_UNSET {
        return current == STATE_AVAILABLE;
    }

    let block = if dt_zicboz { validated_block_size(dt_block_size) } else { None };
    let available = match block {
        Some(b) => probe::cbo_zero_verified(b),
        None => false,
    };

    let want = if available { STATE_AVAILABLE } else { STATE_ABSENT };
    let decided = match ZICBOZ_STATE.compare_exchange(
        STATE_UNSET, want, Ordering::AcqRel, Ordering::Acquire,
    ) {
        Ok(_) => {
            if let Some(b) = block {
                if available {
                    ZICBOZ_BLOCK.store(b, Ordering::Release);
                }
            }
            available
        }
        // Another hart (or a re-entrant call) already decided first.
        Err(already) => already == STATE_AVAILABLE,
    };
    decided
}

/// The mechanism in use: scalar until [`zicboz_select`] has chosen
/// `cbo.zero`.
pub fn zicboz_available() -> bool {
    ZICBOZ_STATE.load(Ordering::Acquire) == STATE_AVAILABLE
}

/// The validated block size `cbo.zero` is being issued at, or `0` if the
/// fast path is not in use.
pub fn zicboz_block_size() -> u32 {
    if zicboz_available() { ZICBOZ_BLOCK.load(Ordering::Acquire) } else { 0 }
}

/// Zero `len` bytes at `addr` (both must be page-aligned — every current
/// caller zeroes exactly one `PAGE_SIZE` region; the block-size divisibility
/// check below is what actually matters for `cbo.zero`, not page alignment,
/// but nothing has asked for a sub-page-aligned call yet).
///
/// Dispatches to `cbo.zero` in strides of the probed block size when
/// [`zicboz_select`] found it available and `len` is a whole multiple of
/// that block size (always true for `len == PAGE_SIZE`, since
/// `validated_block_size` already required the block size to divide
/// `PAGE_SIZE`); `core::ptr::write_bytes` otherwise. Never a hard
/// requirement: a build that never called `zicboz_select`, or one that
/// called it and got `false`, always takes the scalar path.
///
/// # Safety
/// `addr` must be a valid, writable physical address for `len` bytes, with
/// no other live reference to that memory — the same contract
/// `core::ptr::write_bytes` already has, since that is exactly what runs
/// when the fast path is unavailable.
///
/// **It must also be ordinary cacheable RAM, not MMIO.** `cbo.zero` is
/// defined on a cache block; on a device or otherwise non-idempotent PMA it
/// may raise an access fault or do nothing, so the two branches of this
/// function would stop agreeing. Every caller today (`pmm::alloc_page`,
/// `demand::handle_demand_fault`, `vdso::vdso_init`) passes a page the PMM
/// just handed out, which is always RAM.
pub unsafe fn zero_memory(addr: usize, len: usize) {
    let block = zicboz_block_size() as usize;
    if block != 0 && len % block == 0 && addr % block == 0 {
        let mut off = 0usize;
        while off < len {
            unsafe { cbo_zero_block(addr + off) };
            off += block;
        }
    } else {
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len) };
    }
}

/// Emit a single `cbo.zero` at `addr` (must be aligned to the actual
/// hardware block size — every caller in this module gets there only via
/// [`zero_memory`]'s divisibility check, or via the probe's own
/// page-aligned scratch buffer).
///
/// `.option push` / `.option arch, +zicboz` / `.option pop`: scoped to this
/// one instruction, matching the Linux kernel's own convention for the same
/// instruction (`arch/riscv/include/asm/cacheflush.h`) rather than
/// `rvv.rs`'s unscoped `.option arch` — deliberately more conservative here,
/// since an unscoped directive risks widening what later asm in the same
/// translation unit is assembled as, and this file is exactly the place
/// RFC-0045 names as "another axis to probe" if it leaks.
#[inline(always)]
unsafe fn cbo_zero_block(addr: usize) {
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +zicboz",
            "cbo.zero ({0})",
            ".option pop",
            in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

// ============================================================
// The trap-safe execution + content probe
// ============================================================

mod probe {
    use super::PAGE_SIZE;

    /// Scratch buffer for the boot-time probe. Page-sized and page-aligned
    /// so any power-of-two block size up to `PAGE_SIZE` is naturally
    /// aligned at offset 0 — `cbo.zero` requires block alignment, and a
    /// misaligned attempt would fault for a reason that has nothing to do
    /// with whether Zicboz is implemented.
    #[repr(align(4096))]
    struct Scratch([u8; PAGE_SIZE]);
    static mut SCRATCH: Scratch = Scratch([0u8; PAGE_SIZE]);

    // `azos_cbo_zero_probe(addr) -> usize`: 1 if `cbo.zero (addr)` does
    // not trap on this hart, 0 if it does.
    //
    // Identical shape to `clint::smode_timer::azos_stimecmp_probe`: a
    // private `stvec` handler this probe alone installs, so an illegal
    // instruction here never reaches the kernel's normal trap dispatcher —
    // which is the right call, not a shortcut: `txn_is_recoverable`
    // (`domains/robot/safety-core/src/txn.rs`) deliberately excludes
    // TRAP_ILLEGAL_INSTR from recovery, and the generic `handle_exception`
    // arm for an S-mode illegal instruction stops the motors and shuts the
    // board down. A boot-time capability probe cannot be the thing that
    // takes that path on hardware that simply lacks an optional extension.
    //
    // Self-contained: interrupts off, `stvec` pointed at a handler of its
    // own, one `cbo.zero`, `stvec` and `sstatus.SIE` restored. Only an
    // illegal-instruction (or, in principle, an address-misaligned)
    // exception can reach the handler — SIE is clear and the scratch buffer
    // is page-aligned so misalignment cannot occur for any block size up to
    // 4096. Clobbers t0, t1, t3, a1 (caller-saved); a0 carries the address
    // in and the boolean result out.
    core::arch::global_asm!(
        ".pushsection .text.azos_cbo_zero_probe, \"ax\"",
        ".globl azos_cbo_zero_probe",
        ".p2align 2",
        "azos_cbo_zero_probe:",
        "    csrrci t3, sstatus, 2",
        "    csrr   t1, stvec",
        "    la     t0, 1f",
        "    csrw   stvec, t0",
        "    li     a1, 1",
        ".option push",
        ".option arch, +zicboz",
        "    cbo.zero (a0)",
        ".option pop",
        "2:",
        "    csrw   stvec, t1",
        "    andi   t3, t3, 2",
        "    csrs   sstatus, t3",
        "    mv     a0, a1",
        "    ret",
        ".p2align 2",
        "1:",
        "    li     a1, 0",
        "    la     t0, 2b",
        "    csrw   sepc, t0",
        "    sret",
        ".popsection",
    );

    unsafe extern "C" {
        fn azos_cbo_zero_probe(addr: usize) -> usize;
    }

    /// Execute `cbo.zero` once on the scratch buffer and confirm both that
    /// it did not trap **and** that it actually zeroed `block_size` bytes —
    /// the second half is not redundant with the first: RFC-0045's own
    /// "Unresolved questions" section left open whether QEMU's TCG executes
    /// a CBO instruction correctly rather than merely accepting the CPU
    /// property that advertises it, and a silent no-op would pass a
    /// trap-only check while never actually zeroing a page.
    ///
    /// `block_size` must already be validated (nonzero, power of two,
    /// dividing `PAGE_SIZE`) by the caller — this function trusts it enough
    /// to index `block_size` bytes of the scratch buffer, which is exactly
    /// `PAGE_SIZE` bytes, so any validated size is in bounds.
    pub(super) fn cbo_zero_verified(block_size: u32) -> bool {
        let block = block_size as usize;
        // SAFETY: single-threaded boot-time use (called at most once per
        // decision from `zicboz_select`'s compare_exchange race window, and
        // even a concurrent re-entry only re-runs the same read-modify-read
        // sequence on a buffer nothing else touches). No other code in this
        // crate references `SCRATCH`. `addr_of_mut!` (rather than `&mut
        // SCRATCH.0`) never materializes a shared/exclusive reference to the
        // `static mut` itself, only a raw pointer — the modern-safe pattern,
        // and it sidesteps `static_mut_refs` without silencing the lint.
        let ptr = unsafe { core::ptr::addr_of_mut!(SCRATCH.0) } as *mut u8;
        // SAFETY: `ptr` is valid for `PAGE_SIZE` bytes (the array's own
        // size) and `block <= PAGE_SIZE` by construction (the caller only
        // ever passes an already-validated divisor of `PAGE_SIZE`).
        let buf: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(ptr, block) };
        // Poison first: a fresh `.bss` buffer starts at zero already, so an
        // "is it zero" check with no poison step would pass even if
        // `cbo.zero` silently did nothing.
        buf.fill(0xAA);
        let addr = ptr as usize;
        let ran = unsafe { azos_cbo_zero_probe(addr) != 0 };
        if !ran {
            return false;
        }
        buf.iter().all(|&b| b == 0)
    }
}
