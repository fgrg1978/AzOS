// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Identity-map MMU enable for early aarch64 boot.
//!
//! Lifted out of `crates/aarch64-hello/src/main.rs` so the kernel
//! and any future bare-metal binary linking against `arch-aarch64`
//! can share the same VMSAv8-64 setup instead of reimplementing it.
//!
//! The layout is the L1 → L2 → L3 split that B1.user.split shipped
//! in `aarch64-hello` (4 KiB granule shown):
//!
//! ```text
//!   L1[0] = 1 GiB block @ 0x00000000, Device-nGnRE
//!           — covers GIC + UART + flash, kernel-only
//!   L1[1] = table → L2 (covers DRAM base .. base + 1 GiB)
//!     L2[0]      = table → L3 (covers DRAM base .. base + 2 MiB)
//!       L3[i]     = 4 KiB page; AP=00 + UXN by default,
//!                   AP=01 (+ UXN/PXN for stack) on user pages
//!     L2[1..512] = 2 MiB blocks, kernel-only Normal WB IS
//! ```
//!
//! With a 16 KiB or 64 KiB granule ([`crate::mmu::GRANULE`]) one root entry
//! spans 64 GiB / 4 TiB, so the device gigabyte and the DRAM gigabyte share
//! root slot 0 and its L2 table: the device gigabyte becomes L2 blocks (32 ×
//! 32 MiB, or 2 × 512 MiB) next to DRAM's, and the L3 covers the first L2
//! block of DRAM (32 MiB of 16 KiB pages, or 512 MiB of 64 KiB pages). A
//! root-level block is not used there: VMSAv8-64 has none at L1 for those
//! granules without 52-bit addressing.
//!
//! Two `Option<u64>` knobs in [`IdentityMapConfig`] let the caller
//! flag the *physical* addresses of one user-code page and one
//! user-stack page (typically one symbol from a `.user_text`
//! section and one from `.user_bss`). Those L3 entries get
//! AP=01; everything else stays kernel-only.

#[cfg(target_arch = "aarch64")]
use crate::sysregs;

use core::sync::atomic::AtomicU64;
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::Ordering;

/// One translation table: a page of descriptors, page-aligned (512 entries
/// at 4 KiB, 2048 at 16 KiB, 8192 at 64 KiB). Callers allocate these as
/// `static mut` (one each for L1/L2/L3) and pass mutable references into
/// [`enable_identity_map`].
#[repr(C)]
pub struct PageTable(pub [u64; ENTRIES], [azos_arch_api::PageAlign; 0]);

impl PageTable {
    /// Zero-initialised table, suitable as a `static mut` initialiser.
    pub const fn zero() -> Self {
        PageTable([0; ENTRIES], [])
    }
}

const _: () = assert!(core::mem::size_of::<PageTable>() == PAGE_SIZE as usize);
const _: () = assert!(core::mem::align_of::<PageTable>() == PAGE_SIZE as usize);

// ── Bit-encoding constants (Arm ARM §D8.3) ───────────────────────

/// Common low bits for L1/L2 block descriptors: valid + block + AF.
const BLOCK_BASE: u64 = 1 | (1 << 10);
/// L3 page descriptor: valid + page (bit 1 = 1 at L3 means "leaf",
/// the opposite of its meaning at L1/L2) + AF.
const PAGE_BASE: u64 = 0b11 | (1 << 10);
/// Non-leaf table descriptor.
const TABLE_DESC: u64 = 0b11;
/// `AttrIdx` field, bits [5:2].
const fn attr_idx(i: u64) -> u64 {
    i << 2
}
/// `SH = 0b11` (Inner Shareable) in bits [9:8].
const SH_INNER: u64 = 0b11 << 8;
/// `AP[1] = 1` → EL0 + EL1 R/W (bit 6).
const AP_EL0_RW: u64 = 0b01 << 6;
/// `UXN` (bit 54) — Unprivileged eXecute-Never.
const UXN: u64 = 1 << 54;
/// `PXN` (bit 53) — Privileged eXecute-Never.
const PXN: u64 = 1 << 53;

/// The granule this build boots with, and the sizes the tables below derive
/// from it. At 4 KiB these are the literals this file used to carry: 12, 512
/// entries, 2 MiB L2 blocks, 1 GiB root slots.
const G: crate::mmu::Granule = crate::mmu::GRANULE;
const PAGE_SHIFT: u64 = G.page_shift as u64;
const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;
const ENTRIES: usize = G.entries();
const L2_BLOCK_SIZE: u64 = G.level_size(1) as u64;
const L3_INDEX_MASK: u64 = (ENTRIES - 1) as u64;
/// Bytes of DRAM, and of device space at PA 0, the bootstrap maps.
const WINDOW: u64 = 1 << 30;
/// L2 blocks per [`WINDOW`].
const WINDOW_BLOCKS: usize = (WINDOW / L2_BLOCK_SIZE) as usize;
const _: () = assert!(WINDOW_BLOCKS >= 1 && WINDOW % L2_BLOCK_SIZE == 0);

/// `MAIR_EL1` and the indices into it come from `crate::mmu`, the single
/// source — see `mmu::MAIR_VALUE`. They used to be written out here as well,
/// and `mmu.rs` held its own opposite view of the indices until 2026-09-21.
// Gated like `sysregs` above: this crate is also compiled inside the riscv64
// workspace, where the identity-map code below is cfg'd out and an ungated
// import is an unused-import warning — which the gate counts as a failure.
#[cfg(target_arch = "aarch64")]
use crate::mmu::{MAIR_IDX_DEVICE, MAIR_IDX_NORMAL, MAIR_VALUE};

/// `TCR_EL1.AS` (bit 36) — 0 selects an 8-bit ASID, 1 selects 16-bit.
///
/// M41 (coordinator / U10-7, audit): every `switch_pt`/`write_ttbr0_el1`
/// call in this crate already carries a full `u16` ASID
/// (`api_impl::Mmu::switch_pt`, `sysregs::write_ttbr0_el1`) — the Rust
/// side has always been able to express 256..65535, hardware was just
/// told (`AS = 0`) to ignore the top 8 bits of whatever it was handed.
/// With `AS = 0`, a task assigned ASID 257 tags its TLB entries as ASID 1
/// — a cross-task translation aliasing hazard the moment `crates/core/mm`'s
/// allocator hands out an ASID past 255 (unit 09/L1's own scope, not
/// re-verified here). Safe to set unconditionally: on an implementation
/// that only supports 8-bit ASIDs (`ID_AA64MMFR0_EL1.ASIDBits == 0`) this
/// bit is defined RES0 — writing 1 has no effect, never a fault, so no
/// feature probe is needed the way `IPS` (below) requires one.
const TCR_AS: u64 = 1 << 36;

/// `TCR_EL1` for a 39-bit input range over TTBR0 only. Does NOT include
/// `IPS` (bits `[34:32]`, physical address range) — unlike `AS`, IPS must
/// never be written larger than what `ID_AA64MMFR0_EL1.PARange` reports
/// (CONSTRAINED UNPREDICTABLE otherwise per the ARM ARM), so it is a
/// runtime value OR'd in at each write site by [`tcr_value_for_this_cpu`],
/// not a compile-time constant.
const TCR_VALUE: u64 = G.tsz()             // T0SZ → walk starts at L1 (25 at 4/16 KiB)
    | (0b01 << 8)                          // IRGN0  Normal WB inner
    | (0b01 << 10)                         // ORGN0  Normal WB outer
    | (0b11 << 12)                         // SH0    Inner shareable
    | (G.tg0() << 14)                      // TG0    granule (4 KiB = 0b00)
    | (1 << 23)                            // EPD1   disable TTBR1 walks
    | TCR_AS;                              // AS     16-bit ASID

/// `ID_AA64MMFR0_EL1.PARange` (bits `[3:0]`) — the encoded field value IS
/// the `TCR_EL1.IPS` value to program (ARM ARM: same encoding, 0..=7, NOT
/// a bit count needing translation). M41: without this, `IPS` stayed `0`
/// (32-bit physical addresses only) on every CPU regardless of what it
/// actually supports — RAM at or above 4 GiB is architecturally
/// unmappable under stage-1 translation until this is set, independent of
/// how much RAM the platform has (QEMU virt's default is well under 4
/// GiB, so this was never observed to fail on the boards this kernel
/// targets — it is a correctness gap real hardware with more RAM would
/// hit, not a QEMU-observable one).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn ips_field() -> u64 {
    // Clamp to 5 (48-bit PAs, IPS=0b101) even if `PARange` reports more.
    // QEMU `-cpu max` reports PARange=6 (52-bit) here, but a 52-bit `IPS`
    // under a 4 KiB granule is only valid with FEAT_LPA2 engaged
    // (`TCR_EL1.DS` — a bit this crate never sets; `mmu_setup`'s 3-level
    // 4 KiB-granule walk was never built for LPA2's 5-level scheme), so
    // writing `IPS=6` here would be programming a mode this crate's own
    // page tables do not implement. QEMU tolerates it (it clamps
    // internally); nothing this kernel targets has more than 48 bits of
    // real physical address space, so 5 loses nothing.
    core::cmp::min(sysregs::read_id_aa64mmfr0_el1() & 0xF, 5)
}

/// [`TCR_VALUE`] plus this CPU's own `IPS`, read fresh each call rather
/// than cached: called once per PE that programs `TCR_EL1` (the primary
/// via [`enable_identity_map`], each secondary via [`enable_kernel_map`]),
/// and nothing in this crate assumes every PE reports the same `PARange`
/// (true on every SoC this kernel targets, but this function does not
/// have to assume it to stay correct on one that does not).
///
/// Gated the same as [`ips_field`] (`target_os = "none"`, not just
/// `target_arch`) rather than this file's usual `target_arch`-only gate —
/// this is the one function here that reads a real EL1-only register, so
/// it needs the stricter guard `features::detect` documents; every OTHER
/// function in this file is asm the riscv64/host builds never reach
/// anyway (they just don't get compiled for those targets), so the looser
/// gate elsewhere has never been exercised on the aarch64 HOST target the
/// way this one would be if it shared that gate.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn tcr_value_for_this_cpu() -> u64 {
    TCR_VALUE | (ips_field() << 32)
}

/// Stub for every target that is not bare-metal aarch64 (the riscv64
/// workspace target, and the aarch64 HOST target — `target_os` is not
/// `"none"` there, see [`ips_field`]'s doc for why that distinction
/// matters for an EL1-only register).
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn tcr_value_for_this_cpu() -> u64 { TCR_VALUE }

/// L3 table index for a PA inside the first L2 block above `base_pa`.
fn l3_index(pa_offset: u64) -> usize {
    ((pa_offset >> PAGE_SHIFT) & L3_INDEX_MASK) as usize
}

/// Does this PE implement the granule the build selected? Read before the
/// first `TCR_EL1` write: a granule the PE lacks is not a fault, it is an
/// MMU that never translates. `aarch64_early_mmu_init` checks this and stops
/// with a message instead.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn granule_supported() -> bool {
    G.supported_by(sysregs::read_id_aa64mmfr0_el1())
}

/// Fill the bootstrap's L2 (and the L3 under its first DRAM block) for the
/// [`WINDOW`] of DRAM at `base_pa`, as `vpn(base_pa)` selects. `leaf` is the
/// L3 attribute word for page `i` (index into the L3), `block` the L2 one.
/// At 4 KiB: `L2[0] → L3`, `L2[1..512]` blocks — what this file always built.
fn fill_dram_window(
    l2: &mut PageTable, l3: &mut PageTable, l3_pa: u64, base_pa: u64,
    leaf: impl Fn(usize) -> u64, block: u64,
) {
    for i in 0..ENTRIES {
        let pa = base_pa + (i as u64) * PAGE_SIZE;
        l3.0[i] = pa | PAGE_BASE | leaf(i);
    }
    let first = G.vpn(base_pa as usize, 1);
    l2.0[first] = l3_pa | TABLE_DESC;
    for i in 1..WINDOW_BLOCKS {
        let pa = base_pa + (i as u64) * L2_BLOCK_SIZE;
        l2.0[first + i] = pa | BLOCK_BASE | block;
    }
}

/// Caller-provided configuration for [`enable_identity_map`].
///
/// `l1`/`l2`/`l3` are kept as raw pointers (not `&mut`) because
/// they're typically `static mut` page tables shared across the
/// boot path — taking a `&mut` of a `static mut` at module level
/// would require fragile lifetimes and an exclusive borrow that
/// only holds during boot. The function writes through the
/// pointers exactly once each, before MMU enable.
pub struct IdentityMapConfig {
    pub l1: *mut PageTable,
    pub l2: *mut PageTable,
    pub l3: *mut PageTable,
    /// Base physical address of DRAM. The 1 GiB starting at this
    /// PA is mapped Normal WB through L1[1] → L2 → L3.
    pub base_pa: u64,
    /// If `Some(pa)`, the L3 entry covering `pa` gets AP=01 (EL0
    /// + EL1 RW + executable). Must lie in `[base_pa, base_pa + 2 MiB)`.
    pub user_code_pa: Option<u64>,
    /// If `Some(pa)`, the L3 entry covering `pa` gets AP=01 +
    /// UXN + PXN (EL0 + EL1 RW, no-exec — for stacks). Must lie
    /// in `[base_pa, base_pa + 2 MiB)`.
    pub user_stack_pa: Option<u64>,
}

/// Program the page tables, sysregs, and flip `SCTLR.M | C | I`.
///
/// After this returns, the CPU is running with stage-1 translation
/// on, I-cache + D-cache enabled, FP/SIMD trap cleared, and the
/// `IdentityMapConfig` mapping active.
///
/// # Safety
///
/// - Caller must be at EL1.
/// - The three `PageTable` pointers must each be exclusive and
///   live for the lifetime of the program.
/// - `base_pa` should match where the binary is loaded (typically
///   0x40000000 on QEMU virt / cortex-a72).
/// - `user_code_pa` / `user_stack_pa` (when `Some`) must be in
///   the first 2 MiB above `base_pa` — otherwise they fall outside
///   the L3 window and are silently ignored.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub unsafe fn enable_identity_map(cfg: IdentityMapConfig) {
    unsafe {
        // CPACR_EL1.FPEN = 0b11 → allow FP/SIMD at EL0+EL1. The
        // 512-iteration L3 loop below auto-vectorises into NEON
        // stores under hard-float aarch64 targets, and without
        // FPEN the first NEON op traps with EC=0x07.
        core::arch::asm!(
            "msr CPACR_EL1, {0}",
            "isb",
            in(reg) (0b11u64 << 20),
            options(nomem, nostack, preserves_flags),
        );

        let user_code_idx = cfg
            .user_code_pa
            .map(|pa| l3_index(pa.wrapping_sub(cfg.base_pa)));
        let user_stack_idx = cfg
            .user_stack_pa
            .map(|pa| l3_index(pa.wrapping_sub(cfg.base_pa)));

        // L3: pages for the first L2 block above base_pa (2 MiB of 4 KiB
        // pages); L2: that L3, then L2 blocks for the rest of the gigabyte.
        let l3 = &mut *cfg.l3;
        let l2 = &mut *cfg.l2;
        let normal = attr_idx(MAIR_IDX_NORMAL) | SH_INNER;
        fill_dram_window(l2, l3, cfg.l3 as u64, cfg.base_pa, |i| {
            if Some(i) == user_code_idx {
                normal | AP_EL0_RW // EL0 may RWX
            } else if Some(i) == user_stack_idx {
                normal | AP_EL0_RW | UXN | PXN // EL0 RW, no exec
            } else {
                normal | UXN // kernel-only
            }
        }, normal);

        // L1: the Device gigabyte at PA 0, and the table → L2. At 4 KiB they
        // are two root slots (L1[0] a 1 GiB block, L1[1] → L2). At 16/64 KiB
        // both gigabytes sit in root slot 0, so the device gigabyte is L2
        // blocks in the same L2 the DRAM window uses.
        let l1 = &mut *cfg.l1;
        let device = attr_idx(MAIR_IDX_DEVICE);
        let ram_root = G.vpn(cfg.base_pa as usize, 2);
        if ram_root != 0 {
            l1.0[0] = 0x0000_0000 | BLOCK_BASE | device;
        } else {
            for i in 0..WINDOW_BLOCKS {
                l2.0[i] = (i as u64) * L2_BLOCK_SIZE | BLOCK_BASE | device;
            }
        }
        l1.0[ram_root] = (cfg.l2 as u64) | TABLE_DESC;

        sysregs::write_mair_el1(MAIR_VALUE);
        // M41: IPS from THIS CPU's own ID_AA64MMFR0_EL1.PARange, not the
        // `0` (32-bit PAs only) `TCR_VALUE` alone encodes — see
        // `tcr_value_for_this_cpu`'s doc.
        sysregs::write_tcr_el1(tcr_value_for_this_cpu());
        sysregs::write_ttbr0_el1(cfg.l1 as usize, 0);

        core::arch::asm!("isb", options(nomem, nostack));
        sysregs::tlbi_vmalle1is();

        // Enable MMU + caches in one write. Both attr indices set
        // correct memory types so D-cache enable doesn't cache MMIO.
        let sctlr = sysregs::read_sctlr_el1()
            | sysregs::SCTLR_EL1_M
            | sysregs::SCTLR_EL1_C
            | sysregs::SCTLR_EL1_I;
        sysregs::write_sctlr_el1(sctlr);
    }
}

/// Host-build stub.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn enable_identity_map(_cfg: IdentityMapConfig) {
    unreachable!("enable_identity_map() is aarch64-only")
}

/// Turn this PE's MMU on against an ALREADY-BUILT page table — the
/// secondary-core counterpart of [`enable_identity_map`], which instead
/// builds fresh L1/L2/L3 tables. SMP bring-up (Phase 4) needs this because a
/// secondary PE cannot build the kernel's real page table itself: that table
/// is `crates/core/mm::vmm`'s PMM-backed, W^X-enforced one, and getting its root
/// physical address the normal way (`vmm::kernel_pagetable()`) takes a
/// `Mutex` — a compare-exchange, which is CONSTRAINED UNPREDICTABLE against
/// Device memory with THIS PE's own MMU still off. The physical address must
/// instead reach this PE by a route that is safe to read pre-MMU: a plain
/// (non-exclusive) load of a value the primary published after enabling
/// paging itself — see `kernel::entry::aarch64::SECONDARY_TTBR0_PA` and its
/// call site.
///
/// Same `MAIR_EL1`/`TCR_EL1` encoding as [`enable_identity_map`] (the single
/// source, `crate::mmu::MAIR_VALUE` + this file's own `TCR_VALUE`) — every PE
/// must agree on how attribute indices decode, or a page one PE reads as
/// Normal cacheable another reads as Device. Only `TTBR0_EL1` differs per
/// caller.
///
/// # Safety
/// Caller must be at EL1, VBAR_EL1 must already be installed (a fault before
/// this returns is implementation-defined with the MMU still off), and
/// `ttbr0_pa` must be the physical address of a page table already valid for
/// EVERY PE that will ever dereference it through this mapping — i.e. built
/// and fully published (arch-aarch64 has no cache-maintenance step here
/// because QEMU needs none; real silicon's caller must `dc cvac`/`dsb` the
/// table before handing this PA to a second PE — see this function's owning
/// task's report).
#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub unsafe fn enable_kernel_map(ttbr0_pa: usize) {
    unsafe {
        // Same FPEN rationale as `enable_identity_map` — this function's own
        // hard-float codegen (or anything the caller runs right after
        // returning, before boot.S's own CPACR write if that ordering is
        // ever changed) must not trap.
        core::arch::asm!(
            "msr CPACR_EL1, {0}",
            "isb",
            in(reg) (0b11u64 << 20),
            options(nomem, nostack, preserves_flags),
        );

        sysregs::write_mair_el1(MAIR_VALUE);
        // **Preserve this PE's upper half if it is live.** `TCR_VALUE`
        // describes TTBR0 only and sets `EPD1`, which DISABLES TTBR1 walks.
        // Writing it verbatim on a PE whose PC is already a high VA pulls the
        // ground out from under the next instruction, and the fault cannot be
        // reported either — the vector base is high too. That is exactly how
        // a secondary died here (2026-09-23): it printed its way to this call
        // and never returned.
        // M41: this PE's own IPS (`tcr_value_for_this_cpu`, not the bare
        // `TCR_VALUE` constant) — PARange can in principle differ per PE
        // (asymmetric SoC), and even where it does not, `IPS = 0` on every
        // secondary the same way it used to be on the primary is the same
        // "32-bit PAs only" gap this fix closes there.
        let base = tcr_value_for_this_cpu();
        let prev = sysregs::read_tcr_el1();
        let tcr = if prev & crate::mmu::TCR_EPD1 == 0 {
            (base & !crate::mmu::TCR_EPD1) | (prev & crate::mmu::TCR_TTBR1_BITS)
        } else {
            base
        };
        sysregs::write_tcr_el1(tcr);
        sysregs::write_ttbr0_el1(ttbr0_pa, 0);

        core::arch::asm!("isb", options(nomem, nostack));
        sysregs::tlbi_vmalle1is();

        let sctlr = sysregs::read_sctlr_el1()
            | sysregs::SCTLR_EL1_M
            | sysregs::SCTLR_EL1_C
            | sysregs::SCTLR_EL1_I;
        sysregs::write_sctlr_el1(sctlr);
    }
}

/// Host-build stub.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn enable_kernel_map(_ttbr0_pa: usize) {
    unreachable!("enable_kernel_map() is aarch64-only")
}

// ─────────────────────────────────────────────────────────────────────────
// TTBR1_EL1 alias — aarch64 parity program, "move the kernel into TTBR1".
// See `crate::mmu`'s own module doc on `KERNEL_VA_OFFSET`/`TCR_TTBR1_BITS`
// for the field encoding this function programs.
// ─────────────────────────────────────────────────────────────────────────

/// `TTBR1_EL1` right after [`enable_ttbr1_alias`] installs it — read by
/// `kernel_main`'s `[AARCH64-TTBR1]` boot marker and, cross-crate, by
/// `crates/core/sched`'s post-reap check (a user task's own `TTBR0_EL1` switch
/// must never disturb this). `0` means "not yet published" — never a
/// valid `TTBR1_EL1` value once `enable_ttbr1_alias` has run, since the
/// alias table's own static addresses are always nonzero.
pub static TTBR1_BOOT_VALUE: AtomicU64 = AtomicU64::new(0);

/// `TCR_EL1` right after the same call — `kernel_main` decodes
/// `T0SZ`/`T1SZ` out of this with [`crate::mmu::tcr_t0sz`]/[`crate::mmu::tcr_t1sz`]
/// rather than trusting the constants that requested them.
pub static TCR_BOOT_VALUE: AtomicU64 = AtomicU64::new(0);

/// Configuration for [`enable_ttbr1_alias`].
pub struct Ttbr1AliasConfig {
    pub l1: *mut PageTable,
    pub l2: *mut PageTable,
    pub l3: *mut PageTable,
    /// Base physical address of the 1 GiB window this alias covers — pass
    /// the same RAM base [`enable_identity_map`] was given, so the same
    /// physical bytes are reachable both ways.
    pub base_pa: u64,
}

/// Build a standalone page table mapping `[base_pa, base_pa + 1 GiB)` at
/// `base_pa | KERNEL_VA_OFFSET` — the first 2 MiB as 4 KiB pages through
/// an L3, the remaining 1022 MiB as 2 MiB L2 blocks — install it into
/// `TTBR1_EL1`, and turn on
/// TTBR1 walks (`TCR_EL1.EPD1 = 0`, `T1SZ`/`TG1`/`IRGN1`/`ORGN1`/`SH1`
/// programmed per `crate::mmu::TCR_TTBR1_BITS`).
///
/// ## What this is: the bootstrap alias the kernel jumps THROUGH
///
/// This is a **standalone early-boot table** — its own L1/L2/L3, built
/// once, separate from the kernel's real page table (`crates/core/mm::vmm`'s
/// `KERNEL_PT`). It covers 1 GiB above `base_pa` and exists for exactly
/// one purpose: to give `boot.S` a valid upper-half mapping to land in
/// when it adds `KERNEL_VA_OFFSET` to the PC, `VBAR_EL1` and `SP` and
/// branches high. Nothing dereferences memory through it after that.
///
/// **Its life ends inside `kernel_main`.** Once `crates/core/mm::vmm::init`
/// has built the real kernel table keyed on HIGH virtual addresses,
/// `enable_paging` installs it with `ARCH.switch_kernel_pt()` — which on
/// this ISA writes `TTBR1_EL1` — and this alias is never consulted again.
/// `install_device_only_ttbr0()` then reduces `TTBR0_EL1` to the recorded
/// MMIO windows alone. From that point the kernel cannot reach RAM by
/// physical address at all, which is the property the migration was for.
///
/// **Why the entries here are not `PXN`.** They used to be. The kernel
/// FETCHES through this mapping the instant `boot.S` branches high, so a
/// privileged-execute-never alias faults on the first instruction after
/// the jump. `UXN` stays: EL0 has no business here.
///
/// **Why a separate table rather than repointing the real one.** Keeping
/// them separate is what let the two halves land in the same step without
/// a window where they disagreed. Repointing `KERNEL_PT`'s leaves to high
/// VAs while the PC was still low would have left every low-VA lookup
/// silently missing — and worse, `enforce_wx` would have kept reporting
/// W^X enforced on a table the hardware no longer consulted for the
/// kernel's own fetches. An earlier attempt did exactly that: the W^X row
/// stayed green because it inspects table entries, and only the guard
/// probe — which provokes a real fault — caught that the protections had
/// been nullified. See [`crate::mmu::KERNEL_VA_OFFSET`].
///
/// # Safety
/// Caller must be at EL1, after [`enable_identity_map`] has already
/// turned the MMU on (this function only adds TTBR1 on top — it never
/// touches `SCTLR_EL1` or `TTBR0_EL1`). The three `PageTable` pointers
/// must each be exclusive and live for the program's lifetime, same
/// contract as [`enable_identity_map`]'s.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub unsafe fn enable_ttbr1_alias(cfg: Ttbr1AliasConfig) {
    unsafe {
        // L3: pages for the first L2 block above base_pa; L2: that L3, then
        // kernel-only blocks — the same shape [`enable_identity_map`]'s own
        // L2 uses. `UXN` only, deliberately NOT `PXN`: `boot.S` branches into
        // this mapping and executes from it, so privileged-execute-never
        // would fault on the first instruction after the jump. See this
        // function's doc.
        let l3 = &mut *cfg.l3;
        let l2 = &mut *cfg.l2;
        let normal = attr_idx(MAIR_IDX_NORMAL) | SH_INNER | UXN;
        fill_dram_window(l2, l3, cfg.l3 as u64, cfg.base_pa, |_| normal, normal);

        // L1: only the DRAM gigabyte's root slot (index 1 at 4 KiB, the same
        // slot `enable_identity_map` uses; 0 at 16/64 KiB) is populated — this
        // alias never needs the Device gigabyte, since nothing reads MMIO
        // through it.
        let l1 = &mut *cfg.l1;
        l1.0[G.vpn(cfg.base_pa as usize, 2)] = (cfg.l2 as u64) | TABLE_DESC;

        // Install into TTBR1_EL1 — a DIFFERENT register from
        // `enable_identity_map`'s TTBR0_EL1, so this table and the boot
        // identity map coexist without either overwriting the other.
        sysregs::write_ttbr1_el1(cfg.l1 as usize, 0);

        // Turn on TTBR1 walks: OR the upper-half fields into the LIVE
        // TCR_EL1 (never overwrite it outright — T0SZ and TTBR0's other
        // fields must survive), then clear EPD1.
        let tcr = (sysregs::read_tcr_el1() | crate::mmu::TCR_TTBR1_BITS) & !crate::mmu::TCR_EPD1;
        sysregs::write_tcr_el1(tcr);

        core::arch::asm!("isb", options(nomem, nostack));
        sysregs::tlbi_vmalle1is();

        // Publish what the hardware actually latched — see
        // `TTBR1_BOOT_VALUE`/`TCR_BOOT_VALUE`'s own doc comments. Read back
        // rather than re-derived from `cfg`/the computed `tcr` local: the
        // whole point is to report what landed in the register, not what
        // this function asked for.
        TTBR1_BOOT_VALUE.store(sysregs::read_ttbr1_el1(), Ordering::Release);
        TCR_BOOT_VALUE.store(sysregs::read_tcr_el1(), Ordering::Release);
    }
}

/// Host-build stub.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn enable_ttbr1_alias(_cfg: Ttbr1AliasConfig) {
    unreachable!("enable_ttbr1_alias() is aarch64-only")
}
