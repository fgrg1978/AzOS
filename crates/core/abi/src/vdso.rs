// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The vDSO's fixed user-space virtual address — the one constant every
//! side of the user/kernel boundary that touches the vDSO must read from
//! here, never restate.
//!
//! ## Why this lives in `abi` and not `mm`
//!
//! `crates/core/mm::vdso` is RV64/aarch64-only (it allocates the physical page
//! and owns the seqlock). `crates/core/libsys` (built for the SAME target as
//! user ELFs, but a separate compilation) needs the identical numeric
//! value baked into ring-3 code that reads the page directly, without a
//! syscall. `abi` is the one crate both already depend on, has zero
//! dependencies of its own, and is `no_std` + pure — exactly the shape a
//! value that must compile identically on both sides needs. `mm::vdso`
//! re-exports this constant so kernel-side callers keep using
//! `azos_mm::vdso::VDSO_USER_BASE`.
//!
//! ## Why `0x2000_0000` and not `0x5000_0000`
//!
//! The kernel identity-maps a fixed set of physical windows (RAM plus each
//! board's MMIO) into every process's page table lazily, at VPN\[1\] (2 MiB)
//! granularity — see `crates/core/mm/src/vmm.rs`'s `copy_kernel_entries_to_user`
//! and `write_would_enter_kernel_table`. A vDSO placed inside a VPN\[1\] slot
//! the kernel also claims is refused (or, worse, silently shares the
//! kernel's live L1 table with user code, on a board whose kernel entries
//! merge *before* the vDSO is mapped).
//!
//! `0x5000_0000` has VPN\[2\] (1 GiB slot) index 1. On QEMU riscv64 (RAM at
//! `0x8000_0000`, VPN\[2\]=2) that slot happens to be unclaimed, so the
//! vDSO worked there by luck. On VF2 and on aarch64 QEMU `virt` (RAM at
//! `0x4000_0000`, VPN\[2\]=1 on BOTH), it collides with the kernel's own RAM
//! identity map.
//!
//! `0x2000_0000` sits inside VPN\[2\]=0, the slot every board's *low* MMIO
//! cluster lives in (CLINT/PLIC/UART/GPIO/I2C/… — see
//! `crates/drivers/base/src/platform.rs`). Within that slot it still needs to
//! avoid every individual VPN\[1\] (2 MiB) window a board's `hw` module
//! declares; each `hw` module carries a `const` assertion proving that
//! (`same_2mib_slot` below is the shared check), so a moved or added
//! device that collides fails the board's own build instead of silently
//! losing the vDSO. K1 (`RAM_BASE == 0`) cannot be proven disjoint by any
//! address in VPN\[2\]=0 — see `crates/core/mm/src/vmm.rs`'s
//! `kernel_entry_collision` doc and `crates/core/sched/src/process.rs`'s
//! `USER_STACK_TOP` doc for why that is a pre-existing, documented, and
//! (for now) accepted condition, not something this constant can fix.
/// Fixed user-space virtual address of the vDSO page, on every board. See
/// the module doc above for why `0x2000_0000` and not `0x5000_0000`.
pub const VDSO_USER_BASE: usize = 0x2000_0000;

/// The vDSO page is one 4 KiB page — used to size the vDSO's own end of
/// every disjointness check below, so nothing restates `PAGE_SIZE`.
const VDSO_SIZE: usize = 0x1000;

/// True when `[a_base, a_base+a_size)` and `[b_base, b_base+b_size)` share
/// no 2 MiB (VPN\[1\]) window, at that window's granularity — NOT true byte
/// overlap.
///
/// This is the granularity `copy_kernel_entries_to_user` merges kernel
/// mappings into a fresh user page table at (see `crates/core/mm/src/vmm.rs`):
/// a kernel entry for ANY address inside a 2 MiB window claims the WHOLE
/// window for that merge, whether or not every byte in it is actually
/// device-backed, and a device whose mapped size crosses a 2 MiB boundary
/// (this project's PLIC, mapped 4 MiB) claims every window it touches, not
/// just the one its base address falls in — hence a range, not a point,
/// on both sides.
pub const fn ranges_share_a_2mib_slot(
    a_base: usize, a_size: usize,
    b_base: usize, b_size: usize,
) -> bool {
    const SLOT_SHIFT: u32 = 21; // 2 MiB = 1 << 21
    let a_first = a_base >> SLOT_SHIFT;
    let a_last = (a_base + a_size - 1) >> SLOT_SHIFT;
    let b_first = b_base >> SLOT_SHIFT;
    let b_last = (b_base + b_size - 1) >> SLOT_SHIFT;
    a_first <= b_last && b_first <= a_last
}

/// `ranges_share_a_2mib_slot`, specialised to the vDSO's own page against a
/// single-address device whose full mapped size is `size` bytes.
pub const fn vdso_shares_a_2mib_slot_with(device_base: usize, device_size: usize) -> bool {
    ranges_share_a_2mib_slot(VDSO_USER_BASE, VDSO_SIZE, device_base, device_size)
}

/// True when the vDSO page sits entirely below `ram_base` — the same
/// threshold `crates/core/sched/src/process.rs`'s `VDSO_FITS_BELOW_USER_CEILING`
/// checks at runtime (there, against `USER_STACK_TOP`, which equals
/// `RAM_BASE` on every board this covers). A board's RAM is identity-mapped
/// as a contiguous run of megapages starting at `RAM_BASE` and growing
/// upward by however much RAM the DTB reports — a size this crate cannot
/// see at compile time — so "below `RAM_BASE`" is the only RAM check that
/// stays correct regardless of installed RAM size; a 2 MiB-slot check
/// (correct for a point device) would not be.
pub const fn vdso_is_below_ram(ram_base: usize) -> bool {
    VDSO_USER_BASE + VDSO_SIZE <= ram_base
}

// No `#[cfg(test)]` here: this crate builds under the workspace's `no_std`
// RV64 target (`.cargo/config.toml`), which has no `test` crate to link
// against — `cargo test` run directly in `crates/core/abi` fails before it
// reaches this file (confirmed; the workspace's OTHER `#[cfg(test)]` blocks
// in this crate, e.g. `cap.rs`, fail the same way). `tests/host/abi-tests` is
// the real host-side test crate for this code — see its `vdso_tests` module.

// ---------------------------------------------------------------------------
// The per-task vDSO page (DOMAIN_VDSO_MAP, 594): its layout is ABI
// ---------------------------------------------------------------------------

/// `magic` of the per-task vDSO page ("VTSK").
pub const VDSO_TASK_MAGIC: u32 = 0x5654_534B;
/// Byte offsets inside the per-task page, the one definition both sides
/// read: `crates/core/mm/src/vdso.rs` asserts its `VdsoTaskPage` against these
/// with `offset_of!` and `crates/core/libsys` reads the page by them, so a moved
/// field fails the kernel build instead of handing ring 3 the wrong bytes.
pub const VTP_MAGIC: usize = 0;
/// `u32`: the page seqlock; odd while the kernel writes.
pub const VTP_SEQ: usize = 8;
/// `u32`: the TID the page belongs to.
pub const VTP_OWNER_TID: usize = 12;
/// `u64`: timebase ticks charged to the task, sampled at timer interrupts.
pub const VTP_CPU_TIME: usize = 16;
/// `u64`: voluntary context switches.
pub const VTP_SW_VOLUNTARY: usize = 24;
/// `u64`: preemptions by the timer.
pub const VTP_SW_PREEMPTED: usize = 32;
/// `u32`: the `ready_site` tag of the task's last dispatch.
pub const VTP_LAST_READY_SITE: usize = 40;
/// `u32`: bit `t` set when a sensor endpoint for type `t` was bound.
pub const VTP_SENSOR_MASK: usize = 44;
/// `u64`: publications of the page.
pub const VTP_PUBLISHES: usize = 48;
/// `u64`: timebase counter at the last publication.
pub const VTP_LAST_SAMPLE: usize = 56;
/// First sensor slot.
pub const VTP_SENSORS: usize = 64;
/// One sensor slot: `seq u32, len u32, stamp u64, data [u8; 32], acq_ns u64`,
/// padded to 64.
pub const VTP_SENSOR_STRIDE: usize = 64;
/// Offset of the payload inside a slot.
pub const VTP_SENSOR_DATA: usize = 16;
/// Largest payload a slot carries.
pub const VTP_SENSOR_DATA_MAX: usize = 32;
/// Sensor types with a slot: `SENSOR_TYPE_IMU` (0) ..= `SENSOR_TYPE_POWER` (9).
pub const VTP_SENSOR_SLOTS: usize = 10;
/// `u32` at offset 4: the per-task page's layout version.
pub const VTP_VERSION: usize = 4;
/// Layout version the kernel writes. Version 2 (wave 11) adds
/// [`VTP_SENSOR_ACQ_NS`] in what was the slot's padding; every version-1
/// offset is unchanged, so a version-1 reader keeps working.
pub const VDSO_TASK_VERSION: u32 = 2;
/// `u64` inside a slot, version >= 2: when the published value was ACQUIRED,
/// on the vDSO clock in nanoseconds (`azos_abi::sensor_sample`); 0 =
/// unknown. Written inside the page seqlock with the payload it stamps.
/// `stamp` (offset 8) stays the timebase counter at PUBLICATION.
pub const VTP_SENSOR_ACQ_NS: usize = 48;

// ── Hardware capabilities (`VdsoData::hwcap`, byte offset 40) ───────────────
//
// The AT_HWCAP analogue (wave 13): what the CPU implements AND ring 3 may
// execute, detected at boot from the ID registers (aarch64), CPUID (x86_64)
// or the device tree's `riscv,isa` / `riscv,isa-extensions` of cpu@0
// (riscv64), never from build flags. A bit is set only when the extension's
// Kconfig policy allows it (`ExtPolicy::gate`: `n` clears it) AND the CPU has
// it AND, for an extension the OS must switch on for ring 3 (x86 FSGSBASE,
// PKU, CET, the YMM state; aarch64 PAuth, BTI, MTE, SVE), the kernel did:
// such a bit reads 0 until that enable is wired, never "present but traps".
// Written once before the first user task; 0 means "nothing beyond the base
// ISA" (or a kernel too old to publish it). Ring 3 reads it with
// `azos_libsys::vdso_hwcap()`.
//
// One word per ISA, as Linux's AT_HWCAP: each ISA numbers its own bits from
// 0 ([`HWCAP_A64_ALL`], [`HWCAP_RV_ALL`], [`HWCAP_X86_ALL`]), and the word
// means what the RUNNING ISA's table says. A binary runs on one ISA, so a
// bit never means two things to the program reading it. Adding a bit keeps
// the layout: a reader that does not know a bit ignores it. When an ISA's
// first word fills, its next bits go to [`VDSO_HWCAP2_OFFSET`] (AT_HWCAP2).

/// Byte offset of the `hwcap` word in the vDSO page.
pub const VDSO_HWCAP_OFFSET: usize = 40;

// ── Counter scale (`VdsoData::counter_*`, byte offsets 48..72) ──────────────
//
// Where the counter ring 3 reads (`rdtsc` on x86_64) does not run at the
// kernel clock's rate (TIMER_FREQ), the kernel publishes its own conversion,
// written once before the first user task:
//   ticks = ticks_base + ((counter - counter_base) * mult) >> 32
// (64x64 -> 128-bit product). All three are 0 where the counter IS the clock
// (riscv64 `rdtime`) or ring 3 does not read it (aarch64 today).

/// Byte offset of the counter value at the conversion's base.
pub const VDSO_COUNTER_BASE_OFFSET: usize = 48;
/// Byte offset of the clock tick count at the conversion's base.
pub const VDSO_TICKS_BASE_OFFSET: usize = 56;
/// Byte offset of the 32.32 fixed-point counter-to-tick multiplier.
pub const VDSO_COUNTER_MULT_OFFSET: usize = 64;

// ── Second hwcap word and layout version (byte offsets 72..84) ──────────────

/// Byte offset of the `hwcap2` word (`u64`), the AT_HWCAP2 analogue: the
/// overflow word for when an ISA's first [`VDSO_HWCAP_OFFSET`] word fills,
/// numbered per ISA from 0 like the first. Reserved: no ISA defines a bit
/// in it yet, so the kernel leaves it 0.
pub const VDSO_HWCAP2_OFFSET: usize = 72;
/// Byte offset of the layout version (`u32`). Written once by the kernel at
/// boot, before the first user task, outside the seqlock (like `flags` and
/// `hwcap`).
pub const VDSO_LAYOUT_VERSION_OFFSET: usize = 80;
/// Layout version the kernel writes.
pub const VDSO_LAYOUT_VERSION: u32 = 2;
/// Byte offset of the ABI version (`u32`): [`crate::ABI_VERSION`], the version
/// of the native ABI this kernel implements. Written once by the kernel at boot,
/// before the first user task, outside the seqlock. `libsys::abi_matches`
/// compares it with the version the program was built against.
pub const VDSO_ABI_VERSION_OFFSET: usize = 84;
/// Byte offset of the clock words ([`crate::time::ClockWords`], 32 bytes to the
/// end of the page's data): the real, TAI and boot offsets that
/// `libsys::clock_now` adds to the monotonic clock, under their own
/// seqlock generation (not the page's `seq`). Layout version 2.
pub const VDSO_CLOCK_WORDS_OFFSET: usize = 88;

// ── aarch64 (ID registers, `arch/aarch64/src/features.rs`) ──────

/// aarch64 FEAT_CRC32: `crc32{b,h,w,x}` / `crc32c*` (ID_AA64ISAR0_EL1.CRC32 >= 1).
pub const HWCAP_A64_CRC32: u64 = 1 << 0;
/// aarch64 FEAT_AES: `aese`/`aesd`/`aesmc`/`aesimc` (ISAR0.AES >= 1).
pub const HWCAP_A64_AES: u64 = 1 << 1;
/// aarch64 FEAT_PMULL: 64x64 polynomial multiply (ISAR0.AES >= 2).
pub const HWCAP_A64_PMULL: u64 = 1 << 2;
/// aarch64 FEAT_SHA256: `sha256h`/`sha256h2`/`sha256su0`/`sha256su1` (ISAR0.SHA2 >= 1).
pub const HWCAP_A64_SHA2: u64 = 1 << 3;
/// aarch64 FEAT_LSE: the v8.1 atomics (ISAR0.Atomic >= 2).
pub const HWCAP_A64_ATOMICS: u64 = 1 << 4;

// aarch64, OS-enabled: the CPU having it is not enough.

/// aarch64 FEAT_PAuth (ISAR1.APA or API >= 1) with the EL0 instruction key
/// enabled (SCTLR_EL1.EnIA). Without EnIA `pacia`/`autia` are no-ops, so
/// the bit stays 0: today the kernel does not enable it.
pub const HWCAP_A64_PAUTH: u64 = 1 << 5;
/// aarch64 FEAT_BTI (PFR1.BT >= 1) with ring 3's text mapped as guarded
/// pages (the GP bit in its leaf descriptors). Without GP a `bti` pad is a
/// no-op and nothing is enforced: today the bit stays 0.
pub const HWCAP_A64_BTI: u64 = 1 << 6;
/// aarch64 FEAT_MTE (PFR1.MTE >= 1) with EL0 tag access (SCTLR_EL1.ATA0)
/// and a Normal-Tagged attribute in MAIR_EL1. Without them tag loads and
/// stores read 0 / are ignored: today the bit stays 0.
pub const HWCAP_A64_MTE: u64 = 1 << 7;
/// aarch64 MTE with tag checking (PFR1.MTE >= 2), so a synchronous
/// (precise) tag-check fault is available. Only with [`HWCAP_A64_MTE`].
pub const HWCAP_A64_MTE_SYNC: u64 = 1 << 8;
/// aarch64 FEAT_SVE (PFR0.SVE >= 1) with EL0 SVE untrapped (CPACR_EL1.ZEN
/// in the value ring 3 runs with). The kernel neither grants it nor saves
/// the SVE state: today the bit stays 0.
pub const HWCAP_A64_SVE: u64 = 1 << 9;
/// aarch64 PMUv3 cycle counter readable from EL0 (`mrs x, PMCCNTR_EL0`):
/// the probe found it live AND the kernel opened it (`PMUSERENR_EL0`, Kconfig
/// `PMU_USER`). Without the bit that read is an Undefined Instruction.
pub const HWCAP_A64_PMU_CYCLES: u64 = 1 << 10;
/// aarch64 PMUv3 retired-instruction counter readable from EL0
/// (`mrs x, PMEVCNTR0_EL0`, counting INST_RETIRED), as the cycle bit above.
/// Its width is 32 bits unless the PMU is v3p5.
pub const HWCAP_A64_PMU_INSTR: u64 = 1 << 11;

// ── riscv64 (cpu@0's device-tree ISA string) ────────────────────────────────

/// riscv64 Zbb: basic bit manipulation (`ror`, `rev8`, `clz`, ...).
pub const HWCAP_RV_ZBB: u64 = 1 << 0;
/// riscv64 Zbc: carry-less multiply (`clmul`, `clmulh`, `clmulr`).
pub const HWCAP_RV_ZBC: u64 = 1 << 1;
/// riscv64 V: the vector extension. Published only when the kernel also
/// lets ring 3 use it (it saves and restores the vector state).
pub const HWCAP_RV_V: u64 = 1 << 2;
/// riscv64 Zknh: SHA-2 instructions (`sha256sum0/1`, `sha256sig0/1`, ...).
pub const HWCAP_RV_ZKNH: u64 = 1 << 3;
/// riscv64 `rdcycle` readable from U-mode: the probe found it live AND the
/// kernel set `scounteren.CY` (Kconfig `PMU_USER`). Without the bit it traps.
pub const HWCAP_RV_PMU_CYCLES: u64 = 1 << 4;
/// riscv64 `rdinstret` readable from U-mode (`scounteren.IR`), as above.
pub const HWCAP_RV_PMU_INSTR: u64 = 1 << 5;

// ── x86_64 (CPUID, `arch/x86_64/src/features.rs`) ───────────────
//
// Each under its Kconfig `X86_<NAME>` policy.

/// x86_64 SSE4.2 (with SSE3/SSSE3/SSE4.1): `crc32`, `pcmpistri`, ...
pub const HWCAP_X86_SSE4_2: u64 = 1 << 0;
/// x86_64 POPCNT.
pub const HWCAP_X86_POPCNT: u64 = 1 << 1;
/// x86_64 AVX2, only with the YMM state enabled in XCR0 (the kernel saves
/// it per task; an XSAVE area too small for it clears the bit).
pub const HWCAP_X86_AVX2: u64 = 1 << 2;
/// x86_64 BMI1 (`andn`, `blsr`, `tzcnt`, ...).
pub const HWCAP_X86_BMI1: u64 = 1 << 3;
/// x86_64 BMI2 (`pdep`, `pext`, `mulx`, `shlx`, ...).
pub const HWCAP_X86_BMI2: u64 = 1 << 4;
/// x86_64 FMA3, only with the YMM state enabled in XCR0 (as AVX2).
pub const HWCAP_X86_FMA: u64 = 1 << 5;
/// x86_64 MOVBE.
pub const HWCAP_X86_MOVBE: u64 = 1 << 6;
/// x86_64 AES-NI (`aesenc`, `aesdec`, ...).
pub const HWCAP_X86_AES: u64 = 1 << 7;
/// x86_64 PCLMULQDQ: carry-less multiply.
pub const HWCAP_X86_PCLMULQDQ: u64 = 1 << 8;
/// x86_64 SHA-NI (`sha256rnds2`, `sha256msg1/2`, `sha1*`).
pub const HWCAP_X86_SHA_NI: u64 = 1 << 9;
/// x86_64 RDRAND.
pub const HWCAP_X86_RDRAND: u64 = 1 << 10;
/// x86_64 RDSEED.
pub const HWCAP_X86_RDSEED: u64 = 1 << 11;
/// x86_64 ADX (`adcx`, `adox`).
pub const HWCAP_X86_ADX: u64 = 1 << 12;
/// x86_64 FSGSBASE (`rdfsbase`, `wrgsbase`, ...), only with CR4.FSGSBASE
/// set: without it the instructions #UD. Today the kernel does not set it,
/// so the bit stays 0.
pub const HWCAP_X86_FSGSBASE: u64 = 1 << 13;
/// x86_64 protection keys (`rdpkru`/`wrpkru`), only with CR4.PKE set:
/// without it they #UD. Today the bit stays 0.
pub const HWCAP_X86_PKU: u64 = 1 << 14;
/// x86_64 CET indirect-branch tracking, only with CR4.CET set (nothing is
/// enforced without it). Today the bit stays 0.
pub const HWCAP_X86_CET_IBT: u64 = 1 << 15;
/// x86_64 CET shadow stack, only with CR4.CET set. Today the bit stays 0.
pub const HWCAP_X86_CET_SHSTK: u64 = 1 << 16;
/// x86_64 invariant TSC (CPUID.0x80000007:EDX\[8\]): `rdtsc` (and the vDSO
/// counter scale) keeps its rate across C/P-states. A property, not an
/// instruction: ring 3 may trust a TSC delta as time.
pub const HWCAP_X86_INVARIANT_TSC: u64 = 1 << 17;
/// x86_64 cycle counter readable from ring 3 with `rdpmc` (`CR4.PCE`, Kconfig
/// `PMU_USER`), the probe having found it live. The `rdpmc` index is
/// [`HWCAP_X86_PMU_FIXED`]'s.
pub const HWCAP_X86_PMU_CYCLES: u64 = 1 << 18;
/// x86_64 retired-instruction counter readable with `rdpmc`, as above.
pub const HWCAP_X86_PMU_INSTR: u64 = 1 << 19;
/// x86_64: the counters are Intel's fixed-function ones, so `rdpmc` takes
/// `(1 << 30) | 1` for cycles and `1 << 30` for instructions; clear (AMD),
/// they are core counters 0 (cycles) and 1 (instructions). Counters are 48
/// bits wide.
pub const HWCAP_X86_PMU_FIXED: u64 = 1 << 20;

// ── Per-ISA tables ──────────────────────────────────────────────────────────
//
// Each ISA's bits, listed once. `*_ALL` is their union; the asserts below
// prove every bit is a single bit and none repeats within its ISA (the union
// of N distinct single bits has N bits set). Across ISAs the numbers overlap
// by design.

const fn all_unique_single_bits(bits: &[u64]) -> bool {
    let mut all = 0u64;
    let mut i = 0;
    while i < bits.len() {
        if bits[i].count_ones() != 1 || all & bits[i] != 0 {
            return false;
        }
        all |= bits[i];
        i += 1;
    }
    true
}

const fn union(bits: &[u64]) -> u64 {
    let mut all = 0u64;
    let mut i = 0;
    while i < bits.len() {
        all |= bits[i];
        i += 1;
    }
    all
}

const A64_BITS: [u64; 12] = [
    HWCAP_A64_CRC32, HWCAP_A64_AES, HWCAP_A64_PMULL, HWCAP_A64_SHA2, HWCAP_A64_ATOMICS,
    HWCAP_A64_PAUTH, HWCAP_A64_BTI, HWCAP_A64_MTE, HWCAP_A64_MTE_SYNC, HWCAP_A64_SVE,
    HWCAP_A64_PMU_CYCLES, HWCAP_A64_PMU_INSTR,
];
const RV_BITS: [u64; 6] = [
    HWCAP_RV_ZBB, HWCAP_RV_ZBC, HWCAP_RV_V, HWCAP_RV_ZKNH, HWCAP_RV_PMU_CYCLES, HWCAP_RV_PMU_INSTR,
];
const X86_BITS: [u64; 21] = [
    HWCAP_X86_SSE4_2, HWCAP_X86_POPCNT, HWCAP_X86_AVX2, HWCAP_X86_BMI1, HWCAP_X86_BMI2,
    HWCAP_X86_FMA, HWCAP_X86_MOVBE, HWCAP_X86_AES, HWCAP_X86_PCLMULQDQ, HWCAP_X86_SHA_NI,
    HWCAP_X86_RDRAND, HWCAP_X86_RDSEED, HWCAP_X86_ADX, HWCAP_X86_FSGSBASE, HWCAP_X86_PKU,
    HWCAP_X86_CET_IBT, HWCAP_X86_CET_SHSTK, HWCAP_X86_INVARIANT_TSC,
    HWCAP_X86_PMU_CYCLES, HWCAP_X86_PMU_INSTR, HWCAP_X86_PMU_FIXED,
];

/// Every bit aarch64 defines in the `hwcap` word.
pub const HWCAP_A64_ALL: u64 = union(&A64_BITS);
/// Every bit riscv64 defines in the `hwcap` word.
pub const HWCAP_RV_ALL: u64 = union(&RV_BITS);
/// Every bit x86_64 defines in the `hwcap` word.
pub const HWCAP_X86_ALL: u64 = union(&X86_BITS);

const _: () = assert!(all_unique_single_bits(&A64_BITS));
const _: () = assert!(all_unique_single_bits(&RV_BITS));
const _: () = assert!(all_unique_single_bits(&X86_BITS));
const _: () = assert!(
    HWCAP_A64_ALL.count_ones() as usize == A64_BITS.len()
        && HWCAP_RV_ALL.count_ones() as usize == RV_BITS.len()
        && HWCAP_X86_ALL.count_ones() as usize == X86_BITS.len()
);
