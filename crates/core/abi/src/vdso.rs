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
// The per-task vDSO page (SYS_VDSO_TASK_MAP, 594): its layout is ABI
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
/// `u32`: bit `t` set when a `Cap<Sensor>` for type `t` was bound.
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
// execute, detected at boot from the ID registers (aarch64) or the device
// tree's `riscv,isa` / `riscv,isa-extensions` of cpu@0 (riscv64), never from
// build flags. Written once before the first user task; 0 means "nothing
// beyond the base ISA" (or a kernel too old to publish it). One word for both
// ISAs, disjoint bit ranges, so a bit never means two things.

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
/// riscv64 Zbb: basic bit manipulation (`ror`, `rev8`, `clz`, ...).
pub const HWCAP_RV_ZBB: u64 = 1 << 32;
/// riscv64 Zbc: carry-less multiply (`clmul`, `clmulh`, `clmulr`).
pub const HWCAP_RV_ZBC: u64 = 1 << 33;
/// riscv64 V: the vector extension. Published only when the kernel also
/// lets ring 3 use it (it saves and restores the vector state).
pub const HWCAP_RV_V: u64 = 1 << 34;
/// riscv64 Zknh: SHA-2 instructions (`sha256sum0/1`, `sha256sig0/1`, ...).
pub const HWCAP_RV_ZKNH: u64 = 1 << 35;
