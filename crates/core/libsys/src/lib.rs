// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `libsys` — Userspace syscall wrapper library for azos.
//!
//! Provides safe Rust wrappers around the kernel's trap ABI so that
//! no_std ELF programs can make syscalls without writing inline assembly.
//!
//! ABI convention (RISC-V 64):
//!   a7 = syscall number
//!   a0..a5 = arguments
//!   ecall
//!   a0 = return value (i64, negative = error)
//!
//! ABI convention (AArch64):
//!   x8 = syscall number
//!   x0..x5 = arguments
//!   svc #0
//!   x0 = return value (i64, negative = error)
//!
//! ABI convention (x86_64):
//!   rax = syscall number
//!   rdi, rsi, rdx, r10, r8, r9 = arguments
//!   syscall
//!   rax = return value (i64, negative = error)
//!
//! The RISC-V and AArch64 conventions are a direct, register-for-register
//! analogue of each other (`x0..=x5` for `a0..=a5`, `x8` for `a7`); all three
//! are documented in full, including what the kernel must preserve/clobber,
//! in `crates/core/abi/src/syscall_nr.rs`'s "Register convention" section, the
//! canonical home for this. Every raw `asm!` block below that issues a
//! trap is `#[cfg(target_arch = ..)]`-selected within a single function
//! body, so each wrapper is one function on every ISA and the codegen of one
//! ISA is not touched by the branches of the others.

#![no_std]

// Every syscall primitive below selects its trap instruction per ISA; on
// an ISA with no branch the build stops here instead of losing the trap.
#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("libsys: no syscall instruction for this ISA (riscv32, riscv64, aarch64, x86_64)");
// The full API (every item outside the rv32 subset) has a branch per 64-bit
// ISA; a new 64-bit ISA stops here instead of losing those branches.
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64", target_pointer_width = "32")))]
compile_error!("libsys: the full API has no branch for this 64-bit ISA");

// riscv32 (AzOS-micro) has the small API of `rv32` and none of the rest: the
// rest is written in 64-bit words (the rings need 64-bit atomics, the syscall
// wrappers take `u64`), and truncating those silently is worse than not
// compiling. `word64!` wraps every item of that API; it is the one cfg for
// the whole of it.
#[cfg(target_arch = "riscv32")]
mod rv32;
#[cfg(target_arch = "riscv32")]
pub use rv32::*;

macro_rules! word64 {
    ($($item:item)*) => { $( #[cfg(not(target_arch = "riscv32"))] $item )* };
}

// The process entry: the target spec names `_azos_entry` for every native
// image (`-e`, sdk/targets/*.json). A `std` program gets it from
// `azos_stdrt` and a C program from relibc (`tools/sdk_cargo.py` and
// `tools/relibc_build.sh` build with `--cfg azos_std`); any other
// program's `_start` is a Rust function, entered from here with the kernel's
// argument registers untouched (the spawn startup block arrives in the second).
//
// riscv64 and aarch64: a tail jump.
#[cfg(all(target_arch = "riscv64", target_os = "azos", not(azos_std)))]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, @function",
    "_azos_entry:",
    "    j _start",
    ".size _azos_entry, . - _azos_entry",
);
#[cfg(all(target_arch = "aarch64", target_os = "azos", not(azos_std)))]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, %function",
    "_azos_entry:",
    "    b _start",
    ".size _azos_entry, . - _azos_entry",
);
// x86_64 (System V): the kernel starts an image with rsp 16-byte aligned, and
// a function expects rsp + 8 aligned (a `call` pushed its return address):
// realign, call `_start`, never return.
#[cfg(all(target_arch = "x86_64", target_os = "azos", not(azos_std)))]
core::arch::global_asm!(
    ".globl _azos_entry",
    ".type _azos_entry, @function",
    "_azos_entry:",
    "    xor ebp, ebp",
    "    and rsp, -16",
    "    call _start",
    "    ud2",
    ".size _azos_entry, . - _azos_entry",
);

#[cfg(not(target_arch = "riscv32"))]
mod pure;
#[cfg(not(target_arch = "riscv32"))]
pub use pure::*;
#[cfg(not(target_arch = "riscv32"))]
pub mod utest;
#[cfg(not(target_arch = "riscv32"))]
pub mod ioring;
#[cfg(not(target_arch = "riscv32"))]
pub mod pipe;
#[cfg(not(target_arch = "riscv32"))]
mod lock;
#[cfg(not(target_arch = "riscv32"))]
pub use lock::{Lock, LockGuard};

#[cfg(not(target_arch = "riscv32"))]
pub mod dev;

word64! {
use core::arch::asm;

/// `#[main]` and `#[test]` (`azos_libsys_macros`): a program's entry and panic
/// handler, and a test for [`utest`]. Import this crate as `azos` to write
/// `#[azos::main]`.
pub use azos_libsys_macros::{main, test};
// The rings over shared memory (`azos_rings::region`, so the kernel can
// produce into them): every item at this crate's root.
pub use azos_rings::region::*;

// ---------------------------------------------------------------------------
// Syscall numbers.
//
// `crates/core/abi` is the single source of truth (`crates/core/abi/src/syscall_nr.rs`).
// These names are imported, not restated, so a number can no longer drift
// between the kernel-facing definition and this userspace wrapper crate.
// ---------------------------------------------------------------------------
use azos_abi::syscall_nr::{CAP_INFO_LOOKUP, CAP_INFO_QUERY};
use azos_abi::syscall_nr::{
    SYS_EXIT, SYS_INVOKE,
    SYS_GETPID, SYS_YIELD,
    SYS_THREAD_CREATE, SYS_THREAD_EXIT, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
    SYS_CAP_INFO, SYS_CAP_CLOSE, SYS_CAP_DERIVE, SYS_CAP_REVOKE,
    SYS_IPC_FAST_CALL_EP,
    SYS_IPC_FAST_REPLY, SYS_IPC_FAST_ACCEPT,
    SYS_MO_CREATE, SYS_MO_UNMAP,
    SYS_RING_SETUP, SYS_RING_ENTER,
    SYS_MO_MAP,
    SYS_IPC_FAST_REPLY_ACCEPT,
    SYS_SLEEP_UNTIL, SLEEP_RELATIVE,
    SYS_PORT_WAIT,
    SYS_SPAWN_EX, SYS_ALERT,
    SYS_IPC_CALL_V2, SYS_IPC_ACCEPT_V2, SYS_IPC_REPLY_V2, SYS_IPC_REPLY_DELEGATE,
    SYS_SCHEDCTL,
    SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME, SYS_FOREIGN_FORK,
};

// Sensor type IDs: the badge of a `sensor.<type>` endpoint (`dev::lookup(key::SENSOR, ty)`)
pub const SENSOR_TYPE_IMU: u64 = 0;
pub const SENSOR_TYPE_ODOM: u64 = 1;
pub const SENSOR_TYPE_ENCODER: u64 = 2;
pub const SENSOR_TYPE_RANGE: u64 = 3;
pub const SENSOR_TYPE_BATTERY: u64 = 4;
pub const SENSOR_TYPE_GPS: u64 = 5;
pub const SENSOR_TYPE_LIDAR: u64 = 6;
pub const SENSOR_TYPE_GPIO_FLAGS: u64 = 7;
pub const SENSOR_TYPE_CAMERA: u64 = 8;
pub const SENSOR_TYPE_POWER: u64 = 9;

// Driver-server family (E11.AQ3) — a userspace process serves a
// driver `kind` for the in-kernel UserDriverProxy. Distinct from the
// SYS_DRV_* (300) MMIO-ownership family above.

// Untyped shared memory (F00.4). `SYS_IPC_MAP` is gated to the region's
// creator (`dispatch.rs`, SYS_IPC_MAP arm) — cross-task sharing is the
// typed `Cap<Shm>` path's job, not this one.

// Cap<T> typed IPC. Numbers come from
// `crates/core/abi/src/syscall_nr.rs` via the `use` above — no longer mirrored
// or independently diffed here.

/// Security profile IDs for seccomp().
pub const PROFILE_UNRESTRICTED: u64 = 0;
pub const PROFILE_NET: u64 = 1;
pub const PROFILE_MINIMAL: u64 = 2;

/// Activate a syscall filter profile (one-way — cannot be undone).
/// After this call, only syscalls in the profile whitelist are allowed.
pub fn seccomp(profile_id: u64) -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_SET_FILTER, [profile_id, 0, 0, 0]).0
}

/// Narrow what this Domain may ask of the kernel to `mask` (`azos_abi::invoke`'s
/// `PLEDGE_*` bits: [`invoke_abi::pledge_case`], [`invoke_abi::pledge_class`]),
/// one way: nothing a Domain narrows is widened again, and the Domains it
/// creates afterwards start narrowed. A program calls it once its setup is
/// done. Returns the mask now in force; `-EINVAL` for a bit that names nothing,
/// `-EACCES` for a mask wider than the one in force. A call outside the mask is
/// answered `-EACCES` without running.
pub fn pledge(mask: u32) -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_PLEDGE, [mask as u64, 0, 0, 0]).0
}

// ---------------------------------------------------------------------------
// M01: vDSO — zero-ecall kernel time queries
// ---------------------------------------------------------------------------

/// User-space virtual address of the vDSO page.
///
/// Single source: `azos_abi::vdso::VDSO_USER_BASE`. Both `crates/core/mm`
/// (kernel side, maps the page) and this crate (ring 3, reads it directly
/// without a syscall) depend on `abi`, so the same numeric value reaches
/// both compilations without being restated.
use azos_abi::vdso::VDSO_USER_BASE;

/// Read the monotonic uptime tick counter from the vDSO page without issuing
/// an ecall.
///
/// **U07-4: "falls back to 0" is true only if the page exists and reads bad
/// magic.** `vdso_read_u64` checks the magic word before trusting the rest of
/// the page and returns 0 on a mismatch — but that check is itself a read of
/// byte 0, through the same raw pointer at [`VDSO_USER_BASE`]. If the kernel
/// never mapped anything there (the vDSO mapping in
/// `crates/core/sched/src/process.rs` is skipped on VF2/K1 with
/// DTB-sized real RAM — the `VDSO_FITS_BELOW_USER_CEILING` gate can be false,
/// or `vdso::vdso_phys()` can be 0), that first read is a load from an unmapped page and the task
/// takes a page fault. There is **no software fallback for that case**: a
/// missing PTE faults before any value is available to branch on. Do not
/// call this (or [`vdso_now_ns`], or [`vdso_rdtime_native`], which reads the
/// same page unconditionally) on a board that has not itself proven the vDSO
/// page is mapped this run; [`uptime`] is the one caller in this file for
/// which that matters and it is not proven safe either (see its own doc).
/// The real fix is on the kernel side (audit U07-4 Q4): always map a page at
/// `VDSO_USER_BASE`, zero-filled (magic 0) when the real one cannot be
/// placed, so the read this function does is always into mapped memory and
/// "falls back to 0" becomes true again.
///
/// # Safety
/// Reads from a read-only page the kernel is expected, but not guaranteed on
/// every board, to have mapped into this process. See above.
pub fn vdso_uptime_ticks() -> u64 {
    // uptime_ticks is at byte offset 16 (magic u32 + kernel_version u32 +
    // seq u32 + flags u32). Offset 8 is `seq` itself: reading it returned the
    // seqlock counter, which advances by 2 per publish and so still looks
    // like a plausible monotonic tick counter — which is why this went
    // unnoticed. See the layout comment in `vdso_read_u64` below.
    unsafe { vdso_read_u64(16) }
}

/// Read the uptime in milliseconds from the vDSO page without issuing an ecall.
pub fn vdso_uptime_ms() -> u64 {
    unsafe { vdso_read_u64(24) } // uptime_ms at byte offset 24
}

/// Frequency of the `time` counter, in Hz, or 0 if the kernel does not
/// publish it.
pub fn vdso_timebase_hz() -> u64 {
    unsafe { vdso_read_u64(32) } // timebase_hz at byte offset 32
}

/// **Exact** monotonic nanoseconds, with no syscall.
///
/// **Why this exists when `vdso_uptime_ms` already does.** That value is
/// refreshed by the timer ISR, so its granularity is the tick period: at
/// 100 Hz, **10 milliseconds**. Cheap to read and late to arrive.
///
/// This does what the Linux vDSO does: read the hardware counter in ring 3
/// ([`read_time_csr`]: `rdtime`, `scounteren.TM` enabled, on riscv64) and
/// convert using the frequency the page publishes. The result is exact to the nanosecond for
/// the price of one CSR read and two divisions.
///
/// The division is done in two steps **to avoid overflow**: `ticks *
/// 1_000_000_000` leaves `u64` in about 30 minutes at 10 MHz, and a monotonic
/// clock that wraps after half an hour is worse than no clock at all.
///
/// Returns 0 if the page publishes no frequency — a kernel older than this, or
/// one with no vDSO mapped.
///
/// Guarded by [`vdso_rdtime_native`], as [`uptime`] is: where the kernel's
/// probe found the `time` read trapping, the reader takes the `ecall`.
pub fn vdso_now_ns() -> u64 {
    let hz = vdso_timebase_hz();
    if hz == 0 { return 0; }
    // riscv64: `rdtime` traps where the kernel's probe said so: honour the
    // vDSO flag and fall back to the ecall. aarch64: `cntvct_el0` is always EL0-readable
    // and the vDSO flag is a riscv64 statement — reading through the flag
    // there sent `uptime_ms`/`sleep` through DOMAIN_UPTIME's units (gate 182c).
    #[cfg(target_arch = "aarch64")]
    let ticks = read_time_csr();
    #[cfg(not(target_arch = "aarch64"))]
    let ticks = if vdso_rdtime_native() { read_time_csr() } else { uptime_ecall() as u64 };
    ticks_to_ns(ticks, hz)
}

/// The real, TAI and boot offsets the kernel published in the vDSO page
/// (`azos_abi::vdso::VDSO_CLOCK_WORDS_OFFSET`), read under their own
/// seqlock; all zero if no vDSO is mapped (bad magic), when every clock reads
/// as the monotonic one.
pub fn vdso_clock_offsets() -> ClockOffsets {
    // SAFETY: the page is mapped at VDSO_USER_BASE for every user task
    // (see `vdso_read_u64` for the board where it is not, and the magic
    // check in `page_clock_offsets`); `ClockWords` only loads here and the
    // page is 4 KiB.
    unsafe {
        pure::page_clock_offsets(
            core::ptr::read_volatile(VDSO_USER_BASE as *const u32),
            &*((VDSO_USER_BASE + azos_abi::vdso::VDSO_CLOCK_WORDS_OFFSET) as *const ClockWords),
        )
    }
}

/// Now, in nanoseconds, on clock `id`, with no syscall: the vDSO's monotonic
/// clock ([`vdso_now_ns`]) plus the published offset of `REAL`, `TAI` or
/// `BOOT` ([`vdso_clock_offsets`]). `MONO` reads no offset. The other ids
/// are reserved numbers and return [`ClockError::Unsupported`]. Before a time
/// source has set the wall clock, `REAL` and `TAI` read as `MONO`.
///
/// A deadline in a v2 message (`MsgDesc::deadline`) is read on the clock named
/// by its `clock_id`, so `clock_now(MONO)` is what a caller adds its budget
/// to.
pub fn clock_now(id: ClockId) -> Result<u64, ClockError> {
    clock_now_with(id, vdso_now_ns, vdso_clock_offsets)
}

/// The free-running hardware counter, read in ring 3: the RISC-V `time` CSR
/// (`scounteren.TM` is set in `trap_init`), on aarch64 the generic timer's
/// virtual counter `cntvct_el0`, on x86_64 the TSC scaled to the kernel
/// clock's ticks.
///
/// On aarch64 the kernel sets `CNTKCTL_EL1.EL0VCTEN` at boot (the analogue of
/// `scounteren.TM`) and publishes the same vDSO page as on the other ISAs, so
/// [`vdso_now_ns`] reads the counter there unconditionally: the vDSO `flags`
/// bit [`vdso_rdtime_native`] reads is a RISC-V statement, and `cntvct_el0`
/// never traps from EL0.
#[inline(always)]
fn read_time_csr() -> u64 {
    let t: u64;
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)); }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack)); }
    // x86_64: the TSC (`CR4.TSD` clear, so `rdtsc` runs in ring 3), turned
    // into the kernel clock's TIMER_FREQ ticks with the conversion the kernel
    // published (`azos_abi::vdso::VDSO_COUNTER_*`, written once before any
    // user task: no seqlock), the same arithmetic as its own `now_ticks`.
    // Only reached when the vDSO says the counter is native.
    #[cfg(target_arch = "x86_64")]
    {
        let (lo, hi): (u32, u32);
        unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); }
        let tsc = ((hi as u64) << 32) | lo as u64;
        // SAFETY: the page is mapped at VDSO_USER_BASE for every user task.
        let rd = |off: usize| unsafe { core::ptr::read_volatile((VDSO_USER_BASE + off) as *const u64) };
        let (base, ticks, mult) = (rd(azos_abi::vdso::VDSO_COUNTER_BASE_OFFSET),
                                   rd(azos_abi::vdso::VDSO_TICKS_BASE_OFFSET),
                                   rd(azos_abi::vdso::VDSO_COUNTER_MULT_OFFSET));
        t = ticks.wrapping_add(((tsc.wrapping_sub(base) as u128 * mult as u128) >> 32) as u64);
    }
    t
}

/// Does the kernel say `rdtime` works from ring 3 here (vDSO `flags` bit 0)?
///
/// The kernel sets the bit when its boot-time trap-probe of the `time` CSR
/// passes: the read is native, or M-mode firmware answers it (OpenSBI
/// emulates `time` on a hart without the CSR, which is still cheaper than the
/// `ecall`, whose handler reads the same CSR). It leaves the bit clear when
/// the probe trapped and when built to force the trap.
pub fn vdso_rdtime_native() -> bool {
    // `flags` is written once, before any user task runs, and never changes:
    // no seqlock, like the timebase and the magic.
    unsafe { rdtime_is_native(vdso_read_u32(0), vdso_read_u32(12)) }
}


/// The CPU capabilities ring 3 may use ([`hwcap`]`::HWCAP_*`, numbered per
/// ISA from 0): the kernel's AT_HWCAP analogue, detected at boot from the ID registers
/// (aarch64), CPUID (x86_64) or the device tree (riscv64), each under its
/// Kconfig policy. 0 when no vDSO page is mapped. Written once before any
/// user task runs: no seqlock. Test a bit before taking an instruction's
/// path; a clear bit means "take the fallback".
pub fn vdso_hwcap() -> u64 {
    // SAFETY: the page is mapped at VDSO_USER_BASE (or zero-filled); the
    // magic gates the read like every other field.
    unsafe {
        if vdso_read_u32(0) != VDSO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile((VDSO_USER_BASE + azos_abi::vdso::VDSO_HWCAP_OFFSET) as *const u64)
    }
}

/// The page's layout version (`azos_abi::vdso::VDSO_LAYOUT_VERSION`). Written
/// once before any user task runs: no seqlock.
pub fn vdso_layout_version() -> u32 {
    // SAFETY: the page is mapped at VDSO_USER_BASE; the offset is inside it.
    unsafe { vdso_read_u32(azos_abi::vdso::VDSO_LAYOUT_VERSION_OFFSET) }
}

/// The version of the native ABI the running kernel implements
/// (`azos_abi::ABI_VERSION`), as it publishes it in the vDSO page. 0 when no
/// page is mapped. Written once before any user task runs: no seqlock.
pub fn vdso_abi_version() -> u32 {
    // SAFETY: the page is mapped at VDSO_USER_BASE (or zero-filled); the offset
    // is inside it.
    unsafe { vdso_read_u32(azos_abi::vdso::VDSO_ABI_VERSION_OFFSET) }
}

/// Does the running kernel implement the ABI version this program was built
/// against? `false` is the answer a program refuses to continue on: its calls
/// would mean something else.
pub fn abi_matches() -> bool {
    vdso_abi_version() == azos_abi::ABI_VERSION
}

/// The ELF note that names the ABI version this program was built against. The
/// kernel's loader reads it from the image's `PT_NOTE` and refuses a mismatch
/// (see `azos_abi::ABI_VERSION`).
#[repr(C, align(4))]
struct AbiNote {
    namesz: u32,
    descsz: u32,
    ty: u32,
    name: [u8; 8],
    desc: u32,
}

#[used]
#[link_section = ".note.azos.abi"]
static ABI_NOTE: AbiNote = AbiNote {
    namesz: 5,
    descsz: 4,
    ty: azos_abi::ABI_NOTE_TYPE,
    name: *b"AZOS\0\0\0\0",
    desc: azos_abi::ABI_VERSION,
};

/// The second capability word (the AT_HWCAP2 analogue,
/// `azos_abi::vdso::VDSO_HWCAP2_OFFSET`): where an ISA's bits go once its
/// [`vdso_hwcap`] word fills. No ISA defines a bit in it yet, so today it
/// reads 0 everywhere.
pub fn vdso_hwcap2() -> u64 {
    // SAFETY: as `vdso_hwcap`.
    unsafe {
        core::ptr::read_volatile((VDSO_USER_BASE + azos_abi::vdso::VDSO_HWCAP2_OFFSET) as *const u64)
    }
}

/// The bits of [`vdso_hwcap`]. Each ISA numbers its own from 0 and the word
/// means what the running ISA's table says; `HWCAP_*_ALL` is each table's
/// union (their meaning and gating: `crates/core/abi/src/vdso.rs`).
pub mod hwcap {
    pub use azos_abi::vdso::{
        HWCAP_A64_AES, HWCAP_A64_ALL, HWCAP_A64_ATOMICS, HWCAP_A64_BTI, HWCAP_A64_CRC32,
        HWCAP_A64_MTE, HWCAP_A64_MTE_SYNC, HWCAP_A64_PAUTH, HWCAP_A64_PMULL, HWCAP_A64_SHA2,
        HWCAP_A64_PMU_CYCLES, HWCAP_A64_PMU_INSTR, HWCAP_A64_SVE, HWCAP_RV_ALL,
        HWCAP_RV_PMU_CYCLES, HWCAP_RV_PMU_INSTR, HWCAP_RV_V, HWCAP_RV_ZBB, HWCAP_RV_ZBC,
        HWCAP_RV_ZKNH, HWCAP_X86_PMU_CYCLES, HWCAP_X86_PMU_FIXED, HWCAP_X86_PMU_INSTR,
        HWCAP_X86_ADX, HWCAP_X86_AES, HWCAP_X86_ALL, HWCAP_X86_AVX2, HWCAP_X86_BMI1,
        HWCAP_X86_BMI2, HWCAP_X86_CET_IBT, HWCAP_X86_CET_SHSTK, HWCAP_X86_FMA,
        HWCAP_X86_FSGSBASE, HWCAP_X86_INVARIANT_TSC, HWCAP_X86_MOVBE, HWCAP_X86_PCLMULQDQ,
        HWCAP_X86_PKU, HWCAP_X86_POPCNT, HWCAP_X86_RDRAND, HWCAP_X86_RDSEED, HWCAP_X86_SHA_NI,
        HWCAP_X86_SSE4_2,
    };
}

/// Read the kernel version from the vDSO page.
pub fn vdso_kernel_version() -> u32 {
    unsafe { vdso_read_u32(4) } // kernel_version at byte offset 4
}

/// Internal seqlock-aware u64 read from vDSO page at given byte offset.
///
/// # Safety
/// `offset` must be within the vDSO page (< 4096).
#[inline]
unsafe fn vdso_read_u64(offset: usize) -> u64 {
    // Verify magic before trusting any data.
    let magic_ptr = (VDSO_USER_BASE) as *const u32;
    if core::ptr::read_volatile(magic_ptr) != VDSO_MAGIC {
        return 0;
    }
    // VdsoData layout (matches mm/vdso.rs):
    //   +0  magic:          u32
    //   +4  kernel_version: u32
    //   +8  seq:            u32  (seqlock counter)
    //   +12 flags:          u32  (written once, see `vdso_rdtime_native`)
    //   +16 uptime_ticks:   u64
    //   +24 uptime_ms:      u64
    //   +32 timebase_hz:    u64  (written once; the rest below too)
    //   +40 hwcap:          u64
    //   +48 counter_base, +56 ticks_base, +64 counter_mult: u64
    //   +72 hwcap2:         u64
    //   +80 layout_version: u32
    let seq_ptr   = (VDSO_USER_BASE + 8)      as *const u32;
    let data_ptr  = (VDSO_USER_BASE + offset)  as *const u64;

    loop {
        let seq1 = core::ptr::read_volatile(seq_ptr);
        if seq1 & 1 != 0 {
            // Write in progress — spin.
            core::hint::spin_loop();
            continue;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let val = core::ptr::read_volatile(data_ptr);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let seq2 = core::ptr::read_volatile(seq_ptr);
        if seq1 == seq2 {
            return val;
        }
        core::hint::spin_loop();
    }
}

/// Internal u32 read from vDSO page at given byte offset (no seqlock — fields
/// written once at init time so always consistent).
#[inline]
unsafe fn vdso_read_u32(offset: usize) -> u32 {
    core::ptr::read_volatile((VDSO_USER_BASE + offset) as *const u32)
}

// ---------------------------------------------------------------------------
// Wave 6: the per-task vDSO page, futex waits on ring words, and SPSC rings over shm
// ---------------------------------------------------------------------------

use azos_abi::vdso::{
    VDSO_TASK_MAGIC, VTP_CPU_TIME, VTP_LAST_READY_SITE, VTP_LAST_SAMPLE, VTP_MAGIC,
    VTP_OWNER_TID, VTP_PUBLISHES, VTP_SENSORS, VTP_SENSOR_DATA, VTP_SENSOR_DATA_MAX,
    VTP_SENSOR_MASK, VTP_SENSOR_SLOTS, VTP_SENSOR_STRIDE, VTP_SEQ, VTP_SW_PREEMPTED,
    VTP_SW_VOLUNTARY, VTP_SENSOR_ACQ_NS, VTP_VERSION,
};

/// Where [`vdso_task_map`] mapped this process's per-task page; 0 = not yet.
static VDSO_TASK_VA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Map this task's own vDSO page (`DOMAIN_VDSO_MAP`) and remember
/// where. Returns the user address, or `-Errno`. Idempotent.
///
/// A forked child does not inherit the mapping (the kernel leaves the
/// shm/MMIO window out of a fork), and the remembered address is the
/// parent's: a child calls this again before reading.
pub fn vdso_task_map() -> isize {
    let r = domain_op(invoke_abi::DOMAIN_VDSO_MAP, [0; 4]);
    if r > 0 {
        VDSO_TASK_VA.store(r as usize, core::sync::atomic::Ordering::Release);
    }
    r
}

/// Read `f` from the per-task page under its seqlock. `None` when the page is
/// not mapped in this process or carries the wrong magic.
#[inline]
fn vdso_task_read<T>(mut f: impl FnMut(usize) -> T) -> Option<T> {
    use core::sync::atomic::{fence, Ordering};
    let base = VDSO_TASK_VA.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    // SAFETY: `base` is the page `vdso_task_map` mapped read-only into this
    // process; every offset below is inside it.
    unsafe {
        if core::ptr::read_volatile((base + VTP_MAGIC) as *const u32) != VDSO_TASK_MAGIC {
            return None;
        }
        let seq = (base + VTP_SEQ) as *const u32;
        loop {
            let s1 = core::ptr::read_volatile(seq);
            if s1 & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            fence(Ordering::Acquire);
            let v = f(base);
            fence(Ordering::Acquire);
            if core::ptr::read_volatile(seq) == s1 {
                return Some(v);
            }
        }
    }
}

/// This task's own counters, from its page. See `VdsoTaskPage` in
/// `crates/core/mm/src/vdso.rs` for what each is and how fresh.
#[derive(Clone, Copy, Debug, Default)]
pub struct VdsoTaskCounters {
    pub owner_tid: u32,
    /// Timebase ticks, sampled at timer interrupts (tick-granular).
    pub cpu_time: u64,
    pub switches_voluntary: u64,
    pub switches_preempted: u64,
    /// `ready_site` tag: low nibble 1 create, 2 preempt, 3 kc24, 4 wake,
    /// 5 reap, 6 rebalance; high nibble the hart that set it.
    pub last_ready_site: u32,
    pub sensor_mask: u32,
    pub publishes: u64,
    pub last_sample: u64,
}

/// Read [`VdsoTaskCounters`] without a syscall. `None` before [`vdso_task_map`].
pub fn vdso_task_counters() -> Option<VdsoTaskCounters> {
    vdso_task_read(|b| unsafe {
        let u32_at = |o: usize| core::ptr::read_volatile((b + o) as *const u32);
        let u64_at = |o: usize| core::ptr::read_volatile((b + o) as *const u64);
        VdsoTaskCounters {
            owner_tid: u32_at(VTP_OWNER_TID),
            cpu_time: u64_at(VTP_CPU_TIME),
            switches_voluntary: u64_at(VTP_SW_VOLUNTARY),
            switches_preempted: u64_at(VTP_SW_PREEMPTED),
            last_ready_site: u32_at(VTP_LAST_READY_SITE),
            sensor_mask: u32_at(VTP_SENSOR_MASK),
            publishes: u64_at(VTP_PUBLISHES),
            last_sample: u64_at(VTP_LAST_SAMPLE),
        }
    })
}

/// One published sensor value's header, from [`vdso_sensor_read`].
#[derive(Clone, Copy, Debug)]
pub struct VdsoSensorValue {
    /// Publications of this sensor into the page (never 0 here).
    pub seq: u32,
    /// Bytes copied into the caller's buffer.
    pub len: usize,
    /// Timebase counter when PUBLISHED into the page.
    pub stamp: u64,
    /// When the value was ACQUIRED, on [`vdso_now_ns`]'s clock — the stamp
    /// the sensor interface reports for the same read. 0 when unknown,
    /// including on a page older than layout version 2.
    pub acq_ns: u64,
}

/// Copy sensor `sensor_type`'s latest published value into `out`, without a
/// syscall. `None` when the page is not mapped, the type has no slot, or
/// nothing was published into it (the kernel publishes only bound sensors).
pub fn vdso_sensor_read(sensor_type: u32, out: &mut [u8]) -> Option<VdsoSensorValue> {
    if sensor_type as usize >= VTP_SENSOR_SLOTS {
        return None;
    }
    let slot = VTP_SENSORS + sensor_type as usize * VTP_SENSOR_STRIDE;
    // Whole words inside the seqlock, bytes after it: a `copy_from_slice`
    // per word here is a `memcpy` call per word, which cost ten times the
    // read itself in the first measurement of this lane.
    let mut w = [0u64; VTP_SENSOR_DATA_MAX / 8];
    let (mask, seq, len, stamp, acq_ns) = vdso_task_read(|b| unsafe {
        for (i, x) in w.iter_mut().enumerate() {
            *x = core::ptr::read_volatile((b + slot + VTP_SENSOR_DATA + i * 8) as *const u64);
        }
        // Inside the seqlock with the payload it stamps. A version-1 page
        // keeps padding there, which the kernel zeroed: read as "unknown".
        let acq = if core::ptr::read_volatile((b + VTP_VERSION) as *const u32) >= 2 {
            core::ptr::read_volatile((b + slot + VTP_SENSOR_ACQ_NS) as *const u64)
        } else {
            0
        };
        (
            core::ptr::read_volatile((b + VTP_SENSOR_MASK) as *const u32),
            core::ptr::read_volatile((b + slot) as *const u32),
            core::ptr::read_volatile((b + slot + 4) as *const u32) as usize,
            core::ptr::read_volatile((b + slot + 8) as *const u64),
            acq,
        )
    })?;
    // `seq == 0` alone decides, not `mask` too: the KERNEL is what keeps an
    // unbound sensor out of the page, and a reader that also filtered on the
    // mask would hide a kernel that published one anyway — which is the
    // failure `vsbench`'s scope canary exists to catch.
    let _ = mask;
    if seq == 0 {
        return None;
    }
    let n = len.min(out.len()).min(VTP_SENSOR_DATA_MAX);
    let (whole, tail) = out[..n].split_at_mut(n & !7);
    for (c, x) in whole.chunks_exact_mut(8).zip(w.iter()) {
        c.copy_from_slice(&x.to_le_bytes());
    }
    let last = w[(n / 8).min(w.len() - 1)].to_le_bytes();
    tail.copy_from_slice(&last[..tail.len()]);
    Some(VdsoSensorValue { seq, len: n, stamp, acq_ns })
}


/// [`futex_wait`] on a word named by address: the index words of a shm ring,
/// which the ring code holds as a `usize` into a region this task maps. The
/// kernel keys such a word by its region and offset, so the peer that maps the
/// region elsewhere meets it on the same word.
pub fn futex_wait_addr(addr: usize, expected: u32, timeout_ns: u64) -> isize {
    unsafe { syscall3(SYS_FUTEX_WAIT, addr as u64, expected as u64, timeout_ns) }
}

/// [`futex_wake`] on a word named by address ([`futex_wait_addr`]).
pub fn futex_wake_addr(addr: usize, n: u32) -> isize {
    unsafe { syscall2(SYS_FUTEX_WAKE, addr as u64, n as u64) }
}

/// `-ETIMEDOUT`: what a futex wait answers when its timeout passes.
pub const FUTEX_ETIMEDOUT: isize = -110;

/// Kernel entries a ring side made, for the caller to report.
#[derive(Clone, Copy, Debug, Default)]
pub struct RingStats {
    /// `SYS_FUTEX_WAIT` calls (the side found the ring empty/full).
    pub waits: u64,
    /// `SYS_FUTEX_WAKE` calls (the other side said it may be asleep).
    pub wakes: u64,
    /// Waits that ended by timeout. A correct pair never times out in a
    /// running exchange: each one is a wake that did not arrive.
    pub timeouts: u64,
}

/// Backstop on every ring sleep. Never reached by a working pair (see
/// [`RingStats::timeouts`]); it keeps a lost wake from hanging the caller.
pub const RING_WAIT_NS: u64 = 1_000_000_000;

/// Sleep as `s` says, then withdraw the announcement (`woke`) whatever
/// ended the wait.
fn ring_sleep(s: RingSleep, woke: impl FnOnce(), stats: &mut RingStats) {
    if let RingSleep::Wait { addr, expected } = s {
        stats.waits += 1;
        if futex_wait_addr(addr, expected, RING_WAIT_NS) == FUTEX_ETIMEDOUT {
            stats.timeouts += 1;
        }
        woke();
    }
}

/// Append `v`, sleeping while the ring is full. Enters the kernel only to
/// sleep on a full ring or to wake a consumer that said it may be asleep.
///
/// Chain E commit 8: nothing this function holds lives across a trap but
/// what the trap preserves. A native syscall clobbers the temporaries
/// (riscv64 t0-t6/a7, aarch64 x7-x17: crates/core/abi/src/syscall_nr.rs,
/// "Register contract"), so a body that slept and retried inline kept its
/// loop's values in callee-saved registers and saved and restored them on
/// every call, the common no-trap one included (vsbench ring-stream +11% on
/// riscv64). The wake ends the call, so it stays inline; the sleep-and-retry
/// loop is `ring_push_blocked`, tail-called.
pub fn ring_push(r: &SpscRing, v: u64, stats: &mut RingStats) {
    match r.try_push(v) {
        RingStep::Done => {}
        RingStep::DoneWake { addr } => ring_wake(addr, stats),
        RingStep::Blocked => ring_push_blocked(r, v, stats),
    }
}

/// The wake a side owes after a move that found the other side asleep.
#[inline(always)]
fn ring_wake(addr: usize, stats: &mut RingStats) {
    stats.wakes += 1;
    let _ = futex_wake_addr(addr, 1);
}

/// [`ring_push`] on a full ring: sleep, retry, until the item moves.
#[inline(never)]
fn ring_push_blocked(r: &SpscRing, v: u64, stats: &mut RingStats) {
    loop {
        ring_sleep(r.producer_sleep(), || r.producer_woke(), stats);
        match r.try_push(v) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => return ring_wake(addr, stats),
            RingStep::Blocked => {}
        }
    }
}

/// Take the oldest item, sleeping while the ring is empty. Enters the kernel
/// only to sleep on an empty ring or to wake a producer that said it may be
/// asleep. The sleep is out of line, as in [`ring_push`].
pub fn ring_pop(r: &SpscRing, stats: &mut RingStats) -> u64 {
    match r.try_pop() {
        (RingStep::Done, v) => v,
        (RingStep::DoneWake { addr }, v) => {
            ring_wake(addr, stats);
            v
        }
        (RingStep::Blocked, _) => ring_pop_blocked(r, stats),
    }
}

/// [`ring_pop`] on an empty ring: sleep, retry, until an item comes.
#[inline(never)]
fn ring_pop_blocked(r: &SpscRing, stats: &mut RingStats) -> u64 {
    loop {
        ring_sleep(r.consumer_sleep(), || r.consumer_woke(), stats);
        match r.try_pop() {
            (RingStep::Done, v) => return v,
            (RingStep::DoneWake { addr }, v) => {
                ring_wake(addr, stats);
                return v;
            }
            (RingStep::Blocked, _) => {}
        }
    }
}

/// [`ring_push`] for a `W`-word slot ring ([`SpscSlots`]).
pub fn slots_push<const W: usize>(r: &SpscSlots<W>, item: &[u64; W], stats: &mut RingStats) {
    match r.try_push(item) {
        RingStep::Done => {}
        RingStep::DoneWake { addr } => ring_wake(addr, stats),
        RingStep::Blocked => slots_push_blocked(r, item, stats),
    }
}

/// [`slots_push`] on a full ring.
#[inline(never)]
fn slots_push_blocked<const W: usize>(r: &SpscSlots<W>, item: &[u64; W], stats: &mut RingStats) {
    loop {
        ring_sleep(r.producer_sleep(), || r.producer_woke(), stats);
        match r.try_push(item) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => return ring_wake(addr, stats),
            RingStep::Blocked => {}
        }
    }
}

/// [`ring_pop`] for a `W`-word slot ring ([`SpscSlots`]).
pub fn slots_pop<const W: usize>(r: &SpscSlots<W>, out: &mut [u64; W], stats: &mut RingStats) {
    match r.try_pop(out) {
        RingStep::Done => {}
        RingStep::DoneWake { addr } => ring_wake(addr, stats),
        RingStep::Blocked => slots_pop_blocked(r, out, stats),
    }
}

/// [`slots_pop`] on an empty ring.
#[inline(never)]
fn slots_pop_blocked<const W: usize>(r: &SpscSlots<W>, out: &mut [u64; W], stats: &mut RingStats) {
    loop {
        ring_sleep(r.consumer_sleep(), || r.consumer_woke(), stats);
        match r.try_pop(out) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => return ring_wake(addr, stats),
            RingStep::Blocked => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Well-known file descriptors
// ---------------------------------------------------------------------------
/// Standard input file descriptor.
pub const STDIN: u64 = 0;
/// Standard output file descriptor.
pub const STDOUT: u64 = 1;
/// Standard error file descriptor.
pub const STDERR: u64 = 2;

// ---------------------------------------------------------------------------
// Error codes returned by the kernel
// ---------------------------------------------------------------------------
//
// WHY these are here: the kernel has TWO "denied" codes and they are not
// interchangeable, so a caller that hard-codes one will misread the other.
//   * `crates/core/syscall/src/handlers.rs`'s `E_PERM` const (`-99`),
//     returned by every `cap_check` failure inside a handler (gpio, i2c,
//     pwm, motor).
//   * `crates/core/syscall/src/dispatch.rs`  — `const E_PERM: i64 = -1`,
//     returned by the seccomp filter and by the capability checks written
//     directly in the dispatch arms (DOMAIN_MMIO_MAP,
//     SYS_IPC_MAP, port/ring ownership).
// Test only for `rc < 0` unless you have checked which of the two applies to
// the specific syscall number.

/// Capability denied by a handler-side `cap_check`
/// (`crates/core/syscall/src/handlers.rs`).
pub const E_PERM_HANDLER: isize = -99;

/// Denied by the dispatcher: seccomp filter, or a capability check written
/// in the dispatch arm itself (`crates/core/syscall/src/dispatch.rs`).
pub const E_PERM_DISPATCH: isize = -1;

/// Invalid argument, produced *by this library* before the ecall is issued.
///
/// The kernel never returns this value on its own. Kernel rejections in this
/// tree are `-1` ([`E_PERM_DISPATCH`]) and `-99` ([`E_PERM_HANDLER`]), or a
/// typed `-Errno`. See [`has_nul`].
pub const E_INVAL: isize = -22;
/// `-EBADF`: a small fd that is not open (the process fd table).
pub const E_BADF: isize = -9;
/// `-EINTR`: a wait ended by a stop request or a child's exit.
pub const E_INTR: isize = -4;
/// `-EPIPE`: a write to a pipe with no reader left.
pub const E_PIPE: isize = -32;

// ---------------------------------------------------------------------------
// NUL-terminated string safety
// ---------------------------------------------------------------------------

}

/// Build a `&'static [u8; N+1]` from a byte-string literal, with the NUL
/// terminator appended **at compile time**.
///
/// WHY this exists: every path-taking syscall in this kernel is read with
/// `azos_sched::copy_cstr_from_user` (`crates/core/sched/src/process.rs`),
/// which scans forward from the pointer until it finds a zero byte — the
/// slice length this library passes is never seen by the kernel. A caller
/// writing `sys::open_at(dir, b"CONFIG.INI", 0)` therefore hands the kernel a
/// pointer into `.rodata` and lets it walk past the literal into whatever the
/// linker placed next. That is exactly the bug that was found in
/// `userspace/services/brain_client` on 2026-08-21.
///
/// `cstr!` removes the possibility instead of documenting it:
///
/// ```ignore
/// let fd = sys::open_at(dir, sys::cstr!(b"CONFIG.INI"), 0);
/// ```
///
/// An embedded NUL is a *compile* error (a `const` panic is evaluated at
/// build time and never reaches the running image, so this is safe under
/// `panic = "abort"`).
///
/// Zero runtime cost: the terminated array is a `const` item in `.rodata`.
#[macro_export]
macro_rules! cstr {
    ($lit:literal) => {{
        const SRC: &[u8] = $lit;
        const N: usize = SRC.len() + 1;
        const BUF: [u8; N] = {
            let mut out = [0u8; N];
            let mut i = 0;
            while i < SRC.len() {
                // A NUL inside the literal would silently truncate the path
                // the kernel actually opens. Refuse at build time.
                assert!(SRC[i] != 0, "cstr!: embedded NUL in literal");
                out[i] = SRC[i];
                i += 1;
            }
            out
        };
        &BUF
    }};
}

word64! {



// ---------------------------------------------------------------------------
// Raw syscall primitives (unsafe, internal)
// ---------------------------------------------------------------------------

// Each primitive below is ONE function whose trap-issuing `asm!` block is
// `#[cfg(target_arch = ..)]`-selected: one branch per ISA (riscv64 `ecall`,
// aarch64 `svc` mapping `a0..=a5`/`a7` to `x0..=x5`/`x8` register-for-register,
// x86_64 `syscall`) — see
// `crates/core/abi/src/syscall_nr.rs`'s "Register convention" section. Keeping
// one function (not two `#[cfg]`'d functions of the same name) matters for
// `tests/host/seccomp-tests`, whose `libsys_fns()` scanner would otherwise see
// two definitions of the same name and refuse to pick one.

#[inline(always)]
unsafe fn syscall0(nr: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            lateout("a0") ret,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            lateout("x0") ret,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: `syscall`, number in rax, arguments in rdi rsi rdx r10 r8
        // r9 (a0..a5; the kernel's `SYSCALL_ARGS`), result in rax. The
        // instruction itself writes rcx (return RIP) and r11 (RFLAGS).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall1(nr: u64, a0: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: `syscall`, number in rax, arguments in rdi rsi rdx r10 r8
        // r9 (a0..a5; the kernel's `SYSCALL_ARGS`), result in rax. The
        // instruction itself writes rcx (return RIP) and r11 (RFLAGS).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: `syscall`, number in rax, arguments in rdi rsi rdx r10 r8
        // r9 (a0..a5; the kernel's `SYSCALL_ARGS`), result in rax. The
        // instruction itself writes rcx (return RIP) and r11 (RFLAGS).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            in("a2") a2,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: `syscall`, number in rax, arguments in rdi rsi rdx r10 r8
        // r9 (a0..a5; the kernel's `SYSCALL_ARGS`), result in rax. The
        // instruction itself writes rcx (return RIP) and r11 (RFLAGS).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: `syscall`, number in rax, arguments in rdi rsi rdx r10 r8
        // r9 (a0..a5; the kernel's `SYSCALL_ARGS`), result in rax. The
        // instruction itself writes rcx (return RIP) and r11 (RFLAGS).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: `syscall`, number in rax, arguments in rdi rsi rdx r10 r8
        // r9 (a0..a5; the kernel's `SYSCALL_ARGS`), result in rax. The
        // instruction itself writes rcx (return RIP) and r11 (RFLAGS).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: `syscall`, number in rax, arguments in rdi rsi rdx r10 r8
        // r9 (a0..a5; the kernel's `SYSCALL_ARGS`), result in rax. The
        // instruction itself writes rcx (return RIP) and r11 (RFLAGS).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ===========================================================================
//  Safe wrappers — grouped by subsystem
// ===========================================================================

// ---------------------------------------------------------------------------
//  Console
// ---------------------------------------------------------------------------

/// `invoke` on the caller's own domain: the op's first reply word is the
/// result.
#[inline(always)]
fn domain_op(op: u16, w: [u64; 4]) -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), op, w).0
}

/// Write a single character to the console.
pub fn putchar(c: u8) {
    let _ = console_write(STDOUT, &[c]);
}

// ---------------------------------------------------------------------------
//  Process management
// ---------------------------------------------------------------------------

/// Terminate the current process with the given exit code.
pub fn exit(code: i32) -> ! {
    unsafe { syscall1(SYS_EXIT, code as u64); }
    // Kernel should never return, but satisfy the compiler.
    loop {}
}

/// Return the PID of the current process.
pub fn getpid() -> isize {
    unsafe { syscall0(SYS_GETPID) }
}

/// Yield the CPU to the scheduler.
pub fn yield_now() {
    unsafe { syscall0(SYS_YIELD); }
}

/// Sleep for `ms` milliseconds.
pub fn sleep(ms: u64) {
    unsafe { syscall2(SYS_SLEEP_UNTIL, ms.saturating_mul(1_000_000), SLEEP_RELATIVE); }
}

/// What [`sleep_until_ns`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SleepResult {
    /// The caller blocked until the deadline.
    Slept,
    /// The deadline had already passed; the caller did not block.
    Overrun,
    /// The kernel refused the call (the image's profile does not list it).
    Refused(isize),
}

/// Block until `deadline_ns` on the clock [`vdso_now_ns`] reads.
///
/// A periodic loop keeps its deadline and adds the period each time, so no
/// drift accumulates:
///
/// ```ignore
/// let mut next = sys::vdso_now_ns() + PERIOD_NS;
/// loop {
///     work();
///     if sys::sleep_until_ns(next) == sys::SleepResult::Overrun { missed += 1; }
///     next += PERIOD_NS;
/// }
/// ```
pub fn sleep_until_ns(deadline_ns: u64) -> SleepResult {
    match unsafe { syscall2(SYS_SLEEP_UNTIL, deadline_ns, 0) } {
        0 => SleepResult::Slept,
        1 => SleepResult::Overrun,
        rc => SleepResult::Refused(rc),
    }
}

/// `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, deadline)`, the POSIX shape
/// of [`sleep_until_ns`]: 0 once the deadline has passed, whether the caller
/// blocked or the deadline was already behind it, and the kernel's negative
/// code when the call is refused. A loop that wants to count its overruns
/// calls [`sleep_until_ns`] instead.
pub fn clock_nanosleep_abs(deadline_ns: u64) -> isize {
    match sleep_until_ns(deadline_ns) {
        SleepResult::Slept | SleepResult::Overrun => 0,
        SleepResult::Refused(rc) => rc,
    }
}

/// A thread's entry (wave 13, [`thread_create`]): it is called with
/// `(0, stack, arg)` and must end with [`thread_exit`] (or [`exit`], which
/// ends the whole process).
pub type ThreadEntry = extern "C" fn(u64, u64, u64) -> !;

/// Start a thread of this process (`SYS_THREAD_CREATE`, wave 13): it runs
/// `entry(0, stack_top, arg)` on the stack whose (16-byte aligned) top is
/// `stack_top`, sharing this process's memory, capabilities and descriptors.
/// Its exit clears the 32-bit word at `ctid` (if not null) and wakes one
/// [`futex_wait`]er on it: that is a join. Returns its TID, or negative
/// (`-EAGAIN` when the process already has 16 threads or 8 processes have
/// several).
pub fn thread_create(entry: ThreadEntry, stack_top: usize, arg: u64, ctid: *mut u32) -> isize {
    thread_create_with_tls(entry, stack_top, arg, ctid, 0)
}

/// [`thread_create`] with the new thread's thread pointer (`tp` / `TPIDR_EL0` /
/// the FS base; 0: the creator's). It is installed before the thread's first
/// instruction, which is the only way to give one to a thread on x86_64, where
/// ring 3 cannot write its own FS base (`arch-x86_64/src/tls.rs`): a C library
/// whose TLS is addressed through it (relibc) creates every thread, the first
/// one's successor included, this way.
pub fn thread_create_with_tls(entry: ThreadEntry, stack_top: usize, arg: u64, ctid: *mut u32, tls: u64) -> isize {
    unsafe {
        syscall5(SYS_THREAD_CREATE, entry as usize as u64, stack_top as u64, arg, ctid as u64, tls)
    }
}

/// End the calling thread only (`SYS_THREAD_EXIT`, wave 13). The last
/// thread ending ends the process; [`exit`] from any thread ends it at once.
pub fn thread_exit(code: i32) -> ! {
    unsafe {
        syscall1(SYS_THREAD_EXIT, code as u64);
    }
    loop {}
}

/// Wait while the word at `addr` holds `expected` (`SYS_FUTEX_WAIT`, wave
/// 13), at most `timeout_ns` nanoseconds (0: no limit). 0 when woken,
/// `-EAGAIN` (11) when the word differed, `-ETIMEDOUT` (110), `-EINTR`.
pub fn futex_wait(addr: &core::sync::atomic::AtomicU32, expected: u32, timeout_ns: u64) -> isize {
    unsafe { syscall3(SYS_FUTEX_WAIT, addr.as_ptr() as u64, expected as u64, timeout_ns) }
}

/// Wake at most `n` threads of this process waiting on `addr`
/// (`SYS_FUTEX_WAKE`, wave 13). How many were woken.
pub fn futex_wake(addr: &core::sync::atomic::AtomicU32, n: u32) -> isize {
    unsafe { syscall2(SYS_FUTEX_WAKE, addr.as_ptr() as u64, n as u64) }
}

pub use azos_abi::sensor_sample::{sample_is_fresh_ns, SENSOR_SAMPLE_FLAG_SYNTHETIC};

/// Reap one finished child. Returns its TID, or `-1` if none has finished.
///
/// **`WNOHANG` semantics, not POSIX `wait`: this does NOT block.** `-1` means
/// "no child has finished yet", not "error" and not "you have no children" —
/// the caller polls, typically with [`yield_now`] in between.
///
/// **The doc that stood here until 2026-09-06 was false.** It read
/// "Unimplemented in the kernel. `sys_wait` (`handlers.rs::sys_wait`) is
/// `-1  // Phase 8+`. Always returns `-1`." Every part of that was wrong: the
/// handler (`handlers.rs::sys_wait`) calls `azos_sched::take_exit_note`,
/// and it returns the finished child's TID. It was implemented on 2026-08-30
/// and this comment — the one a ring-3 programmer actually reads — was left
/// describing the stub. `userspace/bench/vsbench/src/bench_core.rs` still carries
/// the same stale claim in `fork_exit`'s doc, and says the lane should take
/// the reap back in now that `wait` exists.
///
/// **It does not report HOW the child died**, only which one did. The kernel
/// records the exit code (`note_exit` stores it in the exit-note table) and
/// this call discards it. Use [`wait_status`] when the difference between a
/// clean exit and an abort matters — on a machine built with
/// `panic = "abort"`, that difference is "the task finished" versus "the task
/// panicked", which is not a distinction a supervisor can afford to lose.
pub fn wait() -> isize {
    domain_op(invoke_abi::DOMAIN_WAIT, [0, 0, 0, 0])
}

/// Reap ONE named child and learn its exit code.
///
/// Returns the child's TID; `-1` if that child is still running; `-ECHILD`
/// (-10) if it is not a child of this task or was already reaped; `-EFAULT`
/// if `status` is unwritable. Pass a null `status` to reap without reading the
/// code.
///
/// **`-1` and `-ECHILD` are different, and the difference is what makes a poll
/// terminate.** [`wait`] and [`wait_status`] return the FIRST finished child,
/// so a parent with several must consume and discard its other children's
/// notices to find the one it cares about. Here `-1` means "not yet, poll
/// again" and `-ECHILD` means "this will never answer".
pub fn waitpid(child_tid: u32, status: *mut i32) -> isize {
    domain_op(invoke_abi::DOMAIN_WAIT, [child_tid as u64, status as u64, 0, 0])
}

/// Read one exit-path counter (the exit-stats op): `which` is a
/// `azos_abi::syscall_nr::EXIT_STAT_*` selector. Returns the count, a
/// total since boot over every task, or `-EINVAL` (-22) for an unknown
/// selector.
pub fn exit_stats(which: u64) -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_EXIT_STATS, [which, 0, 0, 0]).0
}

/// The caller's child-subreaper mark (the subreaper op): `op` is
/// `azos_abi::syscall_nr::SUBREAPER_{GET,SET,CLEAR}`. Returns the mark
/// afterwards (0 or 1), or `-EINVAL` (-22) for another `op`. A marked task
/// adopts its orphaned descendants (their `waitpid` and task-list parent).
pub fn task_subreaper(op: u64) -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_SUBREAPER, [op, 0, 0, 0]).0
}

pub use azos_abi::syscall_nr::{SUBREAPER_CLEAR, SUBREAPER_GET, SUBREAPER_SET};

/// The second-argument value on which a `syscall-abi-canary` kernel flips a
/// callee-saved bit on the native syscall exit (abitest's `sysabi:` check).
pub use azos_abi::syscall_nr::SYSCALL_ABI_CANARY_A1;

/// The [`exit_stats`] selectors.
pub use azos_abi::syscall_nr::{
    EXIT_STAT_EARLY_NOTICES, EXIT_STAT_EXIT_TEARDOWNS,
    EXIT_STAT_NOTICE_DROPS, EXIT_STAT_NOTICE_REFUSALS,
    EXIT_STAT_REUSE_TEARDOWNS,
};

/// Reap one finished child AND learn its exit code.
///
/// Writes the child's exit code as an `i32` to `status` and returns the
/// child's TID; returns `-1` without writing when no child has finished.
/// Pass a null `status` to behave exactly like [`wait`].
///
/// # Why a second syscall instead of an argument on the first
///
/// `DOMAIN_WAIT` takes no arguments today, and `syscall0` does not set `a0` — so
/// giving it an out-pointer would have the kernel read whatever the register
/// happened to hold for every existing caller, and write through it. A new
/// number cannot break a caller that does not use it.
///
/// # Why not pack both into the return value
///
/// `(code << 32) | tid` fits, and it makes `-1` ambiguous the moment a child
/// exits with a code whose sign bit lands wrong. The error path of a reaping
/// call is not a place to introduce an encoding that has to be decoded
/// correctly to notice.
pub fn wait_status(status: *mut i32) -> isize {
    domain_op(invoke_abi::DOMAIN_WAIT, [0, status as u64, 0, 0])
}

// ---------------------------------------------------------------------------
//  Page size
// ---------------------------------------------------------------------------

/// The base page this image was built for, in bytes: what `brk`/`mmap` round
/// to, what [`meminfo`] counts, and what the image's `PT_LOAD` segments are
/// aligned to. 4096 on riscv64 and on the default aarch64 build; an aarch64
/// image linked for a 16 or 64 KiB granule (`make AARCH64_PAGE_SIZE=...`)
/// gets that value through `AZOS_PAGE_SIZE` at compile time, the same build
/// that sets its `-z max-page-size`. The kernel only loads images of its own
/// granule (each granule has its own digest table), so this is the kernel's
/// page size too.
pub const PAGE_SIZE: usize = match option_env!("AZOS_PAGE_SIZE") {
    None => 4096,
    Some(s) => parse_page_size(s.as_bytes()),
};

const fn parse_page_size(s: &[u8]) -> usize {
    let mut v = 0usize;
    let mut i = 0;
    while i < s.len() {
        assert!(s[i] >= b'0' && s[i] <= b'9', "AZOS_PAGE_SIZE must be a decimal byte count");
        v = v * 10 + (s[i] - b'0') as usize;
        i += 1;
    }
    assert!(v == 4096 || v == 16384 || v == 65536, "AZOS_PAGE_SIZE must be 4096, 16384 or 65536");
    v
}

// ---------------------------------------------------------------------------
//  File I/O
// ---------------------------------------------------------------------------

/// Largest single transfer honoured by [`read`] / [`write()`]. The kernel
/// bounces through a 4 KiB stack buffer (`handlers.rs::sys_read`, `::sys_write`) and
/// silently clamps anything longer — a short count is normal, not an error.
pub const IO_MAX_BYTES: usize = 4096;

/// The capability handle a POSIX-named call was given, or `None` for a value
/// no handle can take. The kernel reads a handle as 32 bits, so a wider value
/// would reach it as a different handle.
#[inline]
fn handle_arg(fd: u64) -> Option<u32> {
    u32::try_from(fd).ok()
}

/// This task's root directory: the `Cap<Dir>` its signed row granted on `/`
/// (a tree `Cap<File>`, `NODE_OPENAT`'s handle), looked up once. `-ENOENT`
/// when the row grants none: the task then has no root to open beneath and can
/// open only through a directory it holds some other way.
///
/// Whatever the task opens is beneath the directories it holds; this is the
/// widest of them. A POSIX layer (relibc, the Linux runtime) resolves its
/// absolute paths against it; a native program should hold a narrower
/// directory and open beneath that.
pub fn root_dir() -> isize {
    use core::sync::atomic::Ordering;
    let h = ROOT_DIR_CAP.load(Ordering::Relaxed);
    if h != 0 {
        return h as isize;
    }
    let r = cap_lookup(ty::FILE.raw(), invoke_abi::ROOT_DIR_RESOURCE);
    if r > 0 {
        ROOT_DIR_CAP.store(r as u32, Ordering::Relaxed);
    }
    r
}

static ROOT_DIR_CAP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Open `rel`, a NUL-terminated name relative to the directory `dir` (a
/// `Cap<Dir>`: [`root_dir`], or a directory handle the task holds), and receive
/// a `Cap<File>` for it (`NODE_OPENAT`). **There is no open by absolute path:**
/// the name cannot start with `/` and cannot climb above `dir` with `..`; the
/// kernel refuses both (`-1`), whatever the program passes.
///
/// The returned handle is not a small integer and not the descriptor behind
/// it: hand it to [`read`], [`write()`] and [`close`]. The descriptor, when a
/// call with no typed form needs it, is found with
/// `cap_lookup(ty::FILE.raw(), fd)`.
///
/// The kernel reads the name with `copy_cstr_from_user` into a 512-byte
/// buffer: it scans for a zero byte and **never sees `rel.len()`**. This
/// wrapper rejects a slice with no NUL ([`E_INVAL`]) before the call. Prefer
/// [`cstr!`], which appends the terminator at compile time:
///
/// ```ignore
/// let f = sys::open_at(dir, sys::cstr!(b"CONFIG.INI"), 0);
/// ```
///
/// `flags & 3` is the access mode and sets the capability's permissions
/// (`O_RDONLY` 0 -> `READ`, `O_WRONLY` 1 -> `WRITE`, `O_RDWR` 2 -> both); mode
/// 3 is `-EINVAL`. An open that writes, creates or truncates needs a tree of
/// the task's row with `WRITE` that covers the file (`dir` itself when granted
/// with `WRITE`, else another one): the root directory only names where to
/// look, a write is authorised by the row's write trees (`-ECAPPERMS`). Returns the handle (`>= 0`), `-1` if the open
/// fails, `-ECAPKIND` when `dir` is not a directory, or `-EMFILE` when the
/// capability table is full.
pub fn open_at(dir: u32, rel: &[u8], flags: u64) -> isize {
    if !has_nul(rel) {
        return E_INVAL;
    }
    invoke(dir, invoke_abi::NODE_OPENAT, [rel.as_ptr() as u64, flags, 0, 0]).0
}

/// Open `path`, a NUL-terminated absolute name such as `/fat/CONFIG.INI`,
/// beneath this task's root directory ([`root_dir`]): [`open_at`] with the
/// leading `/`s taken off. `-ENOENT` when the task's row grants no root
/// directory (nothing is opened then, and the caller sees a plain failure, not
/// a capability error from a garbage handle); otherwise as [`open_at`].
pub fn open_root(path: &[u8], flags: u64) -> isize {
    let root = root_dir();
    if root < 0 {
        return root;
    }
    open_at(root as u32, below_root(path), flags)
}

/// Close what a handle names: a file from [`open_at`], a socket from
/// [`socket_typed`] — one call for both (`SYS_CAP_CLOSE`).
///
/// **Why one integer can no longer close the wrong object.** File descriptors
/// and socket indices overlap (both count from small numbers), and the
/// untyped `SYS_CAP_CLOSE` reaches the descriptor table only. A program that
/// closed its socket 3 while it had file 3 open closed the file. A handle
/// carries its kind in its top bits (`azos_abi::cap::CapHandle`), and the
/// kernel releases the object that kind names.
///
/// Returns 0, `-ECAPSTALE` for a handle already closed (or never minted), or
/// `-ECAPKIND` for a kind with no close. [`E_INVAL`] for a value wider than a
/// handle, without the call.
pub fn close(fd: u64) -> isize {
    // A small fd is a table entry; only the last fd naming a
    // handle closes it in the kernel.
    if fd < FD_TABLE_LEN as u64 {
        if fd_entry(fd) == FdEntry::Closed {
            return E_BADF;
        }
        return match proc_state().fds.fd_release(fd) {
            Some(h) => close_typed(h),
            None => 0,
        };
    }
    match handle_arg(fd) {
        Some(cap) => close_typed(cap),
        None => E_INVAL,
    }
}

/// Read from the file a handle names into `buf` (`NODE_READ`).
/// Needs `READ`.
///
/// The kernel clamps the count to [`IO_MAX_BYTES`], so a buffer larger than
/// 4 KiB is filled at most 4 KiB per call. There is no stdin descriptor:
/// console input is [`console_wait`].
///
/// Returns bytes read (may be less than `buf.len()`, 0 at end of file), or
/// negative on error. [`E_INVAL`] for a value wider than a handle, without
/// the call.
pub fn read(fd: u64, buf: &mut [u8]) -> isize {
    // Fds 0..=7 are the process's fd table (a startup block's, or
    // 1 and 2 the console). The console has no read.
    if fd < FD_TABLE_LEN as u64 {
        return match fd_entry(fd) {
            FdEntry::Handle(h) => file_read_typed(h, buf),
            FdEntry::Console | FdEntry::Closed => E_BADF,
        };
    }
    match handle_arg(fd) {
        Some(cap) => file_read_typed(cap, buf),
        None => E_INVAL,
    }
}

/// Write `buf` to [`STDOUT`] or [`STDERR`], or to the file a handle names.
///
/// fd 1 and 2 are the console ([`console_write`]): the kernel's
/// descriptor table does not pre-open stdio for user processes, and a
/// capability handle is never 1 or 2 (its kind bits are set). Any other value
/// is a `Cap<File>` handle (`NODE_WRITE`), which needs `WRITE` and is
/// refused with `-EAGAIN` while degraded mode is contained; the console stays
/// live, since it is where a contained program still reports.
///
/// The kernel clamps the count to [`IO_MAX_BYTES`]. Returns bytes written, or
/// negative on error.
pub fn write(fd: u64, buf: &[u8]) -> isize {
    // Fds 0..=7 are the process's fd table. Without a startup block
    // it says 1 and 2 are the console, the rule this function always had.
    if fd < FD_TABLE_LEN as u64 {
        return match fd_entry(fd) {
            FdEntry::Console => console_write(if fd == STDERR { STDERR } else { STDOUT }, buf),
            FdEntry::Handle(h) => file_write_typed(h, buf),
            FdEntry::Closed => E_BADF,
        };
    }
    match handle_arg(fd) {
        Some(cap) => file_write_typed(cap, buf),
        None => E_INVAL,
    }
}

/// Write `buf` to the console: [`STDOUT`] or [`STDERR`], through the console handle's `WRITE` op.
///
/// The console half of [`write()`], for callers that never write a file —
/// [`print`] among them — so a binary that only logs names the console and not
/// the file write it has no use for. Any other `stream` is [`E_INVAL`],
/// without the call.
///
/// Returns the clamped count ([`IO_MAX_BYTES`]) the kernel was handed, not the
/// bytes the UART emitted after LF-to-CRLF translation.
pub fn console_write(stream: u64, buf: &[u8]) -> isize {
    if stream != STDOUT && stream != STDERR {
        return E_INVAL;
    }
    let h = console_cap();
    if h < 0 {
        return h;
    }
    invoke(h as u32, invoke_abi::LOG_CONSOLE_WRITE, [buf.as_ptr() as u64, buf.len() as u64, 0, 0]).0
}

/// Read through a `Cap<File>`. Needs `READ`. Same 4 KiB clamp as [`read`]. A
/// pipe token ([`pipe::is_token`]) is read through the pipe, with no clamp.
pub fn file_read_typed(cap: u32, buf: &mut [u8]) -> isize {
    if pipe::is_token(cap) {
        return pipe::read(cap, buf);
    }
    invoke(cap, invoke_abi::NODE_READ, [buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0]).0
}

/// Write through a `Cap<File>`. Needs `WRITE`; refused with `-EAGAIN` while
/// degraded mode is armed. Same 4 KiB clamp as [`write()`]. A pipe token is
/// written through the pipe.
pub fn file_write_typed(cap: u32, buf: &[u8]) -> isize {
    if pipe::is_token(cap) {
        return pipe::write(cap, buf);
    }
    invoke(cap, invoke_abi::NODE_WRITE, [buf.as_ptr() as u64, buf.len() as u64, 0, 0]).0
}

/// Revoke a capability and release what it names. Handles `Cap<File>`,
/// `Cap<Socket>`, `Cap<Endpoint>` (closing the last `READ` capability of an
/// endpoint the caller serves also ends its role as a server) and a range of
/// I/O ports (its ports close in every thread that opened them); any other
/// kind is `-ECAPKIND`. A second close of the same handle is `-ECAPSTALE`. A pipe
/// token gives up its end ([`pipe::close`]).
pub fn close_typed(cap: u32) -> isize {
    if pipe::is_token(cap) {
        return pipe::close(cap);
    }
    unsafe { syscall1(SYS_CAP_CLOSE, cap as u64) }
}

// `lseek` was here. `SYS_LSEEK` (24) is retired: it took a DESCRIPTOR, and
// since `open_at` returns a `Cap<File>` there was no longer a way to name one.
// No profile granted it and no binary called it, so removing the wrapper
// costs nothing today. Seek returns as `SYS_FILE_SEEK_TYPED` when a caller
// needs it.

// ---------------------------------------------------------------------------
//  Filesystem
// ---------------------------------------------------------------------------

/// Stat a file: size, type and metadata of `path` (NUL-terminated), written
/// to `buf` in the layout `azos_abi::syscall_nr::STAT_BYTES` documents.
/// `0`, `-ENOENT` for no such file, `-EFAULT` for a bad
/// pointer. `buf` shorter than `STAT_BYTES` is refused here with `E_INVAL`,
/// since the kernel always writes the whole record.
pub fn stat(path: &[u8], buf: &mut [u8]) -> isize {
    if !has_nul(path) || buf.len() < azos_abi::syscall_nr::STAT_BYTES {
        return E_INVAL;
    }
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_STAT, [path.as_ptr() as u64, buf.as_mut_ptr() as u64, 0, 0]).0
}

/// Size of the name buffer [`readdir`] must be given. The kernel writes
/// **exactly** this many bytes, always — including on a short name, where the
/// tail is zero-padded.
///
/// Re-exported, NOT restated: this used to be declared here and nowhere else,
/// so the kernel wrote 64 bytes because a constant it could not see said so.
/// The syscall now takes the caller's length in `a5` and compares it against
/// this same definition.
pub use azos_abi::syscall_nr::READDIR_NAME_BYTES;

/// Read one directory entry by index.
///
/// ABI (`sys_readdir`, `handlers.rs::sys_readdir`; dispatch `dispatch.rs`):
///   a0 = **NUL-terminated directory path** (not an fd),
///   a1 = entry index,
///   a2 = name_out — a 64-byte buffer, always fully written,
///   a3 = size_out — `*u32` (4 bytes), or 0 to skip,
///   a4 = is_dir_out — `*u32` (4 bytes), or 0 to skip.
///
/// **The previous wrapper was `readdir(fd, buf, buf.len(), index,
/// max_entries)` — five arguments in an entirely different order, opening
/// with an fd where the kernel reads a path pointer.** Nothing called it.
///
/// The parameters are typed as fixed-size arrays deliberately: the kernel
/// never learns a length for any of the three outputs, so the only place the
/// 64/4/4 sizes can be enforced is here.
///
/// Returns 0 when an entry was written, `-1` when `index` is past the end or
/// the path does not resolve.
pub fn readdir(
    dir_path: &[u8],
    index: u64,
    name_out: &mut [u8; READDIR_NAME_BYTES],
    size_out: &mut u32,
    is_dir_out: &mut u32,
) -> isize {
    if !has_nul(dir_path) {
        return E_INVAL;
    }
    // Six words: past what the register form takes.
    let mut d = MsgDesc { version: azos_abi::ipc_msg::MSG_VERSION, n_words: 6, ..MsgDesc::default() };
    d.words[..6].copy_from_slice(&[
        dir_path.as_ptr() as u64,
        index,
        name_out.as_mut_ptr() as u64,
        size_out as *mut u32 as u64,
        is_dir_out as *mut u32 as u64,
        // The length the kernel checks. The array type above is what makes
        // this true rather than hopeful.
        READDIR_NAME_BYTES as u64,
    ]);
    invoke_desc(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_READDIR, &mut d)
}

/// Create a directory at `path` (**NUL-terminated** — see [`open_at`]).
pub fn mkdir(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_MKDIR, [path.as_ptr() as u64, 0, 0, 0]).0
}

/// Remove a file or directory at `path` (**NUL-terminated** — see [`open_at`]).
pub fn unlink(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_UNLINK, [path.as_ptr() as u64, 0, 0, 0]).0
}

/// Remove the empty directory at `path` (**NUL-terminated**). `0`,
/// `-ENOTEMPTY`, `-ENOTDIR`, `-ENOENT`, or `-ENOSYS` where the filesystem has
/// no rmdir (owner round 23).
pub fn rmdir(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_RMDIR, [path.as_ptr() as u64, 0, 0, 0]).0
}

/// Rename `from` to `to` (both **NUL-terminated**) within one mounted
/// filesystem; across two, `-EINVAL`.
pub fn rename(from: &[u8], to: &[u8]) -> isize {
    if !has_nul(from) || !has_nul(to) {
        return E_INVAL;
    }
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_RENAME, [from.as_ptr() as u64, to.as_ptr() as u64, 0, 0]).0
}

/// Set the size of the file at `path` (**NUL-terminated**) to `len` bytes.
pub fn truncate(path: &[u8], len: u64) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_TRUNCATE, [path.as_ptr() as u64, len, 0, 0]).0
}

/// Make the writes through a `Cap<File>` durable (any permission).
/// `-ECAPSTALE`/`-ECAPKIND` for a bad handle.
pub fn fsync_typed(cap: u32) -> isize {
    invoke(cap, invoke_abi::NODE_FSYNC, [0; 4]).0
}

/// Capacity and free space of the filesystem `path` (**NUL-terminated**) is
/// on, written to `buf` in the layout `azos_abi::syscall_nr::STATFS_BYTES`
/// documents. The kernel is told `buf.len()` and refuses a short one.
pub fn statfs(path: &[u8], buf: &mut [u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_STATFS, [path.as_ptr() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0]).0
}

// ---------------------------------------------------------------------------
//  System info
// ---------------------------------------------------------------------------

/// Number of **free physical pages**.
///
/// `sys_meminfo` (`handlers.rs::sys_meminfo`) is `pmm::free_pages() as i64` — a page
/// count, not "total memory in bytes" as this doc used to claim. Multiply by
/// the 4096-byte page size for bytes.
pub fn meminfo() -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_MEMINFO, [0; 4]).0
}

/// Byte count [`taskinfo`] writes — re-exported so a caller can size its
/// buffer without depending on `azos_abi` directly.
pub use azos_abi::syscall_nr::TASKINFO_BYTES;

/// Facts about the CALLING task: tid, priority, the two context switch
/// counts and the hart it is running on. Writes [`TASKINFO_BYTES`] into `out`
/// and returns that many, or `-EINVAL` if the buffer is short.
///
/// The switch counts are the reason this exists. They are the equivalent of
/// Linux's `voluntary_ctxt_switches` / `nonvoluntary_ctxt_switches`, and both
/// sides count SWITCHES, not calls: a yield that found nothing better to run
/// did not switch and is in neither number. Without that a benchmark cannot
/// tell "we switch slowly" from "they never switched".
///
/// Was a stub returning 0 with an untouched buffer until 2026-09-11.
pub fn taskinfo(out: &mut [u8]) -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_TASKINFO, [out.as_mut_ptr() as u64, out.len() as u64, 0, 0]).0
}

/// The RISC-V `time` counter — **ticks, not milliseconds**.
///
/// Reads the counter with `rdtime`, no trap, when the vDSO page says the read
/// is native ([`vdso_rdtime_native`]); otherwise issues `DOMAIN_UPTIME`, whose
/// handler returns the same counter (`timebase::now()`). Both paths give the
/// same quantity, so a caller cannot tell them apart except by cost. At the
/// frequency [`vdso_timebase_hz`] publishes (10 MHz on QEMU virt),
/// milliseconds are `uptime() / (hz / 1000)`; nanoseconds are
/// [`vdso_now_ns`].
///
/// A binary calling this still names `DOMAIN_UPTIME`, so its seccomp row keeps
/// it: on a machine where the flag is clear the call does trap.
pub fn uptime() -> isize {
    if vdso_rdtime_native() {
        read_time_csr() as isize
    } else {
        uptime_ecall()
    }
}

/// `DOMAIN_UPTIME`, always as a trap. The counter [`uptime`] reads, for a caller
/// that is measuring or checking the trap itself.
pub fn uptime_ecall() -> isize {
    domain_op(invoke_abi::DOMAIN_UPTIME, [0; 4])
}

// ---------------------------------------------------------------------------
//  Network (stack-level)
// ---------------------------------------------------------------------------

/// Current IPv4 address, as `u32::from_be_bytes(addr)` — i.e. the first
/// octet in the **most significant** byte (`handlers.rs::sys_net_getip`). Feed it
/// straight back to `net_ping`, which decodes with
/// `to_be_bytes`.
pub fn net_getip() -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_NET_GETIP, [0; 4]).0
}

// ---------------------------------------------------------------------------
//  Sockets
// ---------------------------------------------------------------------------

/// Size of the `sockaddr_in` the kernel reads. `read_sockaddr`
/// (`handlers.rs::read_sockaddr`) copies **exactly 16 bytes** and never looks at the
/// `addrlen` argument, so a shorter object is read past its end. Build the
/// address with [`sockaddr_in`].
pub const SOCKADDR_LEN: usize = 16;

/// Largest payload a single [`send_typed`] transmits; longer buffers are clamped,
/// not rejected (`handlers.rs::sys_send_syscall`).
pub const SOCK_SEND_MAX: usize = 1460;
/// Largest payload a single [`recv_typed`] returns (`handlers.rs::sys_recv_syscall`).
pub const SOCK_RECV_MAX: usize = 4096;

/// Create a socket and receive a `Cap<Socket>` (`READ | WRITE`) for it rather
/// than a socket index.
///
/// Use it with [`connect_typed`], [`send_typed`], [`recv_typed`] and
/// [`bind_typed`], [`sendto_typed`], [`recvfrom_typed`] and [`close_typed`].
///
/// Returns the raw handle (`>= 0`), `-1` if no socket could be created (the
/// per-task quota included), or `-EMFILE` when the capability table is full.
pub fn socket_typed(domain: u64, sock_type: u64, protocol: u64) -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_SOCKET, [domain, sock_type, protocol, 0]).0
}

/// Connect through a `Cap<Socket>`. Needs `WRITE`, so it is refused with
/// `-EAGAIN` while degraded mode is contained.
pub fn connect_typed(cap: u32, addr: &[u8; SOCKADDR_LEN]) -> isize {
    invoke(cap, invoke_abi::NODE_CONNECT, [addr.as_ptr() as u64, SOCKADDR_LEN as u64, 0, 0]).0
}

/// Send through a `Cap<Socket>`. Needs `WRITE`; refused with `-EAGAIN` while
/// degraded mode is contained.
pub fn send_typed(cap: u32, buf: &[u8]) -> isize {
    invoke(cap, invoke_abi::NODE_SEND, [buf.as_ptr() as u64, buf.len() as u64, 0, 0]).0
}

/// Receive through a `Cap<Socket>`. Needs `READ`, which containment leaves
/// live. Does not block: `0` means nothing has arrived yet. A TCP socket whose
/// connection has ended with nothing left to read answers `-EEOF` (the end of
/// the stream); other refusals are negative too.
pub fn recv_typed(cap: u32, buf: &mut [u8]) -> isize {
    invoke(cap, invoke_abi::NODE_RECV, [buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0]).0
}

/// Bind a `Cap<Socket>` to the local address `addr` (a `sockaddr_in`,
/// [`sockaddr_in`] builds one). Needs `WRITE`. 0, or negative.
pub fn bind_typed(cap: u32, addr: &[u8; SOCKADDR_LEN]) -> isize {
    invoke(cap, invoke_abi::NODE_BIND, [addr.as_ptr() as u64, 0, 0, 0]).0
}

/// Listen on a TCP `Cap<Socket>` at the port [`bind_typed`] gave it. Needs
/// `WRITE`. 0, or negative (not TCP, no port, the port is taken).
pub fn listen_typed(cap: u32) -> isize {
    invoke(cap, invoke_abi::NODE_LISTEN, [0; 4]).0
}

/// Take one connection from a listening `Cap<Socket>`: a new `Cap<Socket>`
/// for it, or `-EAGAIN` when none is waiting (it does not block). Needs
/// `READ`.
pub fn accept_typed(cap: u32) -> isize {
    invoke(cap, invoke_abi::NODE_ACCEPT, [0; 4]).0
}

/// Send `buf` on a `Cap<Socket>` to `addr`, or to the connected peer when
/// `addr` is `None`. Needs `WRITE`. The bytes sent, or negative.
pub fn sendto_typed(cap: u32, buf: &[u8], addr: Option<&[u8; SOCKADDR_LEN]>) -> isize {
    let p = addr.map_or(0, |a| a.as_ptr() as u64);
    invoke(cap, invoke_abi::NODE_SENDTO, [buf.as_ptr() as u64, buf.len() as u64, p, 0]).0
}

/// Receive on a `Cap<Socket>` into `buf`, the sender's `sockaddr_in` into
/// `from` when given. Needs `READ`. **Does not block**: the bytes received, or
/// negative when nothing is queued.
pub fn recvfrom_typed(cap: u32, buf: &mut [u8], from: Option<&mut [u8; SOCKADDR_LEN]>) -> isize {
    let p = from.map_or(0, |a| a.as_mut_ptr() as u64);
    invoke(cap, invoke_abi::NODE_RECVFROM, [buf.as_mut_ptr() as u64, buf.len() as u64, p, 0]).0
}

/// Join the IPv4 multicast `group` (`[239, 1, 2, 3]`) on a UDP `Cap<Socket>`.
///
/// Needs `WRITE`, so it is refused with `-EAGAIN` while degraded mode is
/// contained. Delivery is by port: the socket still has to be [`bind_typed`]-ed to
/// the port the group traffic is sent to. The membership goes back when the
/// socket is closed, however that happens.
///
/// Returns 0 (also for a group this socket already holds), `-EINVAL` for a
/// group outside `224.0.0.0/4` or inside `224.0.0.0/24`, or for a socket that
/// is not UDP, `-EQUOTA` when the socket already holds four groups, `-ENOSPC`
/// when the kernel's group table is full.
pub fn mcast_join_typed(cap: u32, group: [u8; 4]) -> isize {
    invoke(cap, invoke_abi::NODE_MCAST_JOIN, [u32::from_be_bytes(group) as u64, 0, 0, 0]).0
}

/// Leave a group joined with [`mcast_join_typed`] through the same capability.
/// Needs no permission beyond a live capability, so containment leaves it live.
/// Returns 0, or `-EINVAL` for a group this socket does not hold.
pub fn mcast_leave_typed(cap: u32, group: [u8; 4]) -> isize {
    invoke(cap, invoke_abi::NODE_MCAST_LEAVE, [u32::from_be_bytes(group) as u64, 0, 0, 0]).0
}

// ---------------------------------------------------------------------------
//  Memory management
// ---------------------------------------------------------------------------

/// Map anonymous memory.
///
/// ABI (`sys_mmap`, `handlers.rs::sys_mmap`): the POSIX six-argument shape is
/// accepted, but the kernel supports **anonymous mappings only** — it
/// returns `-1` unless `fd == u64::MAX` (i.e. `-1`). `addr`, `flags` and
/// `offset` are ignored; the mapping is placed at the current brk. `prot` is
/// honoured (wave 13): [`PROT_READ`] maps read-only pages (a store faults),
/// [`PROT_READ`]` | `[`PROT_WRITE`] read-write ones, `0` reserves the range
/// and maps nothing, `PROT_EXEC` is refused. `len` is capped at
/// `azos_mm::demand::MAX_DEMAND_ALLOC_BYTES`.
///
/// Returns the mapped virtual address, or `-1`. Kernel tasks get `-1`.
pub fn mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> isize {
    let _ = offset;
    // The anonymous form only: a file descriptor names no memory.
    if fd != MAP_ANON_FD {
        return -1;
    }
    unsafe { syscall5(SYS_MO_MAP, 0, addr, len, prot, flags) }
}

/// `fd` value [`mmap`] requires for an anonymous mapping.
pub const MAP_ANON_FD: u64 = u64::MAX;

/// Map the device registers of the hardware-bus device `handle` (`access`:
/// `CapPerms` bits, READ or READ|WRITE). The virtual address, or `-Errno`;
/// `-1` without the device's capability. A program finds a device's handle in
/// the introspection tree's `devices/` (the directory's name; its `identity`
/// says what the device is).
pub fn mmio_map(handle: u64, access: u64) -> isize {
    domain_op(invoke_abi::DOMAIN_MMIO_MAP, [handle, access, 0, 0])
}

/// [`mmap`]'s `prot` bits (Linux's values).
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;

/// Unmap memory at `addr` for `len` bytes.
pub fn munmap(addr: u64, len: u64) -> isize {
    unsafe { syscall3(SYS_MO_UNMAP, 0, addr, len) }
}

// ---------------------------------------------------------------------------
//  Driver registry bridge
// ---------------------------------------------------------------------------

// ===========================================================================
//  Convenience helpers
// ===========================================================================

/// Write a byte string to stdout.
pub fn print(s: &[u8]) {
    console_write(STDOUT, s);
}

/// Write a byte string to stdout followed by a newline, in **one** syscall.
///
/// # Why the newline is copied instead of written after
///
/// This used to be `console_write(STDOUT, s)` then `putchar(b'\n')`. The
/// kernel's `sys_write` holds the UART guard for the whole of one write
/// (`crates/core/syscall/src/handlers.rs`), so each of those two calls was
/// individually atomic — and the gap between them was not. Another task
/// printing on another hart landed between a line and its newline, producing
/// output like
///
/// ```text
/// [epsrv] endpoint.demo server running[ABITEST]   ok   spawn(...)
/// ```
///
/// which is what the CI scenarios grep. A spliced marker makes a passing run
/// look like a failing one, and it has done so twice — gate 101 (aarch64) and
/// gate 114 (RISC-V), both rows red with the property under test WORKING.
/// Locking harder in the kernel could not fix it: the splice is between two
/// syscalls, so the only place it can be closed is here, by not making two.
///
/// Lines of `MAX` bytes or longer fall back to the old two-call form rather
/// than truncate. That is the honest trade — a program that prints a line this
/// long can still be spliced, and losing its tail would be worse than that.
pub fn println(s: &[u8]) {
    /// Stack buffer for the copy. Sized for a log line, not for data: every
    /// marker any ring-3 program in this tree prints is well under it, and it
    /// is live only for the duration of the call.
    const MAX: usize = 256;
    if s.len() < MAX {
        let mut line = [0u8; MAX];
        line[..s.len()].copy_from_slice(s);
        line[s.len()] = b'\n';
        console_write(STDOUT, &line[..s.len() + 1]);
    } else {
        console_write(STDOUT, s);
        putchar(b'\n');
    }
}

// ===========================================================================
//  Driver server API (AQ4) — userspace driver registration and MMIO/IRQ
// ===========================================================================

/// Bind the interrupt line the `ty::IRQ` handle `line` names to the event
/// port `port` (a `ty::PORT` handle with `WRITE`), with event key `key`,
/// routed to CPU `cpu` ([`DEVICE_IRQ_CPU_ANY`]: the kernel chooses).
/// `DEVICE_IRQ_BIND`.
///
/// Every interrupt on the line masks it and queues one [`PORT_EVENT_IRQ`]
/// event on the port; [`irq_ack`] unmasks it. The caller is the line's
/// handler: with Kconfig `IRQ_THREADED` it must run on a hard reservation
/// (`-EPERM` otherwise), the line goes to the reservation's CPU, and a
/// handler that runs out of budget has its lines held masked until the
/// reservation is replenished.
///
/// Returns the CPU the line was routed to, or `-Errno`: the capability
/// refusals of the line or the port, `-EINVAL` (a line this ISA cannot hand
/// to ring 3; a CPU that is not online or not the reservation's), `-EBUSY`
/// (another task binds the line), `-EMFILE` (binding table full), `-ENODEV`
/// (nothing bound) when the interrupt controller cannot deliver the line.
pub fn irq_bind(line: u32, port: u32, key: u64, cpu: u64) -> isize {
    invoke(line, invoke_abi::DEVICE_IRQ_BIND, [port as u64, key, cpu, 0]).0
}

pub use azos_abi::invoke::DEVICE_IRQ_CPU_ANY;

/// Acknowledge the interrupt line `line` after its device was quietened:
/// unmask it (`DEVICE_IRQ_ACK`). 0 when the line is live again; 1 when the
/// handler's budget is spent and the line stays masked until the reservation
/// is replenished; `-ENOENT` when nobody binds the line.
pub fn irq_ack(line: u32) -> isize {
    invoke(line, invoke_abi::DEVICE_IRQ_ACK, [0; 4]).0
}

// ---- I/O ports (x86_64's port space) ----

/// The I/O ports of one `ty::IOPORT` capability, open to the calling thread
/// ([`ioport_open`]). `in`/`out` on them run in ring 3; on any port no open
/// range holds they fault (#GP), and the task is killed (`KILLED_SEGV`).
#[derive(Clone, Copy, Debug)]
pub struct IoPorts {
    first: u16,
    last: u16,
    /// The capability's handle.
    handle: u32,
}

/// Open the `count` ports from `first` to the calling thread: the capability
/// this task holds for exactly that range (`ioport.<first>.<count>` in its
/// topology row), then `DEVICE_IOPORT_ENABLE` on it. Per thread: a second
/// thread opens them for itself. `Err` is the errno: `-ENOENT` (no such
/// capability), `-ENODEV` (the ISA has no port space: riscv64, aarch64),
/// `-EMFILE` (the thread has Kconfig `X86_IOPORT_RANGES` ranges open
/// already), or the capability's refusal.
pub fn ioport_open(first: u16, count: u16) -> Result<IoPorts, isize> {
    const EINVAL: isize = -22;
    let range = azos_abi::cap::ioport_range(first as u32, count as u32).ok_or(EINVAL)?;
    let h = cap_lookup(ty::IOPORT.raw(), range);
    if h < 0 {
        return Err(h);
    }
    ioport_enable(h as u32)?;
    Ok(IoPorts { first, last: first + (count - 1), handle: h as u32 })
}

/// Give the ports of [`ioport_open`] up: the capability is closed
/// ([`close_typed`]), and the range closes in every thread of this task that
/// opened it, from their next instruction. 0, or the errno.
pub fn ioport_close(ports: IoPorts) -> isize {
    close_typed(ports.handle)
}

/// `DEVICE_IOPORT_ENABLE` on the `ty::IOPORT` handle `h`: 0, or the errno.
pub fn ioport_enable(h: u32) -> Result<(), isize> {
    match invoke(h, invoke_abi::DEVICE_IOPORT_ENABLE, [0; 4]).0 {
        rc if rc < 0 => Err(rc),
        _ => Ok(()),
    }
}

impl IoPorts {
    /// The first and last port of the range.
    pub fn bounds(&self) -> (u16, u16) {
        (self.first, self.last)
    }

    /// `in al, dx`: a byte from `port`. A port outside every open range
    /// faults: that is the hardware's check, not this function's.
    #[inline]
    pub fn inb(&self, port: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            let v: u8;
            // SAFETY: a port read; the kernel opened the range (or the CPU
            // refuses the port with #GP, the task's fault).
            unsafe { asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
            v
        }
        // No port space: `ioport_open` never succeeds here (the kernel
        // answers -ENODEV), so no `IoPorts` exists to call this on.
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = port;
            0xFF
        }
    }

    /// `out dx, al`: a byte to `port`. As [`inb`](Self::inb).
    #[inline]
    pub fn outb(&self, port: u16, v: u8) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: a port write; as `inb`.
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags))
        };
        // No port space: as `inb`.
        #[cfg(not(target_arch = "x86_64"))]
        let _ = (port, v);
    }
}

// ---- Driver server: serve a driver `kind` from userspace (E11.AQ3) ----

/// Find the handle of a capability this task already holds.
///
/// `kind` is a [`CapType`] ([`ty`]`::SHM.raw()`: a kind and its class) and
/// `resource` the object it names — an IRQ line, a
/// `DRV_KIND_*`. Returns the handle as a non-negative value, `-ENOENT` if the
/// task holds no such capability.
///
/// **This is the call that makes every other `*_typed` usable.** A capability
/// granted at boot lands in the task's table with no way for the task to learn
/// its handle, so before this existed the typed hardware syscalls had no
/// possible caller from ring 3.
///
/// It grants nothing: it reads THIS task's table and no other, and a
/// capability the task does not hold has no handle to return.
pub fn cap_lookup(kind: u8, resource: u32) -> isize {
    unsafe { syscall4(SYS_CAP_INFO, 0, CAP_INFO_LOOKUP, kind as u64, resource as u64) }
}

/// This task's capability to the kernel-hosted interface with host key `key`
/// (`azos_devif::key`) that carries `badge` (the resource the topology row
/// stamped: a pin, a bus and an address, a wheel pair; 0 for an interface
/// with no resource), or `-ENOENT`. See [`dev`].
pub fn cap_lookup_host(key: u16, badge: u32) -> isize {
    unsafe { syscall4(SYS_CAP_INFO, 0, CAP_INFO_LOOKUP, ty::ENDPOINT.raw() as u64, (key as u64) << 32 | badge as u64) }
}

/// The [`CapType`] a [`cap_lookup`] asks about.
///
/// Re-exported, NOT restated. The first draft of this declared
/// `CAP_KIND_GPIO: u8 = 8` and friends as plain constants "so a ring-3
/// program need not depend on the ABI crate for two numbers" — which is the
/// exact reasoning that had five files carrying their own `DRV_KIND_*` until
/// those moved into `crates/core/abi` earlier in this commit. `crates/core/libsys`
/// already depends on `azos_abi`; there was never a second number to
/// keep in sync, only a habit.
///
/// Call it as `cap_lookup(ty::IRQ.raw(), line)`.
pub use azos_abi::cap::{ty, CapKind, CapType};

/// Register as the driver for the kind named by `cap` (a
/// `Cap<DriverRegistry>` from [`cap_lookup`]).
///
/// There is no `kind` argument: the kind comes out of the capability, so
/// registering as a device you do not hold is not a request this ABI can
/// express. `mmio_base`/`mmio_size`/`irq` are advisory, as in the untyped
/// form.
pub fn drv_srv_register_typed(cap: u32, mmio_base: u64, mmio_size: u64, irq: u32) -> isize {
    domain_op(invoke_abi::DOMAIN_DRIVER_REGISTER, [cap as u64, mmio_base, mmio_size, irq as u64])
}

/// Release the driver registration named by `cap`. Requires `WRITE`, so it is
/// refused with `-EAGAIN` while degraded mode is contained.
pub fn drv_srv_unregister_typed(cap: u32) -> isize {
    domain_op(invoke_abi::DOMAIN_DRIVER_UNREGISTER, [cap as u64, 0, 0, 0])
}

/// Fetch one pending request for `kind` into the caller's `DriverRequest`
/// buffer (pass `&mut req as *mut _ as *mut u8`).
///
/// ABI (`sys_driver_fetch_request`, `handlers.rs::sys_driver_fetch_request`): the kernel writes
/// **exactly `size_of::<DriverRequest>()` bytes** to `req_ptr` and is never
/// told how large the destination is. The struct is `#[repr(C)]` and lives
/// in `crates/drivers/driver_server/src/lib.rs`:
///
/// ```text
/// token: u64 | client_tid: u32 | op: u32 | in_len: u16 | out_cap: u16
///            | input: [u8; 64]                      →  88 bytes on RV64
/// ```
///
/// `req_ptr` must therefore address at least that many bytes, correctly
/// aligned to 8. `userspace/drivers/gpio_drv` keeps a mirror of the struct; if
/// either copy changes, both must. This stays a raw pointer rather than a
/// typed reference so libsys need not depend on `driver_server`.
///
/// Returns 0 if a request was written, `-1` if the queue is empty.
pub fn drv_srv_fetch_request(kind: u32, req_ptr: *mut u8) -> isize {
    domain_op(invoke_abi::DOMAIN_DRIVER_FETCH, [kind as u64, req_ptr as u64, 0, 0])
}

/// Post a `DriverReply` (pass `&reply as *const _ as *const u8`) for `kind`.
///
/// ABI (`sys_driver_reply`, `handlers.rs::sys_driver_reply`): the kernel **reads
/// `size_of::<DriverReply>()` bytes** from `reply_ptr` — the `#[repr(C)]`
/// struct at `crates/drivers/driver_server/src/lib.rs`:
///
/// ```text
/// token: u64 | status: i32 | out_len: u16 | _pad: u16
///            | output: [u8; 64]                     →  80 bytes on RV64
/// ```
///
/// Same mirroring rule as [`drv_srv_fetch_request`]. Returns 0 on success.
pub fn drv_srv_reply(kind: u32, reply_ptr: *const u8) -> isize {
    domain_op(invoke_abi::DOMAIN_DRIVER_REPLY, [kind as u64, reply_ptr as u64, 0, 0])
}

/// Post the reply owed for `kind` and fetch the next request, in one trap.
/// A serve loop's whole round trip.
///
/// ABI (`DOMAIN_DRIVER_REPLY_FETCH`, `sys_driver_reply_fetch`): `reply_ptr` is a
/// `DriverReply` as for [`drv_srv_reply`], or null when no reply is owed (the
/// loop's first call, or after a turn that fetched nothing); `req_ptr` has room
/// for a `DriverRequest` as for [`drv_srv_fetch_request`].
///
/// Returns `0` (reply posted if given, request written) or `-1` (reply posted
/// if given, queue empty). Any other value means **nothing was done**, so the
/// reply is still owed: `-99` not this kind's driver, `-3` the reply could not
/// be read or published, `-4` `req_ptr` is null or not writable. A call this
/// binary's seccomp row does not grant answers dispatch's `-1`, which reads as
/// "posted"; `tests/host/seccomp-tests` derives every row from the binary's source
/// so such a row cannot ship.
pub fn drv_srv_reply_fetch(kind: u32, reply_ptr: *const u8, req_ptr: *mut u8) -> isize {
    domain_op(invoke_abi::DOMAIN_DRIVER_REPLY_FETCH, [kind as u64, reply_ptr as u64, req_ptr as u64, 0])
}

/// [`drv_srv_reply_fetch`] that blocks while the queue is empty
/// (`DOMAIN_DRIVER_REPLY_WAIT`): the reply owed is posted, then the call returns
/// with the next request, or `-1` once `park_ms` (0 = the kernel's default,
/// at most 1000) has passed with none. A request queued by the kernel's proxy
/// wakes it, so a serve loop on this call never polls.
///
/// Same buffers and the same returns as [`drv_srv_reply_fetch`]: any value
/// other than `0` and `-1` did nothing, and the reply is still owed.
pub fn drv_srv_reply_wait(kind: u32, reply_ptr: *const u8, req_ptr: *mut u8, park_ms: u32) -> isize {
    domain_op(invoke_abi::DOMAIN_DRIVER_REPLY_WAIT, [kind as u64, reply_ptr as u64, req_ptr as u64, park_ms as u64])
}

// ===========================================================================
//  `SYS_INVOKE`: the operations on a handle
// ===========================================================================

/// The ops of every handle type, and the self handles.
pub use azos_abi::invoke as invoke_abi;

/// Invoke op `op` on `handle` in the register form (`azos_abi::invoke`): the
/// words go in `a2..a5`, the value comes back in `a0` and four reply words in
/// `a1..a4`. The reply words are the op's, or the words passed in when the op
/// replies none.
///
/// **Why this is not `syscall6`.** The replies land in argument registers, so
/// they are declared written here: routing the call through a helper that
/// declares `a1..a6` as plain inputs would let rustc assume them intact across
/// the trap (the same rule as the fast IPC call).
#[inline(always)]
pub fn invoke(handle: u32, op: u16, w: [u64; 4]) -> (isize, [u64; 4]) {
    let opw = op as u64 | azos_abi::invoke::INVOKE_REGS;
    let ret: isize;
    let (r1, r2, r3, r4): (u64, u64, u64, u64);
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") SYS_INVOKE,
            inlateout("a0") handle as u64 => ret,
            inlateout("a1") opw => r1,
            inlateout("a2") w[0] => r2,
            inlateout("a3") w[1] => r3,
            inlateout("a4") w[2] => r4,
            inlateout("a5") w[3] => _,
            lateout("a6") _,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_INVOKE,
            inlateout("x0") handle as u64 => ret,
            inlateout("x1") opw => r1,
            inlateout("x2") w[0] => r2,
            inlateout("x3") w[1] => r3,
            inlateout("x4") w[2] => r4,
            inlateout("x5") w[3] => _,
            lateout("x6") _,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: arguments in rdi rsi rdx r10 r8 r9 (a0..a5); a1..a6 come
        // back in rdx rsi rdi r8 r9 r10 (the kernel's `SYSCALL_OUT` order).
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") SYS_INVOKE as isize => ret,
            inlateout("rdi") handle as u64 => r3,
            inlateout("rsi") opw => r2,
            inlateout("rdx") w[0] => r1,
            inlateout("r10") w[1] => _,
            inlateout("r8") w[2] => r4,
            inlateout("r9") w[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (ret, [r1, r2, r3, r4])
}

/// Invoke op `op` on `handle` in the descriptor form: `*desc` carries the
/// op's words in, and the reply words out.
pub fn invoke_desc(handle: u32, op: u16, desc: &mut MsgDesc) -> isize {
    // `a3..a5` are passed as zeros: the descriptor form refuses an invoke
    // whose last three words are not (`sys_invoke`), and a three-argument
    // call leaves those registers to whatever the caller last held in them
    // (x86_64: `ls` read no directory and the hosted runtime saw an empty
    // `/fat`, an `-EINVAL` out of `readdir`).
    unsafe { syscall6(SYS_INVOKE, handle as u64, op as u64, desc as *mut MsgDesc as u64, 0, 0, 0) }
}

static CONSOLE_CAP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// This task's console handle, looked up once (`-ENOENT` when it holds none).
fn console_cap() -> isize {
    use core::sync::atomic::Ordering;
    let h = CONSOLE_CAP.load(Ordering::Relaxed);
    if h != 0 {
        return h as isize;
    }
    let r = cap_lookup(ty::CONSOLE.raw(), 0);
    if r > 0 {
        CONSOLE_CAP.store(r as u32, Ordering::Relaxed);
    }
    r
}

// ===========================================================================
//  IO Ring API (AQ4) — asynchronous I/O submission and completion
// ===========================================================================

// ===========================================================================
//  Channel API (AQ4) — kernel-mediated message passing
// ===========================================================================

// ===========================================================================
//  Port API (AQ5) — multi-source event waiting (like kqueue / Zircon ports)
// ===========================================================================

// The source and event types live in `azos_abi::syscall_nr` (one home).
pub use azos_abi::syscall_nr::{
    PORT_EVENT_CALL_NOTICE, PORT_EVENT_CODE_OFFSET, PORT_EVENT_IRQ, PORT_EVENT_NO_SENDERS, PORT_EVENT_RING,
    PORT_EVENT_PRESSURE, PORT_EVENT_SOURCE_GONE, PORT_EVENT_TIMER, PORT_SRC_ENDPOINT,
    PORT_SRC_PRESSURE, PORT_SRC_RING, PORT_SRC_TIMER,
};
/// [`port_bind_typed`] flag, or-ed into the source type: remove the sources
/// of that type bound with the key instead of binding one.
pub const PORT_BIND_F_REMOVE: u64 = azos_abi::syscall_nr::PORT_BIND_F_REMOVE;

// ===========================================================================
//  Fast-path IPC (M02) — seL4-style register-passing, ≤32 bytes
// ===========================================================================

/// Maximum number of 64-bit words in a fast IPC message.
pub const FAST_IPC_MAX_WORDS: usize = 4;

/// Send a fast IPC request through a `Cap<Endpoint>` (`SYS_IPC_FAST_CALL_EP`)
/// and block until the reply arrives, receiving the FULL
/// four-word reply.
///
/// ABI: a0 = the endpoint capability, a1..a4 = up to 4 × u64 of request data
/// (≤ 32 bytes), a5 = a capability to move (0 for none). On success a0 =
/// reply\[0\] and a1..a3 = reply\[1..3\], delivered through `SyscallOut`
/// exactly like FAST_ACCEPT's request delivery. On failure a0 is negative
/// and a1..a5 are untouched. The kernel touches no user memory — data
/// travels in registers both ways.
///
/// **WHY this cannot go through the shared `syscallN` helpers.** Results
/// land in argument registers, so they must be declared `lateout` in a
/// dedicated block. Routing this through `syscall5` (whose `in("a1")`…
/// operands rustc may assume intact) would be undefined behaviour the moment
/// the kernel writes the reply back.
///
/// **The first reply word and the error code share `a0`.** Success is
/// `reply[0]`, failure is negative, and nothing tags which is which — so a
/// reply\[0\] with bit 63 set is reported here as a failed call. Keep the
/// FIRST fast-IPC reply word in the non-negative `i64` range; the other
/// three are unconstrained. [`fast_ipc_call_ep_status`] keeps the code.
///
/// `None` for everything the TID form returns `None` for, plus a capability
/// that does not resolve, carries no `WRITE`, is refused under degraded-mode
/// containment, or names an endpoint no task serves yet. They are one answer
/// on purpose: distinguishing them would report on capabilities the caller
/// does not hold.
pub fn fast_ipc_call_ep_full(
    endpoint: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
) -> Option<[u64; FAST_IPC_MAX_WORDS]> {
    fast_ipc_call_ep_moving(endpoint, words, NO_CAP_TO_MOVE)
}

/// Handle value meaning "this call moves no capability".
///
/// A capability handle is generation-tagged and never zero, so zero is
/// unambiguous and needs no separate flag.
pub const NO_CAP_TO_MOVE: u32 = 0;

/// [`fast_ipc_call_ep_full`] that also **moves** a capability to the server.
///
/// Under owner decision 38: a move, never a copy. The
/// sender's entry is removed in the same step the server's is installed, so
/// this handle stops resolving for the caller the instant the call returns
/// successfully. The server learns its own handle from `a6` of its accept.
///
/// `moving` is a handle the caller holds, or [`NO_CAP_TO_MOVE`]. Rights are
/// kept; there is no register left in this ABI to lower them.
///
/// **`a5` must be passed, never left to the compiler.** It was `lateout`-only
/// before this change, and the kernel now reads it: an `asm!` that does not
/// write it hands the kernel whatever rustc happened to leave there, which is
/// the `drv_heartbeat` bug (see that wrapper) with a capability move as the
/// consequence instead of a stray watchdog refresh.
pub fn fast_ipc_call_ep_moving(
    endpoint: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
    moving: u32,
) -> Option<[u64; FAST_IPC_MAX_WORDS]> {
    fast_ipc_call_ep_status(endpoint, words, moving).ok()
}

/// [`fast_ipc_call_ep_moving`] that keeps the kernel's code on failure:
/// `Err(-1)` for a refused or abandoned call, and the completion codes
/// `-EPEERDIED` (the serving task died with this call queued or in service)
/// and `-EREVOKED` (the endpoint was destroyed meanwhile) of
/// `azos_abi::error::Errno` (wave 15 N5).
pub fn fast_ipc_call_ep_status(
    endpoint: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
    moving: u32,
) -> Result<[u64; FAST_IPC_MAX_WORDS], isize> {
    fast_ipc_call_ep_a5(endpoint, words, moving as u64)
}

/// [`fast_ipc_call_ep_moving`], sharing the capability instead of moving it
/// (`azos_abi::syscall_nr::FAST_CALL_CAP_SHARE`): the server gets a derived copy
/// and the caller keeps its own handle and, for a `Cap<Shm>`, its mapping. A
/// MOVE of a `Cap<Shm>` takes the caller's mapping with it.
pub fn fast_ipc_call_ep_sharing(
    endpoint: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
    sharing: u32,
) -> Option<[u64; FAST_IPC_MAX_WORDS]> {
    fast_ipc_call_ep_a5(endpoint, words, sharing as u64 | azos_abi::syscall_nr::FAST_CALL_CAP_SHARE).ok()
}

/// The fast call with `a5` as the kernel reads it: the capability handle in
/// the low 32 bits, `FAST_CALL_CAP_SHARE` in bit 32.
fn fast_ipc_call_ep_a5(
    endpoint: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
    a5: u64,
) -> Result<[u64; FAST_IPC_MAX_WORDS], isize> {
    let ret: isize;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_CALL_EP,
            inlateout("a0") endpoint as u64 => ret,
            inlateout("a1") words[0] => r1,
            inlateout("a2") words[1] => r2,
            inlateout("a3") words[2] => r3,
            inlateout("a4") words[3] => _,
            inlateout("a5") a5 => _,
            // The kernel writes `a6` on every arm that opts into `SyscallOut`.
            // Undeclared, rustc is entitled to keep a
            // live value here and the kernel would silently destroy it.
            lateout("a6") _,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        // aarch64 twin of the riscv64 block above.
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_IPC_FAST_CALL_EP,
            inlateout("x0") endpoint as u64 => ret,
            inlateout("x1") words[0] => r1,
            inlateout("x2") words[1] => r2,
            inlateout("x3") words[2] => r3,
            inlateout("x4") words[3] => _,
            inlateout("x5") a5 => _,
            lateout("x6") _,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: arguments in rdi rsi rdx r10 r8 r9 (a0..a5), the reply in
        // the kernel's `SYSCALL_OUT` order: a1..a6 come back in rdx rsi rdi
        // r8 r9 r10 (kernel/src/entry/x86_64.rs). Every one of them is declared
        // written, as a1..a6 are on riscv64; rcx/r11 belong to `syscall`.
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") SYS_IPC_FAST_CALL_EP as isize => ret,
            inlateout("rdi") endpoint as u64 => r3,
            inlateout("rsi") words[0] => r2,
            inlateout("rdx") words[1] => r1,
            inlateout("r10") words[2] => _,
            inlateout("r8") words[3] => _,
            inlateout("r9") a5 => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if ret < 0 { return Err(ret); }
    Ok([ret as u64, r1, r2, r3])
}

/// [`fast_ipc_call_ep_full`] for callers that need only the first reply word.
pub fn fast_ipc_call_ep(endpoint: u32, words: [u64; FAST_IPC_MAX_WORDS]) -> Option<u64> {
    fast_ipc_call_ep_full(endpoint, words).map(|r| r[0])
}

/// The range of [`FastRequest::slot`]: a handle's low six bits, for logging
/// and test sweeps only. The handle is opaque: its low `REC_BITS` bits name
/// the caller's call record (its task slot), so the six bits are the record
/// itself only on a profile of at most 64 tasks and a hash of it otherwise.
pub const FAST_IPC_HANDLE_LOG_SLOTS: usize = 64;

/// The bits of a handle [`FastRequest::slot`] shows (see
/// [`FAST_IPC_HANDLE_LOG_SLOTS`]).
pub const FAST_IPC_HANDLE_LOG_MASK: u64 = (FAST_IPC_HANDLE_LOG_SLOTS as u64) - 1;

/// One accepted fast-IPC request, as the server sees it.
///
/// `handle` is what [`fast_ipc_reply`] takes; `caller_tid` and `words` are the
/// request itself. Read `delivered` before trusting the latter two.
pub struct FastRequest {
    /// **Opaque handle** to hand to [`fast_ipc_reply`], exactly as received.
    ///
    /// It is NOT a slot index: the kernel tags it with a per-slot generation
    /// so a handle from a retired exchange cannot land on the slot's next
    /// occupant. Pass it through untouched — masking it, sign-extending it, or
    /// reconstructing it from `slot` all reintroduce the bug the tag closes.
    pub handle: u64,
    /// The handle's low bits ([`FAST_IPC_HANDLE_LOG_MASK`]), purely for logging and
    /// for the caller's own bookkeeping. **Never** hand this to
    /// [`fast_ipc_reply`].
    pub slot: usize,
    /// TID of the task that issued `SYS_IPC_FAST_CALL`.
    pub caller_tid: u32,
    /// The four request words, exactly as the client passed them.
    pub words: [u64; FAST_IPC_MAX_WORDS],
    /// Handle a capability **moved** with this message took in THIS task's
    /// table, or [`NO_CAP_TO_MOVE`] when the message carried none.
    ///
    /// The move already happened in the caller's own
    /// trap, so this is a record and not something to claim: the capability is
    /// in this task's table whether or not this field is read, and dropping it
    /// on the floor leaks authority rather than declining it.
    pub moved_cap: u32,
    /// **False means the kernel did not deliver the payload**, and
    /// `caller_tid` / `words` are meaningless — not zero, not stale data from
    /// a previous call, simply undelivered.
    ///
    /// The kernel side of the delivery is inert until the trap handler in
    /// `kernel/src/entry/riscv64/trap.rs` calls `syscall_dispatch_out` and copies
    /// `SyscallOut::regs` into the live `TrapFrame`. Distinguishing "the
    /// handler was never migrated" from "the server got the wrong words" is
    /// the whole reason this flag exists rather than a silent zero: two
    /// different bugs that otherwise produce the same failing assertion.
    pub delivered: bool,
}

/// Pre-loaded into `a1` before the `ecall` and looked for on return.
///
/// A TID is a `u32` widened to 64 bits, so a delivered `a1` can never be
/// `u64::MAX`; seeing the sentinel come back therefore means, unambiguously,
/// that nothing wrote the register. The trap entry saves and restores the
/// whole register file, so an unwritten `a1` is preserved verbatim.
const FAST_ACCEPT_SENTINEL: u64 = u64::MAX;

/// Server: block until a client sends a fast IPC call to this TID, and
/// receive the request.
///
/// ABI (`SYS_IPC_FAST_ACCEPT`): takes no argument. On success a0 = slot
/// index, a1 = caller TID, a2..a5 = the four request words. On failure
/// a0 = -1 and a1..a5 are untouched.
///
/// **WHY this cannot go through the shared `syscallN` helpers.** Those pass
/// their arguments as `in("a1")`, `in("a2")`… — operands rustc may assume the
/// `asm!` block leaves intact. This and [`fast_ipc_reply_accept`] are the only
/// syscalls whose *results* land in those registers, so each needs its own
/// block declaring them `lateout`.
/// Calling `syscall0` and reading a1..a5 afterwards would be undefined
/// behaviour, and the compiler is free to make it look like it works.
///
/// Returns `None` when nothing was pending (the kernel's bounded
/// spurious-wake retry ran out, which is indistinguishable from an empty
/// queue from ring 3 — see the `SYS_IPC_FAST_ACCEPT` arm).
pub fn fast_ipc_accept_req() -> Option<FastRequest> {
    let ret: isize;
    let caller: u64;
    let w0: u64;
    let w1: u64;
    let w2: u64;
    let w3: u64;
    let moved: u64;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_ACCEPT,
            lateout("a0") ret,
            inlateout("a1") FAST_ACCEPT_SENTINEL => caller,
            lateout("a2") w0,
            lateout("a3") w1,
            lateout("a4") w2,
            lateout("a5") w3,
            // a6 = the handle a moved capability took in THIS task's table,
            // or `NO_CAP_TO_MOVE`.
            lateout("a6") moved,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        // aarch64 twin — x0..=x6 mirror a0..=a6. See `fast_ipc_call_ep_status`.
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_IPC_FAST_ACCEPT,
            lateout("x0") ret,
            inlateout("x1") FAST_ACCEPT_SENTINEL => caller,
            lateout("x2") w0,
            lateout("x3") w1,
            lateout("x4") w2,
            lateout("x5") w3,
            lateout("x6") moved,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: arguments in rdi rsi rdx r10 r8 r9 (a0..a5), the reply in
        // the kernel's `SYSCALL_OUT` order: a1..a6 come back in rdx rsi rdi
        // r8 r9 r10 (kernel/src/entry/x86_64.rs). Every one of them is declared
        // written, as a1..a6 are on riscv64; rcx/r11 belong to `syscall`.
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") SYS_IPC_FAST_ACCEPT as isize => ret,
            inlateout("rsi") FAST_ACCEPT_SENTINEL => w0,
            lateout("rdx") caller,
            lateout("rdi") w1,
            lateout("r8") w2,
            lateout("r9") w3,
            lateout("r10") moved,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if ret < 0 {
        return None;
    }
    // The kernel guarantees a non-negative handle (bit 63 is always clear), so
    // the `ret < 0` test above already separates handle from error code.
    Some(fast_request(ret as u64, caller, [w0, w1, w2, w3], moved as u32))
}

/// The [`FastRequest`] an accept returned: `handle` from a0, `caller` from a1
/// (still [`FAST_ACCEPT_SENTINEL`] if nothing wrote it), `words` from a2..a5.
/// Shared by [`fast_ipc_accept_req`] and [`fast_ipc_reply_accept`].
fn fast_request(
    handle: u64,
    caller: u64,
    words: [u64; FAST_IPC_MAX_WORDS],
    moved_cap: u32,
) -> FastRequest {
    FastRequest {
        handle,
        moved_cap,
        // Decoded here, from the one place that knows the layout, so callers
        // never re-derive it and drift from the kernel's encoding.
        slot: (handle & FAST_IPC_HANDLE_LOG_MASK) as usize,
        caller_tid: caller as u32,
        words,
        delivered: caller != FAST_ACCEPT_SENTINEL,
    }
}

/// Server: block until a client sends a fast IPC call to this TID, keeping
/// only the reply handle.
///
/// For servers that answer without reading the request (the impersonation
/// tests, and any echo that does not depend on the payload). Servers that need
/// the request want [`fast_ipc_accept_req`].
///
/// The value returned is the **opaque handle** for [`fast_ipc_reply`], not a
/// slot index — it carries a generation tag. Use
/// `handle & FAST_IPC_HANDLE_LOG_MASK` if you need the index for logging.
pub fn fast_ipc_accept() -> Option<u64> {
    fast_ipc_accept_req().map(|r| r.handle)
}

/// Server: reply to a fast IPC call (non-blocking).
///
/// ABI (`SYS_IPC_FAST_REPLY`): a0 = the **handle** [`fast_ipc_accept`]
/// returned, a1..a4 = reply words. Only `words[0]` reaches the client — see
/// [`fast_ipc_call_ep`].
///
/// Returns `0` on success, `-2` if the handle is **stale** (its exchange is
/// gone and the slot has since been recycled), `-1` for anything else.
///
/// Two gates sit behind this call, and `ipctest` asserts both halves of each:
///
///  * **Ownership.** The kernel takes the replier's identity from the
///    scheduler, never from a register, so replying to another task's exchange
///    cannot impersonate its server.
///  * **Generation.** The handle carries a per-slot tag, so a handle kept from
///    a finished exchange cannot deliver attacker-chosen words to whoever
///    occupies that slot next.
///
/// Pass `handle` through **untouched**: no mask, no sign extension, no
/// rebuilding it from `FastRequest::slot`.
pub fn fast_ipc_reply(handle: u64, words: [u64; FAST_IPC_MAX_WORDS]) -> isize {
    unsafe {
        syscall5(SYS_IPC_FAST_REPLY,
            handle,
            words[0], words[1], words[2], words[3])
    }
}

/// Server: reply to the exchange `handle` names and accept the next request,
/// in one trap.
///
/// ABI (`SYS_IPC_FAST_REPLY_ACCEPT`): a0 = the handle, a1 =
/// `FAST_ACCEPT_SENTINEL` (the kernel does not read it), a2..a5 = the reply
/// words. The results are [`fast_ipc_accept_req`]'s. The words ride a2..a5
/// rather than [`fast_ipc_reply`]'s a1..a4 so that a1 can carry the sentinel,
/// which keeps `FastRequest::delivered` meaningful here too.
///
///  * `Ok(Some(req))` — the reply was delivered; `req` is the next request.
///  * `Ok(None)` — the reply was delivered; nothing arrived within the
///    accept's bounded wait.
///  * `Err(-2)` stale handle, `Err(-3)` any other refusal. **Nothing was
///    accepted and the reply reached no one**: the caller still holds it, and
///    a plain [`fast_ipc_accept_req`] is how it takes its next request.
///
/// A call outside this binary's seccomp row answers dispatch's `-1`, which
/// reads as `Ok(None)`; `tests/host/seccomp-tests` derives every row from the
/// binary's source so such a row cannot ship.
///
/// Same handle rule as [`fast_ipc_reply`]: pass it through untouched.
pub fn fast_ipc_reply_accept(
    handle: u64,
    words: [u64; FAST_IPC_MAX_WORDS],
) -> Result<Option<FastRequest>, isize> {
    let ret: u64;
    let caller: u64;
    let w0: u64;
    let w1: u64;
    let w2: u64;
    let w3: u64;
    let moved: u64;
    // Its own `asm!` block, for the reason `fast_ipc_accept_req` gives: the
    // result registers must be declared `lateout`.
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_REPLY_ACCEPT,
            inlateout("a0") handle => ret,
            inlateout("a1") FAST_ACCEPT_SENTINEL => caller,
            inlateout("a2") words[0] => w0,
            inlateout("a3") words[1] => w1,
            inlateout("a4") words[2] => w2,
            inlateout("a5") words[3] => w3,
            // a6 = the handle a capability moved with the NEXT request took
            // in this task's table. Read, not discarded: this call's accept
            // half is a plain accept, so a message that moves a capability
            // reaches this server through here exactly as through
            // `fast_ipc_accept_req`, and dropping it would leak authority on
            // the one path a real server actually loops on.
            lateout("a6") moved,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        // aarch64 twin — x0..=x6 mirror a0..=a6. See `fast_ipc_call_ep_status`.
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_IPC_FAST_REPLY_ACCEPT,
            inlateout("x0") handle => ret,
            inlateout("x1") FAST_ACCEPT_SENTINEL => caller,
            inlateout("x2") words[0] => w0,
            inlateout("x3") words[1] => w1,
            inlateout("x4") words[2] => w2,
            inlateout("x5") words[3] => w3,
            lateout("x6") moved,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: arguments in rdi rsi rdx r10 r8 r9 (a0..a5), the reply in
        // the kernel's `SYSCALL_OUT` order: a1..a6 come back in rdx rsi rdi
        // r8 r9 r10 (kernel/src/entry/x86_64.rs). Every one of them is declared
        // written, as a1..a6 are on riscv64; rcx/r11 belong to `syscall`.
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") SYS_IPC_FAST_REPLY_ACCEPT => ret,
            inlateout("rdi") handle => w1,
            inlateout("rsi") FAST_ACCEPT_SENTINEL => w0,
            inlateout("rdx") words[0] => caller,
            inlateout("r10") words[1] => moved,
            inlateout("r8") words[2] => w2,
            inlateout("r9") words[3] => w3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    match ret as isize {
        r if r >= 0 => Ok(Some(fast_request(ret, caller, [w0, w1, w2, w3], moved as u32))),
        -1 => Ok(None),
        e => Err(e),
    }
}

// ===========================================================================
//  Untyped shared memory (F00.4) — SYS_IPC_SHARE / _MAP / _UNSHARE
// ===========================================================================

/// Shared-memory access mode for [`shm_create_typed`]. Read-only.
pub const SHM_RO: u64 = 0;
/// Shared-memory access mode for [`shm_create_typed`]. Read-write.
pub const SHM_RW: u64 = 1;

// ===========================================================================
//  Cap<T> typed syscalls
// ===========================================================================
//
// Every wrapper below takes a raw `CapHandle` (`u32`) minted by one of the
// `*_create_typed` calls or granted by the kernel's topology, and returns
// `-Errno` from `azos_abi::error::Errno` rather than the bare `-1`/`-99`
// pair the untyped families use. `ECAPSTALE` / `ECAPKIND` / `ECAPPERMS` are
// distinguishable from `EBADF` / `EAGAIN`, which is the whole point of the
// typed path — but the numeric values live in `crates/core/abi`, which this crate
// deliberately does not depend on, so assert on `< 0` unless you have looked
// the value up.
//
// The capability tables are indexed by **task pool slot**, not by TID
// (`crates/core/ipc/src/cap_store.rs`). TIDs are monotone and `MAX_TASKS` is 64,
// so a TID-indexed table made every typed syscall fail permanently once a
// long-lived board had created its 64th task. `ipctest` pushes past that
// boundary on purpose.

/// Allocate a port and mint a `Cap<Port>` for it in the caller's cap table.
///
/// Takes no argument; returns the raw cap handle (positive) or `-Errno`
/// (`EMFILE` when the port pool or the cap table is full).
pub fn port_create_typed() -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_CREATE_PORT, [0; 4]).0
}

/// Create an endpoint **owned by this task** and mint its `Cap<Endpoint>`
/// with `RW` into this task's own capability table.
///
/// Takes no argument; returns the raw handle (positive) or `-Errno`
/// (`EMFILE` when the endpoint pool or the cap table is full).
///
/// # When you need this rather than `cap_lookup`
///
/// An endpoint declared in the topology already has a server: the task whose
/// row grants `READ` on it, fixed when the capability is seeded, by IMAGE
/// name. A task that is not an image — a `fork()`ed child — can never be that
/// server, and before this call existed it could not be a server at all.
///
/// The endpoint this returns is reachable by nobody else until its WRITE half
/// is handed over. There are now TWO ways that happens, and the second one
/// arrived with the fork-time bootstrap grant (2026-09-25):
///
/// 1. **MOVE the capability** (`fast_ipc_call_ep_moving`) — an explicit
///    hand-off to one named callee.
/// 2. **`fork()`** — the child is minted a `WRITE` capability for every
///    endpoint THIS task owns, because the caller of this function is the
///    owner (`owner_tid`), and `fork`'s grant is keyed on that relation, not
///    on capability class. So creating an endpoint and then forking is the
///    supported way to give a child a channel to its parent; see
///    `azos_ipc::endpoint::endpoint_inherit_at_fork`.
///
/// Either way, creating one grants no authority over anything that existed
/// before the call: the grant is bounded by what this task itself owns, and a
/// capability this task merely HOLDS on a third party's endpoint is not
/// inherited.
pub fn endpoint_create_typed() -> isize {
    invoke(invoke_abi::DOMAIN_SELF.as_raw(), invoke_abi::DOMAIN_CREATE_ENDPOINT, [0; 4]).0
}

/// Bytes a [`port_poll_typed`] event occupies. The kernel copies exactly this
/// many bytes and returns the count, so a smaller buffer is a fault, not a
/// short read.
pub const PORT_EVENT_BYTES: usize = 16;

/// Dequeue one event from a `Cap<Port>` into `out` (≥ [`PORT_EVENT_BYTES`]).
///
/// Returns [`PORT_EVENT_BYTES`] on success, or `-Errno` — `-EAGAIN` when the
/// queue is empty. This **does not block**; [`port_wait_typed`] does.
pub fn port_poll_typed(cap: u32, out: &mut [u8]) -> isize {
    if out.len() < PORT_EVENT_BYTES {
        return E_INVAL;
    }
    invoke(cap, invoke_abi::PORT_POLL, [out.as_mut_ptr() as u64, 0, 0, 0]).0
}

/// Bind an event source to the port behind a `Cap<Port>`, with `key` as
/// the event's key.
///
/// ABI (the `PORT_BIND` op of a port handle): a0 = port cap (needs `WRITE`), a1 =
/// source type in the `PORT_SRC_*` encoding (or-ed with
/// [`PORT_BIND_F_REMOVE`] to remove), a2 = the source's capability (a
/// `Cap<Channel>`, `Cap<IoRing>`, `Cap<Irq>` or `Cap<Endpoint>`, each with
/// `READ`), a3 = key. A timer takes its deadline instead:
/// [`port_bind_timer`]; an endpoint: [`port_bind_endpoint`].
///
/// Returns 0, or `-Errno`, in order: `-ECAPSTALE` / `-ECAPKIND` /
/// `-ECAPPERMS` for the port capability, or `-EAGAIN` while containment is
/// armed; `-EINVAL` for a source type above 4 or an unknown flag, or a pressure source whose word is not `DOMAIN_SELF`;
/// `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` for the source capability;
/// `-ECAPSTALE` when the port was destroyed before the binding was stored;
/// `-EMFILE` when the port's source table or the IRQ binding table is full;
/// `-EPERM` when the caller does not serve the endpoint; `-EBUSY` when the
/// channel, ring or endpoint reports to another port; `-ENODEV` (nothing
/// bound) when the interrupt controller cannot deliver the line.
/// The full contract is `azos_abi::syscall_nr::PORT_BIND`'s.
pub fn port_bind_typed(port: u32, source_type: u64, source_cap: u32, key: u64) -> isize {
    invoke(port, invoke_abi::PORT_BIND, [source_type, source_cap as u64, key, 0]).0
}

/// Arm (or, with a key already armed, re-arm) a one-shot timer source on the
/// port behind a `Cap<Port>`: an event with `key` and source type
/// [`PORT_EVENT_TIMER`] at `deadline_ns` (absolute nanoseconds on the time
/// counter, as [`vdso_now_ns`] reads it). `PORT_BIND` with
/// [`PORT_SRC_TIMER`].
pub fn port_bind_timer(port: u32, deadline_ns: u64, key: u64) -> isize {
    invoke(port, invoke_abi::PORT_BIND, [PORT_SRC_TIMER, deadline_ns, key, 0]).0
}

/// Bind the notices of the endpoint behind `ep_cap` (a `Cap<Endpoint>` with
/// `READ`, which the caller serves) to the port behind `port`, with `key`
/// (`PORT_BIND` with [`PORT_SRC_ENDPOINT`]). The port then reports
/// [`PORT_EVENT_NO_SENDERS`] (code `ENOSENDERS`) when no send capability to
/// the endpoint is left, at once if there is none now, and
/// [`PORT_EVENT_SOURCE_GONE`] when the endpoint is destroyed. 0, or `-Errno`
/// ([`port_bind_typed`]'s, and `-EPERM` when the caller does not serve it).
pub fn port_bind_endpoint(port: u32, ep_cap: u32, key: u64) -> isize {
    port_bind_typed(port, PORT_SRC_ENDPOINT, ep_cap, key)
}

/// Have the port behind `port` report this Domain's memory pressure, with
/// `key` (`PORT_BIND` with [`PORT_SRC_PRESSURE`], the source word
/// `DOMAIN_SELF`). The port then gets a [`PORT_EVENT_PRESSURE`] event whenever
/// the Domain's frame budget changes level, from its high watermark on and
/// before the kernel compresses any of its pages; [`pressure_level`] reads it.
/// One port per Domain: a second bind replaces the first. 0, or `-Errno`
/// (`-EINVAL` when the build has no reclaim, so no watermarks; the port
/// capability's refusals as [`port_bind_typed`]).
pub fn port_bind_pressure(port: u32, key: u64) -> isize {
    port_bind_typed(port, PORT_SRC_PRESSURE, invoke_abi::DOMAIN_SELF.as_raw(), key)
}

/// The level a [`PORT_EVENT_PRESSURE`] event reports (a 16-byte event as
/// [`port_poll_typed`] writes it): 0 normal, 1 warning (reclaim is due), 2
/// critical (the limit is reached). `None` for any other event.
pub fn pressure_level(event: &[u8; PORT_EVENT_BYTES]) -> Option<u8> {
    (event[8] == PORT_EVENT_PRESSURE).then(|| event[12])
}

/// Remove the sources of type `source_type` (`PORT_SRC_RING`,
/// `PORT_SRC_TIMER`, `PORT_SRC_ENDPOINT` or `PORT_SRC_PRESSURE`) bound with `key`: 0, or `-ENOENT`
/// when there was none.
pub fn port_unbind_typed(port: u32, source_type: u64, key: u64) -> isize {
    invoke(port, invoke_abi::PORT_BIND, [source_type | PORT_BIND_F_REMOVE, 0, key, 0]).0
}

/// Wait until the port behind a `Cap<Port>` has an event or `deadline_ns`
/// passes, whichever is first (`SYS_PORT_WAIT`).
///
/// `deadline_ns` is absolute, in nanoseconds on the time counter
/// ([`vdso_now_ns`]); `u64::MAX` waits with no deadline, and any instant
/// already passed (0 included) polls. Returns [`PORT_EVENT_BYTES`] with the
/// event in `out` ([`port_poll_typed`]'s layout), 0 when the deadline passed
/// with nothing ready (`out` untouched), or `-Errno`: the capability's
/// `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`, `-EFAULT`, `-ECAPSTALE` when the
/// port is destroyed during the wait, `-EMFILE` when the port has its
/// maximum number of waiters, `-EBUSY` when the scheduler refused to block.
pub fn port_wait_until_typed(cap: u32, out: &mut [u8; PORT_EVENT_BYTES], deadline_ns: u64) -> isize {
    unsafe { syscall3(SYS_PORT_WAIT, cap as u64, out.as_mut_ptr() as u64, deadline_ns) }
}

/// Block until the port behind a `Cap<Port>` has an event, and dequeue it
/// into `out`: [`port_wait_until_typed`] with no deadline.
pub fn port_wait_typed(cap: u32, out: &mut [u8; PORT_EVENT_BYTES]) -> isize {
    port_wait_until_typed(cap, out, u64::MAX)
}

/// Free the port behind a `Cap<Port>`.
///
/// The capability itself is **not** revoked — the handle survives as a stale
/// reference until the caller revokes it, which is what makes `ECAPSTALE`
/// observable rather than a use-after-free.
pub fn port_destroy_typed(cap: u32) -> isize {
    invoke(cap, invoke_abi::PORT_DESTROY, [0; 4]).0
}

/// Create a MemObj of `pages` pages with the creation word `perms` and mint a
/// `Cap<Shm>` for it. The word is the access mode ([`SHM_RO`] / [`SHM_RW`])
/// alone, or with the fields of `SYS_MO_CREATE` in `azos_abi`
/// (attributes `SHM_ATTR_*` shifted by `SHM_CREATE_ATTR_SHIFT`; `SHM_CREATE_CLONE`
/// with the source capability in `63:32` for a copy-on-write snapshot).
///
/// Returns the raw cap handle (positive) or `-Errno`. On cap-table exhaustion
/// the region is rolled back, so a failure never leaves a half-created
/// region behind.
pub fn shm_create_typed(pages: u64, perms: u64) -> isize {
    unsafe { syscall2(SYS_MO_CREATE, pages, perms) }
}

/// Bytes written by [`shm_acquire_typed`]: `page_count u32 LE`, `perms u8`
/// (0 = RO, 1 = RW), 3 bytes of padding.
pub const SHM_INFO_BYTES: usize = 8;

/// Take a reference on the region behind a `Cap<Shm>` and read its geometry
/// into `out` (≥ [`SHM_INFO_BYTES`]). Requires `READ`. The reference is given
/// back by the capability's [`shm_release_typed`], with the task's others.
pub fn shm_acquire_typed(cap: u32, out: &mut [u8]) -> isize {
    if out.len() < SHM_INFO_BYTES {
        return E_INVAL;
    }
    invoke(cap, invoke_abi::MEMOBJ_ACQUIRE, [out.as_mut_ptr() as u64, 0, 0, 0]).0
}

/// Map the region behind a `Cap<Shm>` into the caller's address space and
/// return its base VA.
///
/// ABI (`SYS_MO_MAP`): a0 = cap. Needs `READ`, and `WRITE` too
/// when the region is read-write; the mapping is writable exactly when the
/// region is. The map takes a reference of its own and records the mapping,
/// one per task and region.
///
/// Returns the VA (positive), or `-Errno`: `-ECAPSTALE` / `-ECAPKIND` /
/// `-ECAPPERMS` for the capability, or `-EAGAIN` for a read-write region
/// while containment is armed; `-EBUSY` when this task already maps the
/// region; `-EBADF` when the region has no room for another holder;
/// `-ENOMEM` when the pages could not be mapped.
///
/// [`shm_release_typed`] removes this task's mapping, then gives back the
/// map's reference together with the task's others. After an `-ENOMEM` the
/// reference stays booked to the task until it exits, since a partial mapping
/// may remain.
pub fn shm_map_typed(cap: u32) -> isize {
    // `a1 = 0` selects the map; the kernel reads it, so it is passed, never left
    // to whatever the register held.
    unsafe { syscall2(SYS_MO_MAP, cap as u64, 0) }
}

/// Map the kernel's introspection region `key` (`SHM_INSPECT_PUBLIC` or
/// `SHM_INSPECT_ADMIN`, `azos_abi::cap`) read-only: its address and size in
/// bytes. `Err` is the first refusal: no such capability in the caller's
/// table (its row grants none, the kernel has Kconfig INSPECT off, or the
/// admin region was refused for want of the task view), or the acquire or the
/// map failed. One lookup, one acquire and one map; every read after is a load
/// (`userspace/lib/inspect`).
pub fn inspect_map(key: u32) -> Result<(*const u8, usize), isize> {
    let cap = cap_lookup(ty::SHM.raw(), key);
    if cap < 0 {
        return Err(cap);
    }
    let mut info = [0u8; SHM_INFO_BYTES];
    let rc = shm_acquire_typed(cap as u32, &mut info);
    if rc < 0 {
        return Err(rc);
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = shm_map_typed(cap as u32);
    if va <= 0 {
        return Err(va);
    }
    Ok((va as *const u8, pages * PAGE_SIZE))
}

/// Change the access of this task's mapping of the region behind a `Cap<Shm>`
/// (`SYS_MO_MAP`'s protect form): read-only, or with `write` writable
/// again, never past what the map was allowed. 0, or `-Errno`:
/// `-ECAPPERMS` past the map's rights,
/// `-EBUSY` while the region has frames a clone shares, `-EBADF` with no
/// mapping, `-ECAPSTALE` / `-ECAPKIND` for the capability.
pub fn shm_protect_typed(cap: u32, write: bool) -> isize {
    use azos_abi::syscall_nr::{SHM_MAP_OP_PROTECT, SHM_MAP_PROT_WRITE};
    let op = SHM_MAP_OP_PROTECT | if write { SHM_MAP_PROT_WRITE } else { 0 };
    unsafe { syscall2(SYS_MO_MAP, cap as u64, op) }
}

/// Give back the region behind a `Cap<Shm>`: this task's mapping is removed
/// first, then every reference the task holds on the region (the creation
/// reference, [`shm_acquire_typed`]'s and [`shm_map_typed`]'s), and the
/// capability is revoked. The backing pages go back to the PMM when no task
/// holds a reference; another task's references keep the region live.
/// Requires `READ`. One call per capability: a second answers `-ECAPSTALE`.
pub fn shm_release_typed(cap: u32) -> isize {
    unsafe { syscall3(SYS_MO_UNMAP, cap as u64, 0, 0) }
}

/// Give up the pipe `ends` ([`invoke_abi::SHM_END_READ`], [`invoke_abi::SHM_END_WRITE`])
/// this process holds on the region behind a `Cap<Shm>` (`MEMOBJ_END_DROP`): the
/// kernel keeps the end counts, and wakes the peers when this was the last
/// holder of an end. Requires `READ`.
pub fn shm_end_drop_typed(cap: u32, ends: u64) -> isize {
    invoke(cap, invoke_abi::MEMOBJ_END_DROP, [ends, 0, 0, 0]).0
}

/// Allocate an io_ring, mint a `Cap<IoRing>`, map the ring page into this
/// task, and write its **user virtual address** as `u64` LE into `addr_out`.
///
/// The page is mapped user RW and never executable; its layout is
/// `io_ring::IoRing` in `crates/core/ipc/src/io_ring.rs`, whose offsets are pinned
/// there by compile-time assertions. It stays mapped until
/// [`ioring_destroy_typed`] or exit. Ring 3 is never handed the physical
/// address.
///
/// Returns the raw cap handle (positive) or `-Errno`: `-ENOMEM` when the page
/// cannot be mapped, `-EFAULT` when `addr_out` cannot be written; either way
/// no ring or capability is left behind.
pub fn ioring_create_typed(addr_out: &mut [u8; 8]) -> isize {
    unsafe { syscall1(SYS_RING_SETUP, addr_out.as_mut_ptr() as u64) }
}

/// Execute the pending SQEs on a `Cap<IoRing>` through the kernel's op table.
/// Requires `WRITE`.
///
/// Returns the number of entries completed, `-EBUSY` when an entry was pending
/// and the completion queue had no room (nothing ran: drain `cq_head` and
/// submit again), or `-Errno` for the capability. Each entry is decided on its
/// own: the submitter's seccomp row must list the typed syscall the opcode
/// stands for, the ring's owner must hold its capability, and a write is
/// refused while contained. A refused entry still completes, with
/// `CQE_F_REFUSED` in its flags and a negative errno as its result, and is
/// counted; a motor entry refused by a latched e-stop answers `-EAGAIN`.
pub fn ioring_submit_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_RING_ENTER, cap as u64) }
}

/// Free an io_ring and its backing page. Requires `WRITE`, and is not refused
/// while degraded mode is contained. **The capability is revoked** by the same
/// call, so a later use of it answers `-ECAPSTALE` instead of reaching a ring
/// created at the same index.
pub fn ioring_destroy_typed(cap: u32) -> isize {
    close_typed(cap)
}

// ===========================================================================
//  The user shell's calls and the process startup
// ===========================================================================

pub use azos_abi::ushell::{
    SpawnReq, Move, StartupBlock, StartupFd, MOVE_CONSOLE, SPAWN_F_DIE_WITH_PARENT, SPAWN_F_CONSOLE_IN,
    KILL_REQUEST, KILL_FORCE, KILL_SUBTREE, CONSOLE_WAIT_FOREVER, SPAWN_REQ_VERSION,
};

/// What a process knows about itself: its fd table and, if it was started
/// by `SYS_SPAWN_EX`, its startup block. Programs are single-threaded.
struct ProcState {
    fds: FdTable,
    startup: Option<StartupBlock>,
}

struct ProcCell(core::cell::UnsafeCell<ProcState>);
// SAFETY: a ring-3 program here has one thread; nothing runs concurrently
// with it in its address space.
unsafe impl Sync for ProcCell {}

static PROC: ProcCell = ProcCell(core::cell::UnsafeCell::new(ProcState {
    fds: FdTable::new(),
    startup: None,
}));

fn proc_state() -> &'static mut ProcState {
    // SAFETY: see `ProcCell`; no reference outlives the call that takes it.
    unsafe { &mut *PROC.0.get() }
}

fn fd_entry(fd: u64) -> FdEntry {
    proc_state().fds.fd_slot(fd)
}

/// Read the startup block `SYS_SPAWN_EX` left for this process. Call it
/// first thing in `_start(_a0, a1)` with `a1` (`x1`); 0, or a block that
/// does not validate, leaves the defaults (no arguments; fd 1 and 2 the
/// console). Returns whether a block was taken.
pub fn startup_init(a1: usize) -> bool {
    if a1 == 0 || a1 % 8 != 0 {
        return false;
    }
    // SAFETY: the kernel wrote the block at `a1` on this process's own stack,
    // above the stack pointer it started with; nothing has written there.
    let raw = unsafe { core::slice::from_raw_parts(a1 as *const u8, azos_abi::ushell::STARTUP_BLOCK_SIZE) };
    let Some(sb) = StartupBlock::from_bytes(raw).filter(|b| b.validate()) else { return false };
    let p = proc_state();
    // A pipe end arrives as a `Cap<Shm>`: it becomes a token (the fd's
    // position says which end).
    let mut fds = sb.fds;
    pipe::adopt_startup(&mut fds);
    p.fds = FdTable::fd_table_from_startup(&fds);
    p.startup = Some(sb);
    true
}

fn startup_blob(ptr: u64, len: u32) -> &'static [u8] {
    if ptr == 0 || len == 0 {
        return &[];
    }
    // SAFETY: the pointer and length come from a validated startup block the
    // kernel laid out on this process's stack, above its stack pointer.
    unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

/// Number of arguments (0 without a startup block).
pub fn argc() -> usize {
    proc_state().startup.map_or(0, |b| b.argc as usize)
}

/// Argument `i` (`arg(0)` is the name the program was run by).
pub fn arg(i: usize) -> Option<&'static [u8]> {
    let b = proc_state().startup?;
    cstr_at(startup_blob(b.argv, b.argv_bytes), i)
}

/// The value of environment variable `key`.
pub fn getenv(key: &[u8]) -> Option<&'static [u8]> {
    let b = proc_state().startup?;
    env_lookup(startup_blob(b.env, b.env_bytes), key)
}

/// Environment string `i` (`KEY=VALUE`).
pub fn env_at(i: usize) -> Option<&'static [u8]> {
    let b = proc_state().startup?;
    cstr_at(startup_blob(b.env, b.env_bytes), i)
}

/// The working directory the spawner gave, `/` if none. The kernel keeps no
/// working directory: a program makes its paths absolute against this.
pub fn cwd() -> &'static [u8] {
    match proc_state().startup {
        Some(b) if b.cwd != 0 => startup_blob(b.cwd, b.cwd_bytes),
        _ => b"/",
    }
}

/// What small fd `fd` is.
pub fn fd_get(fd: u64) -> FdEntry {
    fd_entry(fd)
}

/// `dup`: the lowest closed small fd now names what `fd` names. No trap.
pub fn dup(fd: u64) -> isize {
    match proc_state().fds.fd_alias(fd) {
        Some(n) => n as isize,
        None => E_BADF,
    }
}

/// `dup2`: `new` names what `old` names; what `new` named is closed if that
/// was its last fd. Traps only for that close.
pub fn dup2(old: u64, new: u64) -> isize {
    match proc_state().fds.fd_alias_to(old, new) {
        Ok(Some(h)) => {
            let _ = close_typed(h);
            new as isize
        }
        Ok(None) => new as isize,
        Err(()) => E_BADF,
    }
}

/// Make small fd `fd` name handle `h` (closing what it named, if last).
pub fn fd_install(fd: u64, h: u32) {
    if let Some(gone) = proc_state().fds.fd_put_handle(fd, h) {
        let _ = close_typed(gone);
    }
}

/// Start the image at `path` (`SYS_SPAWN_EX`). `req`: arguments,
/// environment, working directory and move list, or `None` for none. The
/// pointers in `req` must stay valid for the call. Returns the child's TID or
/// a negative errno.
pub fn spawn_ex(path: &[u8], req: Option<&SpawnReq>) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    let r = req.map_or(0, |r| r as *const SpawnReq as u64);
    unsafe { syscall2(SYS_SPAWN_EX, path.as_ptr() as u64, r) }
}

/// Wait for console input or a child's exit (the console's `WAIT` op): bytes
/// read, 0 on timeout, `E_INTR` for a pending exit notice or a stop request,
/// `-EBUSY` when another task owns console input. An empty `buf` waits only
/// for a child's exit or the timeout.
pub fn console_wait(buf: &mut [u8], timeout_ns: u64) -> isize {
    let h = console_cap();
    if h < 0 {
        return h;
    }
    invoke(h as u32, invoke_abi::LOG_CONSOLE_WAIT, [buf.as_mut_ptr() as u64, buf.len() as u64, timeout_ns, 0]).0
}

/// Ask descendant `tid` to stop (`SYS_ALERT`): `how` is `KILL_REQUEST` or
/// `KILL_FORCE`, `flags` `KILL_SUBTREE` or 0. Tasks signalled, or a negative
/// errno (`-ESRCH` for anything not a descendant).
pub fn task_kill(tid: u32, how: u64, signo: u64, flags: u64) -> isize {
    unsafe { syscall4(SYS_ALERT, tid as u64, how, signo, flags) }
}

/// The power family's operations and limits (`POWER_OP_*`).
pub use azos_abi::power;

/// The kernel tracer's operations, classes and event ids (wave 15).
pub use azos_abi::trace as trace_abi;

/// Set task `tid`'s dispatch class (`SYS_SCHEDCTL`, N6b; `tid` 0 = the
/// caller): `class` is `SCHEDCTL_CLASS_{FAIR,RT,DL}`, `prio` the base
/// priority, `runtime_us`/`period_us` the DL reservation (0 otherwise),
/// `warrant` a `time` endpoint capability (needed for RT and DL). Returns 0
/// or a negative errno.
pub fn schedctl(tid: u32, class: u64, prio: u32, runtime_us: u64, period_us: u64, warrant: u32) -> i64 {
    unsafe { syscall6(SYS_SCHEDCTL, tid as u64, class, prio as u64, runtime_us, period_us, warrant as u64) as i64 }
}

pub use azos_abi::syscall_nr::{
    QOS_BACKGROUND, QOS_DEFAULT, QOS_LATENCY, QOS_THROUGHPUT, SCHEDCTL_CLASS_DL, SCHEDCTL_CLASS_FAIR,
    SCHEDCTL_CLASS_RT, SCHEDCTL_HINT_QOS,
};

/// Tell the scheduler what this task wants (`SYS_SCHEDCTL`'s QoS hint):
/// `QOS_DEFAULT` 0, `QOS_LATENCY` 1, `QOS_THROUGHPUT` 2, `QOS_BACKGROUND` 3. A
/// hint only; it changes no class and no priority. A task that says
/// throughput or background lets the kernel fire its timers late and share
/// wake-ups with other sleepers (never a real-time or deadline task's).
/// `-EINVAL` above 3.
pub fn qos_hint(level: u32) -> i64 {
    schedctl(0, SCHEDCTL_HINT_QOS, level, 0, 0, 0)
}

/// The kernel tracer's control (wave 15): operation `op`
/// (`azos_abi::invoke::LOG_TRACE_*`) with argument `arg`, on the `Log` handle
/// `cap` of the tracer. The operation's value (`LOG_TRACE_MAP`: the region's
/// address), else a negative errno (`-ENOSYS` with the tracer compiled out,
/// `-ECAPPERMS` etc. without the capability).
pub fn trace_ctl(cap: u32, op: u16, arg: u64) -> isize {
    invoke(cap, op, [arg, 0, 0, 0]).0
}

/// ABI v2 of the call's message descriptor (wave 15 N11).
pub use azos_abi::ipc_msg::{self as ipc_msg_abi, CapDesc, MsgDesc};

/// The v2 call (`SYS_IPC_CALL_V2`, wave 15 N11b): call through the endpoint
/// capability `ep` with the request in `*msg`; blocks until it is answered
/// and writes the answer over `*msg`. 0 when answered, else a negative
/// code (`-EPEERDIED`, `-EREVOKED`, `-EINVAL`, `-EFAULT`, -1 refused).
pub fn ipc_call_v2(ep: u32, msg: &mut MsgDesc) -> isize {
    unsafe { syscall2(SYS_IPC_CALL_V2, ep as u64, msg as *mut MsgDesc as u64) }
}

/// The v2 accept (`SYS_IPC_ACCEPT_V2`): the next call on an endpoint this
/// task serves, written into `*msg` (with the badge for a v2 call). The
/// call's handle (`>= 0`), -1 when nothing arrived, or `-EFAULT`.
pub fn ipc_accept_v2(msg: &mut MsgDesc) -> isize {
    unsafe { syscall1(SYS_IPC_ACCEPT_V2, msg as *mut MsgDesc as u64) }
}

/// The v2 reply (`SYS_IPC_REPLY_V2`): answer call `handle`, as the holder of
/// its reply warrant, with `*msg`. 0, -2 over, -3 not the holder, else a
/// negative code.
pub fn ipc_reply_v2(handle: u64, msg: &MsgDesc) -> isize {
    unsafe { syscall2(SYS_IPC_REPLY_V2, handle, msg as *const MsgDesc as u64) }
}

/// Hand the reply warrant of call `handle` to thread `to` of this process
/// (`SYS_IPC_REPLY_DELEGATE`). 0, -2 over, -3 not the holder, `-EPERM`.
pub fn ipc_reply_delegate(handle: u64, to: u32) -> isize {
    unsafe { syscall2(SYS_IPC_REPLY_DELEGATE, handle, to as u64) }
}

/// Mint a copy of the unbadged endpoint capability `ep` carrying `badge`,
/// with `rights`, lapsing at `expiry_ns` (absolute ns on the MONO clock; 0 none)
/// (`SYS_CAP_DERIVE`). The new handle, or a negative capability error.
pub fn cap_derive(ep: u32, rights: u16, badge: u32, expiry_ns: u64) -> isize {
    unsafe { syscall4(SYS_CAP_DERIVE, ep as u64, rights as u64, badge as u64, expiry_ns) }
}

/// Mint a copy of the unbadged endpoint capability `ep` carrying `badge`, with
/// `rights` (`CapPerms` bits), lapsing at `expiry_ns` (absolute ns on the MONO
/// clock; 0 none) and the `caveats` (`(kind, argument)`, at most
/// [`invoke_abi::ENDPOINT_DERIVE_CAVEATS_MAX`]; `azos_ipc::cap::caveat` names
/// the kinds) after the source's (`ENDPOINT_DERIVE`). The new handle, or a
/// negative error: `-EINVAL` for more caveats than fit, `-ECAPPERMS` for a
/// kind the kernel does not know.
pub fn endpoint_derive(ep: u32, rights: u8, badge: u32, expiry_ns: u64, caveats: &[(u8, u64)]) -> isize {
    if caveats.len() > invoke_abi::ENDPOINT_DERIVE_CAVEATS_MAX {
        return E_INVAL;
    }
    // Seven words, past what the register form takes (`azos_abi::invoke`):
    // rights, count and badge; the deadline; the kinds, a byte each; the
    // arguments.
    let mut d = MsgDesc { version: azos_abi::ipc_msg::MSG_VERSION, n_words: 7, ..MsgDesc::default() };
    d.words[0] = rights as u64 | (caveats.len() as u64) << 8 | (badge as u64) << 32;
    d.words[1] = expiry_ns;
    for (i, &(kind, arg)) in caveats.iter().enumerate() {
        d.words[2] |= (kind as u64) << (8 * i);
        d.words[3 + i] = arg;
    }
    invoke_desc(ep, invoke_abi::ENDPOINT_DERIVE, &mut d)
}

/// Revoke everything derived from `handle` and keep it (`SYS_CAP_REVOKE`):
/// the replacement handle, the old one now stale, or a negative capability
/// error.
pub fn cap_revoke(handle: u32) -> isize {
    unsafe { syscall1(SYS_CAP_REVOKE, handle as u64) }
}

/// What a held handle is (`SYS_CAP_INFO`, `CAP_INFO_QUERY`): its type, rights,
/// badge and expiry. `Err` is a negative capability error (`-ECAPSTALE`).
pub fn cap_info(handle: u32) -> Result<CapInfo, isize> {
    let ret: isize;
    let (badge, expiry): (u64, u64);
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") SYS_CAP_INFO,
            inlateout("a0") handle as u64 => ret,
            inlateout("a1") CAP_INFO_QUERY => badge,
            inlateout("a2") 0u64 => expiry,
            inlateout("a3") 0u64 => _,
            lateout("a4") _, lateout("a5") _, lateout("a6") _,
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_CAP_INFO,
            inlateout("x0") handle as u64 => ret,
            inlateout("x1") CAP_INFO_QUERY => badge,
            inlateout("x2") 0u64 => expiry,
            inlateout("x3") 0u64 => _,
            lateout("x4") _, lateout("x5") _, lateout("x6") _,
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
        // x86_64: a1..a6 come back in rdx rsi rdi r8 r9 r10.
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") SYS_CAP_INFO as isize => ret,
            inlateout("rdi") handle as u64 => _,
            inlateout("rsi") CAP_INFO_QUERY => expiry,
            inlateout("rdx") 0u64 => badge,
            inlateout("r10") 0u64 => _,
            lateout("r8") _, lateout("r9") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if ret < 0 {
        return Err(ret);
    }
    Ok(CapInfo { ty: (ret & 0xFF) as u8, rights: ((ret >> 8) as u8) & azos_abi::cap::CapPerms::ALL.bits(), badge: badge as u32, expiry_ns: expiry })
}

/// The answer of [`cap_info`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapInfo {
    /// The raw `CapType` (`azos_abi::cap::ty`).
    pub ty: u8,
    /// The rights (`CapPerms` bits).
    pub rights: u8,
    /// The badge a derived endpoint copy carries; 0 for none.
    pub badge: u32,
    /// Absolute ns on the MONO clock the capability lapses at; 0 for never.
    pub expiry_ns: u64,
}

/// The flight, behavior, config and OTA families' operations and limits
/// (wave 12).
pub use azos_abi::families;

/// `DOMAIN_MODULE_VERIFY`: ask the kernel to check the module
/// FILE bytes `module` against its digest table under the 8.3 `name`.
/// Returns a one-shot token (`> 0`) for [`module_map_x`], `-EPERM` when the
/// bytes or the name are not in the table (the kernel records it), or
/// `-ENOSYS` on a kernel built without the `lx-loader` feature.
pub fn module_verify(module: &[u8], name: &[u8]) -> isize {
    domain_op(invoke_abi::DOMAIN_MODULE_VERIFY, [
        module.as_ptr() as u64, module.len() as u64, name.as_ptr() as u64, name.len() as u64,
    ])
}

/// `DOMAIN_MODULE_MAP_X`: turn the caller's relocated module
/// text at `addr` (page-aligned, `len` bytes, the caller's own anonymous
/// memory) from read-write into read-execute. Consumes `token` whatever the
/// outcome. `0`, `-EPERM` (token) or `-EINVAL` (range).
pub fn module_map_x(token: u64, addr: u64, len: u64) -> isize {
    domain_op(invoke_abi::DOMAIN_MODULE_MAP_X, [token, addr, len, 0])
}

/// The foreign-ABI family (`azos_abi::foreign`).
pub use azos_abi::foreign as foreign_abi;

/// Register the calling thread's foreign-ABI trap entry (`SYS_FOREIGN_ENTRY`);
/// 0 withdraws it. 0 or a negative errno.
pub fn foreign_entry(entry: u64) -> i64 {
    unsafe { syscall2(SYS_FOREIGN_ENTRY, entry, 0) as i64 }
}

/// Copy the calling process for a hosted foreign `fork` (`SYS_FOREIGN_FORK`):
/// 0 in the child, the child's id in the parent, or a negative errno. Only a
/// thread that registered a foreign entry may ask (`-EPERM` otherwise): a
/// native program creates a process with [`spawn_ex`].
pub fn foreign_fork() -> isize {
    unsafe { syscall0(SYS_FOREIGN_FORK) }
}

/// Hand the calling thread back to its foreign program with `frame`
/// (`SYS_FOREIGN_RESUME`). Does not return on success; the negative errno
/// otherwise (the thread stays in runtime mode).
///
/// # Safety
/// `frame` is read by the kernel, which restores every register in it: the
/// caller answers for the program counter and stack pointer it contains.
pub unsafe fn foreign_resume(frame: *const foreign_abi::ForeignFrame) -> i64 {
    unsafe { syscall1(SYS_FOREIGN_RESUME, frame as u64) as i64 }
}
}
