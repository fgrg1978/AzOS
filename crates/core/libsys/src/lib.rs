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
//! ABI convention (AArch64 — phase 6 prep, no kernel-side dispatch yet):
//!   x8 = syscall number
//!   x0..x5 = arguments
//!   svc #0
//!   x0 = return value (i64, negative = error)
//!
//! The two are a direct, register-for-register analogue of each other
//! (`x0..=x5` for `a0..=a5`, `x8` for `a7`), documented in full —
//! including what the kernel must preserve/clobber — in
//! `crates/core/abi/src/syscall_nr.rs`'s "Register convention" section, the
//! canonical home for this. Every raw `asm!` block below that issues a
//! trap is `#[cfg(target_arch = ..)]`-selected within a single function
//! body, so RISC-V callers see the same function they always did and the
//! RISC-V codegen is untouched byte-for-byte by the aarch64 branch sitting
//! next to it.

#![no_std]

use core::arch::asm;

mod pure;
pub use pure::*;
// The SPSC rings (wave 6; moved out in wave 11 so the kernel can produce
// into them): every item, at its old path.
pub use azos_spsc::*;

// ---------------------------------------------------------------------------
// Syscall numbers.
//
// `crates/core/abi` is the single source of truth (`crates/core/abi/src/syscall_nr.rs`).
// These names are imported, not restated, so a number can no longer drift
// between the kernel-facing definition and this userspace wrapper crate.
// ---------------------------------------------------------------------------
use azos_abi::syscall_nr::{
    SYS_TEST, SYS_PUTCHAR, SYS_GETCHAR, SYS_EXIT,
    SYS_GETPID, SYS_YIELD, SYS_FORK, SYS_EXEC,
    SYS_WAIT, SYS_WAIT_STATUS, SYS_SLEEP, SYS_EXECPATH, SYS_SPAWN,
    SYS_THREAD_CREATE, SYS_THREAD_EXIT, SYS_FUTEX_WAIT, SYS_FUTEX_WAKE,
    SYS_WRITE,
    SYS_GPIO_INFO, SYS_PWM_INFO, SYS_I2C_SCAN,
    SYS_I2C_INFO, SYS_MOTOR_CREATE, SYS_MOTOR_INFO, SYS_MEMINFO,
    SYS_TASKINFO, SYS_UPTIME, SYS_STAT, SYS_READDIR,
    SYS_MKDIR, SYS_UNLINK, SYS_CHDIR, SYS_GETCWD,
    SYS_MOUNT, SYS_UMOUNT, SYS_SYNC, SYS_NET_INFO,
    SYS_RMDIR, SYS_RENAME, SYS_TRUNCATE, SYS_FSYNC_TYPED, SYS_STATFS,
    SYS_NET_GETIP, SYS_NET_SETIP, SYS_NET_PING, SYS_NET_GETMAC,
    SYS_NET_STATS, SYS_CAP_LOOKUP, SYS_DRIVER_REGISTER_TYPED, SYS_DRIVER_UNREGISTER_TYPED,
    SYS_WAITPID, SYS_EXIT_STATS, SYS_TASK_SUBREAPER, SYS_MOTOR_SPEED_TYPED, SYS_SENSOR_READ_TYPED, SYS_SHUTDOWN,
    SYS_REBOOT, SYS_DISK_INFO, SYS_DISK_READ, SYS_DISK_WRITE,
    SYS_DISK_SIZE, SYS_SOCKET,
    SYS_BIND, SYS_LISTEN, SYS_ACCEPT, SYS_CONNECT,
    SYS_SEND, SYS_RECV, SYS_SENDTO, SYS_RECVFROM,
    SYS_SOCK_SHUTDOWN, SYS_BRK, SYS_MMAP, SYS_MUNMAP,
    SYS_DRV_INVOKE, SYS_SERVICE_REGISTER, SYS_SERVICE_DISCOVER, SYS_SERVICE_HEARTBEAT,
    SYS_SERVICE_STOP, SYS_ROBOT_INIT, SYS_ROBOT_START, SYS_ROBOT_STOP,
    SYS_ROBOT_PAUSE, SYS_ROBOT_RESUME, SYS_ROBOT_ESTOP, SYS_ROBOT_MOVE,
    SYS_ROBOT_FORWARD, SYS_ROBOT_ROTATE, SYS_ROBOT_INFO, SYS_SENSOR_INFO,
    SYS_SENSOR_ADD, SYS_DRV_REGISTER, SYS_DRV_MUNMAP,
    SYS_DRV_IRQ_WAIT, SYS_DRV_IRQ_ACK, SYS_IRQ_BIND, SYS_DRV_HEARTBEAT, SYS_DRIVER_FETCH_REQ,
    SYS_DRIVER_REPLY, SYS_IPC_FAST_CALL, SYS_IPC_FAST_CALL_EP, SYS_ENDPOINT_CREATE_TYPED,
    SYS_IPC_FAST_REPLY, SYS_IPC_FAST_ACCEPT,
    SYS_CHAN_WRITE_TYPED, SYS_CHAN_READ_TYPED, SYS_PORT_CREATE_TYPED, SYS_PORT_POLL_TYPED,
    SYS_PORT_DESTROY_TYPED, SYS_SHM_CREATE_TYPED, SYS_SHM_ACQUIRE_TYPED, SYS_SHM_RELEASE_TYPED,
    SYS_IORING_CREATE_TYPED, SYS_IORING_SUBMIT_TYPED, SYS_IORING_DESTROY_TYPED, SYS_GPIO_READ_TYPED,
    SYS_GPIO_WRITE_TYPED, SYS_GPIO_SET_DIR_TYPED, SYS_I2C_READ_TYPED, SYS_I2C_WRITE_TYPED,
    SYS_I2C_DETECT_TYPED, SYS_PWM_ENABLE_TYPED, SYS_PWM_DISABLE_TYPED, SYS_PWM_SET_PERIOD_TYPED,
    SYS_PWM_SET_DUTY_TYPED, SYS_PWM_SET_DUTY_PCT_TYPED, SYS_MOTOR_SET_TARGET_TYPED, SYS_MOTOR_TICK_TYPED,
    SYS_MOTOR_ENABLE_TYPED, SYS_MOTOR_ENABLED_TYPED, SYS_MOTOR_SET_GAINS_TYPED, SYS_MOTOR_RESET_TYPED,
    SYS_TRACE_DUMP, SYS_SECCOMP, SYS_PLATFORM_INFO, SYS_PLATFORM_TYPE,
    SYS_FILE_OPEN_TYPED, SYS_FILE_READ_TYPED, SYS_FILE_WRITE_TYPED, SYS_CLOSE_TYPED,
    SYS_SOCKET_TYPED, SYS_CONNECT_TYPED, SYS_SEND_TYPED, SYS_RECV_TYPED,
    SYS_MCAST_JOIN_TYPED, SYS_MCAST_LEAVE_TYPED, SYS_ADC_READ, SYS_MOTOR_DIRECTION_TYPED,
    SYS_MOTOR_ANGLE_TYPED, SYS_MOTOR_MOVE_TYPED, SYS_CHAN_CREATE_TYPED, SYS_SHM_MAP_TYPED, SYS_PORT_BIND_TYPED,
    SYS_PORT_WAIT_TYPED, SYS_IPC_FAST_REPLY_ACCEPT, SYS_DRIVER_REPLY_FETCH, SYS_DRIVER_REPLY_WAIT,
    SYS_SLEEP_UNTIL, SYS_LINK_KEY_READ_TYPED, SYS_ENTROPY_READ_TYPED,
    SYS_SENSOR_READ_TS,
    SYS_PORT_WAIT_UNTIL_TYPED,
    SYS_PIPE_TYPED, SYS_SPAWN_EX, SYS_CONSOLE_WAIT, SYS_TASK_KILL,
    SYS_NOTIFY_ROBUST, SYS_IPC_LEASE_ACCEPT_MAP,
    SYS_POWER_TYPED,
    SYS_FLIGHT_TYPED, SYS_BEHAVIOR_TYPED, SYS_CONFIG_TYPED, SYS_OTA_TYPED,
    SYS_MODULE_VERIFY, SYS_MODULE_MAP_X,
    SYS_TRACE_CTL_TYPED,
};

// Sensor type IDs for sensor_read_typed()
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

// RFC-0002 driver-server family (E11.AQ3) — a userspace process serves a
// driver `kind` for the in-kernel UserDriverProxy. Distinct from the
// SYS_DRV_* (300) MMIO-ownership family above.

// Untyped shared memory (F00.4). `SYS_IPC_MAP` is gated to the region's
// creator (`dispatch.rs`, SYS_IPC_MAP arm) — cross-task sharing is the
// typed `Cap<Shm>` path's job, not this one.
// 116 was SYS_CAP_GRANT — removed 2026-09-03 (boot-only caps, no dynamic
// delegation; see crates/core/abi/src/syscall_nr.rs). Number retired, not reused.
// `cap_grant()`, its only wrapper here, had zero in-repo callers and is
// removed with it.

// Cap<T> typed IPC — RFC-0003 W3+. Numbers come from
// `crates/core/abi/src/syscall_nr.rs` via the `use` above — no longer mirrored
// or independently diffed here.

/// Security profile IDs for seccomp().
pub const PROFILE_UNRESTRICTED: u64 = 0;
pub const PROFILE_SENSOR: u64 = 1;
pub const PROFILE_MOTOR: u64 = 2;
pub const PROFILE_NET: u64 = 3;
pub const PROFILE_MINIMAL: u64 = 4;

/// Activate a syscall filter profile (one-way — cannot be undone).
/// After this call, only syscalls in the profile whitelist are allowed.
pub fn seccomp(profile_id: u64) -> isize {
    unsafe { syscall1(SYS_SECCOMP, profile_id) }
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
/// never mapped anything there (`crates/core/sched/src/process.rs:653-690`
/// documents this as reachable on VF2/K1 with DTB-sized real RAM — the
/// `VDSO_FITS_BELOW_USER_CEILING` gate can be false, or `vdso::vdso_phys()`
/// can be 0), that first read is a load from an unmapped page and the task
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
    // seq u32 + _pad u32). Offset 8 is `seq` itself: reading it returned the
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
/// This does what the Linux vDSO does: read the hardware counter with
/// `rdtime` — a user instruction, `scounteren.TM` enabled — and convert using
/// the frequency the page publishes. The result is exact to the nanosecond for
/// the price of one CSR read and two divisions.
///
/// The division is done in two steps **to avoid overflow**: `ticks *
/// 1_000_000_000` leaves `u64` in about 30 minutes at 10 MHz, and a monotonic
/// clock that wraps after half an hour is worse than no clock at all.
///
/// Returns 0 if the page publishes no frequency — a kernel older than this, or
/// one with no vDSO mapped.
///
/// U07-18: guarded by [`vdso_rdtime_native`], unlike the version of this
/// function the audit read. Before this fix the CSR read below was
/// unconditional, so on a board where `rdtime` is emulated (RFC-0041 §A —
/// the kernel clears the vDSO `flags` native bit exactly there) every call
/// paid an illegal-instruction trap into firmware instead of the `ecall`
/// [`uptime`] would have used, on the one function whose whole purpose is
/// avoiding a trap. [`uptime`] already made this trade correctly; this
/// brings the nanosecond reader in line with it.
pub fn vdso_now_ns() -> u64 {
    let hz = vdso_timebase_hz();
    if hz == 0 { return 0; }
    // riscv64: `rdtime` may trap without Sstc, so honour the vDSO flag and
    // fall back to the ecall. aarch64: `cntvct_el0` is always EL0-readable
    // and the vDSO flag is a riscv64 statement — reading through the flag
    // there sent `uptime_ms`/`sleep` through SYS_UPTIME's units (gate 182c).
    #[cfg(target_arch = "aarch64")]
    let ticks = read_time_csr();
    #[cfg(not(target_arch = "aarch64"))]
    let ticks = if vdso_rdtime_native() { read_time_csr() } else { uptime_ecall() as u64 };
    ticks_to_ns(ticks, hz)
}

/// The free-running hardware counter, read in ring 3: the RISC-V `time` CSR
/// (`scounteren.TM` is set in `trap_init`) or, on aarch64, the AArch64
/// generic timer's virtual counter `cntvct_el0`.
///
/// **The aarch64 branch has no kernel counterpart yet.** `CNTKCTL_EL1.EL0VCTEN`
/// must be set for EL0 to read `cntvct_el0` without trapping — the aarch64
/// analogue of `scounteren.TM` — and no aarch64 vDSO page exists (`crates/core/mm`)
/// to call [`vdso_rdtime_native`] meaningful, so nothing in this crate calls
/// this function on that target today. It exists for phase 6 parity: when the
/// aarch64 vDSO lands, `vdso_now_ns` needs this exactly as it needs the
/// RISC-V branch now.
#[inline(always)]
fn read_time_csr() -> u64 {
    let t: u64;
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)); }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack)); }
    // x86_64 skeleton: the invariant TSC.
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    todo!("x86_64: libsys read_time_csr: rdtsc");
    t
}

/// Does the kernel say `rdtime` is native here (vDSO `flags` bit 0)?
///
/// Where the `time` CSR is emulated by M-mode firmware, `rdtime` is an
/// illegal-instruction trap into OpenSBI, dearer than the `ecall` it would
/// replace (RFC-0041 §A). The kernel sets the bit only where the read is
/// native, and leaves it clear when built to force the trap.
pub fn vdso_rdtime_native() -> bool {
    // `flags` is written once, before any user task runs, and never changes:
    // no seqlock, like the timebase and the magic.
    unsafe { rdtime_is_native(vdso_read_u32(0), vdso_read_u32(12)) }
}


/// The CPU capabilities ring 3 may use (`azos_abi::vdso::HWCAP_*`): the
/// kernel's AT_HWCAP analogue, detected at boot from the ID registers
/// (aarch64) or the device tree (riscv64). 0 when no vDSO page is mapped.
/// Written once before any user task runs: no seqlock.
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
// Wave 6: the per-task vDSO page, notify/wait, and SPSC rings over shm
// ---------------------------------------------------------------------------

use azos_abi::syscall_nr::{
    SYS_NOTIFY_WAIT, SYS_NOTIFY_WAKE, SYS_VDSO_SENSOR_BIND, SYS_VDSO_TASK_MAP,
};
use azos_abi::vdso::{
    VDSO_TASK_MAGIC, VTP_CPU_TIME, VTP_LAST_READY_SITE, VTP_LAST_SAMPLE, VTP_MAGIC,
    VTP_OWNER_TID, VTP_PUBLISHES, VTP_SENSORS, VTP_SENSOR_DATA, VTP_SENSOR_DATA_MAX,
    VTP_SENSOR_MASK, VTP_SENSOR_SLOTS, VTP_SENSOR_STRIDE, VTP_SEQ, VTP_SW_PREEMPTED,
    VTP_SW_VOLUNTARY, VTP_SENSOR_ACQ_NS, VTP_VERSION,
};

/// Where [`vdso_task_map`] mapped this process's per-task page; 0 = not yet.
static VDSO_TASK_VA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Map this task's own vDSO page (`SYS_VDSO_TASK_MAP`, 594) and remember
/// where. Returns the user address, or `-Errno`. Idempotent.
///
/// A forked child does not inherit the mapping (the kernel leaves the
/// shm/MMIO window out of a fork), and the remembered address is the
/// parent's: a child calls this again before reading.
pub fn vdso_task_map() -> isize {
    let r = unsafe { syscall0(SYS_VDSO_TASK_MAP) };
    if r > 0 {
        VDSO_TASK_VA.store(r as usize, core::sync::atomic::Ordering::Release);
    }
    r
}

/// Publish the sensor a `Cap<Sensor>` names into this task's page
/// (`SYS_VDSO_SENSOR_BIND`, 595). `1`: refreshed at every timer interrupt;
/// `0`: bound, but the type has no interrupt-safe source and its slot stays
/// unpublished; `-ENOENT`: [`vdso_task_map`] first; the capability errors.
pub fn vdso_sensor_bind(cap: u32) -> isize {
    unsafe { syscall1(SYS_VDSO_SENSOR_BIND, cap as u64) }
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
    /// `SYS_SENSOR_READ_TS` reports for the same read. 0 when unknown,
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


/// `SYS_NOTIFY_WAIT` (592): sleep while the `u32` at `addr` — inside a shm
/// region this task has mapped — still holds `expected`, for at most
/// `timeout_ns` ([`NOTIFY_FOREVER`] = no limit). `0` woken, `1` timed out,
/// `-EAGAIN` the word had already changed.
pub fn notify_wait(addr: usize, expected: u32, timeout_ns: u64) -> isize {
    unsafe { syscall3(SYS_NOTIFY_WAIT, addr as u64, expected as u64, timeout_ns) }
}

/// `timeout_ns` for "no limit".
pub const NOTIFY_FOREVER: u64 = u64::MAX;

/// `SYS_NOTIFY_WAKE` (593): wake up to `n` waiters on the word at `addr`.
/// Returns how many were woken, or `-Errno`.
pub fn notify_wake(addr: usize, n: u32) -> isize {
    unsafe { syscall2(SYS_NOTIFY_WAKE, addr as u64, n as u64) }
}

pub use azos_abi::syscall_nr::{
    NOTIFY_WAIT_OWNER_DIED, ROBUST_OWNER_DIED, ROBUST_TID_MASK, ROBUST_WAITERS,
};

/// Register the word at `addr` (in a writable shm region this task maps) as a
/// robust lock word of this task: if the task exits or execs while the word's
/// low 30 bits hold its TID, the kernel sets [`ROBUST_OWNER_DIED`] and wakes
/// every waiter with [`NOTIFY_WAIT_OWNER_DIED`]. `0` or `-Errno`.
pub fn notify_robust_add(addr: usize) -> isize {
    use azos_abi::syscall_nr::NOTIFY_ROBUST_ADD;
    unsafe { syscall2(SYS_NOTIFY_ROBUST, addr as u64, NOTIFY_ROBUST_ADD) }
}

/// Drop [`notify_robust_add`]'s registration. `0` or `-ENOENT`.
pub fn notify_robust_del(addr: usize) -> isize {
    use azos_abi::syscall_nr::NOTIFY_ROBUST_DEL;
    unsafe { syscall2(SYS_NOTIFY_ROBUST, addr as u64, NOTIFY_ROBUST_DEL) }
}

/// How [`robust_lock`] got the word.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RobustLock {
    /// Taken; the previous owner released it.
    Acquired,
    /// Taken from an owner that died holding it (glibc's `EOWNERDEAD`): the
    /// data it guards may be half-updated and must be checked.
    OwnerDied,
    /// `timeout_ns` passed on one wait without the word coming free.
    TimedOut,
    /// A wait failed (`-Errno`): the word is not in a mapping, say.
    Error(isize),
}

/// Take the robust lock word at `addr` for this task (`me`, its TID):
/// Linux's robust-mutex protocol on [`notify_wait`]. Uncontended it is one
/// CAS and no kernel entry. Contended it sets [`ROBUST_WAITERS`] and sleeps;
/// once it has slept it takes the word with `WAITERS` set, so the unlock
/// that follows still wakes whoever else is asleep. A word left
/// [`ROBUST_OWNER_DIED`] by the kernel is taken over and reported as
/// [`RobustLock::OwnerDied`]. The caller registers the word
/// ([`notify_robust_add`]) once; registration is what makes its own death
/// visible to the next owner.
pub fn robust_lock(addr: usize, me: u32, timeout_ns: u64) -> RobustLock {
    use core::sync::atomic::{AtomicU32, Ordering};
    // SAFETY: the caller passes a 4-byte-aligned word of a mapping it holds.
    let w = unsafe { &*(addr as *const AtomicU32) };
    let me = me & ROBUST_TID_MASK;
    let mut slept = false;
    loop {
        let v = w.load(Ordering::Acquire);
        if v & ROBUST_TID_MASK == 0 {
            let keep = if slept { ROBUST_WAITERS } else { v & ROBUST_WAITERS };
            if w.compare_exchange(v, me | keep, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return if v & ROBUST_OWNER_DIED != 0 { RobustLock::OwnerDied } else { RobustLock::Acquired };
            }
            continue;
        }
        let want = v | ROBUST_WAITERS;
        if v & ROBUST_WAITERS == 0
            && w.compare_exchange(v, want, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            continue;
        }
        slept = true;
        match notify_wait(addr, want, timeout_ns) {
            1 => return RobustLock::TimedOut,
            r if r < 0 && r != -11 => return RobustLock::Error(r),
            _ => {} // woken (0), owner died (2), or the word moved (-EAGAIN)
        }
    }
}

/// Release the robust lock word at `addr`, waking one sleeper if
/// [`ROBUST_WAITERS`] was set.
pub fn robust_unlock(addr: usize) {
    use core::sync::atomic::{AtomicU32, Ordering};
    // SAFETY: as `robust_lock`.
    let w = unsafe { &*(addr as *const AtomicU32) };
    if w.swap(0, Ordering::AcqRel) & ROBUST_WAITERS != 0 {
        let _ = notify_wake(addr, 1);
    }
}

/// Kernel entries a ring side made, for the caller to report.
#[derive(Clone, Copy, Debug, Default)]
pub struct RingStats {
    /// `SYS_NOTIFY_WAIT` calls (the side found the ring empty/full).
    pub waits: u64,
    /// `SYS_NOTIFY_WAKE` calls (the other side said it may be asleep).
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
        if notify_wait(addr, expected, RING_WAIT_NS) == 1 {
            stats.timeouts += 1;
        }
        woke();
    }
}

/// Append `v`, sleeping while the ring is full. Enters the kernel only to
/// sleep on a full ring or to wake a consumer that said it may be asleep.
pub fn ring_push(r: &SpscRing, v: u64, stats: &mut RingStats) {
    loop {
        match r.try_push(v) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => {
                stats.wakes += 1;
                let _ = notify_wake(addr, 1);
                return;
            }
            RingStep::Blocked => ring_sleep(r.producer_sleep(), || r.producer_woke(), stats),
        }
    }
}

/// Take the oldest item, sleeping while the ring is empty. Enters the kernel
/// only to sleep on an empty ring or to wake a producer that said it may be
/// asleep.
pub fn ring_pop(r: &SpscRing, stats: &mut RingStats) -> u64 {
    loop {
        match r.try_pop() {
            (RingStep::Done, v) => return v,
            (RingStep::DoneWake { addr }, v) => {
                stats.wakes += 1;
                let _ = notify_wake(addr, 1);
                return v;
            }
            (RingStep::Blocked, _) => ring_sleep(r.consumer_sleep(), || r.consumer_woke(), stats),
        }
    }
}

/// [`ring_push`] for a `W`-word slot ring ([`SpscSlots`]).
pub fn slots_push<const W: usize>(r: &SpscSlots<W>, item: &[u64; W], stats: &mut RingStats) {
    loop {
        match r.try_push(item) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => {
                stats.wakes += 1;
                let _ = notify_wake(addr, 1);
                return;
            }
            RingStep::Blocked => ring_sleep(r.producer_sleep(), || r.producer_woke(), stats),
        }
    }
}

/// [`ring_pop`] for a `W`-word slot ring ([`SpscSlots`]).
pub fn slots_pop<const W: usize>(r: &SpscSlots<W>, out: &mut [u64; W], stats: &mut RingStats) {
    loop {
        match r.try_pop(out) {
            RingStep::Done => return,
            RingStep::DoneWake { addr } => {
                stats.wakes += 1;
                let _ = notify_wake(addr, 1);
                return;
            }
            RingStep::Blocked => ring_sleep(r.consumer_sleep(), || r.consumer_woke(), stats),
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
//   * `crates/core/syscall/src/dispatch.rs:13`  — `const E_PERM: i64 = -1`,
//     returned by the seccomp filter and by the capability checks written
//     directly in the dispatch arms (SYS_MMIO_MAP,
//     SYS_IRQ_BIND, SYS_IPC_MAP, port/ring ownership).
// Test only for `rc < 0` unless you have checked which of the two applies to
// the specific syscall number.

/// Capability denied by a handler-side `cap_check`
/// (`crates/core/syscall/src/handlers.rs`).
pub const E_PERM_HANDLER: isize = -99;

/// Denied by the dispatcher: seccomp filter, or a capability check written
/// in the dispatch arm itself (`crates/core/syscall/src/dispatch.rs`).
pub const E_PERM_DISPATCH: isize = -1;

/// The kernel declined to block: a critical section was open on that hart, so
/// `block_current` refused to park the caller (K-C29). **No time passed and
/// the awaited event did not happen** — the correct response is to call
/// again.
///
/// Currently returned by exactly one syscall, [`drv_irq_wait`]. Every other
/// blocking syscall re-tests its own condition after the block and reports
/// "nothing there" (`-1`) instead, which needs no distinct code; `IRQ_WAIT`
/// gets one because nothing in the kernel records that an IRQ fired for a
/// given task, so it cannot re-test and would otherwise have to report a
/// fired interrupt that never fired.
///
/// This is `-(Errno::EAGAIN)` from the frozen table in
/// `crates/core/abi/src/error.rs`, not a libsys-local invention.
pub const E_AGAIN: isize = -11;

/// Invalid argument, produced *by this library* before the ecall is issued.
///
/// The kernel never returns this value on its own. Kernel rejections in this
/// tree are `-1` ([`E_PERM_DISPATCH`]), `-99` ([`E_PERM_HANDLER`]) or, on the
/// one arm named above, `-11` ([`E_AGAIN`]). See [`has_nul`].
pub const E_INVAL: isize = -22;
/// `-EBADF`: a small fd that is not open (RFC-0055 fd table).
pub const E_BADF: isize = -9;
/// `-EINTR`: a wait ended by a stop request or a child's exit (RFC-0055).
pub const E_INTR: isize = -4;
/// `-EPIPE`: a write to a pipe with no reader left (RFC-0055).
pub const E_PIPE: isize = -32;

// ---------------------------------------------------------------------------
// NUL-terminated string safety
// ---------------------------------------------------------------------------

/// Build a `&'static [u8; N+1]` from a byte-string literal, with the NUL
/// terminator appended **at compile time**.
///
/// WHY this exists: every path-taking syscall in this kernel is read with
/// `azos_sched::copy_cstr_from_user` (`crates/core/sched/src/process.rs:509`),
/// which scans forward from the pointer until it finds a zero byte — the
/// slice length this library passes is never seen by the kernel. A caller
/// writing `sys::open(b"/fat/CONFIG.INI", 0)` therefore hands the kernel a
/// pointer into `.rodata` and lets it walk past the literal into whatever the
/// linker placed next. That is exactly the bug that was found in
/// `userspace/services/brain_client` on 2026-08-21.
///
/// `cstr!` removes the possibility instead of documenting it:
///
/// ```ignore
/// let fd = sys::open(sys::cstr!(b"/fat/CONFIG.INI"), 0);
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



// ---------------------------------------------------------------------------
// Raw syscall primitives (unsafe, internal)
// ---------------------------------------------------------------------------

// Each primitive below is ONE function whose trap-issuing `asm!` block is
// `#[cfg(target_arch = ..)]`-selected: a single RISC-V branch (unchanged
// from before aarch64 parity) and a single aarch64 branch, mapping
// `a0..=a5`/`a7` to `x0..=x5`/`x8` register-for-register — see
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
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            lateout("x0") ret,
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys syscall0: the `syscall` instruction");
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
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys syscall1: the `syscall` instruction");
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
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys syscall2: the `syscall` instruction");
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
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys syscall3: the `syscall` instruction");
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
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys syscall4: the `syscall` instruction");
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
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys syscall5: the `syscall` instruction");
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
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys syscall6: the `syscall` instruction");
    }
    ret
}

// ===========================================================================
//  Safe wrappers — grouped by subsystem
// ===========================================================================

// ---------------------------------------------------------------------------
//  Console
// ---------------------------------------------------------------------------

/// Kernel self-test syscall.
pub fn test() -> isize {
    unsafe { syscall0(SYS_TEST) }
}

/// Write a single character to the kernel console.
pub fn putchar(c: u8) {
    unsafe { syscall1(SYS_PUTCHAR, c as u64); }
}

/// Read a single character from the kernel console.
///
/// **NON-BLOCKING.** `sys_getchar` (`handlers.rs::sys_getchar`) tests
/// `uart::can_read()` and returns `-1` immediately when the RX FIFO is
/// empty — it does not wait. Callers wanting blocking behaviour must loop
/// with [`yield_now`]. (This doc said "blocking" until 2026-08-21; nothing
/// in `userspace/` called it, so nobody noticed.)
///
/// Returns the byte as a non-negative value, or `-1` if no byte is ready.
pub fn getchar() -> isize {
    unsafe { syscall0(SYS_GETCHAR) }
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
    unsafe { syscall1(SYS_SLEEP, ms); }
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

/// Block until `deadline_ns` on the clock [`vdso_now_ns`] reads (RFC-0044).
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
    match unsafe { syscall1(SYS_SLEEP_UNTIL, deadline_ns) } {
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

/// Fork the current process. Returns 0 in the child, child PID in the parent,
/// or negative on error.
pub fn fork() -> isize {
    unsafe { syscall0(SYS_FORK) }
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
    unsafe {
        syscall5(SYS_THREAD_CREATE, entry as usize as u64, stack_top as u64, arg, ctid as u64, 0)
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

/// Maximum ELF image accepted by [`exec`]. Mirrors `EXEC_MAX_BYTES` in
/// `crates/core/syscall/src/handlers.rs`'s `EXEC_MAX_BYTES` (128 KiB). A larger image is
/// **rejected**, not truncated.
pub const EXEC_MAX_BYTES: usize = 128 * 1024;

/// Replace the calling process's address space with the ELF image in `elf`.
///
/// ABI (`sys_exec`, `crates/core/syscall/src/handlers.rs::sys_exec`; dispatch arm
/// `crates/core/syscall/src/dispatch.rs:93`):
///   a0 = pointer to the ELF **image bytes**, a1 = image length in bytes.
///
/// The kernel bounces the whole range through `copy_from_user` into
/// `EXEC_BOUNCE`, a static `[u8; EXEC_MAX_BYTES]`, then calls `exec_user`.
/// It therefore requires the *bytes of an ELF file*, readable through the
/// caller's own page table.
///
/// **This wrapper previously declared `exec(entry_addr, stack_addr)` and
/// passed an entry point where the kernel reads a pointer.** Nothing called
/// it, which is why the drift survived. If either side moves again, it must
/// move here and in `sys_exec` together.
///
/// Returns only on failure (`-1`): `elf` empty, longer than
/// [`EXEC_MAX_BYTES`], not readable through the caller's page table, or not
/// a loadable ELF. On success the trap handler enters the new image on
/// `sret` and this call never returns.
pub fn exec(elf: &[u8]) -> isize {
    unsafe { syscall2(SYS_EXEC, elf.as_ptr() as u64, elf.len() as u64) }
}

/// Replace the calling process's address space with the ELF at `path`.
///
/// ABI (`sys_execpath`, `handlers.rs::sys_execpath`): a0 = pointer to a **NUL-
/// terminated** path. The kernel reads it with `copy_cstr_from_user` into a
/// 256-byte buffer; the slice length is not transmitted. Build `path` with
/// [`cstr!`] or include the `\0` yourself.
///
/// The file is read into the same 128 KiB bounce buffer as [`exec`]; a file
/// that reaches the cap is refused rather than truncated.
///
/// Returns `-1` on failure; does not return on success.
pub fn execpath(path: &[u8]) -> isize {
    // Guard, not trust: without a NUL the kernel scans past the caller's
    // slice. See `has_nul`.
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_EXECPATH, path.as_ptr() as u64) }
}

/// Start a new process from the ELF at `path`.
///
/// ABI (`SYS_SPAWN`, RFC-0043): a0 = pointer to a **NUL-terminated** path,
/// read as [`execpath`] reads its path. No arguments reach the child. It runs
/// under the seccomp profile bound to its image and starts with the
/// capabilities of the topology entry named after that image.
///
/// Returns the child's TID, or a negative value: `path` without a NUL
/// ([`E_INVAL`]), a file that cannot be read, or an image with no profile.
pub fn spawn(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_SPAWN, path.as_ptr() as u64) }
}

/// Read the sensor behind a `Cap<Sensor>` into `buf`. Requires `READ`.
///
/// The sensor TYPE comes from the capability, so there is no type
/// argument. Get the handle with
/// [`cap_lookup`]`(CapKind::Sensor as u8, sensor_type)`.
///
/// Returns bytes written, or `-Errno`. The wire format per type is the
/// kernel's sensor record: IMU 24 B, ODOM 16, ENCODER 16, RANGE 4,
/// BATTERY 2, GPS 16, GPIO_FLAGS 2, POWER 12; LIDAR and CAMERA variable.
pub fn sensor_read_typed(cap: u32, buf: &mut [u8]) -> isize {
    unsafe {
        syscall3(
            SYS_SENSOR_READ_TYPED,
            cap as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

/// The stamped read (`SYS_SENSOR_READ_TS`, 606): what [`sensor_read_typed`]
/// reads, behind a `azos_abi::sensor_sample` header that says when the
/// value was ACQUIRED, on the clock [`vdso_now_ns`] reads. Requires `READ`.
///
/// `buf` must hold the header ([`SENSOR_SAMPLE_HDR_LEN`] bytes) and the
/// payload, or the call is refused with nothing written. Returns header +
/// payload bytes, 0 for "no data" (nothing written), or `-Errno` / `-1`.
/// Parse the header with [`SensorSampleHdr::from_bytes`]; the payload starts
/// at its `hdr_len`.
pub fn sensor_read_ts(cap: u32, buf: &mut [u8]) -> isize {
    unsafe {
        syscall3(
            SYS_SENSOR_READ_TS,
            cap as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

pub use azos_abi::sensor_sample::{
    sample_is_fresh_ns, SensorSampleHdr, SENSOR_SAMPLE_FLAG_SYNTHETIC, SENSOR_SAMPLE_HDR_LEN,
};

/// Drive the wheel behind a `Cap<Motor>` at `speed_pct` (0 stops).
///
/// The wheel comes from the capability, so there is no id argument to name
/// one you do not hold. Get the handle with
/// [`cap_lookup`]`(CapKind::Motor as u8, id)`.
///
/// **This is the only typed motor call that actuates.** `SYS_MOTOR_*_TYPED`
/// 550-555 write shared PID state for the kernel's motor task to consume —
/// a different operation. "Stop this wheel now" is this call.
///
/// While an e-stop is latched or containment is armed, `speed_pct == 0` still
/// coasts and any other speed returns `-EAGAIN`.
pub fn motor_speed_typed(cap: u32, speed_pct: u32) -> isize {
    unsafe { syscall2(SYS_MOTOR_SPEED_TYPED, cap as u64, speed_pct as u64) }
}

/// Set the direction of the wheel behind a `Cap<Motor>`, at a kernel-fixed
/// 50% speed.
///
/// ABI (`SYS_MOTOR_DIRECTION_TYPED`, 576): a0 = cap, a1 = one of the
/// `MOTOR_DIR_*` constants (0 forward, 1 backward, 2 brake, 3 coast). The
/// capability needs `WRITE` and names the wheel, so there is no id argument
/// to name one the task does not hold. Get the handle with
/// [`cap_lookup`]`(CapKind::Motor as u8, id)`.
///
/// In order: a refused capability answers `-ECAPSTALE`, `-ECAPKIND` or
/// `-ECAPPERMS` and writes one `SAFETY_CAP_DENIED_TYPED` record; a direction
/// of 4 or more answers `-EINVAL` and writes no pin; once admitted, 0, or
/// `-EAGAIN` for FORWARD or BACKWARD while an e-stop is latched or
/// containment is armed (BRAKE and COAST are still carried out), or the
/// motor layer's negative code.
///
/// Not [`motor_enable_typed`] (552), which arms the PID loop. The 50% cannot
/// be chosen from here, and a following [`motor_speed_typed`] drives forward
/// again: no single call carries a (direction, speed) pair — see
/// [`motor_move_typed`] (584), which does.
pub fn motor_direction_typed(cap: u32, dir: u64) -> isize {
    unsafe { syscall2(SYS_MOTOR_DIRECTION_TYPED, cap as u64, dir) }
}

/// Drive the wheel behind a `Cap<Motor>` at `(direction, speed_pct)` in one
/// call — U11-12: `SYS_MOTOR_SPEED_TYPED` (560) always drives `Forward`,
/// `SYS_MOTOR_DIRECTION_TYPED` (576) always drives at a kernel-fixed 50 %,
/// and neither can express "back up at 30 %". `userspace/services/reflex`'s
/// obstacle-avoidance backup and `userspace/services/brain_client`'s reverse path
/// both went through 576 and both discarded the magnitude they were
/// actually asked for. This is the call that carries both.
///
/// ABI (`SYS_MOTOR_MOVE_TYPED`, 584): a0 = cap, a1 = one of the
/// `MOTOR_DIR_*` constants (0 forward, 1 backward, 2 brake, 3 coast),
/// a2 = speed_pct (0..=100). The capability needs `WRITE` and names the
/// wheel, exactly as [`motor_direction_typed`] and [`motor_speed_typed`]
/// resolve it.
///
/// In order: a refused capability answers `-ECAPSTALE`, `-ECAPKIND` or
/// `-ECAPPERMS` and writes one `SAFETY_CAP_DENIED_TYPED` record; a direction
/// of 4 or more, or a `speed_pct` over 100, answers `-EINVAL` and writes no
/// pin; once admitted, 0, `-EAGAIN` for FORWARD or BACKWARD while an e-stop
/// is latched or containment is armed (BRAKE and COAST are still carried
/// out), or the motor layer's negative code. Handler:
/// `crates/core/syscall/src/motor_cmd.rs::sys_motor_move_typed`.
pub fn motor_move_typed(cap: u32, dir: u64, speed_pct: u32) -> isize {
    unsafe { syscall3(SYS_MOTOR_MOVE_TYPED, cap as u64, dir, speed_pct as u64) }
}

/// Read the accumulated encoder ticks of the wheel behind a `Cap<Motor>`
/// into `ticks`.
///
/// ABI (`SYS_MOTOR_ANGLE_TYPED`, 578): a0 = cap, a1 = pointer to 8 bytes the
/// kernel writes as `i64` little-endian. The capability needs `READ`, and a
/// read stays live while containment is armed.
///
/// Returns 0, or `-Errno`, in order: `-ECAPSTALE` / `-ECAPKIND` /
/// `-ECAPPERMS` for the capability (one `SAFETY_CAP_DENIED_TYPED` record),
/// `-EINVAL` for a wheel with no encoder (only 0 and 1 have one), `-EFAULT`
/// for an unwritable pointer. Ticks, not degrees. The count travels through
/// `ticks`, so no reading can be mistaken for a refusal.
pub fn motor_angle_typed(cap: u32, ticks: &mut i64) -> isize {
    unsafe { syscall2(SYS_MOTOR_ANGLE_TYPED, cap as u64, ticks as *mut i64 as u64) }
}

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
    unsafe { syscall0(SYS_WAIT) }
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
    unsafe { syscall2(SYS_WAITPID, child_tid as u64, status as u64) }
}

/// Read one exit-path counter (`SYS_EXIT_STATS`, 605): `which` is a
/// `azos_abi::syscall_nr::EXIT_STAT_*` selector. Returns the count, a
/// total since boot over every task, or `-EINVAL` (-22) for an unknown
/// selector.
pub fn exit_stats(which: u64) -> isize {
    unsafe { syscall1(SYS_EXIT_STATS, which) }
}

/// The caller's child-subreaper mark (`SYS_TASK_SUBREAPER`, 619): `op` is
/// `azos_abi::syscall_nr::SUBREAPER_{GET,SET,CLEAR}`. Returns the mark
/// afterwards (0 or 1), or `-EINVAL` (-22) for another `op`. A marked task
/// adopts its orphaned descendants (their `waitpid` and `/proc` parent).
pub fn task_subreaper(op: u64) -> isize {
    unsafe { syscall1(SYS_TASK_SUBREAPER, op) }
}

pub use azos_abi::syscall_nr::{SUBREAPER_CLEAR, SUBREAPER_GET, SUBREAPER_SET};

/// The [`exit_stats`] selectors.
pub use azos_abi::syscall_nr::{
    EXIT_STAT_EARLY_NOTICES, EXIT_STAT_EXIT_TEARDOWNS, EXIT_STAT_LEASE_REVOKED_FAULTS,
    EXIT_STAT_LEASE_SEAL_FAULTS, EXIT_STAT_NOTICE_DROPS, EXIT_STAT_NOTICE_REFUSALS,
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
/// `SYS_WAIT` takes no arguments today, and `syscall0` does not set `a0` — so
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
    unsafe { syscall1(SYS_WAIT_STATUS, status as u64) }
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

/// Largest single transfer honoured by [`read`] / [`write`]. The kernel
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

/// Open a file. POSIX name over [`file_open_typed`] (`SYS_FILE_OPEN_TYPED`).
///
/// **Returns a `Cap<File>` handle, not a descriptor index** (POSIX
/// subset). Hand it to [`read`], [`write`] and [`close`]. The
/// number is not small and is not the descriptor: the descriptor behind it is
/// found, when a call with no typed form needs it, with
/// `cap_lookup(CapKind::File, fd)`.
///
/// The kernel reads the path with `copy_cstr_from_user` into a 256-byte
/// buffer: it scans for a zero byte and **never sees `path.len()`**. This
/// wrapper rejects a slice with no NUL ([`E_INVAL`]) before the call. Prefer
/// [`cstr!`], which appends the terminator at compile time:
///
/// ```ignore
/// let f = sys::open(sys::cstr!(b"/fat/CONFIG.INI"), 0);
/// ```
///
/// `flags & 3` is the access mode and sets the capability's permissions
/// (`O_RDONLY` 0 → `READ`, `O_WRONLY` 1 → `WRITE`, `O_RDWR` 2 → both); mode
/// 3 is `-EINVAL`. Returns the handle (`>= 0`), `-1` if the open fails, or
/// `-EMFILE` when the capability table is full.
pub fn open(path: &[u8], flags: u64) -> isize {
    file_open_typed(path, flags)
}

/// Close what a handle names: a file from [`open`], a socket from
/// [`socket_typed`] — one call for both (`SYS_CLOSE_TYPED`).
///
/// **Why one integer can no longer close the wrong object.** File descriptors
/// and socket indices overlap (both count from small numbers), and the
/// untyped `SYS_CLOSE` reaches the descriptor table only. A program that
/// closed its socket 3 while it had file 3 open closed the file. A handle
/// carries its kind in its top bits (`azos_abi::cap::CapHandle`), and the
/// kernel releases the object that kind names.
///
/// Returns 0, `-ECAPSTALE` for a handle already closed (or never minted), or
/// `-ECAPKIND` for a kind with no close. [`E_INVAL`] for a value wider than a
/// handle, without the call.
pub fn close(fd: u64) -> isize {
    // RFC-0055: a small fd is a table entry; only the last fd naming a
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

/// Read from the file a handle names into `buf` (`SYS_FILE_READ_TYPED`).
/// Needs `READ`.
///
/// The kernel clamps the count to [`IO_MAX_BYTES`], so a buffer larger than
/// 4 KiB is filled at most 4 KiB per call. There is no stdin descriptor:
/// console input is [`getchar`].
///
/// Returns bytes read (may be less than `buf.len()`, 0 at end of file), or
/// negative on error. [`E_INVAL`] for a value wider than a handle, without
/// the call.
pub fn read(fd: u64, buf: &mut [u8]) -> isize {
    // RFC-0055: fds 0..=7 are the process's fd table (a startup block's, or
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
/// fd 1 and 2 are the console ([`console_write`], `SYS_WRITE`): the kernel's
/// descriptor table does not pre-open stdio for user processes, and a
/// capability handle is never 1 or 2 (its kind bits are set). Any other value
/// is a `Cap<File>` handle (`SYS_FILE_WRITE_TYPED`), which needs `WRITE` and is
/// refused with `-EAGAIN` while degraded mode is contained; the console stays
/// live, since it is where a contained program still reports.
///
/// The kernel clamps the count to [`IO_MAX_BYTES`]. Returns bytes written, or
/// negative on error.
pub fn write(fd: u64, buf: &[u8]) -> isize {
    // RFC-0055: fds 0..=7 are the process's fd table. Without a startup block
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

/// Write `buf` to the console: [`STDOUT`] or [`STDERR`], through `SYS_WRITE`.
///
/// The console half of [`write`], for callers that never write a file —
/// [`print`] among them — so a binary that only logs names `SYS_WRITE` and not
/// the file write it has no use for. Any other `stream` is [`E_INVAL`],
/// without the call: `SYS_WRITE` on a descriptor is the untyped file path.
///
/// Returns the clamped count ([`IO_MAX_BYTES`]) the kernel was handed, not the
/// bytes the UART emitted after LF-to-CRLF translation.
pub fn console_write(stream: u64, buf: &[u8]) -> isize {
    if stream != STDOUT && stream != STDERR {
        return E_INVAL;
    }
    unsafe { syscall3(SYS_WRITE, stream, buf.as_ptr() as u64, buf.len() as u64) }
}

/// Open a file and receive a `Cap<File>` for it rather than a descriptor.
///
/// The capability carries `READ` for `O_RDONLY` (0), `WRITE` for `O_WRONLY`
/// (1) and both for `O_RDWR` (2); any other access mode is `-EINVAL`. Use it
/// with [`file_read_typed`], [`file_write_typed`] and [`close_typed`]. While
/// the capability is live the kernel refuses the untyped `SYS_CLOSE` and
/// `SYS_DUP2` on the descriptor behind it, so the handle keeps naming this
/// file.
///
/// Returns the raw handle (`>= 0`), `-1` if the open fails, or `-EMFILE` when
/// the capability table is full.
pub fn file_open_typed(path: &[u8], flags: u64) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall2(SYS_FILE_OPEN_TYPED, path.as_ptr() as u64, flags) }
}

/// Read through a `Cap<File>`. Needs `READ`. Same 4 KiB clamp as [`read`].
pub fn file_read_typed(cap: u32, buf: &mut [u8]) -> isize {
    unsafe { syscall3(SYS_FILE_READ_TYPED, cap as u64, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Write through a `Cap<File>`. Needs `WRITE`; refused with `-EAGAIN` while
/// degraded mode is armed. Same 4 KiB clamp as [`write`].
pub fn file_write_typed(cap: u32, buf: &[u8]) -> isize {
    unsafe { syscall3(SYS_FILE_WRITE_TYPED, cap as u64, buf.as_ptr() as u64, buf.len() as u64) }
}

/// Revoke a capability and release what it names. Handles `Cap<File>` and
/// `Cap<Socket>`; any other kind is `-ECAPKIND`. A second close of the same handle is
/// `-ECAPSTALE`.
pub fn close_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_CLOSE_TYPED, cap as u64) }
}

// `lseek` was here. `SYS_LSEEK` (24) is retired: it took a DESCRIPTOR, and
// since `open` returns a `Cap<File>` there was no longer a way to name one.
// No profile granted it and no binary called it, so removing the wrapper
// costs nothing today. Seek returns as `SYS_FILE_SEEK_TYPED` when a caller
// needs it.

// ---------------------------------------------------------------------------
//  Filesystem
// ---------------------------------------------------------------------------

/// Stat a file: size, type and metadata of `path` (NUL-terminated), written
/// to `buf` in the layout `azos_abi::syscall_nr::STAT_BYTES` documents
/// (RFC-0048 P2). `0`, `-ENOENT` for no such file, `-EFAULT` for a bad
/// pointer. `buf` shorter than `STAT_BYTES` is refused here with `E_INVAL`,
/// since the kernel always writes the whole record.
pub fn stat(path: &[u8], buf: &mut [u8]) -> isize {
    if !has_nul(path) || buf.len() < azos_abi::syscall_nr::STAT_BYTES {
        return E_INVAL;
    }
    unsafe { syscall2(SYS_STAT, path.as_ptr() as u64, buf.as_mut_ptr() as u64) }
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
    unsafe {
        syscall6(
            SYS_READDIR,
            dir_path.as_ptr() as u64,
            index,
            name_out.as_mut_ptr() as u64,
            size_out as *mut u32 as u64,
            is_dir_out as *mut u32 as u64,
            // The length the kernel now checks. The array type above is what
            // makes this true rather than hopeful.
            READDIR_NAME_BYTES as u64,
        )
    }
}

/// Create a directory at `path` (**NUL-terminated** — see [`open`]).
pub fn mkdir(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_MKDIR, path.as_ptr() as u64) }
}

/// Remove a file or directory at `path` (**NUL-terminated** — see [`open`]).
pub fn unlink(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_UNLINK, path.as_ptr() as u64) }
}

/// Remove the empty directory at `path` (**NUL-terminated**). `0`,
/// `-ENOTEMPTY`, `-ENOTDIR`, `-ENOENT`, or `-ENOSYS` where the filesystem has
/// no rmdir (owner round 23).
pub fn rmdir(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_RMDIR, path.as_ptr() as u64) }
}

/// Rename `from` to `to` (both **NUL-terminated**) within one mounted
/// filesystem; across two, `-EINVAL`.
pub fn rename(from: &[u8], to: &[u8]) -> isize {
    if !has_nul(from) || !has_nul(to) {
        return E_INVAL;
    }
    unsafe { syscall2(SYS_RENAME, from.as_ptr() as u64, to.as_ptr() as u64) }
}

/// Set the size of the file at `path` (**NUL-terminated**) to `len` bytes.
pub fn truncate(path: &[u8], len: u64) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall2(SYS_TRUNCATE, path.as_ptr() as u64, len) }
}

/// Make the writes through a `Cap<File>` durable (any permission).
/// `-ECAPSTALE`/`-ECAPKIND` for a bad handle.
pub fn fsync_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_FSYNC_TYPED, cap as u64) }
}

/// Capacity and free space of the filesystem `path` (**NUL-terminated**) is
/// on, written to `buf` in the layout `azos_abi::syscall_nr::STATFS_BYTES`
/// documents. The kernel is told `buf.len()` and refuses a short one.
pub fn statfs(path: &[u8], buf: &mut [u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall3(SYS_STATFS, path.as_ptr() as u64, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Change current working directory to `path` (**NUL-terminated**).
///
/// **No kernel dispatch arm exists.** `SYS_CHDIR` (254) is declared in
/// `crates/core/syscall/src/numbers.rs:83` and has a wrapper here, but
/// `syscall_dispatch` has no `SYS_CHDIR` arm — it falls through to
/// `_ => -1`. Always returns `-1`.
pub fn chdir(path: &[u8]) -> isize {
    if !has_nul(path) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_CHDIR, path.as_ptr() as u64) }
}

/// Get current working directory into `buf`.
///
/// **No kernel dispatch arm exists** — `SYS_GETCWD` (255) falls through to
/// `_ => -1` in `syscall_dispatch`, exactly like [`chdir`]. `buf` is never
/// written. Always returns `-1`.
pub fn getcwd(buf: &mut [u8]) -> isize {
    unsafe { syscall2(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Mount a filesystem (all three arguments **NUL-terminated**).
///
/// **Unimplemented in the kernel.** `sys_mount` (`handlers.rs::sys_mount`) ignores
/// all three arguments and returns `-1`.
pub fn mount(source: &[u8], target: &[u8], fstype: &[u8]) -> isize {
    if !has_nul(source) || !has_nul(target) || !has_nul(fstype) {
        return E_INVAL;
    }
    unsafe { syscall3(SYS_MOUNT, source.as_ptr() as u64, target.as_ptr() as u64, fstype.as_ptr() as u64) }
}

/// Unmount the filesystem at `target` (**NUL-terminated**).
///
/// **Unimplemented in the kernel.** `sys_umount` (`handlers.rs::sys_umount`) returns
/// `-1` unconditionally.
pub fn umount(target: &[u8]) -> isize {
    if !has_nul(target) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_UMOUNT, target.as_ptr() as u64) }
}

/// Flush all filesystem caches to disk.
pub fn sync() -> isize {
    unsafe { syscall0(SYS_SYNC) }
}

// ---------------------------------------------------------------------------
//  GPIO
// ---------------------------------------------------------------------------

/// GPIO direction: input. See [`gpio_set_dir_typed`].
pub const GPIO_DIR_INPUT: u64 = 0;
/// GPIO direction: output. See [`gpio_set_dir_typed`].
pub const GPIO_DIR_OUTPUT: u64 = 1;

/// Print GPIO subsystem info to the kernel console. Always returns 0 —
/// `sys_gpio_info` (`handlers.rs::sys_gpio_info`) is `gpio_info(); 0`; nothing is
/// returned to the caller.
pub fn gpio_info() -> isize {
    unsafe { syscall0(SYS_GPIO_INFO) }
}

// ---------------------------------------------------------------------------
//  PWM
// ---------------------------------------------------------------------------

/// Print PWM subsystem info to the kernel console. Always returns 0.
pub fn pwm_info() -> isize {
    unsafe { syscall0(SYS_PWM_INFO) }
}

// ---------------------------------------------------------------------------
//  I2C
// ---------------------------------------------------------------------------

// `I2C_MAX_XFER` used to live here: a dead constant (no caller anywhere in
// the tree — `grep -rn I2C_MAX_XFER` outside this file returns nothing) whose
// doc was also wrong twice over: it named a syscall (`sys_i2c_scan`) that
// takes no length argument at all, and it claimed "silently clamped" for a
// request that the actual bound (`I2C_TYPED_MAX_BYTES`, below,
// `crates/core/syscall/src/handlers.rs::sys_i2c_read_typed`/`::sys_i2c_write_typed`)
// **rejects** with `EINVAL`, not clamps — the correct doc already sits on
// `I2C_TYPED_MAX_BYTES` itself. Removed rather than fixed in place: keeping
// two same-valued constants for one concept is how the stale one gets read
// by the next caller who does not check which is current.

/// Probe an I2C bus and print what answers.
///
/// `sys_i2c_scan` (`handlers.rs::sys_i2c_scan`) is `i2c_scan(bus); 0` — the device
/// count goes to the kernel console, **not** to the caller. Returns 0 on
/// success, or [`E_PERM_HANDLER`] without an `I2c(bus, 0)` capability.
pub fn i2c_scan(bus: u64) -> isize {
    unsafe { syscall1(SYS_I2C_SCAN, bus) }
}

/// Print I2C subsystem info to the kernel console. Always returns 0.
pub fn i2c_info() -> isize {
    unsafe { syscall0(SYS_I2C_INFO) }
}

// ---------------------------------------------------------------------------
//  Motor
// ---------------------------------------------------------------------------

/// Initialise motor `id` with its PWM channel and two direction pins.
///
/// ABI (`sys_motor_create`, `handlers.rs::sys_motor_create`): a0 = **motor id**,
/// a1 = pwm channel, a2 = direction pin A, a3 = direction pin B. It calls
/// `motor_init(id, pwm_ch, dir_a, dir_b)`.
///
/// The previous wrapper was `(pwm_ch, dir_gpio, enc_gpio, motor_type)` —
/// shifted by one and with no `id` at all, so a1..a3 all landed on the wrong
/// parameter. There is no encoder pin and no motor type in this ABI.
/// Requires a write-capable `Motor(id)` capability, else [`E_PERM_HANDLER`].
pub fn motor_create(id: u64, pwm_ch: u64, dir_pin_a: u64, dir_pin_b: u64) -> isize {
    unsafe { syscall4(SYS_MOTOR_CREATE, id, pwm_ch, dir_pin_a, dir_pin_b) }
}

/// Motor direction for [`motor_direction_typed`]: forward.
pub const MOTOR_DIR_FORWARD: u64 = 0;
/// Motor direction for [`motor_direction_typed`]: backward.
pub const MOTOR_DIR_BACKWARD: u64 = 1;
/// Motor direction for [`motor_direction_typed`]: brake (both pins high).
pub const MOTOR_DIR_BRAKE: u64 = 2;
/// Motor direction for [`motor_direction_typed`]: coast (both pins low).
pub const MOTOR_DIR_COAST: u64 = 3;

/// Print motor subsystem info to the kernel console. Always returns 0.
pub fn motor_info() -> isize {
    unsafe { syscall0(SYS_MOTOR_INFO) }
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
    unsafe { syscall0(SYS_MEMINFO) }
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
    unsafe { syscall2(SYS_TASKINFO, out.as_mut_ptr() as u64, out.len() as u64) }
}

/// The RISC-V `time` counter — **ticks, not milliseconds**.
///
/// Reads the counter with `rdtime`, no trap, when the vDSO page says the read
/// is native ([`vdso_rdtime_native`]); otherwise issues `SYS_UPTIME`, whose
/// handler returns the same counter (`timebase::now()`). Both paths give the
/// same quantity, so a caller cannot tell them apart except by cost. At the
/// frequency [`vdso_timebase_hz`] publishes (10 MHz on QEMU virt),
/// milliseconds are `uptime() / (hz / 1000)`; nanoseconds are
/// [`vdso_now_ns`].
///
/// A binary calling this still names `SYS_UPTIME`, so its seccomp row keeps
/// it: on a machine where the flag is clear the call does trap.
pub fn uptime() -> isize {
    if vdso_rdtime_native() {
        read_time_csr() as isize
    } else {
        uptime_ecall()
    }
}

/// `SYS_UPTIME`, always as a trap. The counter [`uptime`] reads, for a caller
/// that is measuring or checking the trap itself.
pub fn uptime_ecall() -> isize {
    unsafe { syscall0(SYS_UPTIME) }
}

// ---------------------------------------------------------------------------
//  System control
// ---------------------------------------------------------------------------

/// Shut down the system.
pub fn shutdown() -> ! {
    unsafe { syscall0(SYS_SHUTDOWN); }
    loop {}
}

/// Reboot the system.
pub fn reboot() -> ! {
    unsafe { syscall0(SYS_REBOOT); }
    loop {}
}

// ---------------------------------------------------------------------------
//  Disk (raw block device)
// ---------------------------------------------------------------------------

/// Print disk info to the kernel console. Always returns 0 — the sector
/// count goes to the console, not the caller. Use [`disk_size`].
pub fn disk_info() -> isize {
    unsafe { syscall0(SYS_DISK_INFO) }
}

/// Bytes per sector, as the disk syscalls assume (`handlers.rs::sys_disk_read`/`::sys_disk_write`, `DISK_BOUNCE_BYTES`).
pub const DISK_SECTOR_BYTES: usize = 512;
/// Maximum sectors per [`disk_read`] / [`disk_write`] call
/// (`handlers.rs::DISK_MAX_SECTORS`). A larger request is rejected
/// with `-1`, not clamped.
pub const DISK_MAX_SECTORS: usize = 128;

/// The partition selector that means "my only disk capability" (`a3` of
/// the read/write calls, `a0` of [`disk_size`]): `CAP_NULL`, which no
/// capability handle can be. A caller holding capabilities for two or more
/// partitions is refused with it (`E_PERM`, "ambiguous") and names one with
/// the `_on` variants instead.
pub const DISK_SEL_ONLY: u32 = azos_abi::syscall_nr::DISK_SEL_ONLY as u32;

/// Read whole sectors starting at `sector` into `buf`, through the caller's
/// only disk capability ([`DISK_SEL_ONLY`]); [`disk_read_on`] names one.
///
/// ABI (`sys_disk_read`, `handlers.rs::sys_disk_read`; dispatch `dispatch.rs`):
///   a0 = start sector, a1 = **sector count**, a2 = destination buffer,
///   a3 = partition selector (a `Cap<Disk>` handle, or 0).
///
/// **Which sector.** For a caller holding the whole-disk `Cap<Disk>` it is an
/// absolute LBA. For a caller holding a partition-scoped one (topology
/// `disk.part.<n>`) it is RELATIVE to that partition: 0 is the partition's
/// first sector, and the kernel adds the start. A run past the partition's
/// end is refused with `E_PERM` and recorded.
///
/// **The previous wrapper passed `(sector, buf_ptr, buf_len)`** — the buffer
/// pointer landed in the kernel's `count` and the length in its `buf`. The
/// kernel then copies `count * 512` bytes to whatever address `buf.len()`
/// happened to be. Nothing called it.
///
/// The kernel is never told how large `buf` is, so the sector count is
/// derived here from `buf.len()` rather than taken as a parameter: a
/// caller-supplied count is a ring-3 buffer overflow behind an honest-looking
/// signature. `buf` must be a whole number of sectors, at least one and at
/// most [`DISK_MAX_SECTORS`]; anything else returns [`E_INVAL`] without
/// issuing the ecall. Any trailing partial sector is refused rather than
/// ignored — a short read is a data bug, not a rounding question.
///
/// Returns 0 on success (**not** a byte count), negative on error.
pub fn disk_read(sector: u64, buf: &mut [u8]) -> isize {
    disk_read_on(DISK_SEL_ONLY, sector, buf)
}

/// [`disk_read`] through the `Cap<Disk>` `disk` names (a handle from
/// [`cap_lookup`]`(CapKind::Disk, n + 1)` for partition `n`). A handle that
/// is stale, of another kind or without READ is refused with
/// `-ECAPSTALE`/`-ECAPKIND`/`-ECAPPERMS`.
pub fn disk_read_on(disk: u32, sector: u64, buf: &mut [u8]) -> isize {
    let count = buf.len() / DISK_SECTOR_BYTES;
    if count == 0 || count > DISK_MAX_SECTORS || buf.len() % DISK_SECTOR_BYTES != 0 {
        return E_INVAL;
    }
    unsafe { syscall4(SYS_DISK_READ, sector, count as u64, buf.as_mut_ptr() as u64, disk as u64) }
}

/// Write whole sectors from `buf` starting at `sector`.
///
/// ABI (`sys_disk_write`, `handlers.rs::sys_disk_write`): a0 = start sector,
/// a1 = **sector count**, a2 = source buffer — same argument order the old
/// wrapper got wrong for [`disk_read`], and with the same derived-count rule
/// applied here, and a3 = partition selector as for [`disk_read`]. The
/// sector is absolute or partition-relative exactly as for [`disk_read`].
/// Returns 0 on success, negative on error.
pub fn disk_write(sector: u64, buf: &[u8]) -> isize {
    disk_write_on(DISK_SEL_ONLY, sector, buf)
}

/// [`disk_write`] through the `Cap<Disk>` `disk` names, as [`disk_read_on`]
/// (it needs WRITE).
pub fn disk_write_on(disk: u32, sector: u64, buf: &[u8]) -> isize {
    let count = buf.len() / DISK_SECTOR_BYTES;
    if count == 0 || count > DISK_MAX_SECTORS || buf.len() % DISK_SECTOR_BYTES != 0 {
        return E_INVAL;
    }
    unsafe { syscall4(SYS_DISK_WRITE, sector, count as u64, buf.as_ptr() as u64, disk as u64) }
}

/// Size in 512-byte sectors of what the caller's only disk capability names
/// ([`DISK_SEL_ONLY`]): the whole medium for a whole-disk holder, the
/// partition for a partition holder. `E_PERM` without a disk capability.
pub fn disk_size() -> isize {
    disk_size_on(DISK_SEL_ONLY)
}

/// [`disk_size`] of the `Cap<Disk>` `disk` names (needs READ).
pub fn disk_size_on(disk: u32) -> isize {
    unsafe { syscall1(SYS_DISK_SIZE, disk as u64) }
}

// ---------------------------------------------------------------------------
//  Network (stack-level)
// ---------------------------------------------------------------------------

/// Print network interface info to the kernel console. Always returns 0 —
/// nothing is reported to the caller (`sys_net_info`, `handlers.rs::sys_net_info`).
pub fn net_info() -> isize {
    unsafe { syscall0(SYS_NET_INFO) }
}

/// Current IPv4 address, as `u32::from_be_bytes(addr)` — i.e. the first
/// octet in the **most significant** byte (`handlers.rs::sys_net_getip`). Feed it
/// straight back to [`net_ping`] / [`net_setip`], which decode with
/// `to_be_bytes`.
pub fn net_getip() -> isize {
    unsafe { syscall0(SYS_NET_GETIP) }
}

/// Set IP address, netmask and gateway.
///
/// Each `u32` is decoded with `to_be_bytes` (`handlers.rs::sys_net_setip`): the first
/// octet is the most significant byte, matching [`net_getip`]. Always
/// returns 0.
pub fn net_setip(ip: u32, mask: u32, gateway: u32) -> isize {
    unsafe { syscall3(SYS_NET_SETIP, ip as u64, mask as u64, gateway as u64) }
}

/// Ping an IPv4 address (encoded as for [`net_setip`]).
pub fn net_ping(ip: u32) -> isize {
    unsafe { syscall1(SYS_NET_PING, ip as u64) }
}

/// MAC address packed into a `u64`, **least-significant byte first**:
/// `sys_net_getmac` (`handlers.rs::sys_net_getmac`) builds it as
/// `val |= mac[i] << (i * 8)`, so `mac[0]` is bits 0..7 — the reverse of the
/// big-endian convention [`net_getip`] uses. Unpack with `to_le_bytes()`
/// and take the low 6 bytes.
pub fn net_getmac() -> isize {
    unsafe { syscall0(SYS_NET_GETMAC) }
}

/// Print network statistics to the kernel console. Always returns 0;
/// `sys_net_stats` (`handlers.rs::sys_net_stats`) is the same `net_info()` call as
/// [`net_info`] and returns no counters to the caller.
pub fn net_stats() -> isize {
    unsafe { syscall0(SYS_NET_STATS) }
}

// ---------------------------------------------------------------------------
//  Sockets
// ---------------------------------------------------------------------------

/// Create a socket. `domain`, `sock_type`, `protocol` follow POSIX convention.
///
/// **Returns a socket INDEX, not a handle**, unlike [`open`]: [`bind`],
/// [`listen`], [`accept`], [`sendto`], [`recvfrom`] and [`sock_shutdown`] take
/// the index and have no typed form. Release it with [`sock_shutdown`];
/// [`close`] takes a handle and refuses an index as stale. For a socket that
/// closes with [`close`], use [`socket_typed`].
///
/// Returns the socket index or negative on error.
pub fn socket(domain: u64, sock_type: u64, protocol: u64) -> isize {
    unsafe { syscall3(SYS_SOCKET, domain, sock_type, protocol) }
}

/// Size of the `sockaddr_in` the kernel reads. `read_sockaddr`
/// (`handlers.rs::read_sockaddr`) copies **exactly 16 bytes** and never looks at the
/// `addrlen` argument, so a shorter object is read past its end. Build the
/// address with [`sockaddr_in`].
pub const SOCKADDR_LEN: usize = 16;

/// Bind a socket to a local address.
///
/// ABI (`sys_bind`, `handlers.rs::sys_bind`): a0 = fd, a1 = sockaddr pointer,
/// a2 = addrlen — **ignored** (`_addrlen`). `addr` is typed `&[u8; 16]`
/// because 16 is the only length the kernel will read; see [`sockaddr_in`].
pub fn bind(fd: u64, addr: &[u8; SOCKADDR_LEN]) -> isize {
    unsafe { syscall3(SYS_BIND, fd, addr.as_ptr() as u64, SOCKADDR_LEN as u64) }
}

/// Listen on a bound socket.
///
/// ABI (`sys_listen_syscall`, `handlers.rs::sys_listen_syscall`): `backlog` is accepted and
/// **ignored** (`_backlog`); the handler calls `socket_listen_bound(fd)`.
pub fn listen(fd: u64, backlog: u64) -> isize {
    unsafe { syscall2(SYS_LISTEN, fd, backlog) }
}

/// Accept a connection on a listening socket.
///
/// ABI (`sys_accept`, `handlers.rs::sys_accept`): a1/a2 are `_addr_out` /
/// `_addrlen_out` and are **ignored** — the peer address is never reported,
/// so this wrapper does not offer the arguments. The handler polls the net
/// stack, sleeping 1 ms between attempts, and gives up after 10 s
/// (`ACCEPT_WAIT_MS`).
///
/// Returns the new socket fd, or `-1` on timeout/error.
pub fn accept(fd: u64) -> isize {
    unsafe { syscall3(SYS_ACCEPT, fd, 0, 0) }
}

/// Connect a socket to a remote address.
///
/// ABI (`sys_connect_syscall`, `handlers.rs::sys_connect_syscall`): a0 = fd,
/// a1 = sockaddr pointer, a2 = addrlen (**ignored**). The handler blocks
/// yielding until the TCP handshake completes, so success means connected.
/// Local port is chosen by the kernel as `0xC000 + fd`. Refused with
/// `-EAGAIN` while degraded mode is contained, like [`connect_typed`].
pub fn connect(fd: u64, addr: &[u8; SOCKADDR_LEN]) -> isize {
    unsafe { syscall3(SYS_CONNECT, fd, addr.as_ptr() as u64, SOCKADDR_LEN as u64) }
}

/// Largest payload a single [`send`] transmits; longer buffers are clamped,
/// not rejected (`handlers.rs::sys_send_syscall`).
pub const SOCK_SEND_MAX: usize = 1460;
/// Largest payload a single [`recv`] returns (`handlers.rs::sys_recv_syscall`).
pub const SOCK_RECV_MAX: usize = 4096;

/// Send data on a connected socket. `flags` is accepted and **ignored** by
/// the kernel (`_flags`). Returns bytes sent (clamped to [`SOCK_SEND_MAX`]).
/// Refused with `-EAGAIN` while degraded mode is contained, like
/// [`send_typed`]; [`recv`] stays live.
pub fn send(fd: u64, buf: &[u8], flags: u64) -> isize {
    unsafe { syscall4(SYS_SEND, fd, buf.as_ptr() as u64, buf.len() as u64, flags) }
}

/// Receive from a connected socket. **Non-blocking**: `sys_recv_syscall`
/// polls the net stack once and returns 0 if nothing has arrived. `flags` is
/// ignored. Returns bytes read (clamped to [`SOCK_RECV_MAX`]).
pub fn recv(fd: u64, buf: &mut [u8], flags: u64) -> isize {
    unsafe { syscall4(SYS_RECV, fd, buf.as_mut_ptr() as u64, buf.len() as u64, flags) }
}

/// Send to an explicit destination address. **Unconnected UDP.**
///
/// **The previous doc said this ABI carried no address**, and it was right:
/// `SYS_SENDTO` dispatched to the same `sys_send_syscall` as `SYS_SEND` and
/// lost it. Completed on 2026-08-30 — the number was claimed with no signature
/// of its own, so giving it one **breaks nobody**: nobody could use the
/// address form because it did not exist.
///
/// The machinery below already supported it: `udp::sendto` has taken `dst_ip`
/// and `dst_port` all along.
///
/// ABI: a0 = fd, a1 = buf, a2 = len, **a3 = sockaddr pointer**. With
/// `addr = None` it behaves exactly like [`send`] — including `-EAGAIN` while
/// degraded mode is contained, which an address does not change.
pub fn sendto(fd: u64, buf: &[u8], addr: Option<&[u8; SOCKADDR_LEN]>) -> isize {
    let p = match addr { Some(a) => a.as_ptr() as u64, None => 0 };
    unsafe { syscall4(SYS_SENDTO, fd, buf.as_ptr() as u64, buf.len() as u64, p) }
}

/// Receive, **reporting the sender**.
///
/// Same story as [`sendto`]: `udp::recvfrom` has filled the source address all
/// along, and the syscall layer discarded it. A UDP server that does not know
/// who spoke to it cannot answer.
///
/// `addr` is written **after** the data: if copying it out fails, the datagram
/// is already delivered and only the return address is lost.
pub fn recvfrom(
    fd: u64,
    buf: &mut [u8],
    addr: Option<&mut [u8; SOCKADDR_LEN]>,
) -> isize {
    let p = match addr { Some(a) => a.as_mut_ptr() as u64, None => 0 };
    unsafe { syscall4(SYS_RECVFROM, fd, buf.as_mut_ptr() as u64, buf.len() as u64, p) }
}

/// Create a socket and receive a `Cap<Socket>` (`READ | WRITE`) for it rather
/// than a socket index.
///
/// Use it with [`connect_typed`], [`send_typed`], [`recv_typed`] and
/// [`close_typed`]; [`bind`], [`sendto`] and [`recvfrom`] stay untyped. While the
/// capability is live the kernel refuses [`sock_shutdown`] on the socket behind
/// it, so the handle keeps naming this socket.
///
/// Returns the raw handle (`>= 0`), `-1` if no socket could be created (the
/// per-task quota included), or `-EMFILE` when the capability table is full.
pub fn socket_typed(domain: u64, sock_type: u64, protocol: u64) -> isize {
    unsafe { syscall3(SYS_SOCKET_TYPED, domain, sock_type, protocol) }
}

/// Connect through a `Cap<Socket>`. Needs `WRITE`, so it is refused with
/// `-EAGAIN` while degraded mode is contained.
pub fn connect_typed(cap: u32, addr: &[u8; SOCKADDR_LEN]) -> isize {
    unsafe { syscall3(SYS_CONNECT_TYPED, cap as u64, addr.as_ptr() as u64, SOCKADDR_LEN as u64) }
}

/// Send through a `Cap<Socket>`. Needs `WRITE`; refused with `-EAGAIN` while
/// degraded mode is contained.
pub fn send_typed(cap: u32, buf: &[u8]) -> isize {
    unsafe { syscall3(SYS_SEND_TYPED, cap as u64, buf.as_ptr() as u64, buf.len() as u64) }
}

/// Receive through a `Cap<Socket>`. Needs `READ`, which containment leaves
/// live. Does not block: `0` means nothing has arrived yet.
pub fn recv_typed(cap: u32, buf: &mut [u8]) -> isize {
    unsafe { syscall3(SYS_RECV_TYPED, cap as u64, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Join the IPv4 multicast `group` (`[239, 1, 2, 3]`) on a UDP `Cap<Socket>`.
///
/// Needs `WRITE`, so it is refused with `-EAGAIN` while degraded mode is
/// contained. Delivery is by port: the socket still has to be [`bind`]-ed to
/// the port the group traffic is sent to. The membership goes back when the
/// socket is closed, however that happens.
///
/// Returns 0 (also for a group this socket already holds), `-EINVAL` for a
/// group outside `224.0.0.0/4` or inside `224.0.0.0/24`, or for a socket that
/// is not UDP, `-EQUOTA` when the socket already holds four groups, `-ENOSPC`
/// when the kernel's group table is full.
pub fn mcast_join_typed(cap: u32, group: [u8; 4]) -> isize {
    unsafe { syscall2(SYS_MCAST_JOIN_TYPED, cap as u64, u32::from_be_bytes(group) as u64) }
}

/// Leave a group joined with [`mcast_join_typed`] through the same capability.
/// Needs no permission beyond a live capability, so containment leaves it live.
/// Returns 0, or `-EINVAL` for a group this socket does not hold.
pub fn mcast_leave_typed(cap: u32, group: [u8; 4]) -> isize {
    unsafe { syscall2(SYS_MCAST_LEAVE_TYPED, cap as u64, u32::from_be_bytes(group) as u64) }
}

/// **Closes** the socket — this is not a half-close.
///
/// `SYS_SOCK_SHUTDOWN` dispatches to `sys_sock_close`, which checks that the
/// caller owns `fd`, then calls `socket_close(fd)`. There is no `how` argument
/// and no way to shut down only one direction, despite the name. Returns 0 on
/// close and -1 when the caller does not own `fd`, or when a `Cap<Socket>`
/// still names it (close that one with [`close_typed`]) — a denied close is
/// not reported as closed.
pub fn sock_shutdown(fd: u64) -> isize {
    unsafe { syscall1(SYS_SOCK_SHUTDOWN, fd) }
}

// ---------------------------------------------------------------------------
//  Memory management
// ---------------------------------------------------------------------------

/// Adjust the program break (heap end). Returns the new break or negative.
pub fn brk(addr: u64) -> isize {
    unsafe { syscall1(SYS_BRK, addr) }
}

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
    unsafe { syscall6(SYS_MMAP, addr, len, prot, flags, fd, offset) }
}

/// `fd` value [`mmap`] requires for an anonymous mapping.
pub const MAP_ANON_FD: u64 = u64::MAX;

/// [`mmap`]'s `prot` bits (Linux's values).
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;

/// Unmap memory at `addr` for `len` bytes.
pub fn munmap(addr: u64, len: u64) -> isize {
    unsafe { syscall2(SYS_MUNMAP, addr, len) }
}

// ---------------------------------------------------------------------------
//  RFC-0002 Driver registry bridge
// ---------------------------------------------------------------------------

/// Invoke a registered driver via the RFC-0002 registry.
///
/// `kind` is one of the `DRV_KIND_*` values (e.g. `0x0004` for UART,
/// `0x0001` for GPIO). `op` is the driver-defined op code (see the
/// driver's `*_OP_*` constants in the driver class crates). `input` is
/// the request payload, `output` is the reply buffer.
///
/// Returns the number of bytes written to `output` on success
/// (`Ok(n)`), or a negative errno on failure (`Err(errno)`):
/// - `-ENODEV` (-19): no driver registered for `kind`
/// - `-ENOSYS` (-38): driver does not support this `op`
/// - `-EINVAL` (-22): bad input layout or oversize buffer
/// - `-EAGAIN` (-11): driver busy, retry later
/// - `-EIO` (-5): underlying hardware error
///
/// Both buffers are bounded by [`DRIVER_INVOKE_MAX_INPUT_BYTES`] /
/// [`DRIVER_INVOKE_MAX_OUTPUT_BYTES`] (256 each); larger transfers
/// must use the F15 zero-copy pipeline.
pub fn drv_invoke(
    kind: u32,
    op: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, isize> {
    let in_ptr = if input.is_empty() {
        0
    } else {
        input.as_ptr() as u64
    };
    let out_ptr = if output.is_empty() {
        0
    } else {
        output.as_mut_ptr() as u64
    };
    let rc = unsafe {
        syscall6(
            SYS_DRV_INVOKE,
            kind as u64,
            op as u64,
            in_ptr,
            input.len() as u64,
            out_ptr,
            output.len() as u64,
        )
    };
    if rc < 0 {
        Err(rc)
    } else {
        Ok(rc as usize)
    }
}

/// Maximum input payload bytes accepted by [`drv_invoke`]. Re-exported from
/// `azos_abi::syscall_nr::DRIVER_INVOKE_MAX_INPUT_BYTES`.
pub use azos_abi::syscall_nr::DRIVER_INVOKE_MAX_INPUT_BYTES;
/// Maximum output buffer bytes accepted by [`drv_invoke`]. Re-exported from
/// `azos_abi::syscall_nr::DRIVER_INVOKE_MAX_OUTPUT_BYTES`.
pub use azos_abi::syscall_nr::DRIVER_INVOKE_MAX_OUTPUT_BYTES;

// ---------------------------------------------------------------------------
//  Service manager
// ---------------------------------------------------------------------------

// Every syscall in this family is keyed by a **NUL-terminated service name**,
// read with `copy_cstr_from_user` into a 64-byte kernel buffer
// (`handlers.rs::SYS_SERVICE_NAME_MAX`). There is no numeric service
// id anywhere in this ABI — the old `service_heartbeat(service_id: u64)` and
// `service_stop(service_id: u64)` wrappers passed an integer straight into a
// pointer argument. Nothing called them.

/// Longest service name the kernel will copy (`handlers.rs::SYS_SERVICE_NAME_MAX`).
/// Longer names fail the `copy_cstr_from_user` bound and return `-1`.
pub const SERVICE_NAME_MAX: usize = 64;

/// Register a service under `name` (**NUL-terminated**).
///
/// ABI (`sys_service_register`, `handlers.rs::sys_service_register`): a0 = name pointer,
/// a1 = **owning task id**, a2 = ipc channel. The previous wrapper passed
/// `(name_ptr, name_len, port)` — a length where the kernel reads a tid.
///
/// Returns 0 on success, negative on error.
pub fn service_register(name: &[u8], tid: u64, channel: u64) -> isize {
    if !has_nul(name) {
        return E_INVAL;
    }
    unsafe { syscall3(SYS_SERVICE_REGISTER, name.as_ptr() as u64, tid, channel) }
}

/// Look up a service by `name` (**NUL-terminated**).
///
/// ABI (`sys_service_discover`, `handlers.rs::sys_service_discover`): returns the registered
/// service's **task id** (`entry.tid`), not a port as this doc used to say.
/// `-1` if no such service.
pub fn service_discover(name: &[u8]) -> isize {
    if !has_nul(name) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_SERVICE_DISCOVER, name.as_ptr() as u64) }
}

/// Send a liveness heartbeat for the service called `name`
/// (**NUL-terminated** — `sys_service_heartbeat`, `handlers.rs::sys_service_heartbeat`).
pub fn service_heartbeat(name: &[u8]) -> isize {
    if !has_nul(name) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_SERVICE_HEARTBEAT, name.as_ptr() as u64) }
}

/// Stop the service called `name` (**NUL-terminated** —
/// `sys_service_stop_handler`, `handlers.rs::sys_service_stop_handler`).
pub fn service_stop(name: &[u8]) -> isize {
    if !has_nul(name) {
        return E_INVAL;
    }
    unsafe { syscall1(SYS_SERVICE_STOP, name.as_ptr() as u64) }
}

// ---------------------------------------------------------------------------
//  Robot control
// ---------------------------------------------------------------------------
//
// Every syscall in this block is a kernel stub EXCEPT `robot_estop` (325) and
// `sensor_read` (332). `dispatch` collapses the rest with
// `SYS_ROBOT_INIT ..= SYS_SENSOR_ADD => sys_stub()`, and `sys_stub` is `-1`;
// arguments are not read.
//
// `robot_estop` was in that range until 2026-09-10, which meant ring 3's only
// "stop everything" call did nothing at all. It is now implemented and IS a
// safety path — see its own doc below.
//
// They return -1, so a caller that checks the result is merely disappointed
// rather than misled — but do not read a -1 from these as "hardware absent".

/// Initialize robot subsystem. **Kernel stub — always returns `-1`.**
pub fn robot_init() -> isize {
    unsafe { syscall0(SYS_ROBOT_INIT) }
}

/// Start robot operation.
pub fn robot_start() -> isize {
    unsafe { syscall0(SYS_ROBOT_START) }
}

/// Stop robot operation.
pub fn robot_stop() -> isize {
    unsafe { syscall0(SYS_ROBOT_STOP) }
}

/// Pause robot operation.
pub fn robot_pause() -> isize {
    unsafe { syscall0(SYS_ROBOT_PAUSE) }
}

/// Resume robot operation.
pub fn robot_resume() -> isize {
    unsafe { syscall0(SYS_ROBOT_RESUME) }
}

/// Emergency stop — latch the machine's e-stop and halt the drivetrain.
///
/// Does the same work as an operator's kill switch or a `PKT_ESTOP` from the
/// brain: latches `estop_active` so every later motor write from every path is
/// clamped to zero, stops both wheels, disarms the ESC, and writes a durable
/// `SAFETY_ESTOP` record to the flight recorder.
///
/// **The latch is not cleared by calling again, or by the emergency going
/// away.** Rearming is an operator action (`MODE_ID_ESTOP_RESET` from the
/// brain); a program that can stop the machine does not get to decide it is
/// safe to resume.
///
/// Requires WRITE on ANY motor capability — deliberately not all of them and
/// not a capability of its own, because stopping must never demand more
/// authority than driving.
///
/// Returns 0 when the stop was carried out, `-EPERM` when the caller holds no
/// motor, and -1 if the kernel has not armed the handler yet. It never returns
/// 0 for a stop that did not happen.
pub fn robot_estop() -> isize {
    unsafe { syscall0(SYS_ROBOT_ESTOP) }
}

/// Move robot with direction and speed encoded in arguments.
pub fn robot_move(direction: u64, speed: u64) -> isize {
    unsafe { syscall2(SYS_ROBOT_MOVE, direction, speed) }
}

/// Move robot forward by a distance.
pub fn robot_forward(distance: u64) -> isize {
    unsafe { syscall1(SYS_ROBOT_FORWARD, distance) }
}

/// Rotate robot by an angle (in degrees or millidegrees).
pub fn robot_rotate(angle: u64) -> isize {
    unsafe { syscall1(SYS_ROBOT_ROTATE, angle) }
}

/// Query robot status/info.
pub fn robot_info() -> isize {
    unsafe { syscall0(SYS_ROBOT_INFO) }
}

// ---------------------------------------------------------------------------
//  Sensors
// ---------------------------------------------------------------------------

/// Query sensor subsystem info.
/// **Kernel stub — always returns `-1`** (`dispatch.rs:771`).
pub fn sensor_info() -> isize {
    unsafe { syscall0(SYS_SENSOR_INFO) }
}

/// Register/add a sensor of the given type.
/// **Kernel stub — always returns `-1`** (`dispatch.rs:771`). Sensors need
/// no registration: [`sensor_read_typed`] works without it.
pub fn sensor_add(sensor_type: u64) -> isize {
    unsafe { syscall1(SYS_SENSOR_ADD, sensor_type) }
}

/// Read ADC channel `channel` (0-3), in millivolts.
///
/// ABI (`SYS_ADC_READ`, 410): the handler checks an `Adc(channel)` capability
/// first and answers [`E_PERM_HANDLER`] without one, writing one
/// `SAFETY_CAP_DENIED` record within the per-task denial budget. Past the
/// check, a channel above 3 or a driver with no sample answers `-1`, and a
/// reading is returned as a non-negative millivolt value.
///
/// `CapKind::Adc` has no minter and no topology name, so no ring-3
/// capability table holds one and every ring-3 call is refused and recorded.
/// `captest` and `latbench` issue it for that refusal.
pub fn adc_read(channel: u64) -> isize {
    unsafe { syscall1(SYS_ADC_READ, channel) }
}

// ---------------------------------------------------------------------------
//  Platform
// ---------------------------------------------------------------------------

/// Query platform info.
///
/// **Kernel stub — always returns `-1`.** `dispatch.rs:773` is
/// `SYS_PLATFORM_INFO ..= SYS_PLATFORM_TYPE => sys_stub()`.
pub fn platform_info() -> isize {
    unsafe { syscall0(SYS_PLATFORM_INFO) }
}

/// Get platform type.
///
/// **Kernel stub — always returns `-1`,** not a platform id. The 0=QEMU /
/// 1=VF2 / 2=K1 encoding this doc used to promise is not implemented
/// anywhere; the dispatch arm is `sys_stub()`.
pub fn platform_type() -> isize {
    unsafe { syscall0(SYS_PLATFORM_TYPE) }
}

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

/// Register the calling process as a driver named `name`.
///
/// ABI (`SYS_DRV_REGISTER`, `dispatch.rs:613`): a0 = name pointer,
/// a1 = length, **clamped to 32 bytes** — this one takes an explicit length,
/// not a NUL-terminated string, so a longer name is truncated silently.
///
/// Returns a driver id (the `drv_id` [`drv_heartbeat`] needs), or `-1`.
pub fn drv_register(name: &[u8]) -> isize {
    unsafe { syscall2(SYS_DRV_REGISTER, name.as_ptr() as u64, name.len() as u64) }
}

/// Longest driver name [`drv_register`] records (`dispatch.rs:615`).
pub const DRV_NAME_MAX: usize = 32;

/// Unmap a previously mapped MMIO region.
///
/// **Unimplemented.** `SYS_DRV_MUNMAP` is `sys_stub()` (`dispatch.rs:657`)
/// and returns `-1`; both arguments are discarded. A region mapped by
/// `SYS_MMIO_MAP` stays mapped for the life of the process.
pub fn drv_munmap(addr: u64, size: u64) -> isize {
    unsafe { syscall2(SYS_DRV_MUNMAP, addr, size) }
}

/// Block until IRQ `irq` fires.
///
/// ABI: blocks on `WaitReason::Irq(irq)`.
///
///   * `0` — woken. Treat this as "the interrupt fired".
///   * [`E_AGAIN`] (`-11`) — the kernel **did not block** (K-C29: a critical
///     section was open on that hart). Nothing happened and nothing was
///     waited for; call again. Do **not** read or ack device state on this
///     return.
///
/// For the owner of a wake-task binding of `irq` ([`irq_bind`] type 0) the
/// kernel keeps a pending bit: a delivery that landed before this call
/// returns `0` at once, and `-11` then means "nothing was consumed, call
/// again" (`handlers::irq_wait_bound_ret`). Any other caller has no such
/// record, so the refusal is reported instead of swallowed
/// (`handlers::irq_wait_ret`).
///
/// No capability check on this arm — but [`drv_irq_ack`] requires one, so a
/// task that cannot ack should not be waiting.
pub fn drv_irq_wait(irq: u64) -> isize {
    unsafe { syscall1(SYS_DRV_IRQ_WAIT, irq) }
}

/// Bind IRQ line `irq` (`SYS_IRQ_BIND`, 510): `target_type` 0 wakes the
/// caller ([`drv_irq_wait`] then consumes the delivery, even one that
/// arrived before the wait), 1 queues to the port at index `port` with key
/// `key`. Requires an `Irq(irq)` capability, else [`E_PERM_DISPATCH`];
/// `-1` for a line this ISA cannot hand to ring 3 or a full binding table;
/// `-ENODEV` (nothing bound) when the interrupt controller cannot deliver it.
pub fn irq_bind(irq: u32, target_type: u64, port: u64, key: u64) -> isize {
    unsafe { syscall4(SYS_IRQ_BIND, irq as u64, target_type, port, key) }
}

/// Acknowledge an IRQ (PLIC completion) after handling it.
///
/// Requires an `Irq(irq)` capability, else [`E_PERM_DISPATCH`]
/// (`dispatch.rs:667` — a dispatcher-side `-1`, not `-99`).
pub fn drv_irq_ack(irq: u64) -> isize {
    unsafe { syscall1(SYS_DRV_IRQ_ACK, irq) }
}

/// Tell the driver manager that driver `drv_id` is still alive.
///
/// ABI (`SYS_DRV_HEARTBEAT`, `dispatch.rs:747`): a0 = **`drv_id`**, passed
/// to `driver_heartbeat_with_time(a0 as usize, now_ms)`.
///
/// **This wrapper took no arguments and issued `syscall0`.** `syscall0`
/// declares `a0` as `lateout` only, so nothing writes it before the `ecall`
/// and the kernel read whatever the compiler had left in the register — an
/// arbitrary `drv_id`, refreshing some other driver's watchdog or none.
/// Silent because heartbeats have no return value to check.
///
/// Always returns 0, including for an unknown `drv_id`.
pub fn drv_heartbeat(drv_id: u64) -> isize {
    unsafe { syscall1(SYS_DRV_HEARTBEAT, drv_id) }
}

// ---- RFC-0002 driver-server: serve a driver `kind` from userspace (E11.AQ3) ----

/// Find the handle of a capability this task already holds.
///
/// `kind` is a [`CapKind`] discriminant (`CapKind::Gpio as u8`) and
/// `resource` the object it names — a GPIO pin, a motor id, a
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
    unsafe { syscall2(SYS_CAP_LOOKUP, kind as u64, resource as u64) }
}

/// The `CapKind` a [`cap_lookup`] asks about.
///
/// Re-exported, NOT restated. The first draft of this declared
/// `CAP_KIND_GPIO: u8 = 8` and friends as plain constants "so a ring-3
/// program need not depend on the ABI crate for two numbers" — which is the
/// exact reasoning that had five files carrying their own `DRV_KIND_*` until
/// those moved into `crates/core/abi` earlier in this commit. `crates/core/libsys`
/// already depends on `azos_abi`; there was never a second number to
/// keep in sync, only a habit.
///
/// Call it as `cap_lookup(CapKind::Gpio as u8, pin)`.
pub use azos_abi::cap::CapKind;

/// Register as the driver for the kind named by `cap` (a
/// `Cap<DriverRegistry>` from [`cap_lookup`]).
///
/// There is no `kind` argument: the kind comes out of the capability, so
/// registering as a device you do not hold is not a request this ABI can
/// express. `mmio_base`/`mmio_size`/`irq` are advisory, as in the untyped
/// form.
pub fn drv_srv_register_typed(cap: u32, mmio_base: u64, mmio_size: u64, irq: u32) -> isize {
    unsafe {
        syscall4(SYS_DRIVER_REGISTER_TYPED, cap as u64, mmio_base, mmio_size, irq as u64)
    }
}

/// Release the driver registration named by `cap`. Requires `WRITE`, so it is
/// refused with `-EAGAIN` while degraded mode is contained.
pub fn drv_srv_unregister_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_DRIVER_UNREGISTER_TYPED, cap as u64) }
}

/// Fetch one pending request for `kind` into the caller's `DriverRequest`
/// buffer (pass `&mut req as *mut _ as *mut u8`).
///
/// ABI (`sys_driver_fetch_request`, `handlers.rs::sys_driver_fetch_request`): the kernel writes
/// **exactly `size_of::<DriverRequest>()` bytes** to `req_ptr` and is never
/// told how large the destination is. The struct is `#[repr(C)]` and lives
/// in `crates/drivers/driver_server/src/lib.rs:107`:
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
    unsafe { syscall2(SYS_DRIVER_FETCH_REQ, kind as u64, req_ptr as u64) }
}

/// Post a `DriverReply` (pass `&reply as *const _ as *const u8`) for `kind`.
///
/// ABI (`sys_driver_reply`, `handlers.rs::sys_driver_reply`): the kernel **reads
/// `size_of::<DriverReply>()` bytes** from `reply_ptr` — the `#[repr(C)]`
/// struct at `crates/drivers/driver_server/src/lib.rs:137`:
///
/// ```text
/// token: u64 | status: i32 | out_len: u16 | _pad: u16
///            | output: [u8; 64]                     →  80 bytes on RV64
/// ```
///
/// Same mirroring rule as [`drv_srv_fetch_request`]. Returns 0 on success.
pub fn drv_srv_reply(kind: u32, reply_ptr: *const u8) -> isize {
    unsafe { syscall2(SYS_DRIVER_REPLY, kind as u64, reply_ptr as u64) }
}

/// Post the reply owed for `kind` and fetch the next request, in one trap
/// (RFC-0041 §D). A serve loop's whole round trip.
///
/// ABI (`SYS_DRIVER_REPLY_FETCH`, `sys_driver_reply_fetch`): `reply_ptr` is a
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
    unsafe {
        syscall3(SYS_DRIVER_REPLY_FETCH, kind as u64, reply_ptr as u64, req_ptr as u64)
    }
}

/// [`drv_srv_reply_fetch`] that blocks while the queue is empty
/// (`SYS_DRIVER_REPLY_WAIT`): the reply owed is posted, then the call returns
/// with the next request, or `-1` once `park_ms` (0 = the kernel's default,
/// at most 1000) has passed with none. A request queued by the kernel's proxy
/// wakes it, so a serve loop on this call never polls.
///
/// Same buffers and the same returns as [`drv_srv_reply_fetch`]: any value
/// other than `0` and `-1` did nothing, and the reply is still owed.
pub fn drv_srv_reply_wait(kind: u32, reply_ptr: *const u8, req_ptr: *mut u8, park_ms: u32) -> isize {
    unsafe {
        syscall4(SYS_DRIVER_REPLY_WAIT, kind as u64, reply_ptr as u64, req_ptr as u64, park_ms as u64)
    }
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

/// Port source kind: IPC channel. See [`port_bind_typed`].
pub const PORT_SRC_CHANNEL: u64 = 0;
/// Port source kind: IO ring.
pub const PORT_SRC_RING: u64 = 1;
/// Port source kind: hardware IRQ.
pub const PORT_SRC_IRQ: u64 = 2;
/// Port source kind: timer (the bind's source is the deadline, absolute ns).
pub const PORT_SRC_TIMER: u64 = 3;
/// [`port_bind_typed`] flag, or-ed into the source type: remove the sources
/// of that type bound with the key instead of binding one.
pub const PORT_BIND_F_REMOVE: u64 = azos_abi::syscall_nr::PORT_BIND_F_REMOVE;
/// Event source type (byte 8 of an event): a channel.
pub const PORT_EVENT_CHANNEL: u8 = 1;
/// Event source type: an io_ring.
pub const PORT_EVENT_RING: u8 = 2;
/// Event source type: an IRQ.
pub const PORT_EVENT_IRQ: u8 = 3;
/// Event source type: a timer.
pub const PORT_EVENT_TIMER: u8 = 4;

// ===========================================================================
//  Trace API (AQ8) — kernel event ring buffer dump
// ===========================================================================

/// Dump the last `count` kernel trace entries to the console.
///
/// ABI (`SYS_TRACE_DUMP`, `dispatch.rs:1049`): a0 = entry count, where
/// **`0` means the kernel default of 50**.
///
/// **This wrapper took no arguments and issued `syscall0`**, which declares
/// `a0` as `lateout` only — nothing writes the register before the `ecall`,
/// so the kernel read leftover garbage as the count and dumped an arbitrary
/// number of entries. Same defect as the old [`drv_heartbeat`]: a syscall
/// that reads `a0` can never be reached through `syscall0`.
///
/// Always returns 0.
pub fn trace_dump(count: u64) -> isize {
    unsafe { syscall1(SYS_TRACE_DUMP, count) }
}

/// Entry count [`trace_dump`] uses when passed 0 (`dispatch.rs:1051`).
pub const TRACE_DUMP_DEFAULT_COUNT: u64 = 50;

// ===========================================================================
//  Fast-path IPC (M02) — seL4-style register-passing, ≤32 bytes
// ===========================================================================

/// Maximum number of 64-bit words in a fast IPC message.
pub const FAST_IPC_MAX_WORDS: usize = 4;

/// Send a fast IPC message to `server_tid` and block until the reply arrives,
/// receiving the FULL four-word reply.
///
/// ABI (`SYS_IPC_FAST_CALL`, `dispatch.rs`, fast-IPC arms): a0 = server TID,
/// a1..a4 = up to 4 × u64 of request data (≤ 32 bytes). On success a0 =
/// reply\[0\] and a1..a3 = reply\[1..3\], delivered through `SyscallOut`
/// exactly like FAST_ACCEPT's request delivery. On failure a0 = -1 and
/// a1..a5 are untouched. The kernel touches no user memory — data travels in
/// registers both ways.
///
/// **WHY this cannot go through the shared `syscallN` helpers.** Same reason
/// as [`fast_ipc_accept_req`]: results land in argument registers, so they
/// must be declared `lateout` in a dedicated block. Routing this through
/// `syscall5` (whose `in("a1")`… operands rustc may assume intact) would be
/// undefined behaviour the moment the kernel writes the reply back.
///
/// **The first reply word and the error code share `a0`.** Success is
/// `reply[0]`, failure is `-1`, and nothing tags which is which — so a
/// reply\[0\] with bit 63 set is reported here as a failed call. Keep the
/// FIRST fast-IPC reply word in the non-negative `i64` range; the other
/// three are unconstrained.
///
/// Returns `None` when the kernel refused the call: `server_tid` is not a
/// live TID, equals the caller (self-deadlock), or all
/// [`FAST_IPC_MAX_SLOTS`]-many slots are busy.
pub fn fast_ipc_call_full(
    server_tid: u32,
    words: [u64; FAST_IPC_MAX_WORDS],
) -> Option<[u64; FAST_IPC_MAX_WORDS]> {
    let ret: isize;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            in("a7") SYS_IPC_FAST_CALL,
            inlateout("a0") server_tid as u64 => ret,
            inlateout("a1") words[0] => r1,
            inlateout("a2") words[1] => r2,
            inlateout("a3") words[2] => r3,
            // The kernel writes zeros into a4/a5 on success (SyscallOut
            // always writes all five); declared clobbered, values discarded.
            inlateout("a4") words[3] => _,
            lateout("a5") _,
            // The kernel writes `a6` on every arm that opts into `SyscallOut`
            // (RFC-0040 gap 2 stage 4). Undeclared, rustc is entitled to keep a
            // live value here and the kernel would silently destroy it.
            lateout("a6") _,
            options(nostack),
        );
        // aarch64 twin: x0..=x6 mirror a0..=a6 register-for-register (see
        // `crates/core/abi/src/syscall_nr.rs`'s "Register convention"). No
        // aarch64 kernel dispatch exists yet — this is phase 6 prep.
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_IPC_FAST_CALL,
            inlateout("x0") server_tid as u64 => ret,
            inlateout("x1") words[0] => r1,
            inlateout("x2") words[1] => r2,
            inlateout("x3") words[2] => r3,
            inlateout("x4") words[3] => _,
            lateout("x5") _,
            lateout("x6") _,
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys fast_ipc_call_full: the `syscall` instruction");
    }
    if ret < 0 { return None; }
    Some([ret as u64, r1, r2, r3])
}

/// [`fast_ipc_call_full`] addressed by a `Cap<Endpoint>` instead of a TID
/// (`SYS_IPC_FAST_CALL_EP`, RFC-0040 gap 2).
///
/// Same registers, same reply shape, same `a0` overloading of the first reply
/// word with the error code — only `a0` on the way IN differs: a capability
/// handle the caller holds, not a task id it guessed. A caller with no
/// endpoint capability can reach nothing, where the TID form can reach any
/// live task in the system.
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
/// RFC-0040 gap 2 stage 4, under owner decision 38: a move, never a copy. The
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
            inlateout("a5") moving as u64 => _,
            // The kernel writes `a6` on every arm that opts into `SyscallOut`
            // (RFC-0040 gap 2 stage 4). Undeclared, rustc is entitled to keep a
            // live value here and the kernel would silently destroy it.
            lateout("a6") _,
            options(nostack),
        );
        // aarch64 twin — see `fast_ipc_call_full`.
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc #0",
            in("x8") SYS_IPC_FAST_CALL_EP,
            inlateout("x0") endpoint as u64 => ret,
            inlateout("x1") words[0] => r1,
            inlateout("x2") words[1] => r2,
            inlateout("x3") words[2] => r3,
            inlateout("x4") words[3] => _,
            inlateout("x5") moving as u64 => _,
            lateout("x6") _,
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys fast_ipc_call_ep_moving: the `syscall` instruction");
    }
    if ret < 0 { return None; }
    Some([ret as u64, r1, r2, r3])
}

/// [`fast_ipc_call_ep_full`] for callers that need only the first reply word.
pub fn fast_ipc_call_ep(endpoint: u32, words: [u64; FAST_IPC_MAX_WORDS]) -> Option<u64> {
    fast_ipc_call_ep_full(endpoint, words).map(|r| r[0])
}

/// [`fast_ipc_call_full`] for callers that only need the first reply word —
/// the historical shape of this API, kept because most exchanges answer with
/// a single word and the ergonomics matter at every call site.
pub fn fast_ipc_call(server_tid: u32, words: [u64; FAST_IPC_MAX_WORDS]) -> Option<u64> {
    fast_ipc_call_full(server_tid, words).map(|r| r[0])
}

/// Number of fast-IPC slots in the kernel (`FAST_IPC_MAX_SLOTS`,
/// `crates/core/ipc/src/fast_ipc.rs`). A slot index returned by
/// [`fast_ipc_accept`] is always below this.
pub const FAST_IPC_MAX_SLOTS: usize = 64;

/// Low bits of a fast-IPC handle that hold the slot index; the rest is the
/// generation tag. Mirrors `FAST_IPC_SLOT_MASK` in `crates/core/ipc/src/fast_ipc.rs`
/// — the two must agree, and the kernel side carries a compile-time assert
/// tying it to `FAST_IPC_MAX_SLOTS`.
pub const FAST_IPC_SLOT_MASK: u64 = (FAST_IPC_MAX_SLOTS as u64) - 1;

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
    /// Slot index, decoded from `handle` purely for logging and for the
    /// caller's own bookkeeping. **Never** hand this to [`fast_ipc_reply`].
    pub slot: usize,
    /// TID of the task that issued `SYS_IPC_FAST_CALL`.
    pub caller_tid: u32,
    /// The four request words, exactly as the client passed them.
    pub words: [u64; FAST_IPC_MAX_WORDS],
    /// Handle a capability **moved** with this message took in THIS task's
    /// table, or [`NO_CAP_TO_MOVE`] when the message carried none.
    ///
    /// RFC-0040 gap 2 stage 4. The move already happened in the caller's own
    /// trap, so this is a record and not something to claim: the capability is
    /// in this task's table whether or not this field is read, and dropping it
    /// on the floor leaks authority rather than declining it.
    pub moved_cap: u32,
    /// **False means the kernel did not deliver the payload**, and
    /// `caller_tid` / `words` are meaningless — not zero, not stale data from
    /// a previous call, simply undelivered.
    ///
    /// The kernel side of the delivery is inert until the trap handler in
    /// `kernel/src/trap/exception.rs` calls `syscall_dispatch_out` and copies
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
            options(nostack),
        );
        // aarch64 twin — x0..=x6 mirror a0..=a6. See `fast_ipc_call_full`.
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
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys fast_ipc_accept_req: the `syscall` instruction");
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
        slot: (handle & FAST_IPC_SLOT_MASK) as usize,
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
/// `handle & FAST_IPC_SLOT_MASK` if you need the index for logging.
pub fn fast_ipc_accept() -> Option<u64> {
    fast_ipc_accept_req().map(|r| r.handle)
}

/// Server: reply to a fast IPC call (non-blocking).
///
/// ABI (`SYS_IPC_FAST_REPLY`): a0 = the **handle** [`fast_ipc_accept`]
/// returned, a1..a4 = reply words. Only `words[0]` reaches the client — see
/// [`fast_ipc_call`].
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
/// in one trap (RFC-0041 §C).
///
/// ABI (`SYS_IPC_FAST_REPLY_ACCEPT`): a0 = the handle, a1 =
/// [`FAST_ACCEPT_SENTINEL`] (the kernel does not read it), a2..a5 = the reply
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
            options(nostack),
        );
        // aarch64 twin — x0..=x6 mirror a0..=a6. See `fast_ipc_call_full`.
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
            options(nostack),
        );
        // x86_64 skeleton: `syscall` with rax = number, args in rdi rsi rdx
        // r10 r8 r9, rcx/r11 clobbered (the Linux x86_64 convention).
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        todo!("x86_64: libsys fast_ipc_reply_accept: the `syscall` instruction");
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
//  Cap<T> typed syscalls (RFC-0003)
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

/// Create a channel owned by the caller and mint a `Cap<Channel>` with
/// `READ` and `WRITE` for it.
///
/// ABI (`SYS_CHAN_CREATE_TYPED`, 573): no argument. Returns the raw handle
/// (positive), `-EQUOTA` when the task already owns half the channel pool,
/// or `-EMFILE` when the pool or the capability table is full. The
/// channel's index is not published: use the handle with
/// [`chan_write_typed`] and [`chan_read_typed`], and destroy the channel
/// with [`close_typed`].
pub fn chan_create_typed() -> isize {
    unsafe { syscall0(SYS_CHAN_CREATE_TYPED) }
}

/// Typed channel write. `cap` needs `WRITE`. Returns `0` on success, not a
/// byte count, or `-Errno`.
pub fn chan_write_typed(cap: u32, buf: &[u8]) -> isize {
    unsafe { syscall3(SYS_CHAN_WRITE_TYPED, cap as u64, buf.as_ptr() as u64, buf.len() as u64) }
}

/// Typed channel read. `cap` needs `READ`. Returns bytes read.
pub fn chan_read_typed(cap: u32, buf: &mut [u8]) -> isize {
    unsafe { syscall3(SYS_CHAN_READ_TYPED, cap as u64, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Allocate a port and mint a `Cap<Port>` for it in the caller's cap table.
///
/// Takes no argument; returns the raw cap handle (positive) or `-Errno`
/// (`EMFILE` when the port pool or the cap table is full).
pub fn port_create_typed() -> isize {
    unsafe { syscall0(SYS_PORT_CREATE_TYPED) }
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
/// arrived with RFC-0040 gap 3 (2026-09-25):
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
    unsafe { syscall0(SYS_ENDPOINT_CREATE_TYPED) }
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
    unsafe { syscall2(SYS_PORT_POLL_TYPED, cap as u64, out.as_mut_ptr() as u64) }
}

/// Bind an event source to the port behind a `Cap<Port>`, with `key` as
/// the event's key.
///
/// ABI (`SYS_PORT_BIND_TYPED`, 575): a0 = port cap (needs `WRITE`), a1 =
/// source type in the `PORT_SRC_*` encoding (or-ed with
/// [`PORT_BIND_F_REMOVE`] to remove), a2 = the source's capability (a
/// `Cap<Channel>`, `Cap<IoRing>` or `Cap<Irq>`, each with `READ`), a3 = key.
/// A timer takes its deadline instead: [`port_bind_timer`].
///
/// Returns 0, or `-Errno`, in order: `-ECAPSTALE` / `-ECAPKIND` /
/// `-ECAPPERMS` for the port capability, or `-EAGAIN` while containment is
/// armed; `-EINVAL` for a source type above 3 or an unknown flag;
/// `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` for the source capability;
/// `-ECAPSTALE` when the port was destroyed before the binding was stored;
/// `-EMFILE` when the port's source table or the IRQ binding table is full;
/// `-EBUSY` when the channel or ring reports to another port; `-ENODEV`
/// (nothing bound) when the interrupt controller cannot deliver the line.
/// The full contract is `azos_abi::syscall_nr::SYS_PORT_BIND_TYPED`'s.
pub fn port_bind_typed(port: u32, source_type: u64, source_cap: u32, key: u64) -> isize {
    unsafe { syscall4(SYS_PORT_BIND_TYPED, port as u64, source_type, source_cap as u64, key) }
}

/// Arm (or, with a key already armed, re-arm) a one-shot timer source on the
/// port behind a `Cap<Port>`: an event with `key` and source type
/// [`PORT_EVENT_TIMER`] at `deadline_ns` (absolute nanoseconds on the time
/// counter, as [`vdso_now_ns`] reads it). `SYS_PORT_BIND_TYPED` with
/// [`PORT_SRC_TIMER`].
pub fn port_bind_timer(port: u32, deadline_ns: u64, key: u64) -> isize {
    unsafe { syscall4(SYS_PORT_BIND_TYPED, port as u64, PORT_SRC_TIMER, deadline_ns, key) }
}

/// Remove the sources of type `source_type` (`PORT_SRC_CHANNEL`,
/// `PORT_SRC_RING` or `PORT_SRC_TIMER`) bound with `key`: 0, or `-ENOENT`
/// when there was none.
pub fn port_unbind_typed(port: u32, source_type: u64, key: u64) -> isize {
    unsafe { syscall4(SYS_PORT_BIND_TYPED, port as u64, source_type | PORT_BIND_F_REMOVE, 0, key) }
}

/// Wait until the port behind a `Cap<Port>` has an event or `deadline_ns`
/// passes, whichever is first (`SYS_PORT_WAIT_UNTIL_TYPED`, 604).
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
    unsafe { syscall3(SYS_PORT_WAIT_UNTIL_TYPED, cap as u64, out.as_mut_ptr() as u64, deadline_ns) }
}

/// Block until the port behind a `Cap<Port>` has an event, and dequeue it
/// into `out`.
///
/// ABI (`SYS_PORT_WAIT_TYPED`, 577): a0 = cap (needs `READ`; a wait stays
/// live while containment is armed), a1 = `out`. The event layout is
/// [`port_poll_typed`]'s: key `u64` LE in bytes 0..8, source type in byte
/// 8, source id `u32` LE in bytes 12..16.
///
/// Returns [`PORT_EVENT_BYTES`], or `-Errno`, in order: `-ECAPSTALE` /
/// `-ECAPKIND` / `-ECAPPERMS` for the capability; `-EFAULT` for an
/// unwritable `out`, checked before anything is dequeued; `-ECAPSTALE`
/// when the port is destroyed before or during the wait; `-EMFILE` when the
/// port already has its maximum number of waiters; `-EAGAIN` when eight
/// blocks returned with nothing queued.
pub fn port_wait_typed(cap: u32, out: &mut [u8; PORT_EVENT_BYTES]) -> isize {
    unsafe { syscall2(SYS_PORT_WAIT_TYPED, cap as u64, out.as_mut_ptr() as u64) }
}

/// Free the port behind a `Cap<Port>`.
///
/// The capability itself is **not** revoked — the handle survives as a stale
/// reference until the caller revokes it, which is what makes `ECAPSTALE`
/// observable rather than a use-after-free.
pub fn port_destroy_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_PORT_DESTROY_TYPED, cap as u64) }
}

/// Create a shared-memory region of `pages` pages with mode `perms`
/// ([`SHM_RO`] / [`SHM_RW`]) and mint a `Cap<Shm>` for it.
///
/// Returns the raw cap handle (positive) or `-Errno`. On cap-table exhaustion
/// the region is rolled back, so a failure never leaves a half-created
/// region behind.
pub fn shm_create_typed(pages: u64, perms: u64) -> isize {
    unsafe { syscall2(SYS_SHM_CREATE_TYPED, pages, perms) }
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
    unsafe { syscall2(SYS_SHM_ACQUIRE_TYPED, cap as u64, out.as_mut_ptr() as u64) }
}

/// Map the region behind a `Cap<Shm>` into the caller's address space and
/// return its base VA.
///
/// ABI (`SYS_SHM_MAP_TYPED`, 574): a0 = cap. Needs `READ`, and `WRITE` too
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
    unsafe { syscall1(SYS_SHM_MAP_TYPED, cap as u64) }
}

/// Give back the region behind a `Cap<Shm>`: this task's mapping is removed
/// first, then every reference the task holds on the region (the creation
/// reference, [`shm_acquire_typed`]'s and [`shm_map_typed`]'s), and the
/// capability is revoked. The backing pages go back to the PMM when no task
/// holds a reference; another task's references keep the region live.
/// Requires `READ`. One call per capability: a second answers `-ECAPSTALE`.
pub fn shm_release_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_SHM_RELEASE_TYPED, cap as u64) }
}

/// The ring page as ring 3 reads and writes it, and a producer/consumer
/// over it.
pub mod ioring;

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
    unsafe { syscall1(SYS_IORING_CREATE_TYPED, addr_out.as_mut_ptr() as u64) }
}

/// Execute the pending SQEs on a `Cap<IoRing>` through the kernel's op table
/// (RFC-0041 §E). Requires `WRITE`.
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
    unsafe { syscall1(SYS_IORING_SUBMIT_TYPED, cap as u64) }
}

/// Free an io_ring and its backing page. Requires `WRITE`, and is not refused
/// while degraded mode is contained. **The capability is revoked** by the same
/// call, so a later use of it answers `-ECAPSTALE` instead of reaching a ring
/// created at the same index.
pub fn ioring_destroy_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_IORING_DESTROY_TYPED, cap as u64) }
}

/// Read the GPIO pin behind a `Cap<Gpio>`. Requires `READ`. Returns 0 or 1.
///
/// The cap's resource id *is* the pin number, so which pin a task may touch
/// is decided by the grant, not by an argument it chooses.
pub fn gpio_read_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_GPIO_READ_TYPED, cap as u64) }
}

/// Drive the GPIO pin behind a `Cap<Gpio>` (`val`'s low bit). Requires `WRITE`.
pub fn gpio_write_typed(cap: u32, val: u64) -> isize {
    unsafe { syscall2(SYS_GPIO_WRITE_TYPED, cap as u64, val) }
}

/// Set the direction of a `Cap<Gpio>` pin: 0 = input, 1 = output.
/// Requires `WRITE`.
pub fn gpio_set_dir_typed(cap: u32, output: u64) -> isize {
    unsafe { syscall2(SYS_GPIO_SET_DIR_TYPED, cap as u64, output) }
}

/// Largest transfer accepted by [`i2c_read_typed`] / [`i2c_write_typed`].
/// Re-exported from `azos_abi::syscall_nr::I2C_TYPED_MAX_BYTES`. Longer
/// buffers are rejected, not clamped.
pub use azos_abi::syscall_nr::I2C_TYPED_MAX_BYTES;

/// Read `buf.len()` bytes from register `reg` of a `Cap<I2c>` slave.
/// Requires `READ`. Returns bytes read.
pub fn i2c_read_typed(cap: u32, reg: u64, buf: &mut [u8]) -> isize {
    unsafe {
        syscall4(SYS_I2C_READ_TYPED, cap as u64, reg,
                 buf.as_mut_ptr() as u64, buf.len() as u64)
    }
}

/// Write `data` to a `Cap<I2c>` slave. Requires `WRITE`.
/// By I2C convention `data[0]` is the register address.
pub fn i2c_write_typed(cap: u32, data: &[u8]) -> isize {
    unsafe {
        syscall3(SYS_I2C_WRITE_TYPED, cap as u64,
                 data.as_ptr() as u64, data.len() as u64)
    }
}

/// Probe whether the `Cap<I2c>` slave ACKs. Requires `READ`.
/// Returns 1 (present) or 0 (absent).
pub fn i2c_detect_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_I2C_DETECT_TYPED, cap as u64) }
}

/// Start the PWM channel behind a `Cap<Pwm>`. Requires `WRITE`.
pub fn pwm_enable_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_PWM_ENABLE_TYPED, cap as u64) }
}

/// Stop the PWM channel behind a `Cap<Pwm>`. Requires `WRITE`.
pub fn pwm_disable_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_PWM_DISABLE_TYPED, cap as u64) }
}

/// Set the PWM period in **nanoseconds**. Requires `WRITE`.
pub fn pwm_set_period_typed(cap: u32, period_ns: u32) -> isize {
    unsafe { syscall2(SYS_PWM_SET_PERIOD_TYPED, cap as u64, period_ns as u64) }
}

/// Set the PWM duty in **nanoseconds**. Requires `WRITE`.
pub fn pwm_set_duty_typed(cap: u32, duty_ns: u32) -> isize {
    unsafe { syscall2(SYS_PWM_SET_DUTY_TYPED, cap as u64, duty_ns as u64) }
}

/// Set the PWM duty as a percentage (0..=100). Requires `WRITE`.
pub fn pwm_set_duty_pct_typed(cap: u32, pct: u32) -> isize {
    unsafe { syscall2(SYS_PWM_SET_DUTY_PCT_TYPED, cap as u64, pct as u64) }
}

/// Set the target speed of both wheels behind a `Cap<Motor>`.
///
/// ABI: the kernel reads the **low 16 bits** of a1/a2 as `i16`, so a speed
/// outside `i16` is silently truncated by the register, not rejected.
/// Requires `WRITE`.
pub fn motor_set_target_typed(cap: u32, speed_l: i16, speed_r: i16) -> isize {
    unsafe {
        syscall3(SYS_MOTOR_SET_TARGET_TYPED, cap as u64,
                 speed_l as u16 as u64, speed_r as u16 as u64)
    }
}

/// Bytes written by [`motor_tick_typed`]: `pwm_l i32 LE`, `pwm_r i32 LE`.
pub const MOTOR_TICK_BYTES: usize = 8;

/// Run one control tick on a `Cap<Motor>` and read the resulting PWM pair
/// into `out` (≥ [`MOTOR_TICK_BYTES`]). Requires `WRITE`.
/// Returns [`MOTOR_TICK_BYTES`] on success.
pub fn motor_tick_typed(cap: u32, ticks_l: i64, ticks_r: i64, now: u64, out: &mut [u8]) -> isize {
    if out.len() < MOTOR_TICK_BYTES {
        return E_INVAL;
    }
    unsafe {
        syscall5(SYS_MOTOR_TICK_TYPED, cap as u64,
                 ticks_l as u64, ticks_r as u64, now, out.as_mut_ptr() as u64)
    }
}

/// Enable (`1`) or disable (`0`) the motor behind a `Cap<Motor>`.
/// Requires `WRITE`.
pub fn motor_enable_typed(cap: u32, on: u64) -> isize {
    unsafe { syscall2(SYS_MOTOR_ENABLE_TYPED, cap as u64, on) }
}

/// Is the motor behind a `Cap<Motor>` enabled? Requires `READ`.
/// Returns 0 or 1.
pub fn motor_enabled_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_MOTOR_ENABLED_TYPED, cap as u64) }
}

/// Set the PID gains of a `Cap<Motor>`. Requires `WRITE`.
pub fn motor_set_gains_typed(cap: u32, kp: i32, ki: i32, kd: i32) -> isize {
    unsafe {
        syscall4(SYS_MOTOR_SET_GAINS_TYPED, cap as u64,
                 kp as u32 as u64, ki as u32 as u64, kd as u32 as u64)
    }
}

/// Reset the controller state behind a `Cap<Motor>`. Requires `WRITE`.
pub fn motor_reset_typed(cap: u32) -> isize {
    unsafe { syscall1(SYS_MOTOR_RESET_TYPED, cap as u64) }
}

/// Bytes [`link_key_read_typed`] copies on success: the brain-link PSK.
pub const LINK_KEY_BYTES: usize = 32;

/// Read the 32-byte brain-link PSK from the kernel's reserved sector behind
/// a `Cap<LinkKey>` into `buf` (≥ [`LINK_KEY_BYTES`]). Requires `READ`. Get
/// the handle with [`cap_lookup`]`(CapKind::LinkKey as u8, 0)` — singleton,
/// like the buzzer: there is exactly one brain-link key per board, so the
/// resource is always `0`.
///
/// U06-9 (2026-09-26): replaces reading `/fat/LINK.KEY` directly — the
/// kernel keeps the key off the exported FAT volume now, in a reserved tail
/// sector no USB host can address (`kernel/src/msc_gadget.rs`).
///
/// Returns [`LINK_KEY_BYTES`] on success, or `-Errno`: `-ECAPSTALE`/
/// `-ECAPKIND`/`-ECAPPERMS` for a refused capability; `-EAUTH` if the kernel
/// holds no key (absent, unprovisioned image, or all-zero) — the same
/// outcome reading `/fat/LINK.KEY` used to give when the file was missing,
/// just from inside the syscall instead of a FAT read.
pub fn link_key_read_typed(cap: u32, buf: &mut [u8]) -> isize {
    if buf.len() < LINK_KEY_BYTES {
        return E_INVAL;
    }
    unsafe {
        syscall3(
            SYS_LINK_KEY_READ_TYPED,
            cap as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

/// Largest read [`entropy_read_typed`] accepts: 256 bytes, the
/// `getentropy(3)` bound.
pub use azos_abi::syscall_nr::ENTROPY_READ_MAX;

/// Fill `buf` (1..=[`ENTROPY_READ_MAX`] bytes) from the kernel entropy pool
/// behind a `Cap<Entropy>`. Requires `READ`. Get the handle with
/// [`cap_lookup`]`(CapKind::Entropy as u8, 0)` — singleton, like the link key.
///
/// Returns `buf.len()` on success, or `-Errno`: `-ECAPSTALE`/`-ECAPKIND`/
/// `-ECAPPERMS` for a refused capability; `-ENODEV` if the pool is unseeded
/// (no entropy source fed it at boot — nothing seeds it later in the same
/// boot, so retrying does not help; `buf` is left untouched). An empty or
/// oversized `buf` answers [`E_INVAL`] without an `ecall`.
pub fn entropy_read_typed(cap: u32, buf: &mut [u8]) -> isize {
    if buf.is_empty() || buf.len() > ENTROPY_READ_MAX {
        return E_INVAL;
    }
    unsafe {
        syscall3(
            SYS_ENTROPY_READ_TYPED,
            cap as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

// ---------------------------------------------------------------------------
// Lease IPC (RFC-0031), ring-3 wrappers — wave 9
// ---------------------------------------------------------------------------

use azos_abi::syscall_nr::{
    SYS_IPC_LEASE_ACCEPT, SYS_IPC_LEASE_FREE, SYS_IPC_LEASE_GRANT_TYPED, SYS_IPC_LEASE_RETURN,
    SYS_IPC_LEASE_WAIT,
};

/// Grant the shared-memory region `shm` names (a `Cap<Shm>` with `READ`, as
/// [`shm_create_typed`] returns) to `lessee` (`expire_ticks` = 0: never
/// expires). Returns the lease id; the kernel also mints a `Cap<Lease>` for it
/// (find it with [`cap_lookup`]`(CapKind::Lease as u8, lease_id)`).
/// `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` for a refused capability,
/// `-EQUOTA`, `-1`.
pub fn lease_grant(shm: u32, lessee: u32, expire_ticks: u64) -> isize {
    unsafe { syscall3(SYS_IPC_LEASE_GRANT_TYPED, shm as u64, lessee as u64, expire_ticks) }
}

pub use azos_abi::syscall_nr::LEASE_GRANT_SEAL;

/// [`lease_grant`] with grant flags in the high half of the lessee word
/// (wave 11): [`LEASE_GRANT_SEAL`] makes this task's own mapping of the
/// region read-only until the lease ends — a write in between kills the task.
/// Any other flag is `-EINVAL`. `expire_ticks` is on the time counter
/// (`uptime`'s unit), absolute; 0 = none.
pub fn lease_grant_flags(shm: u32, lessee: u32, flags: u64, expire_ticks: u64) -> isize {
    unsafe { syscall3(SYS_IPC_LEASE_GRANT_TYPED, shm as u64, lessee as u64 | flags, expire_ticks) }
}

/// Accept a lease `lessor` granted to the caller, blocking (bounded) until one
/// arrives. Returns the lease id, or -1.
pub fn lease_accept(lessor: u32) -> isize {
    unsafe { syscall1(SYS_IPC_LEASE_ACCEPT, lessor as u64) }
}

/// Accept a lease `lessor` granted to the caller AND map its region for the
/// life of the lease (`SYS_IPC_LEASE_ACCEPT_MAP`, 613). `Ok((lease_id, va))`; the
/// mapping disappears when the lease ends (return, expiry, the lessor's free
/// or exit), and touching it afterwards kills the task. `Err(rc)`: `-1` as
/// [`lease_accept`], `-EFAULT`/`-EINVAL`/`-ENOMEM` otherwise.
pub fn lease_accept_map(lessor: u32) -> Result<(u64, usize), isize> {
    let mut va: u64 = 0;
    let rc = unsafe {
        syscall2(SYS_IPC_LEASE_ACCEPT_MAP, lessor as u64, &mut va as *mut u64 as u64)
    };
    if rc < 0 { Err(rc) } else { Ok((rc as u64, va as usize)) }
}

/// Lessee: give the buffer back. 0, or -1 (not the lessee / not active).
pub fn lease_return(lease_id: u64) -> isize {
    unsafe { syscall1(SYS_IPC_LEASE_RETURN, lease_id) }
}

/// Lessor: free the lease entry (and lose its `Cap<Lease>`). 0, or -1.
pub fn lease_free(lease_id: u64) -> isize {
    unsafe { syscall1(SYS_IPC_LEASE_FREE, lease_id) }
}

/// Lessor: block until the lease behind `cap` (`Cap<Lease>`, `READ`) is
/// returned (`0`) or expires (`1`), lending the caller's priority to the
/// lessee meanwhile. `-1`: freed, or not the caller's lease; `-ECAPSTALE` /
/// `-ECAPKIND` / `-ECAPPERMS` for a refused capability.
pub fn lease_wait(cap: u32) -> isize {
    unsafe { syscall1(SYS_IPC_LEASE_WAIT, cap as u64) }
}

// ===========================================================================
//  The user shell's calls and the process startup (RFC-0055, wave 11)
// ===========================================================================

pub use azos_abi::ushell::{
    SpawnReq, Move, StartupBlock, StartupFd, MOVE_CONSOLE, PIPE_NONBLOCK, SPAWN_F_DIE_WITH_PARENT, SPAWN_F_CONSOLE_IN,
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
    p.fds = FdTable::fd_table_from_startup(&sb.fds);
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

/// Create a pipe (`SYS_PIPE_TYPED`): `out[0]` the read end, `out[1]` the
/// write end, both capability handles. 0, or a negative errno.
pub fn pipe_typed(out: &mut [u32; 2], flags: u64) -> isize {
    unsafe { syscall2(SYS_PIPE_TYPED, out.as_mut_ptr() as u64, flags) }
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

/// Wait for console input or a child's exit (`SYS_CONSOLE_WAIT`): bytes
/// read, 0 on timeout, `E_INTR` for a pending exit notice or a stop request,
/// `-EBUSY` when another task owns console input. An empty `buf` waits only
/// for a child's exit or the timeout.
pub fn console_wait(buf: &mut [u8], timeout_ns: u64) -> isize {
    unsafe { syscall4(SYS_CONSOLE_WAIT, buf.as_mut_ptr() as u64, buf.len() as u64, timeout_ns, 0) }
}

/// Ask descendant `tid` to stop (`SYS_TASK_KILL`): `how` is `KILL_REQUEST` or
/// `KILL_FORCE`, `flags` `KILL_SUBTREE` or 0. Tasks signalled, or a negative
/// errno (`-ESRCH` for anything not a descendant).
pub fn task_kill(tid: u32, how: u64, signo: u64, flags: u64) -> isize {
    unsafe { syscall4(SYS_TASK_KILL, tid as u64, how, signo, flags) }
}

/// The power family's operations and limits (`POWER_OP_*`).
pub use azos_abi::power;

/// The power family (`SYS_POWER_TYPED`, RFC-0055 S5): operation `op`
/// (`azos_abi::power::POWER_OP_*`) with argument `arg`, under the
/// `Cap<Power>` handle `cap`. 0 or the rate read, else a negative errno
/// (`-ECAPPERMS` etc. without the capability). Reboot and shutdown do not
/// return.
pub fn power_typed(cap: u32, op: u64, arg: u64) -> isize {
    unsafe { syscall3(SYS_POWER_TYPED, cap as u64, op, arg) }
}

/// The kernel tracer's operations, classes and event ids (wave 15).
pub use azos_abi::trace as trace_abi;

/// The kernel tracer's control (`SYS_TRACE_CTL_TYPED`, wave 15): operation
/// `op` (`azos_abi::trace::TRACE_OP_*`) with argument `arg`, under the
/// `Cap<Trace>` handle `cap`. The operation's value (`TRACE_OP_MAP`: the
/// region's address), else a negative errno (`-ENOSYS` with the tracer
/// compiled out, `-ECAPPERMS` etc. without the capability).
pub fn trace_ctl_typed(cap: u32, op: u64, arg: u64) -> isize {
    unsafe { syscall3(SYS_TRACE_CTL_TYPED, cap as u64, op, arg) }
}

/// The flight, behavior, config and OTA families' operations and limits
/// (wave 12).
pub use azos_abi::families;

/// The flight family (`SYS_FLIGHT_TYPED`, wave 12): `FLIGHT_OP_ARM` /
/// `FLIGHT_OP_DISARM` under the `Cap<Motor>` handle `cap` (the caller must
/// hold WRITE on both wheels). 0, or a negative errno.
pub fn flight_typed(cap: u32, op: u64) -> isize {
    unsafe { syscall3(SYS_FLIGHT_TYPED, cap as u64, op, 0) }
}

/// The behavior family (`SYS_BEHAVIOR_TYPED`, wave 12): enable or disable
/// `layer`, or read the enabled-layer mask (`layer` 0), under `Cap<Power>`.
pub fn behavior_typed(cap: u32, op: u64, layer: u64) -> isize {
    unsafe { syscall3(SYS_BEHAVIOR_TYPED, cap as u64, op, layer) }
}

/// The config family (`SYS_CONFIG_TYPED`, wave 12): `CONFIG_OP_GET` copies
/// the value of `key` into `val` (its length returned), `CONFIG_OP_SET` sets
/// `key` to `val` and applies it, under `Cap<Power>`.
pub fn config_typed(cap: u32, op: u64, key: &[u8], val: &mut [u8]) -> isize {
    unsafe {
        syscall6(SYS_CONFIG_TYPED, cap as u64, op, key.as_ptr() as u64, key.len() as u64,
                 val.as_mut_ptr() as u64, val.len() as u64)
    }
}

/// The OTA family (`SYS_OTA_TYPED`, wave 12): the packed status word
/// (`families::ota_status_unpack`) or a rollback, under `Cap<Power>`.
pub fn ota_typed(cap: u32, op: u64) -> isize {
    unsafe { syscall3(SYS_OTA_TYPED, cap as u64, op, 0) }
}

/// `SYS_MODULE_VERIFY` (RFC-0053 L0b): ask the kernel to check the module
/// FILE bytes `module` against its digest table under the 8.3 `name`.
/// Returns a one-shot token (`> 0`) for [`module_map_x`], `-EPERM` when the
/// bytes or the name are not in the table (the kernel records it), or
/// `-ENOSYS` on a kernel built without the `lx-loader` feature.
pub fn module_verify(module: &[u8], name: &[u8]) -> isize {
    unsafe {
        syscall4(SYS_MODULE_VERIFY, module.as_ptr() as u64, module.len() as u64,
                 name.as_ptr() as u64, name.len() as u64)
    }
}

/// `SYS_MODULE_MAP_X` (RFC-0053 L0b): turn the caller's relocated module
/// text at `addr` (page-aligned, `len` bytes, the caller's own anonymous
/// memory) from read-write into read-execute. Consumes `token` whatever the
/// outcome. `0`, `-EPERM` (token) or `-EINVAL` (range).
pub fn module_map_x(token: u64, addr: u64, len: u64) -> isize {
    unsafe { syscall3(SYS_MODULE_MAP_X, token, addr, len) }
}
