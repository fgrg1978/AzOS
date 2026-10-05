// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 syscall latency microbenchmark.
//!
//! The point is not "syscalls take N ns" — on QEMU TCG that number means
//! little in absolute terms. The point is the *differences* between the
//! measurements, which isolate where the time goes:
//!
//!   floor        `getpid()`                — trap in, dispatch, trap out. No
//!                                              capability, no user copy.
//!   typed-hit    `sensor_read_typed(IMU)`  — + resolving a `Cap<Sensor>` at
//!                                              its slot in the task's own
//!                                              table, + a 24-byte copy out.
//!   typed-hit    `motor_speed_typed(L,0)`  — + resolving a `Cap<Motor>` and
//!                                              stopping the wheel. No copy.
//!   typed-miss   `sensor_read_typed(0)`    — + a handle naming an empty
//!                                              slot, refused as stale, + the
//!                                              bounded denial-record path.
//!   untyped-miss `adc_read(0)`             — + `cap_check` searching every
//!                                              slot for an `Adc` capability
//!                                              no table holds, + the same
//!                                              record path.
//!
//! `typed-miss` minus `floor` is what a refused handle costs; `untyped-miss`
//! minus `typed-miss` is roughly the whole-table search the untyped check
//! does in place of an indexed lookup. A robot's control loop pays a hit path
//! every tick, and any forged or ungranted resource pays a miss path. Handles
//! are looked up once, before any batch, so no lane pays `cap_lookup`.
//!
//! Timing uses `rdtime` (CLINT mtime, 10 MHz on QEMU virt = 100 ns/tick), so
//! a single call is below the clock's resolution — everything is measured in
//! batches and divided. `scounteren = 0x7` in `trap_init` is what makes the
//! counter readable from U-mode at all.

#![no_std]
#![no_main]

use azos_libsys as sys;

/// Iterations per batch. Large enough that the 100 ns tick granularity is
/// noise against the total, small enough to finish promptly under TCG.
const N: u64 = 2000;

/// CLINT mtime frequency on QEMU virt (RISC-V; see `scale_ticks` for aarch64).
#[cfg(not(target_arch = "aarch64"))]
const TIMER_HZ: u64 = 10_000_000;

/// Counter ticks → nanoseconds, integer-only: `ticks * 1e9 / hz / iters`.
///
/// **The frequency is per ISA, and on aarch64 it is read, not assumed.** The
/// `TIMER_HZ` constant is RISC-V's `time` CSR on QEMU virt. aarch64's
/// `cntvct_el0` runs at whatever `CNTFRQ_EL0` says — 1 GHz under QEMU
/// `-cpu max` — and dividing it by RISC-V's 10 MHz made every aarch64 figure
/// read 100x too high (a 41,300-"instruction" syscall floor on 2026-09-22).
/// `CNTFRQ_EL0` is readable at EL0 whenever `cntvct_el0` is, which this
/// binary already relies on. RISC-V keeps its original expression unchanged.
#[inline(always)]
fn scale_ticks(ticks: u64, iters: u64) -> u64 {
    #[cfg(not(target_arch = "aarch64"))]
    { ticks * (1_000_000_000 / TIMER_HZ) / iters }
    #[cfg(target_arch = "aarch64")]
    {
        let hz: u64;
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) hz, options(nomem, nostack)) };
        // u128: at 1 GHz, `ticks * 1e9` overflows u64 after ~18 s of ticks.
        (ticks as u128 * 1_000_000_000 / hz.max(1) as u128 / iters.max(1) as u128) as u64
    }
}

#[inline(always)]
fn rdtime() -> u64 {
    let t: u64;
    // aarch64 twin: `cntvct_el0`, the generic timer's virtual counter — see
    // `crates/core/libsys/src/lib.rs`'s `read_time_csr` for the same pairing and
    // the `CNTKCTL_EL1.EL0VCTEN` caveat it documents.
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack)) };
    t
}

fn print_u(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if n == 0 { i -= 1; buf[i] = b'0'; }
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    sys::print(&buf[i..]);
}

/// Report one batch as nanoseconds per operation.
fn report(label: &[u8], ticks: u64) {
    // ticks * 1e9 / TIMER_HZ / N, ordered to avoid overflow and keep
    // integer precision (no FPU in this binary).
    let ns_per_op = scale_ticks(ticks, N);
    sys::print(b"[LATBENCH] ");
    sys::print(label);
    sys::print(b" = ");
    print_u(ns_per_op);
    sys::print(b" ns/op  (");
    print_u(ticks);
    sys::print(b" ticks / ");
    print_u(N);
    sys::print(b" ops)\n");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[LATBENCH] Starting - measuring ring-3 syscall latency");

    // The two capabilities the hit lanes resolve. A missing one ends the run
    // before `DONE`: a lane measuring a refusal it did not intend to measure
    // is worse than no number.
    let imu_cap = sys::cap_lookup(sys::CapKind::Sensor as u8, sys::SENSOR_TYPE_IMU as u32);
    let left_cap = sys::cap_lookup(sys::CapKind::Motor as u8, 0);
    if imu_cap < 0 || left_cap < 0 {
        sys::println(b"[LATBENCH] FATAL no Cap<Sensor>(IMU) or Cap<Motor>(0) to resolve");
        sys::exit(1);
    }
    let (imu_cap, left_cap) = (imu_cap as u32, left_cap as u32);

    // Warm up: first-touch page faults and I-cache misses belong to nobody.
    for _ in 0..64 { let _ = sys::getpid(); }

    let t0 = rdtime();
    for _ in 0..N { let _ = sys::getpid(); }
    let floor = rdtime() - t0;
    report(b"floor      getpid()        ", floor);

    let mut imu = [0u8; 24];
    let t0 = rdtime();
    for _ in 0..N { let _ = sys::sensor_read_typed(imu_cap, &mut imu); }
    let hit_copy = rdtime() - t0;
    report(b"typed-hit  sensor(IMU)+copy", hit_copy);

    let t0 = rdtime();
    for _ in 0..N { let _ = sys::motor_speed_typed(left_cap, 0); }
    let hit_motor = rdtime() - t0;
    report(b"typed-hit  motor(L,0)      ", hit_motor);

    // Handle 0 is `Cap::NULL`: a slot that holds nothing.
    let t0 = rdtime();
    for _ in 0..N { let _ = sys::sensor_read_typed(0, &mut imu); }
    let miss_typed = rdtime() - t0;
    report(b"typed-miss sensor(0)       ", miss_typed);

    let t0 = rdtime();
    for _ in 0..N { let _ = sys::adc_read(0); }
    let miss_untyped = rdtime() - t0;
    report(b"untyped-miss adc_read(0)   ", miss_untyped);

    // write() to stdout. Two sizes, because sys_write zeroes a fixed 4 KiB
    // kernel stack buffer regardless of `count` — if that memset dominates,
    // a 1-byte write costs about the same as a 64-byte one, and both cost
    // far more than the syscall floor.
    //
    // Writing to fd 2 (stderr) on purpose: it takes the same UART path as
    // stdout but keeps the benchmark's own report lines on fd 1 readable.
    // Far fewer iterations than the other batches: every one of these
    // actually reaches the console, and N=2000 x 64 bytes buried the report
    // itself under 128 KB of filler. WN is scaled back and `report_n` divides
    // by the right count.
    const WN: u64 = 100;
    let one = b"x";
    let t0 = rdtime();
    for _ in 0..WN { let _ = sys::console_write(2, one); }
    let w1 = (rdtime() - t0) * N / WN;   // normalise to the N-op scale
    report(b"write(2, 1 byte)           ", w1);

    let sixty4 = &[b'y'; 64];
    let t0 = rdtime();
    for _ in 0..WN { let _ = sys::console_write(2, sixty4); }
    let w64 = (rdtime() - t0) * N / WN;
    sys::print(b"\n");                    // close the filler line
    report(b"write(2, 64 bytes)         ", w64);

    // ── Deltas: the actual result ────────────────────────────────────────
    sys::println(b"[LATBENCH] ---- deltas vs floor ----");
    let d = |x: u64| -> u64 {
        if x > floor { scale_ticks(x - floor, N) } else { 0 }
    };
    sys::print(b"[LATBENCH] typed hit + 24B copy        = +");
    print_u(d(hit_copy));
    sys::print(b" ns\n[LATBENCH] typed hit, no copy          = +");
    print_u(d(hit_motor));
    sys::print(b" ns\n[LATBENCH] typed miss (stale handle)   = +");
    print_u(d(miss_typed));
    sys::print(b" ns\n[LATBENCH] untyped miss (table search) = +");
    print_u(d(miss_untyped));
    sys::println(b" ns");

    sys::print(b"[LATBENCH] write 1B vs floor           = +");
    print_u(d(w1));
    sys::print(b" ns\n[LATBENCH] write 64B vs floor          = +");
    print_u(d(w64));
    sys::println(b" ns");

    sys::println(b"[LATBENCH] DONE");
    sys::exit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    sys::println(b"[LATBENCH] PANIC");
    sys::exit(2);
}
