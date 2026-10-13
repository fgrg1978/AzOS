// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System devices every image needs: the console UART (`kprint!`/`kprintln!`,
//! deferred console lines, console input), the monotonic clock and timer
//! programming (`timebase`, `timer_arm`), the hardware watchdog, the WCET
//! instrumentation points, and the kernel-side proxy for ring-3 drivers.
//!
//! The console and the clock are one crate because each calls the other:
//! `uart` reads `timebase::now()` for its deadlines, and `timebase` asks
//! `uart::console_stranded()` before letting an idle hart sleep without a
//! poll timer.

#![no_std]

pub mod uart;

/// Ring-3 console ownership and deferred kernel lines (wave 9); see
/// `uart::console_write_ring3`.
pub mod console_defer;

// RFC-0055 (wave 11): the one owner of console input.
pub mod console_rx;

// First Driver trait migration (A3a). The legacy `uart` module
// stays for `kprint!` + early-boot panic path; this provides the
// unified API for client tasks via `runtime::REGISTRY`.
pub mod uart_driver;

// Kernel-side proxy that adapts a userspace driver (registered via
// `azos_driver_server`) to the `Driver` trait. Together with
// `uart_driver` this proves the same trait spans both
// `DriverIsolation` variants.
pub mod user_driver_proxy;

/// The monotonic clock under an ISA-neutral name — see the module docs for
/// why 129 call sites used to read it as `clint::get_time()`.
pub mod timebase;

/// The next-timer-event arithmetic `timebase` programs, with no hardware in
/// it (host-tested in `tests/host/drivers-tests`).
pub mod timer_arm;

/// Rate limit for a console report (`printk_ratelimit`'s shape), with no
/// hardware in it (host-tested in `tests/host/drivers-tests`).
pub mod ratelimit;

impl ratelimit::RateLimit {
    /// [`check_at`](ratelimit::RateLimit::check_at) now, on this board's
    /// timebase.
    pub fn check(&self) -> Option<u32> {
        self.check_at(timebase::now(), timebase::TIMER_FREQ)
    }
}

// Re-export Uart at crate root: `wcet`'s interrupt-context report writes through
// `crate::Uart`. The kprint!/kprintln! macros go through `uart::kernel_print`.
pub use uart::Uart;

// Hardware watchdog timer (DesignWare WDT on VF2/K1; no-op on QEMU).
pub mod wdt;

// F16: WCET (Worst-Case Execution Time) instrumentation — cycle-accurate
// timing using rdcycle CSR + atomic statistics per named measurement point.
pub mod wcet;
