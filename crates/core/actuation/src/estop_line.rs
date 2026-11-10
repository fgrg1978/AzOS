// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The UART e-stop line at boot. A robot claims the bridge's line for the
//! kernel's e-stop reader; the line is read only once the SoC's UART is
//! initialised, so the claim and the initialisation are one step and its
//! outcome is said. A build with the bridge whose UART does not answer, or
//! fails a loopback of a byte, has no e-stop channel: the robot boots, with the
//! e-stop latched (no motion) until the operator's signed release. What it
//! does not check is the far side: the ESP32 relay answers no probe.

use core::sync::atomic::{AtomicU8, Ordering};

/// What the claim found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Line {
    /// The SoC's UART answered and carried a byte of its own back: the kernel
    /// reads e-stop frames from it.
    Ready,
    /// This build has no bridge hardware (QEMU, K1): there is no line, and
    /// the other e-stop sources are the ones in force.
    NoBridge,
    /// The build has the bridge and its UART did not answer or did not carry a
    /// byte back.
    Dead,
}

/// The line's state: `bridge_in_build` is whether the build has the bridge,
/// `initialised` whether its initialisation succeeded.
pub const fn line(bridge_in_build: bool, initialised: bool) -> Line {
    if cfg!(feature = "estop-line-dead-ready-canary") {
        return if bridge_in_build { Line::Ready } else { Line::NoBridge };
    }
    match (bridge_in_build, initialised) {
        (_, true) => Line::Ready,
        (false, false) => Line::NoBridge,
        (true, false) => Line::Dead,
    }
}

/// Say what the claim found. `false`: the e-stop must be latched.
pub fn report(line: Line) -> bool {
    match line {
        Line::Ready => azos_drv_sys::kprintln!("[SAFETY] UART e-stop line ready (the SoC UART answered; the far side is not probed)"),
        Line::NoBridge => azos_drv_sys::kwarn!("[SAFETY] UART e-stop line ABSENT: no bridge hardware in this build"),
        Line::Dead => azos_drv_sys::kerr!("[SAFETY] UART e-stop line DEAD: the SoC UART does not answer or fails its loopback; the e-stop is latched until the operator's signed release"),
    }
    line != Line::Dead
}

static DEAD: AtomicU8 = AtomicU8::new(0);

/// Remember a dead line for the enforcer's first pass, which latches the
/// e-stop and records it (the latch's stop work and the flight recorder are
/// not up when the line is claimed).
pub fn mark_dead() {
    DEAD.store(1, Ordering::Release);
}

/// Whether a dead line is waiting to be latched and recorded: once.
pub fn take_dead() -> bool {
    DEAD.swap(0, Ordering::AcqRel) != 0
}
