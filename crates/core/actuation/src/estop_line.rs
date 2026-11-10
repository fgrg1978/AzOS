// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The UART e-stop line at boot. A robot claims the bridge's line for the
//! kernel's e-stop reader; the line is read only once the bridge is
//! initialised, so the claim and the initialisation are one step and its
//! outcome is said: a board with the bridge whose line does not respond has
//! no e-stop channel and does not boot as a robot.

/// What the claim found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Line {
    /// The bridge answered: the kernel reads e-stop frames from it.
    Ready,
    /// This build has no bridge hardware (QEMU, K1): there is no line, and
    /// the other e-stop sources are the ones in force.
    NoBridge,
    /// The build has the bridge and it did not respond.
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

/// Say what the claim found. `false`: the robot must not boot.
pub fn report(line: Line) -> bool {
    match line {
        Line::Ready => azos_drv_sys::kprintln!("[SAFETY] UART e-stop line ready"),
        Line::NoBridge => azos_drv_sys::kwarn!("[SAFETY] UART e-stop line ABSENT: no bridge hardware in this build"),
        Line::Dead => azos_drv_sys::kwarn!("[SAFETY] UART e-stop line DEAD: the bridge UART does not respond; refusing to boot a robot without it"),
    }
    line != Line::Dead
}
