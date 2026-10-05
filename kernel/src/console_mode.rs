// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Who has the console (RFC-0055 §5.9): the ring-3 user shell (`SH.ELF`), or
//! the in-kernel shell as a recovery console.
//!
//! States: `Pending` (boot, the user shell has not taken input yet),
//! `UserUp` (it owns console input), `Restarting` (it died and the supervisor
//! is restarting it), `Recovery` (the kernel shell has the console, for good).
//!
//! Input ownership itself is `azos_drv_sys::uart::CONSOLE_RX`, claimed
//! atomically: the user shell claims it with its first `SYS_CONSOLE_WAIT`, the
//! recovery console here before its first `readline`. Whoever claims second is
//! refused, so the two never both read. This module only decides when the
//! kernel shell may try:
//!
//! * at once, in safe mode, with `USER_SHELL` off, when the topology does not
//!   start `SH.ELF`, or when the volume has no `/fat/SH.ELF`;
//! * after the supervisor gave up on the user shell, or it exited 0 (a row
//!   key `restart = always` is not in the parser yet, so `exit` is not a
//!   respawn);
//! * when the user shell has not taken input within `SH_START_TIMEOUT_S` of
//!   boot or of its last death (the actuation gate missing, a respawn that
//!   keeps failing before it reads).
//!
//! Under `CONSOLE_LOCKDOWN` the kernel shell is not created at all
//! (`kernel_main`).

use core::sync::atomic::{AtomicU8, Ordering};

use azos_drv_sys::console_rx::{Claim, RX_OWNER_KERNEL, RX_OWNER_NONE};
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_drv_sys::uart::CONSOLE_RX;

const PENDING: u8 = 0;
const USER_UP: u8 = 1;
const RESTARTING: u8 = 2;
const RECOVERY: u8 = 3;

static MODE: AtomicU8 = AtomicU8::new(PENDING);

/// When the loader last started `SH.ELF` (timebase ticks), 0 = not yet. The
/// start timeout runs from here as well as from boot: a slow boot (four
/// gate QEMUs on one host) must not hand the console over while the shell's
/// image is still being loaded.
static STARTED_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The loader (or the supervisor) has just started the user shell.
pub(crate) fn note_user_shell_started() {
    STARTED_AT.store(now(), Ordering::Release);
}

/// The user shell's image, as `/fat/` plus its topology row's name.
pub(crate) const SH_PATH: &[u8] = b"/fat/SH.ELF";

fn sh_row_starts() -> bool {
    azos_topology::get().is_some_and(|t| {
        t.find_task(&azos_topology::MaybeStr::from_bytes(&SH_PATH[5..])).is_some_and(|r| r.start)
    })
}

fn sh_on_volume() -> bool {
    let mut fds = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fds, SH_PATH, azos_fs::O_RDONLY);
    if fd < 0 {
        return false;
    }
    azos_fs::vfs_close(&mut fds, fd);
    true
}

/// Why the kernel shell takes the console at boot, or `None` if the user
/// shell is expected.
fn recovery_reason_at_boot() -> Option<&'static str> {
    if !azos_limits::USER_SHELL {
        Some("USER_SHELL is off")
    } else if azos_actuation::estop::safe_mode_active() {
        Some("safe mode")
    } else if !sh_row_starts() {
        Some("the topology does not start SH.ELF")
    } else if !sh_on_volume() {
        Some("no /fat/SH.ELF on this volume")
    } else {
        None
    }
}

/// The user shell's input ownership was released by its exit (the task-exit
/// hook). `restarting`: the supervisor will start it again.
pub(crate) fn user_shell_exited(tid: u32, restarting: bool) {
    if restarting {
        MODE.store(RESTARTING, Ordering::Release);
        kprintln!("[CONSOLE] user shell tid={} exited: restarting", tid);
    } else {
        MODE.store(RECOVERY, Ordering::Release);
        azos_drv_sys::kwarn!("[CONSOLE] user shell tid={} gave up: recovery console", tid);
    }
}

/// The kernel shell task's gate: returns when the recovery console owns
/// console input, and never returns while a user shell does.
pub(crate) fn wait_for_recovery() {
    let timeout = azos_limits::SH_START_TIMEOUT_S as u64 * TIMER_FREQ;
    match recovery_reason_at_boot() {
        Some(why) => {
            MODE.store(RECOVERY, Ordering::Release);
            azos_drv_sys::kwarn!("[CONSOLE] recovery console: {}", why);
        }
        None => kprintln!("[CONSOLE] user shell pending (recovery console after {} s without it)",
                          azos_limits::SH_START_TIMEOUT_S),
    }
    let mut since = now();
    loop {
        let owner = CONSOLE_RX.owner();
        let mode = MODE.load(Ordering::Acquire);
        since = since.max(STARTED_AT.load(Ordering::Acquire));
        if mode == RECOVERY {
            match CONSOLE_RX.claim(RX_OWNER_KERNEL) {
                Claim::Got | Claim::Already => return,
                // A user shell holds input: it is alive, so it is up.
                Claim::Busy(_) => {}
            }
        }
        if owner != RX_OWNER_NONE && owner != RX_OWNER_KERNEL {
            if mode != USER_UP {
                MODE.store(USER_UP, Ordering::Release);
                kprintln!("[CONSOLE] user shell tid={} has the console", owner);
            }
            since = now();
        } else if mode != RECOVERY && now().saturating_sub(since) > timeout {
            MODE.store(RECOVERY, Ordering::Release);
            azos_drv_sys::kwarn!("[CONSOLE] user shell did not take the console within {} s: recovery console",
                      azos_limits::SH_START_TIMEOUT_S);
            continue;
        }
        azos_syscall::sleep::sleep_ms(100);
    }
}
