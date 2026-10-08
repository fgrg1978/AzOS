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
//! * at once, in safe mode, with no console program (`CONSOLE_PROGRAM_NONE`),
//!   when the topology does not start it, or when the volume does not carry
//!   it. The console program is Kconfig `CONSOLE_PROGRAM` (`SH.ELF` by
//!   default), or `init=` from the kernel command line with secure boot off;
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

/// When the loader last started the console program (timebase ticks), 0 = not yet. The
/// start timeout runs from here as well as from boot: a slow boot (four
/// gate QEMUs on one host) must not hand the console over while the shell's
/// image is still being loaded.
static STARTED_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The loader (or the supervisor) has just started the user shell.
pub(crate) fn note_user_shell_started() {
    STARTED_AT.store(now(), Ordering::Release);
}

/// "/fat/" plus an 8.3 name.
const PATH_MAX: usize = 5 + 12;

/// The console program's image: `/fat/` plus its topology row's name.
#[derive(Clone, Copy)]
pub(crate) struct ConsolePath {
    buf: [u8; PATH_MAX],
    len: u8,
    /// From `init=` on the kernel command line, not from Kconfig.
    pub(crate) overridden: bool,
}

impl ConsolePath {
    const fn new(path: &[u8], overridden: bool) -> Option<Self> {
        if path.len() <= 5 || path.len() > PATH_MAX {
            return None;
        }
        let mut buf = [0u8; PATH_MAX];
        let mut i = 0;
        while i < path.len() {
            buf[i] = path[i];
            i += 1;
        }
        Some(Self { buf, len: path.len() as u8, overridden })
    }
    /// `/fat/NAME.ELF`.
    pub(crate) fn path(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
    /// `NAME.ELF`, the topology row's name.
    pub(crate) fn name(&self) -> &[u8] {
        &self.path()[5..]
    }
    fn shown(&self) -> &str {
        core::str::from_utf8(self.path()).unwrap_or("?")
    }
}

/// Kconfig's console program (CONSOLE_PROGRAM -> CONSOLE_PATH), `None` for
/// CONSOLE_PROGRAM_NONE. `azos_limits`' build script refused any other shape.
const CONFIGURED: Option<ConsolePath> = ConsolePath::new(azos_limits::CONSOLE_PATH.as_bytes(), false);

/// The topology row of Kconfig's console program, empty without one.
pub(crate) fn configured_row() -> &'static [u8] {
    match &CONFIGURED {
        Some(_) => azos_limits::CONSOLE_PATH.as_bytes().split_at(5).1,
        None => b"",
    }
}

/// `init=` from the kernel command line, when it was honoured.
static INIT: azos_sync::SpinLock<Option<ConsolePath>> = azos_sync::SpinLock::new(None);

/// The console program of this boot: `init=` when it was honoured, else
/// Kconfig's, `None` for none.
pub(crate) fn console_path() -> Option<ConsolePath> {
    (*INIT.lock()).or(CONFIGURED)
}

/// Read the kernel command line (`/chosen/bootargs`) once at boot, before
/// any ring-3 program starts, and honour `init=/fat/NAME.ELF` only with
/// secure boot off and Kconfig `KERNEL_CMDLINE_INIT` (see its help).
pub(crate) fn read_cmdline(dtb_ptr: usize) {
    if dtb_ptr == 0 {
        return;
    }
    let mut line = [0u8; azos_limits::KERNEL_CMDLINE_MAX as usize];
    let n = match unsafe {
        azos_dtb::dtb_bootargs(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8, &mut line)
    } {
        Some(n) => n,
        None => return,
    };
    let line = &line[..n];
    if !line.is_empty() {
        kprintln!("[CMDLINE] {}", core::str::from_utf8(line).unwrap_or("(not UTF-8)"));
    }
    let Some(init) = line.split(|&b| b == b' ').find_map(|w| w.strip_prefix(b"init=")) else {
        return;
    };
    let shown = core::str::from_utf8(init).unwrap_or("?");
    if cfg!(feature = "secure-boot-enforced") && !cfg!(feature = "cmdline-init-canary") {
        azos_drv_sys::kwarn!("[CONSOLE] init={} ignored: secure boot is on", shown);
        return;
    }
    if !azos_limits::KERNEL_CMDLINE_INIT {
        azos_drv_sys::kwarn!("[CONSOLE] init={} ignored: KERNEL_CMDLINE_INIT is off", shown);
        return;
    }
    let name_ok = init.strip_prefix(b"/fat/").is_some_and(|n| {
        n.ends_with(b".ELF") && !n.contains(&b'/') && n.len() <= PATH_MAX - 5
    });
    match ConsolePath::new(init, true).filter(|_| name_ok) {
        Some(p) => {
            *INIT.lock() = Some(p);
            kprintln!("[CONSOLE] init={}: the console program of this boot (secure boot off)", shown);
        }
        None => azos_drv_sys::kwarn!("[CONSOLE] init={} ignored: not an 8.3 image directly under /fat", shown),
    }
}

/// Is `image` (a `/fat/` path) this boot's console program?
pub(crate) fn is_console_path(image: &[u8]) -> bool {
    console_path().is_some_and(|c| c.path() == image)
}

fn console_row_starts(c: &ConsolePath) -> bool {
    azos_topology::get().is_some_and(|t| {
        t.find_task(&azos_topology::MaybeStr::from_bytes(c.name()))
            .is_some_and(|r| r.start || c.overridden)
    })
}

fn console_on_volume(c: &ConsolePath) -> bool {
    let mut fds = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fds, c.path(), azos_fs::O_RDONLY);
    if fd < 0 {
        return false;
    }
    azos_fs::vfs_close(&mut fds, fd);
    true
}

/// Why the kernel shell takes the console at boot, or `None` if the user
/// shell is expected.
fn recovery_reason_at_boot() -> Option<&'static str> {
    let Some(c) = console_path() else {
        return Some("no console program (CONSOLE_PROGRAM_NONE)");
    };
    if azos_actuation::estop::safe_mode_active() {
        Some("safe mode")
    } else if !console_row_starts(&c) {
        kprintln!("[CONSOLE] console program {}: the topology does not start it", c.shown());
        Some("the topology does not start the console program")
    } else if !console_on_volume(&c) {
        kprintln!("[CONSOLE] console program {}: not on this volume", c.shown());
        Some("the console program is not on this volume")
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
