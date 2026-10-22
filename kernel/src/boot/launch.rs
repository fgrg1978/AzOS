// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot launcher: what the kernel itself starts in ring 3, and the plan it
//! hands the component manager.
//!
//! What starts at boot is declared in the signed topology, beside what each
//! image may touch (`start = true`). The ring-3 component manager
//! (`userspace/services/compmgr`) is the only supervisor of those rows, the
//! ring-3 host of a driver that moves between hosts (the buzzer) included: it
//! reads the plan from its view region (`inspect.components`)
//! (`boot::inspect_views`), starts each row with
//! `SYS_SPAWN_EX` and restarts it by the row's `restart` key and the failure
//! contract of what it serves. The placement controller (`crate::buzzer`)
//! neither starts nor ends that host: it only routes the kernel's calls
//! between the two hosts, and the ring-3 one stays up beside a kernel host.
//!
//! The kernel starts only
//!
//! * the manager itself, supervised by the kernel's driver supervisor
//!   (`drv_supervisor`). This is the one remaining kernel supervision of a
//!   ring-3 image, and it cannot be the manager's: a supervisor does not
//!   supervise itself, and nothing in ring 3 could restart the manager.
//!
//! Like `autorun_task`, nothing starts before the actuation gate is
//! installed, and nothing in safe mode.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::*;

/// "/fat/" plus an 8.3 name.
const PATH_MAX: usize = 5 + 12;

/// Words of the bitmap of rows the launcher found it cannot start.
const WORDS: usize = azos_limits::MAX_TASKS.div_ceil(64);

/// One bit per topology row: the launcher looked at the row and its image
/// cannot be started on this boot (the name is not an 8.3 image under `/fat`,
/// or the image is not on this volume). The plan the manager reads leaves
/// those rows out: they are said once, here, and skipped, not started and
/// restarted until a restart budget gives up on them.
static UNSTARTABLE: [AtomicU64; WORDS] = {
    const NONE: AtomicU64 = AtomicU64::new(0);
    [NONE; WORDS]
};

fn mark_unstartable(row: usize) {
    if let Some(w) = UNSTARTABLE.get(row / 64) {
        w.fetch_or(1 << (row % 64), Ordering::Release);
    }
    // The plan the manager reads says so before it runs.
    #[cfg(feature = "inspect")]
    super::inspect_views::component_unstartable(row);
}

/// Is row number `row` of the topology in the plan the manager is shown
/// (given that it starts at all)?
pub(crate) fn row_startable(row: usize) -> bool {
    UNSTARTABLE.get(row / 64).is_none_or(|w| w.load(Ordering::Acquire) & (1 << (row % 64)) == 0)
}

/// Is `r` the component manager's row?
pub(crate) fn is_component_manager(r: &azos_topology::TaskSpec) -> bool {
    r.name.as_bytes() == azos_topology::builder::TASK_COMPMGR_IMAGE
}

/// `/fat/<row name>`, `None` for a name that is not an 8.3 image directly
/// under `/fat`.
fn image_path(row: &azos_topology::TaskSpec, buf: &mut [u8; PATH_MAX]) -> Option<usize> {
    let name = row.name.as_bytes();
    if name.len() > PATH_MAX - 5 || name.contains(&b'/') || !name.ends_with(b".ELF") {
        return None;
    }
    buf[..5].copy_from_slice(b"/fat/");
    buf[5..5 + name.len()].copy_from_slice(name);
    Some(5 + name.len())
}

/// Is the file at `path` on the volume?
pub(crate) fn on_volume(path: &[u8]) -> bool {
    let mut fds = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fds, path, azos_fs::O_RDONLY);
    if fd < 0 {
        return false;
    }
    azos_fs::vfs_close(&mut fds, fd);
    true
}

/// Is `r` the console program's row (Kconfig CONSOLE_PROGRAM, or `init=`)?
fn is_console_row(r: &azos_topology::TaskSpec) -> bool {
    let n = r.name.as_bytes();
    let configured = crate::console_mode::configured_row();
    (!configured.is_empty() && n == configured)
        || crate::console_mode::console_path().is_some_and(|c| n == c.name())
}

/// A Linux class server (`lx_class`) starts only once the hardware bus has
/// bound a device one of that class's ids matched.
fn launch_row_wanted(r: &azos_topology::TaskSpec) -> bool {
    r.lx_class.is_empty() || azos_drv_bus::hwbus::with(|b| b.linux_class_wanted(r.lx_class.as_str()))
}

/// The rows to start at boot, in the order to start them, handed to `f` with
/// their row number, one by one. the `inspect.components` view publishes the same plan
/// for the component manager (the rows it starts: `manager_starts`, in
/// this order).
///
/// The console program (Kconfig CONSOLE_PROGRAM, `SH.ELF` by
/// default, or `init=` with secure boot off) starts LAST, after every other
/// `start = true` row, whatever the row order: a prompt is the sign the system
/// is up. Kconfig's console row is skipped when `init=` replaced it; an
/// `init=` image needs a row that says `start = true`, like any component
/// (the manager holds a launch grant on those rows only, and on the rows
/// an applied package brought, which `pkg_apply` grants it).
///
/// The Terminal object: when the console program is the terminal server, the
/// shell it serves is part of the same session and starts right AFTER it, so
/// its first call finds a server that already holds the endpoint and console
/// input (a shell started first spins on a call nobody answers).
pub(crate) fn for_each_launch_row<'a>(
    topo: &'a azos_topology::Topology<'a>,
    f: &mut dyn FnMut(usize, &'a azos_topology::TaskSpec<'a>),
) {
    let console = crate::console_mode::console_path();
    let session_follower = |r: &azos_topology::TaskSpec| {
        r.name.as_bytes() == azos_topology::builder::TASK_SH_IMAGE
            && console.is_some_and(|c| c.name() == azos_topology::builder::TASK_TERMD_IMAGE)
    };
    let rows = topo.tasks();
    let console_row = console.and_then(|c| {
        rows.iter().enumerate().find(|(_, r)| r.name.as_bytes() == c.name()).filter(|(_, r)| r.start)
    });
    // Behind a console login (Kconfig CONSOLE_LOGIN, users enrolled in the
    // signed topology) the shell is not started here: the login service starts
    // it as a user's session, after a login. With nobody enrolled the shell
    // starts as it always did.
    let gated = azos_topology::builder::console_gated(topo.logins().len());
    let follower_row = rows
        .iter()
        .enumerate()
        .find(|(_, r)| r.start && session_follower(r))
        .filter(|_| console_row.is_some() && !gated);
    for (i, r) in rows.iter().enumerate().filter(|(_, r)| {
        r.start && !is_console_row(r) && !session_follower(r) && launch_row_wanted(r)
    }) {
        f(i, r);
    }
    if let Some((i, r)) = console_row {
        f(i, r);
    }
    if let Some((i, r)) = follower_row {
        f(i, r);
    }
}

/// Start the component manager as a ring-3 `SYS_SPAWN_EX` of `/fat/<name>`
/// would (`spawn_path`) and supervise it from its first instruction
/// (`drv_supervisor::spawn_supervised`): refused unless its bytes are bound to
/// a seccomp image profile, then created under that profile with the class,
/// priority, frame budget and capabilities of its row. The manager is the one
/// ring-3 image whose supervisor is the kernel: nothing in ring 3 could
/// restart it. An image that is not on this volume is said and skipped.
fn start_manager(row: &azos_topology::TaskSpec) {
    let shown = row.name.as_str();
    let mut buf = [0u8; PATH_MAX];
    let Some(len) = image_path(row, &mut buf) else {
        kprintln!("[DRVLAUNCH] row {} has start = true but names no image on /fat -- not started", shown);
        return;
    };
    let path = &buf[..len];
    if !on_volume(path) {
        kprintln!("[DRVLAUNCH] {} is not on this volume -- not started", shown);
        return;
    }
    match drv_supervisor::spawn_supervised(path) {
        tid if tid > 0 => kprintln!("[DRVLAUNCH] {} started tid={} (start = true)", shown, tid),
        rc => kprintln!("[DRVLAUNCH] {} not started (spawn rc={})", shown, rc),
    }
}

/// The boot launcher task (`drv-launch`, a task of its own: starting an image
/// reads its ELF off the volume).
///
/// 1. Says which rows wait for a device (`lx_class`) and, for `init=`, that
///    the image has no row.
/// 2. Looks at every row the manager will start and leaves out of its plan
///    the ones whose image is not on the volume.
/// 3. Starts the manager, the one ring-3 image the kernel starts and
///    supervises itself.
pub(crate) fn boot_launch_task(_: usize) {
    if !azos_actuation::gate::gate_installed() {
        azos_drv_sys::kwarn!("[DRVLAUNCH] REFUSED: actuation gate is not installed -- \
                   refusing to start any ring-3 driver");
        return;
    }
    // Gate canary `safe-mode-launch-canary`: safe mode is ignored here, so
    // the `sh: safe mode` row's forbidden `[compmgr] start SH.ELF` binds.
    if azos_actuation::estop::safe_mode_active() && !cfg!(feature = "safe-mode-launch-canary") {
        azos_drv_sys::kwarn!("[DRVLAUNCH] REFUSED: safe mode -- no ring-3 driver started");
        return;
    }
    let Some(topo) = azos_topology::get() else { return };
    if let Some(c) = crate::console_mode::console_path() {
        if c.overridden && !topo.tasks().iter().any(|r| r.start && r.name.as_bytes() == c.name()) {
            azos_drv_sys::kwarn!("[DRVLAUNCH] init={} has no topology row that starts it -- not started",
                core::str::from_utf8(c.path()).unwrap_or("?"));
        }
    }
    for r in topo.tasks().iter().filter(|r| r.start && !launch_row_wanted(r)) {
        kprintln!("[DRVLAUNCH] {} waits: no device of Linux class {} was admitted",
            r.name.as_str(), r.lx_class.as_str());
    }
    let mut manager = false;
    for_each_launch_row(topo, &mut |i, row| {
        manager |= is_component_manager(row);
        if !azos_topology::builder::manager_starts(row) {
            return;
        }
        // A row a package brought runs the program that package carried, from
        // the staging volume (`boot::pkg_boot`), not one of its name on /fat;
        // the manager is told the directory by `components/<n>/dir` of its view.
        let mut applied = [0u8; 48];
        if let Some(path) = crate::boot::pkg_boot::image_path(row.name.as_bytes(), &mut applied) {
            if !on_volume(path) {
                kprintln!("[DRVLAUNCH] {} is not on this volume -- the component manager does not start it",
                    row.name.as_str());
                mark_unstartable(i);
            }
            return;
        }
        let mut buf = [0u8; PATH_MAX];
        match image_path(row, &mut buf) {
            Some(len) if on_volume(&buf[..len]) => {}
            Some(_) => {
                kprintln!("[DRVLAUNCH] {} is not on this volume -- the component manager does not start it",
                    row.name.as_str());
                mark_unstartable(i);
            }
            None => {
                kprintln!("[DRVLAUNCH] row {} has start = true but names no image on /fat -- the component \
                           manager does not start it", row.name.as_str());
                mark_unstartable(i);
            }
        }
    });
    if !manager {
        azos_drv_sys::kwarn!("[DRVLAUNCH] the topology has no {} row: no ring-3 row is started",
            core::str::from_utf8(azos_topology::builder::TASK_COMPMGR_IMAGE).unwrap_or("?"));
    }
    for_each_launch_row(topo, &mut |_, row| {
        if is_component_manager(row) {
            start_manager(row);
        }
    });
}
