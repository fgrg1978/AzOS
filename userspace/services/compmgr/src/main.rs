// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `COMPMGR.ELF`: the AzOS component manager.
//!
//! The first ring-3 component, and the only supervisor of the rows that start:
//! every ring-3 component of the signed topology is its child, the ring-3 host
//! of a driver that moves between hosts (the buzzer) included. The placement
//! controller in the kernel (`kernel/src/buzzer.rs`) only routes calls between
//! such a driver's two hosts; it never starts or ends a ring-3 one, so the
//! manager's restart policy is the only one that applies to it.
//!
//! **The one remaining kernel supervision of a ring-3 image is this
//! manager's own:** a supervisor cannot supervise itself, and nothing in ring
//! 3 could restart it. The kernel starts it at boot, with the authority of
//! its row (the read-only root directory and `EXEC` on each image it starts),
//! and restarts it if it fails (`kernel/src/drv_supervisor.rs`).
//!
//! The manager reads the signed topology's startable rows through
//! `/proc/components`, starts each with `SYS_SPAWN_EX` (the child's
//! capabilities are those of its own row; the manager lends it no handle and
//! no environment, only the console on stdout and stderr, `request.rs`; it
//! dies with the manager), supervises
//! them as `tree.rs` says, and writes one line to the console for every
//! start, restart, clean end, give-up and refusal. The kernel keeps the
//! task-creation half; the decisions are `tree.rs`, pure and tested on the
//! host (`tests/host/compmgr-tests`).
//!
//! # Waiting
//!
//! A child's end is read with `wait_status`, which does not block. The loop
//! reaps every finished child, lets the tree start what is due **once, after
//! the whole reap** (a session's tasks end together, and the tree must know of
//! all of their ends before it starts any successor), and sleeps until the
//! next restart is due or [`POLL_NS`] has passed. A port source for
//! a child's exit would make the poll unnecessary.

#![no_std]
#![no_main]

mod contracts;
mod request;
mod tree;

use azos_idl::OnFailure;
use azos_libsys as sys;
use tree::{Event, EventKind, Host, Intensity, Tree, VIEW_MAX};

/// How long the loop sleeps when no restart is due: the latency of noticing
/// a child's end.
const POLL_NS: u64 = 20_000_000;
/// The pause between two restarts of one component inside its window.
const COOLDOWN_NS: u64 = 1_000_000_000;
/// The signal number a forced stop carries (`SYS_ALERT` takes 1..=31).
const SIGKILL: u64 = 9;
/// The exit code when `/proc/components` cannot be read (sysexits
/// `EX_NOINPUT`); a panic exits with 70.
const NO_VIEW_EXIT: i32 = 66;
/// A directory, "/", an 8.3 name and the NUL.
const PATH_MAX: usize = tree::DIR_MAX + 1 + 12 + 1;

struct Kernel;

impl Kernel {
    /// `/proc/components` into `buf`: its length, or the negative errno of the
    /// open or of the read that failed.
    fn view(&mut self, buf: &mut [u8]) -> Result<usize, isize> {
        let h = sys::open_root(b"/proc/components\0", 0);
        if h < 0 {
            return Err(h);
        }
        let h = h as u32;
        let got = tree::read_view(buf, |b| sys::file_read_typed(h, b));
        let _ = sys::close_typed(h);
        got
    }
}

impl Host for Kernel {
    fn spawn(&mut self, dir: &[u8], image: &[u8]) -> Result<u32, i32> {
        let mut path = [0u8; PATH_MAX];
        let dir: &[u8] = if dir.is_empty() { b"/fat" } else { dir };
        let n = dir.len() + 1 + image.len();
        if n + 1 > PATH_MAX {
            return Err(-22);
        }
        path[..dir.len()].copy_from_slice(dir);
        path[dir.len()] = b'/';
        path[dir.len() + 1..n].copy_from_slice(image);
        let req = request::child_request();
        let tid = sys::spawn_ex(&path[..n + 1], Some(&req));
        if tid > 0 { Ok(tid as u32) } else { Err(tid as i32) }
    }

    fn stop(&mut self, tid: u32) {
        // A signal number of 0 is refused (`EINVAL`) by `SYS_ALERT`, which
        // left every stop of a dependent undelivered; 9 is what a forced
        // stop is recorded as (exit code 137).
        let _ = sys::task_kill(tid, sys::KILL_FORCE, SIGKILL, 0);
    }

    fn now_ns(&mut self) -> u64 {
        sys::vdso_now_ns()
    }

    fn record(&mut self, e: &Event<'_>) {
        let what: &[u8] = match e.kind {
            EventKind::Start => b"start",
            EventKind::Restart => b"restart",
            EventKind::Exit => b"exit",
            EventKind::GiveUp => b"give-up",
            EventKind::Escalate => b"escalate",
            EventKind::SafeState => b"safe-state",
            EventKind::Stopped => b"stopped",
            EventKind::Blocked => b"blocked",
            EventKind::SpawnRefused => b"spawn-refused",
            EventKind::ViewRejected => b"view-rejected",
        };
        let mut line = Line::new();
        line.put(b"[compmgr] ");
        line.put(what);
        line.put(b" ");
        line.put(e.name);
        line.put(b" tid=");
        line.num(e.tid as i64);
        line.put(b" code=");
        line.num(e.code as i64);
        line.put(b" attempt=");
        line.num(e.attempt as i64);
        line.put(b"\n");
        let _ = sys::console_write(sys::STDOUT, line.bytes());
    }

    fn contract(&mut self, endpoint: &[u8]) -> Option<OnFailure> {
        contracts::contract_of(endpoint)
    }
}

/// One console line.
struct Line {
    b: [u8; 96],
    n: usize,
}

impl Line {
    fn new() -> Line {
        Line { b: [0; 96], n: 0 }
    }

    fn put(&mut self, s: &[u8]) {
        let k = s.len().min(self.b.len() - self.n);
        self.b[self.n..self.n + k].copy_from_slice(&s[..k]);
        self.n += k;
    }

    fn num(&mut self, v: i64) {
        let mut d = [0u8; 20];
        let mut i = d.len();
        let mut u = v.unsigned_abs();
        loop {
            i -= 1;
            d[i] = b'0' + (u % 10) as u8;
            u /= 10;
            if u == 0 {
                break;
            }
        }
        if v < 0 {
            self.put(b"-");
        }
        self.put(&d[i..]);
    }

    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

struct TreeCell(core::cell::UnsafeCell<Tree>);
// SAFETY: one thread.
unsafe impl Sync for TreeCell {}

/// The tree: a static, so its table is not on the stack. The restart limit is
/// the kernel supervisor's, from the same Kconfig symbols.
static TREE: TreeCell = TreeCell(core::cell::UnsafeCell::new(Tree::new(Intensity {
    burst: azos_limits::SUP_RESTART_BURST as u8,
    interval_ns: azos_limits::SUP_RESTART_INTERVAL_S as u64 * 1_000_000_000,
    cooldown_ns: COOLDOWN_NS,
})));

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    let mut host = Kernel;
    let mut view = [0u8; VIEW_MAX];
    let got = host.view(&mut view);
    let _ = sys::console_write(sys::STDOUT, b"[compmgr] AzOS component manager\n");
    // No view, nothing to supervise: end, so the kernel's supervision of the
    // manager sees the failure and restarts it, instead of an idle manager
    // that looks healthy and started nothing.
    let got = match got {
        Ok(n) => n,
        Err(rc) => {
            let mut line = Line::new();
            line.put(b"[compmgr] cannot read /proc/components rc=");
            line.num(rc as i64);
            line.put(b"\n");
            let _ = sys::console_write(sys::STDOUT, line.bytes());
            sys::exit(NO_VIEW_EXIT);
        }
    };
    // SAFETY: the one reference, for the life of the program.
    let tree = unsafe { &mut *TREE.0.get() };
    tree.load(&view[..got], &mut host);
    tree.start_all(&mut host);
    loop {
        // Every child that finished.
        loop {
            let mut code = 0i32;
            let tid = sys::wait_status(&mut code as *mut i32);
            if tid <= 0 {
                break;
            }
            tree.on_exit(tid as u32, code, &mut host);
        }
        tree.tick(&mut host);
        let now = sys::vdso_now_ns();
        let until = tree.wake_at().map_or(now + POLL_NS, |t| t.clamp(now, now + POLL_NS));
        let _ = sys::sleep_until_ns(until);
    }
}
