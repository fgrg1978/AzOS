// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `LOGIND.ELF`: the AzOS login service.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `endpoint.login` (it serves it), `EXEC` on the kernel's `keys` interface
//! limited to its `login` op (it can verify a credential and make or use no
//! key), the right to start `SH.ELF`, and the kernel's view of the signed
//! topology's logins (`MemObj inspect.logins`). It answers the `Login` object (`userspace/lib/login`) to the
//! terminal server, which owns the console, holds the secure-attention prompt
//! and is the only caller.
//!
//! On a verified credential the kernel arms a one-shot grant on this
//! service's Domain; the service spends it at once by starting the shell with
//! `SPAWN_F_USER`, which makes the shell's Domain, and every Domain beneath
//! it, the user's (`owner_root`). The service keeps the shell's TID to end the
//! session (`Login::end`) and holds nothing of the credential: it passes the
//! words through and clears them.
//!
//! Request-driven, like `termd` and `decisd`: accept, dispatch, reply. The
//! logic is in `daemon.rs`, tested on the host; this file binds it to the
//! system calls.

#![no_std]
#![no_main]

mod daemon;

use azos_abi::ushell::{Move, SpawnReq, KILL_FORCE, KILL_SUBTREE, MOVE_CONSOLE, SPAWN_F_DIE_WITH_PARENT, SPAWN_F_USER, SPAWN_REQ_VERSION};
use azos_inspect_lib::{Inspector, Source};
use azos_libsys as sys;
use azos_login::{LoginIdl, MsgDesc, CREDENTIAL_WORDS, NAME_WORDS};
use daemon::{Daemon, Kernel};

/// The shell a session runs.
const SHELL: &[u8] = b"/fat/SH.ELF\0";
/// SIGKILL: the signal a forced stop reports.
const SIGKILL: u64 = 9;
/// How long a stopped shell is waited for before the service gives up reaping
/// it. A forced stop takes effect when the shell next runs (at its next
/// syscall, or its next timer tick), so the wait is in time, not in yields: a
/// busy machine does not run it within any count of them.
const REAP_WAIT_NS: u64 = 5_000_000_000;
/// Pause between two looks for the stopped shell.
const REAP_STEP_MS: u64 = 2;
/// `-ECHILD`.
const ECHILD: isize = -10;

struct Sys {
    keys: u32,
}

/// Print a line on the console.
fn say(line: &str) {
    let _ = sys::console_write(sys::STDOUT, line.as_bytes());
}

impl Kernel for Sys {
    fn enrolled(&mut self) -> bool {
        // The signed topology's logins (`MemObj inspect.logins`): none listed
        // is nobody enrolled. A view that cannot be read is taken as users
        // enrolled: the gate stays shut.
        let tree = sys::inspect_map(azos_abi::cap::SHM_INSPECT_LOGINS)
            .ok()
            // SAFETY: the mapping lives as long as the task, read-only, and
            // the kernel writes it only with aligned 64-bit stores.
            .and_then(|m| unsafe { Inspector::from_mapped(m, None) }.ok());
        let Some(mut tree) = tree else {
            say("[logind] the logins view cannot be read: taking it that users are enrolled\n");
            return true;
        };
        let mut any = true;
        let r = tree.with(Source::Public, |r| {
            any = false;
            let Some(dir) = r.lookup("logins")? else { return Ok(()) };
            r.children(dir, &mut |_, _| any = true)
        });
        any || r.is_err()
    }

    fn verify(&mut self, user: [u64; NAME_WORDS], credential: [u64; CREDENTIAL_WORDS]) -> Result<u32, u32> {
        // Spelled out, not imported: the seccomp tests' scanner reads a `use`
        // of a `sys::dev` item as a libsys function.
        use sys::dev::KeysCall;
        let mut c = sys::dev::KeysClient::new(sys::dev::Ep(self.keys));
        sys::dev::value(c.login(user, credential))
    }

    fn start_session(&mut self, name: &[u8]) -> Result<u32, isize> {
        // The request the component manager starts a child with (the console
        // on fds 1 and 2; stdin is the terminal server's), as the user's
        // session and with the user's name in its environment.
        let mut env = [0u8; 8 + azos_login::NAME_MAX];
        env[..5].copy_from_slice(b"USER=");
        env[5..5 + name.len()].copy_from_slice(name);
        let env_len = 5 + name.len() + 1;
        let mut req = SpawnReq {
            version: SPAWN_REQ_VERSION,
            flags: SPAWN_F_USER | SPAWN_F_DIE_WITH_PARENT,
            env_ptr: env.as_ptr() as u64,
            env_bytes: env_len as u32,
            envc: 1,
            nmoves: 2,
            ..SpawnReq::default()
        };
        for (slot, fd) in [1u32, 2].into_iter().enumerate() {
            req.moves[slot] = Move { child_fd: fd, handle: MOVE_CONSOLE, perms: 0, _pad: 0 };
        }
        match sys::spawn_ex(SHELL, Some(&req)) {
            tid if tid > 0 => Ok(tid as u32),
            rc => Err(rc),
        }
    }

    fn stop_session(&mut self, tid: u32) -> bool {
        let _ = sys::task_kill(tid, KILL_FORCE, SIGKILL, KILL_SUBTREE);
        let deadline = sys::vdso_now_ns().saturating_add(REAP_WAIT_NS);
        loop {
            if self.session_gone(tid) {
                return true;
            }
            if sys::vdso_now_ns() >= deadline {
                break;
            }
            sys::sleep(REAP_STEP_MS);
        }
        say("[logind] the session's shell did not stop: the session stays, no login is taken\n");
        false
    }

    fn session_gone(&mut self, tid: u32) -> bool {
        // -1: still running. The TID, or -ECHILD (reaped, or never ours): gone.
        let r = sys::waitpid(tid, core::ptr::null_mut());
        r >= 0 || r == ECHILD
    }

    fn say(&mut self, line: &str) {
        say(line);
    }
}

struct Cell(core::cell::UnsafeCell<Option<Daemon<Sys>>>);
// SAFETY: one thread.
unsafe impl Sync for Cell {}

static DAEMON: Cell = Cell(core::cell::UnsafeCell::new(None));

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    let Some(keys) = sys::dev::lookup(sys::dev::key::KEYS, 0) else {
        say("[logind] no keys interface: no login can be verified\n");
        sys::exit(1)
    };
    // SAFETY: the one reference, for the life of the program.
    let slot = unsafe { &mut *DAEMON.0.get() };
    let svc = slot.insert(Daemon::new(Sys { keys }));
    say("[logind] AzOS login service (Login on endpoint.login)\n");

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        let mut rep = MsgDesc::default();
        let _ = LoginIdl::dispatch(svc, &req, &mut rep);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}
