// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `TERMD.ELF`: the AzOS terminal server.
//!
//! A ring-3 program with no hardware authority beyond the console's input,
//! which it claims at start (it is the console program, `CONSOLE_PATH`). It
//! serves the `Terminal` object (`userspace/lib/term`) to ONE client, the
//! shell, over the `endpoint.term` endpoint the topology grants: this row
//! holds `READ` (it serves), the shell's row `WRITE` (it calls). The line
//! discipline (`disc.rs`, over the editor `edit.rs`) and the interface's
//! implementation (`service.rs`) are pure and tested on the host
//! (`tests/host/term-tests`); this file is the loop around them.
//!
//! Request-driven: the ABI's accept blocks, so the loop is accept, dispatch,
//! reply. `read_event` runs `LOG_CONSOLE_WAIT` itself inside the call; see
//! `service.rs` for why that is enough for one client.
//!
//! **The input event ring and the screen region.** The kernel's input drivers
//! (PS/2, virtio-input) publish every event the console has no byte for into a
//! kernel-owned ring, and the framebuffer console publishes its screen into a
//! kernel-owned region (the text, the lines scrolled off, the overlay this
//! server asks it to draw, the mouse mode programs asked for). The row grants
//! both as memory objects (`MemObj input.events`, `MemObj console.screen`);
//! this server maps them and, like gpm on a Linux console, turns keys into
//! escape sequences and the mouse into selection, paste, scrollback and
//! reports (`keys.rs`, `mouse.rs`, `input.rs`). No call moves an event, and no
//! timer looks for one: the console wait doubles as the wait for the ring.
//! Without the grants, or without a framebuffer console, it serves as before.
//!
//! The Linux runtime's terminal (`/dev/ptmx`, termios) is NOT mapped here.
//! A foreground Linux job reads the console through the kernel's own line
//! discipline while the console's owner lends it input (`SPAWN_F_CONSOLE_IN`,
//! which needs the spawner to be the owner); that mapping is a front of its
//! own.

#![no_std]
#![no_main]

mod disc;
// The editor's cursor and history-size accessors are for the host tests.
#[allow(dead_code)]
mod edit;
mod input;
mod keys;
mod mouse;
mod secure;
mod service;

use azos_abi::cap::{SHM_CONSOLE_SCREEN, SHM_INPUT_EVENTS};
use azos_input_wire::event::{REGION_BYTES, RING_CAP};
use azos_input_wire::screen::Viewer;
use azos_libsys as sys;
use azos_rings::region::SpscRing;
use azos_login::{ended, state, status, LoginClient, LoginCall};
use azos_term::{MsgDesc, TerminalIdl};
use input::Input;
use service::{Console, Gate, Service};

/// The console as the kernel gives it to its input owner.
struct Uart;

impl Console for Uart {
    fn read(&mut self, buf: &mut [u8], timeout_ns: Option<u64>) -> isize {
        sys::console_wait(buf, timeout_ns.unwrap_or(sys::CONSOLE_WAIT_FOREVER))
    }

    fn write(&mut self, b: &[u8]) {
        let _ = sys::console_write(sys::STDOUT, b);
    }

    fn now_ns(&self) -> u64 {
        sys::vdso_now_ns()
    }

    fn refresh(&mut self) {
        // NUL: the serial line and the text grid take it for nothing; the
        // console's mirror draws the overlay on the write.
        let _ = sys::console_write(sys::STDOUT, &[0]);
    }
}

/// Map the memory object the row grants under `key`. `(base, bytes)`.
fn map_region(key: u32) -> Option<(usize, usize)> {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), key);
    if cap < 0 {
        return None;
    }
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    if sys::shm_acquire_typed(cap as u32, &mut info) < 0 {
        return None;
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = sys::shm_map_typed(cap as u32);
    (va > 0).then_some((va as usize, pages * sys::PAGE_SIZE))
}

/// The input consumer, when the row grants the ring. The screen is optional.
fn open_input() -> Option<Input<SpscRing>> {
    let (ring, len) = map_region(SHM_INPUT_EVENTS)?;
    // The drop counter is after the ring: a region too short is not ours.
    if len < REGION_BYTES {
        return None;
    }
    // SAFETY: a mapping of the kernel's screen region, held for the life of
    // the program; `Viewer::open` checks it is one.
    let screen = map_region(SHM_CONSOLE_SCREEN).and_then(|(va, len)| unsafe { Viewer::open(va as *mut u8, len) });
    Some(Input::new(SpscRing { base: ring, cap: RING_CAP }, screen))
}

/// The login service, over the call right on `endpoint.login`. The kernel mints
/// that right only on a gated console (`azos_topology::builder::login_call_withheld`:
/// the signed topology enrols a user), so the topology decides what an unreachable
/// service means: `ep` 0, no right, no gate and no question (the shell is the
/// component manager's, and a login service that is down cannot take the console);
/// with the right, a service that does not answer keeps the console locked.
struct LoginGate {
    ep: u32,
}

/// The transport of the `Login` client: the v2 call through the capability.
struct Ep(u32);

impl azos_login::Transport for Ep {
    fn call(&self, msg: &mut azos_login::MsgDesc) -> Result<(), azos_login::IdlError> {
        match sys::ipc_call_v2(self.0, msg) {
            0 => Ok(()),
            rc => Err(azos_login::IdlError::Transport(rc)),
        }
    }
}

/// Times the first question to the login service is asked again while it is
/// not serving yet (the manager starts it before this server, but it may not
/// have reached its accept).
const GATE_TRIES: u32 = 20_000;

impl Gate for LoginGate {
    fn state(&mut self) -> u32 {
        if self.ep == 0 {
            return state::OPEN;
        }
        for _ in 0..GATE_TRIES {
            if let Ok(s) = LoginClient::new(Ep(self.ep)).state() {
                return s;
            }
            sys::yield_now();
        }
        // Gated, and the service cannot be reached: the gate stays shut.
        state::LOCKED
    }

    fn login(&mut self, user: [u64; azos_login::NAME_WORDS], credential: [u64; azos_login::CREDENTIAL_WORDS]) -> u32 {
        LoginClient::new(Ep(self.ep)).login(user, credential).unwrap_or(status::NOT_READY)
    }

    fn end(&mut self) -> bool {
        // Anything but a clear "none left" (including a service that does not
        // answer) is a session that may still run.
        matches!(LoginClient::new(Ep(self.ep)).end(), Ok(ended::OK))
    }
}

/// The call right on `endpoint.login`: the `Cap<Endpoint>` of the row that is
/// not the one it serves (`READ`, `endpoint.term`). The rights are in the
/// handle, so the two are told apart without calling either (a call on the
/// endpoint it serves would wait for itself). 0: the row grants none.
fn find_login_endpoint() -> u32 {
    (0..16u32)
        .filter_map(|i| {
            let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
            (h > 0).then_some(h as u32)
        })
        .find(|&h| !azos_abi::cap::CapHandle::from_raw(h).perms().contains(azos_abi::cap::CapPerms::READ))
        .unwrap_or(0)
}

struct ServiceCell(core::cell::UnsafeCell<Service<Uart, LoginGate>>);
// SAFETY: one thread.
unsafe impl Sync for ServiceCell {}

static SERVICE: ServiceCell = ServiceCell(core::cell::UnsafeCell::new(Service::with_gate(Uart, LoginGate { ep: 0 })));

/// `-EBUSY`: another task owns console input.
const E_BUSY: isize = -16;

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    // SAFETY: the one reference, for the life of the program.
    let svc = unsafe { &mut *SERVICE.0.get() };

    // Claim console input now, not at the first read: a zero-timeout wait
    // claims it (the claim is inside any wait with a buffer) and returns at
    // once. A byte that was already typed is kept, not lost.
    let mut one = [0u8; 1];
    let n = sys::console_wait(&mut one, 0);
    if n == E_BUSY {
        let _ = sys::console_write(sys::STDOUT, b"termd: console input belongs to another task\n");
        sys::exit(1);
    }
    if n > 0 {
        svc.d.push(&one[..n as usize]);
    }
    svc.inp = open_input();
    svc.gate.ep = find_login_endpoint();
    svc.sak_serial = azos_limits::LOGIN_SAK_SERIAL_BYTE as u8;
    svc.gate_up();
    let _ = sys::console_write(sys::STDOUT, b"[termd] AzOS terminal server (Terminal on endpoint.term)\n");
    if let Some(inp) = &svc.inp {
        let _ = sys::console_write(
            sys::STDOUT,
            if inp.has_screen() { b"[termd] input ring and screen: keys, mouse\n" } else { b"[termd] input ring: keys (no screen)\n" },
        );
    }

    // Behind a login nobody is served until a user has logged in.
    svc.locked_loop();
    if svc.locked() {
        sys::exit(1);
    }

    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        let mut rep = MsgDesc::default();
        let _ = TerminalIdl::dispatch(svc, &req, &mut rep);
        let _ = sys::ipc_reply_v2(call as u64, &rep);
        if let Some(status) = svc.hung_up {
            if svc.guarded() {
                // Behind a login the shell's end is the session's: the user is
                // logged out and the console waits for the next one.
                if !svc.session_ended() {
                    sys::exit(1);
                }
                svc.locked_loop();
                if svc.locked() {
                    sys::exit(1);
                }
                continue;
            }
            // The client is done: end the session with its status. The exit
            // releases console input; 0 gives the console back to the
            // kernel's recovery shell, anything else is a failed session the
            // supervisor restarts.
            sys::exit(status);
        }
        // The person gave up the prompt the secure-attention key opened.
        if svc.locked() {
            svc.locked_loop();
            if svc.locked() {
                sys::exit(1);
            }
        }
    }
}
