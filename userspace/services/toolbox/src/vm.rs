// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `vm`: launch and end a guest from the shell (Kconfig HV), a client of the
//! `VmCtl` interface (`azos_devif::vmctl`) that `VMMD.ELF` serves.
//!
//! ```text
//! vm list
//! vm start <row|image> [--image NAME] [--cpus N] [--mem MIB]
//! vm stop <id>
//! vm pause <id>
//! vm resume <id>
//! vm console <id>
//! ```
//!
//! `start` builds the machine of a signed guest row and starts it: a number
//! names the row (its kernel is `KERNEL.ELF` beneath the guest directory), a
//! name is a kernel image beneath that directory (row 0). `--image NAME` is
//! the name spelled out, for an image whose name is all digits. `--cpus` and
//! `--mem` make the guest smaller than its row, never larger. A refusal
//! prints the monitor's receipt (the cause, the number that explains it, the
//! serial) and exits 1; a start that fails after the machine was built gives
//! the machine back.
//!
//! `pause` holds a running guest: its vCPUs stop entering guest mode and keep
//! their state, and the guest's clock does not count the time held. The hold
//! is taken within a timer tick; the tool waits briefly for the monitor to
//! report `paused` and says `pausing` if it did not yet. `resume` lets it run
//! on. A refusal (the guest does not run, is already paused, is not paused)
//! prints the receipt like any other.
//!
//! The tool's authority is its row's `imports = ["vmctl"]`: the name server
//! lends it the call right on the monitor's endpoint, and nothing else. The
//! monitor is the one that holds the guest's row, its memory and its devices.
//!
//! `console` maps the ring the monitor lends and copies the guest's console
//! output to stdout until the monitor closes the ring: the guest is over, or
//! another tool took the console and got a ring of its own
//! ([`vmctl::ConsoleRing`]). The ring is read with loads and stores; the tool
//! sleeps between looks, as the monitor offers no wake-up for a reader, and
//! now and then asks the monitor whether it still answers (a monitor that
//! died closes nothing).

use super::{fail, put, put_num};
use azos_devif::vmctl::{self, cause, ImageName, Info, Receipt};
use azos_devif::{outcome, VmCtlCall, VmCtlClient};
use azos_libsys as sys;
use azos_names::{Call, MsgDesc, Renewing};
use azos_rings::region::SpscStream;

/// The v2 call and the close of a handle, for [`Renewing`].
struct SysCall;

impl Call for SysCall {
    fn call(&self, handle: u32, msg: &mut MsgDesc) -> isize {
        sys::ipc_call_v2(handle, msg) as isize
    }

    fn close(&self, handle: u32) {
        let _ = sys::close_typed(handle);
    }
}

type Client = VmCtlClient<Renewing<SysCall>>;

/// The kernel `start` loads for a row.
const DEFAULT_IMAGE: &[u8] = b"KERNEL.ELF";
/// Milliseconds between two looks at an empty console ring.
const POLL_MS: u64 = 20;
/// Looks at an empty ring between two questions to the monitor whether it
/// still answers.
const LOOKS_PER_CHECK: u32 = 50;

/// The client of the monitor, through the name server.
fn connect() -> Result<Client, &'static [u8]> {
    // The only endpoint this row holds at start is its call right on the name
    // server (the kernel gives it to a row that has `imports`).
    let names = (0..16u32)
        .find_map(|i| {
            let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
            (h > 0).then_some(h as u32)
        })
        .ok_or(&b"no name server (this row imports no `vmctl`)"[..])?;
    let name = azos_names::pack_name(vmctl::NAME).ok_or(&b"bad name"[..])?;
    let ep = Renewing::new(SysCall, names, name, 0);
    if !ep.renew() {
        return Err(b"the name server lends no vmctl endpoint (not imported, or the monitor is not running)");
    }
    Ok(VmCtlClient::new(ep))
}

fn number(a: &[u8]) -> Option<u32> {
    if a.is_empty() || a.len() > 9 || !a.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(a.iter().fold(0u32, |v, c| v * 10 + (c - b'0') as u32))
}

fn text(fd: u64, parts: &[&[u8]]) {
    for p in parts {
        let _ = put(fd, p);
    }
}

/// A refusal, as the monitor receipted it.
fn refused(op: &[u8], code: u32, r: &Receipt) -> i32 {
    text(2, &[b"vm: ", op, b" refused: ", cause::text(r.cause)]);
    if r.cause == cause::NONE {
        // A code with no receipt: the interface's own refusal (`DENIED`, ...).
        text(2, &[b" (outcome "]);
        put_num(2, code as u64);
        text(2, &[b")\n"]);
        return 1;
    }
    text(2, &[b" (cause "]);
    put_num(2, r.cause as u64);
    text(2, &[b", "]);
    put_num(2, r.arg);
    text(2, &[b", receipt #"]);
    put_num(2, r.serial as u64);
    text(2, &[b")\n"]);
    1
}

fn unreachable_monitor() -> i32 {
    fail(b"vm", b"the monitor did not answer");
    1
}

fn state_name(s: u32) -> &'static [u8] {
    match s {
        vmctl::STATE_FREE => b"free",
        vmctl::STATE_CREATED => b"created",
        vmctl::STATE_RUNNING => b"running",
        vmctl::STATE_PAUSING => b"pausing",
        vmctl::STATE_PAUSED => b"paused",
        _ => b"?",
    }
}

fn ended_name(e: u32) -> &'static [u8] {
    match e {
        vmctl::ENDED_NEVER => b"never ran",
        vmctl::ENDED_STOPPED => b"stopped",
        vmctl::ENDED_FAULTED => b"faulted",
        _ => b"?",
    }
}

fn list(c: &mut Client) -> i32 {
    text(1, &[b"ID  STATE    CPUS  MEM_MIB  LAST\n"]);
    for index in 0.. {
        let o = match c.list(index) {
            Ok(o) => o,
            Err(_) => return unreachable_monitor(),
        };
        if o.code == outcome::NO_RESOURCE {
            return 0;
        }
        if !o.is_ok() {
            return refused(b"list", o.code, &Receipt::default());
        }
        let Info { id, state, cpus, mem_mib, ended } = o.value;
        put_num(1, id as u64);
        text(1, &[b"   ", state_name(state)]);
        pad(8usize.saturating_sub(state_name(state).len()));
        put_num(1, cpus as u64);
        text(1, &[b"     "]);
        put_num(1, mem_mib as u64);
        text(1, &[b"      "]);
        text(1, &[ended_name(ended), b"\n"]);
    }
    0
}

fn pad(n: usize) {
    for _ in 0..n {
        let _ = put(1, b" ");
    }
}

const START_USAGE: &[u8] = b"usage: vm start <row|image | --image NAME> [--cpus N] [--mem MIB]";

/// `vm start <row|image | --image NAME> [--cpus N] [--mem MIB]`.
fn start(c: &mut Client) -> i32 {
    let (mut target, mut named, mut cpus, mut mem) = (None, false, 0u32, 0u32);
    let mut i = 2;
    while i < sys::argc() {
        let a = sys::arg(i).unwrap_or(b"");
        match a {
            b"--cpus" | b"--mem" => {
                i += 1;
                let Some(v) = sys::arg(i).and_then(number) else {
                    fail(b"vm", START_USAGE);
                    return 2;
                };
                if a == b"--cpus" {
                    cpus = v;
                } else {
                    mem = v;
                }
            }
            b"--image" if target.is_none() => {
                i += 1;
                target = sys::arg(i).filter(|n| !n.is_empty());
                named = true;
                if target.is_none() {
                    fail(b"vm", START_USAGE);
                    return 2;
                }
            }
            _ if target.is_none() && !a.is_empty() && a[0] != b'-' => target = Some(a),
            _ => {
                fail(b"vm", START_USAGE);
                return 2;
            }
        }
        i += 1;
    }
    let Some(target) = target else {
        fail(b"vm", START_USAGE);
        return 2;
    };
    let (row, image) = match number(target) {
        Some(row) if !named => (row, DEFAULT_IMAGE),
        _ => (0, target),
    };
    let Some(image) = ImageName::pack(image) else {
        fail(b"vm", b"the image name is longer than the monitor accepts");
        return 2;
    };
    let id = match c.create(row, cpus, mem, image) {
        Err(_) => return unreachable_monitor(),
        Ok(o) if !o.is_ok() => return refused(b"create", o.code, &o.value),
        Ok(o) => o.value.id,
    };
    match c.start(id) {
        Err(_) => unreachable_monitor(),
        Ok(o) if !o.is_ok() => {
            let rc = refused(b"start", o.code, &o.value);
            // Do not leave a machine built that nobody started.
            let _ = c.stop(id);
            rc
        }
        Ok(_) => {
            text(1, &[b"vm "]);
            put_num(1, id as u64);
            text(1, &[b" started\n"]);
            0
        }
    }
}

/// The id argument of `stop`, `pause`, `resume` and `console`.
fn id_arg(usage: &[u8]) -> Option<u32> {
    let id = sys::arg(2).and_then(number);
    if id.is_none() || sys::argc() != 3 {
        fail(b"vm", usage);
        return None;
    }
    id
}

fn stop(c: &mut Client) -> i32 {
    let Some(id) = id_arg(b"usage: vm stop <id>") else { return 2 };
    match c.stop(id) {
        Err(_) => unreachable_monitor(),
        Ok(o) if !o.is_ok() => refused(b"stop", o.code, &o.value),
        Ok(_) => {
            text(1, &[b"vm "]);
            put_num(1, id as u64);
            text(1, &[b" stopped\n"]);
            0
        }
    }
}

/// Looks at the table, [`POLL_MS`] apart, for a pause to be taken.
const PAUSE_LOOKS: u32 = 50;

/// Has the monitor's table taken the hold of VM `id`?
fn is_paused(c: &mut Client, id: u32) -> bool {
    matches!(c.list(id), Ok(o) if o.is_ok() && o.value.state == vmctl::STATE_PAUSED)
}

fn pause(c: &mut Client) -> i32 {
    let Some(id) = id_arg(b"usage: vm pause <id>") else { return 2 };
    match c.pause(id) {
        Err(_) => return unreachable_monitor(),
        Ok(o) if !o.is_ok() => return refused(b"pause", o.code, &o.value),
        Ok(_) => {}
    }
    let mut held = is_paused(c, id);
    for _ in 0..PAUSE_LOOKS {
        if held {
            break;
        }
        sys::sleep(POLL_MS);
        held = is_paused(c, id);
    }
    text(1, &[b"vm "]);
    put_num(1, id as u64);
    text(1, &[if held { &b" paused\n"[..] } else { &b" pausing (a vCPU has not yet taken the hold)\n"[..] }]);
    0
}

fn resume(c: &mut Client) -> i32 {
    let Some(id) = id_arg(b"usage: vm resume <id>") else { return 2 };
    match c.resume(id) {
        Err(_) => unreachable_monitor(),
        Ok(o) if !o.is_ok() => refused(b"resume", o.code, &o.value),
        Ok(_) => {
            text(1, &[b"vm "]);
            put_num(1, id as u64);
            text(1, &[b" resumed\n"]);
            0
        }
    }
}

/// Does the monitor still answer?
fn answers(c: &mut Client, id: u32) -> bool {
    c.list(id).is_ok()
}

fn console(c: &mut Client) -> i32 {
    let Some(id) = id_arg(b"usage: vm console <id>") else { return 2 };
    let lease = match c.console(id) {
        Err(_) => return unreachable_monitor(),
        Ok(o) if !o.is_ok() => return refused(b"console", o.code, &o.value.receipt),
        Ok(o) => o.value,
    };
    let Some(cap) = lease.ring.get() else {
        fail(b"vm", b"the monitor lent no console ring");
        return 1;
    };
    let va = sys::shm_map_typed(cap.raw());
    if va <= 0 {
        fail(b"vm", b"the console ring cannot be mapped");
        return 1;
    }
    let ring = SpscStream { base: va as usize, cap: vmctl::CONSOLE_RING_CAP };
    let mut buf = [0u8; 256];
    let mut empty = 0;
    loop {
        let (n, _) = ring.read(&mut buf);
        if n > 0 {
            empty = 0;
            let w = put(1, &buf[..n]);
            if w == sys::E_PIPE {
                return 0;
            }
            if w < 0 {
                return if w == sys::E_INTR { 130 } else { 1 };
            }
            continue;
        }
        // The monitor closes the ring after its last byte: what the ring
        // holds after that look is the rest, and read before this look.
        if vmctl::ConsoleRing::closed(ring.base) {
            loop {
                let (n, _) = ring.read(&mut buf);
                if n == 0 || put(1, &buf[..n]) < 0 {
                    return 0;
                }
            }
        }
        empty += 1;
        if empty == LOOKS_PER_CHECK {
            empty = 0;
            if !answers(c, id) {
                fail(b"vm", b"the monitor did not answer: the console is over");
                return 1;
            }
        }
        sys::sleep(POLL_MS);
    }
}

/// `vm <list|start|stop|pause|resume|console> ...`: an exit code.
pub fn run() -> i32 {
    let sub = sys::arg(1).unwrap_or(b"");
    if !matches!(sub, b"list" | b"start" | b"stop" | b"pause" | b"resume" | b"console") {
        fail(
            b"vm",
            b"usage: vm list | start <row|image | --image NAME> [--cpus N] [--mem MIB] | stop <id> | pause <id> | resume <id> | console <id>",
        );
        return 2;
    }
    let mut c = match connect() {
        Ok(c) => c,
        Err(why) => {
            fail(b"vm", why);
            return 1;
        }
    };
    match sub {
        b"list" => list(&mut c),
        b"start" => start(&mut c),
        b"stop" => stop(&mut c),
        b"pause" => pause(&mut c),
        b"resume" => resume(&mut c),
        _ => console(&mut c),
    }
}
