// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `WHY.ELF`: which rule decided, and on what numbers.
//!
//! The ring-3 face of the decision query. Its topology row is its whole
//! authority: a call capability (`WRITE`) on `endpoint.decisions`, the
//! endpoint `DECISD.ELF` serves the `Decisions` object on
//! (`userspace/lib/decisions`). Without it the program finds no endpoint and
//! says so. It decides nothing: it asks, and prints the chain the record
//! holds (`ProvenanceRecord::write_chain`): rule, verdict, subject, the
//! numbers the rule compared, the capability slot and its parent, the
//! topology row, the image hash prefix and the clock, `-` where no call
//! site has the value yet.
//!
//! The first native program on `std` (the SDK, `*-unknown-azos`): the
//! arguments, the output and the exit status are `std`'s; the one native call
//! it makes itself, the endpoint call, is `azos_libsys`'s.
//! With `--remote` first it asks the decision server of the peer node instead,
//! through the proxy endpoint `endpoint.rpc-decisions` (the RPC server,
//! `userspace/services/rpcsrv`, carries the call): the row's second endpoint,
//! the first being the local one (the topology names them in that order). A
//! lost link is `NoConnection`, not a dead server.
//!
//! ```text
//! why [--remote]       the latest decisions, one line each
//! why ID               the chain behind decision ID
//! why list [-r RULE] [-v VERDICT] [-s SUBJECT] [-a AFTER_ID]
//!                      the decisions that pass the filter
//! why crash [TID]      the minidump of a task a fault killed (`crash.rs`)
//! why woke [N]         the last N logged wakes, each with its source, the Domain woken
//!                      and its age (the task IDs, with the admin region), and the first
//!                      Domains the tree publishes (`woke.rs`)
//! ```
//! Exit 0, 1 when the decision (or the dump) is not held, 2 on a usage error
//! or no endpoint, 3 when the server failed.
//!
//! `why crash` and `why woke` do not call the decision server. `why crash` reads
//! the dump files beneath the read-only root directory its row holds
//! (`ROOT_RO`), in the trees the Domains' dumps land in. `why woke` maps the
//! public region of the kernel's introspection tree (its row's `MemObj
//! inspect.public`, Kconfig INSPECT) and, when the row also holds `MemObj
//! inspect.admin` (the task view), the admin one, and reads the wake log in them
//! with loads, no system call per value: with task IDs from the admin region,
//! without from the public one (`woke.rs`).

mod cli;
mod crash;
mod woke;
// The kernel's own layout and report: one source for the writer and the reader.
#[allow(dead_code)]
#[path = "../../../../crates/core/recovery/src/crashdump.rs"]
mod crashdump;

use std::io::{self, Write};
use std::process::ExitCode;

use azos_decisions::{DecisionsClient, IdlError, MsgDesc, Transport};
use azos_libsys as sys;

/// The transport: the v2 call on the endpoint capability.
struct Ep(u32);

impl Transport for Ep {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        match sys::ipc_call_v2(self.0, msg) {
            0 => Ok(()),
            rc => Err(IdlError::Transport(rc)),
        }
    }
}

/// `cli` prints through `core::fmt::Write`; this is that over standard output
/// (a line is one write: `std` flushes a line at a time, so another task's
/// output does not land in the middle of it).
struct Out<W: Write>(W);

impl<W: Write> core::fmt::Write for Out<W> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.write_all(s.as_bytes()).map_err(|_| core::fmt::Error)
    }
}

/// The names the report gives the kernel's decision rules and verdicts.
const NAMES: crashdump::Names = crashdump::Names {
    rule: |r| azos_decisions::RULES.get(r as usize).map_or("?", |x| x.name),
    verdict: |v| azos_decisions::VERDICTS.get(v as usize).copied().unwrap_or("?"),
};

/// The dump files in the directories a Domain's write tree can be
/// ([`crashdump::DUMP_DIRS`]), opened beneath the root directory the row holds
/// (`sys::root_dir`, read-only): slot by slot, by the name the kernel wrote
/// ([`crashdump::slot_path`]); a name that does not open is a slot not used.
struct DirDumps;

impl crash::Dumps for DirDumps {
    fn files(&self) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        let root = sys::root_dir();
        if root <= 0 {
            return all;
        }
        for dir in crashdump::DUMP_DIRS {
            for slot in 0..crashdump::MAX_SLOTS {
                let mut path = [0u8; crashdump::PATH_MAX];
                let n = crashdump::slot_path(dir, slot, &mut path);
                let f = sys::open_at(root as u32, &path[..n + 1], 0);
                if f < 0 {
                    continue;
                }
                let (mut data, mut buf) = (Vec::new(), [0u8; 1024]);
                while data.len() <= crashdump::MAX_BYTES {
                    let got = sys::file_read_typed(f as u32, &mut buf);
                    if got <= 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..got as usize]);
                }
                sys::close_typed(f as u32);
                all.push(data);
            }
        }
        all
    }
}

/// The `n`th `Cap<Endpoint>` this row holds, by pool index: the first is the
/// local decision server's, the second (`--remote`) the proxy of the peer's
/// (the topology names them in that order). Ring 3 has no by-name lookup, so
/// scan the pool indexes.
fn find_endpoint(n: usize) -> Option<u32> {
    (0..16u32)
        .filter_map(|i| {
            let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
            (h > 0).then_some(h as u32)
        })
        .nth(n)
}

/// Map the introspection region the task holds under `key`, read-only (the
/// capability carries `READ|MAP` only): its base and size in bytes. `None`: the
/// row grants none, or the kernel has INSPECT off, or the map failed.
fn map_inspect(key: u32) -> Option<(*const u8, usize)> {
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
    (va > 0).then_some((va as *const u8, pages * sys::PAGE_SIZE))
}

/// `why woke [N]`: the wake log of the introspection tree (`woke.rs`).
fn woke_main(args: &[&[u8]], remote: bool) -> ExitCode {
    let mut err = io::stderr().lock();
    if remote {
        let _ = write!(err, "why: the wake log is this node's: no --remote\n");
        return ExitCode::from(2);
    }
    let words: Vec<&str> = args.iter().filter_map(|a| core::str::from_utf8(a).ok()).collect();
    let count = if words.len() == args.len() { woke::parse_count(&words) } else { None };
    let Some(count) = count else {
        let _ = write!(err, "why: {}\n{}", woke::USAGE, cli::USAGE);
        return ExitCode::from(2);
    };
    let Some(public) = map_inspect(azos_abi::cap::SHM_INSPECT_PUBLIC) else {
        let _ = write!(err, "why: no wake log (the row holds no introspection region, or the kernel has INSPECT off)\n");
        return ExitCode::from(1);
    };
    // The admin region is the row's if it holds the task view; without it the
    // log has no task IDs and `woke::render` says so.
    let admin = map_inspect(azos_abi::cap::SHM_INSPECT_ADMIN);
    // SAFETY: read-only mappings of the kernel's regions, held for the life of
    // the task; the reader only loads from them.
    let Ok(mut view) = (unsafe { azos_inspect_lib::Inspector::from_mapped(public, admin) }) else {
        let _ = write!(err, "why: the region is not a tree this build reads\n");
        return ExitCode::from(1);
    };
    let mut report = Box::new(woke::Report::new());
    match woke::read(&mut view, count, &mut report) {
        Ok(()) => {}
        Err(woke::ReadError::Off) => {
            let _ = write!(err, "why: no wake log (the kernel has WAKE_RING_ENTRIES 0)\n");
            return ExitCode::from(1);
        }
        Err(woke::ReadError::Tree) => {
            let _ = write!(err, "why: cannot read the tree\n");
            return ExitCode::from(1);
        }
    }
    match woke::render(&report, &mut Out(io::stdout().lock())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(3),
    }
}

fn main() -> ExitCode {
    let mut err = io::stderr().lock();
    let argv: Vec<_> = std::env::args_os().skip(1).take(12).collect();
    let args: Vec<&[u8]> = argv.iter().map(|a| a.as_encoded_bytes()).collect();
    let remote = args.first() == Some(&&b"--remote"[..]);
    let rest = &args[remote as usize..];
    if let [b"woke", more @ ..] = rest {
        return woke_main(more, remote);
    }
    if let Some(asked) = crash::parse(rest) {
        let tid = match asked {
            Ok(t) if !remote => t,
            Ok(_) => {
                let _ = write!(err, "why: crash dumps are this node's: no --remote\n");
                return ExitCode::from(2);
            }
            Err(why) => {
                let _ = write!(err, "why: {}\n{}", why, cli::USAGE);
                return ExitCode::from(2);
            }
        };
        return match crash::run(tid, &DirDumps, &NAMES, &mut Out(io::stdout().lock())) {
            Ok(code) => ExitCode::from(code as u8),
            Err(_) => ExitCode::from(3),
        };
    }
    let cmd = match cli::parse(rest) {
        Ok(c) => c,
        Err(why) => {
            let _ = write!(err, "why: {}\n{}", why, cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let Some(ep) = find_endpoint(remote as usize) else {
        let _ = if remote {
            write!(err, "why: no remote decisions endpoint (the row holds no call capability on endpoint.rpc-decisions)\n")
        } else {
            write!(err, "why: no decisions endpoint (the row holds no call capability on endpoint.decisions)\n")
        };
        return ExitCode::from(2);
    };
    let client = DecisionsClient::new(Ep(ep));
    let mut out = Out(io::stdout().lock());
    match cli::run(&cmd, &client, &mut out) {
        Ok(code) => ExitCode::from(code as u8),
        Err(cli::Fail::Call(e)) => {
            let _ = write!(err, "why: the decision server did not answer: {:?}\n", e);
            ExitCode::from(3)
        }
        Err(cli::Fail::Out) => ExitCode::from(3),
    }
}
