// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `why`'s command line and what it prints: pure, over any
//! [`DecisionsCall`] and any [`core::fmt::Write`], so the host suite
//! (`tests/host/decisions-tests`) drives the whole tool through the
//! generated stubs and a loopback, with the server beyond it.
use azos_decisions::{fetch, list, DecisionsCall, Filter, IdlError, RULES, VERDICTS};
use core::fmt::Write;

/// Lines `why` with no arguments prints.
pub const LATEST: usize = 12;
/// Ids one `list` asks for at most.
pub const LIST_MAX: usize = 64;

/// What the command line asks.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    /// The latest [`LATEST`] decisions, one line each.
    Latest,
    /// The chain behind decision `id`.
    Chain(u64),
    /// The decisions that pass the filter, one line each (at most
    /// [`LIST_MAX`], oldest first).
    List(Filter),
}

pub const USAGE: &str = "usage: why [--remote] [ID | list [-r RULE] [-v VERDICT] [-s SUBJECT] [-a AFTER_ID]]\n";

fn number(a: &[u8]) -> Option<u64> {
    if a.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &b in a {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

/// The rule called `name` (`deadline-admission`, `cap-denial`, ...).
pub fn rule_by_name(name: &[u8]) -> Option<u8> {
    RULES.iter().position(|r| r.name.as_bytes() == name).map(|i| i as u8)
}

/// The verdict called `name` (`admit`, `refuse`, `place`, `deny`).
pub fn verdict_by_name(name: &[u8]) -> Option<u8> {
    VERDICTS.iter().position(|v| v.as_bytes() == name).map(|i| i as u8)
}

/// The command `args` (the program's arguments, not its name) ask for.
pub fn parse(args: &[&[u8]]) -> Result<Cmd, &'static str> {
    match args {
        [] => Ok(Cmd::Latest),
        [id] if number(id).is_some() => Ok(Cmd::Chain(number(id).unwrap_or(0))),
        [b"list", opts @ ..] => {
            let mut f = Filter::ANY;
            let mut it = opts.iter();
            while let Some(flag) = it.next() {
                let Some(val) = it.next() else { return Err("a flag needs a value") };
                match *flag {
                    b"-r" => f.rule = Some(rule_by_name(val).ok_or("no such rule")?),
                    b"-v" => f.verdict = Some(verdict_by_name(val).ok_or("no such verdict")?),
                    b"-s" => f.subject = Some(u32::try_from(number(val).ok_or("the subject is a number")?).map_err(|_| "the subject is a number")?),
                    b"-a" => f.after = number(val).ok_or("the id is a number")?,
                    _ => return Err("unknown flag"),
                }
            }
            Ok(Cmd::List(f))
        }
        _ => Err("unknown command"),
    }
}

/// Why `run` stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    /// The server or the transport failed.
    Call(IdlError),
    /// The output could not be written.
    Out,
}

impl From<IdlError> for Fail {
    fn from(e: IdlError) -> Self {
        Fail::Call(e)
    }
}

impl From<core::fmt::Error> for Fail {
    fn from(_: core::fmt::Error) -> Self {
        Fail::Out
    }
}

/// Run `cmd` against the server `c`, printing to `out`. The exit code: 0, or
/// 1 when the decision asked for is not held (gone from the kernel's journal
/// or ring, or never made: ids restart at a reset).
pub fn run<C: DecisionsCall>(cmd: &Cmd, c: &C, out: &mut impl Write) -> Result<i32, Fail> {
    match cmd {
        Cmd::Chain(id) => match fetch(c, *id)? {
            Some(p) => {
                p.write_chain(out)?;
                Ok(0)
            }
            None => {
                write!(out, "why: decision {} is not held (ids restart at a reset; the kernel keeps the latest)\n", id)?;
                Ok(1)
            }
        },
        Cmd::Latest | Cmd::List(_) => {
            let f = match cmd {
                Cmd::List(f) => *f,
                _ => Filter::ANY,
            };
            let mut ids = [0u64; LIST_MAX];
            let (n, total) = list(c, &f, &mut ids)?;
            let shown = if matches!(cmd, Cmd::Latest) { &ids[n.saturating_sub(LATEST)..n] } else { &ids[..n] };
            write!(out, "# {} shown, {} decisions since boot (why <id> for the chain)\n", shown.len(), total)?;
            for &id in shown {
                // One decision can be gone by the time it is asked for.
                if let Some(p) = fetch(c, id)? {
                    p.write_line(out)?;
                }
            }
            Ok(0)
        }
    }
}
