// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `why crash [TID]`: the minidump of a ring-3 task a fault killed.
//!
//! The kernel leaves `CRASHn.DMP` in the root of the first write tree the
//! faulting Domain holds (`kernel/src/trap/crash.rs`); this reads the same
//! names in each directory a write tree can be (`crashdump::DUMP_DIRS`)
//! beneath the read-only root directory the tool's own row holds and prints
//! what it finds: the report of the newest dump of task `TID`
//! (`azos_recovery::crashdump::write_report`), or with no task one line per
//! dump. The layout and the report are the kernel's source file, pulled in
//! with `#[path]` (`main.rs`), so the tool cannot disagree with the writer.
//! Pure over [`Dumps`], so the host suite drives it with files in memory.
//!
//! Exit 0, 1 when no dump matches, 2 on a usage error.

use crate::crashdump as cd;
use core::fmt::{self, Write};

/// Where the dump files come from: every candidate file's bytes.
pub trait Dumps {
    fn files(&self) -> Vec<Vec<u8>>;
}

/// What `why crash` was asked: `None` when the arguments are not a crash
/// command at all, else the task asked for (`None` inside: every dump) or a
/// usage error.
pub fn parse(args: &[&[u8]]) -> Option<Result<Option<u32>, &'static str>> {
    match args {
        [b"crash"] => Some(Ok(None)),
        [b"crash", tid] => Some(
            std::str::from_utf8(tid).ok().and_then(|t| t.parse::<u32>().ok()).map(Some).ok_or("the task is a number"),
        ),
        [b"crash", ..] => Some(Err("crash takes at most one task")),
        _ => None,
    }
}

/// Run the command against `src`, printing to `out`: the exit code.
pub fn run(tid: Option<u32>, src: &impl Dumps, names: &cd::Names, out: &mut impl Write) -> Result<i32, fmt::Error> {
    let files = src.files();
    let mut torn = 0usize;
    let mut found: Vec<cd::View<'_>> = Vec::new();
    for f in &files {
        match cd::decode(f) {
            Ok(v) => found.push(v),
            // Not a dump of this layout, or cut short: counted, never printed as one.
            Err(_) => torn += 1,
        }
    }
    // Oldest first: the serial orders the ring, modulo 2^32.
    found.sort_by(|a, b| (a.serial().wrapping_sub(b.serial()) as i32).cmp(&0));
    match tid {
        None => {
            for v in &found {
                cd::write_line(v, out)?;
            }
            write!(out, "# {} dumps{}\n", found.len(), if torn > 0 { format!(", {} unreadable", torn) } else { String::new() })?;
            Ok(0)
        }
        Some(t) => match found.iter().rev().find(|v| v.tid() == t) {
            Some(v) => {
                cd::write_report(v, names, out)?;
                Ok(0)
            }
            None => {
                write!(out, "why: no crash dump of task {} ({} dumps held{})\n", t, found.len(),
                    if torn > 0 { format!(", {} unreadable", torn) } else { String::new() })?;
                Ok(1)
            }
        },
    }
}
