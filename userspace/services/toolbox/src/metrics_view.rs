// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The text `inspect` prints for a subtree of the introspection tree, and the
//! Perfetto counter track it writes with `-j`. Plain Rust over `core::fmt`,
//! compiled by the host tests (`tests/host/inspect-tests/src/metrics.rs`)
//! through a `#[path]` include.
//!
//! * a node's path comes from the walk's depths ([`PathStack`]): the tree
//!   walk visits a directory before its children and gives each node only its
//!   name and depth;
//! * `inspect PREFIX` prints `path = value`, one leaf a line, for the nodes at
//!   or under PREFIX ([`under`]);
//! * `inspect -j` samples the `u64` leaves under a prefix every period and
//!   writes Chrome trace-event JSON, which `ui.perfetto.dev` opens next to a
//!   `tracectl profile -j` trace: one counter track per node.

use core::fmt::{self, Write};

/// Longest path kept, and deepest tree walked.
pub const PATH_MAX: usize = 128;
pub const DEPTH_MAX: usize = 8;

/// The path of the node a pre-order walk is at.
pub struct PathStack {
    buf: [u8; PATH_MAX],
    ends: [usize; DEPTH_MAX],
}

impl PathStack {
    pub const fn new() -> Self {
        PathStack { buf: [0; PATH_MAX], ends: [0; DEPTH_MAX] }
    }

    /// Enter the node `name` at `depth` (the root's children are at 1) and
    /// return its path. A node too deep or too long for the buffer has the
    /// empty path, and nothing matches it.
    pub fn enter(&mut self, depth: u32, name: &str) -> &str {
        let d = depth as usize;
        if d == 0 || d > DEPTH_MAX {
            return "";
        }
        let mut n = if d == 1 { 0 } else { self.ends[d - 2] };
        if d > 1 {
            if n == 0 || n >= PATH_MAX {
                self.ends[d - 1] = 0;
                return "";
            }
            self.buf[n] = b'/';
            n += 1;
        }
        if n + name.len() > PATH_MAX {
            self.ends[d - 1] = 0;
            return "";
        }
        self.buf[n..n + name.len()].copy_from_slice(name.as_bytes());
        n += name.len();
        self.ends[d - 1] = n;
        core::str::from_utf8(&self.buf[..n]).unwrap_or("")
    }
}

/// Is `path` the node `prefix` names or below it? (`metrics/sched` holds
/// `metrics/sched/migrations`, not `metrics/scheduler`.) An empty prefix holds
/// every path; an empty path is held by none.
pub fn under(prefix: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let prefix = prefix.trim_end_matches('/');
    prefix.is_empty()
        || path == prefix
        || (path.len() > prefix.len() && path.starts_with(prefix) && path.as_bytes()[prefix.len()] == b'/')
}

/// A leaf's value.
pub enum Val<'a> {
    U(u64),
    I(i64),
    S(&'a str),
    H(&'a [u64]),
}

/// `path = value`, one line.
pub fn flat(out: &mut dyn Write, path: &str, v: Val<'_>) -> fmt::Result {
    write!(out, "{path} = ")?;
    match v {
        Val::U(x) => write!(out, "{x}")?,
        Val::I(x) => write!(out, "{x}")?,
        Val::S(s) => write!(out, "{s}")?,
        Val::H(b) => {
            for (i, x) in b.iter().enumerate() {
                if i > 0 {
                    out.write_str(",")?;
                }
                write!(out, "{x}")?;
            }
        }
    }
    out.write_str("\n")
}

/// The start of the trace file.
pub fn trace_begin(out: &mut dyn Write) -> fmt::Result {
    out.write_str("{\"traceEvents\":[\n{\"name\":\"process_name\",\"ph\":\"M\",\"pid\":0,\"args\":{\"name\":\"azos inspect\"}}")
}

/// One counter sample: `path` was `v` at `ts_ns` (nanoseconds from the first
/// sample). Perfetto draws one track per distinct name.
pub fn trace_counter(out: &mut dyn Write, path: &str, ts_ns: u64, v: u64) -> fmt::Result {
    write!(
        out,
        ",\n{{\"name\":\"{}\",\"ph\":\"C\",\"ts\":{}.{:03},\"pid\":0,\"args\":{{\"v\":{v}}}}}",
        Json(path),
        ts_ns / 1000,
        ts_ns % 1000
    )
}

/// A string as JSON string contents: the quote, the backslash and control
/// characters escaped (a node name may hold any of them).
struct Json<'a>(&'a str);

impl fmt::Display for Json<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chars() {
            match c {
                '"' => f.write_str("\\\"")?,
                '\\' => f.write_str("\\\\")?,
                c if (c as u32) < 0x20 => write!(f, "\\u{:04x}", c as u32)?,
                c => f.write_char(c)?,
            }
        }
        Ok(())
    }
}

/// The end of the trace file.
pub fn trace_end(out: &mut dyn Write) -> fmt::Result {
    out.write_str("\n]}\n")
}
