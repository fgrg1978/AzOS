// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `why woke [N]`: the last wakes of the machine, each with its source, its
//! target and its time, and the first Domain groups the tree publishes (in bind order, not ranked).
//!
//! Read from the introspection tree (`metrics/wake/`,
//! `kernel/src/boot/inspect_metrics.rs`; Kconfig `WAKE_RING_ENTRIES`), with
//! loads, no system call per value:
//!
//! ```text
//! metrics/wake/total        wakes since boot (a counter)
//! metrics/wake/offered      the wakes the ring was offered (a counter)
//! metrics/wake/now_us       the clock, in microseconds, when the values were written
//! metrics/wake/sources      the source names, in number order, separated by spaces
//! metrics/wake/r<K>         the K-th newest wake: [seq, at_us, src, line, domain, cpu, from_cpu]
//! metrics/wake/d<G>/{domain, wakes, per_s}
//! wake/now_us               (admin region) the same clock, when the admin tree was written
//! wake/r<K>                 (admin region) the public row and then [tid, waker]
//! ```
//!
//! Two views, one reader. The public region is one for every task that maps it,
//! so it carries no task ID: its rows say what woke which Domain, from which
//! source, and nothing that names a task. A program whose row also holds the
//! admin region (the task view) reads the entries from there, with the task
//! woken and its waker; `why woke` takes the admin view when the admin tree
//! holds the log, else the public one, and says which at the head of the
//! listing ([`View`]). The counters and the Domain groups are public in both.
//!
//! Plain Rust over `core::fmt` and the tree reader, compiled by the host tests
//! (`tests/host/inspect-tests/src/metrics.rs`) through a `#[path]` include.

use core::fmt::{self, Write};

use azos_inspect_lib::{Inspector, Source, Value};

/// Buckets of a ring entry's node in the public region; the admin node has
/// [`ADMIN_FIELDS`], the same and then the task woken and its waker.
pub const FIELDS: usize = 7;
pub const ADMIN_FIELDS: usize = FIELDS + 2;
/// Entries printed by default, and at most.
pub const DEFAULT_ROWS: usize = 16;
pub const ROWS_MAX: usize = 64;
/// Domain groups the tree has (`DOMAIN_GROUPS`).
const GROUPS: usize = 4;

/// Which region the entries were read from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// Without task IDs: all the public region has.
    #[default]
    Public,
    /// With the task woken and its waker: the admin region.
    Admin,
}

/// One wake, as the tree holds it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub seq: u64,
    pub at_us: u64,
    pub src: u8,
    /// The interrupt line of an `irq` wake, else 0.
    pub line: u32,
    /// The Domain key of the task woken; 0 is a kernel task.
    pub domain: u32,
    pub cpu: u8,
    pub from_cpu: u8,
    /// The task woken and the task that woke it (0: the source names none).
    /// Read from the admin region only; 0 in the public view, where they are not.
    pub tid: u32,
    pub waker: u32,
}

impl Row {
    /// A node of the public region (`FIELDS` numbers) or of the admin one.
    fn of(b: &[u64]) -> Option<Row> {
        if b.len() != FIELDS && b.len() != ADMIN_FIELDS {
            return None;
        }
        Some(Row {
            seq: b[0],
            at_us: b[1],
            src: b[2] as u8,
            line: b[3] as u32,
            domain: b[4] as u32,
            cpu: b[5] as u8,
            from_cpu: b[6] as u8,
            tid: b.get(7).map_or(0, |v| *v as u32),
            waker: b.get(8).map_or(0, |v| *v as u32),
        })
    }
}

/// A Domain group of the tree: its key, the wakes it was the target of and the
/// rate over the last refresh.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Group {
    pub domain: u64,
    pub wakes: u64,
    pub per_s: u64,
}

/// What `why woke` read.
pub struct Report {
    pub view: View,
    pub now_us: u64,
    pub total: u64,
    pub offered: u64,
    /// Entries read, newest first.
    pub n: usize,
    pub rows: [Row; ROWS_MAX],
    pub groups: [Group; GROUPS],
    /// Source names separated by spaces (`metrics/wake/sources`), copied.
    names: [u8; 128],
    names_len: usize,
}

impl Report {
    /// The name of source number `n`; `?` for one the kernel did not list.
    pub fn source(&self, n: u8) -> &str {
        let all = core::str::from_utf8(&self.names[..self.names_len]).unwrap_or("");
        all.split(' ').nth(n as usize).filter(|s| !s.is_empty()).unwrap_or("?")
    }
}

/// Why the tree could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The tree has no `metrics/wake` (a kernel with `WAKE_RING_ENTRIES` 0, or
    /// no introspection at all).
    Off,
    Tree,
}

/// Read up to `want` of the newest wakes and the Domain counters: the entries
/// from the admin region when the view holds it and the admin tree has the log,
/// else from the public one.
pub fn read(view: &mut Inspector<'_>, want: usize, report: &mut Report) -> Result<(), ReadError> {
    let want = want.min(ROWS_MAX);
    report.n = 0;
    let Some(total) = view.read_u64("metrics/wake/total").map_err(|_| ReadError::Tree)? else {
        return Err(ReadError::Off);
    };
    report.total = total;
    report.offered = view.read_u64("metrics/wake/offered").map_err(|_| ReadError::Tree)?.unwrap_or(0);
    // The two regions have no path in common, so the node says which it is in.
    // An admin region that cannot be read (a rebuild that did not settle) is the
    // public view, which says so.
    let (prefix, clock) = match view.read("wake/now_us").ok().flatten() {
        Some((Source::Admin, Value::U64(t))) => {
            report.view = View::Admin;
            ("wake/r", t)
        }
        _ => {
            report.view = View::Public;
            ("metrics/wake/r", view.read_u64("metrics/wake/now_us").map_err(|_| ReadError::Tree)?.unwrap_or(0))
        }
    };
    report.now_us = clock;
    report.names_len = 0;
    if let Some((_, Value::Str(s))) = view.read("metrics/wake/sources").map_err(|_| ReadError::Tree)? {
        let s = s.as_str().as_bytes();
        let n = s.len().min(report.names.len());
        report.names[..n].copy_from_slice(&s[..n]);
        report.names_len = n;
    }
    let mut path = Path::new();
    for k in 0..want {
        let p = path.set(prefix, k);
        let Some((_, Value::Hist(h))) = view.read(p).map_err(|_| ReadError::Tree)? else { break };
        let Some(row) = Row::of(h.buckets()) else { break };
        // A slot the kernel had no entry for yet (a young boot) is all zeros
        // with seq 0 and no time: it is not a wake.
        if row.at_us == 0 {
            break;
        }
        report.rows[report.n] = row;
        report.n += 1;
    }
    for g in 0..GROUPS {
        let mut out = Group::default();
        for (leaf, slot) in [("domain", &mut out.domain), ("wakes", &mut out.wakes), ("per_s", &mut out.per_s)] {
            let p = path.group(g, leaf);
            *slot = view.read_u64(p).map_err(|_| ReadError::Tree)?.unwrap_or(0);
        }
        report.groups[g] = out;
    }
    Ok(())
}

impl Report {
    pub const fn new() -> Report {
        Report {
            view: View::Public,
            now_us: 0,
            total: 0,
            offered: 0,
            n: 0,
            rows: [Row { seq: 0, at_us: 0, src: 0, line: 0, domain: 0, cpu: 0, from_cpu: 0, tid: 0, waker: 0 }; ROWS_MAX],
            groups: [Group { domain: 0, wakes: 0, per_s: 0 }; GROUPS],
            names: [0; 128],
            names_len: 0,
        }
    }
}

/// A path built in a stack buffer.
struct Path {
    buf: [u8; 40],
    len: usize,
}

impl Path {
    const fn new() -> Path {
        Path { buf: [0; 40], len: 0 }
    }

    fn set(&mut self, prefix: &str, n: usize) -> &str {
        self.len = 0;
        let _ = write!(self, "{prefix}{n}");
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    fn group(&mut self, g: usize, leaf: &str) -> &str {
        self.len = 0;
        let _ = write!(self, "metrics/wake/d{g}/{leaf}");
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Write for Path {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.buf.get_mut(self.len..end).ok_or(fmt::Error)?.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// An age in microseconds, in the unit that keeps three digits: `850us`,
/// `12.3ms`, `4.52s`, `3m07s`.
pub fn age(w: &mut dyn Write, us: u64) -> fmt::Result {
    match us {
        0..=999 => write!(w, "{us}us"),
        1_000..=99_999 => write!(w, "{}.{}ms", us / 1000, us % 1000 / 100),
        100_000..=999_999 => write!(w, "{}ms", us / 1000),
        1_000_000..=59_999_999 => write!(w, "{}.{:02}s", us / 1_000_000, us % 1_000_000 / 10_000),
        _ => write!(w, "{}m{:02}s", us / 60_000_000, us / 1_000_000 % 60),
    }
}

const HEADER_PUBLIC: &str = "     AGE      SEQ SOURCE     FROM         DOMAIN       CPU\n";
const HEADER_ADMIN: &str = "     AGE      SEQ SOURCE     FROM         WOKE         DOMAIN       CPU\n";

/// The sources that are the machine's own and name no waker (`azos_sched::wake_log::names_waker`):
/// the public view prints a dash for them and `(admin)` for a wake a task made.
const MACHINE_SOURCES: [&str; 4] = ["timer", "irq", "isr", "reap"];

/// The listing: the view it was read from, the header, a line a wake (newest
/// first), then the Domains that have been woken.
pub fn render(r: &Report, w: &mut dyn Write) -> fmt::Result {
    let view = match r.view {
        View::Admin => "admin view",
        View::Public => "public view: task IDs are in the admin region, which this program does not hold",
    };
    writeln!(w, "{} wakes since boot, {} offered to the ring; the last {} logged below ({view})", r.total, r.offered, r.n)?;
    w.write_str(if r.view == View::Admin { HEADER_ADMIN } else { HEADER_PUBLIC })?;
    for row in &r.rows[..r.n] {
        // A column is padded through a buffer: `{:>8}` pads a `Display`
        // that writes in pieces by its first piece only.
        let mut col = Col::new();
        age(&mut col, r.now_us.saturating_sub(row.at_us))?;
        let src = r.source(row.src);
        write!(w, "{:>8} {:>8} {:<10} ", col.as_str(), row.seq, src)?;
        let mut from = Col::new();
        match (src, r.view, row.waker) {
            ("irq", _, _) => write!(from, "line {}", row.line)?,
            (s, _, _) if MACHINE_SOURCES.contains(&s) => from.write_str("-")?,
            (_, View::Public, _) => from.write_str("(admin)")?,
            (_, View::Admin, 0) => from.write_str("-")?,
            (_, View::Admin, tid) => write!(from, "tid {tid}")?,
        }
        write!(w, "{:<12} ", from.as_str())?;
        if r.view == View::Admin {
            let mut woke = Col::new();
            write!(woke, "tid {}", row.tid)?;
            write!(w, "{:<12} ", woke.as_str())?;
        }
        let mut dom = Col::new();
        if row.domain == 0 {
            dom.write_str("kernel")?;
        } else {
            write!(dom, "{:#x}", row.domain)?;
        }
        write!(w, "{:<12} {}", dom.as_str(), row.cpu)?;
        if row.from_cpu != row.cpu {
            write!(w, " (from {})", row.from_cpu)?;
        }
        w.write_str("\n")?;
    }
    let mut any = false;
    for g in r.groups.iter().filter(|g| g.domain != 0) {
        if !any {
            any = true;
            writeln!(w, "woken Domains (key, wakes, per second):")?;
        }
        writeln!(w, "  {:#x} {:>10} {:>7}/s", g.domain, g.wakes, g.per_s)?;
    }
    Ok(())
}

/// A short text, to pad.
struct Col {
    buf: [u8; 24],
    len: usize,
}

impl Col {
    const fn new() -> Col {
        Col { buf: [0; 24], len: 0 }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Write for Col {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.buf.get_mut(self.len..end).ok_or(fmt::Error)?.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The line `why` prints before its usage when `woke` was misused.
pub const USAGE: &str = "usage: why woke [N], N from 1 to 64";

/// `why woke [N]`'s arguments: the number of wakes to print.
pub fn parse_count(args: &[&str]) -> Option<usize> {
    match args {
        [] => Some(DEFAULT_ROWS),
        [n] => n.parse::<usize>().ok().filter(|n| (1..=ROWS_MAX).contains(n)),
        _ => None,
    }
}
