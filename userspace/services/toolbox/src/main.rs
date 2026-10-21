// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `TOOLBOX.ELF`: the user shell's multicall tool image,
//! dispatched on `argv[0]`.
//!
//! Its topology row grants, with Kconfig INSPECT, the kernel's introspection
//! regions, the admin one behind the full task view (`inspect`, `ps`), and the
//! read-only root directory; it reads and writes the fds the shell moved to it
//! (`SYS_SPAWN_EX`), the console, and files it opens beneath that directory
//! (`NODE_OPENAT`; it reads no procfs file; `ls` still names its directory by
//! path, `readdir` has no directory-relative form). A stop request ends its
//! waits with `-EINTR`; it then exits 130.
//!
//! Applets: `args` (prints argv, the environment and the working directory),
//! `beep` (a short tone on the kernel's `sound.0` endpoint: a playback stream
//! of memory-object periods, `sound.rs`; Kconfig DRV_VIRTIO_SND),
//! `cat`, `echo`, `false`, `host` (the addresses of a name, from the stack's
//! resolver), `input` (take the focus from the input server and watch the
//! events it delivers; Kconfig `INPUTD`), `inspect` (the kernel's introspection tree: all of it, a
//! subtree such as `metrics`, or `-j` for a Perfetto counter trace), `log`
//! (the kernel log `logd` keeps in `KLOGn.TXT`, filtered), `ls`,
//! `ntp` (how the SNTP client and the clock discipline stand), `ps` (the task
//! list of the introspection tree), `sleep`, `spin` (computes forever without
//! a syscall), `true`, `vm` (launch and end a guest: a client of `VMMD.ELF`'s
//! `VmCtl`, through the name server; Kconfig HV), `wc`, `window` (put a window
//! on the screen through the compositor; Kconfig `COMPOSITOR`), `yes`. `host` and `ntp`
//! call the kernel's `net` endpoint (and `ntp` the `clock` one), which its row
//! grants with `READ`.

#![no_std]
#![no_main]

use azos_libsys as sys;

// The kernel log's wire, the source `logd` writes the files with: `log` reads
// its text lines, so the ring half is unused here.
#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/klog/wire.rs"]
mod wire;

mod beep;
mod host;
mod input;
#[path = "log_view.rs"]
mod log_view;
mod metrics_view;
mod ntp;
mod ps_view;
mod sound;
mod vm;
mod window;

const PATH_MAX: usize = 128;

fn put(fd: u64, b: &[u8]) -> isize {
    let mut done = 0usize;
    while done < b.len() {
        let r = sys::write(fd, &b[done..]);
        if r <= 0 {
            return r;
        }
        done += r as usize;
    }
    done as isize
}

fn put_num(fd: u64, mut v: u64) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let _ = put(fd, &d[i..]);
}

/// `v` in decimal at the start of `out`; the digits written (at most 20).
fn fmt_num(mut v: u64, out: &mut [u8]) -> usize {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let n = d.len() - i;
    out[..n].copy_from_slice(&d[i..]);
    n
}

fn fail(what: &[u8], why: &[u8]) {
    let _ = put(2, what);
    let _ = put(2, b": ");
    let _ = put(2, why);
    let _ = put(2, b"\n");
}

/// `p` made absolute against the working directory, NUL-terminated.
fn absolute(p: &[u8], out: &mut [u8; PATH_MAX + 1]) -> Option<usize> {
    let mut n = 0usize;
    let mut push = |part: &[u8], n: &mut usize| -> Option<()> {
        for comp in part.split(|&b| b == b'/') {
            match comp {
                b"" | b"." => {}
                b".." => {
                    while *n > 0 && out[*n - 1] != b'/' {
                        *n -= 1;
                    }
                    *n = n.saturating_sub(1);
                }
                c => {
                    if *n + 1 + c.len() > PATH_MAX {
                        return None;
                    }
                    out[*n] = b'/';
                    out[*n + 1..*n + 1 + c.len()].copy_from_slice(c);
                    *n += 1 + c.len();
                }
            }
        }
        Some(())
    };
    if p.first() != Some(&b'/') {
        push(sys::cwd(), &mut n)?;
    }
    push(p, &mut n)?;
    if n == 0 {
        out[0] = b'/';
        n = 1;
    }
    out[n] = 0;
    Some(n)
}

/// Copy `from` to fd 1. Returns an exit code.
fn copy_to_stdout(from: u64) -> i32 {
    let mut b = [0u8; 1024];
    loop {
        let r = sys::read(from, &mut b);
        if r == 0 {
            return 0;
        }
        if r == sys::E_INTR {
            return 130;
        }
        if r < 0 {
            return 1;
        }
        let w = put(1, &b[..r as usize]);
        if w == sys::E_PIPE {
            return 0;
        }
        if w < 0 {
            return if w == sys::E_INTR { 130 } else { 1 };
        }
    }
}

/// Text for the console through a small buffer: `Inspector::render` writes a
/// line at a time into a `core::fmt::Write`.
struct Out {
    buf: [u8; 256],
    n: usize,
    failed: bool,
}

impl Out {
    fn flush(&mut self) {
        if self.n > 0 && put(1, &self.buf[..self.n]) < 0 {
            self.failed = true;
        }
        self.n = 0;
    }
}

impl core::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for chunk in s.as_bytes().chunks(self.buf.len()) {
            if self.n + chunk.len() > self.buf.len() {
                self.flush();
            }
            self.buf[self.n..self.n + chunk.len()].copy_from_slice(chunk);
            self.n += chunk.len();
        }
        if self.failed { Err(core::fmt::Error) } else { Ok(()) }
    }
}

/// Map the introspection region the task holds under `key`, read-only (the
/// capability carries `READ|MAP` only): its base and size in bytes. `Err(rc)`:
/// the lookup, the geometry or the map failed (no capability: the row grants
/// none, or the kernel has INSPECT off).
fn map_inspect(key: u32) -> Result<(*const u8, usize), isize> {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), key);
    if cap < 0 {
        return Err(cap);
    }
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    let rc = sys::shm_acquire_typed(cap as u32, &mut info);
    if rc < 0 {
        return Err(rc);
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        return Err(va);
    }
    Ok((va as *const u8, pages * sys::PAGE_SIZE))
}

/// Why the introspection tree could not be opened.
enum ViewErr {
    /// The row grants no public region, or the kernel has INSPECT off.
    Off,
    /// The region is not a tree this build reads.
    Format,
}

/// The tree the row's regions hold: the public region, and the admin one when
/// the row also holds the task view. After the two maps every read is a load.
fn open_view() -> Result<azos_inspect_lib::Inspector<'static>, ViewErr> {
    let public = map_inspect(azos_abi::cap::SHM_INSPECT_PUBLIC).map_err(|_| ViewErr::Off)?;
    // The admin region is optional: a row without the task view has none.
    let admin = map_inspect(azos_abi::cap::SHM_INSPECT_ADMIN).ok();
    // SAFETY: both spans are read-only mappings of the kernel's regions that
    // this task holds for its whole life; the library only loads from them.
    unsafe { azos_inspect_lib::Inspector::from_mapped(public, admin) }.map_err(|_| ViewErr::Format)
}

/// A decimal argument.
fn parse_u64(a: &[u8]) -> Option<u64> {
    if a.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &c in a {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.saturating_mul(10).saturating_add((c - b'0') as u64);
    }
    Some(v)
}

/// What `inspect` was asked for.
struct InspectOpts {
    /// `-j`: sample the counters and write a Perfetto trace.
    json: bool,
    /// `-t MS`: how long to sample.
    ms: u64,
    /// `-p MS`: sampling period (0: the kernel's refresh period).
    period_ms: u64,
    prefix: Option<&'static str>,
}

fn inspect_opts() -> Option<InspectOpts> {
    let mut o = InspectOpts { json: false, ms: 3000, period_ms: 0, prefix: None };
    let mut i = 1;
    while i < sys::argc() {
        let a = sys::arg(i)?;
        i += 1;
        match a {
            b"-j" => o.json = true,
            b"-t" | b"-p" => {
                let v = parse_u64(sys::arg(i)?)?;
                i += 1;
                if a == b"-t" {
                    o.ms = v;
                } else {
                    o.period_ms = v;
                }
            }
            _ if a.first() == Some(&b'-') || o.prefix.is_some() => return None,
            _ => o.prefix = Some(core::str::from_utf8(a).ok()?),
        }
    }
    Some(o)
}

/// `inspect [-j [-t MS] [-p MS]] [PREFIX]` (Kconfig INSPECT): the kernel's
/// introspection tree. Bare, the whole tree, indented. With a PREFIX
/// (`metrics`, `metrics/sched`), the leaves at or under it, one `path = value`
/// a line. With `-j`, the `u64` leaves under PREFIX (default `metrics`)
/// sampled for MS milliseconds (3000) every PERIOD (the kernel's refresh
/// period, the fastest a value changes) and written as a Perfetto trace of
/// counter tracks: redirect it to a file for `ui.perfetto.dev`.
///
/// The public region needs `MemObj inspect.public`; the admin one (the
/// tasks' names and states) follows when the row also holds the task view.
/// After the two maps every read is a load: no system call per value.
fn inspect() -> i32 {
    let Some(opts) = inspect_opts() else {
        fail(b"inspect", b"usage: inspect [-j [-t MS] [-p MS]] [PREFIX]");
        return 2;
    };
    let mut view = match open_view() {
        Ok(v) => v,
        Err(ViewErr::Off) => {
            fail(b"inspect", b"off (no introspection region granted)");
            return 1;
        }
        Err(ViewErr::Format) => {
            fail(b"inspect", b"the region is not a tree this build reads");
            return 1;
        }
    };
    let mut out = Out { buf: [0; 256], n: 0, failed: false };
    let ok = if opts.json {
        inspect_trace(&mut view, &opts, &mut out)
    } else if let Some(prefix) = opts.prefix {
        inspect_prefix(&mut view, prefix, &mut out)
    } else {
        view.render(&mut out).is_ok()
    };
    out.flush();
    if !ok || out.failed {
        fail(b"inspect", b"cannot read or print the tree");
        return 1;
    }
    0
}

/// The leaves at or under `prefix`, one line each.
fn inspect_prefix(view: &mut azos_inspect_lib::Inspector<'_>, prefix: &str, out: &mut Out) -> bool {
    use azos_inspect_lib::Value;
    let mut path = metrics_view::PathStack::new();
    let mut ok = true;
    let r = view.walk(&mut |_, info, v| {
        let p = path.enter(info.depth, info.name.as_str());
        if !ok || !metrics_view::under(prefix, p) {
            return;
        }
        let r = match v {
            Value::Dir => Ok(()),
            Value::U64(x) => metrics_view::flat(out, p, metrics_view::Val::U(*x)),
            Value::I64(x) => metrics_view::flat(out, p, metrics_view::Val::I(*x)),
            Value::Str(s) => metrics_view::flat(out, p, metrics_view::Val::S(s.as_str())),
            Value::Hist(h) => metrics_view::flat(out, p, metrics_view::Val::H(h.buckets())),
        };
        ok = r.is_ok();
    });
    ok && r.is_ok()
}

/// `inspect -j`: the Perfetto counter trace.
fn inspect_trace(view: &mut azos_inspect_lib::Inspector<'_>, opts: &InspectOpts, out: &mut Out) -> bool {
    use azos_inspect_lib::Value;
    let prefix = opts.prefix.unwrap_or("metrics");
    let period = match opts.period_ms {
        0 => view.read_u64("inspect/refresh_ms").ok().flatten().filter(|p| *p > 0).unwrap_or(250),
        p => p,
    };
    let samples = opts.ms / period + 1;
    let t0 = sys::vdso_now_ns();
    let mut ok = metrics_view::trace_begin(out).is_ok();
    for n in 0..samples {
        if n > 0 {
            sys::sleep(period);
        }
        let ts = sys::vdso_now_ns().saturating_sub(t0);
        let mut path = metrics_view::PathStack::new();
        let r = view.walk(&mut |_, info, v| {
            let p = path.enter(info.depth, info.name.as_str());
            if let Value::U64(x) = v {
                if ok && metrics_view::under(prefix, p) {
                    ok = metrics_view::trace_counter(out, p, ts, *x).is_ok();
                }
            }
        });
        if r.is_err() || !ok {
            return false;
        }
    }
    metrics_view::trace_end(out).is_ok()
}

/// `ps`: the live tasks, from the admin region of the introspection tree
/// (`sched/tasks/<tid>/{name, state, priority, parent}`, read with loads, no
/// system call per value): TID, parent, priority, state, name. The admin region
/// is the full task view: a row without it (or a kernel without INSPECT) has no
/// `ps`. The listing is the tree as of the next refresh after `ps` started.
fn ps() -> i32 {
    if sys::argc() > 1 {
        fail(b"ps", b"takes no arguments");
        return 2;
    }
    let mut view = match open_view() {
        Ok(v) => v,
        Err(ViewErr::Off) => {
            fail(b"ps", b"off (no introspection region granted)");
            return 1;
        }
        Err(ViewErr::Format) => {
            fail(b"ps", b"the region is not a tree this build reads");
            return 1;
        }
    };
    if !view.has_admin() {
        fail(b"ps", b"off (no task view granted)");
        return 1;
    }
    // The tree is rebuilt once a refresh period, so a task made since the last
    // rebuild (this one among them) is not in it yet: wait for the next, at
    // most two periods, so the listing holds every task that existed when
    // `ps` ran.
    let period = view.read_u64("inspect/refresh_ms").ok().flatten().filter(|p| *p > 0).unwrap_or(250);
    if let Some(admin) = view.reader(azos_inspect_lib::Source::Admin) {
        let (seen, t0) = (admin.stamp(), sys::vdso_uptime_ms());
        while admin.stamp() == seen && sys::vdso_uptime_ms().saturating_sub(t0) < 2 * period {
            sys::sleep(5);
        }
    }
    let mut table = ps_view::Table::new();
    let mut path = metrics_view::PathStack::new();
    let walked = view.walk(&mut |src, info, v| {
        use azos_inspect_lib::{Source, Value};
        if src != Source::Admin {
            return;
        }
        let p = path.enter(info.depth, info.name.as_str());
        if p == "sched/tasks" {
            // A region rebuilt during the walk is walked again from its root:
            // this directory is met once per attempt.
            table.clear();
        }
        match v {
            Value::U64(x) => table.feed(p, ps_view::Leaf::U64(*x)),
            Value::Str(s) => table.feed(p, ps_view::Leaf::Str(s.as_str())),
            _ => {}
        }
    });
    let mut out = Out { buf: [0; 256], n: 0, failed: false };
    let ok = walked.is_ok() && table.render(&mut out).is_ok();
    out.flush();
    if !ok || out.failed {
        fail(b"ps", b"cannot read or print the task list");
        return 1;
    }
    0
}

fn cat() -> i32 {
    if sys::argc() < 2 {
        return copy_to_stdout(0);
    }
    // The directory every name is opened beneath: the row's root `Cap<Dir>`.
    let root = sys::root_dir();
    if root < 0 {
        fail(b"cat", b"no root directory granted");
        return 1;
    }
    let mut st = 0;
    for i in 1..sys::argc() {
        let a = sys::arg(i).unwrap_or(b"");
        let mut p = [0u8; PATH_MAX + 1];
        let Some(n) = absolute(a, &mut p) else {
            fail(a, b"path too long");
            st = 1;
            continue;
        };
        let h = sys::open_at(root as u32, sys::below_root(&p[..n + 1]), 0);
        if h < 0 {
            fail(a, b"no such file");
            st = 1;
            continue;
        }
        let mut b = [0u8; 1024];
        loop {
            let r = sys::file_read_typed(h as u32, &mut b);
            if r <= 0 {
                break;
            }
            if put(1, &b[..r as usize]) < 0 {
                break;
            }
        }
        let _ = sys::close_typed(h as u32);
    }
    st
}

fn echo() -> i32 {
    let mut line = [0u8; 1024];
    let mut n = 0;
    for i in 1..sys::argc() {
        let a = sys::arg(i).unwrap_or(b"");
        if i > 1 && n < line.len() {
            line[n] = b' ';
            n += 1;
        }
        let k = a.len().min(line.len() - n);
        line[n..n + k].copy_from_slice(&a[..k]);
        n += k;
    }
    if n < line.len() {
        line[n] = b'\n';
        n += 1;
    }
    if put(1, &line[..n]) < 0 { 1 } else { 0 }
}

fn ls() -> i32 {
    let target = if sys::argc() > 1 { sys::arg(1).unwrap_or(b".") } else { b"." };
    let mut p = [0u8; PATH_MAX + 1];
    let Some(n) = absolute(target, &mut p) else { return 1 };
    let mut idx = 0u64;
    loop {
        let mut nm = [0u8; sys::READDIR_NAME_BYTES];
        let (mut size, mut isdir) = (0u32, 0u32);
        if sys::readdir(&p[..n + 1], idx, &mut nm, &mut size, &mut isdir) != 0 {
            break;
        }
        let l = nm.iter().position(|&b| b == 0).unwrap_or(nm.len());
        let mut line = [0u8; sys::READDIR_NAME_BYTES + 2];
        line[..l].copy_from_slice(&nm[..l]);
        let mut k = l;
        if isdir != 0 {
            line[k] = b'/';
            k += 1;
        }
        line[k] = b'\n';
        if put(1, &line[..k + 1]) < 0 {
            return 1;
        }
        idx += 1;
    }
    if idx == 0 {
        fail(target, b"empty or no such directory");
        return 1;
    }
    0
}

fn wc() -> i32 {
    let (mut lines, mut words, mut bytes) = (0u64, 0u64, 0u64);
    let mut in_word = false;
    let mut b = [0u8; 1024];
    loop {
        let r = sys::read(0, &mut b);
        if r == sys::E_INTR {
            return 130;
        }
        if r <= 0 {
            break;
        }
        for &c in &b[..r as usize] {
            bytes += 1;
            if c == b'\n' {
                lines += 1;
            }
            if c == b' ' || c == b'\n' || c == b'\t' {
                in_word = false;
            } else if !in_word {
                in_word = true;
                words += 1;
            }
        }
    }
    // One write for the whole line: the console keeps a ring-3 write whole
    // (a kernel line is deferred while it lasts), not a line made of six. On
    // aarch64 a reap marker landed between `1 2 ` and `8` (gate row
    // `sh: pipeline`).
    let mut line = [0u8; 64];
    let mut n = 0usize;
    for (i, v) in [lines, words, bytes].into_iter().enumerate() {
        if i > 0 {
            line[n] = b' ';
            n += 1;
        }
        n += fmt_num(v, &mut line[n..]);
    }
    line[n] = b'\n';
    let _ = put(1, &line[..n + 1]);
    0
}

fn args() -> i32 {
    let _ = put(1, b"argc=");
    put_num(1, sys::argc() as u64);
    let _ = put(1, b"\n");
    for i in 0..sys::argc() {
        let _ = put(1, b"argv[");
        put_num(1, i as u64);
        let _ = put(1, b"]=");
        let _ = put(1, sys::arg(i).unwrap_or(b""));
        let _ = put(1, b"\n");
    }
    let mut i = 0;
    while let Some(kv) = sys::env_at(i) {
        let _ = put(1, b"env ");
        let _ = put(1, kv);
        let _ = put(1, b"\n");
        i += 1;
    }
    let _ = put(1, b"cwd=");
    let _ = put(1, sys::cwd());
    let _ = put(1, b"\n");
    0
}

/// A line built in memory and written whole.
struct Line {
    b: [u8; 256],
    n: usize,
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let k = s.len().min(self.b.len() - self.n);
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}

/// The kernel's `net` endpoint, or the reason there is none.
fn net_endpoint(who: &[u8]) -> Option<sys::dev::NetClient<sys::dev::Ep>> {
    match sys::dev::lookup(sys::dev::key::NET, 0) {
        Some(ep) => Some(sys::dev::NetClient::new(sys::dev::Ep(ep))),
        None => {
            fail(who, b"no net endpoint: this image's row does not grant it");
            None
        }
    }
}

/// Say why an op of the `net` interface answered `code`.
fn net_failed(who: &[u8], code: u32) {
    let why: &[u8] = match code {
        sys::dev::outcome::DENIED => b"the net endpoint refused (rights or containment)",
        sys::dev::outcome::BAD_ARGUMENT => b"not a name the resolver takes",
        sys::dev::outcome::NO_SERVER => b"the call did not reach the kernel's net interface",
        _ => b"the net interface failed the call",
    };
    fail(who, why);
}

/// `host NAME`: the A and the AAAA records of NAME.
fn host() -> i32 {
    use azos_devif::net::{FAMILY_V4, FAMILY_V6};
    use sys::dev::NetCall;
    let (Some(name), 2) = (sys::arg(1), sys::argc()) else {
        fail(b"host", b"usage: host NAME");
        return 2;
    };
    let Ok(text) = core::str::from_utf8(name) else {
        fail(b"host", b"the name is not text");
        return 2;
    };
    let Some(net) = net_endpoint(b"host") else { return 1 };
    let mut found = false;
    for family in [FAMILY_V4, FAMILY_V6] {
        let Some(q) = sys::dev::Query::new(family, name) else {
            fail(b"host", b"a name of 1 to 48 bytes");
            return 2;
        };
        match sys::dev::value(net.resolve(q)) {
            Ok(a) => {
                let mut l = Line { b: [0; 256], n: 0 };
                let _ = host::write_line(&mut l, text, &a);
                let _ = put(1, &l.b[..l.n]);
                found = true;
            }
            // No address of this family: ask for the other, say so at the end.
            Err(sys::dev::outcome::NO_RESOURCE) => {}
            Err(code) => {
                net_failed(b"host", code);
                return 1;
            }
        }
    }
    if !found {
        let _ = put(2, b"host: ");
        let _ = put(2, name);
        let _ = put(2, b": no address\n");
        return 1;
    }
    0
}

/// `ntp`: the SNTP client's state and, when the row grants `clock`, the
/// discipline's.
fn ntp() -> i32 {
    use sys::dev::{ClockCall, NetCall};
    if sys::argc() != 1 {
        fail(b"ntp", b"usage: ntp");
        return 2;
    }
    let Some(net) = net_endpoint(b"ntp") else { return 1 };
    let st = match sys::dev::value(net.ntp_status()) {
        Ok(s) => s,
        Err(code) => {
            net_failed(b"ntp", code);
            return 1;
        }
    };
    let clock = sys::dev::lookup(sys::dev::key::CLOCK, 0)
        .and_then(|ep| sys::dev::value(sys::dev::ClockClient::new(sys::dev::Ep(ep)).status()).ok());
    let mut l = Line { b: [0; 256], n: 0 };
    let _ = ntp::write_report(&mut l, &st, clock.as_ref());
    let _ = put(1, &l.b[..l.n]);
    0
}

fn yes() -> i32 {
    let word = if sys::argc() > 1 { sys::arg(1).unwrap_or(b"y") } else { b"y" };
    let mut line = [0u8; 64];
    let n = word.len().min(62);
    line[..n].copy_from_slice(&word[..n]);
    line[n] = b'\n';
    loop {
        let r = put(1, &line[..n + 1]);
        if r == sys::E_PIPE {
            return 0;
        }
        if r == sys::E_INTR {
            return 130;
        }
        if r < 0 {
            return 1;
        }
    }
}

fn spin() -> i32 {
    let _ = put(1, b"spin: computing (no syscalls) until stopped\n");
    let mut x: u64 = 1;
    loop {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        core::hint::black_box(x);
    }
}

fn sleep() -> i32 {
    let ms = sys::arg(1)
        .and_then(|a| {
            let mut v = 0u64;
            for &c in a {
                if !c.is_ascii_digit() {
                    return None;
                }
                v = v.saturating_mul(10).saturating_add((c - b'0') as u64);
            }
            Some(v)
        })
        .unwrap_or(1)
        .saturating_mul(1000);
    sys::sleep(ms);
    0
}

/// `log [-n N] [-l LEVEL] [-m MODULE]` (Kconfig KLOG): the kernel log `logd`
/// keeps, oldest line first. The last N lines that pass (default 20, 0 for
/// all), at or below LEVEL (`e`, `w`, `i`, `d`, or 3 to 7; default all), from
/// modules starting with MODULE. It reads the files `logd` writes
/// (`KLOGn.TXT`, ordered by the serial each opens with) beneath the root
/// directory; it holds no capability on the ring and no write access.
fn log() -> i32 {
    let (mut n, mut level, mut module) = (20u64, wire::LEVEL_DEBUG, &b""[..]);
    let mut i = 1;
    while i < sys::argc() {
        let (Some(a), Some(v)) = (sys::arg(i), sys::arg(i + 1)) else {
            fail(b"log", b"usage: log [-n N] [-l LEVEL] [-m MODULE]");
            return 2;
        };
        i += 2;
        match a {
            b"-n" => match parse_u64(v) {
                Some(x) => n = x,
                None => return log_usage(),
            },
            b"-l" => match log_view::parse_level(v) {
                Some(x) => level = x,
                None => return log_usage(),
            },
            b"-m" => module = v,
            _ => return log_usage(),
        }
    }
    let root = sys::root_dir();
    if root < 0 {
        fail(b"log", b"no root directory granted");
        return 1;
    }
    let root = root as u32;
    // The files, oldest first: each opens with a line naming its serial.
    let mut files = [(0u64, 0u8); wire::FILE_SLOTS_MAX];
    let mut found = 0;
    for slot in 0..wire::FILE_SLOTS_MAX as u8 {
        let mut serial = None;
        read_log_file(root, slot, &mut |text: &[u8]| {
            if serial.is_none() {
                serial = wire::parse(text).and_then(|l| wire::head_serial(&l));
            }
            serial.is_none()
        });
        if let Some(s) = serial {
            files[found] = (s, slot);
            found += 1;
        }
    }
    if found == 0 {
        fail(b"log", b"no log files (logd is not running, or Kconfig KLOG is off)");
        return 1;
    }
    let filter = log_view::Filter { max_level: level, module };
    // Two passes: count what passes, then print the last N of it.
    let mut total = 0u64;
    for slot in log_view::reading_order(&mut files[..found]) {
        read_log_file(root, slot, &mut |text: &[u8]| {
            if wire::parse(text).is_some_and(|l| filter.accepts(&l)) {
                total += 1;
            }
            true
        });
    }
    let mut skip = if n == 0 { 0 } else { total.saturating_sub(n) };
    let mut out = [0u8; log_view::RENDER_MAX];
    let mut broken = false;
    for slot in log_view::reading_order(&mut files[..found]) {
        read_log_file(root, slot, &mut |text: &[u8]| {
            let Some(l) = wire::parse(text).filter(|l| filter.accepts(l)) else { return true };
            if skip > 0 {
                skip -= 1;
                return true;
            }
            let k = log_view::render(&l, &mut out);
            broken = put(1, &out[..k]) < 0;
            !broken
        });
        if broken {
            return 1;
        }
    }
    0
}

fn log_usage() -> i32 {
    fail(b"log", b"usage: log [-n N] [-l LEVEL] [-m MODULE]");
    2
}

/// Feed the lines of log file `slot` to `f` until it returns false.
fn read_log_file(root: u32, slot: u8, f: &mut dyn FnMut(&[u8]) -> bool) {
    let name = wire::file_name(slot);
    let mut path = [0u8; 4 + wire::FILE_NAME_BYTES];
    path[..4].copy_from_slice(b"fat/");
    path[4..].copy_from_slice(&name);
    let h = sys::open_at(root, &path, 0);
    if h < 0 {
        return;
    }
    let mut lines = wire::Lines::new();
    let mut buf = [0u8; 512];
    let mut more = true;
    while more {
        let r = sys::file_read_typed(h as u32, &mut buf);
        if r <= 0 {
            break;
        }
        lines.feed(&buf[..r as usize], &mut |text: &[u8]| {
            if more {
                more = f(text);
            }
        });
    }
    let _ = sys::close_typed(h as u32);
}

#[sys::main(panic_exit = 70)]
fn main() -> i32 {
    let name = sys::arg(0).unwrap_or(b"");
    // `argv[0]` may be a path: dispatch on its last component.
    let base = name.rsplit(|&b| b == b'/').next().unwrap_or(name);
    let code = match base {
        b"args" => args(),
        b"beep" => sound::run(),
        b"cat" => cat(),
        b"echo" => echo(),
        b"false" => 1,
        b"host" => host(),
        b"input" => input::run(),
        b"inspect" => inspect(),
        b"log" => log(),
        b"ls" => ls(),
        b"ntp" => ntp(),
        b"ps" => ps(),
        b"sleep" => sleep(),
        b"spin" => spin(),
        b"true" => 0,
        b"vm" => vm::run(),
        b"wc" => wc(),
        b"window" => window::run(),
        b"yes" => yes(),
        _ => {
            fail(b"toolbox", b"run as one of: args beep cat echo false host input inspect log ls ntp ps sleep spin true vm wc window yes");
            2
        }
    };
    code
}
