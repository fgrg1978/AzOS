// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The tools that filter text: head tail grep sort uniq tr cut tee.

use core::cmp::Ordering;

use crate::argp::{parse_u64, Argp, Item, NUM};
use crate::fs_tools::OPERANDS_MAX;
use crate::host::{Error, Host, Kind, Open};
use crate::lines::LineReader;
use crate::regex::{contains, Regex};
use crate::util::*;
use crate::walk::{Ev, Walk};

/// The `-n N` / `-NUM` count of head and tail, the operands, and the status
/// of a bad command line.
struct Counted<'a> {
    count: u64,
    ops: [&'a [u8]; OPERANDS_MAX],
    n: usize,
}

fn counted<'a, H: Host>(h: &mut H, tool: &[u8], args: &'a [&'a [u8]], text: &[u8]) -> Result<Counted<'a>, i32> {
    let mut c = Counted { count: 10, ops: [b""; OPERANDS_MAX], n: 0 };
    let mut p = Argp::new(args, b"n:#");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Val(b'n' | NUM, v)) => match parse_u64(v) {
                Some(k) => c.count = k,
                None => return Err(usage(h, tool, text)),
            },
            Ok(Item::Operand(o)) if c.n < OPERANDS_MAX => {
                c.ops[c.n] = o;
                c.n += 1;
            }
            Ok(_) => return Err(usage(h, tool, text)),
            Err(e) => return Err(bad_arg(h, tool, e)),
        }
    }
    Ok(c)
}

fn banner<H: Host>(h: &mut H, name: &[u8], first: &mut bool) -> Result<(), Error> {
    if !*first {
        put(h, b"\n")?;
    }
    *first = false;
    put(h, b"==> ")?;
    put(h, if name == b"-" { b"standard input" } else { name })?;
    put(h, b" <==\n")
}

pub fn head<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"head [-n N | -N] [FILE...]";
    let c = match counted(h, b"head", args, USAGE_TEXT) {
        Ok(c) => c,
        Err(s) => return s,
    };
    let limit = scratch.len().min(1024);
    let buf = &mut scratch[..limit];
    let mut first = true;
    each_input(h, b"head", &c.ops[..c.n], &mut |h, name, src| {
        if c.n > 1 {
            banner(h, name, &mut first)?;
        }
        let mut left = c.count;
        while left > 0 {
            let n = read_src(h, src, buf)?;
            if n == 0 {
                break;
            }
            let mut end = n;
            for (i, &b) in buf[..n].iter().enumerate() {
                if b == b'\n' {
                    left -= 1;
                    #[cfg(feature = "head-count-canary")]
                    {
                        left = left.saturating_sub(1);
                    }
                    if left == 0 {
                        end = i + 1;
                        break;
                    }
                }
            }
            put(h, &buf[..end])?;
        }
        Ok(())
    })
}

pub fn tail<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"tail [-n N | -N] [FILE...]";
    if args.contains(&&b"-f"[..]) {
        say(h, b"tail", b"-f", b"files have no change notification here; run tail again, or `watch tail FILE`");
        return USAGE;
    }
    let c = match counted(h, b"tail", args, USAGE_TEXT) {
        Ok(c) => c,
        Err(s) => return s,
    };
    let cap = scratch.len();
    let mut first = true;
    each_input(h, b"tail", &c.ops[..c.n], &mut |h, name, src| {
        if c.n > 1 {
            banner(h, name, &mut first)?;
        }
        // The window of the latest input; when it fills, the older half goes,
        // cut at a line.
        let mut len = 0;
        loop {
            if len == cap {
                let from = cap / 2;
                let cut = scratch[from..len].iter().position(|&b| b == b'\n').map_or(len, |p| from + p + 1);
                scratch.copy_within(cut..len, 0);
                len -= cut;
            }
            let n = read_src(h, src, &mut scratch[len..])?;
            if n == 0 {
                break;
            }
            len += n;
        }
        let win = &scratch[..len];
        let mut start = len;
        let mut seen = 0u64;
        let end = if win.last() == Some(&b'\n') { len - 1 } else { len };
        if c.count > 0 {
            start = 0;
            #[cfg(not(feature = "tail-count-canary"))]
            let want = c.count;
            #[cfg(feature = "tail-count-canary")]
            let want = c.count + 1;
            for i in (0..end).rev() {
                if win[i] == b'\n' {
                    seen += 1;
                    if seen == want {
                        start = i + 1;
                        break;
                    }
                }
            }
        }
        put(h, &win[start..])
    })
}

/// `grep`'s command line.
struct GrepOpts {
    fold: bool,
    invert: bool,
    count: bool,
    number: bool,
    list: bool,
    quiet: bool,
    fixed: bool,
    recursive: bool,
    /// `Some(true)`: `-H`, `Some(false)`: `-h`.
    names: Option<bool>,
}

pub fn grep<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"grep [-ivcnlqFrhH] [-e PATTERN] PATTERN [FILE...]";
    let mut o = GrepOpts {
        fold: false,
        invert: false,
        count: false,
        number: false,
        list: false,
        quiet: false,
        fixed: false,
        recursive: false,
        names: None,
    };
    let mut pattern: Option<&[u8]> = None;
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"ivcnlqFErRhHe:");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(b'i')) => o.fold = true,
            Ok(Item::Flag(b'v')) => o.invert = true,
            Ok(Item::Flag(b'c')) => o.count = true,
            Ok(Item::Flag(b'n')) => o.number = true,
            Ok(Item::Flag(b'l')) => o.list = true,
            Ok(Item::Flag(b'q')) => o.quiet = true,
            Ok(Item::Flag(b'F')) => o.fixed = true,
            Ok(Item::Flag(b'E')) => {}
            Ok(Item::Flag(b'r' | b'R')) => o.recursive = true,
            Ok(Item::Flag(b'h')) => o.names = Some(false),
            Ok(Item::Flag(b'H')) => o.names = Some(true),
            Ok(Item::Val(b'e', v)) => pattern = Some(v),
            Ok(Item::Operand(a)) if pattern.is_none() => pattern = Some(a),
            Ok(Item::Operand(a)) if n < OPERANDS_MAX => {
                ops[n] = a;
                n += 1;
            }
            Ok(_) => return usage(h, b"grep", USAGE_TEXT),
            Err(e) => return bad_arg(h, b"grep", e),
        }
    }
    let Some(pattern) = pattern else { return usage(h, b"grep", USAGE_TEXT) };
    let re = if o.fixed {
        None
    } else {
        match Regex::compile(pattern, o.fold) {
            Ok(r) => Some(r),
            Err(e) => {
                say(h, b"grep", pattern, e.text());
                return USAGE;
            }
        }
    };
    let m = Matcher { re: re.as_ref(), pattern, fold: o.fold };
    if n == 0 && o.recursive {
        ops[0] = b".";
        n = 1;
    }
    let show_names = o.names.unwrap_or(n > 1 || o.recursive);
    let mut any = false;
    let mut status = OK;
    if o.recursive {
        for &given in &ops[..n] {
            match grep_tree(h, given, &o, &m, show_names, scratch, &mut any) {
                Ok(()) => {}
                Err(e) => {
                    say_err(h, b"grep", given, e);
                    status = status.max(status_of(e));
                }
            }
        }
    } else {
        let s = each_input(h, b"grep", &ops[..n], &mut |h, name, src| {
            grep_source(h, src, &o, &m, show_names, name, b"", scratch, &mut any)
        });
        status = status.max(s);
    }
    if status != OK {
        return status.max(USAGE);
    }
    if any { OK } else { FAILED }
}

struct Matcher<'a> {
    re: Option<&'a Regex>,
    pattern: &'a [u8],
    fold: bool,
}

impl Matcher<'_> {
    fn hit(&self, line: &[u8]) -> bool {
        match self.re {
            Some(r) => r.is_match(line),
            None => contains(line, self.pattern, self.fold),
        }
    }
}

fn grep_tree<H: Host>(
    h: &mut H,
    given: &[u8],
    o: &GrepOpts,
    m: &Matcher,
    show_names: bool,
    scratch: &mut [u8],
    any: &mut bool,
) -> Result<(), Error> {
    let root = abs(h, given)?;
    let kind = h.stat(root.as_bytes())?.kind;
    let mut walk = Walk::new(root, kind);
    while let Some(ev) = walk.next(h) {
        if ev? != Ev::File {
            continue;
        }
        let path = *walk.path();
        let suffix = &path.as_bytes()[root.len().min(path.len())..];
        let file = match h.open(path.as_bytes(), Open::Read) {
            Ok(f) => f,
            Err(e) => {
                say_err(h, b"grep", path.as_bytes(), e);
                continue;
            }
        };
        let r = grep_source(h, Src::File(file), o, m, show_names, given, suffix, scratch, any);
        h.close(file);
        if let Err(e) = r {
            say_err(h, b"grep", path.as_bytes(), e);
            if e == Error::Interrupted {
                return Err(e);
            }
        }
        if *any && (o.quiet || o.list) && o.quiet {
            return Ok(());
        }
    }
    Ok(())
}

/// One source through the matcher; the name shown is `name` then `suffix`.
#[allow(clippy::too_many_arguments)]
fn grep_source<H: Host>(
    h: &mut H,
    src: Src<H::File>,
    o: &GrepOpts,
    m: &Matcher,
    show_names: bool,
    name: &[u8],
    suffix: &[u8],
    scratch: &mut [u8],
    any: &mut bool,
) -> Result<(), Error> {
    let mut reader = LineReader::new(scratch);
    let (mut lineno, mut hits) = (0u64, 0u64);
    while let Some(line) = reader.next(h, src)? {
        lineno += 1;
        #[cfg(not(feature = "grep-invert-canary"))]
        let selected = m.hit(line) != o.invert;
        #[cfg(feature = "grep-invert-canary")]
        let selected = m.hit(line);
        if !selected {
            continue;
        }
        hits += 1;
        *any = true;
        if o.quiet || o.list {
            break;
        }
        if o.count {
            continue;
        }
        if show_names {
            put(h, name)?;
            put(h, suffix)?;
            put(h, b":")?;
        }
        if o.number {
            put_u64(h, lineno)?;
            put(h, b":")?;
        }
        put(h, line)?;
        put(h, b"\n")?;
    }
    if o.quiet {
        return Ok(());
    }
    if o.list {
        if hits > 0 {
            put(h, name)?;
            put(h, suffix)?;
            put(h, b"\n")?;
        }
        return Ok(());
    }
    if o.count {
        if show_names {
            put(h, name)?;
            put(h, suffix)?;
            put(h, b":")?;
        }
        put_u64(h, hits)?;
        put(h, b"\n")?;
    }
    Ok(())
}

fn number_key(l: &[u8]) -> i64 {
    let t = l.iter().position(|c| !c.is_ascii_whitespace()).map_or(&l[l.len()..], |p| &l[p..]);
    let (neg, d) = match t.split_first() {
        Some((b'-', d)) => (true, d),
        Some((b'+', d)) => (false, d),
        _ => (false, t),
    };
    let mut v = 0i64;
    for &c in d.iter().take_while(|c| c.is_ascii_digit()) {
        v = v.saturating_mul(10).saturating_add((c - b'0') as i64);
    }
    if neg { -v } else { v }
}

fn order(a: &[u8], b: &[u8], numeric: bool) -> Ordering {
    #[cfg(not(feature = "sort-numeric-canary"))]
    if numeric {
        return number_key(a).cmp(&number_key(b)).then_with(|| a.cmp(b));
    }
    #[cfg(feature = "sort-numeric-canary")]
    let _ = numeric;
    a.cmp(b)
}

/// The index table of `sort`: `(offset, length)` pairs of u32 at the end of the
/// buffer, entry 0 the last 8 bytes.
struct Index<'a> {
    buf: &'a mut [u8],
}

impl Index<'_> {
    fn at(&self, i: usize) -> (usize, usize) {
        let o = self.buf.len() - 8 * (i + 1);
        let off = u32::from_le_bytes(self.buf[o..o + 4].try_into().unwrap());
        let len = u32::from_le_bytes(self.buf[o + 4..o + 8].try_into().unwrap());
        (off as usize, len as usize)
    }

    fn set(&mut self, i: usize, off: usize, len: usize) {
        let o = self.buf.len() - 8 * (i + 1);
        self.buf[o..o + 4].copy_from_slice(&(off as u32).to_le_bytes());
        self.buf[o + 4..o + 8].copy_from_slice(&(len as u32).to_le_bytes());
    }
}

pub fn sort<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"sort [-rnu] [FILE...]";
    let (mut reverse, mut numeric, mut unique) = (false, false, false);
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"rnu");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(b'r')) => reverse = true,
            Ok(Item::Flag(b'n')) => numeric = true,
            Ok(Item::Flag(_)) => unique = true,
            Ok(Item::Operand(a)) if n < OPERANDS_MAX => {
                ops[n] = a;
                n += 1;
            }
            Ok(_) => return usage(h, b"sort", USAGE_TEXT),
            Err(e) => return bad_arg(h, b"sort", e),
        }
    }
    // All the input, line ends kept, then the table of lines after it.
    let mut len = 0usize;
    let cap = scratch.len();
    let st = each_input(h, b"sort", &ops[..n], &mut |h, _, src| {
        let start = len;
        loop {
            if len == cap {
                return Err(Error::NoSpace);
            }
            let k = read_src(h, src, &mut scratch[len..])?;
            if k == 0 {
                break;
            }
            len += k;
        }
        if len > start && scratch[len - 1] != b'\n' {
            if len == cap {
                return Err(Error::NoSpace);
            }
            scratch[len] = b'\n';
            len += 1;
        }
        Ok(())
    });
    if st != OK {
        if st == FAILED && len == cap {
            say(h, b"sort", b"", b"input larger than the sort buffer");
        }
        return st.max(USAGE);
    }
    let lines = scratch[..len].iter().filter(|&&b| b == b'\n').count();
    if len + 8 * lines > cap {
        say(h, b"sort", b"", b"input larger than the sort buffer");
        return USAGE;
    }
    let (data, rest) = scratch.split_at_mut(len);
    let mut idx = Index { buf: rest };
    let (mut off, mut count) = (0usize, 0usize);
    for (k, &b) in data.iter().enumerate() {
        if b == b'\n' {
            idx.set(count, off, k - off);
            count += 1;
            off = k + 1;
        }
    }
    let key = Key { data, numeric, reverse };
    for root in (0..count / 2).rev() {
        sift(&mut idx, &key, count, root);
    }
    for end in (1..count).rev() {
        idx.swap(0, end);
        sift(&mut idx, &key, end, 0);
    }
    let mut prev: Option<usize> = None;
    for i in 0..count {
        if unique && prev.is_some_and(|p| key.cmp(&idx, p, i) == Ordering::Equal) {
            continue;
        }
        prev = Some(i);
        let (o, l) = idx.at(i);
        if put(h, &data[o..o + l]).and_then(|_| put(h, b"\n")).is_err() {
            return FAILED;
        }
    }
    OK
}

struct Key<'a> {
    data: &'a [u8],
    numeric: bool,
    reverse: bool,
}

impl Key<'_> {
    fn cmp(&self, idx: &Index, i: usize, j: usize) -> Ordering {
        let (a, b) = (idx.at(i), idx.at(j));
        let o = order(&self.data[a.0..a.0 + a.1], &self.data[b.0..b.0 + b.1], self.numeric);
        if self.reverse { o.reverse() } else { o }
    }
}

impl Index<'_> {
    fn swap(&mut self, i: usize, j: usize) {
        let (a, b) = (self.at(i), self.at(j));
        self.set(i, b.0, b.1);
        self.set(j, a.0, a.1);
    }
}

/// Heap order for `root` among the first `n` entries.
fn sift(idx: &mut Index, key: &Key, n: usize, mut root: usize) {
    loop {
        let mut child = 2 * root + 1;
        if child >= n {
            return;
        }
        if child + 1 < n && key.cmp(idx, child, child + 1) == Ordering::Less {
            child += 1;
        }
        if key.cmp(idx, root, child) != Ordering::Less {
            return;
        }
        idx.swap(root, child);
        root = child;
    }
}

pub fn uniq<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"uniq [-c | -d | -u] [FILE]";
    let (mut count, mut dups, mut only) = (false, false, false);
    let mut ops = [&b""[..]; 2];
    let mut n = 0;
    let mut p = Argp::new(args, b"cdu");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(b'c')) => count = true,
            Ok(Item::Flag(b'd')) => dups = true,
            Ok(Item::Flag(_)) => only = true,
            Ok(Item::Operand(a)) if n < 1 => {
                ops[n] = a;
                n += 1;
            }
            Ok(_) => return usage(h, b"uniq", USAGE_TEXT),
            Err(e) => return bad_arg(h, b"uniq", e),
        }
    }
    let half = scratch.len() / 2;
    let (read_buf, prev_buf) = scratch.split_at_mut(half);
    each_input(h, b"uniq", &ops[..n], &mut |h, _, src| {
        let mut reader = LineReader::new(read_buf);
        let (mut have, mut plen, mut run) = (false, 0usize, 0u64);
        loop {
            let line = reader.next(h, src)?;
            let same_as_prev = match line {
                Some(l) => have && l.len() <= prev_buf.len() && &prev_buf[..plen] == l,
                None => false,
            };
            if same_as_prev {
                run += 1;
                continue;
            }
            if have {
                flush_run(h, &prev_buf[..plen], run, count, dups, only)?;
            }
            let Some(l) = line else { return Ok(()) };
            plen = l.len().min(prev_buf.len());
            prev_buf[..plen].copy_from_slice(&l[..plen]);
            have = true;
            run = 1;
        }
    })
}

fn flush_run<H: Host>(h: &mut H, line: &[u8], run: u64, count: bool, dups: bool, only: bool) -> Result<(), Error> {
    if (dups && run < 2) || (only && run > 1) {
        return Ok(());
    }
    if count {
        #[cfg(feature = "uniq-count-canary")]
        let run = run + 1;
        let mut d = [0u8; 20];
        let s = fmt_u64(run, &mut d);
        for _ in s.len()..7 {
            put(h, b" ")?;
        }
        put(h, s)?;
        put(h, b" ")?;
    }
    put(h, line)?;
    put(h, b"\n")
}

/// A `tr` set expanded to its bytes: ranges, escapes and classes.
struct Set {
    b: [u8; 256],
    n: usize,
}

fn expand(spec: &[u8]) -> Option<Set> {
    let mut s = Set { b: [0; 256], n: 0 };
    let mut i = 0;
    let push = |s: &mut Set, c: u8| -> Option<()> {
        *s.b.get_mut(s.n)? = c;
        s.n += 1;
        Some(())
    };
    while i < spec.len() {
        if spec[i..].starts_with(b"[:") {
            let end = spec[i..].windows(2).position(|w| w == b":]")? + i;
            let name = &spec[i + 2..end];
            for c in 0..=255u8 {
                let hit = match name {
                    b"upper" => c.is_ascii_uppercase(),
                    b"lower" => c.is_ascii_lowercase(),
                    b"digit" => c.is_ascii_digit(),
                    b"alpha" => c.is_ascii_alphabetic(),
                    b"alnum" => c.is_ascii_alphanumeric(),
                    b"space" => c == b' ' || (b'\t'..=b'\r').contains(&c),
                    _ => return None,
                };
                if hit {
                    push(&mut s, c)?;
                }
            }
            i = end + 2;
            continue;
        }
        let (c, used) = unescape(&spec[i..]);
        i += used;
        if spec.get(i) == Some(&b'-') && i + 1 < spec.len() {
            let (hi, used) = unescape(&spec[i + 1..]);
            i += 1 + used;
            #[cfg(not(feature = "tr-range-canary"))]
            let hi_end = hi;
            #[cfg(feature = "tr-range-canary")]
            let hi_end = hi.saturating_sub(1);
            if hi < c {
                return None;
            }
            for x in c..=hi_end {
                push(&mut s, x)?;
            }
        } else {
            push(&mut s, c)?;
        }
    }
    Some(s)
}

/// The byte at the start of `s` and the bytes it took (`\n`, `\t`, `\r`, `\\`).
fn unescape(s: &[u8]) -> (u8, usize) {
    match (s[0], s.get(1)) {
        (b'\\', Some(b'n')) => (b'\n', 2),
        (b'\\', Some(b't')) => (b'\t', 2),
        (b'\\', Some(b'r')) => (b'\r', 2),
        (b'\\', Some(&c)) => (c, 2),
        (c, _) => (c, 1),
    }
}

pub fn tr<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"tr [-ds] SET1 [SET2]";
    let (mut delete, mut squeeze) = (false, false);
    let mut sets = [&b""[..]; 3];
    let mut n = 0;
    let mut p = Argp::new(args, b"ds");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(b'd')) => delete = true,
            Ok(Item::Flag(_)) => squeeze = true,
            Ok(Item::Operand(a)) if n < 3 => {
                sets[n] = a;
                n += 1;
            }
            Ok(_) => return usage(h, b"tr", USAGE_TEXT),
            Err(e) => return bad_arg(h, b"tr", e),
        }
    }
    let translate = !delete && n == 2;
    if n == 0 || n > 2 || (delete && n != 1 + squeeze as usize) || (!delete && !squeeze && n != 2) {
        return usage(h, b"tr", USAGE_TEXT);
    }
    let (Some(s1), s2) = (expand(sets[0]), if n == 2 { expand(sets[1]) } else { None }) else {
        say(h, b"tr", sets[0], b"not a character set");
        return USAGE;
    };
    if n == 2 && s2.is_none() {
        say(h, b"tr", sets[1], b"not a character set");
        return USAGE;
    }
    let mut map = [0u8; 256];
    let mut in1 = [false; 256];
    for (c, m) in map.iter_mut().enumerate() {
        *m = c as u8;
    }
    for (i, &c) in s1.b[..s1.n].iter().enumerate() {
        in1[c as usize] = true;
        if let Some(s2) = &s2 {
            if translate && s2.n > 0 {
                map[c as usize] = s2.b[i.min(s2.n - 1)];
            }
        }
    }
    // The squeezed set is the last one given.
    let mut sq = [false; 256];
    if squeeze {
        let last = s2.as_ref().unwrap_or(&s1);
        for &c in &last.b[..last.n] {
            sq[c as usize] = true;
        }
    }
    let (inb, outb) = scratch.split_at_mut(scratch.len() / 2);
    let mut prev: Option<u8> = None;
    loop {
        let k = match h.stdin(inb) {
            Ok(0) => return OK,
            Ok(k) => k,
            Err(e) => {
                say_err(h, b"tr", b"", e);
                return status_of(e);
            }
        };
        let mut o = 0;
        for &c in &inb[..k] {
            if delete && in1[c as usize] {
                continue;
            }
            let m = map[c as usize];
            if squeeze && sq[m as usize] && prev == Some(m) {
                continue;
            }
            prev = Some(m);
            outb[o] = m;
            o += 1;
        }
        if put(h, &outb[..o]).is_err() {
            return FAILED;
        }
    }
}

/// A `cut` list: `N`, `N-M`, `N-`, `-M`, separated by commas.
struct Ranges {
    r: [(usize, usize); 8],
    n: usize,
}

fn ranges(list: &[u8]) -> Option<Ranges> {
    let mut out = Ranges { r: [(0, 0); 8], n: 0 };
    for part in list.split(|&c| c == b',') {
        let dash = part.iter().position(|&c| c == b'-');
        let (lo, hi) = match dash {
            None => {
                let v = parse_u64(part)? as usize;
                (v, v)
            }
            Some(d) => {
                let lo = if d == 0 { 1 } else { parse_u64(&part[..d])? as usize };
                let hi = if d + 1 == part.len() { usize::MAX } else { parse_u64(&part[d + 1..])? as usize };
                (lo, hi)
            }
        };
        if lo == 0 || out.n == out.r.len() {
            return None;
        }
        out.r[out.n] = (lo, hi);
        out.n += 1;
    }
    Some(out)
}

impl Ranges {
    /// Is position `p` (counted from 1) in the list.
    fn has(&self, p: usize) -> bool {
        #[cfg(not(feature = "cut-range-canary"))]
        return self.r[..self.n].iter().any(|&(lo, hi)| lo <= p && p <= hi);
        #[cfg(feature = "cut-range-canary")]
        return self.r[..self.n].iter().any(|&(lo, hi)| lo <= p && (p < hi || lo == hi && p == hi));
    }
}

pub fn cut<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"cut -f LIST [-d DELIM] [-s] | -c LIST [FILE...]";
    let (mut delim, mut fields, mut chars, mut only) = (b'\t', None, None, false);
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"d:f:c:b:s");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Val(b'd', v)) if v.len() == 1 => delim = v[0],
            Ok(Item::Val(b'f', v)) => fields = Some(v),
            Ok(Item::Val(_, v)) => chars = Some(v),
            Ok(Item::Flag(_)) => only = true,
            Ok(Item::Operand(a)) if n < OPERANDS_MAX => {
                ops[n] = a;
                n += 1;
            }
            Ok(_) => return usage(h, b"cut", USAGE_TEXT),
            Err(e) => return bad_arg(h, b"cut", e),
        }
    }
    let (list, by_field) = match (fields, chars) {
        (Some(f), None) => (f, true),
        (None, Some(c)) => (c, false),
        _ => return usage(h, b"cut", USAGE_TEXT),
    };
    let Some(r) = ranges(list) else {
        say(h, b"cut", list, b"not a list of positions (N, N-M, N-, -M)");
        return USAGE;
    };
    each_input(h, b"cut", &ops[..n], &mut |h, _, src| {
        let mut reader = LineReader::new(scratch);
        while let Some(line) = reader.next(h, src)? {
            if by_field {
                if !line.contains(&delim) {
                    if !only {
                        put(h, line)?;
                        put(h, b"\n")?;
                    }
                    continue;
                }
                let mut first = true;
                for (k, f) in line.split(|&c| c == delim).enumerate() {
                    if r.has(k + 1) {
                        if !first {
                            put(h, &[delim])?;
                        }
                        first = false;
                        put(h, f)?;
                    }
                }
            } else {
                for (k, &c) in line.iter().enumerate() {
                    if r.has(k + 1) {
                        put(h, &[c])?;
                    }
                }
            }
            put(h, b"\n")?;
        }
        Ok(())
    })
}

pub fn tee<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    const FILES_MAX: usize = 4;
    let mut append = false;
    let mut ops = [&b""[..]; FILES_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"a");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(_)) => append = true,
            Ok(Item::Operand(a)) if n < FILES_MAX => {
                ops[n] = a;
                n += 1;
            }
            Ok(_) => return usage(h, b"tee", b"tee [-a] [FILE...] (at most 4 files)"),
            Err(e) => return bad_arg(h, b"tee", e),
        }
    }
    let mut files: [Option<H::File>; FILES_MAX] = [None; FILES_MAX];
    let mut status = OK;
    for (i, &name) in ops[..n].iter().enumerate() {
        let mode = if append { Open::Append } else { Open::Truncate };
        match abs(h, name).and_then(|p| h.open(p.as_bytes(), mode)) {
            Ok(f) => files[i] = Some(f),
            Err(e) => {
                say_err(h, b"tee", name, e);
                status = FAILED;
            }
        }
    }
    loop {
        let k = match h.stdin(scratch) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) => {
                say_err(h, b"tee", b"", e);
                status = status.max(status_of(e));
                break;
            }
        };
        if put(h, &scratch[..k]).is_err() {
            status = FAILED;
            break;
        }
        for i in 0..FILES_MAX {
            let Some(f) = files[i] else { continue };
            let mut done = 0;
            while done < k {
                match h.write(f, &scratch[done..k]) {
                    Ok(w) if w > 0 => done += w,
                    r => {
                        say(h, b"tee", ops[i], r.err().unwrap_or(Error::NoSpace).text());
                        files[i] = None;
                        status = FAILED;
                        break;
                    }
                }
            }
        }
    }
    for f in files.into_iter().flatten() {
        h.close(f);
    }
    status
}

#[allow(dead_code)]
fn unused(_: Kind) {}
