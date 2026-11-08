// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The tools that name files: cp mv rm mkdir rmdir touch stat du df find.

use crate::argp::{parse_u64, Argp, Item};
use crate::date::put_datetime;
use crate::glob::glob_match;
use crate::host::{Error, FsInfo, Host, Kind, Open, Stat};
use crate::path::{base_name, PathBuf};
use crate::util::*;
use crate::walk::{Ev, Walk, DEPTH};

/// The operands of a tool, at most.
pub const OPERANDS_MAX: usize = 16;

fn kind_of<H: Host>(h: &mut H, p: &PathBuf) -> Result<Kind, Error> {
    h.stat(p.as_bytes()).map(|s| s.kind)
}

fn exists_as_dir<H: Host>(h: &mut H, p: &PathBuf) -> bool {
    matches!(kind_of(h, p), Ok(Kind::Dir))
}

fn copy_file<H: Host>(h: &mut H, from: &PathBuf, to: &PathBuf, buf: &mut [u8]) -> Result<(), Error> {
    if from.as_bytes() == to.as_bytes() {
        return Err(Error::Exists);
    }
    let src = h.open(from.as_bytes(), Open::Read)?;
    #[cfg(not(feature = "cp-no-truncate-canary"))]
    let mode = Open::Truncate;
    #[cfg(feature = "cp-no-truncate-canary")]
    let mode = Open::Create;
    let dst = match h.open(to.as_bytes(), mode) {
        Ok(d) => d,
        Err(e) => {
            h.close(src);
            return Err(e);
        }
    };
    let r = (|| -> Result<(), Error> {
        loop {
        let n = h.read(src, buf)?;
        if n == 0 {
            return Ok(());
        }
        let mut done = 0;
        while done < n {
            let w = h.write(dst, &buf[done..n])?;
            if w == 0 {
                return Err(Error::NoSpace);
            }
            done += w;
        }
        }
    })();
    h.close(src);
    h.close(dst);
    r
}

/// `from` (a file or a tree) copied to `to`, which does not exist yet or is
/// a file being replaced.
fn copy_tree<H: Host>(h: &mut H, from: &PathBuf, kind: Kind, to: &PathBuf, buf: &mut [u8]) -> Result<(), Error> {
    if kind == Kind::File {
        return copy_file(h, from, to, buf);
    }
    if to.is_within(from) {
        return Err(Error::Exists);
    }
    let mut walk = Walk::new(*from, kind);
    while let Some(ev) = walk.next(h) {
        let ev = ev?;
        if ev == Ev::DirPost {
            continue;
        }
        let mut target = *to;
        target.join(&walk.path().as_bytes()[from.len()..])?;
        match ev {
            Ev::DirPre => match h.mkdir(target.as_bytes()) {
                Ok(()) | Err(Error::Exists) => {}
                Err(e) => return Err(e),
            },
            _ => copy_file(h, walk.path(), &target, buf)?,
        }
    }
    Ok(())
}

/// Remove `p` and everything under it. Failures are said and counted, the
/// rest still goes.
fn remove_tree<H: Host>(h: &mut H, tool: &[u8], p: &PathBuf, kind: Kind) -> i32 {
    let mut status = OK;
    let mut walk = Walk::new(*p, kind);
    let mut failed_below = false;
    while let Some(ev) = walk.next(h) {
        let ev = match ev {
            Ok(e) => e,
            Err(e) => {
                say_err(h, tool, walk.path().as_bytes(), e);
                return status.max(status_of(e));
            }
        };
        let r = match ev {
            Ev::DirPre => continue,
            Ev::File => h.unlink(walk.path().as_bytes()),
            Ev::DirPost => h.rmdir(walk.path().as_bytes()),
        };
        match r {
            Ok(()) => walk.removed(),
            Err(e) => {
                if !(ev == Ev::DirPost && e == Error::NotEmpty && failed_below) {
                    say_err(h, tool, walk.path().as_bytes(), e);
                }
                failed_below = true;
                status = status.max(status_of(e));
                if e == Error::Interrupted {
                    break;
                }
            }
        }
    }
    status
}

/// Where `src` goes under `dest`: inside it when it is a directory, else
/// `dest` itself.
fn target_of<H: Host>(h: &mut H, src: &PathBuf, dest: &PathBuf, many: bool) -> Result<PathBuf, Error> {
    if exists_as_dir(h, dest) {
        let mut t = *dest;
        t.push(src.name())?;
        Ok(t)
    } else if many {
        Err(Error::NotDir)
    } else {
        Ok(*dest)
    }
}

pub fn cp<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    let mut recursive = false;
    let mut keep = false;
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"rRn");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(b'r' | b'R')) => recursive = true,
            Ok(Item::Flag(_)) => keep = true,
            Ok(Item::Operand(o)) if n < OPERANDS_MAX => {
                ops[n] = o;
                n += 1;
            }
            Ok(_) => return usage(h, b"cp", b"cp [-rn] SOURCE... DEST"),
            Err(e) => return bad_arg(h, b"cp", e),
        }
    }
    if n < 2 {
        return usage(h, b"cp", b"cp [-rn] SOURCE... DEST");
    }
    let dest = match abs(h, ops[n - 1]) {
        Ok(d) => d,
        Err(e) => {
            say_err(h, b"cp", ops[n - 1], e);
            return FAILED;
        }
    };
    let mut status = OK;
    for &s in &ops[..n - 1] {
        let r = (|| -> Result<(), Error> {
            let src = abs(h, s)?;
            let kind = kind_of(h, &src)?;
            if kind == Kind::Dir && !recursive {
                return Err(Error::IsDir);
            }
            let target = target_of(h, &src, &dest, n > 2)?;
            if keep && h.stat(target.as_bytes()).is_ok() {
                return Ok(());
            }
            copy_tree(h, &src, kind, &target, scratch)
        })();
        if let Err(e) = r {
            let why: &[u8] = if e == Error::IsDir { b"is a directory (use -r)" } else { e.text() };
            say(h, b"cp", s, why);
            status = status.max(status_of(e));
        }
    }
    status
}

pub fn mv<H: Host>(h: &mut H, args: &[&[u8]], scratch: &mut [u8]) -> i32 {
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Operand(o)) if n < OPERANDS_MAX => {
                ops[n] = o;
                n += 1;
            }
            Ok(_) => return usage(h, b"mv", b"mv SOURCE... DEST"),
            Err(e) => return bad_arg(h, b"mv", e),
        }
    }
    if n < 2 {
        return usage(h, b"mv", b"mv SOURCE... DEST");
    }
    let dest = match abs(h, ops[n - 1]) {
        Ok(d) => d,
        Err(e) => {
            say_err(h, b"mv", ops[n - 1], e);
            return FAILED;
        }
    };
    let mut status = OK;
    for &s in &ops[..n - 1] {
        let r = (|| -> Result<(), Error> {
            let src = abs(h, s)?;
            let kind = kind_of(h, &src)?;
            let target = target_of(h, &src, &dest, n > 2)?;
            if target.is_within(&src) {
                return Err(Error::Exists);
            }
            match h.rename(src.as_bytes(), target.as_bytes()) {
                Err(Error::Exists) if kind == Kind::File && kind_of(h, &target) == Ok(Kind::File) => {
                    h.unlink(target.as_bytes())?;
                    h.rename(src.as_bytes(), target.as_bytes())
                }
                Err(Error::OtherVolume) => {
                    copy_tree(h, &src, kind, &target, scratch)?;
                    match remove_tree(h, b"mv", &src, kind) {
                        OK => Ok(()),
                        _ => Err(Error::Io),
                    }
                }
                r => r,
            }
        })();
        if let Err(e) = r {
            say_err(h, b"mv", s, e);
            status = status.max(status_of(e));
        }
    }
    status
}

pub fn rm<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    let (mut recursive, mut force) = (false, false);
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"rRf");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(b'f')) => force = true,
            Ok(Item::Flag(_)) => recursive = true,
            Ok(Item::Operand(o)) if n < OPERANDS_MAX => {
                ops[n] = o;
                n += 1;
            }
            Ok(_) => return usage(h, b"rm", b"rm [-rf] FILE..."),
            Err(e) => return bad_arg(h, b"rm", e),
        }
    }
    if n == 0 {
        return if force { OK } else { usage(h, b"rm", b"rm [-rf] FILE...") };
    }
    let mut status = OK;
    for &o in &ops[..n] {
        let r = (|| -> Result<(), Error> {
            let path = abs(h, o)?;
            let kind = kind_of(h, &path)?;
            match kind {
                Kind::File => h.unlink(path.as_bytes()),
                #[cfg(not(feature = "rm-dir-without-r-canary"))]
                Kind::Dir if !recursive => Err(Error::IsDir),
                Kind::Dir if path.is_root() => Err(Error::Denied),
                Kind::Dir => {
                    status = status.max(remove_tree(h, b"rm", &path, Kind::Dir));
                    Ok(())
                }
            }
        })();
        match r {
            Ok(()) => {}
            Err(Error::NotFound) if force => {}
            Err(e) => {
                let why: &[u8] = match e {
                    Error::IsDir => b"is a directory (use -r, or rmdir)",
                    Error::Denied => b"refusing to remove the root directory",
                    e => e.text(),
                };
                say(h, b"rm", o, why);
                status = status.max(status_of(e));
            }
        }
    }
    status
}

pub fn mkdir<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    let mut parents = false;
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"p");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(_)) => parents = true,
            Ok(Item::Operand(o)) if n < OPERANDS_MAX => {
                ops[n] = o;
                n += 1;
            }
            Ok(_) => return usage(h, b"mkdir", b"mkdir [-p] DIR..."),
            Err(e) => return bad_arg(h, b"mkdir", e),
        }
    }
    if n == 0 {
        return usage(h, b"mkdir", b"mkdir [-p] DIR...");
    }
    let mut status = OK;
    for &o in &ops[..n] {
        let r = abs(h, o).and_then(|path| make_dir(h, &path, parents));
        if let Err(e) = r {
            say_err(h, b"mkdir", o, e);
            status = status.max(status_of(e));
        }
    }
    status
}

fn make_dir<H: Host>(h: &mut H, path: &PathBuf, parents: bool) -> Result<(), Error> {
    #[cfg(feature = "mkdir-p-parent-canary")]
    let parents = false;
    if !parents {
        return h.mkdir(path.as_bytes());
    }
    // Each prefix in turn: one that is already a directory is fine.
    let b = path.as_bytes();
    let mut prefix = PathBuf::root();
    for part in b.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
        prefix.push(part)?;
        match h.mkdir(prefix.as_bytes()) {
            Ok(()) => {}
            Err(Error::Exists) if exists_as_dir(h, &prefix) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn rmdir<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    if args.is_empty() {
        return usage(h, b"rmdir", b"rmdir DIR...");
    }
    let mut status = OK;
    for &o in args {
        if let Err(e) = abs(h, o).and_then(|p| h.rmdir(p.as_bytes())) {
            say_err(h, b"rmdir", o, e);
            status = status.max(status_of(e));
        }
    }
    status
}

/// Creates the files that are not there. A file that is has no time to set:
/// the filesystem stamps a file when it is written.
pub fn touch<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    if args.is_empty() {
        return usage(h, b"touch", b"touch FILE...");
    }
    let mut status = OK;
    for &o in args {
        let r = abs(h, o).and_then(|p| match kind_of(h, &p) {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => h.open(p.as_bytes(), Open::Create).map(|f| h.close(f)),
            Err(e) => Err(e),
        });
        if let Err(e) = r {
            say_err(h, b"touch", o, e);
            status = status.max(status_of(e));
        }
    }
    status
}

pub fn stat<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    if args.is_empty() {
        return usage(h, b"stat", b"stat FILE...");
    }
    let mut status = OK;
    for &o in args {
        match abs(h, o).and_then(|p| h.stat(p.as_bytes())) {
            Ok(s) => {
                if print_stat(h, o, &s).is_err() {
                    return FAILED;
                }
            }
            Err(e) => {
                say_err(h, b"stat", o, e);
                status = status.max(status_of(e));
            }
        }
    }
    status
}

fn print_stat<H: Host>(h: &mut H, name: &[u8], s: &Stat) -> Result<(), Error> {
    put(h, b"  File: ")?;
    put(h, name)?;
    put(h, if s.kind == Kind::Dir { b"\n  Type: directory\n  Size: " } else { b"\n  Type: file\n  Size: " })?;
    put_u64(h, s.size)?;
    if s.mtime != 0 {
        put(h, b" bytes\nModify: ")?;
        put_datetime(h, s.mtime)?;
        put(h, b" UTC")?;
    } else {
        put(h, b" bytes")?;
    }
    put(h, b"\n")
}

/// `bytes` as KiB rounded up, or with a unit under `-h`.
fn put_size<H: Host>(h: &mut H, bytes: u64, human: bool, apparent: bool) -> Result<(), Error> {
    if apparent {
        return put_u64(h, bytes);
    }
    if !human {
        return put_u64(h, bytes.div_ceil(1024));
    }
    let (mut v, mut unit) = (bytes.div_ceil(1024), 0usize);
    while v >= 1024 && unit < 3 {
        v = v.div_ceil(1024);
        unit += 1;
    }
    put_u64(h, v)?;
    put(h, &b"KMGT"[unit..unit + 1])
}

pub fn du<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    let (mut summary, mut human, mut apparent) = (false, false, false);
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"shb");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(b's')) => summary = true,
            Ok(Item::Flag(b'h')) => human = true,
            Ok(Item::Flag(_)) => apparent = true,
            Ok(Item::Operand(o)) if n < OPERANDS_MAX => {
                ops[n] = o;
                n += 1;
            }
            Ok(_) => return usage(h, b"du", b"du [-shb] [PATH...]"),
            Err(e) => return bad_arg(h, b"du", e),
        }
    }
    if n == 0 {
        ops[0] = b".";
        n = 1;
    }
    let mut status = OK;
    for &o in &ops[..n] {
        if let Err(e) = du_one(h, o, summary, human, apparent) {
            say_err(h, b"du", o, e);
            status = status.max(status_of(e));
        }
    }
    status
}

fn du_one<H: Host>(h: &mut H, given: &[u8], summary: bool, human: bool, apparent: bool) -> Result<(), Error> {
    let root = abs(h, given)?;
    let kind = kind_of(h, &root)?;
    let block = match h.fs_info(root.as_bytes()) {
        Ok(i) if i.block > 0 => i.block as u64,
        _ => 1,
    };
    let block = if cfg!(feature = "du-block-canary") { 1 } else { block };
    let mut acc = [0u64; DEPTH + 2];
    let mut walk = Walk::new(root, kind);
    while let Some(ev) = walk.next(h) {
        let ev = ev?;
        let lvl = walk.level();
        match ev {
            Ev::DirPre => acc[lvl] = 0,
            Ev::File => {
                let size = h.stat(walk.path().as_bytes())?.size;
                let used = if apparent { size } else { size.div_ceil(block) * block };
                if lvl == 0 {
                    du_line(h, used, given, human, apparent)?;
                } else {
                    acc[lvl - 1] += used;
                }
            }
            Ev::DirPost => {
                let total = acc[lvl];
                if lvl > 0 {
                    acc[lvl - 1] += total;
                }
                if !summary || lvl == 0 {
                    put_size(h, total, human, apparent)?;
                    put(h, b"\t")?;
                    put(h, given)?;
                    put(h, &walk.path().as_bytes()[root.len().min(walk.path().len())..])?;
                    put(h, b"\n")?;
                }
            }
        }
    }
    Ok(())
}

fn du_line<H: Host>(h: &mut H, used: u64, name: &[u8], human: bool, apparent: bool) -> Result<(), Error> {
    put_size(h, used, human, apparent)?;
    put(h, b"\t")?;
    put(h, name)?;
    put(h, b"\n")
}

pub fn df<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    let mut human = false;
    let mut ops = [&b""[..]; OPERANDS_MAX];
    let mut n = 0;
    let mut p = Argp::new(args, b"h");
    while let Some(it) = p.next() {
        match it {
            Ok(Item::Flag(_)) => human = true,
            Ok(Item::Operand(o)) if n < OPERANDS_MAX => {
                ops[n] = o;
                n += 1;
            }
            Ok(_) => return usage(h, b"df", b"df [-h] [PATH...]"),
            Err(e) => return bad_arg(h, b"df", e),
        }
    }
    if n == 0 {
        ops[0] = b".";
        n = 1;
    }
    if put(h, b"TYPE\tSIZE\tUSED\tAVAIL\tUSE%\tPATH\n").is_err() {
        return FAILED;
    }
    let mut status = OK;
    for &o in &ops[..n] {
        match abs(h, o).and_then(|p| h.fs_info(p.as_bytes())) {
            Ok(i) => {
                if df_line(h, o, &i, human).is_err() {
                    return FAILED;
                }
            }
            Err(e) => {
                say_err(h, b"df", o, e);
                status = status.max(status_of(e));
            }
        }
    }
    status
}

fn df_line<H: Host>(h: &mut H, name: &[u8], i: &FsInfo, human: bool) -> Result<(), Error> {
    let bs = i.block as u64;
    let used = i.blocks.saturating_sub(i.free);
    put(h, i.kind.name())?;
    for v in [i.blocks, used, i.free] {
        put(h, b"\t")?;
        put_size(h, v.saturating_mul(bs), human, false)?;
    }
    put(h, b"\t")?;
    if i.blocks == 0 {
        put(h, b"-")?;
    } else {
        put_u64(h, (used * 100).div_ceil(i.blocks))?;
        put(h, b"%")?;
    }
    put(h, b"\t")?;
    put(h, name)?;
    put(h, b"\n")
}

pub fn find<H: Host>(h: &mut H, args: &[&[u8]], _scratch: &mut [u8]) -> i32 {
    const USAGE_TEXT: &[u8] = b"find [PATH...] [-name GLOB] [-iname GLOB] [-type f|d] [-mindepth N] [-maxdepth N]";
    let mut roots = [&b""[..]; OPERANDS_MAX];
    let mut nroots = 0;
    let mut i = 0;
    while i < args.len() && !args[i].starts_with(b"-") && nroots < OPERANDS_MAX {
        roots[nroots] = args[i];
        nroots += 1;
        i += 1;
    }
    let (mut name, mut iname, mut kind): (Option<&[u8]>, Option<&[u8]>, Option<Kind>) = (None, None, None);
    let (mut min, mut max) = (0usize, usize::MAX);
    while i < args.len() {
        let Some(&v) = args.get(i + 1) else {
            return if args[i] == b"-print" { break } else { usage(h, b"find", USAGE_TEXT) };
        };
        match args[i] {
            b"-name" => name = Some(v),
            b"-iname" => iname = Some(v),
            b"-type" => {
                kind = match v {
                    b"f" => Some(Kind::File),
                    b"d" => Some(Kind::Dir),
                    _ => return usage(h, b"find", USAGE_TEXT),
                }
            }
            b"-mindepth" | b"-maxdepth" => match parse_u64(v) {
                Some(d) if args[i] == b"-mindepth" => min = d as usize,
                Some(d) => max = d as usize,
                None => return usage(h, b"find", USAGE_TEXT),
            },
            b"-print" => {
                i += 1;
                continue;
            }
            _ => return usage(h, b"find", USAGE_TEXT),
        }
        i += 2;
    }
    if nroots == 0 {
        roots[0] = b".";
        nroots = 1;
    }
    let mut status = OK;
    for &given in &roots[..nroots] {
        if let Err(e) = find_one(h, given, name, iname, kind, min, max) {
            say_err(h, b"find", given, e);
            status = status.max(status_of(e));
        }
    }
    status
}

fn find_one<H: Host>(
    h: &mut H,
    given: &[u8],
    name: Option<&[u8]>,
    iname: Option<&[u8]>,
    want: Option<Kind>,
    min: usize,
    max: usize,
) -> Result<(), Error> {
    let root = abs(h, given)?;
    let kind = kind_of(h, &root)?;
    let fold = h.fs_info(root.as_bytes()).is_ok_and(|i| i.kind.folds_case());
    let shown = given.strip_suffix(b"/").filter(|g| !g.is_empty()).unwrap_or(given);
    let mut walk = Walk::new(root, kind);
    while let Some(ev) = walk.next(h) {
        let ev = ev?;
        if ev == Ev::DirPost {
            continue;
        }
        let lvl = walk.level();
        let k = if ev == Ev::File { Kind::File } else { Kind::Dir };
        let leaf = if lvl == 0 { base_name(shown) } else { walk.path().name() };
        #[cfg(not(feature = "find-type-canary"))]
        let kind_ok = want.is_none_or(|w| w == k);
        #[cfg(feature = "find-type-canary")]
        let kind_ok = want.is_none_or(|w| w == k || w == Kind::File);
        let hit = lvl >= min
            && kind_ok
            && name.is_none_or(|g| glob_match(g, leaf, fold))
            && iname.is_none_or(|g| glob_match(g, leaf, true));
        if hit {
            put(h, shown)?;
            put(h, &walk.path().as_bytes()[root.len().min(walk.path().len())..])?;
            put(h, b"\n")?;
        }
        if ev == Ev::DirPre && lvl >= max {
            walk.skip_dir();
        }
    }
    Ok(())
}
