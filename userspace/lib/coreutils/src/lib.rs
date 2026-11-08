// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The native basic utilities, as pure code over [`host::Host`].
//!
//! A tool is `fn(&mut H, args, scratch) -> status`: `args` are the operands
//! after the tool's name, `scratch` the working memory the caller lends
//! ([`SCRATCH_BYTES`]). The toolbox image runs them on libsys; the host tests
//! run them on an in-memory tree. One argument parser ([`argp`]), one walk
//! over trees ([`walk`]), one set of messages ([`util`]).
//!
//! Statuses: 0 done, 1 failed, 2 wrong command line, 126 refused (a Unix
//! command with no native meaning, [`refuse`]), 130 stopped.
#![no_std]

pub mod argp;
pub mod date;
pub mod fs_tools;
pub mod glob;
pub mod host;
pub mod lines;
pub mod misc_tools;
pub mod path;
pub mod refuse;
pub mod regex;
pub mod text_tools;
pub mod util;
pub mod walk;

use host::Host;

/// The scratch a tool is given: `sort` holds its input in it, `tail` its
/// window, `cp` its copy buffer.
pub const SCRATCH_BYTES: usize = 16 * 1024;

/// The scratch of the tools that only stream: a copy buffer, a line.
pub const SMALL_SCRATCH_BYTES: usize = 4096;

/// Every command this crate answers to.
pub const NAMES: &[&[u8]] = &[
    b"basename", b"chgrp", b"chmod", b"chown", b"cp", b"cut", b"date", b"df", b"dirname", b"du", b"env", b"find",
    b"grep", b"head", b"kill", b"ln", b"mkdir", b"mkfifo", b"mv", b"printf", b"pwd", b"rm", b"rmdir", b"seq",
    b"sort", b"stat", b"tail", b"tee", b"touch", b"tr", b"umask", b"uniq",
];

/// What `name` needs lent as scratch (0: none).
pub fn scratch_bytes(name: &[u8]) -> usize {
    match name {
        b"sort" | b"tail" => SCRATCH_BYTES,
        b"cp" | b"mv" | b"head" | b"grep" | b"uniq" | b"tr" | b"cut" | b"tee" => SMALL_SCRATCH_BYTES,
        _ => 0,
    }
}

pub fn is_tool(name: &[u8]) -> bool {
    NAMES.contains(&name)
}

/// Run the tool `name`; `None` when it is not one of [`NAMES`].
pub fn run<H: Host>(h: &mut H, name: &[u8], args: &[&[u8]], scratch: &mut [u8]) -> Option<i32> {
    use fs_tools as f;
    use misc_tools as m;
    use text_tools as t;
    Some(match name {
        b"basename" => m::basename(h, args, scratch),
        b"cp" => f::cp(h, args, scratch),
        b"cut" => t::cut(h, args, scratch),
        b"date" => m::date(h, args, scratch),
        b"df" => f::df(h, args, scratch),
        b"dirname" => m::dirname(h, args, scratch),
        b"du" => f::du(h, args, scratch),
        b"env" => m::env(h, args, scratch),
        b"find" => f::find(h, args, scratch),
        b"grep" => t::grep(h, args, scratch),
        b"head" => t::head(h, args, scratch),
        b"mkdir" => f::mkdir(h, args, scratch),
        b"mv" => f::mv(h, args, scratch),
        b"printf" => m::printf(h, args, scratch),
        b"pwd" => m::pwd(h, args, scratch),
        b"rm" => f::rm(h, args, scratch),
        b"rmdir" => f::rmdir(h, args, scratch),
        b"seq" => m::seq(h, args, scratch),
        b"sort" => t::sort(h, args, scratch),
        b"stat" => f::stat(h, args, scratch),
        b"tail" => t::tail(h, args, scratch),
        b"tee" => t::tee(h, args, scratch),
        b"touch" => f::touch(h, args, scratch),
        b"tr" => t::tr(h, args, scratch),
        b"uniq" => t::uniq(h, args, scratch),
        _ => return refuse::refuse(h, name),
    })
}
