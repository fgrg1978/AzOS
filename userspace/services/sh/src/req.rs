// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Building a `SYS_SPAWN_EX` request block (RFC-0055 §5.2).
//!
//! Pure: [`ReqBuilder::finish`] returns a `SpawnReq` whose pointers name the
//! builder's own buffers, so the builder must outlive the call. Limits are
//! enforced here as well as by the kernel, so the shell can say what was too
//! big instead of reporting `-EINVAL`. `tests/host/sh-tests` checks the
//! result against `SpawnReq::check_shape`, the kernel's own check.

use azos_abi::ushell::{
    Move, SpawnReq, MOVE_CONSOLE, SPAWN_ARGC_MAX, SPAWN_ARGV_MAX, SPAWN_CWD_MAX, SPAWN_ENVC_MAX,
    SPAWN_ENV_MAX, SPAWN_MAX_MOVES, SPAWN_REQ_VERSION,
};

/// What a child fd will be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fd {
    /// Not open in the child.
    Closed,
    /// The console.
    Console,
    /// A handle of the caller's, moved to the child.
    Handle(u32),
}

/// A request under construction.
pub struct ReqBuilder {
    argv: [u8; SPAWN_ARGV_MAX],
    argv_len: usize,
    argc: usize,
    env: [u8; SPAWN_ENV_MAX],
    env_len: usize,
    envc: usize,
    cwd: [u8; SPAWN_CWD_MAX + 1],
    cwd_len: usize,
    fds: [Fd; SPAWN_MAX_MOVES],
}

fn push(buf: &mut [u8], len: &mut usize, s: &[u8]) -> bool {
    if s.contains(&0) || *len + s.len() + 1 > buf.len() {
        return false;
    }
    buf[*len..*len + s.len()].copy_from_slice(s);
    buf[*len + s.len()] = 0;
    *len += s.len() + 1;
    true
}

impl ReqBuilder {
    /// An empty request: no arguments, no environment, every fd closed.
    pub const fn new() -> Self {
        Self {
            argv: [0; SPAWN_ARGV_MAX],
            argv_len: 0,
            argc: 0,
            env: [0; SPAWN_ENV_MAX],
            env_len: 0,
            envc: 0,
            cwd: [0; SPAWN_CWD_MAX + 1],
            cwd_len: 0,
            fds: [Fd::Closed; SPAWN_MAX_MOVES],
        }
    }

    /// Append an argument. `false` if it does not fit (or holds a NUL).
    pub fn arg(&mut self, a: &[u8]) -> bool {
        self.argc < SPAWN_ARGC_MAX && push(&mut self.argv, &mut self.argv_len, a) && {
            self.argc += 1;
            true
        }
    }

    /// Append a `KEY=VALUE` string. `false` if it does not fit.
    pub fn env(&mut self, kv: &[u8]) -> bool {
        self.envc < SPAWN_ENVC_MAX && push(&mut self.env, &mut self.env_len, kv) && {
            self.envc += 1;
            true
        }
    }

    /// Set the working directory (cut to the limit; the shell keeps its own
    /// shorter than that).
    pub fn cwd(&mut self, c: &[u8]) {
        let n = c.len().min(SPAWN_CWD_MAX);
        self.cwd[..n].copy_from_slice(&c[..n]);
        self.cwd[n] = 0;
        self.cwd_len = n;
    }

    /// Set child fd `fd` (0..=7).
    pub fn fd(&mut self, fd: usize, what: Fd) {
        if fd < SPAWN_MAX_MOVES {
            self.fds[fd] = what;
        }
    }

    /// The argv strings as laid out.
    pub fn argv_blob(&self) -> &[u8] {
        &self.argv[..self.argv_len]
    }

    /// The block. Its pointers name this builder's buffers.
    pub fn finish(&self, flags: u32) -> SpawnReq {
        let mut moves = [Move::default(); SPAWN_MAX_MOVES];
        let mut n = 0;
        for (fd, what) in self.fds.iter().enumerate() {
            let handle = match *what {
                Fd::Closed => continue,
                Fd::Console => MOVE_CONSOLE,
                Fd::Handle(h) => h,
            };
            moves[n] = Move { child_fd: fd as u32, handle, perms: 0, _pad: 0 };
            n += 1;
        }
        SpawnReq {
            version: SPAWN_REQ_VERSION,
            flags,
            argv_ptr: if self.argv_len == 0 { 0 } else { self.argv.as_ptr() as u64 },
            argv_bytes: self.argv_len as u32,
            argc: self.argc as u32,
            env_ptr: if self.env_len == 0 { 0 } else { self.env.as_ptr() as u64 },
            env_bytes: self.env_len as u32,
            envc: self.envc as u32,
            cwd_ptr: if self.cwd_len == 0 { 0 } else { self.cwd.as_ptr() as u64 },
            nmoves: n as u32,
            _pad: 0,
            moves,
        }
    }
}

impl Default for ReqBuilder {
    fn default() -> Self {
        Self::new()
    }
}
