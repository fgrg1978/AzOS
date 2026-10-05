// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The user shell's ABI (RFC-0055, wave 11): the `SYS_SPAWN_EX` request block,
//! the startup block a spawned child receives, and the flag values of
//! `SYS_PIPE_TYPED`, `SYS_CONSOLE_WAIT` and `SYS_TASK_KILL`.
//!
//! Everything here is little-endian `repr(C)` with its size and offsets
//! asserted below, and pure: the kernel builds a startup block with
//! [`layout_startup`], `libsys` reads it back with [`StartupBlock::validate`],
//! and `tests/host/abi-tests` checks both against each other.

// ── SYS_PIPE_TYPED (607) ────────────────────────────────────────────────────

/// `SYS_PIPE_TYPED` flag: reads of an empty pipe and writes to a full one
/// answer `-EAGAIN` instead of blocking.
pub const PIPE_NONBLOCK: u64 = 1;

/// A write of at most this many bytes to a pipe is all-or-block: it is never
/// split around another writer's bytes. Larger writes are written in pieces.
/// Equal to the ring's capacity.
pub const PIPE_ATOMIC: usize = 4096;

// ── SYS_SPAWN_EX (608) ──────────────────────────────────────────────────────

/// The one `SpawnReq` version this kernel accepts.
pub const SPAWN_REQ_VERSION: u32 = 1;

/// `SpawnReq::flags`: when the caller exits, the kernel force-stops this child
/// (signal 1) by the same path `SYS_TASK_KILL` takes.
pub const SPAWN_F_DIE_WITH_PARENT: u32 = 1;
/// `SpawnReq::flags`: reserved by RFC-0055 for mapping the per-task vDSO page
/// (the stop word) before release. Not implemented: refused with `-EINVAL`.
pub const SPAWN_F_MAP_TASK_PAGE: u32 = 2;
/// `SpawnReq::flags` (wave 13): the caller, the console's input owner, lends
/// console input to this child for the child's life when the child is a Linux
/// task (a native child has no console read; the flag changes nothing for
/// it). While lent, the child and its descendants read the console through
/// the kernel's line discipline, `^C` is `SIGINT` to the child and its
/// descendants, and the owner's own `SYS_CONSOLE_WAIT` sees no input.
pub const SPAWN_F_CONSOLE_IN: u32 = 4;
/// Every flag this kernel implements.
pub const SPAWN_F_KNOWN: u32 = SPAWN_F_DIE_WITH_PARENT | SPAWN_F_CONSOLE_IN;

/// `Move::handle` value meaning "the child's fd is the console". It moves
/// nothing.
pub const MOVE_CONSOLE: u32 = 0xFFFF_FFFF;

/// Most entries in a move list, and the number of child fds (0..=7).
pub const SPAWN_MAX_MOVES: usize = 8;
/// Child fds a startup block describes.
pub const STARTUP_FDS: usize = 8;
/// Most bytes of NUL-separated argv strings.
pub const SPAWN_ARGV_MAX: usize = 1024;
/// Most bytes of NUL-separated `KEY=VALUE` strings.
pub const SPAWN_ENV_MAX: usize = 1024;
/// Most argv strings.
pub const SPAWN_ARGC_MAX: usize = 16;
/// Most environment strings.
pub const SPAWN_ENVC_MAX: usize = 16;
/// Most bytes of the working directory, its NUL excluded.
pub const SPAWN_CWD_MAX: usize = 64;

/// One move-list entry: give the caller's `handle` to the child as `child_fd`
/// with rights `perms` (a subset of what the caller holds; 0 keeps them).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Move {
    /// The child's fd, 0..=7.
    pub child_fd: u32,
    /// A `Cap<File>` descriptor or `Cap<Pipe>` handle the caller holds, or
    /// [`MOVE_CONSOLE`].
    pub handle: u32,
    /// `CapPerms` bits the child gets; 0 = the caller's.
    pub perms: u32,
    /// Zero.
    pub _pad: u32,
}

/// The `SYS_SPAWN_EX` request block (version 1).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpawnReq {
    /// [`SPAWN_REQ_VERSION`].
    pub version: u32,
    /// `SPAWN_F_*`.
    pub flags: u32,
    /// NUL-separated argv strings (each ends with a NUL), or 0.
    pub argv_ptr: u64,
    /// Bytes at `argv_ptr`, at most [`SPAWN_ARGV_MAX`].
    pub argv_bytes: u32,
    /// Strings at `argv_ptr`, at most [`SPAWN_ARGC_MAX`]; must match.
    pub argc: u32,
    /// NUL-separated `KEY=VALUE` strings, or 0.
    pub env_ptr: u64,
    /// Bytes at `env_ptr`, at most [`SPAWN_ENV_MAX`].
    pub env_bytes: u32,
    /// Strings at `env_ptr`, at most [`SPAWN_ENVC_MAX`]; must match.
    pub envc: u32,
    /// NUL-terminated working directory, or 0.
    pub cwd_ptr: u64,
    /// Entries used in `moves`.
    pub nmoves: u32,
    /// Zero.
    pub _pad: u32,
    /// The move list.
    pub moves: [Move; SPAWN_MAX_MOVES],
}

/// Size of [`SpawnReq`] in bytes.
pub const SPAWN_REQ_SIZE: usize = 184;
const _: () = assert!(core::mem::size_of::<Move>() == 16);
const _: () = assert!(core::mem::size_of::<SpawnReq>() == SPAWN_REQ_SIZE);
const _: () = assert!(core::mem::offset_of!(SpawnReq, argv_ptr) == 8);
const _: () = assert!(core::mem::offset_of!(SpawnReq, env_ptr) == 24);
const _: () = assert!(core::mem::offset_of!(SpawnReq, cwd_ptr) == 40);
const _: () = assert!(core::mem::offset_of!(SpawnReq, nmoves) == 48);
const _: () = assert!(core::mem::offset_of!(SpawnReq, moves) == 56);

/// Why a [`SpawnReq`] is malformed, before any handle or file is looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnReqError {
    /// Version, flags, a count over its limit, a fd out of range, a fd named
    /// twice, or padding not zero: `-EINVAL`.
    Invalid,
}

impl SpawnReq {
    /// Check everything that does not need user memory or a capability table.
    pub fn check_shape(&self) -> Result<(), SpawnReqError> {
        let e = Err(SpawnReqError::Invalid);
        if self.version != SPAWN_REQ_VERSION || self._pad != 0 {
            return e;
        }
        if self.flags & !SPAWN_F_KNOWN != 0 {
            return e;
        }
        if self.argv_bytes as usize > SPAWN_ARGV_MAX || self.argc as usize > SPAWN_ARGC_MAX
            || self.env_bytes as usize > SPAWN_ENV_MAX || self.envc as usize > SPAWN_ENVC_MAX
        {
            return e;
        }
        if (self.argv_ptr == 0) != (self.argv_bytes == 0) || (self.env_ptr == 0) != (self.env_bytes == 0) {
            return e;
        }
        let n = self.nmoves as usize;
        if n > SPAWN_MAX_MOVES {
            return e;
        }
        let mut seen = 0u32;
        for m in &self.moves[..n] {
            if m.child_fd as usize >= STARTUP_FDS || m._pad != 0 || m.perms > 0xF {
                return e;
            }
            let bit = 1u32 << m.child_fd;
            if seen & bit != 0 {
                return e;
            }
            seen |= bit;
        }
        Ok(())
    }
}

/// How many NUL-terminated strings `blob` holds, or `None` if it is not a
/// sequence of them (empty strings are allowed; a missing final NUL is not).
pub fn count_cstrs(blob: &[u8]) -> Option<usize> {
    if blob.is_empty() {
        return Some(0);
    }
    if *blob.last()? != 0 {
        return None;
    }
    Some(blob.iter().filter(|&&b| b == 0).count())
}

// ── The startup block ───────────────────────────────────────────────────────

/// `StartupBlock::magic`: `"KSB1"` read as a little-endian `u32`.
pub const STARTUP_MAGIC: u32 = u32::from_le_bytes(*b"KSB1");
/// `StartupBlock::version`.
pub const STARTUP_VERSION: u32 = 1;

/// A child fd that is not open.
pub const FD_CLOSED: u32 = 0;
/// A child fd that is the console (`SYS_WRITE` for 1 and 2).
pub const FD_CONSOLE: u32 = 1;
/// A child fd that is a capability handle in the child's own table.
pub const FD_HANDLE: u32 = 2;

/// One child fd in a startup block.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartupFd {
    /// `FD_CLOSED`, `FD_CONSOLE` or `FD_HANDLE`.
    pub kind: u32,
    /// The handle, for `FD_HANDLE`. Two fds naming one handle alias it (`2>&1`).
    pub handle: u32,
}

/// What a child spawned by `SYS_SPAWN_EX` receives: its address is in `a1`
/// (`x1`) at the image's entry point. The strings it points at sit beside it
/// at the top of the child's stack.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartupBlock {
    /// [`STARTUP_MAGIC`].
    pub magic: u32,
    /// [`STARTUP_VERSION`].
    pub version: u32,
    /// argv strings.
    pub argc: u32,
    /// Environment strings.
    pub envc: u32,
    /// NUL-separated argv strings.
    pub argv: u64,
    /// Bytes at `argv`.
    pub argv_bytes: u32,
    /// Bytes at `env`.
    pub env_bytes: u32,
    /// NUL-separated `KEY=VALUE` strings.
    pub env: u64,
    /// The working directory (NUL-terminated), or 0.
    pub cwd: u64,
    /// Bytes of the working directory, NUL excluded.
    pub cwd_bytes: u32,
    /// The request's `SPAWN_F_*` flags.
    pub flags: u32,
    /// Child fds 0..=7.
    pub fds: [StartupFd; STARTUP_FDS],
}

/// Size of [`StartupBlock`] in bytes.
pub const STARTUP_BLOCK_SIZE: usize = 120;
const _: () = assert!(core::mem::size_of::<StartupFd>() == 8);
const _: () = assert!(core::mem::size_of::<StartupBlock>() == STARTUP_BLOCK_SIZE);
const _: () = assert!(core::mem::offset_of!(StartupBlock, argv) == 16);
const _: () = assert!(core::mem::offset_of!(StartupBlock, env) == 32);
const _: () = assert!(core::mem::offset_of!(StartupBlock, cwd) == 40);
const _: () = assert!(core::mem::offset_of!(StartupBlock, fds) == 56);

impl StartupBlock {
    /// Is this a block this ABI version wrote? Checks magic, version, the fd
    /// kinds and the limits; the pointers are the kernel's to have made right.
    pub fn validate(&self) -> bool {
        self.magic == STARTUP_MAGIC
            && self.version == STARTUP_VERSION
            && self.argc as usize <= SPAWN_ARGC_MAX
            && self.envc as usize <= SPAWN_ENVC_MAX
            && self.argv_bytes as usize <= SPAWN_ARGV_MAX
            && self.env_bytes as usize <= SPAWN_ENV_MAX
            && self.cwd_bytes as usize <= SPAWN_CWD_MAX
            && self.fds.iter().all(|f| f.kind <= FD_HANDLE)
    }

    fn to_bytes(self) -> [u8; STARTUP_BLOCK_SIZE] {
        let mut o = [0u8; STARTUP_BLOCK_SIZE];
        let mut put = |at: usize, b: &[u8]| o[at..at + b.len()].copy_from_slice(b);
        put(0, &self.magic.to_le_bytes());
        put(4, &self.version.to_le_bytes());
        put(8, &self.argc.to_le_bytes());
        put(12, &self.envc.to_le_bytes());
        put(16, &self.argv.to_le_bytes());
        put(24, &self.argv_bytes.to_le_bytes());
        put(28, &self.env_bytes.to_le_bytes());
        put(32, &self.env.to_le_bytes());
        put(40, &self.cwd.to_le_bytes());
        put(48, &self.cwd_bytes.to_le_bytes());
        put(52, &self.flags.to_le_bytes());
        for (i, f) in self.fds.iter().enumerate() {
            put(56 + 8 * i, &f.kind.to_le_bytes());
            put(60 + 8 * i, &f.handle.to_le_bytes());
        }
        o
    }

    /// Decode a block from its bytes (the inverse of what [`layout_startup`]
    /// writes). `None` if `b` is too short.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < STARTUP_BLOCK_SIZE {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let u64_at = |at: usize| (u32_at(at) as u64) | ((u32_at(at + 4) as u64) << 32);
        let mut fds = [StartupFd::default(); STARTUP_FDS];
        for (i, f) in fds.iter_mut().enumerate() {
            *f = StartupFd { kind: u32_at(56 + 8 * i), handle: u32_at(60 + 8 * i) };
        }
        Some(Self {
            magic: u32_at(0),
            version: u32_at(4),
            argc: u32_at(8),
            envc: u32_at(12),
            argv: u64_at(16),
            argv_bytes: u32_at(24),
            env_bytes: u32_at(28),
            env: u64_at(32),
            cwd: u64_at(40),
            cwd_bytes: u32_at(48),
            flags: u32_at(52),
            fds,
        })
    }
}

/// Lay out a startup block and its strings in `out`, which is mapped at user
/// address `base` (16-byte aligned). Order: the block first, then argv, env,
/// and the cwd with its NUL, each 8-byte aligned. Returns the bytes used, or
/// `None` if they do not fit, `base` is misaligned, or a blob is not a
/// sequence of NUL-terminated strings matching its count.
#[allow(clippy::too_many_arguments)]
pub fn layout_startup(
    out: &mut [u8],
    base: u64,
    argv: &[u8],
    argc: u32,
    env: &[u8],
    envc: u32,
    cwd: &[u8],
    flags: u32,
    fds: &[StartupFd; STARTUP_FDS],
) -> Option<usize> {
    if base % 16 != 0 || cwd.len() > SPAWN_CWD_MAX || cwd.contains(&0) {
        return None;
    }
    if count_cstrs(argv)? != argc as usize || count_cstrs(env)? != envc as usize {
        return None;
    }
    let align8 = |n: usize| (n + 7) & !7;
    let argv_at = STARTUP_BLOCK_SIZE;
    let env_at = align8(argv_at + argv.len());
    let cwd_at = align8(env_at + env.len());
    let end = if cwd.is_empty() { cwd_at } else { cwd_at + cwd.len() + 1 };
    if end > out.len() {
        return None;
    }
    let ptr = |at: usize, len: usize| if len == 0 { 0 } else { base + at as u64 };
    let block = StartupBlock {
        magic: STARTUP_MAGIC,
        version: STARTUP_VERSION,
        argc,
        envc,
        argv: ptr(argv_at, argv.len()),
        argv_bytes: argv.len() as u32,
        env_bytes: env.len() as u32,
        env: ptr(env_at, env.len()),
        cwd: ptr(cwd_at, cwd.len()),
        cwd_bytes: cwd.len() as u32,
        flags,
        fds: *fds,
    };
    out[..end].fill(0);
    out[..STARTUP_BLOCK_SIZE].copy_from_slice(&block.to_bytes());
    out[argv_at..argv_at + argv.len()].copy_from_slice(argv);
    out[env_at..env_at + env.len()].copy_from_slice(env);
    if !cwd.is_empty() {
        out[cwd_at..cwd_at + cwd.len()].copy_from_slice(cwd);
    }
    Some(end)
}

// ── SYS_CONSOLE_WAIT (609) ──────────────────────────────────────────────────

/// `SYS_CONSOLE_WAIT` timeout: wait with no deadline.
pub const CONSOLE_WAIT_FOREVER: u64 = u64::MAX;

// ── SYS_TASK_KILL (611) ─────────────────────────────────────────────────────

/// `how`: ask the target to stop. Its interruptible waits end with `-EINTR`.
pub const KILL_REQUEST: u64 = 1;
/// `how`: stop the target at its next return to user mode (or wake), with
/// exit code `128 + signo`.
pub const KILL_FORCE: u64 = 2;
/// `flags`: the target and every descendant.
pub const KILL_SUBTREE: u64 = 1;
/// The parent chain a caller is looked for in, at most this many steps up.
pub const KILL_MAX_ANCESTRY: usize = 8;
/// Highest `signo`.
pub const KILL_SIGNO_MAX: u64 = 31;
