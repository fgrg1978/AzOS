// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_INVOKE`: one call for every operation on an object a task holds a
//! handle to (D6).
//!
//! ```text
//!   SYS_INVOKE(handle, op, w0, w1, w2, w3)
//!     a0 = the handle (a CapHandle, or a self handle below)
//!     a1 = the op word: bits 0..16 the op, bit 16 INVOKE_REGS
//!     a2..a5 = four words        (INVOKE_REGS: the register form)
//!     a2 = a MsgDesc             (without it: the descriptor form)
//!   result a0: >= 0 the op's value, < 0 an Errno
//!   replies    a1..a4          (register form) / MsgDesc.words (descriptor form)
//! ```
//!
//! The op is read in the namespace of the handle's **type** (kind and class):
//! op 1 of a console is not op 1 of a tracer. A handle is the only address:
//! there is no path, no task id and no integer descriptor in the call. The
//! kernel resolves the handle in the caller's own table, checks the right the
//! op needs, then runs the op; an unknown op is `-EINVAL`, a handle of a type
//! that has no ops `-ECAPKIND`.
//!
//! **Self handles.** A task acts on itself without holding a slot for it: the
//! two handles below name the calling domain and thread, always valid, never
//! stored, never transferable (their generation is 0, which no slot has).
//!
//! **Register form.** The op's words travel in `a2..a5` and its replies come
//! back in `a1..a4`; the kernel touches no user memory for the call itself.
//! This is the form of every op whose words are scalars (a handle, a length, a
//! deadline); a pointer is a scalar. **Descriptor form.** `a2` points at a
//! [`MsgDesc`](crate::ipc_msg::MsgDesc): the words are `words[..n_words]`
//! (up to [`MSG_WORDS_MAX`](crate::ipc_msg::MSG_WORDS_MAX)), the replies are
//! written back into `words` and `n_words`. An op that needs more than four
//! words is descriptor-only.

use crate::cap::{CapHandle, CapKind, CapPerms, CapType};

/// The op word's op field.
pub const INVOKE_OP_MASK: u64 = 0xFFFF;
/// Op-word flag: the register form (words in `a2..a5`, replies in `a1..a4`).
pub const INVOKE_REGS: u64 = 1 << 16;
/// Every flag the call knows; any other bit of the op word is `-EINVAL`.
pub const INVOKE_FLAGS_KNOWN: u64 = INVOKE_REGS;
/// Words of the register form.
pub const INVOKE_REG_WORDS: usize = 4;

// ── The op number ───────────────────────────────────────────────────────────
//
// An op is a 16-bit number that names what it acts on and what it may change:
//
//   bits 12..16  the kind of the handle it is invoked on (`CapKind`)
//   bits  8..12  its class, the unit an image profile grants
//   bits  0..8   its index within the class
//
// So an op read out of a source file says which kind it belongs to (the call
// refuses a handle of another kind) and which class a profile must list for it,
// with no table to keep in step: `azos_sched::seccomp` grants classes, and
// `tests/host/seccomp-tests` derives the classes a program's wrappers need from
// the op names they use.

/// Class: observes (`stat`, `readdir`, an info query, a tracer read).
pub const CLASS_READ: u8 = 0;
/// Class: moves data or changes what the object holds (a console write, a file
/// write, a socket send).
pub const CLASS_WRITE: u8 = 1;
/// Class: blocks for an event (a console wait, a child's exit).
pub const CLASS_WAIT: u8 = 2;
/// Class: makes or ends an object, or steers its life (`create_port`, `map`).
pub const CLASS_CTL: u8 = 3;
/// Class: acts on others or on the system (`subreaper`, a filter, a mask).
pub const CLASS_ADMIN: u8 = 4;
/// Class (`Node`): opens a file beneath a directory the caller holds
/// (`openat`); there is no open by absolute path. A write mode needs the
/// directory's `WRITE`.
pub const CLASS_FS_OPEN: u8 = 5;
/// Class (`Domain`): changes the namespace (`mkdir`, `unlink`, `rmdir`,
/// `rename`, `truncate`); needs a directory tree the caller holds.
pub const CLASS_FS_MUTATE: u8 = 6;
/// Class (`Domain`): loads code (verify a signed module, map it executable).
pub const CLASS_MODULE: u8 = 7;
/// Class: the network (`socket`, `connect`, `send`, `recv`, multicast).
pub const CLASS_NET: u8 = 8;
/// Class (`Domain`): serves a device from ring 3 (an interrupt line, a driver
/// slot).
pub const CLASS_DRIVER: u8 = 9;
/// Classes a kind's mask can hold (the nibble of an op).
pub const CLASSES: u8 = 16;
/// Kinds an op can name (`CapKind` raw values below this).
pub const OP_KINDS: usize = 16;

/// The op of `kind`, `class` and index `n`.
pub const fn op(kind: CapKind, class: u8, n: u8) -> u16 {
    assert!(class < CLASSES);
    ((kind as u16) << 12) | ((class as u16) << 8) | n as u16
}

/// The raw `CapKind` an op belongs to.
#[inline]
pub const fn op_kind(op: u16) -> u8 {
    (op >> 12) as u8
}

/// The class of an op.
#[inline]
pub const fn op_class(op: u16) -> u8 {
    ((op >> 8) & 0xF) as u8
}

/// The op of an op word.
#[inline]
pub const fn op_of(word: u64) -> u16 {
    (word & INVOKE_OP_MASK) as u16
}

/// The calling domain: `invoke` on it acts on the caller's own domain (its
/// ports, endpoints, service names, filter, children). Kind `Domain`,
/// class 1, every right, generation 0.
pub const DOMAIN_SELF: CapHandle =
    CapHandle::pack(CapType::new(CapKind::Domain, 1), CapPerms::ALL, 0, 0);

/// Is `h` the self handle of the calling domain?
#[inline]
pub const fn is_domain_self(h: u32) -> bool {
    h == DOMAIN_SELF.as_raw()
}

// ── Log: the console (class CONSOLE) and the tracer (class TRACE) ───────────

/// Put `w1` bytes at the user address `w0` on the console; `WRITE`. Returns
/// the bytes taken: the count clamped to [`LOG_CONSOLE_WRITE_MAX`], not what
/// the UART emitted after LF-to-CRLF.
pub const LOG_CONSOLE_WRITE: u16 = op(CapKind::Log, CLASS_WRITE, 1);
/// The most bytes one console write takes.
pub const LOG_CONSOLE_WRITE_MAX: u64 = 4096;
/// Wait for console input or a child's exit notice; `READ`. Words: `w0` the
/// buffer, `w1` its length, `w2` the timeout in ns
/// ([`LOG_CONSOLE_WAIT_FOREVER`]), `w3` must be 0. Returns the bytes read (0 on
/// timeout, or when the input event ring has events for the terminal server,
/// the one reader that announces it sleeps there too), `-EINTR` for a stop request or an exit notice, `-EBUSY` when
/// another task reads the console.
pub const LOG_CONSOLE_WAIT: u16 = op(CapKind::Log, CLASS_WAIT, 2);
/// The console wait's timeout meaning no deadline.
pub const LOG_CONSOLE_WAIT_FOREVER: u64 = crate::ushell::CONSOLE_WAIT_FOREVER;

/// The classes compiled into the tracer, as a mask (`1 << TRACE_CLASS_*`).
/// Needs `READ`. `-ENOSYS` when the tracer is compiled out (Kconfig `KTRACE`).
pub const LOG_TRACE_INFO: u16 = op(CapKind::Log, CLASS_READ, 3);
/// The runtime class mask now. Needs `READ`.
pub const LOG_TRACE_GET_MASK: u16 = op(CapKind::Log, CLASS_READ, 4);
/// Bytes of the trace region (what [`LOG_TRACE_MAP`] maps). Needs `READ`.
pub const LOG_TRACE_REGION_BYTES: u16 = op(CapKind::Log, CLASS_READ, 5);
/// Map the trace region (every CPU's ring) into the caller, read-write (the
/// reader stores its tails), and return its base address. Needs `READ` and
/// `WRITE`. `-EBUSY` when the caller already maps it.
pub const LOG_TRACE_MAP: u16 = op(CapKind::Log, CLASS_CTL, 6);
/// Set the runtime class mask to `w0` (bits of classes not compiled in are
/// ignored) and return the previous one. Needs `WRITE`. `0` stops recording.
pub const LOG_TRACE_SET_MASK: u16 = op(CapKind::Log, CLASS_ADMIN, 7);

// ── Domain: the caller's own (`DOMAIN_SELF`) ────────────────────────────────

/// Read one exit-path counter: `w0` an `EXIT_STAT_*` selector. Returns the
/// counter, or `-EINVAL`.
pub const DOMAIN_EXIT_STATS: u16 = op(CapKind::Domain, CLASS_READ, 1);
/// Make an event port in the caller's table; returns its handle.
pub const DOMAIN_CREATE_PORT: u16 = op(CapKind::Domain, CLASS_CTL, 4);
/// Make an endpoint in the caller's table (the caller serves it); returns its
/// handle.
pub const DOMAIN_CREATE_ENDPOINT: u16 = op(CapKind::Domain, CLASS_CTL, 5);
/// The caller's child-subreaper mark: `w0` is `SUBREAPER_GET`, `SUBREAPER_SET`
/// or `SUBREAPER_CLEAR`. Returns the mark.
pub const DOMAIN_SUBREAPER: u16 = op(CapKind::Domain, CLASS_ADMIN, 7);
/// Confine the caller to a role profile, one way: `w0` the profile id
/// (`azos_sched::seccomp::PROFILE_*`). 0, or a negative code (already
/// confined, unknown profile).
pub const DOMAIN_SET_FILTER: u16 = op(CapKind::Domain, CLASS_ADMIN, 8);

/// Narrow what the caller's Domain may ask of the kernel, one way: `w0` the
/// mask the Domain keeps (the `PLEDGE_*` bits below). The Domain's mask can
/// only lose bits: a request that holds a bit the Domain no longer has is
/// refused, so nothing a program narrows is ever widened again, by it or by a
/// thread of it. Every Domain a member of this one creates (spawn, fork)
/// starts with the mask its creator has when it is created; `exec` keeps it. A
/// call outside the mask is not run: the prologue of the trap layer answers
/// `-EACCES` and leaves a `pledge` decision record (see
/// `azos_sched::domain::enter`). Returns the mask now in force, `-EINVAL` for a
/// bit that names nothing, `-EACCES` for a request that would widen. `exit` and
/// `thread_exit` are in every mask ([`PLEDGE_ALWAYS`]).
pub const DOMAIN_PLEDGE: u16 = op(CapKind::Domain, CLASS_ADMIN, 9);

// ── The pledge mask ─────────────────────────────────────────────────────────
//
// A mask has one bit per thing the prologue judges a call by:
//
//   bits 0..=CASES   the foundational case of a native call
//                    (`syscall_nr::syscall_case`; bit 0: a number with no
//                    case, and every call of a Linux task)
//   bits 8..24       the op class of a `SYS_INVOKE` (`CLASS_*`): invoke is one
//                    syscall of case authority, but its ops are the data path
//                    of a socket or a file as much as they are authority, and
//                    the class is the unit this ABI already grants by
//   bit 24           [`PLEDGE_ALWAYS`]
//
// `SYS_INVOKE` is judged by its op's class bit alone (its case bit says
// nothing of the op); every other call by its case bit.

/// Bit of a mask for the calls of foundational case `c` (0: no case).
pub const fn pledge_case(c: u8) -> u32 {
    1 << c
}

/// Bit of a mask for the ops of class `c` on `SYS_INVOKE`.
pub const fn pledge_class(c: u8) -> u32 {
    1 << (PLEDGE_CLASS_SHIFT + c as u32)
}

const PLEDGE_CLASS_SHIFT: u32 = 8;

/// The bit that no mask loses: `exit` and `thread_exit`, which a Domain must
/// always be able to end itself with.
pub const PLEDGE_ALWAYS: u32 = 1 << 24;

/// Every case, every class and [`PLEDGE_ALWAYS`]: the mask of a Domain nobody
/// narrowed.
pub const PLEDGE_ALL: u32 =
    ((1u32 << (crate::syscall_nr::CASES + 1)) - 1) | (((1u32 << CLASSES) - 1) << PLEDGE_CLASS_SHIFT) | PLEDGE_ALWAYS;

/// The bit number of the mask that judges one call: `num` the syscall number,
/// `opw` its second argument (the op word of `SYS_INVOKE`), `linux` whether the
/// task is a Linux one, whose numbers are not the native table's.
#[inline(always)]
pub const fn pledge_bit(num: u64, opw: u64, linux: bool) -> u8 {
    use crate::syscall_nr::{syscall_case, SYS_EXIT, SYS_INVOKE, SYS_THREAD_EXIT};
    if linux {
        0
    } else if num == SYS_EXIT || num == SYS_THREAD_EXIT {
        PLEDGE_ALWAYS.trailing_zeros() as u8
    } else if num == SYS_INVOKE {
        PLEDGE_CLASS_SHIFT as u8 + op_class(op_of(opw))
    } else {
        syscall_case(num)
    }
}

// ── Port: an event port (`ty::PORT`) ────────────────────────────────────────

/// Dequeue one event without blocking: `w0` a user buffer of 16 bytes
/// (`PortEvent`, key `u64`, source type, code, source id). Needs `READ`.
/// Returns 16, or `-EAGAIN` when the queue is empty. The blocking form is
/// `SYS_PORT_WAIT`.
pub const PORT_POLL: u16 = op(CapKind::Port, CLASS_READ, 1);
/// Bind an event source to the port (a `PORT_SRC_*`, or-ed with
/// `PORT_BIND_F_REMOVE` to remove): `w0` the source type, `w1` the source's
/// capability (a timer: its deadline), `w2` the event key. Needs `WRITE`.
pub const PORT_BIND: u16 = op(CapKind::Port, CLASS_CTL, 2);
/// Free the port and revoke the handle. Needs `WRITE`.
pub const PORT_DESTROY: u16 = op(CapKind::Port, CLASS_CTL, 3);

// ── MemObj: a memory object (`ty::SHM`) ─────────────────────────────────────

/// Take a reference on the region and read its geometry: `w0` a user buffer
/// of 8 bytes (`page_count u32`, `perms u8`, 3 bytes of padding). Needs
/// `READ`. Returns 8. The reference is given back, with the caller's others,
/// by the release of the handle.
pub const MEMOBJ_ACQUIRE: u16 = op(CapKind::MemObj, CLASS_CTL, 1);
/// The POSIX pipe's end counts (`azos_bytepipe`, a byte ring in a region): the
/// caller gives up the ends `w0` names ([`SHM_END_READ`] and/or
/// [`SHM_END_WRITE`]) it holds on this region. The kernel, not the program,
/// keeps who holds which end of a pipe region (a creation holds both, a spawn
/// move list and a fork hand them over, a process's death gives back what it
/// still holds), so the counts the peers read are true whatever kills a holder.
/// The last writer's end wakes the readers, the last reader's the writers.
/// Needs `READ`. 0, `-EINVAL` for a `w0` of no end or an end the caller does
/// not hold on this region (a region that is no pipe holds none).
pub const MEMOBJ_END_DROP: u16 = op(CapKind::MemObj, CLASS_CTL, 4);
/// [`MEMOBJ_END_DROP`]'s read end.
pub const SHM_END_READ: u64 = 1;
/// [`MEMOBJ_END_DROP`]'s write end.
pub const SHM_END_WRITE: u64 = 2;

// ── Domain: the namespace and the network, as the caller sees them ──────────
//
// Paths are resolved in the caller's namespace. A path that names something to
// read is open to the caller whose image lists the class; one that changes the
// namespace needs a directory tree the caller holds (`ty::FILE`, a tree) that
// covers it: the check is the tree's, the handle the caller names is its own
// domain.

/// Stat the NUL-terminated path `w0` into the 48-byte buffer `w1`. 0, or -1.
pub const DOMAIN_STAT: u16 = op(CapKind::Domain, CLASS_READ, 13);
/// Entry `w1` of directory `w0` (NUL-terminated path): `w2` a name buffer,
/// `w3` a `*mut u32` for the size, `w4` a `*mut u32` for the is-directory
/// flag, `w5` the name buffer's length (at least `READDIR_NAME_BYTES`). 0, or
/// -1 past the last entry. Descriptor form (six words).
pub const DOMAIN_READDIR: u16 = op(CapKind::Domain, CLASS_READ, 14);
/// Filesystem facts of path `w0` into the buffer `w1` of `w2` bytes.
pub const DOMAIN_STATFS: u16 = op(CapKind::Domain, CLASS_READ, 15);
/// Free pages of memory.
pub const DOMAIN_MEMINFO: u16 = op(CapKind::Domain, CLASS_READ, 16);
/// Task facts into the buffer `w0` of `w1` bytes (`TASKINFO_BYTES`).
pub const DOMAIN_TASKINFO: u16 = op(CapKind::Domain, CLASS_READ, 17);
/// The interface's IPv4 address, as `u32::from_be_bytes`.
pub const DOMAIN_NET_GETIP: u16 = op(CapKind::Domain, CLASS_READ, 18);
/// Make directory `w0`. 0, or a negative code.
pub const DOMAIN_MKDIR: u16 = op(CapKind::Domain, CLASS_FS_MUTATE, 20);
/// Remove file `w0`.
pub const DOMAIN_UNLINK: u16 = op(CapKind::Domain, CLASS_FS_MUTATE, 21);
/// Remove empty directory `w0`.
pub const DOMAIN_RMDIR: u16 = op(CapKind::Domain, CLASS_FS_MUTATE, 22);
/// Rename `w0` to `w1`.
pub const DOMAIN_RENAME: u16 = op(CapKind::Domain, CLASS_FS_MUTATE, 23);
/// Truncate or extend file `w0` to `w1` bytes.
pub const DOMAIN_TRUNCATE: u16 = op(CapKind::Domain, CLASS_FS_MUTATE, 24);
/// Create a socket: `w0` the domain, `w1` the type, `w2` the protocol; returns a
/// `ty::SOCKET` handle with `READ|WRITE|DUP|TRANSFER`.
pub const DOMAIN_SOCKET: u16 = op(CapKind::Domain, CLASS_NET, 28);

// ── Domain: the caller's own process, as the kernel serves it ───────────────

/// Milliseconds since boot.
pub const DOMAIN_UPTIME: u16 = op(CapKind::Domain, CLASS_READ, 30);
/// Reap a finished child of the process, without blocking: `w0` the child's
/// task id (0: any), `w1` a `*mut i32` for its exit code (0: none). Returns the
/// child's task id; `-1` when it (or every child) has not finished;
/// `-ECHILD` for a task that is not a child of the caller or was reaped.
pub const DOMAIN_WAIT: u16 = op(CapKind::Domain, CLASS_WAIT, 31);
/// Map the caller's per-task vDSO page read-only and return its address.
pub const DOMAIN_VDSO_MAP: u16 = op(CapKind::Domain, CLASS_CTL, 33);
/// Verify a signed module: `w0` the buffer, `w1` its length, `w2` the name,
/// `w3` the name's length. Returns a token for [`DOMAIN_MODULE_MAP_X`].
pub const DOMAIN_MODULE_VERIFY: u16 = op(CapKind::Domain, CLASS_MODULE, 34);
/// Map the verified module `w0` executable at `w1` for `w2` bytes.
pub const DOMAIN_MODULE_MAP_X: u16 = op(CapKind::Domain, CLASS_MODULE, 35);
/// Register as the driver for the kind the `DriverRegistry` handle `w0`
/// names: `w1` MMIO base, `w2` size, `w3` interrupt line.
pub const DOMAIN_DRIVER_REGISTER: u16 = op(CapKind::Domain, CLASS_DRIVER, 39);
/// Give up the driver slot of the `DriverRegistry` handle `w0`.
pub const DOMAIN_DRIVER_UNREGISTER: u16 = op(CapKind::Domain, CLASS_DRIVER, 40);
/// Driver loop, take one pending request for driver kind `w0` into the
/// `DriverRequest` at `w1`, without blocking. 0 with a request, -1 with none.
pub const DOMAIN_DRIVER_FETCH: u16 = op(CapKind::Domain, CLASS_DRIVER, 44);
/// Driver loop, publish the reply at `w1` for the request of kind `w0`.
pub const DOMAIN_DRIVER_REPLY: u16 = op(CapKind::Domain, CLASS_DRIVER, 45);
/// Driver loop, publish the reply at `w1` (0: none) and take the next request
/// into `w2` in one call.
pub const DOMAIN_DRIVER_REPLY_FETCH: u16 = op(CapKind::Domain, CLASS_DRIVER, 46);
/// [`DOMAIN_DRIVER_REPLY_FETCH`] that blocks while no request is queued: `w3`
/// the longest park in milliseconds (0: the kernel's default, at most 1000).
pub const DOMAIN_DRIVER_REPLY_WAIT: u16 = op(CapKind::Domain, CLASS_DRIVER, 47);
/// Map device registers: `w0` the handle of a device of the hardware bus (not
/// an address), `w1` the access (`CapPerms` bits: READ, or READ|WRITE). Maps
/// exactly the device's register window read-only unless WRITE was asked and
/// returns its virtual address; needs the `Device` (`ty::MMIO`) capability for
/// the handle, carrying WRITE when WRITE is asked.
pub const DOMAIN_MMIO_MAP: u16 = op(CapKind::Domain, CLASS_DRIVER, 48);

// ── Node: a file or a socket the caller holds ─────────────────────────────

/// Read into the user buffer `w0` of `w1` bytes (clamped to 4096) from the file.
/// Needs `READ`. Returns the bytes read.
pub const NODE_READ: u16 = op(CapKind::Node, CLASS_READ, 1);
/// Write the user buffer `w0` of `w1` bytes to the file. Needs
/// `WRITE`; refused with `-EAGAIN` while containment is armed.
pub const NODE_WRITE: u16 = op(CapKind::Node, CLASS_WRITE, 2);
/// Flush the file to its device. Needs `WRITE`.
pub const NODE_FSYNC: u16 = op(CapKind::Node, CLASS_WRITE, 3);
/// Bind a socket to the local sockaddr `w0` (16 bytes). Needs `WRITE`.
pub const NODE_BIND: u16 = op(CapKind::Node, CLASS_NET, 4);
/// Connect a socket to the sockaddr `w0` of `w1` bytes. Needs `WRITE`.
pub const NODE_CONNECT: u16 = op(CapKind::Node, CLASS_NET, 5);
/// Send the buffer `w0` of `w1` bytes on a connected socket. Needs `WRITE`.
pub const NODE_SEND: u16 = op(CapKind::Node, CLASS_NET, 6);
/// Receive into the buffer `w0` of `w1` bytes. Needs `READ`. Does not block
/// (0: nothing yet). A TCP socket whose connection has ended with nothing left to
/// read answers `-EEOF`; any other refusal is a bare `-1` or a capability errno.
pub const NODE_RECV: u16 = op(CapKind::Node, CLASS_NET, 7);
/// Send the buffer `w0` of `w1` bytes to the sockaddr `w2` (0: the connected
/// peer). Needs `WRITE`.
pub const NODE_SENDTO: u16 = op(CapKind::Node, CLASS_NET, 8);
/// Receive into the buffer `w0` of `w1` bytes, the sender's sockaddr into `w2`
/// (0: none). Needs `READ`. Does not block.
pub const NODE_RECVFROM: u16 = op(CapKind::Node, CLASS_NET, 9);
/// Join IPv4 multicast group `w0` (network byte order) on a UDP socket.
/// Needs `WRITE`.
pub const NODE_MCAST_JOIN: u16 = op(CapKind::Node, CLASS_NET, 10);
/// Leave multicast group `w0`. Needs `WRITE`.
pub const NODE_MCAST_LEAVE: u16 = op(CapKind::Node, CLASS_NET, 11);
/// Listen on the TCP socket, on the local port a [`NODE_BIND`] gave it. Needs
/// `WRITE`; refused with `-EAGAIN` while containment is armed. 0, or -1 (not a
/// TCP socket, no port bound, the port taken, no connection slot).
pub const NODE_LISTEN: u16 = op(CapKind::Node, CLASS_NET, 14);
/// Take one established connection from a listening socket: the new socket, as
/// a `Cap<Socket>` (`READ | WRITE`, giftable) in the caller's own table, owned
/// by the caller. Does not block: `-EAGAIN` when no connection is waiting (and
/// while containment is armed), `-EMFILE` when the capability table is full.
/// Needs `READ` on the listener.
pub const NODE_ACCEPT: u16 = op(CapKind::Node, CLASS_NET, 15);
/// Open the NUL-terminated name `w0` beneath the directory the handle names
/// (a `Cap<Dir>`: a `ty::FILE` tree handle) with `w1` the flags (`O_*`):
/// returns a `ty::FILE` handle, `READ` for `O_RDONLY`, `WRITE` for `O_WRONLY`,
/// both for `O_RDWR`. The name is relative and cannot leave the directory: an
/// absolute name, or a `..` that would climb above it, is refused. Needs
/// `READ` on the directory. An open that changes the tree (a write mode,
/// `O_CREAT` or `O_TRUNC`) also needs a held tree with `WRITE` that covers the
/// result: the directory itself when it was granted with `WRITE`, otherwise
/// another tree of the task's row (`-ECAPPERMS` when none does). Returns `-1`
/// when the open fails, `-ECAPKIND` for a handle that is not a directory.
pub const NODE_OPENAT: u16 = op(CapKind::Node, CLASS_FS_OPEN, 12);
/// Map the file the handle names into the caller: `w0` the length, `w1` the
/// byte offset into the file (a multiple of the page), `w2` the protection
/// (`PROT_READ` 1, `PROT_WRITE` 2; never `PROT_EXEC`), `w3` the flags
/// (`MAP_SHARED` 1 or `MAP_PRIVATE` 2). Returns the address. Needs `READ`, and
/// `WRITE` for a shared writable mapping. The pages are the file's page cache:
/// a shared mapping maps the cache's own frames (every mapper sees every store,
/// and the pages go back to the file at `munmap` and at [`NODE_FSYNC`]); a
/// private one holds a copy of each page it touches. `-ENODEV` for a file the
/// cache cannot serve, `-EBUSY` when the caller already maps a window the call
/// needs, `-EINVAL` for bad arguments.
pub const NODE_MMAP: u16 = op(CapKind::Node, CLASS_CTL, 13);
/// The `ty::FILE` resource of the directory on `/`, the task's root
/// `Cap<Dir>`: what `SYS_CAP_INFO` looks up to find it. The kernel interns the
/// tree on `/` first, so the value never depends on the order the topology
/// names the others in (`azos_ipc::file_cap::ROOT_TREE_RESOURCE` asserts it).
pub const ROOT_DIR_RESOURCE: u32 = 0x4000_0000;

// ── Device: an interrupt line the caller holds ──────────────────────────────

/// `w2` of [`DEVICE_IRQ_BIND`]: let the kernel choose the CPU.
pub const DEVICE_IRQ_CPU_ANY: u64 = u64::MAX;

/// Bind the interrupt line the `ty::IRQ` handle names to an event port (L5):
/// `w0` the port's handle (needs `WRITE`), `w1` the key every event carries,
/// `w2` the CPU the line is routed to ([`DEVICE_IRQ_CPU_ANY`]: the CPU of the
/// caller's reservation, else the caller's pin, else the CPU it binds from).
/// Needs `READ` on the line. Each interrupt masks the line and queues one
/// `PORT_EVENT_IRQ` event (`source_id` the line) on the port, waking its
/// waiter; [`DEVICE_IRQ_ACK`] unmasks the line.
///
/// With Kconfig `IRQ_THREADED` the caller is the line's handler and must run
/// on a hard reservation: the line goes to the reservation's CPU, and a
/// handler that runs out of budget has its lines masked until it is
/// replenished (a decision record, `Rule::IrqBudget`). Returns the CPU the
/// line was routed to, or `-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS` (the line
/// or the port), `-EBUSY` (another task binds the line), `-EPERM`
/// (`IRQ_THREADED` and no hard reservation), `-EINVAL` (a CPU the
/// reservation does not run on, or one that is not online), `-EMFILE` (the
/// binding table is full), `-ENODEV` (the interrupt controller cannot deliver
/// the line, or the platform has no MSI for ring 3; nothing stays bound).
///
/// A **message-signalled slot** (`msi.<k>` in a topology row: a handle whose
/// line has `MSI_LINE` set) is bound by the same op. The bind takes a vector
/// (x86_64: a LAPIC vector; riscv64 with AIA: an IMSIC identity), enables it
/// on the CPU, and the call replies, in the register form, `a1` the address,
/// `a2` the data and `a3` the vector: the message a device writes (an MSI
/// capability or an MSI-X table entry) to raise the event. The vector goes
/// back with the binding. An MSI cannot be masked: while the handler is out of
/// budget the kernel drops its deliveries instead of holding the line.
pub const DEVICE_IRQ_BIND: u16 = op(CapKind::Device, CLASS_DRIVER, 1);
/// Acknowledge the line after its device was quietened: unmask it. Needs
/// `READ` on the line. Returns 0 when the line is live again, 1 when the
/// handler's budget is spent and the line stays masked until the
/// reservation is replenished, `-ENOENT` when nobody binds the line.
pub const DEVICE_IRQ_ACK: u16 = op(CapKind::Device, CLASS_DRIVER, 2);

// ── Endpoint: an endpoint the caller holds ──────────────────────────────────

/// The most caveats [`ENDPOINT_DERIVE`] adds (`azos_ipc::cap::CAVEATS_MAX`).
pub const ENDPOINT_DERIVE_CAVEATS_MAX: usize = 4;

/// Derive a narrowed, badged copy of the unbadged endpoint capability, with
/// caveats: the copy goes into the caller's table as a child of the source in
/// the warrant tree (revoking the source revokes it) and the call returns its
/// handle. Needs `DUP` on the source. A kernel-hosted endpoint refuses (only
/// the kernel stamps its badges).
///
/// Descriptor form, seven words: `w0` the rights of the copy (bits 0..8, a
/// subset of the source's), the number of caveats (bits 8..16, at most
/// [`ENDPOINT_DERIVE_CAVEATS_MAX`]) and the badge (bits 32..64, non-zero);
/// `w1` an expiry (absolute ns on the MONO clock, 0 none; the earlier of it
/// and the source's is kept); `w2` the kinds of the caveats, one per byte
/// (`azos_ipc::cap::caveat`); `w3..w6` their arguments. A word or a byte
/// past the caveats that is not 0 is `-EINVAL`, a kind the kernel does not
/// know `-ECAPPERMS`. The caveats follow the source's, so the copy is never
/// less restricted than the capability it came from; a kind the resolve does
/// not evaluate (`NODE`) is carried and refuses every use. `DECLASSIFY`
/// (`arg`: the label bits, `ipc_msg::LABEL_*`, at least one and no unknown
/// kind, else `-EINVAL`; at most one per call) is the exception to "every
/// caveat restricts": it grants, so only a task whose principal is a user may
/// ask for one (`-ECAPPERMS` for any other, and with Kconfig `IPC_LABELS`
/// off). The copy is a human's one-shot warrant to let a message that passed
/// through an agent go out with those bits off its label; it is handed to
/// whoever is to use it by MOVE (a copy of one is refused), and the call that
/// presents it spends it.
/// This is the call the RPC server's re-mint (`azos_rpc::session::Remint`)
/// needs to put a verified remote token's caveats (`QUOTA`, `RECEIPT`) on the
/// local capability it lends: `SYS_CAP_DERIVE` can badge and date a copy, not
/// narrow it further. The server issues it for every warrant it derives (its
/// warrant cache is keyed by interface and caveat set; the image profile of
/// `RPCSRV.ELF` lists the op), and refuses a token whose `OP_MASK` or
/// `DECLASSIFY` it could never discharge before it derives.
pub const ENDPOINT_DERIVE: u16 = op(CapKind::Endpoint, CLASS_CTL, 1);

/// The words of an [`ENDPOINT_DERIVE`], decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EndpointDerive {
    /// The copy's rights (`CapPerms` bits).
    pub rights: u8,
    /// The copy's badge.
    pub badge: u32,
    /// The copy's deadline (absolute ns, 0 none).
    pub expiry_ns: u64,
    /// How many of `kinds` and `args` are caveats.
    pub n: usize,
    /// Caveat kinds, `n` of them; the rest 0.
    pub kinds: [u8; ENDPOINT_DERIVE_CAVEATS_MAX],
    /// Caveat arguments, `n` of them; the rest 0.
    pub args: [u64; ENDPOINT_DERIVE_CAVEATS_MAX],
}

impl EndpointDerive {
    /// Decode the op's words. `None` for a count past
    /// [`ENDPOINT_DERIVE_CAVEATS_MAX`] or a bit the layout does not use (an
    /// unused bit of `w0`, a kind byte or an argument past the count, a word
    /// past the seventh): a caller that set one means something else.
    pub fn decode(w: &[u64; crate::ipc_msg::MSG_WORDS_MAX]) -> Option<Self> {
        const WORDS: usize = 3 + ENDPOINT_DERIVE_CAVEATS_MAX;
        let n = (w[0] >> 8 & 0xFF) as usize;
        if n > ENDPOINT_DERIVE_CAVEATS_MAX || w[0] >> 16 & 0xFFFF != 0 || w[2] >> (8 * n) != 0 {
            return None;
        }
        if w[3 + n..].iter().any(|&a| a != 0) || w[WORDS..].iter().any(|&a| a != 0) {
            return None;
        }
        let mut d = EndpointDerive { rights: w[0] as u8, badge: (w[0] >> 32) as u32, expiry_ns: w[1], n, kinds: [0; 4], args: [0; 4] };
        for i in 0..n {
            d.kinds[i] = (w[2] >> (8 * i)) as u8;
            d.args[i] = w[3 + i];
        }
        Some(d)
    }
}
