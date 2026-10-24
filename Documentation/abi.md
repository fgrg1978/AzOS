# Native ABI

This document describes the native user/kernel interface: how a ring-3
program enters the kernel, the syscall table, the generic `SYS_INVOKE` call,
the message descriptor, the error model, and the pages the kernel publishes
to every process (the vDSO). It describes what is in the tree; the
definitions are in the `azos_abi` crate (`crates/core/abi`), which is the one
source for every number and layout below. Kernel and user space both import
it and neither keeps a copy.

Related documents: [ipc.md](ipc.md) (endpoints, rings, memory objects,
ports, futex, pipes) and [idl.md](idl.md) (the interface definition language
that sits on top of the message descriptor).

Contents:

- [Entering the kernel](#entering-the-kernel)
- [The syscall table](#the-syscall-table)
- [Cases, entry counters and the pledge](#cases-entry-counters-and-the-pledge)
- [Handles](#handles)
- [SYS_INVOKE](#sys_invoke)
- [The message descriptor](#the-message-descriptor)
- [Error model](#error-model)
- [Clocks](#clocks)
- [The vDSO](#the-vdso)
- [ABI version](#abi-version)
- [Other shared definitions](#other-shared-definitions)

## Entering the kernel

The syscall numbers are the same on every ISA. Which registers carry the
number, the arguments and the results is a per-ISA convention.

| Role | riscv64 | aarch64 | x86_64 |
|---|---|---|---|
| Trap instruction | `ecall` | `svc #0` (immediate not read) | `syscall` |
| Syscall number | `a7` | `x8` | `rax` |
| Arguments (up to 6) | `a0`..`a5` | `x0`..`x5` | `rdi, rsi, rdx, r10, r8, r9` |
| Primary result (`isize`, negative is an error) | `a0` | `x0` | `rax` |
| Extra outputs of the fast-IPC family and of the register form of `SYS_INVOKE` (up to 6) | `a1`..`a6` | `x1`..`x6` | `rdx, rsi, rdi, r8, r9, r10` |

No call takes more than six arguments. The same constants are exported as
`REG_NR_RISCV64`, `REG_ARGS_RISCV64`, `REG_RESULT_RISCV64`,
`REG_FAST_IPC_OUT_RISCV64` and their `AARCH64` twins.

### Register contract

For every native syscall, on return ring 3 may rely on these holding what it
left in them:

- the callee-saved registers of the platform calling convention (riscv64
  `s0`..`s11`; aarch64 `x19`..`x29`, the low halves of `v8`..`v15` and `x18`;
  x86_64 `rbx, rbp, r12`..`r15`);
- the stack and thread pointers (riscv64 `sp, gp, tp`; aarch64 `sp` and
  `TPIDR_EL0`; x86_64 `rsp` and the FS/GS bases);
- the link register (riscv64 `ra`, aarch64 `x30`);
- the call's documented outputs. An extra output register the call does not
  write comes back as the caller passed it.

Everything else is clobbered: riscv64 `t0`..`t6` and `a7`; aarch64
`x7`..`x17`; x86_64 `rcx` and `r11` (which `syscall` itself defines as the
return address and the flags). A ring-3 stub declares them clobbered.

With Kconfig `SYSCALL_LEAN_ENTRY` (default `y`) a native syscall takes a trap
path that does not store the clobbered registers and returns them zeroed,
never with a kernel value in them: riscv64 `t0`..`t6` and `a7`, aarch64
`x10`..`x17` (`x7`..`x9` are stored with the registers they pair with and come
back as they were), and x86_64 `rcx` and `r11` as `sysret` defines them (the
return address and the flags). A trap that is not a syscall, and every syscall
of a Linux-personality task, saves and restores everything. A call that writes extra outputs must write all of them
on every path, success and failure, because a caller that declares them
write-only may assume the trap overwrites them.

A successful exec does not return; the new image starts with every
general-purpose register zero except its stack pointer (and, on x86_64,
`rcx` and `r11` as `sysret` defines them).

Source: `crates/core/abi/src/syscall_nr.rs` (module documentation, `REG_*`
constants), `config/kernel/Kconfig.ipc` (`SYSCALL_LEAN_ENTRY`).

## The syscall table

There are 33 native calls, numbered densely from 1. Everything else is an op
of `SYS_INVOKE`. A number at or above `SYS_NR_RESERVED_UPPER` (34) is
unassigned and answers `-1`. A call added to the table takes the next number
and raises that constant. The Linux personality and the ring-3 Linux runtime
use the Linux numbers, which are translated; they are not in this table.

Case: **A** is authority/protection (the handle table, the page tables and
protection domains are kernel state), **B** is block/wake (the call hands the
hart to another task). See [Cases](#cases-entry-counters-and-the-pledge).

| Nr | Name | Family | Case | Summary |
|---:|---|---|:-:|---|
| 1 | `SYS_CAP_INFO` | handles | A | Query what the caller holds without using it: `CAP_INFO_LOOKUP` (find a handle by type and resource), `CAP_INFO_TREE` (the directory tree covering a path), `CAP_INFO_QUERY` (type, rights, badge, expiry of a handle). |
| 2 | `SYS_CAP_CLOSE` | handles | A | Delete a handle and release what it names, by type. Only the caller's own slot goes: copies made from it stay alive (`SYS_CAP_REVOKE` takes them back). A second close is `-ECAPSTALE`. |
| 3 | `SYS_CAP_DERIVE` | handles | A | From an endpoint handle with `DUP`: mint a child with a subset of the rights, a non-zero badge and an expiry. A kernel-hosted endpoint refuses. |
| 4 | `SYS_CAP_REVOKE` | handles | A | Revoke everything derived from a handle and keep it; returns the replacement handle (the old value is stale). |
| 5 | `SYS_SPAWN_EX` | domain | A | Start the image at a path under the profile and topology row bound to its digest. Needs a `ty::LAUNCH` capability with `EXEC` for the image. Optional `SpawnReq` block (`crates/core/abi/src/ushell.rs`): argv, environment, working directory, a move list of up to 8 file handles, and the flags `SPAWN_F_DIE_WITH_PARENT`, `SPAWN_F_CONSOLE_IN` (lend console input to a Linux child) and `SPAWN_F_USER` (the child is a logged-in user's session; spends the caller's login grant). Returns the child's TID. |
| 6 | `SYS_THREAD_CREATE` | domain | A | New thread of the calling process: entry, stack top, argument, clear-tid word address, thread pointer. At most `GROUP_THREADS_MAX` (16) threads per process and `GROUPS_MAX` (8) multi-thread processes. |
| 7 | `SYS_THREAD_EXIT` | domain | A | End only the calling thread. Does not return. |
| 8 | `SYS_EXIT` | domain | A | End the whole process with the code in `a0`. Does not return. |
| 9 | `SYS_ALERT` | domain | A | Ask a descendant to stop (`KILL_REQUEST`) or force it (`KILL_FORCE`) with a signal number. The caller must be an ancestor (parent chain of at most 8 steps), else `-ESRCH`. |
| 10 | `SYS_GETPID` | domain | A | The caller's process id. Answered before the dispatch table. |
| 11 | `SYS_YIELD` | time, sched | B | Give the hart to another ready task of the same or higher priority. Answered before the dispatch table. |
| 12 | `SYS_SLEEP_UNTIL` | time, sched | B | Block until an absolute deadline in nanoseconds (or, with `SLEEP_RELATIVE` in `a1`, for a duration). Returns 0 after blocking, 1 if the deadline had already passed. |
| 13 | `SYS_SCHEDCTL` | time, sched | A | Set class (`SCHEDCTL_CLASS_DL`, `_RT`, `_FAIR`), priority and deadline reservation; or, with `SCHEDCTL_HINT_QOS`, a QoS hint (`QOS_DEFAULT`, `QOS_LATENCY`, `QOS_THROUGHPUT`, `QOS_BACKGROUND`). RT and DL need a `time` endpoint capability with `WRITE`. |
| 14 | `SYS_MO_CREATE` | memory | A | Create a memory object of `a0` pages and mint a `Cap<Shm>`. `a1` is the creation word (access mode, kind, attributes, clone). |
| 15 | `SYS_MO_MAP` | memory | A | Map a `Cap<Shm>` (or, with handle 0, anonymous memory) into the caller; or change the protection of a mapping (`SHM_MAP_OP_PROTECT`). Returns the address. |
| 16 | `SYS_MO_UNMAP` | memory | A | Unmap a region and give back the caller's references (the capability is revoked), or unmap an anonymous range. |
| 17 | `SYS_IPC_FAST_REPLY_ACCEPT` | IPC | B | Reply to the exchange in hand and accept the next request in one trap. |
| 18 | `SYS_IPC_FAST_REPLY` | IPC | B | Answer an exchange in hand with four words. |
| 19 | `SYS_IPC_FAST_CALL_EP` | IPC | B | Fast call on a `Cap<Endpoint>` with four message words and an optional capability. |
| 20 | `SYS_IPC_FAST_ACCEPT` | IPC | B | A server takes the next request on an endpoint it serves. |
| 21 | `SYS_IPC_CALL_V2` | IPC | B | Call with a `MsgDesc`: inline words, capability entries, deadline, label. |
| 22 | `SYS_IPC_ACCEPT_V2` | IPC | B | Accept a request into a `MsgDesc`. |
| 23 | `SYS_IPC_REPLY_V2` | IPC | B | Reply with a `MsgDesc`. |
| 24 | `SYS_IPC_REPLY_DELEGATE` | IPC | B | Move the reply warrant of an accepted call to another thread of the same process. |
| 25 | `SYS_RING_SETUP` | IPC | A | Allocate an io_ring page and mint a `Cap<IoRing>`; the page address is written to `*a0`. |
| 26 | `SYS_RING_ENTER` | IPC | B | Process the pending submission entries of an io_ring. |
| 27 | `SYS_PORT_WAIT` | IPC | B | Wait on an event port with an absolute deadline; writes a 16-byte event. |
| 28 | `SYS_FUTEX_WAIT` | futex | B | Block while a 32-bit word holds an expected value, with an optional relative timeout. |
| 29 | `SYS_FUTEX_WAKE` | futex | B | Wake at most `n` waiters on a word. |
| 30 | `SYS_FOREIGN_ENTRY` | foreign ABI | A | Register (or with 0 withdraw) the ring-3 runtime's trap entry for reflected traps. |
| 31 | `SYS_FOREIGN_RESUME` | foreign ABI | A | Restore a full register frame (`ForeignFrame`) and return to user mode in foreign mode. |
| 32 | `SYS_INVOKE` | generic | A | Any operation on a handle: [SYS_INVOKE](#sys_invoke). |
| 33 | `SYS_FOREIGN_FORK` | foreign ABI | A | Copy-on-write copy of the calling process for a ring-3 runtime hosting a foreign program's `fork`. Refused with `-EPERM` unless a foreign entry is registered. |

Arguments and results of the IPC calls (17 to 24) are in [ipc.md](ipc.md);
the foreign-ABI frame is defined in `crates/core/abi/src/foreign.rs`.

`SYS_FOREIGN_ENTRY` and `SYS_FOREIGN_FORK` answer `-ENOSYS` in a kernel built
without Kconfig `LINUX_ABI`.

`CAP_TYPED_SYSCALLS` lists the calls that take a handle in `a0` (or `a5` for
`SYS_SCHEDCTL`) or mint one, so that a policy can treat them as a set. The
image profiles (`crates/core/sched/src/seccomp.rs`) grant calls by number
through a bitmap and grant `SYS_INVOKE` ops by class: each filter carries a
per-kind mask of op classes (`ops` in `crates/core/sched/src/filter.rs`).

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/syscall/src/dispatch.rs`
(`SYSCALL_TABLE`), `crates/core/sched/src/seccomp.rs`.

## Cases, entry counters and the pledge

A call is a syscall because one of two things cannot be done in ring 3:
change authority or protection, or block and wake. The `SYSCALL_CASE` table
in `syscall_nr.rs` records that for each number (`CASE_AUTHORITY` = 1,
`CASE_BLOCK_WAKE` = 2, `CASES` = 2); `syscall_case(nr)` reads it and returns 0
for an unassigned number. A call with ops of both kinds, such as `SYS_INVOKE`,
is listed under the case that makes it a syscall at all (authority). Device
access and copies between address spaces are ops of `SYS_INVOKE`, so they are
counted under its case.

The trap prologue (`kernel/src/trap/syscall.rs`) calls
`azos_sched::domain::count_entry` for each native entry, passing the case
(0 for a Linux-personality call). Each Domain keeps `ENTRY_SLOTS` (`CASES + 1`)
relaxed counters, slot 0 for the calls with no case; `entries()` reads them.
The counters exist with Kconfig `DOMAIN_ENTRY_COUNTERS`.

The same prologue judges the call against the Domain's pledge mask, which a
program narrows, one way, with `DOMAIN_PLEDGE`. The mask has one bit per case
(bits 0..=`CASES`, bit 0 for a call with no case and for every call of a Linux
task), one bit per op class of `SYS_INVOKE` (bits 8..24, `pledge_class`), and
`PLEDGE_ALWAYS` (bit 24) for `SYS_EXIT` and `SYS_THREAD_EXIT`, which no mask
loses. `SYS_INVOKE` is judged by its op's class bit, every other call by its
case bit (`pledge_bit`). A call outside the mask does not run: it returns
`-EACCES` and leaves a `pledge` decision record. A Domain created by a member
(spawn, fork) starts with its creator's mask, and exec keeps it. The pledge is
the second filter: the task's seccomp filter judges the call first. An io_ring
entry is judged by the ring owner's mask for the call it stands for, after the
owner's seccomp profile.

`tools/trap_lint.py` fails when a `SYS_*` number has no row in `SYSCALL_CASE`.

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/abi/src/invoke.rs`
(`pledge_bit`, `PLEDGE_*`), `crates/core/sched/src/domain.rs`,
`kernel/src/trap/syscall.rs`, `crates/core/ipc/src/io_ring.rs`,
`tools/trap_lint.py`.

## Handles

A capability crosses the boundary as a `u32` (`CapHandle`):

| Bits | Field |
|---|---|
| 31..26 | type tag (`CapType`: kind in 4 bits, class in 2) |
| 25..20 | permissions (`CapPerms`) |
| 19..9 | generation (11 bits, per slot; a slot is retired at `MAX_GENERATION`, not wrapped) |
| 8..0 | slot in the task's capability table (9 bits) |

Handle 0 is `CAP_NULL`. The kernel resolves a handle in the caller's own
table and refuses a generation that does not match (`-ECAPSTALE`).

Kinds (`CapKind`): `Endpoint` 1, `MemObj` 2, `Queue` 3, `Port` 4, `Domain` 5,
`Node` 6, `Device` 7, `Log` 8. Named types (`ty::*`): `ENDPOINT`, `PORT`,
`SHM`, `IORING`, `TASK`, `FILE`, `LAUNCH`, `SOCKET`, `IRQ`, `MMIO`,
`DRIVER_REGISTRY`, `IOPORT`, `NIC_QUEUE`, `TRACE`, `CONSOLE`.

Permissions (`CapPerms`): `READ` 0x01, `WRITE` 0x02, `EXEC` 0x04, `DUP` 0x08
(make a copy), `TRANSFER` 0x10 (move or send the capability to another
Domain), `MAP` 0x20 (map a memory object). `DELEGATE` is `DUP | TRANSFER`.

Source: `crates/core/abi/src/cap.rs`.

## SYS_INVOKE

```text
SYS_INVOKE(handle, op, w0, w1, w2, w3)
  a0 = the handle (a CapHandle, or DOMAIN_SELF)
  a1 = the op word: bits 0..16 the op, bit 16 INVOKE_REGS
  a2..a5 = four words        (register form, INVOKE_REGS set)
  a2 = pointer to a MsgDesc  (descriptor form, INVOKE_REGS clear)
result a0: >= 0 the op's value, < 0 an Errno
replies a1..a4 (register form) / MsgDesc.words (descriptor form)
```

The op is read in the namespace of the handle's type. A handle is the only
address: there is no path, task id or integer descriptor in the call. The
kernel resolves the handle in the caller's table, checks the right the op
needs, then runs the op. An unknown op is `-EINVAL`; a handle of a type with
no ops is `-ECAPKIND`, and an op whose kind field is not the handle's kind is
`-EINVAL`. A bit of the op word other than the op and `INVOKE_REGS`
(`INVOKE_FLAGS_KNOWN`) is `-EINVAL`. An op whose class the image profile does
not grant is handled like an unlisted syscall number: the task is killed, or
the use is recorded in audit mode.

**Register form.** The op's words travel in `a2..a5` (`INVOKE_REG_WORDS` = 4)
and its replies come back in `a1..a4`; the kernel reads no user memory for the
call itself. A pointer is a scalar. **Descriptor form.** `a2` points at a
[`MsgDesc`](#the-message-descriptor): the words are `words[..n_words]` and the
replies are written back into `words` and `n_words`. In this form `a3`..`a5`
must be 0 and the descriptor carries words only: `n_caps` other than 0 is
`-EINVAL`, and so is a `label` when Kconfig `IPC_LABELS` is off. An op that
needs more than four words is descriptor-only.

**Self handle.** `DOMAIN_SELF` names the calling domain (kind `Domain`, class
1, every right, generation 0). It is always valid, never stored and not
transferable. `is_domain_self(h)` tests for it.

### The op number

An op is a 16-bit number built by `op(kind, class, index)`:

| Bits | Field |
|---|---|
| 15..12 | kind of the handle it is invoked on (`CapKind`); `op_kind()` |
| 11..8 | class, the unit an image profile grants; `op_class()` |
| 7..0 | index within the class |

An op read out of source therefore says which kind it needs and which class a
profile must list for it. Up to `OP_KINDS` (16) kinds and `CLASSES` (16)
classes can be named.

| Class | Name | Meaning |
|---:|---|---|
| 0 | `CLASS_READ` | observes (stat, readdir, info queries, tracer reads) |
| 1 | `CLASS_WRITE` | moves data or changes what the object holds |
| 2 | `CLASS_WAIT` | blocks for an event |
| 3 | `CLASS_CTL` | makes or ends an object, or steers its life |
| 4 | `CLASS_ADMIN` | acts on others or on the system |
| 5 | `CLASS_FS_OPEN` | (`Node`) opens a file beneath a directory the caller holds |
| 6 | `CLASS_FS_MUTATE` | (`Domain`) changes the namespace; needs a directory tree the caller holds |
| 7 | `CLASS_MODULE` | (`Domain`) loads code |
| 8 | `CLASS_NET` | the network |
| 9 | `CLASS_DRIVER` | (`Domain`, `Device`) serves a device from ring 3 |

### Op tables

Value is the full 16-bit op number. "Needs" lists the rights the op checks
where the source states them.

**Log** (kind 8; console class `CONSOLE`, tracer class `TRACE`)

| Op | Value | Class | Summary |
|---|---|---|---|
| `LOG_CONSOLE_WRITE` | 0x8101 | WRITE | Write `w1` bytes at address `w0` (at most `LOG_CONSOLE_WRITE_MAX` = 4096); returns bytes taken. |
| `LOG_CONSOLE_WAIT` | 0x8202 | WAIT | Wait for console input or a child's exit notice; `w0` buffer, `w1` length, `w2` timeout ns (`LOG_CONSOLE_WAIT_FOREVER`). Needs `READ`. |
| `LOG_TRACE_INFO` | 0x8003 | READ | Mask of the classes compiled into the tracer (`-ENOSYS` when compiled out). |
| `LOG_TRACE_GET_MASK` | 0x8004 | READ | The runtime class mask. |
| `LOG_TRACE_REGION_BYTES` | 0x8005 | READ | Size of the trace region. |
| `LOG_TRACE_MAP` | 0x8306 | CTL | Map the trace region read-write; returns its address. Needs `READ` and `WRITE`. |
| `LOG_TRACE_SET_MASK` | 0x8407 | ADMIN | Set the runtime class mask; returns the previous one. Needs `WRITE`. |

**Domain**, on `DOMAIN_SELF` (kind 5): the caller's own process and namespace

| Op | Value | Class | Summary |
|---|---|---|---|
| `DOMAIN_EXIT_STATS` | 0x5001 | READ | Read one exit-path counter (`EXIT_STAT_*` selector in `w0`). |
| `DOMAIN_CREATE_PORT` | 0x5304 | CTL | Make an event port; returns its handle. |
| `DOMAIN_CREATE_ENDPOINT` | 0x5305 | CTL | Make an endpoint the caller serves; returns its handle. |
| `DOMAIN_SUBREAPER` | 0x5407 | ADMIN | Child-subreaper mark: `SUBREAPER_GET`, `_SET`, `_CLEAR`. |
| `DOMAIN_SET_FILTER` | 0x5408 | ADMIN | Confine the caller to a role profile, one way. |
| `DOMAIN_PLEDGE` | 0x5409 | ADMIN | Narrow the pledge mask of the caller's Domain (cases and op classes the trap prologue and the io_ring still admit); it never widens. |
| `DOMAIN_STAT` | 0x500D | READ | Stat a path into a `STAT_BYTES` (64) buffer. |
| `DOMAIN_READDIR` | 0x500E | READ | One directory entry; the name buffer is `READDIR_NAME_BYTES` (64). Descriptor form. |
| `DOMAIN_STATFS` | 0x500F | READ | Filesystem facts into a `STATFS_BYTES` (48) buffer. |
| `DOMAIN_MEMINFO` | 0x5010 | READ | Free pages of memory. |
| `DOMAIN_TASKINFO` | 0x5011 | READ | Task facts into a `TASKINFO_BYTES` (40) buffer. |
| `DOMAIN_NET_GETIP` | 0x5012 | READ | The interface's IPv4 address. |
| `DOMAIN_MKDIR` | 0x5614 | FS_MUTATE | Make a directory. |
| `DOMAIN_UNLINK` | 0x5615 | FS_MUTATE | Remove a file. |
| `DOMAIN_RMDIR` | 0x5616 | FS_MUTATE | Remove an empty directory (`-ENOTEMPTY`). |
| `DOMAIN_RENAME` | 0x5617 | FS_MUTATE | Rename. |
| `DOMAIN_TRUNCATE` | 0x5618 | FS_MUTATE | Truncate or extend a file. |
| `DOMAIN_SOCKET` | 0x581C | NET | Create a socket; returns a `ty::SOCKET` handle with `READ\|WRITE\|DUP\|TRANSFER`. |
| `DOMAIN_UPTIME` | 0x501E | READ | Milliseconds since boot. |
| `DOMAIN_WAIT` | 0x521F | WAIT | Reap a finished child without blocking; `-ECHILD` for a task that is not a child. |
| `DOMAIN_VDSO_MAP` | 0x5321 | CTL | Map the per-task vDSO page read-only; returns its address. |
| `DOMAIN_MODULE_VERIFY` | 0x5722 | MODULE | Verify a signed module (at most `MODULE_MAX_BYTES` = 4 MiB); returns a token. |
| `DOMAIN_MODULE_MAP_X` | 0x5723 | MODULE | Map a verified module executable. |
| `DOMAIN_DRIVER_REGISTER` | 0x5927 | DRIVER | Register as the driver for a kind named by a `DriverRegistry` handle. |
| `DOMAIN_DRIVER_UNREGISTER` | 0x5928 | DRIVER | Give up the driver slot. |
| `DOMAIN_DRIVER_FETCH` | 0x592C | DRIVER | Take one pending driver request without blocking. |
| `DOMAIN_DRIVER_REPLY` | 0x592D | DRIVER | Publish the reply for a request. |
| `DOMAIN_DRIVER_REPLY_FETCH` | 0x592E | DRIVER | Publish a reply and take the next request. |
| `DOMAIN_DRIVER_REPLY_WAIT` | 0x592F | DRIVER | As reply-fetch, blocking up to `w3` ms (default and ceiling 1000). |
| `DOMAIN_MMIO_MAP` | 0x5930 | DRIVER | Map a device's register window; needs the `Device` (`ty::MMIO`) capability. |

**Port** (kind 4); see [ipc.md](ipc.md#event-ports)

| Op | Value | Class | Summary |
|---|---|---|---|
| `PORT_POLL` | 0x4001 | READ | Dequeue one 16-byte event without blocking; `-EAGAIN` when empty. Needs `READ`. |
| `PORT_BIND` | 0x4302 | CTL | Bind (or with `PORT_BIND_F_REMOVE`, remove) an event source. Needs `WRITE`. |
| `PORT_DESTROY` | 0x4303 | CTL | Free the port and revoke the handle. Needs `WRITE`. |

**MemObj** (kind 2)

| Op | Value | Class | Summary |
|---|---|---|---|
| `MEMOBJ_ACQUIRE` | 0x2301 | CTL | Take a reference and read the geometry (`page_count` u32, `perms` u8) into an 8-byte buffer. Needs `READ`. |
| `MEMOBJ_END_DROP` | 0x2304 | CTL | Give up the read and/or write end (`SHM_END_READ`, `SHM_END_WRITE`) the caller holds on a pipe region. |

**Node** (kind 6): files and sockets the caller holds

| Op | Value | Class | Summary |
|---|---|---|---|
| `NODE_READ` | 0x6001 | READ | Read up to 4096 bytes. |
| `NODE_WRITE` | 0x6102 | WRITE | Write; `-EAGAIN` while containment is armed. |
| `NODE_FSYNC` | 0x6103 | WRITE | Flush the file to its device. |
| `NODE_BIND` | 0x6804 | NET | Bind a socket to a local sockaddr. |
| `NODE_CONNECT` | 0x6805 | NET | Connect a socket. |
| `NODE_SEND` | 0x6806 | NET | Send on a connected socket. |
| `NODE_RECV` | 0x6807 | NET | Receive, non-blocking; a closed TCP stream answers `-EEOF`. |
| `NODE_SENDTO` | 0x6808 | NET | Send to a sockaddr. |
| `NODE_RECVFROM` | 0x6809 | NET | Receive with the sender's sockaddr, non-blocking. |
| `NODE_MCAST_JOIN` | 0x680A | NET | Join an IPv4 multicast group on a UDP socket. |
| `NODE_MCAST_LEAVE` | 0x680B | NET | Leave a multicast group. |
| `NODE_LISTEN` | 0x680E | NET | Listen on a TCP socket at the port a `NODE_BIND` gave it; `-EAGAIN` while containment is armed. Needs `WRITE`. |
| `NODE_ACCEPT` | 0x680F | NET | Take one established connection as a new `ty::SOCKET` handle (`READ\|WRITE`); `-EAGAIN` when none waits. Non-blocking. Needs `READ`. |
| `NODE_OPENAT` | 0x650C | FS_OPEN | Open a name beneath a held directory handle; absolute names and `..` above the directory are refused. A write-mode open also needs a held tree with `WRITE` that covers the result. |
| `NODE_MMAP` | 0x630D | CTL | Map a file (shared or private) from the page cache; `PROT_EXEC` is never allowed. |

`ROOT_DIR_RESOURCE` is the `ty::FILE` resource of the directory on `/`, which
`SYS_CAP_INFO` looks up to find the task's root directory handle.

**Queue** (kind 3): a NIC queue (`ty::NIC_QUEUE`)

| Op | Value | Class | Summary |
|---|---|---|---|
| `QUEUE_NICQ_ATTACH` | 0x3903 | DRIVER | Take the NIC queue a `NicQueue` handle names from the stack and run it on two rings the caller made (`a2` receive, `a3` transmit); replies the MAC, the longest frame and the stamp kind. See [network.md](network.md#nic-queues-in-ring-3). |
| `QUEUE_NICQ_KICK` | 0x3804 | NET | Send what the caller pushed on the transmit ring; returns the frames sent. |
| `QUEUE_NICQ_DETACH` | 0x3905 | DRIVER | Give the queue back to the stack. |

**Device** (kind 7)

| Op | Value | Class | Summary |
|---|---|---|---|
| `DEVICE_IRQ_BIND` | 0x7901 | DRIVER | Bind an interrupt line to an event port with a key and a CPU (`DEVICE_IRQ_CPU_ANY`). A message-signalled slot also returns address, data and vector in `a1`..`a3`. |
| `DEVICE_IRQ_ACK` | 0x7902 | DRIVER | Unmask the line after the device was quietened; returns 0, or 1 if the handler's budget is spent. |
| `DEVICE_IOPORT_ENABLE` | 0x7906 | DRIVER | Open the I/O ports of a `ty::IOPORT` capability to the calling thread (x86_64); needs `READ\|WRITE`, every word 0. `-ENODEV` on an ISA without a port space. |

**Endpoint** (kind 1)

| Op | Value | Class | Summary |
|---|---|---|---|
| `ENDPOINT_DERIVE` | 0x1301 | CTL | Derive a narrowed, badged copy with up to `ENDPOINT_DERIVE_CAVEATS_MAX` (4) caveats. Descriptor form, seven words, decoded by `EndpointDerive::decode`. Needs `DUP` on the source. |

Source: `crates/core/abi/src/invoke.rs`, `crates/core/abi/src/syscall_nr.rs`
(sizes and offsets of the stat, statfs and task-info buffers),
`crates/core/libsys/src/lib.rs` (`invoke`, `invoke_desc`).

## The message descriptor

`MsgDesc` is one `repr(C)` layout used by the v2 IPC calls, by their replies
and by the descriptor form of `SYS_INVOKE`. The kernel always copies the whole
struct. Size 224 bytes, alignment 8, asserted at compile time.

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 2 | `version` | `MSG_VERSION` (1); a version the kernel does not know is refused. |
| 2 | 1 | `n_words` | Inline words used, at most `MSG_WORDS_MAX` (8) and the kernel's Kconfig `IPC_MSG_INLINE_WORDS` (4 to 8, default 8 on every ISA). |
| 3 | 1 | `n_caps` | Capability entries used, at most `MSG_CAPS_MAX` (8) and Kconfig `IPC_MSG_MAX_CAPS` (default 4, 2 with `PROFILE_EMBEDDED`). |
| 4 | 4 | `flags` | `MSG_KEEP` (bit 0) on send; `MSG_BADGED` (bit 31) set by the kernel on receive. |
| 8 | 8 | `badge` | Set by the kernel on receive: the badge of the endpoint capability the call came through. Not written by a caller. |
| 16 | 64 | `words` | Eight inline `u64` words. |
| 80 | 128 | `caps` | Eight `CapDesc` entries. |
| 208 | 8 | `deadline` | Absolute nanoseconds on the clock `clock_id` names; 0 means none. |
| 216 | 4 | `clock_id` | A `ClockId` raw value; 0 is `MONO`. Any other clock is refused. |
| 220 | 4 | `label` | Provenance label, see below. Bits outside `LABEL_KNOWN` must be 0. |

`CapDesc` is 16 bytes: `handle` u32 at 0 (the sender's handle; the
receiver's on receive), `mode` u8 at 4 (`CAP_MODE_MOVE` = 1, `CAP_MODE_DUP` =
2), `_pad` u8 at 5, `rights` u16 at 6 (the rights the receiver gets; 0 means
the sender's own), `expiry_ns` u64 at 8 (a deadline for the receiver's copy on
the MONO clock; never later than the sender's; 0 means the sender's own).
A MOVE needs `TRANSFER` on the capability and makes the sender's handle stale;
a DUP needs `TRANSFER` and `DUP`, derives an attenuated child and leaves the
sender's handle in place. All entries move to the receiver or none does.
With `MSG_KEEP`, a refused transfer leaves the sender's MOVE entries in place;
without it they are consumed. `MsgDesc::well_formed()` checks version, counts
and label bits.

**Deadline.** A call whose `deadline` is at or before the kernel's clock is
refused with `-EDEADLINE` before it is queued and nothing moves. The server
reads the same `deadline` and `clock_id` in the descriptor it accepts, so it
can bound its own work by the caller's deadline. Before the call is queued the
server's scheduling context admits the time left: a server with its own
reservation must serve within the time left (its relative deadline), a passive
server (no reservation, its row's `call_budget_us`) must fit its per-call budget
in the time left and in the budget the caller's reservation lends it. A refusal
is `-EADMIT` with a counter-offer written back: `words[0]` the receipt (the id of
the `call-admission` decision record), `words[1]` 1 (deadline) or 2 (budget),
`words[2]` the offered deadline (ns) or budget (us), and `deadline` the offered
deadline. A call with a deadline lends the caller to its server: a passive
server runs on the caller's reservation, in its deadline order and on its
budget (seL4 MCS style), and gets a `PORT_EVENT_CALL_NOTICE` when that budget
runs out (`ETIMEDOUT`) or the caller withdraws (`ECANCELED`). The register-only
fast path carries no deadline and pays for none of this.

**Label.** `label` is a set of principal kinds the data has passed through,
one bit per kind: `LABEL_SYSTEM` 1, `LABEL_SERVICE` 2, `LABEL_USER` 4,
`LABEL_AGENT` 8 (`LABEL_KNOWN` is their union). The kernel ORs the sender's
principal into the label of every message it sends or replies with
(`send_label`); labels only grow along a path. Only a one-shot `DECLASSIFY`
caveat lowers one (see [ipc.md](ipc.md#derived-capabilities-and-caveats)). The
actuation gate holds a physical effect to the most restrictive envelope among
the kinds in the label of the request that caused it.

Source: `crates/core/abi/src/ipc_msg.rs`, `config/limits/Kconfig.limits`.

## Error model

A failing call returns `-(errno)` as an `isize`; success is `>= 0`. `Errno` is
defined in `crates/core/abi/src/error.rs` (`#[repr(i64)]`, non-exhaustive).
`Errno::to_syscall_ret()` and `Errno::from_syscall_ret()` convert; the latter
returns `None` for a non-negative value or a number it does not know.

| Range | Codes |
|---|---|
| POSIX-aligned | `EPERM` 1, `ENOENT` 2, `ESRCH` 3, `EINTR` 4, `EIO` 5, `EBADF` 9, `ECHILD` 10, `EAGAIN` 11, `ENOMEM` 12, `EACCES` 13, `EFAULT` 14, `EBUSY` 16, `EEXIST` 17, `ENODEV` 19, `ENOTDIR` 20, `EISDIR` 21, `EINVAL` 22, `EMFILE` 24, `ENOSPC` 28, `EROFS` 30, `EPIPE` 32, `ENAMETOOLONG` 36, `ENOSYS` 38, `ENOTEMPTY` 39, `ETIMEDOUT` 110, `ECANCELED` 125 |
| Authorization | `ENOTOWNER` 99: not the object's owner, or not otherwise authorized, for checks that are not a capability-table lookup |
| Capabilities | `ECAPKIND` 200 (wrong kind), `ECAPPERMS` 201 (missing right), `ECAPSTALE` 202 (generation stale: revoked or freed) |
| Policy | `ETOPOLOGY` 203 (not allowed by the signed topology), `ESAFETY` 204 (safety policy), `EAUTH` 205, `EREPLAY` 206, `EOTASIG` 207, `EROLLBACK` 208, `EQUOTA` 209, `EABIVERSION` 210 |
| IPC | `EPEERDIED` 211 (the serving task died with the call queued or in service), `EREVOKED` 212 (the endpoint was destroyed), `ENOSENDERS` 213 (no sender left on the endpoint), `EV1ACCEPT` 215 (a v2 call taken by the fast accept), `EDEADLINE` 216 (deadline already passed), `ERTPROXY` 217 (a real-time task called a proxy endpoint), `EEOF` 218 (end of a stream), `EADMIT` 220 (the server cannot meet the call's remaining deadline: the descriptor carries the counter-offer) |
| Memory | `EPURGED` 219 (a volatile memory object lost its frames to memory pressure: the map or clone has nothing to use) |

`EAGAIN` is also what a write-class op answers while containment is armed.
`ETIMEDOUT` (110) is returned by the futex wait (see [ipc.md](ipc.md#futex)) and
by the Linux personality; it is not an `Errno` variant.

**Bare codes.** The fast-IPC family and some other calls return small negative
values that are not `Errno` numbers. `-1` is a generic refusal and has the same
value as `-EPERM`; the contract of each call says which it means.

| Call | Codes |
|---|---|
| `SYS_IPC_FAST_CALL_EP` | `-1`: capability does not resolve, lacks `WRITE`, names an endpoint nobody serves, or the call was given up. Also `-EPEERDIED`, `-EREVOKED`. |
| `SYS_IPC_FAST_REPLY` | 0 delivered, `-2` stale handle, `-1` any other refusal |
| `SYS_IPC_FAST_ACCEPT` | `-1` when nothing arrived |
| `SYS_IPC_FAST_REPLY_ACCEPT` | `-2` stale handle, `-3` any other refusal of the reply (nothing accepted); then as accept |
| `SYS_IPC_REPLY_V2` | `-3` the caller holds no warrant of an unanswered call, `-2` the call ended meanwhile, `-1` refused transfer |
| `SYS_IPC_REPLY_DELEGATE` | `-2` call over, `-3` no warrant, `-EPERM` target is not a thread of the caller's process |
| `SYS_IPC_CALL_V2`, `SYS_IPC_ACCEPT_V2` | `-1` for the capability, a refused transfer, an empty accept or a wait that ran out |

Unassigned syscall numbers answer `-1`.

### Receipts

An actuation effect refused by the effect gate (a full record ring, a deadline
that cannot be met, a device held in its safe state, a provenance envelope) is
written as a decision record, and the record's id is the refusal's receipt
(`Refusal::receipt` in `crates/core/actuation/src/effect_gate.rs`;
`record_receipt` in `crates/core/decision/src/lib.rs`). The id is 0 when
decision records are off in the build, so 0 is never a valid receipt. Records
are read by id through the `Decisions` interface
(`userspace/lib/decisions/src/lib.rs`, served by `userspace/services/decisd`).
The inverse direction also exists: a `RECEIPT` caveat on a capability makes a
use valid only while the recorder holds a recent enough receipt of a given
kind for a device ([ipc.md](ipc.md#derived-capabilities-and-caveats)).

Source: `crates/core/abi/src/error.rs`, `crates/core/abi/src/syscall_nr.rs`,
`crates/core/actuation/src/effect_gate.rs`, `crates/core/decision/src/lib.rs`.

## Clocks

A `ClockId` is a `u32`: kind in bits 31..24, index in bits 23..0
(`ClockId::new`, `kind()`, `index()`, `raw()`).

| Kind | Constant | Served | Meaning |
|---:|---|:-:|---|
| 0 | `ClockId::MONO` | yes | monotonic boot clock (raw value 0, so a zeroed field names it) |
| 1 | `ClockId::REAL` | yes | wall clock (UTC, Unix epoch) |
| 2 | `ClockId::TSC_RAW` | no | raw hardware counter |
| 3 | `KIND_PTP` (`ClockId::ptp(n)`) | no | PTP hardware clock `n` |
| 4 | `KIND_TSN_DOMAIN` (`ClockId::tsn_domain(n)`) | no | time-sensitive-networking domain `n` |
| 5 | `KIND_VCPU` (`ClockId::vcpu(n)`) | no | virtual time of vCPU `n` |
| 6 | `ClockId::TAI` | yes | International Atomic Time, Unix epoch, no leap seconds |
| 7 | `ClockId::BOOT` | yes | monotonic clock plus time spent suspended |

Reserved kinds are numbers a caller can name and be refused
(`ClockError::Unsupported`) instead of being read on the wrong clock. `REAL`
and `TAI` are `MONO` plus an offset the kernel publishes in the vDSO; until a
time source sets them they read like `MONO`. `ClockId::from_posix` maps a
POSIX `clockid_t` to a served clock. All times are nanoseconds
(`NS_PER_SEC`); `ns_to_ticks_ceil` and `ticks_to_ns` convert to and from the
counter frequency the platform publishes, and kernel and user space use the same two
functions. `SYS_IPC_CALL_V2` serves only `MONO`.

Source: `crates/core/abi/src/time.rs`.

## The vDSO

One read-only physical page is mapped into every user process at
`VDSO_USER_BASE` (`0x2000_0000`). The kernel writes it; ring 3 reads it with
ordinary loads and issues no syscall for time. `VdsoData`
(`crates/core/mm/src/vdso.rs`) is the layout, and `azos_abi::vdso` holds the
offsets both sides read; a field moved in one fails the build of the other.

| Offset | Type | Field | Notes |
|---:|---|---|---|
| 0 | u32 | `magic` | `VDSO_MAGIC` (`"VDSO"`) |
| 4 | u32 | `kernel_version` | major<<16 \| minor<<8 \| patch |
| 8 | u32 | `seq` | seqlock; odd while the kernel writes |
| 12 | u32 | `flags` | bit 0 `VDSO_FLAG_RDTIME_NATIVE`: the time counter is readable from user mode without a trap |
| 16 | u64 | `uptime_ticks` | timer-interrupt tick count (under `seq`) |
| 24 | u64 | `uptime_ms` | milliseconds since boot (under `seq`) |
| 32 | u64 | `timebase_hz` | counter frequency; 0 means not published |
| 40 | u64 | `hwcap` | `VDSO_HWCAP_OFFSET`, see below |
| 48 | u64 | `counter_base` | `VDSO_COUNTER_BASE_OFFSET` |
| 56 | u64 | `ticks_base` | `VDSO_TICKS_BASE_OFFSET` |
| 64 | u64 | `counter_mult` | `VDSO_COUNTER_MULT_OFFSET`, 32.32 fixed point |
| 72 | u64 | `hwcap2` | `VDSO_HWCAP2_OFFSET`, overflow word; no bit defined |
| 80 | u32 | `layout_version` | `VDSO_LAYOUT_VERSION` (2) |
| 84 | u32 | `abi_version` | `ABI_VERSION` |
| 88 | 32 B | `clock` | `ClockWords`: generation u32, pad u32, `real`, `tai`, `boot` (u64 each) |

`flags`, `timebase_hz`, `hwcap`, the counter scale, `hwcap2`, `layout_version`
and `abi_version` are written once during boot before the first user task and
sit outside the seqlock. `uptime_ticks` and `uptime_ms` are refreshed by the
timer interrupt, so their granularity is the tick period.

**Seqlock.** A reader loops: load `seq`; if odd, retry; read the fields; load
`seq` again; if it changed, retry. The kernel increments `seq` to odd, stores
the fields, then increments it to even. Several harts may update; a writer
claims the right to write with a compare-and-exchange on `seq`.

**Exact time without a trap.** A program reads the hardware counter itself
(riscv64 `rdtime`, aarch64 `cntvct_el0`; x86_64 `rdtsc`, converted with the
counter scale) and converts with the published frequency.
`ticks = ticks_base + ((counter - counter_base) * mult) >> 32` (128-bit
product) where the counter ring 3 reads does not run at the clock's rate; all
three words are 0 where the counter is the clock, or where ring 3 does not read
it. `azos_libsys::vdso_now_ns()` returns monotonic
nanoseconds this way; on riscv64 and x86_64 it falls back to a syscall where
`flags` bit 0 is clear (aarch64 reads `cntvct_el0` unconditionally, and the
kernel sets the bit only for the riscv64 QEMU build and for x86_64 with a
published counter scale); `azos_libsys::clock_now(ClockId)` adds the offset of `REAL`, `TAI`
or `BOOT`.

**Clock words.** `ClockWords` has its own seqlock generation, separate from
`seq` so that a rare time-source update never makes the per-tick update lose a
tick. `REAL = MONO + real`, `TAI = MONO + tai`, `BOOT = MONO + boot`
(saturating). All zero until a time source sets them.

**Hardware capabilities (`hwcap`).** The analogue of `AT_HWCAP`: what the CPU
implements and ring 3 may execute, detected at boot, never from build flags.
A bit is set only if the extension's Kconfig policy allows it, the CPU has it,
and, for an extension the OS must switch on for ring 3, the kernel did. Each
ISA numbers its own bits from 0 and the word means what the running ISA's
table says; a reader ignores bits it does not know.

| Bit | aarch64 (`HWCAP_A64_*`) | riscv64 (`HWCAP_RV_*`) | x86_64 (`HWCAP_X86_*`) |
|---:|---|---|---|
| 0 | `CRC32` | `ZBB` | `SSE4_2` |
| 1 | `AES` | `ZBC` | `POPCNT` |
| 2 | `PMULL` | `V` | `AVX2` |
| 3 | `SHA2` | `ZKNH` | `BMI1` |
| 4 | `ATOMICS` | `PMU_CYCLES` | `BMI2` |
| 5 | `PAUTH` | `PMU_INSTR` | `FMA` |
| 6 | `BTI` | | `MOVBE` |
| 7 | `MTE` | | `AES` |
| 8 | `MTE_SYNC` | | `PCLMULQDQ` |
| 9 | `SVE` | | `SHA_NI` |
| 10 | `PMU_CYCLES` | | `RDRAND` |
| 11 | `PMU_INSTR` | | `RDSEED` |
| 12 | | | `ADX` |
| 13 | | | `FSGSBASE` |
| 14 | | | `PKU` |
| 15 | | | `CET_IBT` |
| 16 | | | `CET_SHSTK` |
| 17 | | | `INVARIANT_TSC` |
| 18 | | | `PMU_CYCLES` |
| 19 | | | `PMU_INSTR` |
| 20 | | | `PMU_FIXED` |

The `PMU_*` bits publish the cycle and retired-instruction counters to ring 3
(riscv64 `rdcycle`/`rdinstret` through `scounteren`, aarch64
`PMCCNTR_EL0`/`PMEVCNTR0_EL0` through `PMUSERENR_EL0.CR/ER`, read only, x86_64 `rdpmc` through
`CR4.PCE`): set only for a counter the boot probe found moving AND Kconfig
`PMU_USER` opened, so a program that checks the bit never traps. x86_64's
`PMU_FIXED` says which `rdpmc` index: set, Intel's fixed counters (`1 << 30`
instructions, `(1 << 30) | 1` cycles); clear, core counters 0 (cycles) and 1
(instructions). aarch64 instruction counters are 32 bits wide before PMUv3p5.

`HWCAP_A64_ALL`, `HWCAP_RV_ALL` and `HWCAP_X86_ALL` are the unions; compile-time
assertions check that every bit is a single bit and none repeats within an ISA.
`azos_libsys::vdso_hwcap()` and `vdso_hwcap2()` read the words.

### The per-task page

`DOMAIN_VDSO_MAP` maps a second page, per task, read-only, and returns its
address. Its layout is also ABI (`VTP_*` offsets in `azos_abi::vdso`; the kernel
asserts its struct against them with `offset_of!`):

| Offset | Type | Field |
|---:|---|---|
| 0 | u32 | `magic` (`VDSO_TASK_MAGIC`, `"VTSK"`) |
| 4 | u32 | layout version (`VDSO_TASK_VERSION`, 2) |
| 8 | u32 | seqlock (`VTP_SEQ`), odd while the kernel writes |
| 12 | u32 | owner TID |
| 16 | u64 | CPU time charged to the task, timebase ticks |
| 24 | u64 | voluntary context switches |
| 32 | u64 | preemptions by the timer |
| 40 | u32 | `ready_site` tag of the last dispatch |
| 44 | u32 | sensor mask: bit `t` set when a sensor endpoint of type `t` was bound |
| 48 | u64 | publications of the page |
| 56 | u64 | timebase counter at the last publication |
| 64 | 10 slots of 64 B | sensor slots (`VTP_SENSORS`, stride `VTP_SENSOR_STRIDE`) |

A sensor slot: `seq` u32, `len` u32, `stamp` u64 (timebase counter at
publication), `data` up to `VTP_SENSOR_DATA_MAX` (32) bytes at offset 16, and,
from layout version 2, `acq_ns` u64 at offset 48 (when the value was acquired on
the vDSO clock; 0 unknown). There are `VTP_SENSOR_SLOTS` (10) slots, sensor types
0 to 9. A layout-version-1 reader keeps working: version 2 only adds `acq_ns`
in what was padding. `azos_libsys::vdso_task_counters()` and
`vdso_sensor_read()` read the page.

Source: `crates/core/abi/src/vdso.rs`, `crates/core/mm/src/vdso.rs`,
`crates/core/abi/src/time.rs` (`ClockWords`), `crates/core/libsys/src/lib.rs`.

## ABI version

`ABI_VERSION` (`crates/core/abi/src/lib.rs`) is 2. A program and a kernel compare
it at two places:

- **The loader.** `libsys` embeds an ELF note `.note.azos.abi` (name `AZOS`,
  type `ABI_NOTE_TYPE` = 1, the version as a 4-byte descriptor). The kernel's
  ELF loader refuses an image whose note names another version. An image with
  no note is not refused.
- **The vDSO.** The kernel writes the version it implements at
  `VDSO_ABI_VERSION_OFFSET` (84); `azos_libsys::abi_matches()` compares it with
  the version the program was built against.

`Errno::EABIVERSION` (210) names a version mismatch; neither check above
returns it (the loader refuses the image, and `abi_matches()` returns a bool).

The vDSO page has its own `layout_version` (`VDSO_LAYOUT_VERSION`), separate
from `ABI_VERSION`.

Source: `crates/core/abi/src/lib.rs`, `crates/core/abi/src/vdso.rs`.

## Other shared definitions

The rest of `azos_abi` holds layouts and selectors that one subsystem and its
ring-3 users share:

| Module | What it defines |
|---|---|
| `ushell` | The `SYS_SPAWN_EX` request block (`SpawnReq`, 184 bytes, `SPAWN_F_*`, the move list), the `StartupBlock` (120 bytes) a spawned child receives in `a1`, and the flag values of `LOG_CONSOLE_WAIT` and `SYS_ALERT` (`KILL_*`). |
| `io_ring` | The io_ring page as ring 3 sees it: offsets, ring sizes, opcodes and flags; the kernel's `IoRing` asserts its layout against them. |
| `foreign` | `ForeignFrame`, its alignment and red zone, the user flags mask, and the window the ring-3 runtime is mapped in (`RUNTIME_BASE`..`RUNTIME_LIMIT`, above the vDSO). |
| `drv_kind` | The `DRV_KIND_*` device-kind numbers the driver ops of the Domain take. |
| `exit_status` | The exit statuses the kernel assigns when it kills a task (128 + the signal number). |
| `trace` | The tracer's event classes and event ids, used with the `LOG_TRACE_*` ops. |
| `families` | The operation selectors of the kernel-served `flight`, `behavior`, `config` and `ota` interfaces. |
| `power` | The limits and policy words of the `Power` interface. |
| `rt_levels` | The cross-level admission rule for EDF + CBS reservations, shared by the topology's boot check and the scheduler. |
| `sensor_sample` | The acquisition stamp of a sensor sample. |
| `types` | The robot-facing `repr(C)` records `SensorState`, `MotorOutput`, `RobotInfo` and `SafetyProfile`, with their sizes asserted in tests. |

Source: `crates/core/abi/src/lib.rs` and the module files beside it.
