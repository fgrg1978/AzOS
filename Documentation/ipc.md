# IPC, shared memory and rings

This document describes how tasks talk to each other and to the kernel's
services: endpoints and calls, derived capabilities, memory objects, the ring
primitives built on shared memory, the POSIX byte pipe, the futex, event ports
and the io_ring. Numbers and layouts of the calls themselves are in
[abi.md](abi.md); the typed interface layer that most services use on top of
endpoints is in [idl.md](idl.md).

Contents:

- [Endpoints](#endpoints)
- [Fast call](#fast-call)
- [Descriptor call (v2)](#descriptor-call-v2)
- [Derived capabilities and caveats](#derived-capabilities-and-caveats)
- [Memory objects](#memory-objects)
- [Rings](#rings)
- [POSIX byte pipe](#posix-byte-pipe)
- [Futex](#futex)
- [Event ports](#event-ports)
- [io_ring](#io_ring)

## Endpoints

An endpoint is the name a client is given instead of a task id. Holding a
`Cap<Endpoint>` with `WRITE` is the right to send a request to whatever
service listens on it; holding nothing is the right to send nothing. A call
resolves the handle in the caller's own capability table, queues the request
on that endpoint and wakes the task that serves it.

| | Task-hosted endpoint | Kernel-hosted endpoint |
|---|---|---|
| Served by | a ring-3 task | the kernel, for an interface it implements |
| Created by | `DOMAIN_CREATE_ENDPOINT` on `DOMAIN_SELF`, or by the topology at admission | the kernel, one per interface, owned by the host key |
| Call needs | `WRITE` on the handle | any non-empty right; the op class is checked per op inside the call |
| Badge | stamped when a capability is derived (`SYS_CAP_DERIVE`, `ENDPOINT_DERIVE`) | names the resource (a pin, a bus address, a partition); only the kernel stamps it, so deriving from one is refused |

An endpoint records its owner as a single word. For a kernel-hosted endpoint
the owner is `KERNEL_HOST_BASE` (`0xFFFF_0000`) plus a host key in `1..0xFFF0`
(`kernel_host`, `host_key`); no task id falls in that range. The host keys and
interface ids of the kernel-hosted interfaces are in `azos_devif::IFACES`
(see [idl.md](idl.md#interface-ids-and-the-registry)). A task finds a
capability it already holds with `SYS_CAP_INFO` (`CAP_INFO_LOOKUP`; for a
kernel-hosted endpoint the resource is `host_key << 32 | badge`). A request to
a kernel-hosted endpoint may carry capability entries only for the interfaces
whose ops take one (`Uart`, `Adc`, `Vm`, `Display`, `MemCtl`, `Keys`, `Sound`;
`khost::takes_caps`); the entries stay in the caller's table and the kernel
resolves them there. Every other kernel-hosted interface refuses such a
request. The image profile lists the kernel-hosted interfaces a program may
call, and an unlisted one is handled like an unlisted syscall.

An endpoint that is not yet served (a named endpoint that no server has
claimed) refuses calls. If the serving task dies, or the endpoint is destroyed,
while a call is queued or in service, the caller completes with `-EPEERDIED` or
`-EREVOKED`. A caller's priority is donated to the serving task for the length
of an exchange. Each task has at most one call in flight.

Limits: endpoints in the machine (Kconfig `IPC_ENDPOINTS`), endpoints per
task (`IPC_ENDPOINTS_PER_TASK`), names of at most `ENDPOINT_NAME_MAX` (24)
bytes, compared whole. An endpoint created under a name starting with
`PROXY_NAME_PREFIX` (`rpc-`) is a proxy: the local face of a service on
another node. A real-time task that calls a proxy is refused with
`-ERTPROXY` before the call is queued.

A server can bind an endpoint it serves to an event port with
`PORT_SRC_ENDPOINT` to be told when no sender capability is left ([Event ports](#event-ports)).

Source: `crates/core/ipc/src/endpoint.rs`, `crates/core/ipc/src/ep_queue.rs`,
`crates/core/ipc/src/fastcall.rs`, `crates/core/devif/src/lib.rs`,
`crates/core/syscall/src/khost.rs`.

## Fast call

The fast call moves four words through registers. `a0`..`a6` below name argument
and output positions; the registers they map to on each ISA are in the table in
[abi.md](abi.md#entering-the-kernel).

| Call | Inputs | Result |
|---|---|---|
| `SYS_IPC_FAST_CALL_EP` | `a0` `Cap<Endpoint>` (`WRITE`); `a1`..`a4` request words; `a5` a capability to move with the request (0 none), with `FAST_CALL_CAP_SHARE` (bit 32) set to share it instead | `a0` reply word 0, `a1`..`a3` reply words 1 to 3; or a negative code |
| `SYS_IPC_FAST_ACCEPT` | none | `a0` handle of the exchange, `a1` caller's task id, `a2`..`a5` request words, `a6` the server's handle of the capability the request moved (0 when it moved none); `-1` when nothing arrived |
| `SYS_IPC_FAST_REPLY` | `a0` handle from the accept; `a1`..`a4` reply words | 0 delivered, `-2` stale handle, `-1` other refusal |
| `SYS_IPC_FAST_REPLY_ACCEPT` | `a0` handle from the previous accept; `a2`..`a5` reply words; `a1` is not read | as the accept; `-2` stale, `-3` other refusal of the reply (nothing accepted) |

`SYS_IPC_FAST_REPLY_ACCEPT` is the server side of a request loop: it answers
the exchange in hand and then blocks for the next request on the caller's own
endpoints in one trap. The accept blocks for up to eight wakes before it
returns `-1`. The fast path carries no deadline and no label. A capability in
`a5` is moved (the sender's handle goes stale; for a `Cap<Shm>`, the sender's
mapping goes with it) or, with `FAST_CALL_CAP_SHARE`, shared (the receiver gets
a derived copy with the sender's rights and the sender keeps its handle and
mapping).

While containment is armed, the capability resolve of a call on a task-hosted
endpoint is refused, so a contained task cannot open new service requests; a
call on a kernel-hosted endpoint still resolves, and the op class that acts is
refused inside the call.

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/ipc/src/fastcall.rs`,
`crates/core/ipc/src/ep_queue.rs`.

## Descriptor call (v2)

The v2 calls carry a [`MsgDesc`](abi.md#the-message-descriptor): up to
`IPC_MSG_INLINE_WORDS` inline words and `IPC_MSG_MAX_CAPS` capability entries,
a deadline and a label.

| Call | Inputs | Result |
|---|---|---|
| `SYS_IPC_CALL_V2` | `a0` `Cap<Endpoint>` (`WRITE`); `a1` `*mut MsgDesc` | 0 when answered (the answer is written over `*a1`) |
| `SYS_IPC_ACCEPT_V2` | `a0` `*mut MsgDesc` | the call's handle (the reply warrant's name, `>= 0`), `-1` when nothing arrived, `-EFAULT` (the call stays accepted: answer or delegate it by the returned handle) |
| `SYS_IPC_REPLY_V2` | `a0` call handle; `a1` `*const MsgDesc` | 0 |
| `SYS_IPC_REPLY_DELEGATE` | `a0` call handle; `a1` task id of a thread of the caller's own process | 0 |

A call blocks until it is answered. Capability entries move to the other side
all or nothing, before the answer is published. The server receives the words,
its own handles for the moved capabilities, the badge of the capability the call
came through (`MSG_BADGED` set), the deadline, the clock id and the label.

Errors of `SYS_IPC_CALL_V2`:

| Code | Meaning |
|---|---|
| `-EPEERDIED`, `-EREVOKED` | the call completed without an answer |
| `-EV1ACCEPT` | the server took the call with the fast accept, which names only four words and one capability; the server sees nothing and every capability the call carried is back in the caller's table |
| `-EINVAL` | a descriptor the kernel refuses: unknown version, counts above its limits, a mode other than MOVE/DUP, flag bits other than `MSG_KEEP`, a reserved label bit, or a `clock_id` other than `ClockId::MONO` |
| `-EDEADLINE` | the descriptor's deadline is at or before now; refused before queueing, nothing moved |
| `-ERTPROXY` | the caller is a real-time task and the endpoint is a proxy |
| `-EFAULT` | the descriptor is unreadable |
| `-1` | the capability or a transfer is refused (one code on purpose, so the refusal does not reveal which); also when the wait ran out and the call was withdrawn |

`SYS_IPC_REPLY_V2` answers once, as the holder of the call's reply warrant.
To a call that came through the fast path, only the first four words travel and
no capability may (`-EINVAL`). It returns `-3` when the caller holds no warrant
of an unanswered call, `-2` when the call ended between that check and the
answer (the moved capabilities go back), and `-1` for a refused transfer.
`SYS_IPC_REPLY_DELEGATE` moves the warrant so that only the named thread may
answer; it returns `-2` when the call is over, `-3` when the caller does not
hold the warrant, and `-EPERM` when the target is not a live thread of the
caller's process.

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/abi/src/ipc_msg.rs`,
`crates/core/syscall/src/ipc_v2.rs`.

## Derived capabilities and caveats

A capability can be narrowed and lent without giving up the original.

- `SYS_CAP_DERIVE` mints a child of a held endpoint capability (needs `DUP`) with a
  subset of the rights, a non-zero badge and an expiry; the child sits in the
  warrant tree under its source, so `SYS_CAP_REVOKE` on the source revokes it.
  `SYS_CAP_REVOKE` revokes every descendant (in any task they were lent or moved
  to) and returns a replacement handle for the source.
- The `ENDPOINT_DERIVE` op ([abi.md](abi.md#op-tables)) does the same and
  attaches up to `CAVEATS_MAX` (4) caveats. Caveats are append-only and the copy
  carries its source's, so it is never less restricted than the capability it
  came from.
- A DUP entry in a message derives a child for the receiver with explicit rights
  and an expiry, never later than the sender's.

Caveat kinds (`azos_ipc::cap::caveat`):

| Kind | Value | Argument | Effect |
|---|---:|---|---|
| `EXPIRY` | 1 | monotonic deadline in ns | a use at or after it is `Revoked` |
| `QUOTA` | 2 | uses left | each passing use takes one; at 0 the capability is `Revoked` |
| `NODE` | 3 | node | reserved; a capability that carries one refuses every use |
| `OP_MASK` | 4 | mask of op classes (bit n = class n); on a kernel-hosted endpoint, of IDL ops (bit n = op n) | the capability may be invoked only with those classes (ops) |
| `RECEIPT` | 5 | device (bits 0..16), receipt kind (16..24), `max_age_ms` (24..56) | a use is valid only while the recorder's newest receipt of that kind for that device is at most `max_age_ms` old and no later receipt of the contrary kind contradicts it |
| `DECLASSIFY` | 6 | label bits (`LABEL_*`) | a one-shot warrant to take those bits off one message's label; only a task whose principal is a user may mint one; it is moved, never copied, and the call that presents it spends it |

Source: `crates/core/ipc/src/cap.rs` (`caveat`, `CAVEATS_MAX`),
`crates/core/abi/src/invoke.rs` (`ENDPOINT_DERIVE`, `EndpointDerive`),
`crates/core/abi/src/syscall_nr.rs`.

## Memory objects

A memory object (MemObj) is the one kernel object for memory that is named,
charged, transferred or shared. It is named by a `Cap<Shm>`.

| Kind | Raw | Frames | Created by | Charged |
|---|---:|---|---|---|
| `Anon` | 0 | one zeroed frame per page | ring 3 (`SYS_MO_CREATE`) or the kernel | yes |
| `Contig` | 2 | physically contiguous zeroed run, one bus address for a device | ring 3 (`SYS_MO_CREATE`) or the kernel | yes |
| `Paged` | 3 | file pages, filled on demand: a file's page cache | the kernel only | no (system memory) |

A region has at most `MAX_MEMOBJ_PAGES` (64) pages and at most
`MAX_MEMOBJ_HOLDERS` (8) tasks may hold a reference to it at once; a further
holder is refused at the acquire. Frames of `Anon` and `Contig` objects are
charged to the Domain of the task that holds the owning reference and given
back when the last reference goes.

**Creating.** `SYS_MO_CREATE(a0 = pages, a1 = creation word)`:

| Bits | Field |
|---|---|
| 1..0 | access mode: 0 read-only, 1 read-write |
| 15..8 | kind: `SHM_KIND_ANON` (0) or `SHM_KIND_CONTIG` (2); `Paged` is the kernel's. A `Contig` object takes no `SHM_ATTR_SWAPPABLE`, no `SHM_ATTR_VOLATILE` and no clone, and fails with `-ENOMEM` when no run of that length is free |
| 23..16 | attributes: `SHM_ATTR_SWAPPABLE` (1), `SHM_ATTR_NO_KERNEL_MAP` (2); `SHM_ATTR_VOLATILE` (4, `Anon` only): the owner may make the object droppable under memory pressure (`MemCtl`, see [memory.md](memory.md)) |
| 24 | `SHM_CREATE_CLONE`: copy-on-write snapshot of the object the capability in bits 63..32 names (`READ`); `a0` is then 0 or the source's page count |
| 63..32 | the source capability when bit 24 is set, else 0 |

Any other bit is `-EINVAL`. It returns the new `Cap<Shm>` handle, or
`-ENOMEM`, `-EINVAL` or `-EMFILE`.

**Mapping.** `SYS_MO_MAP` with a handle maps the region with its own access
mode and returns the base address. It needs `READ` and `MAP`, and `WRITE` for a
writable region. The mapping is recorded, one per task and region
(`-EBUSY` for a second). With `SHM_MAP_OP_PROTECT` in `a1` it instead changes
the protection of the caller's mapping, never past what the map allowed
(`SHM_MAP_PROT_WRITE` makes it writable again). With handle 0 it maps anonymous
memory: `a2` length, `a3` protection (`PROT_READ` 1, `PROT_WRITE` 2; `PROT_EXEC`
is `-EINVAL`, so writable and executable never coexist). `SYS_MO_UNMAP` removes
the mapping and revokes the capability, giving back every reference the caller
held.

**Transferring.** A buffer travels to another task through an endpoint:

- **MOVE.** A `CAP_MODE_MOVE` entry (or a fast-call capability without
  `FAST_CALL_CAP_SHARE`) hands the sender's reference, its charge (when it
  holds the owning reference) and its ownership to the receiver and removes the
  sender's mapping. The receiver's Domain is charged first, all or nothing.
- **SHARE.** A `CAP_MODE_DUP` entry (or `FAST_CALL_CAP_SHARE`) needs `DUP` and
  `TRANSFER` on the sender's capability and derives an attenuated child. The
  receiver takes its own reference; its map is bounded by the rights it got and
  the sender keeps its handle and mapping.

**Invoke ops** on a `Cap<Shm>`: `MEMOBJ_ACQUIRE` takes a reference and reads
the geometry; `MEMOBJ_END_DROP` gives up a pipe end ([POSIX byte pipe](#posix-byte-pipe)).

A clone shares frames with its source through the frame reference count until
a write mapping or an explicit break gives the clone its own. A paged object
is a window of one file; its clean pages are droppable and its dirty pages are
written back before they go.

Source: `crates/core/ipc/src/memobj.rs`, `crates/core/abi/src/syscall_nr.rs`,
`crates/core/abi/src/invoke.rs`.

## Rings

`crates/core/rings` holds the one single-producer single-consumer index
protocol and the shapes built on it. The crate has no kernel dependency.

| Shape | What it is |
|---|---|
| `Queue<T, N, D>` | In-process SPSC ring, typed slot, compile-time capacity (a power of two). Every item is consumed exactly once. Full policy `Full::Backpressure` (the item comes back) or `Full::DropNewest` (dropped and counted, `Queue::dropped`). |
| `Log<T, N, D>` | One writer, sequence-numbered slots, overwrite-oldest, any number of readers each with a private cursor. A reader that falls behind gets `Next::Overrun(lost)` and jumps to the oldest retained item. `Log<T, 1>` is a latest-value cell: the writer never blocks and a reader retries while a store is in progress. |
| `region::SpscRing` | SPSC ring over a shared mapping, one `u64` per slot. |
| `region::SpscSlots<W>` | the same with `W` words per slot. |
| `region::SpscBytes` | fixed-size byte slots with a 16-byte `SlotInfo` header (`len` u32, `seq` u32, `acq_ns` u64) and a variable-length payload; produced by a `BytesProducer` that never blocks; the newest item is dropped when full. |
| `region::SpscStream` | byte ring: the indices count bytes, a producer publishes any number of bytes with one head store. |
| `region::trace` | the kernel tracer's per-CPU record rings, each record carrying its own sequence stamp. |

`Writer`, `Producer` and `Consumer` are handed out once per ring (a second
request returns `None`) and are neither `Clone` nor `Copy`: one writer is a
property of the type. A `Doorbell` is called after the head moves; a `Queue`
rings it only when its consumer announced that it may be asleep.

**Region layout.** A shared ring is a header at a 64-byte-aligned base, then
the slots; both sides compile the same module, so the layout is a contract.

| Offset | Word |
|---:|---|
| `RING_HEAD` 0 | producer index (free-running `u32`) |
| `RING_TAIL` 64 | consumer index (free-running `u32`) |
| `RING_CONS_WAIT` 128 | consumer-asleep flag |
| `RING_PROD_WAIT` 192 | producer-asleep flag |
| `RING_SLOTS` 256 | first slot |

Each word has a cache line to itself. Fill is `head - tail` (wrapping); the
capacity is a power of two no larger than 2^31. For byte-slot rings the head's
line also holds `RING_DROPS` (8), `RING_WAKES` (12), `RING_GEOM_CAP` (16) and
`RING_GEOM_SLOT_BYTES` (20).

**No kernel entry unless a side must sleep.** The index functions return what
the caller must do next: `RingStep::Done`, `DoneWake { addr }` (the other side
announced it may be asleep: issue `SYS_FUTEX_WAKE` on `addr`) or `Blocked`
(full for a push, empty for a pop); and `RingSleep::Retry` (the index moved
while announcing) or `Wait { addr, expected }` (`SYS_FUTEX_WAIT`). Lost
wakeups are closed twice: in ring 3 by a Dekker handshake (a sleeper stores its
flag, fences and re-reads the index; a waker stores the index, fences and reads
the flag), and in the kernel because the futex compares the index word with the
value the sleeper last saw under the same lock the wake takes.

**Trace region.** A header (`HDR_MAGIC` "KTR1", version, record size 32,
rings, entries, policy, timestamp source and rate, compiled classes, runtime
mask) followed by one ring per CPU (at most `TRACE_MAX_CPUS` = 64). Each ring
has a tail word the consumer writes, a drops word the producer writes, and
32-byte records `{ ts u64, seq u32, event u16, cpu u8, flags u8, args [u32; 4] }`.
A record is published by its own `seq`; there is no shared head or doorbell,
and the reader polls. Policy `POLICY_DROP` refuses the newest record when full;
`POLICY_OVERWRITE` never refuses and the reader counts records overwritten under
it as lost. The producer treats everything the reader can write as untrusted.

`azos_channel::Channel<T>` (`crates/core/channel`) is a `Log` of one slot plus a
timestamp, with a publisher that masks preemption around a store.

Source: `crates/core/rings/src/lib.rs`, `crates/core/rings/src/queue.rs`,
`crates/core/rings/src/log.rs`, `crates/core/rings/src/region/mod.rs`,
`crates/core/rings/src/region/bytes.rs`, `crates/core/rings/src/region/stream.rs`,
`crates/core/rings/src/region/trace.rs`, `crates/core/channel/src/lib.rs`.

## POSIX byte pipe

A pipe is an `SpscStream` byte ring in a `Cap<Shm>` region both ends map, a
header of end counts and sleep events, and the futex as the doorbell. Data moves
with no kernel entry unless a side has to sleep or the other side said it may be
asleep. `BytePipe::init` starts a pipe in a fresh region (capacity a power of
two of at least `PIPE_BUF`); `BytePipe::open` attaches to one; `read` and
`write` take a `Sys` (the futex wait, wake and process id) and a `nonblock` flag.

| Behaviour | Mechanism |
|---|---|
| EOF on the last writer's close | the region counts writer ends (`BytePipe::writers`); a read of an empty pipe with none left returns `Ok(0)` after one more look at the ring |
| `EPIPE` with no reader | a write with no reader end returns `PipeError::Broken`; a writer asleep on a full ring is woken by the last reader's close |
| `O_NONBLOCK` | an argument of each call (a property of the open file description, not of the region): `PipeError::WouldBlock` where a blocking call would sleep |
| atomic small writes | a write of at most `PIPE_BUF` (4096) bytes goes in whole or not at all, under the writer lock |
| interrupted sleep | `PipeError::Interrupted` on a stop request |

Header words (beyond the four ring words): magic `"BPIP"` at 4, capacity at 8,
writer count at 12, reader count at 16, read event at 20, write event at 24,
writer lock at 32, reader lock at 36. Several processes may hold one end, so
writers take a lock word around the part of a call that touches the head, and
readers one around the tail; a lock word holds the owner's process id above two
flag bits (locked, waiters).

The kernel keeps who holds which end, per holding process, and is the only
writer of the two count words: the creator starts with one of each, a spawn move
list and a fork hand ends over (`Header::add_end`), a process gives an end up
with `MEMOBJ_END_DROP` (`Header::drop_end`), and a process's death gives up what
it still holds and opens a lock word it died owning (`Header::recover_locks`).
Programs only load the counts. A reader sleeps on the event word, which the
futex compares, so a state that changes no ring index (the last writer leaving)
still wakes it.

Source: `crates/core/bytepipe/src/lib.rs`, `crates/core/rings/src/region/stream.rs`.

## Futex

`SYS_FUTEX_WAIT(addr, expected, timeout_ns)` blocks while the aligned 32-bit
word at `addr` holds `expected`, until a wake, the relative timeout (0 means
none) or a stop. `SYS_FUTEX_WAKE(addr, n)` wakes at most `n` waiters on the word
and returns how many.

| Result | Meaning |
|---|---|
| 0 | woken |
| `-EAGAIN` | the word differs from `expected` |
| `-ETIMEDOUT` (110) | the timeout expired |
| `-EINTR` | a stop request |
| `-EFAULT` | the word is not readable |
| `-EINVAL` | misaligned |

A word is keyed in the futex table (`crates/core/sched/src/futex_table.rs`) one
of two ways. `Key::Shared` is `(object id, offset)` for a word inside a mapped
`Cap<Shm>` region, so tasks that map the region at different addresses meet on
it (the two sides of a shared ring); no physical address is ever a key.
`Key::Private` is `(process id, address)` for any other word, so only the
threads of one process meet on it. The wait reads the word and files its row
under the table lock, and a wake takes the same lock, so a wake cannot be lost.
The io_ring's `OP_NOTIFY_WAIT` completes on a change of a shared word.

The native surface is these two calls. The Linux personality additionally
supports requeue and priority-inheritance futex operations over the same table.

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/sched/src/futex.rs`,
`crates/core/sched/src/futex_table.rs`, `crates/core/sync/src/pi_futex.rs`.

## Event ports

An event port multiplexes several sources into one wait. `DOMAIN_CREATE_PORT`
makes a `Cap<Port>`; `PORT_BIND` adds a source; `SYS_PORT_WAIT` or `PORT_POLL`
takes an event; `PORT_DESTROY` frees the port.

`PORT_BIND` words: `w0` the source type, or-ed with `PORT_BIND_F_REMOVE`
(`0x100`) to remove; `w1` the source's capability (for a timer, its deadline);
`w2` the event key. The port handle needs `WRITE`.

| Source | `PORT_SRC_*` | Bound with | Event type |
|---|---:|---|---|
| io_ring | 1 | a `Cap<IoRing>` with `READ` | `PORT_EVENT_RING` (2) |
| timer | 2 | an absolute deadline in ns; one-shot; binding a key already armed re-arms it | `PORT_EVENT_TIMER` (4) |
| endpoint notices | 3 | a `Cap<Endpoint>` with `READ`, held by the serving task; only with Kconfig `IPC_PORT_NOTICES` (a bind is `-EINVAL` otherwise) | `PORT_EVENT_NO_SENDERS` (5), `PORT_EVENT_SOURCE_GONE` (6) |
| memory pressure | 4 | `DOMAIN_SELF` (the caller's own Domain); one port per Domain, a second bind replaces the first; remove takes the port and key | `PORT_EVENT_PRESSURE` (7) |
| interrupt line | n/a | from the line's side: `DEVICE_IRQ_BIND` with the port handle | `PORT_EVENT_IRQ` (3) |

Events from rings are edge-triggered and coalesced: one event stands for at
least one completion since the last event, so the receiver drains the
completion queue after each. A timer is evaluated lazily by every poll and wait
against the caller's clock. Interrupt events queue on the port's bounded queue
(`PORT_MAX_SOURCES` deep; a delivery that finds it full is dropped and still
wakes). Queued events and table sources alternate when both are ready, so a
storm on one class does not starve the other. A port holds at most
`PORT_MAX_SOURCES` sources (Kconfig `MAX_PORT_SOURCES`, default 16). The
no-senders event is level at bind: binding an endpoint that has no sender
reports one at once. `PORT_EVENT_SOURCE_GONE` is delivered once when a bound
source is destroyed or its owner dies, and frees the source's slot.
The pressure source has no slot: the Domain keeps the port's reference, and the
reclaim task queues one event per change of the Domain's frame-budget level
(`source_id` 0 normal, 1 warning from the high watermark, 2 critical at the
limit) before it compresses any of the Domain's pages; a first warning gives the
program one poll to give memory back. It exists only with Kconfig
`MM_RECLAIM_COMPRESS` (a bind is `-EINVAL` otherwise).

**The 16-byte event:**

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | key, as bound |
| 8 | 1 | source type (`PORT_EVENT_*`) |
| 9 | 1 | CPU (`PORT_EVENT_CPU_OFFSET`): for `PORT_EVENT_IRQ`, the CPU the line is routed to; 0 for every other event |
| 10 | 2 | code (`PORT_EVENT_CODE_OFFSET`): a positive errno for a notice (`ENOSENDERS`, `EREVOKED`, `EPEERDIED`), 0 for an ordinary event |
| 12 | 4 | source id |

`SYS_PORT_WAIT(a0 = port handle with READ, a1 = 16-byte buffer, a2 = deadline)`
takes the deadline as absolute nanoseconds (`u64::MAX` none; an instant already
passed polls). It returns 16 with the event written, 0 when the deadline passed
with nothing ready, or a negative code: `-EINVAL` (null buffer), the handle's
`-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`, `-EFAULT` (checked before anything is
dequeued), `-ECAPSTALE` if the port is destroyed during the wait, `-EMFILE` when
the port has its maximum number of waiters, `-EBUSY` when the scheduler refused
to block. `PORT_POLL` is the non-blocking form (`-EAGAIN` when empty).

Every port carries a generation stamped at create from its slot, so a reference
to a destroyed port, or to its index after another port took it, answers stale
and touches nothing. A waiter registers with the port under the same hold as its
empty poll, so an event between the poll and the block is not lost.

Source: `crates/core/ipc/src/port.rs`, `crates/core/abi/src/syscall_nr.rs`,
`crates/core/abi/src/invoke.rs`, `crates/core/syscall/src/ipc_handlers.rs`.

## io_ring

An io_ring is a submission queue and a completion queue in one 4 KiB page the
kernel and one task share. `SYS_RING_SETUP(a0 = out_ptr)` allocates the ring,
mints a `Cap<IoRing>`, writes the ring page's user address to `*a0` and maps the
page read-write and never executable; `SYS_CAP_CLOSE` unmaps it. The task fills
submission entries, advances `sq_tail`, and calls `SYS_RING_ENTER(a0 = handle)`
(needs `WRITE`), which returns the number of entries processed.

**Page layout** (`azos_abi::io_ring`, asserted against the kernel's struct):

| Offset | Size | Field |
|---:|---:|---|
| `SQ_HEAD` 0 | 4 | kernel consumes from here |
| `SQ_TAIL` 4 | 4 | ring 3 produces to here |
| `SQ_ENTRIES` 8 | 32 x 32 | submission queue (`SQ_SIZE` = 32 entries) |
| `CQ_HEAD` 1032 | 4 | ring 3 consumes from here |
| `CQ_TAIL` 1036 | 4 | kernel produces to here |
| `CQ_ENTRIES` 1040 | 32 x 16 | completion queue (`CQ_SIZE` = 32 entries) |
| `DATA` 1552 | 2048 | shared data buffer (`DATA_SIZE`) |
| `SQ_FLAGS` 3600 | 4 | `SQ_F_SQPOLL` (1): a poller runs the ring; `SQ_F_NEED_WAKEUP` (2): the poller parked, publish `sq_tail` then kick |
| `VERSION` 3604 | 4 | `IO_RING_VERSION` (2), written at setup |

**Submission entry (32 bytes):** `opcode` u16 at 0, `flags` u16 at 2,
`param0` u32 at 4, `param1` u32 at 8, `param2` u32 at 12, `addr` u16 at 16,
`reg` u16 at 18, `user_data` u64 at 24. `param0` selects a bus, pin, sensor
type, channel or handle; `param1` is an offset into the data buffer for buffer
opcodes or a scalar for register opcodes; `param2` is a length; `addr` and `reg`
are an I2C device address and register. `SQE_F_LINK` (bit 0 of `flags`) links the
next entry: it runs only if this one completed in the same pass and succeeded,
otherwise it completes with `-ECANCELED` and `CQE_F_REFUSED` without running.
`SQE_F_FIXED` (bit 1) names a registered buffer instead of a data-buffer window:
`reg` is the buffer's slot, `param1` the offset inside it and `param2` the length
(see below); only `OP_NET_SEND`, `OP_NET_RECV`, `OP_FILE_READ` and `OP_FILE_WRITE`
take it, any other opcode refuses it with `-EINVAL`.

**Completion entry (16 bytes):** `user_data` u64 at 0 (copied from the
submission), `result` i32 at 8 (bytes, or a negative code), `flags` u32 at 12:

| Flag | Meaning |
|---|---|
| `CQE_F_REFUSED` (1) | the kernel refused the entry; `result` is `-Errno`. Clear when the operation ran: `result` is then the operation's own answer, so a refusal is never mistaken for one. |
| `CQE_F_QUEUED` (2) | accepted onto a queue (the write-back cache, a NIC transmit ring) or completed by the device without a flush behind it (a block write); not yet durable or on the wire. Set only with a positive result. |
| `CQE_F_DURABLE` (4) | an `OP_FSYNC` completed at a flush point. Set only with result 0. |

**Opcodes:**

| Opcode | Value | Meaning |
|---|---:|---|
| `OP_NOP` | 0 | completes with 0 |
| `OP_READ_SENSOR` | 1 | read a sensor into the data buffer |
| `OP_WRITE_GPIO` | 2 | write a GPIO pin |
| `OP_READ_GPIO` | 3 | read a GPIO pin |
| `OP_I2C_READ` | 4 | I2C read into the data buffer |
| `OP_I2C_WRITE` | 5 | I2C write from the data buffer (the register is the first payload byte) |
| `OP_PWM_SET` | 6 | set a PWM channel duty |
| `OP_MOTOR_SPEED` | 7 | set wheel speeds, through the actuation gate |
| `OP_NET_SEND` | 8 | queue a send on a socket handle (`WRITE`); completes `CQE_F_QUEUED` |
| `OP_NET_RECV` | 9 | receive from a socket handle (`READ`) without waiting: the byte count, `0` with nothing queued, `-1` for a socket that cannot receive, `-EEOF` once a stream has ended |
| `OP_BUF_REGISTER` | 10 | pin a range of a `MemObj` this task maps as registered buffer `reg`: `param0` a `Cap<Shm>` handle (`READ | WRITE | MAP`), `param1` the byte offset, `param2` the length |
| `OP_BUF_UNREGISTER` | 11 | give back the pin of registered buffer `reg` |
| `OP_FILE_READ` | 12 | `NODE_READ` on a file handle into a data buffer window; completes from the io_ring worker, never in the submit (Kconfig `IORING_ASYNC`) |
| `OP_FILE_WRITE` | 13 | `NODE_WRITE` on a file handle from a data buffer window; completes `CQE_F_QUEUED` from the io_ring worker |
| `OP_TIMER` | 16 | complete at an absolute deadline; 1 if already passed, otherwise parked and completes with 0 in the first pass at or after it |
| `OP_NOTIFY_WAIT` | 17 | complete when a futex word in a `Cap<Shm>` region changes (1 if it already differs) |
| `OP_SQPOLL_START` | 18 | start a kernel poller that consumes the queue without a syscall; allowed only when the owner's topology row declares `sqpoll_idle_ms`, else `-EPERM` |
| `OP_FSYNC` | 19 | make the writes queued before it durable; completes with `CQE_F_DURABLE` after the flush, never by waiting in the submit |
| `OP_BLOCK_READ` | 20 | read sectors of a partition into the data buffer; `param0` is the `block` endpoint's badge (partition `n` is `n + 1`), `param2` a multiple of 512. Queued on the block request layer and parked; the bytes land in the window when the completion is posted |
| `OP_BLOCK_WRITE` | 21 | write sectors of a partition from the data buffer (copied at the submit). Queued and parked; completes `CQE_F_QUEUED` (completed by the device with no flush behind it, not yet durable) |

**Registered buffers.** The data buffer of the ring page is 2 KiB, and every
entry that moves bytes through a user pointer pays to validate that range and
to bounce through a kernel buffer. `OP_BUF_REGISTER` does that once: the kernel
takes a reference on a `MemObj` the task already maps (it does not take an
object table slot, `MAX_MEMOBJS` is not touched), checks the range lies in one
physically contiguous run of the object's frames and that no clone shares one,
and keeps the direct-map address under a slot (`IORING_MAX_REGBUFS` per ring).
An entry with `SQE_F_FIXED` then names slot, offset and length, and the kernel
reads or fills the frames in place; the owner reads the same bytes through its
own mapping. Every use of a slot is refused `-EBUSY` once its owner no longer
maps the object (released, or moved to another task, whose memory the frames
now are), and a receive or a file read into a buffer also once a clone has come
to share a frame of the object. The pin is given back by
`OP_BUF_UNREGISTER`, the ring's destruction or its owner's exit. Registration
is gated, like any entry, by the owner's seccomp profile (it stands for
`MEMOBJ_ACQUIRE`) and its Domain's pledge mask. The block opcodes do not take
the flag (their `reg` is half of a sector number).

**Authorization.** Each entry is checked, in order, against the ring owner's
seccomp profile for the call the opcode stands for, the owner's Domain pledge
mask for the same call, the capability the owner must hold, and, for a write,
containment; it then runs through the same function its typed call runs. A
refused entry completes with `CQE_F_REFUSED` and one of, in the order checked:
`-ENOSYS` (an opcode this kernel does not execute), `-EPERM` (seccomp),
`-EACCES` (the pledge mask), `-EINVAL` (an argument rejected before the
capability check reads it), `-ECAPPERMS` (a capability the owner does not hold),
`-EAGAIN` (a write refused by containment, or a motor command refused by the
halt rule), or the typed call's own code. At most `RING_SQ_SIZE` entries run per
submit, and never one whose completion the CQ has no room for: `SYS_RING_ENTER`
returns `-EBUSY` when an entry is pending and the CQ is full, with nothing run
and `sq_head` still naming that entry. Without a poller a pass is a submit; a
parked timer completes on the owner's next `SYS_RING_ENTER`. The number of rings
is bounded by Kconfig `MAX_IO_RINGS`.

**Data entries are queued (Kconfig `IORING_ASYNC`, default on).** A submit does
no file system or device work. A block entry becomes a request of the block
request layer (`crates/drivers/block/src/queue.rs`) and parks on the ring like a
timer or an fsync, counting against `IORING_MAX_PARKED`; a file entry is run, in
SQ order, by the io_ring worker (`ioring-wk`). The worker starts the queued
requests, sleeps for the oldest, and posts the completion through the CQ and the
ring's port, so a completion does not wait for the owner's next
`SYS_RING_ENTER`. The kernel owns the request's buffer: a write's bytes are
copied out of the data window at the submit and a read's are copied in when the
completion is posted, so the device never sees the shared page and a ring
destroyed with requests in flight leaves them to the worker. A block entry the
request layer cannot take (a board whose disk is not behind it, a full queue, a
run longer than one device command, no free parked slot) runs on the synchronous
path in a task that may block, and on the worker's otherwise. A network send is
unchanged: it already queues on the socket and the NIC and never waits.

An io_ring can be bound to an event port (`PORT_SRC_RING`) so that a completion
wakes a waiter.

Source: `crates/core/abi/src/io_ring.rs`, `crates/core/ipc/src/io_ring.rs`,
`crates/core/syscall/src/ioring_ops.rs`, `crates/core/syscall/src/ipc_handlers.rs`.
