# The capability model

Every resource a ring-3 program can touch is reached through a **capability**:
an unforgeable reference, held in a table the kernel keeps for the program's
domain, that names an object and the rights the holder has over it. A program
that holds no capability for something cannot name it, and a program that
holds one can do no more with it than its rights allow. This note describes
the model as the kernel implements it: what a handle is, how the kernel checks
one, where capabilities come from, how they move, and how they are withdrawn.

Source: `crates/core/abi/src/cap.rs`, `crates/core/ipc/src/cap.rs`,
`crates/core/ipc/src/cap_store.rs`.

## 1. Motivation

Under ambient authority any task that may issue a syscall can aim it at any
resource whose handle it can guess or learn. A bug in one task then reaches
every resource the syscall layer allows, not only that task's own: a faulty
planner can stop motors that belong to someone else, a compromised update
receiver can write to another task's pipe, and a compromised driver reaches all
the hardware the syscall layer permits. Capabilities replace that with a
mechanical rule: **no capability, no access**. Authority is held in objects,
not in syscall numbers or task identities.

Three consequences shape the rest of the design.

- **Isolation of untrusted components.** A loaded model, a driver or a shell
  receives explicit capabilities to specific objects and can reach nothing
  else through the kernel. A device that masters the bus is outside this: its
  DMA is not confined by capabilities (see "DMA" in
  [security.md](../security.md)).
- **The set a task can reach is readable.** If capabilities come only from a
  few well-defined places (section 5), "which tasks can reach this resource"
  is answered by reading those places, not by replaying every transfer that
  ever happened.
- **Checking is cheap enough to be on every use.** A check is an indexed load
  and a few compares (section 4), so there is no fast path that skips it.

Source: `crates/core/ipc/src/cap.rs`, `crates/core/ipc/src/cap_seed.rs`.

## 2. Handles, kinds and rights

Across the syscall boundary a capability is a 32-bit **handle**. Zero is the
null handle and never valid. The fields tile the word exactly (a compile-time
assertion checks the sum):

```text
  bits 31..26  type         6 bits: kind (4) + class (2)
  bits 25..20  rights       6 bits: READ WRITE EXEC DUP TRANSFER MAP
  bits 19..9   generation   11 bits
  bits  8..0   slot         9 bits: up to 512 slots
```

The handle carries the rights as well as the table does, because some paths
rebuild a slot from the handle alone and a handle that dropped a right would
hand the new holder less than the old one held. A handle is not stored on disk
or put on any wire except a syscall argument register: a topology names kinds
as text and the kernel mints a fresh handle at admission.

**Kinds.** A kind is a generic object, not a device. Hardware and services are
not kinds: a pin, a wheel, a sensor or a partition is the *badge* of an
endpoint capability, and its rights are the operation classes of the interface
behind it.

| Kind | What it is | Classes (`ty::*`) |
|---|---|---|
| `Endpoint` | The right to send a request to a service (task-hosted, or an interface the kernel hosts). | one |
| `MemObj` | A memory object: shared memory a task maps. | `SHM` |
| `Queue` | A queue of requests: an io_ring. | `IORING` |
| `Port` | An event port. | one |
| `Domain` | The right to see every task (a view, not authority over one). | `TASK` |
| `Node` | A node of the name space. | `FILE` (descriptor or directory tree), `LAUNCH` (start one image), `SOCKET` |
| `Device` | A piece of hardware. | `IRQ`, `MMIO`, `DRIVER_REGISTRY` |
| `Log` | A log. | `TRACE`, `CONSOLE` |

An unknown kind or class is not a type; unpacking a corrupt or future handle
fails closed rather than aliasing a real one.

**Rights.** `READ`, `WRITE`, `EXEC` and `MAP` say what the holder may do to the
object. Two more control what the holder may do with the *capability*:

- `DUP` permits a copy: deriving an attenuated child, minting a badged one or
  sending a DUP entry.
- `TRANSFER` permits giving the capability to another domain, as a MOVE entry
  of a message or a spawn's move list, or sending a copy there (a copy also
  needs `DUP`).

They are separate on purpose. A holder may derive for itself without being able
to give authority away, and a capability meant to travel need not be copyable.
`DELEGATE` is the pair; it is what a task gets over an object it created
itself, and what a topology grant with `transfer = true` carries.

**Typed form inside the kernel.** The kernel wraps a handle as `Cap<T>`, a
`repr(transparent)` newtype with a zero-sized marker `T` (`Shm`, `Port`, `File`,
`Socket`, `Endpoint`, `Launch`, `Trace`, `Console`, ...). Two kinds cannot be
interchanged without a compile error. Ring 3 holds only raw handles; there the
same check happens at run time against the type bits.

Source: `crates/core/abi/src/cap.rs` (`CapHandle`, `CapKind`, `CapType`, `ty`,
`CapPerms`, `slot_word`), `crates/core/ipc/src/cap.rs` (`Cap`, `targets`).

## 3. The table

Each protection domain (a process and its threads) owns one capability table,
`CapTable`. The kernel keeps a dense array of them indexed by domain slot, not by
task id: task ids are monotone and an index by task id would run out of space,
whereas domain slots are bounded by the task pool. A table that finds its
recorded owner differs from the domain being looked up wipes itself first, so a
new domain never inherits a previous one's capabilities.

A slot is a **hot word** (64 bits: the type, the rights, a 16-bit generation
field and a 32-bit resource), an **extension word** (with `CAP_SLOT_EXT`; it
holds the badge), and a **warrant** record (section 6). A reader that takes no
lock loads the hot word once and checks one version of the slot. Two flags sit above the six rights in the hot word: one
marks a warrant that carries a deadline, one marks a weak warrant (section 6).
The number of slots is a build option per profile (`MAX_CAPS_PER_TASK`: 32 on
embedded, 256 on edge, 512 on fleet).

**Generations never wrap.** A slot's generation survives a revoke, so a
re-grant gets a fresh one and the previous holder's handle is detectably stale.
Because a wrapped counter would reissue a generation a previous holder still
has, a slot whose generation reaches `MAX_GENERATION` is *retired* and never
granted again. The 11-bit field keeps that budget finite per slot; retired
slots are counted so exhaustion is observable.

**Object generation.** The slot generation answers "is this still the
capability that was granted". For kinds whose objects live in a pool (ports,
shared memory, io_rings, endpoints), the resource word also packs the object's
own generation, so a capability cannot be satisfied by a different object that
reuses the same pool index.

Source: `crates/core/ipc/src/cap_store.rs` (module documentation),
`crates/core/ipc/src/cap.rs` (`CapTable`, `CapSlot`, `objref`),
`config/limits/Kconfig.limits` (`MAX_CAPS_PER_TASK`, `CAP_SLOT_EXT`).

## 4. Dereferencing a handle

Every use goes through one resolve. In order:

1. The handle is not null.
2. The slot index is in range. With Kconfig `MITIGATION_SPECTRE_V1_INDEX`
   (default `y`) it is masked, so a mispredicted check cannot read another
   task's table.
3. The slot is occupied.
4. The handle's generation equals the slot's.
5. The handle's type equals the type the operation expects.
6. The slot's rights contain the right the operation needs. A weak slot is read
   with only `READ` and `MAP`, whatever bits are stored.
7. If a revocation is in flight anywhere, the chain of parents is walked and a
   capability whose ancestor was revoked is refused (section 6).
8. **Containment** (section 7) may refuse a `WRITE`.
9. The warrant's caveats are evaluated: a deadline, a use count, an operation
   mask, a receipt requirement. A use that took a count is one every earlier
   check passed.

The refusals are kept apart on purpose, because they mean different things: `Stale` is a handle to something gone or reused (the forgery shape);
`WrongKind` is a real handle of another family (the confusion shape);
`MissingPerms` is the right object with insufficient rights (the escalation
shape); `Revoked` is a handle that was real and whose warrant ended. They map to
`ECAPSTALE` (stale or revoked), `ECAPKIND` and `ECAPPERMS`; a full receiving
table is `EMFILE`; a contained write is `EAGAIN`. The four that are denials
are written to the flight recorder with the kind and a reason code; containment
is not recorded as a denial, because it would bury the real ones during a
containment episode.

The cost is one indirect load and a few compares; with no revocation in flight
the extra work is two relaxed loads.

Source: `crates/core/ipc/src/cap.rs` (`CapTable::resolve`, `get`,
`get_uncontained`, `get_op`, `CapError`), `crates/core/syscall/src/invoke.rs`
(`errno_cap`), `crates/core/abi/src/error.rs`.

## 5. Where capabilities come from, and how they move

Authority enters the system in three ways and moves in a few more.

**Entering.**

1. **Boot and spawn seeding from the topology** (the signed one, or the
   built-in one where Kconfig `TOPOLOGY_SOURCE` lets the boot fall back to
   it). A topology row lists
   capabilities as (kind, target, permission) triples; the target's syntax is
   per kind (`endpoint.<name>`, `/fat`, `TOOLBOX.ELF`, `irq.<N>`, `tasks`, ...).
   `cap_seed` mints them for a task that is admitted but has not yet run, either
   at boot or in `SYS_SPAWN_EX` for a child. A row grants nothing it does not
   name, and a topology can name only kinds that have a minter.
2. **Self-mint on creation.** A call that creates an object mints a capability
   over it into the *calling domain's own table*, never another's: creating a
   port, an endpoint, a memory object, an io_ring, a socket, or opening a file
   beneath a directory the caller holds. The object is owned by the caller and
   the capability goes to the caller. The console capability is seeded into
   every task at admission.
3. **Kernel-hosted endpoints.** The kernel stamps the badge of a capability to an
   interface it hosts (an interface name plus a resource such as `gpio.20`), so a
   service can tell callers apart by the badge the kernel wrote, not one the
   caller supplied.

**Moving.** No call that transfers a capability takes a *recipient task id*. A capability reaches another
domain only through a path where the receiver takes part or has not yet run:

- **MOVE.** A message entry or a spawn move-list entry. The sender needs
  `TRANSFER`; the sender's handle goes stale. A move out of a slot something
  was derived from takes the copies along, under the capability's new slot.
  All entries of a message move or none do.
- **DUP (share).** The receiver gets a copy with rights possibly lowered and a
  deadline possibly shorter, and the sender keeps its own. The sender needs
  `DUP` and `TRANSFER`. The copy is a child of the source in the warrant tree.
- **Derive.** `SYS_CAP_DERIVE` mints a narrowed, badged, dated copy of an
  endpoint capability into the caller's own table; it needs `DUP`. The
  `ENDPOINT_DERIVE` op adds up to four caveats.
- **Lend by name.** A task that imports a name asks the name server, which
  derives a call-only, dated copy of an endpoint capability its own row holds
  and returns it in a reply. A name is never authority; the row lists what it
  may ask for.
- **Fork.** The foreign-ABI fork (`SYS_FOREIGN_FORK`, for a ring-3 runtime that
  hosts a foreign program's `fork`) gives the child the caller's descriptors and
  pipe regions at the same handles, and the capabilities of its *own* topology
  row, never a copy of the caller's table. A native program has no fork; its
  creation call is `SYS_SPAWN_EX`.

In every transfer rights can only be lowered, never raised, and deadlines only
shortened: no transfer gives the receiver more than the sender held.

**Why the recipient is never named.** If task A could hand a capability to any
task B it names, the holder and the origin of a capability would diverge, and
nothing would record the handoff except whatever bookkeeping that call chose to
keep. The set of tasks that can reach an object would stop being readable from
the mint sites. Here, a transfer is something the *receiving* side participates
in (it accepted a message, or it is a child the sender is creating), a right
(`TRANSFER`) that a topology must have granted gates it, and the warrant tree
records the lineage (section 6).

**A mint without a quota is an exhaustion bug.** Self-mint draws on shared,
finite pools. Each pool has a per-task ceiling so one task cannot starve the
rest, including the task that would carry an emergency stop: ports, memory
objects and io_rings are limited to half their pool per task
(`MAX_PORTS_PER_TASK`, `MAX_MEMOBJS_PER_TASK`, `MAX_IO_RINGS_PER_TASK`); file
descriptors and sockets likewise (`MAX_FDS_PER_TASK`, `MAX_SOCKETS_PER_TASK`);
endpoints have `IPC_ENDPOINTS_PER_TASK`. If the cap table is full the object
just created is released again and the call returns `-EMFILE`, so a refused
grant never leaves an object nothing names.

**A capability keeps naming what it was minted for.** Because a resource number
can be reused, a close that bypassed the capability would free the number while
the capability still held it. Untyped paths therefore refuse to close a
descriptor a capability names, and the one close call (`SYS_CAP_CLOSE`)
revokes under the table lock before it releases, so closing the same handle
twice is refused as stale.

Source: `crates/core/ipc/src/cap_seed.rs`, `crates/core/ipc/src/cap_store.rs`
(`grant`, `move_cap`, `move_caps`, `mint_badged`, `revoke_derived`),
`crates/core/abi/src/ipc_msg.rs` (`CAP_MODE_MOVE`, `CAP_MODE_DUP`, `MSG_KEEP`),
`crates/core/abi/src/syscall_nr.rs` (`SYS_CAP_DERIVE`, `SYS_CAP_REVOKE`,
`SYS_CAP_CLOSE`), `crates/core/abi/src/invoke.rs` (`ENDPOINT_DERIVE`),
`crates/core/syscall/src/caps.rs`, `crates/core/ipc/src/memobj.rs`,
`crates/core/ipc/src/port.rs`, `crates/core/ipc/src/io_ring.rs`,
`crates/core/ipc/src/endpoint.rs`, `userspace/lib/names/src/lib.rs`.

## 6. Warrants: derivation, attenuation and revocation

Every slot records the slot it was derived from. Together the slots form a
**warrant tree** that spans domains.

- A warrant carries a parent reference, a depth (at most `WARRANT_DEPTH_MAX`:
  8, or 4 on embedded), an optional deadline, an optional quota, a weak flag and
  up to four **caveats**.
- Caveats are conditions on a use, in the style of macaroons. The kernel
  evaluates `EXPIRY` (a monotonic deadline), `QUOTA` (uses left), `OP_MASK` (the
  operation classes the capability may be invoked with), `RECEIPT` (a device
  must have left a receipt of a given kind within an age) and `DECLASSIFY` (a
  one-shot permission for a human to lower a message's provenance label). `NODE`
  is reserved. Every derive copies the source's caveats and may only add; a copy
  is never less restricted than its source. `DECLASSIFY` is the one caveat that
  grants rather than restricts, so only a task whose principal is a user may
  ask for it, and it travels by MOVE, is spent on use and cannot be copied.
- A **weak** warrant, and everything derived from it, resolves as `READ` and
  `MAP` only, and has neither `DUP` nor `TRANSFER` to give. A shadow task's
  whole table can be marked weak so every slot granted into it is (Kconfig
  `CAP_WEAK`, default `y`; with it `n` a shadow row is seeded with nothing).
- **Deleting a capability is not revoking it** (owner decision 20-10, seL4's
  rule). A close or an exit frees the task's own slots; copies made from them
  stay alive in their holders' tables and keep their mappings, hung under the
  freed slot's parent.
- **Revoking a capability revokes everything derived from it**, in this domain
  and in any domain the copies were lent or moved to. A sweep finds the
  descendants (a slot only knows its parent, so it scans; the chain is bounded
  by the depth limit) and tells each holder through a notice delivered as the
  `Revoked` answer to the next failed use of the dead handle. `SYS_CAP_REVOKE`
  revokes what was derived from a handle and keeps the handle itself, returning
  a replacement; a server uses it to withdraw what it lent. A delete of a slot
  with copies owes the sweep too, to hang them under their new parent.
- **Use is checked before cleanup.** A capability derived from a revoked one is
  refused on its next use even if the sweep has not freed it yet. While a
  revocation is in flight the resolve walks the parent chain of the slot it is
  about to trust; with none in flight it pays two loads.

Source: `crates/core/ipc/src/cap.rs` (`Warrant`, `caveat`, `derive_warrant`,
`narrow_warrant`, `WARRANT_DEPTH_MAX`), `crates/core/ipc/src/cap_store.rs`
(`sweep`, `revoke_derived`, `warrant_step`), `crates/core/abi/src/cap.rs`
(`slot_word::WEAK`), `config/limits/Kconfig.limits` (`WARRANT_DEPTH_MAX`).

## 7. Containment

A supervisory source can put the system in a graded **degraded mode**. The
level is one of four: full, cautious, slow, contained. Only the contained level
touches capabilities: while it is armed, a `WRITE` resolved through the
containing path (`CapTable::get`) is refused with `Contained`, and a `READ`
stays live. The other levels do not deny anything at the capability layer; they
only clamp motion at the motor envelope.

Three properties make it safe to rely on:

- **Constrain-only.** The level can deny or slow, never grant, so a wrong or
  hostile controller can at worst over-contain.
- **Sticky.** It stays until a new level arrives; fail-closed on a lost link is
  provided by a separate motor watchdog, not by a timeout here.
- **After the forgery checks.** Containment is applied after the type, generation
  and rights checks, so a stale or wrong-kind handle still fails first, and
  before a caveat takes a count, so a contained use does not spend a quota.

Operations that must still work during containment resolve through
`get_uncontained`, which runs the same checks without the containment step:
releasing an object the caller holds (destroying a port or an io_ring,
unregistering a driver), which still needs `WRITE`. Wheels have a rule of their
own in the motor layer, which binds the kernel's control loop as well as ring 3:
while an emergency stop is latched or containment is armed, brake and coast are
written as asked and a forward or backward command is refused (`-EAGAIN` to
ring 3).

Source: `crates/core/ipc/src/cap.rs` (`degrade_level`, `degraded_active`,
`CapTable::get`, `get_uncontained`), `crates/domains/robot/robot/src/motor.rs`
(`set_motor_halt`), `kernel/src/tasks/behavior.rs`.

## 8. The second layer: image confinement

A capability decides *which object and which right*. A separate filter decides
*which calls an image may issue at all*. Each shipped ring-3 image has a profile
bound to the SHA-256 of its bytes: a bitmap of syscall numbers, the `SYS_INVOKE`
operation classes it may use per kind, and the kernel-hosted interfaces it may
call. A call outside the profile ends the task with exit code 159; a capability
refusal returns an error and is recorded. Both must allow a use. A profile also
withholds a topology grant of an endpoint the image does not list, and a
filter, once installed, cannot be removed. The one call that replaces it is a
Linux `execve`, which installs the executed image's own row (a Linux row); a
row other than the caller's needs a `LAUNCH` grant for the image and may be
wider than the caller's (`crates/core/syscall/src/linux.rs`, `sys_execve`).

Source: `crates/core/sched/src/seccomp.rs` (`ImageProfile`, `IMAGE_PROFILES`),
`crates/core/syscall/src/handlers.rs` (`SECCOMP_KILL_EXIT_CODE`),
`tests/host/seccomp-tests`.

## 9. The syscall surface

The native ABI is thirty-three calls, numbered 1 to 33 (the table's length,
`SYS_NR_RESERVED_UPPER`, is 34). Nothing else is a syscall. Every operation on an
object the caller holds a handle to is an *op* of `SYS_INVOKE`, selected by the
handle's type and an op word and gated by an operation class. An op number
encodes the kind it acts on, its class and its index, so reading an op in a
source file says which kind it needs and which class a profile must list.

| Family | Calls |
|---|---|
| handles | `SYS_CAP_INFO`, `SYS_CAP_CLOSE`, `SYS_CAP_DERIVE`, `SYS_CAP_REVOKE` |
| domain | `SYS_SPAWN_EX`, `SYS_THREAD_CREATE`, `SYS_THREAD_EXIT`, `SYS_EXIT`, `SYS_ALERT`, `SYS_GETPID` |
| time and scheduling | `SYS_YIELD`, `SYS_SLEEP_UNTIL`, `SYS_SCHEDCTL` |
| memory | `SYS_MO_CREATE`, `SYS_MO_MAP`, `SYS_MO_UNMAP` |
| IPC | the fast call, reply, accept and reply-accept; the v2 call, accept, reply and reply-delegate; `SYS_RING_SETUP`, `SYS_RING_ENTER`, `SYS_PORT_WAIT` |
| futex | `SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE` |
| foreign ABI | `SYS_FOREIGN_ENTRY`, `SYS_FOREIGN_RESUME`, `SYS_FOREIGN_FORK` |
| generic | `SYS_INVOKE` |

A call is a syscall only if ring 3 cannot do it: changing authority or
protection (the handle table, the page tables, a protection domain are kernel
state), or blocking and waking. `SYS_CAP_INFO` reads what the caller holds;
naming a capability is not using one, so it needs no right and containment does
not apply. `CAP_TYPED_SYSCALLS` lists the calls that take or mint a handle, so a
policy can tell them from the rest: some consume a handle and are therefore
narrower than a call that names its object, and two (`SYS_MO_CREATE`,
`SYS_RING_SETUP`) mint one and are in the set so a sandbox rule cannot grant
the power to create authority by accident.

Source: `crates/core/abi/src/syscall_nr.rs`, `crates/core/abi/src/invoke.rs`,
`crates/core/syscall/src/invoke.rs`.

## 10. Services on other nodes

A capability does not leave its machine. A service on another node is reached
through a *proxy endpoint* served by the RPC server: the caller calls it like a
local endpoint, with the same interface and message layout. The exporting node
runs the call against the real endpoint through a per-session capability derived
from its own, attenuated to the call right, badged with the session and
expiring. Each call carries a token whose caveats the receiving node verifies
and re-mints as local caveats on the derived warrant, so the remote side's
limits become the local kernel's checks.

Source: `userspace/lib/rpc/src/lib.rs`, `userspace/services/rpcsrv`,
`crates/core/abi/src/invoke.rs` (`ENDPOINT_DERIVE`).

## 11. Rationale and alternatives

- **Ambient authority with integer handles (the POSIX shape).** Any task that
  can name a number can use it, so the argument that two components cannot
  interfere has no mechanical basis.
- **Process-level flags such as Linux capabilities.** They are coarse
  ("may administer the network") rather than object-level ("may call this
  endpoint with these rights"), and do not isolate per resource.
- **A full seL4-style model.** Every kernel object, including frames, page
  tables and untyped memory, is a capability, and the verification programme
  is long. This design adopts the philosophy at a different point on the cost
  curve: a small set of generic kinds, rights bits, a warrant tree and a Rust
  type system for the kernel's own checks.
- **This design.** Typed capabilities in a per-domain table seeded from a
  signed topology, with attenuation and revocation through a warrant tree,
  and the run-time check described in section 4.

Source: `crates/core/ipc/src/cap.rs`, `crates/core/topology/src/builder.rs`.

## 12. Prior art

- **seL4** (Klein et al., SOSP 2009). The reference for verified
  capabilities and derivation trees; the revoke-the-subtree rule here follows
  its capability derivation tree in spirit.
- **Hubris** (Oxide). Static topology and typed message handles with per-task
  isolation; the closest in shape for a small system image.
- **Genode.** A capability-based component system with an RPC layer over
  capabilities.
- **EROS and KeyKOS.** Early capability systems; foundational on capability
  semantics and on revocation.
- **Macaroons** (Birgisson et al., NDSS 2014). Contextual caveats that only
  attenuate; the caveat list on a warrant follows that idea.

Source: the publications and systems named above; no repository path.

## 13. Limitations

- **Compile-time kind safety is kernel-internal.** Ring 3 checks types at run
  time through the handle's type bits.
- **Generation budget is finite.** A slot is retired when its generation
  reaches `MAX_GENERATION`; a task that opens and closes capabilities in a loop
  retires its low slots, and nothing is reused.
- **`OP_MASK` is evaluated only by paths that carry an op.** The syscall layer
  names one at every resolve (a typed handler its op, a numbered syscall the
  class-only op of its class). A path that resolves with `get` and no op, as
  the IPC fast paths in `azos_ipc` do, refuses a capability that has an
  op mask and leaves a receipt: fail closed. The exception is a call to an
  endpoint the kernel hosts, whose op is in the request: the resolve passes the
  mask (`get_hosted_uncontained`) and `khost::admit` holds the call to it, as
  IDL op bits, before the interface runs.
- **The `NODE` caveat is reserved.** A capability carrying one is carried and
  derived faithfully but resolves nothing.
- **No persistence.** Capabilities are not stored across reboots; a topology
  mints them again at admission.
- **Per-profile limits.** The slot count, the warrant depth and the per-task
  pool shares are build options; a deployment sizes them.

Source: `crates/core/ipc/src/cap.rs` (`CapKind`, `CAVEATS_MAX` and `caveat`),
`crates/core/abi/src/cap.rs` (`MAX_GENERATION`), `config/limits/Kconfig.limits`.
