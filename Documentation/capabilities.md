# Capabilities

Authority in AzOS is held as capabilities. A task never names an object by a
global identifier and never acts because of who it is; it acts through a handle
in its Domain's capability table, and the kernel checks that handle on every
use. This page describes the handle, the kinds and rights it carries, and the
warrant tree that records where every capability came from and lets the kernel
revoke it. For the use of capabilities to gate physical effects, see
[effects.md](effects.md).

## Handles and slots

A capability crosses the syscall boundary as a `u32` handle. The kernel keeps
the capability itself in a per-Domain table of slots.

| Bits    | Field       | Width | Meaning                                              |
|---------|-------------|-------|------------------------------------------------------|
| 31..26  | type        | 6     | `CapType`: kind in the low 4 bits, class in the high 2 |
| 25..20  | rights      | 6     | `CapPerms` bits                                      |
| 19..9   | generation  | 11    | monotonic per slot                                   |
| 8..0    | slot        | 9     | index in the task's table, 0 to 511                  |

The four fields above tile the word exactly. The source also carries a fifth,
zero-width field, `CapHandle::RESERVED_BITS` (currently 0), and a compile-time
assertion fails if the five widths do not total 32 bits. Another assertion
fails if `MAX_CAPS_PER_TASK` outgrows the slot field. Handle `0` is `CAP_NULL` and is never valid. No handle is stored on
disk or sent over a wire other than a syscall argument.

Source: `crates/core/abi/src/cap.rs` (`CapHandle`, `CAP_NULL`).

### The slot word

Inside the table each slot is two 64-bit words. The first is the word every
check reads (`slot_word` in `crates/core/abi/src/cap.rs`).

| Bits    | Field       | Meaning                                                       |
|---------|-------------|---------------------------------------------------------------|
| 0..8    | type        | `CapType` raw value; 0 means the slot is free                 |
| 8..14   | rights      | `CapPerms` bits as granted                                    |
| 14      | `EXPIRES`   | the slot's warrant has a deadline or at least one caveat      |
| 15      | `WEAK`      | the slot's warrant is weak (see [Weak warrants](#weak-warrants)) |
| 16..32  | generation  | survives a revoke, never wraps                                |
| 32..64  | resource    | the type's own id, or a packed pool index and object generation |

The second word (`CapExt`, with Kconfig `CAP_SLOT_EXT`) holds the badge a
server sees on a call made through an endpoint capability, and eight reserved
bits (`rights_hi`) that nothing reads. With `CAP_SLOT_EXT` off, slots are one
word, every capability is unbadged and minting a badged copy is refused.

For Port, Shm and IoRing capabilities the resource word packs the object's
pool index with the object's own generation (`objref` in
`crates/core/ipc/src/objref.rs`), so a handle also goes stale when the object
it named is freed and its pool slot reused. For every other type the resource
is the bare id.

Source: `crates/core/abi/src/cap.rs` (`slot_word`, `CapHandle`),
`crates/core/ipc/src/cap.rs` (`CapSlot`, `CapExt`, `CapTable`),
`crates/core/ipc/src/objref.rs`, `config/limits/Kconfig.limits`.

### Generations

A slot's generation is never reused. A freed slot keeps its generation; the next
grant of the slot increments it, so a handle held from an earlier grant no
longer matches. The counter does not wrap: when a slot reaches
`CapHandle::MAX_GENERATION` (2,047 with the 11-bit field) it is retired and
`CapTable::grant_raw` never allocates it again. A task that retires every slot
gets `None` from its own grants and affects no other task;
`CapTable::retired` counts retired slots. Generation `0` never appears on a
granted slot.

Tables are indexed by Domain slot, not by task id. The table records which
Domain key (slot plus generation) owns it, and every accessor wipes a table it
finds owned by a different key, so a new Domain cannot inherit the previous
one's capabilities. A table is also wiped when its Domain's last member exits.

Source: `crates/core/ipc/src/cap.rs` (`CapSlot::generation`,
`CapTable::grant_warranted`, `CapTable::retired`),
`crates/core/ipc/src/cap_store.rs`.

### Resolving a handle

`CapTable::get` (and its variants) resolve a typed handle and a required set of
rights. The checks run in this order and the first failure is returned:

1. The handle is not `CAP_NULL`, and its slot index is inside the table. The
   index is masked so a mispredicted bounds check cannot read another task's
   table (`azos_limits::nospec`).
2. The slot is occupied and its generation equals the handle's.
3. The slot's type equals the type the caller asked for.
4. The slot's rights, after the weak mask, contain every required right.
5. If a revocation is in flight, no ancestor of the slot has been revoked
   (see [Lazy revocation](#lazy-revocation)).
6. If the required rights include `WRITE` and the system is in the contained
   degrade level, the use is refused. `get_uncontained` skips this step; it is
   used for releasing an object a task holds and for commanding a wheel.
7. If the `EXPIRES` flag is set, the warrant's deadline and every caveat hold
   (see [Caveats](#caveats)).

`get_op` is `get` for a use that names the operation it performs, which is what
discharges an `OP_MASK` caveat. Every resolve of the syscall layer is a
`get_op`: a typed handler passes the op it is, a numbered syscall the class-only
op of its class (`azos_syscall::invoke::class_op`).  `get` is what is left for
a resolve that has no op; it refuses a capability that carries an op mask.

| `CapError`    | Raised when                                              | `errno_cap` result |
|---------------|----------------------------------------------------------|--------------------|
| `Stale`       | null handle, free slot, or generation mismatch           | `ECAPSTALE`        |
| `Revoked`     | warrant expired, quota spent, or an ancestor was revoked | `ECAPSTALE`        |
| `WrongKind`   | the slot holds another type                              | `ECAPKIND`         |
| `MissingPerms`| rights or caveats do not allow the use                   | `ECAPPERMS`        |
| `Contained`   | contained degrade level and the use needs `WRITE`        | `E_CONTAINED`      |
| `NoSpace`     | the receiving table, caveat pool or chain depth is full  | `EMFILE`           |

`CapError::code` gives each a stable number for the flight recorder. Every
error except `Contained` is a capability denial; `Contained` is the safety
system working and is not recorded as one.

Source: `crates/core/ipc/src/cap.rs` (`CapTable::resolve`, `get`,
`get_uncontained`, `get_op`, `CapError`), `crates/core/syscall/src/invoke.rs`
(`errno_cap`).

## Kinds and classes

A capability's type is a kind and a class within it. Hardware and services are
not kinds: a pin, a wheel, a sensor or a partition is the badge of an
`Endpoint` capability, and its rights are the op classes of the interface behind
it (`azos_devif`).

| `CapKind` | Value | Type constants (class)                                                                 |
|-----------|-------|----------------------------------------------------------------------------------------|
| `Null`    | 0     | none; marks a free slot                                                                |
| `Endpoint`| 1     | `ty::ENDPOINT` (0): the right to send a request to a task-hosted or kernel-hosted endpoint |
| `MemObj`  | 2     | `ty::SHM` (0): a shared-memory region                                                  |
| `Queue`   | 3     | `ty::IORING` (0): an io_ring                                                           |
| `Port`    | 4     | `ty::PORT` (0): an event port                                                          |
| `Domain`  | 5     | `ty::TASK` (0): the right to see every task (resource 0, `READ`)                       |
| `Node`    | 6     | `ty::FILE` (0): a file or directory tree; `ty::LAUNCH` (1): the right to start one image; `ty::SOCKET` (2): a socket |
| `Device`  | 7     | `ty::IRQ` (0): an interrupt line; `ty::MMIO` (1): a device's register window; `ty::DRIVER_REGISTRY` (2): the right to register as the driver for one `DRV_KIND_*`; `ty::IOPORT` (3): a range of I/O ports (x86_64) |
| `Log`     | 8     | `ty::TRACE` (0): the kernel tracer; `ty::CONSOLE` (1): the console                     |

Kind tags 9 and above are not kinds: `CapKind::from_raw` returns `None` for
them, so a corrupt or unknown tag fails closed instead of aliasing a real kind.
`reserved_kind::VM` (10) and `reserved_kind::VCPU` (11) are named constants,
not variants. `CapKind` is `#[non_exhaustive]`. A kind's discriminant is also
the code a denial is recorded under (`CapKind::denial_code`).

Source: `crates/core/abi/src/cap.rs` (`CapKind`, `CapType`, `ty`,
`reserved_kind`), `crates/core/ipc/src/cap.rs` (`Cap<T>`, `CapTarget`,
`targets`).

## Rights

| Right      | Bit      | Meaning                                                                                      |
|------------|----------|----------------------------------------------------------------------------------------------|
| `READ`     | `0b000001` | read access                                                                                |
| `WRITE`    | `0b000010` | write access                                                                               |
| `EXEC`     | `0b000100` | execute, or map as executable (MMIO regions)                                               |
| `DUP`      | `0b001000` | make a copy: derive an attenuated child, mint a badged copy, or send a DUP entry          |
| `TRANSFER` | `0b010000` | move the capability to another Domain over IPC, or send a copy there (a copy also needs `DUP`) |
| `MAP`      | `0b100000` | map a memory object into an address space (`SYS_MO_MAP`)                                   |

`DUP` and `TRANSFER` are separate on purpose: a holder can derive a copy for
itself without being able to give authority away, and a capability meant to
travel need not be copyable. `MAP` is separate from `READ`: reading a region
through the kernel does not give it a window in ring 3. Composite constants:
`NONE`, `RW`, `DELEGATE` (`DUP | TRANSFER`), `RW_DELEGATE` and `ALL`. Bits
outside the six are discarded (`CapPerms::from_bits_truncate`).

Source: `crates/core/abi/src/cap.rs` (`CapPerms`).

## Handle operations

| Syscall          | Effect                                                                                      |
|------------------|---------------------------------------------------------------------------------------------|
| `SYS_CAP_INFO`   | reads what the caller holds without using it. Queries: `CAP_INFO_LOOKUP` (find a handle by type and resource), `CAP_INFO_TREE` (find the directory tree covering a path), `CAP_INFO_QUERY` (type, rights, badge, expiry of a handle). Needs no right and is not subject to containment. |
| `SYS_CAP_CLOSE`  | deletes a handle and releases the object it names by type (io_ring, port, memory object, file, socket or endpoint); copies derived from it stay alive. Closing the last `READ` (serving) capability of an endpoint the caller serves ends its role as a server's death does: queued calls end `PEER_DIED`, a named endpoint stays unclaimed, an anonymous one is freed |
| `SYS_CAP_DERIVE` | mints a badged, optionally dated copy of an endpoint capability that holds `DUP`; the copy is a child of the source in the warrant tree. A kernel-hosted endpoint refuses it, because its badge is the resource. An expiry already past is refused with `EDEADLINE` before anything is minted (`Rule::DeadlineExpired`). |
| `SYS_CAP_REVOKE` | revokes every capability derived from a handle and keeps the handle; returns the replacement handle, and the old value is stale |

Capabilities also move between Domains in an IPC message. Each capability entry
of a message descriptor (`CapDesc`) is a MOVE (the sender's handle goes stale)
or a DUP (the receiver gets a copy and the sender keeps its own). A MOVE needs
`TRANSFER` on the capability; a DUP needs `TRANSFER` and `DUP`. The entry may
lower the receiver's rights and may set a deadline; the kernel takes the earlier
of that deadline and the sender's. A message carries at most
`IPC_MSG_MAX_CAPS` entries, which the ABI ceiling `MSG_CAPS_MAX` (8) bounds. The whole transfer is checked under both tables'
locks before the sender loses anything, and either every entry lands or none
does.

`ENDPOINT_DERIVE` (an `invoke` op on an endpoint capability) is the derive that
can also append caveats, up to `ENDPOINT_DERIVE_CAVEATS_MAX` (4). It applies the
same expiry rule as `SYS_CAP_DERIVE`.

Source: `crates/core/abi/src/syscall_nr.rs` (`SYS_CAP_INFO`, `SYS_CAP_CLOSE`,
`SYS_CAP_DERIVE`, `SYS_CAP_REVOKE`, `CAP_INFO_LOOKUP`, `CAP_INFO_TREE`,
`CAP_INFO_QUERY`), `crates/core/syscall/src/caps.rs`,
`crates/core/abi/src/ipc_msg.rs` (`CapDesc`, `CAP_MODE_MOVE`, `CAP_MODE_DUP`),
`crates/core/abi/src/invoke.rs` (`ENDPOINT_DERIVE`, `EndpointDerive`),
`crates/core/ipc/src/cap_store.rs` (`move_caps`, `CapXfer`).

## The warrant tree

Every slot has a warrant that records where the capability came from. A slot
minted from nothing (a topology grant at admission, a kernel object's
capability, a fork copy) is a root. A slot made by a DUP transfer or a badged
mint is a child of the slot it was copied from, in whichever Domain that slot
lives, and revoking the parent revokes the child.

| Field       | Meaning                                                                                  |
|-------------|------------------------------------------------------------------------------------------|
| `parent`    | `domain_key << 32 \| slot << 16 \| generation` of the source slot (`warrant_ref`); 0 for a root |
| `depth`     | links between this slot and its root                                                     |
| `expiry_ns` | monotonic deadline in nanoseconds; 0 for none                                            |
| `quota`     | a count, or a number of bytes, up to 48 bits; stored and narrowed on derive, but the resolve does not spend it |
| `flags`     | `Warrant::WEAK`                                                                          |
| `caveats`   | an append-only list of conditions on a use                                               |

The parent is a reference, not a pointer, and it is checked rather than
trusted. A parent is alive only if its Domain still owns its table and the
slot still holds the generation the reference names. Because a slot's generation
never repeats, a reference to a revoked, wiped or reused slot is dead for good.

**Attenuation only.** A derive (`derive_warrant`) produces a copy that is never
more than its source:

- Rights are the source's or a subset. Asking for a right the source lacks is
  `MissingPerms`; the kernel does not mask the request, so a caller asking for
  authority it cannot give sees the error.
- The deadline is the earlier of the source's and the one asked.
- The quota is the source's or smaller, in the source's unit. More, or the
  other unit, is `MissingPerms`.
- The caveats are the source's, followed by the ones asked.
- The chain depth may not exceed `WARRANT_DEPTH_MAX` (Kconfig, 1 to 15, default
  8, or 4 on the embedded profile). A derive past it is `NoSpace`.

A MOVE keeps the capability's place in the tree and can still narrow it
(`narrow_warrant`); a DUP adds a link. Moving a capability out of a slot that
other slots were derived from takes those slots along: they hang under the
capability's new slot.

**Delete is not revoke.** Closing a capability, or exiting, frees the task's own
slots and nothing derived from them: a copy a task lent (a DUP over IPC, a
spawn's share) stays alive in its holder's table and keeps what it maps. The
copies of a deleted slot hang under that slot's own parent (a root's copies
become roots) and keep their rights, deadline, quota and caveats. Only an
explicit revoke takes copies back.

**Revoking a subtree.** An explicit revoke (`SYS_CAP_REVOKE`) of a slot that has
descendants revokes all of them, across Domains. `cap_store::sweep` finds them:
one pass over the tables frees every slot whose parent was revoked (and hangs
those whose parent was deleted under its parent), and passes repeat until one
changes nothing, which is at most `WARRANT_DEPTH_MAX + 1` passes. Each freed
slot is recorded (`Rule::CapRevoke`) and its holder is told by a pending
notice, which turns into the `Revoked` answer to the next refused use of a dead
handle. Every derive is recorded as `Rule::CapDerive`.

A slot knows only its parent, so there is no child list: the sweep finds
descendants by scanning, and it skips a table with no derived slot. A delete of
a slot with copies keeps a re-parent row (bounded; a delete that finds the rows
full revokes its copies) until the sweep has hung them under their new parent.

Source: `crates/core/ipc/src/cap.rs` (`Warrant`, `Quota`, `DeriveSpec`,
`derive_warrant`, `narrow_warrant`, `WARRANT_DEPTH_MAX`, `CapTable::sweep_dead`),
`crates/core/ipc/src/cap_store.rs` (`sweep`, `revoke_derived`, `move_caps`,
`mint_badged`), `crates/core/decision/src/prov.rs` (`warrant_ref`),
`config/limits/Kconfig.limits`.

### Lazy revocation

The sweep runs after a revoke with no lock held, so there is a window in which
a descendant still has a live slot word. A use does not wait for the sweep.

Two counters (`cleared`, incremented when a revocation of a slot with
descendants completes, and `swept`, the highest count a sweep confirmed with a
pass that freed nothing) differ exactly while that window is open.
`revocation_in_flight` is true exactly while they differ. While it is true, a
resolve walks the parent chain of the slot it is about to trust
(`CapTable::chain_alive`, one `cap_store::warrant_step` per link, at most
`WARRANT_DEPTH_MAX` links) and answers `Revoked` if any ancestor is gone. A walk
that has not reached a root within the bound is a corrupt chain and fails
closed. While the window is open the resolve cache (`CapTable::word_grants`)
grants nothing, so the full resolve decides. With no revocation in flight a
resolve is unchanged.

Source: `crates/core/ipc/src/cap.rs` (`revocation_in_flight`,
`CapTable::chain_alive`, `CapTable::word_grants`, `sweep_epoch`,
`sweep_confirmed`), `crates/core/ipc/src/cap_store.rs` (`warrant_step`,
`sweep`).

### Weak warrants

A weak warrant, and every warrant derived from it, resolves with its rights
masked to `READ` and `MAP` (`slot_word::WEAK_KEEPS`). `MAP` is kept because
mapping is how a region is read; a weak holder's mapping is read-only.
`WRITE`, `EXEC`, `DUP` and `TRANSFER` are masked, so a weak slot cannot be
delegated away. A derive and a move carry the bit, and nothing in a
`DeriveSpec` can clear it.

A topology task row with `shadow = true` spawns with a weak table:
`CapTable::mark_weak` marks it before the row is seeded, and every slot granted
into it by any minter is weak. Each use the mask refuses returns
`MissingPerms` and is counted per table; the count is recorded as
`Rule::ShadowRefusal` (verdict `Refuse`, with the rights asked and the type of
the slot) when it reaches a power of two, so a loop refused a million times
leaves a bounded number of records. With Kconfig `CAP_WEAK` off, no weak
warrant is ever published and a shadow row is seeded with no capabilities.

Source: `crates/core/abi/src/cap.rs` (`slot_word::WEAK`,
`slot_word::WEAK_KEEPS`, `slot_word::perms`), `crates/core/ipc/src/cap.rs`
(`Warrant::WEAK`, `CapTable::mark_weak`, `CapTable::shadow_refusal`),
`crates/core/topology/src/types.rs` (`shadow`), `config/kernel/Kconfig.ipc`
(`CAP_WEAK`).

## Caveats

A caveat is a condition on the use of a capability: a kind and a 64-bit
argument. A warrant carries up to `CAVEATS_MAX` (4) of them, as an append-only
list (`Caveats`). Appending is the only operation: `Caveats::with` and
`Caveats::append` add entries, and nothing removes or replaces one. A derive or
a move copies the source's list and may only append to it, so a copy is never
less restricted than its source, and anyone who holds a capability may add a
caveat to a copy of it. Every caveat must hold for a use.

| Caveat       | Value | `arg`                                                              | Evaluated by the resolve |
|--------------|-------|--------------------------------------------------------------------|--------------------------|
| `EXPIRY`     | 1     | monotonic deadline in ns; a use at or after it is `Revoked`        | yes                      |
| `QUOTA`      | 2     | uses left; each use takes one, and at 0 the capability is `Revoked` | yes                      |
| `NODE`       | 3     | the node the capability is valid on                                | reserved: carried and derived, but a use is refused (`MissingPerms`) |
| `OP_MASK`    | 4     | mask of op classes (`op_class`, bit n is class n) the capability may be invoked with; on a kernel-hosted endpoint, of the interface's IDL ops (bit n is op n) | yes, by `get_op`; `get` refuses it and leaves a receipt; a call to a kernel-hosted endpoint is held to it by `khost::admit` |
| `RECEIPT`    | 5     | a receipt the device must have left; see [effects.md](effects.md#receipt-conditioned-warrants) | yes |
| `DECLASSIFY` | 6     | label bits the holder may take off one message; see [effects.md](effects.md#declassification) | yes: `Revoked` once spent; spent by `take_declassify` |

A kind the kernel does not know is refused wherever a warrant is built
(`Caveats::with` returns `MissingPerms`), and a full list is `NoSpace`. A
request for a condition the kernel cannot honour is refused rather than
ignored.

Rules for the interaction of caveats:

- Two `EXPIRY` caveats, or a caveat and the warrant's own deadline, give the
  earlier time. Two `OP_MASK` caveats give the intersection of their masks.
- A `QUOTA` is charged last: only a use that every other check passed takes a
  count. Presence tests (a scan for a held capability) charge nothing and name
  no op. A copy starts with what its source has left and counts on its own.
- An `OP_MASK` caveat is discharged only by a resolve that names the op
  (`CapTable::get_op`). Every resolve in the syscall layer does: a typed
  handler names the op it is (`NODE_READ`, `PORT_BIND`, ...), a numbered
  syscall or a ring entry the class-only op (index 0) of its class, and
  releasing a handle (close, destroy, unmap) is the `CTL` class. A mask is a
  set of classes, so a capability with no `CTL` in its mask cannot be closed
  by its holder until the task exits. An endpoint capability is the exception:
  its mask is a mask of the interface's IDL ops, which has no `CTL` class, and
  dropping authority is no escalation, so an endpoint handle closes whatever
  its mask, deadline or quota say. A resolve that names no op (`get`; what
  is left of it is in the IPC paths of `azos_ipc`) refuses a capability
  carrying an op mask (`MissingPerms`) and leaves a receipt, a `CapDenial`
  `Refuse` per table at the powers of two, so the mask fails closed where the
  op is not carried and the call site is found.
- **A call to an endpoint the kernel hosted** is the one IPC path that does
  carry an op, only later than the resolve: the request names it (the IDL op
  number, counted from 1) after the capability has resolved. Its resolve
  (`CapTable::get_hosted_uncontained`) therefore passes an `OP_MASK` and
  evaluates every other caveat as for a use; `khost::admit` then holds the call
  to the mask (`CapTable::hosted_op_mask`, bit n = op n, the intersection of the
  masks on the capability) before any interface runs, and a refused call is the
  call's `E_PERM` with a capability denial recorded. Op 0 and ops past bit 63
  are in no mask. A capability to a task-hosted endpoint that carries a mask
  still resolves nothing. A topology grant of a kernel-hosted interface says
  the ops with its `ops` key (`design/static-topology.md`); `RPCSRV.ELF` and
  `MCPD.ELF` hold `READ` on `linkkey` masked to `node_key`, so their own node
  identity is all they can ask of the key sector, and `SSHD.ELF` holds `READ` and
  `WRITE` on `keys` masked to `generate`, `public` and `sign`, so the host key is
  all it can ask of the keystore.
- `DECLASSIFY` is the one caveat that grants instead of restricting. A derive
  cannot add one (`narrow_warrant` returns `MissingPerms`) and a source that
  carries one has no copy (`derive_warrant` returns `MissingPerms`); only
  `CapTable::mint_badged_issued` makes it.

**Storage.** A slot whose warrant has a deadline or any caveat has the hot
word's `EXPIRES` flag set; that is the single test the resolve makes, and the
resolve cache never answers for such a word. The caveats themselves live in a
small per-table pool of blocks (`CaveatBlock`), one block per eight slots (at
least one), named from the warrant's meta word. Each block records its owning
slot and generation, so a lock-free reader that finds a block re-granted to
another slot refuses instead of evaluating or charging someone else's caveats.
When the pool is full a grant that needs a block fails with `NoSpace`, and a
transfer checks the receiver's free blocks before the sender loses anything.

Source: `crates/core/ipc/src/cap.rs` (`caveat`, `Caveat`, `Caveats`,
`CAVEATS_MAX`, `CaveatBlock`, `CapTable::gate`, `CapTable::get_op`,
`CapTable::mint_badged_caveated`, `CapTable::mint_badged_issued`),
`crates/core/abi/src/invoke.rs` (`ENDPOINT_DERIVE`).

## Domain-subtree policies

A Domain created by a task of another Domain is that Domain's child (a spawn
and a fork are; a kernel task is a root). A topology `[policy.NAME]` row binds
limits to the Domain of the task row it names (`domain = "..."`). With
`scope = "self"` the limits bind that Domain; with `scope = "subtree"` they bind
it and every Domain created beneath it, however deep. The limits are checked at
creation time, whatever capabilities the creating task holds.

| Limit               | Default | Meaning                                                  |
|---------------------|---------|----------------------------------------------------------|
| `create_endpoints`  | `true`  | may the Domain create endpoints (`DOMAIN_CREATE_ENDPOINT`) |
| `create_ports`      | `true`  | may the Domain create ports (`DOMAIN_CREATE_PORT`)         |
| `memobj_max_pages`  | `0`     | largest memory object, in 4 KiB pages, for `SYS_MO_CREATE`; 0 is no ceiling |

A limit only narrows. A row that restricts nothing is refused at admission.
`Limits::narrow` combines two sets of limits by taking what both allow, and the
smaller non-zero memory-object ceiling.

`domain::check_create` walks the actor's own words (its `self` and `subtree`
rows and its floor), then the `subtree` words of its ancestors, nearest first,
at most `WALK_MAX` (8) of them, and returns the first limit that refuses.
Because a bound must not become a hole, the chain is kept within `WALK_MAX` by
construction rather than by failing a deep process tree: a Domain created under
one already `WALK_MAX` levels deep is attached to that Domain's parent, and the
subtree limits that parent carried are folded into the new Domain's `floor`,
which the walk applies as part of the Domain itself. The same fold runs when a
Domain with children ends: the children are re-attached to its parent and take
its subtree limits with them, so a limit outlives the Domain that carried it.

A refusal answers `EACCES` and writes a `Rule::SubtreePolicy` record (verdict
`Refuse`; the numbers are the Domain whose limit refused, how many levels above
the actor it is, and the refused action). `creation_gate` in
`crates/core/syscall/src/families.rs` is the single check the three creation
paths make before they create anything, and `install_policy` binds a row's
policies to the Domain its task runs in at spawn.

Source: `crates/core/sched/src/domain.rs` (`Limits`, `Create`, `WALK_MAX`,
`set_policy`, `refusal`, `check_create`), `crates/core/topology/src/types.rs`
(`PolicySpec`, `PolicyScope`), `crates/core/syscall/src/families.rs`
(`creation_gate`, `install_policy`), `crates/core/abi/src/invoke.rs`
(`DOMAIN_CREATE_ENDPOINT`, `DOMAIN_CREATE_PORT`),
`crates/core/abi/src/syscall_nr.rs` (`SYS_MO_CREATE`).

## Admin warrants instead of root

No native syscall decides by a user id. A privileged action is allowed
because the task holds a specific capability for it, granted by its row in the
signed topology, and the grant is as narrow as the action.

- **The task view.** `ty::TASK` is a `Domain`-kind capability with `READ` on the
  single target `"tasks"`: the warrant the admin introspection region (the
  task list, the wake log, the decision records) is granted against. The
  built-in topology grants it as `TASK_VIEW_CAP`.
- **The view regions.** `inspect.names`, `inspect.rpc`, `inspect.mcp`,
  `inspect.components`, `inspect.logins` and `inspect.clock` carry the signed
  topology's wiring one service needs; `inspect_region::seed_mint` grants a view
  only to a row that declares it (`READ|MAP`), and the kernel builds it for
  exactly those rows.
- **The admin introspection region.** `inspect.admin` names other tasks, so
  `inspect_region::seed_mint` grants it only to a task whose table already
  holds the task view; the task view is the admin warrant. The grant is exactly
  `READ | MAP`, so the holder can neither write the tree nor hand the region on.
  The check is made when the capability is granted; a mapping made then outlives
  it. The public region (`inspect.public`) needs no warrant.
- **Consequential commands.** `AUTHORITY_TABLE` lists the shell commands that
  need `WRITE` on a named kernel-hosted endpoint: `reboot` and `shutdown` on
  the power endpoint, and (under the console lockdown) `config set` of
  `watchdog_ms` and `ota rollback` on the config and OTA endpoints. The ring-3
  tools are checked per op by the kernel-hosted interface they call, over the
  caller's own capability. Under `CONSOLE_LOCKDOWN` the console is seeded with
  none of these capabilities, so every row is refused and recorded.
- **Task policies.** The subtree policy above is the other administrative
  lever: a parent's `subtree` row bounds every Domain beneath it.
- **The pledge.** A program can narrow, one way, which syscall cases and
  `SYS_INVOKE` op classes its own Domain may still use (`DOMAIN_PLEDGE`); see
  [abi.md](abi.md#cases-entry-counters-and-the-pledge). It removes authority
  and grants none.
- **User sessions.** A Domain's owner (`owner_root`, 0 for the system) is
  inherited from the Domain that created it and changes only at a spawn with
  `SPAWN_F_USER`, which spends the one-shot login grant
  the `keys` interface's `login` op arms for the caller's Domain when a
  credential matches a `[login.NAME]` row of the signed topology. The grant
  lapses after Kconfig `LOGIN_GRANT_TTL_S` (default 20 s); without it the
  spawn is refused with `EACCES`.

Source: `crates/core/topology/src/builder.rs` (`TASK_VIEW_CAP`,
`INSPECT_ADMIN_CAP`), `crates/core/ipc/src/inspect_region.rs` (`seed_mint`),
`crates/core/syscall/src/keys.rs` (`take_login_grant`),
`crates/core/sched/src/domain.rs` (`login_grant`),
`crates/core/ipc/src/authority_policy.rs` (`AUTHORITY_TABLE`,
`console_seed_ifaces`, `may_proceed`),
`crates/core/ipc/src/cap_seed.rs`.

## Warrants across nodes

An endpoint on another node is called through a proxy endpoint served by the RPC
server (`userspace/services/rpcsrv`, built on `userspace/lib/rpc`). This is a
ring-3 library; the kernel contributes the caveat evaluation and
`ENDPOINT_DERIVE`. Nothing leaves a node except through an `export` entry of the
RPC server's topology row, and every session is authenticated and sealed.

What crosses a link is a **token**, not a capability: the issuing node, an
interface id, and a list of caveats chained by HMAC-SHA256 in the manner of a
macaroon.

```text
sig0  = HMAC(session key, "azos-rpc warrant/1" || session || issuer || iface)
sigN  = HMAC(sig(N-1), kind || arg)
token = issuer, iface, count, count * (kind, arg), sigN
```

Only a holder of the session key can start a chain. Anyone holding a token can
extend it with one more HMAC step, which needs no key, and no one can shorten or
edit it, because that would need a signature the token does not keep. Binding
the session and issuer into `sig0` stops a token from one session, or reflected
from the other end of the same session, from verifying elsewhere.

The caller's node starts a token and narrows it to the receiving node with a
`NODE` caveat. The serving node verifies the chain and refuses what does not
hold (`session::Refusal`): another issuer, an interface it does not serve to the
peer, an edited, dropped or reordered caveat, a wrong node, an `EXPIRY` that has
run out, a spent `QUOTA`, an `OP_MASK` that leaves no op, or a `DECLASSIFY`
caveat (which only a local user session issues). It then re-mints the token
(`session::Remint`) into a local capability through `ENDPOINT_DERIVE`:

- `EXPIRY` on the wire is the time left when the frame is sent, because clocks
  differ between nodes; the receiver anchors it on its own clock.
- The derived capability is a child of the exporting node's own capability on
  the endpoint, attenuated to the call right, badged with the session id, and
  carrying the token's caveats, so it is never less restricted than the token.
- The warrants a session holds are cached by interface and caveat set, and
  none outlives the token that uses it.
- A `QUOTA` is counted by the serving node per lineage of the token (the chain
  up to that caveat, which every narrowed copy shares), so narrowing a token
  never renews its budget.

A broken session revokes everything minted over it on both nodes. A withdrawn
export is revoked on the peers: `Rpc::revoke_export` closes what the node lent
over the endpoint and sends each peer that holds descending authority a sealed
revoke notice. The peer stops offering the interface, closes the objects it
re-minted and acknowledges. A peer that has not answered within the bound
(Kconfig `RPC_REVOKE_BOUND_MS`) has its session broken. Both nodes record
`Rule::RemoteRevoke`.

Source: `userspace/lib/rpc/src/lib.rs`, `userspace/lib/rpc/src/wire.rs`
(`Token`, `cav`), `userspace/lib/rpc/src/session.rs` (`Remint`, `Refusal`,
`Budget`, `Quota`), `userspace/lib/rpc/src/engine.rs` (`warrant`,
`revoke_export`), `crates/core/abi/src/invoke.rs` (`ENDPOINT_DERIVE`),
`config/subsys/Kconfig.rpc` (`RPC_REVOKE_BOUND_MS`).
