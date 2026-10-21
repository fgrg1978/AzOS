# Effects

An effect is a change a task makes to a device that cannot be taken back by
discarding state: a wheel turning, a clock gated, a regulator switched, a pin
muxed. Holding the right capability ([capabilities.md](capabilities.md)) is
necessary to cause one but is not the whole check. The effect gate sits between
the capability check and the device. It makes sure that every effect that
reached a device has a record, that an effect which cannot meet its deadline is
refused, that a device which stalled is driven to a safe state, and that data
which passed through a less trusted principal cannot drive an effect harder than
that principal is allowed. Every refusal leaves a decision record that
`why` can print.

## Effect gate and actuation authority

**Who may cause an effect.** The caller first resolves a capability. For the
kernel-hosted `Motor` interface, one wheel is one endpoint (`motor.0`,
`motor.1`); the wheel is the endpoint's badge, so there is no wheel argument that
could disagree with the capability. The per-wheel ops need `WRITE`; pair-wide ops
need `WRITE` on both wheels; `estop` needs `WRITE` on any wheel and is never
refused for containment. The per-wheel ops resolve without the containment step
(`get_uncontained`), because whether a command may move the wheel is decided
one level down, by the motor layer's halt rule: while an e-stop is latched or
containment is armed, brake and coast are carried out and forward and backward
are refused. Refusing a stop at the capability layer would leave a task that may
drive unable to stop.

**The gate.** `azos_actuation::effect_gate` is the second check. It is built with
Kconfig `EFFECT_WRITE_AHEAD` (default `y` when the robot domain is built in) and
installed at boot by `azos_actuation::gate::install`. With it off the gate is
neither linked nor installed and a motor op goes straight to the motor layer.
The kernel's own motor writes (the real-time motor task, the PID loop) are not
ring-3 ops and do not pass through it.

An effect is described by an `Effect`: a kind, a class, a subject (the device;
for a motor, the wheel), the asking task id, and two kind-specific arguments (for
a motor, direction and duty percent). Its 20-byte payload is what the flight
recorder stores.

| Kind constant      | Value | Effect                      |
|--------------------|-------|-----------------------------|
| `KIND_MOTOR`       | 1     | one wheel of the drivetrain |
| `KIND_CLOCK`       | 2     | a clock gate or rate        |
| `KIND_RESET`       | 3     | a reset line                |
| `KIND_REGULATOR`   | 4     | a regulator rail            |
| `KIND_PINCTRL`     | 5     | a pin mux or bias           |
| `KIND_POWER_DOMAIN`| 6     | a power domain              |
| `KIND_STORAGE_DELETE` | 7  | a delete on a volume (see [Storage and network envelopes](#storage-and-network-envelopes)) |
| `KIND_NET_EGRESS`  | 8     | a Domain's first packet to a destination off the node |
| `KIND_CONFIG_WRITE`| 9     | a write of a configuration key (see [Configuration, update and real-time-time envelopes](#configuration-update-and-real-time-time-envelopes)) |
| `KIND_OTA_APPLY`   | 10    | a step of applying an update: staging, the slot switch |
| `KIND_RT_TIME`     | 11    | a real-time (deadline) reservation |

| `Class`      | Meaning                                                            | Refused when it cannot be recorded |
|--------------|--------------------------------------------------------------------|------------------------------------|
| `Safe`       | moves a device toward its safe state (stop, brake, coast, gate a clock, assert a reset, cut a rail, power a domain off) | never |
| `Reversible` | any other effect; a later effect can undo it                       | yes, with a receipt                |

A task entitled to switch something on must always be able to switch it off, so
the safe class is never refused. The SoC resource managers (`azos_soc`) hand
each clock, reset, rail, pin-mux and power-domain change to an `EffectSink`
before they touch a register, and the kernel's sink forwards it to the gate
through `effect_gate::record`. That order is the manager's property; the gate
enforces that the record is committed, or the effect refused, when `record`
returns. The SoC kinds have no deadline, safe state or inverse op: they are
recorded, not watched, and `safe_state` tables are sized so a held mask can
never alias them.

**The stop path.** The emergency stop is a latch plus stop work, and both are
shared by every domain with an actuator.

- `estop::estop_activate` sets the latch first. From that store on, every motor
  write from every path is clamped, so no command can slip in between the latch
  and the stop.
- `gate::latch_and_stop` is the one sequence every stop source ends in: it
  latches, then runs the stop hooks the domains registered
  (`register_stop_hook`) in registration order. There is a second table for the
  panic path (`register_panic_stop_hook`), which is lock-free so it can run from
  the panic handler and the timer interrupt.
- `gate::gate_installed` is false until `install` has run and while the domain's
  own readiness check says so. The loader and the driver supervisor refuse to
  start ring-3 images while it is false.
- Releasing the latch needs the operator's signed release proof
  (`estop::verify_operator_release`): an Ed25519 signature over a message that
  includes a nonce, which must be strictly newer than the last accepted one. The
  nonce floor is written to the flight recorder before the in-memory floor
  moves, so a proof captured before a reset cannot be replayed after it. With no
  durable recorder active the release **fails closed**: it is refused with a
  `Rule::EstopRelease` receipt (`ReleaseDenial::NoDurableRecorder`) and the latch
  stays engaged, because an unpersisted floor would let the captured proof replay
  after a reset. Only a development build (Kconfig `BUILD_TYPE_DEV`, the QEMU
  default) proceeds without a recorder. A recorder that is active but cannot take
  the write refuses the same way in every build.
- The release key comes only from the signed topology's `[operator]` section; a
  release build never reads the loose `/fat/OPERATOR.PUB`. The first key a robot
  installs is pinned in the flight recorder (`SAFETY_OPERATOR_KEY`, a 16-byte
  SHA-256 fingerprint), written again by every boot that installs the key and
  carried into every log file a rotation opens, so the log-serial wrap (which
  overwrites the oldest file) cannot take the only copy. A later boot whose topology offers another key installs
  nothing, so every release is refused, and writes a `Rule::EstopRelease`
  receipt (`RELEASE_CAUSE_KEY_CHANGED`). There is no rotation path yet: a
  deliberate key change needs the recorder reprovisioned.

Source: `crates/core/actuation/src/effect_gate.rs` (`Effect`, `Class`,
`KIND_*`, `record`, `issue`), `crates/core/actuation/src/gate.rs`
(`latch_and_stop`, `register_stop_hook`, `gate_installed`, `install`),
`crates/core/actuation/src/estop.rs` (`estop_activate`,
`verify_operator_release`), `crates/core/actuation/src/hooks.rs`,
`crates/core/syscall/src/motor_host.rs`, `crates/drivers/soc/src/effect.rs`,
`config/Kconfig.robot` (`EFFECT_WRITE_AHEAD`).

## Write-ahead receipts and the safety reserve

`effect_gate::issue` takes the device op as a closure and runs it itself, after
the record is committed to the flight recorder's ring. The order is structural:
there is no call that issues an effect without committing its record first. The
consequence is that every effect that reached a device has a record, and the
only other state a stop can leave is a record without an effect (the machine
stopped between the two), which is harmless.

For a reversible effect `issue` runs these steps in order, and the first failure
returns a `Refusal` carrying the `Why` and the receipt:

1. The provenance meet (see [Provenance labels](#provenance-labels-and-the-envelope-meet)).
2. A device held in its safe state takes stops only (`Why::Held`).
3. If the effect declares a deadline and the driver's placement latency plus the
   device row's `commit_ns` cannot fit it, the effect is refused
   (`Why::Deadline`).
4. If the effect can be watched, a watch slot is claimed (`Why::NoWatch` if the
   table is full or the device is out of range).
5. The record is committed (`Why::RingFull` if the ring is at its limit).
6. The device op runs.
7. The watch is taken down, or the miss handled, and a failed op is compensated.

The `Refusal::receipt` is the id of the refusal's decision record (see
[Decision records and `why`](#decision-records-and-why)); 0 means decision
records are off in this build, and the refusal still happened.

**The ring and its reserve.** The flight recorder's ring holds
`LOG_RING_ENTRIES` records. `LOG_RING_SAFETY_RESERVE` of those slots are used
only by safety records: a latching or releasing `SAFETY_ESTOP`, the boot
replay's restore record, and the release nonce floor. Everything else queues
only while fewer than `ORDINARY_RING_LIMIT` (the ring minus the reserve) records
are queued. How the ring treats each kind of record:

| Record                     | Ring below the limit            | Ring at the limit                                           |
|----------------------------|---------------------------------|-------------------------------------------------------------|
| Ordinary record            | queued                          | evicts the oldest unpinned record; with a pinned tail the new record is lost |
| Reversible effect record   | committed and pinned            | refused: `Why::RingFull`, nothing evicted                   |
| Safe effect record (a stop)| committed, not pinned           | uses the reserve, down to the last `STOP_KEEPS_FREE` slots (half the reserve); past that it takes the ordinary path |
| Safety record              | committed                       | may take any free slot, the reserve included; never evicts a pinned effect record |

A committed reversible record is **pinned**: no record evicts it, the latching
e-stop included, so it leaves the ring only when the flusher consumes it.
Durability is the flusher's, a flush interval later. A commit that reaches the
flush watermark also wakes the flusher. A stop is not pinned, so a loop of stops
cannot fill the slots the e-stop needs; and the stop's record is written into
the reserve so that a stop is recorded even when the ring is at its effect
limit.

The promise gives way in two places, and both give way toward safety. A stop
whose record finds a ring at its limit with a pinned tail goes ahead and is
counted as unrecorded (a warning at each power of two). And with no recorder at
all (the logger is off) a safe or reversible effect goes ahead and is counted as
unrecorded, because there is nowhere to commit to.

Source: `crates/core/actuation/src/effect_gate.rs` (`issue`, `Why`, `Refusal`,
`Timing`), `crates/core/actuation/src/logger.rs` (`commit_effect_record`,
`EffectCommit`, `RING_SAFETY_RESERVE`, `ORDINARY_RING_LIMIT`,
`STOP_KEEPS_FREE`, `LOG_FLUSH_WATERMARK`), `config/Kconfig.limits`
(`LOG_RING_SAFETY_RESERVE`).

## Deadline or safe state

A reversible effect may carry a `Timing`, resolved by the effect's host from the
op's IDL contract (`#[deadline_ns]`) and the topology's `[device.*]` row.

| Field          | Meaning                                                              |
|----------------|----------------------------------------------------------------------|
| `deadline_ns`  | longest from request to commit; 0 means none, and the effect is neither checked nor watched |
| `placement_ns` | what one call costs from the caller's side in the host the driver is placed in |
| `commit_ns`    | the row's accepted-command-to-effect-committed time                  |
| `safe_op`      | the op that drives the device to its safe state; 0 means none, so the effect cannot be watched |
| `compensate_op`| the op that undoes this effect; 0 means none declared               |

**Admission.** An effect whose `placement_ns + commit_ns` exceeds its deadline is
refused before anything is recorded or issued, with a `Rule::EffectDeadline`
receipt. The reasoning is in the rule's table entry: the device would act on the
world after the moment the effect was meant for.

**The watch.** An admitted effect with a deadline and a `safe_op` is watched from
admission until its device op returns. The watch table has
`EFFECT_WATCH_SLOTS` slots (Kconfig, default 8); a slot is claimed by one
compare-and-swap, and completion and the sweep race for it, so exactly one
handler writes the record for a missed effect. A full table refuses the effect
(an effect that cannot be watched is not issued).

**The miss.** If the op has not returned by its deadline, the kernel drives the
device to its declared safe state, through its own hold on the device and not
through the driver, which is the thing that stalled. The timer is the system
watchdog's pass (`safe_state::sweep`, called by `sys_wdt`), not the scheduler's
timer heap, which a stalled scheduler would take down with the thing being
watched. A stalled device is therefore driven within its deadline plus one pass.
An op that returns late is a miss too: the caller that finds its own watch
overdue at completion drives the device after its op, so the stop is the last
write. Each kind registers how it is driven (`safe_state::register`, with a safe
drive and a compensating drive); these run in the watchdog's task or the
caller's context and must not block or take a lock the stalled driver may hold.
Only the motor kind has a safe state (`safe_state::MAX_KINDS`). One
`Rule::SafeState` record is written, admit if the drive worked and refuse if it
could not be done.

**The hold.** From the drive on, the device is **held**. A further reversible
effect is refused with a receipt (`Why::Held`, `Rule::SafeState`) and only stops
pass. A stop does not lift the hold, from whichever path: a device that stalled
once is not trusted again because somebody told it to stop. The hold is a time,
not a bit: it records when the device was last driven, and lasts at least
`B2_HOLD_MIN_MS` from then (Kconfig, 0 to 60000, default 500). After that only
`safe_state::release` lifts it. The hold is volatile; a reboot re-initialises the
device.

`release(kind, subject, nonce, sig)` is checked in this order, cheapest and
key-free first:

| Check                              | Failure                           | Record                                  |
|------------------------------------|-----------------------------------|-----------------------------------------|
| the device is held                 | `ReleaseError::NotHeld`           | none                                    |
| the minimum hold has elapsed       | `ReleaseError::TooEarly { remaining_ms }` | `Rule::SafeState` refuse, `CAUSE_RELEASE_TOO_EARLY` |
| the operator's signed warrant verifies (`verify_operator_release`: the same proof and key path as the e-stop release) | `ReleaseError::NoWarrant` | `Rule::SafeState` refuse, `CAUSE_RELEASE_NO_WARRANT` |
| the hold was not re-armed meanwhile (compare-and-swap) | `TooEarly`          | `Rule::SafeState` refuse                |
| success                            | `Ok(())`                          | `Rule::SafeState` admit, `CAUSE_RELEASED` |

A warrant sent too early is not burned: only a release that could be accepted
spends the nonce. The operator reaches `release` through a mode-reset frame that
names the device (`safe_state::release_from_frame`): a body of exactly
`HOLD_RELEASE_BODY_BYTES` (the 8-byte big-endian nonce, the Ed25519 signature,
the device kind and the big-endian subject). Any other body length is not this
frame, so one warrant cannot both release a hold and the e-stop latch.

**Compensation.** An op that reports failure (the device did not take the
effect) is undone by the row's `compensate` op, run by the kernel
(`safe_state::compensate`). One `Rule::Compensation` record is written: admit
when it ran, refuse when the row declares no inverse (`COMP_NO_INVERSE`) or the
kind's driver refuses it (`COMP_REFUSED`).

Stops are never refused by any of this and are never watched.

Source: `crates/core/actuation/src/safe_state.rs` (`arm`, `cancel`,
`complete`, `sweep`, `register`, `held`, `release`, `release_from_frame`,
`ReleaseError`, `compensate`, `HOLD_RELEASE_BODY_BYTES`, `CAUSE_*`, `COMP_*`),
`crates/core/actuation/src/effect_gate.rs` (`Timing`), `crates/core/actuation/src/sys_wdt.rs`,
`config/Kconfig.robot` (`EFFECT_WATCH_SLOTS`, `B2_HOLD_MIN_MS`).

## Receipt-conditioned warrants

A committed effect record is the device's receipt: the gate issues the op only
after it. A warrant can be made conditional on one with the `RECEIPT` caveat
([capabilities.md](capabilities.md#caveats)), so the kernel can ask at the point
of use "did this device stop in the last 200 ms, and has nothing moved it since".

**The index.** The recorder keeps the time of the newest receipt of each device
and receipt kind, one word each, written by whoever commits the record and read
lock-free (`logger::receipt_ages`). It does not walk the ring, which is bounded,
flushed and evicted. A receipt is named by:

- the **device**: `effect kind << 8 | subject`;
- the **receipt kind**: the effect's class byte, `0` for a safe-state effect (a
  stop) and `1` for a reversible one (a drive). The contrary of a kind is the
  other one (`kind ^ 1`).

The index is not durable and not replayed. A reboot leaves no receipts, so a
conditioned warrant refuses until the device acts again (fail closed). A device
or kind outside the index's bounds leaves no receipt, so a caveat naming it is
refused.

**The caveat.** The `RECEIPT` caveat's argument packs the device in bits 0..16,
the receipt kind in bits 16..24 and `max_age_ms` in bits 24..56; bits 56..64 must
be 0. A use is valid while:

1. the newest receipt of that kind on that device exists and is at most
   `max_age_ms` old, and
2. no receipt of the contrary kind is as recent or more recent: a contrary
   receipt whose age is less than or equal to the newest receipt's age
   contradicts it. Equal ages count as contradicted, because the clock cannot
   order them.

A drive receipt is therefore contradicted by a later stop, and the reverse.
Presence tests (is the capability held) are unaffected; only a use is checked.

**Refusal.** A use the caveat does not allow returns `MissingPerms`. The table
counts refusals and writes a `Rule::ReceiptCaveat` record (verdict `Refuse`,
subject the Domain key of the table) when the count reaches a power of two, so a
loop refused a million times leaves a bounded number of records. The record's
first number names the device, the receipt kind and the cause, laid out in
`azos_decision::receipt`:

| Cause           | Value | Meaning                                                   |
|-----------------|-------|-----------------------------------------------------------|
| `MISSING`       | 1     | the device has left no receipt of the kind (or no index is registered) |
| `OLD`           | 2     | the newest receipt is older than the caveat allows        |
| `CONTRADICTED`  | 3     | a later receipt of the contrary kind contradicts it       |

The second number is the age in milliseconds of the newest receipt of the kind
(0 when there is none) and the third the limit. `why` and the recovery console
decode the first number and print the device, the receipt kind and the cause.

The kernel registers the index as the caveat's probe at boot
(`azos_ipc::cap::set_receipt_probe(azos_actuation::logger::receipt_ages)`). With
no probe registered, every `RECEIPT` caveat finds no receipt and refuses.

Source: `crates/core/actuation/src/logger.rs` (`receipt_ages`,
`commit_effect_record`, `NO_RECEIPT_AGE`), `crates/core/ipc/src/cap.rs`
(`caveat::RECEIPT`, `caveat::receipt`, `ReceiptProbe`, `set_receipt_probe`,
`CapTable::receipt_refusal`), `crates/core/decision/src/receipt.rs`
(`MISSING`, `OLD`, `CONTRADICTED`, `word`, `Refusal`), `kernel/src/boot/sched.rs`.

## Storage and network envelopes

Two more kinds are held to the Domain's `[envelope.NAME]` row of the signed
topology: `KIND_STORAGE_DELETE` (row kind `delete`) and `KIND_NET_EGRESS` (row
kind `egress`). The row belongs to a scheduler class; a Domain is held by the
row of the class its task was seeded from. The filesystem and the socket layer
sit below the gate, so each asks through a hook the gate's wiring installs
(`crates/core/actuation/src/envelope.rs`); with `EFFECT_WRITE_AHEAD` off, or on
a build with no topology, nothing is installed and nothing is held.

The row's `level` is a ceiling (`azos_common::envelope`):

| level       | `delete` lets through                         | `egress` lets through (first packet to) |
|-------------|-----------------------------------------------|-----------------------------------------|
| `full`      | every delete                                  | any destination                         |
| `cautious`  | every delete but the drop of a snapshot       | the local link and private networks     |
| `slow`      | a cut below a file's size                     | the local link                          |
| `contained` | no delete                                     | no destination off the node             |

* **Deletes** are an unlink, a rename onto a name that already holds a file,
  a cut below a file's size (`truncate`, or an open with `O_TRUNC` of a file
  that holds data) and the drop of an azvol snapshot, each on a device-backed
  volume (tmpfs holds no stored data). The VFS asks before anything
  changes; a refusal answers `EACCES`, and a delete that finds nothing to delete
  asks nothing.
* **Egress** is a socket's first packet to a destination that is not this node
  (loopback and the node's own addresses are never asked about): the connect, or
  an unconnected `sendto` once per change of destination (the socket remembers
  the last destination it was cleared to). The answer is `-EACCES`. The packet
  is the Domain's own start: replies on an accepted TCP stream are not gated,
  and a kernel-owned socket (the brain link, OTA, TFTP) belongs to no Domain.
* A task seeded from no row (the kernel's own OTA, package apply, log
  rotation), a class with no row, and a row that says `full` hold nothing: the
  effect goes ahead with no record, so a full ring cannot refuse an unlink on a
  dev image. Under any other level an effect the row lets through is recorded
  first, like a reversible effect, and a ring at its limit refuses it.
* The provenance meet applies too: the more restrictive of the row and the
  meet decides, and a tie is the data's (`ProvenanceMeet`).

A refusal is `Rule::EnvelopeDelete` or `Rule::EnvelopeEgress` (see the table
under [Decision records and `why`](#decision-records-and-why)) with a receipt.

Source: `crates/core/actuation/src/effect_gate.rs` (`KIND_STORAGE_DELETE`,
`KIND_NET_EGRESS`, `EnvelopeProbe`, `Why::Envelope`),
`crates/core/actuation/src/envelope.rs`, `crates/core/common/src/envelope.rs`,
`crates/fs/fs/src/vfs.rs` (`DeleteGate`), `crates/fs/fs/src/azvol/snap.rs`,
`crates/net/net/src/socket.rs` (`EgressGate`).

## Configuration, update and real-time-time envelopes

Three more kinds are held to the Domain's `[envelope.NAME]` row the same way
(row kinds `config`, `ota`, `rt_time`; same cost, same `full` fast path, same
provenance meet). The writer sits below the gate, so each asks through one hook,
`azos_common::envelope::asked`, that the gate's wiring installs
(`crates/core/actuation/src/envelope.rs`); with `EFFECT_WRITE_AHEAD` off, or on
a build with no topology, nothing is installed and nothing is held.

| level       | `config` lets through                        | `ota` lets through | `rt_time` lets through (one reservation) |
|-------------|----------------------------------------------|--------------------|------------------------------------------|
| `full`      | every key                                    | stage and switch   | up to a whole hart                       |
| `cautious`  | every key but those that open a way in or change what boots | stage, no switch | half a hart                   |
| `slow`      | tuning keys only                             | nothing            | a tenth of a hart                        |
| `contained` | no key                                       | nothing            | no reservation                           |

* **Config.** `config set` (the console's and the ring-3 `Config` interface's,
  one body: `azos_recovery::families::config_set`; the signed `CONFIG.INI` load
  at boot (`azos_config::signed`) and any other `cfg_set` caller are not
  asked, on purpose: the file is signed by the topology's key, loaded at boot by
  the kernel before a Domain exists to hold, and is the operator's own authority) classes the key
  (`ConfigOp::of_key`): `ota_auto_recv_port`, `bench_boot` and `autorun` open a
  way in or change what boots; `estop_gpio_pin`, `watchdog_ms` and
  `panic_reboot_ms` arm or disarm a guard; any other key tunes. A refusal answers
  `-EACCES` and the store is untouched. The row is asked once per write, before
  the store.
* **OTA.** The updater (`azos_ota::update`) asks once in `stage`, after the
  manifest verified and before the inactive slot is written, and once in
  `switch`, after the staged set verified and before the kernel is promoted, so
  a refusal changes nothing and a forged bundle is refused for what is wrong with
  it before any row is asked. A refusal is `update::Refusal::Envelope`. The
  switch is asked in the kernel under the calling task (the `Ota` interface's
  `switch`, the console's `ota switch`).

  **Open: the installer's staging is not gated.** The whole-system stage that
  `pkgd` (ring 3) writes into the inactive slot runs on a store that takes the
  default `Store::may_apply`, which lets every step go, so a Domain whose `ota`
  row is `slow` or `contained` can still stage a set through `pkgd` (the set is
  verified again at the switch, which the row holds for the calls it makes
  itself). The ring-3 program has no way to ask the gate for the requester: a
  question from `pkgd` is about `pkgd`'s own Domain, not the caller's. Closing it
  takes the requester's identity reaching a kernel-side question before the
  first write (an op on the `Ota` interface, an IDL change, answered under the
  requester's row; no new syscall and no new capability kind); until then the
  `ota` row holds the switch and the kernel's own staging only.
* **RT time.** `rt::reserve` asks once per reservation (`rt_receipt::held_by_row`),
  before it masks anything or takes the admission lock, with the reservation's density in parts per
  million of a hart (`azos_common::envelope::RT_CEILING_PPM`); the row caps one
  reservation, and the scheduler's own admission still decides whether it fits.
  The row is the row of the Domain of the task admitted: a reservation made at
  spawn finds it because `spawn.rs` records the child's row before it reserves
  (`natfork::record_row_named`), and one made by `schedctl` is the caller's own.
  A refusal is
  `Refusal::Envelope` (`EACCES`) and is the gate's own record: the
  `Rule::DeadlineAdmission` record that every other refusal of `rt::reserve`
  leaves (budget asked, budget the best hart could still give, reason) is not
  written for it, so a refusal is one record.
* A class with no row, a task seeded from no row (the kernel's own tasks, the
  recovery console) and a row that says `full` hold nothing, and cost one probe.

A refusal is `Rule::EnvelopeConfig`, `Rule::EnvelopeOta` or
`Rule::EnvelopeRtTime` (see the table under
[Decision records and `why`](#decision-records-and-why)) with a receipt.

Source: `crates/core/common/src/envelope.rs` (`ConfigOp`, `OtaOp`,
`RT_CEILING_PPM`, `Ask`, `asked`), `crates/core/actuation/src/effect_gate.rs`
(`KIND_CONFIG_WRITE`, `KIND_OTA_APPLY`, `KIND_RT_TIME`),
`crates/core/actuation/src/envelope.rs`, `crates/core/recovery/src/families.rs`,
`crates/core/ota/src/update.rs` (`Store::may_apply`), `crates/core/sched/src/rt_receipt.rs`
(`held_by_row`), `crates/core/sched/src/rt.rs`, `crates/core/syscall/src/spawn.rs`.

## Provenance labels and the envelope meet

A **label** is a set of principal kinds that a piece of data has passed through.
It is a `u32` with one bit per kind (`azos_abi::ipc_msg`):

| Bit | Constant        | Principal kind (`PrincipalKind`)                         |
|-----|-----------------|----------------------------------------------------------|
| 0   | `LABEL_SYSTEM`  | `System`: platform code the signed topology vouches for  |
| 1   | `LABEL_SERVICE` | `Service`: an application service                        |
| 2   | `LABEL_USER`    | `User`: a human user's session                           |
| 3   | `LABEL_AGENT`   | `Agent`: an AI agent, untrusted ring-3 code held to an envelope |

`LABEL_KNOWN` is the union. A descriptor that sets any other bit is refused
(`-EINVAL`), so a later kind cannot be mistaken for nothing.

**How labels travel** (Kconfig `IPC_LABELS`; with it off every function is a
no-op and no label is ever set). The kernel keeps two small tables per task and
one per kind, all plain atomics with no lock on the send path:

- The **principal** of a task is the kind its topology row's class declares
  (`principal = "agent"`, and so on). It is set once at spawn, inherited by a
  fork child, and cleared when the task goes. A thread has its process leader's
  principal as well as its own, so a thread of an agent is an agent. In the
  built-in topology one class declares a principal other than `system`:
  `session`, the interactive class (fair-share at the latency QoS tier, reported
  as `interactive`), with `principal = "user"`. The
  interactive shell row (`SH.ELF`) is in it, so the shell is the task that acts
  as the human user; a program the shell starts runs under its own row, and so
  under that row's class. This holds only for the built-in topology. A signed
  SCHED.TOML written by a deployment's own topology tool carries what that tool
  wrote: unless its shell row is in a class with `principal = "user"`, the shell
  there is a `system` task and no task can mint a declassification warrant. The
  scheduler accepts `session` as the name of such a class (it schedules it as
  `interactive`) and no other name beyond the five built-in ones, so a
  deployment that wants a user principal declares `[class.session]`.
- The **scope** of a task is the label of the data it is working on. A server's
  scope is exactly the label of the request it accepted (`label::enter`), back to
  empty at its reply. A caller's scope grows with the label of every answer it
  reads (`label::absorb`) and stays until the task next accepts or replies. A
  kernel-hosted interface serves a request inside the caller's scope.
- The **envelope** of a kind is the most restrictive `envelope` of any class row
  that declares the kind (`label::set_envelope`, which clamps the level and keeps
  the maximum).

A message's label is the union of the data label the sender wrote in
`MsgDesc::label`, the sender's scope and the sender's own principal
(`label::outgoing`, `send_label`). A sender can only add to a label, never take
from it, so a planner that forwards what an agent said cannot drop the agent's
label by not copying it. The register fast path has no label word; there the
label is read from the tasks, the server's scope entered when the call is
accepted, and the replier's label absorbed by the caller before the reply is
published, so the two paths agree.

**The meet.** An envelope is one of four levels, ordered from no restriction to
none at all: `Full` (0), `Cautious` (1), `Slow` (2), `Contained` (3). Because the
levels form a chain, the meet of several envelopes is the most restrictive
(`Envelope::meet`, `label::envelope_of`). The topology's class `envelope` and
`principal` are installed into the kernel's tables when the scheduler topology is
applied (`crates/core/syscall/src/topo_sched.rs`).

The gate asks `label::provenance_of(tid)`, installed with
`effect_gate::set_provenance_probe` when `IPC_LABELS` is on. It returns the label
of the data behind the effect and the meet of the envelopes of the kinds in it.
For a reversible effect this is the first check `issue` makes:

| Meet        | What the gate allows                                                              |
|-------------|-----------------------------------------------------------------------------------|
| `Full`      | no restriction                                                                    |
| `Cautious`, `Slow` | the effect must fit the level's ceiling. A motor effect's duty percent (`a1`) may not exceed `ENVELOPE_DUTY_CAP_PCT` for the level (100, 70, 30, 0 for `Full` to `Contained`); any other kind has no magnitude to compare and passes |
| `Contained` | no reversible effect at all                                                       |

The gate admits or refuses; it never rewrites an effect, so an issuer whose
effect is refused for its duty retries lower. The refusal is `Why::Provenance`
with a `Rule::ProvenanceMeet` receipt whose numbers are the count of kinds in the
label, the label and the meet. A value the agent touched is therefore held to the
agent's envelope even when a fully rated planner issues the effect, because the
planner's label carries the agent's kind. A stop is never refused. Without a
probe, or with an empty label, nothing changes.

What the labels do not cover: a server that hands a request to a worker thread
and replies from another (the scope is the thread's), a server that holds two
requests at once (the scope is the last accepted, and the first reply empties
it), and a task that keeps what it read in memory across requests.

Source: `crates/core/abi/src/ipc_msg.rs` (`LABEL_*`, `LABEL_KNOWN`,
`principal_bit`, `send_label`, `MsgDesc`), `crates/core/ipc/src/endpoint.rs`
(`label`, including `outgoing`, `enter`, `absorb`, `envelope_of`,
`provenance_of`), `crates/core/topology/src/types.rs` (`PrincipalKind`,
`Envelope`), `crates/core/syscall/src/topo_sched.rs`,
`crates/core/syscall/src/fastpath.rs`, `crates/core/actuation/src/effect_gate.rs`
(`ProvenanceProbe`, `set_provenance_probe`, `ENVELOPE_DUTY_CAP_PCT`),
`config/Kconfig.limits` (`IPC_LABELS`).

### Declassification

A label never shrinks on its own. The one way to lower it is a **declassify
warrant**: a one-shot `DECLASSIFY` caveat on an endpoint capability, a human's
authority to let one message that passed through an agent go out with a lower
label.

- **Issuing.** Only a task whose principal is a user may ask, through
  `ENDPOINT_DERIVE` (`mint_badged_issued`): it is refused with `MissingPerms` for
  any other principal and whenever `IPC_LABELS` is off. The argument is the label
  bits the warrant may take off, at least one and only known bits, and at most one
  such caveat per call. `derive_warrant` and `narrow_warrant` refuse to copy or
  add one, since every other caveat only restricts and this one grants; the issued
  copy travels to whoever is to use it by MOVE.
- **Spending.** The call that presents the capability spends it
  (`CapTable::take_declassify`), in the same lock hold that reads its badge. The
  warrant allows the label bits all its `DECLASSIFY` caveats name together
  (their intersection with `LABEL_KNOWN`). If the message carries none of those
  bits, or the warrant is already spent, nothing is taken and an unneeded warrant
  stays whole. Otherwise each caveat's argument is set to 0 with one atomic swap,
  so two racing callers cannot both win, and the message goes out with
  `label & !allowed`. A spent warrant is `Revoked` from then on.
- **Record.** `Rule::Declassify`, verdict admit, subject the table's Domain, and
  the numbers `from` label, `to` label and the handle.
- **Over a link.** A node never accepts a `DECLASSIFY` caveat in a token
  (`session::Refusal::Declassify`); only a local user session issues one.

Source: `crates/core/ipc/src/cap.rs` (`caveat::DECLASSIFY`,
`CapTable::take_declassify`, `CapTable::mint_badged_issued`, `derive_warrant`,
`narrow_warrant`), `crates/core/ipc/src/endpoint.rs` (`mint_badged_issued`),
`crates/core/syscall/src/ipc_v2.rs`, `crates/core/abi/src/invoke.rs`
(`ENDPOINT_DERIVE`).

## Decision records and `why`

Every admission, placement and refusal path writes a decision record. A record
names the rule that decided, the verdict, the subject, up to three numbers the
rule compared and, from the rule's table entry, the alternative it rejected.

| Piece        | Contents                                                                                |
|--------------|-----------------------------------------------------------------------------------------|
| `Rule`       | which rule decided; `RULES` names it, its subject, its three number fields and the alternative rejected for each verdict |
| `Verdict`    | `admit`, `refuse`, `place`, `deny`                                                       |
| `subject`    | a task id, a Domain key, a device or a count: per rule                                  |
| numbers      | the values the rule compared, named by the rule's table entry                           |
| id (`seq`)   | the sequence number the record claimed; unique since boot, restarting at a reset         |

A record can be stored in three places. The ring and the durable sink do not
depend on each other (the sink with the ring off still leaves every refusal's
receipt on the medium); the journal is written where the sink is called:

- **The ring** (Kconfig `DECISION_RECORDS_DEV`, `DECISION_RECORDS_ENTRIES`): every
  verdict, lock-free so the wake path can write to it; the newest 24 are
  published in the introspection tree's admin region
  (`decisions/records/<n>`), oldest first. The oldest record is
  overwritten.
- **The durable sink** (Kconfig `DECISION_REFUSALS_DURABLE`): a `Refuse` record is
  always handed to a sink the kernel installs (`set_durable_sink`), which writes it
  to the flight recorder so it survives the reset. A `Deny` (a capability denial)
  passes a per-subject token bucket first (`DECISION_DENY_DURABLE_PER_SEC`,
  `DECISION_DENY_DURABLE_BURST`); a denial the bucket drops is counted, and the
  count rides in the third number of the next denial that is written. The sink
  must defer when the caller is real-time, so it queues onto the recorder's ring
  and wakes the flusher rather than flushing in the caller.
- **The journal** (`DECISION_JOURNAL_ENTRIES`): every record that reaches the
  durable path is also kept whole in a small RAM journal, so `why` can name it
  whether or not the ring is built.

`record_receipt` is `record` that returns the record's id. That id is the
**receipt** a refusal hands back, and it is 0 only when the record was stored
nowhere, so 0 is never a valid receipt.

The rules this document touches:

| Rule (`Rule::`)      | Written by                                  | Subject | Numbers                                             |
|----------------------|---------------------------------------------|---------|-----------------------------------------------------|
| `EffectRecord`       | gate, ring or watch table full              | task    | effect (`kind << 8 \| class`), reason, ring length   |
| `EffectDeadline`     | gate, deadline cannot be met                | task    | effect, `deadline_ns`, `needed_ns`                  |
| `SafeState`          | miss, held refusal, release                 | device (`kind << 16 \| subject`) | from state, to state, cause (and the asking task or held time above the cause byte) |
| `EstopRelease`       | e-stop release refused (no durable recorder, or the write failed), or the topology's release key differs from the pinned one | -       | cause, nonce floor, nonce offered (key changed: pinned and offered fingerprint words) |
| `Compensation`       | failed effect                               | task    | effect, action (compensating op), status            |
| `ProvenanceMeet`     | gate, envelope meet                         | task    | kinds in the label, label, meet                     |
| `EnvelopeDelete`     | gate, `storage_delete` refused by the Domain's `delete` row | task | op (1 cut, 2 rename over, 3 unlink, 4 snapshot drop), volume, level |
| `EnvelopeEgress`     | gate, `net_egress` refused by the Domain's `egress` row     | task | destination, class (1 link, 2 private, 3 public), level |
| `EnvelopeConfig`     | gate, `config_write` refused by the Domain's `config` row   | task | op (1 tuning key, 2 arms a guard, 3 opens a way in), key (first 8 bytes), level |
| `EnvelopeOta`        | gate, `ota_apply` refused by the Domain's `ota` row         | task | step (1 stage, 2 switch), slot, level |
| `EnvelopeRtTime`     | gate, `rt_time` refused by the Domain's `rt_time` row       | task | asked (ppm of a hart), ceiling (ppm), level |
| `ReceiptCaveat`      | capability resolve, `RECEIPT` caveat        | Domain  | packed device/kind/cause, age (ms), limit (ms)      |
| `Declassify`         | `take_declassify`                           | Domain  | from label, to label, handle                        |
| `ShadowRefusal`      | capability resolve, weak mask               | task    | rule, verdict, would-be word                        |
| `CapDenial`          | capability resolve, any refused handle      | task    | kind, reason code (`CapError::code`), dropped count |
| `CapDerive`          | DUP transfer or badged mint                 | Domain  | new slot reference, parent reference, expiry (ns)   |
| `CapRevoke`          | subtree sweep                               | Domain  | revoked slot reference, parent reference, descendant flag |
| `SubtreePolicy`      | creation gate                               | Domain  | policy Domain, depth, action                        |
| `RemoteRevoke`       | RPC server, withdrawn export                | node    | Domain, capability, epoch                           |

**The full form.** `ProvenanceRecord` is the record plus the fields that say who
and what it was about: the capability slot and its parent (128 bits each), the
topology row, the node, the image hash prefix, the session, and the kernel clock
in TAI-based nanoseconds (time since boot until the offset is set). It has a
104-byte little-endian wire form (`to_bytes`), a 13-word form the journal stores
and the `Decisions` interface carries (`to_words`), and a compact form that fits
the flight recorder's 20-byte payload as two records: a base (the receipt: rule,
verdict, subject and the numbers) and an extension (the image hash prefix and the
topology row). The compact form does not carry the capability references, the
node, the session or the id; they exist in the full form only. A field that a
record's call site does not supply is 0. For the warrant rules (`CapDerive`,
`CapRevoke`) the widening of a ring record moves the first two numbers into
`cap_slot` and `parent_cap`.

**Asking why.** The query is two functions, `lookup` (one record by id) and
`query` (ids that pass a `Filter` on rule, verdict and subject, paged by the last
id seen), which read the ring first and the journal for what the ring has
overwritten or never held. Nothing parses text. They are served three ways:

| Surface                  | Use                                                                            |
|--------------------------|--------------------------------------------------------------------------------|
| recovery console `why`   | `why` lists the latest records; `why <id>` prints the chain (`cmd_why`)        |
| `WHY.ELF` and the `Decisions` interface | a ring-3 client asks `DECISD.ELF` over `endpoint.decisions`; `why`, `why ID`, `why list [-r RULE] [-v VERDICT] [-s SUBJECT] [-a AFTER_ID]`, and `--remote` to ask a peer node's decision server through the RPC proxy endpoint |

The chain `why <id>` prints (`ProvenanceRecord::write_chain`) is one fact a line:
the rule and verdict, the subject, the numbers the rule compared by name, the
alternative it rejected, the capability and its parent, the topology row, the
image hash prefix and the clock, with `-` where no call site has the value. A
receipt-caveat record is decoded into the device, receipt kind and cause, and a
run-time reservation refusal into its reason.

Because the id is the receipt, the path from a refused effect to its explanation
is direct: the refusal returns a receipt id, and `why <id>` shows the effect, the
reason and the figures that were compared.

Source: `crates/core/decision/src/lib.rs` (`Rule`, `Verdict`, `RuleInfo`,
`RULES`, `record`, `record_receipt`, `set_durable_sink`, `set_clock`),
`crates/core/decision/src/journal.rs`, `crates/core/decision/src/query.rs`
(`Filter`, `lookup`, `query`), `crates/core/decision/src/prov.rs`
(`ProvenanceRecord`, `write_line`, `write_chain`, `COMPACT_BYTES`),
`crates/core/decision/src/receipt.rs`, `crates/core/decision/src/deny.rs`,
`userspace/lib/decisions/src/lib.rs` (`DECISIONS_ID`, `ENDPOINT`),
`userspace/services/why/src/main.rs`, `crates/core/recovery/src/lib.rs`
(`cmd_why`), `config/Kconfig.development` (`DECISION_RECORDS_DEV`,
`DECISION_REFUSALS_DURABLE`, `DECISION_DENY_DURABLE_PER_SEC`,
`DECISION_DENY_DURABLE_BURST`, `DECISION_RECORDS_ENTRIES`,
`DECISION_JOURNAL_ENTRIES`).
