// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Write-ahead receipts (innovation B1): the effect gate issues a device op
//! only AFTER the record that describes it is committed to the flight
//! recorder's ring. Every effect that reached a device therefore has a
//! record; a record without an effect (the machine stopped between the two)
//! is the only other state a stop can leave, and it is harmless.
//!
//! [`issue`] takes the device op as a closure and runs it itself, so the order
//! is structural: there is no call that issues without committing.
//!
//! # Classes
//!
//! * [`Class::Safe`]: the effect moves a device toward its safe state (stop,
//!   brake, coast). It is NEVER refused: a task entitled to drive must always
//!   be able to stop, and a full ring must not make the machine unstoppable
//!   (`motor_host.rs`, `motor.rs`). Its record uses the safety reserve (owner
//!   decision 16-10: a stop is always recorded), down to the last
//!   [`crate::logger::STOP_KEEPS_FREE`] slots, which stay for the safety
//!   records proper so a loop of stops cannot fill the e-stop's slots. It is
//!   not pinned. Past that limit it takes the ordinary path, which may evict
//!   the oldest unpinned record; with a pinned tail the effect still goes
//!   ahead and is counted as unrecorded (a warning at each power of two). The
//!   one place the promise gives way, on purpose, and it gives way toward
//!   safety.
//! * [`Class::Reversible`]: the record must be on the ring. A ring holding
//!   [`crate::logger::ORDINARY_RING_LIMIT`] records REFUSES the effect with a
//!   receipt; the [`crate::logger::RING_SAFETY_RESERVE`] slots above stay for
//!   the safety records (e-stop, release, latch). A committed record is
//!   pinned: no record evicts it, the latching `SAFETY_ESTOP` included (it
//!   uses the reserve), so it leaves the ring only when the flusher takes it.
//!   Durability is the flusher's, a flush interval later.
//!
//! # Deadline and safe state (innovation B2)
//!
//! A reversible effect may carry a [`Timing`]: the op's declared deadline, the
//! driver's placement latency and the device row's `commit_ns`. [`issue`]
//! refuses an effect whose placement latency plus commit time cannot fit its
//! deadline (`Rule::EffectDeadline`, with a receipt) before anything is
//! recorded or issued, and a device held in its safe state takes stops only
//! (`Rule::SafeState` receipt). An admitted effect is watched until its op
//! returns ([`crate::safe_state`]): a miss drives the device to its declared
//! safe state, run by the kernel. An op that reports failure is undone by the
//! row's `compensate` op (`Rule::Compensation`). A stop is never refused by
//! any of this and is not watched.
//!
//! There is no irreversible class: no device behind the gate has an effect
//! that cannot be undone by a later one (a motor op is a duty and a
//! direction), so nothing would use the extra rule (wait for the medium's
//! acknowledgement before the effect). It comes back with the first device
//! that has one.
//!
//! With no recorder (the logger is off: no medium opened) a safe or reversible
//! effect goes ahead and is counted as unrecorded: the boot says "console is
//! the record" on such a board. Refusing there too is a stricter policy the
//! owner has not decided.
//!
//! # Provenance (innovation B4)
//!
//! A reversible effect is held to the envelope of every principal the data
//! behind it passed through, not only to the issuer's own. The kernel keeps a
//! label per task (the set of principal kinds in the request it is serving
//! and in the answers it has read, `azos_ipc::endpoint::label`) and the
//! envelope each kind is held to (the most restrictive `envelope` of any
//! SCHED.TOML class that declares it); [`set_provenance_probe`] is the seam
//! that reads both, installed by the kernel. [`issue`] asks it for the label
//! of `e.tid` and the MEET of the label's envelopes (the most restrictive),
//! and applies that level before anything else:
//!
//! * `Full` (0): no restriction.
//! * `Cautious` (1), `Slow` (2): the effect must fit the level's ceiling. The
//!   gate admits or refuses, it never rewrites an effect, so a motor effect
//!   whose duty percent (`a1`) is above [`ENVELOPE_DUTY_CAP_PCT`] is refused
//!   and its issuer retries lower; any other kind has no magnitude to compare
//!   and passes.
//! * `Contained` (3): no reversible effect at all.
//!
//! So a value the LLM brain touched is held to the brain's slow envelope even
//! when a fully rated planner (an envelope `full` class) issues the effect: the
//! planner's label carries the brain's kind. A refusal is
//! `Rule::ProvenanceMeet` (numbers `[contributors, label, meet]`) with a
//! receipt, and a stop is never refused. Without a probe, or with an empty
//! label, nothing changes.
//!
//! # Storage and network envelopes
//!
//! Two more kinds are held to the Domain's `[envelope.NAME]` row of the signed
//! topology, the row of the scheduler class the Domain's task was seeded from:
//! [`KIND_STORAGE_DELETE`] (row kind `delete`) and [`KIND_NET_EGRESS`] (row
//! kind `egress`). The device layer that owns the effect asks the gate before
//! it acts, through a hook the kernel installs (`azos_fs`'s delete gate, the
//! socket layer's egress gate; `gate::install`), so those crates do not
//! depend on this one.
//!
//! * `storage_delete`: `subject` is the op (`azos_common::envelope::DeleteOp`:
//!   a truncate to below the file's size, a rename over an existing file, an
//!   unlink, the drop of an azvol snapshot), `a0` the volume (the VFS mount
//!   index, or the first four bytes of a bare azvol's uuid).
//! * `net_egress`: the Domain's first packet to a destination that is not this
//!   node, by connect, or by `sendto` to a destination the socket has not yet
//!   cleared (the socket layer caches that per socket). `subject` is the
//!   destination port, `a0` the address (IPv4; IPv6 its last four bytes), `a1`
//!   the destination class (`azos_common::envelope::DestClass`). It is the
//!   first packet the Domain starts: the replies of an accepted TCP stream
//!   are not gated.
//!
//! The row's level is a ceiling per op and per class
//! (`DeleteOp::permitted`, `DestClass::permitted`); the provenance meet
//! applies to them too, the more restrictive of the two deciding. A refusal is
//! `Rule::EnvelopeDelete` or `Rule::EnvelopeEgress` (numbers
//! `[op, volume, level]` and `[dest, class, level]`) with a receipt, or
//! `Rule::ProvenanceMeet` when the meet is the binding limit. The probe
//! ([`set_envelope_probe`]) answers [`ENVELOPE_FULL`] for a Domain with no
//! row, a task seeded from no row, or no topology, so the kernel's own work
//! (OTA, package apply, the log's rotation) and every image whose rows say
//! `full` behave as before.
//!
//! **Cost.** A delete or egress held by no envelope (level `full`, no meet)
//! adds the probe and nothing else: no record, no ring slot, so a full ring
//! cannot refuse an unlink on a dev image. An effect held by a restriction
//! that the restriction lets through takes the ordinary reversible path: its
//! record is committed first, and a ring at its limit refuses it
//! ([`Why::RingFull`]), as for any reversible effect.
//!
//! # Configuration, update and real-time-time envelopes
//!
//! Three more kinds are held to a row the same way, from the sites that
//! cannot depend on this crate (`azos_common::envelope::asked`, installed by
//! `envelope.rs`):
//!
//! * [`KIND_CONFIG_WRITE`] (row kind `config`): a write of a configuration key.
//!   `subject` is the op (`ConfigOp`: a tuning key, a key that arms or disarms
//!   a guard, a key that opens a way in or changes what boots), `a0` and `a1`
//!   the first eight bytes of the key.
//! * [`KIND_OTA_APPLY`] (row kind `ota`): a step of applying an update,
//!   staging into the inactive slot or switching the boot record to it
//!   (`OtaOp`). `subject` is the op, `a0` the slot.
//! * [`KIND_RT_TIME`] (row kind `rt_time`): a real-time reservation
//!   (`rt::reserve`). `a0` is its density in parts per million of a hart; the
//!   row's level is the most one reservation may take
//!   (`azos_common::envelope::RT_CEILING_PPM`).
//!
//! A refusal is `Rule::EnvelopeConfig`, `Rule::EnvelopeOta` or
//! `Rule::EnvelopeRtTime` (numbers `[op, key, level]`, `[op, slot, level]` and
//! `[asked_ppm, ceiling_ppm, level]`) with a receipt, or `Rule::ProvenanceMeet`
//! when the data's meet is the binding limit. Cost and the `full` fast path are
//! the delete and egress kinds'.
//!
//! # The receipt
//!
//! A refusal is a decision record (`azos_decision`; `Rule::EffectRecord` for a
//! full ring or watch table, see [`Why`] for the others) and its id is the
//! receipt: `why <id>` shows the effect, the reason and how many records were
//! queued. The refusal path and the B2 miss and compensation paths
//! ([`crate::safe_state`]) are the only places that write a decision record;
//! the issue path writes one ring record and nothing else.
//!
//! # Cost on the issue path
//!
//! A reversible effect adds to the device op: one clock read, a 32-byte encode,
//! a preemption-off section around one compare-and-swap of the ring head, five
//! stores (four data words, one release), one `fetch_max` (the pin), and, past
//! the flush watermark only, a wake of the log flusher. No lock, no I/O, no
//! allocation. Kconfig `EFFECT_WRITE_AHEAD` off: the gate is not installed and
//! the op pays none of it.
//!
//! A reversible effect with a declared deadline adds the watch ([`crate::safe_state`]):
//! two clock reads, one compare-and-swap to claim a slot and one to release
//! it, four stores. Its admission is two loads and a compare. A stop pays
//! none of it but one load (the held mask) after its op.

#[cfg(not(feature = "effect-issue-before-commit-canary"))]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use crate::logger::{self, LOG_PAYLOAD_BYTES};
use crate::safe_state;
#[cfg(not(feature = "effect-issue-before-commit-canary"))]
use crate::logger::EffectCommit;

/// Effect kind: one wheel of the drivetrain (`motor_host.rs`).
pub const KIND_MOTOR: u8 = 1;

// The SoC resource frameworks (`azos_soc`): every clock, reset, rail, pin-mux
// and power-domain change is an effect of one of these kinds. The numbers are
// reserved here and equal `azos_soc::effect::KIND_*` (the kernel's adapter,
// `kernel/src/boot/soc.rs`, asserts it at compile time). For them `subject` is
// the framework's wire word (provider index in the high byte, op in the low
// byte), `a0` the clock, reset or domain id and `a1` the new value saturated
// to 32 bits (`azos_soc::effect::Effect::wire`). None has a deadline, a safe
// state or an inverse op: they are recorded, not watched.
/// Effect kind: a clock gate or rate.
pub const KIND_CLOCK: u8 = 2;
/// Effect kind: a reset line.
pub const KIND_RESET: u8 = 3;
/// Effect kind: a regulator rail.
pub const KIND_REGULATOR: u8 = 4;
/// Effect kind: a pin mux or bias.
pub const KIND_PINCTRL: u8 = 5;
/// Effect kind: a power domain.
pub const KIND_POWER_DOMAIN: u8 = 6;

/// Effect kind: a delete on a volume (an unlink, a rename over a file, a cut
/// below a file's size, the drop of a snapshot). Held to the Domain's `delete`
/// envelope row; see the module docs.
pub const KIND_STORAGE_DELETE: u8 = 7;
/// Effect kind: a Domain's first packet to a destination that is not this node.
/// Held to the Domain's `egress` envelope row; see the module docs.
pub const KIND_NET_EGRESS: u8 = 8;

/// Effect kind: a write of a configuration key. Held to the Domain's `config`
/// envelope row; see the module docs.
pub const KIND_CONFIG_WRITE: u8 = 9;
/// Effect kind: a step of applying an update (stage, switch). Held to the
/// Domain's `ota` envelope row; see the module docs.
pub const KIND_OTA_APPLY: u8 = 10;
/// Effect kind: a real-time reservation. Held to the Domain's `rt_time`
/// envelope row; see the module docs.
pub const KIND_RT_TIME: u8 = 11;

/// The envelope level that holds nothing back (`Envelope::Full`).
pub const ENVELOPE_FULL: u8 = 0;

/// The most a [`KIND_MOTOR`] effect's duty percent (`a1`) may be at each
/// envelope level, `Full` to `Contained`. These are the degrade policy's
/// speed ceilings (`azos_degrade_policy`: 100, 70, 30, 0 percent), kept here
/// as numbers because the gate is generic and links no robot domain.
pub const ENVELOPE_DUTY_CAP_PCT: [u32; 4] = [100, 70, 30, 0];

/// The seam to the kernel's provenance tables: for a task, the label of the
/// data it works on and the meet of the envelopes of the kinds in it
/// (`azos_ipc::endpoint::label::provenance_of`).
pub type ProvenanceProbe = fn(tid: u32) -> (u32, u8);

azos_common::ro_hook! {
    static PROVENANCE: ProvenanceProbe;
}

/// Install the provenance probe (boot, once). Unset, no effect is held to
/// anything but its own record and deadline.
pub fn set_provenance_probe(f: ProvenanceProbe) {
    PROVENANCE.set(f);
}

/// The seam to the signed topology's `[envelope.NAME]` rows: the level of the
/// row that holds effects of `kind` ([`KIND_STORAGE_DELETE`] or
/// [`KIND_NET_EGRESS`], [`KIND_CONFIG_WRITE`], [`KIND_OTA_APPLY`] or
/// [`KIND_RT_TIME`]) for the Domain `tid` runs in, [`ENVELOPE_FULL`] when
/// there is no such row. Installed by the kernel (`gate::install`); this file
/// links no topology.
pub type EnvelopeProbe = fn(tid: u32, kind: u8) -> u8;

azos_common::ro_hook! {
    static ENVELOPE: EnvelopeProbe;
}

/// Install the envelope probe (boot, once). Unset, no storage delete or
/// network egress is held to a row.
pub fn set_envelope_probe(f: EnvelopeProbe) {
    ENVELOPE.set(f);
}

/// Host tests: forget the installed envelope probe (hooks are process-wide
/// there).
#[cfg(not(target_os = "none"))]
pub fn clear_envelope_probe_for_test() {
    ENVELOPE.clear_for_tests();
}

/// Is `kind` one of those held to an `[envelope.NAME]` row?
const fn row_kind(kind: u8) -> bool {
    matches!(kind, KIND_STORAGE_DELETE | KIND_NET_EGRESS | KIND_CONFIG_WRITE | KIND_OTA_APPLY | KIND_RT_TIME)
}

/// The level of the Domain's row for `e`: [`ENVELOPE_FULL`] for a kind no row
/// holds, with no probe, or when the row-canary asks the gate to ignore rows.
fn row_level(e: &Effect) -> u8 {
    #[cfg(feature = "envelope-row-canary")]
    {
        let _ = e;
        return ENVELOPE_FULL;
    }
    #[cfg(not(feature = "envelope-row-canary"))]
    {
        if !row_kind(e.kind) {
            return ENVELOPE_FULL;
        }
        match ENVELOPE.get() {
            Some(f) => f(e.tid, e.kind),
            None => ENVELOPE_FULL,
        }
    }
}

/// Does the envelope level `meet` let `e` through? A motor effect fits when
/// its duty is at or below the level's ceiling; a delete when its op is at or
/// below the level's most destructive op, a first packet when its destination
/// class is within the level's reach (`azos_common::envelope`); every other
/// kind when the level is below `Contained`.
fn within(e: &Effect, meet: u8) -> bool {
    use azos_common::envelope::{rt_permitted, ConfigOp, DeleteOp, DestClass, OtaOp};
    let level = (meet as usize).min(ENVELOPE_DUTY_CAP_PCT.len() - 1);
    match e.kind {
        KIND_MOTOR => e.a1 <= ENVELOPE_DUTY_CAP_PCT[level],
        KIND_STORAGE_DELETE => DeleteOp::from_u8(e.subject as u8).is_some_and(|op| op.permitted(level as u8)),
        KIND_NET_EGRESS => DestClass::from_u8(e.a1 as u8).is_some_and(|c| c.permitted(level as u8)),
        KIND_CONFIG_WRITE => ConfigOp::from_u8(e.subject as u8).is_some_and(|op| op.permitted(level as u8)),
        KIND_OTA_APPLY => OtaOp::from_u8(e.subject as u8).is_some_and(|op| op.permitted(level as u8)),
        KIND_RT_TIME => rt_permitted(level as u8, e.a0),
        _ => level < ENVELOPE_DUTY_CAP_PCT.len() - 1,
    }
}

/// How much an effect may be refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    /// Toward the device's safe state; never refused.
    Safe = 0,
    /// Undoable by a later effect; refused when it cannot be recorded.
    Reversible = 1,
}

/// One physical effect, as the record describes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Effect {
    pub kind: u8,
    pub class: Class,
    /// The device: the wheel for [`KIND_MOTOR`].
    pub subject: u16,
    /// The task that asked.
    pub tid: u32,
    /// The kind's two arguments (a motor: direction and duty percent).
    pub a0: u32,
    pub a1: u32,
}

impl Effect {
    /// The 20-byte payload of the effect's [`logger::LOG_FLAG_EFFECT`] record:
    /// kind, class, subject (u16), tid, `a0`, `a1`, four reserved zero bytes.
    pub fn payload(&self) -> [u8; LOG_PAYLOAD_BYTES] {
        let mut p = [0u8; LOG_PAYLOAD_BYTES];
        p[0] = self.kind;
        p[1] = self.class as u8;
        p[2..4].copy_from_slice(&self.subject.to_le_bytes());
        p[4..8].copy_from_slice(&self.tid.to_le_bytes());
        p[8..12].copy_from_slice(&self.a0.to_le_bytes());
        p[12..16].copy_from_slice(&self.a1.to_le_bytes());
        p
    }

    /// The reader's half of [`Effect::payload`]: `None` for a class byte this
    /// build does not know.
    pub fn from_payload(p: &[u8; LOG_PAYLOAD_BYTES]) -> Option<Effect> {
        let class = match p[1] {
            0 => Class::Safe,
            1 => Class::Reversible,
            _ => return None,
        };
        let word = |o: usize| u32::from_le_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]]);
        Some(Effect {
            kind: p[0],
            class,
            subject: u16::from_le_bytes([p[2], p[3]]),
            tid: word(4),
            a0: word(8),
            a1: word(12),
        })
    }
}

/// What an effect declares about its own timing and its device's inverse ops
/// (nothing of it is in the record's payload). Resolved by the effect's host
/// (`motor_host.rs`) from the op's IDL contract and the topology's
/// `[device.*]` row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Timing {
    /// The op's `#[deadline_ns]`: the longest from request to commit.
    /// 0: none declared, the effect is neither checked nor watched.
    pub deadline_ns: u64,
    /// The driver's placement latency: what one call costs from the caller's
    /// side in the host the driver is placed in.
    pub placement_ns: u64,
    /// The device row's `commit_ns`: accepted command to effect committed.
    pub commit_ns: u64,
    /// The op that drives the device to its safe state (a code of the kind's
    /// driver, `safe_state::register`); 0: none, the effect cannot be watched.
    pub safe_op: u8,
    /// The op that undoes this effect; 0: none declared.
    pub compensate_op: u8,
}

impl Timing {
    /// An effect that declares nothing.
    pub const NONE: Timing = Timing { deadline_ns: 0, placement_ns: 0, commit_ns: 0, safe_op: 0, compensate_op: 0 };

    /// What the device needs between the request and the effect.
    pub const fn needed_ns(&self) -> u64 {
        self.placement_ns.saturating_add(self.commit_ns)
    }

    /// Is the effect watched for a missed deadline?
    const fn watched(&self) -> bool {
        self.deadline_ns != 0 && self.safe_op != 0
    }
}

/// Why an effect was refused (the second number of its decision record).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Why {
    /// The recorder's ring is at its effect limit.
    RingFull = 1,
    /// The device cannot commit within the effect's deadline: placement
    /// latency plus `commit_ns` is longer (`Rule::EffectDeadline`).
    Deadline = 2,
    /// The device missed an earlier deadline and sits in its safe state until
    /// a stop lands (`Rule::SafeState`).
    Held = 3,
    /// The watch table is full, or the device is outside its range: an
    /// effect that cannot be watched is not issued.
    NoWatch = 4,
    /// The meet of the envelopes of the principals the effect's data passed
    /// through does not allow it (`Rule::ProvenanceMeet`).
    Provenance = 5,
    /// The Domain's `[envelope.NAME]` row for the effect's kind does not allow
    /// it (`Rule::EnvelopeDelete`, `Rule::EnvelopeEgress`, `Rule::EnvelopeConfig`,
    /// `Rule::EnvelopeOta`, `Rule::EnvelopeRtTime`).
    Envelope = 6,
}

/// A refused effect's receipt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refusal {
    /// The refusal's decision record id (`Rule::EffectRecord`,
    /// `Rule::EffectDeadline`, `Rule::SafeState`, `Rule::ProvenanceMeet` or
    /// one of the five `Rule::Envelope*` rules, by [`Why`]); 0 when
    /// decision records are off in this build (the refusal still happened).
    pub receipt: u64,
    pub why: Why,
}

/// Effects issued without a record on the ring since boot: a safe effect on a
/// ring whose tail is pinned, or any effect with the recorder off. The target
/// is 0 in a normal run, so each power of two is a warning.
#[cfg(not(feature = "effect-issue-before-commit-canary"))]
static UNRECORDED: AtomicU32 = AtomicU32::new(0);

#[cfg(not(feature = "effect-issue-before-commit-canary"))]
fn unrecorded(e: &Effect) {
    let n = UNRECORDED.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        azos_drv_sys::kwarn!(
            "[SAFETY] effect gate: {} effect(s) issued without a record (last: kind {} wheel {} tid {})",
            n, e.kind, e.subject, e.tid);
    }
}

#[cfg(not(feature = "effect-issue-before-commit-canary"))]
fn refuse(e: &Effect, t: &Timing, why: Why) -> Refusal {
    use azos_decision::{record_receipt, Rule, Verdict};
    let effect = (e.kind as u64) << 8 | e.class as u64;
    let receipt = match why {
        Why::Deadline => record_receipt(
            Rule::EffectDeadline, Verdict::Refuse, e.tid, [effect, t.deadline_ns, t.needed_ns()]),
        Why::Held => safe_state::refuse_held(e),
        Why::Provenance => {
            // The probe answered a moment ago; asking again for the numbers
            // keeps `refuse` the one place a refusal is written.
            let (label, meet) = provenance(e.tid);
            record_receipt(
                Rule::ProvenanceMeet, Verdict::Refuse, e.tid,
                [label.count_ones() as u64, label as u64, meet as u64])
        }
        Why::Envelope => {
            let level = row_level(e) as u64;
            match e.kind {
                KIND_STORAGE_DELETE => {
                    record_receipt(Rule::EnvelopeDelete, Verdict::Refuse, e.tid, [e.subject as u64, e.a0 as u64, level])
                }
                KIND_CONFIG_WRITE => record_receipt(
                    Rule::EnvelopeConfig, Verdict::Refuse, e.tid,
                    [e.subject as u64, e.a0 as u64 | (e.a1 as u64) << 32, level]),
                KIND_OTA_APPLY => {
                    record_receipt(Rule::EnvelopeOta, Verdict::Refuse, e.tid, [e.subject as u64, e.a0 as u64, level])
                }
                KIND_RT_TIME => record_receipt(
                    Rule::EnvelopeRtTime, Verdict::Refuse, e.tid,
                    [e.a0 as u64, azos_common::envelope::rt_ceiling_ppm(level as u8) as u64, level]),
                _ => record_receipt(Rule::EnvelopeEgress, Verdict::Refuse, e.tid, [e.a0 as u64, e.a1 as u64, level]),
            }
        }
        Why::RingFull | Why::NoWatch => record_receipt(
            Rule::EffectRecord, Verdict::Refuse, e.tid, [effect, why as u64, logger::logger_ring_len() as u64]),
    };
    Refusal { receipt, why }
}

/// The label of the data behind `e` and the meet of its envelopes; `(0, 0)`
/// without a probe.
fn provenance(tid: u32) -> (u32, u8) {
    match PROVENANCE.get() {
        Some(f) => f(tid),
        None => (0, 0),
    }
}

/// Commit `e`'s record, or refuse it, for a device write the CALLER runs next:
/// [`issue`] with an op that does nothing. A framework manager that owns its
/// register write (`azos_soc`) cannot hand it over as a closure across its
/// own sink trait, so the order is kept by the manager: it calls this, and
/// only on `Ok` does it write. A [`Class::Safe`] effect is never refused.
///
/// # What is and is not enforced here
///
/// This function enforces that the record is on the ring (or the effect is
/// refused) when it returns; it cannot see the write that follows. That the
/// write does not come first is the manager's property, and it is tested there
/// (`tests/host/soc-tests`, the rows that go red under the feature
/// `effect-after-write-canary`, which makes every manager write first).
///
/// # No safe-state entry can alias these kinds
///
/// A [`Class::Reversible`] effect is refused with [`Why::Held`] when
/// `safe_state::held(kind, subject)` is set. For the SoC kinds `subject` is the
/// framework's wire word (provider index in the high byte, op in the low one),
/// a different space from the motor's wheel numbers, so a held bit of that
/// space would refuse a clock change for the wrong reason. It cannot exist:
/// the safe-state tables are sized to the kinds that have a safe state
/// (`safe_state::MAX_KINDS`, which is `KIND_MOTOR + 1` and checked at compile
/// time to be below every SoC kind), so `held` is false and `can_drive` is
/// false for kinds 2..6, and no watch is ever armed for them.
pub fn record(e: &Effect) -> Result<(), Refusal> {
    issue(e, &Timing::NONE, || ((), true))
}

/// Issue `e`: commit its record, then run `op` (the device write) and return
/// its result; or refuse, without running `op`.
///
/// `op` returns its result and whether the device took the effect (`false`:
/// it failed). A reversible effect whose op failed is undone by
/// `t.compensate_op`. Order, for a reversible effect: a held device is
/// refused, then the deadline admission, then the watch is armed, then the
/// record is committed, then `op` runs, then the watch is taken down (or the
/// miss handled) and a failure compensated.
pub fn issue<R>(e: &Effect, t: &Timing, op: impl FnOnce() -> (R, bool)) -> Result<R, Refusal> {
    // Gate canary (host suites only, feature `effect-issue-before-commit-canary`):
    // the op first, the record after. `actuation-tests` must go red under it.
    #[cfg(feature = "effect-issue-before-commit-canary")]
    {
        let (r, _) = op();
        let _ = logger::commit_effect_record(e.payload(), false);
        let _ = t;
        return Ok(r);
    }
    #[cfg(not(feature = "effect-issue-before-commit-canary"))]
    {
        let payload = e.payload();
        match e.class {
            Class::Safe => {
                if !matches!(logger::commit_effect_record(payload, false), EffectCommit::Committed(_)) {
                    unrecorded(e);
                }
                // A stop never lifts a held device (`safe_state`): only the
                // operator's release does, in this gate and in the device
                // layer, where a stop at the held value passes.
                let (r, _) = op();
                Ok(r)
            }
            Class::Reversible => {
                let (_, meet) = provenance(e.tid);
                // The Domain's own row (storage delete, network egress) and
                // the data's provenance hold an effect together: the more
                // restrictive level decides, and a tie is the data's.
                let row = row_level(e);
                let level = meet.max(row);
                if level != 0 && !within(e, level) {
                    return Err(refuse(e, t, if meet >= row { Why::Provenance } else { Why::Envelope }));
                }
                if row_kind(e.kind) && level == ENVELOPE_FULL {
                    // Nothing holds it: not recorded, not refusable.
                    let (r, _) = op();
                    return Ok(r);
                }
                if safe_state::held(e.kind, e.subject) {
                    return Err(refuse(e, t, Why::Held));
                }
                if t.deadline_ns != 0 && t.needed_ns() > t.deadline_ns {
                    return Err(refuse(e, t, Why::Deadline));
                }
                let ticket = if t.watched() && safe_state::can_drive(e.kind) {
                    match safe_state::arm(e, t.deadline_ns, t.safe_op) {
                        Some(k) => Some(k),
                        None => return Err(refuse(e, t, Why::NoWatch)),
                    }
                } else {
                    None
                };
                match logger::commit_effect_record(payload, true) {
                    EffectCommit::Committed(_) => {}
                    EffectCommit::Full => {
                        if let Some(k) = ticket {
                            safe_state::cancel(k);
                        }
                        return Err(refuse(e, t, Why::RingFull));
                    }
                    EffectCommit::Inactive => unrecorded(e),
                }
                let (r, ok) = op();
                if let Some(k) = ticket {
                    safe_state::complete(k);
                }
                if !ok {
                    safe_state::compensate(e, t.compensate_op);
                }
                Ok(r)
            }
        }
    }
}
