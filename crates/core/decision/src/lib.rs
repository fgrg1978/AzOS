// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Explainable decision records (Kconfig `DECISION_RECORDS_DEV`, kernel cargo
//! feature `decisions`) and durable refusal receipts (Kconfig
//! `DECISION_REFUSALS_DURABLE`, kernel cargo feature `decisions-durable`).
//!
//! An admission, placement or refusal path writes one [`Record`]: the rule
//! that decided ([`Rule`]), the verdict, the subject (a task id, a topology
//! row, a CPU count), up to three numbers the rule compared, and, from the
//! rule's table entry, the alternative it rejected. The kernel renders the
//! ring at `/proc/decisions`, one line per record, oldest first.
//!
//! The ring holds `DECISION_RECORDS_ENTRIES` records; the oldest is
//! overwritten. It is lock-free so the wake path, which runs with the
//! scheduler's locks held and interrupts masked, can write to it: a writer
//! claims a sequence number, clears the slot's sequence word, writes the
//! fields and publishes the sequence with Release; a reader takes a slot
//! only if its sequence reads the same before and after the fields. Records
//! carry numbers only (no pointers), so a torn read is dropped, never
//! misread.
//!
//! Off (feature `on` absent, every deployment profile): [`record`] is empty
//! and the ring is not linked. On: about 40 instructions and six stores
//! per record (the last is the clock stamp), `DECISION_RECORDS_ENTRIES` x
//! 48 bytes of `.bss`.
//!
//! Refusals have a second, independent path. With the `durable` feature
//! (Kconfig `DECISION_REFUSALS_DURABLE`, on in every preset) a record whose
//! verdict is [`Verdict::Refuse`] is also handed to a sink the kernel
//! installs ([`set_durable_sink`]); the sink writes it to the flight
//! recorder, which survives the reset. The ring and the sink do not depend
//! on each other: the ring off and the sink on still leaves every refusal's
//! receipt on the medium, and the sink off leaves the ring as it was. The
//! sink is a function pointer because the recorder (`azos_actuation`) sits
//! above this crate: the scheduler's refusal path cannot name it.
//!
//! A sink may block on the medium, so it must be a function that defers
//! when the caller is real-time: the recorder's `log_*_durable` entry points
//! put the record on the logger's ring and wake the log flusher instead of
//! flushing in the caller (`logger_flush`'s RT rule). A `Refuse` always goes
//! to the sink. A `Deny` (capability denial) goes there too, but it can
//! arrive per syscall, so it passes a token bucket per subject first
//! (Kconfig `DECISION_DENY_DURABLE_PER_SEC`, `DECISION_DENY_DURABLE_BURST`;
//! the `deny` module). A denial the bucket drops is counted, and the count
//! rides in the third number of the next denial record that is written
//! (`dropped`, printed when not zero), durable and ring alike; the total
//! since boot is [`deny_dropped_total`], which `/proc/decisions` shows.
//!
//! # Ids, the clock, the journal and the query
//!
//! A record that is stored anywhere (the ring, or the durable path) claims a
//! sequence number first: its **id**, unique since boot, ring on or off. A
//! record that reaches the durable path is also kept, in full
//! ([`ProvenanceRecord`]), in a small RAM journal of `DECISION_JOURNAL_ENTRIES`
//! slots (`journal`), so a `why <id>` or a [`query`] can name it whether or not
//! the ring is built: the journal is written exactly where the durable sink is
//! called, and it is empty (never linked) without `durable`. Each stored
//! record is stamped with the kernel clock ([`set_clock`]); [`lookup`] and
//! [`query`] read the ring first and the journal for what the ring has
//! overwritten or never held. After a reset the ids restart; the recorder's
//! receipts (compact form, `prov`) carry the recorder's own timestamp.
//!
//! The `Decisions` interface (`userspace/lib/decisions`, `#[azos_interface]`)
//! is this module's [`Filter`], [`query`] and [`lookup`] over an endpoint.
#![no_std]

mod deny;
mod journal;
mod query;

mod prov;
pub use prov::{
    compact_base, compact_ext, warrant_ref, ProvError, ProvenanceRecord, COMPACT_BASE_CODE, COMPACT_BYTES,
    COMPACT_EXT_CODE, SIZE as PROVENANCE_SIZE, WORDS as PROVENANCE_WORDS,
};
pub use query::{lookup, query, Filter};

use core::sync::atomic::{fence, AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Built in.
pub const ON: bool = cfg!(feature = "on");

/// The durable refusal sink is built in (Kconfig `DECISION_REFUSALS_DURABLE`).
pub const DURABLE: bool = cfg!(feature = "durable");

/// Ring depth (Kconfig `DECISION_RECORDS_ENTRIES`).
pub const ENTRIES: usize = azos_limits::DECISION_RECORDS_ENTRIES as usize;
const _: () = assert!(ENTRIES >= 8);

/// Journal depth (Kconfig `DECISION_JOURNAL_ENTRIES`); read only with
/// [`DURABLE`].
pub const JOURNAL_ENTRIES: usize = azos_limits::DECISION_JOURNAL_ENTRIES as usize;
const _: () = assert!(JOURNAL_ENTRIES >= 8);

/// Names of the reasons a run-time reservation is refused for, by code
/// (`azos_sched::rt_core::Refusal::code`, 0 = none; a host test in
/// `sched-policy-tests` holds the two tables together). The third number of
/// such a refusal carries the code in bits 32..40 ([`prov`](crate)'s chain).
pub const REFUSAL_REASONS: [&str; 7] =
    ["none", "malformed", "no-room", "band-cap", "busy", "levels", "class-off"];

/// The rules that write a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Rule {
    /// Boot deadline admission of the topology's real-time rows.
    DeadlineAdmission = 0,
    /// The real-time band cap (`RT_BAND_CAP_PCT`) on one CPU.
    RtBandCap = 1,
    /// Boot memory admission of the topology's ring-3 rows.
    MemoryAdmission = 2,
    /// A woken, unpinned task placed on a CPU other than its last one.
    WakePlacement = 3,
    /// A typed capability check refused a handle.
    CapDenial = 4,
    /// A v2 IPC call whose deadline had already passed, refused before it
    /// was queued.
    DeadlineExpired = 5,
    /// A ring-3 task's locked atomic crossed a cache line (x86_64 split-lock
    /// detection, Kconfig `X86_SPLIT_LOCK`) and the task was killed.
    SplitLock = 6,
    /// A warrant was derived: a capability slot minted from another's
    /// (`cap_store`'s dup transfer, `mint_badged`), rights attenuated.
    CapDerive = 7,
    /// A warrant was revoked, with every descendant of it (`cap_store`).
    CapRevoke = 8,
    /// A topology refused because a row holds a grant a `neverallow` rule
    /// forbids (`azos_topology::neverallow`), at build time, in the signed
    /// file's admission or in the built-in topology's.
    Neverallow = 9,
    /// The hardware bus detected a device a driver table names and did not
    /// bind it: the policy is topology-only and no `[device.*]` row admits
    /// it, or a row refuses it. "Detected, not admitted."
    DeviceAdmission = 10,
    /// A reservation that serves interrupt lines ran out of budget: its lines
    /// are masked until it is replenished (`azos_ipc::irq_bind`).
    IrqBudget = 11,
    /// A driver changed host, or was refused a move (`azos_topology::placement`):
    /// the kernel host to ring 3 after a fault, ring 3 to the kernel host
    /// when its measured call cost broke the row's admitted budget.
    Placement = 12,
    /// A signed application package was admitted (its rows join the topology
    /// at the next boot) or refused (`azos_pkg`: the installer service writes
    /// the receipt, the boot-time apply repeats the decision).
    PackageInstall = 13,
}

/// The verdict of a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Verdict {
    Admit = 0,
    Refuse = 1,
    Place = 2,
    Deny = 3,
}
/// The verdicts' names, by [`Verdict`] index.
pub const VERDICTS: [&str; 4] = ["admit", "refuse", "place", "deny"];

/// One rule's names: what it is called, what its three numbers are, and the
/// alternative it rejected for each verdict it can give.
pub struct RuleInfo {
    pub name: &'static str,
    pub subject: &'static str,
    pub fields: [&'static str; 3],
    /// Rejected alternative when the verdict is Admit / Place.
    pub rejected_if_yes: &'static str,
    /// Rejected alternative when the verdict is Refuse / Deny.
    pub rejected_if_no: &'static str,
}

/// The table, by [`Rule`] index.
pub const RULES: [RuleInfo; 14] = [
    RuleInfo {
        // Two writers: the boot admission (subject = cpus; placed, rows, 0)
        // and the run-time `rt::reserve` refusal (subject = tid; runtime_us,
        // period_us, reason << 32 | available_us), the second after the `|`.
        name: "deadline-admission",
        subject: "cpus|tid",
        fields: ["placed|runtime_us", "rows|period_us", "-|reason<<32+available_us"],
        rejected_if_yes: "refuse the topology: no CPU's density bound is exceeded",
        rejected_if_no: "run the rows (or the task): some row cannot meet its deadline on these CPUs",
    },
    RuleInfo {
        name: "rt-band-cap",
        subject: "cpus",
        fields: ["placed", "cap_pct", "-"],
        rejected_if_yes: "refuse the topology: every CPU's band stays under the cap",
        rejected_if_no: "run the rows: the band's rows on one CPU exceed the cap",
    },
    RuleInfo {
        name: "memory-admission",
        subject: "rows",
        fields: ["need_pages", "free_pages", "reserve_pages"],
        rejected_if_yes: "refuse the topology: need fits in free",
        rejected_if_no: "run the rows and let one fault at run time: need exceeds free",
    },
    RuleInfo {
        name: "wake-placement",
        subject: "tid",
        fields: ["cpu", "last_cpu", "prio"],
        rejected_if_yes: "stay on last_cpu: another CPU ranked better (blocking, then load)",
        rejected_if_no: "-",
    },
    RuleInfo {
        name: "cap-denial",
        subject: "tid",
        // `?dropped` prints only when not zero: the durable records the rate
        // limit dropped since the last one that was written.
        fields: ["kind", "reason", "?dropped"],
        rejected_if_yes: "-",
        rejected_if_no: "grant: the handle is stale (1), of another kind (2), lacks the rights (3) or names a revoked or expired warrant (6), or the caller is real-time and the endpoint a proxy (7)",
    },
    RuleInfo {
        name: "deadline-expired",
        subject: "tid",
        fields: ["deadline_ns", "now_ns", "clock"],
        rejected_if_yes: "-",
        rejected_if_no: "queue the call: the server would work on a request whose caller's deadline is already past",
    },
    RuleInfo {
        name: "split-lock",
        subject: "tid",
        fields: ["rip", "cpu", "-"],
        rejected_if_yes: "-",
        rejected_if_no: "let the task run: its locked access crosses a cache line, a bus lock that stalls every other core (RT jitter)",
    },
    RuleInfo {
        // `cap_slot` / `parent_cap` are the packed warrant references
        // `domain_key << 32 | slot << 16 | generation`; the full-form record
        // carries them as the provenance fields (`prov::ProvenanceRecord`).
        name: "cap-derive",
        subject: "domain",
        fields: ["-", "-", "expiry_ns"],
        rejected_if_yes: "leave the copy outside the tree: revoking its source could not reach it",
        rejected_if_no: "-",
    },
    RuleInfo {
        name: "cap-revoke",
        subject: "domain",
        fields: ["-", "-", "descendant"],
        rejected_if_yes: "-",
        rejected_if_no: "revoke the one handle: the capabilities derived from it would outlive it",
    },
    RuleInfo {
        // The subject is the topology row (its index); `rule` is the rule's
        // index in `azos_topology::neverallow::RULES`, `kind` the
        // `CapKind` code of the grant it matched (0 = none: a rule about the
        // row, not a grant), `grant` the grant's index in the row.
        name: "neverallow",
        subject: "row",
        fields: ["rule", "kind", "grant"],
        rejected_if_yes: "-",
        rejected_if_no: "install the topology: a signed row holds an authority a neverallow rule forbids, whatever the file says",
    },
    RuleInfo {
        // The subject is the bus handle (`azos_hwbus::Handle`). `bus` is 0 PCI,
        // 1 device tree, 2 virtio-mmio, 3 platform; `id` the device's
        // identity (PCI vendor << 16 | device, the virtio id, the FNV-1a hash
        // of the first `compatible`); `why` 1 the policy has no row for it,
        // 2 a row refuses it.
        name: "device-admission",
        subject: "device",
        fields: ["bus", "id", "why"],
        rejected_if_yes: "-",
        rejected_if_no: "bind the driver the table names: the signed topology does not admit this device, so it is left alone",
    },
    RuleInfo {
        // The subject is the handler's task; `line` the first line of its that
        // the overrun reached, `masked` how many were idle and masked now
        // (the others were masked by a delivery and are held at their ACK),
        // `overruns` the count since boot.
        name: "irq-budget",
        subject: "tid",
        fields: ["line", "masked", "overruns"],
        rejected_if_yes: "-",
        rejected_if_no: "keep delivering: an interrupt storm would run the handler past its admitted budget and take the time of the tasks admitted beside it",
    },
    RuleInfo {
        // The subject is the topology row (its index). `move` is
        // `cause << 24 | reason << 16 | from << 8 | to`
        // (`azos_topology::placement::Move::pack`: hosts 1 = kernel, 2 = ring
        // 3; reasons 1 = fault, 2 = deadline; cause 0 for a move made, else
        // why it was refused). A refusal names in `limit_ns` what the move
        // would have had to fit: the counter-offer.
        name: "placement",
        subject: "row",
        fields: ["move", "measured_ns", "limit_ns"],
        rejected_if_yes: "leave the driver on its host: it faulted there (to ring 3), or its measured call cost broke the row's admitted budget (to the kernel)",
        rejected_if_no: "move the driver: the other host's measured cost does not fit the row's admitted budget, or the row does not allow the move (not stateless, or flapping)",
    },
    RuleInfo {
        // The subject is the number of rows the package adds; the record's
        // `image_hash_prefix` is the first 8 bytes of the package id
        // (`azos_pkg::Package::id`), `topology_row_id` the first row it adds.
        // `signer` is the signer's index in the topology plus one (0: none
        // matched), `reason` the refusal's code (`azos_pkg::Refusal::code`,
        // 0: admitted).
        name: "package-install",
        subject: "rows",
        fields: ["images", "signer", "reason"],
        rejected_if_yes: "run the package's programs as they are: unsigned or under any author's name, with whatever authority their own manifest asks for, instead of inside the ceiling the device gives that signer",
        rejected_if_no: "add the package's rows: it is unsigned, signed by a key the device does not admit, asks for more than its signer's ceiling, or the merged topology breaks a rule",
    },
];

/// A record as read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub rule: u8,
    pub verdict: u8,
    pub subject: u32,
    pub n: [u64; 3],
    /// The clock when it was written, in timebase ticks ([`ticks_to_ns`]);
    /// 0 = no clock was installed.
    pub ts: u64,
}

impl Record {
    pub fn rule_info(&self) -> Option<&'static RuleInfo> {
        RULES.get(self.rule as usize)
    }
    pub fn verdict_name(&self) -> &'static str {
        VERDICTS.get(self.verdict as usize).copied().unwrap_or("?")
    }
    /// The alternative the rule rejected.
    pub fn rejected(&self) -> &'static str {
        match self.rule_info() {
            Some(r) if self.verdict == Verdict::Admit as u8 || self.verdict == Verdict::Place as u8 => r.rejected_if_yes,
            Some(r) => r.rejected_if_no,
            None => "?",
        }
    }
}

struct Slot {
    seq: AtomicU64,
    head: AtomicU64,
    n: [AtomicU64; 3],
    ts: AtomicU64,
}
#[allow(clippy::declare_interior_mutable_const)]
const SLOT: Slot = Slot {
    seq: AtomicU64::new(0),
    head: AtomicU64::new(0),
    n: [const { AtomicU64::new(0) }; 3],
    ts: AtomicU64::new(0),
};
static RING: [Slot; ENTRIES] = [SLOT; ENTRIES];
static SEQ: AtomicU64 = AtomicU64::new(0);
/// Gate canary `canary=decision-skip`: [`record`] writes nothing.
static SKIP: AtomicBool = AtomicBool::new(false);

/// The durable sink: the refusal as a [`ProvenanceRecord`]. 0: none.
static SINK: AtomicUsize = AtomicUsize::new(0);

/// Durable denials per second per subject (Kconfig
/// `DECISION_DENY_DURABLE_PER_SEC`); 0: no durable denial record.
pub const DENY_DURABLE_PER_SEC: u64 = azos_limits::DECISION_DENY_DURABLE_PER_SEC as u64;
/// The bucket depth (Kconfig `DECISION_DENY_DURABLE_BURST`).
pub const DENY_DURABLE_BURST: u64 = azos_limits::DECISION_DENY_DURABLE_BURST as u64;
const _: () = assert!(DENY_DURABLE_BURST >= 1 && DENY_DURABLE_BURST <= 64);
const _: () = assert!(DENY_DURABLE_PER_SEC <= 1000);

/// The kernel clock: `(now, ticks per second)`. The denial buckets refill on
/// it and every stored record is stamped with it.
static CLOCK_NOW: AtomicUsize = AtomicUsize::new(0);
static CLOCK_HZ: AtomicU64 = AtomicU64::new(1);

/// Denials the rate limit has not written since the last record that was.
static DENY_PENDING: AtomicU64 = AtomicU64::new(0);
/// Denials the rate limit dropped since boot.
static DENY_DROPPED: AtomicU64 = AtomicU64::new(0);

/// The buckets, behind a flag: a denial is a slow path, and the update is a
/// few loads and stores.
struct Buckets {
    busy: AtomicBool,
    l:    core::cell::UnsafeCell<deny::Limiter>,
}
// SAFETY: `l` is touched only with `busy` held (`with`).
unsafe impl Sync for Buckets {}
static BUCKETS: Buckets = Buckets { busy: AtomicBool::new(false), l: core::cell::UnsafeCell::new(deny::Limiter::new()) };

impl Buckets {
    fn with<R>(&self, f: impl FnOnce(&mut deny::Limiter) -> R) -> R {
        while self.busy.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: `busy` is held.
        let r = f(unsafe { &mut *self.l.get() });
        self.busy.store(false, Ordering::Release);
        r
    }
}

/// Install the clock (the kernel, at boot, with the timebase): `now` in
/// ticks, `hz` ticks a second. The durable-denial buckets refill on it and
/// every stored record is stamped with it. Without it time stands still at 0,
/// a subject keeps only its burst and records carry no clock.
pub fn set_clock(now: fn() -> u64, hz: u64) {
    CLOCK_HZ.store(hz.max(1), Ordering::Relaxed);
    CLOCK_NOW.store(now as usize, Ordering::Release);
}

pub(crate) fn clock_now() -> u64 {
    let f = CLOCK_NOW.load(Ordering::Acquire);
    if f == 0 {
        return 0;
    }
    // SAFETY: only `set_clock` stores here, and it stores a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute::<usize, _>(f) };
    f()
}

/// Timebase ticks to nanoseconds with the installed clock (0 without one).
pub fn ticks_to_ns(t: u64) -> u64 {
    if CLOCK_NOW.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    ((t as u128 * 1_000_000_000) / CLOCK_HZ.load(Ordering::Relaxed) as u128).min(u64::MAX as u128) as u64
}

/// Denials the rate limit dropped since boot (not written durably).
pub fn deny_dropped_total() -> u64 {
    DENY_DROPPED.load(Ordering::Relaxed)
}

/// May this denial leave a durable record? `Some(owed)`: yes, and `owed` is
/// the number dropped since the last one written, for its third number.
/// `None`: dropped (counted), or no durable path to write to.
#[inline(never)]
fn deny_admit(subject: u32) -> Option<u64> {
    if DENY_DURABLE_PER_SEC == 0 || SINK.load(Ordering::Acquire) == 0 {
        return None;
    }
    let (now, hz) = (clock_now(), CLOCK_HZ.load(Ordering::Relaxed));
    if BUCKETS.with(|l| l.admit(subject, now, DENY_DURABLE_PER_SEC, DENY_DURABLE_BURST, hz)) {
        Some(DENY_PENDING.swap(0, Ordering::AcqRel))
    } else {
        DENY_PENDING.fetch_add(1, Ordering::AcqRel);
        DENY_DROPPED.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Install the durable refusal sink (the kernel, at boot, once the flight
/// recorder can take a record). A refusal raised before that is in the ring
/// (when it is on) and in the journal, and not on the medium.
pub fn set_durable_sink(f: fn(&ProvenanceRecord)) {
    SINK.store(f as usize, Ordering::Release);
}

/// Write one record. Empty when both the ring and the durable sink are off.
///
/// `ON`: the ring takes every verdict. `DURABLE`: a [`Verdict::Refuse`] also
/// goes to the sink, always, and so does a [`Verdict::Place`] of
/// [`Rule::Placement`] (a driver's move); a [`Verdict::Deny`] goes there when the
/// subject's bucket has a token (a [`Rule::CapDenial`] only, see
/// [`record_keyed`]), and its third number then carries the
/// count of denials dropped since the last one written (a `Deny` site has
/// that number free), in the ring record too. The tests are on constants
/// (and on the verdict, so a site that passes a literal verdict other than
/// `Refuse` or `Deny` folds it away): a build with neither compiles to
/// nothing.
#[inline(always)]
pub fn record(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) {
    record_keyed(rule, verdict, subject, subject, n)
}

/// [`record`] with the durable bucket keyed by `bucket` instead of the
/// subject: a site that can name the subject's Domain passes its key, so the
/// threads of one process share one bucket (a loop of threads denied in
/// parallel is one subject, not 16).
///
/// Only [`Rule::CapDenial`] goes through the bucket. The warrant rules'
/// `Deny` ([`Rule::CapRevoke`]) are audit records of an operation that
/// happened, whose third number is the slots revoked; they stay in the ring,
/// as before the bucket, and are neither limited nor overwritten.
#[inline(always)]
pub fn record_keyed(rule: Rule, verdict: Verdict, subject: u32, bucket: u32, n: [u64; 3]) {
    let mut n = n;
    // A refusal is always a receipt. A driver's move is one too: it changes
    // which host holds a device's authority, so it is kept whole in the
    // journal and on the medium like a refusal is.
    let mut to_sink = DURABLE
        && (matches!(verdict, Verdict::Refuse) || (matches!(verdict, Verdict::Place) && matches!(rule, Rule::Placement)));
    if DURABLE && matches!(verdict, Verdict::Deny) && matches!(rule, Rule::CapDenial) {
        if let Some(owed) = deny_admit(bucket) {
            n[2] = owed;
            to_sink = true;
        }
    }
    // The id: claimed by a record that is stored anywhere. `SKIP` (gate
    // canary) claims none, so nothing is stored.
    let seq = if ON || to_sink { claim() } else { 0 };
    if ON {
        write(seq, rule, verdict, subject, n);
    }
    if to_sink {
        durable(rule, verdict, subject, n, seq);
    }
}

#[inline(never)]
fn durable(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3], seq: u64) {
    // The fields no call site has a source for yet stay 0 (see `prov`).
    let mut p = ProvenanceRecord::new(rule as u8, verdict as u8, subject, n);
    p.seq = seq;
    // A placement's subject is its topology row's index; the wire's row ids
    // are 1-based (`ProvenanceRecord::topology_row_id`).
    if rule == Rule::Placement {
        p.topology_row_id = subject.wrapping_add(1);
    }
    // Kept in full, before the sink: the journal is what `lookup` and `query`
    // read when the ring is not built, and it does not wait for the recorder.
    if seq != 0 {
        p.clock_ns = ticks_to_ns(clock_now());
        journal::store(&p);
    }
    let f = SINK.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: only `set_durable_sink` stores here, and it stores a
        // `fn(&ProvenanceRecord)`.
        let f: fn(&ProvenanceRecord) = unsafe { core::mem::transmute::<usize, _>(f) };
        f(&p);
    }
}

/// Claim the next id; 0 under the gate canary `decision-skip`.
#[inline(never)]
fn claim() -> u64 {
    if SKIP.load(Ordering::Relaxed) {
        return 0;
    }
    SEQ.fetch_add(1, Ordering::Relaxed) + 1
}

#[inline(never)]
fn write(seq: u64, rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) {
    if seq == 0 {
        return;
    }
    let s = &RING[(seq % ENTRIES as u64) as usize];
    s.seq.store(0, Ordering::Relaxed);
    fence(Ordering::Release);
    s.head.store(rule as u64 | (verdict as u64) << 8 | (subject as u64) << 32, Ordering::Relaxed);
    for (d, v) in s.n.iter().zip(n) {
        d.store(v, Ordering::Relaxed);
    }
    s.ts.store(clock_now(), Ordering::Relaxed);
    s.seq.store(seq, Ordering::Release);
}

/// Ids claimed since boot (the newest record's id).
pub fn total() -> u64 {
    SEQ.load(Ordering::Relaxed)
}

/// Record `seq`, if it is still in the ring and was not being rewritten.
pub fn get(seq: u64) -> Option<Record> {
    if seq == 0 {
        return None;
    }
    let s = &RING[(seq % ENTRIES as u64) as usize];
    if s.seq.load(Ordering::Acquire) != seq {
        return None;
    }
    let head = s.head.load(Ordering::Relaxed);
    let n = [s.n[0].load(Ordering::Relaxed), s.n[1].load(Ordering::Relaxed), s.n[2].load(Ordering::Relaxed)];
    let ts = s.ts.load(Ordering::Relaxed);
    fence(Ordering::Acquire);
    if s.seq.load(Ordering::Relaxed) != seq {
        return None;
    }
    Some(Record { seq, rule: head as u8, verdict: (head >> 8) as u8, subject: (head >> 32) as u32, n, ts })
}

/// Every record still in the ring, oldest first.
pub fn for_each(mut f: impl FnMut(&Record)) {
    let last = total();
    let first = last.saturating_sub(ENTRIES as u64 - 1).max(1);
    for seq in first..=last {
        if let Some(r) = get(seq) {
            f(&r);
        }
    }
}

/// Gate canary `canary=decision-skip` (the kernel calls it at boot).
pub fn set_skip() {
    SKIP.store(true, Ordering::Relaxed);
}
