// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Explainable decision records (Kconfig `DECISION_RECORDS_DEV`, kernel cargo
//! feature `decisions`) and durable refusal receipts (Kconfig
//! `DECISION_REFUSALS_DURABLE`, kernel cargo feature `decisions-durable`).
//!
//! An admission, placement or refusal path writes one [`Record`]: the rule
//! that decided ([`Rule`]), the verdict, the subject (a task id, a topology
//! row, a CPU count), up to three numbers the rule compared, and, from the
//! rule's table entry, the alternative it rejected. The kernel publishes the
//! newest records in its introspection tree's admin region
//! (`decisions/records/<n>`, `kernel/src/boot/inspect_views.rs`), and `why`
//! prints them, one line per record.
//!
//! The ring is the record substrate's decision ring (`azos_records`, one
//! envelope for every source, read by `logd` beside the kernel log): it holds
//! `DECISION_RECORDS_ENTRIES` records and overwrites the oldest. It is
//! lock-free so the wake path, which runs with the scheduler's locks held and
//! interrupts masked, can write to it: a writer claims its index with one
//! `fetch_add`, stores the record between the slot's two stamps and never
//! waits; a reader takes a slot only if its stamp reads the same before and
//! after the fields and the envelope names the index it asked for. A record's
//! id is its index plus one, the same before and after the boot hands the
//! ring over to the shared region. Records carry numbers only (no pointers),
//! so a torn read is dropped, never misread.
//!
//! Off (feature `on` absent, every deployment profile): [`record`] is empty
//! and the ring is not linked. On: `DECISION_RECORDS_ENTRIES` x 64 bytes
//! (the envelope and a 32-byte payload: subject and the three numbers; rule
//! and verdict are the envelope's kind).
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
//! A record can be written from anywhere, a SpinLock section included, so a
//! sink must not block when the caller is real-time or may not block: the
//! recorder's `log_*_durable` entry points put the record on the logger's ring
//! for the log flusher instead of flushing in the caller (`logger_flush`'s
//! rule). A `Refuse` goes to the sink, except for the rules a task can raise
//! once per syscall ([`Rule::caller_paced`]: a capability denial, an expired
//! deadline, a call refused at admission, a refused wait, an exec refused), which pass a token
//! bucket per (Domain, rule) first (Kconfig `DECISION_DENY_DURABLE_PER_SEC`,
//! `DECISION_DENY_DURABLE_BURST`; the `deny` module). What the bucket drops is
//! never silent: the first drop of a run writes a [`Rule::RefusalLimited`]
//! record naming the Domain, the rule and the count, the rest are reported by
//! the pair's next admitted record, by [`flush_limited`] once it has been
//! quiet a second, or when a quieter Domain takes its bucket, and a denial's
//! own third number (`dropped`) carries its count as well. The total since
//! boot is [`deny_dropped_total`], which the introspection tree's
//! `decisions/deny_dropped` shows.
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

mod a64;
mod deny;
mod journal;
mod query;
pub mod receipt;

mod prov;
pub use prov::{
    compact_base, compact_ext, warrant_ref, ProvError, ProvenanceRecord, COMPACT_BASE_CODE, COMPACT_BYTES,
    COMPACT_EXT_CODE, SIZE as PROVENANCE_SIZE, WORDS as PROVENANCE_WORDS,
};
pub use query::{for_each_held, lookup, query, Filter};

pub use azos_seclog::Class as SecClass;

use crate::a64::AtomicU64;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "on")]
use azos_records::record as rec_ring;

/// Built in.
pub const ON: bool = cfg!(feature = "on");

/// The durable refusal sink is built in (Kconfig `DECISION_REFUSALS_DURABLE`).
pub const DURABLE: bool = cfg!(feature = "durable");

/// Ring depth (Kconfig `DECISION_RECORDS_ENTRIES`, rounded up to a power of
/// two, as `azos_records` lays the ring out).
pub const ENTRIES: usize = (azos_limits::DECISION_RECORDS_ENTRIES as usize).next_power_of_two();
const _: () = assert!(ENTRIES >= 8);

/// Journal depth (Kconfig `DECISION_JOURNAL_ENTRIES`); read only with
/// [`DURABLE`].
pub const JOURNAL_ENTRIES: usize = azos_limits::DECISION_JOURNAL_ENTRIES as usize;
const _: () = assert!(JOURNAL_ENTRIES >= 8);

/// Records the admin introspection view publishes (the kernel,
/// `decisions/records/<n>`) and the decision server decodes (`decisd`'s
/// table): Kconfig `DECISION_VIEW_ROWS`, one number for both sides.
pub const VIEW_ROWS: usize = azos_limits::DECISION_VIEW_ROWS as usize;

/// Names of the reasons a run-time reservation is refused for, by code
/// (`azos_sched::rt_core::Refusal::code`, 0 = none; a host test in
/// `sched-policy-tests` holds the two tables together). The third number of
/// such a refusal carries the code in bits 32..40 ([`prov`](crate)'s chain).
pub const REFUSAL_REASONS: [&str; 9] =
    ["none", "malformed", "no-room", "band-cap", "busy", "levels", "class-off", "envelope", "core-class"];

/// The rules that write a record.
///
/// Variants 15..=33 and 36..=62 are reserved: their names, numbers and the
/// three field names of each are fixed here so the fronts that write them add
/// a producer and never edit this enum or [`RULES`]. Until its producer lands a
/// reserved rule writes no record, and its fields are what the first producer
/// fills.
///
/// A rule added after `RefusalLimited` takes no number: its variant goes last
/// in this enum without `= N` and its [`RuleInfo`] last in [`RULES`], and its
/// number is its place, so two fronts that each add one cannot pick the same
/// number (a merge keeps both, in the same order in both places). The host test
/// `every_variant_sits_where_the_table_puts_it` reads this enum's text against
/// [`RULES`]; the numbers up to `RefusalLimited = 78` are pinned there.
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
    /// A task's wait would have closed a cycle of owners (the wait graph,
    /// `azos_sync::waitgraph`, in every build): the wait was refused and the
    /// task told `EDEADLK`.
    WaitCycle = 14,
    /// A physical effect whose device cannot commit it within its deadline (placement latency plus the device row's `commit_ns`): the actuation gate refuses to release it.
    EffectDeadline = 15,
    /// A device was driven into, or held out of, its declared safe state (a missed commit deadline, `azos_actuation::safe_state`).
    SafeState = 16,
    /// A compensating action was run, or refused, for an effect that was released and then failed.
    Compensation = 17,
    /// A receipt's caveat (a limit attached to a delegated authority) was checked and held, or cut an operation short.
    ReceiptCaveat = 18,
    /// A value was moved to a lower information label, or the move was refused.
    Declassify = 19,
    /// A refusal that a rule in shadow (audit-only) mode would have made; the operation went ahead.
    ShadowRefusal = 20,
    /// A policy set on a node of the domain tree decided an operation under it.
    SubtreePolicy = 21,
    /// A capability was revoked on behalf of another node, or the request was refused.
    RemoteRevoke = 22,
    /// Pages were compressed in memory instead of reclaimed another way.
    Compress = 23,
    /// Pages were written out to the backing store to free memory.
    SwapOut = 24,
    /// Kernel memory was charged to a domain's quota, or the charge was refused.
    KmemCharge = 25,
    /// A clock was stepped by more than its slew limit, or the step was refused.
    ClockStep = 26,
    /// A packet was dropped by the network stack's rules before it reached a socket.
    PacketRefused = 27,
    /// A guest (the Linux personality or a VM) tried to reach something outside its grant.
    GuestEgress = 28,
    /// A live patch of the running kernel was applied or refused.
    Livepatch = 29,
    /// A CPU was taken offline or brought online, or the change was refused.
    CpuHotplug = 30,
    /// The system, or a domain, was suspended, or the suspend was refused.
    Suspend = 31,
    /// The system dropped to a lower mode because the battery ran low.
    BatteryDegrade = 32,
    /// Two or more labelled inputs were combined and the result was given the meet of their provenance labels.
    ProvenanceMeet = 33,
    /// A physical effect was refused because its record could not be committed
    /// to the flight recorder first (the effect gate, `azos_actuation::effect_gate`):
    /// the ring was at its effect limit.
    EffectRecord = 34,
    /// A boot stage's digest was extended into a TPM PCR, or the extend failed
    /// (`kernel/src/boot/tpm.rs`, Kconfig `TPM`): the first records of a boot.
    MeasuredBoot = 35,
    /// A hardware guard on the kernel's own access to user memory (x86_64
    /// SMEP/SMAP, aarch64 PAN) is `probe` in Kconfig and the CPU lacks it: the
    /// boot went on without it (`kernel/src/boot/isa.rs`).
    HardeningFallback = 36,
    /// A call, at a trap's prologue or as an `io_ring` entry, was refused by the pledge mask of the caller's Domain (`azos_sched::domain::admit`, narrowed by `DOMAIN_PLEDGE`), or the mask was narrowed.
    Pledge = 37,
    /// A job was admitted to, or refused by, an accelerator (NPU, GPU or DSP): its memory and its time slice did not fit the accelerator's budget.
    AccelAdmission = 38,
    /// A time-sensitive network stream was admitted to the gate schedule of a port, or refused because its slot did not fit.
    TsnAdmission = 39,
    /// A write of a configuration key was made, or refused by the Domain's `config` envelope row.
    EnvelopeConfig = 40,
    /// A step of applying a whole-system update (staging, the slot switch) was taken, or refused by the Domain's `ota` envelope row.
    EnvelopeOta = 41,
    /// A Domain's first packet to a destination off the node was let out, or refused by its `egress` envelope row.
    EnvelopeEgress = 42,
    /// A delete on a volume (cut, rename over a file, unlink, snapshot drop) was made, or refused by the Domain's `delete` envelope row.
    EnvelopeDelete = 43,
    /// A real-time reservation was admitted, or refused by the Domain's `rt_time` envelope row because it asked for more of a hart than the row allows.
    EnvelopeRtTime = 44,
    /// A Domain was frozen (its tasks stopped and kept in memory) or thawed, or the request was refused.
    Freeze = 45,
    /// A task acted on another task (stop, resume, set its registers, read its memory, kill it), or was refused.
    ThreadControl = 46,
    /// A person or a service tried to open a session, and was admitted or refused.
    Login = 47,
    /// A key held by the key service was used (sign, decrypt, derive, wrap), or the use was refused.
    KeyUse = 48,
    /// The memory manager changed its level of pressure, or refused to take the action that level calls for.
    MemPressure = 49,
    /// Cached or secret data was purged (page cache, a Domain's pages at its exit, key material), or the purge was refused.
    Purge = 50,
    /// A region of storage or a device was wiped (overwritten or cryptographically erased), or the wipe was refused.
    Wipe = 51,
    /// An activity was admitted against the energy a mission has left, or refused because it would eat the reserve the mission needs to finish or get home.
    MissionEnergy = 52,
    /// An activity was deferred to an idle moment or a charging window, or the deferral was refused because its deadline would be missed.
    DeferredActivity = 53,
    /// On a switch between two Domains the state that carries timing (caches, branch predictors, the TLB) was flushed or partitioned, or the flush could not be done.
    TimeProtection = 54,
    /// A quote of the machine's measured state was produced for a verifier, or refused.
    Attest = 55,
    /// A link of the boot chain (firmware, loader, kernel, configuration, topology) was verified before it ran, or refused.
    BootChain = 56,
    /// The hardware reported an error (memory, cache, bus, link), and the kernel took an action on it.
    Ras = 57,
    /// A node or a frame on a fieldbus (CAN, EtherCAT, Modbus, serial) was admitted, or refused.
    Fieldbus = 58,
    /// A task opened or kept an audio capture stream, and was admitted or refused.
    AudioCapture = 59,
    /// The input focus moved to another task or Domain, or a task's request to take or grab it was refused.
    Focus = 60,
    /// A USB device was authorized to bind a driver, or refused.
    UsbAuthorize = 61,
    /// A block request did not complete in time, and the driver took an action on it.
    BlockTimeout = 62,
    /// A clock was set outright (not slewed or stepped within the limit, which `clock-step` records), or the set was refused.
    ClockSet = 63,
    /// An operator's e-stop release proof verified and was refused all the
    /// same, because its nonce floor could not be made durable
    /// (`azos_actuation::estop::verify_operator_release`): the latch stays
    /// engaged.
    EstopRelease = 64,
    /// The thermal framework acted on, or stopped acting on, a zone's
    /// temperature: a trip fired or cleared, a domain could not be cooled as
    /// far as the heat asked (the real-time or safety floor holds its clock
    /// up), the degrade level changed, a sensor was lost or came back, or a
    /// critical trip requested the shutdown (`azos_thermal`, Kconfig `THERMAL`).
    Thermal = 65,
    /// A record that must survive a power cut (an anti-rollback floor) was
    /// written, but the device has no cache control, so the kernel does not
    /// claim it durable (owner decision 2026-10-23, Q2).
    Durability = 66,
    /// A NIC's transmit ring held frames past its budget with the device
    /// taking none, and the driver reset the device or latched it dead
    /// (`azos_drv_api::recovery`, Kconfig `NET_TX_TIMEOUT_MS`).
    NetTimeout = 67,
    /// A USB host controller left a command unanswered past its budget, or
    /// reported a host system error or a host controller error, and the
    /// driver reset the controller or latched it dead
    /// (`azos_drv_api::recovery`).
    UsbHostFault = 68,
    /// A v2 IPC call's remaining deadline was admitted against, or refused
    /// by, its server's scheduling context; a refusal carries the nearest
    /// admissible deadline or budget (`azos_syscall::ipc_deadline::admit`).
    CallAdmission = 69,
    /// The energy governor's choice of an OPP stopped reaching the clock (the
    /// actuator refused it, or no apply step answered it by the deadline), or
    /// reaches it again (`azos_sched::energy`, Kconfig `ENERGY`).
    OppApply = 70,
    /// A system power assertion (keep the machine out of system suspend) was
    /// refused by its quota, or released by the kernel because its timeout
    /// passed (`azos_energy::assertion`, Kconfig `ENERGY`).
    PowerAssertion = 71,
    /// A program asked to take a NIC queue from the kernel's stack and run it
    /// from ring 3 (`QUEUE_NICQ_ATTACH`), and was refused: the queue carries
    /// the node's own stack, or the path its e-stop and its link arrive by
    /// (`azos_net::nic_queue`, Kconfig `NET_NIC_QUEUES`).
    NicQueue = 72,
    /// x86_64: the TSC was refused as the clock, at boot (not invariant) or
    /// by the watchdog (it drifted from the HPET or the PM timer), or kept
    /// although not invariant because nothing else can be read
    /// (`azos_arch::timer`, Kconfig `X86_TSC_CLOCK`, `X86_TSC_WATCHDOG`).
    Clocksource = 73,
    /// A signed topology row asked for a range of I/O ports that holds one the
    /// kernel drives itself (`azos_arch_api::ioport::reserve`: COM1, the CMOS
    /// clock, the PCI configuration pair, the 8042, the PIT's channel 0), and
    /// the minter refused the grant (`azos_ipc::ioport_cap`).
    IoportReserved = 74,
    /// A rangefinder was asked for on a board with no driver for it: it stays
    /// not ready instead of serving simulated distances, so obstacle avoidance
    /// and the REFLEX daemon run without it (`azos_drv_sensor::rangefinder`).
    Rangefinder = 75,
    /// The system watchdog found a task blocked on a wait with an owner for
    /// too long, or a CPU that stayed in the kernel with no progress, and
    /// took the action the build's Kconfig `HUNG_ACTION` names
    /// (`azos_actuation::sys_wdt`, Kconfig `HUNG_DETECT`).
    Hang = 76,
    /// A ring-3 task's core file (Kconfig `CRASHDUMP_CORE_*`) was written whole,
    /// written cut to its byte budget, or not written at all.
    CoreDump = 77,
    /// Records of a caller-paced rule (`Rule::caller_paced`) from one Domain
    /// were held back by the durable rate limit: the subject is the Domain's
    /// key, the numbers the rule held back, how many records, and whether the
    /// run just began.
    RefusalLimited = 78,

    /// The CPUs differ in core class and Kconfig `SCHED_ASYM_CPUS` is off, so
    /// every CPU counts as equal: a real-time budget measured on one core
    /// type runs on any (`azos_sched::topo::differs`, noted once at boot).
    AsymCpus = 79,
    /// A reservation was admitted on CPUs that differ, and binds to the core
    /// class of the CPU it pinned to: the one the request named, or the one the
    /// running task was on when it asked for itself (`SYS_SCHEDCTL`).
    RtCoreClass = 80,
    /// A secondary CPU differs in something the kernel already committed to on
    /// the boot CPU and was left offline (`boot::smp`).
    CpuRefused = 81,
    /// A capability slot's generation ran out and a sweep restarted it: from
    /// here a handle of that slot's previous cycle can recur.
    CapSlotRestart = 82,
    /// A grant found no slot in the domain's capability table.
    CapTableFull = 83,
    /// Every CPU is in the real-time set (`azos_sync::qsbr::rt_cpus`), so the RCU callback
    /// task runs on CPU 0, inside it: the one place QSBR callbacks reach a
    /// real-time CPU (`azos_sync::qsbr::callback_placement`).
    RcuCallbackCpu = 84,
    /// A process exec (`SYS_SPAWN_EX`, the Linux `execve`) was admitted by a
    /// launch grant on its image or on its package, or refused for the lack of
    /// one (`azos_syscall::exec_grant`).
    ExecGrant,
    /// An effect of a kind no installed effect provider owns was refused: the
    /// image has no such device (`azos_actuation::effect`).
    EffectUnserved,
    /// A signed repository index was accepted (`azos_pkg::index`): the
    /// installer's journal records which index it keeps, the boot-time apply
    /// which one it judged the security floors by.
    PackageIndex,
    /// A request (`mmap`, a `brk` growth) grew a Domain's budget past its
    /// base, within its row's `mem_pages_max`, or was refused at that ceiling
    /// (`azos_sched::domain::charge_request`).
    BudgetGrow,
    /// An op that would drive or turn a GPIO line the safety core reads (the
    /// kill switch's input, a `gpio-keys` line) was refused, whatever the
    /// capability it came through (`azos_syscall::devices::GpioPin::held`).
    SafetyLine,
    /// A ring-3 driver gave a device memory (`DEVICE_DMA_MAP`, `azos_ipc::dma_bind`)
    /// where no IOMMU confines the device, or was refused it, or its pages were kept.
    Ring3Dma,
    /// A topology row's interrupt line grant (`irq.<N>`, `irq.<selector>`) was
    /// refused because a device ring 3 may not have raises the line, or owns it.
    LineGrant,
    /// An MSI vector a holder gave back was kept for its slot instead of returned
    /// to the pool, or a bind of a slot was refused at its vector bound.
    MsiVector,
    /// A task became a reader of the camera's frames (`Frame::next`), was refused, or read its first
    /// frame; or the frame pool could not be made.
    CamCapture,
    /// A task was killed because memory ran out under it: the page allocator
    /// was empty when it broke copy-on-write, or the first touch of a page it
    /// had reserved needed kernel memory its Domain had no room for.
    MemKill,
    /// A client handed the kernel a swappable memory object as the region of a
    /// ring the kernel's end addresses (a queue, a NIC queue, a call buffer),
    /// and was refused: the kernel does not address memory that can be out.
    SwappableRing,
    /// A storm left a shared object's pages in memory because a process that
    /// maps it pins its memory (a real-time thread, a `mem = "locked"`
    /// Domain), whichever Domain the object is charged to. Once per object
    /// per storm.
    ReclaimSkip,
    /// A process that pins memory (real-time, or a locked Domain) was refused
    /// over a shared swappable object's pages that were out: a map by a process
    /// already admitted (site 1), a change to a real-time class (site 3), an
    /// exec that locks its Domain (site 4) or a `MEMOBJ_RESTORE` (site 5) whose
    /// pages could not come back.
    PinRestore,
}

/// The rules whose records are security records, and their class.
const SECURITY_RULES: [(Rule, SecClass); 14] = [
    (Rule::AudioCapture, SecClass::Microphone),
    (Rule::CamCapture, SecClass::Camera),
    (Rule::EnvelopeEgress, SecClass::Egress),
    (Rule::GuestEgress, SecClass::Egress),
    (Rule::CapDenial, SecClass::CapDenial),
    (Rule::Neverallow, SecClass::CapDenial),
    (Rule::ExecGrant, SecClass::ImageLoad),
    (Rule::Livepatch, SecClass::ImageLoad),
    (Rule::BootChain, SecClass::ImageLoad),
    (Rule::MeasuredBoot, SecClass::ImageLoad),
    (Rule::EnvelopeOta, SecClass::Update),
    (Rule::PackageInstall, SecClass::Update),
    (Rule::Login, SecClass::Login),
    (Rule::UsbAuthorize, SecClass::Usb),
];

impl Rule {
    /// The class of the sealed security log (Kconfig `SEC_LOG`) a record of
    /// this rule belongs to, every verdict alike; `n0` is the record's first
    /// number, which names the rule a [`Rule::RefusalLimited`] report held
    /// back. `None`: not a security record.
    pub const fn security_class(self, n0: u64) -> Option<SecClass> {
        let limited = matches!(self, Rule::RefusalLimited);
        let r = if limited { n0 } else { self as u64 };
        let mut i = 0;
        while i < SECURITY_RULES.len() {
            if SECURITY_RULES[i].0 as u64 == r {
                return Some(if limited { SecClass::Limited } else { SECURITY_RULES[i].1 });
            }
            i += 1;
        }
        None
    }

    /// Rules whose records an unprivileged task can raise once per syscall:
    /// their durable path is rate-limited per Domain
    /// (`DECISION_DENY_DURABLE_PER_SEC`), and what the limit holds back is
    /// reported by [`Rule::RefusalLimited`]. Every other rule's refusals are
    /// system events and are never limited.
    pub const fn caller_paced(self) -> bool {
        matches!(self, Rule::CapDenial | Rule::DeadlineExpired | Rule::CallAdmission | Rule::WaitCycle | Rule::ExecGrant
            | Rule::EffectUnserved | Rule::BudgetGrow | Rule::SafetyLine | Rule::Ring3Dma
            | Rule::LineGrant | Rule::MsiVector | Rule::CamCapture)
    }
}

/// Why [`record_mem_kill`] killed a task, as `Rule::MemKill` numbers it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MemKillReason {
    /// The page allocator was empty when the task broke copy-on-write.
    CowOom = 1,
    /// The first touch of a reserved page needed kernel memory the Domain had no room for.
    Quota = 2,
}

/// Record that memory ran out under the task `victim` and it was killed: its
/// Domain's `charge` in frames and the Domain's pressure level, `step`.
///
/// Canary `mem-kill-unrecorded-canary`: the kill leaves no record.
pub fn record_mem_kill(victim: u32, reason: MemKillReason, charge: u32, step: u8) {
    if cfg!(feature = "mem-kill-unrecorded-canary") {
        return;
    }
    record(Rule::MemKill, Verdict::Refuse, victim, [reason as u64, u64::from(charge), u64::from(step)]);
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
pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        // Two writers: the boot admission (subject = cpus; placed, rows, and
        // on a refusal the first row refused plus one,
        // `DeadlineRefusal::record_row`, 0 when none is named) and the run-time `rt::reserve` refusal (subject = tid; runtime_us,
        // period_us, reason << 32 | available_us), the second after the `|`.
        name: "deadline-admission",
        subject: "cpus|tid",
        fields: ["placed|runtime_us", "rows|period_us", "?row+1|reason<<32+available_us"],
        rejected_if_yes: "refuse the topology: no CPU's density bound is exceeded",
        rejected_if_no: "run the rows (or the task): some row cannot meet its deadline on these CPUs",
    },
    RuleInfo {
        name: "rt-band-cap",
        subject: "cpus",
        fields: ["placed", "cap_pct", "?row+1"],
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
        // 2 a row refuses it. Bus 4 is a `[volume.NAME]` row (the subject and
        // `id` are its partition, 0 the FAT32 boot volume): `why` 3 the row
        // is sealed and the system holds no key for it, 4 the key it holds
        // does not open the volume, 5 the check after an unclean mount found
        // damage and the volume is served read-only, 6 the same and it was
        // not mounted (Kconfig `FS_CHECK_FAILED`).
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
    RuleInfo {
        // The subject is the waiter's task slot (the wait graph's `TaskId`).
        // `kind` is the `azos_sync::waitgraph::EdgeKind` code of the object it
        // asked to wait on, `owner` the task slot that closes the cycle (the
        // waiter itself, or the owner of an object the chain meets twice),
        // `links` how many owner links the walk followed to find it.
        name: "wait-cycle",
        subject: "task",
        fields: ["kind", "owner", "links"],
        rejected_if_yes: "-",
        rejected_if_no: "let the task sleep: the owners it would wait behind end at the task itself, so nobody could ever release the object",
    },
    RuleInfo {
        // The actuation gate (`azos_actuation::effect_gate`): `effect` kind 1 a
        // motor, class 1 reversible; `needed_ns` the driver's placement
        // latency plus the device row's `commit_ns`.
        name: "effect-deadline",
        subject: "tid",
        fields: ["effect", "deadline_ns", "needed_ns"],
        rejected_if_yes: "-",
        rejected_if_no: "release the effect: the device cannot commit it within its deadline, so it would act on the world after the moment it was meant for",
    },
    RuleInfo {
        // The subject is the device, `kind << 16 | subject` (kind 1 a motor, its
        // wheel); `from` and `to` are 1 commanded, 2 safe; `cause` is
        // `tid << 8 | code`, code 1 a missed commit deadline (admit: the
        // kernel drove the device to its safe state; refuse: it could not, no
        // such op for the device or the kernel's driver refused), code 2 an
        // effect refused because the device is held in its safe state.
        name: "safe-state",
        subject: "device",
        fields: ["from", "to", "cause"],
        rejected_if_yes: "leave the device commanded: its commit deadline passed and the kernel drove it to its safe state",
        rejected_if_no: "assume the device is safe: the kernel could not drive it there, or it holds the device out of motion until a stop lands",
    },
    RuleInfo {
        // `action` is the device row's `compensate` op (kernel driver code, 0
        // none); `status` 0 ran, 1 the row declares no inverse, 2 the
        // kernel's driver refused it.
        name: "compensation",
        subject: "tid",
        fields: ["effect", "action", "status"],
        rejected_if_yes: "leave the effect standing: a registered inverse can undo it",
        rejected_if_no: "do nothing: no inverse is registered, or running it would be worse than the effect",
    },
    RuleInfo {
        // `caveat` is the packed first number (`receipt::word`: device, receipt
        // kind, cause); the printers decode it (`receipt::Refusal`), so `why`
        // names the device and the receipt that was missing, old or
        // contradicted, with the age of the newest receipt and the limit.
        name: "receipt-caveat",
        subject: "domain",
        fields: ["caveat", "age_ms", "limit_ms"],
        rejected_if_yes: "-",
        rejected_if_no: "honour the receipt as written: its caveat limits the operation more than the rights alone",
    },
    RuleInfo {
        name: "declassify",
        subject: "domain",
        fields: ["from_label", "to_label", "grant"],
        rejected_if_yes: "keep the label: nothing authorized lowering it",
        rejected_if_no: "refuse the move: no grant authorizes lowering the label",
    },
    RuleInfo {
        name: "shadow-refusal",
        subject: "tid",
        fields: ["rule", "verdict", "would_be"],
        rejected_if_yes: "-",
        rejected_if_no: "enforce at once: the rule is audited first so a wrong rule cannot stop the system",
    },
    RuleInfo {
        name: "subtree-policy",
        subject: "node",
        fields: ["policy", "depth", "action"],
        rejected_if_yes: "let the subtree decide for itself: no ancestor's policy applies",
        rejected_if_no: "apply the ancestor's policy: it bounds every domain below it",
    },
    RuleInfo {
        name: "remote-revoke",
        subject: "node",
        fields: ["domain", "cap", "epoch"],
        rejected_if_yes: "keep the capability: the remote node holds it until its lease ends",
        rejected_if_no: "-",
    },
    RuleInfo {
        name: "compress",
        subject: "pages",
        fields: ["pages", "bytes_in", "bytes_out"],
        rejected_if_yes: "write the pages out or drop them: compressed they cost less than the alternative",
        rejected_if_no: "keep the pages as they are: compression did not pay",
    },
    RuleInfo {
        name: "swap-out",
        subject: "pages",
        fields: ["pages", "reason", "free_pages"],
        rejected_if_yes: "keep the pages resident: free memory was below the reserve",
        rejected_if_no: "refuse the swap: the task is pinned or the store has no room",
    },
    RuleInfo {
        name: "kmem-charge",
        subject: "domain",
        fields: ["bytes", "used", "limit"],
        rejected_if_yes: "leave the allocation uncharged: one domain could take the kernel's memory from the rest",
        rejected_if_no: "fail the allocation: the charge would take the domain past its quota",
    },
    RuleInfo {
        name: "clock-step",
        subject: "clock",
        fields: ["clock", "delta_ns", "limit_ns"],
        rejected_if_yes: "slew the clock: a step is a jump of time every deadline would see",
        rejected_if_no: "refuse the step: it is larger than the limit the topology gives that clock",
    },
    RuleInfo {
        name: "packet-refused",
        subject: "iface",
        fields: ["proto", "reason", "len"],
        rejected_if_yes: "-",
        rejected_if_no: "deliver the packet: it breaks a rule the stack enforces for its interface",
    },
    RuleInfo {
        name: "guest-egress",
        subject: "guest",
        fields: ["kind", "target", "reason"],
        rejected_if_yes: "-",
        rejected_if_no: "let the guest through: its grant does not name this target",
    },
    RuleInfo {
        name: "livepatch",
        subject: "patch",
        fields: ["patch", "symbol", "reason"],
        rejected_if_yes: "leave the code as booted: the signed patch fixes a fault without a reboot",
        rejected_if_no: "apply the patch: it is unsigned, for another build, or touches code that is running",
    },
    RuleInfo {
        name: "cpu-hotplug",
        subject: "cpu",
        fields: ["op", "load", "reason"],
        rejected_if_yes: "keep the CPU as it is: the load or the power budget asked for the change",
        rejected_if_no: "refuse the change: a reservation is pinned to the CPU",
    },
    RuleInfo {
        name: "suspend",
        subject: "domain",
        fields: ["state", "blockers", "reason"],
        rejected_if_yes: "keep running: nothing asked for the suspend",
        rejected_if_no: "refuse the suspend: a task holds a wake lock or an effect is still in flight",
    },
    RuleInfo {
        name: "battery-degrade",
        subject: "mode",
        fields: ["level_pct", "from_mode", "to_mode"],
        rejected_if_yes: "stay in the current mode: the charge covers the mode's draw",
        rejected_if_no: "-",
    },
    RuleInfo {
        name: "provenance-meet",
        subject: "tid",
        fields: ["inputs", "label", "result"],
        rejected_if_yes: "-",
        rejected_if_no: "keep the output's own label: the inputs' labels bound what it may be trusted for",
    },
    RuleInfo {
        // The subject is the task that asked. `effect` is `kind << 8 | class`
        // (`azos_actuation::effect_gate`: kind 1 a motor; class 1 reversible),
        // `reason` 1 the recorder's queue is at its effect limit, 4 the deadline
        // watch table is full, 7 every recorder queue's writer stayed taken;
        // `ring_len` for reason 1 the refusing queue (bits 32..) and its
        // records (bits 0..31), for reason 4 the records the recorder holds.
        name: "effect-record",
        subject: "tid",
        fields: ["effect", "reason", "ring_len"],
        rejected_if_yes: "-",
        rejected_if_no: "issue the effect: its record would not be committed first, so a fault or a power cut could leave an effect nobody can account for",
    },
    RuleInfo {
        // The subject is the PCR. `stage` is 1 the kernel image, 2 the
        // signed configuration, 3 the topology; `digest` the first eight
        // bytes of the SHA-256 that was extended, big endian (the whole
        // value is in the PCR, and in the boot line); `how` is the stage's
        // own detail (kernel: 0 the linked text's build-id, 1 the text as
        // it stands; topology: 0 the signed file, 1 the built-in topology)
        // on an admit, and the driver's error code on a refuse.
        name: "measured-boot",
        subject: "pcr",
        fields: ["stage", "digest", "how"],
        rejected_if_yes: "boot the stage unmeasured: a verifier quoting the PCR could not tell which kernel, configuration or topology ran",
        rejected_if_no: "halt the boot: a TPM that fails would make the board unbootable; the stage stays out of the PCR, so a quote no longer matches the expected value",
    },
    RuleInfo {
        // Written once per absent guard, after the decision sink is installed
        // (the `[SEC]` warning line is printed at the `[ISA]` report, earlier).
        // Subject: 1 smep, 2 smap, 3 pan. `isa`: 0 riscv64, 1 aarch64, 2 x86_64.
        name: "hardening-fallback",
        subject: "guard",
        fields: ["isa", "-", "-"],
        rejected_if_yes: "n/a: the rule only ever refuses (a CPU that has the guard writes no record)",
        rejected_if_no: "refuse the boot (Kconfig `require`): a `probe` kernel is meant to run on CPUs without the guard, such as an Armv8.0 Cortex-A53 without PAN, with kernel accesses to user memory unchecked by hardware",
    },
    RuleInfo {
        // The subject is the task that made the call (for a ring entry, the ring's owner, never the SQ
        // poller). `mask` is the Domain's pledge mask in force. `action` is `what | where << 8`: `what` 0
        // refused with the error, 1 killed the task, 2 narrowed the mask (admit); `where` 0 the trap prologue,
        // 1 an `io_ring` entry, so one rule tells the two doors apart. `nr` is the syscall number or ring op.
        name: "pledge",
        subject: "tid",
        fields: ["mask", "action", "nr"],
        rejected_if_yes: "run the call: the mask still holds its class",
        rejected_if_no: "refuse the call at the door: the Domain gave the class up, whichever door (trap or ring) it came through",
    },
    RuleInfo {
        // The subject is the task that submitted the job. `accel` is the accelerator's device id, `need` the
        // job's memory in KiB and `free` what the accelerator had left.
        name: "accel-admission",
        subject: "tid",
        fields: ["accel", "need_kib", "free_kib"],
        rejected_if_yes: "run the job: it fits the accelerator's budget next to the jobs it already holds",
        rejected_if_no: "refuse the job: one tenant's job could starve the accelerator's other tenants or its real-time work",
    },
    RuleInfo {
        // The subject is the stream id. `reason` 0 admitted, 1 the slot overlaps another stream's window, 2
        // the worst-case latency is above the stream's bound, 3 the port's reserved share is used up.
        name: "tsn-admission",
        subject: "stream",
        fields: ["period_ns", "frame_bytes", "reason"],
        rejected_if_yes: "open the stream: its window fits the port's gate schedule and its latency bound holds",
        rejected_if_no: "refuse the stream: an admitted stream's guaranteed latency would break",
    },
    RuleInfo {
        // The subject is the task whose Domain tried to write a configuration key (the effect gate's
        // `config_write`, `azos_actuation::effect_gate`). `op` is 1 a tuning key, 2 a key that arms or disarms
        // a guard, 3 a key that opens a way in or changes what boots (`azos_common::envelope::ConfigOp`), `key`
        // the first eight bytes of the key (little endian) and `level` the envelope level that held it (1
        // cautious, 2 slow, 3 contained).
        name: "envelope-config",
        subject: "tid",
        fields: ["op", "key", "level"],
        rejected_if_yes: "write the key: the Domain's config row allows a key that can do this much",
        rejected_if_no: "keep the value: the Domain's config row (or the provenance of its data) does not allow a key that can do this much",
    },
    RuleInfo {
        // The subject is the task whose Domain tried to apply an update (the effect gate's `ota_apply`). `step`
        // is 1 stage the set in the inactive slot, 2 switch the boot record to it (`azos_common::envelope::
        // OtaOp`), `slot` the slot the set is for (255 when the caller does not know it) and `level` the
        // envelope level that held it (1 cautious, 2 slow, 3 contained).
        name: "envelope-ota",
        subject: "tid",
        fields: ["step", "slot", "level"],
        rejected_if_yes: "take the step: the Domain's ota row allows an update to get this far",
        rejected_if_no: "leave the running system as it is: the Domain's ota row (or the provenance of its data) does not allow an update to get this far",
    },
    RuleInfo {
        // The subject is the task whose Domain tried to start talking to a destination off the node (the effect
        // gate's `net_egress`, `azos_actuation::effect_gate`). `dest` is the destination (IPv4 as a 32-bit word;
        // IPv6 its last four bytes), `class` its distance (1 local link, 2 private network, 3 anywhere) and
        // `level` the envelope level that held it (1 cautious, 2 slow, 3 contained).
        name: "envelope-egress",
        subject: "tid",
        fields: ["dest", "class", "level"],
        rejected_if_yes: "send the packet: the Domain's egress row reaches the destination's class",
        rejected_if_no: "keep the packet here: the Domain's egress row (or the provenance of its data) does not reach that far",
    },
    RuleInfo {
        // The subject is the task whose Domain tried to delete (the effect gate's `storage_delete`). `op` is 1
        // cut a file below its size, 2 rename over a file, 3 unlink, 4 drop a snapshot; `volume` the VFS mount
        // index (an azvol volume asked directly: the first eight bytes of its uuid); `level` the envelope level
        // that held it (1 cautious, 2 slow, 3 contained).
        name: "envelope-delete",
        subject: "tid",
        fields: ["op", "volume", "level"],
        rejected_if_yes: "delete: the Domain's delete row allows an op that destroys this much",
        rejected_if_no: "keep the data: the Domain's delete row (or the provenance of its data) does not allow an op that destroys this much",
    },
    RuleInfo {
        // The subject is the task whose Domain asked for a real-time reservation (the effect gate's `rt_time`,
        // `rt::reserve`). `asked_ppm` is the reservation's density in parts per million of a hart, `ceiling_ppm`
        // the most the Domain's `rt_time` row lets one reservation take and `level` the envelope level that
        // held it (1 cautious, 2 slow, 3 contained).
        name: "envelope-rt-time",
        subject: "tid",
        fields: ["asked_ppm", "ceiling_ppm", "level"],
        rejected_if_yes: "admit the reservation: it fits the Domain's rt_time row and the hart's room",
        rejected_if_no: "refuse the reservation: it asks for more of a hart than the Domain's rt_time row (or the provenance of its data) allows",
    },
    RuleInfo {
        // The subject is the Domain. `op` is 1 freeze, 2 thaw, `tasks` how many tasks it holds, `reason` 0
        // done, 1 a task holds a real-time reservation, 2 a task is inside an effect that was released but not
        // committed, 3 the caller has no authority over the Domain.
        name: "freeze",
        subject: "domain",
        fields: ["op", "tasks", "reason"],
        rejected_if_yes: "leave the Domain running: nothing asked for the freeze",
        rejected_if_no: "refuse the freeze: stopping the tasks would break a reservation or leave an effect half done",
    },
    RuleInfo {
        // The subject is the acting task. `target` is the task acted on, `op` the action (1 stop, 2 resume, 3
        // get registers, 4 set registers, 5 read memory, 6 kill), `reason` 0 allowed, 1 the target is in
        // another Domain, 2 the caller lacks the right, 3 the target is a service another task depends on.
        name: "thread-control",
        subject: "tid",
        fields: ["target", "op", "reason"],
        rejected_if_yes: "let the task act: it holds the right over the target",
        rejected_if_no: "refuse the action: a task may act only on tasks its capability reaches",
    },
    RuleInfo {
        // The subject is the session the attempt was for (0 before one exists; for a session, its user root).
        // `method` is 1 password, 2 key, 3 token, 4 local console, 5 the brain link (its pre-shared link key,
        // checked at boot: a keyless boot is refused, subject 0), `attempt` how many failed in a row, `reason`
        // 0 admitted, 1 wrong secret, 2 locked out, 3 the method is not allowed on this transport, 4 the board
        // holds no root to verify with, 5 no signed topology is loaded (no table of accounts to check). No secret is ever a number here.
        name: "login",
        subject: "session",
        fields: ["method", "attempt", "reason"],
        rejected_if_yes: "open the session: the secret held and the account was not locked",
        rejected_if_no: "refuse the session: an unproven caller would hold the account's authority",
    },
    RuleInfo {
        // The subject is the task that asked. `key` is the key's handle id, `op` the operation (1 sign, 2
        // decrypt, 3 derive, 4 wrap, 5 export), `reason` 0 allowed, 1 the key does not allow the operation, 2
        // the task is not the key's owner, 3 the use count or the rate is used up, 4 the key has expired.
        name: "key-use",
        subject: "tid",
        fields: ["key", "op", "reason"],
        rejected_if_yes: "use the key: the key allows the operation to this caller",
        rejected_if_no: "refuse the use: a key outside its policy would sign or open for a caller it was never meant for",
    },
    RuleInfo {
        // The subject is the Domain whose use set the level (0 for the whole machine). `level` is 0 normal, 1
        // warning (reclaim is due), 2 critical (the limit is reached), `free_pages` what is free (for a Domain,
        // what is left of its frame limit), `action` what was done (0 none, 1 notify the Domain's Port, 2 reclaim
        // cache, 3 compress, 4 swap, 5 kill the largest low-priority task).
        name: "mem-pressure",
        subject: "domain",
        fields: ["level", "free_pages", "action"],
        rejected_if_yes: "stay at the lower level: the free pages are above the level's mark",
        rejected_if_no: "-",
    },
    RuleInfo {
        // The subject is the Domain. `what` is 1 page cache, 2 anonymous pages, 3 key material, 4 log buffers,
        // `bytes` how much, `reason` 0 purged, 1 a dirty page is still being written back, 2 the caller has no
        // authority over the Domain.
        name: "purge",
        subject: "domain",
        fields: ["what", "bytes", "reason"],
        rejected_if_yes: "keep the data: nothing asked for the purge",
        rejected_if_no: "refuse the purge: dirty data still being written back would be lost",
    },
    RuleInfo {
        // The subject is the device or partition (its topology row id). `how` is 1 overwrite, 2 key erase, 3
        // device secure-erase, `bytes` how much, `status` 0 done, 1 refused: the caller lacks the right, 2
        // refused: the medium holds the running system, 3 failed on the device.
        name: "wipe",
        subject: "device",
        fields: ["how", "bytes", "status"],
        rejected_if_yes: "keep the data: nothing asked for the wipe",
        rejected_if_no: "refuse the wipe: it would destroy the running system's medium, or the caller had no right to",
    },
    RuleInfo {
        // The subject is the task that asked. `need_mj` is the energy the activity needs, `left_mj` what the
        // battery holds above the safety floor, `reserve_mj` what the rest of the mission needs.
        name: "mission-energy",
        subject: "tid",
        fields: ["need_mj", "left_mj", "reserve_mj"],
        rejected_if_yes: "run the activity: the energy left covers it and the reserve for the rest of the mission",
        rejected_if_no: "refuse the activity: it would leave too little to finish the mission or to return safely",
    },
    RuleInfo {
        // The subject is the task that asked. `kind` is 1 sync, 2 index, 3 update, 4 upload, `wait_ms` how
        // long it was deferred, `reason` 0 deferred, 1 its deadline is nearer than the wait, 2 the system is
        // not allowed to idle (a real-time reservation is active).
        name: "deferred-activity",
        subject: "tid",
        fields: ["kind", "wait_ms", "reason"],
        rejected_if_yes: "run it now: the energy and the load allow it",
        rejected_if_no: "run it now anyway: waiting would miss its deadline",
    },
    RuleInfo {
        // The subject is the Domain switched to. `from` is the Domain switched from, `to` the one switched to,
        // `mechanism` 1 flush, 2 colour partition, 3 flush and pad to a fixed time, 0 none available on this
        // CPU.
        name: "time-protection",
        subject: "domain",
        fields: ["from", "to", "mechanism"],
        rejected_if_yes: "switch without it: the two Domains share no timing-visible state the row cares about",
        rejected_if_no: "switch without the flush: the CPU has no way to do it; a timing channel between the two Domains stays open",
    },
    RuleInfo {
        // The subject is the task that asked. `scope` is 1 boot chain, 2 configuration, 3 one Domain's image,
        // `nonce` the first eight bytes of the verifier's nonce, `reason` 0 quoted, 1 no TPM, 2 the PCR does
        // not match the expected value, 3 the caller may not attest.
        name: "attest",
        subject: "tid",
        fields: ["scope", "nonce", "reason"],
        rejected_if_yes: "give the quote: the measured state is the expected one",
        rejected_if_no: "give no quote: a quote of a state that does not match, or to a caller without the right, would vouch for a machine it should not",
    },
    RuleInfo {
        // The subject is the stage (1 loader, 2 kernel, 3 configuration, 4 topology, 5 service image, 6 CPU
        // microcode). `version` is the stage's version, `floor` the rollback floor in force, `reason` 0 verified,
        // 1 bad signature, 2 version below the floor, 3 digest differs from the one the previous stage signed.
        // Stage 6 (kernel/src/entry/x86_64/ext/ucode.rs): `version` is the revision after, `floor` the one
        // before, `reason` bits 0..8 are 0 applied, 1 bad signature, 4 no patch for the CPU, 5 written and not
        // taken, 6 malformed container, 7 a hypervisor owns the microcode, 8 up to date, 9 a secondary unlike
        // the boot CPU; the logical CPU is above them.
        name: "boot-chain",
        subject: "stage",
        fields: ["version", "floor", "reason"],
        rejected_if_yes: "run the stage: its signature, version and digest hold",
        rejected_if_no: "do not run the stage: the chain is broken, and everything after it would run on trust nobody checked",
    },
    RuleInfo {
        // The subject is the CPU that took the report (or the device). `kind` is 1 corrected memory, 2
        // uncorrected memory, 3 cache, 4 bus or link, 5 device, `addr` the physical address or 0, `action` 1
        // logged, 2 page retired, 3 task killed, 4 device reset, 5 system stopped.
        name: "ras",
        subject: "cpu",
        fields: ["kind", "addr", "action"],
        rejected_if_yes: "carry on: a corrected error below the threshold",
        rejected_if_no: "-",
    },
    RuleInfo {
        // The subject is the bus (its topology row id). `node` is the node address, `id` the frame or object
        // id, `reason` 0 admitted, 1 the node is not one the row names, 2 the id is outside the node's allowed
        // set, 3 the rate is above the node's bound, 4 the frame is malformed.
        name: "fieldbus",
        subject: "bus",
        fields: ["node", "id", "reason"],
        rejected_if_yes: "pass the frame: the node and the id are in the row",
        rejected_if_no: "drop the frame: a node or id the row does not name could command or spoof a device",
    },
    RuleInfo {
        // The subject is the requester: the task whose microphone effect decided the open, which is the caller
        // unless it served another task's call (reason 4: the caller is named, there is no requester). `device`
        // is the capture device's id, `rate_hz` the sample rate, `reason` 0 admitted, 1 no grant for the device,
        // 2 the indicator that tells the person a microphone is live is not available, 3 another task holds the
        // device exclusively, 4 a warrant the caller is not serving.
        name: "audio-capture",
        subject: "tid",
        fields: ["device", "rate_hz", "reason"],
        rejected_if_yes: "open the stream: the task holds the grant and the microphone indicator is lit",
        rejected_if_no: "refuse the stream: audio must not be captured without the grant and without the person being told",
    },
    RuleInfo {
        // The subject is the task that asked. `from` is the task that held the focus, `to` the one that gets
        // it, `reason` 0 moved, 1 the task has no grant, 2 a trusted surface (the lock or the safety screen)
        // holds it.
        name: "focus",
        subject: "tid",
        fields: ["from", "to", "reason"],
        rejected_if_yes: "move the focus: the task holds the grant and no trusted surface has it",
        rejected_if_no: "keep the focus: a task that grabs the input could read what is typed for another",
    },
    RuleInfo {
        // The subject is the port. `vid_pid` is `vendor << 16 | product`, `class` the device's class code,
        // `reason` 0 authorized, 1 no row admits the class, 2 the hub is not trusted, 3 the device is a
        // composite whose class set differs from the row.
        name: "usb-authorize",
        subject: "port",
        fields: ["vid_pid", "class", "reason"],
        rejected_if_yes: "bind the driver: a row admits the device's class on this port",
        rejected_if_no: "leave the device unbound: a device no row admits could present itself as a keyboard or a network card",
    },
    RuleInfo {
        // The subject is the block device (its topology row id). `sector` is the request's first sector,
        // `waited_ms` how long it waited, `action` 1 retried, 2 reset the device (back in service), 3 failed
        // the request, 4 took the device offline, 5 latched it dead with its resets spent, 6 the reset did not
        // bring it back. 2, 5 and 6 are the driver's (`azos_drv_api::recovery`), 3 and 4 the request
        // layer's; a latch is then also 4 when a request finds the device dead.
        name: "block-timeout",
        subject: "device",
        fields: ["sector", "waited_ms", "action"],
        rejected_if_yes: "retry: the device answered inside the retry budget",
        rejected_if_no: "-",
    },
    RuleInfo {
        // The subject is the task that asked. `clock` is the clock's id, `new_ns` the value it was set to,
        // `reason` 0 set, 1 the caller lacks the right, 2 the new value is before the last one a log record
        // carries, 3 the clock is disciplined by a source.
        name: "clock-set",
        subject: "tid",
        fields: ["clock", "new_ns", "reason"],
        rejected_if_yes: "set the clock: the caller holds the right and the value does not go back before a record",
        rejected_if_no: "keep the clock: a clock set back would reorder records, and a clock a source disciplines would fight it",
    },
    RuleInfo {
        // No subject (0). `cause` is 1 no durable recorder is active, 2 the
        // active recorder refused the write; `floor` the release-nonce floor
        // at the time, `nonce` the one offered. Only a proof whose signature
        // and freshness already held is recorded, so a forger cannot fill the
        // ring with these.
        name: "estop-release",
        subject: "-",
        fields: ["cause", "floor", "nonce"],
        rejected_if_yes: "-",
        rejected_if_no: "release the latch without a durable floor: a captured proof would verify again after a reset, and the operator could not tell",
    },
    RuleInfo {
        // The verdict says which way the machine moved: `place` a trip that
        // fired (the clock is capped by OPP steps), `refuse` what the heat
        // asked and the machine could not do or declines to do (a floor holds
        // a clock up, the level rose, a sensor was lost, the shutdown was
        // requested), `admit` the relaxation (trip cleared, cooled, level
        // lowered, sensor back). `event` is `azos_energy::thermal::Event`'s
        // number, `arg` its trip, domain or level, `temp_mdeg` the reading
        // (milli-degrees Celsius, 0 for an event with no reading).
        name: "thermal",
        subject: "zone",
        fields: ["event", "arg", "temp_mdeg"],
        rejected_if_yes: "leave the clock where the governor put it: the zone is above a trip and the machine would run hot unannounced",
        rejected_if_no: "cool by the clock alone: a floor holds it up, or the clock will not move, so the machine slows down or shuts down instead",
    },
    RuleInfo {
        // The subject is the record: 1 the topology counter floor, 2 the
        // CONFIG.SIG counter floor. `from` and `to` are the floor before and
        // the one written; `flush` 1 is the device's `Unsupported`. Only
        // `refuse` is recorded: the floor stays the old one for this boot.
        name: "durability",
        subject: "record",
        fields: ["from", "to", "flush"],
        rejected_if_yes: "-",
        rejected_if_no: "claim the floor raised: the device cannot confirm the write survives a power cut, so an older signed file could come back unannounced",
    },
    RuleInfo {
        // The subject is the NIC (its topology row id). `pending` is the frames the transmit ring held,
        // `waited_ms` how long it held them with no progress, `action` 2 reset the device (back in service),
        // 5 latched it dead with its resets spent, 6 the reset did not bring it back
        // (`azos_drv_api::recovery::Action`). There is no request layer above a NIC: the driver's latch is the
        // only record of it.
        name: "net-timeout",
        subject: "device",
        fields: ["pending", "waited_ms", "action"],
        rejected_if_yes: "keep the device: frames sat in its ring and it took none of them",
        rejected_if_no: "reset again: the device wedged once more after a clean reset, and a NIC that keeps half-working is worse than one that is plainly gone",
    },
    RuleInfo {
        // The subject is the controller (its topology row id). `cause_trb` is the cause in its second byte
        // (`azos_usb::xhci::Fault`: 1 a command timed out, 2 USBSTS.HSE, 3 USBSTS.HCE) and, for a timeout,
        // the type of the command the controller did not answer in its first (xHCI 1.2 table 6-91: 9 Enable
        // Slot, 11 Address Device, 12 Configure Endpoint, ...); `waited_ms` how long it waited (0 for an
        // error the controller reported), `action` 2 reset the controller (its devices went away and were
        // enumerated again), 5 latched it dead with its resets spent, 6 the reset did not bring it back
        // (`azos_drv_api::recovery::Action`).
        name: "usb-host-fault",
        subject: "device",
        fields: ["cause_trb", "waited_ms", "action"],
        rejected_if_yes: "keep the controller: it stopped answering or reported an error, and every device behind it is unreachable until it is reset",
        rejected_if_no: "reset again: the controller faulted once more after a clean reset, and a host that keeps half-working loses its devices at random",
    },
    RuleInfo {
        // Only refusals are written: the admitted call is the common case and
        // its record would be one per call. `alt` is the counter-offer: an
        // absolute deadline in ns when `kind` is 1, a budget in us when 2;
        // `kind<<32+server` also names the serving task.
        name: "call-admission",
        subject: "tid",
        fields: ["deadline_ns", "alt", "kind<<32+server"],
        rejected_if_yes: "refuse the call: the server's reservation or the budget the caller lends finishes it by its deadline",
        rejected_if_no: "queue the call and let the server miss the deadline: its scheduling context cannot finish it in the time left",
    },
    RuleInfo {
        // Subject: the performance domain. `choice` is the governor's OPP,
        // `target` the one the apply step asked of the actuator (255: no
        // apply step answered), `outcome` `azos_energy::opp::GovApply::code`
        // (6: overdue). Refuse: the actuator refused; Deny: overdue (written
        // from the tick, so it stays in the ring); Admit: reached again.
        name: "opp-apply",
        subject: "domain",
        fields: ["choice", "target", "outcome"],
        rejected_if_yes: "keep counting the choice as lost: the clock is at it again",
        rejected_if_no: "count the choice as applied: the clock did not move, so the governor's decision would be a number nobody acted on",
    },
    RuleInfo {
        // Subject: the task that holds or asked for the assertion. `reason`
        // is its reason code (`azos_devif::power_assert::REASON_*`), `ttl_ms`
        // the timeout it asked for, `id` the assertion (0 for a refusal).
        // Refuse: refused (reason, timeout, quota, full); Deny: released by
        // the kernel at its timeout, the holder silent. A grant is not
        // recorded (the counters of `PowerAssert::stats` keep it).
        name: "power-assertion",
        subject: "task",
        fields: ["reason", "ttl_ms", "id"],
        rejected_if_yes: "refuse the assertion: the machine could suspend in the middle of the holder's work",
        rejected_if_no: "grant it, or keep it past its timeout: one task could keep the machine awake for ever",
    },
    RuleInfo {
        // The subject is the task that asked. `ifindex` is the interface (`eth0` is 1), `queue` its queue,
        // `why` the refusal (`azos_net::nic_queue::Refusal::code`: 1 the primary interface, 2 the route to the
        // link peer leaves by it).
        name: "nic-queue",
        subject: "tid",
        fields: ["ifindex", "queue", "why"],
        rejected_if_yes: "-",
        rejected_if_no: "hand the queue over: the stack, or the e-stop and the link with it, would go deaf on that interface while the program holds it",
    },
    RuleInfo {
        // The subject is the clock in force after the decision (0 TSC, 1 HPET,
        // 2 ACPI PM timer: `azos_arch::timer::Clocksource`). `reason` 1 the
        // TSC is not invariant (boot), 2 it ran fast, 3 it ran slow (the
        // watchdog), 4 it is not invariant and stays, nothing else to read;
        // `drift_ppm` the drift the watchdog measured (0 at boot), `limit_ppm`
        // its bound. `refuse` for 1-3, `admit` for 4.
        name: "clocksource",
        subject: "clock",
        fields: ["reason", "drift_ppm", "limit_ppm"],
        rejected_if_yes: "refuse the TSC: it is the only counter the board has, so the clock keeps it and says it is not invariant",
        rejected_if_no: "keep the TSC as the clock: its rate is not constant (not invariant) or it left the reference by more than the bound, so every timeout would drift with it",
    },
    RuleInfo {
        // The subject is the task the row seeds. `first` and `last` are the
        // range it asked for, `kernel_port` the first port of it a kernel
        // driver bound.
        name: "ioport-reserved",
        subject: "tid",
        fields: ["first", "last", "kernel_port"],
        rejected_if_yes: "-",
        rejected_if_no: "grant the ports as the signed row asks: a ring-3 access would race the kernel's driver of that port (its console, clock, PCI configuration or timer)",
    },
    RuleInfo {
        // The subject is the sensor type: 0 ultrasonic, 1 time of flight.
        name: "rangefinder",
        subject: "kind",
        fields: ["asked", "max", "-"],
        rejected_if_yes: "-",
        rejected_if_no: "serve the simulated distances: obstacle avoidance would trust a clear path no sensor measured",
    },
    RuleInfo {
        // The subject is the hung task's tid, or the stuck CPU's id. Admit:
        // reported and left alone; Refuse: the action ran (a server stopped,
        // the e-stop latched). Field 1 is `kind << 32 | culprit tid` (kind 0
        // a call waiting for its reply, 1 a wait on an owner, 2 a CPU);
        // field 2 is `action << 32 | detail` (action 0 none, 1 restart,
        // 2 safe stop; detail the call handle, the edge kind or the CPU's
        // progress word, low 32 bits).
        name: "hang",
        subject: "tid|cpu",
        fields: ["waited_ms", "kind<<32|culprit", "action<<32|detail"],
        rejected_if_yes: "act on it: the wait may still end by itself",
        rejected_if_no: "keep waiting: the wait has no bound and nothing else will end it",
    },
    RuleInfo {
        // Refuse with bytes_written > 0 is a core cut to its budget; with 0, no core.
        // The third number is the bytes of the task's writable memory left out, or
        // when no core was made, why: 1 the budget does not hold the headers, 2 the
        // kernel heap refused the buffer, 3 the staging ring was full.
        name: "core-dump",
        subject: "tid",
        fields: ["bytes_written", "limit_bytes", "dropped_bytes|why"],
        rejected_if_yes: "-",
        rejected_if_no: "write the whole core: the task's writable memory does not fit CRASHDUMP_CORE_KB, or the kernel could not stage it",
    },
    RuleInfo {
        // The subject is the Domain key (the task id where the site cannot
        // name the Domain). `started` is 1 when the run's first record was
        // held back (that one is counted in `held`), 0 for the rest of it.
        name: "refusal-limited",
        subject: "domain",
        fields: ["rule", "held", "started"],
        rejected_if_yes: "-",
        rejected_if_no: "write every record of the rule: one Domain's loop would fill the medium and push other Domains' receipts out",
    },
    RuleInfo {
        // Place: the CPUs differ and SCHED_ASYM_CPUS is off; no class is checked.
        name: "asym-cpus",
        subject: "cpus",
        fields: ["classes", "asym_cpus", "0"],
        rejected_if_yes: "-",
        rejected_if_no: "treat the CPUs as unequal: build with SCHED_ASYM_CPUS, so a row's budget is admitted on the core class it declares, and a run-time budget binds to one class and is recorded with it",
    },
    RuleInfo {
        // Place: `azos_sched::rt::reserve`, on CPUs that differ.
        name: "rt-core-class",
        subject: "tid",
        fields: ["core_class", "cpu", "capacity"],
        rejected_if_yes: "-",
        rejected_if_no: "refuse: the task named no class and may have been moved before it asked",
    },
    RuleInfo {
        // Refuse: `boot::smp`, the CPU stays offline.
        name: "cpu-refused",
        subject: "cpu",
        fields: ["fact", "boot_value", "this_cpu_value"],
        rejected_if_yes: "bring the CPU up: code the boot CPU's facts selected would fault or corrupt state on it",
        rejected_if_no: "-",
    },
    RuleInfo {
        name: "cap-slot-restart",
        subject: "domain",
        fields: ["slot", "restarts", "-"],
        rejected_if_yes: "retire the slot for the domain's life: a long-running task would run out of slots",
        rejected_if_no: "-",
    },
    RuleInfo {
        // `parked` slots return with the sweep their park owed.
        name: "cap-table-full",
        subject: "domain",
        fields: ["live", "parked", "refusals"],
        rejected_if_yes: "-",
        rejected_if_no: "grant a slot: every one is live, or waits for the sweep that restarts it",
    },
    RuleInfo {
        name: "rcu-callback-cpu",
        subject: "cpus",
        fields: ["nocbs_mask", "callback_cpu", "-"],
        rejected_if_yes: "refuse a boot with no CPU outside the real-time set, or run callbacks on the last real-time CPU only while it is idle",
        rejected_if_no: "-",
    },
    RuleInfo {
        // basis: 1 image grant, 2 package grant, 3 the caller's own row
        // (admitted); 4 no grant, 5 bytes bound to no row, 6 not a Linux row,
        // 7 no topology row, 8 the package is below its security floor
        // (refused). site: 0 SYS_SPAWN_EX, 1 execve.
        name: "exec-grant",
        subject: "tid",
        fields: ["digest_prefix", "basis", "site"],
        rejected_if_yes: "judge the path the caller named: the grant is on the image the bytes are, or on the package that carries them",
        rejected_if_no: "start the image: the caller holds no launch grant on it, on its package, or the bytes are bound to no row",
    },
    RuleInfo {
        // effect: the kind in the high byte, the class in the low one.
        name: "effect-unserved",
        subject: "tid",
        fields: ["effect", "device", "-"],
        rejected_if_yes: "-",
        rejected_if_no: "hand the effect to a stand-in for the missing device: it would answer as a device fault and leave no record",
    },
    RuleInfo {
        // signer: the topology index plus one; serial: the index's own; event:
        // `azos_pkg::index::MarkEvent`.
        name: "package-index",
        subject: "signer",
        fields: ["entries", "serial", "event"],
        rejected_if_yes: "-",
        rejected_if_no: "keep the index the signer last published: the one offered is older than the one the device recorded, or its body differs at the same serial",
    },
    RuleInfo {
        name: "budget-grow",
        subject: "domain",
        fields: ["pages", "limit", "ceiling"],
        rejected_if_yes: "refuse the request at the base: the row's signed ceiling holds it",
        rejected_if_no: "grow past the ceiling: the signed row bounds the domain there",
    },
    RuleInfo {
        // op: the `Gpio` IDL op (write, set_dir).
        name: "safety-line",
        subject: "tid",
        fields: ["controller", "pin", "op"],
        rejected_if_yes: "-",
        rejected_if_no: "let a holder of the line's capability drive it: an output on the kill switch's input makes the switch read what the holder drives",
    },
    RuleInfo {
        // why: 0 admitted without an IOMMU (DMA_RING3_WITHOUT_IOMMU), 1 refused
        // without one, 2 refused: an earlier binding's pages are kept, 3 kept:
        // the device could not be shown stopped, the domain's unmap failed or
        // the flush after its map was not confirmed, 4 a writable window on it
        // refused (it masters the bus), 5 an I/O port range over a bus
        // master's I/O BAR (or the ISA DMA ports) refused, `bytes` then holds
        // `first | last << 16`. A map refused: 6 a kernel driver owns the
        // device or may still take it, 7 the device has no domain ring 3 may
        // map into, 8 the object or the device is bound or being ended, 9 no
        // free record or the caller's share is held, 10 the object is not one
        // a device may be given, 11 the domain refused the mapping (`bytes` the
        // object's); 12 an unmap of a binding the caller does not hold.
        name: "ring3-dma",
        subject: "device",
        fields: ["tid", "bytes", "why"],
        rejected_if_yes: "refuse ring 3 every device no IOMMU confines: its drivers stay in the kernel",
        rejected_if_no: "let a ring-3 driver program a device that reaches any physical address: the kernel's memory is the driver's to write",
    },
    RuleInfo {
        // why: 0 `irq.<N>`: a device ring 3 may not have raises the line, 1
        // `irq.<selector>`: the device is not one ring 3 may have, 2
        // `irq.<selector>`: its line is shared with one, 3 no device matches
        // the selector, 4 the device has no line known, 5 `irq.<N>` past the
        // controller's lines, 6 `msi.<k>` where the platform has no MSI for
        // ring 3 (x86_64 without interrupt remapping or
        // the acceptance, riscv64 behind an IOMMU) or past 16 bits.
        name: "line-grant",
        subject: "tid",
        fields: ["line", "-", "why"],
        rejected_if_yes: "refuse a ring-3 driver every line a kernel driver's device raises, polled or not",
        rejected_if_no: "grant a line a kernel device shares: the ring-3 holder takes interrupts of a device it does not drive",
    },
    RuleInfo {
        // why: 0 a vector kept for its slot at a holder's unbind or exit (a
        // Place: not a refusal), 1 a bind refused: the slot holds its limit
        // of vectors (IRQ_MSI_PER_SLOT), 2 a bind refused: the slots that hold
        // vectors are at their limit (IRQ_MSI_SLOTS), 3 a device's registers or
        // ports refused arrival in a task that holds a slot (the vector word
        // holds the capability's resource, the subject the receiving task).
        name: "msi-vector",
        subject: "tid",
        fields: ["vector", "slot", "why"],
        rejected_if_yes: "return a given-back vector to the pool: the next holder of it receives the old device's interrupts",
        rejected_if_no: "let one slot take the pool: a row that forks drains the vectors every other driver needs",
    },
    RuleInfo {
        // The subject is the task that asked (0 for the pool). `camera` is the
        // `frame.<n>` index, `seq` the frame's sequence number for reason 3 (else 0), `reason` 0 the task
        // became a reader (granted), 1 its class has no `cam` effect, 2 every reader slot is taken,
        // 3 its first frame was read, 4 the pool could not be made (`seq` is the buffers that were).
        name: "cam-capture",
        subject: "tid",
        fields: ["camera", "seq", "reason"],
        rejected_if_yes: "let the task read the camera: its class has the cam effect and a slot is free",
        rejected_if_no: "refuse the reader: a camera must not be read without the grant, and every read must have a record",
    },
    RuleInfo {
        // The subject is the victim task. `reason` is 1 the allocator was empty breaking copy-on-write, 2 the
        // Domain had no room for the kernel memory a first touch needs; `charge` the frames the victim's Domain
        // held; `step` the Domain's pressure level when the task died (0 normal, 1 warning: reclaim was due, 2
        // critical: at its limit), so "why was my task killed" can be told from the reclaim steps before it.
        name: "mem-kill",
        subject: "tid",
        fields: ["reason", "charge", "step"],
        rejected_if_yes: "let the task run on: it could not be given the memory its access needs",
        rejected_if_no: "-",
    },
    RuleInfo {
        // The subject is the task that handed the region. `region` is the object's packed reference, `pages` its
        // size, `site` 1 a device or sound queue, 2 a NIC queue, 3 a buffer shared for one call.
        name: "swappable-ring",
        subject: "tid",
        fields: ["region", "pages", "site"],
        rejected_if_yes: "-",
        rejected_if_no: "address the object: a ring end that reads and writes by address cannot have its page taken out under it",
    },
    RuleInfo {
        // The subject is the Domain whose storm it was. `object` is the object's packed reference, `mapper` the
        // process that pins it, `pages` the object's size.
        name: "reclaim-skip",
        subject: "domain",
        fields: ["object", "mapper", "pages"],
        rejected_if_yes: "-",
        rejected_if_no: "take the object's pages: a real-time or locked mapper would fault on memory that was out",
    },
    RuleInfo {
        // The subject is the task that asked. `object` is the object's packed reference (0 for a change of class
        // or a Domain lock, which concern all of the process's or the Domain's), `site` 1 a map by a process already
        // admitted, 3 a change to a real-time class or priority, 4 an exec that locks its Domain, 5 a
        // `MEMOBJ_RESTORE`, `errno` why it was refused.
        name: "pin-restore",
        subject: "tid",
        fields: ["object", "site", "errno"],
        rejected_if_yes: "-",
        rejected_if_no: "book the mapping or the class: a real-time task would take its first fault on memory that is out",
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

/// Ids claimed when the ring is not built (the durable path's alone).
static SEQ: AtomicU64 = AtomicU64::new(0);
/// Gate canary `canary=decision-skip`: [`record`] writes nothing.
static SKIP: AtomicBool = AtomicBool::new(false);
/// Gate canary `canary=refusal-limit-off`: no rule is caller-paced.
static PACE_OFF: AtomicBool = AtomicBool::new(false);

azos_common::ro_hook! {
    /// The durable sink: the refusal as a [`ProvenanceRecord`]. Unset: none.
    static SINK: fn(&ProvenanceRecord);
}

/// Durable denials per second per subject (Kconfig
/// `DECISION_DENY_DURABLE_PER_SEC`); 0: no durable denial record.
pub const DENY_DURABLE_PER_SEC: u64 = azos_limits::DECISION_DENY_DURABLE_PER_SEC as u64;
/// The bucket depth (Kconfig `DECISION_DENY_DURABLE_BURST`).
pub const DENY_DURABLE_BURST: u64 = azos_limits::DECISION_DENY_DURABLE_BURST as u64;
const _: () = assert!(DENY_DURABLE_BURST >= 1 && DENY_DURABLE_BURST <= 64);
const _: () = assert!(DENY_DURABLE_PER_SEC <= 1000);

azos_common::ro_hook! {
    /// The kernel clock's reading, with [`CLOCK_HZ`] its ticks per second. The
    /// denial buckets refill on it and every stored record is stamped with it.
    static CLOCK_NOW: fn() -> u64;
}
static CLOCK_HZ: AtomicU64 = AtomicU64::new(1);

azos_common::ro_hook! {
    /// The `flags` of a record stamped now (`azos_records::FLAG_CLOCK_UNCALIBRATED`
    /// while the clock does not run at its rate yet).
    static CLOCK_FLAGS: fn() -> u8;
}

/// Install the record flags source (the kernel, at boot, with the clock).
pub fn set_clock_flags(f: fn() -> u8) {
    CLOCK_FLAGS.set(f);
}

/// Records of caller-paced rules the rate limit dropped since boot.
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
    CLOCK_NOW.set(now);
}

pub(crate) fn clock_now() -> u64 {
    match CLOCK_NOW.get() {
        Some(f) => f(),
        None => 0,
    }
}

/// Timebase ticks to nanoseconds with the installed clock (0 without one).
pub fn ticks_to_ns(t: u64) -> u64 {
    if !CLOCK_NOW.is_set() {
        return 0;
    }
    ((t as u128 * 1_000_000_000) / CLOCK_HZ.load(Ordering::Relaxed) as u128).min(u64::MAX as u128) as u64
}

azos_common::ro_hook! {
    /// The TAI-minus-monotonic offset, in nanoseconds (unset = none yet): the
    /// vDSO's `ClockOffsets::tai`, installed by [`set_tai_offset`].
    static TAI_OFFSET: fn() -> u64;
}

/// Install the TAI source (the kernel, at boot, with the clock): `offset`
/// returns the TAI-minus-monotonic offset in nanoseconds
/// (`azos_abi::time::ClockOffsets::tai`), 0 until PTP or NTP has set it. Owner
/// decision 16-10: a record is stamped on TAI-based monotonic time, the
/// timebase's reading plus that offset. Until the offset is set a stamp is the
/// time since boot, and it is applied when the record is widened, so a ring
/// record written before the first sync reads on TAI like one written after.
pub fn set_tai_offset(offset: fn() -> u64) {
    TAI_OFFSET.set(offset);
}

/// Timebase ticks to TAI nanoseconds (0 without a clock): [`ticks_to_ns`]
/// plus the installed TAI offset.
pub fn ticks_to_tai_ns(t: u64) -> u64 {
    let ns = ticks_to_ns(t);
    match TAI_OFFSET.get() {
        Some(f) if ns != 0 => ns.saturating_add(f()),
        _ => ns,
    }
}

/// Records of caller-paced rules the rate limit dropped since boot (not
/// written durably; each is in a [`Rule::RefusalLimited`] report).
pub fn deny_dropped_total() -> u64 {
    DENY_DROPPED.load(Ordering::Relaxed)
}

/// May this caller-paced record leave a durable record? `Some(since)`: yes, and
/// `since` is the number the (`bucket`, `rule`) pair dropped since its last
/// record. `None`: dropped, counted and reported.
#[inline(never)]
fn paced_admit(rule: Rule, bucket: u32) -> Option<u32> {
    let (now, hz) = (clock_now(), CLOCK_HZ.load(Ordering::Relaxed));
    let o = BUCKETS.with(|l| l.admit(bucket, rule as u8, now, DENY_DURABLE_PER_SEC, DENY_DURABLE_BURST, hz));
    if let Some(r) = o.evicted {
        report_limited(r.key, r.rule, r.count, false);
    }
    match o.gate {
        deny::Gate::Admit { owed, since } => {
            // A denial carries its count in its own third number.
            if owed > 0 && rule != Rule::CapDenial {
                report_limited(bucket, rule as u8, owed, false);
            }
            Some(since)
        }
        deny::Gate::Drop { first } => {
            DENY_DROPPED.fetch_add(1, Ordering::Relaxed);
            if first {
                report_limited(bucket, rule as u8, 1, true);
            }
            None
        }
    }
}

/// Write the report of drops: `held` records of `rule` from the Domain `key`.
#[inline(never)]
fn report_limited(key: u32, rule: u8, held: u32, started: bool) {
    record_full(Rule::RefusalLimited, Verdict::Refuse, key, key, [rule as u64, held as u64, started as u64], Origin::default());
}

/// Report the drops of every (Domain, rule) pair that dropped and has been
/// quiet for a second, so a flood that stops leaves its count on the medium
/// without waiting for the pair's next record. The log flusher calls it once
/// a pass.
pub fn flush_limited() {
    if !DURABLE || DENY_DURABLE_PER_SEC == 0 || !SINK.is_set() {
        return;
    }
    let (now, hz) = (clock_now(), CLOCK_HZ.load(Ordering::Relaxed));
    let mut runs = [deny::Run { key: 0, rule: 0, count: 0 }; deny::SLOTS];
    let mut n = 0;
    BUCKETS.with(|l| {
        l.idle(now, hz, |r| {
            runs[n] = r;
            n += 1;
        })
    });
    for r in &runs[..n] {
        report_limited(r.key, r.rule, r.count, false);
    }
}

azos_common::ro_hook! {
    /// Called with a record's id once it is stored (in the ring or the
    /// journal), and whether it went down the durable path, where it was
    /// recorded: the kernel's introspection tree writes it into the admin
    /// region's records ([`view_slot`]). Any context (some records are made
    /// on the wake path): the hook takes no lock. Unset: none.
    static VIEW: fn(u64, bool);
}

/// Install the [`VIEW`] hook (the kernel, at boot).
pub fn set_view_sink(f: fn(u64, bool)) {
    VIEW.set(f);
}

#[inline(never)]
fn view(seq: u64, durable: bool) {
    if let Some(f) = VIEW.get() {
        f(seq, durable);
    }
}

/// The slot of a view of `rows` slots (the admin region's records) that
/// record `seq` takes. `durable_nth`: how many durable records came before
/// it, for one that went down the durable path; `None` for the others.
///
/// `split` (the ring and the durable path both built): the durable records
/// (refusals, logins, a driver's move, the denials the bucket let through)
/// keep the first half to themselves, by their own count, and the ring's
/// other records share the second half by id. Keyed by id alone, the wake
/// path, which records a placement on every migrating wake, pushed an audit
/// record out of the view within seconds, though the journal still held it
/// (the gate's `login:` rows found no login decision). Not split, every
/// record is of one kind and takes slot `seq % rows`.
pub const fn view_slot(rows: usize, split: bool, seq: u64, durable_nth: Option<u64>) -> usize {
    let half = rows / 2;
    if !split || half == 0 {
        return (seq % rows as u64) as usize;
    }
    match durable_nth {
        Some(n) => (n % half as u64) as usize,
        None => half + (seq % (rows - half) as u64) as usize,
    }
}

/// Is record `id` held as a durable one (in the journal)? For a view that
/// fills its slots after the fact ([`view_slot`]).
pub fn durable_held(id: u64) -> bool {
    DURABLE && journal::get(id).is_some()
}

/// Install the durable refusal sink (the kernel, at boot, once the flight
/// recorder can take a record). A refusal raised before that is in the ring
/// (when it is on) and in the journal, and not on the medium.
pub fn set_durable_sink(f: fn(&ProvenanceRecord)) {
    SINK.set(f);
}

/// Write one record. Empty when both the ring and the durable sink are off.
///
/// `ON`: the ring takes every verdict. `DURABLE`: a [`Verdict::Refuse`] also
/// goes to the sink (a caller-paced rule's through its bucket, below), and so
/// does a [`Verdict::Place`] of
/// [`Rule::Placement`] (a driver's move) and every verdict of [`Rule::Login`]
/// (who was let in is an audit record like who was kept out, and a ring that
/// the wake path fills in seconds would lose it); a [`Verdict::Deny`] of a
/// [`Rule::CapDenial`] goes there when the Domain's bucket has a token (see
/// [`record_keyed`]), and its third number then carries the count of denials
/// dropped since the last one written (a `Deny` site has that number free), in
/// the ring record too. The tests are on constants
/// (and on the verdict, so a site that passes a literal verdict other than
/// `Refuse` or `Deny` folds it away): a build with neither compiles to
/// nothing.
#[inline(always)]
pub fn record(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) {
    record_keyed(rule, verdict, subject, subject, n);
}

/// [`record`], returning the record's id: the receipt a refusal hands back.
/// 0 when the record was stored nowhere (the ring and the durable sink are
/// both off in this build, or the `decision-skip` gate canary is armed), so
/// 0 is never a valid receipt.
#[inline(always)]
pub fn record_receipt(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) -> u64 {
    record_keyed(rule, verdict, subject, subject, n)
}

/// [`record`] with the durable bucket keyed by `bucket` instead of the
/// subject: a site that can name the subject's Domain passes its key, so the
/// threads of one process share one bucket (a loop of threads denied in
/// parallel is one subject, not 16).
///
/// Only a [`Rule::caller_paced`] rule goes through the bucket. The warrant
/// rules' `Deny` ([`Rule::CapRevoke`]) are audit records of an operation that
/// happened, whose third number is the slots revoked; they stay in the ring,
/// as before the bucket, and are neither limited nor overwritten.
#[inline(always)]
pub fn record_keyed(rule: Rule, verdict: Verdict, subject: u32, bucket: u32, n: [u64; 3]) -> u64 {
    record_full(rule, verdict, subject, bucket, n, Origin::default())
}

/// What a caller knows of a decision's subject beyond its number: the
/// topology row it is about (1-based, 0 for none) and the first 8 bytes of
/// its image's hash (0 for none), the [`ProvenanceRecord`] fields the
/// journal and the durable sink keep.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Origin {
    pub topology_row_id: u32,
    pub image_hash_prefix: u64,
}

/// [`record`] with the subject's [`Origin`]: a package install names the
/// package (its id's prefix) and the first row it adds, and the receipt
/// keeps both.
#[inline(always)]
pub fn record_with(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3], origin: Origin) -> u64 {
    record_full(rule, verdict, subject, subject, n, origin)
}

#[inline(always)]
fn record_full(rule: Rule, verdict: Verdict, subject: u32, bucket: u32, n: [u64; 3], origin: Origin) -> u64 {
    let mut n = n;
    // A refusal is always a receipt, but for the rules a task can raise once
    // per syscall (`Rule::caller_paced`), which pass the per-Domain bucket. A
    // driver's move is a receipt too: it changes which host holds a device's
    // authority, so it is kept whole in the journal and on the medium like a
    // refusal is. So is every login verdict: a session opened is as much an
    // audit record as an attempt refused.
    let paced = DURABLE
        && matches!(verdict, Verdict::Refuse | Verdict::Deny)
        && rule.caller_paced()
        && !PACE_OFF.load(Ordering::Relaxed);
    let mut to_sink = DURABLE
        && !paced
        && (matches!(verdict, Verdict::Refuse)
            || matches!(rule, Rule::Login)
            || (matches!(verdict, Verdict::Place) && matches!(rule, Rule::Placement)));
    if paced {
        if !SINK.is_set() {
            to_sink = matches!(verdict, Verdict::Refuse);
        } else if DENY_DURABLE_PER_SEC == 0 {
            DENY_DROPPED.fetch_add(1, Ordering::Relaxed);
        } else if let Some(since) = paced_admit(rule, bucket) {
            if rule == Rule::CapDenial {
                n[2] = since as u64;
            }
            to_sink = true;
        }
    }
    // The id: claimed by a record that is stored anywhere (with the ring, the
    // ring's index claims it). `SKIP` (gate canary) claims none, so nothing
    // is stored.
    let seq = if ON { write(rule, verdict, subject, n) } else if to_sink { claim() } else { 0 };
    if to_sink {
        durable(rule, verdict, subject, n, seq, origin);
    }
    // A paced rule's record the bucket held back is not copied either: the
    // bucket's own `RefusalLimited` report is, so a flood of denials cannot
    // push a microphone's record out of the security ring unseen.
    if azos_records::SECURITY && (!paced || to_sink) {
        if let Some(class) = rule.security_class(n[0]) {
            security(class, rule, verdict, subject, n, seq, origin);
        }
    }
    if seq != 0 {
        view(seq, to_sink);
    }
    seq
}

#[inline(never)]
fn durable(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3], seq: u64, origin: Origin) {
    // The fields no call site has a source for yet stay 0 (see `prov`).
    let mut p = ProvenanceRecord::new(rule as u8, verdict as u8, subject, n);
    p.seq = seq;
    p.topology_row_id = origin.topology_row_id;
    p.image_hash_prefix = origin.image_hash_prefix;
    // A placement's subject is its topology row's index; the wire's row ids
    // are 1-based (`ProvenanceRecord::topology_row_id`).
    if rule == Rule::Placement {
        p.topology_row_id = subject.wrapping_add(1);
    }
    // Kept in full, before the sink: the journal is what `lookup` and `query`
    // read when the ring is not built, and it does not wait for the recorder.
    if seq != 0 {
        p.clock_ns = ticks_to_tai_ns(clock_now());
        journal::store(&p);
    }
    if let Some(f) = SINK.get() {
        f(&p);
    }
}

/// Copy a record to the security ring (`azos_seclog`'s event).
#[inline(never)]
fn security(class: SecClass, rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3], seq: u64, origin: Origin) {
    let Some(w) = azos_records::writer(azos_records::SOURCE_SECURITY) else { return };
    let e = azos_seclog::Event {
        id: seq,
        subject,
        rule: rule as u8,
        verdict: verdict as u8,
        class,
        n,
        image_hash_prefix: origin.image_hash_prefix,
        topology_row_id: origin.topology_row_id,
    };
    let h = azos_records::Head {
        ts: clock_now(),
        clock: azos_records::CLOCK_TIMEBASE,
        kind: azos_seclog::kind::EVENT,
        len: azos_seclog::Event::LEN as u16,
        cpu: 0,
        flags: CLOCK_FLAGS.get().map_or(0, |f| f()),
    };
    w.publish(&h, |p| p.bytes(0, &e.encode()));
}

/// Claim the next id without the ring; 0 under the gate canary `decision-skip`.
#[inline(never)]
fn claim() -> u64 {
    if SKIP.load(Ordering::Relaxed) {
        return 0;
    }
    SEQ.fetch_add(1, Ordering::Relaxed) + 1
}

/// Store a record in the ring; its id (0 under `decision-skip`). A build
/// whose Kconfig keeps no ring (the feature without the symbol) claims the
/// id alone.
#[inline(never)]
fn write(rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) -> u64 {
    if SKIP.load(Ordering::Relaxed) {
        return 0;
    }
    #[cfg(feature = "on")]
    if let Some(w) = azos_records::writer(azos_records::SOURCE_DECISION) {
        let h = azos_records::Head {
            ts: clock_now(),
            clock: azos_records::CLOCK_TIMEBASE,
            kind: rule as u16 | (verdict as u16) << 8,
            len: azos_records::DECISION_PAYLOAD as u16,
            // The crate has no CPU id: a decision's envelope says 0.
            cpu: 0,
            flags: CLOCK_FLAGS.get().map_or(0, |f| f()),
        };
        let i = w.publish(&h, |p| {
            p.word(0, subject as u64);
            p.word(8, n[0]);
            p.word(16, n[1]);
            p.word(24, n[2]);
        });
        return i + 1;
    }
    let _ = (rule, verdict, subject, n);
    claim()
}

/// Ids claimed since boot (the newest record's id).
pub fn total() -> u64 {
    #[cfg(feature = "on")]
    if let Some(r) = azos_records::reader(azos_records::SOURCE_DECISION) {
        return r.head();
    }
    SEQ.load(Ordering::Relaxed)
}

/// Record `seq`, if it is still in the ring and was not being rewritten.
pub fn get(seq: u64) -> Option<Record> {
    if seq == 0 {
        return None;
    }
    #[cfg(feature = "on")]
    if let Some(r) = azos_records::reader(azos_records::SOURCE_DECISION) {
        let (mut c, mut env, mut p) = (seq - 1, rec_ring::Envelope::default(), [0u8; azos_records::DECISION_PAYLOAD]);
        if r.read(&mut c, &mut env, &mut p) != rec_ring::Read::Record {
            return None;
        }
        let w = |i: usize| u64::from_le_bytes([p[i], p[i + 1], p[i + 2], p[i + 3], p[i + 4], p[i + 5], p[i + 6], p[i + 7]]);
        return Some(Record {
            seq,
            rule: env.kind as u8,
            verdict: (env.kind >> 8) as u8,
            subject: w(0) as u32,
            n: [w(8), w(16), w(24)],
            ts: env.ts,
        });
    }
    None
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

/// Gate canary `canary=refusal-limit-off` (the kernel calls it at boot): the
/// durable rate limit holds nothing back.
pub fn set_pace_off() {
    PACE_OFF.store(true, Ordering::Relaxed);
}
