// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Types representing a parsed AZOS topology.
//!
//! All structures are fixed-size and `Copy`; the topology is built
//! during boot in a stack/static buffer and never re-allocated.

use azos_abi::cap::{CapKind, CapPerms};
pub use azos_limits::{MAX_TASKS, MAX_CAPS_TOTAL};

use crate::placement::PlaceSpec;
use crate::{AdmissionError, RowKind};

// ──────────────────────────────────────────────────────────────────────────
// Bounds — fixed at compile time.
// ──────────────────────────────────────────────────────────────────────────

/// Maximum scheduler classes per topology (Kconfig `TOPOLOGY_MAX_CLASSES`).
pub const MAX_CLASSES: usize = azos_limits::TOPOLOGY_MAX_CLASSES;

/// Maximum length of a task or class name (in bytes). Names beyond this
/// are rejected with `ParseError::NameTooLong` (Kconfig `TOPOLOGY_NAME_MAX`).
pub const MAX_TASK_NAME_LEN: usize = azos_limits::TOPOLOGY_NAME_MAX;

/// Maximum length of a cap-target string (e.g. `/cmd/motor`,
/// `bus.0/0x68`). Longer values are rejected (Kconfig `TOPOLOGY_TARGET_MAX`).
pub const MAX_TARGET_LEN: usize = azos_limits::TOPOLOGY_TARGET_MAX;

// ──────────────────────────────────────────────────────────────────────────
// Bounded string — borrows from input bytes
// ──────────────────────────────────────────────────────────────────────────

/// A small string borrowed from the input TOML buffer.
///
/// `MaybeStr` is `Copy` so it can live in the topology's static arrays
/// without owning anything. Equality compares the byte content.
#[derive(Clone, Copy, Debug)]
pub struct MaybeStr<'a> {
    bytes: &'a [u8],
}

impl<'a> MaybeStr<'a> {
    /// Construct from a byte slice. The bytes must be valid UTF-8 — no
    /// runtime check; the parser guarantees this.
    #[inline]
    pub const fn from_bytes(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Borrow as `&str`. Safe because the parser only emits ASCII or
    /// validated UTF-8 ranges.
    #[inline]
    pub fn as_str(&self) -> &'a str {
        // The parser only accepts a printable ASCII subset for names and
        // targets, so this is always valid UTF-8.
        core::str::from_utf8(self.bytes).unwrap_or("")
    }

    /// Returns the underlying byte slice.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns `true` iff this string is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Length in bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl PartialEq for MaybeStr<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for MaybeStr<'_> {}

impl<'a> PartialEq<&str> for MaybeStr<'a> {
    fn eq(&self, other: &&str) -> bool {
        self.bytes == other.as_bytes()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Scheduler class
// ──────────────────────────────────────────────────────────────────────────

/// How the scheduler dispatches a class's tasks: one name per dispatch class
/// the scheduler has (`crates/core/sched/src/classes.rs`, "The mapping").
/// Which one a task actually gets follows from its priority and reservation
/// (a reserved task is DL, a band priority RT, any other fair), so a class's
/// policy says what its range and `admission_control` lead to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PolicyKind {
    /// The real-time band: fixed priority, FIFO inside a level, below
    /// `RT_BAND_THRESHOLD`.
    Fifo = 0,
    /// Earliest-Deadline-First with a Constant Bandwidth Server: the rows'
    /// admitted reservations (`admission_control`).
    Edf = 1,
    /// Fair share (EEVDF), the priority a weight.
    Fair = 2,
    /// The per-CPU idle level.
    Idle = 3,
}

impl PolicyKind {
    /// Parse from the literal TOML string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "fifo" => Some(Self::Fifo),
            "edf" => Some(Self::Edf),
            "fair" => Some(Self::Fair),
            "idle" => Some(Self::Idle),
            _ => None,
        }
    }

    /// The literal TOML string [`PolicyKind::from_str`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Edf => "edf",
            Self::Fair => "fair",
            Self::Idle => "idle",
        }
    }
}

/// Preemption policy for a scheduler class.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Preemption {
    /// Always preempt on a higher-priority arrival.
    Always = 0,
    /// Preempt only when a timer fires.
    TimerOnly = 1,
    /// Never preempt (cooperative).
    Never = 2,
}

impl Preemption {
    /// Parse from the literal TOML string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "always" => Some(Self::Always),
            "timer-only" => Some(Self::TimerOnly),
            "never" => Some(Self::Never),
            _ => None,
        }
    }

    /// The literal TOML string [`Preemption::from_str`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::TimerOnly => "timer-only",
            Self::Never => "never",
        }
    }
}

/// How far a principal's effects are allowed to go: the degrade vocabulary of
/// `crates/domains/robot/degrade-policy` (`DEGRADE_LEVEL_*`), ordered from no
/// restriction to none at all. The same word is a class's `envelope`, a guest's
/// `envelope` and a `[degrade.NAME]` row's `level`.
///
/// The levels form a chain, so the effect gate's *meet* of several
/// contributors' envelopes is the most restrictive one ([`Envelope::meet`]).
///
/// Consumed by B4-MEET (W16, class `envelope`), HV-CORE (W19, guest egress),
/// BATTERY (W24, `[degrade.NAME]`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Envelope {
    /// No restriction (`DEGRADE_LEVEL_FULL`). The default of a class.
    Full = 0,
    /// Reduced authority (`DEGRADE_LEVEL_CAUTIOUS`).
    Cautious = 1,
    /// Slow envelope (`DEGRADE_LEVEL_SLOW`).
    Slow = 2,
    /// No effect at all (`DEGRADE_LEVEL_CONTAINED`).
    Contained = 3,
}

impl Envelope {
    /// The row value: `"full"`, `"cautious"`, `"slow"`, `"contained"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"full" => Some(Envelope::Full),
            b"cautious" => Some(Envelope::Cautious),
            b"slow" => Some(Envelope::Slow),
            b"contained" => Some(Envelope::Contained),
            _ => None,
        }
    }

    /// The row value [`Envelope::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            Envelope::Full => "full",
            Envelope::Cautious => "cautious",
            Envelope::Slow => "slow",
            Envelope::Contained => "contained",
        }
    }

    /// The meet of two envelopes: the more restrictive one.
    pub const fn meet(self, other: Self) -> Self {
        if self as u8 >= other as u8 { self } else { other }
    }
}

/// What kind of principal the tasks of a class act as. A provenance label
/// (innovation B4) is the set of kinds a value has passed through, so a value
/// an `Agent` touched is held to the agent class's envelope even through a
/// `Service`.
///
/// Consumed by B4-LABEL (W15: the sender's kind is ORed into the message
/// label) and B4-MEET (W16).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PrincipalKind {
    /// Platform code the signed topology itself vouches for. The default.
    System = 0,
    /// An application service.
    Service = 1,
    /// A human user's session (a warrant-subtree root).
    User = 2,
    /// An AI agent: untrusted ring-3 code the kernel holds to an envelope.
    Agent = 3,
}

impl PrincipalKind {
    /// The row value: `"system"`, `"service"`, `"user"`, `"agent"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"system" => Some(PrincipalKind::System),
            b"service" => Some(PrincipalKind::Service),
            b"user" => Some(PrincipalKind::User),
            b"agent" => Some(PrincipalKind::Agent),
            _ => None,
        }
    }

    /// The row value [`PrincipalKind::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            PrincipalKind::System => "system",
            PrincipalKind::Service => "service",
            PrincipalKind::User => "user",
            PrincipalKind::Agent => "agent",
        }
    }
}

/// One scheduler class as declared in `SCHED.TOML`.
#[derive(Clone, Copy, Debug)]
pub struct ClassSpec<'a> {
    /// Class name, e.g. `"safety_critical"`. Borrowed from input.
    pub name: MaybeStr<'a>,
    /// Lower budget bound, percent of CPU per partition window.
    pub cpu_budget_min_pct: u8,
    /// Upper budget bound, percent of CPU per partition window.
    pub cpu_budget_max_pct: u8,
    /// Scheduling policy.
    pub policy: PolicyKind,
    /// Inclusive priority range `[lo, hi]` within the class.
    pub priority_range: (u8, u8),
    /// Preemption rule.
    pub preemption: Preemption,
    /// Declared time slice in milliseconds. No dispatch class reads it: the
    /// fair class's slice is Kconfig `FAIR_SLICE_US`.
    pub time_slice_ms: u16,
    /// Whether to reject task admissions that violate Liu-Layland.
    pub admission_control: bool,
    /// `envelope = "full" | "cautious" | "slow" | "contained"` (SCHED.TOML):
    /// the ceiling on the physical effects the tasks of this class may cause.
    /// [`Envelope::Full`] unless declared. Consumed by B4-MEET (W16), which
    /// takes the meet of the envelopes of every class a value passed through.
    pub envelope: Envelope,
    /// `principal = "system" | "service" | "user" | "agent"` (SCHED.TOML):
    /// who the tasks of this class act as. [`PrincipalKind::System`] unless
    /// declared. Consumed by B4-LABEL (W15) and B4-MEET (W16).
    pub principal: PrincipalKind,
}

impl<'a> ClassSpec<'a> {
    /// Construct an empty placeholder class. Used only to fill the
    /// fixed array; never seen by user code outside the parser.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            cpu_budget_min_pct: 0,
            cpu_budget_max_pct: 0,
            policy: PolicyKind::Fifo,
            priority_range: (0, 0),
            preemption: Preemption::Always,
            time_slice_ms: 0,
            admission_control: false,
            envelope: Envelope::Full,
            principal: PrincipalKind::System,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Task + cap specs
// ──────────────────────────────────────────────────────────────────────────

/// One capability grant declared in `CAPS.TOML`.
#[derive(Clone, Copy, Debug)]
pub struct CapSpec<'a> {
    /// Kind tag of the capability.
    pub kind: CapKind,
    /// Permission bits.
    pub perms: CapPerms,
    /// Target string, e.g. `/cmd/motor`, `motor.0`, `bus.0/0x68`.
    /// Resource-specific resolution happens during task spawn.
    pub target: MaybeStr<'a>,
    /// Whether the minted capability carries `CapPerms::DELEGATE`, `DUP` and
    /// `TRANSFER` (owner decision 2026-09-26, O3.4; `TRANSFER` split from `DUP`
    /// 2026-10-17): a task may hand a `TRANSFER`-bearing capability to another
    /// task via `move_cap`, and copy one that also carries `DUP`; without
    /// `TRANSFER` the move is refused. Defaults to `false` — a topology row
    /// transfers authority only when it says so with `transfer = true` (or the
    /// `t` letter of `perm`), never by omission. A *self-created* object's own
    /// creator gets `DELEGATE` through a separate path (the `_create_cap`
    /// syscalls stamp it directly, `crates/core/ipc`), not through this field:
    /// this field is for a capability the signed topology hands to a task
    /// that did not create the object. [`CapSpec::grant_perms`] is the one
    /// place the field is turned into rights.
    pub transfer: bool,
    /// The ops of a kernel-hosted interface the holder may call: bit n is the
    /// op numbered n of the interface, counted from 1 (the `ops` key of a row).
    /// 0 grants every op. A non-zero mask is minted as an `OP_MASK` caveat of
    /// the capability (`azos_ipc::cap::caveat::OP_MASK`), so the holder of a
    /// right on an interface calls only the ops the row lists, whatever the
    /// right would otherwise reach. Only a grant of a kernel-hosted interface
    /// carries one.
    pub ops: u64,
}

impl<'a> CapSpec<'a> {
    /// Construct an empty placeholder.
    pub const fn empty() -> Self {
        Self {
            kind: CapKind::Null,
            perms: CapPerms::NONE,
            target: MaybeStr::from_bytes(&[]),
            transfer: false,
            ops: 0,
        }
    }

    /// The rights the minted capability carries: `perms`, plus `DELEGATE`
    /// when the row says `transfer = true`. What every seeding path
    /// (autorun, spawn, native fork) hands to the minter.
    pub const fn grant_perms(&self) -> CapPerms {
        if self.transfer { self.perms.union(CapPerms::DELEGATE) } else { self.perms }
    }
}

/// One task as declared in `CAPS.TOML`.
#[derive(Clone, Copy, Debug)]
pub struct TaskSpec<'a> {
    /// Task name, must match an entry in SCHED.TOML.
    pub name: MaybeStr<'a>,
    /// Scheduler-class name this task belongs to (cross-referenced after
    /// parsing both files).
    pub class_name: MaybeStr<'a>,
    /// Static priority within the class.
    pub priority: u8,
    /// Index into the topology's caps pool.
    pub caps_start: u32,
    /// Number of caps belonging to this task.
    pub caps_count: u32,
    /// Declared real-time parameters, or `SchedProfile::NONE` for a best-effort
    /// task. Checked by [`Topology::deadline_admission`].
    pub profile: crate::deadline::SchedProfile,
    /// Owner decision 102 — this task's budget of physical frames, in 4 KiB
    /// pages. **`0` means no limit**, which is what every row that does not
    /// declare one gets.
    ///
    /// Scan unit 3 finding 3: CPU has quotas and memory had none, so one
    /// ring-3 task could walk `brk` until the page allocator was empty — and
    /// then the kernel heap, the copy-on-write break and every safety path
    /// that allocates fail too. A VA ceiling (`USER_LOW_MAX`) does not bound
    /// frames.
    ///
    /// Declared here, beside the capabilities and the seccomp profile,
    /// because that is where the rest of what a task is allowed to do is
    /// declared.
    pub mem_pages: u32,
    /// Owner decisions, rounds 13-14: `mem = "locked"` in the
    /// row. A locked row's `mem_pages` is a RESERVATION counted once by
    /// [`Topology::memory_admission`] and must be declared (non-zero); every
    /// other ring-3 row's `mem_pages` is a CEILING, counted twice there
    /// because the row may fork and its budget must cover a full COW copy
    /// (P3). A locked task may not call `SYS_FOREIGN_FORK` or
    /// reserve demand pages and is born only by spawn or exec. `false` unless declared.
    pub mem_locked: bool,
    /// How long, in milliseconds, an io_ring SQ poller of this task keeps
    /// polling an empty submission queue before it parks. **`0` means this
    /// task may not start an SQ poller at all**, which is what every row that
    /// does not declare one gets: a kernel task spinning on a ring costs a
    /// hart, so the signed topology decides who may have one
    /// (`crates/core/ipc/src/io_ring.rs`, `OP_SQPOLL_START`).
    pub sqpoll_idle_ms: u32,
    /// Wave 9: how many instances of this row may be live at
    /// once, `instances = N` in the row. `0` stands for the default, 1 (see
    /// [`TaskSpec::instance_count`]). [`Topology::memory_admission`] counts
    /// the row N times; the kernel refuses the N+1th live spawned (or exec'd)
    /// instance. Fork children are not instances: the memory budget bounds
    /// them.
    pub instances: u16,
    /// `start = true` in the row (wave 9, owner decision): the system starts
    /// this image at boot, from `/fat/<name>`, with the row's own
    /// capabilities, class and frame budget: the component manager does,
    /// except for its own row and a driver that moves between hosts, which
    /// the kernel's boot launcher starts.
    /// Only a row named after an image (`*.ELF`) can mean anything by it.
    /// `false` unless declared: nothing runs because a row exists.
    pub start: bool,
    /// `mem_huge_mib = N` in a `mem = "locked"` row (Kconfig
    /// `LOCKED_HUGE_LEAVES`, riscv64): N MiB reserved at boot, 2 MiB-aligned,
    /// and mapped at exec with 2 MiB leaves at the task's locked arena. Even,
    /// at most [`MAX_HUGE_MIB`]; `0` (the default) means no region. Counted by
    /// [`Topology::memory_admission`] as `N × 256` locked pages per instance.
    pub mem_huge_mib: u16,
    /// Wave 11 (DRVPLACE): `restart = always | on-failure | no` in the row
    /// (topology format 2), what the kernel's supervisor does when a
    /// supervised task of this row ends. [`RestartPolicy::OnFailure`] unless
    /// declared, which is what every row of a format-1 topology gets.
    pub restart: RestartPolicy,
    /// Wave 12: `abi = "native" | "linux"` in the row (topology
    /// format 3), the syscall table the image's numbers are read against.
    /// [`TaskAbi::Native`] unless declared: no image is translated because
    /// it looks like a Linux binary. A Linux row holds no hardware
    /// capability ([`Topology::set_last_task_abi`]).
    pub abi: TaskAbi,
    /// `timer_slack = true` in the row (CAPS.TOML format 5): the row's task may
    /// have its timers coalesced by its QoS tier (Kconfig
    /// `QOS_TIMER_TOLERANCE_ROWS_ONLY`: only such a row gets slack; without
    /// that option every fair task does and the key changes nothing). Never
    /// extends to a real-time or deadline task: the scheduler gives those
    /// none whatever the row says. `false` unless declared.
    pub timer_slack: bool,
    /// `lx_class = "<class>"` in the row (CAPS.TOML format 6): the row is the
    /// server of a Linux driver class (`lxsrv-<class>`), and the kernel starts
    /// it only once the hardware bus has bound a device one of that class's
    /// ids matched (`azos_hwbus::Bus::linux_class_wanted`). Empty unless
    /// declared: every other row starts as `start` says.
    pub lx_class: MaybeStr<'a>,
    /// Start of this row's names in the imports pool.
    pub imports_start: u32,
    /// `imports = [...]` (CAPS.TOML format 5): how many endpoint names the
    /// name server may hand this row. **A name is never authority; the list
    /// is what the signed row says it may ask for**, and the capability the
    /// server lends for one is a derived, attenuated link of the server's own.
    /// 0 unless the row declares them.
    pub imports_count: u32,
    /// `place`, `stateless` and `call_budget_us` in the row (CAPS.TOML format
    /// 6): the host the driver starts in, whether it may move between hosts
    /// at run time and the call budget a move to the kernel is admitted
    /// against. [`PlaceSpec::DEFAULT`] unless declared: ring 3, fixed there.
    pub place: PlaceSpec,
    /// Start of this row's entries in the exports pool.
    pub exports_start: u32,
    /// `export = [...]` (CAPS.TOML format 6): how many `NAME@CLASS` entries
    /// the RPC server's row declares, each the right to lend the endpoint
    /// `NAME` to the nodes of peer class `CLASS` ([`PeerSpec`]). **Nothing
    /// leaves the node except through one of these rows.** 0 unless declared;
    /// only the row of [`RPC_IMAGE`] may.
    pub exports_count: u32,
    /// `shadow = true` in the row (CAPS.TOML format 7): the row's task is
    /// admitted in observe-only mode. It spawns holding only weak
    /// (transitively read-only) capabilities, and each effect it asks for that
    /// a strong holder would have been refused is recorded as a would-be
    /// refusal instead of being applied. Authority is then granted by editing
    /// the signed row, with the records as evidence. `false` unless declared.
    /// Consumed by WEAK-CAPS (W12, `crates/core/sched/src/spawn.rs`).
    pub shadow: bool,
    /// `isolated = true` in the row (CAPS.TOML format 7): the row's real-time
    /// task owns one CPU of the `[sched] isolcpus` set alone, and that CPU may
    /// stop its periodic tick while the task runs (NOHZ-FULL: the CPU is in
    /// `isolcpus`, runs this one band task and nothing else, because fair
    /// tasks are not placed on `isolcpus` and no other row may be).
    /// Needs a declared real-time profile in a class with admission control,
    /// one instance, and a `cpu_mask` that names exactly one CPU of
    /// `isolcpus` no other isolated row names. A row with `isolated = true`
    /// and no `cpu_mask` is **refused** at admission
    /// (`Deadline(IsolatedWithoutCpu)`, a `DeadlineAdmission` refusal record at
    /// boot): the topology never chooses the CPU for it. `false` unless
    /// declared.
    pub isolated: bool,
    /// `kmem_kib = N` in the row (CAPS.TOML format 7): the kernel memory, in
    /// KiB, that kernel allocations made on behalf of this row's Domain (cap
    /// tables, endpoint queues, page tables, ...) may hold at once. **`0`
    /// means no ceiling of its own**, which is what every row that does not
    /// declare one gets. Consumed by KMEM-CHARGE (W12,
    /// `crates/core/mm/src/budget.rs`).
    pub kmem_kib: u32,
    /// `principal = "user"` in the row (CAPS.TOML format 7): who this row's
    /// task acts as, **over** what its class says. `None` (every row that
    /// does not declare one) is the class's. A class is a scheduling class, so
    /// it cannot tell one row of `best_effort` from another; this is how a row
    /// is the principal of a human's session (the SSH server) without a
    /// scheduling class of its own. Consumed by `apply_principal`
    /// (`crates/core/syscall/src/topo_sched.rs`), at the spawn of the row.
    pub principal: Option<PrincipalKind>,
    /// `security_boundary = true` in the row (CAPS.TOML format 8): the row's
    /// Domain is a security boundary, not only a grouping. Its memory and its
    /// authority are isolated from the other Domains by the hardware's
    /// partitioning, not by the kernel's bookkeeping alone. `false` unless
    /// declared.
    pub security_boundary: bool,
    /// `partition_id = N` in the row (CAPS.TOML format 8): the hardware
    /// resource partition (cache, memory-bandwidth and I/O partition id) the
    /// row's Domain runs in, 1 to 65535; 0 (absent) for none. Only a
    /// `security_boundary` row has one.
    pub partition_id: u16,
}

/// The syscall table a row's image is run against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskAbi {
    /// The AzOS syscall numbers. The default.
    Native,
    /// Linux numbers (asm-generic), translated by the kernel's Linux
    /// personality (Kconfig `LINUX_ABI`).
    Linux,
}

impl TaskAbi {
    /// The row value: `"native"`, `"linux"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"native" => Some(TaskAbi::Native),
            b"linux" => Some(TaskAbi::Linux),
            _ => None,
        }
    }

    /// The row value [`TaskAbi::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            TaskAbi::Native => "native",
            TaskAbi::Linux => "linux",
        }
    }

    /// Capability kinds a Linux row may hold: files, sockets, pipes and the
    /// right to start an image (a Linux task holds no hardware
    /// capability; it reaches the machine only through files and sockets
    /// that native tasks serve). Everything else is refused at admission.
    pub const fn linux_may_hold(kind: CapKind) -> bool {
        matches!(kind, CapKind::Node)
    }
}

/// What the supervisor does when a supervised task of a row ends (systemd's
/// `Restart=`). Restarts are counted against the same budget in every case
/// (`SUP_RESTART_BURST` within `SUP_RESTART_INTERVAL_S`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RestartPolicy {
    /// Restart after a failure (a non-zero exit code, a kill, a fault); a
    /// clean exit (code 0) ends it. The default.
    OnFailure,
    /// Restart after any end, a clean exit included.
    Always,
    /// Never restart: the first end, clean or not, is final.
    No,
}

impl RestartPolicy {
    /// The row value: `"always"`, `"on-failure"`, `"no"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"always" => Some(RestartPolicy::Always),
            b"on-failure" => Some(RestartPolicy::OnFailure),
            b"no" => Some(RestartPolicy::No),
            _ => None,
        }
    }

    /// The row value [`RestartPolicy::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            RestartPolicy::Always => "always",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::No => "no",
        }
    }
}

/// Largest `mem_huge_mib` a row may declare: 256 MiB, half of the 512 MiB
/// shm/MMIO window the region is placed in, which leaves the other half for
/// the task's shm and MMIO mappings.
pub const MAX_HUGE_MIB: u16 = 256;

impl<'a> TaskSpec<'a> {
    /// Construct an empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            class_name: MaybeStr::from_bytes(&[]),
            priority: 0,
            caps_start: 0,
            caps_count: 0,
            profile: crate::deadline::SchedProfile::NONE,
            mem_pages: 0,
            mem_locked: false,
            sqpoll_idle_ms: 0,
            instances: 0,
            start: false,
            mem_huge_mib: 0,
            restart: RestartPolicy::OnFailure,
            abi: TaskAbi::Native,
            timer_slack: false,
            lx_class: MaybeStr::from_bytes(&[]),
            imports_start: 0,
            imports_count: 0,
            place: PlaceSpec::DEFAULT,
            exports_start: 0,
            exports_count: 0,
            shadow: false,
            isolated: false,
            kmem_kib: 0,
            principal: None,
            security_boundary: false,
            partition_id: 0,
        }
    }

    /// [`TaskSpec::instances`] with the default applied: never 0.
    pub const fn instance_count(&self) -> u16 {
        if self.instances == 0 { 1 } else { self.instances }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Top-level topology
// ──────────────────────────────────────────────────────────────────────────

/// Optional global scheduler configuration declared at the top of
/// `SCHED.TOML`.
#[derive(Clone, Copy, Debug)]
pub struct SchedConfig {
    /// Adaptive Partitioning window in microseconds.
    pub partition_window_us: u32,
    /// `isolcpus = N` in `[sched]`: the CPUs kept for isolated real-time rows,
    /// bit n = CPU n like a profile's `cpu_mask`. Fair-share tasks are not
    /// placed on them, and a row with `isolated = true` runs on one of
    /// them ([`TaskSpec::isolated`]); no other row may run on one: a profile
    /// that names one is refused ([`Topology::admission_check`]) and a profile
    /// with no mask is placed off them ([`Topology::deadline_admission`]). `0`, the default, isolates none; a mask
    /// that covers every CPU of the machine is refused by
    /// [`Topology::deadline_admission`], since nothing could run the rest.
    /// Consumed by NOHZ-FULL (W20) and CPU-TOPO (W12).
    pub isolcpus: u32,
}

impl SchedConfig {
    /// Default: 10 ms window, no isolated CPU.
    pub const DEFAULT: Self = Self {
        partition_window_us: 10_000,
        isolcpus: 0,
    };
}

// `TaskSpec::caps_start` / `caps_count` index the capability pool as u32 (they
// were u16, one short of fleet's MAX_CAPS_TOTAL = 65 536). The counters themselves are `usize`: a u8
// task counter overflowed at the 256th row whatever MAX_TASKS allowed (fleet
// is 4096), and a u16 pool length stored 65 536 entries as 0 (wave 11 LIMDOC).
const _: () = assert!(MAX_CAPS_TOTAL <= u32::MAX as usize,
    "MAX_CAPS_TOTAL must fit TaskSpec::caps_start (u32)");

/// Parsed topology — the kernel-internal in-memory form of CAPS.TOML +
/// SCHED.TOML.
///
/// Lifetime `'a` is the lifetime of the source TOML byte buffers; the
/// kernel stores those in BSS and never frees them post-boot.
pub struct Topology<'a> {
    classes: [ClassSpec<'a>; MAX_CLASSES],
    classes_len: u8,
    tasks: [TaskSpec<'a>; MAX_TASKS],
    tasks_len: usize,
    caps_pool: [CapSpec<'a>; MAX_CAPS_TOTAL],
    caps_pool_len: usize,
    sched_config: SchedConfig,
    /// The e-stop release-authority public key declared by an `[operator]`
    /// section of `CAPS.TOML` (W2-B5). All-zero means "not
    /// declared", the same sentinel `/fat/OPERATOR.PUB`-loading code
    /// already treats as "no release authority provisioned" (see
    /// `azos_behavior::safety::operator_authority_init`). Declaring it
    /// here instead of on a loose, unsigned FAT file puts the key under
    /// the SAME `.SIG` sidecar as every other capability grant: a
    /// tampered or unsigned CAPS.TOML fails verification before this
    /// field is ever populated, whereas `/fat/OPERATOR.PUB` had (and,
    /// until a signed loader replaces `fill_default_minimal`, still has)
    /// no signature at all.
    operator_pubkey: [u8; 32],
    /// `[pipeline.NAME]` sections of `CAPS.TOML`: the DMA pool
    /// each declared pipeline needs. The boot pool is the larger of their sum
    /// and the Kconfig floor ([`Topology::dma_pool_pages`]).
    pipelines: [PipelineSpec<'a>; MAX_PIPELINES],
    pipelines_len: u8,
    /// The names rows import, `TaskSpec::imports_start`/`imports_count` slice it.
    imports_pool: [MaybeStr<'a>; IMPORTS_TOTAL],
    imports_pool_len: usize,
    /// `[device.NAME]` rows of `CAPS.TOML` (format 6): what the hardware bus
    /// does with the devices they select.
    devices: [DeviceSpec<'a>; MAX_DEVICE_ROWS],
    devices_len: u8,
    /// The `[signer.NAME]` sections of `CAPS.TOML` (format 6): the device
    /// policy of signed application packages.
    signers: [SignerSpec<'a>; MAX_SIGNERS],
    signers_len: u8,
    /// The warrant ceilings signers declare, `SignerSpec::warrants_start`/
    /// `warrants_count` slice it.
    warrants_pool: [MaybeStr<'a>; SIGNER_WARRANTS_TOTAL],
    warrants_pool_len: usize,
    /// The `export` entries of the RPC server's row, `TaskSpec::exports_start`/
    /// `exports_count` slice it.
    exports_pool: [ExportSpec<'a>; EXPORTS_TOTAL],
    exports_pool_len: usize,
    /// `[peer.NAME]` sections of `CAPS.TOML` (format 6): the classes of remote
    /// nodes an `export` may name.
    peers: [PeerSpec<'a>; MAX_PEERS],
    peers_len: u8,
    /// `[policy.NAME]` rows of `CAPS.TOML` (format 7).
    policies: [PolicySpec<'a>; MAX_POLICIES],
    policies_len: u8,
    /// `[livepatch.NAME]` rows of `CAPS.TOML` (format 7).
    livepatches: [LivepatchSpec<'a>; MAX_LIVEPATCHES],
    livepatches_len: u8,
    /// `[degrade.NAME]` rows of `CAPS.TOML` (format 7).
    degrades: [DegradeSpec<'a>; MAX_DEGRADE_ROWS],
    degrades_len: u8,
    /// The `[clock]` row of `CAPS.TOML` (format 7).
    clock: ClockSpec,
    /// `[swap.NAME]` rows of `CAPS.TOML` (format 7).
    swaps: [SwapSpec<'a>; MAX_SWAPS],
    swaps_len: u8,
    /// `[login.NAME]` rows of `CAPS.TOML` (format 7).
    logins: [LoginSpec<'a>; MAX_LOGINS],
    logins_len: u8,
    /// `[volume.NAME]` rows of `CAPS.TOML` (format 7).
    volumes: [VolumeSpec<'a>; MAX_VOLUMES],
    volumes_len: u8,
    /// `[guest.NAME]` rows of `CAPS.TOML` (format 7).
    guests: [GuestSpec<'a>; MAX_GUESTS],
    guests_len: u8,
    /// `[route.NAME]` rows of `CAPS.TOML` (format 7).
    routes: [RouteSpec<'a>; MAX_ROUTES],
    routes_len: u8,
    /// `[firewall.NAME]` rows of `CAPS.TOML` (format 7), in rule order.
    firewalls: [FirewallSpec<'a>; MAX_FIREWALL_ROWS],
    firewalls_len: u8,
    /// `[tsn.NAME]` rows of `CAPS.TOML` (format 8).
    tsns: Table<TsnSpec<'a>, MAX_TSN>,
    /// `[fieldbus.NAME]` rows (format 8).
    fieldbuses: Table<FieldbusSpec<'a>, MAX_FIELDBUS>,
    /// `[audio.NAME]` rows (format 8).
    audios: Table<AudioSpec<'a>, MAX_AUDIO>,
    /// `[display.NAME]` rows (format 8).
    displays: Table<DisplaySpec<'a>, MAX_DISPLAYS>,
    /// `[user.NAME]` rows (format 8).
    users: Table<UserSpec<'a>, MAX_USERS>,
    /// `[key.NAME]` rows (format 8).
    keys: Table<KeySpec<'a>, MAX_KEYS>,
    /// The `[mission]` row (format 8).
    mission: Option<MissionSpec<'a>>,
    /// `[boot_chain.NAME]` rows (format 8).
    boot_chain: Table<BootChainSpec<'a>, MAX_BOOT_STAGES>,
    /// `[island.NAME]` rows (format 8).
    islands: Table<IslandSpec<'a>, MAX_ISLANDS>,
    /// `[activity.NAME]` rows (format 8).
    activities: Table<ActivitySpec<'a>, MAX_ACTIVITIES>,
    /// `[numa.NAME]` rows (format 8).
    numas: Table<NumaSpec<'a>, MAX_NUMA>,
    /// `[envelope.NAME]` rows (format 8).
    envelopes: Table<EnvelopeSpec<'a>, MAX_ENVELOPES>,
    /// The `[rtc]` row (format 8).
    rtc: Option<RtcSpec<'a>>,
    /// `[nic.NAME]` rows (format 8).
    nics: Table<NicSpec<'a>, MAX_NICS>,
    /// `[model.NAME]` rows (format 8).
    models: Table<ModelSpec<'a>, MAX_MODELS>,
    /// `[usb.NAME]` rows (format 8), in rule order.
    usbs: Table<UsbSpec<'a>, MAX_USB_RULES>,
    /// The energy mode and model `SCHED.TOML` declares
    /// (`[energy]`, `[energy.domain.NAME]`). Only with the `energy` feature:
    /// without it the sections are skipped and the kernel runs with no model.
    #[cfg(feature = "energy")]
    energy: azos_energy::EnergySpec,
}

/// Maximum `[pipeline.NAME]` sections in one topology (Kconfig
/// `TOPOLOGY_MAX_PIPELINES`).
pub const MAX_PIPELINES: usize = azos_limits::TOPOLOGY_MAX_PIPELINES;

/// Maximum `[device.NAME]` rows in one topology (Kconfig
/// `TOPOLOGY_MAX_DEVICE_ROWS`).
pub const MAX_DEVICE_ROWS: usize = azos_limits::TOPOLOGY_MAX_DEVICE_ROWS;
const _: () = assert!(MAX_DEVICE_ROWS <= u8::MAX as usize, "MAX_DEVICE_ROWS is kept in a u8");

/// Bytes of a device row's `driver` name (the longest `hwbus.ids` driver name
/// has to fit; `azos_hwbus::NAME_LEN`).
pub const DEVICE_DRIVER_MAX: usize = 32;
/// Bytes of a device row's `match` selector text.
pub const DEVICE_SELECT_MAX: usize = 64;

/// Names one row may import (Kconfig `TOPOLOGY_MAX_IMPORTS`).
pub const MAX_IMPORTS: usize = azos_limits::TOPOLOGY_MAX_IMPORTS;
/// Imports across all rows (Kconfig `TOPOLOGY_IMPORTS_TOTAL`).
pub const IMPORTS_TOTAL: usize = azos_limits::TOPOLOGY_IMPORTS_TOTAL;

/// Package signers one topology admits (Kconfig `TOPOLOGY_MAX_SIGNERS`).
pub const MAX_SIGNERS: usize = azos_limits::TOPOLOGY_MAX_SIGNERS;
/// Warrant ceilings across all signers (Kconfig
/// `TOPOLOGY_SIGNER_WARRANTS_TOTAL`).
pub const SIGNER_WARRANTS_TOTAL: usize = azos_limits::TOPOLOGY_SIGNER_WARRANTS_TOTAL;
/// `[peer.NAME]` sections in one topology (Kconfig `TOPOLOGY_MAX_PEERS`).
pub const MAX_PEERS: usize = azos_limits::TOPOLOGY_MAX_PEERS;
/// Nodes one peer class may list (Kconfig `TOPOLOGY_PEER_NODES`).
pub const PEER_NODES: usize = azos_limits::TOPOLOGY_PEER_NODES;
/// `export` entries across all rows (Kconfig `TOPOLOGY_EXPORTS_TOTAL`).
pub const EXPORTS_TOTAL: usize = azos_limits::TOPOLOGY_EXPORTS_TOTAL;

/// `[policy.NAME]` rows in one topology (Kconfig `TOPOLOGY_MAX_POLICIES`).
pub const MAX_POLICIES: usize = azos_limits::TOPOLOGY_MAX_POLICIES;
const _: () = assert!(MAX_POLICIES <= u8::MAX as usize, "MAX_POLICIES is kept in a u8");

/// `[livepatch.NAME]` rows in one topology (Kconfig
/// `TOPOLOGY_MAX_LIVEPATCHES`).
pub const MAX_LIVEPATCHES: usize = azos_limits::TOPOLOGY_MAX_LIVEPATCHES;
const _: () = assert!(MAX_LIVEPATCHES <= u8::MAX as usize, "MAX_LIVEPATCHES is kept in a u8");

/// Entries of the `[clock]` row's TAI-UTC table (Kconfig
/// `TOPOLOGY_LEAP_ENTRIES`).
pub const LEAP_ENTRIES: usize = azos_limits::TOPOLOGY_LEAP_ENTRIES;
const _: () = assert!(LEAP_ENTRIES <= u8::MAX as usize, "LEAP_ENTRIES is kept in a u8");

/// The largest IEEE 1588 `domainNumber` the default and alternate profiles use.
pub const PTP_DOMAIN_MAX: u8 = 127;

/// `[swap.NAME]` rows in one topology (Kconfig `TOPOLOGY_MAX_SWAPS`).
pub const MAX_SWAPS: usize = azos_limits::TOPOLOGY_MAX_SWAPS;
/// `[volume.NAME]` rows in one topology (Kconfig `TOPOLOGY_MAX_VOLUMES`).
pub const MAX_VOLUMES: usize = azos_limits::TOPOLOGY_MAX_VOLUMES;
const _: () = assert!(MAX_SWAPS <= u8::MAX as usize && MAX_VOLUMES <= u8::MAX as usize, "kept in a u8");

/// `[login.NAME]` rows in one topology (Kconfig `TOPOLOGY_MAX_LOGINS`).
pub const MAX_LOGINS: usize = azos_limits::TOPOLOGY_MAX_LOGINS;
/// `ssh_key` entries one login row may list (Kconfig `TOPOLOGY_LOGIN_KEYS`).
pub const LOGIN_KEYS: usize = azos_limits::TOPOLOGY_LOGIN_KEYS;
const _: () = assert!(MAX_LOGINS <= u8::MAX as usize && LOGIN_KEYS <= u8::MAX as usize, "kept in a u8");

/// `[guest.NAME]` rows in one topology (Kconfig `TOPOLOGY_MAX_GUESTS`).
pub const MAX_GUESTS: usize = azos_limits::TOPOLOGY_MAX_GUESTS;
/// Device backends one guest row may list (Kconfig `TOPOLOGY_GUEST_DEVICES`).
pub const GUEST_DEVICES: usize = azos_limits::TOPOLOGY_GUEST_DEVICES;
const _: () = assert!(MAX_GUESTS <= u8::MAX as usize && GUEST_DEVICES <= u8::MAX as usize, "kept in a u8");

/// `[route.NAME]` rows in one topology (Kconfig `TOPOLOGY_MAX_ROUTES`).
pub const MAX_ROUTES: usize = azos_limits::TOPOLOGY_MAX_ROUTES;
/// `[firewall.NAME]` rows in one topology (Kconfig
/// `TOPOLOGY_MAX_FIREWALL_ROWS`).
pub const MAX_FIREWALL_ROWS: usize = azos_limits::TOPOLOGY_MAX_FIREWALL_ROWS;
const _: () = assert!(MAX_ROUTES <= u8::MAX as usize && MAX_FIREWALL_ROWS <= u8::MAX as usize, "kept in a u8");

/// The highest partition number a row may name: the block layer's partition
/// table holds 16 entries (`azos_drv_block::partition::MAX_PARTS`); partitions
/// are numbered from 1, as in the `block.part.N` grant targets.
pub const PARTITION_MAX: u8 = 16;

/// `[degrade.NAME]` rows in one topology: one per level below
/// [`Envelope::Full`], so three.
pub const MAX_DEGRADE_ROWS: usize = 3;

/// The image of the RPC server (`userspace/services/rpcsrv`): the one row that
/// may carry `export`, and the one that may serve a proxy endpoint.
pub const RPC_IMAGE: &[u8] = b"RPCSRV.ELF";

/// The prefix of a proxy endpoint's name (`endpoint.rpc-<service>`): the
/// local face of a service on another node. The RPC server serves it, the
/// local callers hold its `WRITE`; the kernel marks the endpoint a proxy when
/// it creates it, and a real-time caller is refused on it.
pub const PROXY_PREFIX: &[u8] = b"rpc-";

/// The endpoint the name server serves (`READ`) and every importing row calls
/// (`WRITE`). The kernel grants an importing row its half at spawn.
pub const NAMES_ENDPOINT: &[u8] = b"names";

/// The name in an `endpoint.<name>` grant target.
pub fn endpoint_target<'a>(c: &CapSpec<'a>) -> Option<&'a [u8]> {
    c.target.as_bytes().strip_prefix(b"endpoint.")
}

/// A name a row imports: 1..=`ENDPOINT_NAME_MAX` bytes of `[A-Za-z0-9_-]`,
/// the alphabet of an endpoint name (`cap_seed::parse_endpoint_name`), so an
/// import can only ever name something a grant could.
pub fn import_name_ok(n: &[u8]) -> bool {
    !n.is_empty()
        && n.len() <= 24
        && n.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

/// The lengths of a topology's row pools at one moment
/// ([`Topology::checkpoint`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    tasks_len: usize,
    caps_pool_len: usize,
    imports_pool_len: usize,
    exports_pool_len: usize,
    pipelines_len: u8,
}

/// One `[signer.NAME]` section: an author key the device admits, and the
/// ceiling of what that author's packages may ask for.
///
/// The key is named by its id, the SHA-256 of the algorithm number (2 bytes,
/// little endian) and the public key (`azos_pkg::key_id`), so the entry is the
/// same size whatever signature algorithm the key belongs to.
#[derive(Clone, Copy, Debug)]
pub struct SignerSpec<'a> {
    /// The signer's name in the topology, unique.
    pub name: MaybeStr<'a>,
    /// `sha256(alg_le16 || public key)`, unique.
    pub key_id: [u8; 32],
    /// May a package of this signer ask for real time: a reservation or a
    /// priority in the band, locked or huge memory, a ring poller?
    pub rt: bool,
    /// The most frames one row of this signer's packages may declare, over
    /// all its instances (a huge region counts 256 a MiB).
    pub mem_pages_max: u32,
    warrants_start: u32,
    warrants_count: u32,
}

impl<'a> SignerSpec<'a> {
    /// Construct an empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            key_id: [0; 32],
            rt: false,
            mem_pages_max: 0,
            warrants_start: 0,
            warrants_count: 0,
        }
    }
}

/// A signer's warrant ceiling is `kind:prefix`: a kind word a grant can carry
/// (`parser::cap_kind_word`), a colon, then at most `MAX_TARGET_LEN` bytes of
/// target prefix, possibly none (every target of the kind).
fn warrant_split(w: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = w.iter().position(|&b| b == b':')?;
    Some((&w[..i], &w[i + 1..]))
}

fn warrant_ok(w: &[u8]) -> bool {
    warrant_split(w)
        .is_some_and(|(kind, prefix)| prefix.len() <= MAX_TARGET_LEN && crate::parser::parse_cap_kind(kind).is_ok())
}

/// The name of the peer class the brain link reads: `[peer.brain]`.
const BRAIN_PEER: &[u8] = b"brain";

/// One class of remote nodes: `[peer.NAME]` with `nodes = [2, 3]`. A node
/// belongs to at most one class, so an `export` to a class names its nodes
/// without ambiguity. The node id is the identity the link handshake proves
/// (Noise/DICE; until they exist, the id a peer claims).
#[derive(Clone, Copy, Debug)]
pub struct PeerSpec<'a> {
    /// Class name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// Node ids, never 0 (0 is this node), none twice.
    pub nodes: [u32; PEER_NODES],
    /// Entries of `nodes` in use.
    pub nodes_len: u8,
    /// `noise_pk = ["<64 hex>", ...]` (format 7): the static Noise (X25519)
    /// public key of each node, in the order of `nodes`: `noise_pks[i]` is the
    /// key node `nodes[i]` proves at the link handshake. Either one key per
    /// node or none (`noise_pks_len == 0`: the class is not yet pinned to
    /// keys). Never all-zero, and no key is shared by two nodes of any class.
    /// Consumed by RPCSRV-NOISE (W14).
    pub noise_pks: [[u8; 32]; PEER_NODES],
    /// Entries of `noise_pks` in use: 0 or `nodes_len`.
    pub noise_pks_len: u8,
    /// `measurement = "<64 hex>"` (format 7): the image measurement (SHA-256,
    /// the DICE layer's) every node of the class must attest at the
    /// handshake. `None` when the class does not pin one. Never all-zero.
    /// Consumed by DICE-ID (W16).
    pub measurement: Option<[u8; 32]>,
}

impl<'a> PeerSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            nodes: [0; PEER_NODES],
            nodes_len: 0,
            noise_pks: [[0; 32]; PEER_NODES],
            noise_pks_len: 0,
            measurement: None,
        }
    }

    /// The nodes of the class.
    pub fn nodes(&self) -> &[u32] {
        &self.nodes[..self.nodes_len as usize]
    }

    /// The pinned Noise keys, parallel to [`PeerSpec::nodes`]; empty when the
    /// class pins none.
    pub fn noise_pks(&self) -> &[[u8; 32]] {
        &self.noise_pks[..self.noise_pks_len as usize]
    }

    /// The Noise key pinned for `node`, if the class pins keys and lists it.
    pub fn noise_pk_of(&self, node: u32) -> Option<&[u8; 32]> {
        let i = self.nodes().iter().position(|&n| n == node)?;
        self.noise_pks().get(i)
    }
}

/// One `export` entry, `NAME@CLASS`: the endpoint `NAME` (an `endpoint.NAME`
/// grant of the same row) may be lent to the nodes of peer class `CLASS`.
#[derive(Clone, Copy, Debug)]
pub struct ExportSpec<'a> {
    /// The endpoint name.
    pub endpoint: MaybeStr<'a>,
    /// The peer class name.
    pub peer: MaybeStr<'a>,
}

impl<'a> ExportSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { endpoint: MaybeStr::from_bytes(&[]), peer: MaybeStr::from_bytes(&[]) }
    }
}

/// One `[pipeline.NAME]` section: a data path (camera -> ML -> brain, say)
/// and the physically contiguous DMA memory it needs, in 4 KiB pages
/// (declared as `dma_kb`, rounded up).
#[derive(Clone, Copy, Debug)]
pub struct PipelineSpec<'a> {
    /// Pipeline name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// DMA pool pages this pipeline needs.
    pub dma_pages: u32,
}

/// One `[device.NAME]` row (CAPS.TOML format 6): a selector for hardware the
/// bus detects and what the topology says about it.
#[derive(Clone, Copy, Debug)]
pub struct DeviceSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `match`: the selector text (`azos_hwbus::Pattern::parse`).
    pub select: MaybeStr<'a>,
    /// `admit`: `false` refuses the device (it is detected and never bound).
    pub admit: bool,
    /// `driver`: the native driver to bind instead of the table's choice;
    /// empty for none.
    pub driver: MaybeStr<'a>,
    /// `safe_state = "<op>"` (format 7): the operation of the device's
    /// interface that drives it to its safe state (`brake`, `off`, `hold`, an
    /// IDL op name: 1 to 24 bytes of `[A-Za-z0-9_-]`). When a commit deadline
    /// passes the kernel, not the driver, issues it. Empty for none: the
    /// device has no declared safe state. Consumed by B2-SAFE-TIMER (W15).
    pub safe_state: MaybeStr<'a>,
    /// `commit_ns = N` (format 7): the longest the device takes from an
    /// accepted command to the effect being committed, in nanoseconds. B2
    /// admission adds it to the driver's placement latency and refuses an
    /// effect whose deadline is shorter. `0`: none declared. Consumed by
    /// B2-DEADLINE (W13).
    pub commit_ns: u64,
    /// `compensate = "<op>"` (format 7): the operation that undoes a
    /// reversible effect (same alphabet as `safe_state`); a saga step is
    /// admitted together with it. Empty for none. Consumed by B2-SAGA (W17).
    pub compensate: MaybeStr<'a>,
}

impl<'a> DeviceSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            select: MaybeStr::from_bytes(&[]),
            admit: true,
            driver: MaybeStr::from_bytes(&[]),
            safe_state: MaybeStr::from_bytes(&[]),
            commit_ns: 0,
            compensate: MaybeStr::from_bytes(&[]),
        }
    }
}

/// How far a `[policy.NAME]` row reaches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PolicyScope {
    /// The named Domain only (the default).
    This = 0,
    /// The named Domain and every Domain created beneath it, however deep:
    /// the parent's limit holds for a descendant whatever the descendant is
    /// granted.
    Subtree = 1,
}

impl PolicyScope {
    /// The row value: `"self"`, `"subtree"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"self" => Some(PolicyScope::This),
            b"subtree" => Some(PolicyScope::Subtree),
            _ => None,
        }
    }

    /// The row value [`PolicyScope::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyScope::This => "self",
            PolicyScope::Subtree => "subtree",
        }
    }
}

/// One `[policy.NAME]` row (CAPS.TOML format 7): a limit on what the Domain of
/// the task row `domain` (and, with [`PolicyScope::Subtree`], its descendants)
/// may create. A limit only narrows: a row that restricts nothing is refused.
///
/// Consumed by SUBTREE-POLICY (W14: `crates/core/sched/src/domain.rs` walks at
/// most 8 parents, `crates/core/syscall/src/families.rs` is the gate).
#[derive(Clone, Copy, Debug)]
pub struct PolicySpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `domain`: the name of a `[task.NAME]` row; the policy binds the Domain
    /// that row's task runs in. Checked at admission.
    pub domain: MaybeStr<'a>,
    /// `scope = "self" | "subtree"`; [`PolicyScope::This`] unless declared.
    pub scope: PolicyScope,
    /// `create_endpoints`: may the Domain create endpoints? `true` unless
    /// declared.
    pub create_endpoints: bool,
    /// `create_ports`: may the Domain create ports? `true` unless declared.
    pub create_ports: bool,
    /// `memobj_max_pages`: the largest MemObj, in 4 KiB pages, the Domain may
    /// create. **`0` means no ceiling.**
    pub memobj_max_pages: u32,
}

impl<'a> PolicySpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            domain: MaybeStr::from_bytes(&[]),
            scope: PolicyScope::This,
            create_endpoints: true,
            create_ports: true,
            memobj_max_pages: 0,
        }
    }

    /// Does the row restrict anything?
    pub const fn restricts(&self) -> bool {
        !self.create_endpoints || !self.create_ports || self.memobj_max_pages != 0
    }
}

/// The instruction set a livepatch blob is built for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PatchIsa {
    /// `riscv64`.
    Riscv64 = 1,
    /// `aarch64`.
    Aarch64 = 2,
    /// `x86_64`.
    X86_64 = 3,
}

impl PatchIsa {
    /// The row value: `"riscv64"`, `"aarch64"`, `"x86_64"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"riscv64" => Some(PatchIsa::Riscv64),
            b"aarch64" => Some(PatchIsa::Aarch64),
            b"x86_64" => Some(PatchIsa::X86_64),
            _ => None,
        }
    }

    /// The row value [`PatchIsa::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            PatchIsa::Riscv64 => "riscv64",
            PatchIsa::Aarch64 => "aarch64",
            PatchIsa::X86_64 => "x86_64",
        }
    }
}

/// A kernel build-id: 8 to 32 bytes (a linker's `--build-id` is 8 for `fast`,
/// 16 for `md5`/`uuid`, 20 for `sha1`, 32 for a SHA-256 the build computes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BuildId {
    /// The id, in `bytes[..len]`.
    pub bytes: [u8; 32],
    /// Bytes in use: 8..=32.
    pub len: u8,
}

impl BuildId {
    /// The shortest build-id a row may pin.
    pub const MIN_LEN: usize = 8;

    /// The bytes of the id.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// An id from `b`; `None` unless `MIN_LEN..=32` bytes.
    pub fn new(b: &[u8]) -> Option<Self> {
        if b.len() < Self::MIN_LEN || b.len() > 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes[..b.len()].copy_from_slice(b);
        Some(Self { bytes, len: b.len() as u8 })
    }
}

/// One `[livepatch.NAME]` row (CAPS.TOML format 7): the signed topology's
/// admission of ONE kernel livepatch blob. The blob itself is signed apart
/// (an RSIG); this row says which blob, for which kernel, may be applied at
/// all. A blob no row names is refused, and so is a row's blob whose build-id
/// is not the running kernel's or whose `sec_epoch` is below the device's
/// floor. Only functions that never sleep may be patched (the checker, not
/// the row, decides which).
///
/// Consumed by LIVEPATCH (W20, `kernel/src/boot/livepatch.rs`).
#[derive(Clone, Copy, Debug)]
pub struct LivepatchSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `isa`: the instruction set the blob is built for.
    pub isa: PatchIsa,
    /// `build_id`: the kernel build the blob is bound to (hex, 16 to 64
    /// digits).
    pub build_id: BuildId,
    /// `sec_epoch`: the security epoch of the blob, at least 1; refused at
    /// apply time below the device's floor.
    pub sec_epoch: u32,
    /// `sha256`: SHA-256 of the blob (64 hex digits), never all zero. Two rows
    /// never name one blob for one ISA.
    pub sha256: [u8; 32],
}

impl<'a> LivepatchSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            isa: PatchIsa::Riscv64,
            build_id: BuildId { bytes: [0; 32], len: BuildId::MIN_LEN as u8 },
            sec_epoch: 0,
            sha256: [0; 32],
        }
    }
}

/// One `[degrade.NAME]` row (CAPS.TOML format 7): the battery state of charge
/// at which the system enters a degrade level, declared in the signed topology
/// so that entering it is a recorded decision and never a silent one.
///
/// A level applies while the state of charge is at or below `battery_pct` and
/// stays until it rises above `clear_pct` (hysteresis, so a reading that jitters
/// around the threshold does not toggle the level). Rows are consistent: no
/// level twice, and a more restrictive level has a strictly lower threshold.
///
/// Consumed by BATTERY (W24, `POWERSVC`).
#[derive(Clone, Copy, Debug)]
pub struct DegradeSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `level`: the level entered; never [`Envelope::Full`].
    pub level: Envelope,
    /// `battery_pct`: state of charge, in percent (1 to 100), at or below
    /// which the level is entered.
    pub battery_pct: u8,
    /// `clear_pct`: state of charge, in percent, above which the level is
    /// left again: `battery_pct` to 100, `battery_pct` itself (no hysteresis)
    /// unless declared.
    pub clear_pct: u8,
}

impl<'a> DegradeSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), level: Envelope::Cautious, battery_pct: 0, clear_pct: 0 }
    }
}

/// One entry of the TAI-UTC table: from UTC second `utc_secs` (Unix time) on,
/// TAI is UTC plus `tai_offset` seconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeapEntry {
    /// The first UTC second (Unix time) the offset applies to.
    pub utc_secs: u64,
    /// TAI minus UTC from then on, in seconds; at least 1.
    pub tai_offset: u16,
}

/// The `[clock]` row (CAPS.TOML format 7), at most one: how the node tells
/// time, as the signed topology declares it.
///
/// * `ptp_domain = N`: the IEEE 1588 `domainNumber` (0 to
///   [`PTP_DOMAIN_MAX`]) the node's PTP daemon serves and listens on; absent
///   when the node takes no part in PTP.
/// * `leaps = ["unix:offset", ...]`: the TAI-UTC table, oldest first; each
///   entry's time is later than the one before, and the offset moves by
///   exactly one second (a positive or a negative leap second) at each.
///
/// Consumed by CLOCK-IDS (W16: TAI served from the table) and PTP-UDP (W18).
#[derive(Clone, Copy, Debug)]
pub struct ClockSpec {
    /// `ptp_domain`, if declared.
    pub ptp_domain: Option<u8>,
    leaps: [LeapEntry; LEAP_ENTRIES],
    leaps_len: u8,
}

impl ClockSpec {
    /// No `[clock]` row.
    pub const NONE: ClockSpec = ClockSpec {
        ptp_domain: None,
        leaps: [LeapEntry { utc_secs: 0, tai_offset: 0 }; LEAP_ENTRIES],
        leaps_len: 0,
    };

    /// The TAI-UTC table, oldest first.
    pub fn leaps(&self) -> &[LeapEntry] {
        &self.leaps[..self.leaps_len as usize]
    }

    /// Does the row declare anything?
    pub fn is_declared(&self) -> bool {
        self.ptp_domain.is_some() || self.leaps_len != 0
    }
}

/// One `[swap.NAME]` row (CAPS.TOML format 7): the partition that holds a swap
/// area. Consumed by SWAP-OUT (W16, `kernel/src/boot/swap.rs`).
#[derive(Clone, Copy, Debug)]
pub struct SwapSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `partition = N`: 1 to [`PARTITION_MAX`]. The partition is used by this
    /// row only (no other swap or volume row names it).
    pub partition: u8,
}

impl<'a> SwapSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), partition: 0 }
    }
}

/// One `[login.NAME]` row (CAPS.TOML format 7): an account. Its keys are the
/// ssh-ed25519 public keys that log in over SSH and, with Kconfig
/// `CONSOLE_LOGIN`, the verifiers of the console credential
/// (`azos_crypto::keystore::login_public`, `tests/host/logind-tests`' `login_enroll`). The row's
/// place in the file plus one is the user's `owner_root`.
/// Consumed by the `inspect.logins` view (`kernel/src/boot/inspect_views.rs`), which the SSH server
/// (`userspace/services/sshd`) reads at every connection and the login service
/// (`userspace/services/logind`) reads for whether anybody is enrolled, and by
/// the `login` op of `keys` (`crates/core/syscall/src/keys.rs`).
#[derive(Clone, Copy, Debug)]
pub struct LoginSpec<'a> {
    /// Row name, unique in the topology: the user name `ssh` is given
    /// (the endpoint alphabet, 24 bytes at most).
    pub name: MaybeStr<'a>,
    /// `ssh_key = ["<64 hex>", ...]`: the ssh-ed25519 public keys that log in
    /// as `name`. At least one, never all-zero, none listed twice in the
    /// topology (a key that two accounts share would log in as either).
    pub keys: [[u8; 32]; LOGIN_KEYS],
    /// Entries of `keys` in use.
    pub keys_len: u8,
}

impl<'a> LoginSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), keys: [[0; 32]; LOGIN_KEYS], keys_len: 0 }
    }

    /// The keys of the login.
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys[..self.keys_len as usize]
    }
}

/// One `[volume.NAME]` row (CAPS.TOML format 7): a native azvol volume and
/// where it is mounted. Consumed by AZVOL-FORMAT (W21), AZVOL-AEAD (W23) and
/// AZVOL-MOUNT (W24, `kernel/src/boot/azvol.rs`).
#[derive(Clone, Copy, Debug)]
pub struct VolumeSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `partition = N`: 1 to [`PARTITION_MAX`]; used by this row only.
    pub partition: u8,
    /// `mount = "/path"`: absolute, no trailing slash, no empty, `.` or `..`
    /// component, at most `MAX_TARGET_LEN` bytes, never `/` itself nor `/fat`
    /// (the boot volume) or anything beneath it; unique among the rows.
    pub mount: MaybeStr<'a>,
    /// `read_only = true`: mounted without write access. `false` unless
    /// declared.
    pub read_only: bool,
    /// `aead = true`: every block is encrypted and authenticated at rest.
    /// `false` unless declared.
    pub aead: bool,
    /// `verity_root = "<64 hex>"`: the root hash of the volume's hash tree;
    /// the mount is refused if the volume does not match it. Only a read-only
    /// volume has one. Never all-zero.
    pub verity_root: Option<[u8; 32]>,
}

impl<'a> VolumeSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            partition: 0,
            mount: MaybeStr::from_bytes(&[]),
            read_only: false,
            aead: false,
            verity_root: None,
        }
    }
}

/// Where the kernel mounts the FAT32 volume of a USB stick (Kconfig
/// `USB_STORAGE_VOLUME`, `azos_fs::usbvol`): a tree a row may be granted
/// (the shell's, to write the crash log out), and a path no volume row may
/// take.
pub const USB_VOLUME_PATH: &[u8] = b"/usb";

/// Is `p` a mount point a volume row may name? Not `/fat` and not
/// [`USB_VOLUME_PATH`], nor anything beneath them: those are the kernel's.
pub fn mount_path_ok(p: &[u8]) -> bool {
    if p.len() < 2 || p.len() > MAX_TARGET_LEN || p[0] != b'/' {
        return false;
    }
    let comps_ok = p[1..].split(|&b| b == b'/').all(|c| {
        !c.is_empty()
            && c != b"."
            && c != b".."
            && c.iter().all(|&b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'#'))
    });
    comps_ok && !paths_overlap(p, b"/fat") && !paths_overlap(p, USB_VOLUME_PATH)
}

/// Whether two [`mount_path_ok`] paths are equal or one lies inside the other,
/// compared component by component (`/a/b` is inside `/a`, not inside `/ab`).
fn paths_overlap(a: &[u8], b: &[u8]) -> bool {
    let inside = |inner: &[u8], outer: &[u8]| inner.starts_with(outer) && (inner.len() == outer.len() || inner[outer.len()] == b'/');
    inside(a, b) || inside(b, a)
}

/// One `[guest.NAME]` row (CAPS.TOML format 7): a virtual machine the device
/// may run. The guest holds no warrant: the ring-3 backends that serve its
/// devices do, so every effect from inside the guest passes the same envelope
/// and leaves the same record as one from a native task.
///
/// Consumed by HV-CORE (W19, `crates/core/hv`) and VMMD-CORE (W21).
#[derive(Clone, Copy, Debug)]
pub struct GuestSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `cpus = N`: virtual CPUs, 1 to 255.
    pub cpus: u8,
    /// `mem_mib = N`: guest RAM in MiB, at least 1.
    pub mem_mib: u32,
    /// `devices = [...]`: the backends the guest is given, each 1 to 24 bytes
    /// of `[A-Za-z0-9_-]`, none twice; in `devices[..devices_len]`.
    pub devices: [MaybeStr<'a>; GUEST_DEVICES],
    /// Entries of `devices` in use.
    pub devices_len: u8,
    /// `envelope`: the ceiling on the effects the guest may cause through its
    /// backends. **Required**: there is no default for a guest, which is
    /// untrusted code.
    pub envelope: Envelope,
    /// `passthrough = [...]` (format 8): the physical devices handed to the
    /// guest itself, each a name [`import_name_ok`] accepts, none twice and
    /// none also in `devices`; in `passthrough[..passthrough_len]`. Parsed,
    /// checked and emitted here; the hypervisor core and the monitor do not
    /// read it, so no device is handed to a guest.
    pub passthrough: [MaybeStr<'a>; GUEST_PASSTHROUGH],
    /// Entries of `passthrough` in use.
    pub passthrough_len: u8,
    /// `static = true` (format 8): a static partition. The guest owns the
    /// physical CPUs `pcpus` and the memory at `mem_base` from boot, with no
    /// overcommit and no scheduling against other guests: the AzOS guest of a
    /// partitioning hypervisor. `false` unless declared.
    pub static_partition: bool,
    /// `pcpus`: the physical CPUs of a static partition as a mask, as many
    /// as `cpus`, in no other static guest. 0 for a guest that is not static.
    pub pcpus: u64,
    /// `mem_base`: the physical address of a static partition's memory,
    /// [`GUEST_STATIC_ALIGN`]-aligned, `mem_mib` MiB long, overlapping no other
    /// static guest. 0 for a guest that is not static.
    pub mem_base: u64,
}

impl<'a> GuestSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            cpus: 0,
            mem_mib: 0,
            devices: [MaybeStr::from_bytes(&[]); GUEST_DEVICES],
            devices_len: 0,
            envelope: Envelope::Contained,
            passthrough: [MaybeStr::from_bytes(&[]); GUEST_PASSTHROUGH],
            passthrough_len: 0,
            static_partition: false,
            pcpus: 0,
            mem_base: 0,
        }
    }

    /// The physical devices handed to the guest.
    pub fn passthrough(&self) -> &[MaybeStr<'a>] {
        &self.passthrough[..self.passthrough_len as usize]
    }

    /// The physical range `[mem_base, mem_base + mem_mib MiB)` of a static
    /// partition, or `None` when the length overflows.
    fn static_range(&self) -> Option<(u64, u64)> {
        let end = self.mem_base.checked_add((self.mem_mib as u64) << 20)?;
        Some((self.mem_base, end))
    }

    /// The backends the guest is given.
    pub fn devices(&self) -> &[MaybeStr<'a>] {
        &self.devices[..self.devices_len as usize]
    }
}

// ── Network rows: addresses ──────────────────────────────────────────────

/// An IPv4 or IPv6 address as a route or firewall row declares it. The rows
/// carry parsed bytes, not text, so the consumer compiles its tables without
/// parsing anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IpAddr {
    /// IPv6 when `true`, IPv4 when `false`.
    pub v6: bool,
    /// The address in network order: all 16 bytes for IPv6, the first 4 for
    /// IPv4 (the rest are zero).
    pub bytes: [u8; 16],
}

impl IpAddr {
    /// The unspecified address of a family.
    pub const fn unspecified(v6: bool) -> Self {
        Self { v6, bytes: [0; 16] }
    }

    /// Bits in an address of this family: 32 or 128.
    pub const fn bits(&self) -> u8 {
        if self.v6 { 128 } else { 32 }
    }

    /// Is this the all-zero address (`0.0.0.0`, `::`)?
    pub fn is_unspecified(&self) -> bool {
        self.bytes == [0u8; 16]
    }

    /// Parse dotted-quad IPv4 (four decimal octets, no leading zeros) or IPv6
    /// text (`::` once, 1 to 4 hex digits a group; no embedded IPv4, no zone).
    pub fn parse(t: &[u8]) -> Option<Self> {
        if t.contains(&b':') {
            parse_v6(t).map(|bytes| Self { v6: true, bytes })
        } else {
            parse_v4(t).map(|b| {
                let mut bytes = [0u8; 16];
                bytes[..4].copy_from_slice(&b);
                Self { v6: false, bytes }
            })
        }
    }
}

impl core::fmt::Display for IpAddr {
    /// IPv4 as a dotted quad; IPv6 as eight groups, lower case, no `::`
    /// (which [`IpAddr::parse`] reads back to the same bytes).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.v6 {
            for i in 0..8 {
                if i != 0 {
                    f.write_str(":")?;
                }
                write!(f, "{:x}", u16::from_be_bytes([self.bytes[2 * i], self.bytes[2 * i + 1]]))?;
            }
            Ok(())
        } else {
            write!(f, "{}.{}.{}.{}", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3])
        }
    }
}

fn parse_v4(t: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in t.split(|&b| b == b'.') {
        if n == 4 || part.is_empty() || part.len() > 3 || (part.len() > 1 && part[0] == b'0') {
            return None;
        }
        let mut v = 0u32;
        for &d in part {
            if !d.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (d - b'0') as u32;
        }
        if v > 255 {
            return None;
        }
        out[n] = v as u8;
        n += 1;
    }
    (n == 4).then_some(out)
}

/// `a:b:c` into groups; an empty string is no groups.
fn v6_groups(s: &[u8], out: &mut [u16; 8]) -> Option<usize> {
    if s.is_empty() {
        return Some(0);
    }
    let mut n = 0;
    for g in s.split(|&b| b == b':') {
        if n == 8 || g.is_empty() || g.len() > 4 {
            return None;
        }
        let mut v = 0u16;
        for &d in g {
            let x = (d as char).to_digit(16)? as u16;
            v = v << 4 | x;
        }
        out[n] = v;
        n += 1;
    }
    Some(n)
}

fn parse_v6(t: &[u8]) -> Option<[u8; 16]> {
    let (mut head, mut tail) = ([0u16; 8], [0u16; 8]);
    let (hn, tn);
    match t.windows(2).position(|w| w == b"::") {
        None => {
            hn = v6_groups(t, &mut head)?;
            tn = 0;
            if hn != 8 {
                return None;
            }
        }
        Some(i) => {
            hn = v6_groups(&t[..i], &mut head)?;
            tn = v6_groups(&t[i + 2..], &mut tail)?;
            // `::` stands for at least one group of zeros.
            if hn + tn > 7 {
                return None;
            }
        }
    }
    let mut groups = [0u16; 8];
    groups[..hn].copy_from_slice(&head[..hn]);
    groups[8 - tn..].copy_from_slice(&tail[..tn]);
    let mut out = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
    }
    Some(out)
}

/// An address prefix, `addr/len`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IpPrefix {
    /// The network address: every bit past `len` is zero.
    pub addr: IpAddr,
    /// Leading bits that matter: 0 to 32 (IPv4) or 128 (IPv6).
    pub len: u8,
}

impl IpPrefix {
    /// Parse `addr/len`: `len` decimal without leading zeros, at most the
    /// family's bits, and no host bits set (`10.0.0.1/8` is refused, not
    /// masked: a prefix that says something else than it means is a typo).
    pub fn parse(t: &[u8]) -> Option<Self> {
        let slash = t.iter().position(|&b| b == b'/')?;
        let addr = IpAddr::parse(&t[..slash])?;
        let l = &t[slash + 1..];
        if l.is_empty() || l.len() > 3 || (l.len() > 1 && l[0] == b'0') || !l.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let len = l.iter().fold(0u32, |a, &d| a * 10 + (d - b'0') as u32);
        if len > addr.bits() as u32 {
            return None;
        }
        let len = len as u8;
        let host_clear = (len as usize..addr.bits() as usize).all(|bit| addr.bytes[bit / 8] & (0x80 >> (bit % 8)) == 0);
        host_clear.then_some(Self { addr, len })
    }
}

impl core::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// An interface name a row may name: 1 to 15 bytes of `[A-Za-z0-9_.-]` (the
/// kernel's `IFNAMSIZ` less the terminator).
pub fn ifname_ok(n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= 15 && n.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// One `[route.NAME]` row (CAPS.TOML format 7): a static route.
///
/// Consumed by NET-IFS+RAW (W16: the routing table) and ROUTE-NAT (W24).
#[derive(Clone, Copy, Debug)]
pub struct RouteSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `dest = "10.1.0.0/16"` or `"fd00::/8"`; `0.0.0.0/0` and `::/0` are the
    /// default routes.
    pub dest: IpPrefix,
    /// `via = "10.0.0.1"`: the gateway, of the destination's family and not
    /// the unspecified address; `None` for a destination on the link.
    pub via: Option<IpAddr>,
    /// `dev = "eth0"`: the interface the route leaves by ([`ifname_ok`]).
    pub dev: MaybeStr<'a>,
    /// `metric = N`: lower wins between routes of equal prefix length; `0`
    /// unless declared. No two rows share a destination and metric.
    pub metric: u32,
}

impl<'a> RouteSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            dest: IpPrefix { addr: IpAddr::unspecified(false), len: 0 },
            via: None,
            dev: MaybeStr::from_bytes(&[]),
            metric: 0,
        }
    }
}

/// Which way a firewall rule looks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FwDir {
    /// Packets for this node.
    In = 1,
    /// Packets this node originates.
    Out = 2,
    /// Packets this node routes between interfaces.
    Forward = 3,
}

impl FwDir {
    /// The row value: `"in"`, `"out"`, `"forward"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"in" => Some(FwDir::In),
            b"out" => Some(FwDir::Out),
            b"forward" => Some(FwDir::Forward),
            _ => None,
        }
    }

    /// The row value [`FwDir::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            FwDir::In => "in",
            FwDir::Out => "out",
            FwDir::Forward => "forward",
        }
    }
}

/// The protocol a firewall rule matches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FwProto {
    /// Any protocol (the default).
    Any = 0,
    /// TCP.
    Tcp = 1,
    /// UDP.
    Udp = 2,
    /// ICMP, and ICMPv6 for an IPv6 address.
    Icmp = 3,
}

impl FwProto {
    /// The row value: `"any"`, `"tcp"`, `"udp"`, `"icmp"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"any" => Some(FwProto::Any),
            b"tcp" => Some(FwProto::Tcp),
            b"udp" => Some(FwProto::Udp),
            b"icmp" => Some(FwProto::Icmp),
            _ => None,
        }
    }

    /// The row value [`FwProto::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            FwProto::Any => "any",
            FwProto::Tcp => "tcp",
            FwProto::Udp => "udp",
            FwProto::Icmp => "icmp",
        }
    }
}

/// What a firewall rule does to a packet it matches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FwAction {
    /// Let it through.
    Allow = 1,
    /// Discard it silently.
    Drop = 2,
    /// Discard it and tell the sender: ICMP destination unreachable,
    /// "administratively prohibited" (a local sender's `send` says -1).
    Reject = 3,
}

impl FwAction {
    /// The row value: `"allow"`, `"drop"`, `"reject"`.
    pub fn from_bytes(v: &[u8]) -> Option<Self> {
        match v {
            b"allow" => Some(FwAction::Allow),
            b"drop" => Some(FwAction::Drop),
            b"reject" => Some(FwAction::Reject),
            _ => None,
        }
    }

    /// The row value [`FwAction::from_bytes`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            FwAction::Allow => "allow",
            FwAction::Drop => "drop",
            FwAction::Reject => "reject",
        }
    }
}

/// One `[firewall.NAME]` row (CAPS.TOML format 7): a packet filter rule.
/// Rules are tried in file order and the first that matches decides; a packet
/// no rule matches is the filter's own default.
///
/// Consumed by FW-RULES (W19, the net crate's `filter.rs`: compiled at boot)
/// and ROUTE-NAT (W24).
#[derive(Clone, Copy, Debug)]
pub struct FirewallSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `dir = "in" | "out" | "forward"`, required.
    pub dir: FwDir,
    /// `proto = "any" | "tcp" | "udp" | "icmp"`; [`FwProto::Any`] unless
    /// declared.
    pub proto: FwProto,
    /// `port = N`: the first port matched (1 to 65535), 0 for any port. Only
    /// with `tcp` or `udp`. Matched against the packet's destination port,
    /// whatever the direction.
    pub port_lo: u16,
    /// `port_end = M`: the last port matched, at least `port_lo`; equal to it
    /// for a single port, 0 for any port.
    pub port_hi: u16,
    /// `addr = "10.0.0.0/8"`: the remote address prefix (source of an `in`
    /// packet, destination of an `out` or `forward` one); `None` for any.
    pub addr: Option<IpPrefix>,
    /// `action = "allow" | "drop" | "reject"`, required.
    pub action: FwAction,
}

impl<'a> FirewallSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            dir: FwDir::In,
            proto: FwProto::Any,
            port_lo: 0,
            port_hi: 0,
            addr: None,
            action: FwAction::Drop,
        }
    }

    /// Do the two rules match the same packets (everything but the name and
    /// the action)? The later one could never be reached.
    fn same_match(&self, o: &Self) -> bool {
        self.dir == o.dir
            && self.proto == o.proto
            && self.port_lo == o.port_lo
            && self.port_hi == o.port_hi
            && self.addr == o.addr
    }
}

// ──────────────────────────────────────────────────────────────────────────
// CAPS.TOML format 8: the rows later fronts consume (TOPO-ROWS-C)
// ──────────────────────────────────────────────────────────────────────────

/// An enum read from and written as one lowercase word of a row. Generates the
/// type, `from_bytes` and `as_str`, so the parser and the emitter agree by
/// construction.
macro_rules! word_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $var:ident = $word:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum $name {
            $($(#[$vm])* $var),+
        }

        impl $name {
            /// The variant a row value names.
            pub fn from_bytes(v: &[u8]) -> Option<Self> {
                $(if v == $word.as_bytes() { return Some(Self::$var); })+
                None
            }

            /// The row value [`Self::from_bytes`] reads back.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$var => $word),+
                }
            }
        }
    };
}

word_enum! {
    /// The fieldbus a `[fieldbus.NAME]` row runs (Kconfig `FIELDBUS`).
    FieldbusKind {
        /// EtherCAT master: a cyclic frame with a fixed period.
        EtherCat = "ethercat",
        /// CANopen over native CAN.
        CanOpen = "canopen",
        /// Modbus TCP or RTU.
        Modbus = "modbus",
    }
}

word_enum! {
    /// Which way an `[audio.NAME]` stream flows.
    AudioDir {
        /// Output only.
        Playback = "playback",
        /// Input only.
        Capture = "capture",
        /// Both directions on one device.
        Duplex = "duplex",
    }
}

word_enum! {
    /// What a `[key.NAME]` row's key is for.
    KeyPurpose {
        /// A node's static key on a link (Noise).
        Link = "link",
        /// Signing: an image, a record, an attestation.
        Sign = "sign",
        /// Encryption at rest (an azvol volume key).
        Aead = "aead",
    }
}

word_enum! {
    /// Where a `[key.NAME]` row's key comes from.
    KeySource {
        /// Derived from the device seed and the image measurement (DICE).
        Dice = "dice",
        /// Held in a user's keystore (the row names the `user`).
        Keystore = "keystore",
        /// Held by a secure element, TPM or other hardware root.
        Hardware = "hardware",
    }
}

word_enum! {
    /// The effect kinds beyond motors that an `[envelope.NAME]` row bounds
    /// (a kind is an effect a record names).
    EffectKind {
        /// A write to the signed configuration.
        Config = "config",
        /// Applying an OTA image.
        Ota = "ota",
        /// A packet that leaves the node.
        Egress = "egress",
        /// Deleting stored data.
        Delete = "delete",
        /// Asking for real-time time: a deadline reservation (`rt::reserve`),
        /// bounded by the share of a hart one reservation may take.
        RtTime = "rt_time",
        /// Capturing audio: opening a `Sound` capture stream (`azos_devif::sound`).
        Mic = "mic",
    }
}

word_enum! {
    /// When an `[activity.NAME]` row's deferred work may run.
    ActivityTrigger {
        /// While the machine is idle.
        Idle = "idle",
        /// While external power is connected.
        Charging = "charging",
        /// Every `period_ms`.
        Timer = "timer",
    }
}

word_enum! {
    /// What a `[usb.NAME]` row does with the devices it matches.
    UsbAuthorize {
        /// The device may bind a driver.
        Allow = "allow",
        /// The device is refused.
        Deny = "deny",
    }
}

/// A fixed table of at most `N` rows, `N` at most 255.
#[derive(Clone, Copy)]
struct Table<T: Copy, const N: usize> {
    rows: [T; N],
    len: u8,
}

impl<T: Copy, const N: usize> Table<T, N> {
    const fn new(empty: T) -> Self {
        Self { rows: [empty; N], len: 0 }
    }

    fn as_slice(&self) -> &[T] {
        &self.rows[..self.len as usize]
    }

    /// `false` when the table is full.
    fn push(&mut self, row: T) -> bool {
        if self.len as usize >= N {
            return false;
        }
        self.rows[self.len as usize] = row;
        self.len += 1;
        true
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

macro_rules! table_limits {
    ($($(#[$m:meta])* $name:ident = $limit:ident;)+) => {
        $(
            $(#[$m])*
            pub const $name: usize = azos_limits::$limit;
            const _: () = assert!($name <= u8::MAX as usize, "kept in a u8");
        )+
    };
}

table_limits! {
    /// `[tsn.NAME]` rows in one topology (Kconfig `TOPOLOGY_MAX_TSN`).
    MAX_TSN = TOPOLOGY_MAX_TSN;
    /// `[fieldbus.NAME]` rows (Kconfig `TOPOLOGY_MAX_FIELDBUS`).
    MAX_FIELDBUS = TOPOLOGY_MAX_FIELDBUS;
    /// `[audio.NAME]` rows (Kconfig `TOPOLOGY_MAX_AUDIO`).
    MAX_AUDIO = TOPOLOGY_MAX_AUDIO;
    /// `[display.NAME]` rows (Kconfig `TOPOLOGY_MAX_DISPLAYS`).
    MAX_DISPLAYS = TOPOLOGY_MAX_DISPLAYS;
    /// `[user.NAME]` rows (Kconfig `TOPOLOGY_MAX_USERS`).
    MAX_USERS = TOPOLOGY_MAX_USERS;
    /// `[key.NAME]` rows (Kconfig `TOPOLOGY_MAX_KEYS`).
    MAX_KEYS = TOPOLOGY_MAX_KEYS;
    /// `[boot_chain.NAME]` rows, one per stage (Kconfig
    /// `TOPOLOGY_MAX_BOOT_STAGES`).
    MAX_BOOT_STAGES = TOPOLOGY_MAX_BOOT_STAGES;
    /// `[island.NAME]` rows (Kconfig `TOPOLOGY_MAX_ISLANDS`).
    MAX_ISLANDS = TOPOLOGY_MAX_ISLANDS;
    /// Wake events one island row may list (Kconfig `TOPOLOGY_ISLAND_WAKE`).
    ISLAND_WAKE = TOPOLOGY_ISLAND_WAKE;
    /// `[activity.NAME]` rows (Kconfig `TOPOLOGY_MAX_ACTIVITIES`).
    MAX_ACTIVITIES = TOPOLOGY_MAX_ACTIVITIES;
    /// `[numa.NAME]` rows (Kconfig `TOPOLOGY_MAX_NUMA`).
    MAX_NUMA = TOPOLOGY_MAX_NUMA;
    /// `[envelope.NAME]` rows (Kconfig `TOPOLOGY_MAX_ENVELOPES`).
    MAX_ENVELOPES = TOPOLOGY_MAX_ENVELOPES;
    /// `[nic.NAME]` rows (Kconfig `TOPOLOGY_MAX_NICS`).
    MAX_NICS = TOPOLOGY_MAX_NICS;
    /// `[model.NAME]` rows (Kconfig `TOPOLOGY_MAX_MODELS`).
    MAX_MODELS = TOPOLOGY_MAX_MODELS;
    /// `[usb.NAME]` rows (Kconfig `TOPOLOGY_MAX_USB_RULES`).
    MAX_USB_RULES = TOPOLOGY_MAX_USB_RULES;
    /// Devices one guest row may pass through (Kconfig
    /// `TOPOLOGY_GUEST_PASSTHROUGH`).
    GUEST_PASSTHROUGH = TOPOLOGY_GUEST_PASSTHROUGH;
}

/// The largest link rate a `[tsn.NAME]` budget may name, in kbit/s (10 Gbit/s).
pub const TSN_LINK_BUDGET_MAX: u32 = 10_000_000;
/// The longest Qbv window a `[tsn.NAME]` row may name, in microseconds (1 s).
pub const TSN_WINDOW_US_MAX: u32 = 1_000_000;
/// An `[audio.NAME]` sample rate, in Hz: the lowest and the highest.
pub const AUDIO_RATE_HZ: (u32, u32) = (8_000, 384_000);
/// Channels an `[audio.NAME]` stream may carry.
pub const AUDIO_CHANNELS_MAX: u8 = 32;
/// The MTU a `[nic.NAME]` row has unless it declares one.
pub const NIC_MTU_DEFAULT: u16 = 1500;
/// The MTU range a `[nic.NAME]` row may declare: the IPv4 floor and a jumbo
/// frame.
pub const NIC_MTU_RANGE: (u16, u16) = (576, 9216);
/// The largest `[numa.NAME]` node id.
pub const NUMA_NODE_MAX: u8 = 63;
/// Bytes of a guest's static memory alignment: one page.
pub const GUEST_STATIC_ALIGN: u64 = 4096;

/// A device or file name in a row: 1 to `MAX_TASK_NAME_LEN` bytes of
/// `[A-Za-z0-9_.-]`, not starting with `.`.
pub fn dev_name_ok(n: &[u8]) -> bool {
    !n.is_empty()
        && n.len() <= MAX_TASK_NAME_LEN
        && n[0] != b'.'
        && n.iter().all(|c| c.is_ascii_alphanumeric() || matches!(*c, b'_' | b'.' | b'-'))
}

/// One `[tsn.NAME]` row (CAPS.TOML format 8): a time-sensitive-networking
/// admission for the link `dev`. A real-time caller of a proxy endpoint over
/// that link is admitted only against a row: a Qbv gate window that repeats
/// every `window_us`, and the share of the link the traffic may use.
///
/// Consumed by RPCSRV (RT callers on a `Proxy` endpoint) and the TSN rows of
/// the dwmac driver.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TsnSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `dev`: the network device the schedule is programmed on; one row per
    /// device.
    pub dev: MaybeStr<'a>,
    /// `window_us`: the Qbv gate cycle, 1 to [`TSN_WINDOW_US_MAX`].
    pub window_us: u32,
    /// `link_budget`: the bandwidth the admitted traffic may use, in kbit/s,
    /// 1 to [`TSN_LINK_BUDGET_MAX`].
    pub link_budget: u32,
}

impl<'a> TsnSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), dev: MaybeStr::from_bytes(&[]), window_us: 0, link_budget: 0 }
    }
}

/// One `[fieldbus.NAME]` row (CAPS.TOML format 8): a fieldbus master on the
/// device `dev`. Process-data outputs are effects; the row says which bus and,
/// for a cyclic one, how often it runs.
///
/// Consumed by the fieldbus servers (EtherCAT first).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FieldbusSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `kind`: the bus.
    pub kind: FieldbusKind,
    /// `dev`: the device (a NIC, a CAN controller, a UART); one row per device.
    pub dev: MaybeStr<'a>,
    /// `cycle_us`: the cyclic frame period. Required for EtherCAT, absent
    /// (0) for the others.
    pub cycle_us: u32,
}

impl<'a> FieldbusSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), kind: FieldbusKind::EtherCat, dev: MaybeStr::from_bytes(&[]), cycle_us: 0 }
    }
}

/// One `[audio.NAME]` row (CAPS.TOML format 8): an audio stream the audio
/// server opens on `dev`.
///
/// Consumed by the audio server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AudioSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `dev`: the codec or controller; one row per device.
    pub dev: MaybeStr<'a>,
    /// `rate_hz`: the sample rate, within [`AUDIO_RATE_HZ`].
    pub rate_hz: u32,
    /// `channels`: 1 to [`AUDIO_CHANNELS_MAX`].
    pub channels: u8,
    /// `dir`: the direction.
    pub dir: AudioDir,
}

impl<'a> AudioSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), dev: MaybeStr::from_bytes(&[]), rate_hz: 0, channels: 0, dir: AudioDir::Playback }
    }
}

/// One `[display.NAME]` row (CAPS.TOML format 8): a panel the compositor
/// drives.
///
/// Consumed by the compositor (`compmgr`) and the framebuffer console.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisplaySpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `dev`: the display device; one row per device.
    pub dev: MaybeStr<'a>,
    /// `width` in pixels, at least 1.
    pub width: u16,
    /// `height` in pixels, at least 1.
    pub height: u16,
    /// `rotation`: 0, 90, 180 or 270 degrees; 0 unless declared.
    pub rotation: u16,
    /// `primary = true`: the display the console and the login screen use.
    /// At most one row. `false` unless declared.
    pub primary: bool,
}

impl<'a> DisplaySpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), dev: MaybeStr::from_bytes(&[]), width: 0, height: 0, rotation: 0, primary: false }
    }
}

/// One `[user.NAME]` row (CAPS.TOML format 8): a human user. The user root
/// warrant is a `Cap<Dir>` on `root`; the user's keys live under `keystore`.
///
/// Consumed by the login service and the identity model (single user in v1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UserSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `root`: the directory the user's root warrant covers, a path
    /// [`mount_path_ok`] accepts; used by this row only.
    pub root: MaybeStr<'a>,
    /// `keystore`: where the user's keys are kept, a path [`mount_path_ok`]
    /// accepts, different from `root`.
    pub keystore: MaybeStr<'a>,
}

impl<'a> UserSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), root: MaybeStr::from_bytes(&[]), keystore: MaybeStr::from_bytes(&[]) }
    }
}

/// One `[key.NAME]` row (CAPS.TOML format 8): a key the system holds, by
/// purpose and by where it comes from. The row never carries key material.
///
/// Consumed by the key service (RPC links, volume encryption, signing).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeySpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `purpose`.
    pub purpose: KeyPurpose,
    /// `source`.
    pub source: KeySource,
    /// `user`: the `[user.NAME]` row whose keystore holds the key. Required
    /// by [`KeySource::Keystore`], refused for the other sources.
    pub user: Option<MaybeStr<'a>>,
}

impl<'a> KeySpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), purpose: KeyPurpose::Link, source: KeySource::Dice, user: None }
    }
}

/// The `[mission]` row (CAPS.TOML format 8), at most one: the energy the
/// machine keeps back so the mission can end safely (a return, a parking, a
/// controlled stop). Energy admission and the degrade levels never spend it.
///
/// Consumed by the power server (BATTERY) and the energy model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MissionSpec<'a> {
    /// `reserve_mj`: the reserve, in millijoules, at least 1.
    pub reserve_mj: u32,
    /// `task`: the `[task.NAME]` row that ends the mission with the reserve,
    /// if one does.
    pub task: Option<MaybeStr<'a>>,
}

/// One `[boot_chain.NAME]` row (CAPS.TOML format 8): a stage of the boot
/// chain and the digest it must measure to. The digests are the first decision
/// records of the boot.
///
/// Consumed by measured boot (boot chain per board, DICE).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BootChainSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `stage`: the position in the chain, from 0, each number once; the
    /// stages of a topology are consecutive from 0
    /// ([`Topology::admission_check`]).
    pub stage: u8,
    /// `digest`: the SHA-256 the stage must measure to, never all-zero.
    pub digest: [u8; 32],
}

impl<'a> BootChainSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), stage: 0, digest: [0; 32] }
    }
}

/// One `[island.NAME]` row (CAPS.TOML format 8): a low-power island, a
/// co-processor that runs signed firmware over a mailbox queue and wakes the
/// main kernel only on a declared event.
///
/// Consumed by the island placement (`place = lp-island`) and the BLE host.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IslandSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `image`: the firmware file, a name [`dev_name_ok`] accepts.
    pub image: MaybeStr<'a>,
    /// `sha256`: the firmware's digest, never all-zero.
    pub sha256: [u8; 32],
    /// `mailbox`: the Queue the island and the kernel exchange messages on, a
    /// name [`import_name_ok`] accepts.
    pub mailbox: MaybeStr<'a>,
    /// `wake = [...]`: the events that wake the main kernel, each a name
    /// [`import_name_ok`] accepts, none twice; in `wake[..wake_len]`.
    pub wake: [MaybeStr<'a>; ISLAND_WAKE],
    /// Entries of `wake` in use.
    pub wake_len: u8,
}

impl<'a> IslandSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self {
            name: MaybeStr::from_bytes(&[]),
            image: MaybeStr::from_bytes(&[]),
            sha256: [0; 32],
            mailbox: MaybeStr::from_bytes(&[]),
            wake: [MaybeStr::from_bytes(&[]); ISLAND_WAKE],
            wake_len: 0,
        }
    }

    /// The events that wake the main kernel.
    pub fn wake(&self) -> &[MaybeStr<'a>] {
        &self.wake[..self.wake_len as usize]
    }
}

/// One `[activity.NAME]` row (CAPS.TOML format 8): deferred work. The task
/// row `task` is not started at boot; it runs when `trigger` says the machine
/// can spare it.
///
/// Consumed by the deferred-work scheduler (energy policy).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ActivitySpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `task`: a `[task.NAME]` row; each task has at most one activity.
    pub task: MaybeStr<'a>,
    /// `trigger`.
    pub trigger: ActivityTrigger,
    /// `period_ms`: the period of a [`ActivityTrigger::Timer`] row, at least
    /// 1; 0 (absent) for the others.
    pub period_ms: u32,
}

impl<'a> ActivitySpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), task: MaybeStr::from_bytes(&[]), trigger: ActivityTrigger::Idle, period_ms: 0 }
    }
}

/// One `[numa.NAME]` row (CAPS.TOML format 8): a memory node and the CPUs
/// attached to it. Where firmware describes the nodes (SRAT, devicetree) the
/// rows are the signed expectation; where it does not they are the only
/// source.
///
/// Consumed by the page allocator's per-node free lists and the balancer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NumaSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `node`: the node id, 0 to [`NUMA_NODE_MAX`], each once.
    pub node: u8,
    /// `cpus`: the CPUs of the node as a mask, not empty, in no other row.
    pub cpus: u64,
}

impl<'a> NumaSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), node: 0, cpus: 0 }
    }
}

/// One `[envelope.NAME]` row (CAPS.TOML format 8): the most an effect of
/// `kind` may do on behalf of the tasks of class `class`, in the degrade
/// vocabulary. The effect gate takes the meet of this and the class's own
/// envelope; every refusal leaves a record.
///
/// Consumed by the effect gate (config write, OTA apply, egress, delete and
/// real-time reservation effects) and by the kernel's sound host (opening a
/// capture stream, kind `mic`, on the requester's class: the client's when the
/// audio server opens it for one).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnvelopeSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `kind`: the effect.
    pub kind: EffectKind,
    /// `class`: a scheduler class; one row per class and kind.
    pub class: MaybeStr<'a>,
    /// `level`: the ceiling.
    pub level: Envelope,
}

impl<'a> EnvelopeSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), kind: EffectKind::Config, class: MaybeStr::from_bytes(&[]), level: Envelope::Full }
    }
}

/// The `[rtc]` row (CAPS.TOML format 8), at most one: the battery-backed
/// clock that seeds wall time at boot.
///
/// Consumed by the RTC driver and the clock service.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RtcSpec<'a> {
    /// `dev`: the RTC device.
    pub dev: MaybeStr<'a>,
    /// `utc`: the RTC keeps UTC (`true`, the default) rather than local time.
    pub utc: bool,
}

/// One `[nic.NAME]` row (CAPS.TOML format 8): what the stack configures a
/// network device with.
///
/// Consumed by the interface registry and the NIC drivers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NicSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `dev`: the device; one row per device.
    pub dev: MaybeStr<'a>,
    /// `mtu`: within [`NIC_MTU_RANGE`]; [`NIC_MTU_DEFAULT`] unless declared.
    pub mtu: u16,
    /// `mac = "aa:bb:cc:dd:ee:ff"`: a unicast address overriding the
    /// device's own, in no other row. `None` unless declared.
    pub mac: Option<[u8; 6]>,
}

impl<'a> NicSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), dev: MaybeStr::from_bytes(&[]), mtu: NIC_MTU_DEFAULT, mac: None }
    }
}

/// One `[model.NAME]` row (CAPS.TOML format 8): a model bundle the inference
/// service may load. The effect record names the bundle hash and variant of
/// the model that decided.
///
/// Consumed by the inference service and the provenance records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ModelSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `bundle`: the SHA-256 of the bundle, never all-zero, in no other row.
    pub bundle: [u8; 32],
    /// `variant`: a name [`import_name_ok`] accepts, or empty for none.
    pub variant: MaybeStr<'a>,
}

impl<'a> ModelSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), bundle: [0; 32], variant: MaybeStr::from_bytes(&[]) }
    }
}

/// One `[usb.NAME]` row (CAPS.TOML format 8): whether a USB device may bind a
/// driver. Rows are tried in file order and the first match wins; a row with
/// no selector matches every device and ends the list. A device no row
/// matches is refused.
///
/// Consumed by the USB core (`Rule::UsbAuthorize` records).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UsbSpec<'a> {
    /// Row name, unique in the topology.
    pub name: MaybeStr<'a>,
    /// `vid`: the vendor id (4 hex digits), if the row selects one.
    pub vid: Option<u16>,
    /// `pid`: the product id (4 hex digits); needs `vid`.
    pub pid: Option<u16>,
    /// `class`: the device or interface class code, if the row selects one.
    pub class: Option<u8>,
    /// `authorize`: what happens to a device the row matches.
    pub authorize: UsbAuthorize,
}

impl<'a> UsbSpec<'a> {
    /// An empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), vid: None, pid: None, class: None, authorize: UsbAuthorize::Allow }
    }

    /// Does the row match every device?
    pub const fn is_catch_all(&self) -> bool {
        self.vid.is_none() && self.class.is_none()
    }

    /// Do `self` and `o` select the same devices?
    fn same_selector(&self, o: &Self) -> bool {
        self.vid == o.vid && self.pid == o.pid && self.class == o.class
    }
}

/// A MAC address the NIC rows accept: unicast and not all-zero.
const fn mac_ok(m: &[u8; 6]) -> bool {
    m[0] & 1 == 0 && (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) != 0
}

/// The rows of CAPS.TOML format 8: tables, singletons and their admission.
impl<'a> Topology<'a> {
    /// Borrow the declared `[tsn.NAME]` rows, in file order.
    pub fn tsns(&self) -> &[TsnSpec<'a>] {
        self.tsns.as_slice()
    }

    /// Append a `[tsn.NAME]` row. `Err(DuplicateRow(Tsn))` for a repeated name
    /// or device, or a full table; `Err(BadRow(Tsn))` for a name outside the
    /// endpoint alphabet, a device [`dev_name_ok`] refuses, a window outside
    /// 1..=[`TSN_WINDOW_US_MAX`] or a budget outside 1..=[`TSN_LINK_BUDGET_MAX`].
    pub fn push_tsn(&mut self, spec: TsnSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || !dev_name_ok(spec.dev.as_bytes())
            || !(1..=TSN_WINDOW_US_MAX).contains(&spec.window_us)
            || !(1..=TSN_LINK_BUDGET_MAX).contains(&spec.link_budget)
        {
            return Err(AdmissionError::BadRow(RowKind::Tsn));
        }
        if self.tsns().iter().any(|r| r.name == spec.name || r.dev == spec.dev) || !self.tsns.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::Tsn));
        }
        Ok(())
    }

    /// The row that admits real-time traffic on device `dev`.
    pub fn tsn_for(&self, dev: &[u8]) -> Option<&TsnSpec<'a>> {
        self.tsns().iter().find(|r| r.dev.as_bytes() == dev)
    }

    /// Borrow the declared `[fieldbus.NAME]` rows, in file order.
    pub fn fieldbuses(&self) -> &[FieldbusSpec<'a>] {
        self.fieldbuses.as_slice()
    }

    /// Append a `[fieldbus.NAME]` row. `Err(DuplicateRow(Fieldbus))` for a
    /// repeated name or device, or a full table; `Err(BadRow(Fieldbus))` for a
    /// name outside the endpoint alphabet, a device [`dev_name_ok`] refuses,
    /// an EtherCAT row without a cycle or another bus with one.
    pub fn push_fieldbus(&mut self, spec: FieldbusSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || !dev_name_ok(spec.dev.as_bytes())
            || (spec.kind == FieldbusKind::EtherCat) != (spec.cycle_us != 0)
        {
            return Err(AdmissionError::BadRow(RowKind::Fieldbus));
        }
        if self.fieldbuses().iter().any(|r| r.name == spec.name || r.dev == spec.dev) || !self.fieldbuses.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::Fieldbus));
        }
        Ok(())
    }

    /// Borrow the declared `[audio.NAME]` rows, in file order.
    pub fn audios(&self) -> &[AudioSpec<'a>] {
        self.audios.as_slice()
    }

    /// Append an `[audio.NAME]` row. `Err(DuplicateRow(Audio))` for a repeated
    /// name or device, or a full table; `Err(BadRow(Audio))` for a name outside
    /// the endpoint alphabet, a device [`dev_name_ok`] refuses, a rate outside
    /// [`AUDIO_RATE_HZ`] or a channel count outside 1..=[`AUDIO_CHANNELS_MAX`].
    pub fn push_audio(&mut self, spec: AudioSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || !dev_name_ok(spec.dev.as_bytes())
            || !(AUDIO_RATE_HZ.0..=AUDIO_RATE_HZ.1).contains(&spec.rate_hz)
            || !(1..=AUDIO_CHANNELS_MAX).contains(&spec.channels)
        {
            return Err(AdmissionError::BadRow(RowKind::Audio));
        }
        if self.audios().iter().any(|r| r.name == spec.name || r.dev == spec.dev) || !self.audios.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::Audio));
        }
        Ok(())
    }

    /// Borrow the declared `[display.NAME]` rows, in file order.
    pub fn displays(&self) -> &[DisplaySpec<'a>] {
        self.displays.as_slice()
    }

    /// Append a `[display.NAME]` row. `Err(DuplicateRow(Display))` for a
    /// repeated name or device, a second primary, or a full table;
    /// `Err(BadRow(Display))` for a name outside the endpoint alphabet, a device
    /// [`dev_name_ok`] refuses, a zero size or a rotation that is not a right
    /// angle.
    pub fn push_display(&mut self, spec: DisplaySpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || !dev_name_ok(spec.dev.as_bytes())
            || spec.width == 0
            || spec.height == 0
            || !matches!(spec.rotation, 0 | 90 | 180 | 270)
        {
            return Err(AdmissionError::BadRow(RowKind::Display));
        }
        if self.displays().iter().any(|r| r.name == spec.name || r.dev == spec.dev || (spec.primary && r.primary))
            || !self.displays.push(spec)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Display));
        }
        Ok(())
    }

    /// Borrow the declared `[user.NAME]` rows, in file order.
    pub fn users(&self) -> &[UserSpec<'a>] {
        self.users.as_slice()
    }

    /// The `[user.NAME]` row called `name`.
    pub fn find_user(&self, name: &[u8]) -> Option<&UserSpec<'a>> {
        self.users().iter().find(|u| u.name.as_bytes() == name)
    }

    /// Append a `[user.NAME]` row. `Err(DuplicateRow(User))` for a repeated
    /// name or root, or a full table; `Err(BadRow(User))` for a name outside
    /// the endpoint alphabet, a root or keystore [`mount_path_ok`] refuses, or
    /// a path that overlaps another: no root or keystore of this row may equal,
    /// lie inside or contain the root or keystore of another row or of this
    /// one, so no user's warrant over a root reaches another user's keys.
    pub fn push_user(&mut self, spec: UserSpec<'a>) -> Result<(), AdmissionError> {
        let (root, keystore) = (spec.root.as_bytes(), spec.keystore.as_bytes());
        if !import_name_ok(spec.name.as_bytes())
            || !mount_path_ok(root)
            || !mount_path_ok(keystore)
            || paths_overlap(root, keystore)
        {
            return Err(AdmissionError::BadRow(RowKind::User));
        }
        if self.users().iter().any(|r| r.name == spec.name || r.root == spec.root) {
            return Err(AdmissionError::DuplicateRow(RowKind::User));
        }
        if self.users().iter().any(|r| {
            let (or, ok) = (r.root.as_bytes(), r.keystore.as_bytes());
            paths_overlap(root, or) || paths_overlap(root, ok) || paths_overlap(keystore, or) || paths_overlap(keystore, ok)
        }) {
            return Err(AdmissionError::BadRow(RowKind::User));
        }
        if !self.users.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::User));
        }
        Ok(())
    }

    /// Borrow the declared `[key.NAME]` rows, in file order.
    pub fn keys(&self) -> &[KeySpec<'a>] {
        self.keys.as_slice()
    }

    /// Append a `[key.NAME]` row. `Err(DuplicateRow(Key))` for a repeated name
    /// or a full table; `Err(BadRow(Key))` for a name outside the endpoint
    /// alphabet, a user name outside it, a keystore key without a user or a
    /// key from another source with one. That the user's row exists is checked
    /// by [`Topology::admission_check`], when every row is known.
    pub fn push_key(&mut self, spec: KeySpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || spec.user.is_some_and(|u| !import_name_ok(u.as_bytes()))
            || (spec.source == KeySource::Keystore) != spec.user.is_some()
        {
            return Err(AdmissionError::BadRow(RowKind::Key));
        }
        if self.keys().iter().any(|r| r.name == spec.name) || !self.keys.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::Key));
        }
        Ok(())
    }

    /// The `[mission]` row, if there is one.
    pub fn mission(&self) -> Option<&MissionSpec<'a>> {
        self.mission.as_ref()
    }

    /// Declare the `[mission]` row. `Err(DuplicateRow(Mission))` for a second
    /// one; `Err(BadRow(Mission))` for a zero reserve or a task name outside
    /// the endpoint alphabet. That the task row exists is checked by
    /// [`Topology::admission_check`].
    pub fn set_mission(&mut self, spec: MissionSpec<'a>) -> Result<(), AdmissionError> {
        if spec.reserve_mj == 0 || spec.task.is_some_and(|t| t.is_empty() || t.len() > MAX_TASK_NAME_LEN) {
            return Err(AdmissionError::BadRow(RowKind::Mission));
        }
        if self.mission.is_some() {
            return Err(AdmissionError::DuplicateRow(RowKind::Mission));
        }
        self.mission = Some(spec);
        Ok(())
    }

    /// Borrow the declared `[boot_chain.NAME]` rows, in file order.
    pub fn boot_chain(&self) -> &[BootChainSpec<'a>] {
        self.boot_chain.as_slice()
    }

    /// Append a `[boot_chain.NAME]` row. `Err(DuplicateRow(BootChain))` for a
    /// repeated name or stage, or a full table; `Err(BadRow(BootChain))` for a
    /// name outside the endpoint alphabet or an all-zero digest. That the
    /// stages are consecutive from 0 is checked by
    /// [`Topology::admission_check`].
    pub fn push_boot_stage(&mut self, spec: BootChainSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes()) || spec.digest == [0; 32] {
            return Err(AdmissionError::BadRow(RowKind::BootChain));
        }
        if self.boot_chain().iter().any(|r| r.name == spec.name || r.stage == spec.stage) || !self.boot_chain.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::BootChain));
        }
        Ok(())
    }

    /// Borrow the declared `[island.NAME]` rows, in file order.
    pub fn islands(&self) -> &[IslandSpec<'a>] {
        self.islands.as_slice()
    }

    /// Append an `[island.NAME]` row. `Err(DuplicateRow(Island))` for a
    /// repeated name, image or mailbox, or a full table; `Err(BadRow(Island))`
    /// for a name or mailbox outside the endpoint alphabet, an image
    /// [`dev_name_ok`] refuses, an all-zero digest, or a wake event outside the
    /// endpoint alphabet or listed twice.
    pub fn push_island(&mut self, spec: IslandSpec<'a>) -> Result<(), AdmissionError> {
        let wake = spec.wake();
        if !import_name_ok(spec.name.as_bytes())
            || !dev_name_ok(spec.image.as_bytes())
            || !import_name_ok(spec.mailbox.as_bytes())
            || spec.sha256 == [0; 32]
            || !wake.iter().all(|w| import_name_ok(w.as_bytes()))
            || wake.iter().enumerate().any(|(i, w)| wake[..i].contains(w))
        {
            return Err(AdmissionError::BadRow(RowKind::Island));
        }
        if self.islands().iter().any(|r| r.name == spec.name || r.image == spec.image || r.mailbox == spec.mailbox)
            || !self.islands.push(spec)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Island));
        }
        Ok(())
    }

    /// Borrow the declared `[activity.NAME]` rows, in file order.
    pub fn activities(&self) -> &[ActivitySpec<'a>] {
        self.activities.as_slice()
    }

    /// The activity of task row `task`.
    pub fn activity_of(&self, task: &[u8]) -> Option<&ActivitySpec<'a>> {
        self.activities().iter().find(|a| a.task.as_bytes() == task)
    }

    /// Append an `[activity.NAME]` row. `Err(DuplicateRow(Activity))` for a
    /// repeated name or task, or a full table; `Err(BadRow(Activity))` for a
    /// name outside the endpoint alphabet, a task name that is empty or too
    /// long, a timer without a period or another trigger with one. That the
    /// task row exists is checked by [`Topology::admission_check`].
    pub fn push_activity(&mut self, spec: ActivitySpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || spec.task.is_empty()
            || spec.task.len() > MAX_TASK_NAME_LEN
            || (spec.trigger == ActivityTrigger::Timer) != (spec.period_ms != 0)
        {
            return Err(AdmissionError::BadRow(RowKind::Activity));
        }
        if self.activities().iter().any(|r| r.name == spec.name || r.task == spec.task) || !self.activities.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::Activity));
        }
        Ok(())
    }

    /// Borrow the declared `[numa.NAME]` rows, in file order.
    pub fn numa_nodes(&self) -> &[NumaSpec<'a>] {
        self.numas.as_slice()
    }

    /// Append a `[numa.NAME]` row. `Err(DuplicateRow(Numa))` for a repeated
    /// name or node, a CPU another node has, or a full table;
    /// `Err(BadRow(Numa))` for a name outside the endpoint alphabet, a node
    /// above [`NUMA_NODE_MAX`] or no CPU.
    pub fn push_numa(&mut self, spec: NumaSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes()) || spec.node > NUMA_NODE_MAX || spec.cpus == 0 {
            return Err(AdmissionError::BadRow(RowKind::Numa));
        }
        if self.numa_nodes().iter().any(|r| r.name == spec.name || r.node == spec.node || r.cpus & spec.cpus != 0)
            || !self.numas.push(spec)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Numa));
        }
        Ok(())
    }

    /// Borrow the declared `[envelope.NAME]` rows, in file order.
    pub fn envelopes(&self) -> &[EnvelopeSpec<'a>] {
        self.envelopes.as_slice()
    }

    /// The ceiling `[envelope.NAME]` rows put on effects of `kind` for class
    /// `class`; [`Envelope::Full`] when no row does.
    pub fn effect_ceiling(&self, class: &[u8], kind: EffectKind) -> Envelope {
        self.envelopes()
            .iter()
            .find(|e| e.kind == kind && e.class.as_bytes() == class)
            .map_or(Envelope::Full, |e| e.level)
    }

    /// Append an `[envelope.NAME]` row. `Err(DuplicateRow(Envelope))` for a
    /// repeated name, a second row for one class and kind, or a full table;
    /// `Err(BadRow(Envelope))` for a name outside the endpoint alphabet or a
    /// class name that is empty or too long. That the class exists is checked
    /// by [`Topology::admission_check`].
    pub fn push_envelope(&mut self, spec: EnvelopeSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes()) || spec.class.is_empty() || spec.class.len() > MAX_TASK_NAME_LEN {
            return Err(AdmissionError::BadRow(RowKind::Envelope));
        }
        if self.envelopes().iter().any(|r| r.name == spec.name || (r.kind == spec.kind && r.class == spec.class))
            || !self.envelopes.push(spec)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Envelope));
        }
        Ok(())
    }

    /// The `[rtc]` row, if there is one.
    pub fn rtc(&self) -> Option<&RtcSpec<'a>> {
        self.rtc.as_ref()
    }

    /// Declare the `[rtc]` row. `Err(DuplicateRow(Rtc))` for a second one;
    /// `Err(BadRow(Rtc))` for a device [`dev_name_ok`] refuses.
    pub fn set_rtc(&mut self, spec: RtcSpec<'a>) -> Result<(), AdmissionError> {
        if !dev_name_ok(spec.dev.as_bytes()) {
            return Err(AdmissionError::BadRow(RowKind::Rtc));
        }
        if self.rtc.is_some() {
            return Err(AdmissionError::DuplicateRow(RowKind::Rtc));
        }
        self.rtc = Some(spec);
        Ok(())
    }

    /// Borrow the declared `[nic.NAME]` rows, in file order.
    pub fn nics(&self) -> &[NicSpec<'a>] {
        self.nics.as_slice()
    }

    /// Append a `[nic.NAME]` row. `Err(DuplicateRow(Nic))` for a repeated
    /// name, device or address, or a full table; `Err(BadRow(Nic))` for a name
    /// outside the endpoint alphabet, a device [`dev_name_ok`] refuses, an MTU
    /// outside [`NIC_MTU_RANGE`] or an address that is multicast or all-zero.
    pub fn push_nic(&mut self, spec: NicSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || !dev_name_ok(spec.dev.as_bytes())
            || !(NIC_MTU_RANGE.0..=NIC_MTU_RANGE.1).contains(&spec.mtu)
            || spec.mac.is_some_and(|m| !mac_ok(&m))
        {
            return Err(AdmissionError::BadRow(RowKind::Nic));
        }
        if self.nics().iter().any(|r| r.name == spec.name || r.dev == spec.dev || (spec.mac.is_some() && r.mac == spec.mac))
            || !self.nics.push(spec)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Nic));
        }
        Ok(())
    }

    /// Borrow the declared `[model.NAME]` rows, in file order.
    pub fn models(&self) -> &[ModelSpec<'a>] {
        self.models.as_slice()
    }

    /// Append a `[model.NAME]` row. `Err(DuplicateRow(Model))` for a repeated
    /// name or bundle, or a full table; `Err(BadRow(Model))` for a name outside
    /// the endpoint alphabet, an all-zero bundle hash or a variant outside the
    /// endpoint alphabet.
    pub fn push_model(&mut self, spec: ModelSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || spec.bundle == [0; 32]
            || (!spec.variant.is_empty() && !import_name_ok(spec.variant.as_bytes()))
        {
            return Err(AdmissionError::BadRow(RowKind::Model));
        }
        if self.models().iter().any(|r| r.name == spec.name || r.bundle == spec.bundle) || !self.models.push(spec) {
            return Err(AdmissionError::DuplicateRow(RowKind::Model));
        }
        Ok(())
    }

    /// Borrow the declared `[usb.NAME]` rows, in file order.
    pub fn usb_rules(&self) -> &[UsbSpec<'a>] {
        self.usbs.as_slice()
    }

    /// What the `[usb.NAME]` rows decide for a device: the first row that
    /// matches, or [`UsbAuthorize::Deny`] when none does.
    pub fn usb_decision(&self, vid: u16, pid: u16, class: u8) -> UsbAuthorize {
        self.usb_rules()
            .iter()
            .find(|r| {
                r.vid.is_none_or(|v| v == vid) && r.pid.is_none_or(|p| p == pid) && r.class.is_none_or(|c| c == class)
            })
            .map_or(UsbAuthorize::Deny, |r| r.authorize)
    }

    /// Append a `[usb.NAME]` row. `Err(DuplicateRow(Usb))` for a repeated name,
    /// a row that an earlier one with the same selector or a catch-all makes
    /// unreachable, or a full table; `Err(BadRow(Usb))` for a name outside the
    /// endpoint alphabet or a `pid` without a `vid`.
    pub fn push_usb(&mut self, spec: UsbSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes()) || (spec.pid.is_some() && spec.vid.is_none()) {
            return Err(AdmissionError::BadRow(RowKind::Usb));
        }
        if self.usb_rules().iter().any(|r| r.name == spec.name || r.is_catch_all() || r.same_selector(&spec))
            || !self.usbs.push(spec)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Usb));
        }
        Ok(())
    }

    /// The cross-row checks of format 8, once every row is known: the task,
    /// user and class rows that rows name exist, and the boot chain has no gap.
    fn format8_admission(&self) -> Result<(), AdmissionError> {
        if let Some(m) = &self.mission {
            if m.task.is_some_and(|t| self.find_task(&t).is_none()) {
                return Err(AdmissionError::BadRow(RowKind::Mission));
            }
        }
        if self.activities().iter().any(|a| self.find_task(&a.task).is_none()) {
            return Err(AdmissionError::BadRow(RowKind::Activity));
        }
        if self.keys().iter().any(|k| k.user.is_some_and(|u| self.find_user(u.as_bytes()).is_none())) {
            return Err(AdmissionError::BadRow(RowKind::Key));
        }
        if self.envelopes().iter().any(|e| self.find_class(&e.class).is_none()) {
            return Err(AdmissionError::BadRow(RowKind::Envelope));
        }
        let stages = self.boot_chain();
        if (0..stages.len()).any(|i| !stages.iter().any(|s| s.stage as usize == i)) {
            return Err(AdmissionError::BadRow(RowKind::BootChain));
        }
        Ok(())
    }
}

impl<'a> PipelineSpec<'a> {
    /// Construct an empty placeholder.
    pub const fn empty() -> Self {
        Self { name: MaybeStr::from_bytes(&[]), dma_pages: 0 }
    }
}

impl<'a> Topology<'a> {
    /// Construct an empty topology, ready to receive parsed entries.
    pub const fn empty() -> Self {
        Self {
            classes: [ClassSpec::empty(); MAX_CLASSES],
            classes_len: 0,
            tasks: [TaskSpec::empty(); MAX_TASKS],
            tasks_len: 0,
            caps_pool: [CapSpec::empty(); MAX_CAPS_TOTAL],
            caps_pool_len: 0,
            sched_config: SchedConfig::DEFAULT,
            operator_pubkey: [0u8; 32],
            pipelines: [PipelineSpec::empty(); MAX_PIPELINES],
            pipelines_len: 0,
            imports_pool: [MaybeStr::from_bytes(&[]); IMPORTS_TOTAL],
            imports_pool_len: 0,
            devices: [DeviceSpec::empty(); MAX_DEVICE_ROWS],
            devices_len: 0,
            signers: [SignerSpec::empty(); MAX_SIGNERS],
            signers_len: 0,
            warrants_pool: [MaybeStr::from_bytes(&[]); SIGNER_WARRANTS_TOTAL],
            warrants_pool_len: 0,
            exports_pool: [ExportSpec::empty(); EXPORTS_TOTAL],
            exports_pool_len: 0,
            peers: [PeerSpec::empty(); MAX_PEERS],
            peers_len: 0,
            policies: [PolicySpec::empty(); MAX_POLICIES],
            policies_len: 0,
            livepatches: [LivepatchSpec::empty(); MAX_LIVEPATCHES],
            livepatches_len: 0,
            degrades: [DegradeSpec::empty(); MAX_DEGRADE_ROWS],
            degrades_len: 0,
            clock: ClockSpec::NONE,
            swaps: [SwapSpec::empty(); MAX_SWAPS],
            swaps_len: 0,
            logins: [LoginSpec::empty(); MAX_LOGINS],
            logins_len: 0,
            volumes: [VolumeSpec::empty(); MAX_VOLUMES],
            volumes_len: 0,
            guests: [GuestSpec::empty(); MAX_GUESTS],
            guests_len: 0,
            routes: [RouteSpec::empty(); MAX_ROUTES],
            routes_len: 0,
            firewalls: [FirewallSpec::empty(); MAX_FIREWALL_ROWS],
            firewalls_len: 0,
            tsns: Table::new(TsnSpec::empty()),
            fieldbuses: Table::new(FieldbusSpec::empty()),
            audios: Table::new(AudioSpec::empty()),
            displays: Table::new(DisplaySpec::empty()),
            users: Table::new(UserSpec::empty()),
            keys: Table::new(KeySpec::empty()),
            mission: None,
            boot_chain: Table::new(BootChainSpec::empty()),
            islands: Table::new(IslandSpec::empty()),
            activities: Table::new(ActivitySpec::empty()),
            numas: Table::new(NumaSpec::empty()),
            envelopes: Table::new(EnvelopeSpec::empty()),
            rtc: None,
            nics: Table::new(NicSpec::empty()),
            models: Table::new(ModelSpec::empty()),
            usbs: Table::new(UsbSpec::empty()),
            #[cfg(feature = "energy")]
            energy: azos_energy::EnergySpec::DEFAULT,
        }
    }

    /// Empty this topology in place. Entries past each length are never read,
    /// so resetting the lengths is enough, and no `Topology`-sized value is
    /// built to do it: a ring-3 program that reloads the signed files for each
    /// request (`pkgd`) calls this instead of assigning `Topology::empty()`
    /// to a topology its stack could not hold twice.
    pub fn clear(&mut self) {
        self.classes_len = 0;
        self.tasks_len = 0;
        self.caps_pool_len = 0;
        self.imports_pool_len = 0;
        self.signers_len = 0;
        self.warrants_pool_len = 0;
        self.exports_pool_len = 0;
        self.peers_len = 0;
        self.sched_config = SchedConfig::DEFAULT;
        self.operator_pubkey = [0u8; 32];
        self.pipelines_len = 0;
        self.devices_len = 0;
        self.policies_len = 0;
        self.livepatches_len = 0;
        self.degrades_len = 0;
        self.clock.ptp_domain = None;
        self.clock.leaps_len = 0;
        self.swaps_len = 0;
        self.logins_len = 0;
        self.volumes_len = 0;
        self.guests_len = 0;
        self.routes_len = 0;
        self.firewalls_len = 0;
        self.tsns.clear();
        self.fieldbuses.clear();
        self.audios.clear();
        self.displays.clear();
        self.users.clear();
        self.keys.clear();
        self.mission = None;
        self.boot_chain.clear();
        self.islands.clear();
        self.activities.clear();
        self.numas.clear();
        self.envelopes.clear();
        self.rtc = None;
        self.nics.clear();
        self.models.clear();
        self.usbs.clear();
        #[cfg(feature = "energy")]
        {
            self.energy = azos_energy::EnergySpec::DEFAULT;
        }
    }

    /// Where the rows stand: [`Topology::rollback`] returns to it.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            tasks_len: self.tasks_len,
            caps_pool_len: self.caps_pool_len,
            imports_pool_len: self.imports_pool_len,
            exports_pool_len: self.exports_pool_len,
            pipelines_len: self.pipelines_len,
        }
    }

    /// Drop every row, grant, import, export and pipeline added since `c`. The rows are
    /// appended to pools in order, so the lengths are all there is to undo. A
    /// package whose rows were parsed in and then refused leaves the topology
    /// as it found it.
    pub fn rollback(&mut self, c: Checkpoint) {
        debug_assert!(c.tasks_len <= self.tasks_len && c.caps_pool_len <= self.caps_pool_len);
        self.tasks_len = c.tasks_len;
        self.caps_pool_len = c.caps_pool_len;
        self.imports_pool_len = c.imports_pool_len;
        self.exports_pool_len = c.exports_pool_len;
        self.pipelines_len = c.pipelines_len;
    }

    /// The energy mode and model this topology declares
    /// ([`azos_energy::EnergySpec::DEFAULT`], performance and no model,
    /// when it declares none). Not validated here: the kernel resolves it
    /// against the machine (`azos_energy::resolve`).
    #[cfg(feature = "energy")]
    #[inline]
    pub fn energy(&self) -> &azos_energy::EnergySpec {
        &self.energy
    }

    /// Set the energy declaration (the `SCHED.TOML` parser, and the built-in
    /// topology's profile default).
    #[cfg(feature = "energy")]
    pub fn set_energy(&mut self, spec: azos_energy::EnergySpec) {
        self.energy = spec;
    }

    /// Borrow the declared pipelines.
    pub fn pipelines(&self) -> &[PipelineSpec<'a>] {
        &self.pipelines[..self.pipelines_len as usize]
    }

    /// Append a `[pipeline.NAME]`. `Err(DuplicatePipeline)` for a repeated
    /// name or a full table.
    pub fn push_pipeline(&mut self, name: MaybeStr<'a>, dma_pages: u32) -> Result<(), AdmissionError> {
        if self.pipelines_len as usize >= MAX_PIPELINES
            || self.pipelines().iter().any(|p| p.name == name)
        {
            return Err(AdmissionError::DuplicatePipeline);
        }
        self.pipelines[self.pipelines_len as usize] = PipelineSpec { name, dma_pages };
        self.pipelines_len += 1;
        Ok(())
    }

    /// Borrow the declared `[device.NAME]` rows, in file order.
    pub fn devices(&self) -> &[DeviceSpec<'a>] {
        &self.devices[..self.devices_len as usize]
    }

    /// Append a `[device.NAME]` row. `Err(DuplicateDevice)` for a repeated
    /// name or a full table; `Err(BadDevice)` for a selector the hardware bus
    /// cannot read, a driver name that is empty-but-present or too long, an
    /// operation name (`safe_state`, `compensate`) outside the endpoint
    /// alphabet, or a refused device that declares any of them or a commit time.
    pub fn push_device(&mut self, spec: DeviceSpec<'a>) -> Result<(), AdmissionError> {
        let op_ok = |op: &MaybeStr<'_>| op.is_empty() || import_name_ok(op.as_bytes());
        if azos_hwbus::Pattern::parse(spec.select.as_str()).is_none()
            || spec.driver.len() > DEVICE_DRIVER_MAX
            || (!spec.admit && !spec.driver.is_empty())
            || !op_ok(&spec.safe_state)
            || !op_ok(&spec.compensate)
            // A refused device is never commanded: it has no safe state, no
            // commit time and nothing to compensate.
            || (!spec.admit
                && (!spec.safe_state.is_empty() || spec.commit_ns != 0 || !spec.compensate.is_empty()))
        {
            return Err(AdmissionError::BadDevice);
        }
        if self.devices_len as usize >= MAX_DEVICE_ROWS
            || self.devices().iter().any(|d| d.name == spec.name)
        {
            return Err(AdmissionError::DuplicateDevice);
        }
        self.devices[self.devices_len as usize] = spec;
        self.devices_len += 1;
        Ok(())
    }

    /// Borrow the declared `[policy.NAME]` rows, in file order.
    pub fn policies(&self) -> &[PolicySpec<'a>] {
        &self.policies[..self.policies_len as usize]
    }

    /// Append a `[policy.NAME]` row. `Err(DuplicateRow(Policy))` for a
    /// repeated name or a full table; `Err(BadRow(Policy))` for a name outside
    /// the endpoint alphabet, a `domain` that is empty or too long, or a row
    /// that restricts nothing. That the Domain's row exists is checked at
    /// admission, once every row is known.
    pub fn push_policy(&mut self, spec: PolicySpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || spec.domain.is_empty()
            || spec.domain.len() > MAX_TASK_NAME_LEN
            || !spec.restricts()
        {
            return Err(AdmissionError::BadRow(RowKind::Policy));
        }
        if self.policies_len as usize >= MAX_POLICIES || self.policies().iter().any(|p| p.name == spec.name) {
            return Err(AdmissionError::DuplicateRow(RowKind::Policy));
        }
        // One row per Domain and scope: two would leave it unsaid which holds.
        if self.policies().iter().any(|p| p.domain == spec.domain && p.scope == spec.scope) {
            return Err(AdmissionError::DuplicateRow(RowKind::Policy));
        }
        self.policies[self.policies_len as usize] = spec;
        self.policies_len += 1;
        Ok(())
    }

    /// Borrow the declared `[livepatch.NAME]` rows, in file order.
    pub fn livepatches(&self) -> &[LivepatchSpec<'a>] {
        &self.livepatches[..self.livepatches_len as usize]
    }

    /// The row that admits the blob with SHA-256 `sha256` for `isa`.
    pub fn find_livepatch(&self, isa: PatchIsa, sha256: &[u8; 32]) -> Option<&LivepatchSpec<'a>> {
        self.livepatches().iter().find(|l| l.isa == isa && &l.sha256 == sha256)
    }

    /// Append a `[livepatch.NAME]` row. `Err(DuplicateRow(Livepatch))` for a
    /// repeated name, a blob (for one ISA) another row already admits, or a
    /// full table; `Err(BadRow(Livepatch))` for a name outside the endpoint
    /// alphabet, a `sec_epoch` of 0 or an all-zero `sha256`.
    pub fn push_livepatch(&mut self, spec: LivepatchSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes()) || spec.sec_epoch == 0 || spec.sha256 == [0u8; 32] {
            return Err(AdmissionError::BadRow(RowKind::Livepatch));
        }
        if self.livepatches_len as usize >= MAX_LIVEPATCHES
            || self.livepatches().iter().any(|l| l.name == spec.name)
            || self.find_livepatch(spec.isa, &spec.sha256).is_some()
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Livepatch));
        }
        self.livepatches[self.livepatches_len as usize] = spec;
        self.livepatches_len += 1;
        Ok(())
    }

    /// Borrow the declared `[degrade.NAME]` rows, in file order.
    pub fn degrades(&self) -> &[DegradeSpec<'a>] {
        &self.degrades[..self.degrades_len as usize]
    }

    /// Append a `[degrade.NAME]` row. `Err(DuplicateRow(Degrade))` for a
    /// repeated name or a level another row already declares;
    /// `Err(BadRow(Degrade))` for a name outside the endpoint alphabet, the
    /// level `full`, a `battery_pct` outside 1..=100, a `clear_pct` outside
    /// `battery_pct..=100`, or a threshold that is not strictly lower than
    /// that of every less restrictive level (and strictly higher than that of
    /// every more restrictive one).
    pub fn push_degrade(&mut self, spec: DegradeSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || spec.level == Envelope::Full
            || !(1..=100).contains(&spec.battery_pct)
            || spec.clear_pct < spec.battery_pct
            || spec.clear_pct > 100
        {
            return Err(AdmissionError::BadRow(RowKind::Degrade));
        }
        if self.degrades_len as usize >= MAX_DEGRADE_ROWS
            || self.degrades().iter().any(|d| d.name == spec.name || d.level == spec.level)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Degrade));
        }
        let ordered = self.degrades().iter().all(|d| {
            if d.level < spec.level { d.battery_pct > spec.battery_pct } else { d.battery_pct < spec.battery_pct }
        });
        if !ordered {
            return Err(AdmissionError::BadRow(RowKind::Degrade));
        }
        self.degrades[self.degrades_len as usize] = spec;
        self.degrades_len += 1;
        Ok(())
    }

    /// Borrow the declared `[route.NAME]` rows, in file order.
    pub fn routes(&self) -> &[RouteSpec<'a>] {
        &self.routes[..self.routes_len as usize]
    }

    /// Append a `[route.NAME]` row. `Err(DuplicateRow(Route))` for a repeated
    /// name, a destination and metric another row has, or a full table;
    /// `Err(BadRow(Route))` for a name outside the endpoint alphabet, an
    /// interface name [`ifname_ok`] refuses, or a gateway that is the
    /// unspecified address or of another family than the destination.
    pub fn push_route(&mut self, spec: RouteSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || !ifname_ok(spec.dev.as_bytes())
            || spec.via.is_some_and(|g| g.v6 != spec.dest.addr.v6 || g.is_unspecified())
        {
            return Err(AdmissionError::BadRow(RowKind::Route));
        }
        if self.routes_len as usize >= MAX_ROUTES
            || self.routes().iter().any(|r| r.name == spec.name || (r.dest == spec.dest && r.metric == spec.metric))
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Route));
        }
        self.routes[self.routes_len as usize] = spec;
        self.routes_len += 1;
        Ok(())
    }

    /// Borrow the declared `[firewall.NAME]` rows, in rule order.
    pub fn firewalls(&self) -> &[FirewallSpec<'a>] {
        &self.firewalls[..self.firewalls_len as usize]
    }

    /// Append a `[firewall.NAME]` row after the rules so far.
    /// `Err(DuplicateRow(Firewall))` for a repeated name, a rule that matches
    /// what an earlier one already matches (it could never be reached), or a
    /// full table; `Err(BadRow(Firewall))` for a name outside the endpoint
    /// alphabet, a port with a protocol that has none, or a port range that
    /// is empty or has no start.
    pub fn push_firewall(&mut self, spec: FirewallSpec<'a>) -> Result<(), AdmissionError> {
        let ports_ok = if spec.port_lo == 0 {
            spec.port_hi == 0
        } else {
            matches!(spec.proto, FwProto::Tcp | FwProto::Udp) && spec.port_hi >= spec.port_lo
        };
        if !import_name_ok(spec.name.as_bytes()) || !ports_ok {
            return Err(AdmissionError::BadRow(RowKind::Firewall));
        }
        if self.firewalls_len as usize >= MAX_FIREWALL_ROWS
            || self.firewalls().iter().any(|f| f.name == spec.name || f.same_match(&spec))
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Firewall));
        }
        self.firewalls[self.firewalls_len as usize] = spec;
        self.firewalls_len += 1;
        Ok(())
    }

    /// Borrow the declared `[guest.NAME]` rows, in file order.
    pub fn guests(&self) -> &[GuestSpec<'a>] {
        &self.guests[..self.guests_len as usize]
    }

    /// Append a `[guest.NAME]` row. `Err(DuplicateRow(Guest))` for a repeated
    /// name or a full table; `Err(BadRow(Guest))` for a name outside the
    /// endpoint alphabet, no CPU or no memory, a device or passthrough name
    /// outside the endpoint alphabet or listed twice (or in both lists), a
    /// static partition whose `pcpus` are not `cpus` CPUs or whose `mem_base`
    /// is zero, unaligned or overflows, or `pcpus`/`mem_base` on a guest that
    /// is not static. A static partition that shares a CPU or memory with an
    /// earlier static guest is `Err(DuplicateRow(Guest))`.
    pub fn push_guest(&mut self, spec: GuestSpec<'a>) -> Result<(), AdmissionError> {
        let devs = spec.devices();
        let pass = spec.passthrough();
        let static_ok = if spec.static_partition {
            spec.pcpus.count_ones() == spec.cpus as u32
                && spec.mem_base % GUEST_STATIC_ALIGN == 0
                && spec.static_range().is_some_and(|(lo, hi)| lo != 0 && hi > lo)
        } else {
            spec.pcpus == 0 && spec.mem_base == 0
        };
        if !import_name_ok(spec.name.as_bytes())
            || spec.cpus == 0
            || spec.mem_mib == 0
            || !devs.iter().all(|d| import_name_ok(d.as_bytes()))
            || devs.iter().enumerate().any(|(i, d)| devs[..i].iter().any(|e| e.as_bytes() == d.as_bytes()))
            || !pass.iter().all(|d| import_name_ok(d.as_bytes()))
            || pass.iter().enumerate().any(|(i, d)| pass[..i].contains(d))
            || pass.iter().any(|d| devs.contains(d))
            || !static_ok
        {
            return Err(AdmissionError::BadRow(RowKind::Guest));
        }
        // Static partitions own their CPUs and their memory alone.
        let clash = |g: &GuestSpec<'_>| {
            g.static_partition
                && spec.static_partition
                && (g.pcpus & spec.pcpus != 0
                    || matches!((g.static_range(), spec.static_range()), (Some(a), Some(b)) if a.0 < b.1 && b.0 < a.1))
        };
        if self.guests_len as usize >= MAX_GUESTS || self.guests().iter().any(|g| g.name == spec.name || clash(g)) {
            return Err(AdmissionError::DuplicateRow(RowKind::Guest));
        }
        self.guests[self.guests_len as usize] = spec;
        self.guests_len += 1;
        Ok(())
    }

    /// Does a swap or volume row already use partition `n`?
    fn partition_taken(&self, n: u8) -> bool {
        self.swaps().iter().any(|s| s.partition == n) || self.volumes().iter().any(|v| v.partition == n)
    }

    /// Borrow the declared `[swap.NAME]` rows, in file order.
    pub fn swaps(&self) -> &[SwapSpec<'a>] {
        &self.swaps[..self.swaps_len as usize]
    }

    /// Append a `[swap.NAME]` row. `Err(DuplicateRow(Swap))` for a repeated
    /// name, a partition another swap or volume row uses, or a full table;
    /// `Err(BadRow(Swap))` for a name outside the endpoint alphabet or a
    /// partition outside 1..=[`PARTITION_MAX`].
    pub fn push_swap(&mut self, spec: SwapSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes()) || !(1..=PARTITION_MAX).contains(&spec.partition) {
            return Err(AdmissionError::BadRow(RowKind::Swap));
        }
        if self.swaps_len as usize >= MAX_SWAPS
            || self.swaps().iter().any(|s| s.name == spec.name)
            || self.partition_taken(spec.partition)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Swap));
        }
        self.swaps[self.swaps_len as usize] = spec;
        self.swaps_len += 1;
        Ok(())
    }

    /// Borrow the declared `[login.NAME]` rows, in file order.
    pub fn logins(&self) -> &[LoginSpec<'a>] {
        &self.logins[..self.logins_len as usize]
    }

    /// Append a `[login.NAME]` row. `Err(BadRow(Login))` and nothing recorded
    /// for a name outside the endpoint alphabet, no key, more than
    /// [`LOGIN_KEYS`] or an all-zero one; `Err(DuplicateRow(Login))` for a
    /// repeated name, a key that any login (or this one) already lists, or a
    /// full table.
    pub fn push_login(&mut self, name: MaybeStr<'a>, keys: &[[u8; 32]]) -> Result<(), AdmissionError> {
        if !import_name_ok(name.as_bytes()) || keys.is_empty() || keys.len() > LOGIN_KEYS || keys.contains(&[0u8; 32]) {
            return Err(AdmissionError::BadRow(RowKind::Login));
        }
        if self.logins_len as usize >= MAX_LOGINS
            || self.logins().iter().any(|l| l.name == name || keys.iter().any(|k| l.keys().contains(k)))
            || keys.iter().enumerate().any(|(i, k)| keys[..i].contains(k))
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Login));
        }
        let mut spec = LoginSpec { name, keys_len: keys.len() as u8, ..LoginSpec::empty() };
        spec.keys[..keys.len()].copy_from_slice(keys);
        self.logins[self.logins_len as usize] = spec;
        self.logins_len += 1;
        Ok(())
    }

    /// Borrow the declared `[volume.NAME]` rows, in file order.
    pub fn volumes(&self) -> &[VolumeSpec<'a>] {
        &self.volumes[..self.volumes_len as usize]
    }

    /// Append a `[volume.NAME]` row. `Err(DuplicateRow(Volume))` for a
    /// repeated name or mount point, a partition another swap or volume row
    /// uses, or a full table; `Err(BadRow(Volume))` for a name outside the
    /// endpoint alphabet, a partition outside 1..=[`PARTITION_MAX`], a mount
    /// point [`mount_path_ok`] refuses, an all-zero `verity_root`, or a
    /// `verity_root` on a volume that is not read-only.
    pub fn push_volume(&mut self, spec: VolumeSpec<'a>) -> Result<(), AdmissionError> {
        if !import_name_ok(spec.name.as_bytes())
            || !(1..=PARTITION_MAX).contains(&spec.partition)
            || !mount_path_ok(spec.mount.as_bytes())
            || spec.verity_root == Some([0u8; 32])
            || (spec.verity_root.is_some() && !spec.read_only)
        {
            return Err(AdmissionError::BadRow(RowKind::Volume));
        }
        if self.volumes_len as usize >= MAX_VOLUMES
            || self.volumes().iter().any(|v| v.name == spec.name || v.mount == spec.mount)
            || self.partition_taken(spec.partition)
        {
            return Err(AdmissionError::DuplicateRow(RowKind::Volume));
        }
        self.volumes[self.volumes_len as usize] = spec;
        self.volumes_len += 1;
        Ok(())
    }

    /// The `[clock]` row ([`ClockSpec::NONE`] when there is none).
    pub fn clock(&self) -> &ClockSpec {
        &self.clock
    }

    /// Declare the `[clock]` row. `Err(DuplicateRow(Clock))` for a second one
    /// or more entries than `LEAP_ENTRIES`; `Err(BadRow(Clock))` for a row
    /// that declares nothing, a PTP domain above [`PTP_DOMAIN_MAX`], an offset
    /// of 0, entries not in strictly increasing time, or an offset that does
    /// not move by exactly one second between entries.
    pub fn set_clock(&mut self, ptp_domain: Option<u8>, leaps: &[LeapEntry]) -> Result<(), AdmissionError> {
        if self.clock.is_declared() || leaps.len() > LEAP_ENTRIES {
            return Err(AdmissionError::DuplicateRow(RowKind::Clock));
        }
        let steps_ok = leaps.windows(2).all(|w| {
            w[1].utc_secs > w[0].utc_secs && w[1].tai_offset.abs_diff(w[0].tai_offset) == 1
        });
        if (ptp_domain.is_none() && leaps.is_empty())
            || ptp_domain.is_some_and(|d| d > PTP_DOMAIN_MAX)
            || leaps.iter().any(|l| l.tai_offset == 0)
            || !steps_ok
        {
            return Err(AdmissionError::BadRow(RowKind::Clock));
        }
        self.clock.ptp_domain = ptp_domain;
        self.clock.leaps[..leaps.len()].copy_from_slice(leaps);
        self.clock.leaps_len = leaps.len() as u8;
        Ok(())
    }

    /// The declared operator release-authority public key, or all-zero if
    /// no `[operator]` section was present. Callers use the same
    /// "all-zero ⇒ absent" convention `operator_authority_init` already
    /// applies to the FAT-file key.
    #[inline]
    pub fn operator_pubkey(&self) -> [u8; 32] {
        self.operator_pubkey
    }

    /// Returns `true` iff an `[operator]` section declared a non-zero key.
    #[inline]
    pub fn has_operator_pubkey(&self) -> bool {
        self.operator_pubkey != [0u8; 32]
    }

    /// Set the operator public key (called by the parser when `CAPS.TOML`
    /// declares an `[operator]` section).
    pub fn set_operator_pubkey(&mut self, key: [u8; 32]) {
        self.operator_pubkey = key;
    }

    /// Number of classes parsed.
    #[inline]
    pub fn classes_len(&self) -> usize {
        self.classes_len as usize
    }

    /// Number of tasks parsed.
    #[inline]
    pub fn tasks_len(&self) -> usize {
        self.tasks_len
    }

    /// Total caps in the pool.
    #[inline]
    pub fn caps_pool_len(&self) -> usize {
        self.caps_pool_len
    }

    /// Borrow the parsed classes (slice of valid entries only).
    pub fn classes(&self) -> &[ClassSpec<'a>] {
        &self.classes[..self.classes_len as usize]
    }

    /// Borrow the parsed tasks.
    pub fn tasks(&self) -> &[TaskSpec<'a>] {
        &self.tasks[..self.tasks_len]
    }

    /// Borrow the caps belonging to a given task.
    pub fn caps_of(&self, task: &TaskSpec<'a>) -> &[CapSpec<'a>] {
        let start = task.caps_start as usize;
        let end = start + task.caps_count as usize;
        &self.caps_pool[start..end]
    }

    /// The names row `task` imports.
    pub fn imports_of(&self, task: &TaskSpec<'a>) -> &[MaybeStr<'a>] {
        let start = task.imports_start as usize;
        &self.imports_pool[start..start + task.imports_count as usize]
    }

    /// The declared package signers.
    pub fn signers(&self) -> &[SignerSpec<'a>] {
        &self.signers[..self.signers_len as usize]
    }

    /// The signer whose key id is `key_id`.
    pub fn find_signer(&self, key_id: &[u8; 32]) -> Option<&SignerSpec<'a>> {
        self.signers().iter().find(|s| &s.key_id == key_id)
    }

    /// The warrant ceilings of signer `s`, each `kind:prefix` (the kind word
    /// of a grant, `endpoint`, `memobj`, ..., then the leading bytes of its
    /// target).
    pub fn warrants_of(&self, s: &SignerSpec<'a>) -> &[MaybeStr<'a>] {
        let start = s.warrants_start as usize;
        &self.warrants_pool[start..start + s.warrants_count as usize]
    }

    /// Does a ceiling of signer `s` cover grant `c`: an entry whose kind word
    /// is the grant's and whose prefix starts the grant's target?
    pub fn signer_covers(&self, s: &SignerSpec<'a>, c: &CapSpec<'_>) -> bool {
        let Some(word) = crate::parser::cap_kind_word(c.kind) else { return false };
        self.warrant_covers(s, word.as_bytes(), c.target.as_bytes())
    }

    /// Does a ceiling of signer `s` cover importing `name` from the name
    /// server? An import is the right to ask for an endpoint by name, and the
    /// server lends a held endpoint to any row that lists it, so it is
    /// authority exactly like an `endpoint` grant of that name and needs an
    /// `endpoint:` entry whose prefix starts it.
    pub fn signer_covers_import(&self, s: &SignerSpec<'a>, name: &MaybeStr<'_>) -> bool {
        self.warrant_covers(s, b"endpoint", name.as_bytes())
    }

    fn warrant_covers(&self, s: &SignerSpec<'a>, kind: &[u8], target: &[u8]) -> bool {
        self.warrants_of(s)
            .iter()
            .any(|w| warrant_split(w.as_bytes()).is_some_and(|(k, prefix)| k == kind && target.starts_with(prefix)))
    }

    /// Declare a package signer. Refused (`TooManySigners`, `BadSigner`) and
    /// nothing recorded for a full table or pool, a name or key id already
    /// declared, an entry that is not `kind:prefix` with a kind a grant can
    /// have, or a signer with no frame ceiling.
    pub fn push_signer(
        &mut self,
        name: MaybeStr<'a>,
        key_id: [u8; 32],
        rt: bool,
        mem_pages_max: u32,
        warrants: &[MaybeStr<'a>],
    ) -> Result<(), AdmissionError> {
        if self.signers_len as usize >= MAX_SIGNERS || self.warrants_pool_len + warrants.len() > SIGNER_WARRANTS_TOTAL {
            return Err(AdmissionError::TooManySigners);
        }
        if name.is_empty()
            || mem_pages_max == 0
            || self.signers().iter().any(|s| s.name == name || s.key_id == key_id)
            || !warrants.iter().all(|w| warrant_ok(w.as_bytes()))
        {
            return Err(AdmissionError::BadSigner);
        }
        let start = self.warrants_pool_len;
        self.warrants_pool[start..start + warrants.len()].copy_from_slice(warrants);
        self.warrants_pool_len += warrants.len();
        self.signers[self.signers_len as usize] = SignerSpec {
            name,
            key_id,
            rt,
            mem_pages_max,
            warrants_start: start as u32,
            warrants_count: warrants.len() as u32,
        };
        self.signers_len += 1;
        Ok(())
    }

    /// Declare the names the task pushed most recently imports. Refused
    /// (`BadImport`, `TooManyImports`) and nothing recorded for a name outside
    /// the endpoint alphabet, a repeat within the row, more than
    /// `MAX_IMPORTS`, or a full pool. Whether the name server holds each one
    /// is checked at admission ([`Topology::admission_check`]), once every row
    /// is known.
    pub fn set_last_task_imports(&mut self, names: &[MaybeStr<'a>]) -> Result<(), AdmissionError> {
        if names.is_empty() {
            return Ok(());
        }
        if names.len() > MAX_IMPORTS || self.imports_pool_len + names.len() > IMPORTS_TOTAL {
            return Err(AdmissionError::TooManyImports);
        }
        for (i, n) in names.iter().enumerate() {
            if !import_name_ok(n.as_bytes()) || names[..i].iter().any(|m| m.as_bytes() == n.as_bytes()) {
                return Err(AdmissionError::BadImport);
            }
        }
        let Some(t) = self.tasks_len.checked_sub(1) else { return Err(AdmissionError::BadImport) };
        // A row declares its imports once: its slice is the pool's tail.
        if self.tasks[t].imports_count != 0 {
            return Err(AdmissionError::BadImport);
        }
        let start = self.imports_pool_len;
        self.imports_pool[start..start + names.len()].copy_from_slice(names);
        self.imports_pool_len += names.len();
        self.tasks[t].imports_start = start as u32;
        self.tasks[t].imports_count = names.len() as u32;
        Ok(())
    }

    /// The row that serves the name server's endpoint: the one holding
    /// `READ` on `endpoint.names`.
    pub fn names_server_row(&self) -> Option<usize> {
        self.tasks().iter().position(|t| {
            self.caps_of(t).iter().any(|c| {
                c.kind == CapKind::Endpoint
                    && c.perms.contains(CapPerms::READ)
                    && endpoint_target(c) == Some(NAMES_ENDPOINT)
            })
        })
    }

    /// Does the name server's row hold a lendable endpoint called `name`: a
    /// `WRITE` grant with `transfer = true` (so `DUP`) and no `READ`, which
    /// would make it the server of that name? `names` itself is never lent.
    pub fn names_server_exports(&self, name: &[u8]) -> bool {
        let Some(r) = self.names_server_row() else { return false };
        name != NAMES_ENDPOINT
            && self.caps_of(&self.tasks()[r]).iter().any(|c| {
                c.kind == CapKind::Endpoint
                    && c.transfer
                    && c.perms.contains(CapPerms::WRITE)
                    && !c.perms.contains(CapPerms::READ)
                    && endpoint_target(c) == Some(name)
            })
    }

    /// The `export` entries of row `task`.
    pub fn exports_of(&self, task: &TaskSpec<'a>) -> &[ExportSpec<'a>] {
        let start = task.exports_start as usize;
        &self.exports_pool[start..start + task.exports_count as usize]
    }

    /// The declared peer classes.
    pub fn peers(&self) -> &[PeerSpec<'a>] {
        &self.peers[..self.peers_len as usize]
    }

    /// The class called `name`.
    pub fn find_peer(&self, name: &[u8]) -> Option<&PeerSpec<'a>> {
        self.peers().iter().find(|p| p.name.as_bytes() == name)
    }

    /// The static Noise key the `[peer.brain]` row pins for the brain link: the
    /// key of the first node of the class. `None` when the topology has no such
    /// row or the row pins no key, and the link then runs `Noise_XX`,
    /// authenticated by the link key.
    pub fn brain_noise_pk(&self) -> Option<[u8; 32]> {
        let p = self.find_peer(BRAIN_PEER)?;
        p.noise_pk_of(*p.nodes().first()?).copied()
    }

    /// Declare a `[peer.NAME]`. Refused (`DuplicatePeer`, `BadPeer`) and
    /// nothing recorded for a repeated or ill-formed name, a full table, no
    /// node, more than `PEER_NODES`, a node 0, a node twice in the class, a
    /// node that another class already lists, a number of Noise keys that is
    /// neither 0 nor one per node, an all-zero key or measurement, or a key
    /// that any node of any class already has.
    pub fn push_peer(
        &mut self,
        name: MaybeStr<'a>,
        nodes: &[u32],
        noise_pks: &[[u8; 32]],
        measurement: Option<[u8; 32]>,
    ) -> Result<(), AdmissionError> {
        if !import_name_ok(name.as_bytes()) {
            return Err(AdmissionError::BadPeer);
        }
        if self.peers_len as usize >= MAX_PEERS || self.find_peer(name.as_bytes()).is_some() {
            return Err(AdmissionError::DuplicatePeer);
        }
        if nodes.is_empty() || nodes.len() > PEER_NODES {
            return Err(AdmissionError::BadPeer);
        }
        for (i, n) in nodes.iter().enumerate() {
            if *n == 0
                || nodes[..i].contains(n)
                || self.peers().iter().any(|p| p.nodes().contains(n))
            {
                return Err(AdmissionError::BadPeer);
            }
        }
        if !noise_pks.is_empty() && noise_pks.len() != nodes.len() {
            return Err(AdmissionError::BadPeer);
        }
        for (i, k) in noise_pks.iter().enumerate() {
            if *k == [0u8; 32]
                || noise_pks[..i].contains(k)
                || self.peers().iter().any(|p| p.noise_pks().contains(k))
            {
                return Err(AdmissionError::BadPeer);
            }
        }
        if measurement == Some([0u8; 32]) {
            return Err(AdmissionError::BadPeer);
        }
        let mut spec = PeerSpec { name, nodes_len: nodes.len() as u8, noise_pks_len: noise_pks.len() as u8, measurement, ..PeerSpec::empty() };
        spec.nodes[..nodes.len()].copy_from_slice(nodes);
        spec.noise_pks[..noise_pks.len()].copy_from_slice(noise_pks);
        self.peers[self.peers_len as usize] = spec;
        self.peers_len += 1;
        Ok(())
    }

    /// Declare the `export` entries of the task pushed most recently. Refused
    /// (`BadExport`, `TooManyExports`) and nothing recorded for an entry that
    /// is not `NAME@CLASS` over the endpoint alphabet, one listed twice, a
    /// row that is not the RPC server's ([`RPC_IMAGE`]), a second
    /// declaration, or a full pool. That the row holds the endpoint and that
    /// the class exists is checked at admission, once every row and section
    /// is known.
    pub fn set_last_task_exports(&mut self, entries: &[ExportSpec<'a>]) -> Result<(), AdmissionError> {
        if entries.is_empty() {
            return Ok(());
        }
        if self.exports_pool_len + entries.len() > EXPORTS_TOTAL {
            return Err(AdmissionError::TooManyExports);
        }
        for (i, e) in entries.iter().enumerate() {
            if !import_name_ok(e.endpoint.as_bytes())
                || !import_name_ok(e.peer.as_bytes())
                || entries[..i].iter().any(|f| f.endpoint.as_bytes() == e.endpoint.as_bytes() && f.peer.as_bytes() == e.peer.as_bytes())
            {
                return Err(AdmissionError::BadExport);
            }
        }
        let Some(t) = self.tasks_len.checked_sub(1) else { return Err(AdmissionError::BadExport) };
        if self.tasks[t].exports_count != 0 || self.tasks[t].name.as_bytes() != RPC_IMAGE {
            return Err(AdmissionError::BadExport);
        }
        let start = self.exports_pool_len;
        self.exports_pool[start..start + entries.len()].copy_from_slice(entries);
        self.exports_pool_len += entries.len();
        self.tasks[t].exports_start = start as u32;
        self.tasks[t].exports_count = entries.len() as u32;
        Ok(())
    }

    /// Does `row` hold what lending the endpoint `name` takes: `WRITE` with
    /// `transfer = true` (so `DUP`) and no `READ`, which would make it the
    /// server of that name?
    pub fn row_lends(&self, row: &TaskSpec<'a>, name: &[u8]) -> bool {
        self.caps_of(row).iter().any(|c| {
            c.kind == CapKind::Endpoint
                && c.transfer
                && c.perms.contains(CapPerms::WRITE)
                && !c.perms.contains(CapPerms::READ)
                && endpoint_target(c) == Some(name)
        })
    }

    /// Get the global scheduler config (window, etc.).
    #[inline]
    pub fn sched_config(&self) -> SchedConfig {
        self.sched_config
    }

    /// Look up a class by name. O(`classes_len`) but `classes_len ≤ 8`.
    pub fn find_class(&self, name: &MaybeStr<'a>) -> Option<&ClassSpec<'a>> {
        self.classes().iter().find(|c| c.name == *name)
    }

    /// Look up a task by name.
    pub fn find_task(&self, name: &MaybeStr<'a>) -> Option<&TaskSpec<'a>> {
        self.tasks().iter().find(|t| t.name == *name)
    }

    /// Add `extra` to the grants of the row named `name`, which need not be
    /// the last one pushed: its grants move to the end of the pool, followed
    /// by `extra` (one move however many are added; when they already end the
    /// pool they stay). `false`, and nothing changed, when no row has that
    /// name, a grant is a `Null` kind or the pool is full.
    ///
    /// Not undone by [`Topology::rollback`]: a rollback to a checkpoint taken
    /// before this call would cut the pool below the row's new grants. The
    /// boot's package apply calls it after its last merge, on a candidate
    /// that is refilled from scratch, never rolled back, if it is refused.
    pub fn extend_task_caps(&mut self, name: &MaybeStr<'a>, extra: &[CapSpec<'a>]) -> bool {
        let Some(i) = self.tasks().iter().position(|t| t.name == *name) else { return false };
        if extra.iter().any(|c| matches!(c.kind, CapKind::Null)) {
            return false;
        }
        let (start, count) = (self.tasks[i].caps_start as usize, self.tasks[i].caps_count as usize);
        let at_end = start + count == self.caps_pool_len;
        let new_start = if at_end { start } else { self.caps_pool_len };
        let new_end = new_start + count + extra.len();
        if new_end > MAX_CAPS_TOTAL {
            return false;
        }
        if !at_end {
            self.caps_pool.copy_within(start..start + count, new_start);
        }
        self.caps_pool[new_start + count..new_end].copy_from_slice(extra);
        self.caps_pool_len = new_end;
        self.tasks[i].caps_start = new_start as u32;
        self.tasks[i].caps_count = (count + extra.len()) as u32;
        true
    }

    /// Append a class. Returns `Err` if the table is full or the name
    /// duplicates an existing class.
    pub fn push_class(&mut self, class: ClassSpec<'a>) -> Result<(), AdmissionError> {
        if (self.classes_len as usize) >= MAX_CLASSES {
            return Err(AdmissionError::DuplicateClass); // closest existing variant
        }
        if self.find_class(&class.name).is_some() {
            return Err(AdmissionError::DuplicateClass);
        }
        if class.priority_range.0 > class.priority_range.1 {
            return Err(AdmissionError::InvalidPriorityRange);
        }
        self.classes[self.classes_len as usize] = class;
        self.classes_len += 1;
        Ok(())
    }

    /// Append a task and consume its caps from the parser. The caller
    /// passes the caps inline.
    pub fn push_task(
        &mut self,
        name: MaybeStr<'a>,
        class_name: MaybeStr<'a>,
        priority: u8,
        caps: &[CapSpec<'a>],
    ) -> Result<(), AdmissionError> {
        self.push_task_profiled(name, class_name, priority, caps, crate::deadline::SchedProfile::NONE)
    }

    /// [`push_task`](Self::push_task) with declared real-time parameters.
    pub fn push_task_profiled(
        &mut self,
        name: MaybeStr<'a>,
        class_name: MaybeStr<'a>,
        priority: u8,
        caps: &[CapSpec<'a>],
        profile: crate::deadline::SchedProfile,
    ) -> Result<(), AdmissionError> {
        if self.tasks_len >= MAX_TASKS {
            return Err(AdmissionError::DuplicateTask);
        }
        if self.find_task(&name).is_some() {
            return Err(AdmissionError::DuplicateTask);
        }
        let new_pool_len = self.caps_pool_len + caps.len();
        if new_pool_len > MAX_CAPS_TOTAL {
            return Err(AdmissionError::DuplicateTask);
        }
        // `caps_start` is a u32 in `TaskSpec`; the assert above the struct
        // keeps every pool index representable, so this cast cannot truncate.
        let caps_start = self.caps_pool_len as u32;
        for (i, c) in caps.iter().enumerate() {
            if matches!(c.kind, CapKind::Null) {
                return Err(AdmissionError::UnknownCapKind);
            }
            self.caps_pool[caps_start as usize + i] = *c;
        }
        self.caps_pool_len = new_pool_len;
        self.tasks[self.tasks_len as usize] = TaskSpec {
            name,
            class_name,
            priority,
            caps_start,
            caps_count: caps.len() as u32,
            profile,
            // No limit unless the row says otherwise — see
            // `set_last_task_mem_pages`, which is how every caller declares
            // one without this function growing a seventh parameter it would
            // then have to grow again for the next per-task property.
            mem_pages: 0,
            // A ceiling unless the row says `mem = "locked"`
            // (`set_last_task_mem_locked`).
            mem_locked: false,
            // No SQ poller unless the row declares one
            // (`set_last_task_sqpoll_idle_ms`).
            sqpoll_idle_ms: 0,
            // One live instance unless the row says otherwise
            // (`set_last_task_instances`).
            instances: 0,
            // Not started at boot unless the row says `start = true`
            // (`set_last_task_start`).
            start: false,
            // No 2 MiB-leaf region unless the row declares one
            // (`set_last_task_mem_huge_mib`).
            mem_huge_mib: 0,
            // Restarted on failure unless the row says otherwise
            // (`set_last_task_restart`).
            restart: RestartPolicy::OnFailure,
            // Native unless the row says otherwise (`set_last_task_abi`).
            abi: TaskAbi::Native,
            // Exact timers unless the row says `timer_slack = true`
            // (`set_last_task_timer_slack`).
            timer_slack: false,
            // The class's principal unless the row declares one
            // (`set_last_task_principal`).
            principal: None,
            // No Linux class unless the row declares one
            // (`set_last_task_lx_class`).
            lx_class: MaybeStr::from_bytes(&[]),
            // No imports unless the row declares them
            // (`set_last_task_imports`).
            imports_start: 0,
            imports_count: 0,
            // Ring 3, fixed there, unless the row declares a placement
            // (`set_last_task_place`).
            place: PlaceSpec::DEFAULT,
            // No exports unless the RPC server's row declares them
            // (`set_last_task_exports`).
            exports_start: 0,
            exports_count: 0,
            // Authority as declared unless the row says `shadow = true`
            // (`set_last_task_shadow`).
            shadow: false,
            // Shares its CPU unless the row says `isolated = true`
            // (`set_last_task_isolated`).
            isolated: false,
            // No kernel-memory ceiling unless the row declares one
            // (`set_last_task_kmem_kib`).
            kmem_kib: 0,
            // Not a security boundary, in no partition, unless the row says
            // so (`set_last_task_boundary`).
            security_boundary: false,
            partition_id: 0,
        };
        self.tasks_len += 1;
        Ok(())
    }

    /// Declare a frame budget for the task pushed most recently.
    ///
    /// A setter rather than an argument to `push_task_profiled`: that call
    /// already has six parameters and fourteen call sites across the builder,
    /// the parser and the tests, and threading a seventh through all of them
    /// would change far more code than the feature is. Returns `false` when no
    /// task has been pushed yet.
    pub fn set_last_task_mem_pages(&mut self, pages: u32) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].mem_pages = pages;
        true
    }

    /// Declare the 2 MiB-leaf region of the most recently pushed task
    /// ([`TaskSpec::mem_huge_mib`]). `false` when no task has been pushed, or
    /// for an odd size or one above [`MAX_HUGE_MIB`] (a region that is not a
    /// whole number of 2 MiB leaves is not one this field can describe).
    pub fn set_last_task_mem_huge_mib(&mut self, mib: u16) -> bool {
        if self.tasks_len == 0 || mib % 2 != 0 || mib > MAX_HUGE_MIB {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].mem_huge_mib = mib;
        true
    }

    /// Mark the most recently pushed task `mem = "locked"`
    /// ([`TaskSpec::mem_locked`]). `false` when no task has been pushed.
    pub fn set_last_task_mem_locked(&mut self, locked: bool) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].mem_locked = locked;
        true
    }

    /// Declare how many live instances the most recently pushed task may have
    /// ([`TaskSpec::instances`]). `false` when no task has been pushed, or
    /// for 0 (a row that may have no instance is not a row).
    pub fn set_last_task_instances(&mut self, n: u16) -> bool {
        if self.tasks_len == 0 || n == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].instances = n;
        true
    }

    /// Set the SQ poller idle time of the most recently pushed task
    /// ([`TaskSpec::sqpoll_idle_ms`]). `false` when no task has been pushed.
    pub fn set_last_task_sqpoll_idle_ms(&mut self, ms: u32) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].sqpoll_idle_ms = ms;
        true
    }

    /// Set the restart policy of the most recently pushed task
    /// ([`TaskSpec::restart`]). `false` when no task has been pushed.
    pub fn set_last_task_restart(&mut self, restart: RestartPolicy) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].restart = restart;
        true
    }

    /// Set the syscall ABI of the most recently pushed task
    /// ([`TaskSpec::abi`]). A Linux row must hold only what
    /// [`TaskAbi::linux_may_hold`] allows: any other capability refuses the
    /// whole topology ([`AdmissionError::LinuxRowHoldsHardware`]), so a
    /// translated image can never be seeded with one. `Ok(false)` when no
    /// task has been pushed.
    pub fn set_last_task_abi(&mut self, abi: TaskAbi) -> Result<bool, AdmissionError> {
        if self.tasks_len == 0 {
            return Ok(false);
        }
        let t = self.tasks[self.tasks_len as usize - 1];
        if abi == TaskAbi::Linux {
            let caps = &self.caps_pool[t.caps_start as usize..(t.caps_start + t.caps_count) as usize];
            if caps.iter().any(|c| !TaskAbi::linux_may_hold(c.kind)) {
                return Err(AdmissionError::LinuxRowHoldsHardware);
            }
        }
        self.tasks[self.tasks_len as usize - 1].abi = abi;
        Ok(true)
    }

    /// The ABI of the row named `name`, or [`TaskAbi::Native`] when no row
    /// has that name.
    pub fn abi_of(&self, name: &[u8]) -> TaskAbi {
        self.tasks()
            .iter()
            .find(|t| t.name.as_bytes() == name)
            .map_or(TaskAbi::Native, |t| t.abi)
    }

    /// The restart policy of the row named `name` (an image's 8.3 name), or
    /// the default ([`RestartPolicy::OnFailure`]) when no row has that name.
    pub fn restart_of(&self, name: &[u8]) -> RestartPolicy {
        self.tasks()
            .iter()
            .find(|t| t.name.as_bytes() == name)
            .map_or(RestartPolicy::OnFailure, |t| t.restart)
    }

    /// Mark the most recently pushed task to be started at boot
    /// ([`TaskSpec::start`]). `false` when no task has been pushed.
    pub fn set_last_task_start(&mut self, start: bool) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].start = start;
        true
    }

    /// Mark the task named `name` to be started at boot. `false` when no
    /// task has that name.
    pub fn set_task_start(&mut self, name: &MaybeStr<'a>, start: bool) -> bool {
        let n = self.tasks_len as usize;
        match self.tasks[..n].iter_mut().find(|t| t.name == *name) {
            Some(t) => {
                t.start = start;
                true
            }
            None => false,
        }
    }

    /// Let the most recently pushed task's timers be coalesced by its QoS
    /// tier ([`TaskSpec::timer_slack`]). `false` when no task has been pushed.
    pub fn set_last_task_timer_slack(&mut self, on: bool) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].timer_slack = on;
        true
    }

    /// Make the most recently pushed task act as `principal` whatever its class
    /// says ([`TaskSpec::principal`]); `None` leaves it to the class. `false`
    /// when no task has been pushed.
    pub fn set_last_task_principal(&mut self, principal: Option<PrincipalKind>) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].principal = principal;
        true
    }

    /// The principal the row named `name` declares for itself
    /// ([`TaskSpec::principal`]); `None` for a row that declares none and for a
    /// name no row has.
    pub fn row_principal(&self, name: &[u8]) -> Option<PrincipalKind> {
        self.tasks().iter().find(|t| t.name.as_bytes() == name).and_then(|t| t.principal)
    }

    /// Mark the most recently pushed task as the server of Linux driver class
    /// `class` ([`TaskSpec::lx_class`]). `Err(BadDevice)` for an empty or
    /// over-long class name, or one outside `[a-z0-9-]`; `Ok(false)` when no
    /// task has been pushed.
    pub fn set_last_task_lx_class(&mut self, class: MaybeStr<'a>) -> Result<bool, AdmissionError> {
        let ok = !class.is_empty()
            && class.len() <= DEVICE_DRIVER_MAX
            && class.as_bytes().iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        if !ok {
            return Err(AdmissionError::BadDevice);
        }
        if self.tasks_len == 0 {
            return Ok(false);
        }
        self.tasks[self.tasks_len as usize - 1].lx_class = class;
        Ok(true)
    }

    /// Does the row named `name` say `timer_slack = true`
    /// ([`TaskSpec::timer_slack`])? `false` for a name no row has.
    pub fn row_timer_slack(&self, name: &[u8]) -> bool {
        self.tasks().iter().any(|t| t.timer_slack && t.name.as_bytes() == name)
    }

    /// Declare the placement of the most recently pushed task
    /// ([`TaskSpec::place`]). `false` when no task has been pushed.
    pub fn set_last_task_place(&mut self, place: PlaceSpec) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].place = place;
        true
    }

    /// Run the most recently pushed task in observe-only mode
    /// ([`TaskSpec::shadow`]). `false` when no task has been pushed.
    pub fn set_last_task_shadow(&mut self, on: bool) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].shadow = on;
        true
    }

    /// Give the most recently pushed task a CPU of its own
    /// ([`TaskSpec::isolated`]). Whether the row can have one is checked by
    /// [`Topology::admission_check`], once `isolcpus` and every row are
    /// known. `false` when no task has been pushed.
    pub fn set_last_task_isolated(&mut self, on: bool) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].isolated = on;
        true
    }

    /// Declare a kernel-memory ceiling for the most recently pushed task
    /// ([`TaskSpec::kmem_kib`]). `false` when no task has been pushed.
    pub fn set_last_task_kmem_kib(&mut self, kib: u32) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].kmem_kib = kib;
        true
    }

    /// Declare the security boundary and partition id of the most recently
    /// pushed task ([`TaskSpec::security_boundary`], [`TaskSpec::partition_id`]).
    /// `false` when no task has been pushed, or when a partition id is given
    /// to a row that is not a security boundary.
    pub fn set_last_task_boundary(&mut self, security_boundary: bool, partition_id: u16) -> bool {
        if self.tasks_len == 0 || (partition_id != 0 && !security_boundary) {
            return false;
        }
        let t = &mut self.tasks[self.tasks_len - 1];
        t.security_boundary = security_boundary;
        t.partition_id = partition_id;
        true
    }

    /// The placement of the row named `name` ([`TaskSpec::place`]); `None`
    /// for a name no row has.
    pub fn row_place(&self, name: &[u8]) -> Option<PlaceSpec> {
        self.tasks().iter().find(|t| t.name.as_bytes() == name).map(|t| t.place)
    }

    /// Set the global scheduler config (called by parser when SCHED.TOML
    /// declares one).
    pub fn set_sched_config(&mut self, cfg: SchedConfig) {
        self.sched_config = cfg;
    }

    // REQ-005
    /// Cross-cutting admission check. Returns the **first** error
    /// found; the caller is expected to abort boot on `Err`.
    ///
    /// Checks performed:
    ///
    /// - Total class budgets do not exceed 100 %.
    /// - Every task references a known class.
    /// - No motor is declared WRITE by two tasks.
    /// - Every row imports only what the name server holds.
    /// - No `neverallow` rule is broken (Kconfig `TOPOLOGY_NEVERALLOW`).
    /// - The real-time rows are schedulable, and the band's rows are locked.
    /// - A row holding `WRITE` on the `flight` endpoint also holds `WRITE` on
    ///   both wheels.
    /// - Every `[policy.NAME]` binds a task row that exists, and every row
    ///   with `isolated = true` names the one CPU of `isolcpus` it owns in its
    ///   `cpu_mask` (`BadRow(Policy | Task)`, or
    ///   `Deadline(IsolatedWithoutCpu)` when the row names none).
    pub fn admission_check(&self) -> Result<(), AdmissionError> {
        let mut total: u32 = 0;
        for class in self.classes() {
            total += class.cpu_budget_min_pct as u32;
        }
        if total > 100 {
            return Err(AdmissionError::BudgetOverflow);
        }
        for task in self.tasks() {
            if self.find_class(&task.class_name).is_none() {
                return Err(AdmissionError::UnknownClass);
            }
        }
        // One writer per motor: the rule `parse_caps` applies to a loaded
        // file, applied here to whatever topology is being installed —
        // `state::init_with(fill_default_minimal)` included.
        if crate::parser::motor_write_conflict(self).is_some() {
            return Err(AdmissionError::MotorWriteConflict);
        }
        // Arming flight is authority over the whole drivetrain.
        if crate::parser::flight_without_drivetrain(self).is_some() {
            return Err(AdmissionError::FlightWithoutDrivetrain);
        }
        // A row may import only what the name server's row holds: an import
        // nothing can answer is a typo in a signed file, refused here rather
        // than discovered as a refused lookup at run time.
        for task in self.tasks() {
            for n in self.imports_of(task) {
                if !self.names_server_exports(n.as_bytes()) {
                    return Err(AdmissionError::UnknownImport);
                }
            }
        }
        // An export lends an endpoint the row holds to a class that exists:
        // anything else is a typo in a signed file that would silently open
        // nothing (or, worse, read as if it had).
        for task in self.tasks() {
            for e in self.exports_of(task) {
                if !self.row_lends(task, e.endpoint.as_bytes()) || self.find_peer(e.peer.as_bytes()).is_none() {
                    return Err(AdmissionError::UnknownExport);
                }
            }
        }
        // What no topology may grant, whatever its file says (`neverallow`).
        if azos_limits::TOPOLOGY_NEVERALLOW {
            crate::neverallow::check(self, &crate::neverallow::Env::BUILD)
                .map_err(AdmissionError::Neverallow)?;
        }
        // Real-time tasks must be schedulable. The CPU count is not known this
        // early, so this checks against every CPU a mask can name, and the
        // dispatch order is the scheduler's, so this checks under the one
        // the cross-level rule does not bind in (EDF across levels, the
        // default): the more lenient side of both. The kernel repeats it with
        // the real hart count and the order it dispatches in once both are
        // known ([`deadline_admission`](Self::deadline_admission)).
        // (It runs `isolation_admission` first: the isolated rows' rules.)
        self.deadline_admission(crate::deadline::MAX_ADMISSION_CPUS, crate::deadline::LevelOrder::Edf)?;
        // A policy binds the Domain of a row that exists: a typo in a signed
        // file would otherwise limit nothing and read as if it limited
        // something.
        for p in self.policies() {
            if self.find_task(&p.domain).is_none() {
                return Err(AdmissionError::BadRow(RowKind::Policy));
            }
        }
        // Wave 11 SCHED-RT: a row that would run in the band with a
        // reservation must be `mem = "locked"`.
        for ti in 0..self.tasks().len() {
            if self.row_band_entry(ti) == crate::deadline::BandEntry::NotLocked {
                return Err(AdmissionError::Deadline(
                    crate::deadline::DeadlineRefusal::BandNotLocked { task: ti as u16 }));
            }
        }
        // The rows of format 8 name tasks, users and classes that must exist.
        self.format8_admission()?;
        Ok(())
    }

    /// Every row with `isolated = true` has a CPU of its own: a declared
    /// real-time profile in a class with admission control (anything else is
    /// never placed), one instance, and a `cpu_mask` that names exactly one
    /// CPU of `[sched] isolcpus` that no other isolated row names
    /// (`BadRow(Task)` otherwise). A row that is not isolated may not name any
    /// CPU of `isolcpus` in its profile either: those CPUs are exclusive, and
    /// NOHZ-FULL stops the tick there (`BadRow(Task)`).
    ///
    /// A row that is isolated and otherwise sound but names no CPU is refused
    /// with `Deadline(IsolatedWithoutCpu)`, which names the row: the topology
    /// does not pick the CPU of an isolated row for it.
    fn isolation_admission(&self) -> Result<(), AdmissionError> {
        let iso = self.sched_config.isolcpus;
        let mut taken = 0u32;
        for (ti, t) in self.tasks().iter().enumerate() {
            let m = t.profile.cpu_mask;
            if !t.isolated {
                if m & iso != 0 {
                    return Err(AdmissionError::BadRow(crate::RowKind::Task));
                }
                continue;
            }
            let placed = self.find_class(&t.class_name).is_some_and(|c| c.admission_control);
            if !t.profile.is_declared()
                || !placed
                || (m != 0 && (m & (m - 1) != 0 || m & !iso != 0 || taken & m != 0))
                || t.instance_count() != 1
            {
                return Err(AdmissionError::BadRow(crate::RowKind::Task));
            }
            if m == 0 {
                return Err(AdmissionError::Deadline(
                    crate::deadline::DeadlineRefusal::IsolatedWithoutCpu { task: ti as u16 }));
            }
            taken |= m;
        }
        Ok(())
    }

    /// [`band_entry`](crate::deadline::band_entry) for task `ti`: its priority
    /// clamped into its class, whether its profile is admitted (declared, in a
    /// class with `admission_control`), whether it is `mem = "locked"`. A task
    /// with no such index or an undeclared class is `NoReservation` when its
    /// raw priority is in the band.
    pub fn row_band_entry(&self, ti: usize) -> crate::deadline::BandEntry {
        let Some(t) = self.tasks().get(ti) else { return crate::deadline::BandEntry::NotBand };
        let (prio, admitted) = match self.find_class(&t.class_name) {
            Some(c) => {
                let (lo, hi) = c.priority_range;
                (t.priority.clamp(lo, hi.max(lo)), t.profile.is_declared() && c.admission_control)
            }
            None => (t.priority, false),
        };
        crate::deadline::band_entry(prio, admitted, t.mem_locked)
    }

    /// The priority level task `ti`'s reservation runs at: its priority
    /// clamped into its class, capped at
    /// [`MAX_ROW_LEVEL`](crate::deadline::MAX_ROW_LEVEL) (what `resolve`
    /// applies to a row with a reservation, floor 0). Boot admission books
    /// this level and run-time `reserve` is handed the same one
    /// (`azos_syscall::topo_sched::row_reservation`), so both apply the
    /// cross-level rule to the same set. An unknown row or class gives the
    /// raw priority, capped.
    pub fn row_level(&self, ti: usize) -> u32 {
        let Some(t) = self.tasks().get(ti) else { return crate::deadline::MAX_ROW_LEVEL };
        let prio = match self.find_class(&t.class_name) {
            Some(c) => {
                let (lo, hi) = c.priority_range;
                t.priority.clamp(lo, hi.max(lo))
            }
            None => t.priority,
        };
        crate::apply::ring3_priority(prio as u32, 0, crate::deadline::MAX_ROW_LEVEL).0
    }

    // REQ-019
    /// Can every real-time task in a class with `admission_control` meet its
    /// deadline on the `ncpus` CPUs it may run on?
    ///
    /// Tasks in classes without `admission_control` are best-effort by
    /// declaration and are neither checked nor counted. Returns the per-CPU load
    /// so the boot log can show how much of each CPU is spoken for.
    ///
    /// `[sched] isolcpus` is applied here: a row with no `cpu_mask` may use
    /// every CPU except those of `isolcpus`. The row-level rules of an isolated
    /// row (one instance, a `cpu_mask` of one isolated CPU, which a row with
    /// none is refused for) are
    /// [`isolation_admission`](Self::isolation_admission)'s, run first.
    ///
    /// `order` is how the scheduler dispatches reservations at different
    /// levels (`azos_sched::classes::level_order`): the cross-level rule binds
    /// only under fixed priority between them.
    pub fn deadline_admission(
        &self,
        ncpus: usize,
        order: crate::deadline::LevelOrder,
    ) -> Result<crate::deadline::Report, AdmissionError> {
        use crate::deadline::{admit, DeadlineRefusal, Item, SchedProfile, MAX_PROFILED, PPM};
        let iso = self.sched_config.isolcpus;
        let all = if ncpus >= 32 { u32::MAX } else { (1u32 << ncpus) - 1 };
        // `isolcpus` must leave the machine a CPU for everything else.
        if ncpus > 0 && iso & all == all {
            return Err(AdmissionError::BadRow(crate::RowKind::Sched));
        }
        self.isolation_admission()?;
        let mut budget = [0u32; MAX_CLASSES];
        for (i, c) in self.classes().iter().enumerate() {
            budget[i] = (c.cpu_budget_max_pct.min(100) as u32) * (PPM / 100);
        }
        let mut items = [Item { task: 0, class: 0, level: 0, profile: SchedProfile::NONE }; MAX_PROFILED];
        let mut n = 0usize;
        for (ti, t) in self.tasks().iter().enumerate() {
            if !t.profile.is_declared() {
                continue;
            }
            let Some(ci) = self.classes().iter().position(|c| c.name == t.class_name) else {
                continue; // an unknown class is `admission_check`'s error, reported first
            };
            if !self.classes()[ci].admission_control {
                continue;
            }
            if n == MAX_PROFILED {
                return Err(AdmissionError::Deadline(DeadlineRefusal::TooManyProfiles));
            }
            let mut profile = t.profile;
            // An isolated row has its mask (`isolation_admission`); any other
            // row that names no CPU stays off the isolated ones.
            if profile.cpu_mask == 0 && iso != 0 {
                profile.cpu_mask = !iso;
            }
            items[n] = Item { task: ti as u16, class: ci as u8, level: self.row_level(ti), profile };
            n += 1;
        }
        admit(&items[..n], ncpus, &budget, order).map_err(AdmissionError::Deadline)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_topology_is_consistent() {
        let t = Topology::empty();
        assert_eq!(t.classes_len(), 0);
        assert_eq!(t.tasks_len(), 0);
        assert_eq!(t.caps_pool_len(), 0);
        assert!(t.admission_check().is_ok());
    }

    #[test]
    fn duplicate_class_rejected() {
        let mut t = Topology::empty();
        let c = ClassSpec {
            name: MaybeStr::from_bytes(b"safety"),
            cpu_budget_min_pct: 20,
            cpu_budget_max_pct: 100,
            policy: PolicyKind::Fifo,
            priority_range: (0, 7),
            preemption: Preemption::Always,
            time_slice_ms: 0,
            admission_control: false,
            envelope: Envelope::Full,
            principal: PrincipalKind::System,
        };
        t.push_class(c).unwrap();
        assert_eq!(t.push_class(c), Err(AdmissionError::DuplicateClass));
    }

    #[test]
    fn budget_overflow_caught() {
        // MaybeStr borrows; sources must outlive the Topology.
        const CLASS_NAMES: [&[u8]; 3] = [b"c0", b"c1", b"c2"];
        let mut t = Topology::empty();
        for name in CLASS_NAMES {
            t.push_class(ClassSpec {
                name: MaybeStr::from_bytes(name),
                cpu_budget_min_pct: 50,
                cpu_budget_max_pct: 100,
                policy: PolicyKind::Fifo,
                priority_range: (0, 7),
                preemption: Preemption::Always,
                time_slice_ms: 0,
                admission_control: false,
                envelope: Envelope::Full,
                principal: PrincipalKind::System,
            })
            .unwrap();
        }
        // 50 + 50 + 50 = 150 > 100
        assert_eq!(
            t.admission_check(),
            Err(AdmissionError::BudgetOverflow)
        );
    }

    #[test]
    fn task_must_reference_known_class() {
        let mut t = Topology::empty();
        t.push_task(
            MaybeStr::from_bytes(b"motor_loop"),
            MaybeStr::from_bytes(b"hard_rt"),
            5,
            &[CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(b"motor.0"),
            }],
        )
        .unwrap();
        assert_eq!(
            t.admission_check(),
            Err(AdmissionError::UnknownClass)
        );
    }

    #[test]
    fn caps_of_returns_correct_slice() {
        let mut t = Topology::empty();
        t.push_task(
            MaybeStr::from_bytes(b"a"),
            MaybeStr::from_bytes(b"any"),
            0,
            &[
                CapSpec {
                    kind: CapKind::Port,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(b"/x"),
                },
                CapSpec {
                    kind: CapKind::Port,
                    perms: CapPerms::WRITE,
                    target: MaybeStr::from_bytes(b"/y"),
                },
            ],
        )
        .unwrap();
        let task = &t.tasks()[0];
        let caps = t.caps_of(task);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].target, MaybeStr::from_bytes(b"/x"));
        assert_eq!(caps[1].target, MaybeStr::from_bytes(b"/y"));
    }

    #[test]
    fn null_cap_kind_rejected() {
        let mut t = Topology::empty();
        let r = t.push_task(
            MaybeStr::from_bytes(b"a"),
            MaybeStr::from_bytes(b"any"),
            0,
            &[CapSpec {
                kind: CapKind::Null,
                perms: CapPerms::READ,
                target: MaybeStr::from_bytes(b"/x"),
            }],
        );
        assert_eq!(r, Err(AdmissionError::UnknownCapKind));
    }

    #[test]
    fn policy_parse_round_trip() {
        assert_eq!(PolicyKind::from_str("edf"), Some(PolicyKind::Edf));
        assert_eq!(PolicyKind::from_str("fair"), Some(PolicyKind::Fair));
        // Names the scheduler has no dispatch class for.
        for gone in ["rr", "cfs", "sporadic", "nope"] {
            assert_eq!(PolicyKind::from_str(gone), None, "{gone}");
        }
    }
}
