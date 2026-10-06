// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Types representing a parsed AZOS topology — RFC-0005.
//!
//! All structures are fixed-size and `Copy`; the topology is built
//! during boot in a stack/static buffer and never re-allocated.

use azos_abi::cap::{CapKind, CapPerms};
pub use azos_limits::{MAX_TASKS, MAX_CAPS_TOTAL};

use crate::AdmissionError;

// ──────────────────────────────────────────────────────────────────────────
// Bounds — fixed at compile time. RFC-0005.
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

/// Scheduler-policy kind, RFC-0004.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PolicyKind {
    /// Fixed-priority FIFO.
    Fifo = 0,
    /// Earliest-Deadline-First with Constant Bandwidth Server.
    Edf = 1,
    /// Round-robin with quantum.
    Rr = 2,
    /// Completely-Fair Scheduler-style fair share.
    Cfs = 3,
    /// Sporadic server.
    Sporadic = 4,
}

impl PolicyKind {
    /// Parse from the literal TOML string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "fifo" => Some(Self::Fifo),
            "edf" => Some(Self::Edf),
            "rr" => Some(Self::Rr),
            "cfs" => Some(Self::Cfs),
            "sporadic" => Some(Self::Sporadic),
            _ => None,
        }
    }

    /// The literal TOML string [`PolicyKind::from_str`] reads back.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Edf => "edf",
            Self::Rr => "rr",
            Self::Cfs => "cfs",
            Self::Sporadic => "sporadic",
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
    /// Round-robin time slice in milliseconds (only if `policy == Rr`).
    pub time_slice_ms: u16,
    /// Whether to reject task admissions that violate Liu-Layland.
    pub admission_control: bool,
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
    /// Whether the minted capability carries `CapPerms::DUP` (owner decision
    /// 2026-09-26, O3.4): a task may hand a `DUP`-bearing capability to
    /// another task via `move_cap`; without it the move is refused. Defaults
    /// to `false` — a topology row transfers authority only when it says so
    /// with `transfer = true`, never by omission. A *self-created* object's
    /// own creator gets `DUP` through a separate path (the `_create_cap`
    /// syscalls stamp it directly, `crates/core/ipc`), not through this field:
    /// this field is for a capability the signed topology hands to a task
    /// that did not create the object.
    pub transfer: bool,
}

impl<'a> CapSpec<'a> {
    /// Construct an empty placeholder.
    pub const fn empty() -> Self {
        Self {
            kind: CapKind::Null,
            perms: CapPerms::NONE,
            target: MaybeStr::from_bytes(&[]),
            transfer: false,
        }
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
    /// RFC-0049 P1/P2 (owner decisions rounds 13-14): `mem = "locked"` in the
    /// row. A locked row's `mem_pages` is a RESERVATION counted once by
    /// [`Topology::memory_admission`] and must be declared (non-zero); every
    /// other ring-3 row's `mem_pages` is a CEILING, counted twice there
    /// because the row may fork and its budget must cover a full COW copy
    /// (P3). A locked task may not call `SYS_FORK`/`SYS_FORK_COW`/
    /// `SYS_ALLOC_DEMAND` and is born only by exec. `false` unless declared.
    pub mem_locked: bool,
    /// How long, in milliseconds, an io_ring SQ poller of this task keeps
    /// polling an empty submission queue before it parks. **`0` means this
    /// task may not start an SQ poller at all**, which is what every row that
    /// does not declare one gets: a kernel task spinning on a ring costs a
    /// hart, so the signed topology decides who may have one
    /// (`crates/core/ipc/src/io_ring.rs`, `OP_SQPOLL_START`).
    pub sqpoll_idle_ms: u32,
    /// RFC-0049 M1, wave 9: how many instances of this row may be live at
    /// once, `instances = N` in the row. `0` stands for the default, 1 (see
    /// [`TaskSpec::instance_count`]). [`Topology::memory_admission`] counts
    /// the row N times; the kernel refuses the N+1th live spawned (or exec'd)
    /// instance. Fork children are not instances: the memory budget bounds
    /// them.
    pub instances: u16,
    /// `start = true` in the row (wave 9, owner decision): the kernel starts
    /// this image at boot, from `/fat/<name>`, with the row's own
    /// capabilities, class and frame budget (`ring3_driver_launch_task`).
    /// Only a row named after an image (`*.ELF`) can mean anything by it.
    /// `false` unless declared: nothing runs because a row exists.
    pub start: bool,
    /// `mem_huge_mib = N` in a `mem = "locked"` row (Kconfig
    /// `LOCKED_HUGE_LEAVES`, riscv64): N MiB reserved at boot, 2 MiB-aligned,
    /// and mapped at exec with 2 MiB leaves at the task's locked arena. Even,
    /// at most [`MAX_HUGE_MIB`]; `0` (the default) means no region. Counted by
    /// [`Topology::memory_admission`] as `N × 256` locked pages per instance.
    pub mem_huge_mib: u16,
    /// `lease_seal = true` in the row (wave 11, LEASE3): every lease this
    /// task grants must carry the producer-side write seal
    /// (`LEASE_GRANT_SEAL`); an unsealed grant is refused with `-EACCES`.
    /// `false` unless declared.
    pub lease_seal: bool,
    /// Wave 11 (DRVPLACE): `restart = always | on-failure | no` in the row
    /// (topology format 2), what the kernel's supervisor does when a
    /// supervised task of this row ends. [`RestartPolicy::OnFailure`] unless
    /// declared, which is what every row of a format-1 topology gets.
    pub restart: RestartPolicy,
    /// RFC-0047 (wave 12): `abi = "native" | "linux"` in the row (topology
    /// format 3), the syscall table the image's numbers are read against.
    /// [`TaskAbi::Native`] unless declared: no image is translated because
    /// it looks like a Linux binary. A Linux row holds no hardware
    /// capability ([`Topology::set_last_task_abi`]).
    pub abi: TaskAbi,
}

/// The syscall table a row's image is run against (RFC-0047).
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
    /// right to start an image (RFC-0047 P6: a Linux task holds no hardware
    /// capability; it reaches the machine only through files and sockets
    /// that native tasks serve). Everything else is refused at admission.
    pub const fn linux_may_hold(kind: CapKind) -> bool {
        matches!(kind, CapKind::File | CapKind::Socket | CapKind::Pipe | CapKind::Launch)
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
            lease_seal: false,
            restart: RestartPolicy::OnFailure,
            abi: TaskAbi::Native,
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
}

impl SchedConfig {
    /// RFC-0004 default: 10 ms window.
    pub const DEFAULT: Self = Self {
        partition_window_us: 10_000,
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
    /// section of `CAPS.TOML` — RFC-0005 + W2-B5. All-zero means "not
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
    /// `[pipeline.NAME]` sections of `CAPS.TOML` (RFC-0049 P7): the DMA pool
    /// each declared pipeline needs. The boot pool is the larger of their sum
    /// and the Kconfig floor ([`Topology::dma_pool_pages`]).
    pipelines: [PipelineSpec<'a>; MAX_PIPELINES],
    pipelines_len: u8,
    /// RFC-0051 E2: the energy mode and model `SCHED.TOML` declares
    /// (`[energy]`, `[energy.domain.NAME]`). Only with the `energy` feature:
    /// without it the sections are skipped and the kernel runs with no model.
    #[cfg(feature = "energy")]
    energy: azos_energy::EnergySpec,
}

/// Maximum `[pipeline.NAME]` sections in one topology (Kconfig
/// `TOPOLOGY_MAX_PIPELINES`).
pub const MAX_PIPELINES: usize = azos_limits::TOPOLOGY_MAX_PIPELINES;

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
            #[cfg(feature = "energy")]
            energy: azos_energy::EnergySpec::DEFAULT,
        }
    }

    /// Empty this topology in place. Entries past each length are never read,
    /// so resetting the lengths is enough, and no `Topology`-sized value is
    /// built to do it.
    pub(crate) fn clear(&mut self) {
        self.classes_len = 0;
        self.tasks_len = 0;
        self.caps_pool_len = 0;
        self.sched_config = SchedConfig::DEFAULT;
        self.operator_pubkey = [0u8; 32];
        self.pipelines_len = 0;
        #[cfg(feature = "energy")]
        {
            self.energy = azos_energy::EnergySpec::DEFAULT;
        }
    }

    /// RFC-0051: the energy mode and model this topology declares
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
            // Unsealed grants allowed unless the row says otherwise
            // (`set_last_task_lease_seal`).
            lease_seal: false,
            // Restarted on failure unless the row says otherwise
            // (`set_last_task_restart`).
            restart: RestartPolicy::OnFailure,
            // Native unless the row says otherwise (`set_last_task_abi`).
            abi: TaskAbi::Native,
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

    /// Require sealed lease grants from the most recently pushed task
    /// ([`TaskSpec::lease_seal`]). `false` when no task has been pushed.
    pub fn set_last_task_lease_seal(&mut self, seal: bool) -> bool {
        if self.tasks_len == 0 {
            return false;
        }
        self.tasks[self.tasks_len as usize - 1].lease_seal = seal;
        true
    }

    /// Does the row named `name` require sealed lease grants
    /// ([`TaskSpec::lease_seal`])? `false` for a name no row has.
    pub fn row_lease_seal(&self, name: &[u8]) -> bool {
        self.tasks().iter().any(|t| t.lease_seal && t.name.as_bytes() == name)
    }

    /// Set the global scheduler config (called by parser when SCHED.TOML
    /// declares one).
    pub fn set_sched_config(&mut self, cfg: SchedConfig) {
        self.sched_config = cfg;
    }

    /// Cross-cutting admission check. Returns the **first** error
    /// found; the caller is expected to abort boot on `Err`.
    ///
    /// Checks performed:
    ///
    /// - Total class budgets do not exceed 100 %.
    /// - Every task references a known class.
    /// - No motor is declared WRITE by two tasks.
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
        // Real-time tasks must be schedulable. The CPU count is not known this
        // early, so this checks against every CPU a mask can name; the kernel
        // repeats it with the real hart count once that is known
        // ([`deadline_admission`](Self::deadline_admission)).
        self.deadline_admission(crate::deadline::MAX_ADMISSION_CPUS)?;
        // Wave 11 SCHED-RT: a row that would run in the band with a
        // reservation must be `mem = "locked"`.
        for ti in 0..self.tasks().len() {
            if self.row_band_entry(ti) == crate::deadline::BandEntry::NotLocked {
                return Err(AdmissionError::Deadline(
                    crate::deadline::DeadlineRefusal::BandNotLocked { task: ti as u16 }));
            }
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

    /// Can every real-time task in a class with `admission_control` meet its
    /// deadline on the `ncpus` CPUs it may run on?
    ///
    /// Tasks in classes without `admission_control` are best-effort by
    /// declaration and are neither checked nor counted. Returns the per-CPU load
    /// so the boot log can show how much of each CPU is spoken for.
    pub fn deadline_admission(&self, ncpus: usize) -> Result<crate::deadline::Report, AdmissionError> {
        use crate::deadline::{admit, DeadlineRefusal, Item, SchedProfile, MAX_PROFILED, PPM};
        let mut budget = [0u32; MAX_CLASSES];
        for (i, c) in self.classes().iter().enumerate() {
            budget[i] = (c.cpu_budget_max_pct.min(100) as u32) * (PPM / 100);
        }
        let mut items = [Item { task: 0, class: 0, profile: SchedProfile::NONE }; MAX_PROFILED];
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
            items[n] = Item { task: ti as u16, class: ci as u8, profile: t.profile };
            n += 1;
        }
        admit(&items[..n], ncpus, &budget).map_err(AdmissionError::Deadline)
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
                kind: CapKind::Pwm,
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
                    kind: CapKind::Channel,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(b"/x"),
                },
                CapSpec {
                    kind: CapKind::Channel,
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
        assert_eq!(PolicyKind::from_str("cfs"), Some(PolicyKind::Cfs));
        assert_eq!(PolicyKind::from_str("nope"), None);
    }
}
