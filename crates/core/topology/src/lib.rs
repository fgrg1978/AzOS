// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AZOS static topology.
//!
//! At boot, the kernel loads two signed TOML files (`CAPS.TOML` and
//! `SCHED.TOML`) and parses them into a fixed-pool, alloc-free
//! `Topology` structure. Every user-space task spawned thereafter
//! takes its capability table and scheduler class from this structure;
//! no runtime discovery is permitted in safety mode.
//!
//! # Crate layout
//!
//! - [`types`] — `Topology`, `ClassSpec`, `TaskSpec`, `CapSpec`, fixed
//!   pool sizes, lookup helpers.
//! - [`parser`] — alloc-free TOML subset parser.
//! - [`neverallow`] — the assertions no topology may break, checked by
//!   `admission_check` and `make check-neverallow`.
//! - [`boot_admission`] — the pure half of the kernel's boot admission and
//!   the records it writes, shared with the host dry boot (`tools/gate/azos_sim`).
//! - [`placement`] — where a driver row runs, and whether it may move.
//! - [`verify`] — Ed25519 signature verification of the TOML bytes
//!   against the trusted topology key.
//! - [`paths`] — the FAT 8.3 file names a loader opens (`CAPS.TOM`,
//!   `CAPS.SIG`, `SCHED.TOM`; `SCHED.SIG` is retired), and why they are not
//!   `CAPS.TOML`/`CAPS.TOML.SIG`.
//!
//! # Lifecycle
//!
//! ```text
//!   ┌─────────────────────────────────────────────────────────────┐
//!   │ Boot (kernel/src/boot/topology.rs, install_topology)        │
//!   │                                                             │
//!   │  Kconfig TOPOLOGY_SOURCE (signed::decide):                  │
//!   │  1. read CAPS.TOM, CAPS.SIG and SCHED.TOM off /fat          │
//!   │  2. verify CAPS.SIG, check the binding (SCHED.TOM's hash,   │
//!   │     device, counter floor), THEN parse (signed::fill_signed)│
//!   │  3. admission_check + the boot admission (deadlines on the  │
//!   │     real harts, RT band, memory) on the candidate           │
//!   │  4. publish it (try_init_with) — or, if refused or absent,  │
//!   │     record SAFETY_TOPO_SOURCE and install                   │
//!   │     fill_default_minimal (builder.rs), or halt              │
//!   │  5. STATIC_TOPOLOGY is immutable thereafter                 │
//!   └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! [`emit`] writes a topology back out as the two files; the host emitter
//! (`tests/host/topology-tests/src/bin/topo_emit.rs`, `make topology-files`)
//! ships the built-in topology as a signed pair that way.
//!
//! # Memory budget
//!
//! The slot is sized by Kconfig (`TOPOLOGY_MAX_CLASSES`, `MAX_TASKS`,
//! `MAX_CAPS_TOTAL`, `TOPOLOGY_MAX_PIPELINES`); the kernel keeps the file
//! buffers (`TOPOLOGY_CAPS_MAX_KB` + `TOPOLOGY_SCHED_MAX_KB`) for its life,
//! since a signed topology's strings borrow from them.

#![no_std]
#![deny(missing_docs)]

pub mod apply;
pub mod boot_admission;
pub mod builder;
pub mod deadline;
pub mod device_record;
pub mod emit;
pub mod memory;
pub mod neverallow;
pub mod parser;
pub mod paths;
pub mod placement;
pub mod signed;
pub mod state;
pub mod types;
pub mod verify;

pub use apply::{ring3_priority, RowSched, ServiceEdge};
pub use memory::{frames_for, units_for, MemReport, MemoryRefusal, RowMem, AUTORUN_ROW, RING3_DEFAULT_PAGES, TOPOLOGY_PAGE};
pub use builder::{default_minimal, fill_default_minimal};
pub use parser::{parse_binding, parse_caps, parse_sched, Binding, ParseError};
pub use state::{get, init, init_with, is_ready, try_init_with, InitError, TryInitError};
pub use types::{
    CapSpec, Checkpoint, ClassSpec, DeviceSpec, Envelope, MaybeStr, PolicyKind, Preemption, PrincipalKind, RestartPolicy, SchedConfig, SignerSpec, TaskAbi,
    PipelineSpec, TaskSpec, Topology, MAX_CAPS_TOTAL, MAX_CLASSES, MAX_DEVICE_ROWS, MAX_PIPELINES, MAX_SIGNERS,
    SIGNER_WARRANTS_TOTAL,
    MAX_TASKS, MAX_TASK_NAME_LEN, MAX_IMPORTS, IMPORTS_TOTAL, NAMES_ENDPOINT, ExportSpec, PeerSpec,
    EXPORTS_TOTAL, MAX_PEERS, PEER_NODES, PROXY_PREFIX, RPC_IMAGE, MAX_POLICIES, PolicyScope, PolicySpec, BuildId, LivepatchSpec, PatchIsa, MAX_LIVEPATCHES, DegradeSpec, MAX_DEGRADE_ROWS, ClockSpec, LeapEntry, LEAP_ENTRIES, PTP_DOMAIN_MAX, SwapSpec, VolumeSpec, LoginSpec, MAX_LOGINS, LOGIN_KEYS, MAX_SWAPS, MAX_VOLUMES, PARTITION_MAX, GuestSpec, MAX_GUESTS, GUEST_DEVICES, FirewallSpec, FwAction, FwDir, FwProto, IpAddr, IpPrefix, RouteSpec, MAX_FIREWALL_ROWS, MAX_ROUTES,
};
pub use types::{
    dev_name_ok, ActivitySpec, ActivityTrigger, AudioDir, AudioSpec, BootChainSpec, DisplaySpec, EffectKind, EnvelopeSpec,
    FieldbusKind, FieldbusSpec, IslandSpec, KeyPurpose, KeySource, KeySpec, MissionSpec, ModelSpec, NicSpec, NumaSpec,
    RtcSpec, TsnSpec, UsbAuthorize, UsbSpec, UserSpec, USB_VOLUME_PATH, AUDIO_CHANNELS_MAX, AUDIO_RATE_HZ, GUEST_PASSTHROUGH,
    GUEST_STATIC_ALIGN, ISLAND_WAKE, MAX_ACTIVITIES, MAX_AUDIO, MAX_BOOT_STAGES, MAX_DISPLAYS, MAX_ENVELOPES,
    MAX_FIELDBUS, MAX_ISLANDS, MAX_KEYS, MAX_MODELS, MAX_NICS, MAX_NUMA, MAX_TSN, MAX_USB_RULES, MAX_USERS,
    NIC_MTU_DEFAULT, NIC_MTU_RANGE, NUMA_NODE_MAX, TSN_LINK_BUDGET_MAX, TSN_WINDOW_US_MAX,
};
pub use deadline::{band_entry, BandEntry, DeadlineRefusal, ProfileFault, SchedProfile, RT_BAND_THRESHOLD};
pub use paths::{CAPS_SIG_PATH, CAPS_TOML_PATH, SCHED_SIG_PATH, SCHED_TOML_PATH};
pub use verify::{verify_config_sig_v2, verify_signature, ConfigSigError, VerifyError, CONFIG_SIG_V2_LEN, SIDECAR_MAX, TRUSTED_PUBKEY};

/// Top-level errors a boot loader is expected to discriminate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TopologyError {
    /// CAPS.TOML or SCHED.TOML signature verification failed.
    Signature(VerifyError),
    /// Parser error (syntax, oversized, unknown field).
    Parse(ParseError),
    /// Admission-control failure (e.g., class budgets sum > 100 %, task
    /// references a non-existent class, duplicate task name).
    Admission(AdmissionError),
}

/// Admission-control errors detected after parsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdmissionError {
    /// Class budgets sum to more than 100 %.
    BudgetOverflow,
    /// A task references a scheduler class not declared.
    UnknownClass,
    /// Two tasks share the same name.
    DuplicateTask,
    /// Two classes share the same name.
    DuplicateClass,
    /// A class's `priority_range` is empty or inverted.
    InvalidPriorityRange,
    /// CapSpec references an unknown kind tag.
    UnknownCapKind,
    /// Two tasks declare WRITE on the same motor
    /// (`parser::motor_write_conflict`).
    MotorWriteConflict,
    /// A row holds `WRITE` on the `flight` endpoint without `WRITE` on both
    /// wheels of the drivetrain (`parser::flight_without_drivetrain`).
    FlightWithoutDrivetrain,
    /// The declared real-time tasks cannot all meet their deadlines on the CPUs
    /// they may run on, or a profile is malformed (`deadline::admit`).
    Deadline(DeadlineRefusal),
    /// The ring-3 rows' frame budgets do not fit the RAM left after the
    /// kernel, or a locked row declares none (`Topology::memory_admission`).
    Memory(MemoryRefusal),
    /// Two `[pipeline.NAME]` sections share a name, or there are more than
    /// `MAX_PIPELINES`.
    DuplicatePipeline,
    /// Two `[device.NAME]` rows share a name, or there are more than
    /// `MAX_DEVICE_ROWS`.
    DuplicateDevice,
    /// A `[device.NAME]` row whose `match` is not a hardware bus selector,
    /// whose `driver` is too long, or that both refuses the device and names
    /// a driver for it.
    BadDevice,
    /// A row with `abi = "linux"` declares a capability other
    /// than a file, socket, pipe or launch grant.
    LinuxRowHoldsHardware,
    /// An `imports` name is empty, too long, outside `[A-Za-z0-9_-]`, or listed
    /// twice in one row.
    BadImport,
    /// A row lists more than `MAX_IMPORTS` names, or the imports pool
    /// (`IMPORTS_TOTAL`) is full.
    TooManyImports,
    /// A row imports a name the name server's row does not hold, or imports
    /// at all when no row serves `endpoint.names`.
    UnknownImport,
    /// A `[signer.NAME]` repeats a name or a key id, has no frame ceiling or
    /// a warrant ceiling that is not `kind:prefix`.
    BadSigner,
    /// More `[signer.NAME]` sections than `MAX_SIGNERS`, or more warrant
    /// ceilings than `SIGNER_WARRANTS_TOTAL`.
    TooManySigners,
    /// An `export` entry is not `NAME@CLASS` over the endpoint alphabet, is
    /// listed twice, or belongs to a row other than the RPC server's.
    BadExport,
    /// The `export` pool (`EXPORTS_TOTAL`) is full.
    TooManyExports,
    /// An `export` names an endpoint its row does not hold the lend right on
    /// (`WRITE` with `transfer = true`, no `READ`), or a peer class that no
    /// `[peer.NAME]` section declares.
    UnknownExport,
    /// A `[peer.NAME]` has a name outside the endpoint alphabet, no node, too
    /// many, a node 0, or a node that is listed twice or in another class.
    BadPeer,
    /// Two `[peer.NAME]` sections share a name, or there are more than
    /// `MAX_PEERS`.
    DuplicatePeer,
    /// A row of a kind CAPS.TOML format 7 or 8 added (see [`RowKind`]) holds a
    /// value that cannot be admitted: out of range, malformed, naming
    /// something that does not exist, or contradicting another row.
    BadRow(RowKind),
    /// Two rows of a kind share a name (or the one thing that identifies them,
    /// as `RowKind` says), or there are more than the kind's Kconfig limit.
    DuplicateRow(RowKind),
    /// A row holds a grant a `neverallow` rule forbids
    /// (`neverallow::check`, Kconfig `TOPOLOGY_NEVERALLOW`).
    Neverallow(neverallow::NeverallowRefusal),
}

/// The kinds of row [`AdmissionError::BadRow`] and
/// [`AdmissionError::DuplicateRow`] name: the ones CAPS.TOML formats 7 and 8 and
/// the newest SCHED.TOML keys added.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowKind {
    /// A key of `[sched]`: `isolcpus`.
    Sched,
    /// A key of a `[task.NAME]` row: `shadow`, `isolated`, `kmem_kib`, `principal`,
    /// `security_boundary`, `partition_id`.
    Task,
    /// A `[policy.NAME]` row: name unique per topology, and one row per
    /// Domain and scope.
    Policy,
    /// A `[livepatch.NAME]` row: name unique per topology, one row per blob
    /// and ISA.
    Livepatch,
    /// A `[degrade.NAME]` row: name and level unique per topology, thresholds
    /// that agree with the order of the levels.
    Degrade,
    /// The `[clock]` row: at most one, its TAI-UTC table consistent.
    Clock,
    /// A `[swap.NAME]` row: name unique, its partition used by no other swap
    /// or volume row.
    Swap,
    /// A `[login.NAME]` row: name unique, at least one key and at most
    /// `LOGIN_KEYS`, no key listed twice in the topology.
    Login,
    /// A `[volume.NAME]` row: name, mount point unique, its partition used by
    /// no other swap or volume row.
    Volume,
    /// A `[guest.NAME]` row: name unique, CPUs and memory present, device
    /// backends named once.
    Guest,
    /// A `[route.NAME]` row: name unique, a destination once per metric, a
    /// gateway of the destination's family.
    Route,
    /// A `[firewall.NAME]` row: name unique, no rule that an earlier one makes
    /// unreachable, ports only with tcp and udp.
    Firewall,
    /// A `[tsn.NAME]` row: name and device unique, window and budget in range.
    Tsn,
    /// A `[fieldbus.NAME]` row: name and device unique, a cycle for EtherCAT
    /// only.
    Fieldbus,
    /// An `[audio.NAME]` row: name and device unique, rate and channels in
    /// range.
    Audio,
    /// A `[display.NAME]` row: name and device unique, one primary at most,
    /// a size and a right-angle rotation.
    Display,
    /// A `[user.NAME]` row: name and root unique, root and keystore are
    /// distinct paths.
    User,
    /// A `[key.NAME]` row: name unique, a user exactly when the key is in a
    /// keystore, and that user exists.
    Key,
    /// The `[mission]` row: at most one, a reserve, a task that exists.
    Mission,
    /// A `[boot_chain.NAME]` row: name and stage unique, stages consecutive
    /// from 0, a digest.
    BootChain,
    /// An `[island.NAME]` row: name, image and mailbox unique, a digest, wake
    /// events named once.
    Island,
    /// An `[activity.NAME]` row: name and task unique, the task exists, a
    /// period exactly for a timer.
    Activity,
    /// A `[numa.NAME]` row: name and node unique, CPUs in one node only.
    Numa,
    /// An `[envelope.NAME]` row: name unique, one row per class and kind, the
    /// class exists.
    Envelope,
    /// The `[rtc]` row: at most one, a device.
    Rtc,
    /// A `[nic.NAME]` row: name, device and address unique, an MTU in range
    /// and a unicast address.
    Nic,
    /// A `[model.NAME]` row: name and bundle hash unique, a hash.
    Model,
    /// A `[usb.NAME]` row: name unique, no row after a catch-all or with the
    /// selector of an earlier one, a `pid` only with a `vid`.
    Usb,
}

impl From<VerifyError> for TopologyError {
    fn from(e: VerifyError) -> Self {
        Self::Signature(e)
    }
}

impl From<ParseError> for TopologyError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<AdmissionError> for TopologyError {
    fn from(e: AdmissionError) -> Self {
        Self::Admission(e)
    }
}
