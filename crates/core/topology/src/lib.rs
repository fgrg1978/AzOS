// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AZOS static topology — RFC-0005.
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

pub use apply::{ring3_priority, RowSched};
pub use memory::{frames_for, units_for, MemReport, MemoryRefusal, RowMem, AUTORUN_ROW, RING3_DEFAULT_PAGES, TOPOLOGY_PAGE};
pub use builder::{default_minimal, fill_default_minimal};
pub use parser::{parse_binding, parse_caps, parse_sched, Binding, ParseError};
pub use state::{get, init, init_with, is_ready, try_init_with, InitError, TryInitError};
pub use types::{
    CapSpec, Checkpoint, ClassSpec, DeviceSpec, MaybeStr, PolicyKind, Preemption, RestartPolicy, SchedConfig, SignerSpec, TaskAbi,
    PipelineSpec, TaskSpec, Topology, MAX_CAPS_TOTAL, MAX_CLASSES, MAX_DEVICE_ROWS, MAX_PIPELINES, MAX_SIGNERS,
    SIGNER_WARRANTS_TOTAL,
    MAX_TASKS, MAX_TASK_NAME_LEN, MAX_IMPORTS, IMPORTS_TOTAL, NAMES_ENDPOINT, ExportSpec, PeerSpec,
    EXPORTS_TOTAL, MAX_PEERS, PEER_NODES, PROXY_PREFIX, RPC_IMAGE,
};
pub use deadline::{band_entry, BandEntry, DeadlineRefusal, ProfileFault, SchedProfile, RT_BAND_THRESHOLD};
pub use paths::{CAPS_SIG_PATH, CAPS_TOML_PATH, SCHED_SIG_PATH, SCHED_TOML_PATH};
pub use verify::{verify_config_sig_v2, verify_signature, ConfigSigError, VerifyError, TRUSTED_PUBKEY};

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
    /// RFC-0047 P6: a row with `abi = "linux"` declares a capability other
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
    /// A row holds a grant a `neverallow` rule forbids
    /// (`neverallow::check`, Kconfig `TOPOLOGY_NEVERALLOW`).
    Neverallow(neverallow::NeverallowRefusal),
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
