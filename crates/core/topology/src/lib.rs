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
//! - [`verify`] — Ed25519 signature verification of the TOML bytes
//!   against the trusted topology key.
//! - [`paths`] — the FAT 8.3 file names a loader opens (`CAPS.TOM`,
//!   `CAPS.SIG`, `SCHED.TOM`, `SCHED.SIG`), and why they are not
//!   `CAPS.TOML`/`CAPS.TOML.SIG`.
//!
//! # Lifecycle
//!
//! ```text
//!   ┌─────────────────────────────────────────────────────────────┐
//!   │ Boot (kernel/src/boot/topology.rs, install_topology)        │
//!   │                                                             │
//!   │  1. init_with(fill_default_minimal): the topology built     │
//!   │     into the image (builder.rs)                             │
//!   │  2. deadline_admission(num_cpus) against the real harts     │
//!   │  3. STATIC_TOPOLOGY = topology  (immutable thereafter)      │
//!   │                                                             │
//!   │  Any failure ⇒ kernel halts; user-space spawn is blocked.   │
//!   └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! The signed-TOML path (`CAPS.TOM`/`CAPS.SIG`, `SCHED.TOM`/`SCHED.SIG`:
//! `verify::verify_signature`, then `parser::parse_caps` /
//! `parser::parse_sched`) is implemented and host-tested, but the kernel
//! does not call it at boot today.
//!
//! # Memory budget
//!
//! Worst case: 8 classes + 64 tasks + 1024 caps total + 64 KiB
//! source-text buffer ≈ ~96 KiB static, all stored in BSS.

#![no_std]
#![deny(missing_docs)]

pub mod apply;
pub mod builder;
pub mod deadline;
pub mod device_record;
pub mod memory;
pub mod parser;
pub mod paths;
pub mod state;
pub mod types;
pub mod verify;

pub use apply::{ring3_priority, RowSched};
pub use memory::{frames_for, units_for, MemReport, MemoryRefusal, RowMem, AUTORUN_ROW, RING3_DEFAULT_PAGES, TOPOLOGY_PAGE};
pub use builder::{default_minimal, fill_default_minimal};
pub use parser::{parse_caps, parse_sched, ParseError};
pub use state::{get, init, init_with, is_ready, InitError};
pub use types::{
    CapSpec, ClassSpec, MaybeStr, PolicyKind, Preemption, RestartPolicy, SchedConfig, TaskAbi,
    PipelineSpec, TaskSpec, Topology, MAX_CAPS_TOTAL, MAX_CLASSES, MAX_PIPELINES,
    MAX_TASKS, MAX_TASK_NAME_LEN,
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
    /// The declared real-time tasks cannot all meet their deadlines on the CPUs
    /// they may run on, or a profile is malformed (`deadline::admit`).
    Deadline(DeadlineRefusal),
    /// The ring-3 rows' frame budgets do not fit the RAM left after the
    /// kernel, or a locked row declares none (`Topology::memory_admission`).
    Memory(MemoryRefusal),
    /// Two `[pipeline.NAME]` sections share a name, or there are more than
    /// `MAX_PIPELINES`.
    DuplicatePipeline,
    /// RFC-0047 P6: a row with `abi = "linux"` declares a capability other
    /// than a file, socket, pipe or launch grant.
    LinuxRowHoldsHardware,
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
