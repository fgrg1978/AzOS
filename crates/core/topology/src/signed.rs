// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The signed topology on the volume, and which topology a boot installs.
//!
//! `CAPS.TOM` + `CAPS.SIG` and `SCHED.TOM` ([`crate::paths`]). ONE signature
//! covers both (wave 15 follow-up): `CAPS.SIG` is verified against the
//! embedded key before any byte is interpreted; the verified `CAPS.TOM`'s
//! top-level [`Binding`] then names the SHA-256 of the one `SCHED.TOM` it was
//! signed with, this device's id and a counter. Only after the hash, the
//! device and the counter floor pass is `SCHED.TOM` parsed (the classes), then
//! `CAPS.TOM` (the rows). The kernel runs this inside
//! [`crate::try_init_with`], with its boot admission (deadlines, the real-time
//! band, memory) as the check, so a topology refused at any step is never
//! published.
//!
//! `SCHED.SIG` is retired: a second signature cost one more Ed25519
//! verification (about 1.35 M instructions on riscv64) and authenticated a
//! file that could be replayed independently of `CAPS.TOM`. The signed path
//! never shipped with it (it landed earlier in the same wave), so nothing
//! depends on it; a `SCHED.SIG` left on a volume is ignored.
//!
//! [`decide`] is the policy (Kconfig `TOPOLOGY_SOURCE`, `TOPOLOGY_INVALID`):
//! a pure function of the policy and what the volume held, host-tested in
//! `tests/host/topology-tests`. The kernel only reads the files, prints,
//! records, raises the floor and halts (`kernel/src/boot/topology.rs`).

use crate::device_record::DEVICE_ID_LEN;
use crate::parser::{parse_binding, parse_caps, parse_sched, Binding, ParseError};
use crate::types::Topology;
use crate::verify::{verify_signature, VerifyError};
use crate::AdmissionError;

/// One of the two signed files.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignedFile {
    /// `CAPS.TOM` (the rows, their grants, the binding) or its sidecar.
    Caps = 1,
    /// `SCHED.TOM` (the scheduler classes).
    Sched = 2,
}

/// A binding key a policy requires and the file lacks (bit values of the
/// `Unbound` refusal's detail).
pub const UNBOUND_DEVICE: u8 = 1;
/// `counter` missing.
pub const UNBOUND_COUNTER: u8 = 2;
/// `sched_sha256` missing.
pub const UNBOUND_SCHED: u8 = 4;

/// Why a signed topology that is on the volume was not installed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignedRefusal {
    /// Some of the three files are on the volume and some are not
    /// (`present` bit 0 CAPS.TOM, 1 CAPS.SIG, 2 SCHED.TOM). A partial set is
    /// not an absent one: something removed or never wrote part of it.
    Incomplete {
        /// Which of the three files were found.
        present: u8,
    },
    /// A file is larger than its buffer (Kconfig `TOPOLOGY_CAPS_MAX_KB`,
    /// `TOPOLOGY_SCHED_MAX_KB`); nothing of it was verified.
    TooLarge(SignedFile),
    /// CAPS.SIG does not verify against the embedded key.
    Signature(SignedFile, VerifyError),
    /// A file does not parse (CAPS.TOM after its signature, SCHED.TOM after
    /// its hash).
    Parse(SignedFile, ParseError),
    /// The parsed topology is refused by `admission_check` or by the boot
    /// admission (deadlines, band, memory).
    Admission(AdmissionError),
    /// A row declares `mem_huge_mib` on a kernel built without
    /// `LOCKED_HUGE_LEAVES`.
    HugeLeaves,
    /// SCHED.TOM is not the file CAPS.TOM's `sched_sha256` names.
    SchedHashMismatch,
    /// CAPS.TOM names another device.
    WrongDevice,
    /// CAPS.TOM's counter is below this device's topology floor: an older
    /// signed topology put back.
    Replay {
        /// The file's counter.
        counter: u64,
        /// The device's floor.
        floor: u64,
    },
    /// A binding key the policy requires is missing (`UNBOUND_*` bits).
    Unbound {
        /// Which keys are missing.
        missing: u8,
    },
    /// The policy binds the topology to this device, and the device has no
    /// record (`tools/device_provision.py`) to compare with.
    Unprovisioned,
}

impl SignedRefusal {
    /// The `detail` word of the flight-recorder record: bits 28..31 the step
    /// that refused (1 incomplete, 2 too large, 3 signature, 4 parse,
    /// 5 admission, 6 huge leaves, 7 SCHED.TOM hash, 8 wrong device,
    /// 9 replay, 10 unbound, 11 unprovisioned), bits 24..27 the file (1 CAPS,
    /// 2 SCHED, 0 none), bits 0..23 the step's own value: the `present` mask
    /// of an incomplete set, the missing-key bits of an unbound one, the
    /// replayed counter (saturated) of a replay.
    pub const fn code(&self) -> u32 {
        let (step, file, low) = match *self {
            SignedRefusal::Incomplete { present } => (1u32, 0u32, present as u32),
            SignedRefusal::TooLarge(f) => (2, f as u32, 0),
            SignedRefusal::Signature(f, _) => (3, f as u32, 0),
            SignedRefusal::Parse(f, _) => (4, f as u32, 0),
            SignedRefusal::Admission(_) => (5, 0, 0),
            SignedRefusal::HugeLeaves => (6, 0, 0),
            SignedRefusal::SchedHashMismatch => (7, SignedFile::Sched as u32, 0),
            SignedRefusal::WrongDevice => (8, SignedFile::Caps as u32, 0),
            SignedRefusal::Replay { counter, .. } => {
                (9, SignedFile::Caps as u32, if counter > 0xFF_FFFF { 0xFF_FFFF } else { counter as u32 })
            }
            SignedRefusal::Unbound { missing } => (10, SignedFile::Caps as u32, missing as u32),
            SignedRefusal::Unprovisioned => (11, 0, 0),
        };
        (step << 28) | (file << 24) | low
    }
}

/// The three files, as read off the volume. The two texts must outlive the
/// topology: every name and target in it borrows from them.
#[derive(Clone, Copy, Debug)]
pub struct SignedFiles<'a> {
    /// `CAPS.TOM`'s bytes.
    pub caps: &'a [u8],
    /// `CAPS.SIG`'s bytes (64 when well formed).
    pub caps_sig: &'a [u8],
    /// `SCHED.TOM`'s bytes.
    pub sched: &'a [u8],
}

/// What the loader checks the binding against, and how strictly (Kconfig
/// `TOPOLOGY_BIND_DEVICE`, `TOPOLOGY_COUNTER_FLOOR`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceContext {
    /// This device's id (the device record CONFIG.SIG v2 uses), if any.
    pub device_id: Option<[u8; DEVICE_ID_LEN]>,
    /// The topology counter floor (0: none accepted yet, or no record).
    pub floor: u64,
    /// `device` is required and must be this device's id.
    pub bind_device: bool,
    /// `counter` is required and must be at least the floor.
    pub enforce_floor: bool,
}

impl DeviceContext {
    /// The Kconfig policy, with this device's id and floor.
    pub const fn kconfig(device_id: Option<[u8; DEVICE_ID_LEN]>, floor: u64) -> Self {
        Self {
            device_id,
            floor,
            bind_device: azos_limits::TOPOLOGY_BIND_DEVICE,
            enforce_floor: azos_limits::TOPOLOGY_COUNTER_FLOOR,
        }
    }
}

/// The binding checks, in order: SCHED.TOM's hash (always required: it is
/// what authenticates SCHED.TOM), then the device, then the counter. A key the
/// policy does not require is still checked when present, so a file never
/// boots on a device or below a floor it names. `Ok(counter)` is the counter
/// to raise the floor to, if the file has one.
pub fn check_binding(b: &Binding, sched: &[u8], ctx: &DeviceContext) -> Result<Option<u64>, SignedRefusal> {
    let mut missing = 0u8;
    if b.sched_sha256.is_none() {
        missing |= UNBOUND_SCHED;
    }
    if ctx.bind_device && b.device.is_none() {
        missing |= UNBOUND_DEVICE;
    }
    if ctx.enforce_floor && b.counter.is_none() {
        missing |= UNBOUND_COUNTER;
    }
    if missing != 0 {
        return Err(SignedRefusal::Unbound { missing });
    }
    if !cfg!(feature = "topo-sched-hash-canary")
        && b.sched_sha256 != Some(azos_crypto::sha256::sha256(sched))
    {
        return Err(SignedRefusal::SchedHashMismatch);
    }
    if !cfg!(feature = "topo-device-canary") {
        match (b.device, ctx.device_id) {
            (Some(_), None) if ctx.bind_device => return Err(SignedRefusal::Unprovisioned),
            (Some(want), Some(have)) if want != have => return Err(SignedRefusal::WrongDevice),
            _ => {}
        }
    }
    if let Some(c) = b.counter {
        if !cfg!(feature = "topo-replay-canary") && c < ctx.floor {
            return Err(SignedRefusal::Replay { counter: c, floor: ctx.floor });
        }
    }
    Ok(b.counter)
}

/// Verify CAPS.TOM against `key`, check its binding against SCHED.TOM and
/// `ctx`, then parse SCHED.TOM and CAPS.TOM into `topo` (which the caller has
/// emptied). No byte of either file is interpreted before CAPS.SIG has
/// verified, and none of SCHED.TOM before its hash has matched. Returns the
/// counter to raise the floor to, if any.
///
/// Under the `topo-verify-skip-canary` feature the signature check is
/// skipped: the gate's tampered-file row must turn red on such a kernel.
/// `topo-sched-hash-canary`, `topo-device-canary` and `topo-replay-canary`
/// skip the binding checks one by one, for the anti-replay rows.
pub fn fill_signed<'a>(
    topo: &mut Topology<'a>,
    files: &SignedFiles<'a>,
    key: &[u8],
    ctx: &DeviceContext,
) -> Result<Option<u64>, SignedRefusal> {
    if !cfg!(feature = "topo-verify-skip-canary") {
        verify_signature(files.caps, files.caps_sig, key)
            .map_err(|e| SignedRefusal::Signature(SignedFile::Caps, e))?;
    }
    let binding = parse_binding(files.caps).map_err(|e| SignedRefusal::Parse(SignedFile::Caps, e))?;
    let counter = check_binding(&binding, files.sched, ctx)?;
    parse_sched(files.sched, topo).map_err(|e| SignedRefusal::Parse(SignedFile::Sched, e))?;
    parse_caps(files.caps, topo).map_err(|e| SignedRefusal::Parse(SignedFile::Caps, e))?;
    Ok(counter)
}

/// [`fill_signed`] then `admission_check`: everything a host tool can check
/// about a signed pair without a machine (`verify_board_volume`, the host
/// suites). The kernel adds its boot admission on top.
pub fn load_signed<'a>(
    topo: &mut Topology<'a>,
    files: &SignedFiles<'a>,
    key: &[u8],
    ctx: &DeviceContext,
) -> Result<Option<u64>, SignedRefusal> {
    let counter = fill_signed(topo, files, key, ctx)?;
    topo.admission_check().map_err(SignedRefusal::Admission)?;
    Ok(counter)
}

/// Kconfig `TOPOLOGY_SOURCE` (and `TOPOLOGY_INVALID` under the middle one).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourcePolicy {
    /// Install the topology built into the image; never read the volume.
    Builtin,
    /// The signed topology when it is present and valid, else the built-in
    /// one. `invalid_halts`: a PRESENT but invalid set halts instead.
    SignedOrBuiltin {
        /// Kconfig `TOPOLOGY_INVALID_HALT`.
        invalid_halts: bool,
    },
    /// The signed topology or nothing: missing or invalid halts.
    SignedRequired,
}

impl SourcePolicy {
    /// The policy this kernel was configured with.
    pub const KCONFIG: SourcePolicy = if azos_limits::TOPOLOGY_SOURCE_SIGNED_REQUIRED {
        SourcePolicy::SignedRequired
    } else if azos_limits::TOPOLOGY_SOURCE_SIGNED_OR_BUILTIN {
        SourcePolicy::SignedOrBuiltin { invalid_halts: azos_limits::TOPOLOGY_INVALID_HALT }
    } else {
        SourcePolicy::Builtin
    };
}

/// What the volume held, as far as the loader got.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Candidate {
    /// None of the four files is on the volume (or there is no volume).
    Absent,
    /// The set is there and was refused.
    Refused(SignedRefusal),
    /// The set verified, parsed and was admitted (and is installed).
    Valid,
}

/// What the boot does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceAction {
    /// The signed topology is installed.
    Signed,
    /// Policy `Builtin`: the built-in topology, nothing read, nothing recorded.
    Builtin,
    /// No signed set: the built-in topology, with a warning and a record.
    FallbackMissing,
    /// A signed set was refused: the built-in topology, with an error and a
    /// record.
    FallbackInvalid(SignedRefusal),
    /// No signed set under `SignedRequired`: record and halt.
    HaltMissing,
    /// A signed set was refused and the policy halts: record and halt.
    HaltInvalid(SignedRefusal),
}

/// The policy table. `Builtin` ignores the candidate (the kernel does not
/// read the volume under it).
pub const fn decide(policy: SourcePolicy, candidate: Candidate) -> SourceAction {
    match (policy, candidate) {
        (SourcePolicy::Builtin, _) => SourceAction::Builtin,
        (_, Candidate::Valid) => SourceAction::Signed,
        (SourcePolicy::SignedOrBuiltin { .. }, Candidate::Absent) => SourceAction::FallbackMissing,
        (SourcePolicy::SignedOrBuiltin { invalid_halts: false }, Candidate::Refused(r)) => {
            SourceAction::FallbackInvalid(r)
        }
        (SourcePolicy::SignedOrBuiltin { invalid_halts: true }, Candidate::Refused(r)) => {
            SourceAction::HaltInvalid(r)
        }
        (SourcePolicy::SignedRequired, Candidate::Absent) => SourceAction::HaltMissing,
        (SourcePolicy::SignedRequired, Candidate::Refused(r)) => SourceAction::HaltInvalid(r),
    }
}
