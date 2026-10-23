// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side parser tests for `azos_topology`, plus the P1
//! topology→cap_store cap-seed bridge suite (the migration to boot-seeded typed capabilities).
//!
//! The kernel-side crate is `no_std` and bound to RISC-V; running its
//! parser tests on the host requires this excluded crate (matching the
//! `ota-tests` pattern). Build / run:
//!
//! ```bash
//! cd tests/host/topology-tests
//! cargo test
//! ```
//!
//! # The cap-seed bridge modules
//!
//! `azos_topology` itself has no RV64-only dependencies (see its
//! `Cargo.toml`: `azos_abi` + `azos_crypto` + `azos_limits`,
//! all host-friendly), so it is a plain crate dependency above. The bridge
//! it feeds (`crates/core/ipc/src/cap_seed.rs`) lives in `azos_ipc`, which
//! IS RV64-only as a whole crate — so, same trick as `tests/host/cap-tests`,
//! the handful of `ipc` source files the bridge actually needs are pulled
//! in directly via `#[path]` instead, with host stand-ins swapped in via
//! Cargo dependency renames for the two RV64-only things they call into
//! (`azos_sync`, `azos_sched`) plus a third for this suite
//! specifically (`azos_drv_*`: the hardware bus and the partition table). See `shims/*/src/lib.rs` for what each
//! stand-in actually provides.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `topology_seed_test_drivers`.
extern crate topology_seed_test_drivers as azos_drv_base;
extern crate topology_seed_test_drivers as azos_drv_bus;
extern crate topology_seed_test_drivers as azos_drv_block;
extern crate topology_seed_test_drivers as azos_drv_irqchip;

/// Does the `autorun` row of the built-in topology hold the drivetrain: the
/// build declares one (`azos_topology::builder::DRIVETRAIN`) and the gate's
/// `flight-tool-drivetrain` row has not moved it to `FLIGHT.ELF`.
#[cfg(test)]
const AUTORUN_DRIVETRAIN: bool =
    azos_topology::builder::DRIVETRAIN && !cfg!(feature = "flight-tool-drivetrain");

// The component manager's tree and failure-contract table
// (`userspace/services/compmgr`), pulled in to check the table against the
// endpoints this topology serves.
#[allow(dead_code)]
#[path = "../../../../userspace/services/compmgr/src/tree.rs"]
pub mod tree;

#[allow(dead_code)]
#[path = "../../../../userspace/services/compmgr/src/contracts.rs"]
pub mod contracts;

#[path = "../../../../crates/core/ipc/src/cap.rs"]
pub mod cap;

#[path = "../../../../crates/core/ipc/src/cap_store.rs"]
pub mod cap_store;

// `drvreg_cap.rs` needs no shim at all: unlike its four siblings above it
// touches no driver, only `cap_store` (see that file's "Why the ops are not
// here"). It is pulled in because `cap_seed`'s `DriverRegistry` arm calls it.
#[path = "../../../../crates/core/ipc/src/drvreg_cap.rs"]
pub mod drvreg_cap;


// A channel bound to an event port stores this link (wave 11, PORTWAIT).
#[path = "../../../../crates/core/ipc/src/port_link.rs"]
pub mod port_link;

/// Host stand-ins for the `crates/core/ipc/src/port.rs` entries the pulled-in
/// modules call. No test here binds a source to a port, so no link is ever
/// stored and none is reached; they answer "the port is gone".
mod port {
    /// The kinds the pulled-in modules name (wave 15 N5b).
    #[allow(dead_code)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum PortSourceKind {
        Ring(u32),
        Irq(u32),
        Endpoint(u32),
    }

    /// A gone source: nothing is bound in this harness.
    #[allow(dead_code)]
    pub fn port_source_gone(_link: crate::port_link::PortLink, _kind: PortSourceKind, _code: u16) -> bool {
        false
    }

    /// An endpoint's notice: nothing is bound in this harness.
    #[allow(dead_code)]
    pub fn port_signal(_link: crate::port_link::PortLink, _kind: PortSourceKind) -> bool {
        false
    }
}

// `mmio_cap.rs` touches `cap_store` and the hardware bus, which
// the drivers shim pulls in real (`azos_drv_bus::hwbus`). `cap_seed`'s
// `Device` arm calls it.
#[path = "../../../../crates/core/ipc/src/mmio_cap.rs"]
pub mod mmio_cap;

// Wave 10: `cap_seed`'s `File` arm mints a directory-tree capability through
// this.
#[path = "../../../../crates/core/ipc/src/file_cap.rs"]
pub mod file_cap;

// `cap_seed`'s `Launch` arm mints a launch grant through
// this.
#[path = "../../../../crates/core/ipc/src/launch_cap.rs"]
pub mod launch_cap;

// `seed_one_cap` mints an endpoint, so the module it mints
// through has to be under this harness too — the seed arm is what makes
// `"endpoint"` in `CAPS.TOML` grant something rather than silently nothing.
#[path = "../../../../crates/core/ipc/src/endpoint.rs"]
pub mod endpoint;

/// The serial lock `endpoint.rs`'s embedded suite takes.
///
/// Thinner than `tests/host/ipc-tests`'s namesake on purpose: that one also
/// resets the `azos_sched` and `azos_mm` shims, which this crate does
/// not carry. What the endpoint suite needs here is only that its tests do not
/// run at the same time as each other — each begins by wiping the endpoint
/// pool, and `cargo test` runs test functions on several threads, so without
/// this one test's reset lands inside another's assertions.
/// `#[cfg(test)]`, and that is not cosmetic: only the embedded `mod tests`
/// uses it, so in the plain library build both items are dead code — and this
/// gate counts a warning as a failure. `tests/host/ipc-tests`'s namesake is
/// unconditional because its own suites reference it from non-test paths.
#[cfg(test)]
pub(crate) mod harness {
    use std::sync::{Mutex, MutexGuard};

    pub static SERIAL: Mutex<()> = Mutex::new(());

    pub fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Host stand-in for `crates/core/ipc/src/irq_bind.rs` (which pulls `port`, the
/// PLIC bound and the scheduler): the seed bridge's `irq` arm resolves here
/// to "no minter on the host", which is what every test in this crate
/// expects — the declaration path is what these tests pin, not the grant.
mod irq_bind {
    /// Same bound and same grant as the real minter (`irq_bind.rs`), minus
    /// the binding table nothing here exercises.
    pub fn irq_grant_cap(
        tid: u32,
        irq: u32,
        perms: crate::cap::CapPerms,
    ) -> Option<crate::cap::Cap<crate::cap::targets::Irq>> {
        if irq == 0 || irq >= azos_drv_irqchip::plic::MAX_IRQS {
            return None;
        }
        crate::cap_store::grant::<crate::cap::targets::Irq>(tid, perms, irq)
    }

    /// A message-signalled slot is minted only where the platform has MSI for
    /// ring 3; the host has none. (The real minter and its ops are covered by
    /// `tests/host/ipc-tests`.)
    pub fn irq_grant_msi_cap(
        _tid: u32,
        _k: u32,
        _perms: crate::cap::CapPerms,
    ) -> Option<crate::cap::Cap<crate::cap::targets::Irq>> {
        None
    }
}
#[path = "../../../../crates/core/ipc/src/cap_seed.rs"]
pub mod cap_seed;

#[cfg(test)]
mod sched_tests {
    use azos_topology::{
        parse_sched, AdmissionError, ParseError, PolicyKind, Preemption, Topology,
    };

    /// A minimal but realistic SCHED.TOML — three classes summing to 100 %.
    const SCHED_OK: &[u8] = b"\
[class.safety_critical]
cpu_budget_min_pct  = 15
cpu_budget_max_pct  = 100
policy              = \"fifo\"
priority_range      = [0, 7]
preemption          = \"always\"

[class.hard_rt]
cpu_budget_min_pct  = 30
cpu_budget_max_pct  = 50
policy              = \"edf\"
admission_control   = true

[class.best_effort]
cpu_budget_min_pct  = 5
cpu_budget_max_pct  = 100
policy              = \"fair\"
priority_range      = [16, 30]

[sched]
partition_window_us = 5000
";

    /// Energy-aware scheduling, answer I4, on a kernel built without Kconfig ENERGY (this crate builds
    /// the topology without its `energy` feature): a SCHED.TOML that declares
    /// an energy mode and model parses, its classes are read, and the energy
    /// sections are skipped, not refused. Refusing would let a signed model
    /// stop a board from booting on a kernel that ignores models anyway.
    #[test]
    fn energy_sections_are_skipped_without_the_energy_feature() {
        let mut text = SCHED_OK.to_vec();
        text.extend_from_slice(b"
[energy]
mode = \"endurance\"

[energy.domain.all]
cpus = 15
opps = [
  { freq_khz = 1000000, capacity = 1024, power_mw = 500 },
]
idle = [ { name = \"wfi\", exit_latency_us = 1, target_residency_us = 1 } ]
");
        let text: &'static [u8] = Box::leak(text.into_boxed_slice());
        let mut topo = Topology::empty();
        parse_sched(text, &mut topo).unwrap();
        assert_eq!(topo.classes_len(), 3);
        assert_eq!(topo.sched_config().partition_window_us, 5000);
        // An unknown top-level section is still refused: only the energy ones
        // are known-and-skipped.
        let mut topo = Topology::empty();
        assert_eq!(parse_sched(b"[watts]\nmode = 1\n", &mut topo), Err(ParseError::UnknownSection));
    }

    #[test]
    fn parse_three_classes() {
        let mut topo = Topology::empty();
        parse_sched(SCHED_OK, &mut topo).unwrap();
        assert_eq!(topo.classes_len(), 3);
        let safety = topo.classes()[0];
        assert_eq!(safety.cpu_budget_min_pct, 15);
        assert_eq!(safety.policy, PolicyKind::Fifo);
        assert_eq!(safety.preemption, Preemption::Always);
        let hard = topo.classes()[1];
        assert_eq!(hard.policy, PolicyKind::Edf);
        assert!(hard.admission_control);
        let be = topo.classes()[2];
        assert_eq!(be.policy, PolicyKind::Fair);
        assert_eq!(be.priority_range, (16, 30));
        assert_eq!(topo.sched_config().partition_window_us, 5000);
    }

    // REQ-005
    #[test]
    fn budget_overflow_rejected_by_admission() {
        let toml = b"\
[class.a]
cpu_budget_min_pct = 60
policy             = \"fifo\"

[class.b]
cpu_budget_min_pct = 60
policy             = \"fifo\"
";
        let mut topo = Topology::empty();
        parse_sched(toml, &mut topo).unwrap();
        assert_eq!(
            topo.admission_check(),
            Err(AdmissionError::BudgetOverflow)
        );
    }

    #[test]
    fn unknown_policy_rejected() {
        let toml = b"\
[class.weird]
cpu_budget_min_pct = 10
policy             = \"made_up\"
";
        let mut topo = Topology::empty();
        let r = parse_sched(toml, &mut topo);
        assert!(matches!(r, Err(ParseError::UnknownEnumValue)));
    }

    #[test]
    fn unterminated_section_rejected() {
        let toml = b"[class.broken\n";
        let mut topo = Topology::empty();
        let r = parse_sched(toml, &mut topo);
        assert!(matches!(r, Err(ParseError::UnterminatedSection)));
    }

    #[test]
    fn unknown_section_rejected() {
        let toml = b"[unknown.thing]\n";
        let mut topo = Topology::empty();
        let r = parse_sched(toml, &mut topo);
        assert!(matches!(r, Err(ParseError::UnknownSection)));
    }

    #[test]
    fn unknown_field_rejected() {
        let toml = b"\
[class.x]
cpu_budget_min_pct = 5
made_up_field = 1
";
        let mut topo = Topology::empty();
        let r = parse_sched(toml, &mut topo);
        assert!(matches!(r, Err(ParseError::UnknownField)));
    }

    #[test]
    fn priority_range_parses() {
        let toml = b"\
[class.x]
cpu_budget_min_pct = 5
policy = \"fifo\"
priority_range = [3, 9]
time_slice_ms = 12
";
        let mut topo = Topology::empty();
        parse_sched(toml, &mut topo).unwrap();
        let c = topo.classes()[0];
        assert_eq!(c.priority_range, (3, 9));
        assert_eq!(c.time_slice_ms, 12);
    }

    #[test]
    fn comments_and_blank_lines_ok() {
        let toml = b"\
# Top of file comment.

# Another comment.
[class.x]    # inline comment
cpu_budget_min_pct = 5  # trailing comment
policy             = \"fifo\"

# Trailing comment.
";
        let mut topo = Topology::empty();
        parse_sched(toml, &mut topo).unwrap();
        assert_eq!(topo.classes_len(), 1);
    }

    #[test]
    fn duplicate_class_caught() {
        let toml = b"\
[class.x]
cpu_budget_min_pct = 1
policy = \"fifo\"

[class.x]
cpu_budget_min_pct = 2
policy = \"fair\"
";
        let mut topo = Topology::empty();
        let r = parse_sched(toml, &mut topo);
        assert!(matches!(
            r,
            Err(ParseError::Admission(AdmissionError::DuplicateClass))
        ));
    }
}

#[cfg(test)]
mod caps_tests {
    #[allow(unused_imports)] // profile-gated tests (M40) use these
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::{parse_caps, parse_sched, AdmissionError, ParseError, Topology};

    const SCHED_PRIMER: &[u8] = b"\
[class.safety_critical]
cpu_budget_min_pct = 15
policy             = \"fifo\"

[class.hard_rt]
cpu_budget_min_pct = 30
policy             = \"edf\"

[class.best_effort]
cpu_budget_min_pct = 5
policy             = \"fair\"
";

    /// A row declares a message-signalled interrupt slot with the `msi.<k>`
    /// device target (`cap_seed.rs` mints it as a `Cap<Irq>` where the
    /// platform has MSI for ring 3): the parser takes a device target as an
    /// opaque string, so the convention needs nothing on the declaration side.
    ///
    /// **Canary.** Make `parse_caps` validate a device target against
    /// `irq.`/`mmio.`/`drv.`: this row is refused.
    #[test]
    fn an_msi_slot_is_declared_by_a_device_row() {
        let caps = b"[task.nic_drv]\ncaps = [ { kind = \"device\", target = \"msi.0\", perm = \"r\" } ]\n";
        let mut topo = Topology::empty();
        parse_caps(caps, &mut topo).unwrap();
        let task = topo.tasks()[0];
        let list = topo.caps_of(&task);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].kind, CapKind::Device);
        assert_eq!(list[0].target.as_str(), "msi.0");
    }

    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn parse_one_task_with_three_caps() {
        let caps = b"\
[task.rt_motor]
class    = \"hard_rt\"
priority = 5
caps = [
    { kind = \"endpoint\",    target = \"motor.0\", perm = \"rw\" },
    { kind = \"endpoint\",    target = \"motor.1\", perm = \"rw\" },
    { kind = \"endpoint\", target = \"endpoint.motor_cmd\", perm = \"r\" },
]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        parse_caps(caps, &mut topo).unwrap();
        assert_eq!(topo.tasks_len(), 1);
        let task = topo.tasks()[0];
        assert_eq!(task.priority, 5);
        let caps_slice = topo.caps_of(&task);
        assert_eq!(caps_slice.len(), 3);
        assert_eq!(caps_slice[0].kind, CapKind::Endpoint);
        assert_eq!(caps_slice[0].perms, CapPerms::RW);
        assert_eq!(caps_slice[2].kind, CapKind::Endpoint);
        assert_eq!(caps_slice[2].perms, CapPerms::READ);
    }

    #[test]
    fn cross_reference_unknown_class_rejected() {
        let caps = b"\
[task.lonely]
class = \"does_not_exist\"
caps = []
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        parse_caps(caps, &mut topo).unwrap();
        assert_eq!(
            topo.admission_check(),
            Err(AdmissionError::UnknownClass)
        );
    }

    #[test]
    fn null_kind_rejected_with_admission_error() {
        // "null" is not in the kind table → UnknownEnumValue from parser.
        let caps = b"\
[task.bad]
caps = [
    { kind = \"unknown_kind\", target = \"x\", perm = \"r\" },
]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        let r = parse_caps(caps, &mut topo);
        assert!(matches!(r, Err(ParseError::UnknownEnumValue)));
    }

    #[test]
    fn empty_caps_array_ok() {
        let caps = b"\
[task.passive]
caps = []
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        parse_caps(caps, &mut topo).unwrap();
        assert_eq!(topo.tasks_len(), 1);
        assert_eq!(topo.caps_of(&topo.tasks()[0]).len(), 0);
    }

    /// **One writer per motor.** Two tasks each holding WRITE on motor 0 are
    /// two command sources for one wheel, with nothing between them.
    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn two_tasks_declaring_write_on_one_motor_are_rejected() {
        let caps = b"\
[task.a]
class = \"hard_rt\"
caps = [ { kind = \"endpoint\", target = \"motor.0\", perm = \"rw\" } ]

[task.b]
class = \"best_effort\"
caps = [ { kind = \"endpoint\", target = \"motor.0\", perm = \"w\" } ]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::MotorWriteConflict));
    }

    /// The id, not the spelling: `motor.00` and `motor.+0` mint motor 0
    /// (`cap_seed::parse_dotted` is a `u32` parse), so they conflict with it.
    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn a_second_spelling_of_the_same_motor_is_the_same_motor() {
        for alias in ["motor.00", "motor.+0"] {
            let caps = format!(
                "[task.a]\ncaps = [ {{ kind = \"endpoint\", target = \"motor.0\", perm = \"rw\" }} ]\n\n\
                 [task.b]\ncaps = [ {{ kind = \"endpoint\", target = \"{alias}\", perm = \"rw\" }} ]\n"
            );
            let mut topo = Topology::empty();
            parse_sched(SCHED_PRIMER, &mut topo).unwrap();
            assert_eq!(
                parse_caps(caps.as_bytes(), &mut topo),
                Err(ParseError::MotorWriteConflict),
                "{alias}"
            );
        }
    }

    /// What the rule does not refuse: readers alongside the writer, one
    /// writer per wheel, and one task naming its own motor twice.
    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn one_writer_per_motor_with_readers_is_accepted() {
        let caps = b"\
[task.drive]
class = \"hard_rt\"
caps = [
    { kind = \"endpoint\", target = \"motor.0\", perm = \"rw\" },
    { kind = \"endpoint\", target = \"motor.0\", perm = \"rw\" },
]

[task.other_wheel]
caps = [ { kind = \"endpoint\", target = \"motor.1\", perm = \"rw\" } ]

[task.observer]
caps = [
    { kind = \"endpoint\", target = \"motor.0\", perm = \"r\" },
    { kind = \"endpoint\", target = \"motor.1\", perm = \"r\" },
]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        assert_eq!(parse_caps(caps, &mut topo), Ok(()));
        assert_eq!(topo.tasks_len(), 3);
    }

    #[test]
    fn duplicate_task_rejected() {
        let caps = b"\
[task.x]
caps = []

[task.x]
caps = []
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        let r = parse_caps(caps, &mut topo);
        assert!(matches!(
            r,
            Err(ParseError::Admission(AdmissionError::DuplicateTask))
        ));
    }

    #[test]
    fn perm_string_combinations() {
        let caps = b"\
[task.x]
caps = [
    { kind = \"memobj\", target = \"a\", perm = \"r\" },
    { kind = \"memobj\", target = \"b\", perm = \"rw\" },
    { kind = \"memobj\", target = \"c\", perm = \"rwx\" },
    { kind = \"memobj\", target = \"d\", perm = \"rwxd\" },
]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        parse_caps(caps, &mut topo).unwrap();
        let task_caps = topo.caps_of(&topo.tasks()[0]);
        assert_eq!(task_caps[0].perms, CapPerms::READ);
        assert_eq!(task_caps[1].perms, CapPerms::RW);
        assert!(task_caps[2].perms.contains(CapPerms::EXEC));
        assert!(task_caps[3].perms.contains(CapPerms::DUP));
    }

    #[test]
    fn missing_kind_field_rejected() {
        let caps = b"\
[task.x]
caps = [
    { target = \"a\", perm = \"r\" },
]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        let r = parse_caps(caps, &mut topo);
        assert!(matches!(r, Err(ParseError::MissingField)));
    }

    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn realistic_caps_example_from_the_format_spec() {
        // Adapted from the original static topology format example (slightly trimmed).
        let caps = b"\
[task.rt_motor]
class    = \"hard_rt\"
priority = 5
caps = [
    { kind = \"endpoint\",    target = \"motor.0\",     perm = \"rw\" },
    { kind = \"endpoint\",    target = \"motor.1\",     perm = \"rw\" },
    { kind = \"endpoint\",    target = \"sensor.2\",    perm = \"r\" },
    { kind = \"endpoint\",    target = \"sensor.1\",    perm = \"r\" },
    { kind = \"endpoint\", target = \"endpoint.motor_cmd\",  perm = \"r\" },
    { kind = \"endpoint\", target = \"endpoint.motor_state\",perm = \"w\" },
]

[task.sensor_ahrs]
class    = \"hard_rt\"
priority = 4
caps = [
    { kind = \"endpoint\",    target = \"i2c.0.0x68\",  perm = \"rw\" },
    { kind = \"endpoint\",    target = \"i2c.0.0x76\",  perm = \"rw\" },
    { kind = \"endpoint\", target = \"endpoint.sensors_imu\",perm = \"w\" },
    { kind = \"endpoint\", target = \"endpoint.sensors_baro\",perm = \"w\" },
]

[task.behavior]
class    = \"best_effort\"
priority = 0
caps = [
    { kind = \"endpoint\", target = \"endpoint.sensors_imu\",  perm = \"r\" },
    { kind = \"endpoint\", target = \"endpoint.sensors_baro\", perm = \"r\" },
    { kind = \"endpoint\", target = \"endpoint.motor_cmd\",    perm = \"w\" },
    { kind = \"endpoint\",     target = \"endpoint.policy\", perm = \"rw\" },
]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        parse_caps(caps, &mut topo).unwrap();
        assert_eq!(topo.tasks_len(), 3);
        let admitted = topo.admission_check();
        if azos_limits::USE_DESKTOP {
            // The example drives motors; a desktop image holds none
            // (`desktop-grants-no-motor`, rule 1 of `neverallow::RULES`).
            assert!(matches!(admitted, Err(azos_topology::AdmissionError::Neverallow(r)) if r.rule == 1), "{admitted:?}");
        } else {
            admitted.unwrap();
        }
    }
}

#[cfg(test)]
mod verify_tests {
    use crate::topo_rows::dsig;
    use azos_topology::{verify_signature, VerifyError, SIDECAR_MAX};

    #[test]
    fn zero_signature_rejected() {
        let toml = b"[task.a]\ncaps = []\n";
        let key = [0u8; 32];
        let r = verify_signature(toml, &dsig([0u8; 64]), &key);
        assert_eq!(r, Err(VerifyError::InvalidSignature));
    }

    /// A sidecar is a `DSIG` of the device's algorithm, whole: the magic, the
    /// algorithm id, the signature length, the signature, and nothing else.
    #[test]
    fn a_sidecar_that_is_not_a_dsig_of_the_device_is_caught() {
        let toml = b"[task.a]\n";
        let key = [0u8; 32];
        let good = dsig([0u8; 64]);
        assert_eq!(good.len(), SIDECAR_MAX);
        // The bare signature of the format before the algorithm id.
        assert_eq!(verify_signature(toml, &[0u8; 64], &key), Err(VerifyError::BadSidecar));
        assert_eq!(verify_signature(toml, &[0u8; 30], &key), Err(VerifyError::BadSidecar));
        assert_eq!(verify_signature(toml, &[], &key), Err(VerifyError::BadSidecar));
        // Cut, and extended.
        assert_eq!(verify_signature(toml, &good[..good.len() - 1], &key), Err(VerifyError::BadSidecar));
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(verify_signature(toml, &longer, &key), Err(VerifyError::BadSidecar));
        // Another algorithm's id (ML-DSA-65, SLH-DSA, reserved, unknown), or a length it has not.
        for alg in [0u16, 2, 3, 4, 0xFFFF] {
            let mut f = good.clone();
            f[4..6].copy_from_slice(&alg.to_le_bytes());
            assert_eq!(verify_signature(toml, &f, &key), Err(VerifyError::BadSidecar), "algorithm {alg}");
        }
        for len in [0u16, 63, 65, 3309] {
            let mut f = good.clone();
            f[6..8].copy_from_slice(&len.to_le_bytes());
            assert_eq!(verify_signature(toml, &f, &key), Err(VerifyError::BadSidecar), "sig_len {len}");
        }
        // Another algorithm's whole shape: ML-DSA-65's id, signature length and bytes.
        let mut ml = good.clone();
        ml[4..6].copy_from_slice(&2u16.to_le_bytes());
        ml[6..8].copy_from_slice(&3309u16.to_le_bytes());
        ml.resize(8 + 3309, 0);
        assert_eq!(verify_signature(toml, &ml, &key), Err(VerifyError::BadSidecar), "ML-DSA-65 on an Ed25519 device");
        let mut f = good;
        f[0] = b'X';
        assert_eq!(verify_signature(toml, &f, &key), Err(VerifyError::BadSidecar), "magic");
    }

    #[test]
    fn wrong_key_size_caught() {
        let toml = b"[task.a]\n";
        let r = verify_signature(toml, &dsig([0u8; 64]), &[0u8; 16]);
        assert_eq!(r, Err(VerifyError::BadKeyLen));
    }
}

/// The component manager picks a restart strategy from the IDL failure
/// contract of what a row serves (`userspace/services/compmgr/src/contracts.rs`
/// `SERVED`, endpoint name -> interface). A served endpoint missing from that
/// table silently gets no contract, and the manager restarts its callers behind
/// it. This is the other half of the table: every endpoint a row of the built-in
/// topology serves is either in `SERVED` or named below as one with no IDL
/// interface, so a new served endpoint fails here until it is classified.
#[cfg(test)]
mod compmgr_contracts {
    use azos_abi::cap::{CapKind, CapPerms};

    /// Endpoints a row serves that carry no IDL interface: raw message
    /// endpoints (demo and bench servers), and the RPC proxy faces.
    const NO_INTERFACE: &[&str] = &[
        "endpoint.demo",
        "endpoint.bench",
        "endpoint.rpc-decisions",
    ];

    #[test]
    fn every_served_endpoint_is_classified() {
        let topo = azos_topology::default_minimal();
        let mut seen = 0;
        for row in topo.tasks() {
            for c in topo.caps_of(row) {
                // Task-hosted endpoints only: `pwm.4` and the like are
                // kernel-hosted interfaces, whose `READ` is an op class.
                if c.kind != CapKind::Endpoint
                    || !c.perms.contains(CapPerms::READ)
                    || azos_topology::types::endpoint_target(c).is_none()
                {
                    continue;
                }
                seen += 1;
                let ep = c.target.as_str();
                let in_table = crate::contracts::SERVED.iter().any(|(e, _)| *e == ep.as_bytes());
                let exempt = NO_INTERFACE.contains(&ep);
                assert!(
                    in_table != exempt,
                    "{} serves {ep}: it must be in compmgr's contracts::SERVED (it has an IDL \
                     interface) or in NO_INTERFACE above, and not in both", row.name.as_str()
                );
            }
        }
        assert!(seen > 0, "no row serves an endpoint: the test looks at nothing");
    }

    /// The table names only endpoints the topology declares (a renamed
    /// endpoint leaves a dead entry), when the build has the serving row.
    #[test]
    fn served_table_names_declared_endpoints() {
        let topo = azos_topology::default_minimal();
        let declared = |ep: &[u8]| {
            topo.tasks().iter().any(|r| {
                topo.caps_of(r).iter().any(|c| c.kind == CapKind::Endpoint && c.target.as_bytes() == ep)
            })
        };
        let declared_any = crate::contracts::SERVED.iter().filter(|(e, _)| declared(e)).count();
        assert!(declared_any > 0);
        for (ep, ops) in crate::contracts::SERVED {
            assert!(!ops.is_empty());
            // Rows exist only under some features (PKGD_ROW, VMMD_ROW, INPUTD_ROW, LOGIND_ROW,
            // COMPOSITOR_ROW, AUDIOD_ROW): a table
            // entry without its row is dead only when the row is built.
            let row_built = match *ep {
                b"endpoint.packages" => azos_topology::builder::PKGD_ROW,
                b"endpoint.vmctl" => azos_topology::builder::VMMD_ROW,
                b"endpoint.input" => azos_topology::builder::INPUTD_ROW,
                b"endpoint.login" => azos_topology::builder::LOGIND_ROW,
                b"endpoint.compositor" => azos_topology::builder::COMPOSITOR_ROW,
                b"endpoint.pm-ina" => azos_topology::builder::INADRV_ROW,
                b"endpoint.audio" => azos_topology::builder::AUDIOD_ROW,
                _ => true,
            };
            if row_built {
                assert!(declared(ep), "SERVED names {} but no row declares it", String::from_utf8_lossy(ep));
            }
        }
    }
}

/// The dependencies the component manager derives from the view of the
/// built-in topology. A need is matched against what a row serves **as the
/// same string**, so the view must spell a name a row imports (`term`) as the
/// endpoint it stands for (`endpoint.term`): spelled raw, the shell had no
/// dependency on the terminal server it asks the name server for, and was
/// started again ahead of it (`[namesd] REFUSED lookup ... (not-held)`).
#[cfg(test)]
mod compmgr_view {
    use crate::tree::{Event, Host, Intensity, Row, State, Tree};
    use azos_idl::OnFailure;
    use azos_topology::builder::{manager_starts, manager_view_endpoints};

    #[derive(Default)]
    struct World {
        next: u32,
        spawned: Vec<(String, u32)>,
        stopped: Vec<u32>,
    }

    impl Host for World {
        fn spawn(&mut self, _dir: &[u8], image: &[u8]) -> Result<u32, i32> {
            self.next += 1;
            self.spawned.push((String::from_utf8(image.to_vec()).unwrap(), self.next));
            Ok(self.next)
        }
        fn stop(&mut self, tid: u32) {
            self.stopped.push(tid);
        }
        fn now_ns(&mut self) -> u64 {
            1_000_000_000
        }
        fn record(&mut self, _e: &Event<'_>) {}
        fn contract(&mut self, endpoint: &[u8]) -> Option<OnFailure> {
            crate::contracts::contract_of(endpoint)
        }
    }

    /// The manager's plan for the rows the session starts, one line a row as
    /// `image restart serves needs` (the fields of the `inspect.components`
    /// view): the kernel lists the console program and then its follower, the
    /// shell, last (`for_each_launch_row`).
    fn view(topo: &azos_topology::Topology<'_>) -> String {
        use core::fmt::Write;
        let mut rows: Vec<_> = topo.tasks().iter().filter(|r| manager_starts(r)).collect();
        for last in [azos_topology::builder::TASK_TERMD_IMAGE, azos_topology::builder::TASK_SH_IMAGE] {
            if let Some(i) = rows.iter().position(|r| r.name.as_bytes() == last) {
                let r = rows.remove(i);
                rows.push(r);
            }
        }
        let mut out = String::new();
        for r in rows {
            write!(out, "{} {} ", r.name.as_str(), r.restart.as_str()).unwrap();
            manager_view_endpoints(topo, r, &mut out).unwrap();
            out.push('\n');
        }
        out
    }

    /// The plan's rows, as the manager reads them from the view.
    fn plan_rows(view: &str) -> Vec<Row<'_>> {
        view.lines()
            .map(|l| {
                let f: Vec<&str> = l.split(' ').filter(|x| !x.is_empty()).collect();
                Row {
                    image: f[0].as_bytes(),
                    restart: f[1].as_bytes(),
                    serves: f[2].as_bytes(),
                    needs: f[3].as_bytes(),
                    dir: f.get(4).copied().unwrap_or("").as_bytes(),
                }
            })
            .collect()
    }

    fn row_of<'a>(view: &'a str, image: &str) -> Vec<&'a str> {
        view.lines().find(|l| l.starts_with(&format!("{image} "))).expect("row in the view").split(' ').collect()
    }

    /// **Canary.** Render an import raw (`write!(w, "{}", name.as_str())` for
    /// the names, as the view did before): the shell's `needs` lose
    /// `endpoint.term`, its order no longer follows the terminal server and the
    /// terminal server's failure does not stop it.
    #[test]
    fn the_shell_depends_on_the_name_server_and_the_terminal_server() {
        let topo = azos_topology::default_minimal();
        if !topo.tasks().iter().any(|r| r.name.as_bytes() == azos_topology::builder::TASK_SH_IMAGE && r.start)
            || topo.find_task(&azos_topology::MaybeStr::from_bytes(azos_topology::builder::TASK_TERMD_IMAGE)).is_none_or(|r| !r.start)
        {
            return; // no native shell session in this build (Kconfig CONSOLE_PROGRAM)
        }
        let v = view(&topo);
        let sh = row_of(&v, "SH.ELF");
        assert!(sh[3].split(',').any(|n| n == "endpoint.term"), "SH.ELF needs: {}", sh[3]);
        assert!(sh[3].split(',').any(|n| n == "endpoint.names"), "SH.ELF needs: {}", sh[3]);
        assert!(row_of(&v, "TERMD.ELF")[2].split(',').any(|n| n == "endpoint.term"));
        assert!(row_of(&v, "NAMESD.ELF")[2].split(',').any(|n| n == "endpoint.names"));
        // Every name a started row imports is the endpoint of that name.
        for r in topo.tasks().iter().filter(|r| manager_starts(r)) {
            for name in topo.imports_of(r) {
                let needs = row_of(&v, r.name.as_str())[3];
                assert!(needs.split(',').any(|n| n == format!("endpoint.{}", name.as_str())), "{}: {needs}", r.name.as_str());
            }
        }

        // The tree built from it: the shell starts after both servers, and
        // the terminal server's failure stops the shell behind it.
        let mut w = World::default();
        let mut t = Tree::new(Intensity { burst: 3, interval_ns: 300_000_000_000, cooldown_ns: 1_000_000_000 });
        t.load(&plan_rows(&v), true, &mut w);
        t.start_all(&mut w);
        let at = |n: &str| w.spawned.iter().position(|(i, _)| i == n).unwrap_or_else(|| panic!("{n} was not started"));
        assert!(at("SH.ELF") > at("TERMD.ELF") && at("SH.ELF") > at("NAMESD.ELF"));
        let termd = w.spawned[at("TERMD.ELF")].1;
        let sh = w.spawned[at("SH.ELF")].1;
        t.on_exit(termd, 1, &mut w);
        assert_eq!(w.stopped, [sh], "the terminal server's failure stops the shell, nothing else");
        assert_eq!(t.state_of(b"SH.ELF"), Some(State::Stopping));
    }

    /// A `World` whose spawn of `fail` is refused: the other images start.
    struct Refusing<'a>(World, &'a str);

    impl Host for Refusing<'_> {
        fn spawn(&mut self, dir: &[u8], image: &[u8]) -> Result<u32, i32> {
            if image == self.1.as_bytes() {
                return Err(-13);
            }
            self.0.spawn(dir, image)
        }
        fn stop(&mut self, tid: u32) {
            self.0.stop(tid)
        }
        fn now_ns(&mut self) -> u64 {
            self.0.now_ns()
        }
        fn record(&mut self, e: &Event<'_>) {
            self.0.record(e)
        }
        fn contract(&mut self, endpoint: &[u8]) -> Option<OnFailure> {
            self.0.contract(endpoint)
        }
    }

    fn tree_over(view: &str, w: &mut impl Host) -> Tree {
        let mut t = Tree::new(Intensity { burst: 3, interval_ns: 300_000_000_000, cooldown_ns: 1_000_000_000 });
        t.load(&plan_rows(view), true, w);
        t.start_all(w);
        t
    }

    /// **The terminal server waits for the login service exactly when the build
    /// has one, and the manager starts the terminal server and the shell last
    /// either way.** The failure the `sh: family tools (rv)` gate row showed (the
    /// manager silent after `LOGD.ELF`, the console program never started) is
    /// ruled in or out here, for the view of the built-in topology: the terminal
    /// server's `needs` column is `-` without the console login (so nothing it
    /// could wait for is missing), and `endpoint.login` with it; the tree over that
    /// view starts `TERMD.ELF` then `SH.ELF` after every other row.
    ///
    /// **Canary.** Grant `TERMD.ELF` the call right on `endpoint.login` whatever
    /// `LOGIND_ROW` says: with the console login off, its `needs` is not `-` and a
    /// server nobody starts is waited for.
    #[test]
    fn the_terminal_server_needs_the_login_service_only_when_the_build_has_one() {
        let topo = azos_topology::default_minimal();
        if !topo.tasks().iter().any(|r| r.name.as_bytes() == azos_topology::builder::TASK_SH_IMAGE && r.start)
            || topo.find_task(&azos_topology::MaybeStr::from_bytes(azos_topology::builder::TASK_TERMD_IMAGE)).is_none_or(|r| !r.start)
        {
            return; // no native shell session in this build (Kconfig CONSOLE_PROGRAM)
        }
        let v = view(&topo);
        let needs = row_of(&v, "TERMD.ELF")[3].trim_end().to_string();
        let want = if azos_topology::builder::LOGIND_ROW { "endpoint.login" } else { "-" };
        assert_eq!(needs, want, "TERMD.ELF needs");
        let mut w = World::default();
        let _t = tree_over(&v, &mut w);
        let started: Vec<&str> = w.spawned.iter().map(|(n, _)| n.as_str()).collect();
        let last = started.len() - 2;
        assert_eq!(&started[last..], ["TERMD.ELF", "SH.ELF"], "the console program last: {started:?}");
        assert_eq!(started.len(), v.lines().count(), "every row of the view was started: {started:?}");
    }

    /// **A login service that cannot start holds back the console only when the
    /// terminal server depends on it.** The same tree over the view of a build with
    /// the console login (`LOGIND.ELF` serves `endpoint.login`, `TERMD.ELF` calls it)
    /// and over the view of one without: with the service refused, the first starts
    /// neither the terminal server nor the shell, the second starts both.
    ///
    /// **Canary.** Make the view list the call right in a build without the service
    /// (`TERMD.ELF ... endpoint.login`) and keep `LOGIND.ELF` out: the second tree
    /// then waits for a server that is not in it.
    #[test]
    fn a_refused_login_service_holds_back_the_console_only_with_the_dependency() {
        let with = "NAMESD.ELF on-failure endpoint.names -\n\
                    LOGIND.ELF on-failure endpoint.login -\n\
                    TERMD.ELF on-failure endpoint.term endpoint.login\n\
                    SH.ELF on-failure - endpoint.names,endpoint.term\n";
        let without = "NAMESD.ELF on-failure endpoint.names -\n\
                       LOGD.ELF on-failure - -\n\
                       TERMD.ELF on-failure endpoint.term -\n\
                       SH.ELF on-failure - endpoint.names,endpoint.term\n";
        let names = |w: &Refusing<'_>| w.0.spawned.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
        let mut a = Refusing(World::default(), "LOGIND.ELF");
        let _ta = tree_over(with, &mut a);
        assert_eq!(names(&a), ["NAMESD.ELF"], "the console waits for the service it calls");
        let mut b = Refusing(World::default(), "LOGIND.ELF");
        let _tb = tree_over(without, &mut b);
        assert_eq!(names(&b), ["NAMESD.ELF", "LOGD.ELF", "TERMD.ELF", "SH.ELF"], "no service, nothing to wait for");
    }
}

/// The component manager starts every `start = true` row with `SYS_SPAWN_EX`,
/// which checks a `Cap<Launch>` on the image whoever the caller is
/// (`crates/core/syscall/src/ushell.rs`): its row must hold `EXEC` on each
/// image it starts, and on no other. A row with a grant missing is a row the
/// manager records as refused on every boot.
#[cfg(test)]
mod manager_authority {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::builder::{manager_starts, MANAGER_CAPS_MAX, TASK_COMPMGR_IMAGE};

    /// The built-in topology has the manager's row exactly when the build has
    /// its image (Kconfig `USERSPACE_COMPMGR`): a row for an image the volume
    /// lacks would be started, and refused, on every boot.
    ///
    /// **Canary.** Push the row unconditionally in `default_minimal_topology`:
    /// with the image off, the row is there and this fails.
    #[test]
    fn the_managers_row_follows_its_image() {
        let topo = azos_topology::default_minimal();
        let row = topo.find_task(&azos_topology::MaybeStr::from_bytes(TASK_COMPMGR_IMAGE));
        assert_eq!(row.is_some(), azos_topology::builder::COMPMGR_ROW);
        assert_eq!(azos_topology::builder::COMPMGR_ROW, azos_limits::USERSPACE_COMPMGR);
    }

    fn manager_launches(topo: &azos_topology::Topology<'_>) -> Vec<String> {
        let row = topo.find_task(&azos_topology::MaybeStr::from_bytes(TASK_COMPMGR_IMAGE)).expect("COMPMGR.ELF row");
        topo.caps_of(row)
            .iter()
            .filter(|c| c.kind == CapKind::Node && c.perms == CapPerms::EXEC)
            .map(|c| c.target.as_str().to_string())
            .collect()
    }

    /// The manager's launch grants are exactly the rows it starts, in row
    /// order, and it starts: every `start = true` row but its own. The buzzer's
    /// ring-3 host, the row of a driver that moves between hosts, is one of
    /// them like any other.
    ///
    /// **Canary.** Start the grants one row late (skip the first startable
    /// row in `default_minimal_topology`): the lists differ. Put back the
    /// `!place.elastic()` clause in `manager_starts`: the buzzer's row is
    /// started (`start = true`) and not in `wanted`, so the last assertion
    /// of the buzzer fails.
    #[test]
    fn the_manager_may_launch_exactly_the_rows_it_starts() {
        if !azos_topology::builder::COMPMGR_ROW {
            return; // no row, no grants (`the_managers_row_follows_its_image`)
        }
        let topo = azos_topology::default_minimal();
        let wanted: Vec<String> = topo.tasks().iter().filter(|r| manager_starts(r)).map(|r| r.name.as_str().to_string()).collect();
        assert_eq!(manager_launches(&topo), wanted);
        assert!(wanted.len() < MANAGER_CAPS_MAX, "{} startable rows past the manager's table", wanted.len());
        // The elastic row is the manager's like any other: started, it is in
        // the list, and its launch grant is minted (the list above).
        let buzz = topo.find_task(&azos_topology::MaybeStr::from_bytes(b"BUZZDRV.ELF")).unwrap();
        assert!(buzz.place.elastic());
        assert_eq!(wanted.iter().any(|n| n == "BUZZDRV.ELF"), buzz.start);
        // Nor is the manager its own component.
        assert!(!wanted.iter().any(|n| n.as_bytes() == TASK_COMPMGR_IMAGE));
        // The row starts, so the kernel starts it, and restarts it.
        let row = topo.find_task(&azos_topology::MaybeStr::from_bytes(TASK_COMPMGR_IMAGE)).unwrap();
        assert!(row.start);
        assert_eq!(row.restart, azos_topology::RestartPolicy::OnFailure);
    }

    /// The row's cap slots and the manager's table agree.
    #[test]
    fn the_caps_slots_follow_the_managers_table() {
        assert_eq!(MANAGER_CAPS_MAX, 1 + crate::tree::MAX_COMPONENTS);
    }

    /// Every distinct image any row may launch is interned in the kernel's
    /// launch-name table (`azos_ipc::launch_cap::MAX_LAUNCH_NAMES`); a name
    /// past it is a grant the kernel refuses to mint.
    #[test]
    fn the_launch_names_fit_the_kernels_table() {
        let src = include_str!("../../../../crates/core/ipc/src/launch_cap.rs");
        let max: usize = src
            .lines()
            .find_map(|l| l.strip_prefix("pub const MAX_LAUNCH_NAMES: usize = "))
            .and_then(|r| r.trim_end_matches(';').trim().parse().ok())
            .expect("MAX_LAUNCH_NAMES in launch_cap.rs");
        let topo = azos_topology::default_minimal();
        let mut names: Vec<&str> = Vec::new();
        for r in topo.tasks() {
            for c in topo.caps_of(r) {
                if c.kind == CapKind::Node && c.perms == CapPerms::EXEC && !c.target.as_str().starts_with('/')
                    && !names.contains(&c.target.as_str())
                {
                    names.push(c.target.as_str());
                }
            }
        }
        assert!(names.len() <= max, "{} launch names ({names:?}) for a table of {max}", names.len());
    }
}

#[cfg(test)]
mod start_flag_tests {
    use azos_topology::{default_minimal, parse_caps, ParseError, Topology};

    /// **`start` reaches the row it is declared on, and only that row**
    /// (wave 9, owner decision: what the kernel starts at boot is declared in
    /// the signed topology). A row that says nothing is not started; only the
    /// words `true` and `false` are accepted.
    ///
    /// **Canaries.** Drop the reset when a new `[task.*]` section starts: `b`
    /// inherits `a`'s `true`. Drop `set_last_task_start` from the final
    /// commit: `c` reads `false` while it declares `true`. Accept `parse_bool`
    /// with a tail: `trueish` parses as `true`.
    #[test]
    fn start_is_per_row_and_off_by_default() {
        let mut topo = Topology::empty();
        parse_caps(b"[task.A.ELF]\nstart = true\ncaps = []\n[task.B.ELF]\ncaps = []\n", &mut topo).unwrap();
        assert!(topo.tasks()[0].start);
        assert!(!topo.tasks()[1].start, "b inherited a's start flag");

        let mut topo = Topology::empty();
        parse_caps(b"[task.C.ELF]\ncaps = []\nstart = true   # boot it\n", &mut topo).unwrap();
        assert!(topo.tasks()[0].start, "the last row's value was dropped");

        let mut topo = Topology::empty();
        parse_caps(b"[task.D.ELF]\nstart = false\n", &mut topo).unwrap();
        assert!(!topo.tasks()[0].start);

        for bad in [&b"[task.E.ELF]\nstart = yes\n"[..], b"[task.E.ELF]\nstart = trueish\n",
                    b"[task.E.ELF]\nstart = 1\n", b"[task.E.ELF]\nstart = \"true\"\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::BadValue),
                "{:?}", core::str::from_utf8(bad));
        }
    }

    /// QoS timer tolerance: `timer_slack = true` in a row lets its task's
    /// timers be coalesced by its QoS tier. Per row, off by default, kept on
    /// the last row, only the words `true`/`false`, a format-5 key (earlier
    /// formats refuse it), and the emitter writes it back: a signed file
    /// regenerated from the topology says the same thing.
    ///
    /// **Canaries.** Drop the reset when a new `[task.*]` section starts: `B`
    /// inherits `A`'s `true`. Drop `set_last_task_timer_slack` from the final
    /// commit: `C` reads `false`. Drop the `format < 5` refusal: the
    /// format-4 file parses. Drop the `timer_slack` line from `emit_caps`: the
    /// round trip differs in "task timer_slack".
    #[test]
    fn timer_slack_is_per_row_and_off_by_default() {
        use azos_topology::emit::{emit_caps, first_difference};
        use azos_topology::Binding;
        let mut topo = Topology::empty();
        parse_caps(b"format = 5\n[task.A.ELF]\ntimer_slack = true\ncaps = []\n[task.B.ELF]\ncaps = []\n", &mut topo).unwrap();
        assert!(topo.tasks()[0].timer_slack);
        assert!(!topo.tasks()[1].timer_slack, "B inherited A's timer_slack");
        assert!(topo.row_timer_slack(b"A.ELF"));
        assert!(!topo.row_timer_slack(b"B.ELF"));
        assert!(!topo.row_timer_slack(b"NONE.ELF"), "no row, no slack");

        let mut topo = Topology::empty();
        parse_caps(b"format = 5\n[task.C.ELF]\ncaps = []\ntimer_slack = true   # housekeeping\n", &mut topo).unwrap();
        assert!(topo.tasks()[0].timer_slack, "the last row's value was dropped");

        for bad in [&b"format = 5\n[task.E.ELF]\ntimer_slack = yes\n"[..],
                    b"format = 5\n[task.E.ELF]\ntimer_slack = trueish\n",
                    b"format = 5\n[task.E.ELF]\ntimer_slack = 1\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::BadValue),
                "{:?}", core::str::from_utf8(bad));
        }
        for bad in [&b"[task.A.ELF]\ntimer_slack = true\ncaps = []\n"[..],
                    b"format = 4\n[task.A.ELF]\ntimer_slack = false\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::FieldNeedsFormat),
                "{:?}", core::str::from_utf8(bad));
        }

        let mut topo = Topology::empty();
        parse_caps(b"format = 5\n[task.A.ELF]\ntimer_slack = true\ncaps = []\n[task.B.ELF]\ncaps = []\n", &mut topo).unwrap();
        let mut caps = String::new();
        emit_caps(&topo, &Binding::default(), &mut caps).unwrap();
        assert_eq!(caps.matches("timer_slack = true").count(), 1, "{caps}");
        let mut back = Topology::empty();
        parse_caps(caps.as_bytes(), &mut back).unwrap();
        assert_ne!(first_difference(&topo, &back), Some("task timer_slack"));
        assert!(back.row_timer_slack(b"A.ELF") && !back.row_timer_slack(b"B.ELF"));
    }

    /// Format 6: the placement keys are per row, default to ring 3 fixed
    /// there, are refused before format 6 and survive the emitter.
    /// **Canary.** Stop the parser committing `current_task_place` at the end
    /// of the file: the last-row assertion goes red.
    #[test]
    fn placement_keys_are_per_row_format_six_and_round_trip() {
        use azos_topology::emit::{emit_caps, first_difference};
        use azos_topology::placement::{Host, PlaceSpec};
        use azos_topology::Binding;
        let mut topo = Topology::empty();
        parse_caps(b"format = 6\n[task.A.ELF]\nplace = \"kernel\"\nstateless = true\ncall_budget_us = 250\ncaps = []\n[task.B.ELF]\ncaps = []\n[task.C.ELF]\nstateless = true # last row\n", &mut topo).unwrap();
        assert_eq!(topo.tasks()[0].place, PlaceSpec { host: Host::Kernel, stateless: true, call_budget_us: 250 });
        assert_eq!(topo.tasks()[1].place, PlaceSpec::DEFAULT, "B inherited A's placement");
        assert_eq!(topo.row_place(b"C.ELF"), Some(PlaceSpec { host: Host::Ring3, stateless: true, call_budget_us: 0 }), "the last row's value was dropped");
        assert_eq!(topo.row_place(b"NONE.ELF"), None);
        assert!(PlaceSpec::DEFAULT.is_default() && !PlaceSpec::DEFAULT.elastic());
        assert!(topo.tasks()[0].place.elastic() && !topo.tasks()[0].place.is_default());

        for bad in [&b"format = 6\n[task.A.ELF]\nplace = \"cloud\"\n"[..], b"format = 6\n[task.A.ELF]\nplace = kernel\n"] {
            let mut topo = Topology::empty();
            assert!(parse_caps(bad, &mut topo).is_err(), "{:?}", core::str::from_utf8(bad));
        }
        for bad in [&b"format = 6\n[task.A.ELF]\nstateless = 1\n"[..],
                    b"format = 6\n[task.A.ELF]\ncall_budget_us = 4294967296\n",
                    b"format = 6\n[task.A.ELF]\ncall_budget_us = 12 34\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::BadValue), "{:?}", core::str::from_utf8(bad));
        }
        for bad in [&b"[task.A.ELF]\nstateless = true\n"[..], b"format = 5\n[task.A.ELF]\nplace = \"kernel\"\n",
                    b"format = 5\n[task.A.ELF]\ncall_budget_us = 1\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::FieldNeedsFormat), "{:?}", core::str::from_utf8(bad));
        }

        let mut topo = Topology::empty();
        parse_caps(b"format = 6\n[task.A.ELF]\nplace = \"kernel\"\nstateless = true\ncall_budget_us = 250\ncaps = []\n[task.B.ELF]\ncaps = []\n", &mut topo).unwrap();
        let mut caps = String::new();
        emit_caps(&topo, &Binding::default(), &mut caps).unwrap();
        assert_eq!(caps.matches("place = ").count() + caps.matches("stateless = ").count() + caps.matches("call_budget_us = ").count(), 3, "{caps}");
        let mut back = Topology::empty();
        parse_caps(caps.as_bytes(), &mut back).unwrap();
        assert_eq!(first_difference(&topo, &back), None);
        // The comparison itself sees a placement.
        let mut other = Topology::empty();
        parse_caps(b"format = 6\n[task.A.ELF]\nplace = \"ring3\"\nstateless = true\ncall_budget_us = 250\ncaps = []\n[task.B.ELF]\ncaps = []\n", &mut other).unwrap();
        assert_eq!(first_difference(&topo, &other), Some("task placement"));
    }

    /// Which rows of the built-in topology the kernel starts. A board build
    /// (this crate's default features, as `vf2`/`k1`) starts only the user
    /// shell, and only with Kconfig `USER_SHELL`; the
    /// `qemu` shape (`ring3-driver-start`) adds exactly the two ring-3 driver
    /// images, and nothing else — least of all a row that names a role, not
    /// an image.
    #[test]
    fn only_the_ring3_driver_rows_start_and_only_under_qemu() {
        let topo = default_minimal();
        let started: Vec<&str> = topo.tasks().iter().filter(|t| t.start).map(|t| t.name.as_str()).collect();
        // The native shell session is two images (the Terminal object): the
        // shell, and the terminal server that is the console program.
        let shell: &[&str] = if azos_limits::USER_SHELL { &["SH.ELF", "TERMD.ELF", "NAMESD.ELF"] } else { &[] };
        // The decision server starts when the kernel keeps decisions to serve
        // (Kconfig `DECISION_REFUSALS_DURABLE` or `DECISION_RECORDS_DEV`).
        let decisions: &[&str] =
            if azos_limits::DECISION_REFUSALS_DURABLE || azos_limits::DECISION_RECORDS_DEV { &["DECISD.ELF"] } else { &[] };
        // The package installer starts wherever it has a row.
        let packages: &[&str] = if azos_topology::builder::PKGD_ROW { &["PKGD.ELF"] } else { &[] };
        // The RPC server starts when a peer is configured (Kconfig `RPC_PEER_NODE`).
        let rpc: &[&str] = if azos_limits::RPC_PEER_NODE != 0 { &["RPCSRV.ELF"] } else { &[] };
        // The component manager has a row, and starts, when the volume carries its image.
        let compmgr: &[&str] = if azos_topology::builder::COMPMGR_ROW { &["COMPMGR.ELF"] } else { &[] };
        // The Zenoh gateway has a row, and starts, only with Kconfig `ZENOH_GW`.
        let zenoh: &[&str] = if azos_topology::builder::ZENOH_GW_ROW { &["ZENOHD.ELF"] } else { &[] };
        // The PTP daemon has a row, and starts, only with Kconfig `PTPD`.
        let ptpd: &[&str] = if azos_topology::builder::PTPD_ROW { &["PTPD.ELF"] } else { &[] };
        // The audio server has a row, and starts, only with Kconfig `AUDIOD`.
        let audiod: &[&str] = if azos_topology::builder::AUDIOD_ROW { &["AUDIOD.ELF"] } else { &[] };
        // The relay of the QUIC link has a row, and starts, only with Kconfig `RPC_QUIC`.
        let rpcquic: &[&str] = if azos_topology::builder::RPCQUIC_ROW { &["RPCQUIC.ELF"] } else { &[] };
        // The MCP bridge has a row, and starts, only with Kconfig `MCP_BRIDGE`.
        let mcp: &[&str] = if azos_topology::builder::MCP_BRIDGE_ROW { &["MCPD.ELF"] } else { &[] };
        // The SSH server has a row, and starts, with Kconfig `SSHD` (default y; n on MICRO and a certifiable build).
        let sshd: &[&str] = if azos_topology::builder::SSHD_ROW { &["SSHD.ELF"] } else { &[] };
        // The login service has a row, and starts, with Kconfig `CONSOLE_LOGIN` (default n).
        let logind: &[&str] = if azos_topology::builder::LOGIND_ROW { &["LOGIND.ELF"] } else { &[] };
        // The kernel log's sink starts with the log (Kconfig `KLOG`).
        let klog: &[&str] = if azos_limits::KLOG { &["LOGD.ELF"] } else { &[] };
        #[cfg(not(feature = "ring3-driver-start"))]
        {
            let mut want = shell.to_vec();
            want.extend_from_slice(decisions);
            want.extend_from_slice(packages);
            want.extend_from_slice(rpc);
            if cfg!(feature = "lx-server") { want.push("LXSRV.ELF"); }
            if azos_topology::builder::VMMD_ROW { want.push("VMMD.ELF"); }
            want.extend_from_slice(zenoh);
            want.extend_from_slice(ptpd);
            want.extend_from_slice(audiod);
            want.extend_from_slice(rpcquic);
            want.extend_from_slice(mcp);
            want.extend_from_slice(sshd);
            want.extend_from_slice(logind);
            want.extend_from_slice(klog);
            if azos_topology::builder::INPUTD_ROW { want.push("INPUTD.ELF"); }
            if azos_topology::builder::COMPOSITOR_ROW { want.push("COMPSRV.ELF"); }
            // The component manager is pushed last of the rows that start:
            // its launch grants name every one of them.
            want.extend_from_slice(compmgr);
            assert_eq!(started, want, "a board topology starts {started:?}");
        }
        #[cfg(feature = "ring3-driver-start")]
        {
            let mut want = vec![];
            // The buzzer's ring-3 host is started at boot whichever host the
            // driver starts in: it is the standby of a driver placed in the
            // kernel, and the component manager's like any other row.
            want.push("BUZZDRV.ELF");
            if azos_topology::builder::INADRV_ROW { want.push("INADRV.ELF"); }
            want.extend_from_slice(shell);
            want.extend_from_slice(decisions);
            want.extend_from_slice(packages);
            want.extend_from_slice(rpc);
            // The Linux server skeleton starts too, and only
            // under `lx-server`.
            if cfg!(feature = "lx-server") { want.push("LXSRV.ELF"); }
            if azos_topology::builder::VMMD_ROW { want.push("VMMD.ELF"); }
            want.extend_from_slice(zenoh);
            want.extend_from_slice(ptpd);
            want.extend_from_slice(audiod);
            want.extend_from_slice(rpcquic);
            want.extend_from_slice(mcp);
            want.extend_from_slice(sshd);
            want.extend_from_slice(logind);
            want.extend_from_slice(klog);
            if azos_topology::builder::INPUTD_ROW { want.push("INPUTD.ELF"); }
            if azos_topology::builder::COMPOSITOR_ROW { want.push("COMPSRV.ELF"); }
            // The component manager is pushed last of the rows that start:
            // its launch grants name every one of them.
            want.extend_from_slice(compmgr);
            assert_eq!(started, want);
            for n in want.iter().filter(|n| n.ends_with(".ELF") && **n != "SH.ELF").map(|n| n.as_bytes()) {
                assert!(topo.find_task(&azos_topology::MaybeStr::from_bytes(n)).unwrap().start);
            }
        }
    }
}

#[cfg(test)]
mod restart_tests {
    use azos_topology::{default_minimal, parse_caps, ParseError, RestartPolicy, Topology};

    /// **Wave 11 (DRVPLACE): `restart` is a format-2 key.** A topology written
    /// before it (no `format` line: format 1) parses as it always did and
    /// every row gets `on-failure`; a format-2 file sets it per row, reset
    /// at each new row; a format-1 file that carries the key is refused
    /// (its writer did not mean it), as is a format this parser does not
    /// know, a second `format` line, a value outside the three words, and
    /// anything after the value.
    ///
    /// **Canaries.** Drop the reset at a new `[task.*]` section: B inherits
    /// A's `always`. Drop `set_last_task_restart` from the final commit: C
    /// reads `on-failure`. Accept the key in format 1: the `FieldNeedsFormat`
    /// assertion goes red. Let `format = 3` through: `UnsupportedFormat`
    /// goes red.
    #[test]
    fn restart_is_a_format_2_key_with_on_failure_by_default() {
        // Format 1 (no `format` line): the pre-wave-11 file.
        let mut topo = Topology::empty();
        parse_caps(b"[task.A.ELF]\nstart = true\ncaps = []\n", &mut topo).unwrap();
        assert_eq!(topo.tasks()[0].restart, RestartPolicy::OnFailure);
        let mut topo = Topology::empty();
        parse_caps(b"format = 1\n[task.A.ELF]\ncaps = []\n", &mut topo).unwrap();
        assert_eq!(topo.tasks()[0].restart, RestartPolicy::OnFailure);

        // Format 2: per row, reset at each row, the last row committed.
        let mut topo = Topology::empty();
        parse_caps(b"# a comment first\nformat = 2   # wave 11\n\
[task.A.ELF]\nrestart = \"always\"\ncaps = []\n\
[task.B.ELF]\ncaps = []\n\
[task.N.ELF]\nrestart = \"no\"\n\
[task.O.ELF]\nrestart = \"on-failure\"\n\
[task.C.ELF]\ncaps = []\nrestart = \"always\"  # last row\n", &mut topo).unwrap();
        let r: Vec<RestartPolicy> = topo.tasks().iter().map(|t| t.restart).collect();
        assert_eq!(r, [RestartPolicy::Always, RestartPolicy::OnFailure, RestartPolicy::No,
                       RestartPolicy::OnFailure, RestartPolicy::Always]);
        assert_eq!(topo.restart_of(b"N.ELF"), RestartPolicy::No);
        assert_eq!(topo.restart_of(b"NOROW.ELF"), RestartPolicy::OnFailure, "no row: the default");

        // Format 1 with the key: refused, not read.
        for bad in [&b"[task.A.ELF]\nrestart = \"always\"\n"[..],
                    b"format = 1\n[task.A.ELF]\nrestart = \"no\"\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::FieldNeedsFormat),
                "{:?}", core::str::from_utf8(bad));
        }
        // Formats this parser does not know, and a second declaration.
        // (4 became known in wave 15: the TOPOSIGN binding keys; 5 with the
        // `imports` task key; 6 with the `[device.NAME]`, `[signer.NAME]` and `[peer.NAME]` sections, `export` and the placement keys; 7 with TOPO-ROWS-A/B; 8 with TOPO-ROWS-C.)
        for bad in [&b"format = 9\n[task.A.ELF]\n"[..], b"format = 0\n[task.A.ELF]\n",
                    b"format = 2\nformat = 2\n[task.A.ELF]\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::UnsupportedFormat),
                "{:?}", core::str::from_utf8(bad));
        }
        // Not a number, or something after it.
        for bad in [&b"format = two\n"[..], b"format = 2x\n", b"format = \"2\"\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::BadValue),
                "{:?}", core::str::from_utf8(bad));
        }
        // Values: the three words, quoted, nothing after.
        let mut topo = Topology::empty();
        assert_eq!(parse_caps(b"format = 2\n[task.A.ELF]\nrestart = \"sometimes\"\n", &mut topo),
                   Err(ParseError::UnknownEnumValue));
        for bad in [&b"format = 2\n[task.A.ELF]\nrestart = always\n"[..],
                    b"format = 2\n[task.A.ELF]\nrestart = \"no\" extra\n"] {
            let mut topo = Topology::empty();
            assert!(parse_caps(bad, &mut topo).is_err(), "{:?}", core::str::from_utf8(bad));
        }
        // A `format` line inside a section is a task key, and not one.
        let mut topo = Topology::empty();
        assert_eq!(parse_caps(b"[task.A.ELF]\nformat = 2\n", &mut topo), Err(ParseError::UnknownField));
    }

    /// The built-in topology: every row restarts on failure, the user shell
    /// included (its "exit gives the console back" depends on it), unless the
    /// gate's `restart-smoke` topology sets the buzzer's ring-3 row.
    #[test]
    fn built_in_rows_restart_on_failure() {
        let topo = default_minimal();
        for t in topo.tasks() {
            let want = match t.name.as_bytes() {
                #[cfg(feature = "restart-smoke")]
                b"BUZZDRV.ELF" => RestartPolicy::No,
                _ => RestartPolicy::OnFailure,
            };
            assert_eq!(t.restart, want, "{}", t.name.as_str());
        }
        assert_eq!(topo.restart_of(b"SH.ELF"), RestartPolicy::OnFailure);
    }

    /// Wave 11 (DRVPLACE): the INA219's ring-3 row exists exactly when the
    /// driver is placed in ring 3.
    #[test]
    fn the_inadrv_row_follows_the_placement() {
        let topo = default_minimal();
        let has = topo.tasks().iter().any(|t| t.name.as_bytes() == b"INADRV.ELF");
        assert_eq!(has, azos_topology::builder::INADRV_ROW);
        #[cfg(not(feature = "ina219-kernel"))]
        assert!(has, "ring-3 placement without its row");
        #[cfg(feature = "ina219-kernel")]
        assert!(!has, "kernel placement still declares INADRV.ELF");
    }

    /// The buzzer's ring-3 row exists in every build, and says where the
    /// driver starts and that it may move: `place` follows the kernel
    /// feature `buzzer-kernel` (Kconfig `DRV_BUZZER_PLACEMENT`), `stateless`
    /// is set, and the call budget is Kconfig's.
    ///
    /// **Canary.** Make `BUZZER_START_HOST` ring 3 regardless: the
    /// `buzzer-kernel` run (gate `topology(drvplace)`) goes red.
    #[test]
    fn the_buzzdrv_row_declares_where_the_driver_starts_and_that_it_may_move() {
        use azos_topology::placement::Host;
        let topo = default_minimal();
        let task = topo.find_task(&azos_topology::MaybeStr::from_bytes(b"BUZZDRV.ELF")).expect("the row is always there");
        assert_eq!(task.place.host, azos_topology::builder::BUZZER_START_HOST);
        #[cfg(not(feature = "buzzer-kernel"))]
        assert_eq!(task.place.host, Host::Ring3);
        #[cfg(feature = "buzzer-kernel")]
        assert_eq!(task.place.host, Host::Kernel);
        assert!(task.place.stateless && task.place.elastic(), "the buzzer keeps nothing a restart cannot rebuild");
        assert_eq!(task.place.call_budget_us as u64, azos_limits::DRV_BUZZER_CALL_BUDGET_US);
        assert_eq!(topo.row_place(b"BUZZDRV.ELF"), Some(task.place));
    }
}

#[cfg(test)]
mod abi_tests {
    use azos_topology::{default_minimal, parse_caps, AdmissionError, ParseError, TaskAbi, Topology};

    /// **`abi` is a format-3 key (Linux personality).** A row is native unless
    /// it says `abi = "linux"`, reset at each new row; the key is refused in
    /// a format-1 or format-2 file, and outside the two words.
    ///
    /// **Canaries.** Drop the reset at a new `[task.*]` section: B inherits
    /// A's `linux`. Drop `set_last_task_abi` from the final commit: C stays
    /// native. Accept the key below format 3: the format-2 row parses.
    #[test]
    fn abi_is_a_format_3_key_native_by_default() {
        let caps = b"format = 3\n[task.A.ELF]\nabi = \"linux\"\n[task.B.ELF]\n[task.C.ELF]\nabi = \"linux\"\n";
        let mut topo = Topology::empty();
        parse_caps(caps, &mut topo).unwrap();
        let abis: Vec<_> = topo.tasks().iter().map(|t| t.abi).collect();
        assert_eq!(abis, [TaskAbi::Linux, TaskAbi::Native, TaskAbi::Linux]);
        assert_eq!(topo.abi_of(b"B.ELF"), TaskAbi::Native);
        assert_eq!(topo.abi_of(b"NOROW.ELF"), TaskAbi::Native, "no row: native");

        for bad in [&b"[task.A.ELF]\nabi = \"linux\"\n"[..],
                    b"format = 2\n[task.A.ELF]\nabi = \"linux\"\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::FieldNeedsFormat),
                "{:?}", core::str::from_utf8(bad));
        }
        let mut topo = Topology::empty();
        assert_eq!(parse_caps(b"format = 3\n[task.A.ELF]\nabi = \"freebsd\"\n", &mut topo),
                   Err(ParseError::UnknownEnumValue));
        let mut topo = Topology::empty();
        assert!(parse_caps(b"format = 3\n[task.A.ELF]\nabi = linux\n", &mut topo).is_err());
    }

    /// **A Linux row holds no hardware capability.** Files,
    /// sockets, pipes and launch grants are admitted; a GPIO line refuses
    /// the whole topology, wherever the row sits. The same capability on a
    /// native row is admitted.
    ///
    /// **Canary.** Let `TaskAbi::linux_may_hold` answer `true` for every
    /// kind: the GPIO row parses.
    #[test]
    fn a_linux_row_with_a_hardware_capability_is_refused() {
        let ok = b"format = 3\n[task.L.ELF]\nabi = \"linux\"\ncaps = [ { kind = \"node\", target = \"/fat\", perm = \"rw\" }, { kind = \"node\", target = \"L.ELF\", perm = \"x\" } ]\n";
        let mut topo = Topology::empty();
        parse_caps(ok, &mut topo).unwrap();
        assert_eq!(topo.abi_of(b"L.ELF"), TaskAbi::Linux);

        let gpio_linux = b"format = 3\n[task.L.ELF]\nabi = \"linux\"\ncaps = [ { kind = \"endpoint\", target = \"gpio.3\", perm = \"rw\" } ]\n[task.N.ELF]\n";
        let mut topo = Topology::empty();
        assert_eq!(parse_caps(gpio_linux, &mut topo),
                   Err(ParseError::Admission(AdmissionError::LinuxRowHoldsHardware)));
        // Last row too (the final commit, not only the section switch).
        let gpio_last = b"format = 3\n[task.N.ELF]\n[task.L.ELF]\nabi = \"linux\"\ncaps = [ { kind = \"endpoint\", target = \"gpio.3\", perm = \"rw\" } ]\n";
        let mut topo = Topology::empty();
        assert_eq!(parse_caps(gpio_last, &mut topo),
                   Err(ParseError::Admission(AdmissionError::LinuxRowHoldsHardware)));
        let gpio_native = b"format = 3\n[task.N.ELF]\ncaps = [ { kind = \"endpoint\", target = \"gpio.3\", perm = \"rw\" } ]\n";
        let mut topo = Topology::empty();
        parse_caps(gpio_native, &mut topo).unwrap();
        for k in [
                  azos_abi::cap::CapKind::Device,
                  azos_abi::cap::CapKind::Endpoint] {
            assert!(!TaskAbi::linux_may_hold(k), "{k:?}");
        }
    }

    /// The built-in topology: native everywhere, except (gate only) the
    /// personality's test row, which holds nothing.
    #[test]
    fn built_in_rows_are_native_but_the_linux_test_row() {
        let topo = default_minimal();
        for t in topo.tasks() {
            let want = if (cfg!(feature = "linux-abi-test") && t.name.as_bytes() == b"LXHELLO.ELF")
                || (azos_topology::builder::BUSYBOX_ROW && t.name.as_bytes() == b"BUSYBOX.ELF")
            {
                TaskAbi::Linux
            } else {
                TaskAbi::Native
            };
            assert_eq!(t.abi, want, "{}", t.name.as_str());
        }
    }

    /// Wave 13: the BusyBox row is not gate-only. It is there exactly when the
    /// `.config` says `BUSYBOX` (or the gate asks), with the personality; it
    /// holds `/tmp` and no hardware; and the shell holds the grant to start
    /// it exactly then. A deployment that ships BusyBox can run it from the
    /// shell; one that does not has neither the row nor the grant.
    ///
    /// **Canary:** drop `azos_limits::BUSYBOX` from `BUSYBOX_ROW` and run
    /// with a `.config` that sets `BUSYBOX`: red.
    #[test]
    fn the_busybox_row_and_the_shell_grant_follow_the_config() {
        use azos_abi::cap::{CapKind, CapPerms};
        let expect = (cfg!(feature = "linux-busybox-test") || azos_limits::BUSYBOX) && azos_limits::LINUX_ABI;
        assert_eq!(azos_topology::builder::BUSYBOX_ROW, expect);
        let topo = default_minimal();
        let row = topo.tasks().iter().find(|t| t.name.as_bytes() == b"BUSYBOX.ELF");
        assert_eq!(row.is_some(), expect, "the BUSYBOX.ELF row");
        if let Some(r) = row {
            assert_eq!(r.abi, TaskAbi::Linux);
            assert!(topo.caps_of(r).iter().any(|c| c.kind == CapKind::Node && c.target.as_bytes() == b"/tmp"));
            assert!(topo.caps_of(r).iter().all(|c| TaskAbi::linux_may_hold(c.kind)));
        }
        let sh = topo.tasks().iter().find(|t| t.name.as_bytes() == b"SH.ELF").expect("SH.ELF row");
        let grant = topo.caps_of(sh).iter().any(|c| {
            c.kind == CapKind::Node && c.perms.contains(CapPerms::EXEC) && c.target.as_bytes() == b"BUSYBOX.ELF"
        });
        assert_eq!(grant, expect && !azos_limits::CONSOLE_LOCKDOWN, "the shell's launch grant for BUSYBOX.ELF");
    }
}

#[cfg(test)]
mod sqpoll_tests {
    use azos_topology::{default_minimal, parse_caps, MaybeStr, ParseError, Topology};

    /// **`sqpoll_idle_ms` reaches the row it is declared on, and only that
    /// row**: a task that does not declare it gets 0 (no SQ poller), and a
    /// value past `u32` is refused, not truncated.
    ///
    /// **Canaries.** Drop the reset to 0 when a new `[task.*]` section starts:
    /// `b` inherits `a`'s 20. Drop `set_last_task_sqpoll_idle_ms` from the
    /// final commit: `c` reads 0 while it declares 7.
    #[test]
    fn sqpoll_idle_ms_is_per_row_and_off_by_default() {
        let mut topo = Topology::empty();
        let caps = b"[task.a]\nsqpoll_idle_ms = 20\ncaps = []\n[task.b]\ncaps = []\n";
        parse_caps(caps, &mut topo).unwrap();
        assert_eq!(topo.tasks()[0].sqpoll_idle_ms, 20);
        assert_eq!(topo.tasks()[1].sqpoll_idle_ms, 0, "b inherited a's poller");

        let mut topo = Topology::empty();
        parse_caps(b"[task.c]\ncaps = []\nsqpoll_idle_ms = 7\n", &mut topo).unwrap();
        assert_eq!(topo.tasks()[0].sqpoll_idle_ms, 7, "the last row's value was dropped");

        let mut topo = Topology::empty();
        assert_eq!(
            parse_caps(b"[task.d]\nsqpoll_idle_ms = 4294967296\n", &mut topo),
            Err(ParseError::BadValue)
        );
    }

    /// The built-in topology permits no SQ poller unless `sqpoll-bench` is on.
    #[test]
    fn the_default_topology_permits_no_sq_poller() {
        let topo = default_minimal();
        let autorun = topo.find_task(&MaybeStr::from_bytes(b"autorun")).expect("autorun");
        #[cfg(not(feature = "sqpoll-bench"))]
        assert_eq!(autorun.sqpoll_idle_ms, 0);
        #[cfg(feature = "sqpoll-bench")]
        assert_eq!(autorun.sqpoll_idle_ms, 20);
        assert!(topo.tasks().iter().filter(|t| t.name != MaybeStr::from_bytes(b"autorun")).all(|t| t.sqpoll_idle_ms == 0));
    }
}

#[cfg(test)]
mod builder_tests {
    use azos_topology::{default_minimal, MaybeStr};

    /// The topology the kernel installs has one writer per motor, and the
    /// predicate names the pair when a builder-made topology does not.
    /// `parse_caps` applies it to a loaded file; the built-in topology goes
    /// through `admission_check`, not the parser.
    #[test]
    fn the_default_topology_has_one_writer_per_motor() {
        #[allow(unused_imports)] // profile-gated tests (M40) use these
    use azos_abi::cap::{CapKind, CapPerms};
        use azos_topology::parser::{motor_write_conflict, MotorWriteConflict};
        use azos_topology::CapSpec;

        let t = default_minimal();
        assert_eq!(motor_write_conflict(&t), None);

        // The FIRST writer is pushed here, not taken from `default_minimal()`.
        // It used to be `autorun`'s `motor.1` grant, which made this test —
        // about a rule of the parser — depend on the default topology being a
        // robot's. Since `profile-actuation` (2026-09-21) it is not, and the
        // rule still has to hold in both builds, so the test now declares
        // both halves of the conflict itself.
        let mut t = default_minimal();
        t.push_task(
            MaybeStr::from_bytes(b"first_driver"),
            MaybeStr::from_bytes(b"best_effort"),
            0,
            &[CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false, ops: 0,
            }],
        )
        .unwrap();
        let autorun = t
            .tasks()
            .iter()
            .position(|task| task.name == MaybeStr::from_bytes(b"first_driver"))
            .expect("the first writer this test just pushed");
        t.push_task(
            MaybeStr::from_bytes(b"second_driver"),
            MaybeStr::from_bytes(b"best_effort"),
            0,
            &[CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::WRITE,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false, ops: 0,
            }],
        )
        .unwrap();
        // Derived, not the literal 3. The index a pushed task lands on moves
        // whenever the default topology gains a row — this test failed once
        // for exactly that reason, reporting a "motor writer conflict" that
        // had nothing to do with motors. `autorun` above was already derived;
        // this half was not.
        let second = t
            .tasks()
            .iter()
            .position(|task| task.name == MaybeStr::from_bytes(b"second_driver"))
            .expect("the task this test just pushed");
        assert_eq!(
            motor_write_conflict(&t),
            Some(MotorWriteConflict { motor_id: 2, first_task: autorun, second_task: second })
        );
    }

    /// The rule on the path the kernel takes: `state::init_with` runs
    /// `admission_check`, not the parser.
    #[test]
    fn admission_refuses_a_second_writer_on_a_motor() {
        #[allow(unused_imports)] // profile-gated tests (M40) use these
    use azos_abi::cap::{CapKind, CapPerms};
        use azos_topology::{AdmissionError, CapSpec};

        let mut t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        // A desktop image holds no motor at all (`desktop-grants-no-motor`),
        // so the second writer is unreachable there: the first is refused.
        if azos_limits::USE_DESKTOP {
            t.push_task(
                MaybeStr::from_bytes(b"first_driver"),
                MaybeStr::from_bytes(b"best_effort"),
                0,
                &[CapSpec { kind: CapKind::Endpoint, perms: CapPerms::RW, target: MaybeStr::from_bytes(b"motor.2"), transfer: false, ops: 0 }],
            )
            .unwrap();
            assert!(matches!(t.admission_check(), Err(AdmissionError::Neverallow(r)) if r.rule == 1));
            return;
        }
        // Both writers are pushed here. Same reason as
        // `the_default_topology_has_one_writer_per_motor`: the rule belongs
        // to admission, not to whether the default topology happens to
        // declare a drivetrain — which, without `profile-actuation`, it does
        // not.
        // `motor.2`, which no row of `default_minimal()` claims in EITHER
        // build — the actuation profile declares wheels 0 and 1, so reusing
        // one of those would have this test collide with the profile instead
        // of with its own second writer, and report a conflict it did not
        // create.
        t.push_task(
            MaybeStr::from_bytes(b"first_driver"),
            MaybeStr::from_bytes(b"best_effort"),
            0,
            &[CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false, ops: 0,
            }],
        )
        .unwrap();
        assert_eq!(t.admission_check(), Ok(()),
            "one writer on motor 2 is exactly what the rule allows");
        t.push_task(
            MaybeStr::from_bytes(b"second_driver"),
            MaybeStr::from_bytes(b"best_effort"),
            0,
            &[CapSpec {
                kind: CapKind::Endpoint,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false, ops: 0,
            }],
        )
        .unwrap();
        assert_eq!(t.admission_check(), Err(AdmissionError::MotorWriteConflict));
    }

    #[test]
    fn default_topology_has_all_five_classes_and_the_session_class() {
        let t = default_minimal();
        assert_eq!(t.classes_len(), 6);
        // Names match.
        let names: [&[u8]; 6] = [
            b"safety_critical",
            b"hard_rt",
            b"soft_rt",
            b"best_effort",
            b"idle",
            b"session",
        ];
        for (cls, want) in t.classes().iter().zip(names.iter()) {
            assert_eq!(cls.name, MaybeStr::from_bytes(want));
        }
    }

    /// No task in a BOARD topology may be granted a resource the drivetrain
    /// owns.
    ///
    /// The list is restated here rather than imported because
    /// `crates/core/topology` parses static configuration and must not depend on
    /// `domains/robot/robot` to do it. The source of truth is `robot::robot_init`:
    /// motor 0 is PWM channel 0 with direction pins 0 and 1, motor 1 is
    /// channel 1 with pins 2 and 3. If that wiring changes, this list is one
    /// of the places that has to change with it — which is the cost of the
    /// layering, and it is written down rather than assumed.
    ///
    /// This is the check that would have caught the grant while it was
    /// unconditional: the two entries read as deliberate in their own file,
    /// and nothing asked whether a robot should carry them.
    #[test]
    fn board_topology_grants_nothing_the_drivetrain_owns() {
        use azos_abi::cap::CapKind;
        const MOTOR_PWM: [&[u8]; 2] = [b"pwm.0", b"pwm.1"];
        const MOTOR_GPIO: [&[u8]; 4] = [b"gpio.0", b"gpio.1", b"gpio.2", b"gpio.3"];

        let t = default_minimal();
        let mut offenders = 0;
        for task in t.tasks() {
            for c in t.caps_of(task) {
                let hit = match c.kind {
                    // A device is an endpoint of its interface (`pwm.N`,
                    // `gpio.N`): the spelling names the resource.
                    CapKind::Endpoint => MOTOR_PWM
                        .iter()
                        .chain(MOTOR_GPIO.iter())
                        .any(|r| c.target == MaybeStr::from_bytes(r)),
                    // The `motor.N` endpoints are the drivetrain's OWN family
                    // and are granted on purpose — the point of this test is
                    // the two families that reach the same hardware from
                    // underneath.
                    _ => false,
                };
                if hit {
                    offenders += 1;
                }
            }
        }
        assert_eq!(
            offenders,
            if cfg!(feature = "cap-refusal-canary") { 2 } else { 0 },
            "a board build must grant no PWM channel and no GPIO pin the \
             motors own; only the refusal canary may, and only two"
        );
    }

    #[test]
    fn default_topology_has_supervisor_and_brain_link() {
        let t = default_minimal();
        // supervisor, brain_link, autorun (P1 cap-seed migration entry —
        // see `default_topology_has_autorun_motor_grants` below).
        // 5 since 2026-09-21: supervisor, brain_link, autorun, the
        // `VSSRV.ELF` benchmark server (a `fork()`ed peer can never be
        // addressed by capability) and the
        // `EPSRV.ELF` row — the first named after an IMAGE, which is how a
        // spawned process gets any capability at all.
        // +3 since 2026-09-24: the unconditional board service registry rows
        // (`GPIODRV.ELF`/`REFLEX.ELF`/`BRAINCLI.ELF`) — owner decision, an
        // ELF ships on a board volume iff the topology declares a service it
        // provides. See `crates/core/topology/src/builder.rs`'s
        // `TASK_GPIODRV_IMAGE` block comment.
        // +3 in wave 9: the ring-3 ML service (MLSRV.ELF) and the ring-3
        // driver rows (BUZZDRV.ELF/INADRV.ELF).
        // +1 with the Terminal object: the terminal server (TERMD.ELF).
        // +1 with the Names object: the name server (NAMESD.ELF).
        // +2 with the Decisions object: the decision server and its tool
        // (DECISD.ELF, WHY.ELF).
        // +2 with the Packages object: the installer and its tool
        // (PKGD.ELF, PKG.ELF).
        // +1 with transparent RPC: the RPC server (RPCSRV.ELF).
        // +1 with the structured kernel log: its sink (LOGD.ELF).
        assert_eq!(t.tasks_len(), if cfg!(feature = "ipc-endpoint-canary") { 27 } else { 25 }
            - 2 * !azos_topology::builder::PKGD_ROW as usize
            - !azos_topology::builder::INADRV_ROW as usize
            + cfg!(feature = "lx-server") as usize
            + azos_topology::builder::LXHELLO_ROW as usize
            + azos_topology::builder::BUSYBOX_ROW as usize
            + azos_topology::builder::COMPMGR_ROW as usize
            + azos_topology::builder::COMPOSITOR_ROW as usize
            + azos_topology::builder::ZENOH_GW_ROW as usize
            + azos_topology::builder::PTPD_ROW as usize
            + azos_topology::builder::AUDIOD_ROW as usize
            + azos_topology::builder::RPCQUIC_ROW as usize
            + azos_topology::builder::MCP_BRIDGE_ROW as usize
            + azos_topology::builder::SSHD_ROW as usize
            + azos_topology::builder::LOGIND_ROW as usize
            + azos_topology::builder::VMMD_ROW as usize
            + azos_topology::builder::INPUTD_ROW as usize); // +1 with Kconfig INPUTD: INPUTD.ELF; +1 with Kconfig HV: VMMD.ELF; +1 with Kconfig MCP_BRIDGE: MCPD.ELF; +1 with Kconfig SSHD: SSHD.ELF; +1 with Kconfig CONSOLE_LOGIN: LOGIND.ELF; +1 with Kconfig PTPD: PTPD.ELF; +1 with Kconfig AUDIOD: AUDIOD.ELF; +1 with Kconfig RPC_QUIC: RPCQUIC.ELF; +1 with Kconfig ZENOH_GW: ZENOHD.ELF; +1 with Kconfig USERSPACE_COMPMGR: COMPMGR.ELF; +3 in wave 11: SH.ELF, TOOLBOX.ELF, POWER; +4 in wave 12: FLIGHT/BEHAVIOR/CONFIG/OTA.ELF; -1 per driver placed in the kernel; +1 under lx-server: LXSRV.ELF; +1 for the wave-12 Linux test row (gate only); +1 in wave 15: TRACECTL.ELF
        let supervisor = t
            .find_task(&MaybeStr::from_bytes(b"supervisor"))
            .expect("supervisor present");
        let class = t.find_class(&supervisor.class_name).unwrap();
        assert_eq!(class.name, MaybeStr::from_bytes(b"safety_critical"));
        let brain = t
            .find_task(&MaybeStr::from_bytes(b"brain_link"))
            .expect("brain_link present");
        assert!(t.find_class(&brain.class_name).is_some());
    }

    /// The board service registry (owner decision 2026-09-24): the three
    /// real board programs get their own topology row, unconditionally (no
    /// feature gate), each carrying zero capabilities — the grant still
    /// flows through the generic `autorun` row until the kernel-side P1
    /// name→spawn wiring lands. This is the row `tools/gen_board_manifest.py`
    /// (via the `board_elfs` binary in this crate) reads to build the
    /// board's FAT32 ELF list: every `.ELF`-named row, present in EVERY
    /// feature combination (unlike `EPSRV.ELF`/`VSSRV.ELF`, which only exist
    /// under `ipc-endpoint-canary` and are correctly absent here).
    /// The ML service's row is the whole of its authority (it is spawned by
    /// the kernel, not run as `autorun`, so nothing else grants it anything):
    /// `READ` (serving) on `endpoint.infer`, where the inference broker answers
    /// (the behavior task calls it through a capability the kernel mints, and no
    /// driver kind is registered any more), `WRITE` on `memctl` (to mark its blob arena droppable
    /// between calls: not `READ`, it serves nothing there), and the read-only
    /// root directory it opens its model files beneath; a frame budget of its
    /// own.
    #[test]
    fn the_ml_service_row_grants_exactly_its_endpoints() {
        let t = default_minimal();
        let task = t.find_task(&MaybeStr::from_bytes(b"MLSRV.ELF")).expect("MLSRV.ELF row");
        use azos_abi::cap::{CapKind, CapPerms};
        let caps = t.caps_of(task);
        assert_eq!(caps.len(), 3, "the inference endpoint, memctl and the root directory, nothing else");
        assert_eq!((caps[0].kind, caps[0].perms, caps[0].target), (CapKind::Endpoint, CapPerms::READ, MaybeStr::from_bytes(b"endpoint.infer")),
            "READ serves: the broker is the server of its endpoint and calls nothing through it");
        assert_eq!((caps[1].kind, caps[1].perms, caps[1].target), (CapKind::Endpoint, CapPerms::WRITE, MaybeStr::from_bytes(b"memctl")),
            "WRITE changes what reclaim may take of its own object, and is all it does there");
        assert_eq!((caps[2].kind, caps[2].perms, caps[2].target), (CapKind::Node, CapPerms::READ, MaybeStr::from_bytes(b"/")),
            "the root directory is read-only: it names, a write tree writes");
        assert_eq!(task.mem_pages, 80, "a small row's 64 pages and the 16 its stack holds beyond the default");
    }

    #[test]
    fn board_service_registry_declares_the_three_real_board_images() {
        let t = default_minimal();
        for name in [&b"GPIODRV.ELF"[..], &b"REFLEX.ELF"[..], &b"BRAINCLI.ELF"[..]] {
            let task = t
                .find_task(&MaybeStr::from_bytes(name))
                .unwrap_or_else(|| panic!("board service row missing: {:?}", core::str::from_utf8(name)));
            // `BRAINCLI.ELF` reads `CONFIG.INI` beneath the read-only root
            // directory and holds nothing else; `GPIODRV.ELF` serves its
            // `DevicePower` endpoint (`pm_endpoint_tests`).
            let want = usize::from(name == b"BRAINCLI.ELF" || name == b"GPIODRV.ELF");
            let caps = t.caps_of(task);
            assert_eq!(
                caps.len(),
                want,
                "board service rows carry no caps but the read-only root — authority still flows through `autorun`"
            );
            for c in caps {
                use azos_abi::cap::{CapKind, CapPerms};
                if name == b"GPIODRV.ELF" {
                    assert_eq!((c.kind, c.perms, c.target), (CapKind::Endpoint, CapPerms::READ, MaybeStr::from_bytes(b"endpoint.pm-gpio")));
                } else {
                    assert_eq!((c.kind, c.perms, c.target), (CapKind::Node, CapPerms::READ, MaybeStr::from_bytes(b"/")));
                }
            }
        }
        // EPSRV.ELF/VSSRV.ELF are canary-only test scaffolding, never a
        // board's — confirms the two registries do not collide by name.
        #[cfg(not(feature = "ipc-endpoint-canary"))]
        {
            assert!(t.find_task(&MaybeStr::from_bytes(b"EPSRV.ELF")).is_none());
            assert!(t.find_task(&MaybeStr::from_bytes(b"VSSRV.ELF")).is_none());
        }
    }

    #[test]
    fn default_topology_has_autorun_motor_and_driver_registry_grants() {
        #[allow(unused_imports)] // profile-gated tests (M40) use these
    use azos_abi::cap::{CapKind, CapPerms};
        let t = default_minimal();
        let autorun = t
            .find_task(&MaybeStr::from_bytes(b"autorun"))
            .expect("autorun present — the P1 bridge seeds from this entry");
        let caps = t.caps_of(autorun);
        // 17 on a board; 20 under `cap-refusal-canary`, which adds the two
        // motor-bound grants the refusal scenario needs to hold and the MMIO
        // region `userspace/tests/captest` maps. The 17th is `endpoint.demo` WRITE
        // — the CALLER half of the demo service; the server
        // half is `READ` on the `EPSRV.ELF` row.
        // Under `ipc-endpoint-canary` only: a board topology declares no
        // endpoint it does not serve, so these rows compile out entirely.
        assert_eq!(
            caps.iter().any(|c| c.kind == CapKind::Endpoint && c.perms == CapPerms::WRITE),
            cfg!(feature = "ipc-endpoint-canary"),
            "the demo endpoint's CALLER half must exist under the canary and only there",
        );
        // **The ordering is load-bearing, so it is asserted rather than
        // assumed.** The boot creates every named endpoint in row order
        // before anything is spawned (`declare_endpoints`), `cap_lookup`
        // matches on the POOL INDEX, and ring 3 has no by-name lookup — so
        // `abitest` reaching `endpoint.demo` at index 0 and `vsbench`
        // `endpoint.bench` at 1 depend on them being the first two endpoint
        // grants of the rows. Swap them, or declare one ahead of them, and
        // this fails, instead of `abitest` silently calling the benchmark's
        // server.
        let mut all: Vec<&[u8]> = Vec::new();
        for task in t.tasks() {
            for c in t.caps_of(task) {
                // The endpoints the KERNEL hosts (`entropy`, ...) take a pool
                // index when first granted, after every named one is declared.
                let hosted = azos_devif::parse_target(c.target.as_str()).is_some();
                if c.kind == CapKind::Endpoint && !hosted && !all.contains(&c.target.as_bytes()) {
                    all.push(c.target.as_bytes());
                }
            }
        }
        assert!(
            all.len() >= 2 || !cfg!(feature = "ipc-endpoint-canary"),
            "the demo and bench endpoints are declared under the canary",
        );
        if cfg!(feature = "ipc-endpoint-canary") {
            assert_eq!(&all[..2], &[&b"endpoint.demo"[..], &b"endpoint.bench"[..]][..],
                "`endpoint.demo` and `endpoint.bench` must be the first endpoint grants of the rows");
        }
        let eps: Vec<&[u8]> = caps
            .iter()
            .filter(|c| c.kind == CapKind::Endpoint && azos_devif::parse_target(c.target.as_str()).is_none())
            .map(|c| c.target.as_bytes())
            .collect();
        let want: Vec<&[u8]> = if cfg!(feature = "ipc-endpoint-canary") {
            vec![&b"endpoint.demo"[..], &b"endpoint.bench"[..]]
        } else {
            Vec::new()
        };
        assert_eq!(
            eps, want,
            "endpoint order changed: `endpoint.demo` must be seeded first, and a \
             board topology must declare none at all",
        );
        // The drivetrain, and ONLY under `profile-actuation`. This is the
        // half of the 2026-09-21 pivot that a count alone would not catch: a
        // generic deployment must hold no `Motor` capability whatsoever, not
        // merely a different number of capabilities.
        assert_eq!(
            caps.iter().any(|c| c.kind == CapKind::Endpoint && c.target.as_str().starts_with("motor.")),
            crate::AUTORUN_DRIVETRAIN,
            "a drivetrain belongs to a deployment profile, not to the default topology",
        );
        // Shutdown/reboot authority is NOT in the default topology (owner
        // decision 2026-09-26: the power endpoint is minted from the SIGNED
        // topology). Granting it here would hand it to whatever image
        // CONFIG.INI autoruns; before the kind had a minter, ring 3 could not
        // shut the machine down at all, and the default keeps it that way. A
        // signed topology that wants a ring-3 power manager names `power` for
        // that image.
        assert!(
            !caps.iter().any(|c| c.kind == CapKind::Endpoint && c.target == MaybeStr::from_bytes(b"power")),
            "the default topology must not grant the power endpoint to autorun",
        );
        // The brain-link key: the kernel-hosted `linkkey` endpoint, READ only,
        // one grant, never transferable. The kernel additionally withholds it
        // from any image whose seccomp row does not list the interface
        // (kernel/src/tasks/loader.rs autorun seeding), so this row alone does
        // not decide who gets the key.
        let lk: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::Endpoint && azos_devif::parse_target(c.target.as_str()).is_some_and(|(i, _)| i.name == "linkkey"))
            .collect();
        assert_eq!(lk.len(), 1, "exactly one linkkey endpoint grant in the default topology");
        assert_eq!(lk[0].perms, CapPerms::READ, "the link key is read, never written");
        assert!(!lk[0].transfer, "the link key capability must not be transferable");
        // The entropy pool (wave 9, P9): the kernel-hosted `entropy`
        // endpoint, READ only, one grant, never transferable.
        let en: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::Endpoint && azos_devif::parse_target(c.target.as_str()).is_some_and(|(i, _)| i.name == "entropy"))
            .collect();
        assert_eq!(en.len(), 1, "exactly one entropy endpoint grant in the default topology");
        assert_eq!(en[0].perms, CapPerms::READ, "the entropy pool is read, never written");
        assert!(!en[0].transfer, "the entropy capability must not be transferable");
        let motors = if crate::AUTORUN_DRIVETRAIN { 2 } else { 0 };
        // `disk.part.1` RW and (wave 10) `disk.part.0` READ under
        // `disk-part-row` only (partition-scoped block gate row).
        let disk = if cfg!(feature = "disk-part-row") { 2 } else { 0 };
        assert_eq!(
            caps.len(),
            motors + disk
                + match (cfg!(feature = "cap-refusal-canary"), cfg!(feature = "ipc-endpoint-canary")) {
                    // `ipc-endpoint-canary`: the demo and bench endpoints,
                    // and (wave 12) `Cap<Launch>` on TOOLBOX.ELF for
                    // vsbench's `spawn+wait` lane.
                    (true, true) => 25, (true, false) => 22,
                    (false, true) => 20, (false, false) => 17,
                }
                // Kconfig INSPECT: the task view, the public region and (with an
                // admin region) the admin one, last.
                + if azos_limits::INSPECT { 2 + (azos_limits::INSPECT_ADMIN_PAGES != 0) as usize } else { 0 },
            "drv.1 RW + sensor.0-9 READ + pwm.4 RW + gpio.20 RW + i2c.0.0x68 READ + linkkey READ \
             + entropy READ, \
             plus pwm.0/gpio.0/mmio.dt:sifive,test1 and the /fat and /tmp trees under the canary, plus \
             motor.0/1 RW only under the actuation profile"
        );
        // The MMIO grant: READ on a device nothing drives, named by what it is
        // (the MMIO region index), and only in the canary build. A READ-only grant carries
        // no WRITE.
        let mmio: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::Device && c.target.as_str().starts_with("mmio."))
            .collect();
        assert_eq!(mmio.len(), if cfg!(feature = "cap-refusal-canary") { 1 } else { 0 });
        if let Some(m) = mmio.first() {
            assert_eq!(m.perms, CapPerms::READ);
            assert_eq!(m.target.as_str(), "mmio.dt:sifive,test1");
        }
        // The partition grants: exactly `block.part.1` RW and `block.part.0`
        // READ under `disk-part-row`, and no block endpoint of any kind in
        // any other build.
        let disks: Vec<_> = caps.iter()
            .filter(|c| c.kind == CapKind::Endpoint && c.target.as_str().starts_with("block."))
            .collect();
        assert_eq!(disks.len(), disk, "a block grant outside the disk-part-row build");
        if let [d1, d0] = disks[..] {
            assert_eq!((d1.perms, d1.target.as_str()), (CapPerms::RW, "block.part.1"));
            assert_eq!((d0.perms, d0.target.as_str()), (CapPerms::READ, "block.part.0"));
        }
        // The root directory (Storage L12), read-only and never transferable:
        // every row reads beneath it, and it writes nothing.
        let roots: Vec<_> = caps.iter().filter(|c| c.kind == CapKind::Node && c.target.as_str() == "/").collect();
        assert_eq!(roots.len(), 1, "exactly one root directory grant");
        assert!(roots[0].perms == CapPerms::READ && !roots[0].transfer);
        // Wave 10: the directory trees ring 3 may change, WRITE, never
        // transferable, and only under the canary (a board grants no tree).
        let trees: Vec<_> = caps.iter().filter(|c| c.kind == CapKind::Node && c.target.as_str() != "/").collect();
        let want_trees: Vec<&str> = if cfg!(feature = "cap-refusal-canary") {
            vec!["/fat", "/tmp"]
        } else {
            Vec::new()
        };
        assert_eq!(trees.iter().map(|c| c.target.as_str()).collect::<Vec<_>>(), want_trees);
        assert!(trees.iter().all(|c| c.perms == CapPerms::RW && !c.transfer));
        // The two grants that exist to be REFUSED AT USE. Asserted here so a
        // later tidy-up cannot quietly drop them: without the grant, the
        // kernel's `pwm_channel_is_motor_bound` / `gpio_pin_is_motor_bound`
        // guards become unreachable again and `userspace: captest` would pass
        // with them deleted.
        //
        // Both directions are asserted, because both are properties someone
        // could break: under the canary they must be PRESENT (or the refusal
        // stops being observable), and without it they must be ABSENT (or a
        // board build ships a standing capability over motor 0's H-bridge).
        let has_pwm_motor = caps.iter().any(|c| c.kind == CapKind::Endpoint
            && c.target == MaybeStr::from_bytes(b"pwm.0"));
        let has_gpio_motor = caps.iter().any(|c| c.kind == CapKind::Endpoint
            && c.target == MaybeStr::from_bytes(b"gpio.0"));
        assert_eq!(
            has_pwm_motor,
            cfg!(feature = "cap-refusal-canary"),
            "the motor-bound PWM grant is what makes the actuation guard \
             testable from ring 3, and it must exist ONLY there"
        );
        assert_eq!(
            has_gpio_motor,
            cfg!(feature = "cap-refusal-canary"),
            "the motor-bound GPIO grant, same rule"
        );
        // Two wheels under the actuation profile, none without it. Asserted
        // as a count rather than a presence so a topology that declares ONE
        // wheel fails here: `require_pair_write` would refuse it at runtime,
        // which reads as a broken drivetrain rather than a malformed decl.
        assert_eq!(
            caps.iter()
                .filter(|c| c.kind == CapKind::Endpoint && c.target.as_str().starts_with("motor.") && c.perms == CapPerms::RW)
                .count(),
            if crate::AUTORUN_DRIVETRAIN { 2 } else { 0 }
        );
        // The IMU is READ-only, in every build. `i2c.0.0x68` is the MPU-6050
        // that feeds L0's Falling/Spinning/tilt checks; WRITE on it is the
        // authority to sleep the device and blind the reflex layer without
        // tripping anything. Asserted on the PERMS, not on the presence, so a
        // widening back to RW fails here rather than on a robot.
        let imu: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::Endpoint && c.target.as_str().starts_with("i2c."))
            .collect();
        assert_eq!(imu.len(), 1, "one I2C grant, the IMU");
        assert_eq!(
            imu[0].perms,
            CapPerms::READ,
            "the IMU grant must never carry WRITE: the `I2c` interface's `read` and \
             `detect` both need only READ, so WRITE buys a reader \
             nothing and buys an attacker `PWR_MGMT_1`"
        );
        // The driver-registry grant names ONE kind. `drv.1` is
        // `azos_abi::drv_kind::DRV_KIND_GPIO` (0x0001) in decimal, per
        // the target convention in `crates/core/ipc/src/cap_seed.rs`; the number
        // is asserted below against the constant itself, which this crate can
        // reach and `crates/core/topology` deliberately cannot.
        let drv: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::Device && c.target.as_str().starts_with("drv."))
            .collect();
        assert_eq!(drv.len(), 1, "exactly one driver-registry grant");
        assert_eq!(drv[0].perms, CapPerms::RW);
        assert_eq!(drv[0].target.as_str(), "drv.1");
    }

    /// The literal in `builder.rs` and the constant in `driver_server` are
    /// held apart by a deliberate missing dependency (topology must not pull
    /// in the driver registry to parse static configuration), so nothing in
    /// either crate can catch them drifting. This test is the join.
    ///
    /// It fails loudly if `DRV_KIND_GPIO` is ever renumbered, which would
    /// otherwise silently move the autorun grant onto whatever kind inherits
    /// 0x0001 — i.e. hand the ring-3 GPIO driver a different device.
    #[test]
    fn autorun_driver_registry_target_names_drv_kind_gpio() {
        use azos_abi::cap::CapKind;
        let t = default_minimal();
        let autorun = t.find_task(&MaybeStr::from_bytes(b"autorun")).unwrap();
        let drv = t
            .caps_of(autorun)
            .iter()
            .find(|c| c.kind == CapKind::Device && c.target.as_str().starts_with("drv."))
            .copied()
            .expect("driver-registry grant present");
        let declared: u32 = drv
            .target
            .as_str()
            .strip_prefix("drv.")
            .expect("target uses the drv.<kind> convention")
            .parse()
            .expect("kind is decimal");
        assert_eq!(
            declared,
            azos_abi::drv_kind::DRV_KIND_GPIO,
            "builder.rs's `drv.N` literal has drifted from DRV_KIND_GPIO"
        );
    }

    /// Wave 9 (DRV1): each ring-3 driver row holds exactly the authority its
    /// device needs. The INA219 registers as its one driver kind and holds its
    /// one I2C slave, read from `crates/core/abi` (the join `autorun`'s
    /// `drv.1` has); the buzzer serves its one endpoint (`READ` on
    /// `endpoint.buzzer`, which is how it claims it) and holds its one PWM
    /// channel.
    #[test]
    fn ring3_driver_rows_grant_one_service_and_one_device() {
        use azos_abi::cap::{CapKind, CapPerms};
        use azos_abi::drv_kind::DRV_KIND_POWER_MON;
        let t = default_minimal();
        // The buzzer: the endpoint it serves, then its channel.
        let task = t.find_task(&MaybeStr::from_bytes(b"BUZZDRV.ELF")).expect("driver row present");
        let caps = t.caps_of(task);
        assert_eq!(caps.len(), 2);
        assert_eq!((caps[0].kind, caps[0].perms, caps[0].target.as_str()), (CapKind::Endpoint, CapPerms::READ, azos_devif::buzzer::ENDPOINT));
        assert_eq!((caps[1].kind, caps[1].perms, caps[1].target.as_str()), (CapKind::Endpoint, CapPerms::RW, "pwm.5"));
        assert_eq!(task.mem_pages, 64, "frame budget");
        // The INA219.
        if !azos_topology::builder::INADRV_ROW {
            assert!(t.find_task(&MaybeStr::from_bytes(b"INADRV.ELF")).is_none());
            return;
        }
        let task = t.find_task(&MaybeStr::from_bytes(b"INADRV.ELF")).expect("driver row present");
        let caps = t.caps_of(task);
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0].kind, CapKind::Device);
        assert_eq!(caps[0].perms, CapPerms::RW);
        assert_eq!(caps[0].target.as_str(), format!("drv.{DRV_KIND_POWER_MON}"));
        assert_eq!(caps[1].kind, CapKind::Endpoint);
        assert_eq!(caps[1].perms, CapPerms::RW);
        assert_eq!(caps[1].target.as_str(), "i2c.1.0x40");
        // The endpoint it serves `DevicePower` on, for the power service.
        assert_eq!((caps[2].kind, caps[2].perms, caps[2].target.as_str()), (CapKind::Endpoint, CapPerms::READ, "endpoint.pm-ina"));
        assert_eq!(task.mem_pages, 64, "frame budget");
    }

    #[test]
    fn default_topology_admission_passes() {
        let t = default_minimal();
        t.admission_check()
            .expect("default minimal topology must pass admission");
    }
}

#[cfg(test)]
mod state_tests {
    use azos_topology::{default_minimal, get, init, is_ready, InitError};

    /// Note: the state slot is a `static`. We can only exercise the
    /// init→ready transition once per test binary. Rust runs each
    /// `#[test]` in its own thread inside one process, so this test
    /// can't be split — we drive the full sequence in one shot.
    #[test]
    fn init_then_get_then_double_init_fails() {
        // Pre: slot is empty, get() returns None.
        assert!(!is_ready());
        assert!(get().is_none());

        // Init succeeds.
        init(default_minimal()).expect("first init must succeed");
        assert!(is_ready());

        // get() now returns the loaded topology.
        let t = get().expect("post-init get must yield topology");
        assert_eq!(t.classes_len(), 6);
        // supervisor, brain_link, autorun (P1 cap-seed migration entry).
        // 5 since 2026-09-21: supervisor, brain_link, autorun, the
        // `VSSRV.ELF` benchmark server (a `fork()`ed peer can never be
        // addressed by capability) and the
        // `EPSRV.ELF` row — the first named after an IMAGE, which is how a
        // spawned process gets any capability at all.
        // +3 since 2026-09-24: the unconditional board service registry rows
        // (`GPIODRV.ELF`/`REFLEX.ELF`/`BRAINCLI.ELF`) — owner decision, an
        // ELF ships on a board volume iff the topology declares a service it
        // provides. See `crates/core/topology/src/builder.rs`'s
        // `TASK_GPIODRV_IMAGE` block comment.
        // +3 in wave 9: the ring-3 ML service (MLSRV.ELF) and the ring-3
        // driver rows (BUZZDRV.ELF/INADRV.ELF).
        // +1 with the Terminal object: the terminal server (TERMD.ELF).
        // +1 with the Names object: the name server (NAMESD.ELF).
        // +2 with the Decisions object: the decision server and its tool
        // (DECISD.ELF, WHY.ELF).
        // +1 with transparent RPC: the RPC server (RPCSRV.ELF).
        // +1 with the structured kernel log: its sink (LOGD.ELF).
        assert_eq!(t.tasks_len(), if cfg!(feature = "ipc-endpoint-canary") { 27 } else { 25 }
            - 2 * !azos_topology::builder::PKGD_ROW as usize
            - !azos_topology::builder::INADRV_ROW as usize
            + cfg!(feature = "lx-server") as usize
            + azos_topology::builder::LXHELLO_ROW as usize
            + azos_topology::builder::BUSYBOX_ROW as usize
            + azos_topology::builder::COMPMGR_ROW as usize
            + azos_topology::builder::COMPOSITOR_ROW as usize
            + azos_topology::builder::ZENOH_GW_ROW as usize
            + azos_topology::builder::PTPD_ROW as usize
            + azos_topology::builder::AUDIOD_ROW as usize
            + azos_topology::builder::RPCQUIC_ROW as usize
            + azos_topology::builder::MCP_BRIDGE_ROW as usize
            + azos_topology::builder::SSHD_ROW as usize
            + azos_topology::builder::LOGIND_ROW as usize
            + azos_topology::builder::VMMD_ROW as usize
            + azos_topology::builder::INPUTD_ROW as usize); // +1 with Kconfig INPUTD: INPUTD.ELF; +1 with Kconfig HV: VMMD.ELF; +1 with Kconfig MCP_BRIDGE: MCPD.ELF; +1 with Kconfig SSHD: SSHD.ELF; +1 with Kconfig CONSOLE_LOGIN: LOGIND.ELF; +1 with Kconfig PTPD: PTPD.ELF; +1 with Kconfig AUDIOD: AUDIOD.ELF; +1 with Kconfig RPC_QUIC: RPCQUIC.ELF; +1 with Kconfig ZENOH_GW: ZENOHD.ELF; +1 with Kconfig USERSPACE_COMPMGR: COMPMGR.ELF; +3 in wave 11: SH.ELF, TOOLBOX.ELF, POWER; +4 in wave 12: FLIGHT/BEHAVIOR/CONFIG/OTA.ELF; -1 per driver placed in the kernel; +1 under lx-server: LXSRV.ELF; +1 for the wave-12 Linux test row (gate only); +1 in wave 15: TRACECTL.ELF

        // A second init must fail with AlreadyInit, by either path, and
        // `init_with` must not run its fill on a slot it does not hold.
        let r = init(default_minimal());
        assert_eq!(r, Err(InitError::AlreadyInit));
        let mut filled = false;
        let r = azos_topology::init_with(|_| filled = true);
        assert_eq!(r, Err(InitError::AlreadyInit));
        assert!(!filled, "init_with ran its fill after the slot was published");

        // get() still returns the originally-loaded topology.
        let t = get().expect("topology still installed");
        // 5 since 2026-09-21: supervisor, brain_link, autorun, the
        // `VSSRV.ELF` benchmark server (a `fork()`ed peer can never be
        // addressed by capability) and the
        // `EPSRV.ELF` row — the first named after an IMAGE, which is how a
        // spawned process gets any capability at all.
        // +3 since 2026-09-24: the unconditional board service registry rows
        // (`GPIODRV.ELF`/`REFLEX.ELF`/`BRAINCLI.ELF`) — owner decision, an
        // ELF ships on a board volume iff the topology declares a service it
        // provides. See `crates/core/topology/src/builder.rs`'s
        // `TASK_GPIODRV_IMAGE` block comment.
        // +3 in wave 9: the ring-3 ML service (MLSRV.ELF) and the ring-3
        // driver rows (BUZZDRV.ELF/INADRV.ELF).
        // +1 with the Terminal object: the terminal server (TERMD.ELF).
        // +1 with the Names object: the name server (NAMESD.ELF).
        // +2 with the Decisions object: the decision server and its tool
        // (DECISD.ELF, WHY.ELF).
        // +1 with transparent RPC: the RPC server (RPCSRV.ELF).
        // +1 with the structured kernel log: its sink (LOGD.ELF).
        assert_eq!(t.tasks_len(), if cfg!(feature = "ipc-endpoint-canary") { 27 } else { 25 }
            - 2 * !azos_topology::builder::PKGD_ROW as usize
            - !azos_topology::builder::INADRV_ROW as usize
            + cfg!(feature = "lx-server") as usize
            + azos_topology::builder::LXHELLO_ROW as usize
            + azos_topology::builder::BUSYBOX_ROW as usize
            + azos_topology::builder::COMPMGR_ROW as usize
            + azos_topology::builder::COMPOSITOR_ROW as usize
            + azos_topology::builder::ZENOH_GW_ROW as usize
            + azos_topology::builder::PTPD_ROW as usize
            + azos_topology::builder::AUDIOD_ROW as usize
            + azos_topology::builder::RPCQUIC_ROW as usize
            + azos_topology::builder::MCP_BRIDGE_ROW as usize
            + azos_topology::builder::SSHD_ROW as usize
            + azos_topology::builder::LOGIND_ROW as usize
            + azos_topology::builder::VMMD_ROW as usize
            + azos_topology::builder::INPUTD_ROW as usize); // +1 with Kconfig INPUTD: INPUTD.ELF; +1 with Kconfig HV: VMMD.ELF; +1 with Kconfig MCP_BRIDGE: MCPD.ELF; +1 with Kconfig SSHD: SSHD.ELF; +1 with Kconfig CONSOLE_LOGIN: LOGIND.ELF; +1 with Kconfig PTPD: PTPD.ELF; +1 with Kconfig AUDIOD: AUDIOD.ELF; +1 with Kconfig RPC_QUIC: RPCQUIC.ELF; +1 with Kconfig ZENOH_GW: ZENOHD.ELF; +1 with Kconfig USERSPACE_COMPMGR: COMPMGR.ELF; +3 in wave 11: SH.ELF, TOOLBOX.ELF, POWER; +4 in wave 12: FLIGHT/BEHAVIOR/CONFIG/OTA.ELF; -1 per driver placed in the kernel; +1 under lx-server: LXSRV.ELF; +1 for the wave-12 Linux test row (gate only); +1 in wave 15: TRACECTL.ELF
    }

    /// The kernel installs `fill_default_minimal` in place
    /// (`init_with`); host tests and tools use `default_minimal`. Both
    /// must describe the same topology, entry by entry.
    #[test]
    fn fill_in_place_matches_default_minimal() {
        let built = default_minimal();
        let mut filled = azos_topology::Topology::empty();
        azos_topology::fill_default_minimal(&mut filled);

        assert_eq!(filled.classes_len(), built.classes_len());
        assert_eq!(filled.tasks_len(), built.tasks_len());
        assert_eq!(filled.caps_pool_len(), built.caps_pool_len());
        assert_eq!(filled.sched_config().partition_window_us, built.sched_config().partition_window_us);
        for (a, b) in filled.classes().iter().zip(built.classes()) {
            assert!(a.name == b.name && a.priority_range == b.priority_range);
        }
        for (a, b) in filled.tasks().iter().zip(built.tasks()) {
            assert!(a.name == b.name && a.class_name == b.class_name && a.priority == b.priority);
            let (ca, cb) = (filled.caps_of(a), built.caps_of(b));
            assert_eq!(ca.len(), cb.len());
            for (x, y) in ca.iter().zip(cb) {
                assert!(x.kind == y.kind && x.perms == y.perms && x.target == y.target);
            }
        }
        assert!(filled.admission_check().is_ok());
    }
}

// ──────────────────────────────────────────────────────────────────────────
// P1 cap-seed bridge — migration to boot-seeded typed capabilities
// ──────────────────────────────────────────────────────────────────────────
//
// `crates/core/ipc/src/cap_seed.rs` decodes a `CapSpec { kind, perms, target, transfer: false, ops: 0 }` (the
// exact triple `azos_topology::CapSpec` carries) and mints the
// corresponding typed cap. These tests build declarations the same way
// `default_minimal()` does (`Topology::push_task`), run them through the
// bridge, and verify the result the same way the typed syscall handlers
// consume it: decode the returned raw handle back into a `Cap<T>` and
// dereference it through `cap_store::get`.
#[cfg(test)]
mod cap_seed_bridge_tests {
    #[allow(unused_imports)] // profile-gated tests (M40) use these
    use azos_abi::cap::{CapKind, CapPerms};
    #[allow(unused_imports)] // profile-gated tests (M40) use these
    use azos_topology::{CapSpec, MaybeStr, Topology};
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::cap::{targets, Cap, CapError};
    use crate::cap_store;

    /// First TID this counter hands out. Below it is the range of the OTHER
    /// counter in this binary: `crates/core/ipc/src/cap_seed.rs`'s own test module
    /// (`tests_support::fresh_tid`, from 1), compiled in by the `#[path]`
    /// mount above. Both started at 1, so a bridge test and a `cap_seed` test
    /// running in parallel could share a slot's table — seen as a one-in-twenty
    /// failure of `a_motor_id_outside_the_drivetrain_is_not_minted`, whose
    /// "nothing was written" check read the other test's mints.
    /// 32, not the 8 it was: `cap_seed` grew to 12 TIDs and the ranges met
    /// again (4 in 30 under `cap-refusal-canary`). `cap_seed`'s counter now
    /// asserts it stays below this.
    /// 24, not 32: with the canary features on (`cap-refusal-canary` and the
    /// profile ones) the bridge suite mints more TIDs than the 32 slots left
    /// of `MAX_TASKS` = 64 (the sensor-endpoint tests ran out of pool);
    /// `cap_seed` uses 8..20, so 24 splits the pool without the two meeting.
    const FIRST_TID: u32 = 24;

    static NEXT_ID: AtomicU32 = AtomicU32::new(FIRST_TID);

    /// Hand out a fresh, never-reused TID bound to its own task-pool slot in
    /// the `azos_sched` shim — mirrors `tests/host/cap-tests`' `fresh_task`.
    /// `pub(crate)` so `sensor_endpoint_tests` uses this ONE counter.
    ///
    /// Sharing is the requirement, not a convenience: both suites mint into
    /// the same shim task pool, keyed by `tid == slot`, so two counters would
    /// hand out the same slot to two tests and make each one's table depend on
    /// whether the other ran first. See [`FIRST_TID`] for the counter that
    /// cannot share this one.
    pub(crate) fn fresh_tid() -> u32 {
        let tid = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let slot = tid as usize;
        assert!(
            slot < azos_sched::task::MAX_TASKS,
            "cap-seed bridge suite has outgrown the task pool"
        );
        azos_sched::shim_bind(tid, slot);
        tid
    }

    /// **The input server derives its warrants from its one grant.** The row's
    /// grant (`READ|WRITE` + `transfer`) mints as one capability: it claims the
    /// endpoint, and a badged copy with the call right and the right to be lent
    /// can be derived from it (`ENDPOINT_DERIVE`); the copy carries the warrant
    /// badge and can be revoked without losing the source. A grant that is only
    /// the serving half cannot be derived from.
    ///
    /// **Canary.** Make `CapSpec::grant_perms` ignore `transfer`: the grant has
    /// no `DUP` and the derive is refused (red here; the row test pins
    /// `INPUT_SERVE.transfer`).
    #[test]
    fn the_input_servers_grant_can_derive_warrants() {
        let tid = fresh_tid();
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let spec = CapSpec {
            kind: CapKind::Endpoint,
            perms: CapPerms::READ.union(CapPerms::WRITE),
            target: MaybeStr::from_bytes(b"endpoint.input"),
            transfer: true, ops: 0,
        };
        let src = crate::cap_seed::seed_one_cap(tid, CapKind::Endpoint, spec.grant_perms(), "endpoint.input")
            .expect("the server's grant mints");
        let lent = CapPerms::WRITE.union(CapPerms::DELEGATE);
        let badge = azos_devif::input::warrant_badge(1);
        let w = cap_store::mint_badged(tid, src, badge, lent).expect("a warrant derives from the grant");
        let (perms, got) = cap_store::with_table(tid, |t| (t.peek_raw(w).map(|p| p.1), t.ext_of(w).map(|e| e.badge))).unwrap();
        assert_eq!(perms, Some(lent), "the call right and the right to lend it, nothing else");
        assert_eq!(got, Some(badge));
        // Revoking what was lent through the warrant keeps the warrant's source.
        assert!(cap_store::revoke_derived(tid, w).is_ok());
        assert!(cap_store::mint_badged(tid, src, azos_devif::input::warrant_badge(2), lent).is_ok());
        // The serving half alone is no source.
        let tid2 = fresh_tid();
        crate::endpoint::__endpoint_reset_for_tests();
        let serve_only = crate::cap_seed::seed_one_cap(tid2, CapKind::Endpoint, CapPerms::READ, "endpoint.input").unwrap();
        assert!(cap_store::mint_badged(tid2, serve_only, badge, CapPerms::WRITE).is_err());
    }

    /// A decl with GPIO/I2C/PWM device endpoints and a Motor grant produces
    /// exactly those minted caps -- the part A requirement, end to end:
    /// `Topology` decl -> bridge -> `cap_store` sees the right badge under
    /// each interface's own op classes.
    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints -- this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn a_decl_with_gpio_i2c_pwm_motor_grants_produces_exactly_those_mints() {
        let mut topo = Topology::empty();
        topo.push_task(
            MaybeStr::from_bytes(b"probe"),
            MaybeStr::from_bytes(b"any"),
            0,
            &[
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"gpio.9"),
                    transfer: false, ops: 0,
                },
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(b"i2c.1.0x76"),
                    transfer: false, ops: 0,
                },
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::WRITE,
                    target: MaybeStr::from_bytes(b"pwm.3"),
                    transfer: false, ops: 0,
                },
                CapSpec {
                    kind: CapKind::Endpoint,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"motor.1"),
                    transfer: false, ops: 0,
                },
            ],
        )
        .unwrap();
        let task = topo.find_task(&MaybeStr::from_bytes(b"probe")).unwrap();
        let tid = fresh_tid();
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();

        let mut minted = Vec::new();
        for cap in topo.caps_of(task) {
            let handle = crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str())
                .unwrap_or_else(|| panic!("expected a typed minter for {:?}", cap.kind));
            minted.push((cap.kind, cap.target.as_str().to_string(), handle));
        }
        assert_eq!(minted.len(), 4, "exactly the four declared grants, no more, no less");

        let holds = |key: u16, badge: u32, need: CapPerms| {
            cap_store::with_table(tid, |t| crate::endpoint::table_holds_host_badge_right(t, key, badge, need)).unwrap()
        };
        use azos_devif::{i2c, key};
        for (kind, target, _handle) in minted {
            match (kind, target.as_str()) {
                (CapKind::Endpoint, "gpio.9") => assert!(holds(key::GPIO, 9, CapPerms::RW)),
                (CapKind::Endpoint, "i2c.1.0x76") => {
                    assert!(holds(key::I2C, i2c::badge(1, 0x76), CapPerms::READ));
                    assert!(!holds(key::I2C, i2c::badge(1, 0x76), CapPerms::WRITE));
                }
                (CapKind::Endpoint, "pwm.3") => assert!(holds(key::PWM, 3, CapPerms::WRITE)),
                (CapKind::Endpoint, "motor.1") => assert!(holds(key::MOTOR, 1, CapPerms::WRITE)),
                other => panic!("unexpected grant in this decl: {:?}", other),
            }
        }
    }

    /// Kinds with no typed minter yet (`Irq`) or a target that does not parse
    /// under its kind's convention are skipped (`None`), not guessed at or
    /// panicked on.
    ///
    /// The sensor endpoint's negative cases are in `sensor_endpoint_tests`
    /// and in the malformed targets below.
    /// **A wheel outside the drivetrain mints nothing** (audit unit 2). Ids 2
    /// and 3 are real slots in `azos_robot`'s four-motor table, and a minted
    /// `motor.2` would be authority over that slot. The two wheels still mint,
    /// in the same table.
    // M40 (2026-09-26): the `motor` endpoint is a profile target; without
    // `profile-actuation` the parser refuses it and no wheel mints -- this
    // test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn a_motor_id_outside_the_drivetrain_is_not_minted() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let tid = fresh_tid();
        for target in ["motor.2", "motor.3", "motor.4", "motor.4294967295"] {
            assert!(
                crate::cap_seed::seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, target).is_none(),
                "{target}"
            );
        }
        assert_eq!(cap_store::occupied(tid), 0, "and nothing was written to the table");
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "motor.0").is_some());
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "motor.1").is_some());
    }

    #[test]
    fn unminted_kinds_and_unparseable_targets_are_skipped() {
        let tid = fresh_tid();
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Endpoint, CapPerms::READ, "sensor.imu")
            .is_none());
        // U03-2 (2026-09-26): `Cap<Irq>` HAS a minter now; line 0 is the one
        // it refuses (SBI/M-mode reserved), so that is the "skipped" case here.
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Device, CapPerms::READ, "irq.0").is_none());
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Endpoint, CapPerms::RW, "motor.left")
            .is_none());
        // A queue is created by its owner, never granted by a row.
        assert!(
            crate::cap_seed::seed_one_cap(tid, CapKind::Queue, CapPerms::RW, "7")
                .is_none()
        );
    }

    /// The negative half of part B's validation requirement: without
    /// seeding, the exact lookup the typed syscall handlers perform
    /// (`Cap::from_raw` → `cap_store::get`) reports `Stale`, matching
    /// `ECAPSTALE` at the syscall boundary.
    #[test]
    fn without_seeding_the_typed_consumer_path_sees_stale() {
        let tid = fresh_tid();
        let forged: Cap<targets::Socket> = Cap::NULL;
        assert_eq!(
            cap_store::get(tid, forged, CapPerms::WRITE),
            Err(CapError::Stale)
        );
    }

    /// `default_minimal()`'s "autorun" entry (added for the P1 migration —
    /// see `crates/core/topology/src/builder.rs`) round-trips through the same
    /// bridge call `kernel/src/tasks/loader.rs`'s autorun block makes, and the
    /// result satisfies the pair rule the `Motor` interface enforces for every
    /// PID op (`WRITE` on both wheels' endpoints).
    #[test]
    fn default_minimal_autorun_entry_seeds_a_write_satisfying_motor_pair() {
        let topo = azos_topology::default_minimal();
        let task = topo
            .find_task(&MaybeStr::from_bytes(b"autorun"))
            .expect("autorun task declared in default_minimal()");
        let tid = fresh_tid();
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        // The `mmio.<selector>` grant of the canary build names a device of
        // the machine; this host's has it.
        crate::host_machine::machine();

        let mut minted = 0;
        for cap in topo.caps_of(task) {
            if crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str())
                .is_some()
            {
                minted += 1;
            }
        }
        // The drivetrain is two of these and moves with `profile-actuation`.
        let motors = if crate::AUTORUN_DRIVETRAIN { 2 } else { 0 };
        assert_eq!(
            minted,
            motors
                + match (cfg!(feature = "cap-refusal-canary"), cfg!(feature = "ipc-endpoint-canary")) {
                    // `ipc-endpoint-canary`: the demo and bench endpoints,
                    // and (wave 12) `Cap<Launch>` on TOOLBOX.ELF for
                    // vsbench's `spawn+wait` lane.
                    (true, true) => 25, (true, false) => 22,
                    (false, true) => 20, (false, false) => 17,
                }
                // Kconfig INSPECT: the task view mints; the regions have no
                // minter on the host.
                + azos_limits::INSPECT as usize,
            "driver-registry + 10 sensor types + 1 pwm + 1 gpio + 1 i2c + linkkey + entropy, \
             plus pwm.0/gpio.0/mmio.dt:sifive,test1 and the /fat and /tmp trees under the canary, plus the \
             2 motors only under the actuation profile"
        );

        // The primitive the pair rule uses -- proves the seed is locatable by
        // interface and badge, not just "some cap got minted".
        //
        // And the negative half, which is the point of the 2026-09-21 pivot:
        // without the actuation profile the autorun row holds NEITHER wheel,
        // so the pair rule cannot be satisfied by anything this topology
        // declares. A grant that silently came back would flip this.
        let wheel = |t: &crate::cap::CapTable, w: u32| {
            crate::endpoint::table_holds_host_badge_right(t, azos_devif::key::MOTOR, w, CapPerms::WRITE)
        };
        let holds_either = cap_store::with_table(tid, |t| wheel(t, 0) || wheel(t, 1));
        let pair_ok = cap_store::with_table(tid, |t| wheel(t, 0) && wheel(t, 1));
        if crate::AUTORUN_DRIVETRAIN {
            assert_eq!(pair_ok, Some(true), "the actuation profile declares both wheels");
        } else {
            assert_eq!(holds_either, Some(false),
                "a generic deployment holds no motor capability at all");
        }
    }

    /// The pair rule, end to end from a declaration: a task declaring BOTH
    /// wheels holds `WRITE` on both endpoints; a task declaring one wheel holds
    /// `WRITE` on one only, so the `Motor` interface's pair-wide ops
    /// (`motor_host.rs`, tested against the real server in `tests/host/syscall-tests`)
    /// are refused to it. topology decl -> cap_seed -> the table the server
    /// asks.
    ///
    /// The negative half declares one wheel only. That is not a hypothetical
    /// shape: `default_minimal()` is a development default and the production
    /// path parses a signed `CAPS.TOML`, which can name `motor.0` alone.
    // M40 (2026-09-26): the `motor` endpoint is a profile target; without
    // `profile-actuation` the parser refuses it -- this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn topology_seeded_endpoints_satisfy_the_pair_rule_only_when_both_wheels_are_declared() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let both = [
            CapSpec { kind: CapKind::Endpoint, perms: CapPerms::RW, target: MaybeStr::from_bytes(b"motor.0"), transfer: false, ops: 0 },
            CapSpec { kind: CapKind::Endpoint, perms: CapPerms::RW, target: MaybeStr::from_bytes(b"motor.1"), transfer: false, ops: 0 },
        ];
        let tids = [fresh_tid(), fresh_tid()];
        for (tid, caps) in [(tids[0], &both[..]), (tids[1], &both[..1])] {
            for cap in caps {
                assert!(crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str()).is_some());
            }
        }
        let pair = |tid: u32| {
            cap_store::with_table(tid, |t| {
                (0..2).all(|w| {
                    crate::endpoint::table_holds_host_badge_right(t, azos_devif::key::MOTOR, w, CapPerms::WRITE)
                })
            })
        };
        assert_eq!(pair(tids[0]), Some(true), "both wheels declared: the pair rule is satisfied");
        assert_eq!(pair(tids[1]), Some(false), "one wheel declared: driving the shared drivetrain must be refused");
    }

    /// The typed driver-registry cap the same bridge call mints, checked by
    /// kind AND resource index — which is the property the whole migration
    /// turns on.
    ///
    /// The untyped `sys_driver_register` (retired with the untyped port/channel calls) took the
    /// kind in `a0` and gated on `DriverRegistry(a0)`; the typed one has no kind argument
    /// and reads it out of the cap. Both refuse `DRV_KIND_MOTOR_PID` to a
    /// holder of the GPIO cap, so the negative half below is not new — what
    /// is new is that with the typed syscall, asking is not expressible.
    ///
    /// **Canary.** Weakening `holds_kind_resource_with` to ignore its
    /// resource argument (i.e. degrading it to `holds_kind_with`) must turn
    /// the `MOTOR_PID` assertion red. If it does not, this test is checking
    /// the kind tag and nothing else.
    #[test]
    fn seeded_driver_registry_cap_names_gpio_and_not_the_motor_driver() {
        let topo = azos_topology::default_minimal();
        let task = topo
            .find_task(&MaybeStr::from_bytes(b"autorun"))
            .expect("autorun task declared in default_minimal()");
        let tid = fresh_tid();
        for cap in topo.caps_of(task) {
            let _ = crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str());
        }

        let held = cap_store::with_table(tid, |t| {
            (
                t.holds_kind_resource_with(
                    crate::cap::ty::DRIVER_REGISTRY,
                    azos_abi::drv_kind::DRV_KIND_GPIO,
                    CapPerms::WRITE,
                ),
                t.holds_kind_resource_with(
                    crate::cap::ty::DRIVER_REGISTRY,
                    azos_abi::drv_kind::DRV_KIND_MOTOR_PID,
                    CapPerms::WRITE,
                ),
            )
        });
        assert_eq!(
            held,
            Some((true, false)),
            "the autorun seed must hold DriverRegistry(GPIO) and NOT \
             DriverRegistry(MOTOR_PID)"
        );
    }

    /// `drvreg_kind_of` — the dereference the typed syscalls use — returns
    /// the kind the cap names, and refuses a cap minted without `WRITE`.
    ///
    /// A read-only registry capability would authorise neither register nor
    /// unregister, so `drvreg_kind_of` demands `WRITE`. Asserted rather than
    /// assumed, because a `READ`-only grant that silently dereferenced would
    /// be a capability that reads as weaker than it is.
    #[test]
    fn drvreg_kind_of_returns_the_kind_and_requires_write() {
        use crate::cap::targets;
        let tid = fresh_tid();

        let rw = crate::drvreg_cap::drvreg_grant_cap(
            tid,
            azos_abi::drv_kind::DRV_KIND_I2C,
            CapPerms::RW,
        )
        .expect("grant with RW");
        let ro = crate::drvreg_cap::drvreg_grant_cap(
            tid,
            azos_abi::drv_kind::DRV_KIND_UART,
            CapPerms::READ,
        )
        .expect("grant with READ");

        let got = cap_store::with_table(tid, |t| {
            (
                crate::drvreg_cap::drvreg_kind_of(t, rw, azos_abi::invoke::DOMAIN_DRIVER_REGISTER),
                crate::drvreg_cap::drvreg_kind_of(t, ro, azos_abi::invoke::DOMAIN_DRIVER_REGISTER),
            )
        })
        .expect("table exists");
        assert_eq!(got.0, Ok(azos_abi::drv_kind::DRV_KIND_I2C));
        assert_eq!(got.1, Err(CapError::MissingPerms));

        // And a cap of a different kind must not dereference through it —
        // `Cap<T>` is a compile-time type, but the RAW handle carries the
        // kind tag and this is the runtime half of that guarantee.
        let other = cap_store::grant::<targets::Socket>(tid, CapPerms::RW, 0).expect("grant");
        let confused: Cap<targets::DriverRegistry> =
            Cap::from_raw(other.raw());
        let wrong = cap_store::with_table(tid, |t| {
            crate::drvreg_cap::drvreg_kind_of(t, confused, azos_abi::invoke::DOMAIN_DRIVER_REGISTER)
        });
        assert_eq!(wrong, Some(Err(CapError::WrongKind)));
    }
}

// ── The `sensor` endpoints: the largest untyped family, now an interface ──

#[cfg(test)]
mod pm_endpoint_tests;

#[cfg(test)]
mod input_trusted_tests;

#[cfg(test)]
mod sensor_endpoint_tests {
    use crate::cap::CapPerms;
    use crate::cap_seed::seed_one_cap;
    use crate::cap_store;
    use azos_abi::cap::CapKind;
    use azos_topology::MaybeStr;

    use super::cap_seed_bridge_tests::fresh_tid;

    fn holds(tid: u32, ty: u32, need: CapPerms) -> bool {
        cap_store::with_table(tid, |t| {
            crate::endpoint::table_holds_host_badge_right(t, azos_devif::key::SENSOR, ty, need)
        })
        .unwrap_or(false)
    }

    /// `default_minimal()`'s autorun entry mints all ten sensor types, and
    /// each one is findable by its OWN type -- not merely "some sensor
    /// endpoint exists".
    ///
    /// **Canary.** Make the `sensor` resource parser ignore its type and always
    /// answer 0: this must go red, because nine of the ten lookups would then
    /// find nothing at their own badge.
    #[test]
    fn the_topology_seeds_every_sensor_type_at_its_own_badge() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let topo = azos_topology::default_minimal();
        let task = topo
            .find_task(&MaybeStr::from_bytes(b"autorun"))
            .expect("autorun declared");
        let tid = fresh_tid();
        for cap in topo.caps_of(task) {
            let _ = seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str());
        }

        let held = (0u32..=9).filter(|&ty| holds(tid, ty, CapPerms::READ)).count();
        assert_eq!(held, 10, "all ten sensor types must be seeded READ");

        // And NOT with WRITE: a sensor read is a read, and a grant carrying
        // WRITE would be authority the interface never asks for.
        let writable = (0u32..=9).filter(|&ty| holds(tid, ty, CapPerms::WRITE)).count();
        assert_eq!(writable, 0, "sensor endpoints must be READ-only");
        assert!(!holds(tid, 10, CapPerms::READ), "there is no sensor type 10");
    }

    /// A sensor type the kernel does not serve, or a spelling that is not a
    /// type, cannot be minted.
    ///
    /// The bound is the interface's own (`azos_devif::sensor::TYPES`): the
    /// server refuses a badge past it, and the seed refuses it earlier, so the
    /// cap table describes only grantable objects.
    #[test]
    fn a_sensor_type_the_kernel_does_not_serve_cannot_be_minted() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let tid = fresh_tid();
        assert!(seed_one_cap(tid, CapKind::Endpoint, CapPerms::READ, "sensor.9").is_some(),
                "9 is SENSOR_TYPE_POWER, the highest the kernel serves");
        for bad in ["sensor.10", "sensor.11", "sensor.255", "sensor.4294967295", "sensor.imu", "sensor"] {
            assert!(
                seed_one_cap(tid, CapKind::Endpoint, CapPerms::READ, bad).is_none(),
                "{bad} must not be mintable"
            );
        }
    }
}

// ── The machine the host suites run on ───────────────────────────────────
//
// The hardware bus is process-wide, so the machine is built once, by whichever
// test needs a device first: a goldfish RTC and a `sifive,test1` finisher
// nothing drives (what the built-in topology's `mmio.<selector>` grants name),
// a UART the kernel drives (bound to its boot driver), two twin devices to
// tell `#N` apart, a node with no window, and a virtio disk the kernel's
// driver owns.

#[cfg(test)]
pub(crate) mod host_machine {
    use azos_drv_bus::hwbus::{self, Access as _};
    use std::sync::Once;

    pub(crate) struct Quiet;
    impl hwbus::Sink for Quiet {
        fn event(&mut self, _: &hwbus::Event<'_>) {}
    }

    /// Binds every native choice and releases nothing.
    pub(crate) struct Accepting;
    impl hwbus::Drivers for Accepting {
        fn probe(&mut self, _: &str, _: hwbus::Handle, _: &hwbus::Device) -> Result<(), hwbus::ProbeError> {
            Ok(())
        }
        fn remove(&mut self, _: &str, _: hwbus::Handle, _: &hwbus::Device) -> Result<(), hwbus::ProbeError> {
            Err(hwbus::ProbeError::Busy)
        }
    }

    pub(crate) fn machine() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            hwbus::with(|b| {
                let mut q = Quiet;
                b.add(hwbus::Device::dt("rtc@101000", b"google,goldfish-rtc\0", 0x10_1000, 0x1000, 11), &mut q).unwrap();
                b.add(hwbus::Device::dt("test@100000", b"sifive,test1\0sifive,test0\0syscon\0", 0x10_0000, 0x1000, 0), &mut q).unwrap();
                b.add(hwbus::Device::dt("gpio@9030000", b"arm,pl061\0arm,primecell\0", 0x903_0000, 0x1000, 39), &mut q).unwrap();
                b.add(hwbus::Device::dt("pl031@9010000", b"arm,pl031\0arm,primecell\0", 0x901_0000, 0x1000, 34), &mut q).unwrap();
                b.add(hwbus::Device::dt("uart@10000000", b"ns16550a\0", 0x1000_0000, 0x100, 10), &mut q).unwrap();
                b.add(hwbus::Device::dt("twin@a", b"vendor,twin\0", 0x2000_0000, 0x1000, 0), &mut q).unwrap();
                b.add(hwbus::Device::dt("twin@b", b"vendor,twin\0", 0x2000_1000, 0x1000, 0), &mut q).unwrap();
                b.add(hwbus::Device::dt("nowindow@0", b"vendor,nowindow\0", 0x3000_0000, 0, 0), &mut q).unwrap();
                b.add(hwbus::Device::virtio_mmio(0x1000_2000, 0x1000, 2, 2), &mut q).unwrap();
                // What the kernel drives is bound to its driver.
                let rules = hwbus::Rules {
                    native: &[
                        hwbus::NativeEntry { pattern: hwbus::Pattern::Dt("ns16550a"), driver: "uart", boot: true },
                        hwbus::NativeEntry { pattern: hwbus::Pattern::Virtio(2), driver: "virtio-blk", boot: false },
                    ],
                    linux: &[],
                    rows: &[],
                    policy: hwbus::Policy::Auto,
                };
                b.bind_all(&rules, &mut Accepting, &mut q);
            });
        });
    }
}

// ── Cap<Device>: a device of the hardware bus and its window ─────
//
// The bus is the real `azos_hwbus` (and the real `azos_drv_bus::hwbus` static,
// over the host `SpinLock`), filled once with a small machine: a goldfish RTC
// nothing drives, a UART the kernel drives (bound to its boot driver), two
// twin devices to tell `#N` apart, a PCI function with no BAR, and a virtio
// disk the kernel's driver owns.

#[cfg(test)]
mod mmio_cap_tests {
    use crate::cap::{targets, Cap, CapPerms};
    use crate::cap_seed::seed_one_cap;
    use crate::cap_store;
    use crate::mmio_cap::{mmio_grant_cap, mmio_resolve, MmioMapError};
    use azos_abi::cap::CapKind;
    use azos_drv_bus::hwbus;

    use super::cap_seed_bridge_tests::fresh_tid;
    use crate::host_machine::machine;

    const ACCESS_READ: u64 = CapPerms::READ.bits() as u64;
    const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;

    const RTC: &str = "dt:google,goldfish-rtc";

    fn handle(selector: &str) -> u32 {
        machine();
        hwbus::resolve(selector).unwrap_or_else(|| panic!("{selector} is on the machine"))
    }

    /// Does `tid` hold any `Device` capability at all?
    fn holds_any_mmio(tid: u32) -> Option<bool> {
        cap_store::with_table(tid, |t| t.holds_kind_with(crate::cap::ty::MMIO, CapPerms::NONE))
    }

    #[test]
    fn the_machine_is_what_these_tests_assume() {
        machine();
        let (rtc, uart, disk) = (handle(RTC), handle("dt:ns16550a"), handle("virtio:2"));
        assert_eq!(hwbus::user_window(rtc), Some((0x10_1000, 0x1000)), "the RTC nothing drives is mappable");
        assert_eq!(hwbus::user_window(uart), None, "the UART is the kernel's");
        assert_eq!(hwbus::user_window(disk), None, "so is the disk");
        assert_eq!(hwbus::user_window(handle("dt:vendor,nowindow")), None, "no window, nothing to map");
    }

    /// A topology `mmio.<selector>` grant mints a capability whose resource is
    /// the device's HANDLE, with the permission declared, found by the same
    /// presence test `cap_check` runs for `DOMAIN_MMIO_MAP`.
    #[test]
    fn a_topology_grant_mints_the_devices_handle_as_its_resource() {
        let tid = fresh_tid();
        let rtc = handle(RTC);
        let ro = seed_one_cap(tid, CapKind::Device, CapPerms::READ, "mmio.dt:google,goldfish-rtc")
            .expect("READ on the RTC mints");
        let rw = seed_one_cap(tid, CapKind::Device, CapPerms::RW, "mmio.dt:vendor,twin")
            .expect("RW on a twin mints");
        assert_eq!(cap_store::get(tid, Cap::<targets::MmioRegion>::from_raw(ro), CapPerms::READ), Ok(rtc));
        assert_eq!(
            cap_store::get(tid, Cap::<targets::MmioRegion>::from_raw(rw), CapPerms::WRITE),
            Ok(handle("dt:vendor,twin"))
        );
        let held = cap_store::with_table(tid, |t| {
            (
                t.holds_kind_resource_uncontained(crate::cap::ty::MMIO, rtc, CapPerms::READ),
                t.holds_kind_resource_uncontained(crate::cap::ty::MMIO, rtc, CapPerms::WRITE),
                t.holds_kind_resource_uncontained(crate::cap::ty::MMIO, 0x10_1000, CapPerms::READ),
            )
        });
        assert_eq!(held, Some((true, false, false)), "READ on the RTC, no WRITE, nothing at its address");
    }

    /// `#N` picks the Nth match in slot order, so two identical devices are
    /// told apart by where the bus listed them; a count past the matches names
    /// nothing.
    #[test]
    fn a_selector_counts_identical_devices_in_slot_order() {
        let tid = fresh_tid();
        let (a, b) = (handle("dt:vendor,twin"), handle("dt:vendor,twin#1"));
        assert_ne!(a, b);
        assert_eq!(hwbus::user_window(a), Some((0x2000_0000, 0x1000)));
        assert_eq!(hwbus::user_window(b), Some((0x2000_1000, 0x1000)));
        let h = seed_one_cap(tid, CapKind::Device, CapPerms::READ, "mmio.dt:vendor,twin#1").unwrap();
        assert_eq!(cap_store::get(tid, Cap::<targets::MmioRegion>::from_raw(h), CapPerms::READ), Ok(b));
        assert!(hwbus::resolve("dt:vendor,twin#2").is_none());
        assert!(seed_one_cap(tid, CapKind::Device, CapPerms::READ, "mmio.dt:vendor,twin#2").is_none());
    }

    /// A selector mints nothing unless it names a device of this machine that
    /// ring 3 may map, however it is spelled.
    #[test]
    fn minting_refuses_what_names_no_mappable_device() {
        machine();
        let tid = fresh_tid();
        for target in [
            "mmio.dt:no,such-device",   // nothing on the machine
            "mmio.dt:ns16550a",         // the kernel's UART
            "mmio.virtio:2",            // the kernel's disk
            "mmio.dt:vendor,nowindow",  // no window
            "mmio.pci:1af4:1041",       // not here
            "mmio.0",                   // an index is not a selector
            "mmio.4294967295",
            "mmio.dt:",
            "mmio.dt:vendor,twin#x",
            "mmio.usb:1:2",
            "mmio",
            "mmio.",
        ] {
            assert!(
                seed_one_cap(tid, CapKind::Device, CapPerms::READ, target).is_none(),
                "`{target}` must not mint"
            );
        }
        assert_eq!(holds_any_mmio(tid), Some(false), "a refused grant minted something");
        // Positive control: the same minter, a device it may give.
        assert!(seed_one_cap(tid, CapKind::Device, CapPerms::READ, "mmio.dt:google,goldfish-rtc").is_some());
    }

    /// A grant no mapping could honour mints nothing: no READ (a mapping is
    /// always readable), EXEC or DUP (a mapping is never executable, and
    /// nothing delegates).
    ///
    /// **Canary.** Make `mmio_grant_cap` skip `grant_fits`: the first
    /// assertions go red.
    #[test]
    fn minting_refuses_a_permission_no_mapping_could_honour() {
        machine();
        let tid = fresh_tid();
        for (perms, what) in [
            (CapPerms::WRITE, "WRITE without READ"),
            (CapPerms::NONE, "no permission at all"),
            (CapPerms::ALL, "EXEC and DUP"),
            (CapPerms::from_bits_truncate(0b0101), "READ|EXEC"),
            (CapPerms::from_bits_truncate(0b1001), "READ|DUP"),
        ] {
            assert!(mmio_grant_cap(tid, RTC, perms).is_none(), "{what}");
        }
        assert_eq!(holds_any_mmio(tid), Some(false), "a refused grant minted something");
        // Positive controls: without them every line above is satisfied by a
        // minter that refuses everything.
        assert!(mmio_grant_cap(tid, RTC, CapPerms::READ).is_some());
        assert!(mmio_grant_cap(tid, RTC, CapPerms::RW).is_some());
    }

    /// `DOMAIN_MMIO_MAP`'s argument check: the window to map and whether it is
    /// writable, or the errno. Asserted on the syscall return values, since
    /// those are the ABI.
    #[test]
    fn map_arguments_resolve_to_the_window_or_the_errno() {
        let rtc = handle(RTC);
        assert_eq!(mmio_resolve(rtc as u64, ACCESS_READ), Ok((rtc, (0x10_1000, 0x1000), false)));
        assert_eq!(mmio_resolve(rtc as u64, ACCESS_RW), Ok((rtc, (0x10_1000, 0x1000), true)),
                   "writing is the capability's to allow, not the device's");

        // A handle no live device has (past the table), one a kernel driver owns,
        // one with no window.
        for bad in [handle("dt:ns16550a"), handle("virtio:2"), handle("dt:vendor,nowindow"), hwbus::MAX_DEVICES as u32, u32::MAX] {
            assert_eq!(mmio_resolve(bad as u64, ACCESS_READ), Err(MmioMapError::BadIndex), "handle {bad:#x}");
        }
        assert_eq!(MmioMapError::BadIndex.errno().to_syscall_ret(), -22, "EINVAL");

        // Only READ and READ|WRITE: not zero, not WRITE alone, no EXEC or
        // DUP, nothing above the low nibble.
        for bad in [0u64, 0b0010, 0b0100, 0b0101, 0b0111, 0b1001, 0b1111, (1 << 32) | 1, u64::MAX] {
            assert_eq!(mmio_resolve(rtc as u64, bad), Err(MmioMapError::BadAccess), "access {bad:#x}");
        }
        assert_eq!(MmioMapError::BadAccess.errno().to_syscall_ret(), -22, "EINVAL");
    }

    /// **The alias the width closes.** The call takes a 64-bit register, and
    /// a handle 4 GiB above a live one must name nothing.
    ///
    /// **Canary.** Narrow `handle` to `u32` before the range check in
    /// `mmio_resolve`: `rtc + 2^32` resolves to the RTC and this goes red.
    #[test]
    fn a_handle_above_32_bits_names_no_device() {
        let rtc = handle(RTC) as u64;
        for high in [1u64 << 32, (1 << 32) | rtc, rtc + (1 << 33), (1u64 << 63) | rtc] {
            assert_eq!(mmio_resolve(high, ACCESS_READ), Err(MmioMapError::BadIndex), "{high:#x}");
            assert_eq!(mmio_resolve(high, ACCESS_RW), Err(MmioMapError::BadIndex));
        }
    }
}

/// Deadline admission (`azos_topology::deadline`, `Topology::deadline_admission`).
///
/// **What it enforces.** `ClassSpec::admission_control` was parsed, declared
/// `true` for the safety classes, and read by nothing. These tests drive the real
/// parser with real TOML and require an infeasible real-time set to be refused by
/// `admission_check`, which is what makes the kernel halt at boot instead of
/// running with deadline misses.
///
/// The canary of the deadline-admission design is `two_60_percent_tasks_pinned_to_one_cpu_are_refused`.
#[cfg(test)]
mod deadline_admission_tests {
    use azos_topology::deadline::{admit, DeadlineRefusal, Item, ProfileFault, SchedProfile, MAX_ADMISSION_CPUS, PPM};
    use azos_topology::{parse_caps, parse_sched, AdmissionError, ParseError, Topology, MAX_CLASSES};

    /// `rt` may take a whole CPU, `rt_half` half of one, `best` is not checked.
    const SCHED: &[u8] = b"\
[class.rt]
cpu_budget_min_pct  = 10
cpu_budget_max_pct  = 100
policy              = \"edf\"
admission_control   = true

[class.rt_half]
cpu_budget_min_pct  = 10
cpu_budget_max_pct  = 50
policy              = \"edf\"
admission_control   = true

[class.best_effort]
cpu_budget_min_pct  = 5
cpu_budget_max_pct  = 100
policy              = \"fair\"
priority_range      = [16, 30]

[class.rt_wide]
cpu_budget_min_pct  = 10
cpu_budget_max_pct  = 100
policy              = \"edf\"
admission_control   = true
priority_range      = [0, 11]
";

    fn topo(caps: &'static str) -> Result<Topology<'static>, ParseError> {
        let mut t = Topology::empty();
        parse_sched(SCHED, &mut t)?;
        parse_caps(caps.as_bytes(), &mut t)?;
        Ok(t)
    }

    /// Priority 5 is in the real-time band, where a profiled row must be
    /// `mem = "locked"` (wave 11 SCHED-RT): these rows are, so the density
    /// rules below are what decides.
    fn task(name: &str, class: &str, profile: &str) -> String {
        format!("[task.{name}]\nclass = \"{class}\"\npriority = 5\nmem = \"locked\"\nmem_pages = 1\n{profile}\ncaps = []\n\n")
    }

    /// The same row with demand-paged memory and a chosen priority.
    fn task_unlocked(name: &str, class: &str, priority: u8, profile: &str) -> String {
        format!("[task.{name}]\nclass = \"{class}\"\npriority = {priority}\n{profile}\ncaps = []\n\n")
    }

    fn leak(s: String) -> &'static str { Box::leak(s.into_boxed_str()) }

    // ── the design canary ─────────────────────────────────────────────────────

    // REQ-019
    #[test]
    fn two_60_percent_tasks_pinned_to_one_cpu_are_refused() {
        let t = topo(leak(
            task("a", "rt", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 1")
                + &task("b", "rt", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 1"),
        )).unwrap();
        match t.admission_check() {
            Err(AdmissionError::Deadline(DeadlineRefusal::NoCpuFits { task })) => assert_eq!(task, 1, "the second one is the one that does not fit"),
            other => panic!("an infeasible topology was not refused: {other:?}"),
        }
    }

    #[test]
    fn the_same_two_tasks_are_admitted_when_two_cpus_are_allowed() {
        let t = topo(leak(
            task("a", "rt", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 3")
                + &task("b", "rt", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 3"),
        )).unwrap();
        let r = t.deadline_admission(2).expect("60% + 60% on two CPUs is feasible");
        assert_eq!(&r.cpu_load_ppm[..2], &[600_000, 600_000], "one per CPU");
        // And refused if the board really has one.
        assert!(matches!(t.deadline_admission(1), Err(AdmissionError::Deadline(DeadlineRefusal::NoCpuFits { .. }))));
    }

    // ── the bound itself ───────────────────────────────────────────────────

    #[test]
    fn exactly_one_hundred_percent_fits_and_one_microsecond_more_does_not() {
        let full = task("a", "rt", "period_us = 10000\nruntime_us = 5000\ncpu_mask = 1")
            + &task("b", "rt", "period_us = 10000\nruntime_us = 5000\ncpu_mask = 1");
        assert!(topo(leak(full.clone())).unwrap().admission_check().is_ok(), "50% + 50% is 100% and must be admitted");
        let over = full + &task("c", "rt", "period_us = 10000\nruntime_us = 1\ncpu_mask = 1");
        assert!(topo(leak(over)).unwrap().admission_check().is_err(), "100% + 0.001% must be refused");
    }

    /// Density is runtime / min(deadline, period). Utilisation would call these
    /// 20% each and admit all three; they are 50% each.
    #[test]
    fn a_constrained_deadline_is_charged_by_density_not_utilisation() {
        let two = task("a", "rt", "period_us = 10000\nruntime_us = 2000\ndeadline_us = 4000\ncpu_mask = 1")
            + &task("b", "rt", "period_us = 10000\nruntime_us = 2000\ndeadline_us = 4000\ncpu_mask = 1");
        assert!(topo(leak(two.clone())).unwrap().admission_check().is_ok(), "50% + 50%");
        let three = two + &task("c", "rt", "period_us = 10000\nruntime_us = 2000\ndeadline_us = 4000\ncpu_mask = 1");
        assert!(topo(leak(three)).unwrap().admission_check().is_err(), "three 50% tasks on one CPU are infeasible");
    }

    /// Division rounds UP. 1/3 is 333,334 ppm, so two are 666,668 (the exact 2/3
    /// would be 666,666) and three are refused although their exact sum is 1.
    /// A density is never under-stated.
    #[test]
    fn a_density_is_rounded_up_never_down() {
        let two = task("a", "rt", "period_us = 3\nruntime_us = 1\ncpu_mask = 1") + &task("b", "rt", "period_us = 3\nruntime_us = 1\ncpu_mask = 1");
        let r = topo(leak(two.clone())).unwrap().deadline_admission(1).unwrap();
        assert_eq!(r.cpu_load_ppm[0], 666_668);
        let three = two + &task("c", "rt", "period_us = 3\nruntime_us = 1\ncpu_mask = 1");
        assert!(topo(leak(three)).unwrap().deadline_admission(1).is_err(), "rounded up, three thirds exceed one CPU");
    }

    // ── classes ────────────────────────────────────────────────────────────

    // REQ-019
    #[test]
    fn a_task_over_its_class_budget_is_refused_though_the_cpu_has_room() {
        let t = topo(leak(task("a", "rt_half", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 1"))).unwrap();
        assert!(matches!(t.admission_check(), Err(AdmissionError::Deadline(DeadlineRefusal::ClassBudget { task: 0 }))));
        let ok = topo(leak(task("a", "rt_half", "period_us = 10000\nruntime_us = 5000\ncpu_mask = 1"))).unwrap();
        assert!(ok.admission_check().is_ok(), "50% is the class's own limit");
    }

    #[test]
    fn a_class_without_admission_control_is_not_checked_or_counted() {
        // A best-effort task with a profile no CPU could satisfy, next to a
        // real-time task that fits: the best-effort one is nobody's guarantee.
        let t = topo(leak(
            task("rt1", "rt", "period_us = 10000\nruntime_us = 9000\ncpu_mask = 1")
                + &task("be", "best_effort", "period_us = 10\nruntime_us = 9\ncpu_mask = 1"),
        )).unwrap();
        assert!(t.admission_check().is_ok());
        assert_eq!(t.deadline_admission(1).unwrap().placed, 1, "only the checked class was placed");
    }

    // ── malformed profiles are named, not silently dropped ─────────────────

    #[test]
    fn a_malformed_profile_is_refused_and_says_why() {
        let bad = |profile: &'static str, ncpus: usize| {
            let t = topo(leak(task("a", "rt", profile))).unwrap();
            t.deadline_admission(ncpus)
        };
        let fault = |r: Result<_, AdmissionError>| match r {
            Err(AdmissionError::Deadline(DeadlineRefusal::Invalid { fault, .. })) => fault,
            other => panic!("expected an Invalid refusal, got {other:?}"),
        };
        assert_eq!(fault(bad("runtime_us = 100", 4)), ProfileFault::ZeroPeriod, "a half-filled profile is not 'no profile'");
        assert_eq!(fault(bad("period_us = 100", 4)), ProfileFault::ZeroRuntime);
        assert_eq!(fault(bad("period_us = 100\nruntime_us = 50\ndeadline_us = 200", 4)), ProfileFault::DeadlineExceedsPeriod);
        assert_eq!(fault(bad("period_us = 100\nruntime_us = 60\ndeadline_us = 50", 4)), ProfileFault::RuntimeExceedsDeadline);
        assert_eq!(fault(bad("period_us = 100\nruntime_us = 10\ncpu_mask = 4", 2)), ProfileFault::NoCpuInMask, "CPU 2 does not exist on a 2-CPU board");
    }

    #[test]
    fn a_value_that_does_not_fit_u32_is_rejected_by_the_parser_not_truncated() {
        let r = topo(leak(task("a", "rt", "period_us = 4294967296\nruntime_us = 1")));
        assert_eq!(r.err(), Some(ParseError::BadValue), "2^32 would wrap to 0, a different schedule");
    }

    // ── the function itself, against the obvious computation ───────────────

    /// For tasks pinned to one CPU each, the verdict is exactly "every CPU's
    /// summed density is at most one CPU". Random sets, compared with that sum.
    #[test]
    fn pinned_sets_match_the_per_cpu_sum() {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
        let budget = [PPM; MAX_CLASSES];
        for round in 0..2000 {
            let ncpus = 1 + (next() % 4) as usize;
            let n = 1 + (next() % 6) as usize;
            let mut items = Vec::new();
            let mut sum = [0u64; MAX_ADMISSION_CPUS];
            for i in 0..n {
                let period = 100 + (next() % 900) as u32;
                let runtime = 1 + (next() % (period as u64 / 2 + 1)) as u32;
                let cpu = (next() % ncpus as u64) as usize;
                let d = ((runtime as u64 * PPM as u64) + period as u64 - 1) / period as u64;
                sum[cpu] += d;
                items.push(Item { task: i as u16, class: 0, level: 0, profile: SchedProfile { period_us: period, runtime_us: runtime, deadline_us: 0, cpu_mask: 1 << cpu } });
            }
            let want = (0..ncpus).all(|c| sum[c] <= PPM as u64);
            assert_eq!(admit(&items, ncpus, &budget).is_ok(), want, "round {round}: sums {:?}", &sum[..ncpus]);
        }
    }

    // ── wave 11 SCHED-RT: a band row needs a reservation AND locked memory ──

    /// The one rule topology admission and `SYS_SPAWN_EX` both apply.
    #[test]
    fn band_entry_needs_an_admitted_profile_and_locked_memory() {
        use azos_topology::{band_entry, BandEntry, RT_BAND_THRESHOLD};
        assert_eq!(RT_BAND_THRESHOLD, 12);
        assert_eq!(band_entry(4, true, true), BandEntry::Admitted);
        assert_eq!(band_entry(4, true, false), BandEntry::NotLocked, "spawn refuses this");
        assert_eq!(band_entry(4, false, true), BandEntry::NoReservation, "floored, not admitted");
        assert_eq!(band_entry(4, false, false), BandEntry::NoReservation);
        assert_eq!(band_entry(11, true, false), BandEntry::NotLocked);
        assert_eq!(band_entry(12, true, false), BandEntry::NotBand, "12 is outside the band");
        assert_eq!(band_entry(20, false, false), BandEntry::NotBand);
    }

    /// Topology admission refuses a profiled band row that is not locked, and
    /// names it; the same row locked, or outside the band, or without a
    /// profile, is admitted.
    #[test]
    fn a_profiled_band_row_without_locked_memory_is_refused_at_admission() {
        let p = "period_us = 10000\nruntime_us = 1000\ncpu_mask = 1";
        let t = topo(leak(task("ok", "rt", p) + &task_unlocked("demand", "rt", 4, p))).unwrap();
        assert_eq!(t.admission_check(),
                   Err(AdmissionError::Deadline(DeadlineRefusal::BandNotLocked { task: 1 })));
        assert_eq!(t.row_band_entry(1), azos_topology::BandEntry::NotLocked);
        assert_eq!(t.row_band_entry(0), azos_topology::BandEntry::Admitted);
        // Outside the band: best_effort's range is [16, 30].
        let t = topo(leak(task_unlocked("slow", "best_effort", 20, p))).unwrap();
        assert_eq!(t.admission_check(), Ok(()));
        // In the band without a profile: admitted (a ring-3 task named after
        // it is floored at spawn instead).
        let t = topo(leak(task_unlocked("plain", "rt", 4, ""))).unwrap();
        assert_eq!(t.admission_check(), Ok(()));
        assert_eq!(t.row_band_entry(0), azos_topology::BandEntry::NoReservation);
    }

    // ── wave 11 SCHED-RT: placement and the band cap ──────────────────────

    /// Run-time attachment pins a row's task to the CPU admission placed it
    /// on, so the report must say which CPU that was.
    #[test]
    fn the_report_names_the_cpu_each_task_was_placed_on() {
        let t = topo(leak(
            task("a", "rt", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 3")
                + &task("b", "rt", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 3")
                + &task("c", "best_effort", "period_us = 10000\nruntime_us = 1000"),
        )).unwrap();
        let r = t.deadline_admission(2).unwrap();
        assert_eq!(r.cpu_of(0), Some(0));
        assert_eq!(r.cpu_of(1), Some(1));
        assert_eq!(r.cpu_of(2), None, "a class without admission_control is not placed");
    }

    /// The band's reservations on one CPU may take at most the band cap; the
    /// same load outside the band is only bounded by the CPU.
    #[test]
    fn band_reservations_past_the_band_cap_are_refused() {
        use azos_topology::deadline::profile_density;
        let t = topo(leak(
            task("a", "rt", "period_us = 10000\nruntime_us = 6000\ncpu_mask = 1")
                + &task("b", "rt", "period_us = 10000\nruntime_us = 4000\ncpu_mask = 1"),
        )).unwrap();
        let r = t.deadline_admission(1).expect("60 % + 40 % fit one CPU");
        let density = |task: u16| profile_density(&t.tasks()[task as usize].profile).unwrap();
        assert_eq!(r.band_check(|_| true, density, 950_000), Err(DeadlineRefusal::BandCap { task: 1 }));
        assert_eq!(r.band_check(|task| task == 0, density, 950_000), Ok(()), "only `a` in the band");
        assert_eq!(r.band_check(|_| true, density, 1_000_000), Ok(()), "no cap");
    }

    /// A locked `rt_wide` row at `priority`.
    fn task_at(name: &str, priority: u8, profile: &str) -> String {
        format!("[task.{name}]\nclass = \"rt_wide\"\npriority = {priority}\nmem = \"locked\"\nmem_pages = 1\n{profile}\ncaps = []\n\n")
    }

    /// Wave 15: boot admission applies the cross-level rule run-time
    /// `reserve` applies (`azos_abi::rt_levels::levels_fit`). 25 % + 5 % of
    /// one CPU fits by density, but the level-6 row's 2 ms deadline sits
    /// behind 5 ms of the level-4 row: refused at boot, naming the row, its
    /// level and the level that fails, instead of passing boot and being
    /// refused at `reserve()`. Same set as `sched-policy-tests` `rt_core`.
    #[test]
    fn a_mixed_level_set_that_fits_by_density_is_refused_at_boot() {
        let t = topo(leak(
            task_at("hi", 4, "period_us = 20000\nruntime_us = 5000\ncpu_mask = 1")
                + &task_at("lo", 6, "period_us = 20000\nruntime_us = 1000\ndeadline_us = 2000\ncpu_mask = 1"),
        )).unwrap();
        assert_eq!(t.row_level(0), 4);
        assert_eq!(t.row_level(1), 6);
        match t.admission_check() {
            Err(AdmissionError::Deadline(DeadlineRefusal::Levels { task, cpu, level, failing_level })) =>
                assert_eq!((task, cpu, level, failing_level), (0, 0, 4, 6),
                    "`lo` (denser) is placed first; `hi` above it breaks level 6"),
            other => panic!("a mixed-level set that misses deadlines was admitted at boot: {other:?}"),
        }
        // A second CPU it may use takes it: the rule skips a CPU, like `first_fit_by`.
        let t = topo(leak(
            task_at("hi", 4, "period_us = 20000\nruntime_us = 5000\ncpu_mask = 3")
                + &task_at("lo", 6, "period_us = 20000\nruntime_us = 1000\ndeadline_us = 2000\ncpu_mask = 3"),
        )).unwrap();
        let r = t.deadline_admission(2).expect("one per CPU");
        assert_eq!((r.cpu_of(1), r.cpu_of(0)), (Some(0), Some(1)));
    }

    /// The same two reservations at one level reduce to the density sum: admitted.
    #[test]
    fn the_same_set_at_one_level_is_admitted_at_boot() {
        let t = topo(leak(
            task_at("hi", 4, "period_us = 20000\nruntime_us = 5000\ncpu_mask = 1")
                + &task_at("lo", 4, "period_us = 20000\nruntime_us = 1000\ndeadline_us = 2000\ncpu_mask = 1"),
        )).unwrap();
        assert!(t.admission_check().is_ok());
        let r = t.deadline_admission(1).expect("one level, 75 % of one CPU");
        assert_eq!(r.placed, 2);
        assert_eq!(r.cpu_load_ppm[0], 750_000);
    }
}

/// Wave 7: the class and priority each default-topology row asks for, which
/// the autorun loader and `SYS_SPAWN_EX` now apply. Pinned by value, so a row
/// edit that moves a ring-3 program's priority fails here, by name.
#[cfg(test)]
mod row_sched_tests {
    use azos_topology::{default_minimal, parse_sched, MaybeStr, RowSched, Topology};

    fn applied(t: &Topology<'_>, name: &[u8]) -> (String, u8, u8) {
        match t.row_sched(name) {
            RowSched::Apply { class_name, declared, priority } => {
                (class_name.as_str().to_string(), declared, priority)
            }
            other => panic!("{:?}: expected a row, got {:?}", core::str::from_utf8(name), other),
        }
    }

    #[test]
    fn default_rows_resolve_to_the_documented_class_and_priority() {
        let t = default_minimal();
        // The generic loader row: what every image without a row of its own
        // runs at. 16 = the scheduler's default, so nothing unnamed moves.
        assert_eq!(applied(&t, b"autorun"), ("soft_rt".into(), 16, 16));
        // The three board programs: best_effort at the service number, 24,
        // declared as such (no row relies on the clamp).
        for n in [&b"GPIODRV.ELF"[..], b"REFLEX.ELF", b"BRAINCLI.ELF"] {
            assert_eq!(applied(&t, n), ("best_effort".into(), 24, 24));
        }
        // The ML service: soft_rt at the default 16; it runs at the behavior
        // task's 14 only by donation, while the loop waits on it.
        assert_eq!(applied(&t, b"MLSRV.ELF"), ("soft_rt".into(), 16, 16));
        // The buzzer's ring-3 host (wave 9): best_effort 24, like GPIODRV.ELF
        // (owner decision 2026-09-28; it was soft_rt 16), above the shell.
        assert_eq!(applied(&t, b"BUZZDRV.ELF"), ("best_effort".into(), 24, 24));
        // The INA219's: hard_rt 15 with its reservation
        // (`ring3_priority_order`). Placed in the kernel (DRVPLACE): no row.
        if azos_topology::builder::INADRV_ROW {
            assert_eq!(applied(&t, b"INADRV.ELF"), ("hard_rt".into(), 15, 15));
        }
        // The user shell below the servers it calls and above every tool it
        // starts, all scheduled as best_effort (the shell's class is
        // `session`, which has the same range), so ^C does not depend on
        // equal-priority slicing.
        let (sh, tool) = (26, 27);
        assert_eq!(applied(&t, b"TERMD.ELF"), ("best_effort".into(), 25, 25));
        assert_eq!(applied(&t, b"NAMESD.ELF"), ("best_effort".into(), 24, 24));
        assert_eq!(applied(&t, b"SH.ELF"), ("session".into(), sh, sh));
        for n in [&b"TOOLBOX.ELF"[..], b"POWER.ELF", b"FLIGHT.ELF", b"BEHAVIOR.ELF", b"CONFIG.ELF", b"OTA.ELF"] {
            assert_eq!(applied(&t, n), ("best_effort".into(), tool, tool));
        }
        // Rows that name no task the kernel creates; resolved all the same.
        assert_eq!(applied(&t, b"supervisor"), ("safety_critical".into(), 0, 0));
        assert_eq!(applied(&t, b"brain_link"), ("best_effort".into(), 24, 24));
        // Gate-only rows: the servers of `autorun` (16), one above it.
        #[cfg(feature = "ipc-endpoint-canary")]
        {
            assert_eq!(applied(&t, b"VSSRV.ELF"), ("hard_rt".into(), 15, 15));
            assert_eq!(applied(&t, b"EPSRV.ELF"), ("hard_rt".into(), 15, 15));
        }
    }

    #[test]
    fn a_name_without_a_row_is_no_row() {
        let t = default_minimal();
        for n in [&b"VSBENCH.ELF"[..], b"ABITEST.ELF", b"forked", b"net-poll", b""] {
            assert_eq!(t.row_sched(n), RowSched::NoRow);
        }
    }

    /// The autorun row must stay out of the band the tick never preempts
    /// (`RT_PRIORITY_THRESHOLD` = 12 in `crates/core/sched/src/task.rs`): at 8 it
    /// starved `net-poll` off hart 3 (see `builder.rs`).
    #[test]
    fn the_autorun_row_is_preemptible() {
        let t = default_minimal();
        let (_, _, p) = applied(&t, b"autorun");
        assert!(p >= 12, "autorun resolves to {}, inside the non-preemptible band", p);
    }

    /// Clamping at both ends of a parsed range, and a value inside it kept.
    #[test]
    fn priority_is_clamped_into_the_class_range_both_ways() {
        const SCHED: &[u8] = b"\
[class.soft_rt]
cpu_budget_min_pct  = 50
cpu_budget_max_pct  = 100
policy              = \"fair\"
priority_range      = [16, 23]

[class.gpu_batch]
cpu_budget_min_pct  = 50
cpu_budget_max_pct  = 100
policy              = \"fair\"
priority_range      = [24, 30]

";
        let mut t = Topology::empty();
        parse_sched(SCHED, &mut t).expect("parse");
        // Tasks come from CAPS.TOML; pushed directly, with no caps.
        for (name, class, prio) in [
            (&b"low"[..], &b"soft_rt"[..], 3u8),
            (b"high", b"soft_rt", 200),
            (b"mid", b"soft_rt", 19),
            (b"odd", b"gpu_batch", 26),
        ] {
            t.push_task(MaybeStr::from_bytes(name), MaybeStr::from_bytes(class), prio, &[]).expect("push");
        }
        assert!(t.admission_check().is_ok());
        assert_eq!(applied(&t, b"low"), ("soft_rt".into(), 3, 16));
        assert_eq!(applied(&t, b"high"), ("soft_rt".into(), 200, 23));
        assert_eq!(applied(&t, b"mid"), ("soft_rt".into(), 19, 19));
        // A class this crate declares but the kernel's scheduler has no
        // counterpart for: resolved here; the refusal is the kernel's
        // (`SchedClass::from_name` is `None`).
        assert_eq!(applied(&t, b"odd"), ("gpu_batch".into(), 26, 26));
    }

    /// A row naming a class the topology never declares resolves to
    /// `UndeclaredClass` (admission refuses such a topology; the kernel treats
    /// it as a refusal if one ever reached it).
    #[test]
    fn an_undeclared_class_is_not_applied() {
        let mut t = Topology::empty();
        t.push_task(MaybeStr::from_bytes(b"ghost"), MaybeStr::from_bytes(b"nope"), 5, &[]).expect("push");
        assert_eq!(t.row_sched(b"ghost"), RowSched::UndeclaredClass);
    }
}

/// The ring-3 priority bounds (owner decision 2026-09-28): nothing in ring 3
/// may sit below `RT_PRIORITY_THRESHOLD` (12), where the tick never preempts.
#[cfg(test)]
mod ring3_priority_floor {
    use azos_topology::ring3_priority;
    const FLOOR: u32 = 12;
    const CEIL: u32 = 30;

    #[test]
    fn below_the_floor_is_raised_and_flagged() {
        // The pre-wave-7 `autorun` row: hard_rt priority 0 → 8 after its class
        // range; either way it must land on 12, flagged.
        assert_eq!(ring3_priority(0, FLOOR, CEIL), (12, true));
        assert_eq!(ring3_priority(8, FLOOR, CEIL), (12, true));
        assert_eq!(ring3_priority(11, FLOOR, CEIL), (12, true));
    }

    #[test]
    fn inside_the_band_is_untouched() {
        for p in FLOOR..=CEIL {
            assert_eq!(ring3_priority(p, FLOOR, CEIL), (p, false), "priority {p}");
        }
    }

    #[test]
    fn above_the_ceiling_is_capped_not_flagged() {
        assert_eq!(ring3_priority(31, FLOOR, CEIL), (30, false));
        assert_eq!(ring3_priority(u32::MAX, FLOOR, CEIL), (30, false));
    }
}

/// Memory admission: the `mem` / `mem_pages` / `[pipeline.*]`
/// fields and boot-time memory admission.
///
/// **Canaries, run by hand before landing** (2026-09-28; the tests each broke):
/// - count a ceiling row once, not twice (`r.cow_pages += pages` removed):
///   `ceiling_rows_pay_for_one_cow_copy`, `the_boundary_is_inclusive`,
///   `a_row_without_pages_takes_the_profile_default`,
///   `kernel_rows_are_not_counted` fail;
/// - a locked row without pages resolved to the default instead of refused:
///   `a_locked_row_must_declare_its_pages` fails;
/// - `is_ring3` answering `true` for every row:
///   `kernel_rows_are_not_counted`, `ring3_rows_are_images_and_autorun` fail.
#[cfg(test)]
mod memory_admission_tests {
    use azos_topology::{
        default_minimal, parse_caps, parse_sched, AdmissionError, MaybeStr, MemoryRefusal,
        ParseError, TaskSpec, Topology,
    };

    const SCHED: &[u8] = b"[class.best_effort]\ncpu_budget_min_pct = 10\ncpu_budget_max_pct = 100\npolicy = \"fair\"\npriority_range = [24, 30]\n";

    /// Every row may fork: the pre-wave-9 arithmetic, which the tests below
    /// written before the fork predicate existed still pin.
    const FORKS: fn(&TaskSpec<'_>) -> bool = |_| true;

    fn topo<'a>(caps: &'a [u8]) -> Topology<'a> {
        let mut t = Topology::empty();
        parse_sched(SCHED, &mut t).unwrap();
        parse_caps(caps, &mut t).unwrap();
        t
    }

    #[test]
    fn mem_field_parses_locked_and_ceiling_and_nothing_else() {
        let t = topo(b"[task.A.ELF]\nmem = \"locked\"\nmem_pages = 10\ncaps = []\n[task.B.ELF]\ncaps = []\n[task.C.ELF]\nmem = \"ceiling\"\n");
        assert!(t.tasks()[0].mem_locked);
        assert_eq!(t.tasks()[0].mem_pages, 10);
        assert!(!t.tasks()[1].mem_locked, "B inherited A's lock");
        assert!(!t.tasks()[2].mem_locked);
        let mut t = Topology::empty();
        assert_eq!(parse_caps(b"[task.D.ELF]\nmem = \"lock\"\n", &mut t), Err(ParseError::UnknownEnumValue));
        let mut t = Topology::empty();
        assert_eq!(parse_caps(b"[task.E.ELF]\nmem = locked\n", &mut t), Err(ParseError::BadValue));
    }

    #[test]
    fn ring3_rows_are_images_and_autorun() {
        let t = topo(b"[task.autorun]\n[task.GPIODRV.ELF]\n[task.supervisor]\n[task.brain_link]\n[task.x.elf]\n");
        let r: Vec<bool> = t.tasks().iter().map(|t| t.is_ring3()).collect();
        assert_eq!(r, vec![true, true, false, false, true]);
    }

    #[test]
    fn ceiling_rows_pay_for_one_cow_copy() {
        // 100 locked (once) + 50 ceiling (twice) + 7 reserve = 207.
        let t = topo(b"[task.L.ELF]\nmem = \"locked\"\nmem_pages = 100\n[task.C.ELF]\nmem_pages = 50\n");
        let r = t.memory_admission(1000, 7, 999, &FORKS).unwrap();
        assert_eq!((r.rows, r.locked_rows, r.locked_pages, r.ceiling_pages, r.cow_pages), (2, 1, 100, 50, 50));
        assert_eq!(r.need, 207);
    }

    #[test]
    fn a_row_without_pages_takes_the_profile_default() {
        let t = topo(b"[task.autorun]\n[task.A.ELF]\nmem_pages = 3\n");
        let r = t.memory_admission(1 << 20, 0, 40, &FORKS).unwrap();
        assert_eq!(r.ceiling_pages, 43);
        assert_eq!(r.need, 86);
        let m = t.row_mem(b"autorun", None, 40).unwrap();
        assert_eq!((m.limit, m.locked), (40, false));
    }

    #[test]
    fn the_boundary_is_inclusive() {
        let t = topo(b"[task.A.ELF]\nmem_pages = 10\n");
        assert!(t.memory_admission(25, 5, 0, &FORKS).is_ok(), "20 + 5 = 25 fits in 25");
        assert_eq!(
            t.memory_admission(24, 5, 0, &FORKS),
            Err(AdmissionError::Memory(MemoryRefusal::Overcommit { need: 25, free: 24 }))
        );
    }

    #[test]
    fn a_locked_row_must_declare_its_pages() {
        let t = topo(b"[task.A.ELF]\nmem_pages = 1\n[task.B.ELF]\nmem = \"locked\"\n");
        assert_eq!(
            t.memory_admission(1 << 30, 0, 64, &FORKS),
            Err(AdmissionError::Memory(MemoryRefusal::LockedWithoutPages { task: 1 }))
        );
    }

    #[test]
    fn kernel_rows_are_not_counted() {
        let t = topo(b"[task.supervisor]\nmem_pages = 1000000\n[task.A.ELF]\nmem_pages = 1\n");
        assert_eq!(t.memory_admission(2, 0, 0, &FORKS).unwrap().need, 2);
    }

    #[test]
    fn row_mem_follows_the_image_row_then_the_fallback() {
        let t = topo(b"[task.autorun]\nmem_pages = 9\n[task.U.ELF]\nmem = \"locked\"\nmem_pages = 5\n");
        let u = t.row_mem(b"U.ELF", Some(b"autorun"), 1).unwrap();
        assert_eq!((u.row, u.limit, u.locked), (&b"U.ELF"[..], 5, true));
        let v = t.row_mem(b"V.ELF", Some(b"autorun"), 1).unwrap();
        assert_eq!((v.row, v.limit, v.locked), (&b"autorun"[..], 9, false));
        assert!(t.row_mem(b"V.ELF", None, 1).is_none());
    }

    #[test]
    fn pipelines_size_the_dma_pool_above_the_floor() {
        let t = topo(b"[pipeline.camera]\ndma_kb = 320\n[pipeline.lidar]\ndma_kb = 1\n[task.A.ELF]\n");
        assert_eq!(t.pipelines().len(), 2);
        assert_eq!(t.pipelines()[0].dma_pages, 80);
        assert_eq!(t.pipelines()[1].dma_pages, 1, "1 KiB rounds up to a page");
        assert_eq!(t.dma_pool_pages(64), 81);
        assert_eq!(t.dma_pool_pages(512), 512, "the Kconfig floor wins");
        assert_eq!(t.tasks().len(), 1, "a pipeline section must not open a task");
        let mut t = Topology::empty();
        assert_eq!(
            parse_caps(b"[pipeline.p]\ndma_kb = 1\n[pipeline.p]\ndma_kb = 2\n", &mut t),
            Err(ParseError::Admission(AdmissionError::DuplicatePipeline))
        );
        let mut t = Topology::empty();
        assert_eq!(parse_caps(b"[pipeline.p]\nkb = 1\n", &mut t), Err(ParseError::UnknownField));
    }

    /// The built-in topology: every ring-3 row gets a budget, the kernel rows
    /// none, and it fits the edge profile's RAM with room to spare.
    #[test]
    fn the_default_topology_is_admitted() {
        let t = default_minimal();
        let autorun = t.find_task(&MaybeStr::from_bytes(b"autorun")).unwrap();
        assert_eq!(autorun.mem_pages as usize, azos_limits::AUTORUN_MEM_PAGES);
        let default = azos_limits::RING3_MEM_PAGES_DEFAULT as u32;
        let r = t.memory_admission(u64::MAX, 0, default, &FORKS).unwrap();
        assert!(r.rows >= 4, "autorun + the three board images");
        assert_eq!(r.locked_rows, 0);
        // 256 MiB edge QEMU = 65,536 pages; half of it is a generous bound for
        // the heap, the image and the DMA pool.
        assert!(r.need < 32 * 1024, "default topology needs {} pages", r.need);
    }

    // ── wave 9: `instances = N` and the fork predicate ─────────────────────

    #[test]
    fn instances_parse_default_to_one_and_refuse_zero_and_too_many() {
        let t = topo(b"[task.A.ELF]\ninstances = 3\n[task.B.ELF]\nmem_pages = 1\n");
        assert_eq!(t.tasks()[0].instance_count(), 3);
        assert_eq!(t.tasks()[1].instance_count(), 1, "B inherited A's instances");
        let mut t = Topology::empty();
        assert_eq!(parse_caps(b"[task.C.ELF]\ninstances = 0\n", &mut t), Err(ParseError::BadValue));
        let too_many = format!("[task.D.ELF]\ninstances = {}\n", azos_limits::MAX_TASKS + 1);
        let mut t = Topology::empty();
        assert_eq!(parse_caps(too_many.as_bytes(), &mut t), Err(ParseError::BadValue));
        let mut t = Topology::empty();
        assert!(!t.set_last_task_instances(2), "no task pushed yet");
    }

    #[test]
    fn every_instance_is_counted() {
        // 3 x 10 ceiling, 3 x 10 COW (it forks), 2 x 5 locked, + 1 reserve.
        let t = topo(b"[task.A.ELF]\nmem_pages = 10\ninstances = 3\n[task.L.ELF]\nmem = \"locked\"\nmem_pages = 5\ninstances = 2\n");
        let r = t.memory_admission(1000, 1, 0, &FORKS).unwrap();
        assert_eq!((r.instances, r.ceiling_pages, r.cow_pages, r.locked_pages), (5, 30, 30, 10));
        assert_eq!(r.fork_rows, 1, "a locked row never pays for a COW copy");
        assert_eq!(r.need, 71);
    }

    #[test]
    fn only_a_row_that_can_fork_pays_for_a_cow_copy() {
        let t = topo(b"[task.F.ELF]\nmem_pages = 10\n[task.N.ELF]\nmem_pages = 7\n");
        let only_f = |t: &TaskSpec<'_>| t.name.as_bytes() == b"F.ELF";
        let r = t.memory_admission(1000, 0, 0, &only_f).unwrap();
        assert_eq!((r.ceiling_pages, r.cow_pages, r.fork_rows), (17, 10, 1));
        assert_eq!(r.need, 27);
    }

    #[test]
    fn row_mem_carries_the_row_index_and_its_instances() {
        let t = topo(b"[task.autorun]\ninstances = 2\n[task.U.ELF]\n");
        let u = t.row_mem(b"U.ELF", Some(b"autorun"), 1).unwrap();
        assert_eq!((u.index, u.instances), (1, 1));
        let v = t.row_mem(b"V.ELF", Some(b"autorun"), 1).unwrap();
        assert_eq!((v.index, v.instances), (0, 2));
    }

    // ── Kconfig LOCKED_HUGE_LEAVES: `mem_huge_mib` ─────────────────────────

    /// Parsed on a locked row, carried by `row_mem`, refused when odd, zero
    /// or above `MAX_HUGE_MIB` (256, restated in crates/core/sched/src/
    /// process.rs as MAX_HUGE_BYTES — this pins the topology side).
    #[test]
    fn mem_huge_mib_parses_even_bounded_sizes_only() {
        assert_eq!(azos_topology::types::MAX_HUGE_MIB, 256);
        let t = topo(b"[task.L.ELF]\nmem = \"locked\"\nmem_pages = 16\nmem_huge_mib = 4\n[task.C.ELF]\n");
        assert_eq!(t.tasks()[0].mem_huge_mib, 4);
        assert_eq!(t.tasks()[1].mem_huge_mib, 0, "C inherited L's region");
        assert_eq!(t.row_mem(b"L.ELF", None, 1).unwrap().huge_mib, 4);
        for bad in [&b"[task.X.ELF]\nmem_huge_mib = 3\n"[..], b"[task.X.ELF]\nmem_huge_mib = 0\n",
                    b"[task.X.ELF]\nmem_huge_mib = 258\n"] {
            let mut t = Topology::empty();
            assert_eq!(parse_caps(bad, &mut t), Err(ParseError::BadValue), "{:?}", core::str::from_utf8(bad));
        }
    }

    /// Counted as locked pages, `N × 256` topology pages (4 KiB each), on top
    /// of the row's own `mem_pages`.
    ///
    /// **Canary.** Drop the `r.locked_pages += huge` line: `locked_pages` is
    /// 16 and `need` 16 + 7, and this fails.
    #[test]
    fn a_huge_region_is_counted_as_locked_pages() {
        let t = topo(b"[task.L.ELF]\nmem = \"locked\"\nmem_pages = 16\nmem_huge_mib = 4\n");
        let r = t.memory_admission(1 << 20, 7, 64, &FORKS).unwrap();
        assert_eq!((r.locked_rows, r.huge_pages, r.locked_pages), (1, 1024, 16 + 1024));
        assert_eq!(r.need, 16 + 1024 + 7);
    }

    /// A region on a ceiling row, or on a row with more than one instance,
    /// is refused by admission rather than half-honoured.
    #[test]
    fn a_huge_region_needs_a_locked_single_instance_row() {
        let t = topo(b"[task.A.ELF]\nmem_pages = 1\n[task.C.ELF]\nmem_pages = 16\nmem_huge_mib = 2\n");
        assert_eq!(
            t.memory_admission(1 << 30, 0, 64, &FORKS),
            Err(AdmissionError::Memory(MemoryRefusal::HugeWithoutLocked { task: 1 }))
        );
        let t = topo(b"[task.L.ELF]\nmem = \"locked\"\nmem_pages = 16\nmem_huge_mib = 2\ninstances = 2\n");
        assert_eq!(
            t.memory_admission(1 << 30, 0, 64, &FORKS),
            Err(AdmissionError::Memory(MemoryRefusal::HugeInstances { task: 0 }))
        );
    }

    /// Kconfig AARCH64_PAGE_*: topology pages are 4 KiB on every granule; the
    /// kernel converts at the allocator, rounding a budget up to whole frames.
    #[test]
    fn topology_pages_convert_to_frames_of_any_granule() {
        use azos_topology::{frames_for, units_for};
        for (units, page, frames) in [(64u64, 4096u64, 64u64), (64, 16384, 16), (65, 16384, 17),
                                      (64, 65536, 4), (1, 65536, 1), (0, 65536, 0)] {
            assert_eq!(frames_for(units, page), frames, "{units} units at {page}");
        }
        assert_eq!(units_for(5, 4096), 5);
        assert_eq!(units_for(5, 16384), 20);
        assert_eq!(units_for(5, 65536), 80);
        assert_eq!(frames_for(u64::MAX, 65536), u64::MAX / 16, "saturates, never wraps");
    }
}

// Partition-scoped block endpoints: `endpoint = "block.part.<n>"`, minted with badge `n + 1` against
// the partition table the kernel published. One test on purpose: the published
// table is a process-wide static, and this crate's tests run on several threads.
#[cfg(test)]
mod block_endpoint_tests {
    use crate::cap::CapPerms;
    use crate::cap_seed::{seed_one_cap_outcome, SeedOutcome};
    use crate::cap_store;
    use azos_abi::cap::CapKind;
    use azos_drv_block::partition::{self, Partition, Scheme, Table, MAX_PARTS};
    use azos_topology::{parse_caps, Topology};

    use super::cap_seed_bridge_tests::fresh_tid;

    fn holds(tid: u32, badge: u32, need: CapPerms) -> bool {
        cap_store::with_table(tid, |t| {
            crate::endpoint::table_holds_host_badge_right(t, azos_devif::key::BLOCK, badge, need)
        })
        .unwrap_or(false)
    }

    /// **Canary.** Remove the `block_grantable` arm from the endpoint seed: the
    /// unpublished-table line reads `Minted`. Drop its permission test: the
    /// `exec` line reads `Minted`.
    #[test]
    fn a_block_part_row_parses_and_mints_only_a_published_partition() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"endpoint\", target = \"block.part.0\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok(), "the block endpoint must parse");
        let spec = topo.caps_of(&topo.tasks()[0])[0];
        assert_eq!((spec.kind, spec.target.as_str()), (CapKind::Endpoint, "block.part.0"));

        partition::reset_for_tests();
        let tid = fresh_tid();
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::RW, "block.part.0"),
            SeedOutcome::Refused,
            "no table published: nothing to scope the capability by",
        );
        let none = Partition { start: 0, sectors: 0, mbr_type: 0 };
        let mut parts = [none; MAX_PARTS];
        parts[0] = Partition { start: 2048, sectors: 4096, mbr_type: 0x83 };
        assert!(partition::publish(&Table { scheme: Scheme::Mbr, parts, count: 1 }));

        match seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::RW, "block.part.0") {
            SeedOutcome::Minted(_) => {}
            o => panic!("block.part.0 did not mint: {o:?}"),
        }
        assert!(holds(tid, 1, CapPerms::WRITE), "partition 0 is badge 1; badge 0 is the whole medium");
        assert!(!holds(tid, 0, CapPerms::READ), "nothing names the whole medium");
        for bad in ["block.part.1", "block.part", "block.0", "block", "part.0", "block.part.-1"] {
            assert_eq!(seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::RW, bad),
                       SeedOutcome::Refused, "{bad}");
        }
        // Read and/or write, nothing else.
        assert_eq!(seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::EXEC, "block.part.0"),
                   SeedOutcome::Refused, "exec");
        assert_eq!(seed_one_cap_outcome(tid, CapKind::Endpoint, CapPerms::NONE, "block.part.0"),
                   SeedOutcome::Refused, "no rights");
        partition::reset_for_tests();
    }
}

// Wave 10: `kind = "file"`, target the absolute root of a directory tree,
// minted as a tree `Cap<File>` (`crates/core/ipc/src/file_cap.rs`) — the authority
// for mkdir/unlink/rmdir/rename/truncate. The tree table is a process-wide
// static, so one test.
#[cfg(test)]
mod file_tree_cap_tests {
    use crate::cap::{targets, Cap, CapPerms};
    use crate::cap_seed::{seed_one_cap_outcome, SeedOutcome};
    use crate::cap_store;
    use azos_abi::cap::CapKind;
    use azos_topology::{parse_caps, Topology};

    use super::cap_seed_bridge_tests::fresh_tid;

    /// **Canary.** Remove the `CapKind::Node` arm from
    /// `seed_one_cap_outcome`: the seed reads `NoMinter` instead of
    /// `Minted`/`Refused`.
    #[test]
    fn a_file_tree_row_parses_and_mints_only_a_plain_absolute_root() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"node\", target = \"/fat\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok(), "the file word must parse");
        let tid = fresh_tid();
        let h = match seed_one_cap_outcome(tid, CapKind::Node, CapPerms::RW, "/fat") {
            SeedOutcome::Minted(h) => h,
            o => panic!("a plain absolute tree root was not minted: {o:?}"),
        };
        let r = cap_store::get(tid, Cap::<targets::File>::from_raw(h), CapPerms::WRITE)
            .expect("the tree grant resolves with WRITE");
        assert!(crate::file_cap::is_tree_resource(r), "a tree grant named a descriptor: {r:#x}");
        for bad in ["fat", "/fat/../etc", "/fat/./x", ""] {
            assert_eq!(seed_one_cap_outcome(tid, CapKind::Node, CapPerms::RW, bad),
                       SeedOutcome::Refused, "{bad:?}");
        }
        assert_eq!(seed_one_cap_outcome(tid, CapKind::Node, CapPerms::RW_DELEGATE, "/fat"),
                   SeedOutcome::Refused, "a tree grant cannot carry DUP");
    }
}

// ── CONFIG.SIG v2 and the device record (hardware root of trust) ──────
//
// Fixtures produced by the host tools, so the tests prove the WIRE FORMAT the
// tools and the kernel agree on:
//   printf 'sched_hz=42\nlink_encrypt=1\n' > fx.ini
//   python3 tools/gen_config_sig.py fx.ini --config-v2 --counter 3 \
//       --device-id 00112233445566778899aabbccddeeff --out fx.sig
//   python3 -c "import device_provision as d; \
//       print(d.record(bytes.fromhex('00112233445566778899aabbccddeeff'), 7).hex())"
// with `tools/keys/test_priv.bin`, whose public half this crate embeds
// (`dev-key`). Regenerating the key pair breaks these: re-sign instead.
#[cfg(test)]
mod config_sig_v2_tests {
    use azos_topology::device_record::{DeviceRecord, DEVICE_RECORD_LEN};
    use azos_topology::{verify_config_sig_v2, ConfigSigError, TRUSTED_PUBKEY};

    const INI: &[u8] = b"sched_hz=42\nlink_encrypt=1\n";
    const DEVICE: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    const SIDECAR_HEX: &str = "4b4346470200010000112233445566778899aabbccddeeff0300000000000000\
        8931408a5739d12c85cf293a7669f112e2b9f35cb05862b708e94218570b18cc\
        103ee9dc783e95900f86c992118c9a41d02b8bfb3a4900d0f194faa7b92e0707";
    const RECORD_HEX: &str = "4b4445560100112233445566778899aabbccddeeff07000000000000007fd24d44";

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The tool's sidecar verifies for its device and yields its counter.
    #[test]
    fn a_tool_signed_v2_sidecar_verifies_and_yields_its_counter() {
        let sig = hex(SIDECAR_HEX);
        assert_eq!(sig.len(), 96);
        assert_eq!(verify_config_sig_v2(INI, &sig, &DEVICE, &TRUSTED_PUBKEY), Ok(3));
    }

    /// Another device's id is refused before the signature is checked, and the
    /// signature is checked over OUR id: rewriting the id field in the sidecar
    /// to ours does not make another device's signature verify.
    #[test]
    fn a_sidecar_for_another_device_is_refused() {
        let sig = hex(SIDECAR_HEX);
        let mut other = DEVICE;
        other[15] ^= 1;
        assert_eq!(verify_config_sig_v2(INI, &sig, &other, &TRUSTED_PUBKEY), Err(ConfigSigError::WrongDevice));
        let mut forged = sig.clone();
        forged[8 + 15] ^= 1;
        assert_eq!(verify_config_sig_v2(INI, &forged, &other, &TRUSTED_PUBKEY), Err(ConfigSigError::InvalidSignature));
    }

    /// The counter, the file and the signature are all covered: change any one
    /// and it no longer verifies. (A replay to an OLDER counter needs a
    /// signature for it; a counter field rewritten in place has none.)
    #[test]
    fn the_counter_the_file_and_the_signature_are_all_signed() {
        let sig = hex(SIDECAR_HEX);
        let mut c = sig.clone();
        c[24] = 2;
        assert_eq!(verify_config_sig_v2(INI, &c, &DEVICE, &TRUSTED_PUBKEY), Err(ConfigSigError::InvalidSignature));
        let mut ini = INI.to_vec();
        ini[9] ^= 1;
        assert_eq!(verify_config_sig_v2(&ini, &sig, &DEVICE, &TRUSTED_PUBKEY), Err(ConfigSigError::InvalidSignature));
        let mut s = sig.clone();
        s[40] ^= 1;
        assert_eq!(verify_config_sig_v2(INI, &s, &DEVICE, &TRUSTED_PUBKEY), Err(ConfigSigError::InvalidSignature));
    }

    /// The v1 format (a bare 64-byte signature) is refused by its own error,
    /// as are a wrong length, magic, version, padding and counter 0.
    #[test]
    fn v1_and_malformed_sidecars_are_refused() {
        let sig = hex(SIDECAR_HEX);
        assert_eq!(verify_config_sig_v2(INI, &sig[32..], &DEVICE, &TRUSTED_PUBKEY), Err(ConfigSigError::V1Format));
        assert_eq!(verify_config_sig_v2(INI, &sig[..95], &DEVICE, &TRUSTED_PUBKEY), Err(ConfigSigError::BadFormat));
        // Magic, version, padding, the algorithm id (ML-DSA-65's, none, one
        // that is two bytes wide), the counter.
        for (at, v) in [(0usize, b'X'), (4, 1), (5, 1), (6, 2), (6, 0), (7, 1), (24, 0)] {
            let mut m = sig.clone();
            m[at] = v;
            if at == 24 {
                m[25..32].fill(0);
            }
            assert_eq!(verify_config_sig_v2(INI, &m, &DEVICE, &TRUSTED_PUBKEY), Err(ConfigSigError::BadFormat), "byte {at}");
        }
    }

    /// The device record round-trips, matches the provisioning tool byte for
    /// byte, and a corrupt, foreign or empty sector decodes to nothing.
    #[test]
    fn the_device_record_matches_the_tool_and_rejects_garbage() {
        let rec = DeviceRecord { device_id: DEVICE, floor: 7 };
        assert_eq!(rec.encode().to_vec(), hex(RECORD_HEX));
        let mut sector = [0u8; 512];
        sector[..DEVICE_RECORD_LEN].copy_from_slice(&rec.encode());
        assert_eq!(DeviceRecord::decode(&sector), Some(rec));
        assert_eq!(DeviceRecord::decode(&[0u8; 512]), None);
        let mut torn = sector;
        torn[21] ^= 1; // the floor changed without the tag
        assert_eq!(DeviceRecord::decode(&torn), None);
        let mut seed = sector;
        seed[..4].copy_from_slice(b"SEED");
        assert_eq!(DeviceRecord::decode(&seed), None);
        assert_eq!(DeviceRecord::decode(&sector[..DEVICE_RECORD_LEN - 1]), None);
    }
}

// `kind = "launch"`, target an image name, perm `x` —
// the right to start that image with `SYS_SPAWN_EX`
// (`crates/core/ipc/src/launch_cap.rs`). There is no `"pipe"` word: a pipe end
// is never granted by a row. The name table is a process-wide static, so one
// test.
#[cfg(test)]
mod launch_cap_tests {
    use crate::cap::{targets, Cap, CapPerms};
    use crate::cap_seed::{seed_one_cap_outcome, SeedOutcome};
    use crate::cap_store;
    use azos_abi::cap::CapKind;
    use azos_topology::{default_minimal, parse_caps, MaybeStr, ParseError, Topology};

    use super::cap_seed_bridge_tests::fresh_tid;

    /// **Canary.** Remove the `CapKind::Node` arm from
    /// `seed_one_cap_outcome`: the seed reads `NoMinter`.
    #[test]
    fn a_launch_row_parses_and_mints_exec_on_an_image_name_only() {
        let mut topo = Topology::empty();
        let caps = b"[task.SH.ELF]\ncaps = [ { kind = \"node\", target = \"TOOLBOX.ELF\", perm = \"x\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok(), "the launch word must parse");
        assert_eq!(topo.caps_of(&topo.tasks()[0])[0].kind, CapKind::Node);
        let mut topo = Topology::empty();
        let pipe = b"[task.SH.ELF]\ncaps = [ { kind = \"pipe\", target = \"x\", perm = \"r\" } ]\n";
        assert_eq!(parse_caps(pipe, &mut topo), Err(ParseError::UnknownEnumValue),
                   "a pipe end is never granted by a row");

        let tid = fresh_tid();
        let h = match seed_one_cap_outcome(tid, CapKind::Node, CapPerms::EXEC, "TOOLBOX.ELF") {
            SeedOutcome::Minted(h) => h,
            o => panic!("a launch grant on an image name was not minted: {o:?}"),
        };
        let r = cap_store::get(tid, Cap::<targets::Launch>::from_raw(h), CapPerms::EXEC)
            .expect("the launch grant resolves with EXEC");
        assert_eq!(crate::launch_cap::launch_resource_of(b"TOOLBOX.ELF"), Some(r));
        assert_eq!(crate::launch_cap::launch_resource_of(b"NOROW.ELF"), None,
                   "an image no row names has no resource");
        for bad in ["toolbox.elf", "TOOLBOX", "LONGNAME9.ELF", "/fat/TOOLBOX.ELF", ""] {
            assert_eq!(seed_one_cap_outcome(tid, CapKind::Node, CapPerms::EXEC, bad),
                       SeedOutcome::Refused, "{bad:?}");
        }
        assert_eq!(seed_one_cap_outcome(tid, CapKind::Node, CapPerms::RW, "TOOLBOX.ELF"),
                   SeedOutcome::Refused, "only EXEC is a launch right");
    }

    /// The shell's own row holds no hardware authority: a launch grant on
    /// the tool image, directory trees, (wave 12) the full task
    /// view and no endpoint at all: it reaches the terminal server through the
    /// name server (`imports = ["term"]`, the kernel's badged `endpoint.names`
    /// at spawn), not by a grant of its own. The tool image holds only the view, the introspection
    /// regions, `READ` on the `net` and `clock` endpoints (`host`, `ntp`:
    /// observation, never the right to move time) and, with Kconfig
    /// DRV_VIRTIO_SND, `READ|WRITE` on `sound.0` (`beep`).
    ///
    /// **Canary.** Give the shell a grant on `endpoint.term` back (the old
    /// `TERM_CALL`): red on the no-endpoint assertion. Give the tool image
    /// `WRITE` on `clock`: red on the endpoint assertion. Make the sound grant
    /// `transfer`: red on its assertion.
    #[test]
    fn the_shell_row_holds_no_hardware_authority() {
        let topo = default_minimal();
        let sh = topo.find_task(&MaybeStr::from_bytes(b"SH.ELF")).expect("SH.ELF row");
        for c in topo.caps_of(sh) {
            assert!(matches!(c.kind, CapKind::Node | CapKind::Domain),
                    "SH.ELF holds {:?}: no endpoint, the name server lends it one", c.kind);
            assert!(!c.transfer, "nothing the shell holds is transferable by its row");
        }
        let tb = topo.find_task(&MaybeStr::from_bytes(b"TOOLBOX.ELF")).expect("TOOLBOX.ELF row");
        for c in topo.caps_of(tb) {
            // The task view, and the read-only introspection regions.
            match c.kind {
                CapKind::Domain => {}
                // The sound device's stream (`beep`): run, and nothing else.
                CapKind::Endpoint if c.target == MaybeStr::from_bytes(b"sound.0") => {
                    assert!(azos_limits::DRV_VIRTIO_SND, "the grant is only there with the device");
                    assert_eq!((c.perms, c.transfer), (CapPerms::RW, false), "a stream, not the right to pass it on");
                }
                CapKind::Endpoint if c.target == MaybeStr::from_bytes(b"endpoint.compositor") => {
                    // `window` attaches a window of its own: the call right, not
                    // transferable, not the serving half.
                    assert_eq!((c.perms, c.transfer), (CapPerms::WRITE, false), "TOOLBOX.ELF only calls the compositor");
                }
                CapKind::Endpoint if c.target == MaybeStr::from_bytes(b"endpoint.input") => {
                    // `input watch` asks the input server for the focus: the
                    // call right, not transferable, not the serving half.
                    assert_eq!((c.perms, c.transfer), (CapPerms::WRITE, false), "TOOLBOX.ELF only calls the input server");
                }
                // The audio server's endpoint (`beep` plays through it): the call
                // right, lent so the tool can derive its stream badge, never
                // `READ` (which would serve it), and no `sound.0` beside it.
                CapKind::Endpoint if c.target == MaybeStr::from_bytes(b"endpoint.audio") => {
                    assert!(azos_topology::builder::AUDIOD_ROW, "the grant is only there with the server");
                    assert_eq!((c.perms, c.transfer), (CapPerms::WRITE, true), "a caller, not the server");
                }
                // The resolver and the clock's state: observation only.
                CapKind::Endpoint => {
                    assert!(c.target == MaybeStr::from_bytes(b"net") || c.target == MaybeStr::from_bytes(b"clock"),
                            "TOOLBOX.ELF holds an endpoint other than net, clock, sound.0 and the input server's");
                    assert_eq!((c.perms, c.transfer), (CapPerms::READ, false), "TOOLBOX.ELF observes, it does not act");
                }
                // The root directory, read-only: it names, it cannot write.
                CapKind::Node => assert_eq!((c.perms, c.target), (CapPerms::READ, MaybeStr::from_bytes(b"/"))),
                CapKind::MemObj => assert!(
                    c.target == MaybeStr::from_bytes(b"inspect.public") || c.target == MaybeStr::from_bytes(b"inspect.admin"),
                    "TOOLBOX.ELF holds a memory object other than the introspection regions"),
                k => panic!("TOOLBOX.ELF holds {k:?}"),
            }
        }
        let sound = topo.caps_of(tb).iter().filter(|c| c.target == MaybeStr::from_bytes(b"sound.0")).count();
        // With the audio server the tool plays through it and holds no device of its own.
        assert_eq!(
            sound,
            usize::from(azos_limits::DRV_VIRTIO_SND && !azos_topology::builder::AUDIOD_ROW),
            "the sound grant follows Kconfig DRV_VIRTIO_SND, and is the server's with Kconfig AUDIOD",
        );
        assert!(!tb.start);
    }

    /// The Terminal object's endpoint has exactly one server and one holder
    /// of the call right: `TERMD.ELF` holds `READ` on `endpoint.term` (it
    /// serves), `NAMESD.ELF` `WRITE` with `transfer` (it lends), and the
    /// shell, which imports `term`, holds no grant on it. The three images
    /// start together when the native shell session is the console program.
    ///
    /// **Canaries.** Give `SH.ELF` `READ` too (a second server): red on the
    /// server count. Drop `TERM_INPUT_EVENTS` from `TERMD_CAPS`: red on the
    /// region count. Drop `TERM_SERVE` from `TERMD_CAPS`: red on the server
    /// assertion. Drop the `set_task_start` of the shell or the name server
    /// next to the console row: red on the start assertion. Make `TERM_LEND`
    /// `transfer: false`: red on the lend assertion (and on admission).
    #[test]
    fn the_terminal_endpoint_has_one_server_termd_and_one_caller_the_shell() {
        let topo = default_minimal();
        let mut servers = Vec::new();
        let mut callers = Vec::new();
        for t in topo.tasks() {
            for c in topo.caps_of(t) {
                if c.kind == CapKind::Endpoint && c.target.as_bytes() == b"endpoint.term" {
                    if c.perms.contains(CapPerms::READ) { servers.push(t.name.as_str().to_string()); }
                    if c.perms.contains(CapPerms::WRITE) { callers.push(t.name.as_str().to_string()); }
                }
            }
        }
        assert_eq!(servers, ["TERMD.ELF"], "one server, the terminal server");
        assert_eq!(callers, ["NAMESD.ELF"], "one holder of the call right, the name server");
        let nd = topo.find_task(&MaybeStr::from_bytes(b"NAMESD.ELF")).unwrap();
        assert!(topo.caps_of(nd).iter().any(|c| c.target.as_bytes() == b"endpoint.term" && c.transfer),
                "the name server can lend it (DUP)");
        let sh = topo.find_task(&MaybeStr::from_bytes(b"SH.ELF")).unwrap();
        assert_eq!(topo.imports_of(sh).iter().map(|n| n.as_bytes()).collect::<Vec<_>>(), [&b"term"[..]]);
        assert_eq!(topo.admission_check(), Ok(()), "the shell's import is something the name server can lend");
        if azos_limits::USER_SHELL {
            for n in ["SH.ELF", "TERMD.ELF", "NAMESD.ELF"] {
                assert!(topo.find_task(&MaybeStr::from_bytes(n.as_bytes())).unwrap().start,
                        "{n} starts with the native shell session");
            }
        }
        let termd = topo.find_task(&MaybeStr::from_bytes(b"TERMD.ELF")).unwrap();
        // Its endpoint, and the two kernel-owned regions it turns into keys and
        // a mouse: nothing else.
        assert!(
            topo.caps_of(termd).iter().all(|c| c.kind == CapKind::Endpoint
                || (c.kind == CapKind::MemObj
                    && (c.target == MaybeStr::from_bytes(b"input.events") || c.target == MaybeStr::from_bytes(b"console.screen"))
                    && c.perms == CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP)
                    && !c.transfer)),
            "the terminal server holds its endpoint and the input regions, read-write and not transferable"
        );
        let regions = topo.caps_of(termd).iter().filter(|c| c.kind == CapKind::MemObj).count();
        assert_eq!(
            regions,
            azos_topology::builder::TERM_INPUT_RING as usize + (azos_topology::builder::TERM_INPUT_RING && azos_topology::builder::TERM_SCREEN_REGION) as usize,
            "one region per thing the kernel has"
        );
    }

    /// The monitor's control endpoint (`VmCtl`) has exactly one server and one
    /// holder of the call right, and the tool image reaches it only through the
    /// name server: `VMMD.ELF` holds `READ` on `endpoint.vmctl`, `NAMESD.ELF`
    /// `WRITE` with `transfer`, and `TOOLBOX.ELF` imports `vmctl` and holds no
    /// grant on it. All of it exists with the monitor's row (Kconfig HV) and
    /// not under `CONSOLE_LOCKDOWN` for the import.
    ///
    /// **Canaries.** Give `TOOLBOX.ELF` a grant on the endpoint (a second
    /// holder): red on the callers. Make `VMCTL_LEND` `transfer: false`: red on
    /// the lend assertion and on admission. Drop the `imports` of the tool
    /// image: red on the import assertion.
    #[test]
    fn the_monitors_control_endpoint_has_one_server_and_the_tool_reaches_it_through_the_name_server() {
        let topo = default_minimal();
        let (mut servers, mut callers) = (Vec::new(), Vec::new());
        for t in topo.tasks() {
            for c in topo.caps_of(t) {
                if c.kind == CapKind::Endpoint && c.target.as_bytes() == b"endpoint.vmctl" {
                    if c.perms.contains(CapPerms::READ) { servers.push(t.name.as_str().to_string()); }
                    if c.perms.contains(CapPerms::WRITE) { callers.push(t.name.as_str().to_string()); }
                }
            }
        }
        let tb = topo.find_task(&MaybeStr::from_bytes(b"TOOLBOX.ELF")).unwrap();
        let imports: Vec<_> = topo.imports_of(tb).iter().map(|n| n.as_bytes()).collect();
        if azos_topology::builder::VMMD_ROW {
            assert_eq!(servers, ["VMMD.ELF"], "one server, the monitor");
            assert_eq!(callers, ["NAMESD.ELF"], "one holder of the call right, the name server");
            let nd = topo.find_task(&MaybeStr::from_bytes(b"NAMESD.ELF")).unwrap();
            assert!(topo.caps_of(nd).iter().any(|c| c.target.as_bytes() == b"endpoint.vmctl" && c.transfer), "the name server can lend it (DUP)");
            let want: &[&[u8]] = if azos_limits::CONSOLE_LOCKDOWN { &[] } else { &[b"vmctl"] };
            assert_eq!(imports, want);
        } else {
            assert!(servers.is_empty() && callers.is_empty(), "no monitor row, no control endpoint");
            assert!(imports.is_empty());
        }
        assert_eq!(topo.admission_check(), Ok(()), "what the tool imports is something the name server can lend");
    }

    /// The input server (Kconfig `INPUTD`): its endpoint has one server, which
    /// holds ONE grant of it: `READ` (it serves) with the call right and
    /// `transfer` (the source its warrants are derived from; two grants of one
    /// endpoint would be found by `SYS_CAP_INFO` as the first only); the tool
    /// image is the one caller; the drivers' region is granted to it read-write
    /// and not transferable, beside the terminal server's grant of the same
    /// object. No row at all without the switch.
    ///
    /// **Canaries.** Give `NAMESD.ELF` a grant on `endpoint.input`: red on the
    /// callers. Make `INPUT_SERVE` `transfer: false`: red on the server
    /// assertion (the server could not derive a lendable warrant). Drop
    /// `TOOLBOX_CAPS_WITH_INPUT`: red on the caller assertion.
    #[test]
    fn the_input_servers_endpoint_has_one_server_and_the_tool_calls_it() {
        let topo = default_minimal();
        let (mut servers, mut callers, mut trusted, mut grants) = (Vec::new(), Vec::new(), Vec::new(), 0);
        for t in topo.tasks() {
            for c in topo.caps_of(t) {
                if c.kind == CapKind::Endpoint && c.target.as_bytes() == b"endpoint.input" {
                    let name = t.name.as_str().to_string();
                    grants += 1;
                    if c.perms.contains(CapPerms::READ) {
                        assert!(c.perms.contains(CapPerms::WRITE) && c.transfer, "the server's one grant is call + serve + transfer");
                        servers.push(name);
                    } else if c.perms.contains(CapPerms::WRITE) && c.perms.contains(CapPerms::EXEC) {
                        // The trusted surface's call right (the kernel badges it).
                        assert!(!c.transfer, "a caller's grant is not transferable");
                        assert_eq!(c.perms, CapPerms::WRITE.union(CapPerms::EXEC));
                        trusted.push(name);
                    } else if c.perms.contains(CapPerms::WRITE) {
                        assert!(!c.transfer, "a caller's grant is not transferable");
                        callers.push(name);
                    }
                }
            }
        }
        if azos_topology::builder::INPUTD_ROW {
            assert_eq!(servers, ["INPUTD.ELF"], "one server");
            let want: &[&str] = if azos_limits::CONSOLE_LOCKDOWN { &[] } else { &["TOOLBOX.ELF"] };
            assert_eq!(callers, want, "the tool image is the one caller");
            let want_trusted: &[&str] = if azos_topology::builder::COMPOSITOR_ROW { &["COMPSRV.ELF"] } else { &[] };
            assert_eq!(trusted, want_trusted, "the compositor is the one trusted surface");
            assert_eq!(grants, 1 + want.len() + want_trusted.len(), "no other grant of the endpoint, the server holds exactly one");
            let inputd = topo.find_task(&MaybeStr::from_bytes(b"INPUTD.ELF")).unwrap();
            assert!(inputd.start, "the server starts at boot");
            let regions: Vec<_> = topo.caps_of(inputd).iter().filter(|c| c.kind == CapKind::MemObj).collect();
            assert_eq!(regions.iter().map(|c| c.target.as_bytes()).collect::<Vec<_>>(), [&b"input.events"[..], &b"input.focus"[..]]);
            for r in &regions {
                assert_eq!(r.perms, CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP));
                assert!(!r.transfer);
            }
            assert_eq!(topo.caps_of(inputd).len(), 3, "its endpoint, the drivers' region and the focus word: nothing else");
        } else {
            assert!(servers.is_empty() && callers.is_empty() && grants == 0, "no server row, no endpoint");
            assert!(topo.find_task(&MaybeStr::from_bytes(b"INPUTD.ELF")).is_none());
        }
        assert_eq!(topo.admission_check(), Ok(()));
    }

    /// **Discriminates** the focus split (owner 2026-10-23): the focus word,
    /// which decides whether the console or the focus holder gets the keyboard,
    /// is granted to the input server's row alone. Every other row, the
    /// terminal server's first (it maps the event region read-write), holds no
    /// capability on `input.focus`, so it cannot map, let alone write, the word.
    ///
    /// **Canary.** Add `INPUTD_FOCUS` to `TERMD_CAPS` (the terminal server
    /// could then set itself the holder): red here, and on the terminal
    /// server's own row test.
    #[test]
    fn only_the_input_server_is_granted_the_focus_word() {
        let topo = default_minimal();
        let holders: Vec<String> = topo
            .tasks()
            .iter()
            .filter(|t| topo.caps_of(t).iter().any(|c| c.target.as_bytes() == b"input.focus"))
            .map(|t| t.name.as_str().to_string())
            .collect();
        let want: &[&str] = if azos_topology::builder::INPUTD_ROW { &["INPUTD.ELF"] } else { &[] };
        assert_eq!(holders, want, "the focus word is the input server's alone");
        if let Some(termd) = topo.find_task(&MaybeStr::from_bytes(b"TERMD.ELF")) {
            assert!(topo.caps_of(termd).iter().all(|c| c.target.as_bytes() != b"input.focus"), "the console cannot set who holds the keyboard");
        }
    }

    /// Wave 12 (owner round 48): the shell and the tool image (`ps`) hold the
    /// full task view — `Cap<Task>` `READ` on `"tasks"`, exactly — off the
    /// console lockdown and not under it; the decision server holds it (the
    /// warrant of the admin region its records are in), and with Kconfig
    /// INSPECT the autorun row (its conformance images watch the task list);
    /// no other default row holds it; and the grant mints.
    ///
    /// **Canary.** Drop `TASK_VIEW_CAP` from `TOOLBOX_CAPS`: red on
    /// "TOOLBOX.ELF lacks the task view".
    #[test]
    fn the_shell_and_ps_hold_the_full_task_view_off_the_lockdown_only() {
        use azos_abi::cap::CapPerms;
        let topo = default_minimal();
        let want = !azos_limits::CONSOLE_LOCKDOWN;
        for (i, t) in topo.tasks().iter().enumerate() {
            let views: Vec<_> = topo.caps_of(t).iter().filter(|c| c.kind == CapKind::Domain).collect();
            let named = |n: &[u8]| t.name == MaybeStr::from_bytes(n);
            if named(b"SH.ELF") || named(b"TOOLBOX.ELF") {
                assert_eq!(views.len(), want as usize, "{} lacks the task view (row {i})",
                           if named(b"SH.ELF") { "SH.ELF" } else { "TOOLBOX.ELF" });
                for c in views {
                    assert_eq!((c.perms, c.target), (CapPerms::READ, MaybeStr::from_bytes(b"tasks")));
                    assert!(!c.transfer);
                }
            } else if ((named(b"DECISD.ELF") || named(b"ABICHILD.ELF")) && azos_limits::INSPECT && azos_limits::INSPECT_ADMIN_PAGES != 0)
                || (named(b"autorun") && azos_limits::INSPECT)
            {
                assert_eq!(views.len(), 1, "row {i} lacks the task view");
            } else {
                assert!(views.is_empty(), "row {i} holds the task view");
            }
        }
        let tid = crate::cap_seed_bridge_tests::fresh_tid();
        assert!(matches!(
            crate::cap_seed::seed_one_cap_outcome(tid, CapKind::Domain, CapPerms::READ, "tasks"),
            crate::cap_seed::SeedOutcome::Minted(_)
        ));
    }

    /// Kconfig INSPECT: the tool image (`inspect`) holds the public region and,
    /// with an admin region configured, the admin one AFTER the task view (the
    /// grant of `inspect.admin` asks the table for it: the admin warrant); both
    /// `READ`, never `DUP`; nothing under the console lockdown; `WHY.ELF` holds
    /// the public one only (`why woke`: metrics, no task names); no other default
    /// row holds either; and a host without the kernel's minter refuses them.
    ///
    /// **Canary.** Swap the admin and task-view entries of `TOOLBOX_CAPS`: red
    /// on "the admin region precedes the task view". Add `INSPECT_ADMIN_CAP` to
    /// `WHY_CAPS`: red on "WHY.ELF holds the admin region".
    #[test]
    fn the_tool_image_holds_the_introspection_regions_after_the_task_view() {
        use azos_abi::cap::CapPerms;
        let topo = default_minimal();
        let public = MaybeStr::from_bytes(b"inspect.public");
        let admin = MaybeStr::from_bytes(b"inspect.admin");
        let want_public = azos_limits::INSPECT && !azos_limits::CONSOLE_LOCKDOWN;
        let want_admin = want_public && azos_limits::INSPECT_ADMIN_PAGES != 0;
        for (i, t) in topo.tasks().iter().enumerate() {
            let caps = topo.caps_of(t);
            let held = |n: MaybeStr| caps.iter().filter(|c| c.kind == CapKind::MemObj && c.target == n).count();
            if t.name == MaybeStr::from_bytes(b"TOOLBOX.ELF") {
                assert_eq!(held(public), want_public as usize, "TOOLBOX.ELF public region");
                assert_eq!(held(admin), want_admin as usize, "TOOLBOX.ELF admin region");
                for c in caps.iter().filter(|c| c.kind == CapKind::MemObj && (c.target == public || c.target == admin)) {
                    assert_eq!((c.perms, c.transfer), (CapPerms::READ.union(CapPerms::MAP), false));
                }
                if want_admin {
                    let at = |f: &dyn Fn(&azos_topology::CapSpec) -> bool| caps.iter().position(|c| f(c)).unwrap();
                    let view = at(&|c| c.kind == CapKind::Domain);
                    let region = at(&|c| c.kind == CapKind::MemObj && c.target == admin);
                    assert!(view < region, "the admin region precedes the task view");
                }
            } else if t.name == MaybeStr::from_bytes(b"WHY.ELF") {
                // `why woke` reads the wake log: the public region, read-only,
                // and not the admin one (no task names, no task view).
                assert_eq!(held(public), want_public as usize, "WHY.ELF public region");
                assert_eq!(held(admin), 0, "WHY.ELF holds the admin region");
                for c in caps.iter().filter(|c| c.kind == CapKind::MemObj && c.target == public) {
                    assert_eq!((c.perms, c.transfer), (CapPerms::READ.union(CapPerms::MAP), false));
                }
                assert!(!caps.iter().any(|c| c.kind == CapKind::Domain), "WHY.ELF holds the task view");
            } else if want_admin
                && (t.name == MaybeStr::from_bytes(b"DECISD.ELF")
                    || t.name == MaybeStr::from_bytes(b"ABICHILD.ELF")
                    || t.name == MaybeStr::from_bytes(b"autorun"))
            {
                // The admin region (decision records, the task list) after the
                // task view, and the public one beside it.
                assert_eq!((held(public), held(admin)), (1, 1), "row {i} regions");
                let at = |f: &dyn Fn(&azos_topology::CapSpec) -> bool| caps.iter().position(|c| f(c)).unwrap();
                assert!(at(&|c| c.kind == CapKind::Domain) < at(&|c| c.kind == CapKind::MemObj && c.target == admin));
            } else {
                assert_eq!(held(public) + held(admin), 0, "row {i} holds an introspection region");
            }
        }
        // No kernel here, no installed minter: the grant is refused, not skipped.
        let tid = crate::cap_seed_bridge_tests::fresh_tid();
        assert!(matches!(
            crate::cap_seed::seed_one_cap_outcome(tid, CapKind::MemObj, CapPerms::READ.union(CapPerms::MAP), "inspect.public"),
            crate::cap_seed::SeedOutcome::Refused
        ));
    }

    /// `POWER.ELF` holds the `power` endpoint RW and the power
    /// monitor (`sensor.9`) READ, and nothing else, is never started by the
    /// kernel, and the shell may start it only off the console lockdown.
    #[test]
    fn the_power_tool_row_holds_power_write_only_and_the_shell_may_launch_it() {
        use azos_abi::cap::CapPerms;
        let topo = default_minimal();
        let pw = topo.find_task(&MaybeStr::from_bytes(b"POWER.ELF")).expect("POWER.ELF row");
        assert!(!pw.start);
        let caps = topo.caps_of(pw);
        // `power`, `sensor.9`, and the `DevicePower` endpoint of each device
        // it manages (`pm_endpoint_tests`).
        assert_eq!(caps.len(), if azos_topology::builder::INADRV_ROW { 4 } else { 3 });
        if cfg!(feature = "power-cap-canary") {
            // The canary keeps the endpoint and takes the right to act away.
            assert_eq!((caps[0].kind, caps[0].perms), (CapKind::Endpoint, CapPerms::READ));
        } else {
            assert_eq!(caps[0].kind, CapKind::Endpoint);
            assert_eq!(caps[0].perms, CapPerms::RW);
            assert_eq!(caps[0].target, MaybeStr::from_bytes(b"power"));
        }
        // The battery model's input: observe only.
        assert_eq!(caps[1].kind, CapKind::Endpoint);
        assert_eq!(caps[1].perms, CapPerms::READ);
        assert_eq!(caps[1].target, MaybeStr::from_bytes(b"sensor.9"));
        let sh = topo.find_task(&MaybeStr::from_bytes(b"SH.ELF")).expect("SH.ELF row");
        let launches_power = topo.caps_of(sh).iter()
            .any(|c| c.kind == CapKind::Node && c.target == MaybeStr::from_bytes(b"POWER.ELF"));
        assert_eq!(launches_power, !azos_limits::CONSOLE_LOCKDOWN,
                   "the shell launches POWER.ELF exactly when the console is not locked down");
    }

    /// Wave 12: the four family tools. BEHAVIOR/CONFIG/OTA hold their own
    /// endpoint RW only; FLIGHT holds the `flight` endpoint and the drivetrain
    /// only under the gate's `flight-tool-drivetrain`, and then the autorun
    /// row does not (one writer per motor, and the topology still admits).
    /// Under
    /// `family-cap-canary` every tool holds its endpoint with `READ` only.
    /// None is started by the kernel; the shell may start each only off the
    /// console lockdown.
    #[test]
    fn the_family_tool_rows_hold_their_family_right_and_the_shell_may_launch_them() {
        use azos_abi::cap::CapPerms;
        let topo = default_minimal();
        let sh = topo.find_task(&MaybeStr::from_bytes(b"SH.ELF")).expect("SH.ELF row");
        for img in [&b"FLIGHT.ELF"[..], b"BEHAVIOR.ELF", b"CONFIG.ELF", b"OTA.ELF"] {
            let row = topo.find_task(&MaybeStr::from_bytes(img)).expect("family tool row");
            assert!(!row.start, "{:?} is started by the kernel", core::str::from_utf8(img));
            let caps = topo.caps_of(row);
            let want_perms = if cfg!(feature = "family-cap-canary") { CapPerms::READ } else { CapPerms::RW };
            if img == b"FLIGHT.ELF" {
                if cfg!(feature = "family-cap-canary") {
                    assert_eq!(caps.len(), 1);
                    assert_eq!((caps[0].kind, caps[0].perms), (CapKind::Endpoint, CapPerms::READ));
                    assert_eq!(caps[0].target, MaybeStr::from_bytes(b"flight"));
                } else if cfg!(feature = "flight-tool-drivetrain") && azos_topology::builder::DRIVETRAIN {
                    // The drivetrain and the endpoint that arms it: flight is
                    // pair-wide (`flight_without_drivetrain`).
                    let mut got: Vec<_> = caps.iter()
                        .map(|c| (c.kind, c.perms, c.target.as_str().to_string())).collect();
                    got.sort_by(|a, b| a.2.cmp(&b.2));
                    assert_eq!(got, [(CapKind::Endpoint, CapPerms::RW, "flight".into()),
                                     (CapKind::Endpoint, CapPerms::RW, "motor.0".into()),
                                     (CapKind::Endpoint, CapPerms::RW, "motor.1".into())]);
                } else {
                    assert!(caps.is_empty(), "the drivetrain is the autorun row's");
                }
            } else {
                let name: &[u8] = match img {
                    b"BEHAVIOR.ELF" => b"behavior",
                    b"CONFIG.ELF" => b"config",
                    _ => b"ota",
                };
                assert_eq!(caps.len(), 1);
                assert_eq!((caps[0].kind, caps[0].perms), (CapKind::Endpoint, want_perms));
                assert_eq!(caps[0].target, MaybeStr::from_bytes(name));
            }
            let launches = topo.caps_of(sh).iter()
                .any(|c| c.kind == CapKind::Node && c.target == MaybeStr::from_bytes(img));
            assert_eq!(launches, !azos_limits::CONSOLE_LOCKDOWN);
        }
        let autorun = topo.find_task(&MaybeStr::from_bytes(b"autorun")).expect("autorun row");
        let autorun_motors = topo.caps_of(autorun).iter().any(|c| c.kind == CapKind::Endpoint && c.target.as_str().starts_with("motor."));
        assert_eq!(autorun_motors,
                   azos_topology::builder::DRIVETRAIN && !cfg!(feature = "flight-tool-drivetrain"));
        assert!(topo.admission_check().is_ok(), "one writer per motor");
    }

    /// Flight is pair-wide: a row holding `WRITE` on the `flight` endpoint
    /// must hold `WRITE` on both wheels; `READ` alone arms nothing.
    ///
    /// **Canary.** Make `flight_without_drivetrain` always `None`: the
    /// one-wheel and no-wheel rows are admitted and this is red.
    #[test]
    #[cfg(feature = "profile-actuation")]
    fn a_row_may_arm_flight_only_with_the_whole_drivetrain() {
        use azos_topology::{parse_caps, AdmissionError, ParseError, Topology};
        let flies = |motors: &str, perm: &str| {
            format!(
                "format = 3\n[task.F.ELF]\ncaps = [ {motors}{{ kind = \"endpoint\", target = \"flight\", perm = \"{perm}\" }} ]\n"
            )
        };
        let m0 = "{ kind = \"endpoint\", target = \"motor.0\", perm = \"rw\" }, ";
        let m1 = "{ kind = \"endpoint\", target = \"motor.1\", perm = \"rw\" }, ";
        let parse = |text: String| {
            let mut topo = Topology::empty();
            parse_caps(text.as_bytes(), &mut topo)
        };
        assert_eq!(parse(flies("", "rw")), Err(ParseError::Admission(AdmissionError::FlightWithoutDrivetrain)));
        assert_eq!(parse(flies(m0, "rw")), Err(ParseError::Admission(AdmissionError::FlightWithoutDrivetrain)));
        assert_eq!(parse(flies(&format!("{m0}{m1}"), "rw")), Ok(()));
        assert_eq!(parse(flies("", "r")), Ok(()), "READ arms nothing");
    }

    /// The Linux driver server skeleton has a row only under
    /// `lx-server`; there it is started, `best_effort`, and holds one
    /// capability, READ on the entropy pool for its allocator (a Linux server
    /// never holds an actuator), and no other row may launch it.
    ///
    /// **Canary.** Give the row a gpio endpoint in `builder.rs`: red under
    /// `--features lx-server`.
    /// **A Linux row reads where it always could and writes only where its
    /// row says.** Every Linux row holds the read-only root directory (its
    /// guest opens `/fat/...` read-only: the personality, or `lxrt` through
    /// `root_dir()`, finds it) and `/tmp` read-write; the only other tree is
    /// `/fat`, read-write, in the gate's `linux-exec-row-test` row. A
    /// read-write `/` would let every guest write the volume.
    ///
    /// **Canary.** Grant `/` read-write (`ROOT_RO` with `CapPerms::RW`): the
    /// write assertion goes red.
    #[test]
    fn linux_rows_hold_the_read_only_root_and_write_only_their_trees() {
        use azos_abi::cap::{CapKind, CapPerms};
        let topo = default_minimal();
        for row in topo.tasks().iter().filter(|r| r.abi == azos_topology::TaskAbi::Linux) {
            let trees: Vec<_> = topo.caps_of(row).iter()
                .filter(|c| c.kind == CapKind::Node && c.target.as_bytes().first() == Some(&b'/'))
                .collect();
            let root = trees.iter().find(|c| c.target.as_bytes() == b"/")
                .unwrap_or_else(|| panic!("{} holds no root directory", row.name.as_str()));
            assert_eq!(root.perms, CapPerms::READ, "{}: the root directory writes", row.name.as_str());
            for c in trees.iter().filter(|c| c.perms.contains(CapPerms::WRITE)) {
                assert!(c.target.as_bytes() == b"/tmp" || c.target.as_bytes() == b"/fat",
                    "{} writes {}", row.name.as_str(), c.target.as_str());
            }
        }
    }

    #[test]
    fn the_linux_server_row_exists_only_under_lx_server_and_holds_only_entropy_read_and_the_root() {
        let topo = default_minimal();
        let row = topo.find_task(&MaybeStr::from_bytes(b"LXSRV.ELF"));
        if !cfg!(feature = "lx-server") {
            assert!(row.is_none(), "a default topology names a Linux server");
            return;
        }
        let lx = row.expect("LXSRV.ELF row under lx-server");
        assert!(lx.start, "the skeleton is started from its row");
        let caps = topo.caps_of(lx);
        assert!(
            caps.len() == 2 && caps[0].kind == CapKind::Endpoint && caps[0].target == MaybeStr::from_bytes(b"entropy")
                && caps[0].perms == CapPerms::READ && !caps[0].transfer
                && caps[1].kind == CapKind::Node && caps[1].target == MaybeStr::from_bytes(b"/")
                && caps[1].perms == CapPerms::READ && !caps[1].transfer,
            "LXSRV.ELF holds {} capabilities, want a non-transferable READ on the entropy pool and the read-only root directory",
            caps.len(),
        );
        // The component manager starts every `start = true` row, this one
        // included (`manager_starts`: one `EXEC` grant per component, nothing
        // wider); no other row holds a grant on the image.
        for t in topo.tasks() {
            let grants = topo.caps_of(t).iter()
                .filter(|c| c.kind == CapKind::Node && c.target == MaybeStr::from_bytes(b"LXSRV.ELF"))
                .collect::<Vec<_>>();
            if t.name.as_bytes() == azos_topology::builder::TASK_COMPMGR_IMAGE {
                assert!(grants.iter().all(|c| c.perms == CapPerms::EXEC && !c.transfer),
                        "COMPMGR.ELF holds more than a launch grant on the Linux server");
            } else {
                assert!(grants.is_empty(), "{} may launch the Linux server", t.name.as_str());
            }
        }
    }
}

// ── Wave 15 TOPOSIGN: the built-in topology as signed files ─────────────────
//
// The emitter (`azos_topology::emit`) writes the topology `builder.rs` builds
// for THIS crate's feature set; the parser must read back the same topology,
// field by field. The gate runs this crate with the board feature set (none)
// and the QEMU one (`cap-refusal-canary,profile-actuation,...`), so both
// shapes round-trip. `topo_emit` runs the same check on every file it writes.
//
// One signature (CAPS.SIG) covers both files: CAPS.TOM (format 4) binds the
// SHA-256 of SCHED.TOM, the device id and a counter (`check_binding`).
//
// Canaries (host bucket), each must fail the named test:
//   --features azos_topology/topo-verify-skip-canary  tampered_caps_is_refused_by_its_signature
//   --features azos_topology/topo-sched-hash-canary   a_swapped_sched_tom_is_refused
//   --features azos_topology/topo-device-canary       another_devices_file_is_refused
//   --features azos_topology/topo-replay-canary       an_older_counter_is_a_replay
#[cfg(test)]
mod signed_topology_tests {
    use azos_abi::cap::CapKind;
    use azos_topology::device_record::{topo_floor_decode, topo_floor_encode};
    use azos_topology::emit::{emit_caps, emit_sched, first_difference, EMIT_FORMAT};
    use azos_topology::parser::cap_kind_word;
    use azos_topology::signed::{
        decide, load_signed, Candidate, DeviceContext, SignedFile, SignedFiles, SignedRefusal,
        SourceAction, SourcePolicy, UNBOUND_COUNTER, UNBOUND_DEVICE, UNBOUND_SCHED,
    };
    use azos_topology::{parse_binding, parse_caps, parse_sched, Binding, ParseError, Topology, VerifyError};
    use ed25519_dalek::{Signer, SigningKey};

    const DEV: [u8; 16] = [0xd0; 16];
    const OTHER: [u8; 16] = [0x0e; 16];

    fn builtin() -> Box<Topology<'static>> {
        let mut t = Box::new(Topology::empty());
        azos_topology::fill_default_minimal(&mut t);
        t
    }

    /// The built-in topology as (CAPS.TOM, SCHED.TOM), bound to `device` and
    /// `counter` and to its own SCHED.TOM.
    fn emitted_bound(t: &Topology<'_>, device: Option<[u8; 16]>, counter: Option<u64>) -> (String, String) {
        let mut sched = String::new();
        emit_sched(t, &mut sched).expect("emit SCHED.TOM");
        let b = Binding {
            format: EMIT_FORMAT,
            device,
            counter,
            sched_sha256: Some(azos_crypto::sha256::sha256(sched.as_bytes())),
        };
        let mut caps = String::new();
        emit_caps(t, &b, &mut caps).expect("emit CAPS.TOM");
        (caps, sched)
    }

    fn emitted(t: &Topology<'_>) -> (String, String) {
        emitted_bound(t, Some(DEV), Some(1))
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x5a; 32])
    }

    fn ctx(floor: u64) -> DeviceContext {
        DeviceContext { device_id: Some(DEV), floor, bind_device: true, enforce_floor: true }
    }

    fn load(caps: &str, sched: &str, c: &DeviceContext) -> Result<Option<u64>, SignedRefusal> {
        let sig = crate::topo_rows::dsig(key().sign(caps.as_bytes()).to_bytes());
        let files = SignedFiles { caps: caps.as_bytes(), caps_sig: &sig, sched: sched.as_bytes() };
        let mut t = Box::new(Topology::empty());
        load_signed(&mut t, &files, key().verifying_key().as_bytes(), c)
    }

    #[test]
    fn builtin_topology_round_trips_through_its_emitted_text() {
        let built = builtin();
        let (caps, sched) = emitted(&built);
        let mut parsed = Box::new(Topology::empty());
        parse_sched(sched.as_bytes(), &mut parsed).expect("SCHED.TOM parses back");
        parse_caps(caps.as_bytes(), &mut parsed).expect("CAPS.TOM parses back");
        parsed.admission_check().expect("the parsed topology is admitted");
        assert_eq!(first_difference(&built, &parsed), None);
        let b = parse_binding(caps.as_bytes()).unwrap();
        assert_eq!((b.format, b.device, b.counter), (8, Some(DEV), Some(1)));
        assert_eq!(b.sched_sha256, Some(azos_crypto::sha256::sha256(sched.as_bytes())));
    }

    /// The comparison itself discriminates: one changed field is found.
    #[test]
    fn first_difference_sees_a_changed_priority() {
        let built = builtin();
        let (caps, sched) = emitted(&built);
        let caps = caps.replacen("priority = 0", "priority = 1", 1);
        let mut parsed = Box::new(Topology::empty());
        parse_sched(sched.as_bytes(), &mut parsed).unwrap();
        parse_caps(caps.as_bytes(), &mut parsed).unwrap();
        assert_eq!(first_difference(&built, &parsed), Some("task priority"));
    }

    /// Every kind the emitter names is the kind the parser reads for it.
    #[test]
    fn every_cap_kind_word_parses_back_to_its_kind() {
        let sched = b"[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";
        let mut named = 0;
        for raw in 0u8..64 {
            let Some(kind) = CapKind::from_raw(raw) else { continue };
            let Some(word) = cap_kind_word(kind) else { continue };
            let text = format!("[task.x]\ncaps = [\n    {{ kind = \"{word}\", target = \"t\", perm = \"r\" }},\n]\n");
            let mut t = Box::new(Topology::empty());
            parse_sched(sched, &mut t).unwrap();
            parse_caps(text.as_bytes(), &mut t).unwrap_or_else(|e| panic!("{word}: {e:?}"));
            assert_eq!(t.caps_of(&t.tasks()[0])[0].kind, kind, "{word}");
            named += 1;
        }
        assert!(named >= 7, "only {named} kinds have a word");
    }

    #[test]
    fn signed_bound_pair_loads_and_equals_the_builtin_topology() {
        let built = builtin();
        let (caps, sched) = emitted_bound(&built, Some(DEV), Some(3));
        let sig = crate::topo_rows::dsig(key().sign(caps.as_bytes()).to_bytes());
        let files = SignedFiles { caps: caps.as_bytes(), caps_sig: &sig, sched: sched.as_bytes() };
        let mut t = Box::new(Topology::empty());
        assert_eq!(load_signed(&mut t, &files, key().verifying_key().as_bytes(), &ctx(3)), Ok(Some(3)));
        assert_eq!(first_difference(&built, &t), None);
    }

    // REQ-015
    /// A one-digit change that still parses and is still admitted: only the
    /// signature can refuse it (the gate's tampered row uses the same edit).
    #[test]
    fn tampered_caps_is_refused_by_its_signature() {
        let (caps, sched) = emitted(&builtin());
        let sig = crate::topo_rows::dsig(key().sign(caps.as_bytes()).to_bytes());
        let tampered = caps.replacen("priority = 16", "priority = 17", 1);
        assert_ne!(tampered, caps, "the built-in topology has a priority-16 row to tamper with");
        let mut probe = Box::new(Topology::empty());
        parse_sched(sched.as_bytes(), &mut probe).unwrap();
        parse_caps(tampered.as_bytes(), &mut probe).expect("the tampered file still parses");
        probe.admission_check().expect("and is still admitted");
        let files = SignedFiles { caps: tampered.as_bytes(), caps_sig: &sig, sched: sched.as_bytes() };
        let mut t = Box::new(Topology::empty());
        assert_eq!(
            load_signed(&mut t, &files, key().verifying_key().as_bytes(), &ctx(0)),
            Err(SignedRefusal::Signature(SignedFile::Caps, VerifyError::InvalidSignature)),
        );
    }

    #[test]
    fn wrong_key_or_short_sidecar_is_refused() {
        let (caps, sched) = emitted(&builtin());
        let sig = crate::topo_rows::dsig(key().sign(caps.as_bytes()).to_bytes());
        let other = SigningKey::from_bytes(&[0x11; 32]);
        let files = SignedFiles { caps: caps.as_bytes(), caps_sig: &sig, sched: sched.as_bytes() };
        let mut t = Box::new(Topology::empty());
        assert_eq!(
            load_signed(&mut t, &files, other.verifying_key().as_bytes(), &ctx(0)),
            Err(SignedRefusal::Signature(SignedFile::Caps, VerifyError::InvalidSignature)),
        );
        let short = SignedFiles { caps_sig: &sig[..sig.len() - 1], ..files };
        let mut t = Box::new(Topology::empty());
        assert_eq!(
            load_signed(&mut t, &short, key().verifying_key().as_bytes(), &ctx(0)),
            Err(SignedRefusal::Signature(SignedFile::Caps, VerifyError::BadSidecar)),
        );
    }

    /// SCHED.TOM is authenticated by the hash in the signed CAPS.TOM: a
    /// different, well-formed SCHED.TOM is refused before it is parsed.
    #[test]
    fn a_swapped_sched_tom_is_refused() {
        let (caps, sched) = emitted(&builtin());
        let swapped = sched.replacen("time_slice_ms = ", "time_slice_ms = 1", 1);
        assert_ne!(swapped, sched);
        assert_eq!(load(&caps, &swapped, &ctx(0)), Err(SignedRefusal::SchedHashMismatch));
        assert_eq!(load(&caps, "[class.x\n", &ctx(0)), Err(SignedRefusal::SchedHashMismatch));
    }

    #[test]
    fn another_devices_file_is_refused() {
        let (caps, sched) = emitted_bound(&builtin(), Some(OTHER), Some(1));
        assert_eq!(load(&caps, &sched, &ctx(0)), Err(SignedRefusal::WrongDevice));
        // Checked when present even if the policy does not require it.
        let lax = DeviceContext { bind_device: false, ..ctx(0) };
        assert_eq!(load(&caps, &sched, &lax), Err(SignedRefusal::WrongDevice));
    }

    #[test]
    fn an_older_counter_is_a_replay() {
        let (caps, sched) = emitted_bound(&builtin(), Some(DEV), Some(1));
        assert_eq!(load(&caps, &sched, &ctx(2)), Err(SignedRefusal::Replay { counter: 1, floor: 2 }));
        assert_eq!(load(&caps, &sched, &ctx(1)), Ok(Some(1)), "a counter equal to the floor loads");
    }

    #[test]
    fn missing_binding_keys_are_refused_by_policy() {
        let built = builtin();
        let (caps, sched) = emitted_bound(&built, None, None);
        assert_eq!(
            load(&caps, &sched, &ctx(0)),
            Err(SignedRefusal::Unbound { missing: UNBOUND_DEVICE | UNBOUND_COUNTER }),
        );
        let lax = DeviceContext { bind_device: false, enforce_floor: false, ..ctx(0) };
        assert_eq!(load(&caps, &sched, &lax), Ok(None));
        // No sched_sha256: never acceptable, SCHED.TOM would be unauthenticated.
        let no_hash: String = caps.lines().filter(|l| !l.starts_with("sched_sha256")).map(|l| format!("{l}\n")).collect();
        assert_eq!(load(&no_hash, &sched, &lax), Err(SignedRefusal::Unbound { missing: UNBOUND_SCHED }));
        // A bound file on a device with no record.
        let (caps, sched) = emitted(&built);
        let unprov = DeviceContext { device_id: None, ..ctx(0) };
        assert_eq!(load(&caps, &sched, &unprov), Err(SignedRefusal::Unprovisioned));
    }

    #[test]
    fn binding_keys_need_format_4_once_and_well_formed() {
        let h = "0".repeat(64);
        assert_eq!(parse_binding(b"format = 3\ncounter = 2\n"), Err(ParseError::FieldNeedsFormat));
        assert_eq!(parse_binding(b"format = 4\ncounter = 2\ncounter = 3\n"), Err(ParseError::BadValue));
        assert_eq!(parse_binding(b"format = 4\ncounter = 0\n"), Err(ParseError::BadValue));
        assert_eq!(parse_binding(b"format = 4\ndevice = \"abcd\"\n"), Err(ParseError::BadValue));
        let ok = format!("format = 4\ncounter = 7\nsched_sha256 = \"{h}\"\n[task.a]\ncounter = 9\n");
        let b = parse_binding(ok.as_bytes()).unwrap();
        assert_eq!((b.counter, b.sched_sha256, b.device), (Some(7), Some([0u8; 32]), None));
        // A repeated key fails the full parse too, not only the binding read.
        let mut t = Box::new(Topology::empty());
        assert_eq!(parse_caps(b"format = 4\ncounter = 2\ncounter = 3\n", &mut t), Err(ParseError::BadValue));
    }

    #[test]
    fn the_topology_floor_record_round_trips() {
        let mut sector = [0u8; 512];
        assert_eq!(topo_floor_decode(&sector), None, "a fresh sector is no record (floor 0)");
        let rec = topo_floor_encode(5);
        sector[..rec.len()].copy_from_slice(&rec);
        assert_eq!(topo_floor_decode(&sector), Some(5));
        sector[6] ^= 1;
        assert_eq!(topo_floor_decode(&sector), None, "a torn record is no record");
    }

    // REQ-015
    #[test]
    fn the_source_policy_table() {
        let bad = SignedRefusal::Signature(SignedFile::Caps, VerifyError::InvalidSignature);
        let fb = SourcePolicy::SignedOrBuiltin { invalid_halts: false };
        let hb = SourcePolicy::SignedOrBuiltin { invalid_halts: true };
        let rq = SourcePolicy::SignedRequired;
        let b = SourcePolicy::Builtin;
        for c in [Candidate::Absent, Candidate::Valid, Candidate::Refused(bad)] {
            assert_eq!(decide(b, c), SourceAction::Builtin);
        }
        assert_eq!(decide(fb, Candidate::Valid), SourceAction::Signed);
        assert_eq!(decide(fb, Candidate::Absent), SourceAction::FallbackMissing);
        assert_eq!(decide(fb, Candidate::Refused(bad)), SourceAction::FallbackInvalid(bad));
        assert_eq!(decide(hb, Candidate::Valid), SourceAction::Signed);
        assert_eq!(decide(hb, Candidate::Absent), SourceAction::FallbackMissing);
        assert_eq!(decide(hb, Candidate::Refused(bad)), SourceAction::HaltInvalid(bad));
        assert_eq!(decide(rq, Candidate::Valid), SourceAction::Signed);
        assert_eq!(decide(rq, Candidate::Absent), SourceAction::HaltMissing);
        assert_eq!(decide(rq, Candidate::Refused(bad)), SourceAction::HaltInvalid(bad));
    }

    #[test]
    fn refusal_codes_name_the_step_and_the_file() {
        assert_eq!(SignedRefusal::Incomplete { present: 0b101 }.code(), 0x1000_0005);
        assert_eq!(SignedRefusal::TooLarge(SignedFile::Sched).code(), 0x2200_0000);
        assert_eq!(SignedRefusal::Signature(SignedFile::Caps, VerifyError::InvalidSignature).code(), 0x3100_0000);
        assert_eq!(SignedRefusal::HugeLeaves.code(), 0x6000_0000);
        assert_eq!(SignedRefusal::SchedHashMismatch.code(), 0x7200_0000);
        assert_eq!(SignedRefusal::WrongDevice.code(), 0x8100_0000);
        assert_eq!(SignedRefusal::Replay { counter: 1, floor: 2 }.code(), 0x9100_0001);
        assert_eq!(SignedRefusal::Replay { counter: u64::MAX, floor: 2 }.code(), 0x91FF_FFFF);
        assert_eq!(SignedRefusal::Unbound { missing: UNBOUND_DEVICE }.code(), 0xA100_0001);
        assert_eq!(SignedRefusal::Unprovisioned.code(), 0xB000_0000);
    }
}

#[cfg(test)]
mod imports_tests {
    use azos_topology::{parse_caps, parse_sched, AdmissionError, ParseError, Topology};

    const SCHED: &[u8] = b"[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";

    /// A name server row (serves `names`, holds `term` and `log` lendable
    /// to others) and a client that imports from it.
    fn file(format: u8, client_imports: &str) -> &'static str {
        Box::leak(format!(
            "format = {format}\n\
[task.NAMESD.ELF]\ncaps = [\n\
  {{ kind = \"endpoint\", target = \"endpoint.names\", perm = \"r\" }},\n\
  {{ kind = \"endpoint\", target = \"endpoint.term\", perm = \"w\", transfer = true }},\n\
  {{ kind = \"endpoint\", target = \"endpoint.log\", perm = \"w\", transfer = true }},\n\
  {{ kind = \"endpoint\", target = \"endpoint.kept\", perm = \"w\" }},\n\
]\n\
[task.SH.ELF]\n{client_imports}caps = []\n"
        ).into_boxed_str())
    }

    fn parse(text: &str) -> (Topology<'_>, Result<(), ParseError>) {
        let mut t = Topology::empty();
        parse_sched(SCHED, &mut t).unwrap();
        let r = parse_caps(text.as_bytes(), &mut t);
        (t, r)
    }

    /// **`imports` is a format-5 key** that lists, in a row, the endpoint
    /// names the name server may hand it. The parser records them per row
    /// and resets at each new row.
    ///
    /// **Canaries.** Make the parser skip `set_last_task_imports`: the list
    /// is empty and the first assertion goes red. Accept the key below
    /// format 5: the `FieldNeedsFormat` assertion goes red.
    #[test]
    fn imports_parse_in_format_5_per_row() {
        let text = file(5, "imports = [\"term\", \"log\"]\n");
        let (t, r) = parse(&text);
        assert_eq!(r, Ok(()));
        assert_eq!(t.admission_check(), Ok(()));
        let sh = &t.tasks()[1];
        let names: Vec<&[u8]> = t.imports_of(sh).iter().map(|n| n.as_bytes()).collect();
        assert_eq!(names, [&b"term"[..], &b"log"[..]]);
        // The server row, declared first, imports nothing.
        assert!(t.imports_of(&t.tasks()[0]).is_empty());
        assert_eq!(t.names_server_row(), Some(0));

        // A row after the client does not inherit its list.
        let text = format!("{}[task.NEXT.ELF]\ncaps = []\n", file(5, "imports = [\"term\"]\n")).leak();
        let (t, r) = parse(text);
        assert_eq!(r, Ok(()));
        assert!(t.imports_of(&t.tasks()[2]).is_empty());

        // The last row's list is committed too, and an empty list is none.
        let (t, _) = parse(&file(5, "imports = []\n"));
        assert!(t.imports_of(&t.tasks()[1]).is_empty());

        // Below format 5 the key is refused, not read.
        for f in 1..=4u8 {
            let (_, r) = parse(&file(f, "imports = [\"term\"]\n"));
            assert_eq!(r, Err(ParseError::FieldNeedsFormat), "format {f}");
        }
    }

    /// **A name is never authority: an import must be something the name
    /// server's row can lend**, a `WRITE` grant with `transfer = true` and no
    /// `READ`. Admission refuses a typo, a name the server holds but may not
    /// give away, the server's own `names`, and any import at all when no row
    /// serves `endpoint.names`.
    ///
    /// **Canary.** Skip the imports loop in `admission_check`: every
    /// assertion below goes red.
    #[test]
    fn an_import_the_server_cannot_lend_is_refused_at_admission() {
        for bad in ["typo", "kept", "names"] {
            let (t, r) = parse(&file(5, &format!("imports = [\"{bad}\"]\n")));
            assert_eq!(r, Ok(()), "{bad} parses; admission decides");
            assert_eq!(t.admission_check(), Err(AdmissionError::UnknownImport), "{bad}");
        }
        // No name server at all.
        let (t, r) = parse("format = 5\n[task.SH.ELF]\nimports = [\"term\"]\ncaps = []\n");
        assert_eq!(r, Ok(()));
        assert_eq!(t.admission_check(), Err(AdmissionError::UnknownImport));
        // A server whose `names` grant is also `READ` + `WRITE` is still the server.
        let (t, _) = parse(&file(5, "imports = [\"term\"]\n"));
        assert!(t.names_server_exports(b"term"));
        assert!(!t.names_server_exports(b"kept"));
    }

    /// The shape of a name: the alphabet of an endpoint name, once per row,
    /// at most `MAX_IMPORTS` of them.
    ///
    /// **Canary.** Loosen `import_name_ok` to accept `.`: `a.b` goes green
    /// and the assertion goes red.
    #[test]
    fn a_malformed_import_is_refused_when_the_row_is_committed() {
        for bad in ["a.b", "", "x y", "/etc/passwd", "0123456789012345678901234"] {
            let (_, r) = parse(&file(5, &format!("imports = [\"{bad}\"]\n")));
            assert_eq!(r, Err(ParseError::Admission(AdmissionError::BadImport)), "{bad:?}");
        }
        let (_, r) = parse(&file(5, "imports = [\"term\", \"term\"]\n"));
        assert_eq!(r, Err(ParseError::Admission(AdmissionError::BadImport)), "a repeat");
        let many: Vec<String> = (0..azos_topology::MAX_IMPORTS + 1).map(|i| format!("\"n{i}\"")).collect();
        let (_, r) = parse(&file(5, &format!("imports = [{}]\n", many.join(", "))));
        assert_eq!(r, Err(ParseError::Admission(AdmissionError::TooManyImports)));
        // Syntax: a list, closed, comma-separated.
        for bad in ["imports = \"term\"\n", "imports = [\"term\"\n", "imports = [\"term\" \"log\"]\n",
                    "imports = [\"term\"] x\n", "imports = [term]\n"] {
            let (_, r) = parse(&file(5, bad));
            assert!(r.is_err(), "{bad:?}");
        }
    }

    /// The emitter writes the list and the round trip keeps it: a signed
    /// file regenerated from a topology says the same thing.
    ///
    /// **Canary.** Drop the `imports` line from `emit_caps`: the round trip
    /// differs in "task imports" and this goes red.
    #[test]
    fn the_emitter_round_trips_imports() {
        use azos_topology::emit::{emit_caps, emit_sched, first_difference};
        use azos_topology::Binding;
        let (t, r) = parse(&file(5, "imports = [\"term\", \"log\"]\n"));
        assert_eq!(r, Ok(()));
        let mut caps = String::new();
        emit_caps(&t, &Binding::default(), &mut caps).unwrap();
        assert!(caps.contains("imports = [\"term\", \"log\"]"), "{caps}");
        let mut sched = String::new();
        emit_sched(&t, &mut sched).unwrap();
        let mut back = Topology::empty();
        parse_caps(caps.as_bytes(), &mut back).unwrap();
        // The classes live in SCHED.TOML; the rows are what is compared here.
        assert_ne!(first_difference(&t, &back), Some("task imports"));
    }
}

/// The kernel half of the Names object, with the real capability tables: what
/// the name server's lookup reply does to the warrant tree. (The server's own
/// decision and refusal record are `tests/host/names-tests`.)
#[cfg(test)]
mod names_tests {
    use crate::cap::{targets, Cap, CapError};
    use crate::cap_seed::{seed_names_import, seed_one_cap_outcome, SeedOutcome};
    use crate::cap_store::{self, CapXfer};
    use crate::endpoint;
    use azos_abi::cap::{CapHandle, CapKind, CapPerms};

    /// The name server's endpoint is spelled in two crates that cannot see
    /// each other (the topology's and the seeder's): one test pins them.
    #[test]
    fn the_name_servers_endpoint_is_spelled_alike_on_both_sides() {
        assert_eq!(azos_topology::NAMES_ENDPOINT, crate::cap_seed::NAMES_ENDPOINT);
    }

    fn pool_index(name: &[u8]) -> u32 {
        (0..endpoint::MAX_ENDPOINTS as u32)
            .find(|&i| matches!(endpoint::endpoint_name_owner(i as usize), Some((n, l, _)) if &n[..l] == name))
            .expect("the endpoint exists")
    }

    /// **A lent endpoint is a derived, attenuated child of the server's.** The
    /// reply of `Names::lookup` is a DUP transfer with explicit rights out of
    /// the name server's table into the borrower's: the borrower holds the
    /// call right and nothing else, can call the service, cannot pass the
    /// capability on, cannot widen it, sits one link below the server's in the
    /// warrant tree, and loses it when the server's is revoked.
    ///
    /// **Canaries.** Transfer with `rights: None`: the borrower holds `WRITE |
    /// DUP` and the equality and the regift assertions go red. Transfer as a
    /// MOVE (`dup: false`): the server's own capability goes stale and the
    /// revoke assertion at the end has nothing to revoke. Skip the revoke of
    /// the server's capability: the last assertion goes red.
    #[test]
    fn a_lent_endpoint_is_a_child_with_the_call_right_only() {
        let _g = crate::harness::serial();
        endpoint::__endpoint_reset_for_tests();
        let (term, namesd, client, other) = (
            super::cap_seed_bridge_tests::fresh_tid(),
            super::cap_seed_bridge_tests::fresh_tid(),
            super::cap_seed_bridge_tests::fresh_tid(),
            super::cap_seed_bridge_tests::fresh_tid(),
        );
        // The rows: TERMD serves `term`; NAMESD serves `names` and holds `term`
        // with `transfer = true` (so DUP); the shell holds its badged `names`.
        assert!(matches!(seed_one_cap_outcome(term, CapKind::Endpoint, CapPerms::READ, "endpoint.term"), SeedOutcome::Minted(_)));
        assert!(matches!(seed_one_cap_outcome(namesd, CapKind::Endpoint, CapPerms::READ, "endpoint.names"), SeedOutcome::Minted(_)));
        let SeedOutcome::Minted(held) = seed_one_cap_outcome(
            namesd, CapKind::Endpoint, CapPerms::WRITE.union(CapPerms::DELEGATE), "endpoint.term",
        ) else { panic!("namesd's term grant") };
        assert!(matches!(seed_names_import(client, 7), SeedOutcome::Minted(_)));
        // The shell cannot call `term` by itself: it holds no capability on it.
        let term_idx = pool_index(b"term");
        assert!(cap_store::with_table(client, |t| t.lookup(crate::cap::ty::ENDPOINT, term_idx)).flatten().is_none());

        // The lookup reply: a DUP copy with the call right only.
        let mut out = [CapHandle(0); 1];
        let x = CapXfer { rights: Some(CapPerms::WRITE), ..CapXfer::new(held, true) };
        assert_eq!(cap_store::move_caps(namesd, client, &[x], true, &mut out), Ok(1));
        let lent = out[0];

        let (kind, perms, _) = cap_store::with_table(client, |t| t.peek_raw(lent)).flatten().unwrap();
        assert_eq!(kind, crate::cap::ty::ENDPOINT);
        assert_eq!(perms, CapPerms::WRITE, "the call right and nothing else");
        // It reaches the service the server holds, by capability.
        assert_eq!(endpoint::endpoint_dest_for(client, lent.as_raw()), Ok(term));
        // One link below the server's in the warrant tree.
        let w = cap_store::with_table(client, |t| t.warrant_of(lent)).flatten().unwrap();
        assert_eq!(w.depth, 1);
        assert_ne!(w.parent, 0, "a derived warrant names its parent");
        // The server kept its own.
        assert!(cap_store::with_table(namesd, |t| t.peek_raw(held)).flatten().is_some());

        // Not giftable, not widenable.
        let again = CapXfer::new(lent, true);
        assert_eq!(cap_store::move_caps(client, other, &[again], true, &mut out), Err(CapError::MissingPerms));
        let widen = CapXfer { rights: Some(CapPerms::RW), ..CapXfer::new(held, true) };
        assert_eq!(cap_store::move_caps(namesd, client, &[widen], true, &mut out), Err(CapError::MissingPerms));

        // Revoking the server's capability takes the borrowed one with it.
        cap_store::revoke(namesd, Cap::<targets::Endpoint>::from_raw(held));
        assert!(endpoint::endpoint_dest_for(client, lent.as_raw()).is_err(), "the child outlived its parent");
    }
}

/// The `neverallow` rules (`azos_topology::neverallow`): what each forbids,
/// that the exceptions stay as narrow as the table says, that the built-in
/// topology of every feature set the host rows build passes, and that
/// `admission_check` is where a violation is refused.
///
/// **Canary** (`--features neverallow-canary`, `neverallow::check` finds
/// nothing): `each_rule_refuses_its_grant`,
/// `an_exception_covers_its_rule_its_row_and_its_grants_only`,
/// `the_listed_rows_hold_only_their_own_actuators`,
/// `admission_check_refuses_a_row_a_rule_forbids` and
/// `a_desktop_image_grants_no_motor` go red, and nothing else does.
#[cfg(test)]
mod neverallow_tests {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::neverallow::{self, Env, NeverallowRefusal, RULES};
    use azos_topology::{default_minimal, AdmissionError, CapSpec, MaybeStr, Topology};

    const SERVER: Env = Env { desktop: false };
    const DESKTOP: Env = Env { desktop: true };

    fn cap(kind: CapKind, perms: CapPerms, target: &'static [u8]) -> CapSpec<'static> {
        CapSpec { kind, perms, target: MaybeStr::from_bytes(target), transfer: false, ops: 0 }
    }

    /// A topology of exactly one row.
    fn one_row(name: &'static [u8], caps: &[CapSpec<'static>]) -> Box<Topology<'static>> {
        let mut t = Box::new(Topology::empty());
        t.push_task(MaybeStr::from_bytes(name), MaybeStr::from_bytes(b"best_effort"), 0, caps).unwrap();
        t
    }

    fn rule(id: &str) -> u8 {
        RULES.iter().position(|r| r.id == id).unwrap_or_else(|| panic!("no rule {id}")) as u8
    }

    fn refusal(t: &Topology<'_>, env: &Env) -> Option<NeverallowRefusal> {
        neverallow::check(t, env).err()
    }

    /// The table is well formed: ids are unique, every rule has a statement,
    /// every exception names a row and says why, and a rule's exceptions do
    /// not repeat.
    #[test]
    fn the_table_is_well_formed() {
        for (i, r) in RULES.iter().enumerate() {
            assert!(!r.id.is_empty() && !r.text.is_empty(), "rule {i} is unnamed");
            assert_eq!(rule(r.id) as usize, i, "{} is found at its own index", r.id);
            assert!(RULES[..i].iter().all(|o| o.id != r.id), "{} is listed twice", r.id);
            for (j, e) in r.exceptions.iter().enumerate() {
                assert!(!e.row.is_empty(), "{}: an exception names no row", r.id);
                assert!(e.reason.len() >= 20, "{}: the exception for {} gives no reason", r.id, e.row);
                assert!(!e.permits.is_empty(), "{}: the exception for {} permits no grant", r.id, e.row);
                for (k, p) in e.permits.iter().enumerate() {
                    assert!(!p.target.is_empty(), "{}: {} permits a {:?} with no target", r.id, e.row, p.kind);
                    assert!(
                        e.permits[..k].iter().all(|o| !(o.kind == p.kind && o.target == p.target)),
                        "{}: {} permits {:?} {} twice", r.id, e.row, p.kind, p.target,
                    );
                }
                assert!(r.exceptions[..j].iter().all(|o| o.row != e.row), "{}: {} listed twice", r.id, e.row);
            }
        }
    }

    /// The built-in topology of this feature set breaks no rule, as a server
    /// and as a desktop (a desktop only if the build declares no drivetrain,
    /// which is what Kconfig `TOPOLOGY_DRIVETRAIN` is for).
    #[test]
    fn the_built_in_topology_breaks_no_rule() {
        let t = default_minimal();
        assert_eq!(neverallow::check(&t, &SERVER), Ok(()));
        let in_desktop = neverallow::check(&t, &DESKTOP);
        if azos_topology::builder::DRIVETRAIN {
            let r = in_desktop.unwrap_err();
            assert_eq!(r.rule, rule("desktop-grants-no-motor"));
            assert_eq!(r.kind, CapKind::Endpoint.denial_code());
        } else {
            assert_eq!(in_desktop, Ok(()));
        }
        // The environment the build says it is: `topo_neverallow` and the
        // kernel both read it.
        assert_eq!(neverallow::check(&t, &Env::BUILD), Ok(()));
    }

    /// Rule 0: a ring-3 row holds an actuator only if it is listed.
    #[test]
    fn each_rule_refuses_its_grant() {
        // actuation-outside-actuation-row: a motor, a PWM or GPIO write, the buzzer.
        for (kind, perms, target) in [
            (CapKind::Endpoint, CapPerms::RW, &b"motor.2"[..]),
            (CapKind::Endpoint, CapPerms::WRITE, b"pwm.6"),
            (CapKind::Endpoint, CapPerms::RW, b"gpio.21"),
            (CapKind::Endpoint, CapPerms::WRITE, b"pwm.5"),
        ] {
            let t = one_row(b"STRANGER.ELF", &[cap(CapKind::Endpoint, CapPerms::READ, b"sensor.0"), cap(kind, perms, target)]);
            assert_eq!(
                refusal(&t, &SERVER),
                Some(NeverallowRefusal { rule: 0, row: 0, kind: kind.denial_code(), grant: 1 }),
                "{kind:?}",
            );
        }
        // Reading a pin or a channel moves nothing.
        let t = one_row(b"STRANGER.ELF", &[cap(CapKind::Endpoint, CapPerms::READ, b"pwm.6"), cap(CapKind::Endpoint, CapPerms::READ, b"gpio.21")]);
        assert_eq!(refusal(&t, &SERVER), None);
        // A kernel task is not a ring-3 row.
        let t = one_row(b"kernel_task", &[cap(CapKind::Endpoint, CapPerms::RW, b"motor.2")]);
        assert_eq!(refusal(&t, &SERVER), None);

        // names-import-and-service-export.
        for (kind, perms, target, refused) in [
            (CapKind::Endpoint, CapPerms::READ, &b"endpoint.svc"[..], true),
            (CapKind::Device, CapPerms::RW, b"drv.20", true),
            (CapKind::Endpoint, CapPerms::WRITE, b"endpoint.svc", false),
            // READ on a kernel-hosted interface is a client's grant: the
            // kernel serves `net` and `clock`, the row only calls them.
            (CapKind::Endpoint, CapPerms::READ, b"net", false),
            (CapKind::Endpoint, CapPerms::READ, b"clock", false),
        ] {
            let mut t = one_row(b"CLIENT.ELF", &[cap(kind, perms, target)]);
            t.set_last_task_imports(&[MaybeStr::from_bytes(b"term")]).unwrap();
            let want = refused.then_some(NeverallowRefusal {
                rule: rule("names-import-and-service-export"), row: 0, kind: kind.denial_code(), grant: 0,
            });
            assert_eq!(refusal(&t, &SERVER), want, "{kind:?} {perms:?}");
            // The same grant without the import is fine.
            let t = one_row(b"CLIENT.ELF", &[cap(kind, perms, target)]);
            assert_eq!(refusal(&t, &SERVER), None, "{kind:?} without an import");
        }

        // actuation-grant-not-transferable (a kernel row, so rule 0 stays out of it).
        let mut moto = cap(CapKind::Endpoint, CapPerms::RW, b"motor.2");
        moto.transfer = true;
        let t = one_row(b"kernel_task", &[moto]);
        assert_eq!(refusal(&t, &SERVER).map(|r| r.rule), Some(rule("actuation-grant-not-transferable")));
        let mut sensor = cap(CapKind::Endpoint, CapPerms::READ, b"sensor.0");
        sensor.transfer = true;
        assert_eq!(refusal(&one_row(b"kernel_task", &[sensor]), &SERVER), None);
        // The `t` letter of `perm` is the same right as `transfer = true`; `d` alone (a
        // copy that cannot leave the table) and `m` are not TRANSFER.
        for (perms, refused) in [
            (CapPerms::RW.union(CapPerms::TRANSFER), true),
            (CapPerms::RW.union(CapPerms::DUP), false),
            (CapPerms::RW, false),
        ] {
            let t = one_row(b"kernel_task", &[cap(CapKind::Endpoint, perms, b"motor.2")]);
            assert_eq!(
                refusal(&t, &SERVER).map(|r| r.rule),
                refused.then(|| rule("actuation-grant-not-transferable")),
                "{perms:?}"
            );
        }
    }

    /// Rule 1 depends on the environment, and on nothing but the motor.
    #[test]
    fn a_desktop_image_grants_no_motor() {
        let t = one_row(b"kernel_task", &[cap(CapKind::Endpoint, CapPerms::READ, b"motor.2")]);
        assert_eq!(refusal(&t, &SERVER), None, "a server may hold one");
        assert_eq!(
            refusal(&t, &DESKTOP),
            Some(NeverallowRefusal { rule: rule("desktop-grants-no-motor"), row: 0, kind: CapKind::Endpoint.denial_code(), grant: 0 }),
        );
        // Even an actuation row: the exception of rule 0 is not one of rule 1.
        let t = one_row(b"autorun", &[cap(CapKind::Endpoint, CapPerms::RW, b"motor.0")]);
        assert_eq!(refusal(&t, &SERVER), None);
        assert_eq!(refusal(&t, &DESKTOP).map(|r| r.rule), Some(rule("desktop-grants-no-motor")));
        let t = one_row(b"autorun", &[cap(CapKind::Endpoint, CapPerms::RW, b"pwm.4")]);
        assert_eq!(refusal(&t, &DESKTOP), None, "a PWM channel is not a motor");
    }

    /// An exception lifts its own rule for its own row and for the grants it
    /// lists, nothing wider: each permitted grant passes on that row, a row
    /// that merely shares a prefix is refused, the permitted grant does not
    /// escape rule 3, and the same row holding any other kind of actuator, or
    /// the same kind on another target, is refused.
    #[test]
    fn an_exception_covers_its_rule_its_row_and_its_grants_only() {
        let r0 = &RULES[rule("actuation-outside-actuation-row") as usize];
        assert!(!r0.exceptions.is_empty());
        let leak = |s: &str| -> &'static [u8] { Box::leak(s.as_bytes().to_vec().into_boxed_slice()) };
        // Every actuator of every kind that is not among a row's permits.
        let actuators: [(CapKind, &'static [u8]); 7] = [
            (CapKind::Endpoint, b"motor.0"), (CapKind::Endpoint, b"motor.1"), (CapKind::Endpoint, b"motor.2"),
            (CapKind::Endpoint, b"pwm.4"), (CapKind::Endpoint, b"pwm.5"),
            (CapKind::Endpoint, b"gpio.20"), (CapKind::Endpoint, b"gpio.21"),
        ];
        for e in r0.exceptions {
            let name = leak(e.row);
            let other = if e.row.ends_with(".ELF") { format!("X{}", e.row) } else { "OTHER.ELF".to_string() };
            let other = leak(&other);
            for p in e.permits {
                let target = leak(p.target);
                let t = one_row(name, &[cap(p.kind, CapPerms::RW, target)]);
                assert_eq!(refusal(&t, &SERVER), None, "{} may hold {:?} {}", e.row, p.kind, p.target);
                let mut moved = cap(p.kind, CapPerms::RW, target);
                moved.transfer = true;
                assert_eq!(
                    refusal(&one_row(name, &[moved]), &SERVER).map(|r| r.rule),
                    Some(rule("actuation-grant-not-transferable")),
                    "{}: the exception is rule 0's alone", e.row,
                );
                // Another ring-3 row, the nearest one the name allows.
                let t = one_row(other, &[cap(p.kind, CapPerms::RW, target)]);
                assert_eq!(refusal(&t, &SERVER).map(|r| r.rule), Some(0), "a row beside {}", e.row);
            }
            // Every actuator the row is not permitted is refused, and the
            // refusal names the grant (after a permitted one).
            for (kind, target) in actuators {
                let permitted = e.permits.iter().any(|p| p.kind == kind && p.target.as_bytes() == target);
                let first = e.permits[0];
                let t = one_row(name, &[cap(first.kind, CapPerms::RW, leak(first.target)), cap(kind, CapPerms::RW, target)]);
                let want = (!permitted).then_some(NeverallowRefusal { rule: 0, row: 0, kind: kind.denial_code(), grant: 1 });
                assert_eq!(refusal(&t, &SERVER), want, "{} holding {:?} {}", e.row, kind, String::from_utf8_lossy(target));
            }
        }
    }

    /// The three names the table lists are each narrow, spelled out: a motor
    /// on the buzzer driver, the buzzer on the flight tool, a second motor on
    /// the flight tool and the buzzer's channel on autorun are all refused.
    #[test]
    fn the_listed_rows_hold_only_their_own_actuators() {
        for (row, kind, target, refused) in [
            (&b"BUZZDRV.ELF"[..], CapKind::Endpoint, &b"pwm.5"[..], false),
            (b"BUZZDRV.ELF", CapKind::Endpoint, b"motor.0", true),
            (b"BUZZDRV.ELF", CapKind::Endpoint, b"pwm.4", true),
            (b"BUZZDRV.ELF", CapKind::Endpoint, b"gpio.20", true),
            (b"FLIGHT.ELF", CapKind::Endpoint, b"motor.1", false),
            (b"FLIGHT.ELF", CapKind::Endpoint, b"motor.2", true),
            (b"FLIGHT.ELF", CapKind::Endpoint, b"pwm.5", true),
            (b"autorun", CapKind::Endpoint, b"gpio.20", false),
            (b"autorun", CapKind::Endpoint, b"pwm.5", true),
            (b"autorun", CapKind::Endpoint, b"motor.2", true),
        ] {
            let t = one_row(row, &[cap(kind, CapPerms::RW, target)]);
            let want = refused.then_some(NeverallowRefusal { rule: 0, row: 0, kind: kind.denial_code(), grant: 0 });
            assert_eq!(
                refusal(&t, &SERVER), want,
                "{} holding {:?} {}", String::from_utf8_lossy(row), kind, String::from_utf8_lossy(target),
            );
        }
    }

    /// `admission_check` is where a topology is refused, with the refusal the
    /// kernel records, and the decision follows Kconfig `TOPOLOGY_NEVERALLOW`.
    #[test]
    fn admission_check_refuses_a_row_a_rule_forbids() {
        let mut t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        let row = t.tasks_len() as u16;
        t.push_task(
            MaybeStr::from_bytes(b"STRANGER.ELF"),
            MaybeStr::from_bytes(b"best_effort"),
            0,
            &[cap(CapKind::Endpoint, CapPerms::RW, b"pwm.6")],
        )
        .unwrap();
        let want = if azos_limits::TOPOLOGY_NEVERALLOW {
            Err(AdmissionError::Neverallow(NeverallowRefusal { rule: 0, row, kind: CapKind::Endpoint.denial_code(), grant: 0 }))
        } else {
            Ok(())
        };
        assert_eq!(t.admission_check(), want);
        // The rules themselves do not look at the option.
        assert_eq!(refusal(&t, &SERVER).map(|r| (r.rule, r.row)), Some((0, row)));
    }
}

#[cfg(test)]
mod device_rows_tests {
    use azos_topology::emit::{emit_caps, first_difference};
    use azos_topology::{parse_caps, parse_sched, AdmissionError, Binding, ParseError, Topology};

    const SCHED: &[u8] = b"[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";

    fn parse(text: &str) -> (Topology<'_>, Result<(), ParseError>) {
        let mut t = Topology::empty();
        parse_sched(SCHED, &mut t).unwrap();
        let r = parse_caps(text.as_bytes(), &mut t);
        (t, r)
    }

    /// **`[device.NAME]` is a format-6 section**: what the hardware bus does
    /// with the devices `match` selects. `admit` defaults to true; `driver`
    /// names another native driver for them.
    ///
    /// **Canary.** Make `commit_device` skip `push_device`: the rows are
    /// empty and the first assertion goes red.
    #[test]
    fn device_rows_parse_in_format_6() {
        let text = "format = 6\n\
[device.nic]\nmatch = \"pci:1af4:1041\"\n\
[device.disk]\nmatch = \"virtio:2\"\ndriver = \"virtio-blk\"\n\
[device.uart]\nmatch = \"dt:ns16550a\"\nadmit = false\n\
[task.A.ELF]\ncaps = []\n";
        let (t, r) = parse(text);
        assert_eq!(r, Ok(()));
        let d = t.devices();
        assert_eq!(d.len(), 3);
        assert_eq!((d[0].name.as_str(), d[0].select.as_str(), d[0].admit, d[0].driver.as_str()),
                   ("nic", "pci:1af4:1041", true, ""));
        assert_eq!((d[1].select.as_str(), d[1].driver.as_str()), ("virtio:2", "virtio-blk"));
        assert!(!d[2].admit);
        // The task after the sections is still read.
        assert_eq!(t.tasks().len(), 1);
    }

    /// An earlier format's writer did not mean the section.
    #[test]
    fn a_device_section_below_format_6_is_refused() {
        for f in 1..=5u8 {
            let (_, r) = parse(&format!("format = {f}\n[device.nic]\nmatch = \"virtio:2\"\n"));
            assert_eq!(r, Err(ParseError::FieldNeedsFormat), "format {f}");
        }
    }

    /// A row that selects nothing, a selector the bus cannot read, a name
    /// twice, a refusal that also names a driver: all refused, none read as
    /// "every device".
    #[test]
    fn a_malformed_device_row_is_refused() {
        let cases: [(&str, ParseError); 7] = [
            ("[device.a]\n", ParseError::MissingField),
            ("[device.a]\nmatch = \"usb:1:2\"\n", ParseError::Admission(AdmissionError::BadDevice)),
            ("[device.a]\nmatch = \"pci:zz:1\"\n", ParseError::Admission(AdmissionError::BadDevice)),
            ("[device.a]\nmatch = \"virtio:2\"\n[device.a]\nmatch = \"virtio:1\"\n",
             ParseError::Admission(AdmissionError::DuplicateDevice)),
            ("[device.a]\nmatch = \"virtio:2\"\nadmit = false\ndriver = \"x\"\n",
             ParseError::Admission(AdmissionError::BadDevice)),
            ("[device.a]\nmatch = \"virtio:2\"\nmatch = \"virtio:1\"\n", ParseError::BadValue),
            ("[device.a]\nmatch = \"virtio:2\"\nspeed = 3\n", ParseError::UnknownField),
        ];
        for (body, want) in cases {
            let (_, r) = parse(&format!("format = 6\n{body}"));
            assert_eq!(r, Err(want), "{body:?}");
        }
        let many: String = (0..azos_topology::MAX_DEVICE_ROWS + 1)
            .map(|i| format!("[device.d{i}]\nmatch = \"virtio:{i}\"\n"))
            .collect();
        let (_, r) = parse(&format!("format = 6\n{many}"));
        assert_eq!(r, Err(ParseError::Admission(AdmissionError::DuplicateDevice)), "one past the table");
    }

    /// The emitter writes the rows the parser reads, and `first_difference`
    /// sees a changed one.
    #[test]
    fn device_rows_round_trip_through_the_emitter() {
        let text = "format = 6\n[device.nic]\nmatch = \"pci:1af4:1041\"\n\
[device.uart]\nmatch = \"dt:ns16550a\"\nadmit = false\n[device.x]\nmatch = \"virtio:3\"\ndriver = \"other\"\n";
        let (t, r) = parse(text);
        assert_eq!(r, Ok(()));
        let mut out = String::new();
        emit_caps(&t, &Binding::default(), &mut out).unwrap();
        let out: &str = Box::leak(out.into_boxed_str());
        let (back, r) = parse(out);
        assert_eq!(r, Ok(()));
        assert_eq!(first_difference(&t, &back), None);
        let other = "format = 6\n[device.nic]\nmatch = \"pci:1af4:1042\"\n\
[device.uart]\nmatch = \"dt:ns16550a\"\nadmit = false\n[device.x]\nmatch = \"virtio:3\"\ndriver = \"other\"\n";
        let (changed, _) = parse(other);
        assert_eq!(first_difference(&t, &changed), Some("device row"));
    }

    /// `lx_class` marks a row as the server of a Linux driver class (format 6):
    /// a lower-case word, once, in a file of format 6.
    #[test]
    fn a_row_may_name_the_linux_class_it_serves() {
        let ok = "format = 6\n[task.LXUSB.ELF]\nstart = true\nlx_class = \"usb\"\ncaps = []\n\
[task.OTHER.ELF]\ncaps = []\n";
        let (t, r) = parse(ok);
        assert_eq!(r, Ok(()));
        assert_eq!(t.tasks()[0].lx_class.as_str(), "usb");
        assert!(t.tasks()[1].lx_class.is_empty(), "the next row does not inherit it");
        // Round trip.
        let mut out = String::new();
        emit_caps(&t, &Binding::default(), &mut out).unwrap();
        assert!(out.contains("lx_class = \"usb\""), "{out}");
        let out: &str = Box::leak(out.into_boxed_str());
        let (back, r) = parse(out);
        assert_eq!(r, Ok(()));
        assert_eq!(first_difference(&t, &back), None);
        // Below format 6 the key is refused, not read.
        for f in 1..=5u8 {
            let (_, r) = parse(&format!("format = {f}\n[task.A.ELF]\nlx_class = \"usb\"\ncaps = []\n"));
            assert_eq!(r, Err(ParseError::FieldNeedsFormat), "format {f}");
        }
        // A class is a word.
        for bad in ["", "USB", "u sb", "usb/1", "0123456789012345678901234567890123"] {
            let (_, r) = parse(&format!("format = 6\n[task.A.ELF]\nlx_class = \"{bad}\"\ncaps = []\n"));
            assert!(r.is_err(), "{bad:?} must not parse");
        }
    }

    /// The built-in rows of the QEMU build admit what its drivers bind, and
    /// nothing else; the plain (board) build lists none.
    #[test]
    fn the_builtin_topology_admits_the_qemu_devices_only_in_the_qemu_build() {
        use azos_topology::builder::{default_minimal, BUILTIN_DEVICE_ROWS};
        let t = default_minimal();
        if cfg!(feature = "qemu-devices") {
            assert_eq!(t.devices().len(), BUILTIN_DEVICE_ROWS.len());
            assert!(t.devices().iter().any(|d| d.select.as_str() == "virtio:2" && d.admit),
                    "the boot disk is admitted");
            assert!(t.devices().iter().all(|d| azos_hwbus::Pattern::parse(d.select.as_str()).is_some()));
        } else {
            assert!(t.devices().is_empty() && BUILTIN_DEVICE_ROWS.is_empty());
        }
    }
}


/// Format 6: `[signer.NAME]`, the package signers a device admits (the policy
/// of `azos_pkg`).
#[cfg(test)]
mod signer_tests {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::emit::{emit_caps, first_difference};
    use azos_topology::{parse_caps, AdmissionError, Binding, CapSpec, MaybeStr, ParseError, Topology};

    const KEY_A: &str = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100";
    const KEY_B: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn parse(text: &str) -> (Box<Topology<'_>>, Result<(), ParseError>) {
        let mut t = Box::new(Topology::empty());
        let r = parse_caps(text.as_bytes(), &mut t);
        (t, r)
    }

    fn signer(name: &str, extra: &str) -> String {
        format!("format = 6\n[signer.{name}]\nkey_id = \"{KEY_A}\"\nmem_pages_max = 64\n{extra}")
    }

    fn grant(kind: CapKind, target: &'static [u8]) -> CapSpec<'static> {
        CapSpec { kind, perms: CapPerms::RW, target: MaybeStr::from_bytes(target), transfer: false, ops: 0 }
    }

    #[test]
    fn a_signer_section_is_read_with_its_ceiling() {
        let text = signer("acme", "rt = true\nwarrants = [\"endpoint:endpoint.acme\", \"memobj:\"]\n");
        let (t, r) = parse(&text);
        assert_eq!(r, Ok(()));
        let s = &t.signers()[0];
        assert_eq!(s.name.as_bytes(), b"acme");
        assert_eq!(s.key_id[0], 0x0f);
        assert!(s.rt);
        assert_eq!(s.mem_pages_max, 64);
        assert_eq!(t.warrants_of(s).len(), 2);
        assert!(t.find_signer(&s.key_id).is_some());
        assert!(t.find_signer(&[0; 32]).is_none());
    }

    /// The ceiling is a kind and a target prefix.
    ///
    /// **Canary.** Make `signer_covers` return true: the refusals go red.
    #[test]
    fn a_warrant_ceiling_covers_its_kind_and_prefix_only() {
        let text = signer("acme", "warrants = [\"endpoint:endpoint.acme\", \"memobj:stream.\"]\n");
        let (t, _) = parse(&text);
        let s = &t.signers()[0];
        assert!(t.signer_covers(s, &grant(CapKind::Endpoint, b"endpoint.acme")));
        assert!(t.signer_covers(s, &grant(CapKind::Endpoint, b"endpoint.acme.sub")));
        assert!(t.signer_covers(s, &grant(CapKind::MemObj, b"stream.cam")));
        assert!(!t.signer_covers(s, &grant(CapKind::Endpoint, b"endpoint.other")));
        assert!(!t.signer_covers(s, &grant(CapKind::Endpoint, b"motor.0")));
        assert!(!t.signer_covers(s, &grant(CapKind::Node, b"/fat")));
        assert!(!t.signer_covers(s, &grant(CapKind::MemObj, b"endpoint.acme")));
    }

    /// An import is the right to ask for an endpoint by name: only an
    /// `endpoint:` entry covers it.
    #[test]
    fn an_import_is_covered_by_an_endpoint_warrant_only() {
        let text = signer("acme", "warrants = [\"endpoint:te\", \"memobj:log\", \"node:names\"]\n");
        let (t, _) = parse(&text);
        let s = &t.signers()[0];
        assert!(t.signer_covers_import(s, &MaybeStr::from_bytes(b"term")));
        assert!(!t.signer_covers_import(s, &MaybeStr::from_bytes(b"log")));
        assert!(!t.signer_covers_import(s, &MaybeStr::from_bytes(b"names")));
        assert!(!t.signer_covers_import(s, &MaybeStr::from_bytes(b"t")));
    }

    #[test]
    fn a_signer_needs_format_six() {
        let (_, r) = parse(&signer("acme", "").replace("format = 6", "format = 5"));
        assert_eq!(r, Err(ParseError::FieldNeedsFormat));
    }

    #[test]
    fn a_malformed_signer_is_refused() {
        // No key id.
        let (_, r) = parse("format = 6\n[signer.acme]\nmem_pages_max = 4\n");
        assert_eq!(r, Err(ParseError::MissingField));
        // No frame ceiling.
        let (_, r) = parse(&format!("format = 6\n[signer.acme]\nkey_id = \"{KEY_A}\"\n"));
        assert_eq!(r, Err(ParseError::Admission(AdmissionError::BadSigner)));
        // Key id of the wrong length, an unknown key, a repeated key.
        for bad in ["key_id = \"abcd\"\nmem_pages_max = 4\n", "colour = 1\n"] {
            let (_, r) = parse(&format!("format = 6\n[signer.acme]\n{bad}"));
            assert!(r.is_err(), "{bad:?}");
        }
        let (_, r) = parse(&signer("acme", &format!("key_id = \"{KEY_B}\"\n")));
        assert_eq!(r, Err(ParseError::BadValue));
        // A ceiling that is not kind:prefix, or of a kind no grant has.
        for bad in ["warrants = [\"endpoint\"]\n", "warrants = [\"queue:x\"]\n", "warrants = [\"x\", ]\n",
                    "warrants = \"endpoint:\"\n"] {
            let (_, r) = parse(&signer("acme", bad));
            assert!(r.is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_signer_is_declared_once_by_name_and_by_key() {
        let two = format!(
            "{}[signer.acme]\nkey_id = \"{KEY_B}\"\nmem_pages_max = 8\n", signer("acme", ""));
        assert_eq!(parse(&two).1, Err(ParseError::Admission(AdmissionError::BadSigner)), "same name");
        let two = format!(
            "{}[signer.other]\nkey_id = \"{KEY_A}\"\nmem_pages_max = 8\n", signer("acme", ""));
        assert_eq!(parse(&two).1, Err(ParseError::Admission(AdmissionError::BadSigner)), "same key");
        let many: String = (0..azos_topology::MAX_SIGNERS + 1)
            .map(|i| format!("[signer.s{i}]\nkey_id = \"{:064x}\"\nmem_pages_max = 1\n", i + 1))
            .collect();
        assert_eq!(
            parse(&format!("format = 6\n{many}")).1,
            Err(ParseError::Admission(AdmissionError::TooManySigners))
        );
    }

    /// A signer section between two rows closes the row before it and leaves
    /// the one after it intact.
    #[test]
    fn signers_and_rows_interleave() {
        let text = format!(
            "format = 6\n[task.A.ELF]\ncaps = []\n[signer.acme]\nkey_id = \"{KEY_A}\"\nmem_pages_max = 4\n[task.B.ELF]\ncaps = []\n");
        let (t, r) = parse(&text);
        assert_eq!(r, Ok(()));
        assert_eq!((t.tasks().len(), t.signers().len()), (2, 1));
    }

    /// The emitter writes the policy and the round trip keeps it.
    ///
    /// **Canary.** Drop the signer loop of `emit_caps`: the comparison names
    /// "signer count".
    #[test]
    fn the_emitter_round_trips_signers() {
        let text = signer("acme", "rt = true\nwarrants = [\"endpoint:endpoint.acme\", \"memobj:\"]\n");
        let (a, r) = parse(&text);
        assert_eq!(r, Ok(()));
        let mut out = String::new();
        emit_caps(&a, &Binding::default(), &mut out).unwrap();
        let (b, r) = parse(&out);
        assert_eq!(r, Ok(()), "{out}");
        assert_eq!(first_difference(&a, &b), None);
        let (empty, _) = parse("format = 6\n");
        assert_eq!(first_difference(&a, &empty), Some("signer count"));
    }
}

/// `export` and `[peer.NAME]` (CAPS.TOML format 6): the only way an endpoint
/// leaves the node, and the rules that bound it.
#[cfg(test)]
mod exports_tests {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::neverallow::{self, Env, RULES};
    use azos_topology::{parse_caps, parse_sched, AdmissionError, CapSpec, MaybeStr, ParseError, SchedProfile, Topology};

    const SCHED: &[u8] = b"[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";

    /// The RPC server's row (serves a proxy endpoint, may lend `decisions`)
    /// with `extra` lines in it, then the peer sections `peers`.
    fn file(format: u8, extra: &str, peers: &str) -> &'static str {
        Box::leak(format!(
            "format = {format}\n\
[task.RPCSRV.ELF]\n{extra}caps = [\n\
  {{ kind = \"endpoint\", target = \"endpoint.rpc-decisions\", perm = \"r\" }},\n\
  {{ kind = \"endpoint\", target = \"endpoint.decisions\", perm = \"w\", transfer = true }},\n\
  {{ kind = \"endpoint\", target = \"endpoint.kept\", perm = \"w\" }},\n\
]\n{peers}"
        ).into_boxed_str())
    }

    const FLEET: &str = "[peer.fleet]\nnodes = [2, 3]\n";

    fn parse(text: &str) -> (Topology<'_>, Result<(), ParseError>) {
        let mut t = Topology::empty();
        parse_sched(SCHED, &mut t).unwrap();
        let r = parse_caps(text.as_bytes(), &mut t);
        (t, r)
    }

    /// **`export` and `[peer.NAME]` are format-6 syntax**, recorded per row and
    /// per class, refused below format 6.
    ///
    /// **Canaries.** Skip `set_last_task_exports` in the parser: the list is
    /// empty and the first assertion goes red. Accept the key or the section
    /// below format 6: the `FieldNeedsFormat` assertions go red.
    #[test]
    fn exports_and_peers_parse_in_format_6() {
        let (t, r) = parse(&file(6, "export = [\"decisions@fleet\"]\n", FLEET));
        assert_eq!(r, Ok(()));
        assert_eq!(t.admission_check(), Ok(()));
        let e = t.exports_of(&t.tasks()[0]);
        assert_eq!((e.len(), e[0].endpoint.as_bytes(), e[0].peer.as_bytes()), (1, &b"decisions"[..], &b"fleet"[..]));
        assert_eq!(t.peers().len(), 1);
        assert_eq!(t.find_peer(b"fleet").unwrap().nodes(), [2, 3]);
        // No export unless the row says so.
        let (t, _) = parse(&file(6, "", FLEET));
        assert!(t.exports_of(&t.tasks()[0]).is_empty());
        for f in 1..=5u8 {
            let (_, r) = parse(&file(f, "export = [\"decisions@fleet\"]\n", ""));
            assert_eq!(r, Err(ParseError::FieldNeedsFormat), "export, format {f}");
            let (_, r) = parse(&file(f, "", FLEET));
            assert_eq!(r, Err(ParseError::FieldNeedsFormat), "peer section, format {f}");
        }
        // A peer section before the rows, and a second class.
        let text: &'static str = Box::leak(format!(
            "format = 6\n[peer.a]\nnodes = [1]\n[peer.b]\nnodes = [4, 5]\n{}", file(6, "export = [\"decisions@b\"]\n", "").split_once('\n').unwrap().1
        ).into_boxed_str());
        let (t, r) = parse(text);
        assert_eq!(r, Ok(()));
        assert_eq!(t.admission_check(), Ok(()));
        assert_eq!(t.peers().iter().map(|p| p.nodes().len()).collect::<Vec<_>>(), [1, 2]);
    }

    /// **Nothing leaves the node but through a row that holds what it lends,
    /// to a class that exists.** Admission refuses an export of an endpoint
    /// the row cannot lend (not held, or held without `transfer`) and a class
    /// nobody declared.
    ///
    /// **Canary.** Skip the exports loop of `admission_check`: every
    /// assertion goes red.
    #[test]
    fn an_export_the_row_cannot_lend_or_no_class_receives_is_refused() {
        // A proxy endpoint is served, never lent: the row holds only its `READ`.
        for bad in ["nothere@fleet", "kept@fleet", "decisions@nobody", "rpc-decisions@fleet"] {
            let (t, r) = parse(&file(6, &format!("export = [\"{bad}\"]\n"), FLEET));
            assert_eq!(r, Ok(()), "{bad} parses; admission decides");
            assert_eq!(t.admission_check(), Err(AdmissionError::UnknownExport), "{bad}");
        }
    }

    /// The shape: `NAME@CLASS` over the endpoint alphabet, once per row,
    /// only in the RPC server's row, at most `EXPORTS_TOTAL`; a class has 1 to
    /// `PEER_NODES` distinct non-zero nodes, none shared with another class.
    ///
    /// **Canary.** Drop the `RPC_IMAGE` test of `set_last_task_exports`: the
    /// stranger's row stops being refused and the assertion goes red.
    #[test]
    fn a_malformed_export_or_peer_is_refused_when_it_is_committed() {
        for bad in ["decisions", "@fleet", "decisions@", "a.b@fleet", "decisions@fl eet", "rpc.decisions@fleet"] {
            let (_, r) = parse(&file(6, &format!("export = [\"{bad}\"]\n"), FLEET));
            assert!(r.is_err(), "{bad:?}");
        }
        let (_, r) = parse(&file(6, "export = [\"decisions@fleet\", \"decisions@fleet\"]\n", FLEET));
        assert_eq!(r, Err(ParseError::Admission(AdmissionError::BadExport)), "a repeat");
        let many: Vec<String> = (0..azos_topology::EXPORTS_TOTAL + 1).map(|i| format!("\"n{i}@fleet\"")).collect();
        let (_, r) = parse(&file(6, &format!("export = [{}]\n", many.join(", ")), FLEET));
        assert_eq!(r, Err(ParseError::Admission(AdmissionError::TooManyExports)));
        // Only the RPC server's row may export.
        let text: &'static str = Box::leak(file(6, "export = [\"decisions@fleet\"]\n", FLEET).replace("RPCSRV.ELF", "STRANGER.ELF").into_boxed_str());
        let (_, r) = parse(text);
        assert_eq!(r, Err(ParseError::Admission(AdmissionError::BadExport)));
        for bad in ["export = decisions@fleet\n", "export = [\"decisions@fleet\"\n", "export = [\"decisions@fleet\" \"x@fleet\"]\n"] {
            let (_, r) = parse(&file(6, bad, FLEET));
            assert!(r.is_err(), "{bad:?}");
        }
        // Peers.
        for (bad, want) in [
            ("[peer.f]\nnodes = []\n", AdmissionError::BadPeer),
            ("[peer.f]\nnodes = [0]\n", AdmissionError::BadPeer),
            ("[peer.f]\nnodes = [2, 2]\n", AdmissionError::BadPeer),
            ("[peer.f]\nnodes = [2]\n[peer.g]\nnodes = [2]\n", AdmissionError::BadPeer),
            ("[peer.f]\nnodes = [2]\n[peer.f]\nnodes = [3]\n", AdmissionError::DuplicatePeer),
            ("[peer.a.b]\nnodes = [2]\n", AdmissionError::BadPeer),
        ] {
            let (_, r) = parse(&file(6, "", bad));
            assert_eq!(r, Err(ParseError::Admission(want)), "{bad:?}");
        }
        let (_, r) = parse(&file(6, "", "[peer.f]\nnodes = [4294967296]\n"));
        assert_eq!(r, Err(ParseError::BadValue), "a node that does not fit is refused, not truncated");
        let (_, r) = parse(&file(6, "", "[peer.f]\nname = 1\n"));
        assert!(r.is_err());
    }

    /// The emitter writes both and the round trip keeps them.
    ///
    /// **Canary.** Drop the `export` line or the `[peer.NAME]` section from
    /// `emit_caps`: the round trip differs and this goes red.
    #[test]
    fn the_emitter_round_trips_exports_and_peers() {
        use azos_topology::emit::{emit_caps, first_difference};
        use azos_topology::Binding;
        let (t, r) = parse(&file(6, "export = [\"decisions@fleet\"]\n", FLEET));
        assert_eq!(r, Ok(()));
        let mut caps = String::new();
        emit_caps(&t, &Binding::default(), &mut caps).unwrap();
        assert!(caps.contains("export = [\"decisions@fleet\"]") && caps.contains("[peer.fleet]\nnodes = [2, 3]"), "{caps}");
        let mut back = Topology::empty();
        parse_sched(SCHED, &mut back).unwrap();
        parse_caps(caps.as_bytes(), &mut back).unwrap();
        assert_eq!(first_difference(&t, &back), None);
        // And the comparison sees a difference when one is there.
        let (u, _) = parse(&file(6, "export = [\"decisions@fleet\"]\n", "[peer.fleet]\nnodes = [2, 4]\n"));
        assert_eq!(first_difference(&t, &u), Some("peer"));
        let (u, _) = parse(&file(6, "", FLEET));
        assert_eq!(first_difference(&t, &u), Some("task exports"));
    }

    fn cap(perms: CapPerms, target: &'static [u8]) -> CapSpec<'static> {
        CapSpec { kind: CapKind::Endpoint, perms, target: MaybeStr::from_bytes(target), transfer: false, ops: 0 }
    }

    fn row(name: &'static [u8], profile: SchedProfile, caps: &[CapSpec<'static>]) -> Box<Topology<'static>> {
        class_row(name, b"best_effort", profile, caps)
    }

    fn class_row(name: &'static [u8], class: &'static [u8], profile: SchedProfile, caps: &[CapSpec<'static>]) -> Box<Topology<'static>> {
        let mut t = Box::new(Topology::empty());
        t.push_task_profiled(MaybeStr::from_bytes(name), MaybeStr::from_bytes(class), 0, caps, profile).unwrap();
        t
    }

    fn rule(id: &str) -> u8 {
        RULES.iter().position(|r| r.id == id).unwrap_or_else(|| panic!("no rule {id}")) as u8
    }

    /// **A real-time row (a declared reservation, or a real-time class) holds
    /// no proxy endpoint**, in either half, and **only the RPC server serves
    /// one**.
    ///
    /// **Canaries.** Make `proxy_endpoint_not_realtime` ignore the profile:
    /// the ordinary row in the third assertion is refused and it goes red.
    /// Drop the `READ` test of `proxy_endpoint_served_by_rpcsrv_only`: the
    /// caller's `WRITE` grant is refused and the same assertion goes red.
    #[test]
    fn a_proxy_endpoint_is_called_by_ordinary_rows_and_served_by_rpcsrv_only() {
        let env = Env { desktop: false };
        let rt = SchedProfile { period_us: 1000, runtime_us: 100, deadline_us: 0, cpu_mask: 0 };
        let call = cap(CapPerms::WRITE, b"endpoint.rpc-decisions");
        let serve = cap(CapPerms::READ, b"endpoint.rpc-decisions");
        // A real-time caller, and a real-time row of any right.
        let t = row(b"MOTORLOOP.ELF", rt, &[call]);
        assert_eq!(neverallow::check(&t, &env).map(|_| ()).unwrap_err().rule, rule("proxy-endpoint-not-realtime"));
        // A row of a real-time class with no profile declared is real time too.
        for class in [&b"safety_critical"[..], b"hard_rt", b"soft_rt"] {
            let t = class_row(b"MOTORLOOP.ELF", class, SchedProfile::NONE, &[call]);
            assert_eq!(
                neverallow::check(&t, &env).unwrap_err().rule,
                rule("proxy-endpoint-not-realtime"),
                "{}", String::from_utf8_lossy(class),
            );
        }
        // An ordinary caller is fine, and so is one of the fair classes.
        let t = row(b"WHY.ELF", SchedProfile::NONE, &[call]);
        assert_eq!(neverallow::check(&t, &env), Ok(()));
        let t = class_row(b"WHY.ELF", b"idle", SchedProfile::NONE, &[call]);
        assert_eq!(neverallow::check(&t, &env), Ok(()));
        // The server half in any other row is refused; in the RPC server's, not.
        let t = row(b"STRANGER.ELF", SchedProfile::NONE, &[serve]);
        assert_eq!(neverallow::check(&t, &env).unwrap_err().rule, rule("proxy-endpoint-served-by-rpcsrv-only"));
        let t = row(b"RPCSRV.ELF", SchedProfile::NONE, &[serve]);
        assert_eq!(neverallow::check(&t, &env), Ok(()));
        // An endpoint that merely resembles a proxy is none.
        let t = row(b"MOTORLOOP.ELF", rt, &[cap(CapPerms::WRITE, b"endpoint.rpcx"), cap(CapPerms::WRITE, b"endpoint.names")]);
        assert_eq!(neverallow::check(&t, &env), Ok(()));
    }
}

/// The kernel half of the proxy endpoint, with the real endpoint table.
#[cfg(test)]
mod proxy_endpoint_tests {
    use crate::cap_seed::{seed_one_cap_outcome, SeedOutcome};
    use crate::endpoint;
    use azos_abi::cap::{CapKind, CapPerms};

    /// The proxy prefix is spelled in two crates that cannot see each other.
    #[test]
    fn the_proxy_prefix_is_spelled_alike_on_both_sides() {
        assert_eq!(azos_topology::PROXY_PREFIX, endpoint::PROXY_NAME_PREFIX);
    }

    /// **An endpoint is a proxy exactly when the topology names it
    /// `rpc-...`**, from the first grant on, for the server's half and the
    /// callers' alike, and the slot forgets it when the endpoint is destroyed.
    ///
    /// **Canaries.** Make `create_core` store `false`: the first assertion
    /// goes red. Drop the clear in `unpublish`: the reused slot answers
    /// `true` for the ordinary endpoint and the last assertion goes red.
    #[test]
    fn an_endpoint_is_a_proxy_when_its_name_says_so() {
        let _g = crate::harness::serial();
        endpoint::__endpoint_reset_for_tests();
        let (server, client) = (
            super::cap_seed_bridge_tests::fresh_tid(),
            super::cap_seed_bridge_tests::fresh_tid(),
        );
        for (tid, perms, name) in [
            (server, CapPerms::READ, "endpoint.rpc-decisions"),
            (server, CapPerms::READ, "endpoint.plain"),
        ] {
            assert!(matches!(seed_one_cap_outcome(tid, CapKind::Endpoint, perms, name), SeedOutcome::Minted(_)), "{name}");
        }
        let SeedOutcome::Minted(call) = seed_one_cap_outcome(client, CapKind::Endpoint, CapPerms::WRITE, "endpoint.rpc-decisions")
            else { panic!("the caller's grant") };
        let SeedOutcome::Minted(plain) = seed_one_cap_outcome(client, CapKind::Endpoint, CapPerms::WRITE, "endpoint.plain")
            else { panic!("the plain grant") };
        let d = endpoint::endpoint_resolve(client, call.as_raw()).expect("resolves");
        assert!(endpoint::is_proxy(&d));
        let p = endpoint::endpoint_resolve(client, plain.as_raw()).expect("resolves");
        assert!(!endpoint::is_proxy(&p));
        // Destroying the proxy clears the flag of its slot.
        endpoint::destroy_ref(d.r).expect("destroyed");
        assert!(!endpoint::is_proxy(&d), "a destroyed endpoint is no proxy");
    }
}

#[cfg(test)]
mod placement_tests;

// TOPO-ROWS-A and TOPO-ROWS-B: the format-7 rows and fields.
#[cfg(test)]
mod topo_rows;

// TOPO-ROWS-C: the format-8 rows and fields.
#[cfg(test)]
mod topo_rows_c;

// SUBTREE-POLICY: the shell's `[policy.shjobs]` row in the built-in topology.
#[cfg(test)]
mod subtree_policy;

// The shell row's `session` class, the one shipped class with `principal = "user"`.
#[cfg(test)]
mod principal_session;

// The built-in rows' priorities: stated, unclamped, in service-graph order.
#[cfg(test)]
mod ring3_priority_order;
// Who may write the USB stick's volume (`/usb`, Kconfig `USB_STORAGE_VOLUME`).
#[cfg(test)]
mod usb_volume_grant;

/// A grant's `ops` becomes the op mask of the capability the task holds.
#[cfg(test)]
mod linkkey_mask_seed_tests {
    use crate::cap::CapPerms;
    use crate::cap_seed::{seed_one_cap_ops, SeedOutcome};
    use crate::cap_store;
    use azos_abi::cap::CapKind;

    use super::cap_seed_bridge_tests::fresh_tid;

    /// The op mask of the `linkkey` capability `tid` holds.
    fn linkkey_mask(tid: u32) -> Option<u64> {
        cap_store::with_table(tid, |t| {
            let h = t.lookup_where(azos_abi::cap::ty::ENDPOINT, |r, _, _| {
                crate::endpoint::host_key_of_ref(r) == Some(azos_devif::key::LINK_KEY)
            })?;
            Some(t.hosted_op_mask(h))
        })
        .flatten()
    }

    /// **Seeded from the built-in topology, the rows that need an identity hold
    /// `linkkey` masked to `node_key` and the link task holds it whole.** The
    /// `ops` of each row's grant reaches the capability the kernel mints
    /// (`seed_one_cap_ops`, what the loader and the spawn path call).
    ///
    /// **Canary.** Seed with `ops` 0 (the loader forgetting `cap.ops`): the
    /// identity rows read all ops.
    #[test]
    fn the_rows_that_need_an_identity_are_seeded_with_the_node_key_mask() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let topo = azos_topology::default_minimal();
        let mut seen = 0;
        // Only the rows that hold the grant: a task id is a scarce slot here.
        for row in topo.tasks().iter().filter(|r| topo.caps_of(r).iter().any(|c| c.target.as_bytes() == b"linkkey")) {
            let tid = fresh_tid();
            // Only the grant under test: seeding a whole row would leave its
            // devices and endpoints behind for the suites that count them.
            for cap in topo.caps_of(row).iter().filter(|c| c.target.as_bytes() == b"linkkey") {
                let _ = seed_one_cap_ops(tid, cap.kind, cap.grant_perms(), cap.target.as_str(), cap.ops);
            }
            match (row.name.as_bytes() == b"autorun", linkkey_mask(tid)) {
                (_, None) => {}
                (true, Some(m)) => {
                    seen += 1;
                    assert_eq!(m, u64::MAX, "the link task reads the key, whole");
                }
                (false, Some(m)) => {
                    seen += 1;
                    assert_eq!(m, azos_devif::linkkey::NODE_KEY_OPS, "{:?}", row.name.as_bytes());
                }
            }
        }
        let want = 2 // the link task and RPCSRV.ELF
            + usize::from(azos_topology::builder::MCP_BRIDGE_ROW);
        assert_eq!(seen, want);
    }

    /// **The SSH server's `keys` grant reaches the capability the kernel mints
    /// with its mask**: `generate`, `public` and `sign`, and the rights `READ` and
    /// `WRITE`, so `import`, `derive`, `wrap` and `destroy` are refused before the
    /// keystore runs.
    ///
    /// **Canary.** Seed with `ops` 0 (the loader forgetting `cap.ops`): the mask
    /// reads every op.
    #[test]
    fn the_ssh_row_is_seeded_with_the_signer_mask() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let topo = azos_topology::default_minimal();
        let Some(row) = topo.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_SSHD_IMAGE) else {
            assert!(!azos_topology::builder::SSHD_ROW);
            return;
        };
        let tid = fresh_tid();
        let mut minted = 0;
        for cap in topo.caps_of(row).iter().filter(|c| c.target.as_bytes() == b"keys") {
            assert!(matches!(
                seed_one_cap_ops(tid, cap.kind, cap.grant_perms(), cap.target.as_str(), cap.ops),
                SeedOutcome::Minted(_)
            ));
            minted += 1;
        }
        assert_eq!(minted, 1);
        let mask = cap_store::with_table(tid, |t| {
            let h = t.lookup_where(azos_abi::cap::ty::ENDPOINT, |r, _, _| {
                crate::endpoint::host_key_of_ref(r) == Some(azos_devif::key::KEYS)
            })?;
            Some(t.hosted_op_mask(h))
        })
        .flatten();
        assert_eq!(mask, Some(azos_devif::keys::SIGNER_OPS));
    }

    /// An `ops` mask names ops of a kernel-hosted interface and nothing else:
    /// on a task's endpoint, a directory, a device or a port it is refused (an
    /// `OP_MASK` of another kind would be read as op classes), as is a mask on
    /// a target that names no interface. The same grants without the mask mint.
    ///
    /// **Canary.** Drop the check in `seed_one_cap_ops`: the task's endpoint
    /// mints a capability no call can ever use.
    #[test]
    fn a_mask_is_refused_where_it_means_nothing() {
        let _g = crate::harness::serial();
        crate::endpoint::__endpoint_reset_for_tests();
        let tid = fresh_tid();
        let grants = [
            (CapKind::Endpoint, CapPerms::READ, "endpoint.svc"),
            (CapKind::Endpoint, CapPerms::READ, "nothing.0"),
            (CapKind::Node, CapPerms::RW, "/fat"),
            (CapKind::Device, CapPerms::READ, "irq.3"),
        ];
        for (kind, perms, target) in grants {
            assert_eq!(seed_one_cap_ops(tid, kind, perms, target, 4), SeedOutcome::Refused, "{target}");
        }
        assert!(matches!(seed_one_cap_ops(tid, CapKind::Endpoint, CapPerms::READ, "linkkey", 4), SeedOutcome::Minted(_)));
        assert!(matches!(seed_one_cap_ops(tid, CapKind::Endpoint, CapPerms::READ, "endpoint.svc", 0), SeedOutcome::Minted(_)));
    }
}

/// The RPC server's row in the built-in topology.
#[cfg(test)]
mod rpc_row_tests {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::{default_minimal, PROXY_PREFIX, RPC_IMAGE};

    /// **The row is the whole of the server's authority**: it serves the proxy
    /// of `decisions` (and only a proxy: `neverallow` pins that), holds the lend
    /// right on `decisions` (`WRITE` + `transfer`, no `READ`), and exports it
    /// to the class `fleet` exactly when Kconfig `RPC_PEER_NODE` names a
    /// peer; only then does it start. `WHY.ELF` calls both endpoints, the
    /// local one first (the tool takes the second as the remote one).
    ///
    /// **Canaries.** Give the row `READ` on `endpoint.decisions`: admission
    /// refuses the export (it would be the server of that name). Swap the
    /// order of `WHY_CAPS`: the order assertion goes red.
    #[test]
    fn the_rpc_server_row_serves_a_proxy_and_lends_decisions() {
        let t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        let ri = t.tasks().iter().position(|r| r.name.as_bytes() == RPC_IMAGE).expect("an RPCSRV.ELF row");
        let row = &t.tasks()[ri];
        let caps = t.caps_of(row);
        assert_eq!(caps.len(), 5, "the proxy, the lend right, the two secrets, the root directory");
        let proxy = &caps[0];
        assert_eq!((proxy.kind, proxy.perms, proxy.transfer), (CapKind::Endpoint, CapPerms::READ, false));
        assert!(azos_topology::types::endpoint_target(proxy).unwrap().starts_with(PROXY_PREFIX), "the proxy is named as a proxy");
        assert!(t.row_lends(row, b"decisions"), "the lend right on decisions");
        // The handshake's two secrets: the entropy pool and the node key (`READ`
        // on `linkkey` masked to `node_key`: its own identity, not the board
        // seed the unmasked `READ` returns).
        assert_eq!((caps[2].kind, caps[2].perms, caps[2].target.as_bytes(), caps[2].transfer), (CapKind::Endpoint, CapPerms::READ, &b"entropy"[..], false));
        assert_eq!(caps[2].ops, 0);
        super::mcp_row_tests::assert_identity_grant(&caps[3]);
        // Its view of the topology: the peers, the exports of what it holds.
        assert_eq!(
            (caps[4].kind, caps[4].perms, caps[4].target.as_bytes()),
            (CapKind::MemObj, CapPerms::READ.union(CapPerms::MAP), &b"inspect.rpc"[..])
        );
        assert_eq!(row.start, azos_limits::RPC_PEER_NODE != 0);
        match azos_limits::RPC_PEER_NODE {
            0 => {
                assert!(t.exports_of(row).is_empty() && t.peers().is_empty(), "no peer, nothing leaves");
            }
            n => {
                let e = t.exports_of(row);
                assert_eq!((e.len(), e[0].endpoint.as_bytes(), e[0].peer.as_bytes()), (1, &b"decisions"[..], &b"fleet"[..]));
                assert_eq!(t.find_peer(b"fleet").unwrap().nodes(), [n as u32]);
            }
        }
        // The caller: the local endpoint, then the proxy, then the kernel's
        // entropy endpoint (READ) that keys the allocator `std` brings.
        let why = t.tasks().iter().find(|r| r.name.as_bytes() == b"WHY.ELF").unwrap();
        let w = t.caps_of(why);
        // `why woke` adds the public introspection region (Kconfig INSPECT).
        let region = azos_limits::INSPECT && !azos_limits::CONSOLE_LOCKDOWN;
        assert_eq!(w.len(), 4 + usize::from(region));
        assert_eq!(azos_topology::types::endpoint_target(&w[0]), Some(&b"decisions"[..]));
        assert_eq!(azos_topology::types::endpoint_target(&w[1]), Some(&b"rpc-decisions"[..]));
        assert!(w[..2].iter().all(|c| c.perms == CapPerms::WRITE && !c.transfer));
        assert_eq!((w[2].kind, w[2].perms), (CapKind::Endpoint, CapPerms::READ));
        // `why crash` reads the dumps beneath the read-only root directory, no write tree.
        assert_eq!((w[3].kind, w[3].perms, w[3].target.as_bytes()), (CapKind::Node, CapPerms::READ, &b"/"[..]));
        if region {
            assert_eq!(
                (w[4].kind, w[4].perms, w[4].target.as_bytes()),
                (CapKind::MemObj, CapPerms::READ.union(CapPerms::MAP), &b"inspect.public"[..])
            );
        }
        // The server's row comes after the tool's: the proxy is declared by the tool's
        // row first, the local endpoint by the decision server's before both.
        let di = t.tasks().iter().position(|r| r.name.as_bytes() == b"DECISD.ELF").unwrap();
        let wi = t.tasks().iter().position(|r| r.name.as_bytes() == b"WHY.ELF").unwrap();
        assert!(di < wi, "the local endpoint is named first");
    }
}

/// The kernel log sink's row in the built-in topology (Kconfig `KLOG`).
#[cfg(test)]
mod logd_row_tests {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::default_minimal;

    /// **The row is the whole of the sink's authority**: the kernel's log ring
    /// `READ|MAP` (it can neither write the ring nor hand it on), the `/fat`
    /// tree its files are written in, and the read-only root directory they are
    /// opened beneath. No endpoint, to serve or to call; it starts exactly with
    /// Kconfig `KLOG`, and the supervisor restarts it on failure.
    ///
    /// **Canary.** Add `WRITE` to the ring grant: the permission assertion goes
    /// red (and `azos_ipc::kregion` would refuse the row at boot). Give it an
    /// endpoint: the kind assertion goes red.
    #[test]
    fn the_sink_row_reads_the_ring_and_writes_its_tree() {
        let t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        let row = t.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_LOGD_IMAGE).expect("the row");
        let caps = t.caps_of(row);
        assert_eq!(caps.len(), 3);
        assert_eq!((caps[0].kind, caps[0].perms, caps[0].transfer), (CapKind::MemObj, CapPerms::READ.union(CapPerms::MAP), false));
        assert_eq!(caps[0].target.as_bytes(), b"klog.ring");
        assert_eq!((caps[1].kind, caps[1].perms, caps[1].target.as_bytes()), (CapKind::Node, CapPerms::RW, &b"/fat"[..]));
        assert_eq!((caps[2].kind, caps[2].perms, caps[2].target.as_bytes()), (CapKind::Node, CapPerms::READ, &b"/"[..]));
        assert!(caps.iter().all(|c| c.kind != CapKind::Endpoint), "it serves and calls nothing");
        assert_eq!(row.start, azos_limits::KLOG, "it starts exactly with the log");
        assert_eq!(row.restart, azos_topology::RestartPolicy::OnFailure);
    }
}

/// The Zenoh gateway's row in the built-in topology.
#[cfg(test)]
mod zenoh_row_tests {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::default_minimal;

    /// **The row is the whole of the gateway's authority**: the lend right on
    /// `decisions` (`WRITE` + `transfer`, no `READ`: the receipts and the
    /// topics, and the source of the per-query warrants of an export under that
    /// name) and `READ` on `entropy` (its ZenohID and the allocator's seed).
    /// The row exists, and starts, only with Kconfig `ZENOH_GW`; the built-in
    /// topology exports nothing to Zenoh, and the gateway is not the RPC server,
    /// so it carries no export at all.
    ///
    /// **Canary.** Give the row `READ` on `endpoint.decisions`: the lend
    /// assertion goes red (it would be the server of that name, not a caller).
    /// Give it a directory grant (the read-only root): the no-directory
    /// assertion goes red.
    /// With `ZENOH_GW` off the test checks only that no row exists.
    #[test]
    fn the_gateway_row_calls_decisions_and_reads_entropy() {
        let t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        let row = t.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_ZENOHD_IMAGE);
        assert_eq!(row.is_some(), azos_topology::builder::ZENOH_GW_ROW, "a row exactly when Kconfig ZENOH_GW");
        let Some(row) = row else { return };
        let caps = t.caps_of(row);
        assert_eq!(caps.len(), 2);
        assert!(caps.iter().all(|c| c.kind == CapKind::Endpoint), "no directory: the gateway opens no file (its configuration is Kconfig)");
        assert!(t.row_lends(row, b"decisions"), "the lend right on decisions");
        assert_eq!((caps[1].kind, caps[1].perms, caps[1].transfer), (CapKind::Endpoint, CapPerms::READ, false));
        assert_eq!(caps[1].target.as_bytes(), b"entropy");
        assert!(row.start, "the kernel starts it with the row");
        assert!(t.exports_of(row).is_empty(), "exports with a key belong to a signed topology's RPC row");
    }

    /// The relay of the QUIC link (`userspace/lib/quic`, Kconfig `RPC_QUIC`): its
    /// row is its whole authority, `READ` on `entropy` and nothing else (the
    /// network is its seccomp profile's). No lend right, no export, no endpoint
    /// it serves: the QUIC stack and its TLS hold nothing the RPC server's
    /// lend rights are. It starts with the row and is restarted on failure.
    /// The row exists exactly with `RPC_QUIC`.
    ///
    /// **Canary.** Give the row a `WRITE` on `decisions`: the capability count
    /// goes red. With `RPC_QUIC` off the test checks only that no row exists.
    #[test]
    fn the_relay_row_reads_entropy_and_holds_nothing_else() {
        let t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        let row = t.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_RPCQUIC_IMAGE);
        assert_eq!(row.is_some(), azos_topology::builder::RPCQUIC_ROW, "a row exactly when Kconfig RPC_QUIC");
        let Some(row) = row else { return };
        let caps = t.caps_of(row);
        assert_eq!(caps.len(), 1);
        assert_eq!((caps[0].kind, caps[0].perms, caps[0].transfer), (CapKind::Endpoint, CapPerms::READ, false));
        assert_eq!(caps[0].target.as_bytes(), b"entropy");
        assert!(row.start, "the kernel starts it with the row");
        assert!(t.exports_of(row).is_empty(), "the relay exports nothing: the RPC server does");
        assert!(!t.row_lends(row, b"decisions"));
    }
}

#[cfg(test)]
mod mcp_row_tests {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::{default_minimal, parse_caps, Topology};

    /// **The row is the whole of the bridge's authority**: the lend right on
    /// `decisions` (the receipts, and the source of the per-call warrants of
    /// the interface it fronts), `READ` on `entropy` (its boot epoch and the
    /// allocator's seed) and `READ` on `linkkey` masked to `node_key` (the
    /// image's DICE identity, the root of the warrants it signs). The row exists, and starts, only with Kconfig
    /// `MCP_BRIDGE`; it exports nothing (it is a client of the endpoints it
    /// fronts, not a server of any).
    ///
    /// **Canary.** Give the row `READ` on `endpoint.decisions`: the lend
    /// assertion goes red. With `MCP_BRIDGE` off the test checks only that no
    /// row exists.
    #[test]
    fn the_bridge_row_calls_decisions_and_reads_its_two_secrets() {
        let t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        let row = t.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_MCPD_IMAGE);
        assert_eq!(row.is_some(), azos_topology::builder::MCP_BRIDGE_ROW, "a row exactly when Kconfig MCP_BRIDGE");
        let Some(row) = row else { return };
        let caps = t.caps_of(row);
        assert_eq!(caps.len(), 4, "the lend right, the two secrets, the root directory");
        assert!(t.row_lends(row, b"decisions"), "the lend right on decisions");
        assert_eq!((caps[1].kind, caps[1].perms, caps[1].target.as_bytes(), caps[1].transfer), (CapKind::Endpoint, CapPerms::READ, &b"entropy"[..], false));
        assert_identity_grant(&caps[2]);
        assert_eq!((caps[3].kind, caps[3].perms, caps[3].target.as_bytes()), (CapKind::Node, CapPerms::READ, &b"/"[..]));
        assert!(row.start, "the kernel starts it with the row");
        assert!(t.exports_of(row).is_empty());
    }

    /// **The row is the whole of the SSH server's authority**: `READ` on
    /// `entropy` (the ephemeral keys) and `READ` and `WRITE` on `keys` masked to
    /// open a key, read its public part and sign (its host key, which lives in
    /// the kernel's keystore; no `linkkey`, so no board seed and no node key),
    /// the `/fat` tree read-write (wider than it needs: the file layer opens no
    /// file inside a directory, see `SSHD_CAPS`), the right to start the tool image a
    /// command runs
    /// as and nothing else, and the read-only root directory. It exports
    /// nothing and lends nothing. The row exists, and starts, with Kconfig
    /// `SSHD`, and acts as a `User`.
    ///
    /// **Canary.** Add a launch grant for `POWER.ELF` to the row (a login that
    /// can reboot): the count and the launch-list assertion go red.
    #[test]
    fn the_ssh_row_reads_entropy_and_the_keystore_writes_the_volume_and_starts_only_the_tool_image() {
        let t = default_minimal();
        assert_eq!(t.admission_check(), Ok(()));
        let row = t.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_SSHD_IMAGE);
        assert_eq!(row.is_some(), azos_topology::builder::SSHD_ROW, "a row exactly when Kconfig SSHD");
        let Some(row) = row else { return };
        let caps = t.caps_of(row);
        assert_eq!(caps.len(), 6, "entropy, the keystore, the volume, the tool launch, the root directory, the logins view");
        assert_eq!((caps[0].kind, caps[0].perms, caps[0].target.as_bytes()), (CapKind::Endpoint, CapPerms::READ, &b"entropy"[..]));
        assert_eq!(
            (caps[1].kind, caps[1].perms, caps[1].target.as_bytes(), caps[1].transfer, caps[1].ops),
            (CapKind::Endpoint, CapPerms::RW, &b"keys"[..], false, azos_devif::keys::SIGNER_OPS),
            "the host key is opened, read and signed with, and nothing else of the keystore",
        );
        assert!(
            caps.iter().all(|c| c.target.as_bytes() != b"linkkey"),
            "the server that faces the network holds neither the board seed nor a node key",
        );
        assert_eq!((caps[2].kind, caps[2].perms, caps[2].target.as_bytes()), (CapKind::Node, CapPerms::RW, &b"/fat"[..]));
        assert_eq!((caps[3].kind, caps[3].perms, caps[3].target.as_bytes()), (CapKind::Node, CapPerms::EXEC, &b"TOOLBOX.ELF"[..]));
        assert_eq!((caps[4].kind, caps[4].perms, caps[4].target.as_bytes()), (CapKind::Node, CapPerms::READ, &b"/"[..]));
        assert_eq!(
            (caps[5].kind, caps[5].perms, caps[5].target.as_bytes()),
            (CapKind::MemObj, CapPerms::READ.union(CapPerms::MAP), &b"inspect.logins"[..])
        );
        let launches: Vec<_> = caps.iter().filter(|c| c.kind == CapKind::Node && c.perms == CapPerms::EXEC).collect();
        assert_eq!(launches.len(), 1, "a login starts the tool image and no privileged one");
        assert!(caps.iter().all(|c| !c.transfer), "nothing it holds can be passed on");
        assert!(row.start, "the kernel starts it with the row");
        assert!(t.exports_of(row).is_empty());
        // A login is a human's session: the row is a `User` whatever its class
        // says, and the images it starts inherit that at the spawn.
        assert_eq!(t.row_principal(azos_topology::builder::TASK_SSHD_IMAGE), Some(azos_topology::PrincipalKind::User));
    }

    /// The grant of a task that needs its own node identity and nothing else of
    /// `linkkey`: an endpoint grant of the bare interface name, `READ`, the op
    /// mask of `node_key` alone (`azos_devif::linkkey::NODE_KEY_OPS`), not
    /// transferable.
    pub fn assert_identity_grant(c: &azos_topology::CapSpec<'_>) {
        assert_eq!(
            (c.kind, c.perms, c.target.as_bytes(), c.transfer, c.ops),
            (CapKind::Endpoint, CapPerms::READ, &b"linkkey"[..], false, azos_devif::linkkey::NODE_KEY_OPS),
        );
    }

    /// **The builder's copy of the mask is the interface's.** The topology crate
    /// cannot depend on `azos_devif`, so it restates the bit of `node_key`; the
    /// op table says which op that is, and that `read` and `brain_pk` are other
    /// bits.
    ///
    /// **Canary.** Move `node_key` in the trait (or change the builder's
    /// constant): red.
    #[test]
    fn the_builders_node_key_mask_is_the_interfaced_op() {
        use azos_devif::LinkKeyIdl;
        let bit = |name: &str| LinkKeyIdl::OPS.iter().find(|o| o.name == name).map(|o| 1u64 << o.op).expect("an op of that name");
        assert_eq!(azos_topology::builder::LINK_KEY_NODE_KEY_OPS, bit("node_key"));
        assert_eq!(azos_devif::linkkey::NODE_KEY_OPS, bit("node_key"));
        assert_eq!(azos_devif::linkkey::NODE_KEY_OPS & (bit("read") | bit("brain_pk")), 0);
    }

    /// **The builder's copy of the signer mask is the interface's.** The topology
    /// crate cannot depend on `azos_devif`, so it restates the bits of `generate`,
    /// `public` and `sign`; the op table says which ops those are.
    ///
    /// **Canary.** Move an op in the trait (or change the builder's constant): red.
    #[test]
    fn the_builders_signer_mask_is_the_interfaces() {
        assert_eq!(azos_topology::builder::KEYS_SIGNER_OPS, azos_devif::keys::SIGNER_OPS);
        let bit = |name: &str| azos_devif::KeysIdl::OPS.iter().find(|o| o.name == name).map(|o| 1u64 << o.op).expect("an op of that name");
        assert_eq!(azos_devif::keys::SIGNER_OPS, bit("generate") | bit("public") | bit("sign"));
    }

    /// **The builder's copy of the login mask is the interface's**: one op,
    /// `login`, and nothing a signer or a key user needs.
    ///
    /// **Canary.** Move `login` in the trait (or change the builder's constant): red.
    #[test]
    fn the_builders_login_mask_is_the_interfaces() {
        assert_eq!(azos_topology::builder::KEYS_LOGIN_OPS, azos_devif::keys::LOGIN_OPS);
        let bit = |name: &str| azos_devif::KeysIdl::OPS.iter().find(|o| o.name == name).map(|o| 1u64 << o.op).expect("an op of that name");
        assert_eq!(azos_devif::keys::LOGIN_OPS, bit("login"));
        assert_eq!(azos_devif::keys::LOGIN_OPS & azos_devif::keys::SIGNER_OPS, 0);
    }

    /// **The login service's row is the whole of its authority, and the terminal
    /// server calls it.** Serve `endpoint.login`, `login` on `keys` and no other
    /// op, the right to start the shell, the read-only root: no file tree, no
    /// entropy, no device. The terminal server's row serves `endpoint.term`
    /// first and calls `endpoint.login` second (`READ` and `WRITE`), so ring 3
    /// can tell them apart by the rights in the handles. Without a console
    /// login there is neither the row nor the call right.
    ///
    /// **Canary.** Grant the login service `RW` on `keys` or no mask: the mask
    /// assertion is red. Grant the terminal server `endpoint.login` with
    /// `READ`: it would serve what it calls.
    #[test]
    fn the_login_service_row_and_the_terminal_servers_call() {
        use azos_abi::cap::CapPerms;
        use azos_abi::cap::CapKind;
        use azos_topology::MaybeStr;
        let t = azos_topology::default_minimal();
        let row = |n: &[u8]| t.tasks().iter().find(|r| r.name.as_bytes() == n);
        let eps = |n: &[u8]| -> Vec<(CapPerms, String)> {
            let Some(r) = row(n) else { return vec![] };
            t.caps_of(r).iter().filter(|c| c.kind == CapKind::Endpoint && c.target.as_bytes().starts_with(b"endpoint.")).map(|c| (c.perms, c.target.as_str().to_string())).collect()
        };
        let termd = eps(b"TERMD.ELF");
        assert_eq!(termd[0], (CapPerms::READ, "endpoint.term".to_string()), "it serves the terminal first");
        let logind = row(azos_topology::builder::TASK_LOGIND_IMAGE);
        assert_eq!(logind.is_some(), azos_topology::builder::LOGIND_ROW, "a row exactly when Kconfig CONSOLE_LOGIN");
        let Some(l) = logind else {
            assert_eq!(termd.len(), 1, "no login service, no call to it");
            return;
        };
        assert_eq!(termd[1], (CapPerms::WRITE, "endpoint.login".to_string()), "and calls the login service second");
        assert!(l.start);
        assert_eq!(t.restart_of(b"LOGIND.ELF"), azos_topology::RestartPolicy::OnFailure);
        let caps = t.caps_of(l);
        assert_eq!(caps.len(), 4);
        assert_eq!((caps[0].kind, caps[0].perms, caps[0].target.as_str()), (CapKind::Endpoint, CapPerms::READ, "endpoint.login"));
        assert_eq!((caps[1].kind, caps[1].perms, caps[1].target.as_str(), caps[1].ops), (CapKind::Endpoint, CapPerms::EXEC, "keys", azos_devif::keys::LOGIN_OPS));
        assert_eq!((caps[2].kind, caps[2].perms, caps[2].target), (CapKind::Node, CapPerms::EXEC, MaybeStr::from_bytes(b"SH.ELF")));
        assert_eq!(caps[3].kind, CapKind::Node, "the read-only root");
        assert!(!caps.iter().any(|c| c.perms.contains(CapPerms::WRITE)), "nothing it can write");
    }

    /// **The gate's enrolment is a text append.** `tools/ci_check.sh` (the
    /// `login: console` rows) takes the CAPS.TOM the emitter wrote for a volume,
    /// appends a `[login.alice]` row and signs it again; the kernel reads that
    /// file. The result must parse, enrol exactly that user and leave the rows
    /// alone.
    ///
    /// **Canary.** Append the row to a file whose `format` is below 7: the
    /// parse is refused (`FieldNeedsFormat`), and the gate's rows would have
    /// booted a volume that enrols nobody.
    #[test]
    fn a_login_row_appended_to_the_emitted_topology_parses_and_changes_only_the_logins() {
        use azos_topology::emit::emit_caps;
        use azos_topology::{parse_caps, Binding, Topology};
        let topo = azos_topology::default_minimal();
        let mut text = String::new();
        emit_caps(&topo, &Binding::default(), &mut text).unwrap();
        let key = "11".repeat(32);
        text.push_str(&format!("\n[login.alice]\nssh_key = [\"{key}\"]\n"));
        let mut back = Topology::empty();
        parse_caps(text.as_bytes(), &mut back).expect("the emitted file plus a login row parses");
        assert_eq!(back.logins().len(), 1);
        assert_eq!(back.logins()[0].name.as_str(), "alice");
        assert_eq!(back.logins()[0].keys()[0], [0x11u8; 32]);
        assert_eq!(back.tasks_len(), topo.tasks_len());
        assert_eq!(azos_topology::builder::console_gated(back.logins().len()), azos_topology::builder::LOGIND_ROW);
    }

    /// **The component manager starts the shell unless the console is gated.**
    ///
    /// **Canary.** Gate on the row alone: the console is gated with nobody
    /// enrolled and the shell never starts.
    #[test]
    fn the_console_is_gated_only_with_the_service_and_a_user() {
        assert!(!azos_topology::builder::console_gated(0), "nobody enrolled: the shell starts as it always did");
        assert_eq!(azos_topology::builder::console_gated(1), azos_topology::builder::LOGIND_ROW);
        assert_eq!(azos_topology::builder::console_gated(8), azos_topology::builder::LOGIND_ROW);
    }

    /// **The terminal server's call right on the login service is minted only for
    /// a gated console.** Withheld with nobody enrolled whatever the build, kept
    /// (with the service in the build and a user enrolled) otherwise; the right to
    /// serve the endpoint, and every other capability, are never withheld. The
    /// topology decides what a login service that does not answer means: no right,
    /// no question, so a console nobody can log in to is not locked by it.
    ///
    /// **Canary.** Drop the `console_gated` clause of `login_call_withheld`: the
    /// first assertion is red; drop the `READ` clause: the serving half is withheld.
    #[test]
    fn the_login_call_right_is_minted_only_for_a_gated_console() {
        use azos_abi::cap::{CapKind, CapPerms};
        use azos_topology::builder::{console_gated, login_call_withheld};
        use azos_topology::{CapSpec, MaybeStr};
        let cap = |kind, perms, target: &'static [u8]| CapSpec { kind, perms, target: MaybeStr::from_bytes(target), transfer: false, ops: 0 };
        let call = cap(CapKind::Endpoint, CapPerms::WRITE, b"endpoint.login");
        assert!(login_call_withheld(&call, 0), "nobody enrolled: no right to ask");
        assert_eq!(login_call_withheld(&call, 1), !console_gated(1), "a user enrolled: kept exactly when the build gates");
        let serve = cap(CapKind::Endpoint, CapPerms::READ, b"endpoint.login");
        assert!(!login_call_withheld(&serve, 0) && !login_call_withheld(&serve, 1), "the service's own half");
        let other = cap(CapKind::Endpoint, CapPerms::WRITE, b"endpoint.decisions");
        assert!(!login_call_withheld(&other, 0), "no other endpoint");
        assert!(!login_call_withheld(&cap(CapKind::Node, CapPerms::WRITE, b"endpoint.login"), 0), "only an endpoint");
    }

    /// **No task row can read the raw board seed.** `LinkKey::read` returns the
    /// reserved-sector key, which is also the seed every node key derives from.
    /// The rows that need an identity (`RPCSRV.ELF`, `MCPD.ELF`) hold `READ` on
    /// `linkkey` masked to `node_key` and nothing else on that endpoint. Only the
    /// `autorun` row (the kernel seeds `brain_client`, the link itself, from it)
    /// is `READ` unmasked. The network-facing `SSHD.ELF` holds no `linkkey` at all:
    /// its host key is in the keystore.
    ///
    /// **Canary.** Give either row the grant without its mask: red.
    #[test]
    fn no_task_row_may_read_the_board_seed_and_the_identity_rows_hold_a_masked_read() {
        let t = default_minimal();
        let linkkey = |c: &&azos_topology::CapSpec<'_>| c.kind == CapKind::Endpoint && c.target.as_bytes() == b"linkkey";
        let mut identity_rows = 0;
        for row in t.tasks().iter().filter(|r| r.name.as_bytes() != b"autorun") {
            for c in t.caps_of(row).iter().filter(linkkey) {
                identity_rows += 1;
                assert_identity_grant(c);
            }
        }
        // `RPCSRV.ELF`'s row is always there (it starts with `RPC_PEER_NODE`).
        let want = 1 + usize::from(azos_topology::builder::MCP_BRIDGE_ROW);
        assert_eq!(identity_rows, want, "a row gained or lost its node-identity grant");
        let autorun = t.tasks().iter().find(|r| r.name.as_bytes() == b"autorun").expect("the autorun row");
        let link: Vec<_> = t.caps_of(autorun).iter().filter(linkkey).collect();
        assert_eq!(link.len(), 1);
        assert_eq!((link[0].perms, link[0].ops), (CapPerms::READ, 0), "the link reads the key, whole");
    }

    /// **A row's `ops` survives the text.** A grant with a mask is emitted as
    /// `ops = N` and parses back to the same mask, and the topology comparison
    /// sees it; a grant without one is emitted without the key and reads as
    /// every op. A mask on a grant that names no kernel-hosted interface (a
    /// task's endpoint, a file), a mask of 0 and a mask that is not a number
    /// are refused at parse.
    ///
    /// **Canary.** Drop the `ops` key from the emitter: the mask reads 0 after
    /// the round trip. Drop the comparison in `first_difference`: the last
    /// assertion reads `None`.
    #[test]
    fn a_grants_op_mask_round_trips_and_is_refused_where_it_means_nothing() {
        use azos_topology::emit::{emit_caps, first_difference};
        use azos_topology::Binding;
        let row = |caps: &str| format!("[task.A.ELF]\ncaps = [ {caps} ]\n");
        let masked = row("{ kind = \"endpoint\", target = \"linkkey\", perm = \"r\", ops = 4 }");
        let mut topo = Topology::empty();
        parse_caps(masked.as_bytes(), &mut topo).expect("a masked grant");
        let c = topo.caps_of(&topo.tasks()[0])[0];
        assert_eq!((c.perms, c.ops), (CapPerms::READ, 4));
        let mut text = String::new();
        emit_caps(&topo, &Binding::default(), &mut text).unwrap();
        assert_eq!(text.matches("ops = 4").count(), 1, "{text}");
        let mut back = Topology::empty();
        parse_caps(text.as_bytes(), &mut back).unwrap();
        assert_eq!(first_difference(&topo, &back), None);
        assert_eq!(back.caps_of(&back.tasks()[0])[0].ops, 4);

        let plain = row("{ kind = \"endpoint\", target = \"linkkey\", perm = \"r\" }");
        let mut open = Topology::empty();
        parse_caps(plain.as_bytes(), &mut open).expect("an unmasked grant");
        assert_eq!(open.caps_of(&open.tasks()[0])[0].ops, 0);
        let mut text = String::new();
        emit_caps(&open, &Binding::default(), &mut text).unwrap();
        assert!(!text.contains("ops"), "{text}");
        assert_eq!(first_difference(&topo, &open), Some("grant ops"));

        for bad in [
            "{ kind = \"endpoint\", target = \"endpoint.svc\", perm = \"r\", ops = 4 }",
            "{ kind = \"node\", target = \"/fat\", perm = \"r\", ops = 4 }",
            "{ kind = \"endpoint\", target = \"linkkey\", perm = \"r\", ops = 0 }",
            "{ kind = \"endpoint\", target = \"linkkey\", perm = \"r\", ops = \"node_key\" }",
        ] {
            let mut t = Topology::empty();
            assert!(parse_caps(row(bad).as_bytes(), &mut t).is_err(), "{bad}");
        }
    }

    /// The row of the VM's monitor is granted its VM and one endpoint for every
    /// vCPU the pool can hold (up to what one monitor serves), so a guest with
    /// more than one CPU finds an endpoint for each. Canary: grant only
    /// `vcpu.0.0` again and the count is wrong.
    #[test]
    fn the_vmmd_row_grants_an_endpoint_for_every_vcpu_it_can_serve() {
        let t = default_minimal();
        let row = t.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_VMMD_IMAGE);
        assert_eq!(row.is_some(), azos_topology::builder::VMMD_ROW);
        let Some(row) = row else { return };
        let caps = t.caps_of(row);
        let vcpus = (azos_limits::HV_MAX_VCPUS as usize).min(azos_topology::builder::VMMD_VCPUS_MAX);
        assert_eq!(caps.len(), 1 + vcpus + 3, "vm.0, a vCPU each, the VmCtl endpoint it serves, the disk tree, the root");
        assert_eq!(caps[0].target.as_bytes(), b"vm.0");
        for k in 0..vcpus {
            let want = format!("vcpu.0.{k}");
            assert_eq!(caps[1 + k].target.as_bytes(), want.as_bytes());
            assert_eq!((caps[1 + k].kind, caps[1 + k].perms), (CapKind::Endpoint, CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::EXEC)));
        }
        assert_eq!((caps[1 + vcpus].target.as_bytes(), caps[1 + vcpus].kind, caps[1 + vcpus].perms), (&b"endpoint.vmctl"[..], CapKind::Endpoint, CapPerms::READ));
        assert_eq!(caps[2 + vcpus].target.as_bytes(), b"/fat/VM");
        assert_eq!(
            row.mem_pages as u64,
            azos_topology::builder::vmmd_pages(t.guests()),
            "the monitor's own frames and the RAM of the guests the built-in topology declares (none, or the example guest)"
        );
    }

    /// Kconfig `HV_EXAMPLE_GUEST` (`make azos-guest`): the built-in topology
    /// declares one guest, and only then. Its backends are the three an AzOS
    /// kernel's virtio drivers use, its RAM the Kconfig value, its envelope the
    /// `cautious` one (a NIC may reach the network, nothing physical).
    /// Canary: declare it unconditionally and a default build has a guest.
    #[test]
    fn the_example_guest_is_declared_only_under_its_kconfig() {
        let t = default_minimal();
        assert_eq!(t.guests().len(), azos_topology::builder::EXAMPLE_GUEST_ROW as usize);
        // Off (the default build): no guest at all. The test has teeth in both
        // builds; the declared row is checked with the Kconfig on: expand
        // config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+hv-host+hv-example-guest.config into a file and run the tests
        // with KCONFIG_CONFIG=<that file>.
        if !azos_topology::builder::EXAMPLE_GUEST_ROW {
            assert!(t.guests().is_empty(), "no HV_EXAMPLE_GUEST: the built-in topology declares no guest");
            return;
        }
        let g = t.guests().first().expect("HV_EXAMPLE_GUEST: the built-in topology declares the example guest");
        assert_eq!(g.name.as_bytes(), b"azos");
        assert_eq!((g.cpus, g.mem_mib), (1, azos_limits::HV_EXAMPLE_GUEST_MEM_MIB as u32));
        let devices: Vec<&[u8]> = g.devices().iter().map(|d| d.as_bytes()).collect();
        assert_eq!(devices, [&b"virtio-console"[..], b"virtio-blk", b"virtio-net"]);
        assert_eq!(g.envelope, azos_topology::Envelope::Cautious);
    }

    /// The monitor's row has to hold its own frames and each guest's RAM, in
    /// 4 KiB pages.
    #[test]
    fn the_vmmd_budget_is_its_own_frames_plus_the_ram_of_every_guest() {
        use azos_topology::GuestSpec;
        let g = |mib: u32| GuestSpec { cpus: 1, mem_mib: mib as _, ..GuestSpec::empty() };
        let own = azos_topology::builder::VMMD_MEM_PAGES as u64;
        assert_eq!(azos_topology::builder::vmmd_pages(&[]), own);
        assert_eq!(azos_topology::builder::vmmd_pages(&[g(1)]), own + 256);
        assert_eq!(azos_topology::builder::vmmd_pages(&[g(16), g(3)]), own + 19 * 256);
    }
}
