// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side parser tests for `azos_topology`, plus the P1
//! topology→cap_store cap-seed bridge suite (RFC-0003/RFC-0005 migration).
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
//! specifically (`azos_drv_*`, needed by `gpio_cap.rs`/`i2c_cap.rs`/
//! `pwm_cap.rs`/`motor_cap.rs`). See `shims/*/src/lib.rs` for what each
//! stand-in actually provides.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `topology_seed_test_drivers`.
extern crate topology_seed_test_drivers as azos_drv_actuator;
extern crate topology_seed_test_drivers as azos_drv_base;
extern crate topology_seed_test_drivers as azos_drv_block;
extern crate topology_seed_test_drivers as azos_drv_bus;
extern crate topology_seed_test_drivers as azos_drv_gpio;
extern crate topology_seed_test_drivers as azos_drv_irqchip;

#[path = "../../../../crates/core/ipc/src/cap.rs"]
pub mod cap;

#[path = "../../../../crates/core/ipc/src/cap_store.rs"]
pub mod cap_store;

#[path = "../../../../crates/core/ipc/src/gpio_cap.rs"]
pub mod gpio_cap;

#[path = "../../../../crates/core/ipc/src/i2c_cap.rs"]
pub mod i2c_cap;

#[path = "../../../../crates/core/ipc/src/pwm_cap.rs"]
pub mod pwm_cap;

#[path = "../../../../crates/core/ipc/src/motor_cap.rs"]
pub mod motor_cap;

// `drvreg_cap.rs` needs no shim at all: unlike its four siblings above it
// touches no driver, only `cap_store` (see that file's "Why the ops are not
// here"). It is pulled in because `cap_seed`'s `DriverRegistry` arm calls it.
#[path = "../../../../crates/core/ipc/src/drvreg_cap.rs"]
pub mod drvreg_cap;

// Real, no shim: `sensor_cap.rs` touches only `cap_store`, for the same reason
// `drvreg_cap.rs` does — the sensor READ lives in `crates/core/syscall` where the
// per-type dispatch can reach `azos_imu` and friends.
#[path = "../../../../crates/core/ipc/src/sensor_cap.rs"]
pub mod sensor_cap;

// `cap_seed`'s Channel arm mints through `channel::channel_grant_cap`, which
// reads the live channel's generation under the pool lock (RFC-0040 gap 1).
// Its own suite runs in `tests/host/ipc-chan-tests`; `channel.rs` has no embedded
// tests.
#[path = "../../../../crates/core/ipc/src/channel.rs"]
pub mod channel;

// A channel bound to an event port stores this link (wave 11, PORTWAIT).
#[path = "../../../../crates/core/ipc/src/port_link.rs"]
pub mod port_link;

/// Host stand-in for the `crates/core/ipc/src/port.rs` entry a linked channel's
/// send calls. No test here binds a channel to a port, so no link is ever
/// stored and this is never reached; it answers "the port is gone".
mod port {
    pub fn port_signal_channel(_link: crate::port_link::PortLink, _channel_ref: u32) -> bool {
        false
    }

    /// The kinds the pulled-in modules name (wave 15 N5b).
    #[allow(dead_code)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum PortSourceKind {
        Channel(u32),
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

// `mmio_cap.rs` touches `cap_store` and the board's MMIO region table, which
// the drivers shim pulls in real (`azos_drv_base::platform`). `cap_seed`'s
// `MmioRegion` arm calls it.
#[path = "../../../../crates/core/ipc/src/mmio_cap.rs"]
pub mod mmio_cap;

// RFC-0048 P3: `cap_seed`'s `Disk` arm mints through this, against the REAL
// partition table module the drivers shim pulls in.
#[path = "../../../../crates/core/ipc/src/disk_cap.rs"]
pub mod disk_cap;

// Wave 10: `cap_seed`'s `File` arm mints a directory-tree capability through
// this.
#[path = "../../../../crates/core/ipc/src/file_cap.rs"]
pub mod file_cap;

// RFC-0055 (wave 11): `cap_seed`'s `Launch` arm mints a launch grant through
// this.
#[path = "../../../../crates/core/ipc/src/launch_cap.rs"]
pub mod launch_cap;

// RFC-0040 gap 2: `seed_one_cap` mints an endpoint, so the module it mints
// through has to be under this harness too — the seed arm is what makes
// `"endpoint"` in `CAPS.TOML` grant something rather than silently nothing.
#[path = "../../../../crates/core/ipc/src/endpoint.rs"]
pub mod endpoint;

/// The serial lock `endpoint.rs`'s embedded suite takes.
///
/// Thinner than `tests/host/ipc-lease-tests`'s namesake on purpose: that one also
/// resets the `azos_sched` and `azos_mm` shims, which this crate does
/// not carry. What the endpoint suite needs here is only that its tests do not
/// run at the same time as each other — each begins by wiping the endpoint
/// pool, and `cargo test` runs test functions on several threads, so without
/// this one test's reset lands inside another's assertions.
/// `#[cfg(test)]`, and that is not cosmetic: only the embedded `mod tests`
/// uses it, so in the plain library build both items are dead code — and this
/// gate counts a warning as a failure. `tests/host/ipc-lease-tests`'s namesake is
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
policy              = \"cfs\"
priority_range      = [16, 30]

[sched]
partition_window_us = 5000
";

    /// RFC-0051 I4 on a kernel built without Kconfig ENERGY (this crate builds
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
        assert_eq!(be.policy, PolicyKind::Cfs);
        assert_eq!(be.priority_range, (16, 30));
        assert_eq!(topo.sched_config().partition_window_us, 5000);
    }

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
policy = \"rr\"
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
policy = \"rr\"
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
policy             = \"cfs\"
";

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
    { kind = \"motor\",       target = \"motor.0\", perm = \"rw\" },
    { kind = \"motor\",       target = \"motor.1\", perm = \"rw\" },
    { kind = \"channel-sub\", target = \"/cmd/motor\", perm = \"r\" },
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
        assert_eq!(caps_slice[0].kind, CapKind::Motor);
        assert_eq!(caps_slice[0].perms, CapPerms::RW);
        assert_eq!(caps_slice[2].kind, CapKind::Channel);
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
caps = [ { kind = \"motor\", target = \"motor.0\", perm = \"rw\" } ]

[task.b]
class = \"best_effort\"
caps = [ { kind = \"motor\", target = \"motor.0\", perm = \"w\" } ]
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
                "[task.a]\ncaps = [ {{ kind = \"motor\", target = \"motor.0\", perm = \"rw\" }} ]\n\n\
                 [task.b]\ncaps = [ {{ kind = \"motor\", target = \"{alias}\", perm = \"rw\" }} ]\n"
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
    { kind = \"motor\", target = \"motor.0\", perm = \"rw\" },
    { kind = \"motor\", target = \"motor.0\", perm = \"rw\" },
]

[task.other_wheel]
caps = [ { kind = \"motor\", target = \"motor.1\", perm = \"rw\" } ]

[task.observer]
caps = [
    { kind = \"motor\", target = \"motor.0\", perm = \"r\" },
    { kind = \"motor\", target = \"motor.1\", perm = \"r\" },
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
    { kind = \"shm\", target = \"a\", perm = \"r\" },
    { kind = \"shm\", target = \"b\", perm = \"rw\" },
    { kind = \"shm\", target = \"c\", perm = \"rwx\" },
    { kind = \"shm\", target = \"d\", perm = \"rwxd\" },
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
    fn realistic_caps_example_from_rfc() {
        // Verbatim from RFC-0005 (slightly trimmed).
        let caps = b"\
[task.rt_motor]
class    = \"hard_rt\"
priority = 5
caps = [
    { kind = \"motor\",       target = \"motor.0\",     perm = \"rw\" },
    { kind = \"motor\",       target = \"motor.1\",     perm = \"rw\" },
    { kind = \"encoder\",     target = \"encoder.0\",   perm = \"r\" },
    { kind = \"encoder\",     target = \"encoder.1\",   perm = \"r\" },
    { kind = \"channel-sub\", target = \"/cmd/motor\",  perm = \"r\" },
    { kind = \"channel-pub\", target = \"/state/motor\",perm = \"w\" },
]

[task.sensor_ahrs]
class    = \"hard_rt\"
priority = 4
caps = [
    { kind = \"i2c\",         target = \"bus.0/0x68\",  perm = \"rw\" },
    { kind = \"i2c\",         target = \"bus.0/0x76\",  perm = \"rw\" },
    { kind = \"channel-pub\", target = \"/sensors/imu\",perm = \"w\" },
    { kind = \"channel-pub\", target = \"/sensors/baro\",perm = \"w\" },
]

[task.behavior]
class    = \"best_effort\"
priority = 0
caps = [
    { kind = \"channel-sub\", target = \"/sensors/imu\",  perm = \"r\" },
    { kind = \"channel-sub\", target = \"/sensors/baro\", perm = \"r\" },
    { kind = \"channel-pub\", target = \"/cmd/motor\",    perm = \"w\" },
    { kind = \"service-call\", target = \"policy.run\",   perm = \"rw\" },
]
";
        let mut topo = Topology::empty();
        parse_sched(SCHED_PRIMER, &mut topo).unwrap();
        parse_caps(caps, &mut topo).unwrap();
        assert_eq!(topo.tasks_len(), 3);
        topo.admission_check().unwrap();
    }
}

#[cfg(test)]
mod verify_tests {
    use azos_topology::{verify_signature, VerifyError};

    #[test]
    fn zero_signature_rejected() {
        let toml = b"[task.a]\ncaps = []\n";
        let sig = [0u8; 64];
        let key = [0u8; 32];
        let r = verify_signature(toml, &sig, &key);
        assert_eq!(r, Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn wrong_signature_size_caught() {
        let toml = b"[task.a]\n";
        let key = [0u8; 32];
        let r = verify_signature(toml, &[0u8; 30], &key);
        assert_eq!(r, Err(VerifyError::BadSignatureLen));
    }

    #[test]
    fn wrong_key_size_caught() {
        let toml = b"[task.a]\n";
        let sig = [0u8; 64];
        let r = verify_signature(toml, &sig, &[0u8; 16]);
        assert_eq!(r, Err(VerifyError::BadKeyLen));
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

    /// Wave 11 (LEASE3): `lease_seal = true` in a row requires sealed lease
    /// grants from its task. Per row, off by default, kept on the last row,
    /// and only the words `true`/`false`; `row_lease_seal` answers by name.
    /// A format-2 key, as `restart` (wave 12): a format-1 file carrying it is
    /// refused with `FieldNeedsFormat`, whatever its value.
    ///
    /// **Canaries.** Drop the reset when a new `[task.*]` section starts: `B`
    /// inherits `A`'s `true`. Drop `set_last_task_lease_seal` from the final
    /// commit: `C` reads `false`. Drop the `format < 2` refusal from the
    /// `lease_seal` arm: the format-1 files parse and the `FieldNeedsFormat`
    /// assertion goes red.
    #[test]
    fn lease_seal_is_per_row_and_off_by_default() {
        let mut topo = Topology::empty();
        parse_caps(b"format = 2\n[task.A.ELF]\nlease_seal = true\ncaps = []\n[task.B.ELF]\ncaps = []\n", &mut topo).unwrap();
        assert!(topo.tasks()[0].lease_seal);
        assert!(!topo.tasks()[1].lease_seal, "B inherited A's lease_seal");
        assert!(topo.row_lease_seal(b"A.ELF"));
        assert!(!topo.row_lease_seal(b"B.ELF"));
        assert!(!topo.row_lease_seal(b"NONE.ELF"), "no row, no requirement");

        let mut topo = Topology::empty();
        parse_caps(b"format = 2\n[task.C.ELF]\ncaps = []\nlease_seal = true   # producer\n", &mut topo).unwrap();
        assert!(topo.tasks()[0].lease_seal, "the last row's value was dropped");

        for bad in [&b"format = 2\n[task.E.ELF]\nlease_seal = yes\n"[..],
                    b"format = 2\n[task.E.ELF]\nlease_seal = trueish\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::BadValue),
                "{:?}", core::str::from_utf8(bad));
        }

        // Format 1 (no `format` line, or `format = 1`): refused, not read,
        // for either value — `false` too, since the writer did not mean it.
        for bad in [&b"[task.A.ELF]\nlease_seal = true\ncaps = []\n"[..],
                    b"format = 1\n[task.A.ELF]\nlease_seal = false\n"] {
            let mut topo = Topology::empty();
            assert_eq!(parse_caps(bad, &mut topo), Err(ParseError::FieldNeedsFormat),
                "{:?}", core::str::from_utf8(bad));
        }
    }

    /// Which rows of the built-in topology the kernel starts. A board build
    /// (this crate's default features, as `vf2`/`k1`) starts only the user
    /// shell, and only with Kconfig `USER_SHELL` (RFC-0055, wave 11); the
    /// `qemu` shape (`ring3-driver-start`) adds exactly the two ring-3 driver
    /// images, and nothing else — least of all a row that names a role, not
    /// an image.
    #[test]
    fn only_the_ring3_driver_rows_start_and_only_under_qemu() {
        let topo = default_minimal();
        let started: Vec<&str> = topo.tasks().iter().filter(|t| t.start).map(|t| t.name.as_str()).collect();
        let shell: &[&str] = if azos_limits::USER_SHELL { &["SH.ELF"] } else { &[] };
        #[cfg(not(feature = "ring3-driver-start"))]
        {
            let mut want = shell.to_vec();
            if cfg!(feature = "lx-server") { want.push("LXSRV.ELF"); }
            assert_eq!(started, want, "a board topology starts {started:?}");
        }
        #[cfg(feature = "ring3-driver-start")]
        {
            let mut want = vec![];
            if azos_topology::builder::BUZZDRV_ROW { want.push("BUZZDRV.ELF"); }
            if azos_topology::builder::INADRV_ROW { want.push("INADRV.ELF"); }
            want.extend_from_slice(shell);
            // RFC-0053 L0: the Linux server skeleton starts too, and only
            // under `lx-server`.
            if cfg!(feature = "lx-server") { want.push("LXSRV.ELF"); }
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
        // (4 became known in wave 15: the TOPOSIGN binding keys.)
        for bad in [&b"format = 5\n[task.A.ELF]\n"[..], b"format = 0\n[task.A.ELF]\n",
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
    /// gate's `restart-smoke` topology sets the two ring-3 driver rows.
    #[test]
    fn built_in_rows_restart_on_failure() {
        let topo = default_minimal();
        for t in topo.tasks() {
            let want = match t.name.as_bytes() {
                #[cfg(feature = "restart-smoke")]
                b"BUZZDRV.ELF" => RestartPolicy::Always,
                #[cfg(feature = "restart-smoke")]
                b"INADRV.ELF" => RestartPolicy::No,
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

    /// Wave 12 (DRVPLACE): the buzzer's ring-3 row exists exactly when the
    /// driver is placed in ring 3.
    ///
    /// **Canary.** Make `BUZZDRV_ROW` `true` regardless: the `buzzer-kernel`
    /// run (gate `topology(drvplace)`) goes red on the second assertion.
    #[test]
    fn the_buzzdrv_row_follows_the_placement() {
        let topo = default_minimal();
        let has = topo.tasks().iter().any(|t| t.name.as_bytes() == b"BUZZDRV.ELF");
        assert_eq!(has, azos_topology::builder::BUZZDRV_ROW);
        #[cfg(not(feature = "buzzer-kernel"))]
        assert!(has, "ring-3 placement without its row");
        #[cfg(feature = "buzzer-kernel")]
        assert!(!has, "kernel placement still declares BUZZDRV.ELF");
    }
}

#[cfg(test)]
mod abi_tests {
    use azos_topology::{default_minimal, parse_caps, AdmissionError, ParseError, TaskAbi, Topology};

    /// **Wave 12 (RFC-0047): `abi` is a format-3 key.** A row is native unless
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

    /// **RFC-0047 P6: a Linux row holds no hardware capability.** Files,
    /// sockets, pipes and launch grants are admitted; a GPIO line refuses
    /// the whole topology, wherever the row sits. The same capability on a
    /// native row is admitted.
    ///
    /// **Canary.** Let `TaskAbi::linux_may_hold` answer `true` for every
    /// kind: the GPIO row parses.
    #[test]
    fn a_linux_row_with_a_hardware_capability_is_refused() {
        let ok = b"format = 3\n[task.L.ELF]\nabi = \"linux\"\ncaps = [ { kind = \"file\", target = \"/fat\", perm = \"rw\" }, { kind = \"launch\", target = \"L.ELF\", perm = \"x\" } ]\n";
        let mut topo = Topology::empty();
        parse_caps(ok, &mut topo).unwrap();
        assert_eq!(topo.abi_of(b"L.ELF"), TaskAbi::Linux);

        let gpio_linux = b"format = 3\n[task.L.ELF]\nabi = \"linux\"\ncaps = [ { kind = \"gpio\", target = \"gpio.3\", perm = \"rw\" } ]\n[task.N.ELF]\n";
        let mut topo = Topology::empty();
        assert_eq!(parse_caps(gpio_linux, &mut topo),
                   Err(ParseError::Admission(AdmissionError::LinuxRowHoldsHardware)));
        // Last row too (the final commit, not only the section switch).
        let gpio_last = b"format = 3\n[task.N.ELF]\n[task.L.ELF]\nabi = \"linux\"\ncaps = [ { kind = \"gpio\", target = \"gpio.3\", perm = \"rw\" } ]\n";
        let mut topo = Topology::empty();
        assert_eq!(parse_caps(gpio_last, &mut topo),
                   Err(ParseError::Admission(AdmissionError::LinuxRowHoldsHardware)));
        let gpio_native = b"format = 3\n[task.N.ELF]\ncaps = [ { kind = \"gpio\", target = \"gpio.3\", perm = \"rw\" } ]\n";
        let mut topo = Topology::empty();
        parse_caps(gpio_native, &mut topo).unwrap();
        for k in [azos_abi::cap::CapKind::Gpio, azos_abi::cap::CapKind::Motor,
                  azos_abi::cap::CapKind::Irq, azos_abi::cap::CapKind::MmioRegion,
                  azos_abi::cap::CapKind::Power, azos_abi::cap::CapKind::Disk] {
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
            assert!(topo.caps_of(r).iter().any(|c| c.kind == CapKind::File && c.target.as_bytes() == b"/tmp"));
            assert!(topo.caps_of(r).iter().all(|c| TaskAbi::linux_may_hold(c.kind)));
        }
        let sh = topo.tasks().iter().find(|t| t.name.as_bytes() == b"SH.ELF").expect("SH.ELF row");
        let grant = topo.caps_of(sh).iter().any(|c| {
            c.kind == CapKind::Launch && c.perms.contains(CapPerms::EXEC) && c.target.as_bytes() == b"BUSYBOX.ELF"
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
                kind: CapKind::Motor,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false,
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
                kind: CapKind::Motor,
                perms: CapPerms::WRITE,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false,
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
                kind: CapKind::Motor,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false,
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
                kind: CapKind::Motor,
                perms: CapPerms::RW,
                target: MaybeStr::from_bytes(b"motor.2"),
                transfer: false,
            }],
        )
        .unwrap();
        assert_eq!(t.admission_check(), Err(AdmissionError::MotorWriteConflict));
    }

    #[test]
    fn default_topology_has_all_five_classes() {
        let t = default_minimal();
        assert_eq!(t.classes_len(), 5);
        // Names match.
        let names: [&[u8]; 5] = [
            b"safety_critical",
            b"hard_rt",
            b"soft_rt",
            b"best_effort",
            b"idle",
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
                    CapKind::Pwm => MOTOR_PWM
                        .iter()
                        .any(|r| c.target == MaybeStr::from_bytes(r)),
                    CapKind::Gpio => MOTOR_GPIO
                        .iter()
                        .any(|r| c.target == MaybeStr::from_bytes(r)),
                    // `CapKind::Motor` is the drivetrain's OWN family and is
                    // granted on purpose — the point of this test is the two
                    // families that reach the same hardware from underneath.
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
        // spawned process gets any capability at all (RFC-0040 gap 2).
        // +3 since 2026-09-24: the unconditional board service registry rows
        // (`GPIODRV.ELF`/`REFLEX.ELF`/`BRAINCLI.ELF`) — owner decision, an
        // ELF ships on a board volume iff the topology declares a service it
        // provides. See `crates/core/topology/src/builder.rs`'s
        // `TASK_GPIODRV_IMAGE` block comment.
        // +3 in wave 9: the ring-3 ML service (MLSRV.ELF) and the ring-3
        // driver rows (BUZZDRV.ELF/INADRV.ELF).
        assert_eq!(t.tasks_len(), if cfg!(feature = "ipc-endpoint-canary") { 19 } else { 17 }
            - !azos_topology::builder::INADRV_ROW as usize
            - !azos_topology::builder::BUZZDRV_ROW as usize
            + cfg!(feature = "lx-server") as usize
            + azos_topology::builder::LXHELLO_ROW as usize
            + azos_topology::builder::BUSYBOX_ROW as usize); // +3 in wave 11: SH.ELF, TOOLBOX.ELF, POWER (RFC-0055); +4 in wave 12: FLIGHT/BEHAVIOR/CONFIG/OTA.ELF; -1 per driver placed in the kernel; +1 under lx-server: LXSRV.ELF (RFC-0053 L0); +1 for the wave-12 Linux test row (gate only); +1 in wave 15: TRACECTL.ELF
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
    /// the right to register as `DRV_KIND_ML` (18), read-write, and no other
    /// capability; a frame budget of its own.
    #[test]
    fn the_ml_service_row_grants_exactly_its_driver_kind() {
        let t = default_minimal();
        let task = t.find_task(&MaybeStr::from_bytes(b"MLSRV.ELF")).expect("MLSRV.ELF row");
        use azos_abi::cap::{CapKind, CapPerms};
        let caps = t.caps_of(task);
        assert_eq!(caps.len(), 1, "one capability, nothing else");
        assert_eq!(caps[0].kind, CapKind::DriverRegistry);
        assert_eq!(caps[0].perms, CapPerms::RW);
        assert_eq!(caps[0].target, MaybeStr::from_bytes(b"drv.18"));
        assert_eq!(task.mem_pages, 64);
    }

    #[test]
    fn board_service_registry_declares_the_three_real_board_images() {
        let t = default_minimal();
        for name in [&b"GPIODRV.ELF"[..], &b"REFLEX.ELF"[..], &b"BRAINCLI.ELF"[..]] {
            let task = t
                .find_task(&MaybeStr::from_bytes(name))
                .unwrap_or_else(|| panic!("board service row missing: {:?}", core::str::from_utf8(name)));
            assert_eq!(
                t.caps_of(task).len(),
                0,
                "board service rows must carry no caps — authority still flows through `autorun`"
            );
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
        // (RFC-0040 gap 2) — the CALLER half of the demo service; the server
        // half is `READ` on the `EPSRV.ELF` row.
        // Under `ipc-endpoint-canary` only: a board topology declares no
        // endpoint it does not serve, so these rows compile out entirely.
        assert_eq!(
            caps.iter().any(|c| c.kind == CapKind::Endpoint && c.perms == CapPerms::WRITE),
            cfg!(feature = "ipc-endpoint-canary"),
            "the demo endpoint's CALLER half must exist under the canary and only there",
        );
        // **The ordering is load-bearing, so it is asserted rather than
        // assumed.** Endpoints are created in the order their capabilities
        // are seeded, `cap_lookup` matches on the POOL INDEX, and ring 3 has
        // no by-name lookup — so `abitest` reaching `endpoint.demo` at index
        // 0 depends on nothing being created before it. Swap these two rows
        // and this fails, instead of `abitest` silently calling the
        // benchmark's server.
        let eps: Vec<&[u8]> = caps
            .iter()
            .filter(|c| c.kind == CapKind::Endpoint)
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
            caps.iter().any(|c| c.kind == CapKind::Motor),
            cfg!(feature = "profile-actuation"),
            "a drivetrain belongs to a deployment profile, not to the default topology",
        );
        // Shutdown/reboot and model-load authority are NOT in the default
        // topology (owner decision 2026-09-26: `Cap<Power>`/`Cap<AiSession>`
        // are minted from the SIGNED topology). Granting them here would hand
        // them to whatever image CONFIG.INI autoruns; before these kinds had a
        // minter, ring 3 could not shut the machine down at all, and the
        // default keeps it that way. A signed topology that wants a ring-3
        // power manager names `power` / `ai.session` for that image.
        assert!(
            !caps.iter().any(|c| c.kind == CapKind::Power || c.kind == CapKind::AiSession),
            "the default topology must not grant Power/AiSession to autorun",
        );
        // The brain-link key: READ only, one grant, never transferable. The
        // kernel additionally withholds it from any image whose seccomp row
        // does not list SYS_LINK_KEY_READ_TYPED (kernel/src/tasks/loader.rs autorun
        // seeding), so this row alone does not decide who gets the key.
        let lk: Vec<_> = caps.iter().filter(|c| c.kind == CapKind::LinkKey).collect();
        assert_eq!(lk.len(), 1, "exactly one LinkKey grant in the default topology");
        assert_eq!(lk[0].perms, CapPerms::READ, "the link key is read, never written");
        assert!(!lk[0].transfer, "the link key capability must not be transferable");
        // The entropy pool (wave 9, P9): READ only, one grant, never
        // transferable, and withheld by the kernel from an image whose row
        // does not list SYS_ENTROPY_READ_TYPED, like the link key.
        let en: Vec<_> = caps.iter().filter(|c| c.kind == CapKind::Entropy).collect();
        assert_eq!(en.len(), 1, "exactly one Entropy grant in the default topology");
        assert_eq!(en[0].perms, CapPerms::READ, "the entropy pool is read, never written");
        assert!(!en[0].transfer, "the entropy capability must not be transferable");
        let motors = if cfg!(feature = "profile-actuation") { 2 } else { 0 };
        // `disk.part.1` RW and (wave 10) `disk.part.0` READ under
        // `disk-part-row` only (RFC-0048 P3 gate row).
        let disk = if cfg!(feature = "disk-part-row") { 2 } else { 0 };
        assert_eq!(
            caps.len(),
            motors + disk
                + match (cfg!(feature = "cap-refusal-canary"), cfg!(feature = "ipc-endpoint-canary")) {
                    // `ipc-endpoint-canary`: the demo and bench endpoints,
                    // and (wave 12) `Cap<Launch>` on TOOLBOX.ELF for
                    // vsbench's `spawn+wait` lane.
                    (true, true) => 24, (true, false) => 21,
                    (false, true) => 19, (false, false) => 16,
                },
            "drv.1 RW + sensor.0-9 READ + pwm.4 RW + gpio.20 RW + bus.0/0x68 RW + linkkey READ \
             + entropy READ, \
             plus pwm.0/gpio.0/mmio.0 and the /fat and /tmp trees under the canary, plus \
             motor.0/1 RW only under the actuation profile"
        );
        // The MMIO grant: READ on index 0, the read-only RTC, and only in the
        // build whose table has it (RFC-0043). WRITE would be refused at mint.
        let mmio: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::MmioRegion)
            .collect();
        assert_eq!(mmio.len(), if cfg!(feature = "cap-refusal-canary") { 1 } else { 0 });
        if let Some(m) = mmio.first() {
            assert_eq!(m.perms, CapPerms::READ);
            assert_eq!(m.target.as_str(), "mmio.0");
        }
        // The partition grants: exactly `disk.part.1` RW and `disk.part.0`
        // READ under `disk-part-row`, and no disk capability of any kind in
        // any other build.
        let disks: Vec<_> = caps.iter().filter(|c| c.kind == CapKind::Disk).collect();
        assert_eq!(disks.len(), disk, "a Disk grant outside the disk-part-row build");
        if let [d1, d0] = disks[..] {
            assert_eq!((d1.perms, d1.target.as_str()), (CapPerms::RW, "disk.part.1"));
            assert_eq!((d0.perms, d0.target.as_str()), (CapPerms::READ, "disk.part.0"));
        }
        // Wave 10: the directory trees ring 3 may change, WRITE, never
        // transferable, and only under the canary (a board grants no tree).
        let trees: Vec<_> = caps.iter().filter(|c| c.kind == CapKind::File).collect();
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
        let has_pwm_motor = caps.iter().any(|c| c.kind == CapKind::Pwm
            && c.target == MaybeStr::from_bytes(b"pwm.0"));
        let has_gpio_motor = caps.iter().any(|c| c.kind == CapKind::Gpio
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
                .filter(|c| c.kind == CapKind::Motor && c.perms == CapPerms::RW)
                .count(),
            if cfg!(feature = "profile-actuation") { 2 } else { 0 }
        );
        // The IMU is READ-only, in every build. `bus.0/0x68` is the MPU-6050
        // that feeds L0's Falling/Spinning/tilt checks; WRITE on it is the
        // authority to sleep the device and blind the reflex layer without
        // tripping anything. Asserted on the PERMS, not on the presence, so a
        // widening back to RW fails here rather than on a robot.
        let imu: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::I2c)
            .collect();
        assert_eq!(imu.len(), 1, "one I2C grant, the IMU");
        assert_eq!(
            imu[0].perms,
            CapPerms::READ,
            "the IMU grant must never carry WRITE: `i2c_read_cap` and \
             `i2c_detect_cap` both need only READ, so WRITE buys a reader \
             nothing and buys an attacker `PWR_MGMT_1`"
        );
        // The driver-registry grant names ONE kind. `drv.1` is
        // `azos_abi::drv_kind::DRV_KIND_GPIO` (0x0001) in decimal, per
        // the target convention in `crates/core/ipc/src/cap_seed.rs`; the number
        // is asserted below against the constant itself, which this crate can
        // reach and `crates/core/topology` deliberately cannot.
        let drv: Vec<_> = caps
            .iter()
            .filter(|c| c.kind == CapKind::DriverRegistry)
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
            .find(|c| c.kind == CapKind::DriverRegistry)
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
    /// device needs — registering as its one driver kind, and its one PWM
    /// channel or I2C slave — and its `drv.N` target is the kind the driver
    /// registers, read from `crates/core/abi` (the join `autorun`'s `drv.1` has).
    #[test]
    fn ring3_driver_rows_grant_one_kind_and_one_device() {
        use azos_abi::cap::{CapKind, CapPerms};
        use azos_abi::drv_kind::{DRV_KIND_BUZZER, DRV_KIND_POWER_MON};
        let t = default_minimal();
        for (image, kind, dev_kind, dev) in [
            (&b"BUZZDRV.ELF"[..], DRV_KIND_BUZZER, CapKind::Pwm, "pwm.5"),
            (&b"INADRV.ELF"[..], DRV_KIND_POWER_MON, CapKind::I2c, "bus.1/0x40"),
        ] {
            // Wave 11/12 (DRVPLACE): no ring-3 row under the kernel placement.
            if (image == b"INADRV.ELF" && !azos_topology::builder::INADRV_ROW)
                || (image == b"BUZZDRV.ELF" && !azos_topology::builder::BUZZDRV_ROW)
            {
                assert!(t.find_task(&MaybeStr::from_bytes(image)).is_none());
                continue;
            }
            let task = t.find_task(&MaybeStr::from_bytes(image)).expect("driver row present");
            let caps = t.caps_of(task);
            assert_eq!(caps.len(), 2, "{:?}", core::str::from_utf8(image));
            assert_eq!(caps[0].kind, CapKind::DriverRegistry);
            assert_eq!(caps[0].perms, CapPerms::RW);
            assert_eq!(caps[0].target.as_str(), format!("drv.{kind}"));
            assert_eq!(caps[1].kind, dev_kind);
            assert_eq!(caps[1].perms, CapPerms::RW);
            assert_eq!(caps[1].target.as_str(), dev);
            assert_eq!(task.mem_pages, 64, "frame budget");
        }
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
        assert_eq!(t.classes_len(), 5);
        // supervisor, brain_link, autorun (P1 cap-seed migration entry).
        // 5 since 2026-09-21: supervisor, brain_link, autorun, the
        // `VSSRV.ELF` benchmark server (a `fork()`ed peer can never be
        // addressed by capability) and the
        // `EPSRV.ELF` row — the first named after an IMAGE, which is how a
        // spawned process gets any capability at all (RFC-0040 gap 2).
        // +3 since 2026-09-24: the unconditional board service registry rows
        // (`GPIODRV.ELF`/`REFLEX.ELF`/`BRAINCLI.ELF`) — owner decision, an
        // ELF ships on a board volume iff the topology declares a service it
        // provides. See `crates/core/topology/src/builder.rs`'s
        // `TASK_GPIODRV_IMAGE` block comment.
        // +3 in wave 9: the ring-3 ML service (MLSRV.ELF) and the ring-3
        // driver rows (BUZZDRV.ELF/INADRV.ELF).
        assert_eq!(t.tasks_len(), if cfg!(feature = "ipc-endpoint-canary") { 19 } else { 17 }
            - !azos_topology::builder::INADRV_ROW as usize
            - !azos_topology::builder::BUZZDRV_ROW as usize
            + cfg!(feature = "lx-server") as usize
            + azos_topology::builder::LXHELLO_ROW as usize
            + azos_topology::builder::BUSYBOX_ROW as usize); // +3 in wave 11: SH.ELF, TOOLBOX.ELF, POWER (RFC-0055); +4 in wave 12: FLIGHT/BEHAVIOR/CONFIG/OTA.ELF; -1 per driver placed in the kernel; +1 under lx-server: LXSRV.ELF (RFC-0053 L0); +1 for the wave-12 Linux test row (gate only); +1 in wave 15: TRACECTL.ELF

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
        // spawned process gets any capability at all (RFC-0040 gap 2).
        // +3 since 2026-09-24: the unconditional board service registry rows
        // (`GPIODRV.ELF`/`REFLEX.ELF`/`BRAINCLI.ELF`) — owner decision, an
        // ELF ships on a board volume iff the topology declares a service it
        // provides. See `crates/core/topology/src/builder.rs`'s
        // `TASK_GPIODRV_IMAGE` block comment.
        // +3 in wave 9: the ring-3 ML service (MLSRV.ELF) and the ring-3
        // driver rows (BUZZDRV.ELF/INADRV.ELF).
        assert_eq!(t.tasks_len(), if cfg!(feature = "ipc-endpoint-canary") { 19 } else { 17 }
            - !azos_topology::builder::INADRV_ROW as usize
            - !azos_topology::builder::BUZZDRV_ROW as usize
            + cfg!(feature = "lx-server") as usize
            + azos_topology::builder::LXHELLO_ROW as usize
            + azos_topology::builder::BUSYBOX_ROW as usize); // +3 in wave 11: SH.ELF, TOOLBOX.ELF, POWER (RFC-0055); +4 in wave 12: FLIGHT/BEHAVIOR/CONFIG/OTA.ELF; -1 per driver placed in the kernel; +1 under lx-server: LXSRV.ELF (RFC-0053 L0); +1 for the wave-12 Linux test row (gate only); +1 in wave 15: TRACECTL.ELF
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
// P1 cap-seed bridge — RFC-0003/RFC-0005 migration
// ──────────────────────────────────────────────────────────────────────────
//
// `crates/core/ipc/src/cap_seed.rs` decodes a `CapSpec { kind, perms, target, transfer: false }` (the
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
    const FIRST_TID: u32 = 32;

    static NEXT_ID: AtomicU32 = AtomicU32::new(FIRST_TID);

    /// Hand out a fresh, never-reused TID bound to its own task-pool slot in
    /// the `azos_sched` shim — mirrors `tests/host/cap-tests`' `fresh_task`.
    /// `pub(crate)` so `sensor_cap_tests` uses this ONE counter.
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

    /// A decl with GPIO/I2C/PWM/Motor grants produces exactly those
    /// minted caps — the part A requirement, end to end: `Topology` decl →
    /// bridge → `cap_store::get` sees the right resource id under each
    /// kind's own permission requirement.
    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
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
                    kind: CapKind::Gpio,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"gpio.9"),
                    transfer: false,
                },
                CapSpec {
                    kind: CapKind::I2c,
                    perms: CapPerms::READ,
                    target: MaybeStr::from_bytes(b"bus.1/0x76"),
                    transfer: false,
                },
                CapSpec {
                    kind: CapKind::Pwm,
                    perms: CapPerms::WRITE,
                    target: MaybeStr::from_bytes(b"pwm.3"),
                    transfer: false,
                },
                CapSpec {
                    kind: CapKind::Motor,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"motor.1"),
                    transfer: false,
                },
            ],
        )
        .unwrap();
        let task = topo.find_task(&MaybeStr::from_bytes(b"probe")).unwrap();
        let tid = fresh_tid();

        let mut minted = Vec::new();
        for cap in topo.caps_of(task) {
            let handle = crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str())
                .unwrap_or_else(|| panic!("expected a typed minter for {:?}", cap.kind));
            minted.push((cap.kind, handle));
        }
        assert_eq!(minted.len(), 4, "exactly the four declared grants, no more, no less");

        for (kind, handle) in minted {
            match kind {
                CapKind::Gpio => assert_eq!(
                    cap_store::get(tid, Cap::<targets::Gpio>::from_raw(handle), CapPerms::READ),
                    Ok(9)
                ),
                CapKind::I2c => assert_eq!(
                    cap_store::get(tid, Cap::<targets::I2c>::from_raw(handle), CapPerms::READ),
                    Ok((1u32 << 8) | 0x76)
                ),
                CapKind::Pwm => assert_eq!(
                    cap_store::get(tid, Cap::<targets::Pwm>::from_raw(handle), CapPerms::WRITE),
                    Ok(3)
                ),
                CapKind::Motor => assert_eq!(
                    cap_store::get(tid, Cap::<targets::Motor>::from_raw(handle), CapPerms::WRITE),
                    Ok(1)
                ),
                other => panic!("unexpected kind in this decl: {:?}", other),
            }
        }
    }

    /// Kinds with no typed minter yet (`Irq`) or a target that does not parse
    /// under its kind's convention are skipped (`None`), not guessed at or
    /// panicked on.
    ///
    /// `Sensor` was in the first list until 2026-09-07 and is now minted; its
    /// negative cases moved to `sensor_cap_tests` and to the malformed
    /// targets below, so this test lost none of its reach.
    /// **A motor id outside the drivetrain mints nothing** (audit unit 2).
    /// Ids 2 and 3 are real slots in `azos_robot`'s four-motor table, and
    /// `SYS_MOTOR_SPEED_TYPED` hands a cap's id to `motor_set_reporting`
    /// without the pair rule, so a minted `motor.2` was authority over that
    /// slot. The two wheels still mint, in the same table.
    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn a_motor_id_outside_the_drivetrain_is_not_minted() {
        let tid = fresh_tid();
        for target in ["motor.2", "motor.3", "motor.4", "motor.4294967295"] {
            assert!(
                crate::cap_seed::seed_one_cap(tid, CapKind::Motor, CapPerms::RW, target).is_none(),
                "{target}"
            );
        }
        assert_eq!(cap_store::occupied(tid), 0, "and nothing was written to the table");
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Motor, CapPerms::RW, "motor.0").is_some());
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Motor, CapPerms::RW, "motor.1").is_some());
        assert_eq!(crate::motor_cap::DRIVETRAIN_MOTORS, 2);
    }

    #[test]
    fn unminted_kinds_and_unparseable_targets_are_skipped() {
        let tid = fresh_tid();
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Sensor, CapPerms::READ, "sensor.imu")
            .is_none());
        // U03-2 (2026-09-26): `Cap<Irq>` HAS a minter now; line 0 is the one
        // it refuses (SBI/M-mode reserved), so that is the "skipped" case here.
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Irq, CapPerms::READ, "irq.0").is_none());
        assert!(crate::cap_seed::seed_one_cap(tid, CapKind::Motor, CapPerms::RW, "motor.left")
            .is_none());
        // Path-shaped channel target — no name->id registry (documented gap).
        assert!(
            crate::cap_seed::seed_one_cap(tid, CapKind::Channel, CapPerms::RW, "/safety/estop")
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
        let forged: Cap<targets::Motor> = Cap::NULL;
        assert_eq!(
            cap_store::get(tid, forged, CapPerms::WRITE),
            Err(CapError::Stale)
        );
    }

    /// `default_minimal()`'s "autorun" entry (added for the P1 migration —
    /// see `crates/core/topology/src/builder.rs`) round-trips through the same
    /// bridge call `kernel/src/tasks/loader.rs`'s autorun block makes, and the
    /// result satisfies the pair-write rule `motor_cap.rs::require_pair_write`
    /// enforces for every actuation syscall.
    #[test]
    fn default_minimal_autorun_entry_seeds_a_write_satisfying_motor_pair() {
        let topo = azos_topology::default_minimal();
        let task = topo
            .find_task(&MaybeStr::from_bytes(b"autorun"))
            .expect("autorun task declared in default_minimal()");
        let tid = fresh_tid();

        let mut minted = 0;
        for cap in topo.caps_of(task) {
            if crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str())
                .is_some()
            {
                minted += 1;
            }
        }
        // The drivetrain is two of these and moves with `profile-actuation`.
        let motors = if cfg!(feature = "profile-actuation") { 2 } else { 0 };
        assert_eq!(
            minted,
            motors
                + match (cfg!(feature = "cap-refusal-canary"), cfg!(feature = "ipc-endpoint-canary")) {
                    // `ipc-endpoint-canary`: the demo and bench endpoints,
                    // and (wave 12) `Cap<Launch>` on TOOLBOX.ELF for
                    // vsbench's `spawn+wait` lane.
                    (true, true) => 24, (true, false) => 21,
                    (false, true) => 19, (false, false) => 16,
                },
            "driver-registry + 10 sensor types + 1 pwm + 1 gpio + 1 i2c + linkkey + entropy, \
             plus pwm.0/gpio.0/mmio.0 and the /fat and /tmp trees under the canary, plus the \
             2 motors only under the actuation profile"
        );

        // Same primitive `require_pair_write` uses — proves the seed is
        // locatable by kind+resource, not just "some cap got minted".
        //
        // And the negative half, which is the point of the 2026-09-21 pivot:
        // without the actuation profile the autorun row holds NEITHER motor,
        // so `require_pair_write` cannot be satisfied by anything this
        // topology declares. A grant that silently came back would flip this.
        let holds_either = cap_store::with_table(tid, |t| {
            t.holds_kind_resource_with(CapKind::Motor, 0, CapPerms::WRITE)
                || t.holds_kind_resource_with(CapKind::Motor, 1, CapPerms::WRITE)
        });
        let pair_ok = cap_store::with_table(tid, |t| {
            t.holds_kind_resource_with(CapKind::Motor, 0, CapPerms::WRITE)
                && t.holds_kind_resource_with(CapKind::Motor, 1, CapPerms::WRITE)
        });
        if cfg!(feature = "profile-actuation") {
            assert_eq!(pair_ok, Some(true), "the actuation profile declares both wheels");
        } else {
            assert_eq!(holds_either, Some(false),
                "a generic deployment holds no motor capability at all");
        }
    }

    /// The same seed, taken through the gate the actuation syscalls actually
    /// call instead of through the primitive underneath it.
    ///
    /// The test above asks `holds_kind_resource_with` directly. That proves
    /// the seed is locatable; it does not prove `require_pair_write` consults
    /// it, because nothing in that assertion runs `require_pair_write`. This
    /// one calls `motor_cap::motor_set_target_cap` — the exact function
    /// `crates/core/syscall/src/handlers.rs::sys_motor_set_target_typed` calls with
    /// the handle `SYS_CAP_LOOKUP` hands back — so topology decl → cap_seed →
    /// pair rule is covered end to end.
    ///
    /// The negative half declares one wheel only. That is not a hypothetical
    /// shape: `default_minimal()` is a development default and the production
    /// path parses a signed `CAPS.TOML`, which can name `motor.0` alone.
    // M40 (2026-09-26): `motor` is a profile word; without `profile-actuation`
    // the parser refuses it and no Motor cap mints — this test is profile-only.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn topology_seeded_cap_drives_the_pair_gate_only_when_both_wheels_are_declared() {
        use crate::cap::CapError;
        use crate::motor_cap::{motor_set_target_cap, MotorCapError};

        // Positive: a task declaring BOTH wheels.
        //
        // This used to read `default_minimal()`'s `autorun` row. Since
        // `profile-actuation` (2026-09-21) that row declares a drivetrain
        // only in a deployment that actuates, and the pair rule is not a
        // property of any one deployment — so the two-wheel decl is built
        // here and the test holds in every build. That the SHIPPED topology
        // is such a decl when the profile is on is asserted separately, by
        // `default_minimal_autorun_entry_seeds_a_write_satisfying_motor_pair`.
        let mut topo = Topology::empty();
        topo.push_task(
            MaybeStr::from_bytes(b"two_wheels"),
            MaybeStr::from_bytes(b"any"),
            0,
            &[
                CapSpec {
                    kind: CapKind::Motor,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"motor.0"),
                    transfer: false,
                },
                CapSpec {
                    kind: CapKind::Motor,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"motor.1"),
                    transfer: false,
                },
            ],
        )
        .unwrap();
        let task = topo
            .find_task(&MaybeStr::from_bytes(b"two_wheels"))
            .expect("the two-wheel task this test just pushed");
        let tid = fresh_tid();
        let mut left: Option<Cap<targets::Motor>> = None;
        for cap in topo.caps_of(task) {
            let handle =
                crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str());
            if cap.kind == CapKind::Motor && cap.target == MaybeStr::from_bytes(b"motor.0") {
                left = handle.map(Cap::from_raw);
            }
        }
        let left = left.expect("motor.0 is declared and has a typed minter");
        assert_eq!(
            cap_store::with_table(tid, |t| motor_set_target_cap(t, left, 0, 0)),
            Some(Ok(())),
            "both wheels declared: the pair-wide actuation gate must open"
        );

        // Negative: same bridge, a decl that names the left wheel only.
        let mut half_topo = Topology::empty();
        half_topo
            .push_task(
                MaybeStr::from_bytes(b"one_wheel"),
                MaybeStr::from_bytes(b"any"),
                0,
                &[CapSpec {
                    kind: CapKind::Motor,
                    perms: CapPerms::RW,
                    target: MaybeStr::from_bytes(b"motor.0"),
                    transfer: false,
                }],
            )
            .unwrap();
        let half = half_topo
            .find_task(&MaybeStr::from_bytes(b"one_wheel"))
            .unwrap();
        let half_tid = fresh_tid();
        let mut only: Option<Cap<targets::Motor>> = None;
        for cap in half_topo.caps_of(half) {
            only = crate::cap_seed::seed_one_cap(half_tid, cap.kind, cap.perms, cap.target.as_str())
                .map(Cap::from_raw);
        }
        let only = only.expect("motor.0 mints on its own");
        assert_eq!(
            cap_store::with_table(half_tid, |t| motor_set_target_cap(t, only, 0, 0)),
            Some(Err(MotorCapError::Cap(CapError::MissingPerms))),
            "one wheel declared: driving the shared drivetrain must be refused"
        );
    }

    /// The typed driver-registry cap the same bridge call mints, checked by
    /// kind AND resource index — which is the property the whole migration
    /// turns on.
    ///
    /// The untyped `sys_driver_register` (retired in RFC-0040 gap 1) took the
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
                    CapKind::DriverRegistry,
                    azos_abi::drv_kind::DRV_KIND_GPIO,
                    CapPerms::WRITE,
                ),
                t.holds_kind_resource_with(
                    CapKind::DriverRegistry,
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
                crate::drvreg_cap::drvreg_kind_of(t, rw),
                crate::drvreg_cap::drvreg_kind_of(t, ro),
            )
        })
        .expect("table exists");
        assert_eq!(got.0, Ok(azos_abi::drv_kind::DRV_KIND_I2C));
        assert_eq!(got.1, Err(CapError::MissingPerms));

        // And a cap of a different kind must not dereference through it —
        // `Cap<T>` is a compile-time type, but the RAW handle carries the
        // kind tag and this is the runtime half of that guarantee.
        let motor = crate::motor_cap::motor_grant_cap(tid, 0, CapPerms::RW)
            .expect("motor grant");
        let confused: Cap<targets::DriverRegistry> =
            Cap::from_raw(motor.raw());
        let wrong = cap_store::with_table(tid, |t| {
            crate::drvreg_cap::drvreg_kind_of(t, confused)
        });
        assert_eq!(wrong, Some(Err(CapError::WrongKind)));
    }
}

// ── Cap<Sensor>: the largest untyped family, now mintable ─────────────────

#[cfg(test)]
mod sensor_cap_tests {
    use crate::cap::{targets, Cap, CapError, CapPerms};
    use crate::{cap_store, sensor_cap};
    use azos_abi::cap::CapKind;
    use azos_topology::MaybeStr;

    use super::cap_seed_bridge_tests::fresh_tid;

    /// `default_minimal()`'s autorun entry mints all ten sensor types, and
    /// each one is findable by its OWN type — not merely "some sensor cap
    /// exists".
    ///
    /// **Canary.** Make `sensor_grant_cap` ignore its `sensor_type` and always
    /// grant 0: this must go red, because nine of the ten lookups would then
    /// find nothing at their own index.
    #[test]
    fn the_topology_seeds_every_sensor_type_at_its_own_index() {
        let topo = azos_topology::default_minimal();
        let task = topo
            .find_task(&MaybeStr::from_bytes(b"autorun"))
            .expect("autorun declared");
        let tid = fresh_tid();
        for cap in topo.caps_of(task) {
            let _ = crate::cap_seed::seed_one_cap(tid, cap.kind, cap.perms, cap.target.as_str());
        }

        let held = cap_store::with_table(tid, |t| {
            (0u32..=9)
                .filter(|&ty| t.holds_kind_resource_with(CapKind::Sensor, ty, CapPerms::READ))
                .count()
        });
        assert_eq!(held, Some(10), "all ten sensor types must be seeded READ");

        // And NOT with WRITE. The legacy seed grants `HandlePerms::RO`; a
        // typed grant carrying WRITE would hand ring 3 authority the untyped
        // path never had, which is the failure this whole migration is
        // written to avoid.
        let writable = cap_store::with_table(tid, |t| {
            (0u32..=9)
                .filter(|&ty| t.holds_kind_resource_with(CapKind::Sensor, ty, CapPerms::WRITE))
                .count()
        });
        assert_eq!(writable, Some(0), "sensor caps must be READ-only");
    }

    /// `sensor_type_of` returns the type the cap names, and refuses a cap of
    /// another kind presented through the same raw handle.
    #[test]
    fn sensor_type_of_returns_its_own_type_and_refuses_another_kind() {
        let tid = fresh_tid();
        let range = sensor_cap::sensor_grant_cap(tid, 3, CapPerms::READ).expect("grant");
        let battery = sensor_cap::sensor_grant_cap(tid, 4, CapPerms::READ).expect("grant");

        let got = cap_store::with_table(tid, |t| {
            (
                sensor_cap::sensor_type_of(t, range),
                sensor_cap::sensor_type_of(t, battery),
            )
        })
        .expect("table");
        assert_eq!(got.0, Ok(3));
        assert_eq!(got.1, Ok(4));

        // A motor cap re-labelled as a sensor cap must not dereference.
        let motor = crate::motor_cap::motor_grant_cap(tid, 0, CapPerms::RW).expect("grant");
        let confused: Cap<targets::Sensor> = Cap::from_raw(motor.raw());
        let wrong = cap_store::with_table(tid, |t| sensor_cap::sensor_type_of(t, confused));
        assert_eq!(wrong, Some(Err(CapError::WrongKind)));
    }

    /// A sensor type the kernel does not dispatch cannot be minted.
    ///
    /// The bound is not invented here: `sensor_read_dispatch`'s `match` has a
    /// `_ => -1` arm, so an out-of-range type is already refused downstream.
    /// Refusing at mint keeps the cap table describing only grantable objects.
    #[test]
    fn a_sensor_type_the_kernel_does_not_dispatch_cannot_be_minted() {
        let tid = fresh_tid();
        assert!(sensor_cap::sensor_grant_cap(tid, 9, CapPerms::READ).is_some(),
                "9 is SENSOR_TYPE_POWER, the highest the kernel dispatches");
        for bad in [10u32, 11, 255, u32::MAX] {
            assert!(
                sensor_cap::sensor_grant_cap(tid, bad, CapPerms::READ).is_none(),
                "sensor type {bad} is not dispatched and must not be mintable"
            );
        }
    }
}

// ── Cap<MmioRegion>: an index into the board's region table (RFC-0043) ────
//
// This crate builds no board feature, so the table under test is QEMU's:
// index 0 the read-only goldfish RTC, index 1 a writable page nobody is
// granted. `the_qemu_table_has_the_shape_these_tests_assume` pins that, so a
// change to the table fails there first rather than as a puzzling refusal.

#[cfg(test)]
mod mmio_cap_tests {
    use crate::cap::{targets, Cap, CapPerms};
    use crate::cap_seed::seed_one_cap;
    use crate::cap_store;
    use crate::mmio_cap::{mmio_grant_cap, mmio_resolve, MmioMapError};
    use azos_abi::cap::CapKind;
    use azos_drv_base::platform::hw::MMIO_REGIONS;
    use azos_drv_base::platform::mmio_region_record_base;

    use super::cap_seed_bridge_tests::fresh_tid;

    const RO: u32 = 0;
    const RW: u32 = 1;
    /// Index 2 (wave 9 IRQ4) is the RTC again, writable: an alias of index 0.
    const RTC_RW: u32 = 2;
    const OUTSIDE: u32 = 3;

    const ACCESS_READ: u64 = CapPerms::READ.bits() as u64;
    const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;

    /// Does `tid` hold any `MmioRegion` capability at all?
    fn holds_any_mmio(tid: u32) -> Option<bool> {
        cap_store::with_table(tid, |t| t.holds_kind_with(CapKind::MmioRegion, CapPerms::NONE))
    }

    #[test]
    fn the_qemu_table_has_the_shape_these_tests_assume() {
        assert_eq!(MMIO_REGIONS.len(), OUTSIDE as usize);
        assert!(!MMIO_REGIONS[RO as usize].writable, "index 0 is the read-only RTC");
        assert!(MMIO_REGIONS[RW as usize].writable, "index 1 is the writable page");
        let (ro, rtc) = (MMIO_REGIONS[RO as usize], MMIO_REGIONS[RTC_RW as usize]);
        assert!(rtc.writable && rtc.base == ro.base && rtc.size == ro.size,
                "index 2 is the RTC of index 0, writable");
    }

    /// A topology `mmio.N` grant mints a capability whose resource is the
    /// INDEX, with the permission declared — found by the same presence test
    /// `cap_check` runs for `SYS_MMIO_MAP`, and not found at the region's
    /// address, which is what the resource used to be.
    #[test]
    fn a_topology_grant_mints_mmio_n_with_the_index_as_its_resource() {
        let tid = fresh_tid();
        let ro = seed_one_cap(tid, CapKind::MmioRegion, CapPerms::READ, "mmio.0")
            .expect("mmio.0 READ mints");
        let rw = seed_one_cap(tid, CapKind::MmioRegion, CapPerms::RW, "mmio.1")
            .expect("mmio.1 RW mints");
        assert_eq!(
            cap_store::get(tid, Cap::<targets::MmioRegion>::from_raw(ro), CapPerms::READ),
            Ok(RO)
        );
        assert_eq!(
            cap_store::get(tid, Cap::<targets::MmioRegion>::from_raw(rw), CapPerms::WRITE),
            Ok(RW)
        );
        let held = cap_store::with_table(tid, |t| {
            (
                t.holds_kind_resource_uncontained(CapKind::MmioRegion, RO, CapPerms::READ),
                t.holds_kind_resource_uncontained(CapKind::MmioRegion, RO, CapPerms::WRITE),
                t.holds_kind_resource_uncontained(CapKind::MmioRegion, RW, CapPerms::WRITE),
                t.holds_kind_resource_uncontained(
                    CapKind::MmioRegion,
                    MMIO_REGIONS[RO as usize].base as u32,
                    CapPerms::READ,
                ),
            )
        });
        assert_eq!(
            held,
            Some((true, false, true, false)),
            "READ on 0, no WRITE on 0, WRITE on 1, nothing at the RTC's address"
        );
    }

    /// An index outside the table mints nothing, however it is spelled —
    /// including the spellings that would name region 0 if narrowed.
    #[test]
    fn minting_refuses_an_index_outside_the_table() {
        let tid = fresh_tid();
        for target in [
            "mmio.3",
            "mmio.4294967295",
            "mmio.4294967296",
            "mmio.-1",
            "mmio.0x0",
            "mmio",
            "mmio.",
        ] {
            assert!(
                seed_one_cap(tid, CapKind::MmioRegion, CapPerms::READ, target).is_none(),
                "`{target}` must not mint"
            );
        }
        assert!(mmio_grant_cap(tid, OUTSIDE, CapPerms::READ).is_none());
        assert!(mmio_grant_cap(tid, u32::MAX, CapPerms::READ).is_none());
        assert_eq!(holds_any_mmio(tid), Some(false), "a refused grant minted something");
    }

    /// A grant no mapping of the region could honour mints nothing: WRITE
    /// over a read-only region, no READ (a mapping is always readable), and
    /// EXEC or DUP (a mapping is never executable, and nothing delegates).
    ///
    /// **Canary.** Make `mmio_grant_cap` skip `grant_fits`: the first
    /// assertion goes red, because the RTC then mints RW.
    #[test]
    fn minting_refuses_a_permission_the_region_cannot_honour() {
        let tid = fresh_tid();
        assert!(mmio_grant_cap(tid, RO, CapPerms::RW).is_none(), "RW over the read-only RTC");
        assert!(mmio_grant_cap(tid, RO, CapPerms::WRITE).is_none(), "WRITE over the read-only RTC");
        assert!(
            seed_one_cap(tid, CapKind::MmioRegion, CapPerms::RW, "mmio.0").is_none(),
            "the topology path refuses it too"
        );
        assert!(mmio_grant_cap(tid, RW, CapPerms::WRITE).is_none(), "WRITE without READ");
        assert!(mmio_grant_cap(tid, RW, CapPerms::NONE).is_none(), "no permission at all");
        assert!(mmio_grant_cap(tid, RW, CapPerms::ALL).is_none(), "EXEC and DUP");
        assert!(
            mmio_grant_cap(tid, RO, CapPerms::from_bits_truncate(0b0101)).is_none(),
            "READ|EXEC"
        );
        assert!(
            mmio_grant_cap(tid, RO, CapPerms::from_bits_truncate(0b1001)).is_none(),
            "READ|DUP"
        );
        assert_eq!(holds_any_mmio(tid), Some(false), "a refused grant minted something");

        // Positive control on the same table: without it every line above is
        // satisfied by a minter that refuses everything.
        assert!(mmio_grant_cap(tid, RO, CapPerms::READ).is_some());
        assert!(mmio_grant_cap(tid, RW, CapPerms::RW).is_some());
        assert!(mmio_grant_cap(tid, RW, CapPerms::READ).is_some());
    }

    /// `SYS_MMIO_MAP`'s argument check: the region to map and whether it is
    /// writable, or the errno. Asserted on the syscall return values, since
    /// those are the ABI.
    #[test]
    fn map_arguments_resolve_to_the_table_entry_or_the_errno() {
        assert_eq!(mmio_resolve(0, ACCESS_READ), Ok((RO, MMIO_REGIONS[0], false)));
        assert_eq!(mmio_resolve(1, ACCESS_RW), Ok((RW, MMIO_REGIONS[1], true)));
        assert_eq!(
            mmio_resolve(1, ACCESS_READ),
            Ok((RW, MMIO_REGIONS[1], false)),
            "a writable region may still be mapped read-only"
        );

        assert_eq!(mmio_resolve(0, ACCESS_RW), Err(MmioMapError::ReadOnly));
        assert_eq!(MmioMapError::ReadOnly.errno().to_syscall_ret(), -13, "EACCES");

        assert_eq!(mmio_resolve(OUTSIDE as u64, ACCESS_READ), Err(MmioMapError::BadIndex));
        assert_eq!(mmio_resolve(u32::MAX as u64, ACCESS_READ), Err(MmioMapError::BadIndex));
        assert_eq!(MmioMapError::BadIndex.errno().to_syscall_ret(), -22, "EINVAL");

        // Only READ and READ|WRITE: not zero, not WRITE alone, no EXEC or
        // DUP, nothing above the low nibble.
        for bad in [0u64, 0b0010, 0b0100, 0b0101, 0b0111, 0b1001, 0b1111, (1 << 32) | 1, u64::MAX] {
            assert_eq!(mmio_resolve(0, bad), Err(MmioMapError::BadAccess), "access {bad:#x} on 0");
            assert_eq!(mmio_resolve(1, bad), Err(MmioMapError::BadAccess), "access {bad:#x} on 1");
        }
        assert_eq!(MmioMapError::BadAccess.errno().to_syscall_ret(), -22, "EINVAL");
    }

    /// **The alias the index closes.** The call takes a 64-bit register, and
    /// an index 4 GiB above a granted one must name nothing — the physical
    /// base this call used to take passed a check narrowed to 32 bits.
    ///
    /// **Canary.** Narrow `index` to `u32` before the range check in
    /// `mmio_resolve`: `1 << 32` resolves to region 0 and this goes red.
    #[test]
    fn an_index_above_32_bits_names_no_region() {
        for high in [1u64 << 32, (1u64 << 32) | 1, 1u64 << 33, (1u64 << 63) | 1] {
            assert_eq!(
                mmio_resolve(high, ACCESS_READ),
                Err(MmioMapError::BadIndex),
                "index {high:#x} must not alias region {}",
                high as u32
            );
            assert_eq!(mmio_resolve(high, ACCESS_RW), Err(MmioMapError::BadIndex));
        }
    }

    /// Decision 72, the table half: the denial record for an `MmioRegion`
    /// capability names the region's base, and 0 outside the table. Literals
    /// on purpose, as in `tests/host/syscall-tests/src/cap_denial_record.rs`.
    #[test]
    fn the_denial_record_base_is_the_regions_base_and_zero_outside_the_table() {
        assert_eq!(mmio_region_record_base(0), 0x0010_1000);
        assert_eq!(mmio_region_record_base(1), 0x0400_0000);
        assert_eq!(mmio_region_record_base(2), 0x0010_1000, "the RTC's writable alias");
        assert_eq!(mmio_region_record_base(3), 0);
        assert_eq!(mmio_region_record_base(u32::MAX), 0);
    }
}

// ── The MMIO region table's invariants (RFC-0043) ─────────────────────────

#[cfg(test)]
mod mmio_table_tests {
    use azos_drv_base::platform::hw::{FW_CFG_BASE, MMIO_REGIONS, PLIC_BASE, RAM_BASE, UART_BASE};

    const PAGE: usize = 0x1000;

    /// `USER_MMIO_MAX_SIZE` in `crates/core/sched/src/process.rs`, restated: that
    /// constant is private to the kernel crate, and `mmio_map_user` refuses a
    /// range larger than it, so such an entry could never be mapped.
    const USER_MMIO_MAX_SIZE: usize = 1024 * 1024;

    #[test]
    fn every_region_is_page_aligned_mappable_outside_ram_and_recordable() {
        for (i, r) in MMIO_REGIONS.iter().enumerate() {
            assert!(r.size > 0, "region {i}: empty");
            assert_eq!(r.base % PAGE, 0, "region {i}: base {:#x} not page aligned", r.base);
            assert_eq!(r.size % PAGE, 0, "region {i}: size {:#x} not whole pages", r.size);
            assert!(r.size <= USER_MMIO_MAX_SIZE, "region {i}: larger than one user mapping");
            let end = r.base.checked_add(r.size).unwrap_or_else(|| panic!("region {i}: wraps"));
            assert!(end <= RAM_BASE, "region {i}: {:#x}..{end:#x} reaches RAM", r.base);
            assert!(
                r.base <= u32::MAX as usize,
                "region {i}: the denial record carries the base in 32 bits"
            );
        }
    }

    #[test]
    fn no_two_regions_overlap() {
        for (i, a) in MMIO_REGIONS.iter().enumerate() {
            for (j, b) in MMIO_REGIONS.iter().enumerate().skip(i + 1) {
                // The one exception: an exact alias at the other authority
                // level (index 0's RTC read-only, index 2 the same page
                // writable, for captest's interrupt section).
                let alias = a.base == b.base && a.size == b.size && a.writable != b.writable;
                assert!(
                    alias || a.base + a.size <= b.base || b.base + b.size <= a.base,
                    "regions {i} and {j} overlap"
                );
            }
        }
    }

    /// The QEMU `virt` windows the kernel and the firmware drive, from
    /// `virt_memmap[]`: the test/reset device OpenSBI resets through, CLINT,
    /// ACLINT SSWI, PLIC, UART0, the eight virtio-mmio slots and `fw_cfg`. A
    /// capability over any of them would hand ring 3 the kernel's own devices.
    #[test]
    fn no_region_covers_a_device_the_kernel_or_firmware_drives() {
        let owned: [(&str, usize, usize); 7] = [
            ("VIRT_TEST", 0x0010_0000, 0x1000),
            ("CLINT", 0x0200_0000, 0x1_0000),
            ("ACLINT SSWI", 0x02F0_0000, 0x4000),
            ("PLIC", PLIC_BASE, 0x60_0000),
            ("UART0", UART_BASE, 0x1000),
            ("virtio-mmio", 0x1000_1000, 8 * 0x1000),
            ("fw_cfg", FW_CFG_BASE, 0x1000),
        ];
        for (i, r) in MMIO_REGIONS.iter().enumerate() {
            for (name, base, size) in owned {
                assert!(
                    r.base + r.size <= base || base + size <= r.base,
                    "region {i} overlaps {name}"
                );
            }
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
/// The canary from RFC-0042 §4 is `two_60_percent_tasks_pinned_to_one_cpu_are_refused`.
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
policy              = \"cfs\"
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

    // ── the RFC canary ─────────────────────────────────────────────────────

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

    /// The one rule topology admission and `SYS_SPAWN` both apply.
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
/// the autorun loader and `SYS_SPAWN` now apply. Pinned by value, so a row
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
    fn default_rows_resolve_to_the_documented_class_and_clamped_priority() {
        let t = default_minimal();
        // The generic loader row: what every image without a row of its own
        // runs at. 16 = the scheduler's default, so nothing unnamed moves.
        assert_eq!(applied(&t, b"autorun"), ("soft_rt".into(), 16, 16));
        // The three board programs: best_effort, 0 clamped to the bottom of
        // [24, 30].
        for n in [&b"GPIODRV.ELF"[..], b"REFLEX.ELF", b"BRAINCLI.ELF"] {
            assert_eq!(applied(&t, n), ("best_effort".into(), 0, 24));
        }
        // The ML service: soft_rt at the default 16; it runs at the behavior
        // task's 14 only by donation, while the loop waits on it.
        assert_eq!(applied(&t, b"MLSRV.ELF"), ("soft_rt".into(), 16, 16));
        // The ring-3 drivers (wave 9): best_effort, 0 clamped to 24, like
        // GPIODRV.ELF (owner decision 2026-09-28; they were soft_rt 16).
        for n in [&b"BUZZDRV.ELF"[..], b"INADRV.ELF"] {
            if (n == b"INADRV.ELF" && !azos_topology::builder::INADRV_ROW)
                || (n == &b"BUZZDRV.ELF"[..] && !azos_topology::builder::BUZZDRV_ROW)
            {
                continue; // placed in the kernel (DRVPLACE): no row
            }
            assert_eq!(applied(&t, n), ("best_effort".into(), 0, 24));
        }
        // RFC-0055: the user shell above every tool it starts, both inside
        // best_effort, so ^C does not depend on equal-priority slicing.
        let (sh, tool) = if cfg!(feature = "ushell-prio-canary") { (26, 24) } else { (24, 26) };
        assert_eq!(applied(&t, b"SH.ELF"), ("best_effort".into(), sh, sh));
        for n in [&b"TOOLBOX.ELF"[..], b"POWER.ELF", b"FLIGHT.ELF", b"BEHAVIOR.ELF", b"CONFIG.ELF", b"OTA.ELF"] {
            assert_eq!(applied(&t, n), ("best_effort".into(), tool, tool));
        }
        // Rows that name no task the kernel creates; resolved all the same.
        assert_eq!(applied(&t, b"supervisor"), ("safety_critical".into(), 0, 0));
        assert_eq!(applied(&t, b"brain_link"), ("best_effort".into(), 0, 24));
        // Gate-only rows. The benchmark server shares its client's bucket so
        // `ipc-roundtrip` measures IPC, not a cross-priority hand-off.
        #[cfg(feature = "ipc-endpoint-canary")]
        {
            assert_eq!(applied(&t, b"VSSRV.ELF"), ("soft_rt".into(), 16, 16));
            assert_eq!(applied(&t, b"EPSRV.ELF"), ("best_effort".into(), 0, 24));
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
policy              = \"rr\"
priority_range      = [16, 23]

[class.gpu_batch]
cpu_budget_min_pct  = 50
cpu_budget_max_pct  = 100
policy              = \"cfs\"
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

/// RFC-0049 stage M1 (wave 8): the `mem` / `mem_pages` / `[pipeline.*]`
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

    const SCHED: &[u8] = b"[class.best_effort]\ncpu_budget_min_pct = 10\ncpu_budget_max_pct = 100\npolicy = \"cfs\"\npriority_range = [24, 30]\n";

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

// RFC-0048 P3: `kind = "disk"`, target `"disk.part.<n>"`, minted as resource
// `n + 1` against the partition table the kernel published. One test on
// purpose: the published table is a process-wide static, and this crate's
// tests run on several threads.
#[cfg(test)]
mod disk_cap_tests {
    use crate::cap::{targets, Cap, CapPerms};
    use crate::cap_seed::{seed_one_cap_outcome, SeedOutcome};
    use crate::cap_store;
    use azos_abi::cap::CapKind;
    use azos_drv_block::partition::{self, Partition, Scheme, Table, MAX_PARTS};
    use azos_topology::{parse_caps, Topology};

    use super::cap_seed_bridge_tests::fresh_tid;

    /// **Canary.** Remove the `"disk"` arm from `parse_cap_kind`: the parse
    /// assertion fails with `UnknownEnumValue`. **Canary.** Remove the
    /// `CapKind::Disk` arm from `seed_one_cap_outcome`: the seed reads
    /// `NoMinter` instead of `Refused`/`Minted`.
    #[test]
    fn a_disk_part_row_parses_and_mints_only_a_published_partition() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"disk\", target = \"disk.part.0\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok(), "the disk word must parse");
        let spec = topo.caps_of(&topo.tasks()[0])[0];
        assert_eq!(spec.kind, CapKind::Disk);

        partition::reset_for_tests();
        let tid = fresh_tid();
        assert_eq!(
            seed_one_cap_outcome(tid, CapKind::Disk, CapPerms::RW, "disk.part.0"),
            SeedOutcome::Refused,
            "no table published: nothing to scope the capability by",
        );
        let none = Partition { start: 0, sectors: 0, mbr_type: 0 };
        let mut parts = [none; MAX_PARTS];
        parts[0] = Partition { start: 2048, sectors: 4096, mbr_type: 0x83 };
        assert!(partition::publish(&Table { scheme: Scheme::Mbr, parts, count: 1 }));

        let h = match seed_one_cap_outcome(tid, CapKind::Disk, CapPerms::RW, "disk.part.0") {
            SeedOutcome::Minted(h) => h,
            o => panic!("disk.part.0 did not mint: {o:?}"),
        };
        assert_eq!(cap_store::get(tid, Cap::<targets::Disk>::from_raw(h), CapPerms::WRITE), Ok(1),
                   "partition 0 is resource 1; resource 0 is the whole disk");
        for bad in ["disk.part.1", "disk.part", "disk.0", "disk", "part.0", "disk.part.-1"] {
            assert_eq!(seed_one_cap_outcome(tid, CapKind::Disk, CapPerms::RW, bad),
                       SeedOutcome::Refused, "{bad}");
        }
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

    /// **Canary.** Remove the `CapKind::File` arm from
    /// `seed_one_cap_outcome`: the seed reads `NoMinter` instead of
    /// `Minted`/`Refused`.
    #[test]
    fn a_file_tree_row_parses_and_mints_only_a_plain_absolute_root() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"file\", target = \"/fat\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok(), "the file word must parse");
        let tid = fresh_tid();
        let h = match seed_one_cap_outcome(tid, CapKind::File, CapPerms::RW, "/fat") {
            SeedOutcome::Minted(h) => h,
            o => panic!("a plain absolute tree root was not minted: {o:?}"),
        };
        let r = cap_store::get(tid, Cap::<targets::File>::from_raw(h), CapPerms::WRITE)
            .expect("the tree grant resolves with WRITE");
        assert!(crate::file_cap::is_tree_resource(r), "a tree grant named a descriptor: {r:#x}");
        for bad in ["fat", "/fat/../etc", "/fat/./x", ""] {
            assert_eq!(seed_one_cap_outcome(tid, CapKind::File, CapPerms::RW, bad),
                       SeedOutcome::Refused, "{bad:?}");
        }
        assert_eq!(seed_one_cap_outcome(tid, CapKind::File, CapPerms::RW_DUP, "/fat"),
                   SeedOutcome::Refused, "a tree grant cannot carry DUP");
    }
}

// ── CONFIG.SIG v2 and the device record (wave 11, RFC-0054 finding 7) ──────
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
    const SIDECAR_HEX: &str = "4b4346470200000000112233445566778899aabbccddeeff0300000000000000\
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
        for (at, v) in [(0usize, b'X'), (4, 1), (5, 1), (24, 0)] {
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

// RFC-0055 (wave 11): `kind = "launch"`, target an image name, perm `x` —
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

    /// **Canary.** Remove the `CapKind::Launch` arm from
    /// `seed_one_cap_outcome`: the seed reads `NoMinter`.
    #[test]
    fn a_launch_row_parses_and_mints_exec_on_an_image_name_only() {
        let mut topo = Topology::empty();
        let caps = b"[task.SH.ELF]\ncaps = [ { kind = \"launch\", target = \"TOOLBOX.ELF\", perm = \"x\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok(), "the launch word must parse");
        assert_eq!(topo.caps_of(&topo.tasks()[0])[0].kind, CapKind::Launch);
        let mut topo = Topology::empty();
        let pipe = b"[task.SH.ELF]\ncaps = [ { kind = \"pipe\", target = \"x\", perm = \"r\" } ]\n";
        assert_eq!(parse_caps(pipe, &mut topo), Err(ParseError::UnknownEnumValue),
                   "a pipe end is never granted by a row");

        let tid = fresh_tid();
        let h = match seed_one_cap_outcome(tid, CapKind::Launch, CapPerms::EXEC, "TOOLBOX.ELF") {
            SeedOutcome::Minted(h) => h,
            o => panic!("a launch grant on an image name was not minted: {o:?}"),
        };
        let r = cap_store::get(tid, Cap::<targets::Launch>::from_raw(h), CapPerms::EXEC)
            .expect("the launch grant resolves with EXEC");
        assert_eq!(crate::launch_cap::launch_resource_of(b"TOOLBOX.ELF"), Some(r));
        assert_eq!(crate::launch_cap::launch_resource_of(b"NOROW.ELF"), None,
                   "an image no row names has no resource");
        for bad in ["toolbox.elf", "TOOLBOX", "LONGNAME9.ELF", "/fat/TOOLBOX.ELF", ""] {
            assert_eq!(seed_one_cap_outcome(tid, CapKind::Launch, CapPerms::EXEC, bad),
                       SeedOutcome::Refused, "{bad:?}");
        }
        assert_eq!(seed_one_cap_outcome(tid, CapKind::Launch, CapPerms::RW, "TOOLBOX.ELF"),
                   SeedOutcome::Refused, "only EXEC is a launch right");
    }

    /// The shell's own row holds no hardware authority: a launch grant on
    /// the tool image, directory trees and (wave 12) the full `/proc` task
    /// view, nothing else. The tool image holds only that view.
    #[test]
    fn the_shell_row_holds_no_hardware_authority() {
        let topo = default_minimal();
        let sh = topo.find_task(&MaybeStr::from_bytes(b"SH.ELF")).expect("SH.ELF row");
        for c in topo.caps_of(sh) {
            assert!(matches!(c.kind, CapKind::Launch | CapKind::File | CapKind::Task), "SH.ELF holds {:?}", c.kind);
            assert!(!c.transfer, "nothing the shell holds is transferable by its row");
        }
        let tb = topo.find_task(&MaybeStr::from_bytes(b"TOOLBOX.ELF")).expect("TOOLBOX.ELF row");
        for c in topo.caps_of(tb) {
            assert_eq!(c.kind, CapKind::Task, "TOOLBOX.ELF holds {:?}", c.kind);
        }
        assert!(!tb.start);
    }

    /// Wave 12 (owner round 48, Linux `hidepid=2`): the shell and the tool
    /// image (`ps`) hold the full `/proc` task view — `Cap<Task>` `READ` on
    /// `"tasks"`, exactly — off the console lockdown and not under it; no
    /// other default row holds it; and the grant mints.
    ///
    /// **Canary.** Drop `TASK_VIEW_CAP` from `TOOLBOX_CAPS`: red on
    /// "TOOLBOX.ELF lacks the task view".
    #[test]
    fn the_shell_and_ps_hold_the_full_task_view_off_the_lockdown_only() {
        use azos_abi::cap::CapPerms;
        let topo = default_minimal();
        let want = !azos_limits::CONSOLE_LOCKDOWN;
        for (i, t) in topo.tasks().iter().enumerate() {
            let views: Vec<_> = topo.caps_of(t).iter().filter(|c| c.kind == CapKind::Task).collect();
            let named = |n: &[u8]| t.name == MaybeStr::from_bytes(n);
            if named(b"SH.ELF") || named(b"TOOLBOX.ELF") {
                assert_eq!(views.len(), want as usize, "{} lacks the task view (row {i})",
                           if named(b"SH.ELF") { "SH.ELF" } else { "TOOLBOX.ELF" });
                for c in views {
                    assert_eq!((c.perms, c.target), (CapPerms::READ, MaybeStr::from_bytes(b"tasks")));
                    assert!(!c.transfer);
                }
            } else {
                assert!(views.is_empty(), "row {i} holds the task view");
            }
        }
        let tid = crate::cap_seed_bridge_tests::fresh_tid();
        assert!(matches!(
            crate::cap_seed::seed_one_cap_outcome(tid, CapKind::Task, CapPerms::READ, "tasks"),
            crate::cap_seed::SeedOutcome::Minted(_)
        ));
    }

    /// RFC-0055 S5: `POWER.ELF` holds `Cap<Power>` RW and nothing else, is
    /// never started by the kernel, and the shell may start it only off the
    /// console lockdown.
    #[test]
    fn the_power_tool_row_holds_power_write_only_and_the_shell_may_launch_it() {
        use azos_abi::cap::CapPerms;
        let topo = default_minimal();
        let pw = topo.find_task(&MaybeStr::from_bytes(b"POWER.ELF")).expect("POWER.ELF row");
        assert!(!pw.start);
        let caps = topo.caps_of(pw);
        if cfg!(feature = "power-cap-canary") {
            assert!(caps.is_empty());
        } else {
            assert_eq!(caps.len(), 1);
            assert_eq!(caps[0].kind, CapKind::Power);
            assert_eq!(caps[0].perms, CapPerms::RW);
            assert_eq!(caps[0].target, MaybeStr::from_bytes(b"power"));
        }
        let sh = topo.find_task(&MaybeStr::from_bytes(b"SH.ELF")).expect("SH.ELF row");
        let launches_power = topo.caps_of(sh).iter()
            .any(|c| c.kind == CapKind::Launch && c.target == MaybeStr::from_bytes(b"POWER.ELF"));
        assert_eq!(launches_power, !azos_limits::CONSOLE_LOCKDOWN,
                   "the shell launches POWER.ELF exactly when the console is not locked down");
    }

    /// Wave 12: the four family tools. BEHAVIOR/CONFIG/OTA hold `Cap<Power>`
    /// RW only; FLIGHT holds the drivetrain only under the gate's
    /// `flight-tool-drivetrain`, and then the autorun row does not (one
    /// writer per motor, and the topology still admits). None is started by
    /// the kernel; the shell may start each only off the console lockdown.
    ///
    /// **Canary.** Grant the drivetrain to `FLIGHT.ELF` without taking it
    /// from autorun: the `flight-tool-drivetrain` run is red on admission.
    #[test]
    fn the_family_tool_rows_hold_their_family_right_and_the_shell_may_launch_them() {
        use azos_abi::cap::CapPerms;
        let topo = default_minimal();
        let sh = topo.find_task(&MaybeStr::from_bytes(b"SH.ELF")).expect("SH.ELF row");
        for img in [&b"FLIGHT.ELF"[..], b"BEHAVIOR.ELF", b"CONFIG.ELF", b"OTA.ELF"] {
            let row = topo.find_task(&MaybeStr::from_bytes(img)).expect("family tool row");
            assert!(!row.start, "{:?} is started by the kernel", core::str::from_utf8(img));
            let caps = topo.caps_of(row);
            if cfg!(feature = "family-cap-canary") {
                assert!(caps.is_empty());
            } else if img == b"FLIGHT.ELF" {
                if cfg!(feature = "flight-tool-drivetrain") {
                    let mut wheels: Vec<_> = caps.iter()
                        .map(|c| (c.kind, c.perms, c.target.as_str().to_string())).collect();
                    wheels.sort_by(|a, b| a.2.cmp(&b.2));
                    assert_eq!(wheels, [(CapKind::Motor, CapPerms::RW, "motor.0".into()),
                                        (CapKind::Motor, CapPerms::RW, "motor.1".into())]);
                } else {
                    assert!(caps.is_empty(), "the drivetrain is the autorun row's");
                }
            } else {
                assert_eq!(caps.len(), 1);
                assert_eq!((caps[0].kind, caps[0].perms), (CapKind::Power, CapPerms::RW));
                assert_eq!(caps[0].target, MaybeStr::from_bytes(b"power"));
            }
            let launches = topo.caps_of(sh).iter()
                .any(|c| c.kind == CapKind::Launch && c.target == MaybeStr::from_bytes(img));
            assert_eq!(launches, !azos_limits::CONSOLE_LOCKDOWN);
        }
        let autorun = topo.find_task(&MaybeStr::from_bytes(b"autorun")).expect("autorun row");
        let autorun_motors = topo.caps_of(autorun).iter().any(|c| c.kind == CapKind::Motor);
        assert_eq!(autorun_motors,
                   cfg!(feature = "profile-actuation") && !cfg!(feature = "flight-tool-drivetrain"));
        assert!(topo.admission_check().is_ok(), "one writer per motor");
    }

    /// RFC-0053 L0: the Linux driver server skeleton has a row only under
    /// `lx-server`; there it is started, `best_effort`, and holds NO
    /// capability (a Linux server never holds an actuator, RFC-0053 3), and
    /// no other row may launch it.
    ///
    /// **Canary.** Give the row `Cap<Gpio>` in `builder.rs`: red under
    /// `--features lx-server`.
    #[test]
    fn the_linux_server_row_exists_only_under_lx_server_and_holds_nothing() {
        let topo = default_minimal();
        let row = topo.find_task(&MaybeStr::from_bytes(b"LXSRV.ELF"));
        if !cfg!(feature = "lx-server") {
            assert!(row.is_none(), "a default topology names a Linux server");
            return;
        }
        let lx = row.expect("LXSRV.ELF row under lx-server");
        assert!(lx.start, "the skeleton is started from its row");
        assert!(topo.caps_of(lx).is_empty(), "LXSRV.ELF holds {} capabilities", topo.caps_of(lx).len());
        for t in topo.tasks() {
            assert!(!topo.caps_of(t).iter().any(|c| c.kind == CapKind::Launch
                    && c.target == MaybeStr::from_bytes(b"LXSRV.ELF")),
                    "{} may launch the Linux server", t.name.as_str());
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
        let sig = key().sign(caps.as_bytes()).to_bytes();
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
        assert_eq!((b.format, b.device, b.counter), (4, Some(DEV), Some(1)));
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
        let sched = b"[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"cfs\"\n";
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
        assert!(named >= 20, "only {named} kinds have a word");
    }

    #[test]
    fn signed_bound_pair_loads_and_equals_the_builtin_topology() {
        let built = builtin();
        let (caps, sched) = emitted_bound(&built, Some(DEV), Some(3));
        let sig = key().sign(caps.as_bytes()).to_bytes();
        let files = SignedFiles { caps: caps.as_bytes(), caps_sig: &sig, sched: sched.as_bytes() };
        let mut t = Box::new(Topology::empty());
        assert_eq!(load_signed(&mut t, &files, key().verifying_key().as_bytes(), &ctx(3)), Ok(Some(3)));
        assert_eq!(first_difference(&built, &t), None);
    }

    /// A one-digit change that still parses and is still admitted: only the
    /// signature can refuse it (the gate's tampered row uses the same edit).
    #[test]
    fn tampered_caps_is_refused_by_its_signature() {
        let (caps, sched) = emitted(&builtin());
        let sig = key().sign(caps.as_bytes()).to_bytes();
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
        let sig = key().sign(caps.as_bytes()).to_bytes();
        let other = SigningKey::from_bytes(&[0x11; 32]);
        let files = SignedFiles { caps: caps.as_bytes(), caps_sig: &sig, sched: sched.as_bytes() };
        let mut t = Box::new(Topology::empty());
        assert_eq!(
            load_signed(&mut t, &files, other.verifying_key().as_bytes(), &ctx(0)),
            Err(SignedRefusal::Signature(SignedFile::Caps, VerifyError::InvalidSignature)),
        );
        let short = SignedFiles { caps_sig: &sig[..63], ..files };
        let mut t = Box::new(Topology::empty());
        assert_eq!(
            load_signed(&mut t, &short, key().verifying_key().as_bytes(), &ctx(0)),
            Err(SignedRefusal::Signature(SignedFile::Caps, VerifyError::BadSignatureLen)),
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
