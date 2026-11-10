// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The actuation gate every domain shares: the panic-path stop, the gate flag
//! the loader checks, and the seams the kernel installs at boot
//! (capability-denial and audit recorders, the ring-3 e-stop). The one
//! latch-and-stop sequence is `crate::estop::latch_and_stop`, re-exported here.
//!
//! Moved out of `crates/domains/robot/safety-core/src/actuation.rs` (
//! DOMAIN). What stays there is the robot's own part: the motor gate and
//! halt query, the motor-command record, the flight-arm gate, and the
//! registration of the robot's stop work into the tables below.

use core::sync::atomic::{AtomicBool, Ordering};
use azos_drv_sys::kprintln;

/// Run every effect provider's panic-path stop (`crate::providers`).
/// Lock-free: the panic handler and the timer interrupt
/// (`watchdog::halt_if_panicked`) call it.
#[inline]
pub fn run_panic_stops() {
    crate::providers::panic_stop_all();
}

pub use crate::estop::latch_and_stop;

/// Set by [`install`]; read by [`gate_installed`].
static INSTALLED: AtomicBool = AtomicBool::new(false);
/// Set when [`install`] starts: it runs once.
static ENTERED: AtomicBool = AtomicBool::new(false);

/// Is the actuation gate in place? False until [`install`] has run, and
/// while any effect provider says its own gate is not
/// (`azos_ext_api::Provider::ready`). The loader and the driver supervisor
/// refuse to start ring-3 images while this is false: fail closed, as the
/// motor gate itself does. Lock-free: the exit path's respawn
/// (`kernel/src/drv_supervisor.rs`) asks it.
pub fn gate_installed() -> bool {
    INSTALLED.load(Ordering::Acquire) && crate::providers::all_ready()
}

/// Install the seams every domain needs, in the order the kernel always
/// installed them. Called once from `kernel_main`, after the domain's own
/// install (`azos_safety_core::actuation::install` in a robot image).
pub fn install() {
    assert!(!ENTERED.swap(true, Ordering::AcqRel), "the actuation gate's install ran twice");
    // The capability layer's refusals reach the black box the same way the
    // motor gate reaches the safety layer: through a hook the kernel
    // installs, because `crates/core/syscall` cannot depend on
    // `crates/domains/robot/behavior` without closing a cycle.
    //
    // `SAFETY_CAP_DENIED` existed as an event code with no production
    // caller — the refusal happened, nothing recorded it. A denial is a
    // ring-3 program reaching for an actuator it does not hold, and it is
    // the one event a denied caller has every reason not to report itself.
    fn record_cap_denial(kind_code: u8, target: u32, need_write: bool) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_CAP_DENIED,
            kind_code,
            // The write bit rides in the top bit of the detail word: on an
            // actuator the difference between a refused read and a refused
            // write is the difference between snooping and commanding, and
            // a record that cannot tell them apart is half a record.
            target | if need_write { 0x8000_0000 } else { 0 },
        );
    }
    azos_syscall::handlers::set_cap_deny_recorder(record_cap_denial);

    // And the same for the TYPED path, which until now recorded nothing.
    //
    // `cap_check` — the hook above — is the ONLY caller of the untyped
    // recorder, and no `*_TYPED` handler goes through it. So every refusal
    // of a `Cap<T>` was invisible: a forged handle against the motor
    // capability produced an errno and no record. As families migrate to
    // `Cap<T>` that silence grows, one family at a time, with the gate
    // green throughout.
    //
    // A separate event code, not a second caller of the same one: the two
    // records carry different things and reusing `SAFETY_CAP_DENIED` would
    // make an unmeasured `detail = 0` indistinguishable from the real
    // `detail = 0` an untyped Power denial writes. The KIND code is shared
    // (`CapKind::denial_code`), so grouping a recording by device still
    // sees both paths as one device.
    fn record_cap_denial_typed(kind_code: u8, reason_code: u32) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_CAP_DENIED_TYPED,
            kind_code,
            reason_code,
        );
    }
    azos_syscall::handlers::set_cap_deny_typed_recorder(record_cap_denial_typed);

    // Both hooks above write into the ring only, and the ring overwrites its
    // oldest record: a ring-3 loop of forged handles evicted the degrade and
    // sys-wdt records next to it. At most four denial records per task per
    // second; the rest are counted and written as ONE summary when the
    // window closes. Clock and summary arrive together, so a bound can never
    // be installed without somewhere for its counts to go.
    fn record_cap_denials_suppressed(kind_code: u8, count: u32) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_CAP_DENIED_SUPPRESSED,
            kind_code,
            count,
        );
    }
    azos_syscall::handlers::set_cap_deny_limiter(
        azos_drv_sys::timebase::now,
        azos_drv_sys::timebase::TIMER_FREQ,
        record_cap_denials_suppressed,
    );

    // Seccomp audit records and ring-3 exec refusals. `CAPTEST.ELF` and
    // `ABITEST.ELF` run under image profiles in audit mode
    // (`crates/core/sched/src/seccomp.rs`): a syscall outside their rows is let
    // through and recorded here, `detail` the syscall number. A ring-3
    // `SYS_SPAWN_EX` or Linux `execve` of an image no profile is bound to is
    // refused and recorded here, `detail` the digest's first four bytes. Both go the way the
    // denials above go: ring only, through the same
    // per-task entry, window and summary with a budget of their own per class
    // (so the denials cannot starve them, nor they the denials), onto the disk
    // with the watchdog's flush, and never a synchronous write on the caller's
    // syscall path.
    fn record_seccomp_audit(syscall_nr: u16) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_SECCOMP_AUDIT,
            0,
            syscall_nr as u32,
        );
    }
    azos_syscall::handlers::set_seccomp_audit_recorder(record_seccomp_audit);
    fn record_exec_refused(action_code: u8, digest_head: u32) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_EXEC_REFUSED,
            action_code,
            digest_head,
        );
    }
    azos_syscall::handlers::set_exec_refused_recorder(record_exec_refused);
    // A topology row naming a scheduling class this build lacks, so a
    // ring-3 task runs at a priority its signed topology does not declare.
    // Ring only, like the refusals above: `SYS_SPAWN_EX` is a syscall path.
    fn record_topo_class_refused(site: u8, tid: u32) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_TOPO_CLASS_REFUSED,
            site,
            tid,
        );
    }
    azos_syscall::topo_sched::set_refusal_recorder(record_topo_class_refused);
    // A wait-graph boost of a ring-3 task held at the ring-3 floor,
    // under the topology floor's code with its own site. Once per target task.
    fn record_donation_floored(tid: u32) {
        azos_syscall::topo_sched::record_refusal(
            azos_syscall::topo_sched::SITE_DONATION_FLOOR,
            tid,
        );
    }
    azos_sched::set_pi_floor_recorder(record_donation_floored);
    kprintln!("[SAFETY] capability denials recorded to the flight recorder");

    // And the emergency stop ring 3 never actually had.
    //
    // `motor.estop` was declared in the ABI, exposed by `libsys` and
    // swallowed by `dispatch`'s stub range, so the companion's
    // `FLAG_EMERGENCY` reached the wheels through `companion_client` as an
    // ordinary speed-0 command — no latch, no disarm, no record. This body
    // is deliberately the SAME work the two `PKT_ESTOP` handlers do; the
    // only difference is the source code in the record.
    //
    // Through a hook for the usual reason: `crates/core/syscall` cannot depend
    // on `crates/domains/robot/behavior` (cycle), and the latch, the recorder and the
    // ESC all live above it.
    fn ring3_estop() {
        // ALREADY LATCHED IS ALREADY DONE — and this guard is the fix
        // for a real audit finding, not a micro-optimisation.
        //
        // Without it every call repeated the whole body, including
        // `log_safety_violation_durable`: a SYNCHRONOUS disk write. A
        // ring-3 loop therefore had an unmetered path to evict the real
        // e-stop record from the flight recorder with copies of itself —
        // destroying the only evidence of why the machine stopped — plus
        // flash wear at syscall rate and a console-lock stall per call.
        // The attacker pays nothing: the machine is already stopped, so
        // nothing it gives up matters to it.
        //
        // Returning without redoing the work is the truth rather than a
        // shortcut, and BOTH reasons were checked rather than assumed:
        //   · `motor_envelope` opens with `if estop_is_active() { (0,0) }`,
        //     so no wheel can have restarted while the latch held;
        //   · the only `esc_arm()` in the tree is an operator shell
        //     command, so no control loop can have undone the disarm.
        //
        // Re-latching after an operator `MODE_ID_ESTOP_RESET` still works:
        // the flag is false again by then, and the record below says the stop
        // undid a clear. And the check lives HERE rather
        // than in `MotorServer::estop` because `crates/core/syscall` cannot reach
        // `crates/domains/robot/behavior` — the same cycle that put this behind a hook.
        if crate::estop::estop_is_active() { return; }

        // The operator's clear, read BEFORE the latch: arming spends the
        // stamp (`estop_activate`), and the record is written after the latch.
        let cleared_at = crate::estop::estop_cleared_at();
        // Latch and stop, in the one place that sequence lives. The order
        // (latch before wheels) and why motors 0 and 1 are all of them are
        // documented on `latch_and_stop`.
        latch_and_stop();
        azos_drv_sys::kwarn!("[SAFETY] ESTOP from ring 3 — motors stopped, envelope latched");
        // Durable, same rationale as the other three: an e-stop is the
        // event most likely to be followed by the reset that would erase
        // an unflushed record.
        //
        // Attributable: the tid of the program that latched (this hook runs
        // on its syscall), and whether it did so within seconds of an
        // operator clearing the latch — `ring3_estop_record` has the format
        // and the reason the stop is never refused for it.
        let (action, detail) = crate::estop::ring3_estop_record(
            azos_sched::current_task_tid(), cleared_at,
            azos_drv_sys::timebase::now());
        let _ = crate::logger::log_safety_violation_durable(
            crate::logger::SAFETY_ESTOP, action, detail);
    }
    azos_syscall::handlers::set_estop_handler(ring3_estop);
    kprintln!("[SAFETY] ring-3 emergency stop armed (motor.estop)");

    #[cfg(feature = "effect-gate")]
    {
        // B4: the effect gate holds an effect to the envelopes of the
        // principals its data passed through (the kernel's per-task labels).
        // Without Kconfig IPC_LABELS no task has a label and the probe would
        // only answer "none".
        if azos_ipc::endpoint::label::ENABLED {
            crate::effect_gate::set_provenance_probe(azos_ipc::endpoint::label::provenance_of);
        }
        // The storage-delete and network-egress kinds of the same gate: the
        // Domain's `delete` and `egress` envelope rows (`envelope.rs`).
        crate::envelope::install();
    }
    // A ring-3 motor op on an image no provider gives wheels is refused with
    // a receipt instead of reaching a motor layer that has none.
    fn motor_served(e: &azos_syscall::motor_host::MotorEffect) -> bool {
        use crate::kind::Class;
        let class = if e.toward_safe { Class::Safe } else { Class::Reversible };
        crate::effect::admit_kind(crate::kind::KIND_MOTOR, class, e.wheel, e.tid).is_ok()
    }
    azos_syscall::motor_host::set_provider_check(motor_served);
    // The kinds the extensions' providers own (a robot's wheels) are wired
    // by the providers themselves.
    crate::providers::effects();
    INSTALLED.store(true, Ordering::Release);
}
