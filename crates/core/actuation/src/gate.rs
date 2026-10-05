// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The actuation gate every domain shares: the one latch-and-stop sequence,
//! the stop work domains register into it, and the seams the kernel installs
//! at boot (capability-denial and audit recorders, the ring-3 e-stop).
//!
//! Moved out of `domains/robot/safety-core/src/actuation.rs` (wave 11,
//! DOMAIN). What stays there is the robot's own part: the motor gate and
//! halt query, the motor-command record, the flight-arm gate, and the
//! registration of the robot's stop work into the tables below.

use core::sync::atomic::{AtomicBool, Ordering};
use azos_drv_sys::kprintln;

use crate::hooks::HookTable;

/// Stop work run by [`latch_and_stop`] after the latch, in registration order.
static STOP_HOOKS: HookTable = HookTable::new();
/// Lock-free stop work run on the panic path ([`run_panic_stop_hooks`]).
static PANIC_STOP_HOOKS: HookTable = HookTable::new();

/// Register the work that stops a domain's actuators. [`latch_and_stop`] runs
/// it after the latch is set, so from its first instruction every write from
/// every path is already clamped. Panics when the table is full.
pub fn register_stop_hook(hook: fn()) {
    STOP_HOOKS.register(hook);
}

/// Register a domain's panic-path stop: lock-free, callable from the panic
/// handler and the timer interrupt (`watchdog::halt_if_panicked`).
pub fn register_panic_stop_hook(hook: fn()) {
    PANIC_STOP_HOOKS.register(hook);
}

/// Run every registered panic-path stop. Lock-free.
#[inline]
pub fn run_panic_stop_hooks() {
    PANIC_STOP_HOOKS.run();
}

/// How many stop hooks are registered (diagnostic; the boot banner prints it).
pub fn stop_hooks_registered() -> usize {
    STOP_HOOKS.len()
}

/// Latch the envelope and stop everything that can move. **The one copy.**
///
/// Every emergency stop in this kernel ends in these four calls, in this
/// order. There were four hand-written copies of them until 2026-09-18 —
/// ring 3 (`actuation::ring3_estop`), the GPIO kill switch
/// (`sys_wdt`), and the two `PKT_ESTOP` handlers in `kernel/src/tasks/behavior.rs`
/// (TCP and UART) — and the cost of that is on the record: the GPIO copy
/// *"used to stop the motors and nothing else — it never called
/// `estop_activate()`"*, so the physical kill switch stopped the wheels once
/// and let the next command move them again, while a remote e-stop held. One
/// copy of four silently lost the most important line, on the control a
/// person reaches for when the machine is already doing something wrong.
///
/// **The order is load-bearing, not stylistic.** The latch goes first because
/// the actuation gate opens with `if estop_is_active()`: from that
/// instruction on, every motor write from every path — this task,
/// `rt_motor_task`, another ring-3 program — is clamped to 0. Stopping the
/// wheels first would leave a window in which the control loop's next tick
/// re-applies `CH_MOTOR_CMD`.
///
/// **Motors 0 and 1 are every motor that exists**: `robot_init` calls
/// `motor_init` exactly twice, and `motor_stop` on an uninitialised id
/// returns -1 without touching anything. Said out loud because `MAX_MOTORS`
/// is 4 and the gap invites a second look.
///
/// What this deliberately does NOT do is record. Each caller writes its own
/// `SAFETY_ESTOP` record with its own source code — which of the sources
/// fired is the first question after an incident — and `ring3_estop` must
/// additionally read `estop_cleared_at()` *before* calling this, because
/// arming spends that stamp.
///
/// The latch lives here; the stop work belongs to the domain that owns the
/// actuators and is registered with [`register_stop_hook`] (the robot domain
/// registers motors 0 and 1, the ESC and the payload, in that order). An
/// image with no actuator domain latches and stops nothing else.
pub fn latch_and_stop() {
    crate::estop::estop_activate();
    STOP_HOOKS.run();
}

/// Set by [`install`]; read by [`gate_installed`].
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// The readiness check a domain adds to [`gate_installed`] (the robot domain:
/// its motor gate is installed). Null until one registers. An atomic, not a
/// lock: `gate_installed` is asked from the exit path's respawn
/// (`kernel/src/drv_supervisor.rs`), and the motor-gate query it replaces
/// was a plain atomic load.
static DOMAIN_GATE_CHECK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Register the domain's own readiness check for [`gate_installed`].
pub fn set_domain_gate_check(check: fn() -> bool) {
    DOMAIN_GATE_CHECK.store(check as *mut (), Ordering::Release);
}

/// Is the actuation gate in place? False until [`install`] has run, and,
/// once a domain registered a check, false while that check says so. The
/// loader and the driver supervisor refuse to start ring-3 images while this
/// is false: fail closed, as the motor gate itself does.
pub fn gate_installed() -> bool {
    if !INSTALLED.load(Ordering::Acquire) {
        return false;
    }
    let p = DOMAIN_GATE_CHECK.load(Ordering::Acquire);
    if p.is_null() {
        return true;
    }
    // SAFETY: the only store is `set_domain_gate_check`'s, from a
    // `fn() -> bool`; function pointers round-trip through `*mut ()`.
    let check: fn() -> bool = unsafe { core::mem::transmute::<*mut (), fn() -> bool>(p) };
    check()
}

/// Install the seams every domain needs, in the order the kernel always
/// installed them. Called once from `kernel_main`, after the domain's own
/// install (`azos_safety_core::actuation::install` in a robot image).
pub fn install() {
    // The capability layer's refusals reach the black box the same way the
    // motor gate reaches the safety layer: through a hook the kernel
    // installs, because `crates/core/syscall` cannot depend on
    // `domains/robot/behavior` without closing a cycle.
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
    // `SYS_EXEC`/`SYS_EXECPATH` of an image no profile is bound to is refused and
    // recorded here, `detail` the digest's first four bytes. Both go the way the
    // denials above go (owner decision 2026-09-14): ring only, through the same
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
    fn record_service_refused(op: u8, detail: u32) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_SERVICE_REFUSED,
            op,
            detail,
        );
    }
    azos_syscall::handlers::set_service_refused_recorder(record_service_refused);
    // Wave 7: a topology row naming a scheduling class this build lacks, so a
    // ring-3 task runs at a priority its signed topology does not declare.
    // Ring only, like the refusals above: `SYS_SPAWN` is a syscall path.
    fn record_topo_class_refused(site: u8, tid: u32) {
        crate::logger::log_safety_violation(
            crate::logger::SAFETY_TOPO_CLASS_REFUSED,
            site,
            tid,
        );
    }
    azos_syscall::topo_sched::set_refusal_recorder(record_topo_class_refused);
    // Wave 9: a priority donation to a ring-3 task raised to the ring-3 floor
    // (`azos_sched::donate_priority`), under the topology floor's code
    // with its own site. Once per target task.
    fn record_donation_floored(tid: u32) {
        azos_syscall::topo_sched::record_refusal(
            azos_syscall::topo_sched::SITE_DONATION_FLOOR,
            tid,
        );
    }
    azos_sched::set_donation_floor_recorder(record_donation_floored);
    kprintln!("[SAFETY] capability denials recorded to the flight recorder");

    // And the emergency stop ring 3 never actually had.
    //
    // `SYS_ROBOT_ESTOP` was declared in the ABI, exposed by `libsys` and
    // swallowed by `dispatch`'s stub range, so the brain's
    // `FLAG_EMERGENCY` reached the wheels through `brain_client` as an
    // ordinary speed-0 command — no latch, no disarm, no record. This body
    // is deliberately the SAME work the two `PKT_ESTOP` handlers do; the
    // only difference is the source code in the record.
    //
    // Through a hook for the usual reason: `crates/core/syscall` cannot depend
    // on `domains/robot/behavior` (cycle), and the latch, the recorder and the
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
        // than in `sys_robot_estop` because `crates/core/syscall` cannot reach
        // `domains/robot/behavior` — the same cycle that put this behind a hook.
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
    kprintln!("[SAFETY] ring-3 emergency stop armed (SYS_ROBOT_ESTOP)");
    INSTALLED.store(true, Ordering::Release);
}
