// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The buzzer as the kernel's callers see it, in whichever host it runs
//! (Phase 4 elasticity; the first driver whose row is `stateless`).
//!
//! `buzzer_beep()` and the rest are one call on a [`BuzzerPlaced`]: the
//! direct-call stub over the kernel host (`azos_drv_actuator::buzzer`) while
//! the driver is placed in the kernel, the endpoint-call stub through
//! [`KernelEndpoint`] (the capability the kernel mints for the calling task on
//! `endpoint.buzzer`, which `BUZZDRV.ELF` serves) while it is placed in ring
//! 3. The caller does not know which; the placement of the topology row
//! (`BUZZDRV.ELF`'s `place`, `stateless`, `call_budget_us`) and the
//! controller that applies it (`azos_topology::placement::Elastic`) decide,
//! and can change it while the system runs:
//!
//! * **Demote on fault.** A panic in the kernel host is contained and ends its
//!   task; the supervisor's exit hook ([`host_died`]) tells the controller
//!   instead of restarting the task in the kernel, and the supervisor task
//!   ([`run_work`]) routes the callers to the ring-3 host, which is already
//!   up (see below) and serves the same endpoint the kernel's callers hold.
//! * **Promote on deadline.** Every call is timed from the caller
//!   ([`observe`]); when [`azos_topology::placement::Policy::misses`] of the
//!   last 16 break the row's budget, and the kernel host's measured cost
//!   (calibrated at boot, [`init`]) fits it, the supervisor task starts the
//!   kernel host, waits for the calls in flight and the callers switch to the
//!   direct stub.
//!
//! **The controller routes; it never starts or ends the ring-3 host.** That
//! host is a component of the signed topology like any other `start = true`
//! row: the component manager (`userspace/services/compmgr`) starts it at
//! boot, restarts it by the row's `restart` key and answers for its death. It
//! stays up, idle, while the driver is placed in the kernel, so a demotion
//! finds a host already serving (no gap in which a call is refused) and a
//! move never leaves a task for a second supervisor to undo. The kernel host
//! is the controller's own task (`drv_supervisor::start_kernel_host`).
//!
//! **One holder of the channel.** Both hosts drive the one PWM channel, so the
//! channel has one holder at a time and the controller hands it over with the
//! move (`azos_drv_actuator::buzzer_channel::set_ring3_holds_channel`): the `Pwm`
//! interface the kernel serves refuses the ring-3 host's writes to it while the
//! kernel host holds it. The standby host's start-up silencing and the timed
//! step of a sound it was playing before a promotion therefore never touch what
//! the kernel host plays.
//!
//! Every move is [`azos_topology::placement::Elastic::commit`], which writes
//! the `Rule::Placement` decision record; a refusal is recorded too.
//!
//! The caller never blocks under a lock: the endpoint stub's transport refuses
//! where the context may not block (`azos_syscall::kcall`), and nothing here
//! holds a lock across a call.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use azos_devif::buzzer::ENDPOINT_NAME;
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{freq, now};
use azos_sync::SpinLock;
use azos_topology::placement::{Decision, Elastic, Host, Policy, Receipt};

/// The kernel host task's name, and its supervisor entry's.
pub(crate) const HOST_NAME: &str = "buzzer";

/// Where the driver is, for the callers (lock-free).
const NOWHERE: u8 = 0;
const IN_KERNEL: u8 = 1;
const IN_RING3: u8 = 2;
/// A move is under way: callers wait for it (bounded) and then go to the new
/// host.
const MOVING: u8 = 3;

static HOST: AtomicU8 = AtomicU8::new(NOWHERE);
/// Calls between [`enter`] and [`leave`].
static INFLIGHT: AtomicU32 = AtomicU32::new(0);
/// The controller of the row. `None` until [`init`], and for a topology that
/// has no `BUZZDRV.ELF` row.
static PLACEMENT: SpinLock<Option<Elastic>> = SpinLock::new(None);
/// A promotion the controller admitted, for the supervisor task to do.
static PROMOTE: SpinLock<Option<Receipt>> = SpinLock::new(None);
/// The kernel host died: the supervisor task asks the controller what to do.
static FAULTED: AtomicBool = AtomicBool::new(false);

/// How long a move waits for the calls in flight to finish.
const QUIESCE_MS: u64 = 2_000;
/// How long a move waits for the host it starts to be serving.
const START_WAIT_MS: u64 = 3_000;

fn ticks_per_ms() -> u64 {
    (freq() / 1000).max(1)
}

fn now_ns() -> u64 {
    azos_abi::time::ticks_to_ns(now(), freq())
}

fn sleep_ms(ms: u64) {
    let due = now() + ms * ticks_per_ms();
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

const fn code(h: Host) -> u8 {
    match h {
        Host::Kernel => IN_KERNEL,
        Host::Ring3 => IN_RING3,
    }
}

/// Find the row, start the controller, measure the kernel host and say where
/// the driver starts. Called once by `kernel_main`, with the topology
/// installed and the PWM controller up, before any caller and before the
/// ring-3 rows are started. `None`: the topology has no `BUZZDRV.ELF` row, so
/// there is no buzzer.
pub(crate) fn init() -> Option<Host> {
    let topo = azos_topology::get()?;
    let row = topo.tasks().iter().position(|t| t.name.as_bytes() == azos_topology::builder::TASK_BUZZDRV_IMAGE)?;
    let spec = topo.tasks()[row].place;
    let mut e = Elastic::new(row as u32, spec, Policy::from_limits());
    let kernel_ns = azos_drv_actuator::buzzer::calibrate(8);
    e.set_kernel_cost(kernel_ns);
    *PLACEMENT.lock() = Some(e);
    HOST.store(code(spec.host), Ordering::Release);
    azos_drv_actuator::buzzer_channel::set_ring3_holds_channel(spec.host == Host::Ring3);
    kprintln!("[BUZZER] row {}: place = {}, stateless = {}, call budget {} us, kernel host measured {} ns",
              row, spec.host.as_str(), spec.stateless, spec.call_budget_us, kernel_ns);
    Some(spec.host)
}

/// The host the driver is in now, `None` while a move is under way or there
/// is no buzzer. For the smokes that check where it runs.
#[cfg(any(feature = "ring3-drv-smoke", feature = "drv-contain-smoke", feature = "supall-smoke", feature = "restart-smoke"))]
pub(crate) fn host() -> Option<Host> {
    match HOST.load(Ordering::Acquire) {
        IN_KERNEL => Some(Host::Kernel),
        IN_RING3 => Some(Host::Ring3),
        _ => None,
    }
}

/// The task serving the buzzer now: the kernel host task, or the owner of
/// `endpoint.buzzer`. For the smokes.
#[cfg(any(feature = "ring3-drv-smoke", feature = "drv-contain-smoke", feature = "supall-smoke", feature = "restart-smoke"))]
pub(crate) fn driver_tid() -> Option<u32> {
    match host()? {
        Host::Kernel => azos_drv_actuator::buzzer::host_tid(),
        Host::Ring3 => ring3_host_tid(),
    }
}

// ── The callers ─────────────────────────────────────────────────────────────
//
// The plays: the robot domain's (behavior, sensors) and the driver smokes'.
// An image with neither still places, restarts and moves the driver (the
// sections below); the kernel just never calls it.

#[cfg(any(feature = "use-robot", feature = "ring3-drv-smoke", feature = "drv-contain-smoke",
          feature = "supall-smoke", feature = "restart-smoke"))]
pub(crate) use callers::*;

#[cfg(any(feature = "use-robot", feature = "ring3-drv-smoke", feature = "drv-contain-smoke",
          feature = "supall-smoke", feature = "restart-smoke"))]
mod callers {
    use core::sync::atomic::Ordering;

    use azos_devif::buzzer::ENDPOINT_NAME;
    use azos_devif::{BuzzerCall, BuzzerClient, BuzzerDirect, BuzzerPlaced, IdlResult, Out};
    use azos_drv_actuator::buzzer::KernelBuzzer;
    use azos_drv_sys::timebase::{freq, now};
    use azos_syscall::kcall::{self, KernelEndpoint};
    use azos_topology::placement::{Decision, Host};

    use super::{now_ns, sleep_ms, ticks_per_ms, HOST, INFLIGHT, IN_KERNEL, IN_RING3, MOVING, PLACEMENT, PROMOTE};

    /// How long a caller waits for a move to finish before it gives up on its
    /// call.
    const MOVE_WAIT_MS: u64 = 500;

    type Stub = BuzzerPlaced<KernelBuzzer, KernelEndpoint>;

    /// Register a call and find its host. A move waits for the calls in flight
    /// (they were counted before the host was read), and a call that finds a move
    /// under way waits for it, bounded, if its context may block. The count and the
    /// host read here, and the host store and count read of a move, are a
    /// store-then-load handshake (Dekker): all four are `SeqCst`, or each side could
    /// miss the other (store buffering on x86, a release store reordered after an
    /// acquire load on riscv64).
    fn enter() -> Option<Host> {
        let give_up = now() + MOVE_WAIT_MS * ticks_per_ms();
        loop {
            INFLIGHT.fetch_add(1, Ordering::SeqCst);
            match HOST.load(Ordering::SeqCst) {
                IN_KERNEL => return Some(Host::Kernel),
                IN_RING3 => return Some(Host::Ring3),
                MOVING if azos_sync::preempt::may_block() && now() < give_up => {
                    INFLIGHT.fetch_sub(1, Ordering::AcqRel);
                    sleep_ms(1);
                }
                _ => {
                    INFLIGHT.fetch_sub(1, Ordering::AcqRel);
                    return None;
                }
            }
        }
    }

    fn leave() {
        INFLIGHT.fetch_sub(1, Ordering::AcqRel);
    }

    /// One call to the driver, wherever it runs. `true` when it answered and the
    /// op was served. A call that reached the interface is timed and reported to
    /// the controller.
    fn call(f: impl FnOnce(&mut Stub) -> IdlResult<Out<()>>) -> bool {
        let Some(host) = enter() else { return false };
        let mut stub: Stub = match host {
            Host::Kernel => BuzzerPlaced::Direct(BuzzerDirect(KernelBuzzer)),
            Host::Ring3 => match kcall::endpoint_handle(ENDPOINT_NAME.as_bytes()) {
                Some(h) => BuzzerPlaced::Endpoint(BuzzerClient::new(KernelEndpoint(h))),
                None => {
                    leave();
                    return false;
                }
            },
        };
        let t0 = now();
        let r = f(&mut stub);
        let cost_ns = azos_abi::time::ticks_to_ns(now().saturating_sub(t0), freq());
        leave();
        if r.is_ok() {
            observe(host, cost_ns);
        }
        matches!(r, Ok(o) if o.is_ok())
    }

    /// A call to the driver on `host` took `cost_ns`. The controller may ask for
    /// a move; the supervisor task does it.
    fn observe(host: Host, cost_ns: u64) {
        let d = {
            let mut g = PLACEMENT.lock();
            match g.as_mut() {
                // A call that began before a move and ended after it says nothing
                // of the new host.
                Some(e) if e.host() == host => e.observe(cost_ns, now_ns()),
                _ => Decision::Stay,
            }
        };
        if let Decision::Move(r) = d {
            *PROMOTE.lock() = Some(r);
            crate::drv_supervisor::wake();
        }
    }

    /// Play `freq_hz` for `duration_ms`. Returns once the tone has STARTED.
    #[cfg(any(feature = "ring3-drv-smoke", feature = "drv-contain-smoke"))]
    pub(crate) fn buzzer_tone(freq_hz: u16, duration_ms: u32) -> bool {
        call(|b| b.tone(freq_hz as u32, duration_ms))
    }

    /// Start a continuous tone; `0` stops.
    #[cfg(feature = "ring3-drv-smoke")]
    pub(crate) fn buzzer_on(freq_hz: u16) -> bool {
        call(|b| b.on(freq_hz as u32))
    }

    /// Stop whatever is playing.
    pub(crate) fn buzzer_off() -> bool {
        call(|b| b.off())
    }

    /// A 100 ms beep at `TONE_OK`.
    #[cfg(any(feature = "use-robot", feature = "drv-contain-smoke"))]
    pub(crate) fn buzzer_beep() -> bool {
        call(|b| b.beep())
    }

    /// Three 80 ms beeps at `TONE_ALERT`, 60 ms apart.
    #[cfg(feature = "use-robot")]
    pub(crate) fn buzzer_alert() -> bool {
        call(|b| b.alert())
    }
}

// ── The moves ───────────────────────────────────────────────────────────────

/// The exit hook of the supervisor saw the kernel host's task end. If the
/// row may move, this is a fault the controller decides on: the entry is not
/// restarted in the kernel, and the supervisor task is woken to do whatever
/// the controller says. `false`: the row is not elastic (or there is no
/// controller), and the supervisor restarts the host where it is.
pub(crate) fn host_died() -> bool {
    let elastic = PLACEMENT.lock().as_ref().is_some_and(|e| e.is_elastic() && e.host() == Host::Kernel);
    if elastic {
        FAULTED.store(true, Ordering::Release);
    }
    elastic
}

/// Is there a move for the supervisor task to do?
pub(crate) fn work_pending() -> bool {
    FAULTED.load(Ordering::Acquire) || PROMOTE.lock().is_some()
}

/// Do the moves asked for (the supervisor task's duty).
pub(crate) fn run_work() {
    if FAULTED.swap(false, Ordering::AcqRel) {
        demote();
    }
    let asked = PROMOTE.lock().take();
    if let Some(r) = asked {
        promote(r);
    }
}

/// Wait for the calls in flight to end, at most `ms`. `true` when none is.
fn quiesce(ms: u64) -> bool {
    let end = now() + ms * ticks_per_ms();
    while INFLIGHT.load(Ordering::SeqCst) != 0 {
        if now() >= end {
            return false;
        }
        sleep_ms(1);
    }
    true
}

/// Wait until the kernel host task has registered, or the ring-3 host owns its
/// endpoint, at most `ms`.
fn serving(host: Host, ms: u64) -> bool {
    let end = now() + ms * ticks_per_ms();
    loop {
        let up = match host {
            Host::Kernel => azos_drv_actuator::buzzer::host_tid().is_some(),
            Host::Ring3 => ring3_host_tid().is_some(),
        };
        if up {
            return true;
        }
        if now() >= end {
            return false;
        }
        sleep_ms(5);
    }
}

fn demote() {
    let d = {
        let mut g = PLACEMENT.lock();
        g.as_mut().map(|e| e.fault(now_ns())).unwrap_or(Decision::Stay)
    };
    let Decision::Move(r) = d else { return };
    HOST.store(MOVING, Ordering::SeqCst);
    let _ = quiesce(QUIESCE_MS);
    // The host is gone: nothing it was playing is remembered, and no call is
    // served in the kernel until a host registers again.
    azos_drv_actuator::buzzer::host_gone();
    // The ring-3 host is the component manager's and has been up since boot;
    // if it is not serving (still starting, or the manager gave up on it), the
    // controller waits a while for it and does not start one itself.
    let up = serving(Host::Ring3, START_WAIT_MS);
    let mut g = PLACEMENT.lock();
    let Some(e) = g.as_mut() else { return };
    if !up {
        e.failed(r, now_ns());
        // No host runs: the calls answer "no driver".
        HOST.store(IN_KERNEL, Ordering::Release);
        azos_drv_sys::kerr!("[BUZZER] the kernel host faulted and BUZZDRV.ELF is not serving: \
                             the buzzer is down");
        return;
    }
    e.commit(r);
    azos_drv_actuator::buzzer_channel::set_ring3_holds_channel(true);
    HOST.store(IN_RING3, Ordering::Release);
    kprintln!("[BUZZER] placement: kernel -> ring 3 (fault), BUZZDRV.ELF tid={}", ring3_host_tid().unwrap_or(0));
}

/// The owner of `endpoint.buzzer`, the ring-3 host serving now.
fn ring3_host_tid() -> Option<u32> {
    let r = azos_ipc::endpoint::endpoint_ref_by_name(ENDPOINT_NAME.as_bytes())?;
    azos_ipc::endpoint::endpoint_owner_ref(r).ok().filter(|&t| t != azos_ipc::endpoint::UNCLAIMED)
}

fn promote(r: Receipt) {
    let still = PLACEMENT.lock().as_ref().is_some_and(|e| e.host() == r.mv.from);
    if !still {
        return;
    }
    // The kernel host first, while the ring-3 driver still serves: a host
    // that does not start leaves everything as it was.
    let Some(host_tid) = crate::drv_supervisor::start_kernel_host(HOST_NAME, crate::tasks::buzzer_host_task, azos_sched::DEFAULT_PRIORITY)
    else {
        fail_promotion(r, "the kernel host task could not be created");
        return;
    };
    if !serving(Host::Kernel, START_WAIT_MS) {
        let _ = azos_sched::supervisor::sup_retire(host_tid);
        azos_sched::scheduler::task_stop(host_tid, true, 15);
        azos_drv_actuator::buzzer::host_gone();
        fail_promotion(r, "the kernel host did not start");
        return;
    }
    HOST.store(MOVING, Ordering::SeqCst);
    // The channel is the kernel host's from here: the ring-3 host's writes to
    // it are refused (`azos_drv_actuator::buzzer_channel::ring3_channel_write`), so the
    // timed step of a sound it was playing cannot land on what the kernel host
    // plays next, and its standby start cannot cut it. Nothing is asked of that
    // host here: a call to a host that misses its deadlines could block this
    // task, which every supervised image shares.
    azos_drv_actuator::buzzer_channel::set_ring3_holds_channel(false);
    let _ = quiesce(QUIESCE_MS);
    // The ring-3 host stays up, idle: it is the component manager's, and a
    // later demotion routes to it. What it has in service finishes first (the
    // handover's count of calls in service, from any client, bounded).
    if let Some(old) = ring3_host_tid() {
        let end = now() + QUIESCE_MS * ticks_per_ms();
        while azos_ipc::endpoint::endpoint_handover_in_service(old) != 0 && now() < end {
            sleep_ms(1);
        }
    }
    let mut g = PLACEMENT.lock();
    let Some(e) = g.as_mut() else { return };
    e.commit(r);
    HOST.store(IN_KERNEL, Ordering::Release);
    kprintln!("[BUZZER] placement: ring 3 -> kernel (call cost {} ns over the {} ns budget)", r.measured_ns, r.limit_ns);
}

fn fail_promotion(r: Receipt, why: &str) {
    if let Some(e) = PLACEMENT.lock().as_mut() {
        e.failed(r, now_ns());
    }
    azos_drv_sys::kwarn!("[BUZZER] promotion to the kernel failed: {}; the driver stays in ring 3", why);
}
