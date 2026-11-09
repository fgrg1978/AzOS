// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where the INA219 power monitor runs, and how the kernel reaches it.
//!
//! The row of `INADRV.ELF` says (`place`): `ring3` (the default), served by
//! `userspace/drivers/ina_drv` on `endpoint.powermon`, or `kernel`, sampled by
//! a kernel task. `azos_drv_sensor::ina219` is the API the sensor syscall and
//! the smokes call; this tells it the placement and gives it the transport of
//! a call to the ring-3 host. The driver integrates charge over time, so it
//! is not `stateless` and does not move while the system runs.
//!
//! A topology with no `INADRV.ELF` row has no ring-3 host; it places the
//! driver in the kernel only when the kernel was built for it
//! (Kconfig `DRV_INA219_PLACEMENT = kernel`).

use core::sync::atomic::{AtomicU32, Ordering};

use azos_devif::powermon::ENDPOINT_NAME;
use azos_drv_sensor::ina219::{self, Placement};
use azos_drv_sys::kprintln;
use azos_devif::{IdlError, IdlResult, MsgDesc, Transport};
use azos_syscall::kcall::{self, KernelEndpoint, KernelNamed, Purpose};

use crate::call_task::CallTask;
use azos_topology::placement::Host;

/// One call to the ring-3 host, made by the call task ([`call_task`]) as the
/// kernel (`kcall::call_named`): no capability on `endpoint.powermon` is put in
/// any task's table, so a reader of the sensor gains no handle it could call
/// the driver with directly, and a restarted host is found by its name.
/// Runtime canary `powermon-mint`: the call goes through a capability minted
/// into the calling task's table, and the ktest
/// `a_power_read_leaves_no_capability_with_the_reader` goes red.
pub(crate) fn call_host(msg: &mut MsgDesc) -> IdlResult {
    if canary!("powermon-mint") {
        let h = kcall::endpoint_handle(ENDPOINT_NAME.as_bytes()).ok_or(IdlError::Transport(-1))?;
        KernelEndpoint(h).call(msg)?;
    } else {
        // Each op says whether it acts (`azos_devif::powermon::OBSERVING_OPS`);
        // under containment only one that reads is made.
        let observes = msg.n_words > 0 && azos_devif::powermon::request_observes(msg.words[0]);
        let purpose = if observes { Purpose::Observe } else { Purpose::Act };
        KernelNamed(ENDPOINT_NAME.as_bytes(), purpose).call(msg)?;
    }
    // Word 5 is the first word of a `read` record: voltage_mv in its low bytes.
    if canary!("ina219-wrong-value") && msg.n_words > 5 {
        msg.words[5] = msg.words[5].wrapping_add(1);
    }
    Ok(())
}

// ── The bounded wait ─────────────────────────────────────────────────────
//
// The kernel's endpoint call waits for the server for as long as it takes
// (`azos_syscall::kcall`), and a power read is made on the syscall path of
// any task. So the call task makes the calls, one at a time, and a reader
// waits for it with a timer, as the behavior loop waits for its inference
// helper: a host that is alive and not answering costs
// a reader `REPLY_TIMEOUT_MS`, then "no data", never more. Readers that ask
// what the call under way asks (every read is the same request: the last
// sample) share its answer; a different request (the counters) while one is
// under way, or a reader past `READERS`, gets "no data" at once.

/// How long a reader waits for the ring-3 host's answer: Kconfig
/// `PROXY_REPLY_TIMEOUT_MS`, the reply budget of an in-kernel client of a
/// ring-3 driver.
const REPLY_TIMEOUT_MS: u64 = azos_limits::PROXY_REPLY_TIMEOUT_MS;
/// Readers that can wait at once.
const READERS: usize = 8;

static CALLS: CallTask<0, READERS> = CallTask::new("powermon-call", true, serve, |_| {});
/// Reads that ended at `REPLY_TIMEOUT_MS` with no answer.
static TIMED_OUT: AtomicU32 = AtomicU32::new(0);

fn serve(_: Option<u32>, msg: &mut MsgDesc) -> IdlResult {
    call_host(msg)
}

/// Reads that ended at the reply budget with no answer from the host.
#[cfg(feature = "ktest")]
pub(crate) fn timed_out() -> u32 {
    TIMED_OUT.load(Ordering::Relaxed)
}

/// Start the call task, once. Called by [`init`] for the ring-3 placement
/// (from `kernel_main`, so the task is a kernel root, not a child of a
/// reader's Domain).
pub(crate) fn start_call_task() {
    CALLS.start();
}

/// The call task's TID, 0 before it ran.
#[cfg(feature = "ktest")]
pub(crate) fn call_task_tid() -> u32 {
    CALLS.tid()
}

/// The transport the drivers crate calls (`ina219::Ring3`): the request in
/// `*msg` to the ring-3 host through the call task, answered within
/// `REPLY_TIMEOUT_MS` or not at all (`IdlError::DeadlineExpired`). Blocks the
/// reader: never from an interrupt handler or with a lock held.
pub(crate) fn endpoint_call(msg: &mut MsgDesc) -> IdlResult {
    // Runtime canary `powermon-unbounded`: the reader waits for the answer
    // however long it takes (the ktest `a_power_read_of_a_hung_host_is_bounded`
    // goes red).
    let reply_ms = if canary!("powermon-unbounded") { u64::MAX } else { REPLY_TIMEOUT_MS };
    let res = CALLS.call(None, msg, reply_ms);
    if res == Err(IdlError::DeadlineExpired) {
        TIMED_OUT.fetch_add(1, Ordering::Relaxed);
    }
    res
}

/// Read the row, tell the drivers crate and say where the driver starts.
/// Called once by `kernel_main` with the topology installed. `None`: no row
/// and no kernel placement, so there is no power monitor.
pub(crate) fn init() -> Option<Host> {
    let row = azos_topology::get().and_then(|t| t.row_place(azos_topology::builder::TASK_INADRV_IMAGE));
    let host = match row {
        // The INA219 does not move between hosts (it has no placement
        // controller: `azos_topology::builder::MOVABLE_DRIVERS`), so a
        // `stateless` row runs where its `place` says, and the component
        // manager agrees (`manager_starts`).
        Some(p) => {
            if p.stateless {
                kprintln!("[INA219] stateless ignored: the driver runs where its row's place says");
            }
            p.host
        }
        None if cfg!(feature = "ina219-kernel") => Host::Kernel,
        None => return None,
    };
    ina219::init(
        match host {
            Host::Kernel => Placement::Kernel,
            Host::Ring3 => Placement::Ring3,
        },
        endpoint_call,
    );
    if host == Host::Ring3 {
        start_call_task();
    }
    kprintln!("[INA219] placement: {}", host.as_str());
    Some(host)
}

/// The owner of `endpoint.powermon`, the ring-3 host serving now.
#[cfg(any(feature = "ring3-drv-smoke", feature = "sup-smoke"))]
pub(crate) fn ring3_host_tid() -> Option<u32> {
    let r = azos_ipc::endpoint::endpoint_ref_by_name(ENDPOINT_NAME.as_bytes())?;
    azos_ipc::endpoint::endpoint_owner_ref(r).ok().filter(|&t| t != azos_ipc::endpoint::UNCLAIMED)
}

/// The task serving the monitor now: the kernel host task, or the owner of
/// `endpoint.powermon`. For the smokes.
#[cfg(feature = "ring3-drv-smoke")]
pub(crate) fn driver_tid() -> Option<u32> {
    match ina219::placement()? {
        Placement::Kernel => azos_drv_sensor::ina219::kernel_host::host_tid(),
        Placement::Ring3 => ring3_host_tid(),
    }
}
