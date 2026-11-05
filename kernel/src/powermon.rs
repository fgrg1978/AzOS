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

use azos_devif::powermon::ENDPOINT_NAME;
use azos_drv_sensor::ina219::{self, Placement};
use azos_drv_sys::kprintln;
use azos_devif::{IdlError, IdlResult, MsgDesc, Transport};
use azos_syscall::kcall::{self, KernelEndpoint, KernelNamed};
use azos_topology::placement::Host;

/// A call to the ring-3 host. It is made on the syscall path of whatever task
/// read the sensor, so it is the kernel's call (`kcall::call_named`): the
/// reader gets no capability on `endpoint.powermon` it could call the driver
/// with directly. Runtime canary `powermon-mint`: the call goes through a
/// capability minted into the reader's table, and the ktest
/// `a_power_read_leaves_no_capability_with_the_reader` goes red.
pub(crate) fn endpoint_call(msg: &mut MsgDesc) -> IdlResult {
    if canary!("powermon-mint") {
        let h = kcall::endpoint_handle(ENDPOINT_NAME.as_bytes()).ok_or(IdlError::Transport(-1))?;
        KernelEndpoint(h).call(msg)?;
    } else {
        KernelNamed(ENDPOINT_NAME.as_bytes()).call(msg)?;
    }
    // Word 5 is the first word of a `read` record: voltage_mv in its low bytes.
    if canary!("ina219-wrong-value") && msg.n_words > 5 {
        msg.words[5] = msg.words[5].wrapping_add(1);
    }
    Ok(())
}

/// Read the row, tell the drivers crate and say where the driver starts.
/// Called once by `kernel_main` with the topology installed. `None`: no row
/// and no kernel placement, so there is no power monitor.
pub(crate) fn init() -> Option<Host> {
    let row = azos_topology::get().and_then(|t| t.row_place(azos_topology::builder::TASK_INADRV_IMAGE));
    let host = match row {
        Some(p) => p.host,
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
    kprintln!("[INA219] placement: {}", host.as_str());
    Some(host)
}

/// The owner of `endpoint.powermon`, the ring-3 host serving now.
#[cfg(feature = "ring3-drv-smoke")]
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
