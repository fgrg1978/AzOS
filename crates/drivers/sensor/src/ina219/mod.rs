// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INA219 power monitor: the kernel API, in either placement.
//!
//! One chip-logic source, `crates/drivers/ina219`, and two hosts that serve
//! the `PowerMon` interface (`azos_devif::powermon`):
//!
//! * `ring3`: `userspace/drivers/ina_drv` (`INADRV.ELF`) on
//!   `endpoint.powermon`, started from its topology row; a call is an
//!   endpoint call through [`PowerMonClient`] over the transport the kernel
//!   registers at [`init`].
//! * `kernel`: [`kernel_host`] — a kernel task samples the chip over
//!   `azos_drv_bus::i2c` and publishes the chip state; a call is a direct read
//!   of that state, no message, no wake-up.
//!
//! The row's `place` says which one runs ([`init`] is told by the kernel after
//! it read the row); the callers (the sensor syscall, the gate smokes) hold a
//! [`PowerMonPlaced`] and do not know. The record is the same from either.
//!
//! Not read by any safety decision (the only consumer is the sensor syscall),
//! which is what allows the ring-3 placement at all; the drivers a safety
//! decision reads have no placement switch (config/subsys/Kconfig.drivers).

use core::sync::atomic::{AtomicU8, Ordering};

use azos_devif::powermon::{PowerMonCall, PowerMonClient, PowerMonDirect, PowerMonPlaced, PowerStats, RECORD_BYTES};
use azos_devif::{IdlError, IdlResult, MsgDesc, Transport};
use azos_sync::SpinLock;

pub mod kernel_host;
use kernel_host::KernelPowerMon;

/// Bytes of one power record: voltage_mv u16, current_ma u16, mah_used u32,
/// capacity_pct u8, sag u8, failsafe u8, pad u8 (all LE).
pub const POWER_DATA_SIZE: usize = RECORD_BYTES;

/// The chip-logic source (`AZOS-CHIP-SRC ina219 <hex>`), which the kernel
/// host prints at start (`tools/lint/chip_source_check.py`).
pub const SOURCE_MARKER: &[u8] = &azos_ina219::SOURCE_MARKER;

/// Where the INA219 runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    Kernel,
    Ring3,
}

impl Placement {
    /// For the log and the gate rows.
    pub const fn as_str(self) -> &'static str {
        match self {
            Placement::Kernel => "kernel",
            Placement::Ring3 => "ring-3",
        }
    }
}

const NOWHERE: u8 = 0;
const IN_KERNEL: u8 = 1;
const IN_RING3: u8 = 2;

static PLACEMENT: AtomicU8 = AtomicU8::new(NOWHERE);

/// One endpoint call: the kernel's `kcall` through a capability on
/// `endpoint.powermon` (this crate sits below the syscall layer and cannot
/// name it).
pub type EndpointCall = fn(&mut MsgDesc) -> IdlResult;

static ENDPOINT_CALL: SpinLock<Option<EndpointCall>> = SpinLock::new(None);

/// The kernel read the row: the driver is placed at `placement`, and a call to
/// the ring-3 host goes through `call`.
pub fn init(placement: Placement, call: EndpointCall) {
    *ENDPOINT_CALL.lock() = Some(call);
    PLACEMENT.store(match placement { Placement::Kernel => IN_KERNEL, Placement::Ring3 => IN_RING3 }, Ordering::Release);
}

/// Where the driver is, `None` before [`init`].
pub fn placement() -> Option<Placement> {
    match PLACEMENT.load(Ordering::Acquire) {
        IN_KERNEL => Some(Placement::Kernel),
        IN_RING3 => Some(Placement::Ring3),
        _ => None,
    }
}

/// The ring-3 host's transport.
pub struct Ring3;

impl Transport for Ring3 {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let call = (*ENDPOINT_CALL.lock()).ok_or(IdlError::Transport(-1))?;
        call(msg)
    }
}

type Stub = PowerMonPlaced<KernelPowerMon, Ring3>;

fn stub() -> Option<Stub> {
    match placement()? {
        Placement::Kernel => Some(PowerMonPlaced::Direct(PowerMonDirect(KernelPowerMon))),
        Placement::Ring3 => Some(PowerMonPlaced::Endpoint(PowerMonClient::new(Ring3))),
    }
}

/// The last sample into `buf` and its acquisition time (vDSO-clock
/// nanoseconds, the host read right after the register transfers behind it):
/// `(POWER_DATA_SIZE, acq_ns)`, or `(0, 0)` without a configured chip or an
/// answering host.
///
/// Blocks the caller for a ring-3 host's reply: never call from an interrupt
/// handler or with a lock held.
pub fn ina219_read_power_stamped(buf: &mut [u8]) -> (usize, u64) {
    if buf.len() < POWER_DATA_SIZE {
        return (0, 0);
    }
    let Some(mut s) = stub() else { return (0, 0) };
    match s.read() {
        Ok(o) if o.is_ok() && o.value.len as usize == POWER_DATA_SIZE => (o.value.copy_to(buf), o.value.acq_ns),
        _ => (0, 0),
    }
}

/// [`ina219_read_power_stamped`] without the stamp.
pub fn ina219_read_power(buf: &mut [u8]) -> usize {
    ina219_read_power_stamped(buf).0
}

/// The monitor's counters, `None` without an answering host.
pub fn ina219_stats() -> Option<PowerStats> {
    match stub()?.stats() {
        Ok(o) if o.is_ok() => Some(o.value),
        _ => None,
    }
}
