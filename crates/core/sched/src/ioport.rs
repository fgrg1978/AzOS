// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 port I/O: the ports each thread has open, one
//! [`PortGrant`] per task slot, and the hand-off to the ISA on every switch
//! (`azos_arch_api::IoPorts::io_ports_load`).
//!
//! A thread opens a range with `DEVICE_IOPORT_ENABLE` on a `Device`
//! capability that names it (`crates/core/syscall/src/ioport.rs`); [`enable`]
//! adds it to the thread's set and loads the set on this CPU at once, and
//! [`switch`] loads the incoming thread's set on every switch. Per thread,
//! as Linux's `ioperm`: a slot's next task, a forked child (a new slot) and a
//! thread created later start with no port open ([`reset`]). Only the native
//! ABI reaches the op, so the one in-place exec there is (the in-kernel Linux
//! personality's `execve`) never carries a port.
//!
//! Where the ISA has no port space ([`PORTS`] 0: riscv64, aarch64) the table
//! is empty, [`switch`] is nothing and [`enable`] refuses: the same code on
//! every ISA, no `cfg`.

use azos_arch_api::ioport::{PortGrant, PORTS};
use azos_arch_api::{Interrupts, IoPorts};

use crate::task::MAX_TASKS;

/// Slots with a set: every task slot where the ISA has ports, none elsewhere.
const SLOTS: usize = if PORTS == 0 { 0 } else { MAX_TASKS };

static GRANTS: [PortGrant; SLOTS] = [const { PortGrant::new() }; SLOTS];

/// The set of a slot past [`SLOTS`] (the idle tasks): no port.
static NONE: PortGrant = PortGrant::new();

/// Why [`enable`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnableError {
    /// The ISA has no port space, or the range runs past [`PORTS`].
    NoPorts,
    /// The thread already holds Kconfig `X86_IOPORT_RANGES` ranges.
    Full,
}

/// CPU `cpu` is about to run the task in slot `next`: show ring 3 its ports.
/// Called by `set_current_task`, the one place a CPU changes task, with
/// interrupts off.
#[inline(always)]
pub fn switch(cpu: usize, next: usize) {
    if SLOTS == 0 {
        return;
    }
    azos_arch::ARCH.io_ports_load(cpu, GRANTS.get(next).unwrap_or(&NONE));
}

/// Open `first..=last` to the calling thread, and load its set on this CPU
/// before it returns to ring 3.
pub fn enable(first: u16, last: u16) -> Result<(), EnableError> {
    if SLOTS == 0 || last as u32 >= PORTS || first > last {
        return Err(EnableError::NoPorts);
    }
    let irq = azos_arch::ARCH.disable_all();
    let r = match crate::scheduler::current_slot().and_then(|me| GRANTS.get(me)) {
        Some(g) => match g.add(first, last) {
            Ok(_) => {
                azos_arch::ARCH.io_ports_load(crate::smp::current_cpu_id(), g);
                Ok(())
            }
            Err(_) => Err(EnableError::Full),
        },
        None => Err(EnableError::NoPorts),
    };
    azos_arch::ARCH.restore(irq);
    r
}

/// The task in slot `idx` is new: no port open. A CPU still holding the old
/// set's bitmap never shows it again, since the next set takes a new key.
pub fn reset(idx: usize) {
    if let Some(g) = GRANTS.get(idx) {
        g.clear();
    }
}
