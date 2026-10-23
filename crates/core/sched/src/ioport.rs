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
//! A capability over a range that leaves its table closes the range in the
//! threads of that table that opened it ([`revoke`], from the capability
//! store's event hook): their sets take new keys, this CPU loads its running
//! thread's set again at once and every other CPU does from an IPI
//! ([`refresh`], the IPI's work), so no thread runs a revoked port past the
//! next instruction its CPU takes after the interrupt.
//!
//! Where the ISA has no port space ([`PORTS`] 0: riscv64, aarch64) the table
//! is empty, [`switch`], [`refresh`] and [`revoke`] are nothing and
//! [`enable`] refuses: the same code on every ISA, no `cfg`.

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

/// Open `first..=last` to the calling thread, through a capability of the
/// capability table `table` (its own), and load its set on this CPU before
/// it returns to ring 3. The caller holds that table's lock, which a
/// revocation of the capability also holds ([`revoke`]): the capability
/// cannot go between its check and the open.
pub fn enable(first: u16, last: u16, table: u32) -> Result<(), EnableError> {
    if SLOTS == 0 || last as u32 >= PORTS || first > last {
        return Err(EnableError::NoPorts);
    }
    let irq = azos_arch::ARCH.disable_all();
    let r = match crate::scheduler::current_slot().and_then(|me| GRANTS.get(me)) {
        Some(g) => match g.add(first, last, table) {
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

/// A capability over `first..=last` left the capability table `table`:
/// close every range inside it that a thread of the table opened through it.
/// The threads' sets take new keys: a switch to one loads the smaller set,
/// this CPU loads its running thread's again now, and every other online CPU
/// is sent an IPI whose work does the same ([`refresh`]). Called with the
/// table's lock held (the capability store's event hook), so an [`enable`]
/// through the same table is before or after it, whole. Returns the threads
/// that lost a range.
pub fn revoke(table: u32, first: u16, last: u16) -> usize {
    if SLOTS == 0 {
        return 0;
    }
    let irq = azos_arch::ARCH.disable_all();
    let closed = GRANTS.iter().filter(|g| g.remove_within(table, first, last)).count();
    if closed != 0 {
        let me = crate::smp::current_cpu_id();
        load_current(me);
        // Every other CPU, whatever it runs: a revocation is rare. The new
        // keys are visible before the IPI is (x86_64: an xAPIC ICR write is
        // a store after them, an x2APIC one is fenced by `apic::send_raw`).
        for cpu in (0..azos_percpu::nr_cpu_ids()).filter(|&c| c != me && azos_percpu::cpu_online(c)) {
            azos_arch::ARCH.send_ipi(cpu);
        }
    }
    azos_arch::ARCH.restore(irq);
    closed
}

/// The running thread's set may have changed under it ([`revoke`] on another
/// CPU): load it again. An IPI's work, on every ISA; nothing where the ISA
/// has no port space, and two loads and a test for a port-less thread.
#[inline]
pub fn refresh() {
    if SLOTS == 0 {
        return;
    }
    let irq = azos_arch::ARCH.disable_all();
    load_current(crate::smp::current_cpu_id());
    azos_arch::ARCH.restore(irq);
}

/// Load the set of the thread running on `cpu` (the caller's own, interrupts off).
fn load_current(cpu: usize) {
    if let Some(me) = crate::scheduler::current_slot() {
        switch(cpu, me);
    }
}

/// The task in slot `idx` is new: no port open. A CPU still holding the old
/// set's bitmap never shows it again, since the next set takes a new key.
pub fn reset(idx: usize) {
    if let Some(g) = GRANTS.get(idx) {
        g.clear();
    }
}
