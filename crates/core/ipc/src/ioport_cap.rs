// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cap<Device> over a range of I/O ports (`ty::IOPORT`).
//!
//! The capability names the ports themselves: its resource is the range
//! (`azos_abi::cap::ioport_range`), first and last port. A PC's legacy
//! devices sit at ports the architecture fixed (the PIT at 0x40, the speaker
//! gate at 0x61), with no bus to enumerate them by, so unlike `mmio_cap.rs`
//! there is no device to name instead. What the holder can do with it is
//! `DEVICE_IOPORT_ENABLE` (`crates/core/syscall/src/ioport.rs`): open the
//! range to the calling thread.
//!
//! **What a grant hands out.** A port is a register of the machine, not of a
//! process: the signed topology decides which ports a row gets, and the
//! kernel refuses, whatever the row says, a range that holds a port one of
//! its own drivers bound (`azos_arch_api::ioport::reserve`, called where
//! each binds: COM1, the CMOS clock, the PCI configuration pair, the 8042,
//! the PIT's channel 0, the 8259s, the ACPI PM timer). A ring-3 access there
//! would race the kernel's driver of it. Each such refusal is recorded
//! (`Rule::IoportReserved`: the range and the first kernel port in it).
//!
//! Two ports reach the kernel's devices and are granted all the same, by rule:
//!
//! - **0x43, the PIT's mode register**, also selects and reprograms channel
//!   0. The kernel reads channel 0 only to measure the TSC, at boot, before
//!   any task runs (`timer::calibrate`), and keeps its line (IRQ 0) masked at
//!   both 8259s and the IOAPIC; the clock and the timer are the TSC and the
//!   LAPIC from then on. A holder that rewrites channel 0 after boot changes
//!   nothing the kernel reads. Channel 0's own data port (0x40) stays the
//!   kernel's. A kernel that measures against the PIT again after boot (a
//!   resume that recalibrates) must reserve 0x43 there.
//! - **0x61, the speaker gate**, also holds the enables of the parity (SERR#)
//!   and channel-check (IOCHK#) NMIs, bits 2 and 3, and their status, bits 6
//!   and 7. The kernel's NMI handler counts an NMI and returns: it reads no
//!   reason from 0x61, so a holder that masks or unmasks those sources hides
//!   or shows NMIs nothing in the kernel acts on (the PC speaker driver,
//!   `azos_pcspk`, writes them back as it read them). A kernel that grows a
//!   reason decoder (Linux's `default_do_nmi`) must reserve 0x61 and serve
//!   the gate itself.
//!
//! The NMI mask bit of the CMOS index port (0x70, bit 7) needs no rule: the
//! CMOS pair is the clock's, reserved.
//!
//! [`ioport_grant_cap`] is the topology minter, `"ioport.<first>.<count>"`
//! (decimal, as every dotted target of `cap_seed.rs`). It refuses a target
//! that does not read, an empty range or one past the ISA's port space
//! (`azos_arch_api::ioport::PORTS`: none at all on riscv64 and aarch64), any
//! permission but `READ|WRITE` (the CPU's bitmap opens a port for `in` and
//! `out` together, so a read-only grant could not be honoured), and a range
//! the kernel reserved.

use azos_decision::{Rule, Verdict};

use crate::cap::{targets, Cap, CapPerms};

/// The resource `"<first>.<count>"` names, when the range fits a port space
/// of `ports` ports and `perms` is a grant the bitmap can honour.
pub fn ioport_resolve(spec: &str, perms: CapPerms, ports: u32) -> Option<u32> {
    if perms != CapPerms::RW {
        return None;
    }
    let (first, count) = spec.split_once('.')?;
    let (first, count) = (first.parse::<u32>().ok()?, count.parse::<u32>().ok()?);
    if count == 0 || first >= ports || count > ports - first {
        return None;
    }
    azos_abi::cap::ioport_range(first, count)
}

/// Topology-loader entry: grant `tid` a `Cap<Device>` over the ports
/// `spec` (`"<first>.<count>"`, the target after `ioport.`) names. `None`
/// when [`ioport_resolve`] refuses, the kernel drives a port of the range,
/// or the cap-table is full.
pub fn ioport_grant_cap(tid: u32, spec: &str, perms: CapPerms) -> Option<Cap<targets::IoPorts>> {
    ioport_grant_in(tid, spec, perms, azos_arch_api::ioport::PORTS, azos_arch_api::ioport::reserved)
}

/// [`ioport_grant_cap`] on a space of `ports` ports where `reserved` names
/// the first kernel port of a range (`azos_arch_api::ioport::reserved`): the
/// host suites, whose build has no port space, pass their own. A range with
/// a kernel port is refused and recorded (`Rule::IoportReserved`).
pub fn ioport_grant_in(
    tid: u32,
    spec: &str,
    perms: CapPerms,
    ports: u32,
    reserved: impl Fn(u16, u16) -> Option<u16>,
) -> Option<Cap<targets::IoPorts>> {
    let range = ioport_resolve(spec, perms, ports)?;
    let (first, last) = azos_abi::cap::ioport_bounds(range)?;
    if let Some(port) = reserved(first, last) {
        azos_decision::record(Rule::IoportReserved, Verdict::Refuse, tid, [first as u64, last as u64, port as u64]);
        return None;
    }
    crate::cap_store::grant::<targets::IoPorts>(tid, perms, range)
}
