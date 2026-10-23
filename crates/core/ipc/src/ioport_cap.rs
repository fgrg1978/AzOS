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
//! process: the signed topology is the only gate on which ports a row gets,
//! and nothing here knows which ports the kernel drives itself (COM1, the
//! CMOS index pair, the 8042, 0xCF8/0xCFC, the ACPI blocks). A row that
//! names one of those breaks the kernel's driver of it. The PIT's command
//! port (0x43) also reaches channel 0, and port 0x61 also holds the NMI
//! enables for parity and channel errors (bits 2 and 3).
//!
//! [`ioport_grant_cap`] is the topology minter, `"ioport.<first>.<count>"`
//! (decimal, as every dotted target of `cap_seed.rs`). It refuses a target
//! that does not read, an empty range or one past the ISA's port space
//! (`azos_arch_api::ioport::PORTS`: none at all on riscv64 and aarch64), and
//! any permission but `READ|WRITE`: the CPU's bitmap opens a port for `in`
//! and `out` together, so a read-only grant could not be honoured.

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
/// when [`ioport_resolve`] refuses or the cap-table is full.
pub fn ioport_grant_cap(tid: u32, spec: &str, perms: CapPerms) -> Option<Cap<targets::IoPorts>> {
    let range = ioport_resolve(spec, perms, azos_arch_api::ioport::PORTS)?;
    crate::cap_store::grant::<targets::IoPorts>(tid, perms, range)
}
