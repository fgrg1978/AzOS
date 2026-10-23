// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `DEVICE_IOPORT_ENABLE`, the one way ring 3 reaches I/O ports.
//!
//! The handle is a `Device` capability that names a range of ports
//! (`ty::IOPORT`, minted by `crates/core/ipc/src/ioport_cap.rs`); the op
//! opens the whole range to the calling thread (`azos_sched::ioport`), whose
//! `in`/`out` on it then run in ring 3 and on any other port fault (#GP, the
//! task's fault: `KILLED_SEGV`).
//!
//! Where the ISA has no port space (riscv64, aarch64: `PORTS` 0) the op
//! answers `-ENODEV` before it looks at the handle: the same seam on every
//! ISA, not a `cfg`.

use azos_abi::cap::{ioport_bounds, ty, CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::invoke::DEVICE_IOPORT_ENABLE;
use azos_ipc::cap::{targets, Cap, CapError};

use crate::invoke::{errno_cap, Call};

/// Ops on a range of I/O ports the caller holds.
pub(crate) fn ioport_op(c: &mut Call) -> i64 {
    if c.op != DEVICE_IOPORT_ENABLE {
        return Errno::EINVAL.to_syscall_ret();
    }
    if azos_arch_api::ioport::PORTS == 0 {
        return Errno::ENODEV.to_syscall_ret();
    }
    if c.w[..azos_abi::invoke::INVOKE_REG_WORDS].iter().any(|&w| w != 0) {
        return Errno::EINVAL.to_syscall_ret();
    }
    let cap: Cap<targets::IoPorts> = Cap::from_raw(CapHandle::from_raw(c.handle));
    // A port write reaches the machine: a contained program is refused.
    let r = azos_ipc::cap_store::read_table(c.tid, |t| t.get_op(cap, CapPerms::RW, c.op));
    let range = match r.unwrap_or(Err(CapError::Stale)) {
        Ok(range) => range,
        Err(e) => {
            crate::handlers::note_typed_denial_for(c.tid, ty::IOPORT, e);
            return errno_cap(e);
        }
    };
    let Some((first, last)) = ioport_bounds(range) else { return Errno::EINVAL.to_syscall_ret() };
    match azos_sched::ioport::enable(first, last) {
        Ok(()) => 0,
        Err(azos_sched::ioport::EnableError::Full) => Errno::EMFILE.to_syscall_ret(),
        Err(azos_sched::ioport::EnableError::NoPorts) => Errno::ENODEV.to_syscall_ret(),
    }
}
