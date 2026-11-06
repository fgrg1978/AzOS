// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `DOMAIN_MMIO_MAP`, the one way ring 3 maps device registers.
//!
//! The caller names a device of the hardware bus by its handle, not
//! an address; the bus decides the range, the capability whether it may be
//! written. See `crates/core/ipc/src/mmio_cap.rs` for the argument check.

use crate::handlers::*;

/// A capability refusal written at dispatch level returns -1, the value of
/// `dispatch.rs`'s `E_PERM`, not a handler's -99.
const E_PERM: i64 = -1;

/// `DOMAIN_MMIO_MAP`: a0 = device handle, a1 = access (`CapPerms` bits: READ,
/// or READ|WRITE). Maps exactly the device's register window into the calling
/// task's user page table, read-only unless WRITE was asked, and returns its
/// virtual address.
///
/// Refusals, in order: a handle above `u32::MAX`, naming no device or a device
/// a kernel driver owns or may still take, one whose probe failed, or one with
/// no window, or any other access word, `EINVAL`; no `Device` capability for the handle with the access asked
/// (WRITE needs a capability that carries WRITE), `-1`, recorded as a
/// capability denial. A mapping the page table cannot take is `-1`. The
/// mapping is booked with the bus before it is made: from then on no kernel
/// driver is bound to the device.
pub fn sys_mmio_map(a0: u64, a1: u64) -> i64 {
    let (index, _, writable) = match azos_ipc::mmio_cap::mmio_resolve(a0, a1) {
        Ok(r) => r,
        Err(e) => return e.errno().to_syscall_ret(),
    };
    if !cap_check(azos_abi::cap::ty::MMIO, index, writable) {
        return E_PERM;
    }
    let Some((base, size)) = azos_ipc::mmio_cap::mmio_claim(index) else {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    };
    match azos_sched::process::mmio_map_user(base as usize, size as usize, writable) {
        Some(va) => va as i64,
        None => {
            azos_ipc::mmio_cap::mmio_unclaim(index);
            -1
        }
    }
}

/// Ops on a device the caller holds (`ty::MMIO`): the memory its device
/// reaches (`DEVICE_DMA_MAP`, `DEVICE_DMA_UNMAP`). The device and the object
/// are resolved in one hold of the caller's table; the binding is the
/// process's, so a thread's exit leaves it.
pub(crate) fn device_op(c: &mut crate::invoke::Call) -> i64 {
    use azos_abi::cap::{ty, CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_abi::invoke::{CLASS_CTL, DEVICE_DMA_MAP, DEVICE_DMA_UNMAP, DMA_BIDIRECTIONAL, DMA_FROM_DEVICE, DMA_TO_DEVICE};
    use azos_ipc::cap::{targets, Cap, CapError};
    use azos_ipc::dma_bind::{self, DmaBindError, Direction};
    enum Refusal {
        Device(CapError),
        Object(CapError),
    }
    let map = match c.op {
        DEVICE_DMA_MAP => true,
        DEVICE_DMA_UNMAP => false,
        _ => return Errno::EINVAL.to_syscall_ret(),
    };
    let dir = match (map, c.w[1]) {
        (false, _) => Direction::Bidirectional,
        (true, DMA_TO_DEVICE) => Direction::ToDevice,
        (true, DMA_FROM_DEVICE) => Direction::FromDevice,
        (true, DMA_BIDIRECTIONAL) => Direction::Bidirectional,
        _ => return Errno::EINVAL.to_syscall_ret(),
    };
    if c.w[0] > u32::MAX as u64 {
        return Errno::ECAPSTALE.to_syscall_ret();
    }
    let dev: Cap<targets::MmioRegion> = Cap::from_raw(CapHandle::from_raw(c.handle));
    let obj: Cap<targets::Shm> = Cap::from_raw(CapHandle::from_raw(c.w[0] as u32));
    let op = c.op;
    // A map gives a device a way to write memory: containment refuses it. The
    // unmap takes one back and stays live.
    let resolved = azos_ipc::cap_store::with_table(c.tid, |t| {
        let d = if map { t.get_op(dev, CapPerms::WRITE, op) } else { t.get_op_uncontained(dev, CapPerms::WRITE, op) };
        let d = d.map_err(Refusal::Device)?;
        let o = t
            .get_op_uncontained(obj, CapPerms::RW, crate::invoke::class_op(ty::SHM, CLASS_CTL))
            .map_err(Refusal::Object)?;
        Ok((d, o))
    });
    let (dev, obj) = match resolved {
        None => return Errno::ECAPSTALE.to_syscall_ret(),
        Some(Err(Refusal::Device(e))) => {
            crate::handlers::note_typed_denial_for(c.tid, ty::MMIO, e);
            return crate::invoke::errno_cap(e);
        }
        Some(Err(Refusal::Object(e))) => {
            crate::handlers::note_typed_denial_for(c.tid, ty::SHM, e);
            return crate::invoke::errno_cap(e);
        }
        Some(Ok(v)) => v,
    };
    let owner = azos_sched::group::proc_tid(c.tid);
    let errno = |e: DmaBindError| match e {
        DmaBindError::BadObject => Errno::EINVAL,
        DmaBindError::NoDomain => Errno::ENODEV,
        DmaBindError::Busy => Errno::EBUSY,
        DmaBindError::Full => Errno::EMFILE,
        DmaBindError::Refused | DmaBindError::Kept => Errno::EIO,
        DmaBindError::NotBound => Errno::ENOENT,
    }
    .to_syscall_ret();
    if !map {
        return dma_bind::unmap(owner, dev, obj).map_or_else(errno, |()| 0);
    }
    match dma_bind::map(owner, dev, obj, dir) {
        Ok((bus, len)) => {
            c.rep[..2].copy_from_slice(&[bus.0, len as u64]);
            c.nrep = 2;
            0
        }
        Err(e) => errno(e),
    }
}
