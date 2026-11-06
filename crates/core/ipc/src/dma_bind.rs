// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The memory a ring-3 driver's device reaches (`DEVICE_DMA_MAP`,
//! `DEVICE_DMA_UNMAP`): the kernel's table of `azos_dma::bind` bindings, each a
//! ring-3 Contig object pinned by a kernel reference and mapped in the domain
//! of the device a `Device` capability names.
//!
//! The kernel answers the domain of a device and how to stop one
//! ([`set_hooks`]): the boot knows the IOMMU, the PCI functions and the
//! virtio transports, this crate does not. A binding ends by the driver's
//! unmap or the driver's exit ([`release_all`], first in the exit's release
//! order after the interrupt lines, so the frames are out of the domain
//! before the task's own references go); at the exit the device is stopped
//! first unless its domain is an IOMMU's, whose unmap alone confines it. A
//! binding books its device with the bus as a mapped register window does
//! (`hwbus::claim_user_window`), for as long as the device may reach it.

use azos_dma::bind::{self, Binding, BindError, Table};
pub use azos_dma::Direction;
use azos_dma::{DmaAddr, DmaDomain, DomainKind};
use azos_sync::SpinLock;

/// What the kernel answers for a device of the hardware bus.
#[derive(Clone, Copy)]
pub struct Hooks {
    /// The domain of device `dev`, ready for ring 3 to map into (an IOMMU
    /// domain exists and translates, so nothing unmapped is reachable);
    /// `None` for a device that has none.
    pub domain: fn(dev: u32) -> Option<&'static dyn DmaDomain>,
    /// Stop device `dev` issuing DMA; `false` when it cannot be shown
    /// stopped.
    pub quiesce: fn(dev: u32) -> bool,
}

static HOOKS: SpinLock<Option<Hooks>> = SpinLock::new(None);

/// Install the kernel's answers. Boot, before the first ring-3 task.
pub fn set_hooks(h: Hooks) {
    *HOOKS.lock() = Some(h);
}

/// Live ring-3 bindings at once: as many as one domain can map
/// (Kconfig `DMA_MAP_ENTRIES`).
const BINDINGS: usize = azos_limits::DMA_MAP_ENTRIES as usize;

static TABLE: SpinLock<Table<BINDINGS>> = SpinLock::new(Table::new());

/// Why a map or an unmap was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaBindError {
    /// The object is not one a device may be given (not a read-write Contig
    /// object ring 3 created), or it is gone.
    BadObject,
    /// A kernel driver owns the device (or may still take it), or it has no
    /// domain ring 3 may map into.
    NoDomain,
    /// The object is bound already.
    Busy,
    /// No free record.
    Full,
    /// The domain refused the mapping.
    Refused,
    /// No such binding of the caller's.
    NotBound,
    /// The domain's unmap failed: the frames stay out of the allocator.
    Kept,
}

/// Map the object `obj` for device `dev` on behalf of `owner`, moving data
/// `dir`: the bus address and length the device is given.
pub fn map(owner: u32, dev: u32, obj: u32, dir: Direction) -> Result<(DmaAddr, usize), DmaBindError> {
    let hooks = (*HOOKS.lock()).ok_or(DmaBindError::NoDomain)?;
    // A device a kernel driver owns, or may still take, keeps its domain; one
    // ring 3 gives memory to is booked like a mapped window, so no kernel
    // driver binds it while the binding lives.
    if azos_drv_bus::hwbus::claim_user_window(dev).is_none() {
        return Err(DmaBindError::NoDomain);
    }
    let r = bind_claimed(hooks, owner, dev, obj, dir);
    if r.is_err() {
        azos_drv_bus::hwbus::unclaim_user_window(dev);
    }
    r
}

fn bind_claimed(hooks: Hooks, owner: u32, dev: u32, obj: u32, dir: Direction) -> Result<(DmaAddr, usize), DmaBindError> {
    let domain = (hooks.domain)(dev).ok_or(DmaBindError::NoDomain)?;
    let mut t = TABLE.lock();
    t.can_insert(obj).map_err(|e| match e {
        BindError::Busy => DmaBindError::Busy,
        _ => DmaBindError::Full,
    })?;
    let (pa, len) = crate::memobj::memobj_dma_pin(obj).map_err(|_| DmaBindError::BadObject)?;
    let bus = match bind::map(domain, pa, len, dir) {
        Ok(b) => b,
        Err(_) => {
            drop(t);
            crate::memobj::memobj_frames_unpin(obj);
            return Err(DmaBindError::Refused);
        }
    };
    // Checked above, under the same hold.
    let _ = t.insert(Binding { owner, dev, obj, pa, len, bus });
    Ok((bus, len))
}

/// End `b`: out of its domain, then the kernel's reference, then the
/// device's booking. A binding whose pages the device may still reach keeps
/// the booking with them: no kernel driver takes that device.
fn end(b: &Binding, domain: Option<&'static dyn DmaDomain>) -> Result<(), DmaBindError> {
    let Some(domain) = domain else {
        // The domain the map used answered then; one that is gone now
        // cannot say the device lost the pages.
        azos_dma::note_leak(b.len);
        return Err(DmaBindError::Kept);
    };
    bind::release(domain, b, crate::memobj::memobj_frames_unpin).map_err(|_| DmaBindError::Kept)?;
    azos_drv_bus::hwbus::unclaim_user_window(b.dev);
    Ok(())
}

/// The driver's unmap of `obj` from `dev`: the device must already be
/// stopped from reaching it.
pub fn unmap(owner: u32, dev: u32, obj: u32) -> Result<(), DmaBindError> {
    let hooks = (*HOOKS.lock()).ok_or(DmaBindError::NotBound)?;
    let b = TABLE.lock().take(owner, dev, obj).ok_or(DmaBindError::NotBound)?;
    end(&b, (hooks.domain)(b.dev))
}

/// The task `tid` is gone: every binding it made ends. A device whose domain
/// is not an IOMMU's is stopped first; one that cannot be shown stopped
/// keeps its frames (counted), as a failed unmap does.
pub fn release_all(tid: u32) {
    let Some(hooks) = *HOOKS.lock() else { return };
    loop {
        let Some(b) = TABLE.lock().take_owned(tid) else { return };
        let domain = (hooks.domain)(b.dev);
        let confined = domain.is_some_and(|d| matches!(d.kind(), DomainKind::Iommu(_)));
        if !confined && !(hooks.quiesce)(b.dev) {
            azos_dma::note_leak(b.len);
            continue;
        }
        let _ = end(&b, domain);
    }
}
