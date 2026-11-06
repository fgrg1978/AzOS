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
//! before the task's own references go).
//!
//! * Only behind a translating IOMMU domain does the device reach the bound
//!   pages and nothing else. A device no IOMMU confines is given memory only
//!   where the build accepts that ring 3 is then kernel-trust
//!   ([`Hooks::unconfined`], Kconfig `DMA_RING3_WITHOUT_IOMMU`), and each
//!   such binding is recorded (`Rule::Ring3Dma`).
//! * At an unconfined device's unmap or exit the device is stopped first: its
//!   frames go back only once it is shown stopped. One that cannot be is
//!   *parked*: the pages stay pinned, the device stays booked, and it gets no
//!   new binding, so a crash loop keeps one object's worth, not one per crash.
//! * A binding books its device with the bus as a mapped register window does
//!   (`hwbus::claim_user_window`), for as long as the device may reach it.
//! * A binding is the thread's that made it, as an interrupt line's is.

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
    /// May ring 3 give memory to a device no IOMMU confines (Kconfig
    /// `DMA_RING3_WITHOUT_IOMMU`): its driver is then kernel-trust.
    pub unconfined: bool,
    /// Say what an end of a binding came to (the console's business).
    pub report: fn(Ended),
}

/// How a binding ended, for [`Hooks::report`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    pub dev: u32,
    pub tid: u32,
    pub bytes: usize,
    /// At the thread's exit (else at its unmap).
    pub exit: bool,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Out of the domain, the frames back.
    Released,
    /// Parked: the device could not be shown stopped.
    NotStopped,
    /// Parked: the domain's unmap failed.
    UnmapFailed,
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
    /// A kernel driver owns the device (or may still take it), it has no
    /// domain ring 3 may map into, or no IOMMU confines it and the build does
    /// not accept that.
    NoDomain,
    /// The object is bound already, or an earlier binding of the device is
    /// parked.
    Busy,
    /// No free record, or the caller holds its share of the table.
    Full,
    /// The domain refused the mapping.
    Refused,
    /// No such binding of the caller's.
    NotBound,
    /// The device could not be shown stopped, or the domain's unmap failed:
    /// the frames stay out of the allocator, parked.
    Kept,
}

/// What a binding came to.
const WHY_ADMITTED: u32 = 0;
const WHY_UNCONFINED: u32 = 1;
const WHY_PARKED: u32 = 2;
const WHY_KEPT: u32 = 3;

fn record(verdict: azos_decision::Verdict, dev: u32, tid: u32, bytes: usize, why: u32) {
    azos_decision::record(azos_decision::Rule::Ring3Dma, verdict, dev, [u64::from(tid), bytes as u64, u64::from(why)]);
}

fn confined(d: &dyn DmaDomain) -> bool {
    matches!(d.kind(), DomainKind::Iommu(_))
}

/// What a map gave the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapped {
    pub bus: DmaAddr,
    pub len: usize,
    /// The device snoops the CPU's caches: no clean or invalidate around a
    /// transfer.
    pub coherent: bool,
}

/// Map the object `obj` for device `dev` on behalf of `owner`, moving data
/// `dir`.
pub fn map(owner: u32, dev: u32, obj: u32, dir: Direction) -> Result<Mapped, DmaBindError> {
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

fn bind_claimed(hooks: Hooks, owner: u32, dev: u32, obj: u32, dir: Direction) -> Result<Mapped, DmaBindError> {
    use azos_decision::Verdict;
    let domain = (hooks.domain)(dev).ok_or(DmaBindError::NoDomain)?;
    let unconfined = !confined(domain);
    if unconfined && !(hooks.unconfined || cfg!(feature = "dma-ring3-unconfined-canary")) {
        record(Verdict::Refuse, dev, owner, 0, WHY_UNCONFINED);
        return Err(DmaBindError::NoDomain);
    }
    let mut t = TABLE.lock();
    if let Err(e) = t.can_insert(owner, dev, obj) {
        return Err(match e {
            BindError::Busy => DmaBindError::Busy,
            BindError::Parked => {
                drop(t);
                record(Verdict::Refuse, dev, owner, 0, WHY_PARKED);
                return Err(DmaBindError::Busy);
            }
            _ => DmaBindError::Full,
        });
    }
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
    drop(t);
    if unconfined {
        record(Verdict::Admit, dev, owner, len, WHY_ADMITTED);
    }
    Ok(Mapped { bus, len, coherent: domain.coherent() })
}

/// End `b`, just taken from the table: an unconfined device is stopped
/// first; then out of its domain, then the kernel's reference, then the
/// device's booking. A device not shown stopped, or an unmap that failed,
/// parks the binding instead (pages pinned, device booked), recorded.
fn end(b: Binding, hooks: Hooks, exit: bool) -> Result<(), DmaBindError> {
    let domain = (hooks.domain)(b.dev);
    let stopped = domain.is_some_and(confined) || (hooks.quiesce)(b.dev);
    let released = match domain {
        Some(d) if stopped => bind::release(d, &b, crate::memobj::memobj_frames_unpin).is_ok(),
        _ => false,
    };
    let mut ended = Ended { dev: b.dev, tid: b.owner, bytes: b.len, exit, outcome: Outcome::Released };
    if released {
        azos_drv_bus::hwbus::unclaim_user_window(b.dev);
        (hooks.report)(ended);
        return Ok(());
    }
    if !stopped {
        // `bind::release` counts what it keeps; this path never reached it.
        azos_dma::note_leak(b.len);
    }
    ended.outcome = if stopped { Outcome::UnmapFailed } else { Outcome::NotStopped };
    record(azos_decision::Verdict::Refuse, b.dev, b.owner, b.len, WHY_KEPT);
    TABLE.lock().park(b);
    (hooks.report)(ended);
    Err(DmaBindError::Kept)
}

/// The driver's unmap of `obj` from `dev`. An unconfined device is stopped
/// by the kernel first, whatever the driver did.
pub fn unmap(owner: u32, dev: u32, obj: u32) -> Result<(), DmaBindError> {
    let hooks = (*HOOKS.lock()).ok_or(DmaBindError::NotBound)?;
    let b = TABLE.lock().take(owner, dev, obj).ok_or(DmaBindError::NotBound)?;
    end(b, hooks, false)
}

/// The thread `tid` is gone: every binding it made ends, as [`unmap`] ends
/// one.
pub fn release_all(tid: u32) {
    let Some(hooks) = *HOOKS.lock() else { return };
    loop {
        let Some(b) = TABLE.lock().take_owned(tid) else { return };
        let _ = end(b, hooks, true);
    }
}
