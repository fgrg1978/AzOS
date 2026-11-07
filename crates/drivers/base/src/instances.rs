// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The controllers of one class, by instance number.
//!
//! A class (GPIO, ...) serves one interface for every controller it has; the
//! capability's badge names the instance, and the class looks the controller
//! up here. Instance 0 is the board's own controller, there from the start
//! and never given back: the kernel's own lines (the e-stop's, a motor's) are
//! on it. Every other controller is a bound device: its driver's probe
//! registers it and its unbind unregisters it.
//!
//! An instance number belongs to the device that first took it, for the
//! life of the boot. The device is its bus handle AND the generation of that
//! handle's slot ([`DeviceId`]): the same device bound again gets its number
//! back, and no other device ever does, not even one that later takes the
//! same bus slot, so a capability on instance 1 can name only that device,
//! present or not. How many instances a class keeps is its Kconfig limit
//! (`N`).
//!
//! **Ops in flight.** [`Instances::get`] hands out a [`Lease`] and the caller
//! runs the op with no lock held. [`Instances::unregister`] closes the slot to
//! new leases and waits for the ones out to be dropped, so when it returns
//! no op is inside the controller and the driver's unbind may power it down.

use azos_sync::SpinLock;
use core::sync::atomic::{AtomicU32, Ordering};

/// A bound device, as the bus names it for the boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId {
    /// Its bus handle.
    pub handle: u32,
    /// The occupancy of that handle's slot.
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Nobody,
    Board,
    Device(DeviceId),
}

/// Why a registration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// Every instance number the class keeps belongs to another device.
    Full,
    /// The device's controller is registered already.
    Registered,
}

/// Why an unregistration did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnregisterError {
    /// The device has no controller registered.
    NotRegistered,
    /// Ops were still inside controller `instance` when the caller's patience
    /// ran out: it stays registered.
    InFlight { instance: u32 },
}

struct Slot<C: ?Sized + 'static> {
    owner: Owner,
    ctrl: Option<&'static C>,
    /// No new lease: an unregistration is waiting for the ones out.
    closing: bool,
}

impl<C: ?Sized + 'static> Clone for Slot<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: ?Sized + 'static> Copy for Slot<C> {}

/// A controller in use: the slot's in-flight count holds while it lives.
pub struct Lease<'a, C: ?Sized + 'static> {
    ctrl: &'static C,
    inflight: &'a AtomicU32,
}

impl<C: ?Sized + 'static> core::ops::Deref for Lease<'_, C> {
    type Target = C;
    fn deref(&self) -> &C {
        self.ctrl
    }
}

impl<C: ?Sized + 'static> Drop for Lease<'_, C> {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::Release);
    }
}

/// The controllers of one class: at most `N`, instance 0 the board's.
pub struct Instances<C: ?Sized + 'static, const N: usize> {
    slots: SpinLock<[Slot<C>; N]>,
    /// Leases out, by instance; taken under the lock, given back without it.
    inflight: [AtomicU32; N],
}

impl<C: ?Sized + Sync + 'static, const N: usize> Instances<C, N> {
    /// A class with nothing registered: the board's own instances are added
    /// with [`register_boards`](Self::register_boards), in the order that fixes
    /// their numbers.
    pub const fn empty() -> Self {
        let slots = [Slot { owner: Owner::Nobody, ctrl: None, closing: false }; N];
        Instances { slots: SpinLock::new(slots), inflight: [const { AtomicU32::new(0) }; N] }
    }

    /// A class whose instance 0 is `board`.
    pub const fn with_board(board: &'static C) -> Self {
        assert!(N >= 1, "a class keeps at least the board's controller");
        let mut slots = [Slot { owner: Owner::Nobody, ctrl: None, closing: false }; N];
        slots[0] = Slot { owner: Owner::Board, ctrl: Some(board), closing: false };
        Instances { slots: SpinLock::new(slots), inflight: [const { AtomicU32::new(0) }; N] }
    }

    /// Register several of the board's own instances at once, consecutively,
    /// or none: the number of the first, or `Full` when they do not all fit
    /// (nothing is taken then, so no number is left registered with nobody to
    /// use it). Never given back.
    pub fn register_boards(&self, ctrls: &[&'static C]) -> Result<u32, RegisterError> {
        let mut slots = self.slots.lock();
        let free = slots.iter().filter(|s| s.owner == Owner::Nobody).count();
        if free < ctrls.len() || ctrls.is_empty() {
            return Err(RegisterError::Full);
        }
        let mut first = None;
        for c in ctrls {
            let i = fresh(&slots[..]).ok_or(RegisterError::Full)?;
            slots[i] = Slot { owner: Owner::Board, ctrl: Some(*c), closing: false };
            first.get_or_insert(i as u32);
        }
        first.ok_or(RegisterError::Full)
    }

    /// Register device `dev`'s controller: the instance number it had before,
    /// else the lowest no device has had.
    pub fn register(&self, dev: DeviceId, ctrl: &'static C) -> Result<u32, RegisterError> {
        let mut slots = self.slots.lock();
        let i = match slots.iter().position(|s| s.owner == Owner::Device(dev)) {
            Some(i) if slots[i].ctrl.is_some() => return Err(RegisterError::Registered),
            Some(i) => i,
            None => fresh(&slots[..]).ok_or(RegisterError::Full)?,
        };
        slots[i] = Slot { owner: Owner::Device(dev), ctrl: Some(ctrl), closing: false };
        Ok(i as u32)
    }

    /// Withdraw device `dev`'s controller once no op is inside it; the
    /// instance it had. `patience` is asked while ops are in flight: `false`
    /// gives up, and the controller stays registered. The number stays the
    /// device's either way.
    pub fn unregister(&self, dev: DeviceId, patience: &mut dyn FnMut() -> bool) -> Result<u32, UnregisterError> {
        let i = {
            let mut slots = self.slots.lock();
            let i = slots
                .iter()
                .position(|s| s.owner == Owner::Device(dev) && s.ctrl.is_some() && !s.closing)
                .ok_or(UnregisterError::NotRegistered)?;
            slots[i].closing = true;
            i
        };
        while !cfg!(feature = "instances-no-drain-canary") && self.inflight[i].load(Ordering::Acquire) != 0 {
            if !patience() {
                self.slots.lock()[i].closing = false;
                return Err(UnregisterError::InFlight { instance: i as u32 });
            }
            core::hint::spin_loop();
        }
        let mut slots = self.slots.lock();
        slots[i].ctrl = None;
        slots[i].closing = false;
        Ok(i as u32)
    }

    /// The controller of instance `n`, if one is registered and not being
    /// withdrawn.
    pub fn get(&self, n: u32) -> Option<Lease<'_, C>> {
        let slots = self.slots.lock();
        let s = slots.get(n as usize)?;
        let ctrl = s.ctrl.filter(|_| !s.closing)?;
        self.inflight[n as usize].fetch_add(1, Ordering::Acquire);
        Some(Lease { ctrl, inflight: &self.inflight[n as usize] })
    }

    /// How many controllers are registered now.
    pub fn count(&self) -> usize {
        self.slots.lock().iter().filter(|s| s.ctrl.is_some()).count()
    }
}

/// The lowest instance number no device has had.
#[cfg(not(feature = "instances-reuse-canary"))]
fn fresh<C: ?Sized + 'static>(slots: &[Slot<C>]) -> Option<usize> {
    slots.iter().position(|s| s.owner == Owner::Nobody)
}

/// Canary: any number without a controller is free, so a device bound later
/// takes a number an unbound device's capabilities still name.
#[cfg(feature = "instances-reuse-canary")]
fn fresh<C: ?Sized + 'static>(slots: &[Slot<C>]) -> Option<usize> {
    slots.iter().position(|s| s.ctrl.is_none())
}
