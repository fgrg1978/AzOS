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
//! life of the boot: the same device bound again gets it back, and no other
//! device ever does, so a capability on instance 1 can name only that
//! device, present or not. How many instances a class keeps is its Kconfig
//! limit (`N`).
//!
//! A controller is `'static`: [`Instances::get`] copies it out and the caller
//! uses it with no lock held, so an op that overlaps the device's unbind runs
//! on a controller whose driver answers for itself (an unbound driver fails
//! the op).

use azos_sync::SpinLock;

/// Who an instance number belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Nobody,
    Board,
    /// The bus's handle of a bound device.
    Device(u32),
}

/// Why a registration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// Every instance number the class keeps belongs to another device.
    Full,
    /// The device's controller is registered already.
    Registered,
}

struct Slot<C: ?Sized + 'static> {
    owner: Owner,
    ctrl: Option<&'static C>,
}

impl<C: ?Sized + 'static> Clone for Slot<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: ?Sized + 'static> Copy for Slot<C> {}

/// The controllers of one class: at most `N`, instance 0 the board's.
pub struct Instances<C: ?Sized + 'static, const N: usize> {
    slots: SpinLock<[Slot<C>; N]>,
}

impl<C: ?Sized + Sync + 'static, const N: usize> Instances<C, N> {
    /// A class whose instance 0 is `board`.
    pub const fn with_board(board: &'static C) -> Self {
        assert!(N >= 1, "a class keeps at least the board's controller");
        let mut slots = [Slot { owner: Owner::Nobody, ctrl: None }; N];
        slots[0] = Slot { owner: Owner::Board, ctrl: Some(board) };
        Instances { slots: SpinLock::new(slots) }
    }

    /// Register device `dev`'s controller: the instance number it had before,
    /// else the lowest no device has had.
    pub fn register(&self, dev: u32, ctrl: &'static C) -> Result<u32, RegisterError> {
        let mut slots = self.slots.lock();
        let i = match slots.iter().position(|s| s.owner == Owner::Device(dev)) {
            Some(i) if slots[i].ctrl.is_some() => return Err(RegisterError::Registered),
            Some(i) => i,
            None => slots.iter().position(|s| s.owner == Owner::Nobody).ok_or(RegisterError::Full)?,
        };
        slots[i] = Slot { owner: Owner::Device(dev), ctrl: Some(ctrl) };
        Ok(i as u32)
    }

    /// Withdraw device `dev`'s controller; the instance it had, `None` when
    /// it had none registered. The number stays the device's.
    pub fn unregister(&self, dev: u32) -> Option<u32> {
        let mut slots = self.slots.lock();
        let i = slots.iter().position(|s| s.owner == Owner::Device(dev) && s.ctrl.is_some())?;
        slots[i].ctrl = None;
        Some(i as u32)
    }

    /// The controller of instance `n`, if one is registered.
    pub fn get(&self, n: u32) -> Option<&'static C> {
        self.slots.lock().get(n as usize).and_then(|s| s.ctrl)
    }

    /// How many controllers are registered now.
    pub fn count(&self) -> usize {
        self.slots.lock().iter().filter(|s| s.ctrl.is_some()).count()
    }
}
