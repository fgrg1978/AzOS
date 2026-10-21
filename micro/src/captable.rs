// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A task's capability table, over a slice the kernel carved from the task's
//! grant. The slot is the main kernel's: 128 bits, the hot word of
//! `azos_abi::cap::slot_word` (kind, rights, generation, resource) and the
//! extension word (the badge of a v2 call; nothing here writes it, the
//! layout is kept so a topology and a capability mean the same on both
//! kernels). Handles are `azos_abi::cap::CapHandle`, the same 32-bit
//! packing.
//!
//! The rules are the main kernel's (`crates/core/ipc/src/cap.rs`): a handle
//! is checked for occupancy, generation, kind and rights in that order; a
//! freed slot keeps its generation and the next grant takes the next one;
//! a slot whose generation reached the field's maximum is retired, never
//! reissued.

use azos_abi::cap::{slot_word, CapHandle, CapPerms, CapType};

/// One slot: 128 bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct CapSlot {
    /// `slot_word`'s word.
    pub hot: u64,
    /// The extension word.
    pub ext: u64,
}

const _: () = assert!(core::mem::size_of::<CapSlot>() == 16, "a capability slot is 128 bits");
const _: () = assert!(core::mem::align_of::<CapSlot>() == 8);

impl CapSlot {
    /// A free slot that has never been granted.
    pub const EMPTY: Self = Self { hot: 0, ext: 0 };
}

/// Why a handle did not resolve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapError {
    /// No live slot has this handle (null, out of range, freed, or reissued).
    Stale,
    /// The slot holds another kind.
    WrongKind,
    /// The slot lacks a right asked for.
    MissingPerms,
}

/// The table: the slots, borrowed.
pub struct CapTable<'a> {
    slots: &'a mut [CapSlot],
}

impl<'a> CapTable<'a> {
    /// Over `slots`, which the caller has cleared (a fresh grant).
    pub fn new(slots: &'a mut [CapSlot]) -> Self {
        Self { slots }
    }

    /// Mint a capability into a free slot; its handle, or `None` when the
    /// table is full (every slot occupied or retired).
    pub fn install(&mut self, kind: CapType, perms: CapPerms, resource: u32) -> Option<CapHandle> {
        let idx = self.slots.iter().position(|s| {
            !slot_word::occupied(s.hot) && slot_word::generation(s.hot) < CapHandle::MAX_GENERATION
        })?;
        let generation = slot_word::generation(self.slots[idx].hot) + 1;
        self.slots[idx].hot = slot_word::encode(kind, perms, generation, resource);
        Some(CapHandle::pack(kind, perms, generation, idx as u16))
    }

    fn slot_of(&self, h: CapHandle) -> Result<usize, CapError> {
        if h.is_null() {
            return Err(CapError::Stale);
        }
        let idx = h.slot() as usize;
        let w = self.slots.get(idx).ok_or(CapError::Stale)?.hot;
        if !slot_word::occupied(w) || slot_word::generation(w) != h.generation() {
            return Err(CapError::Stale);
        }
        Ok(idx)
    }

    /// The resource `h` names, if it is live, of kind `kind`, with the rights
    /// `need`.
    pub fn resolve(&self, h: CapHandle, kind: CapType, need: CapPerms) -> Result<u32, CapError> {
        let w = self.slots[self.slot_of(h)?].hot;
        if !slot_word::ty_is(w, kind) {
            return Err(CapError::WrongKind);
        }
        if !slot_word::perms(w).contains(need) {
            return Err(CapError::MissingPerms);
        }
        Ok(slot_word::resource(w))
    }

    /// What `h` names, if it is live: any kind, any rights.
    pub fn resolve_any(&self, h: CapHandle) -> Result<(CapType, CapPerms, u32), CapError> {
        let w = self.slots[self.slot_of(h)?].hot;
        Ok((slot_word::ty(w), slot_word::perms(w), slot_word::resource(w)))
    }

    /// Free the slot `h` names (any kind, any rights): the handle and every
    /// copy of it go stale. What it named, for the caller to tear down.
    pub fn close(&mut self, h: CapHandle) -> Result<(CapType, CapPerms, u32), CapError> {
        let idx = self.slot_of(h)?;
        let w = self.slots[idx].hot;
        self.slots[idx].hot = slot_word::cleared(w);
        self.slots[idx].ext = 0;
        Ok((slot_word::ty(w), slot_word::perms(w), slot_word::resource(w)))
    }

    /// The handle of the live capability of `kind` naming `resource` (the
    /// caller's own table: a lookup that invented a handle would be a mint).
    pub fn lookup(&self, kind: CapType, resource: u32) -> Option<CapHandle> {
        self.slots.iter().enumerate().find_map(|(i, s)| {
            let w = s.hot;
            (slot_word::ty_is(w, kind) && slot_word::resource(w) == resource).then(|| {
                CapHandle::pack(kind, slot_word::perms(w), slot_word::generation(w), i as u16)
            })
        })
    }

    /// Slots in use.
    pub fn live(&self) -> usize {
        self.slots.iter().filter(|s| slot_word::occupied(s.hot)).count()
    }

    /// Free every slot: a task that ends. Generations are kept, so a handle
    /// of the old task can never resolve against a new one's grant.
    pub fn clear_all(&mut self) {
        for s in self.slots.iter_mut() {
            s.hot = slot_word::cleared(s.hot);
            s.ext = 0;
        }
    }
}
