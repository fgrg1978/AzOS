// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Keystore roots held in guarded memory. The kernel writes a root into pages
//! it donates with `guard_pages` and names it here; from then on no EL1 or EL0
//! access reaches the bytes, and the monitor is the only one that can run the
//! root through HKDF. The root never leaves: `key_derive` returns what was
//! derived from it.

use crate::ct::secure_zero;
use crate::state::HYP;
use azos_hyp_api::{
    derive_req_addr_error, key_root_error, DeriveReq, DENIED, INVALID, INV_KEY_ROOTS, KEY_LEN, KEY_ROOTS, OK,
};
use core::sync::atomic::{AtomicU64, Ordering};

/// Where each root is (0: not set), written once.
static ROOT_PA: [AtomicU64; KEY_ROOTS] = [const { AtomicU64::new(0) }; KEY_ROOTS];

/// `key_root_set(slot, pa)`: refused for an unknown slot, for bytes outside
/// guarded memory, and for a slot already set.
pub fn root_set(slot: u64, pa: u64) -> i64 {
    super::s2::with_guard(|g, _, _| {
        if key_root_error(slot, pa, g).is_some() {
            return INVALID;
        }
        if ROOT_PA[slot as usize].compare_exchange(0, pa, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return DENIED;
        }
        HYP.set_invariant(INV_KEY_ROOTS);
        OK
    })
}

/// `key_derive(slot, req_pa)`.
pub fn derive(slot: u64, req_pa: u64) -> Result<[u8; KEY_LEN], i64> {
    let root_pa = ROOT_PA.get(slot as usize).map_or(0, |p| p.load(Ordering::Acquire));
    if root_pa == 0 {
        return Err(DENIED);
    }
    super::s2::with_guard(|g, hole, hole_end| {
        if derive_req_addr_error(req_pa, hole, hole_end, g).is_some() {
            return Err(INVALID);
        }
        // SAFETY: the EL2 identity map covers RAM; the request is the kernel's
        // (8-aligned, clear of the monitor and of guarded pages, checked above)
        // and the root lies in guarded memory (checked when it was set).
        let (req, mut root): (DeriveReq, [u8; KEY_LEN]) = unsafe {
            (core::ptr::read_volatile(req_pa as *const DeriveReq), core::ptr::read_volatile(root_pa as *const [u8; KEY_LEN]))
        };
        let out = super::kdf::derive(&root, &req);
        secure_zero(&mut root);
        out.ok_or(INVALID)
    })
}
