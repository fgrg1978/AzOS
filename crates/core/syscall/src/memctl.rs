// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `MemCtl` interface the kernel hosts: the owner of a volatile memory
//! object says when reclaim may drop it (`azos_devif::memctl` has the
//! contract; `azos_ipc::memobj`, "Volatile objects", the mechanism).
//!
//! The ops are endpoint ops and not syscalls: they change what the kernel may
//! take, which is authority, but they are rare (once per use of the object)
//! and the interface needs no number of its own. The object is named by a
//! `Cap<Shm>` carried in the request; it stays in the caller's table and is
//! resolved there (`khost::takes_caps`).
//!
//! User: `infsrv`, the inference service (`userspace/services/infsrv`). Its
//! blob arena, the weights of every loaded model, is a volatile object it can
//! make again from the signed bundles on the volume: it marks it droppable
//! between calls and held during one, and loads the bundles again when
//! `set_nonvolatile` says it was purged. The other callers are the host tests
//! (`syscall-tests`, `memctl_guards`; `devif-tests`, `memctl`).
//!
//! Availability: the purge stage is part of the reclaim pass, which exists
//! only with `MM_RECLAIM_COMPRESS`. On a `MM_RECLAIM_OFF` image the ops work
//! and the object is created, marked and unmarked, but it is never purged.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::invoke::CLASS_CTL;
use azos_devif::memctl::VolatileMem;
use azos_devif::{outcome, Cap as WireCap, Out};
use azos_ipc::cap::{targets, Cap, CapError, CapTarget};
use azos_ipc::memobj::{memobj_set_volatile_ref, MemObjError};

use crate::invoke::class_op;
use crate::khost::Caller;

/// The `MemCtl` interface served for one caller.
pub struct Server(pub Caller);

impl Server {
    /// Make the object `mem` names droppable (`volatile`) or in use again.
    ///
    /// In order: the endpoint's `WRITE` (one capability-denial record on
    /// refusal); the handle (a memory object the caller holds with `READ`:
    /// a right it lacks is recorded as a typed denial, anything else is
    /// `BAD_ARGUMENT`); the object (volatile, and the caller its owner).
    fn set(&self, mem: WireCap<VolatileMem>, volatile: bool) -> Out<bool> {
        if let Err(e) = self.0.gate::<bool>(CapPerms::WRITE) {
            return e;
        }
        let tid = self.0.tid;
        let cap: Cap<targets::Shm> = Cap::from_raw(CapHandle::from_raw(mem.raw()));
        let r = match azos_ipc::cap_store::with_table(tid, |t| t.get_op(cap, CapPerms::READ, class_op(<targets::Shm as CapTarget>::TYPE, CLASS_CTL))) {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
                crate::handlers::note_typed_denial_for(tid, <targets::Shm as CapTarget>::TYPE, e);
                return Out::err(match e {
                    CapError::MissingPerms | CapError::Contained => outcome::DENIED,
                    _ => outcome::BAD_ARGUMENT,
                });
            }
            None => return Out::err(outcome::BAD_ARGUMENT),
        };
        // The process owns the object, not the thread (`current_proc_tid`).
        let owner = azos_sched::group::proc_tid(tid);
        match memobj_set_volatile_ref(owner, r, volatile) {
            Ok(purged) => Out::ok(purged),
            Err(MemObjError::Cap(_)) => {
                self.0.deny(CapPerms::WRITE);
                Out::err(outcome::DENIED)
            }
            Err(_) => Out::err(outcome::BAD_ARGUMENT),
        }
    }
}

impl azos_devif::MemCtl for Server {
    fn set_volatile(&mut self, mem: WireCap<VolatileMem>) -> Out<bool> {
        self.set(mem, true)
    }

    fn set_nonvolatile(&mut self, mem: WireCap<VolatileMem>) -> Out<bool> {
        self.set(mem, false)
    }
}
