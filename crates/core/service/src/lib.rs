// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Service manager — port of kernel/core/service.c
//!
//! Microservice registry: register, discover, stop, heartbeat.
//! Services communicate via IPC channels.

use azos_sync::SpinLock;
pub use azos_limits::MAX_SERVICES;
pub const MAX_SERVICE_NAME: usize = 32;

#[derive(Clone, Copy, PartialEq)]
pub enum ServiceState {
    Free    = 0,
    Running = 1,
    Stopped = 2,
}

#[derive(Clone, Copy)]
pub struct ServiceEntry {
    pub name:        [u8; MAX_SERVICE_NAME],
    pub tid:         u32,
    pub state:       ServiceState,
    pub heartbeat:   u32,
    pub ipc_channel: u32,
}

impl ServiceEntry {
    pub const fn new() -> Self {
        ServiceEntry {
            name:        [0u8; MAX_SERVICE_NAME],
            tid:         0,
            state:       ServiceState::Free,
            heartbeat:   0,
            ipc_channel: 0,
        }
    }
}

struct ServiceTable {
    entries: [ServiceEntry; MAX_SERVICES],
    count:   usize,
}

impl ServiceTable {
    const fn new() -> Self {
        ServiceTable {
            entries: [ServiceEntry::new(); MAX_SERVICES],
            count:   0,
        }
    }

    fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        let query_len = name.len().min(MAX_SERVICE_NAME);
        for i in 0..MAX_SERVICES {
            if self.entries[i].state == ServiceState::Free { continue; }
            let ent_name = &self.entries[i].name;
            // Compare byte-by-byte up to query length, then check null terminator
            if ent_name[..query_len] == name[..query_len] {
                if query_len == MAX_SERVICE_NAME || ent_name[query_len] == 0 {
                    return Some(i);
                }
            }
        }
        None
    }

    fn find_free(&self) -> Option<usize> {
        for i in 0..MAX_SERVICES {
            if self.entries[i].state == ServiceState::Free { return Some(i); }
        }
        None
    }
}

static SERVICE_TABLE: SpinLock<ServiceTable> = SpinLock::new(ServiceTable::new());

pub fn service_init() {
    // Static initialization handles zero-fill. Nothing extra needed.
}

/// Register a new service with the given name, task ID and IPC channel.
/// Returns 0 on success, -1 if name already registered or table full.
///
/// One exception to "already registered": a `Stopped` entry held for `tid`
/// itself is taken up again (`Running`, the new channel). That is the entry
/// the M4 supervisor held across a supervised driver's death and handed to
/// its successor ([`service_orphan_all`], [`service_adopt`]); the successor's
/// image registers its names exactly as the first one did.
pub fn service_register(name: &[u8], tid: u32, channel: u32) -> i32 {
    let mut t = SERVICE_TABLE.lock();
    if let Some(i) = t.find_by_name(name) {
        let e = &mut t.entries[i];
        if tid != 0 && e.tid == tid && e.state == ServiceState::Stopped {
            e.state       = ServiceState::Running;
            e.heartbeat   = 0;
            e.ipc_channel = channel;
            return 0;
        }
        return -1;
    }
    let idx = match t.find_free() {
        Some(i) => i,
        None    => return -1,
    };
    let e = &mut t.entries[idx];
    let n = name.len().min(MAX_SERVICE_NAME);
    e.name[..n].copy_from_slice(&name[..n]);
    if n < MAX_SERVICE_NAME { e.name[n] = 0; }
    e.tid         = tid;
    e.state       = ServiceState::Running;
    e.heartbeat   = 0;
    e.ipc_channel = channel;
    t.count += 1;
    0
}

/// Look up a service by name.  Returns a copy of the entry or None.
pub fn service_discover(name: &[u8]) -> Option<ServiceEntry> {
    let t = SERVICE_TABLE.lock();
    t.find_by_name(name).map(|i| t.entries[i])
}

/// Stop (but don't remove) a service.
pub fn service_stop(name: &[u8]) -> i32 {
    let mut t = SERVICE_TABLE.lock();
    match t.find_by_name(name) {
        Some(i) => { t.entries[i].state = ServiceState::Stopped; 0 }
        None    => -1,
    }
}

/// Restart a previously stopped service.
pub fn service_restart(name: &[u8], tid: u32) -> i32 {
    let mut t = SERVICE_TABLE.lock();
    match t.find_by_name(name) {
        Some(i) => {
            t.entries[i].tid   = tid;
            t.entries[i].state = ServiceState::Running;
            0
        }
        None => -1,
    }
}

/// `service_stop_as` / `service_heartbeat_as`: no service by that name.
pub const SERVICE_NOT_FOUND: i32 = -1;
/// `service_stop_as` / `service_heartbeat_as`: the caller is not the task the
/// service is registered to. Nothing was changed.
pub const SERVICE_NOT_OWNER: i32 = -2;

/// Stop `name` on behalf of `caller`: only the registered owner may. The
/// syscall path uses this; `service_stop` stays for kernel-internal callers.
/// On `SERVICE_NOT_OWNER` the second value is the owner's TID.
pub fn service_stop_as(name: &[u8], caller: u32) -> (i32, u32) {
    let mut t = SERVICE_TABLE.lock();
    match t.find_by_name(name) {
        Some(i) if t.entries[i].tid != caller => (SERVICE_NOT_OWNER, t.entries[i].tid),
        Some(i) => { t.entries[i].state = ServiceState::Stopped; (0, caller) }
        None    => (SERVICE_NOT_FOUND, 0),
    }
}

/// Heartbeat `name` on behalf of `caller`: only the owner may. A heartbeat
/// is a liveness claim, and one task claiming another's is a dead service
/// reported alive. Same return shape as [`service_stop_as`].
pub fn service_heartbeat_as(name: &[u8], caller: u32) -> (i32, u32) {
    let mut t = SERVICE_TABLE.lock();
    match t.find_by_name(name) {
        Some(i) if t.entries[i].tid != caller => (SERVICE_NOT_OWNER, t.entries[i].tid),
        Some(i) => {
            t.entries[i].heartbeat = t.entries[i].heartbeat.wrapping_add(1);
            (0, caller)
        }
        None => (SERVICE_NOT_FOUND, 0),
    }
}

/// Record a heartbeat from a running service.
pub fn service_heartbeat(name: &[u8]) -> i32 {
    let mut t = SERVICE_TABLE.lock();
    match t.find_by_name(name) {
        Some(i) => {
            t.entries[i].heartbeat = t.entries[i].heartbeat.wrapping_add(1);
            0
        }
        None => -1,
    }
}

/// Free every entry registered to `tid`; returns how many. Called from the
/// kernel's task-exit hook. Before it existed an entry outlived its task: the
/// name stayed taken for good, and `service_discover` kept answering the dead
/// TID — or, once the task-pool slot and TID were reused, a stranger's.
pub fn service_release_all(tid: u32) -> usize {
    let mut t = SERVICE_TABLE.lock();
    let mut freed = 0;
    for i in 0..MAX_SERVICES {
        if t.entries[i].state != ServiceState::Free && t.entries[i].tid == tid {
            t.entries[i] = ServiceEntry::new();
            freed += 1;
        }
    }
    t.count -= freed;
    freed
}

/// Hold every entry registered to `tid` for a successor: each stays in the
/// table, `Stopped`, still naming `tid`. Returns how many.
///
/// The exit path calls this instead of [`service_release_all`] for a driver
/// the M4 supervisor is restarting, so the name is not free for another task
/// to take during the gap. `discover` answers the dead TID with state
/// `Stopped` until [`service_adopt`] names the successor and the successor
/// registers. If no successor comes, [`service_release_all`] with the same
/// `tid` frees them, as it would have at the death.
pub fn service_orphan_all(tid: u32) -> usize {
    if tid == 0 { return 0; }
    let mut t = SERVICE_TABLE.lock();
    let mut n = 0;
    for i in 0..MAX_SERVICES {
        if t.entries[i].state != ServiceState::Free && t.entries[i].tid == tid {
            t.entries[i].state = ServiceState::Stopped;
            n += 1;
        }
    }
    n
}

/// Hand every entry held for `dead_tid` ([`service_orphan_all`]) to `heir`,
/// still `Stopped`: `heir` takes each up by registering it. Returns how many.
pub fn service_adopt(dead_tid: u32, heir: u32) -> usize {
    if dead_tid == 0 || heir == 0 { return 0; }
    let mut t = SERVICE_TABLE.lock();
    let mut n = 0;
    for i in 0..MAX_SERVICES {
        if t.entries[i].state == ServiceState::Stopped && t.entries[i].tid == dead_tid {
            t.entries[i].tid = heir;
            n += 1;
        }
    }
    n
}

/// Return the number of registered services (Running or Stopped).
pub fn service_count() -> usize {
    SERVICE_TABLE.lock().count
}

/// List all services (calls `cb` for each entry).
pub fn service_list(mut cb: impl FnMut(&ServiceEntry)) {
    let t = SERVICE_TABLE.lock();
    for i in 0..MAX_SERVICES {
        if t.entries[i].state != ServiceState::Free {
            cb(&t.entries[i]);
        }
    }
}
