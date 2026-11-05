// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The typed kernel object caches at boot: the TLB per-space record is
//! allocated, the TCP table's source is registered, and with
//! `MM_PRELOAD_CACHES` every boot cache is filled and sealed.

use azos_mm::cache::{Cache, PRELOAD};
use azos_net::tcp::ConnArray;

static TCP_CONNS: Cache<ConnArray> = Cache::new();

fn tcp_conns() -> *mut ConnArray { TCP_CONNS.alloc() }

/// After `kheap::init`, before the first user switch.
pub(crate) fn init() {
    azos_mm::cache::init_spaces();
    azos_net::tcp::set_conn_source(tcp_conns);
    if !azos_net::tcp::provision() {
        azos_drv_sys::kerr!("[MM] FAILED: no memory for the TCP connection table");
        super::early::halt();
    }
    if !azos_ipc::endpoint::provision() {
        azos_drv_sys::kerr!("[MM] FAILED: no memory for the endpoint table");
        super::early::halt();
    }
    if !azos_mm::memobj::provision() {
        azos_drv_sys::kerr!("[MM] FAILED: no memory for the MemObj headers");
        super::early::halt();
    }
    if PRELOAD {
        let ok = TCP_CONNS.preload(1)
            & azos_fs::fat32::preload_boot_cache()
            & azos_syscall::handlers::preload_exec_bounce()
            & azos_ipc::cap_store::preload_cells()
            & azos_sched::scheduler::preload_tasks();
        if !ok {
            azos_drv_sys::kprintln!("[MM] preload: a boot cache could not be filled");
        }
    }
}

/// Every boot cache is filled and sealed.
#[cfg(feature = "ktest")]
pub(crate) fn all_sealed() -> bool {
    azos_mm::cache::spaces_sealed()
        && TCP_CONNS.is_sealed()
        && azos_fs::fat32::boot_cache_sealed()
        && azos_syscall::handlers::exec_bounce_sealed()
        && azos_ipc::endpoint::array_sealed()
        && azos_mm::memobj::array_sealed()
        && azos_ipc::cap_store::CELL_CACHE.is_sealed()
        && azos_sched::scheduler::tasks_sealed()
}
