// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Topology install and memory admission against the DTB/fallback RAM window.

use crate::*;

/// Install the static topology before any task that mints a capability
/// from it can run.
///
/// Shared between both `kernel_main`s (riscv64 called this in place until
/// 2026-09-22; aarch64 never called it at all, which is why `captest` and
/// `abitest`'s topology-seeded checks — `cap_lookup(Endpoint, ...)` for
/// `endpoint.demo` among them — failed there: `azos_topology::get()`
/// returned `None`, and the autorun cap-seed bridge logs "topology not
/// installed — nothing minted" instead of granting anything). For now this
/// ships the built-in `default_minimal()` topology; W4+ replaces it with a
/// signed CAPS.TOML / SCHED.TOML loaded from FAT32 (see RFC-0005).
///
/// Built in place in the topology's static slot: the table is sized by the
/// limits and is megabytes on the fleet profile. Built on the boot stack
/// and passed by value, it ran past the stack into `.bss` and the fleet
/// image faulted in the driver registry it had overwritten.
///
/// `num_cpus` gates deadline admission: the install-time check can only
/// assume every CPU a mask names, so a profile pinned to a CPU this board
/// does not have is refused here, once the board's real hart count is
/// known, before anything is spawned. Halts the board on either failure —
/// callers do not return past this on an error path.
pub(crate) fn install_topology(num_cpus: usize) {
    match azos_topology::init_with(azos_topology::fill_default_minimal) {
        Ok(()) => {
            kprintln!(
                "[TOPO] Topology installed: {} classes, {} tasks",
                azos_topology::get().map(|t| t.classes_len()).unwrap_or(0),
                azos_topology::get().map(|t| t.tasks_len()).unwrap_or(0),
            );
            if let Some(topo) = azos_topology::get() {
                match topo.deadline_admission(num_cpus) {
                    Ok(r) if r.placed > 0 => {
                        kprintln!(
                            "[TOPO] Deadline admission: {} real-time task(s) placed on {} CPU(s)",
                            r.placed, num_cpus,
                        );
                        band_admission(topo, &r);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        azos_drv_sys::kerr!("[TOPO] Deadline admission REFUSED on {} CPU(s): {:?} — halting", num_cpus, e);
                        loop { azos_arch::cpu::wfi(); }
                    }
                }
            }
            if let Some(topo) = azos_topology::get() {
                memory_admission(topo);
            }
        }
        Err(e) => {
            azos_drv_sys::kerr!("[TOPO] Topology install FAILED: {:?} — halting", e);
            loop { azos_arch::cpu::wfi(); }
        }
    }
}

/// Wave 11 SCHED-RT: the second condition of boot admission. The rows placed
/// on a CPU whose priority (clamped into their class) is in the real-time band
/// may take at most `RT_BAND_CAP_PCT` of it: the band budget keeps the rest
/// for the tasks outside the band, so a band set denser than the cap would be
/// admitted only to be throttled past its deadlines. Halts like the density
/// check does; run-time admission (`azos_sched::rt::reserve`) applies the
/// same limit to every reservation made after boot.
fn band_admission(topo: &azos_topology::Topology<'static>, r: &azos_topology::deadline::Report) {
    let tasks = topo.tasks();
    let in_band = |ti: u16| {
        let Some(t) = tasks.get(ti as usize) else { return false };
        let Some(c) = topo.find_class(&t.class_name) else { return false };
        let (lo, hi) = c.priority_range;
        (t.priority.clamp(lo, hi.max(lo)) as u32) < azos_sched::RT_PRIORITY_THRESHOLD
    };
    let density = |ti: u16| tasks.get(ti as usize)
        .and_then(|t| azos_topology::deadline::profile_density(&t.profile))
        .unwrap_or(u32::MAX);
    let limit = (azos_limits::RT_BAND_CAP_PCT as u32).saturating_mul(10_000);
    if let Err(e) = r.band_check(in_band, density, limit) {
        azos_drv_sys::kerr!("[TOPO] Deadline admission REFUSED: {:?} — the band's rows on that CPU exceed \
                   RT_BAND_CAP_PCT={} % — halting", e, azos_limits::RT_BAND_CAP_PCT);
        loop { azos_arch::cpu::wfi(); }
    }
}

/// RFC-0049 M1b + P7, once, before the first ring-3 task: reserve the DMA
/// pool, then check that every ring-3 row's frame budget fits the RAM that is
/// left. Halts the board on either failure, as the deadline check does:
/// booting a topology whose budgets cannot all be honoured would turn a
/// declared guarantee into a race for the last frames.
///
/// The kernel reserve is Kconfig `MEM_KERNEL_RESERVE_KB` plus one vDSO page
/// per task slot (`azos_mm::vdso::task_page_claim` allocates one per slot
/// on first use and never frees it).
fn memory_admission(topo: &azos_topology::Topology<'static>) {
    // Everything below is in topology pages (4 KiB, `TOPOLOGY_PAGE`); the
    // allocator counts frames of PAGE_SIZE. At 4 KiB the two conversions are
    // the identity; under an aarch64 16/64 KiB granule they keep a signed
    // topology meaning the same bytes (`azos_topology::memory`'s doc).
    let page = azos_arch_api::PAGE_SIZE as u64;
    let floor = (azos_limits::DMA_POOL_FLOOR_KB as u64).div_ceil(4);
    let pool = topo.dma_pool_pages(floor);
    let free_before = azos_topology::units_for(azos_mm::pmm::free_pages() as u64, page);
    match azos_mm::pmm::reserve_dma_pool(azos_topology::frames_for(pool, page) as usize) {
        Ok(base) => kprintln!(
            "[MM] DMA pool: {} KiB reserved at {:#x} (floor {} KiB, {} pipeline(s) declare {} KiB)",
            pool * 4, base.as_usize(), floor * 4, topo.pipelines().len(),
            topo.pipelines().iter().map(|p| p.dma_pages as u64 * 4).sum::<u64>(),
        ),
        Err(_) => {
            azos_drv_sys::kerr!("[TOPO] Memory admission REFUSED: {:?} — halting",
                azos_topology::MemoryRefusal::DmaPool { need: pool, free: free_before });
            loop { azos_arch::cpu::wfi(); }
        }
    }
    let reserve = (azos_limits::MEM_KERNEL_RESERVE_KB as u64).div_ceil(4)
        + azos_topology::units_for(azos_limits::MAX_TASKS as u64, page);
    let free = azos_topology::units_for(azos_mm::pmm::free_pages() as u64, page);
    // Wave 9: only a row whose image can fork pays for a COW copy. The
    // image's seccomp profile decides (`seccomp::profile_can_fork`); the
    // generic `autorun` row and a row naming no shipped image are assumed to
    // fork, since any image may run under them.
    let may_fork = |t: &azos_topology::TaskSpec<'_>| -> bool {
        let name = t.name.as_bytes();
        if name == azos_topology::AUTORUN_ROW {
            return true;
        }
        azos_sched::seccomp::profile_named(name)
            .map_or(true, azos_sched::seccomp::profile_can_fork)
    };
    // Kconfig LOCKED_HUGE_LEAVES: a row that asks for a 2 MiB-leaf region on
    // a kernel built without the option is refused here, not run without
    // the region it was written for.
    if !azos_limits::LOCKED_HUGE_LEAVES {
        if let Some((i, t)) = topo.tasks().iter().enumerate().find(|(_, t)| t.mem_huge_mib != 0) {
            azos_drv_sys::kerr!("[TOPO] Memory admission REFUSED: row {} ({}) declares mem_huge_mib = {} but this kernel was built without LOCKED_HUGE_LEAVES — halting",
                i, t.name.as_str(), t.mem_huge_mib);
            loop { azos_arch::cpu::wfi(); }
        }
    }
    match topo.memory_admission(free, reserve, azos_topology::RING3_DEFAULT_PAGES, &may_fork) {
        Ok(r) => kprintln!(
            "[TOPO] Memory admission: {} ring-3 row(s) ({} locked, {} forking), {} instance(s): {} locked + {} ceiling + {} COW copy + {} kernel reserve = {} of {} free pages",
            r.rows, r.locked_rows, r.fork_rows, r.instances, r.locked_pages, r.ceiling_pages, r.cow_pages, r.reserve_pages, r.need, r.free,
        ),
        Err(e) => {
            azos_drv_sys::kerr!("[TOPO] Memory admission REFUSED: {:?} — halting", e);
            loop { azos_arch::cpu::wfi(); }
        }
    }
    if azos_limits::LOCKED_HUGE_LEAVES {
        reserve_huge_regions(topo);
    }
}

/// Kconfig LOCKED_HUGE_LEAVES: take each `mem_huge_mib` row's region out of
/// the allocator now, once — admission has just counted it as locked pages —
/// as one physically contiguous, 2 MiB-aligned run (`azos_mm::huge`).
/// Exec maps it with 2 MiB leaves. A region that cannot be reserved halts the
/// board like any other admission failure: the row was promised it.
fn reserve_huge_regions(topo: &azos_topology::Topology<'static>) {
    for (i, t) in topo.tasks().iter().enumerate() {
        if t.mem_huge_mib == 0 {
            continue;
        }
        let bytes = t.mem_huge_mib as usize * 1024 * 1024;
        match azos_mm::huge::reserve((i + 1) as u16, bytes) {
            Ok(pa) => kprintln!(
                "[MM] huge region: row {} ({}) {} MiB reserved at pa {:#x}, mapped with 2 MiB leaves at exec",
                i, t.name.as_str(), t.mem_huge_mib, pa,
            ),
            Err(e) => {
                azos_drv_sys::kerr!("[TOPO] Memory admission REFUSED: row {} ({}) huge region of {} MiB: {:?} — halting",
                    i, t.name.as_str(), t.mem_huge_mib, e);
                loop { azos_arch::cpu::wfi(); }
            }
        }
    }
}

/// `mem_start + mem_size` for display and for the W^X "outside the image"
/// sweep range — both ISAs' `kernel_main` compute this from `mem_size`
/// straight off a DTB `/memory` node, several times each (the "RAM
/// detected"/"RAM fallback" `kprintln!` arms, then again once each for the
/// two `strip_exec_outside_image`/`verify_no_exec_outside_image` calls).
/// A hostile `mem_size` (e.g. `usize::MAX`) can carry that raw addition
/// past `usize::MAX`; under this kernel's release profile
/// (`overflow-checks = true`, `panic = "abort"`) an unchecked `+` there is
/// an immediate, undiagnosed board reset — the same failure class DTB
/// audit closed on the parser side and `pmm::init` now refuses on the
/// `mem_start > kernel_end` side. Saturating instead of refusing here:
/// unlike `pmm::init`'s range, this one only feeds a log line and the W^X
/// sweep's upper bound, and `azos_mm::pmm::init` (called first, on
/// every path to this) is what already refuses to boot on a `mem_start`
/// it cannot trust — this helper just keeps the arithmetic that runs
/// after that decision from resetting the board on its own account.
#[inline]
pub(crate) fn mem_range_end(mem_start: usize, mem_size: usize) -> usize {
    mem_start.saturating_add(mem_size)
}
