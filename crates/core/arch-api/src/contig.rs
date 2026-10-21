// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Contiguous runs of level-0 leaves: the aarch64 contiguous hint and the
//! riscv64 Svnapot 64 KiB leaf, planned ISA-neutrally.
//!
//! A run is [`Mmu::contig_run_pages`](crate::Mmu::contig_run_pages) leaves, the
//! first at a virtual address AND a physical address aligned to the run's size,
//! the frames consecutive, every word one set of attributes. The hardware may
//! cache the whole run as one TLB entry; that is the gain, and also the rule
//! that makes a run a unit: one member changed alone and the TLB may still
//! translate the old state through the others. Everything that changes a
//! member (unmap, mprotect) breaks the run first (`vmm::break_contig_run`).
//!
//! x86_64 has no counterpart below a 2 MiB leaf (PS at level 1: a different
//! level, a locked row's region or a promoted block, not a run of 4 KiB
//! leaves); its `contig_run_pages` stays 0 and `vmm::map_contig_range` maps
//! page by page.
//!
//! This file is the arithmetic only (no page table), so the host suite links
//! the real code (`tests/host/mm-tests/src/pgsz.rs`).

/// Kconfig `A64_CONTIG_HINT`: the aarch64 port writes the contiguous hint.
/// (The riscv64 switch is the Svnapot probe, `ext::napot::select`.)
pub const A64_HINT: bool = azos_limits::A64_CONTIG_HINT;

/// The most pages any ISA's run spans (aarch64 at a 16 KiB granule: 128): the
/// size of the scratch a break keeps its parked words in.
pub const MAX_RUN_PAGES: usize = 128;

/// Is the run of `run_pages` pages that starts at `va` and whose frames are
/// `phys[..run_pages]` mappable as one run? Both `va` and `phys[0]` aligned to
/// the run's size, the frames consecutive. `false` when `run_pages < 2`
/// (the ISA has no run) or `phys` holds fewer than `run_pages` frames.
pub fn is_run(page_size: usize, run_pages: usize, va: usize, phys: &[usize]) -> bool {
    if run_pages < 2 || phys.len() < run_pages {
        return false;
    }
    let bytes = run_pages * page_size;
    if va & (bytes - 1) != 0 || phys[0] & (bytes - 1) != 0 {
        return false;
    }
    phys[..run_pages].windows(2).all(|w| w[1] == w[0] + page_size)
}

/// How many pages the next mapping step of `phys` at `va` covers: `run_pages`
/// when [`is_run`], else 1.
pub fn step_pages(page_size: usize, run_pages: usize, va: usize, phys: &[usize]) -> usize {
    if is_run(page_size, run_pages, va, phys) { run_pages } else { 1 }
}
