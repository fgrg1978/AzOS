// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Memory admission and per-row frame budgets (RFC-0049 stage M1, owner
//! decisions rounds 13-14).
//!
//! # What a row's `mem_pages` means (P1)
//!
//! - `mem = "locked"`: a RESERVATION. Counted once, and it must be declared: a
//!   locked row without `mem_pages` is refused.
//! - otherwise: a CEILING. A ring-3 row that declares none takes the profile
//!   default (`RING3_MEM_PAGES_DEFAULT`), so no ring-3 row is unbounded.
//!
//! The budget covers every frame the task holds: image, stack, page tables,
//! heap, anonymous and demand pages, shared memory it created, its io_ring
//! pages. See `crates/core/sched/src/scheduler.rs` (`mm_charge`) for where each is
//! charged.
//!
//! # The unit: 4 KiB, whatever the base page
//!
//! A `mem_pages` page is 4 KiB ([`TOPOLOGY_PAGE`]) on every build, including
//! an aarch64 kernel built with a 16 or 64 KiB granule (config/Kconfig.arch).
//! A signed topology therefore means the same number of bytes on every ISA
//! and granule. The kernel converts at the allocator boundary — a budget of
//! `n` topology pages is `ceil(n × 4 KiB / PAGE_SIZE)` frames
//! ([`frames_for`]), and `f` free frames are `f × PAGE_SIZE / 4 KiB`
//! topology pages ([`units_for`]) — so a row is rounded up to whole frames,
//! and a task whose frames are only partly used (a 16 KiB stack page holding
//! 4 KiB of stack) pays for the whole frame. At 4 KiB both are the identity.
//!
//! # Copy-on-write (P3)
//!
//! A COW break is observed, not charged, at run time: an innocent break never
//! kills a task. The worst case is paid here instead. A row whose image may
//! fork is counted twice: its own pages plus a full private copy for one
//! child. Whether it may fork is the caller's answer (the kernel reads it from
//! the image's seccomp profile at boot); a locked row never forks.
//!
//! # Instances (wave 9)
//!
//! A row declares `instances = N` (default 1): N live instances, each with
//! the row's budget. Admission counts every one of them, and the kernel
//! enforces the count: the N+1th live spawned (or exec'd) instance of the row
//! is refused. Fork children are not instances (owner decision, wave 9): they
//! are bounded by the memory budget, and the COW copy counted above pays for
//! them.
//!
//! # The rule
//!
//! `Σ N × locked pages + Σ N × ceiling pages × (2 if it may fork, else 1)
//! + kernel reserve <= free pages`, over the ring-3 rows, with `free pages`
//! read from the page allocator after the kernel heap and the DMA pool are
//! taken. Kernel rows (`supervisor`, `brain_link`, ...) run on the kernel's
//! own mappings and hold no user frames; they are not counted. Pure
//! arithmetic, so `tests/host/topology-tests` pins it; the kernel calls it once,
//! before the first ring-3 task exists.
//!
//! # What it does not cover
//!
//! An image with no row of its own that is spawned runs under the profile
//! default and is not counted (nor limited in number). A fork child's own
//! COW breaks are not charged to it; the ×2 is the bound.

use crate::types::{TaskSpec, Topology};
use crate::AdmissionError;

/// The budget of a ring-3 row that declares no `mem_pages`, in pages: Kconfig
/// `RING3_MEM_PAGES_DEFAULT` for this build's profile.
pub const RING3_DEFAULT_PAGES: u32 = azos_limits::RING3_MEM_PAGES_DEFAULT as u32;

/// Bytes in one topology page (`mem_pages`, `dma_pages`, the admission
/// arithmetic): fixed at 4 KiB, independent of the base page. See the module
/// doc.
pub const TOPOLOGY_PAGE: u64 = 4096;

/// Frames of `page_size` bytes that hold `units` topology pages, rounded up.
/// `page_size` is a power of two `>= TOPOLOGY_PAGE`. Saturates rather than
/// wrapping (a budget is a ceiling, never a negative).
pub const fn frames_for(units: u64, page_size: u64) -> u64 {
    let per = page_size / TOPOLOGY_PAGE;
    units.saturating_add(per - 1) / per
}

/// Topology pages in `frames` frames of `page_size` bytes.
pub const fn units_for(frames: u64, page_size: u64) -> u64 {
    frames.saturating_mul(page_size / TOPOLOGY_PAGE)
}

/// The name of the generic row every autorun image without a row of its own
/// runs under.
pub const AUTORUN_ROW: &[u8] = b"autorun";

/// Why [`Topology::memory_admission`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryRefusal {
    /// The rows and the kernel reserve need more pages than are free.
    Overcommit {
        /// Pages the rows and the reserve need.
        need: u64,
        /// Pages the allocator has free.
        free: u64,
    },
    /// A `mem = "locked"` row declares no `mem_pages`. A reservation of
    /// "whatever the default is" is not a reservation anyone sized.
    LockedWithoutPages {
        /// Index of the row in [`Topology::tasks`].
        task: u16,
    },
    /// A row declares `mem_huge_mib` without `mem = "locked"`. The region is
    /// pinned for the task's life and never forked; only a locked row makes
    /// the same promise about the rest of the task.
    HugeWithoutLocked {
        /// Index of the row in [`Topology::tasks`].
        task: u16,
    },
    /// A row with `mem_huge_mib` declares more than one instance: the region
    /// is one boot-reserved block per row.
    HugeInstances {
        /// Index of the row in [`Topology::tasks`].
        task: u16,
    },
    /// The declared pipelines need a larger DMA pool than can be reserved.
    DmaPool {
        /// Pages the pool needs.
        need: u64,
        /// Pages free when the pool was reserved.
        free: u64,
    },
    /// Row `task` asks for a `mib` MiB 2 MiB-leaf region and the allocator
    /// has no free, 2 MiB-aligned contiguous run of that size.
    HugeRegion {
        /// Index of the row in the task table.
        task: u16,
        /// The region's size, from the row's `mem_huge_mib`.
        mib: u16,
    },
}

/// What admission counted, for the boot log.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MemReport {
    /// Ring-3 rows counted.
    pub rows: u32,
    /// Rows marked `mem = "locked"`.
    pub locked_rows: u32,
    /// Pages reserved by locked rows, their 2 MiB-leaf regions included.
    pub locked_pages: u64,
    /// Of `locked_pages`, those of `mem_huge_mib` regions (`N × 256`).
    pub huge_pages: u64,
    /// Pages of ceilings, once (without the COW copy).
    pub ceiling_pages: u64,
    /// Pages added for the one full COW copy each instance of a forking row
    /// may make.
    pub cow_pages: u64,
    /// Instances admitted, over all ring-3 rows (Σ N).
    pub instances: u32,
    /// Ring-3 rows counted twice because their image may fork.
    pub fork_rows: u32,
    /// The kernel reserve passed in.
    pub reserve_pages: u64,
    /// `locked_pages + ceiling_pages + cow_pages + reserve_pages`.
    pub need: u64,
    /// Free pages it was checked against.
    pub free: u64,
}

/// A row's budget as the kernel applies it to a running task.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RowMem<'a> {
    /// The row it came from.
    pub row: &'a [u8],
    /// Frame limit in pages (never 0 for a row that exists: an undeclared
    /// budget is the profile default).
    pub limit: u32,
    /// `mem = "locked"`.
    pub locked: bool,
    /// Index of the row in [`Topology::tasks`]: what the kernel keys its
    /// live-instance counts on.
    pub index: u16,
    /// [`TaskSpec::instance_count`] of the row.
    pub instances: u16,
    /// [`TaskSpec::mem_huge_mib`] of the row.
    pub huge_mib: u16,
}

impl TaskSpec<'_> {
    /// Does this row describe a ring-3 program?
    ///
    /// The convention the loaders already follow: a program's row is named
    /// after its IMAGE (`SYS_SPAWN`'s `topology_key = profile.image`, the
    /// autorun loader's `resolve_image`), which is a FAT 8.3 name ending in
    /// `.ELF`; images without a row of their own run under `autorun`. Every
    /// other row names a kernel task.
    pub fn is_ring3(&self) -> bool {
        let n = self.name.as_bytes();
        n == AUTORUN_ROW || (n.len() > 4 && n[n.len() - 4..].eq_ignore_ascii_case(b".ELF"))
    }

    /// The pages this row's budget is, with `default_pages` for a ceiling row
    /// that declares none. `None` for a locked row without `mem_pages`.
    pub fn budget_pages(&self, default_pages: u32) -> Option<u32> {
        match (self.mem_pages, self.mem_locked) {
            (0, true) => None,
            (0, false) => Some(default_pages),
            (n, _) => Some(n),
        }
    }
}

impl<'a> Topology<'a> {
    /// RFC-0049 M1: can every instance of every ring-3 row hold what it
    /// declares, at once, with `reserve_pages` left for the kernel's own
    /// dynamic consumers?
    ///
    /// `free_pages` is the allocator's free count at the moment of the check;
    /// `default_pages` the budget of a ceiling row that declares none;
    /// `may_fork` answers, per row, whether its image can fork (the kernel
    /// derives it from the image's seccomp profile). A locked row is never
    /// counted twice, whatever `may_fork` says: a locked task cannot fork.
    pub fn memory_admission(
        &self,
        free_pages: u64,
        reserve_pages: u64,
        default_pages: u32,
        may_fork: &dyn Fn(&TaskSpec<'_>) -> bool,
    ) -> Result<MemReport, AdmissionError> {
        let mut r = MemReport { reserve_pages, free: free_pages, ..MemReport::default() };
        for (i, t) in self.tasks().iter().enumerate() {
            if !t.is_ring3() {
                continue;
            }
            let n = t.instance_count() as u64;
            let pages = t
                .budget_pages(default_pages)
                .ok_or(AdmissionError::Memory(MemoryRefusal::LockedWithoutPages { task: i as u16 }))?
                as u64
                * n;
            r.rows += 1;
            r.instances += n as u32;
            if t.mem_huge_mib != 0 {
                if !t.mem_locked {
                    return Err(AdmissionError::Memory(MemoryRefusal::HugeWithoutLocked { task: i as u16 }));
                }
                if n != 1 {
                    return Err(AdmissionError::Memory(MemoryRefusal::HugeInstances { task: i as u16 }));
                }
                let huge = t.mem_huge_mib as u64 * (1024 * 1024 / TOPOLOGY_PAGE);
                r.huge_pages += huge;
                r.locked_pages += huge;
            }
            if t.mem_locked {
                r.locked_rows += 1;
                r.locked_pages += pages;
            } else {
                r.ceiling_pages += pages;
                if may_fork(t) {
                    r.fork_rows += 1;
                    r.cow_pages += pages;
                }
            }
        }
        r.need = r.locked_pages + r.ceiling_pages + r.cow_pages + r.reserve_pages;
        if r.need > free_pages {
            return Err(AdmissionError::Memory(MemoryRefusal::Overcommit { need: r.need, free: free_pages }));
        }
        Ok(r)
    }

    /// The DMA pool to reserve at boot, in pages: the larger of the pipelines'
    /// sum and `floor_pages` (Kconfig `DMA_POOL_FLOOR_KB`).
    pub fn dma_pool_pages(&self, floor_pages: u64) -> u64 {
        let declared: u64 = self.pipelines().iter().map(|p| p.dma_pages as u64).sum();
        declared.max(floor_pages)
    }

    /// The budget of the row named `name`, else of `fallback`'s row, else
    /// `None` (no such row). Same lookup order as the scheduling row
    /// (`azos_syscall::topo_sched::resolve_image`), so a program's
    /// class, priority and memory come from one row.
    ///
    /// A locked row without pages resolves to `limit: 0`; admission refuses
    /// such a topology before any task runs, so an installed one never has it.
    pub fn row_mem(&self, name: &[u8], fallback: Option<&[u8]>, default_pages: u32) -> Option<RowMem<'a>> {
        let find = |n: &[u8]| self.tasks().iter().position(|t| t.name.as_bytes() == n);
        let i = find(name).or_else(|| fallback.and_then(find))?;
        let t = self.tasks()[i];
        Some(RowMem {
            row: t.name.as_bytes(),
            limit: t.budget_pages(default_pages).unwrap_or(0),
            locked: t.mem_locked,
            index: i as u16,
            instances: t.instance_count(),
            huge_mib: t.mem_huge_mib,
        })
    }
}
