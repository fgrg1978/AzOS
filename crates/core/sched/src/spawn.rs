// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Creating a process from an ELF image for `SYS_SPAWN` (RFC-0043): load the
//! image into a fresh address space, create the child task under the image's
//! seccomp filter, and release it once its capabilities are in place.
//!
//! Two calls, because the capabilities are minted between them and this crate
//! cannot mint them: `azos_ipc` depends on `azos_sched`. The handler
//! (`crates/core/syscall/src/spawn.rs`) calls [`spawn_prepare`], seeds the child's
//! capability table by its TID, then calls [`spawn_release`].
//!
//! # The child runs no user instruction before it is released
//!
//! The task starts in [`fork_child_entry`], a kernel loop that yields until a
//! hand-off is published on its own slot (`scheduler::set_task_fork_ctx`) and
//! only then SRETs to user mode. [`spawn_release`] is that publication. Until
//! then the child is a kernel task parked in that loop, so no user code can
//! observe a capability table that is still being filled.
//!
//! # The filter is in place before the task is runnable
//!
//! It goes in through [`TaskInit`], under the same `POOL_LOCK` section that
//! fills the rest of the slot and before the enqueue publishes it. Fork writes
//! its child's filter after creation (`sys_fork_impl`); that is harmless there
//! only because its child also waits for its hand-off.

use crate::filter::{SyscallFilter, TaskInit};
use crate::process::{fork_child_entry, load_elf};
use azos_mm::vmm;

/// A child created by [`spawn_prepare`] that has not run any user code.
///
/// Consumed by [`spawn_release`]. Dropped without it, the child stays parked
/// in [`fork_child_entry`] for good.
#[must_use = "the child stays parked until `spawn_release` publishes its hand-off"]
pub struct SpawnPrepared {
    idx: usize,
    tid: u32,
    entry: u64,
    user_sp: u64,
    satp: u64,
    /// The child's page-table root, for [`SpawnPrepared::write_startup`].
    user_pt: usize,
    /// RFC-0055: the startup block's user address, handed over in `a1`
    /// (`x1`); 0 = none.
    startup: u64,
    /// RFC-0047: what the auxiliary vector of a Linux image reports, read
    /// from the image's headers by [`spawn_prepare`].
    aux: azos_linux_abi::ImageAux,
    /// The initial break [`spawn_prepare`]'s load set (wave 14, SPAWNCACHE:
    /// kept with the image's frames for its next spawn).
    brk: u64,
    /// RFC-0047: the child runs under the Linux personality
    /// ([`SpawnPrepared::set_linux`]).
    linux: bool,
    /// RFC-0047: [`SpawnPrepared::write_linux_stack`] has laid out the
    /// initial stack.
    linux_stack: bool,
}

impl SpawnPrepared {
    /// The child's TID: what the capabilities are seeded under and what
    /// `SYS_SPAWN` returns.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// RFC-0055 (`SYS_SPAWN_EX`): write a startup block at the top of the
    /// child's stack and hand its address to the child in `a1` (`x1`) — `a0`
    /// is zeroed by the hand-off, as a fork's is. `fill(base, buf)` lays the
    /// block out in `buf` for user address `base` and returns the bytes used.
    /// The stack pointer moves below the block, 16-byte aligned. `false`
    /// (nothing written) when the block does not fit `max` bytes or the
    /// stack pages are not mapped yet (a demand-paged stack under
    /// `mem-locked-canary`).
    pub fn write_startup(
        &mut self,
        max: usize,
        fill: &mut dyn FnMut(u64, &mut [u8]) -> Option<usize>,
    ) -> bool {
        // A block, 1 KiB of argv, 1 KiB of environment, a 64-byte working
        // directory and alignment: the most `SYS_SPAWN_EX` lays out. Kept to
        // that, not a page, because it sits on the syscall's kernel stack
        // under the request's own copies.
        const MAX: usize = 2304;
        if max > MAX {
            return false;
        }
        let mut buf = [0u8; MAX];
        let base = (crate::process::USER_STACK_TOP as u64 - 16 - max as u64) & !15;
        let Some(n) = fill(base, &mut buf[..max]) else { return false };
        let mut done = 0usize;
        while done < n {
            let va = base as usize + done;
            let Some(pa) = vmm::translate(self.user_pt, va) else { return false };
            let in_page = azos_arch::mmu::PAGE_SIZE - (va & (azos_arch::mmu::PAGE_SIZE - 1));
            let chunk = in_page.min(n - done);
            // SAFETY: `pa` is a frame of the child's eagerly mapped stack,
            // reached through the kernel's own mapping of it; the child has
            // run no instruction yet, so nothing else writes it.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf[done..].as_ptr(),
                    azos_mm::addr::phys_to_virt(pa) as *mut u8,
                    chunk,
                );
            }
            done += chunk;
        }
        self.startup = base;
        self.user_sp = (base - 16) & !15;
        true
    }
}

impl SpawnPrepared {
    /// Is the child a Linux task (created with `linux` by
    /// [`spawn_prepare`])?
    pub fn is_linux(&self) -> bool {
        self.linux
    }

    /// Has the initial stack of a Linux child been written?
    pub fn linux_stack_written(&self) -> bool {
        self.linux_stack
    }

    /// RFC-0047: lay out the initial stack a static Linux binary's `_start`
    /// reads (`azos_linux_abi::layout_initial_stack`: argc, argv, envp,
    /// the auxiliary vector, `AT_RANDOM`'s 16 bytes) at the top of the
    /// child's stack, and start the child with `sp` at `argc` and `a0`/`a1`
    /// zero. `argv`/`env` are NUL-terminated strings, `argc`/`envc` of them.
    /// `false` (nothing written) when they do not fit or the stack pages are
    /// not mapped.
    pub fn write_linux_stack(
        &mut self,
        argv: &[u8],
        argc: usize,
        env: &[u8],
        envc: usize,
        random: &[u8; 16],
    ) -> bool {
        // 1 KiB of argv and 1 KiB of environment (the `SYS_SPAWN_EX`
        // limits), 16 random bytes, and the pointer block: at most 16 + 16
        // pointers, three words and 17 auxiliary pairs. On the syscall's
        // kernel stack, as `write_startup`'s buffer is.
        let Some(sp) = write_linux_stack_into(self.user_pt, &self.aux, argv, argc, env, envc, random) else {
            return false;
        };
        self.startup = 0;
        self.user_sp = sp;
        self.linux_stack = true;
        true
    }
}

/// Lay out a Linux initial stack (argc, argv, envp, auxv, `AT_RANDOM`) at the
/// top of the stack of the address space `user_pt`, which no task runs on yet
/// (a spawn's child before release, or an `execve`'s new image before the
/// switch). The stack pointer, or `None` when it does not fit or the stack
/// pages are not mapped.
pub fn write_linux_stack_into(
    user_pt: usize,
    aux: &azos_linux_abi::ImageAux,
    argv: &[u8],
    argc: usize,
    env: &[u8],
    envc: usize,
    random: &[u8; 16],
) -> Option<u64> {
    // 2 KiB of strings, 16 random bytes, and the pointer block: at most
    // 32 + 32 pointers, three words and 17 auxiliary pairs. On the calling
    // syscall's kernel stack.
    const MAX: usize = 2048 + 1024;
    let mut buf = [0u8; MAX];
    let base = (crate::process::USER_STACK_TOP as u64 - 16 - MAX as u64) & !15;
    let sp = azos_linux_abi::layout_initial_stack(&mut buf, base, argv, argc, env, envc, random, aux)?;
    let mut done = (sp - base) as usize;
    while done < MAX {
        let va = base as usize + done;
        let pa = vmm::translate(user_pt, va)?;
        let in_page = azos_arch::mmu::PAGE_SIZE - (va & (azos_arch::mmu::PAGE_SIZE - 1));
        let chunk = in_page.min(MAX - done);
        // SAFETY: a frame of the eagerly mapped stack of an address space no
        // task runs on yet, reached through the kernel's own mapping of RAM.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf[done..].as_ptr(),
                azos_mm::addr::phys_to_virt(pa) as *mut u8,
                chunk,
            );
        }
        done += chunk;
    }
    Some(sp)
}

/// Release `child` so that it ends before running a user instruction, with
/// exit code `128 + 9`: a spawn that failed after the child existed
/// (RFC-0055, the move list). It goes through the normal exit path, so
/// whatever it was given is released.
pub fn spawn_abort(child: SpawnPrepared) -> bool {
    crate::scheduler::task_stop(child.tid, true, 9);
    spawn_release(child)
}

/// The image [`spawn_prepare`] loads: the whole file in memory, or (RFC-0047
/// stage 3, an image larger than the exec bounce buffer) its header bytes
/// and a filler that copies the segments in and returns whether the bytes it
/// copied hash to the digest the spawn was planned by.
pub enum ElfImage<'a> {
    /// The whole image.
    Bytes(&'a [u8]),
    /// `hdr`: the ELF and program headers; `len`: the file's length;
    /// `fill(user_pt)`: copies the segments in ([`crate::process::fill_elf_segments`])
    /// and checks the digest.
    Streamed { hdr: &'a [u8], len: usize, fill: &'a mut dyn FnMut(usize) -> bool },
    /// Wave 14 (SPAWNCACHE): an image the verified-image cache kept from an
    /// earlier spawn of the same bytes ([`capture_image`]): its frames, and
    /// the entry, break and auxiliary values that load produced.
    Cached { pages: &'a azos_mm::image_frames::ImagePages, kept: KeptImage },
}

pub use azos_mm::image_frames::KeptImage;

/// The auxiliary values a [`KeptImage`] carries, as the loader reports them.
pub(crate) fn kept_aux(kept: &KeptImage) -> azos_linux_abi::ImageAux {
    let a = kept.aux;
    azos_linux_abi::ImageAux { phdr: a[0], phent: a[1], phnum: a[2], entry: a[3], pagesz: a[4] }
}

/// Wave 14 (SPAWNCACHE): keep the image `child` was just loaded from — its
/// executable frames by reference, its other pages as copies — for the next
/// spawn of the same bytes (`azos_mm::image_frames`). Called after
/// [`spawn_prepare`] and before anything writes into the child (its startup
/// block, its stack): the pages are still exactly what the loader made of
/// the verified bytes. `hdr` is the image's headers. `None` when the image
/// cannot be kept (see `image_frames::capture`) or needs more than
/// `max_frames` frames.
pub fn capture_image(
    child: &SpawnPrepared,
    hdr: &[u8],
    max_frames: u32,
) -> Option<(azos_mm::image_frames::ImagePages, KeptImage)> {
    let (lo, hi) = crate::process::image_page_range(hdr)?;
    let pages = azos_mm::image_frames::capture(child.user_pt, lo, hi, max_frames)?;
    let a = child.aux;
    Some((pages, KeptImage {
        entry: child.entry, brk: child.brk, aux: [a.phdr, a.phent, a.phnum, a.entry, a.pagesz],
    }))
}

/// Why [`spawn_prepare`] created no child. Nothing it allocated is left behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpawnError {
    /// `load_elf` refused the image or could not build its address space.
    BadImage,
    /// The task pool is full.
    NoTask,
    /// RFC-0049 M1: the image's address space exceeds its row's budget.
    OverBudget,
    /// RFC-0049 M1, wave 9: the image's row already has `instances` live
    /// spawned instances.
    Instances,
}

/// Load `elf` into a new address space and create its task, parked, under
/// `filter`, with the current task as its parent. `name` is the task's name.
///
/// `sched` is the child's `(priority, class_raw)`: its topology row's when it
/// has one (wave 7, resolved by the caller), `None` for the scheduler's
/// default (`DEFAULT_PRIORITY`, `DEFAULT_SCHED_CLASS_RAW`).
///
/// Every failure after the address space exists destroys it with
/// `vmm::destroy_user_pagetable`, the teardown for a page table no task has
/// published (fork's failure exits use the same one). `load_elf` tears down
/// its own on its failures. The ASID `load_elf` took is not returned:
/// `alloc_asid` is a counter with no release.
pub fn spawn_prepare(
    elf: ElfImage<'_>,
    filter: SyscallFilter,
    name: &str,
    sched: Option<(u32, u8)>,
    mem: crate::process::MemSpec,
    linux: bool,
) -> Result<SpawnPrepared, SpawnError> {
    // RFC-0047: without the personality a Linux child cannot be made.
    if linux && !azos_limits::LINUX_ABI {
        return Err(SpawnError::BadImage);
    }
    // Kconfig LOCKED_HUGE_LEAVES: a row's 2 MiB-leaf region is installed by
    // exec, on the task that will own it (its window reservation is that
    // task's). Spawning such a row would start it without the region it was
    // admitted with, so it is refused.
    if mem.huge_mib != 0 {
        azos_drv_sys::kwarn!(
            "[MEM] spawn REFUSED: {} -- its row has a 2 MiB-leaf region, which only exec installs",
            name,
        );
        return Err(SpawnError::BadImage);
    }
    // The auxiliary values are read from the headers `load_elf` accepted;
    // unused unless the row makes the child a Linux task.
    let aux_of = |hdr: &[u8]| {
        azos_linux_abi::image_aux(hdr, azos_arch::mmu::PAGE_SIZE as u64).unwrap_or_default()
    };
    let (ctx, aux) = match elf {
        ElfImage::Bytes(b) => (load_elf(b).ok_or(SpawnError::BadImage)?, aux_of(b)),
        ElfImage::Streamed { hdr, len, fill } => {
            let ctx = crate::process::load_elf_hdr(hdr, len).ok_or(SpawnError::BadImage)?;
            if !fill(ctx.user_pt as usize) {
                vmm::destroy_user_pagetable(ctx.user_pt as usize);
                return Err(SpawnError::BadImage);
            }
            crate::process::sync_loaded_text(&ctx, hdr);
            (ctx, aux_of(hdr))
        }
        ElfImage::Cached { pages, kept } => (
            crate::process::load_elf_cached(pages, kept.entry, kept.brk).ok_or(SpawnError::BadImage)?,
            kept_aux(&kept),
        ),
    };
    let user_pt = ctx.user_pt as usize;
    // RFC-0049 M1: an image that does not fit its row's budget is refused
    // before any task exists for it.
    if mem.limit != 0 && ctx.frames > mem.limit {
        azos_drv_sys::kwarn!(
            "[MEM] spawn REFUSED: {} needs {} pages, its budget is {}",
            name, ctx.frames, mem.limit,
        );
        crate::scheduler::note_mm_quota_refusal();
        vmm::destroy_user_pagetable(user_pt);
        return Err(SpawnError::OverBudget);
    }

    // Wave 9: the child is one of its row's live instances, refused past the
    // row's `instances` before any task exists for it. Given back on the
    // failure exits below; from `set_task_mem_row` on, the child's exit
    // gives it back.
    if !crate::scheduler::row_claim(mem.row, mem.instances) {
        let live = crate::scheduler::row_live(mem.row);
        let n = crate::scheduler::note_mm_instance_refusal();
        azos_drv_sys::kwarn!(
            "[MEM] spawn REFUSED: {} -- its row already has {} of {} live instance(s) (instance refusals: {})",
            name, live, mem.instances, n,
        );
        vmm::destroy_user_pagetable(user_pt);
        return Err(SpawnError::Instances);
    }

    let (priority, class_raw) = match sched {
        Some((p, c)) => (p, Some(c)),
        None => (crate::DEFAULT_PRIORITY, None),
    };
    let init = TaskInit {
        syscall_filter: Some(filter),
        class_raw,
        // Set with the slot, under the exit-notice admission (wave 12).
        parent: crate::current_task_tid(),
        abi: if linux { crate::task::ABI_LINUX } else { crate::task::ABI_NATIVE },
        ..TaskInit::default()
    };
    // Fallible creation: `SYS_SPAWN` is reachable from ring 3 in a loop, and
    // `task_create` panics on a full pool (K-A13).
    let idx = match crate::try_task_create_init(
        name, fork_child_entry, 0, priority, -1, init,
    ) {
        Some(idx) => idx,
        None => {
            vmm::destroy_user_pagetable(user_pt);
            crate::scheduler::row_release(mem.row);
            return Err(SpawnError::NoTask);
        }
    };
    // The child cannot have exited: `fork_child_entry` does not return before
    // it consumes a hand-off, and none is published yet.
    let tid = match crate::tid_for_idx(idx) {
        Some(tid) => tid,
        None => {
            vmm::destroy_user_pagetable(user_pt);
            crate::scheduler::row_release(mem.row);
            return Err(SpawnError::NoTask);
        }
    };

    // From here the page table is published on the child's slot: the child's
    // exit path owns its teardown (K-C22(C)), and the reuse-time reclaim in
    // `try_task_create_init` if the child was already past that point.
    crate::scheduler::set_task_user_info(idx, ctx.satp, ctx.user_pt, ctx.brk);
    // Checked against `mem.limit` above, so this cannot refuse.
    let _ = crate::scheduler::set_task_mem(idx, mem.limit, mem.locked, ctx.frames);
    crate::scheduler::set_task_mem_row(idx, mem.row);

    Ok(SpawnPrepared {
        idx,
        tid,
        entry: ctx.entry,
        user_sp: ctx.user_sp,
        satp: ctx.satp,
        user_pt,
        startup: 0,
        aux,
        brk: ctx.brk,
        linux,
        linux_stack: false,
    })
}

/// Publish the child's hand-off: it SRETs to the image's entry point with its
/// own stack pointer and every other register zero (`a0` too, which
/// `sret_to_user_forked` forces).
///
/// `false` when the slot no longer belongs to the child. Its page table is not
/// destroyed then, for the reason `sys_fork_impl` gives at the same step: it
/// was published on the slot: the child's exit or the reuse-time reclaim frees it.
pub fn spawn_release(child: SpawnPrepared) -> bool {
    let mut regs = crate::task::UserRegs::default();
    // ISA-shaped: riscv64 (and the host-build fallback, same shape) carries
    // `sp` as `x2` inside the `[u64; 32]` array; aarch64 banks EL0's SP
    // separately as `SP_EL0` (`ForkRegs::sp_el0`, see that struct's module
    // doc) — it is not one of the 31 GPRs `regs.gpr` holds. Everything else
    // stays zero: a fresh spawn is not a fork, so there is no parent state
    // to replay, only the entry PC and this one stack pointer.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    { regs.sp_el0 = child.user_sp; regs.gpr[1] = child.startup; }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    { regs[2] = child.user_sp; regs[11] = child.startup; }
    crate::scheduler::set_task_fork_ctx(
        child.idx, child.tid, child.entry, child.user_sp, child.satp, &regs,
    )
}
