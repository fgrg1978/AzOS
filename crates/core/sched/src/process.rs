// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Process management: ELF loader, exec, SRET to U-mode.
// Phase 7 — enables kernel to launch RISC-V 64-bit ELF user programs.

use azos_arch::{ArchPlatform, ARCH};
use azos_arch::PAGE_SIZE;
use azos_arch_api::PagePerms;

/// O3.2 (owner decision, PAN/SUM): one name for the RAII "I am about to
/// touch user-tagged memory on purpose" guard on either ISA —
/// `arch-aarch64::sysregs::UserAccess` (`msr PAN, #0/#1`) or
/// `arch-riscv64::csr::UserAccess` (`csrs`/`csrc sstatus.SUM`). Construct
/// it immediately before, and let it drop immediately after, the ONE
/// access that legitimately reaches user-tagged memory in each of this
/// module's copy_* routines — see [`copy_from_user`]'s own doc for why
/// today's access (`phys_to_virt`) does not actually NEED it, and why the
/// guard is placed here anyway.

/// Encode the address-space-activation value this crate's `satp`/`task_satp`
/// fields carry: the ISA's user-root word (`ArchPlatform::user_root_word`).
/// riscv64: a real Sv39 `satp` word (MODE|ASID|PPN), later written by
/// `context_switch.S`'s `csrw satp`. aarch64: the bare `TTBR0_EL1` table PA,
/// `0` meaning "keep the kernel's own table"; the ASID is unused because the
/// kernel flushes on every address-space switch.
#[inline]
fn make_satp(root_pt_phys: usize, asid: u16) -> usize {
    ARCH.user_root_word(root_pt_phys, asid)
}
use azos_mm::{pmm, vmm, vdso};
use azos_common::error::KernelError;

// ── User-space memory layout ──────────────────────────────────────────────────

use azos_limits::USER_STACK_SIZE_BYTES as USER_STACK_SIZE;
use azos_drv_base::platform::hw::RAM_BASE;

// Kconfig allows any KiB value in 4..=1024. A size that is not a whole number
// of pages makes `USER_STACK_TOP - USER_STACK_SIZE` unaligned, `vmm::map`
// answers `NotAligned` for the first stack page, and every exec fails at run
// time. Refuse the build instead.
const _: () = assert!(USER_STACK_SIZE % PAGE_SIZE == 0, "USER_STACK_SIZE_KB must be a multiple of 4");

/// Top of user virtual stack, and the ceiling of the *entire* user address
/// space (mirrored as `USER_VA_TOP` in `crates/core/syscall/src/handlers.rs` via
/// `azos_sched::process::USER_STACK_TOP` — one definition now, not two
/// hand-kept-in-sync literals; see that file's former comment on the
/// duplication this replaces).
///
/// Derived from the platform's own [`RAM_BASE`], not hardcoded to `0x8000_0000`.
/// Why the derivation must exist at all: `vmm::init` identity-maps physical
/// RAM starting at `RAM_BASE` with 2 MiB megapages, so every VA at or above
/// `RAM_BASE` is a kernel-owned megapage the moment the board has enough RAM
/// to reach it. `USER_STACK_TOP` used to be the literal `0x8000_0000`, which
/// is exactly QEMU's `RAM_BASE` — the two have always had to be the same
/// number, they were just never written as the same *expression*. On the VF2
/// (`RAM_BASE = 0x4000_0000`), the literal put the user stack and the whole
/// MMIO/shm window (`USER_MMIO_BASE = 0x6000_0000`) *inside* VPN[2]=1, which
/// is entirely kernel RAM there on any board with >=1 GiB installed (VF2
/// ships with 2/4/8 GiB) — so `vmm::kernel_entry_collision` refused every
/// `exec`, unconditionally, on real VF2 hardware. Deriving from `RAM_BASE`
/// reproduces today's QEMU value exactly (no behaviour change there) and
/// gives VF2 a ceiling that sits below its own RAM instead of inside it.
///
/// K1 (`RAM_BASE == 0`) cannot be solved by any value of this constant: RAM
/// starting at VA 0 means the kernel's identity map already owns everything
/// from 0 upward, so there is no positive ceiling that keeps the user AS out
/// of kernel RAM — the image itself (linked at `0x1_0000`) is already inside
/// it. That is a pre-existing, already-documented condition (see
/// [`vmm::kernel_entry_collision`]'s own doc comment on the K1 case) that
/// needs relocating the user image, not a ceiling constant, so K1 keeps the
/// historical `0x8000_0000` value below rather than folding to 0: it does not
/// fix K1, but it also does not make an already-broken board fail in a new
/// way (a 0-sized address space instead of a merge collision).
pub const USER_STACK_TOP: usize = if RAM_BASE == 0 { 0x8000_0000 } else { RAM_BASE };

// The whole point of deriving the constant above: it must never claim more
// VA than the platform actually reserves for the kernel's identity map.
// Every board except K1 (handled by the special case in the definition
// itself, and asserted separately in `vmm.rs`'s own K1 note) must satisfy
// this trivially, by construction — this assertion exists to catch a future
// edit that reintroduces a literal here, not because the `if` above can fail.
const _: () = assert!(RAM_BASE == 0 || USER_STACK_TOP <= RAM_BASE);

/// Whether the vDSO page (`vdso::VDSO_USER_BASE`, defined in
/// `crates/core/abi/src/vdso.rs` and re-exported from `crates/core/mm/src/vdso.rs` —
/// ring 3 also reads it directly, via `crates/core/libsys/src/lib.rs`; none of
/// those three files is owned here) has room below [`USER_STACK_TOP`] on the
/// board this binary is built for.
///
/// `VDSO_USER_BASE` is a fixed address, untouched by the derivation above.
/// As of the 2026-09-22 fix (`VDSO_USER_BASE = 0x2000_0000`, VPN[2]=0 on
/// every board) this is true everywhere `USER_STACK_TOP` is derived from
/// `RAM_BASE` — every board's `RAM_BASE` is at least `0x4000_0000` — so the
/// flag is now a defence-in-depth check rather than a live skip: kept
/// rather than removed, because it is the one runtime guard that would
/// still catch a future board whose `RAM_BASE` drops below the vDSO's own
/// ceiling. Before the fix, `0x5000_0000` sat inside VPN[2]=1 — the slot
/// VF2's and aarch64's own RAM identity maps claim — and this flag was the
/// only thing standing between that collision and a corrupted kernel page
/// table; see `crates/core/abi/src/vdso.rs`'s module doc for the full mechanism
/// and `crates/drivers/base/src/platform.rs`'s per-board `const` asserts for the
/// compile-time proof that replaced relying on this flag alone.
const VDSO_FITS_BELOW_USER_CEILING: bool =
    vdso::VDSO_USER_BASE + PAGE_SIZE <= USER_STACK_TOP;

// ── ELF constants ─────────────────────────────────────────────────────────────

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;
use elf_bounds::{PF_W, PF_X};

/// Ceiling for everything userspace places in the low VA region: the loaded
/// image and the `brk` heap.
///
/// Every user page table carries the kernel's own mappings, merged in by
/// [`vmm::copy_kernel_entries_to_user`] at VPN[1] granularity for VPN[2]=0.
/// The lowest address the kernel identity-maps on the RV64 boards this OS
/// targets is the CLINT at `0x0200_0000`; PLIC (`0x0C00_0000`), UART
/// (`0x1000_0000`) and the rest sit above it, and RAM is at `0x8000_0000`.
/// Keeping the image and the heap strictly below the CLINT means user VPN[1]
/// slots (0..=15) and kernel VPN[1] slots (16, 96, 128, …) never collide, so
/// the merge never has to choose between a user mapping and a kernel one.
///
/// It also keeps the image clear of the two other things that live in a user
/// address space — the vDSO at `vdso::VDSO_USER_BASE` (`0x2000_0000` as of
/// 2026-09-22; `crates/core/abi/src/vdso.rs`) and the stack just below
/// `USER_STACK_TOP` — whose overlap was previously swallowed by an ignored
/// `vmm::map` result.
///
/// [`vmm::kernel_entry_collision`] is the platform-independent backstop for
/// this constant: if some board maps something lower, exec fails loudly
/// instead of silently losing a kernel mapping.
const USER_LOW_MAX: usize = 0x0200_0000; // 32 MiB — CLINT base

/// Pure `PT_LOAD` bounds checks, in their own file only so the host test
/// runner (`tests/host/sched-wake-tests`) can compile them — the rest of this
/// module cannot leave the target. Declared here rather than in `lib.rs` to
/// keep it plainly a part of the loader.
#[path = "elf_bounds.rs"]
pub mod elf_bounds;

/// The address limits `elf_bounds` enforces, taken from their real
/// definitions. This is the only place they are named together; `elf_bounds`
/// declares none of them itself, so there is nothing to drift.
#[inline]
const fn seg_limits() -> elf_bounds::SegLimits {
    elf_bounds::SegLimits {
        guard_limit: vmm::USER_GUARD_LIMIT,
        low_max: USER_LOW_MAX,
        page_size: PAGE_SIZE,
    }
}

// ── ExecContext ────────────────────────────────────────────────────────────────

/// Loader output: everything `exec_user` needs to install the new address
/// space on the current task. Internal to the loader — the hand-off to the
/// consumption sites travels on the task's own `exec_*` fields (K-C21) and
/// comes back out as an [`ExecHandoff`].
pub struct ExecContext {
    pub satp:    u64, // new user SATP
    pub entry:   u64, // ELF entry point virtual address
    pub user_sp: u64, // user stack pointer (aligned)
    pub sstatus: u64, // SSTATUS to restore: SPP=0, SPIE=1
    pub user_pt: u64, // physical address of user page table
    pub brk:     u64, // initial brk (= end of last loaded segment, page-aligned)
    /// RFC-0049 M1: frames this address space holds when it is handed over —
    /// image pages, stack pages, the root and every page table under it. The
    /// task that receives it is charged exactly this.
    pub frames:  u32,
}

/// RFC-0049 M1: the budget an exec installs. `None` keeps the task's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemSpec {
    /// Frame limit in pages; `0` = no limit.
    pub limit: u32,
    /// `mem = "locked"`.
    pub locked: bool,
    /// The topology row the budget came from, as index + 1; `0` = no row
    /// (nothing is counted against any row's `instances`).
    pub row: u16,
    /// That row's `instances` (live spawned/exec'd instances allowed).
    pub instances: u16,
    /// That row's `mem_huge_mib` (Kconfig `LOCKED_HUGE_LEAVES`): MiB of its
    /// boot-reserved region, mapped with 2 MiB leaves at [`LOCKED_ARENA_VA`]
    /// by exec. `0` = none.
    pub huge_mib: u16,
}

/// What [`take_current_task_exec_ctx`] hands the consumption sites: the
/// register-visible half of the exec (`user_pt`/`brk` were already applied to
/// the task by `exec_user`, and the old address space is already gone by the
/// time this struct exists).
pub struct ExecHandoff {
    pub entry:   u64,
    pub user_sp: u64,
    pub sstatus: u64,
    pub satp:    u64,
}

// K-A15: the parent's ecall sepc/user_sp used to be captured into a global
// (`ECALL_SEPC`/`ECALL_USER_SP`, set by the trap handler before every
// syscall dispatch) and the fork hand-off into another global
// (`FORK_CHILD_CTX`) — both raced against concurrent syscalls/forks on
// other harts (audit finding K-A15). sepc/user_sp
// are now threaded through as plain function parameters (hart-local, no
// shared state, no race possible) all the way from the trap handler down to
// `sys_fork_impl`; the fork hand-off itself now lives on the child's own
// Task struct (`fork_entry`/`fork_user_sp`/`fork_satp`/`fork_ctx_ready` —
// see their doc in `crates/core/sched/src/task.rs`) instead of a single shared
// slot, via `scheduler::set_task_fork_ctx`/`take_current_task_fork_ctx`.
//
// K-C21: the exec hand-off (`PENDING_EXEC`, a global
// `SpinLock<Option<ExecContext>>` drained at the end of every U-mode ecall
// on every hart) was the last survivor of that same class, and it raced the
// same way: another hart finishing any syscall in the window SRET'd into
// the exec'er's fresh address space while the exec'er resumed its old sepc
// under the new page table. It now lives on the exec'ing task's own slot
// (`exec_entry`/`exec_user_sp`/`exec_sstatus`/`exec_satp`/`exec_old_pt`/
// `exec_ctx_ready` — see their doc in `crates/core/sched/src/task.rs`).

// ── ELF loader ────────────────────────────────────────────────────────────────

/// Load a RISC-V ELF64 binary into a new Sv39 user address space.
///
/// On success: publishes the hand-off on the CURRENT task (consumed by the
/// same task via [`take_current_task_exec_ctx`]) and returns 0.
/// On failure: returns -1.
///
/// The task's seccomp filter (`syscall_filter`) is not touched here: exec keeps
/// it, as Linux keeps a seccomp filter across `execve` (see `SyscallFilter` in
/// `filter.rs`). The kernel exec sites that start a program on an unconfined
/// kernel task install the image's own profile after this returns 0
/// (`seccomp::install_image_profile`).
pub fn exec_user(elf: &[u8]) -> i64 {
    exec_user_mem(elf, None)
}

/// [`exec_user`] that also installs the budget `mem` (the image's topology
/// row, RFC-0049 M1); `None` keeps the task's current limit and lock.
///
/// The new address space is charged in full — image, stack, page tables — and
/// an image that does not fit its budget is REFUSED here, before the task
/// gives up the image it is running: the new address space is torn down and
/// `-1` returned, and the refusal is counted with every other budget refusal.
pub fn exec_user_mem(elf: &[u8], mem: Option<MemSpec>) -> i64 {
    exec_install(load_elf(elf), mem, None)
}

/// RFC-0047 (Linux `execve`): exec `img` (a whole image, or one too large for
/// the bounce buffer, streamed and digest-checked by its filler), then let
/// `stack(user_pt, aux)` lay out the new image's initial stack and return its
/// stack pointer. `-1` and the old image kept on any failure.
pub fn exec_user_image(
    img: crate::spawn::ElfImage<'_>,
    mem: Option<MemSpec>,
    stack: &mut dyn FnMut(usize, &azos_linux_abi::ImageAux) -> Option<u64>,
) -> i64 {
    let (ctx, aux) = load_image(img);
    exec_install(ctx, mem, Some((&aux, stack)))
}

/// Load `img` into a new address space: its context and its auxiliary
/// vector, or `None` (nothing left behind) when it does not load.
fn load_image(img: crate::spawn::ElfImage<'_>) -> (Option<ExecContext>, azos_linux_abi::ImageAux) {
    let aux_of = |hdr: &[u8]| azos_linux_abi::image_aux(hdr, PAGE_SIZE as u64).unwrap_or_default();
    match img {
        crate::spawn::ElfImage::Bytes(b) => (load_elf(b), aux_of(b)),
        crate::spawn::ElfImage::Streamed { hdr, len, fill } => {
            let ctx = match load_elf_hdr(hdr, len) {
                Some(c) if fill(c.user_pt as usize) => {
                    sync_loaded_text(&c, hdr);
                    Some(c)
                }
                Some(c) => {
                    vmm::destroy_user_pagetable(c.user_pt as usize);
                    None
                }
                None => None,
            };
            (ctx, aux_of(hdr))
        }
        crate::spawn::ElfImage::Cached { pages, kept } => (
            load_elf_cached(pages, kept.entry, kept.brk),
            crate::spawn::kept_aux(&kept),
        ),
    }
}

/// The second half of every exec: admission against the row's budget, then
/// the address-space switch is published for the trap return. With `stack`,
/// the initial stack is laid out first and its pointer replaces the image's.
#[allow(clippy::type_complexity)]
fn exec_install(
    ctx: Option<ExecContext>,
    mem: Option<MemSpec>,
    stack: Option<(&azos_linux_abi::ImageAux, &mut dyn FnMut(usize, &azos_linux_abi::ImageAux) -> Option<u64>)>,
) -> i64 {
    match exec_admit(ctx, mem, stack) {
        Some(p) => exec_commit(p),
        None => -1,
    }
}

/// An exec admitted but not yet committed (wave 15, plan 4a): the new address
/// space is built, its budget and row instance checked and claimed, its stack
/// laid out; the caller's image is untouched. Everything that can refuse an
/// exec has run. [`exec_commit`] switches to it (it cannot fail);
/// [`exec_abort`] gives it back. Between the two the caller ends its other
/// threads (`scheduler::exec_end_other_threads`), so an exec that fails
/// leaves the process and its threads as they were.
pub struct PreparedExec {
    ctx: ExecContext,
    spec: MemSpec,
    /// The process's row when the exec was admitted, and whether the image's
    /// row differs from it (an instance of `spec.row` was then claimed).
    cur_row: u16,
    row_change: bool,
}

/// [`exec_user_mem`] up to the commit: `None` when the image does not load or
/// is refused (nothing is left behind).
pub fn exec_prepare_mem(elf: &[u8], mem: Option<MemSpec>) -> Option<PreparedExec> {
    exec_admit(load_elf(elf), mem, None)
}

/// [`exec_user_image`] up to the commit.
pub fn exec_prepare_image(
    img: crate::spawn::ElfImage<'_>,
    mem: Option<MemSpec>,
    stack: &mut dyn FnMut(usize, &azos_linux_abi::ImageAux) -> Option<u64>,
) -> Option<PreparedExec> {
    let (ctx, aux) = load_image(img);
    exec_admit(ctx, mem, Some((&aux, stack)))
}

/// Admission: everything an exec checks before it may replace the caller's
/// image. The process's limit, lock and row are read through its leader's
/// slot (`proc_slot`): the caller may be any of its threads.
#[allow(clippy::type_complexity)]
fn exec_admit(
    ctx: Option<ExecContext>,
    mem: Option<MemSpec>,
    stack: Option<(&azos_linux_abi::ImageAux, &mut dyn FnMut(usize, &azos_linux_abi::ImageAux) -> Option<u64>)>,
) -> Option<PreparedExec> {
    let mut ctx = ctx?;
    let (cur_limit, cur_locked) = crate::scheduler::current_mem_policy();
    let cur_row = crate::scheduler::current_proc_mem_row();
    let spec = mem.unwrap_or(MemSpec {
        limit: cur_limit, locked: cur_locked, row: cur_row, instances: 0, huge_mib: 0,
    });
    // Kconfig LOCKED_HUGE_LEAVES: the row's region, mapped now that
    // the address space exists and before anything is charged or
    // claimed, so a refusal leaves nothing behind but the new table.
    // The tables the mapping hung (one level-1 table at most) are
    // charged with the rest of the address space.
    if spec.huge_mib != 0 {
        match install_locked_arena(ctx.user_pt as usize, &spec) {
            Ok((va, bytes)) => {
                ctx.frames = ctx.frames.saturating_add(crate::scheduler::take_current_pt_build());
                report_locked_arena(ctx.user_pt as usize, spec.row, va, bytes);
            }
            Err(why) => {
                let _ = crate::scheduler::take_current_pt_build();
                azos_drv_sys::kwarn!("[MEM] exec REFUSED: the row's 2 MiB-leaf region: {}", why);
                vmm::destroy_user_pagetable(ctx.user_pt as usize);
                return None;
            }
        }
    }
    if spec.limit != 0 && ctx.frames > spec.limit {
        azos_drv_sys::kwarn!(
            "[MEM] exec REFUSED: the image needs {} pages, its budget is {}",
            ctx.frames, spec.limit,
        );
        crate::scheduler::note_mm_quota_refusal();
        vmm::destroy_user_pagetable(ctx.user_pt as usize);
        return None;
    }
    if let Some((aux, f)) = stack {
        match f(ctx.user_pt as usize, aux) {
            Some(sp) => ctx.user_sp = sp,
            None => {
                vmm::destroy_user_pagetable(ctx.user_pt as usize);
                return None;
            }
        }
    }
    // Wave 9: an exec into a different row becomes one of that row's
    // live instances, refused past its `instances` before the task
    // gives up the image it is running. The count taken here is given
    // back by `exec_abort`, or (the one the process held) by the commit.
    let row_change = spec.row != cur_row;
    if row_change && !crate::scheduler::row_claim(spec.row, spec.instances) {
        let live = crate::scheduler::row_live(spec.row);
        let n = crate::scheduler::note_mm_instance_refusal();
        azos_drv_sys::kwarn!(
            "[MEM] exec REFUSED: its row already has {} of {} live instance(s) (instance refusals: {})",
            live, spec.instances, n,
        );
        vmm::destroy_user_pagetable(ctx.user_pt as usize);
        return None;
    }
    Some(PreparedExec { ctx, spec, cur_row, row_change })
}

/// Give back an admitted exec that will not run: its address space and
/// the row instance it claimed. The caller keeps its image.
pub fn exec_abort(p: PreparedExec) {
    vmm::destroy_user_pagetable(p.ctx.user_pt as usize);
    if p.row_change {
        crate::scheduler::row_release(p.spec.row);
    }
}

/// Switch the current task to an admitted exec. Cannot fail: returns 0.
/// The current task must be its process's only thread by now (after
/// `scheduler::exec_end_other_threads`, whose PID hand-over put the process's
/// state on this slot when a thread that was not the leader execs).
pub fn exec_commit(p: PreparedExec) -> i64 {
    let PreparedExec { ctx, spec, cur_row, row_change } = p;
    // K-C22(A): capture the address space this task is abandoning
    // BEFORE `set_current_user_info` overwrites `user_pt` with the
    // new one — this is the only moment the old root is still
    // reachable. It rides in the hand-off because it must be
    // destroyed by the CONSUMER, after satp points at the new page
    // table: right now this hart is still fetching kernel code
    // through the old PT's kernel entries.
    let old_pt = crate::scheduler::current_user_pt() as u64;
    // Store user PT info into the current task so context_switch.S can
    // write the correct SATP on every subsequent context switch.
    crate::scheduler::set_current_user_info(ctx.satp, ctx.user_pt, ctx.brk);
    crate::scheduler::mm_install_frames(spec.limit, spec.locked, ctx.frames);
    if row_change {
        crate::scheduler::row_release(cur_row);
        crate::scheduler::set_current_mem_row(spec.row);
    }
    crate::scheduler::set_current_task_exec_slots(
        ctx.entry, ctx.user_sp, ctx.sstatus, ctx.satp, old_pt,
    );
    0
}

/// K-C21/K-C22: consume the exec hand-off published by [`exec_user`] on the
/// CURRENT task, install the new address space, and destroy the old one.
///
/// Every consumption site (the tail of the U-mode ecall arm in the kernel's
/// trap handler; the shell and autorun kernel tasks just before their
/// `sret_to_user`) must go through this function — the ordering inside it is
/// the entire K-C22(A) fix:
///
///  1. `csrw satp` to the NEW page table (with full `sfence.vma`). Safe at
///     any of the call sites: `load_elf_into` finished with
///     [`vmm::copy_kernel_entries_to_user`], so kernel text, stacks and MMIO
///     are mapped in the new PT and this function keeps executing across the
///     switch — the same property every trap from U-mode already relies on.
///  2. Only THEN destroy the old address space. Destroying before the switch
///     would free frames — including live page-table frames — that this
///     hart's satp/TLB still translates through; another hart reallocating
///     them mid-walk turns that into silent corruption. After the switch the
///     old root is referenced by nothing: `task_satp`/`user_pt` already point
///     at the new PT (step done in `exec_user`), and any OTHER hart that ever
///     ran this PT flushed its TLB when `context_switch.S` moved it off
///     (full `sfence.vma` on every satp change).
///
/// The trap-handler site still returns `satp` for the SRET path's own
/// `csrw satp`; that re-write of the value already installed here is
/// harmless, as is the one inside `sret_to_user` for the kernel-task sites.
///
/// Same-task-only, like the slot it drains: no TID check is needed (contrast
/// `set_task_fork_ctx`) because publisher and consumer are one task in one
/// syscall — the slot cannot be freed, reused, or observed by another hart
/// in between.
///
/// The test is split from the take: every syscall runs the inlined plain-load
/// test (`current_task_exec_ctx_pending`), and only a pending hand-off reaches
/// the out-of-line swap, satp switch and teardown below.
#[inline(always)]
pub fn take_current_task_exec_ctx() -> Option<ExecHandoff> {
    if !crate::scheduler::current_task_exec_ctx_pending() {
        return None;
    }
    take_current_task_exec_ctx_slow()
}

#[inline(never)]
fn take_current_task_exec_ctx_slow() -> Option<ExecHandoff> {
    let (entry, user_sp, sstatus, satp, old_pt) =
        crate::scheduler::take_current_task_exec_slots()?;
    // Step 1 on both ISAs. aarch64 used to skip it ("no register write here
    // yet") and leave the switch to `trap_entry.S`'s exec hand-off before
    // `eret`, so the destroy below freed the old table while this PE's
    // `TTBR0_EL1` still named it — and the kernel reaches its devices through
    // the low half on this ISA, so an interrupt taken during the teardown
    // could walk the table being freed. `satp` is the new root's PA there (see
    // `make_satp`); the hand-off's later write of the same value is harmless.
    // riscv64: `csrw satp` + `sfence.vma`; aarch64: TTBR0_EL1 + local flush,
    // skipped for a zero word (no root lives at PA 0 there).
    ARCH.install_user_root_local(satp as usize);
    if old_pt != 0 {
        // A ring-3 task looping SYS_EXEC used to drain the PMM through the
        // success path — nothing ever freed the replaced address space.
        destroy_user_address_space(old_pt);
    }
    Some(ExecHandoff { entry, user_sp, sstatus, satp })
}

/// K-C22: tear down an address space that no hart can still be running on.
///
/// This is the teardown for the *post-construction* lifetime (exec replaced
/// it, or its task exited and the pool slot is being reused) — as opposed to
/// [`vmm::destroy_user_pagetable`], which the load/fork failure paths call on
/// page tables that never left their builder. The difference: a live process
/// may have had shm ([`shm_map_user`]) and MMIO ([`mmio_map_user`]) frames
/// mapped USER into its PT, and those frames are NOT owned by the address
/// space — shm pages belong to the shm registry (other processes may map
/// them; freeing here is a cross-process use-after-free), MMIO frames belong
/// to the hardware. Both only ever live in the [`USER_MMIO_BASE`,
/// [`USER_MMIO_LIMIT`]) VA window ([`reserve_window_va`] is the single
/// allocator), so the teardown spares every leaf frame in that window while
/// still freeing the window's L0/L1 tables — those ARE this PT's own.
///
/// Refused, and the address space leaked, when a hart still translates
/// through it (`vmm::destroy_user_pagetable_skip_range`). Printed, because
/// every caller has just argued that cannot happen.
pub fn destroy_user_address_space(user_pt: u64) {
    let holders =
        vmm::destroy_user_pagetable_skip_range(user_pt as usize, USER_MMIO_BASE, USER_MMIO_LIMIT);
    if holders != 0 {
        azos_drv_sys::kerr!(
            "[MM] page-table root {:#x} still live on hart mask {:#x}: teardown refused, address space leaked (refusals: {})",
            user_pt, holders,
            vmm::LIVE_ROOT_REFUSALS.load(core::sync::atomic::Ordering::Relaxed),
        );
    }
}

/// RFC-0047 stage 3: copy an image's `PT_LOAD` file bytes into the pages
/// [`load_elf_hdr`] mapped in `user_pt`, reading the WHOLE file in order
/// through `read(offset, buf)` (bytes read; short only at the end) and
/// feeding every byte read to `hasher`. The caller compares the digest with
/// the one it planned the image by: the bytes in memory are then the bytes
/// hashed, whatever the file did between the two reads. `buf` is the
/// caller's scratch (a page or more). `false` on a short or failed read.
pub fn fill_elf_segments(
    user_pt: usize,
    hdr: &[u8],
    file_len: usize,
    buf: &mut [u8],
    read: &mut dyn FnMut(usize, &mut [u8]) -> usize,
    hasher: &mut azos_crypto::sha256::Sha256,
) -> bool {
    if hdr.len() < 64 || buf.is_empty() {
        return false;
    }
    let e_phoff = r64(hdr, 32) as usize;
    let e_phentsize = r16(hdr, 54) as usize;
    let e_phnum = r16(hdr, 56) as usize;
    let mut off = 0usize;
    while off < file_len {
        let want = buf.len().min(file_len - off);
        let n = read(off, &mut buf[..want]);
        if n != want {
            return false;
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            if ph + 56 > hdr.len() || r32(hdr, ph) != PT_LOAD {
                continue;
            }
            let p_offset = r64(hdr, ph + 8) as usize;
            let p_vaddr = r64(hdr, ph + 16) as usize;
            let p_filesz = r64(hdr, ph + 32) as usize;
            // The overlap of this chunk with the segment's file range.
            let lo = off.max(p_offset);
            let hi = (off + n).min(p_offset.saturating_add(p_filesz));
            let mut x = lo;
            while x < hi {
                let va = p_vaddr + (x - p_offset);
                let page = va & !(PAGE_SIZE - 1);
                let in_page = (PAGE_SIZE - (va - page)).min(hi - x);
                let Some(phys) = vmm::translate_user(user_pt, page, false) else { return false };
                // SAFETY: `phys` is a frame `load_elf_hdr` mapped for this
                // segment in an address space no task runs on yet; it is
                // reached through the kernel's own mapping of RAM.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        chunk.as_ptr().add(x - off),
                        (azos_mm::addr::phys_to_virt(phys) + (va - page)) as *mut u8,
                        in_page,
                    );
                }
                x += in_page;
            }
        }
        off += n;
    }
    true
}

pub(crate) fn load_elf(elf: &[u8]) -> Option<ExecContext> {
    let ctx = load_elf_impl(elf, elf.len(), true)?;
    sync_loaded_text(&ctx, elf);
    Some(ctx)
}

/// [`sync_image_text`] over the image range of the headers `hdr`.
pub(crate) fn sync_loaded_text(ctx: &ExecContext, hdr: &[u8]) {
    if let Some((lo, hi)) = image_page_range(hdr) {
        sync_image_text(ctx.user_pt as usize, lo, hi);
    }
}

/// RFC-0047 stage 3: build the address space of an image larger than the
/// exec bounce buffer from its first bytes only. `hdr` holds the ELF header
/// and every program header (the caller refuses an image whose table lies
/// past it); `file_len` is the whole file's length, which every `PT_LOAD`
/// is bounded by. The segments' pages are mapped and left zeroed: the caller
/// fills them with [`fill_elf_segments`], hashing the bytes it copies.
pub(crate) fn load_elf_hdr(hdr: &[u8], file_len: usize) -> Option<ExecContext> {
    load_elf_impl(hdr, file_len, false)
}

/// Wave 14 (SPAWNCACHE): build the address space of an image the
/// verified-image cache kept (`azos_mm::image_frames`): its executable
/// frames shared read-execute, every other page a fresh copy, then the same
/// stack, vDSO and kernel entries as [`load_elf`]. `entry` and `brk` are the
/// ones the first load of those bytes produced. `frames` counts every image
/// page, shared or not, as [`load_elf`] does: a row's budget admits the same
/// image the same way whether or not it was cached.
pub(crate) fn load_elf_cached(
    pages: &azos_mm::image_frames::ImagePages,
    entry: u64,
    brk: u64,
) -> Option<ExecContext> {
    if cfg!(feature = "no-mmu") {
        return None;
    }
    let _ = crate::scheduler::take_current_pt_build();
    let user_pt = vmm::create_pagetable().ok()?;
    let built = azos_mm::image_frames::map_into(pages, user_pt)
        .and_then(|n| finish_user_space(user_pt, entry, brk as usize, n));
    match built {
        Some(mut ctx) => {
            ctx.frames = ctx.frames
                .saturating_add(1)
                .saturating_add(crate::scheduler::take_current_pt_build());
            Some(ctx)
        }
        None => {
            let _ = crate::scheduler::take_current_pt_build();
            vmm::destroy_user_pagetable(user_pt);
            None
        }
    }
}

/// Wave 14 (SPAWNCACHE): the page range `[lo, hi)` the `PT_LOAD` segments of
/// the image whose headers are `hdr` occupy (headers [`load_elf`] or
/// [`load_elf_hdr`] already accepted). `None` without a loaded segment.
pub(crate) fn image_page_range(hdr: &[u8]) -> Option<(usize, usize)> {
    if hdr.len() < 64 { return None; }
    let e_phoff = r64(hdr, 32) as usize;
    let e_phentsize = r16(hdr, 54) as usize;
    let e_phnum = r16(hdr, 56) as usize;
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for i in 0..e_phnum {
        let ph = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        if ph.checked_add(56)? > hdr.len() { return None; }
        if r32(hdr, ph) != PT_LOAD { continue; }
        let p_vaddr = r64(hdr, ph + 16) as usize;
        let p_memsz = r64(hdr, ph + 40) as usize;
        if p_memsz == 0 { continue; }
        lo = lo.min(p_vaddr & !(PAGE_SIZE - 1));
        hi = hi.max(p_vaddr.checked_add(p_memsz)?.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1));
    }
    if hi > lo && hi <= USER_LOW_MAX { Some((lo, hi)) } else { None }
}

/// Wave 14: make every hart's instruction fetch see the image text the
/// loader just wrote into the frames of `user_pt` over `[lo, hi)`, before any
/// task runs in it (it may run on any hart, and a frame may have held other
/// code before). Called once per load that WROTE executable frames: a fresh
/// load ([`load_elf`]) and a streamed fill. A kept image's shared text
/// ([`load_elf_cached`]) is not written again (it was synchronised when it
/// was loaded) and its copied pages are never executable, and a copy-on-write
/// break never produces an executable page (`handle_cow_fault` refuses one),
/// so neither path needs this.
///
/// * riscv64: `fence rw, rw` (the copies are visible), `fence.i` here, and
///   the SBI remote `fence.i` on every other hart (the sequence
///   `SYS_MODULE_MAP_X` uses; Zifencei has no range form).
/// * aarch64: clean each executable frame to the point of unification by
///   the kernel's alias of it (the D-cache is PIPT, any alias cleans the
///   line; no EL1 maintenance on an EL0 mapping), `DSB ISH`, then
///   `IC IALLUIS` + `DSB ISH` + `ISB` (`cache::icache_invalidate_all`): one
///   broadcast invalidate instead of `IC IVAU` per line, which on a
///   multi-page image costs more instructions and needs the user VA.
pub(crate) fn sync_image_text(user_pt: usize, lo: usize, hi: usize) {
    // `icache_needs_dcache_clean` is a constant per ISA (false on riscv64,
    // whose `fence.i` needs no clean): the loop folds away there.
    if ARCH.icache_needs_dcache_clean() {
        let mut va = lo;
        while va < hi {
            if let Some(pa) = vmm::translate_user(user_pt, va, false) {
                if matches!(vmm::user_page(user_pt, va), vmm::UserPage::Leaf { exec: true }) {
                    let k = azos_mm::addr::phys_to_virt(pa & !(PAGE_SIZE - 1));
                    // SAFETY: a whole frame of RAM through the kernel's map.
                    unsafe { ARCH.dcache_clean(k, PAGE_SIZE) };
                }
            }
            va += PAGE_SIZE;
        }
    }
    ARCH.icache_sync_all();
}

/// The loader behind [`load_elf`] and [`load_elf_hdr`]: `elf` is the whole
/// image when `copy`, else its header bytes, and `file_len` the image length.
fn load_elf_impl(elf: &[u8], file_len: usize, copy: bool) -> Option<ExecContext> {
    // `no-mmu`: no ring-3 image is ever loaded. That build has no Sv39 address
    // space to confine one — a user program would run over the kernel's own
    // memory — so the answer is a compile-time constant and the loader below
    // it is dead code the build drops. Every ring-3 entry comes through here:
    // `exec_user` (SYS_EXEC, SYS_EXECPATH, autorun) and `spawn::spawn_prepare`
    // (SYS_SPAWN). The shell's `exec` and `fork` are compiled out already.
    if cfg!(feature = "no-mmu") {
        return None;
    }
    if elf.len() < 64               { return None; }
    if &elf[0..4] != ELF_MAGIC      { return None; }
    if elf[4] != 2                  { return None; } // ELFCLASS64
    if elf[5] != 1                  { return None; } // ELFDATA2LSB
    // e_machine must match the ISA this kernel binary is itself built for —
    // checked per-ISA (not "either machine accepted on both") so a RISC-V
    // kernel can never be handed an aarch64 image or vice versa, whatever
    // FAT32 file name it arrived under.
    #[cfg(target_arch = "riscv64")]
    const EXPECTED_MACHINE: u16 = 0xf3;  // EM_RISCV
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    const EXPECTED_MACHINE: u16 = 0xb7;  // EM_AARCH64
    // Host builds (e.g. `cargo test` on aarch64-apple-darwin, where
    // `target_arch = "aarch64"` but `target_os != "none"`) compile this
    // function too (this module has no host-exclusion at the `mod` level)
    // AND exercise it for real: `tests/host/syscall-tests`' `exec_binding`
    // suite feeds the REAL `build/uhello.elf` (RISC-V bytes) through this
    // exact loader on the host to test seccomp image binding
    // (`exec_of_a_shipped_image_reaches_the_loader_with_the_bytes_hashed`).
    // `0xffff` here — "matches neither real ISA" — broke that test: it
    // turned a real machine-check pass (RISC-V bytes, RISC-V expectation)
    // into a rejection before the loader ever got far enough to hit the
    // check that test is actually about. EM_RISCV on host preserves this
    // function's ENTIRE pre-existing behavior there (the literal was
    // `0xf3` unconditionally before this task); it is not a claim that a
    // host build ever really execs anything.
    #[cfg(not(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none"))))]
    const EXPECTED_MACHINE: u16 = 0xf3;  // EM_RISCV — see comment above
    if r16(elf, 18) != EXPECTED_MACHINE { return None; }

    let e_entry     = r64(elf, 24);
    let e_phoff     = r64(elf, 32) as usize;
    let e_phentsize = r16(elf, 54) as usize;
    let e_phnum     = r16(elf, 56) as usize;

    if e_phentsize < 56 || e_phnum == 0 { return None; }

    // RFC-0049 M1: tables this task allocated for some earlier, abandoned
    // build are not this address space's; start the count clean.
    let _ = crate::scheduler::take_current_pt_build();
    let user_pt = vmm::create_pagetable().ok()?;

    // Every failure inside `load_elf_into` leaves behind a root page table,
    // the L1/L0 tables built for it, and every data page copied so far.
    // `exec` is reachable from ring 3, so a loop of malformed images used to
    // drain the PMM one image at a time until the kernel could no longer
    // allocate anything — a slow, silent death rather than a rejected exec.
    // Funnelling the whole build through one call gives a single teardown
    // point that covers all of them.
    match load_elf_into(elf, file_len, copy, user_pt, e_entry, e_phoff, e_phentsize, e_phnum) {
        Some(mut ctx) => {
            // The root, plus every table `vmm::walk` hung under it while the
            // image, the stack and the vDSO were mapped (counted by the
            // scheduler's table hook, since `user_pt` is not this task's own).
            ctx.frames = ctx.frames
                .saturating_add(1)
                .saturating_add(crate::scheduler::take_current_pt_build());
            Some(ctx)
        }
        None => {
            let _ = crate::scheduler::take_current_pt_build();
            vmm::destroy_user_pagetable(user_pt);
            None
        }
    }
}

/// Build the address space for `user_pt`. Returns `None` on any rejection;
/// the caller owns the teardown.
///
/// Ordering is load-bearing (see [`vmm::copy_kernel_entries_to_user`]): all
/// user mappings go in first, and the kernel entries are merged in as the
/// very last step. Consequently **there is no failure path after the merge** —
/// every `return None` below happens while `user_pt` still contains nothing
/// but tables this function allocated, which is exactly what
/// [`vmm::destroy_user_pagetable`] needs in order to free them safely.
#[allow(clippy::too_many_arguments)]
fn load_elf_into(
    elf: &[u8],
    file_len: usize,
    copy: bool,
    user_pt: usize,
    e_entry: u64,
    e_phoff: usize,
    e_phentsize: usize,
    e_phnum: usize,
) -> Option<ExecContext> {
    // Track the highest mapped virtual address for initial brk.
    let mut brk_va: usize = 0;
    // RFC-0049 M1: data frames allocated (image and stack); the caller adds
    // the page tables.
    let mut frames: u32 = 0;

    // Does `e_entry` land in a mapped, file-backed, executable segment?
    // Nothing validated it before, and it is handed straight to `sret_to_user`
    // as sepc: an ELF could name any address at all — an unmapped page, the
    // stack, the vDSO — and the SRET would fault immediately in U-mode with
    // the kernel treating it as a fatal user trap.
    let mut entry_ok = false;

    // End (`p_vaddr + p_memsz`, unaligned) of the last accepted segment. The
    // page-reuse branch below *documents* that segments arrive in ascending
    // vaddr order, and then relies on it; nothing checked it. See
    // `elf_bounds::check_pt_load`.
    let mut prev_seg_end: usize = 0;
    // How the last accepted segment is mapped: a segment that starts on the
    // page it ends on must be mapped alike (`elf_bounds::check_page_sharing`).
    let mut prev_perms: Option<elf_bounds::SegPerms> = None;

    for i in 0..e_phnum {
        // Bounded ph offset — `i * e_phentsize` must not overflow, and
        // the program header itself (56 bytes) must fit entirely in the
        // ELF blob. Even if e_phentsize > 56, we only read 56 bytes.
        //
        // These reject the image instead of `break`ing out of the loop:
        // breaking meant a truncated or bogus `e_phoff`/`e_phentsize` loaded
        // however many segments happened to fit and then SRET'd into a
        // half-built address space, which is a far worse outcome than a
        // failed exec.
        let ph = match e_phoff.checked_add(i.checked_mul(e_phentsize)?) {
            Some(p) => p,
            None    => return None,
        };
        if ph.checked_add(56).map_or(true, |end| end > elf.len()) { return None; }

        if r32(elf, ph) != PT_LOAD { continue; }

        let p_flags  = r32(elf, ph + 4);
        let p_offset = r64(elf, ph + 8)  as usize;
        let p_vaddr  = r64(elf, ph + 16) as usize;
        let p_filesz = r64(elf, ph + 32) as usize;
        let p_memsz  = r64(elf, ph + 40) as usize;

        // Sanity bounds on user-supplied ELF fields. Without these a
        // malicious ELF can:
        //   - set p_vaddr = 0 → the null-guard page mapped for real, which
        //     un-does `handle_demand_fault`/`handle_cow_fault`'s refusal to
        //     resolve anything below `vmm::USER_GUARD_LIMIT` (a task that
        //     jumps through a null pointer goes back to executing zeros)
        //   - set p_vaddr over kernel MMIO or over the stack/vDSO (see
        //     USER_LOW_MAX) → S-mode mappings clobbered in the user PT
        //   - set p_memsz huge → infinite alloc loop / OOM kernel
        //   - set p_filesz > p_memsz → unspecified by ELF spec, refuse
        //   - set p_offset+p_filesz > elf.len() → OOB read
        //   - emit segments out of vaddr order → a later segment's file bytes
        //     rewritten over an earlier segment's already-mapped page
        // All of them live in `elf_bounds` so they can actually be tested;
        // nothing about them is duplicated here.
        let (va_start, va_end) = match elf_bounds::check_pt_load(
            p_offset, p_vaddr, p_filesz, p_memsz,
            file_len, prev_seg_end, seg_limits(),
        ) {
            elf_bounds::SegCheck::Empty     => continue,
            elf_bounds::SegCheck::Reject(_) => return None,
            elf_bounds::SegCheck::Load(r)   => {
                let perms = elf_bounds::seg_perms(p_flags);
                if elf_bounds::check_page_sharing(prev_seg_end, prev_perms, p_vaddr, perms, PAGE_SIZE)
                    .is_err()
                {
                    return None;
                }
                prev_seg_end = r.seg_end;
                prev_perms = Some(perms);
                (r.va_start, r.va_end)
            }
        };

        // Entry point must sit in the *file-backed* part of a segment this
        // loader actually maps executable.
        //
        // `p_memsz` would be too loose: its tail is the zero-filled BSS, and
        // an entry there executes zeros (illegal instruction). And `PF_X`
        // alone would be too loose in the other direction — the flag
        // derivation below maps any writable segment as USER_RW with no EXEC
        // bit, so an `RWX` segment (p_flags = 7) advertises X in the header
        // but faults on instruction fetch. The check has to agree with the
        // mapper, not with the ELF header.
        if p_flags & PF_X != 0 && p_flags & PF_W == 0 {
            let e = e_entry as usize;
            if e >= p_vaddr && e < p_vaddr.saturating_add(p_filesz) {
                entry_ok = true;
            }
        }

        // W^X, in both directions.
        //
        // This used to be a two-way split: writable → RW, everything else →
        // **RX**. So a plain read-only segment (`p_flags = PF_R`, no PF_X) was
        // mapped executable, and that was not merely loose — it was an RWX
        // hole reachable from ring 3. A crafted image with a writable segment
        // followed by an `R`-only segment sharing its page hit the reuse
        // branch below with `add = USER_RX`; `add_user_leaf_perms` only
        // refuses WRITE-onto-EXEC, so EXEC-onto-WRITE went through and the
        // page ended up R+W+X. Ring 3 could then write instructions into it
        // and jump there, with the entry-point check satisfied by a separate,
        // well-formed PF_X segment.
        //
        // Three-way now (`elf_bounds::seg_perms`), and `.rodata` loses the X
        // bit it never needed. A page two segments share used to take the
        // union of their permissions, so `.rodata` on the last `.text` page
        // stayed executable; such an image is refused now unless both are
        // mapped alike (`check_page_sharing` above), and every
        // `userspace/*/user*.ld` starts `.rodata` on a page of its own.
        //
        // Canary `rodata-exec-canary`: the old two-way split (read-only maps
        // read-execute); abitest's `elfperm:` check then runs its `.rodata`.
        let flags = match elf_bounds::seg_perms(p_flags) {
            elf_bounds::SegPerms::ReadWrite => {
                PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW }
            }
            elf_bounds::SegPerms::ReadOnly if !cfg!(feature = "rodata-exec-canary") => {
                PagePerms { accessed: true, ..PagePerms::USER_RO }
            }
            _ => PagePerms { accessed: true, ..PagePerms::USER_RX },
        };

        if va_end > brk_va { brk_va = va_end; }

        let mut va = va_start;
        while va < va_end {
            // A previous PT_LOAD segment may already have mapped this page:
            // Rust ELFs emit separate RX (.text) / R (.rodata) / RW (.data)
            // LOAD segments that frequently share a boundary page. Mapping a
            // fresh page per segment let the later segment clobber the earlier
            // one — e.g. an R-only .rodata page overwriting the RX .text page,
            // silently dropping the X bit so the very first user instruction
            // faulted. Reuse the existing physical page instead; segments are
            // ordered by ascending vaddr so the executable text maps first and
            // its RX flags (which already permit reads) cover the shared page.
            //
            // The reuse lookup uses `translate_user`, not the permission-blind
            // `translate`: the latter resolves *any* valid PTE, including the
            // kernel's identity-mapped MMIO. An ELF with `p_vaddr =
            // 0x0200_4000` therefore got the CLINT's physical address handed
            // back and the memcpy below wrote attacker-chosen file bytes into
            // CLINT registers in S-mode. `translate_user` requires
            // VALID + USER + READ at every leaf level, so a kernel/MMIO leaf
            // resolves to `None` and never becomes a memcpy destination.
            //
            // `write = false` is deliberate. The page being reused is
            // typically the RX `.text` page a following `.rodata` segment
            // shares; asking for WRITE would reject it and defeat the whole
            // reuse branch. Write permission is not the question here — these
            // are pages this function allocated moments ago and still owns,
            // and their final PTE flags are what user mode will be held to.
            let phys = match vmm::translate_user(user_pt, va, false) {
                Some(existing) => {
                    // The page is already mapped by the previous segment,
                    // which `check_page_sharing` above required to be mapped
                    // exactly like this one: the widening below finds the
                    // permissions already there and changes nothing. It
                    // stays as the backstop it was before that check (an
                    // `.rodata`/`.data` page widened, a `.text`/`.data` one
                    // refused rather than made writable-executable).
                    //
                    // The other half of W^X is ours: `add_user_leaf_perms`
                    // refuses WRITE onto an EXEC leaf, but nothing there
                    // refuses EXEC onto a WRITE leaf. An executable segment
                    // therefore never gets to reuse a page some earlier
                    // segment already mapped — it must own its first page
                    // outright. Real images satisfy this trivially (the RX
                    // segment is the first one and starts page-aligned at
                    // 0x10000 in all 12 binaries under `build/`); a crafted
                    // one that puts a writable segment first fails closed.
                    if flags.exec {
                        return None;
                    }
                    if vmm::add_user_leaf_perms(user_pt, va, flags).is_err() {
                        return None;
                    }
                    existing
                }
                None => {
                    // A page the segment's file bytes cover whole is
                    // overwritten by the copy below before any task runs on
                    // this table, so its zero-fill would be discarded (wave
                    // 14: ~1,500 instructions a page, rv64). The test is the
                    // copy's own: `copy_start == va`, `copy_end == page_end`
                    // and the source in bounds, so the copy is certain to
                    // run over all of it. Any other page is zeroed as before.
                    let full = copy
                        && va >= p_vaddr
                        && p_vaddr.saturating_add(p_filesz) >= va.saturating_add(PAGE_SIZE)
                        && p_offset
                            .checked_add(va - p_vaddr)
                            .and_then(|o| o.checked_add(PAGE_SIZE))
                            .is_some_and(|end| end <= elf.len());
                    let page = if full {
                        // SAFETY: every byte is written by the copy below
                        // (the conditions above are the copy's), before the
                        // table is installed on any task.
                        unsafe { pmm::alloc_page_uninit() }.ok()?
                    } else {
                        pmm::alloc_page().ok()?
                    };
                    frames = frames.saturating_add(1);
                    let p = page.as_usize();
                    // A map failure here means the VA is already occupied by
                    // something we cannot write through (only reachable if the
                    // ordering invariant above is ever broken). Ignoring it
                    // used to leak `page` *and* leave the copy below writing
                    // into a frame that is in no page table at all.
                    if vmm::map(user_pt, va, p, flags).is_err() {
                        let _ = pmm::free_page(page);
                        return None;
                    }
                    p
                }
            };

            // Copy the intersection of this page [va, va+PAGE) with the
            // segment's file-backed range [p_vaddr, p_vaddr+p_filesz) into the
            // page at the correct *destination offset*. When a segment starts
            // mid-page (p_vaddr > va, e.g. .rodata sharing the .text page), its
            // bytes must land at `p_vaddr - va` within the page — not at offset
            // 0, which previously clobbered the preceding segment's code.
            let page_end     = va.saturating_add(PAGE_SIZE);
            let seg_file_end = p_vaddr.saturating_add(p_filesz);
            let copy_start   = va.max(p_vaddr);
            let copy_end     = page_end.min(seg_file_end);
            if copy && copy_start < copy_end {
                let dest_off = copy_start - va;        // offset within the page
                let seg_off  = copy_start - p_vaddr;   // offset within the segment
                let src_off  = p_offset.saturating_add(seg_off);
                let copy_n   = copy_end - copy_start;
                if let (Some(src_end), Some(dst_end)) =
                    (src_off.checked_add(copy_n), dest_off.checked_add(copy_n))
                {
                    if src_end <= elf.len() && dst_end <= PAGE_SIZE {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                elf.as_ptr().add(src_off),
                                // The allocator hands back a PHYSICAL page;
                                // the kernel reaches it through its own
                                // mapping. Identity on riscv64, the upper
                                // half on aarch64.
                                (azos_mm::addr::phys_to_virt(phys) + dest_off) as *mut u8,
                                copy_n,
                            );
                        }
                    }
                }
            }
            va += PAGE_SIZE;
        }
    }

    // Reject an entry point we cannot vouch for. RISC-V fetches on 2-byte
    // boundaries (compressed instructions), so an odd address is malformed by
    // construction.
    //
    // `e_entry` needs no bound of its own, above or below: `entry_ok` is only
    // ever set from inside a segment that already passed
    // `elf_bounds::check_pt_load`, so it is transitively confined to
    // `USER_GUARD_LIMIT..USER_LOW_MAX`. That is worth stating because it is
    // the only ELF-supplied address here that is *not* checked directly —
    // it is handed straight to `sret_to_user` as sepc.
    if !entry_ok || (e_entry & 1) != 0 {
        return None;
    }
    finish_user_space(user_pt, e_entry, brk_va, frames)
}

/// The part of an address space every image gets — the stack, the vDSO and
/// sigreturn pages, the kernel's entries, the SATP — after its segments are
/// mapped in `user_pt`: the tail of [`load_elf_into`], and of
/// [`load_elf_cached`] (wave 14, SPAWNCACHE). `frames` counts the image's
/// data frames so far; the stack's are added. Same teardown rule as
/// [`load_elf_into`]: on `None` the caller destroys `user_pt`.
fn finish_user_space(user_pt: usize, e_entry: u64, brk_va: usize, mut frames: u32) -> Option<ExecContext> {
    // User stack
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let mut va = stack_bottom;
    while va < USER_STACK_TOP {
        frames = frames.saturating_add(1);
        // RFC-0049 M1c canary: populate the stack lazily, so a task takes a
        // demand fault on its first stack touch. A `mem = "locked"` row must
        // then report faults > 0 and its gate row must fail. Never in a
        // normal build: the stack is eager, which is why a locked task does
        // not fault.
        #[cfg(feature = "mem-locked-canary")]
        {
            if azos_mm::demand::map_demand(
                user_pt, va, PagePerms { accessed: true, ..PagePerms::USER_RW },
            ).is_err() {
                return None;
            }
            va += PAGE_SIZE;
            continue;
        }
        #[allow(unreachable_code)]
        let page = pmm::alloc_page().ok()?;
        if vmm::map(
            user_pt, va, page.as_usize(),
            PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW },
        ).is_err() {
            let _ = pmm::free_page(page);
            return None;
        }
        va += PAGE_SIZE;
    }

    // Map vDSO page (read-only) so user-space can read kernel time data
    // without issuing an ecall.
    //
    // Gated by `VDSO_FITS_BELOW_USER_CEILING`: this call runs *before* the
    // `kernel_entry_collision` check below, on a user root that has no
    // kernel entries yet, so `vmm::map` would happily install a user-owned
    // L1 at whatever VPN[2] `vdso::VDSO_USER_BASE` falls in — including one
    // the kernel's own identity map claims, if it ever did again. Mapping it
    // anyway would turn "vDSO missing, ecall fallback" (the documented,
    // non-fatal case below) into "exec refused", for a mapping the loader
    // added on its own rather than one the image asked for. As of the
    // 2026-09-22 fix this gate and `crates/drivers/base/src/platform.rs`'s
    // per-board `const` asserts both hold for every board, so this branch
    // should always be taken — the readback below is what actually proves
    // that on hardware whose installed RAM the compile-time asserts cannot
    // see (VF2/K1 DTB-sized RAM; see `crates/core/abi/src/vdso.rs`).
    let vdso_phys = vdso::vdso_phys();
    if vdso_phys != 0 && VDSO_FITS_BELOW_USER_CEILING {
        // A failure here is not fatal — the vDSO is an optimisation and
        // userspace falls back to the ecall path. It cannot collide with the
        // image either (USER_LOW_MAX) or the stack (different VPN[1]) —
        // and, now, it is not even attempted where it would collide with the
        // kernel's own RAM map instead.
        let map_result = vmm::map(
            user_pt,
            vdso::VDSO_USER_BASE,
            vdso_phys,
            PagePerms { accessed: true, ..PagePerms::USER_RO },
        );
        // A readback, not just "map returned
        // Ok" — `translate` walks the SAME user page table `map` just wrote
        // and reports what is actually there, which is the only thing that
        // discriminates "mapped at the address we asked for" from "map
        // silently landed somewhere else" or "map returned Ok but the PTE
        // reads back invalid" (lesson from gate 143: a persistence claim
        // must print after the write, read back). Checked on every exec —
        // cheap (one page-table walk of an already-hot table) and this is
        // the one place this fact is knowable; a boot-time-only check would
        // miss a per-process page-table bug. A mismatch always prints.
        match vmm::translate(user_pt, vdso::VDSO_USER_BASE) {
            // Wave 14: the success line is debug output (owner: console
            // output only in debug modes; feature `spawn-log`); no gate row
            // reads it. The two lines below, which report a fallback, stay.
            Some(pa) if map_result.is_ok() && pa == vdso_phys => {
                if cfg!(feature = "spawn-log") {
                    azos_drv_sys::kprintln!(
                        "[VDSO] mapped: user VA {:#x} -> PA {:#x} (readback OK)",
                        vdso::VDSO_USER_BASE, pa,
                    );
                }
            }
            // Neither arm below uses the `FAILED:` prefix the gate greps for
            // a row failure: this branch (`VDSO_FITS_BELOW_USER_CEILING`
            // true, map attempted) is expected to always succeed on the
            // four boards this task covers, proven by the compile-time
            // asserts — but the vDSO is documented as an optimisation ring
            // 3 falls back from (ecall path), never a hard requirement, so
            // a real board this task did not enumerate (DTB-sized RAM on
            // VF2/K1 real hardware) must not turn a soft fallback into a
            // gate-failing row.
            Some(pa) => {
                azos_drv_sys::kwarn!(
                    "[VDSO] not mapped as requested: user VA {:#x} reads back PA {:#x}, \
                     expected {:#x} (map result {:?}) — falling back to the ecall path",
                    vdso::VDSO_USER_BASE, pa, vdso_phys, map_result,
                );
            }
            None => {
                azos_drv_sys::kwarn!(
                    "[VDSO] not mapped: user VA {:#x} unmapped after vmm::map (result {:?}) — \
                     falling back to the ecall path",
                    vdso::VDSO_USER_BASE, map_result,
                );
            }
        }
    }

    // Wave 13: the riscv64 sigreturn trampoline, read-execute, the page after
    // the vDSO (`vdso::SIGTRAMP_USER_VA`). Shared, never written by a task:
    // a fork shares the leaf as it is (`cow::fork_cow`) and teardown never
    // frees it. Absent (0) on aarch64, whose musl passes its own restorer. A
    // failure is not fatal: a handler without its return path is refused at
    // delivery and the task ends as the default action would end it.
    let tramp = vdso::sigtramp_phys();
    if tramp != 0 && VDSO_FITS_BELOW_USER_CEILING && vdso::SIGTRAMP_USER_VA < USER_STACK_TOP {
        let _ = vmm::map(
            user_pt,
            vdso::SIGTRAMP_USER_VA,
            tramp,
            PagePerms { accessed: true, ..PagePerms::USER_RX },
        );
    }

    // ── Kernel entries — LAST, and after this point nothing may fail ────────
    //
    // Refuse the image if merging the kernel's mappings would have to drop one
    // of them because a user mapping already owns the slot. Losing, say, the
    // CLINT in this address space is not a load-time error: the process starts
    // and then the first timer interrupt taken under its SATP faults in S-mode
    // on an address the kernel believes is identity-mapped. Checking before
    // the copy also keeps the teardown above valid — it must never see a page
    // table holding pointers into the kernel's own tables.
    if let Some((vpn2, vpn1)) = vmm::kernel_entry_collision(user_pt) {
        azos_drv_sys::kwarn!(
            "[EXEC] refused: image occupies kernel slot VPN2={} VPN1={}",
            vpn2, vpn1,
        );
        return None;
    }

    // Copy kernel L2/L1 entries into the user PT so that the trap handler
    // (trap_vector at ~0x80200000) and MMIO (UART, CLINT, etc.) are
    // reachable in S-mode when an ecall fires with the user PT active.
    // Kernel pages have no USER bit — U-mode cannot access them directly.
    vmm::copy_kernel_entries_to_user(user_pt);

    let user_satp = make_satp(user_pt, crate::alloc_asid()) as u64;
    let user_sp   = (USER_STACK_TOP - 16) as u64;
    // sstatus: SPP=0 (U-mode), SPIE=1 (enable interrupts after SRET), SIE=0
    let sstatus   = 1u64 << 5; // SPIE

    Some(ExecContext {
        satp:    user_satp,
        entry:   e_entry,
        user_sp,
        sstatus,
        user_pt: user_pt as u64,
        brk:     brk_va as u64,
        frames,
    })
}

// ── SRET to user mode ─────────────────────────────────────────────────────────

/// Publish `satp` as this hart's translation root (`tlb::AZOS_HART_SATP`)
/// before an `sret_to_user*` installs it. Both used to write `satp` without
/// publishing, so a forked child ran ring 3 on a hart whose record still
/// named the kernel root: a shootdown of the child's table skipped that hart,
/// and the free-time check (`Mmu::root_holders`) could not see it either.
///
/// Interrupts go off first, and the asm that follows keeps them off until the
/// `sret`: published but not yet installed, a switch away from this task
/// compares the incoming root with the LIVE `satp`, skips when they match
/// (idle after a kernel task), and would leave this hart publishing a root it
/// never ran — a table the free check then refuses to release.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn publish_user_root(satp: usize) {
    use azos_arch::csr;
    csr::write_sstatus(csr::read_sstatus() & !csr::SSTATUS_SIE);
    azos_arch::tlb::publish(azos_arch::Cpu::hart_id(&ARCH), satp);
}

/// Switch from kernel S-mode to user U-mode.  Never returns.
///
/// Sets sscratch = current kernel SP (so the next U-mode trap can find the
/// kernel stack), switches to the user page table, then SRETs to `entry`.
///
/// # Safety
/// Caller must guarantee `entry` and `user_sp` are valid user-space addresses.
#[cfg(target_arch = "riscv64")]
pub unsafe fn sret_to_user(entry: usize, user_sp: usize, satp: usize) -> ! {
    publish_user_root(satp);
    let sspie: usize = 1 << 5; // SPIE bit — interrupts enabled in U-mode
    core::arch::asm!(
        // `sstatus` first: it clears SIE, and an interrupt taken after `sepc`
        // is set but before interrupts are off overwrites `sepc` with kernel
        // text, sending the `sret` below into U-mode at a kernel address.
        // See the long note in `sret_to_user_forked`, where the same ordering
        // was measured killing a forked child before its first instruction.
        // This path runs once per exec rather than once per fork, so its
        // exposure was far lower -- not absent.
        "csrw  sstatus, {sspie}",   // SPP=0 (U-mode), SPIE=1, SIE=0
        "csrw  sepc, {entry}",      // sepc = user entry point
        "csrw  sscratch, sp",       // sscratch = kernel SP (for re-entry)
        "csrw  satp, {satp}",       // switch page table
        "sfence.vma zero, zero",
        "mv    sp, {user_sp}",      // switch to user stack
        // K-C18: zero EVERY general-purpose register, not just a0-a7.
        //
        // **WHY the old version was a live kernel-pointer leak.** Only the
        // argument registers were cleared, so a fresh process entered its ELF
        // entry point with `ra`, `gp`, `t0..t6` and `s0..s11` still holding
        // whatever the kernel task that ran the loader had left in them.
        // Observed in a real run: `regs[1] (ra) = 0x8020198a`, a kernel text
        // address, handed to ring 3 at every exec. That defeats any layout
        // randomisation and gives an unprivileged task a free oracle.
        //
        // It was also a crash. Nothing in the RISC-V ELF entry ABI defines
        // these registers, so a program is entitled to `ret` from a leaf that
        // never set `ra` — and that jumps straight into kernel text. Measured:
        // `[PAGE FAULT] Instruction page fault at 0x80244110` (inside
        // `_start`..`_text_end`), task killed. The guard held, so this was
        // never an escalation, but the pointer had no business being there.
        //
        // **And K-C11 made it inheritable.** Now that fork faithfully copies
        // the parent's whole register file to the child, a parent that never
        // overwrote its garbage `ra` passes it on. Fixing the loader is what
        // stops the garbage existing in the first place; the fork path is
        // correct to copy whatever it finds.
        //
        // `sp` is set above and `tp` is deliberately left holding the kernel's
        // hart id — see `sret_to_user_forked` for why touching it is the one
        // change that would reintroduce K-A11.
        "li ra,0", "li gp,0",
        "li t0,0","li t1,0","li t2,0","li t3,0","li t4,0","li t5,0","li t6,0",
        "li s0,0","li s1,0","li s2,0","li s3,0","li s4,0","li s5,0",
        "li s6,0","li s7,0","li s8,0","li s9,0","li s10,0","li s11,0",
        "li a0,0","li a1,0","li a2,0","li a3,0",
        "li a4,0","li a5,0","li a6,0","li a7,0",
        "sret",
        entry   = in(reg) entry,
        sspie   = in(reg) sspie,
        satp    = in(reg) satp,
        user_sp = in(reg) user_sp,
        options(noreturn),
    )
}

/// aarch64: a task's first entry into a fresh EL0 image — the ISA
/// counterpart of the RISC-V `sret` body above.
///
/// Delegates to the kernel's `aarch64_enter_user`
/// (`kernel/src/entry/aarch64.rs`), which builds an ordinary `TrapFrame`
/// (every GPR zero — the K-C18 property: no kernel register value reaches
/// ring 3, `x18` included; `SPSR_EL1` = EL0t with DAIF clear; `ELR_EL1` =
/// `entry`; `SP_EL0` = `user_sp`), drops the task's lazy FP state, and
/// returns through the same `trap_return` tail every trap uses
/// (`kernel/src/entry/aarch64/asm/trap_entry.S`): DAIF masked before
/// `ELR_EL1`/`SPSR_EL1`/`SP_EL0`/`TTBR0_EL1` are written (the ordering this
/// function used to carry its own copy of), `TTBR0_EL1` switched only when
/// `satp != 0`. One EL0-return sequence instead of three.
///
/// # Safety
/// Caller must guarantee `entry` and `user_sp` are valid user-space
/// addresses and `satp` (a `TTBR0_EL1` physical address, or `0` to keep the
/// table already installed) names a page table that maps `entry` as
/// EL0+executable and `user_sp`'s page as EL0+writable.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn sret_to_user(entry: usize, user_sp: usize, satp: usize) -> ! {
    unsafe extern "C" {
        fn aarch64_enter_user(entry: u64, user_sp: u64, ttbr0: u64) -> !;
    }
    unsafe { aarch64_enter_user(entry as u64, user_sp as u64, satp as u64) }
}

/// x86_64: delegates to the kernel's `x86_64_enter_user`
/// (`kernel/src/entry/x86_64.rs`), which builds a `TrapFrame` (every GPR
/// zero, user selectors, IF set) and returns through `trap_entry.S`'s
/// `trap_return` like every trap: CR3 when `satp != 0`, the initial FP
/// state, then `iretq`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn sret_to_user(entry: usize, user_sp: usize, satp: usize) -> ! {
    unsafe extern "C" {
        fn x86_64_enter_user(entry: u64, user_sp: u64, cr3: u64) -> !;
    }
    unsafe { x86_64_enter_user(entry as u64, user_sp as u64, satp as u64) }
}

/// Any further ISA: not ported.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))))]
pub unsafe fn sret_to_user(_entry: usize, _user_sp: usize, _satp: usize) -> ! {
    todo!("sret_to_user: not ported to this ISA")
}

/// SRET into user mode restoring a forked child's **complete** register file
/// (K-C11). Fork-only; a fresh `exec` still uses [`sret_to_user`].
///
/// `regs` is the parent's trap frame in `x0..x31` order. It must point at
/// memory reachable *after* `satp` is switched — in practice the caller's
/// kernel stack; see `scheduler::take_current_task_fork_ctx`.
///
/// ## What is deliberately NOT restored
///
/// **`tp` (x4) IS restored** (RFC-0047 stage 3): the child gets its
/// parent's thread pointer, which a Linux (musl) child dereferences at once
/// for its thread descriptor. This was skipped while `trap_entry.S` ran the
/// kernel on the user's `tp`; since K-C16 every trap from U-mode re-derives the
/// kernel `tp` (the hart id) from `stvec`, so a user `tp` never reaches kernel
/// context and the K-A11 concern no longer applies.
///
/// **`x0`** is hardwired zero, and **`a0`** is forced to 0 last: `fork()`
/// returns 0 in the child, and that must survive the restore.
///
/// # Safety
/// Switches `satp` and never returns. `entry`, `satp` and `regs` must all
/// describe the same, fully-published child context.
#[cfg(target_arch = "riscv64")]
pub unsafe fn sret_to_user_forked(entry: usize, satp: usize, regs: &crate::task::UserRegs) -> ! {
    publish_user_root(satp);
    let sspie: usize = 1 << 5; // SPIE — interrupts enabled in U-mode, SPP=0
    let base = regs.as_ptr();
    core::arch::asm!(
        // **`sstatus` BEFORE `sepc`, and the order is the whole point.**
        //
        // `sspie` clears SIE, so this write is what closes the door on S-mode
        // interrupts. Writing `sepc` first left exactly one instruction
        // boundary during which interrupts were still enabled and `sepc`
        // already held the user entry point. An interrupt taken there makes
        // the hardware overwrite `sepc` with the address of the very next
        // instruction; the trap handler saves and restores that value and
        // returns here in S-mode, so the CSR now points at kernel text
        // instead of the user program. Execution then walks on through
        // `satp`, restores the register block and `sret`s -- straight to a
        // kernel address in U-mode. Instruction page fault, "Killing user
        // task", and a forked child that never executed one byte of its own
        // code.
        //
        // Measured, not theorised: one run in a hundred of the ring-3
        // `ipctest` scenario lost a phase-A child this way. `tid=129` appears
        // nowhere in 56,509 lines of that log, the only `[PAGE FAULT]` in two
        // hundred captured runs sits between two forks, and its address --
        // 0x80240b52 in that build -- disassembles to exactly the
        // `csrw sstatus` that followed the `csrw sepc`. The parent then
        // blocked forever in `fast_ipc_accept` waiting for two hundred calls
        // from a task the kernel had killed at birth, which is what the
        // scenario reported as an unexplained wedge.
        //
        // With SIE cleared first, every CSR write and the whole register
        // restore below are atomic with respect to interrupts.
        //
        // CSRs first: every asm input is consumed before any GPR is clobbered.
        "csrw  sstatus, {sspie}",
        "csrw  sepc, {entry}",
        "csrw  sscratch, sp",        // kernel SP, for the next trap's re-entry
        "csrw  satp, {satp}",
        "sfence.vma zero, zero",
        // t0 is the base pointer from here on; it is reloaded from its own
        // slot as the very last GPR so the block stays addressable throughout.
        "mv    t0, {base}",
        "ld    x1,   8(t0)",         // ra
        "ld    x2,  16(t0)",         // sp  — user stack, from the frame itself
        "ld    x3,  24(t0)",         // gp
        "ld    x4,  32(t0)",         // tp — the parent's own; see the doc above
        "ld    x6,  48(t0)",         // t1
        "ld    x7,  56(t0)",         // t2
        "ld    x8,  64(t0)",         // s0/fp
        "ld    x9,  72(t0)",         // s1
        "ld    x10, 80(t0)",         // a0 (overwritten with 0 below)
        "ld    x11, 88(t0)",         // a1
        "ld    x12, 96(t0)",         // a2
        "ld    x13, 104(t0)",        // a3
        "ld    x14, 112(t0)",        // a4
        "ld    x15, 120(t0)",        // a5
        "ld    x16, 128(t0)",        // a6
        "ld    x17, 136(t0)",        // a7
        "ld    x18, 144(t0)",        // s2
        "ld    x19, 152(t0)",        // s3
        "ld    x20, 160(t0)",        // s4
        "ld    x21, 168(t0)",        // s5
        "ld    x22, 176(t0)",        // s6
        "ld    x23, 184(t0)",        // s7
        "ld    x24, 192(t0)",        // s8
        "ld    x25, 200(t0)",        // s9
        "ld    x26, 208(t0)",        // s10
        "ld    x27, 216(t0)",        // s11
        "ld    x28, 224(t0)",        // t3
        "ld    x29, 232(t0)",        // t4
        "ld    x30, 240(t0)",        // t5
        "ld    x31, 248(t0)",        // t6
        "ld    x5,  40(t0)",         // t0 — base register, restored last
        "li    a0, 0",               // fork() returns 0 in the child
        "sret",
        entry = in(reg) entry,
        sspie = in(reg) sspie,
        satp  = in(reg) satp,
        base  = in(reg) base,
        options(noreturn),
    )
}

/// aarch64 counterpart of the riscv64 `sret_to_user_forked` above — a
/// forked child's first entry into EL0 with the parent's **complete**
/// AArch64 EL0 context (31 GPRs, `SP_EL0`, `SPSR_EL1`, `TPIDR_EL0`, the FP
/// state) from `regs` ([`crate::task::UserRegs`],
/// `azos_arch::fork_regs::ForkRegs` on this ISA — see that struct's
/// module doc for why it is not `[u64; 32]`), x0 = 0, resuming at `entry`.
///
/// Delegates to the kernel's `aarch64_enter_user_forked`
/// (`kernel/src/entry/aarch64.rs`), which makes the parent's FP state the
/// child's saved lazy-FP state, builds a `TrapFrame` from `regs` and
/// returns through the same `trap_return` tail every trap uses
/// (`kernel/src/entry/aarch64/asm/trap_entry.S`), `TPIDR_EL0` written with
/// IRQs masked just before it.
///
/// `entry` is the child's `ELR_EL1` — already the correct "instruction
/// after the parent's `svc`" value computed by `sys_fork_impl`'s
/// `child_resume_pc` (aarch64's raw `ELR_EL1`, UNCHANGED — the ARM ARM
/// already leaves it past the `svc`, unlike RISC-V's `sepc`). `SPSR_EL1` is
/// restored verbatim from `regs`: NZCV/DAIF at the instant of the parent's
/// `svc` are part of what the child clones.
///
/// # Safety
/// Switches `TTBR0_EL1` and never returns. `entry`, `satp` and `regs` must
/// all describe the same, fully-published child context — same contract as
/// riscv64's `sret_to_user_forked`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn sret_to_user_forked(entry: usize, satp: usize, regs: &crate::task::UserRegs) -> ! {
    unsafe extern "C" {
        fn aarch64_enter_user_forked(
            entry: u64,
            ttbr0: u64,
            regs: *const crate::task::UserRegs,
        ) -> !;
    }
    unsafe { aarch64_enter_user_forked(entry as u64, satp as u64, regs) }
}

/// x86_64: delegates to the kernel's `x86_64_enter_user_forked`
/// (`kernel/src/entry/x86_64.rs`): the child's registers from `regs`
/// (`azos_arch::fork_regs::ForkRegs`, with its XSAVE image), rax = 0, FS/GS
/// bases, then `trap_return`'s `iretq`. `entry` is the parent's RIP after
/// its `syscall`, unchanged (`child_resume_pc`).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn sret_to_user_forked(entry: usize, satp: usize, regs: &crate::task::UserRegs) -> ! {
    unsafe extern "C" {
        fn x86_64_enter_user_forked(entry: u64, cr3: u64, regs: *const crate::task::UserRegs) -> !;
    }
    unsafe { x86_64_enter_user_forked(entry as u64, satp as u64, regs) }
}

/// Any further ISA: not ported.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))))]
pub unsafe fn sret_to_user_forked(_entry: usize, _satp: usize, _regs: &crate::task::UserRegs) -> ! {
    todo!("sret_to_user_forked: not ported to this ISA")
}

// ── User-space memory access ──────────────────────────────────────────────────

/// Copy `len` bytes FROM user virtual address `user_src` INTO kernel buffer `kernel_dst`.
///
/// When the current task has a user PT (user_pt != 0), each source page is
/// translated via [`vmm::translate_user`] — which enforces `VALID + USER +
/// READ`, rejecting kernel/MMIO addresses — and copied from the physical
/// address a page at a time.  For kernel tasks (user_pt == 0) the pointer is
/// trusted and used directly; that path is unreachable from U-mode (a task
/// that ran an ELF via `exec_user`, or a forked child, always has
/// `user_pt != 0` set before it can issue a syscall).
///
/// Hostile-input handling (must never panic under `overflow-checks = true`):
///   - `len == 0` → success, no walk.
///   - `user_src + len` wrapping the address space → reject.
///   - a range that starts in valid user memory and crosses into an unmapped
///     or non-USER page → reject at that page (whole-range validation).
///   - NULL / near-NULL → the zero page is not USER-mapped → reject.
///
/// Returns `true` on success, `false` on any unmapped/forbidden page.
///
/// **O3.2 (owner decision, PAN/SUM) — why the [`UserAccess`] guard around
/// this function's own access does not protect THIS access.** The
/// per-page read below goes through `azos_mm::addr::phys_to_virt(pa)`
/// — the kernel's OWN mapping of that physical frame (`U=0`/no `AP_EL0` on
/// aarch64; a plain kernel VA on riscv64), never the user's own `U=1`/
/// `AP_EL0` mapping of the same page. Neither PAN nor `SUM=0` gates a
/// `U=0` translation at all, so `translate_user`'s own permission check
/// (`VALID + USER + READ`) is what makes this specific line safe, not the
/// guard. The guard is placed here anyway, matching the coordinator's
/// explicit instruction, as the narrow, auditable window this codebase's
/// ONE legitimate user-memory reader opens — so a FUTURE change to this
/// function (or a different function that copies its shape) which starts
/// dereferencing the user's own VA directly, instead of going through
/// `phys_to_virt`, still faults outside this window instead of silently
/// working. The bug PAN/SUM catch lives in code that skips this function
/// entirely.
pub fn copy_from_user(kernel_dst: *mut u8, user_src: usize, len: usize) -> bool {
    if len == 0 { return true; }
    // Reject a length that wraps `user_src` past the end of the address space.
    // Once this holds, every `user_src + done` below (done < len) is provably
    // non-overflowing.
    if user_src.checked_add(len).is_none() { return false; }

    let user_pt = crate::scheduler::current_user_pt();
    if user_pt == 0 {
        // Kernel task — identity-mapped; pointer is trusted.
        unsafe { core::ptr::copy_nonoverlapping(user_src as *const u8, kernel_dst, len); }
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let va   = user_src + done;
        let Some(pa) = vmm::translate_user(user_pt, va, false) else { return false; };
        let chunk = (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
        // O3.2: PAN/SUM window around the one access that touches this
        // page's contents. `translate_user` above already validated
        // `VALID + USER + READ` against the page table — this guard is not
        // what makes THIS access safe (that is `translate_user`'s job);
        // it is what keeps a FUTURE bug that skips `translate_user` and
        // dereferences a raw user VA directly from silently succeeding
        // outside this narrow window.
        {
            let _ua = ARCH.user_access();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    azos_mm::addr::phys_to_virt(pa) as *const u8,
                    kernel_dst.add(done),
                    chunk,
                );
            }
        }
        done += chunk;
    }
    true
}

/// Copy `len` bytes FROM kernel buffer `kernel_src` INTO user virtual address `user_dst`.
///
/// Each destination page is validated via [`vmm::translate_user`] with
/// `write = true`, which enforces `VALID + USER + WRITE` and rejects
/// kernel/MMIO addresses. A copy-on-write page (shared read-only after
/// `fork`) is broken into a private copy before the write, so a legitimate
/// post-fork write lands in the caller's own page instead of the previously
/// unchecked path silently writing the page still shared with the parent.
///
/// Same hostile-input handling as [`copy_from_user`]: `len == 0` → success,
/// wrapping range → reject, cross into non-USER/unmapped page → reject,
/// NULL → reject. Never panics.
///
/// Returns `true` on success, `false` on any forbidden/unmapped page.
/// Can `len` bytes be written at `user_dst` right now?
///
/// **NO PRODUCTION CALLER TODAY, and that is deliberate — owner decision,
/// 2026-09-19.** All three callers this was written for
/// (`sys_port_wait_typed`, `sys_driver_poll_event`, `sys_driver_fetch_request`)
/// moved to [`user_range_prepare_write`], because each of them CONSUMES
/// something it cannot put back and therefore needs a guarantee rather than an
/// answer: a copy-on-write leaf reports writable here and can still fail in
/// `copy_to_user` when the COW break finds no free page.
///
/// Kept rather than deleted, by the owner's call: this is the honest
/// non-mutating query that decision 100c produced, and the rule it embodies —
/// a function named as a question must not allocate — is the reason
/// `user_range_prepare_write` had to be a separate, differently-named
/// function instead of this one quietly regaining its side effect.
///
/// **If you are about to use this: are you sure you do not want
/// `user_range_prepare_write`?** Anything that consumes state before copying
/// out does.
///
/// The check a syscall needs BEFORE it does something it cannot undo.
///
/// `copy_to_user` reports failure after the fact, which is fine when the
/// syscall has only read state — it returns an error and nothing is lost. It is
/// not fine when the syscall has already consumed something. Two handlers were
/// found doing exactly that: `sys_driver_fetch_request` POPS a client's request
/// off the queue and then copies it out, and `sys_driver_poll_event` clears the
/// latched IRQ flag and then copies. A destination whose base is mapped but
/// whose tail runs into an unmapped page — the narrowest possible bad pointer,
/// and one a buggy driver hits by accident — makes the copy fail, the syscall
/// return -1, and the request or the interrupt is gone. No other consumer will
/// ever see it and the client waits forever.
///
/// Walks the same pages, with the same write permission, that `copy_to_user`
/// would. There is no TOCTOU window worth guarding: the only writer of this
/// task's page table is its own page-fault handler, synchronous on this hart.
///
/// Returns true for kernel context, where `copy_to_user` does an unchecked raw
/// copy and there is nothing to validate against.
pub fn user_range_writable(user_dst: usize, len: usize) -> bool {
    if len == 0 { return true; }
    if user_dst.checked_add(len).is_none() { return false; }
    let user_pt = crate::scheduler::current_user_pt();
    if user_pt == 0 { return true; }

    let mut done = 0usize;
    while done < len {
        let va = user_dst + done;
        // **A question, not an action** (owner decision 100c).
        //
        // This used to call `translate_user(.., true)`, which on a COW leaf
        // runs `handle_cow_fault` and ALLOCATES a private copy. So a range
        // that was only being CHECKED got its pages copied, and a check that
        // then failed for another reason had already paid for them — a
        // function named as a query, mutating the address space.
        //
        // The probe reports a COW leaf as writable, because a write to it will
        // succeed: `copy_to_user` breaks the COW at the moment it is needed.
        //
        // **NO TEST PROVES THIS, and here is what one would need.** A test was
        // written and withdrawn because its canary did not discriminate: a
        // freshly mapped COW page has refcount 1, so `handle_cow_fault` takes
        // its sole-owner path and flips `WRITE` in place WITHOUT allocating —
        // the page count a test watches never moves, with or without this fix.
        // A real test has to build a page with refcount >= 2 (via the COW
        // refcount table, `crates/core/mm/src/cow_table.rs`) so the handler must
        // copy, and then assert the leaf still lacks `WRITE` afterwards, which
        // needs a flags accessor this crate does not have today.
        // Every caller of this function validates a fixed, small output buffer
        // (8 bytes, a `PortEvent`, a `DriverRequest`) — none takes a length
        // from ring 3 — so this was never the memory-amplification vector it
        // first looked like. It is a correctness-of-naming fix, priced as one.
        if !vmm::user_write_would_be_permitted(user_pt, va) { return false; }
        done += (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
    }
    true
}

/// Make `len` bytes at `user_dst` writable NOW, so the `copy_to_user` that
/// follows cannot fail for a permission or allocation reason.
///
/// **This is an action, and it is named as one.** Owner decision 100c removed
/// the COW break from `user_range_writable` because a function named as a
/// query must not mutate the address space — that stands. What 100c left
/// behind is that the three callers never wanted a query: each of them
/// CONSUMES something it cannot put back (`sys_port_wait_typed` dequeues an
/// event, `sys_driver_poll_event` clears a latched IRQ,
/// `sys_driver_fetch_request` pops a request) and then copies out. A query
/// cannot give them what they need.
///
/// **The gap it closes, verified rather than reasoned:** a copy-on-write leaf
/// answers `true` to `user_range_writable`, because a write to it *will*
/// succeed — normally. `translate_user(.., true)` breaks the COW through
/// `handle_cow_fault`, whose first act is `pmm::alloc_page()?`
/// (`crates/core/mm/src/cow.rs:245`). Under memory exhaustion that returns `None`,
/// `copy_to_user` answers `false`, and the event, the interrupt or the request
/// is gone — the exact loss `user_range_writable` was introduced to prevent,
/// reachable whenever the destination sits in a page the task has not written
/// since it forked. Ring 3 can drive the allocator toward that state.
///
/// After this returns `true`, nothing between here and the copy can revoke the
/// permission: the only writer of this task's page table is its own fault
/// handler, which cannot run while this hart is inside the syscall.
///
/// On a partial failure the pages already broken stay broken. That is the cost
/// 100c objected to when a *check* paid it; here the caller was going to write
/// every one of those pages anyway, and the failure path is an allocator that
/// is already out of memory.
///
/// # NO TEST PROVES THIS, and here is what one would need
///
/// Three were written and withdrawn, each failing differently, which is why
/// the reasons are recorded instead of the tests:
///
///  1. **Assert the destination's physical address moved by the end of the
///     syscall.** It moves either way — `copy_to_user` breaks the COW a few
///     lines after the pop. The canary passed 252/252 against the reverted
///     fix. An end-state observable cannot separate "prepared before the pop"
///     from "broken after it".
///  2. **Drain the page allocator so the break must fail, then assert the
///     request survived.** That genuinely discriminates, and it is the shape a
///     real test wants — but `syscall-tests`' `serial()` does not cover
///     `mmap_guards.rs`, whose tests compare frame identity and free-page
///     counts and run concurrently. One new test became three red ones;
///     restoring the arena in LIFO order did not fix it.
///  3. **Test the two functions directly** (probe leaves the COW, preparation
///     breaks it). It passed — and its canary turned those same two
///     `mmap_guards` tests red, which showed they were passing only because of
///     how many pages the new test happened to allocate. A test that holds two
///     unrelated ones hostage to its allocation count is worse than none.
///
/// What is actually needed is per-test allocator isolation: `azos_mm` has
/// `shim_reset`, but nothing gives one test its own arena. Until that exists,
/// this function is held by reading — `handle_cow_fault`'s first statement is
/// `pmm::alloc_page()?` at `crates/core/mm/src/cow.rs:245` — and not by the suite.
/// Refcount 2 is the other half a real test must get right: at refcount 1 the
/// handler flips `WRITE` in place without allocating, and nothing observable
/// moves for either function.
///
/// Returns `true` for kernel context, where `copy_to_user` does an unchecked
/// raw copy and there is nothing to prepare.
pub fn user_range_prepare_write(user_dst: usize, len: usize) -> bool {
    if len == 0 { return true; }
    if user_dst.checked_add(len).is_none() { return false; }
    let user_pt = crate::scheduler::current_user_pt();
    if user_pt == 0 { return true; }

    let mut done = 0usize;
    while done < len {
        let va = user_dst + done;
        if vmm::translate_user(user_pt, va, true).is_none() { return false; }
        done += (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
    }
    true
}

pub fn copy_to_user(user_dst: usize, kernel_src: *const u8, len: usize) -> bool {
    if len == 0 { return true; }
    if user_dst.checked_add(len).is_none() { return false; }

    let user_pt = crate::scheduler::current_user_pt();
    if user_pt == 0 {
        unsafe { core::ptr::copy_nonoverlapping(kernel_src, user_dst as *mut u8, len); }
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let va   = user_dst + done;
        let Some(pa) = vmm::translate_user(user_pt, va, true) else { return false; };
        let chunk = (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
        // O3.2: see copy_from_user's own comment on this guard.
        {
            let _ua = ARCH.user_access();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    kernel_src.add(done),
                    azos_mm::addr::phys_to_virt(pa) as *mut u8,
                    chunk,
                );
            }
        }
        done += chunk;
    }
    true
}

/// Copy a NUL-terminated C string from user space into `dst` (at most
/// `dst.len()` bytes including the NUL). Returns the number of bytes copied
/// (excluding the NUL) on success, or `None` on fault / missing terminator /
/// forbidden address.
///
/// For user tasks this walks the page table **once per page** (not once per
/// byte): a page is resolved via [`vmm::translate_user`] (enforcing
/// `VALID + USER + READ`, so kernel/MMIO source addresses are rejected), then
/// scanned for the NUL up to the page boundary, re-walking only when the
/// scan crosses into the next page. `user_ptr + len` is guarded with
/// `checked_add` so a near-`usize::MAX` pointer rejects instead of panicking
/// under `overflow-checks = true`.
pub fn copy_cstr_from_user(dst: &mut [u8], user_ptr: usize) -> Option<usize> {
    let user_pt = crate::scheduler::current_user_pt();
    let mut len = 0usize;

    if user_pt == 0 {
        // Kernel task — trusted, identity-mapped. Bounded by `dst`.
        loop {
            if len >= dst.len() { return None; }
            let va = user_ptr.checked_add(len)?;
            let b = unsafe { *(va as *const u8) };
            dst[len] = b;
            if b == 0 { return Some(len); }
            len += 1;
        }
    }

    // User task — resolve and scan one page at a time.
    loop {
        if len >= dst.len() { return None; }
        let va = user_ptr.checked_add(len)?;
        let pa = vmm::translate_user(user_pt, va, false)?;
        // Bytes remaining in this physical page starting at `va`.
        let page_remaining = PAGE_SIZE - (va & (PAGE_SIZE - 1));
        let mut off = 0usize;
        while off < page_remaining {
            if len >= dst.len() { return None; }
            // `pa` is PHYSICAL (from `translate_user`); the kernel reads it
            // through its own mapping — identity on riscv64, upper half on
            // aarch64. O3.2 guard: see copy_from_user's own comment.
            let b = {
                let _ua = ARCH.user_access();
                unsafe { *((azos_mm::addr::phys_to_virt(pa) + off) as *const u8) }
            };
            dst[len] = b;
            if b == 0 { return Some(len); }
            len += 1;
            off += 1;
        }
        // Crossed the page boundary; next iteration re-walks the next page.
    }
}

// ── sys_brk ───────────────────────────────────────────────────────────────────

/// Implement the brk(2) syscall: extend or query the user heap.
///
/// - `addr == 0`: return current brk
/// - `addr > current_brk`: reserve the new pages (demand markers; allocated
///   at once only for a `mem = "locked"` task), advance brk, return new brk
/// - `addr < current_brk` (shrink): unsupported in Phase 7, return current brk
///
/// Hostile-input handling — `addr` comes straight from a ring-3 register:
///   - **No arithmetic may overflow.** With `panic = "abort"` +
///     `overflow-checks = true` an overflow is not a wrong answer, it is a
///     board reset: on a robot, a physical-safety event. `brk(u64::MAX)`
///     cleared every guard above and then overflowed the page-round-up.
///     [`page_up`] now saturates.
///   - **The heap is bounded** by [`USER_LOW_MAX`]. Unbounded, a single
///     `brk(0x7FFF_FFFF)` walks ~500K pages: it drains the PMM, and on the way
///     it maps over the kernel's MMIO slots and (further up) the user stack.
///   - **Mapping failures are not swallowed.** The old `let _ = vmm::map(..)`
///     dropped `AlreadyMapped` on the floor, leaking the page it had just
///     allocated on every repeated call over the same range.
pub fn sys_brk_impl(addr: u64) -> i64 {
    let user_pt = crate::scheduler::current_user_pt();
    if user_pt == 0 { return -1; } // kernel task

    let cur_brk = crate::scheduler::update_user_brk(0); // query
    if addr == 0 || addr == cur_brk { return cur_brk as i64; }
    if addr < cur_brk { return cur_brk as i64; } // shrink not supported

    // Saturating round-up: `u64::MAX` lands on `0xFFFF_FFFF_FFFF_F000`, which
    // the ceiling below then rejects — no wrap, no panic, no allocation.
    let new_brk = page_up(addr as usize) as u64;
    if new_brk > USER_LOW_MAX as u64 { return cur_brk as i64; }

    // Commit whatever we managed to map, so a partial extension is reported
    // honestly instead of handing back pages the caller cannot see.
    let commit = |va: usize| -> i64 {
        if va as u64 > cur_brk {
            crate::scheduler::update_user_brk(va as u64) as i64
        } else {
            cur_brk as i64
        }
    };

    // Allocate pages from cur_brk to addr. `va < new_brk <= USER_LOW_MAX`, so
    // the `va += PAGE_SIZE` below cannot overflow either.
    // Reserved, not allocated (wave 14), as Linux grows a heap: each page is
    // a demand marker, charged now (the reservation is what the budget
    // admits, as `sys_alloc_demand` charges it) and backed by a zeroed frame
    // at its first touch, by the task or by a copy into it
    // (`vmm::translate_user`). A heap grown and never touched used to cost
    // an allocation and a 4 KiB zero-fill per page, and then a refcount, two
    // entries and a teardown visit per page in every fork (vsbench: 200
    // such pages in each `fork+exit`). A `mem = "locked"` task never takes a
    // fault (RFC-0049): its heap is still allocated here, eagerly.
    let lazy = !crate::scheduler::current_mem_locked();
    let mut va = page_up(cur_brk as usize);
    while (va as u64) < new_brk {
        // Owner decision 102 — charge BEFORE allocating, one page at a time.
        //
        // Before the frame, because a charge that fails must leave the
        // allocator untouched; and per page rather than for the whole
        // extension, so a task at its budget still grows by whatever is left
        // of it instead of being refused outright. `commit` then reports the
        // honest partial answer, exactly as it does for OOM — to the caller a
        // budget refusal and an empty allocator look the same, which is
        // correct: both mean "this is all the memory you get".
        if !crate::scheduler::mm_charge(1) {
            return commit(va);
        }
        if lazy {
            match vmm::map_demand(
                user_pt, va,
                PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW },
            ) {
                Ok(()) => {}
                // Already a page or a reservation: kept, not charged twice.
                Err(KernelError::AlreadyMapped) => crate::scheduler::mm_discharge(1),
                Err(_) => {
                    crate::scheduler::mm_discharge(1);
                    return commit(va);
                }
            }
            va += PAGE_SIZE;
            continue;
        }
        let page = match pmm::alloc_page() {
            Ok(p) => p,
            Err(_) => {
                crate::scheduler::mm_discharge(1);
                return commit(va); // OOM — keep what we mapped
            }
        };
        match vmm::map(
            user_pt, va, page.as_usize(),
            PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW },
        ) {
            Ok(()) => {}
            Err(KernelError::AlreadyMapped) => {
                // Already backed (an image page overlapping the first heap
                // page, or a re-issued brk over the same range). Hand the
                // fresh frame straight back — the old code leaked it — and
                // the charge with it: this page was already somebody's, and
                // charging twice for one frame is the ratchet that would
                // eventually refuse a task memory it is entitled to.
                let _ = pmm::free_page(page);
                crate::scheduler::mm_discharge(1);
            }
            Err(_) => {
                let _ = pmm::free_page(page);
                crate::scheduler::mm_discharge(1);
                return commit(va);
            }
        }
        va += PAGE_SIZE;
    }
    crate::scheduler::update_user_brk(new_brk) as i64
}

// ── fork() ──────────────────────────────────────────────────────────────────

/// The address the CHILD must resume at — "the instruction after the
/// parent's syscall" — computed from the raw `sepc`/`ELR_EL1` this ISA's
/// trap entry handed to `syscall_dispatch_out`.
///
/// **The two ISAs disagree about what that raw value already points at,
/// and this is the one place fork's shared code must know it.** RISC-V's
/// `kernel/src/trap/exception.rs` passes `frame.sepc` UNADJUSTED — the hardware
/// leaves `sepc` pointing AT the `ecall` itself, and the trap handler's own
/// normal-return path only does `frame.sepc += 4` AFTER this call, on ITS
/// copy of the frame (see that call site's own comment) — so the fork path
/// must add the 4 bytes of `ecall`'s own encoding to land past it.
/// aarch64's `kernel/src/entry/aarch64.rs` passes `frame.elr_el1`, and the
/// ARM ARM (§D1.10, "Exceptions from an SVC, HVC, or SMC instruction")
/// already defines `ELR_ELx` as the address AFTER the `svc` by the time any
/// handler runs — `aarch64_trap_entry` never adds 4 to it, for the exact
/// same self-test-observed reason documented on that function's SVC arm.
///
/// **Getting this wrong is silent, not a crash.** Before this function
/// existed, `sys_fork_impl` did `sepc + 4` unconditionally — correct for
/// RISC-V, but on aarch64 (where `sepc` here is already `ELR_EL1`,
/// post-`svc`) it would have handed every forked child an entry PC one
/// instruction PAST the one the parent's `svc` actually returns to,
/// skipping whatever real instruction sits there — the same class of bug
/// `aarch64_trap_entry`'s own SVC arm found and fixed for the non-fork
/// return path, not yet fixed here because this path had no aarch64
/// implementation to expose it until now.
#[inline]
fn child_resume_pc(sepc: u64) -> u64 {
    #[cfg(target_arch = "riscv64")]
    { sepc + 4 }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    { sepc }
    // x86_64: `syscall` leaves RIP (RCX) past itself, like aarch64's ELR.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    { sepc }
    #[cfg(not(any(
        target_arch = "riscv64",
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "x86_64", target_os = "none"),
    )))]
    { sepc + 4 }
}

// ── Fork-refusal diagnostics ────────────────────────────────────────────
//
// `sys_fork_impl` returns the ABI-frozen wire value `-1` from SIX distinct
// sites, not five: `crates/core/libsys::fork` documents "negative on error" and
// every userspace caller (`crates/core/libsys`, `userspace/*`) treats any
// negative return as failure without inspecting a specific code, so
// changing the wire value is a real ABI question this fix does not need to
// answer -- `-1` stays. But that also means a `rc=-1` in a log cannot say
// which of the six fired, which is exactly what mis-filed an aarch64
// `fork+exit` failure as a known gap for a week. These counters make the
// next occurrence name itself.
//
// Not extracted into its own file or crate: `crates/core/sched/src/lib.rs`'s
// `mod` list is out of scope for this change (owned edit list), and
// `crates/core/abi`'s own charter ("Pure types only -- no kernel internals, no
// allocator") rules it out as a home for mutable runtime diagnostic state.
// It stays inline where all six call sites already are. That also means it
// is NOT reachable by any host `#[path]` pull -- `process.rs` is the
// RV64+aarch64 task-table/ELF-loader module `tests/host/syscall-tests/shims/
// sched/src/lib.rs` already documents as un-pullable to the host (it pulls
// in `azos_mm`, `azos_arch`, `azos_arch_api`, none of which
// build for the host target). No host test below duplicates this logic as
// a twin; the QEMU row is the proof (see `row-fork-refusal-sites.sh`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ForkRefusalSite {
    /// Parent is a kernel task (`current_user_pt() == 0`) — cannot fork.
    KernelTask = 0,
    /// `vmm::fork_cow` returned `Err` (COW page-table setup failed).
    CowFailed = 1,
    /// The child's user layout collides with a kernel page-table slot.
    KernelSlotCollision = 2,
    /// `try_task_create_affinity` returned `None` — the fork-bomb guard:
    /// the task pool (`MAX_TASKS`) is exhausted.
    PoolExhausted = 3,
    /// `tid_for_idx` returned `None` for the slot claimed lines earlier in
    /// this same call. Documented unreachable ("the slot was just
    /// allocated"); defensive only.
    TidLookupMiss = 4,
    /// `set_task_fork_ctx`'s identity check failed: the child's slot
    /// stopped being the child's between claim and publish. Documented
    /// unreachable while the child is waiting ("it never exits before
    /// consuming"); defensive only, a slot-reuse race guard.
    ForkCtxIdentityMiss = 5,
    /// RFC-0049 P2: the parent is `mem = "locked"`; a locked task never forks.
    MemLocked = 6,
    /// RFC-0049 M1: the child's page tables alone exceed the budget it would
    /// inherit.
    MemBudget = 7,
}

const FORK_REFUSAL_SITES: usize = 8;

static FORK_REFUSAL_COUNTS: [core::sync::atomic::AtomicU32; FORK_REFUSAL_SITES] = [
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
];

fn fork_refusal_site_name(site: ForkRefusalSite) -> &'static str {
    match site {
        ForkRefusalSite::KernelTask => "kernel-task",
        ForkRefusalSite::CowFailed => "cow-failed",
        ForkRefusalSite::KernelSlotCollision => "kernel-slot-collision",
        ForkRefusalSite::PoolExhausted => "pool-exhausted",
        ForkRefusalSite::TidLookupMiss => "tid-lookup-miss",
        ForkRefusalSite::ForkCtxIdentityMiss => "fork-ctx-identity-miss",
        ForkRefusalSite::MemLocked => "mem-locked",
        ForkRefusalSite::MemBudget => "mem-budget",
    }
}

/// Record a refusal at `site`; always returns `-1`, so call sites read
/// `return note_fork_refusal(ForkRefusalSite::X);` in place of `return -1;`.
///
/// Saturating: this profile is `panic = "abort"` + `overflow-checks = true`,
/// and atomics bypass overflow checks entirely, so a bare `fetch_add` would
/// silently wrap to 0 at `u32::MAX` instead of panicking or saturating --
/// exactly backwards for a diagnostic counter. The pattern (load ->
/// saturating_add -> store) matches `note_stalled_tick`
/// (`crates/core/actuation/src/watchdog.rs`) and `note_cow_break`
/// (`crates/core/mm/src/cow_table.rs`).
///
/// Unlike `note_stalled_tick` (hart-0-owned by construction), fork can run
/// concurrently on any hart, so two simultaneous refusals at the same site
/// can race the load and lose an increment. Accepted for a best-effort
/// diagnostic: nothing downstream needs an exact count, only "did this ever
/// fire" and "roughly how often" — the same standard `mm_quota_refusals`
/// and `cow_break_frames` already hold to.
///
/// Cost on the four sites that are already error paths (`CowFailed`,
/// `KernelSlotCollision`, `PoolExhausted`, `TidLookupMiss`) is a load, a
/// saturating add and a store on a path that was about to return anyway —
/// nearly free per the design brief. `KernelTask` is the one call site NOT
/// already on an error path (it is the entry check), so this is the one
/// site where the load/store is pure added cost on `sys_fork_impl`'s
/// measured path — still a handful of instructions, not a lock or a scan.
///
/// Prints a ONE-SHOT `[FORK]` line the first time a given site is EVER hit
/// (the 0 -> 1 transition), so the next real occurrence names itself in the
/// serial log without a `kprintln!` on every fork failure. This is the
/// both-ISA reader: `kprintln!` via `azos_drv_sys` builds for riscv64
/// and aarch64 alike, unlike `kernel/src/trap/interrupt.rs`'s periodic census dump,
/// which is riscv64-only and `ipc-census`-gated (see that file's own
/// `#[cfg(target_arch = "riscv64")]` note on `dump_sched_counters`). The
/// census dump also gets a line reading these same counters back, as a
/// second, coarser reader for builds that have it — but this one-shot print
/// is what actually reaches aarch64 by default.
#[inline]
fn note_fork_refusal(site: ForkRefusalSite) -> i64 {
    let c = &FORK_REFUSAL_COUNTS[site as usize];
    let prev = c.load(core::sync::atomic::Ordering::Relaxed);
    c.store(prev.saturating_add(1), core::sync::atomic::Ordering::Relaxed);
    if prev == 0 {
        azos_drv_sys::kprintln!(
            "[FORK] refusal site first hit: {}",
            fork_refusal_site_name(site),
        );
    }
    -1
}

/// Current counts, indexed by `ForkRefusalSite as usize`. Read by
/// `kernel/src/trap/interrupt.rs`'s census dump (riscv64 + `ipc-census` only); the
/// one-shot print in [`note_fork_refusal`] is what reaches every build.
pub fn fork_refusal_counts() -> [u32; FORK_REFUSAL_SITES] {
    core::array::from_fn(|i| {
        FORK_REFUSAL_COUNTS[i].load(core::sync::atomic::Ordering::Relaxed)
    })
}

/// Implement fork(): create a child process that is a copy of the parent.
///
/// Returns child TID to the parent (>0), 0 to the child, or -1 on error.
///
/// Implementation:
///  1. Duplicate the parent's user page table (deep copy: new physical pages).
///  2. Create a new kernel task with name "forked".
///  3. The child's a0 register (return value) is set to 0.
///  4. The parent receives the child's TID.
///
/// Limitations:
///  - Only works for user-mode tasks (user_pt != 0).
///  - The shm/MMIO window is not inherited: the child holds no capability or
///    mapping record for what is mapped there (see `vmm::fork_cow`).
///  - Descriptors and capabilities are not this function's: the caller's
///    `before_release` hook gives the child its own (a native child's
///    descriptors and row, `azos_syscall::natfork`; a Linux child's,
///    `azos_syscall::linux`). Without a hook the child holds none.
///
/// K-A15: `sepc`/`user_sp` are the trap-time values from the parent's own
/// ecall — passed as plain parameters (not read back from shared state) so
/// they're inherently hart-local: the value this specific `sys_fork_impl`
/// call sees can never be another hart's concurrent syscall's sepc/user_sp.
pub fn sys_fork_impl(sepc: u64, user_sp: u64, regs: &crate::task::UserRegs) -> i64 {
    sys_fork_impl_hooked(sepc, user_sp, regs, &mut |_| true)
}

/// [`sys_fork_impl`] with `before_release(child_tid)` run after the child
/// exists and before it can run its first instruction (RFC-0047: a Linux
/// child is reseeded from its row and given its descriptors there). `false`
/// ends the child before its first instruction (it exits with code 137),
/// and the fork answers -1. A Linux parent makes a Linux child.
pub fn sys_fork_impl_hooked(
    sepc: u64,
    user_sp: u64,
    regs: &crate::task::UserRegs,
    before_release: &mut dyn FnMut(u32) -> bool,
) -> i64 {
    let t_fork = crate::prof::t();
    let r = fork_hooked_inner(sepc, user_sp, regs, before_release);
    crate::prof::add(0, t_fork);
    r
}

fn fork_hooked_inner(
    sepc: u64,
    user_sp: u64,
    regs: &crate::task::UserRegs,
    before_release: &mut dyn FnMut(u32) -> bool,
) -> i64 {
    let parent_pt = crate::scheduler::current_user_pt();
    // kernel task can't fork
    if parent_pt == 0 { return note_fork_refusal(ForkRefusalSite::KernelTask); }

    // AQ9: Copy-on-Write fork — share all user pages read-only instead of
    // copying them eagerly.  The COW fault handler allocates new pages on write.
    // The shm/MMIO window is left out of the child.
    // RFC-0049 P2: a `mem = "locked"` task is born by exec and never forks —
    // a fork would put its every page under copy-on-write, and the break is a
    // fault a locked task must never take. Checked here, not only by its
    // seccomp profile, because an audit-mode profile lets unlisted calls run.
    if crate::scheduler::current_mem_locked() {
        return note_fork_refusal(ForkRefusalSite::MemLocked);
    }

    // RFC-0049 M1: the child's page tables are allocated by this task under a
    // root that is not its own; `fork_cow` leaves the count in `pt_build`.
    let _ = crate::scheduler::take_current_pt_build();
    let t_ph = crate::prof::t();
    // Wave 13: a thread group's other members may fault on the parent's
    // entries while they are walked (`fork_cow_shared`).
    let concurrent = crate::scheduler::current_slot().is_some_and(|i| crate::group::lead_of_idx(i) != 0);
    let (child_pt, child_reserved) = match vmm::fork_cow_shared(parent_pt, USER_MMIO_BASE, USER_MMIO_LIMIT, concurrent) {
        Ok(r) => r,
        Err(_) => {
            let _ = crate::scheduler::take_current_pt_build();
            return note_fork_refusal(ForkRefusalSite::CowFailed);
        }
    };
    // The root and every table under it. The data pages stay shared
    // copy-on-write: their breaks are observed, not charged (P3 -- the row's
    // admission paid for one full copy).
    crate::prof::add(1, t_ph);
    // Wave 14: plus the demand reservations it inherited (a lazily grown
    // heap): pages it may still commit, charged now as the parent's were at
    // reservation, so the budget is never overcommitted (the rule DEMANDPAGE's
    // region fork follows too).
    let child_charge = 1u32
        .saturating_add(crate::scheduler::take_current_pt_build())
        .saturating_add(u32::try_from(child_reserved).unwrap_or(u32::MAX));
    let (parent_limit, _) = crate::scheduler::current_mem_policy();
    if parent_limit != 0 && child_charge > parent_limit {
        crate::scheduler::note_mm_quota_refusal();
        vmm::destroy_user_pagetable(child_pt);
        return note_fork_refusal(ForkRefusalSite::MemBudget);
    }

    // Copy kernel entries so traps work in the child.
    //
    // Ordering here is already the correct one and must stay that way:
    // `fork_cow` has populated the child's own L1/L0 tables for every user
    // page, so this merges into a PT that owns its tables (see the ordering
    // invariant on `vmm::copy_kernel_entries_to_user` and the matching tail of
    // `load_elf_into`). The collision check is a formality — the child's user
    // layout is a copy of the parent's, which passed the same check at exec —
    // but a dropped kernel entry would be just as fatal here, and refusing the
    // fork is recoverable where a child with no CLINT is not.
    let t_ph = crate::prof::t();
    if let Some((vpn2, vpn1)) = vmm::kernel_entry_collision(child_pt) {
        azos_drv_sys::kwarn!(
            "[FORK] refused: child occupies kernel slot VPN2={} VPN1={}",
            vpn2, vpn1,
        );
        vmm::destroy_user_pagetable(child_pt);
        return note_fork_refusal(ForkRefusalSite::KernelSlotCollision);
    }
    vmm::copy_kernel_entries_to_user(child_pt);
    crate::prof::add(2, t_ph);

    // Get parent's brk to set in child.
    let parent_brk = crate::scheduler::update_user_brk(0);

    // Create child task. We use a trampoline that just yields forever — the real
    // entry will be set via the pending exec mechanism when we SRET.
    //
    // K-A13: fork() is reachable from unprivileged userspace in an unbounded
    // loop (fork-bomb). `task_create` panics — a full board reset under this
    // profile's `panic = "abort"` — when the task pool is exhausted, so this
    // MUST use the fallible variant and report -1 (matches the existing
    // fork-failure convention just above), not let the kernel abort.
    //
    // Both failure exits below still own `child_pt` outright (nothing
    // references it until `set_task_user_info` publishes it), so they must
    // release it — otherwise a fork-bomb that exhausts the task pool leaks a
    // full COW page table per attempt and turns a bounded, recoverable denial
    // into permanent PMM exhaustion.
    // The child runs in its parent's class at its parent's BASE priority
    // (wave 7), as a Linux fork child keeps its parent's policy and nice.
    // It used to be `DEFAULT_PRIORITY` whatever the parent was: harmless while
    // every ring-3 task ran at the default, an escalation once the topology is
    // applied — a `best_effort` program at 24 could fork itself a child at 16.
    // The base, not a donated boost: a donation belongs to the parent's
    // critical section, not to a new process.
    let t_ph = crate::prof::t();
    let (child_prio, child_class) = crate::scheduler::current_sched_params();
    // Who created whom, so `wait` knows who to notify: set with the slot, under
    // the exit-notice admission (wave 12).
    let child_idx = match crate::try_task_create_init(
        "forked", fork_child_entry, 0, child_prio, -1,
        crate::filter::TaskInit {
            class_raw: Some(child_class),
            // Wave 13: a fork from a thread is its process's child.
            parent: crate::scheduler::current_proc_tid(),
            abi: if crate::scheduler::current_is_linux() { crate::task::ABI_LINUX } else { crate::task::ABI_NATIVE },
            ..crate::filter::TaskInit::default()
        },
    ) {
        Some(idx) => idx,
        None => {
            vmm::destroy_user_pagetable(child_pt);
            return note_fork_refusal(ForkRefusalSite::PoolExhausted);
        }
    };

    // Capture the child's TID immediately. Safe against slot reuse: the child
    // cannot have exited yet — `fork_child_entry` never exits before consuming
    // the fork context, which is only published below — so the slot still
    // belongs to it. The TID is what identifies the child from here on
    // (`set_task_fork_ctx` re-checks it under POOL_LOCK) and is also the
    // correct return value: the pool INDEX (returned previously) can
    // legitimately be 0 for a reused slot 0, which the parent would
    // misinterpret as "I am the child" — and it also disagreed with
    // `sys_getpid`, which reports TIDs.
    let child_tid = match crate::tid_for_idx(child_idx) {
        Some(tid) => tid,
        None => {
            // Unreachable: the slot was just allocated. Still release the page
            // table — it is not yet published on any task.
            vmm::destroy_user_pagetable(child_pt);
            return note_fork_refusal(ForkRefusalSite::TidLookupMiss);
        }
    };

    crate::prof::add(3, t_ph);
    let t_ph = crate::prof::t();
    // Apply the child's user page table so context_switch.S writes the
    // correct SATP when the child is scheduled.
    let child_satp = make_satp(child_pt, crate::alloc_asid()) as u64;
    crate::scheduler::set_task_user_info(child_idx, child_satp, child_pt as u64, parent_brk);
    // RFC-0049 M1: the child runs under its parent's budget limit (it has no
    // row of its own) and starts charged for its page tables. It is never
    // locked: a locked parent cannot get here.
    // `child_charge <= parent_limit` was checked before the child existed.
    let _ = crate::scheduler::set_task_mem(child_idx, parent_limit, false, child_charge);

    // AQ11: Inherit parent's syscall filter — child cannot be less restricted.
    let parent_filter = crate::scheduler::current_syscall_filter();
    crate::scheduler::set_task_syscall_filter(child_idx, parent_filter);
    crate::prof::add(4, t_ph);

    // Publish the hand-off on the child's OWN task slot — the instruction
    // AFTER the parent's syscall as its entry PC (see `child_resume_pc`,
    // which is where the two ISAs' "skip the syscall instruction" actually
    // differs), the parent's user SP, and the child's own SATP. See the
    // K-A15 doc above and on `Task::fork_ctx_ready`. Identity-checked
    // against `child_tid` under POOL_LOCK; failure means the slot no
    // longer belongs to our child, which cannot happen while the child is
    // waiting (it never exits before consuming) — defensive only.

    // RFC-0047 / wave 13: the caller's setup of the child (a Linux child's
    // descriptors and row, a native child's descriptors at the parent's
    // exact handles and its row); refused, the child ends at its first
    // scheduling (the forced stop is checked before its `sret`). FIRST into
    // the child's empty table: a native child's inherited descriptors must
    // land on the parent's slots, which a grant made before could take.
    let t_ph = crate::prof::t();
    let refused = !before_release(child_tid);
    if refused {
        crate::scheduler::task_stop(child_tid, true, 9);
    }
    crate::prof::add(5, t_ph);
    let t_ph = crate::prof::t();

    // RFC-0040 gap 3: bootstrap capability grant. Still running as the
    // PARENT here — no context switch has happened — so `current_task_tid()`
    // is the parent's own identity and needs no lookup. Fires before
    // `set_task_fork_ctx` below publishes the child's entry point, so the
    // grant is in the child's cap table before the child can ever run a
    // single user instruction. Goes through the same registered-callback
    // indirection `TASK_EXIT_HOOK` uses (`crates/core/ipc` depends on
    // `crates/core/sched`, so this crate cannot call `azos_ipc` directly) —
    // see `scheduler::invoke_task_fork_hook` and `kernel/src/boot/sched.rs`'s
    // `install_sched_hooks`, which registers `azos_ipc::task_fork_grant`.
    // A missing registration is a silent no-grant, never a failed fork.
    crate::scheduler::invoke_task_fork_hook(crate::current_task_tid(), child_tid);
    crate::prof::add(6, t_ph);
    let t_ph = crate::prof::t();

    crate::fp::fork_copy(child_idx);

    if !crate::scheduler::set_task_fork_ctx(
        child_idx, child_tid, child_resume_pc(sepc), user_sp, child_satp, regs,
    ) {
        // Reachable only if the child's slot stopped being the child's
        // (defensive — see above). `child_pt` is NOT destroyed here, unlike
        // the earlier failure exits, because at this point it has already
        // been PUBLISHED on the slot by `set_task_user_info`, and the
        // identity check failing means the slot moved on without us — in one
        // of two states we cannot tell apart:
        //  (a) the child exited with it (its exit path destroyed it,
        //      K-C22(C)), or the slot was already reused and the claim in
        //      `try_task_create_affinity` destroyed it (K-C22(B)) —
        //      destroying again here would be a double-free;
        //  (b) freed but not yet reused: `user_pt` still holds `child_pt` on
        //      the dead slot, and the next claim of that slot destroys it.
        // Either way the reuse-time reclaim owns the teardown; abandoning
        // the PT here leaks nothing.
        return note_fork_refusal(ForkRefusalSite::ForkCtxIdentityMiss);
    }

    crate::prof::add(7, t_ph);
    if refused { -1 } else { child_tid as i64 }
}

/// Wave 13 (THREADS): create a thread of the calling task's process.
///
/// The new task runs on its creator's address space (same root and
/// translation word: no copy, no COW), shares its capability and descriptor
/// tables through the group leader (`group`), and starts at `entry` with the
/// creator's registers at the call except: the stack pointer `stack`, the
/// thread pointer `tls` (riscv64 `tp`, aarch64 `TPIDR_EL0`) when given, and
/// the return register 0. `ctid` (0: none) is the word its exit clears and
/// wakes. `before_release(child)` runs before it can run (the Linux clone's
/// `CLONE_PARENT_SETTID` store); `false` stops it at birth.
///
/// Returns the new TID, `-EAGAIN` (11) when the group, the group table or the
/// task pool is full or the group is ending, `-1` for a caller with no user
/// address space.
pub fn thread_create_impl(
    entry: u64,
    stack: u64,
    tls: Option<u64>,
    ctid: u64,
    regs: &crate::task::UserRegs,
    arg: Option<u64>,
    before_release: &mut dyn FnMut(u32) -> bool,
) -> i64 {
    const EAGAIN: i64 = -11;
    let user_pt = crate::scheduler::current_user_pt();
    let satp = crate::scheduler::current_task_satp();
    if user_pt == 0 || stack == 0 {
        return -1;
    }
    let Some(me_idx) = crate::scheduler::current_slot() else { return -1 };
    let me = crate::current_task_tid();
    let leader = crate::group::proc_of(me_idx, me);
    let Some(leader_idx) = crate::idx_for_tid(leader) else { return -1 };
    if crate::group::exiting(leader).is_some() || !crate::group::admit(leader, leader_idx) {
        return EAGAIN;
    }
    let (prio, class) = crate::scheduler::current_sched_params();
    let child_idx = match crate::try_task_create_init(
        "thread", fork_child_entry, 0, prio, -1,
        crate::filter::TaskInit {
            class_raw: Some(class),
            // A thread is nobody's child: its exit posts no notice.
            parent: 0,
            abi: if crate::scheduler::current_is_linux() { crate::task::ABI_LINUX } else { crate::task::ABI_NATIVE },
            syscall_filter: Some(crate::scheduler::current_syscall_filter()),
            ..crate::filter::TaskInit::default()
        },
    ) {
        Some(i) => i,
        None => {
            crate::group::unadmit(leader, leader_idx);
            return EAGAIN;
        }
    };
    let Some(child) = crate::tid_for_idx(child_idx) else {
        crate::group::unadmit(leader, leader_idx);
        return EAGAIN;
    };
    crate::group::join(child_idx, leader);
    crate::scheduler::set_task_thread_info(child_idx, satp, user_pt as u64);
    crate::group::set_clear_tid(child_idx, ctid);
    let refused = !before_release(child);
    if refused {
        crate::scheduler::task_stop(child, true, 9);
    }
    crate::fp::fork_copy(child_idx);
    let mut r = *regs;
    // Gate canary only: the new thread keeps its creator's thread pointer
    // (musl's thread-local storage is then the creator's).
    let tls = if cfg!(feature = "threads-tls-canary") { None } else { tls };
    // Wave 15: a native thread's argument, in its third argument register.
    // aarch64's trap path hands this call no register snapshot (`regs` is
    // zeroed there: copying the creator's file, its 528-byte FP state
    // included, cost every create about 1,000 instructions), so the one
    // register the thread is promised is written here; the rest start
    // zeroed, the FP file clean. Gate canary `thread-regs-canary` leaves it
    // out (the argument then reads 0 on aarch64).
    let arg = if cfg!(feature = "thread-regs-canary") { None } else { arg };
    #[cfg(target_arch = "riscv64")]
    {
        r[2] = stack;
        if let Some(t) = tls {
            r[4] = t;
        }
        if let Some(a) = arg {
            r[12] = a;
        }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        r.sp_el0 = stack;
        if let Some(t) = tls {
            r.tpidr_el0 = t;
        }
        if let Some(a) = arg {
            r.gpr[2] = a;
        }
    }
    #[cfg(not(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none"))))]
    let _ = (&mut r, tls);
    if !crate::scheduler::set_task_fork_ctx(child_idx, child, entry, stack, satp, &r) {
        return EAGAIN;
    }
    if refused { EAGAIN } else { child as i64 }
}

/// The user PC after the trapping instruction at `sepc` (the Linux clone's
/// child resumes there with a 0 return).
pub fn resume_pc_after(sepc: u64) -> u64 {
    child_resume_pc(sepc)
}

/// How long `fork_child_entry` waits for its hand-off before it says so, in
/// milliseconds. A log threshold, NOT an exit bound: exiting here would leak
/// the child's COW page table and break fork's contract (the parent has
/// already been promised a child TID).
///
/// **A clock, not a yield count** (RFC-0055 follow-up, wave 11). The threshold
/// used to be 1000 `task_yield`s. A child dispatched onto an idle hart burns
/// those in about a millisecond, and the parent's window from task creation
/// to the publish is about that long on QEMU: `SYS_SPAWN`/`SYS_SPAWN_EX` print
/// the `[SPAWN][PRIO]` line, seed the capabilities and (608) write the startup
/// block and move descriptors inside it. Measured 2026-10-03 (riscv64, -smp 4,
/// gate rows): the line fired on most spawns, and every one of those children
/// was published 1.7-2.0 ms after it started waiting (1001-1913 yields) — a
/// bounded window, not a stalled parent. 100 ms is fifty times that window,
/// so the line now means what it says.
const FORK_CTX_WAIT_DIAG_MS: u64 = 100;

/// Fork child entry point.  Reads the saved context and SRETs to user
/// mode with a0=0 (the fork return value for the child process).
pub(crate) fn fork_child_entry(_arg: usize) {
    // K-A15: the parent may not have finished publishing our fork context
    // yet if we were dispatched on another (idle) hart immediately after
    // try_task_create_affinity() enqueued us — yield until it lands. This
    // wait terminates: the parent's path from task creation to
    // `set_task_fork_ctx` is straight-line, non-blocking code with no early
    // return, and while we wait our slot stays valid with our TID, so the
    // identity-checked publish is guaranteed to reach us. Yielding keeps the
    // hart available to other work in the meantime.
    let t_entry = crate::prof::t();
    let started = azos_drv_sys::timebase::now();
    let diag_after = azos_drv_sys::timebase::TIMER_FREQ * FORK_CTX_WAIT_DIAG_MS / 1000;
    let mut said = false;
    loop {
        if let Some((entry, _user_sp, satp, regs)) =
            crate::scheduler::take_current_task_fork_ctx()
        {
            // Gate canary only: a thread (not a forked process) first runs
            // user code 100 ms after it started, as one does on a loaded
            // host. Checked after the hand-off, which `group::join` precedes.
            // Yields, so the rest of the machine runs on.
            #[cfg(feature = "threads-late-start-canary")]
            if crate::group::shares_tables(crate::current_task_tid()) {
                let late = azos_drv_sys::timebase::TIMER_FREQ / 10;
                while azos_drv_sys::timebase::now().wrapping_sub(started) < late {
                    crate::task_yield();
                }
            }
            // RFC-0055: a spawn aborted after the child existed (its move
            // list failed) releases it with a forced stop pending; it ends
            // here, before its first user instruction, by the normal exit.
            crate::scheduler::exit_if_forced();
            crate::prof::add(16, t_entry);
            // K-C11: SRET into user mode restoring the parent's *whole*
            // register file, not just pc/sp. `regs` is a by-value copy living
            // on this function's kernel stack — see
            // `take_current_task_fork_ctx` for why it must not be a pointer
            // into `TASKS`.
            //
            // `user_sp` is deliberately unused: the stack pointer is `regs[2]`
            // and comes back with everything else. Restoring it from a second,
            // independent source is how the two quietly drift apart.
            unsafe { sret_to_user_forked(entry as usize, satp as usize, &regs); }
        }
        if !said && azos_drv_sys::timebase::now().wrapping_sub(started) > diag_after {
            said = true;
            azos_drv_sys::kwarn!(
                "[FORK] child tid {} still waiting for fork ctx after {} ms (parent hart stalled?)",
                crate::current_task_tid(), FORK_CTX_WAIT_DIAG_MS,
            );
        }
        crate::task_yield();
    }
}

// ── MMIO mapping for userspace drivers (F00.2) ──────────────────────────────

/// Size of the MMIO/shm VA window below [`USER_STACK_TOP`] (512 MiB).
///
/// A fixed *size*, not a fixed base: on QEMU this reproduces the historical
/// `USER_MMIO_BASE = 0x6000_0000` exactly (`0x8000_0000 - 0x2000_0000`). On a
/// board with a lower [`USER_STACK_TOP`] (VF2), the window keeps the same
/// capacity and just slides down with the ceiling, rather than shrinking —
/// there is no reason a smaller board should hand userspace drivers fewer or
/// smaller MMIO mappings.
const USER_MMIO_WINDOW_SIZE: usize = 0x2000_0000; // 512 MiB

/// The raw "512 MiB below the stack" base [`USER_MMIO_WINDOW_SIZE`]'s own doc
/// describes. Named separately from [`USER_MMIO_BASE`] because on a board
/// where this collides with the vDSO page (see that constant's doc), the
/// real base clamps upward and this identifier is what a reader needs to see
/// the un-clamped value the doc comment is talking about.
const USER_MMIO_BASE_RAW: usize = USER_STACK_TOP - USER_MMIO_WINDOW_SIZE;

/// Base virtual address for user-space MMIO mappings.
///
/// See [`USER_MMIO_WINDOW_SIZE`] for why this is `USER_STACK_TOP` minus a
/// fixed window rather than a board-independent literal — normally exactly
/// [`USER_MMIO_BASE_RAW`].
///
/// **Clamped above the vDSO page, found 2026-09-22 the hard way.** The vDSO
/// is a SEPARATE fixed address (`vdso::VDSO_USER_BASE`, `crates/core/abi/src/
/// vdso.rs`), not derived from `USER_STACK_TOP` at all — nothing before this
/// clamp related the two. On RISC-V (`RAM_BASE = 0x8000_0000`)
/// `USER_MMIO_BASE_RAW` lands at `0x6000_0000`, far above
/// `VDSO_USER_BASE = 0x2000_0000`, so the two windows never met and this was
/// never exercised. On aarch64's QEMU `virt` (`RAM_BASE = 0x4000_0000`,
/// exactly `VDSO_USER_BASE + USER_MMIO_WINDOW_SIZE`) `USER_MMIO_BASE_RAW`
/// computes to `0x2000_0000` — THE SAME ADDRESS as the vDSO page. `fork_cow`
/// treats `[USER_MMIO_BASE, USER_MMIO_LIMIT)` as the shm/MMIO window it
/// deliberately does not COW-copy into a forked child (see its own doc); with
/// the collision, that window swallowed the vDSO page too, so every forked
/// child's page table had NO mapping at `VDSO_USER_BASE` at all. Silent right
/// up until the child's first vDSO read (e.g. `sys::uptime()`'s fast path)
/// took an instruction/data abort at `FAR_EL1 = 0x2000_0000` — measured on
/// `ipctest`'s phase A (8 forked children racing a fast-IPC server; every one
/// died on its first `uptime()` call) once `sret_to_user_forked`'s aarch64
/// arm existed to let a child run far enough to hit it. `fork()` itself, and
/// every check that never calls `sys::uptime()`/`sys::clock()`, was
/// unaffected — which is why `abitest`'s and `ipctest`'s simpler fork checks
/// passed clean while this one didn't.
///
/// Clamping the base to `max(USER_MMIO_BASE_RAW, VDSO_USER_BASE + PAGE_SIZE)`
/// keeps riscv64's value EXACTLY `0x6000_0000` (the raw value already clears
/// the clamp there) while giving aarch64's QEMU `virt` a window that starts
/// one page later — negligible against 512 MiB of capacity, and correct on
/// every other board's arithmetic too, present or future, without a
/// per-board special case.
pub(crate) const USER_MMIO_BASE: usize = {
    let vdso_clearance = vdso::VDSO_USER_BASE + PAGE_SIZE;
    if USER_MMIO_BASE_RAW < vdso_clearance { vdso_clearance } else { USER_MMIO_BASE_RAW }
};

// The window must stay clear of the image/heap ceiling on every board this
// derives a value for (K1's pre-existing brokenness aside, per the note on
// `USER_STACK_TOP`) — otherwise a `brk` at its cap and an MMIO mapping at its
// base would land on the same page.
const _: () = assert!(USER_MMIO_BASE > USER_LOW_MAX);

// The clamp above is the general form of this fact; assert it directly too,
// so a future edit to either constant fails loudly here instead of silently
// reproducing the 2026-09-22 aarch64 vDSO-in-a-forked-child bug this clamp
// exists to prevent.
const _: () = assert!(USER_MMIO_BASE >= vdso::VDSO_USER_BASE + PAGE_SIZE);

/// Maximum size of a single MMIO mapping (1 MiB).
const USER_MMIO_MAX_SIZE: usize = 1024 * 1024;

/// Hard ceiling for the MMIO/shm VA window: the bottom of the user stack.
///
/// No reservation ([`reserve_window_va`]) may end past it. Past it lies the
/// user stack, and past that `0x8000_0000` — the VPN[2]=2 slot that
/// [`vmm::copy_kernel_entries_to_user`] grafts in wholesale, meaning the L2
/// entry there points at the *kernel's own* L1 table. A `vmm::map` at such a
/// VA would allocate an L0 table inside the kernel page table and publish
/// USER leaves in it: the same address-space corruption the loader ordering
/// fix removes, arriving through a different door.
pub(crate) const USER_MMIO_LIMIT: usize = USER_STACK_TOP - USER_STACK_SIZE;

// `USER_MMIO_BASE` must sit strictly below `USER_MMIO_LIMIT`, i.e. the window
// must not invert. Only reachable if `USER_STACK_SIZE` (a build-time config
// value, see `azos_limits`) were ever configured larger than
// `USER_MMIO_WINDOW_SIZE` (512 MiB) — nothing this tree ships does, but a
// future config change should fail the build, not silently reserve a
// negative-size window.
const _: () = assert!(USER_MMIO_BASE < USER_MMIO_LIMIT);

/// Kconfig `LOCKED_HUGE_LEAVES`: where exec maps a locked row's boot-reserved
/// region (`mem_huge_mib`) — the first level-1 leaf boundary (2 MiB) at or
/// above the shm/MMIO window's base. Derived from the window, so it follows
/// every board's `RAM_BASE` the way the window does; inside the window, so
/// `sys_brk`/`sys_mmap` (capped at the window's base) never reach it, the
/// exit path never frees its frames, and the window allocator is told about
/// it (the exec reserves it in the task's window table) so no shm or MMIO
/// mapping is placed on it.
pub const LOCKED_ARENA_VA: usize = (USER_MMIO_BASE + vmm::MEGA_SIZE - 1) & !(vmm::MEGA_SIZE - 1);
/// `azos_topology::MAX_HUGE_MIB` (256) in bytes, restated because this
/// crate does not depend on the topology crate; `tests/host/topology-tests`
/// pins the topology side.
const MAX_HUGE_BYTES: usize = 256 * 1024 * 1024;
const _: () = assert!(
    !azos_limits::LOCKED_HUGE_LEAVES || LOCKED_ARENA_VA + MAX_HUGE_BYTES <= USER_MMIO_LIMIT,
    "the largest mem_huge_mib region must fit the shm/MMIO window above LOCKED_ARENA_VA",
);

/// Map the row's 2 MiB-leaf region into the address space exec just built
/// (Kconfig `LOCKED_HUGE_LEAVES`), zeroed, at [`LOCKED_ARENA_VA`], read-write
/// and never executable, with A/D preset (a locked task must take no fault).
/// Returns `(va, bytes)`; the reason as text when refused, with nothing
/// mapped and no reservation kept.
fn install_locked_arena(user_pt: usize, spec: &MemSpec) -> Result<(usize, usize), &'static str> {
    if !azos_limits::LOCKED_HUGE_LEAVES {
        return Err("this kernel was built without LOCKED_HUGE_LEAVES");
    }
    if !spec.locked {
        return Err("the row is not mem = \"locked\"");
    }
    let (pa, bytes) = azos_mm::huge::region(spec.row).ok_or("no region was reserved for the row at boot")?;
    if bytes != spec.huge_mib as usize * 1024 * 1024 {
        return Err("the reserved region is not the size the row declares");
    }
    let va = LOCKED_ARENA_VA;
    if va.checked_add(bytes).map_or(true, |end| end > USER_MMIO_LIMIT) {
        return Err("the region does not fit the shm/MMIO window");
    }
    // The task's window table: a re-exec holds the exact reservation already.
    let _ = crate::scheduler::release_current_user_window(va, bytes);
    if crate::scheduler::reserve_current_user_window(va, va + bytes, bytes) != Some(va) {
        return Err("the window is taken where the region goes");
    }
    // Zeroed at every exec: the frames are the row's for the whole boot and
    // the previous instance's data must not reach the next one.
    unsafe { core::ptr::write_bytes(azos_mm::addr::phys_to_virt(pa) as *mut u8, 0, bytes) };
    let flags = PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW };
    #[cfg(not(feature = "huge-leaves-canary"))]
    let mapped = vmm::map_user_mega_range(user_pt, va, pa, bytes, flags);
    // Canary: the same frames as page leaves. The exec-time walk must then
    // report page-mapped slots, and the gate row must fail.
    #[cfg(feature = "huge-leaves-canary")]
    let mapped = {
        let mut r = Ok(());
        let mut off = 0;
        while off < bytes && r.is_ok() {
            r = vmm::map(user_pt, va + off, pa + off, flags);
            off += PAGE_SIZE;
        }
        r
    };
    if mapped.is_err() {
        let _ = crate::scheduler::release_current_user_window(va, bytes);
        return Err("the page table refused the mapping");
    }
    Ok((va, bytes))
}

/// The exec-time evidence for [`install_locked_arena`], from the page table
/// itself: how many of the region's 2 MiB slots a level-1 leaf maps, how many
/// are page-mapped instead, and whether a user-permission walk resolves the
/// first, a middle and the last byte to the reserved frames.
fn report_locked_arena(user_pt: usize, row: u16, va: usize, bytes: usize) {
    let pa = azos_mm::huge::region(row).map_or(0, |r| r.0);
    let (mut leaves, mut paged, mut other) = (0usize, 0usize, 0usize);
    let mut off = 0;
    while off < bytes {
        match vmm::leaf_level(user_pt, va + off) {
            Some(1) => leaves += 1,
            Some(0) => paged += 1,
            _ => other += 1,
        }
        off += vmm::MEGA_SIZE;
    }
    let walk_ok = [0, bytes / 2 + PAGE_SIZE + 8, bytes - 8]
        .iter()
        .all(|&k| vmm::translate_user(user_pt, va + k, true) == Some(pa + k));
    azos_drv_sys::kprintln!(
        "[HUGE] row {} region {:#x}+{} MiB at pa {:#x}: {} of {} 2 MiB slots are level-1 leaves, {} page-mapped, {} unmapped; user walk {}",
        row.saturating_sub(1), va, bytes >> 20, pa, leaves, bytes / vmm::MEGA_SIZE, paged, other,
        if walk_ok { "ok" } else { "MISMATCH" },
    );
}

/// Reserve `pages` consecutive pages of the current task's MMIO/shm VA window.
///
/// Per task ([`crate::user_window`], `Task::user_window`): a release gives the
/// addresses back to the task that reserved them ([`release_user_window`]),
/// and the slot reuse after an exit gives back the rest. `None` when the task's
/// reservation table is full or no gap below [`USER_MMIO_LIMIT`] fits: a
/// refused mapping, never an address past the limit (see there).
///
/// Per task rather than board-wide is sound because no two tasks share a page
/// table: fork builds the child its own (and leaves this window out of it, see
/// `vmm::fork_cow`), and nothing else installs a `user_pt` on a second task.
fn reserve_window_va(pages: usize) -> Option<usize> {
    let span = pages.checked_mul(PAGE_SIZE)?;
    crate::scheduler::reserve_current_user_window(USER_MMIO_BASE, USER_MMIO_LIMIT, span)
}

/// Give back the window addresses a mapping of `pages` pages at `va` reserved,
/// once its PTEs are gone. `false` when the current task holds no such
/// reservation.
pub fn release_user_window(va: usize, pages: usize) -> bool {
    match pages.checked_mul(PAGE_SIZE) {
        Some(span) => crate::scheduler::release_current_user_window(va, span),
        None => false,
    }
}

/// Map a shared memory region (F00.4) into the current task's user page table.
///
/// Takes the physical pages directly from the caller to avoid a dependency on
/// `azos_ipc` (which already depends on `azos_sched` — would be circular).
///
/// - `phys_pages`: slice of physical page addresses to map contiguously.
/// - `rw`: true = read-write, false = read-only.
///
/// Returns the virtual base address, or None on failure. The addresses come
/// from the current task's window ([`reserve_window_va`]); the typed release
/// gives them back with [`release_user_window`] after it unmaps.
pub fn shm_map_user(phys_pages: &[usize], rw: bool) -> Option<usize> {
    // Wave 13: one layout change at a time per thread group.
    let _mm = crate::group::mm_lock();
    let user_pt = crate::scheduler::current_user_pt();
    if user_pt == 0 {
        return None; // kernel task
    }
    let page_count = phys_pages.len();
    if page_count == 0 {
        return None;
    }
    let va_base = reserve_window_va(page_count)?;
    let flags = if rw {
        PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW }
    } else {
        PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RO }
    };
    for (i, &phys) in phys_pages.iter().enumerate() {
        let va = va_base + i * PAGE_SIZE;
        if vmm::map(user_pt, va, phys, flags).is_err() {
            // Partial mapping; the caller pins its reference. The addresses
            // stay reserved until the task exits: the PTEs already installed
            // are still there, and nothing else may be mapped over them.
            return None;
        }
    }
    Some(va_base)
}

/// Map the physical MMIO range `phys_base..phys_base + size` into the current
/// task's user page table. Returns the virtual address in user space, or None
/// on failure.
///
/// The range is mapped exactly: `phys_base` and `size` must both be page
/// aligned, and nothing is rounded. The caller (`SYS_MMIO_MAP`) passes an
/// entry of the board's region table, so a misaligned or wrapping range here
/// is refused rather than widened to the next page.
///
/// USER_MMIO_RW when `writable`, USER_MMIO_RO otherwise (user-accessible,
/// never exec, uncached).
/// A+D bits are pre-set to avoid software-managed A/D faults on MMIO.
pub fn mmio_map_user(phys_base: usize, size: usize, writable: bool) -> Option<usize> {
    // Wave 13: one layout change at a time per thread group.
    let _mm = crate::group::mm_lock();
    if size == 0 || size > USER_MMIO_MAX_SIZE {
        return None;
    }
    if phys_base & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
        return None;
    }
    phys_base.checked_add(size)?;
    let user_pt = crate::scheduler::current_user_pt();
    if user_pt == 0 {
        return None; // kernel task — no user page table
    }

    let size_pages = size / PAGE_SIZE;

    // Allocate contiguous VA range
    let va_base = reserve_window_va(size_pages)?;

    // Map each page: physical MMIO directly into the user PT, U+R(+W)+A+D,
    // UNCACHED (device memory). It used USER_RW/RO, which are cacheable.
    let flags = if writable { PagePerms::USER_MMIO_RW } else { PagePerms::USER_MMIO_RO };

    for i in 0..size_pages {
        let va = va_base + i * PAGE_SIZE;
        let pa = phys_base + i * PAGE_SIZE;
        if vmm::map(user_pt, va, pa, flags).is_err() {
            // Roll back and fail. The old `break` returned `Some(va_base)` for
            // a range that was only partially mapped, so the driver got a
            // pointer that faults somewhere in the middle of the region it was
            // told it owned. Unmapping is safe here: these are device frames
            // the PMM never owned, so nothing is freed. With nothing left
            // mapped, the addresses go back to the task's window.
            for j in 0..i {
                vmm::unmap(user_pt, va_base + j * PAGE_SIZE);
            }
            release_user_window(va_base, size_pages);
            return None;
        }
    }

    Some(va_base)
}

// ── Little-endian helpers ─────────────────────────────────────────────────────

#[inline] fn r16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([d[off], d[off+1]])
}
#[inline] fn r32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off+1], d[off+2], d[off+3]])
}
#[inline] fn r64(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        d[off],   d[off+1], d[off+2], d[off+3],
        d[off+4], d[off+5], d[off+6], d[off+7],
    ])
}
/// Round `a` up to the next page boundary, saturating instead of wrapping.
///
/// `a + PAGE_SIZE - 1` overflows for any `a` within a page of `usize::MAX`,
/// and under this build profile (`overflow-checks = true`, `panic = "abort"`)
/// an overflow reboots the board. `sys_brk_impl` passes a raw ring-3 register
/// here, so that was a one-instruction reset available to unprivileged code.
/// Saturating yields `0xFFFF_FFFF_FFFF_F000`, which every caller's range check
/// rejects.
#[inline] fn page_up(a: usize) -> usize {
    a.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}
