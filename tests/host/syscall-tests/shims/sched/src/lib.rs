// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sched`, used only by `tests/host/syscall-tests`.
//!
//! **WHY this exists.** The real `azos_sched` is RV64-only (context
//! switch asm, CSRs, PLIC) and enormous — `handlers.rs` reaches into it 125
//! times, but only a handful of calls matter to this crate's tests.
//!
//! **Settable test doubles — "who is calling right now", nothing more:**
//! `current_user_pt` / `current_task_tid`, which `socket_access_ok`
//! (`handlers.rs:861`) uses to decide whether the caller is a kernel task
//! (bypass) or a specific user task (checked against the socket's owner
//! stamp), and which every mmap/munmap guard reads first. These are state,
//! not behaviour: no claim about scheduling is made or tested.
//!
//! **`update_user_brk` is real, with the kernel's own semantics**
//! (`crates/core/sched/src/scheduler.rs:3147`): `0` reads the current break, any
//! other value sets it and returns it. `sys_mmap` and `sys_alloc_demand`
//! both take it as the base of the range they hand out, so the null-brk
//! refusal (`base < USER_GUARD_LIMIT`) and the VA-ceiling check (`end_va`
//! against the base of [`user_shm_window`]) are both functions of it — a `todo!()` here
//! means zero mmap coverage. [`shim_set_brk`] is the test-only writer.
//!
//! **`copy_from_user` / `copy_to_user` are a deliberate transcription, and
//! the only place in this crate where kernel logic is retyped rather than
//! pulled.** The originals live in `crates/core/sched/src/process.rs:752` and
//! `:792`, inside a 4,000-line RV64 module (fork, context switch, ELF
//! loading) that cannot be `#[path]`-pulled. What is copied is the
//! zero-length/overflow guard and the per-page chunking loop; **the decision
//! that matters — is this user VA mapped, with USER and the right R/W bit —
//! is not copied**, it is a call into the real `azos_mm::vmm::
//! translate_user`. So a test that shows `sys_connect` refusing a pointer
//! whose 16-byte read crosses into an unmapped page is exercising the
//! kernel's real Sv39 permission walk; only the loop around it is local.
//! Read any such test as proving what `sys_connect` does with a refusal,
//! not as coverage of `process.rs` itself.
//!
//! Every other function signature here matches the real one exactly (so
//! `handlers.rs` compiles unchanged) but is `todo!()`: no test in this crate
//! reaches any handler that calls them. A stub that returned a plausible
//! value instead of panicking would make some other function's behaviour
//! silently look like part of what this crate proves.

use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The "current task" the pulled `handlers.rs` observes. `0` for `user_pt`
/// means "kernel context" — the bypass branch every AQ6 gate takes.
static CURRENT_USER_PT: AtomicUsize = AtomicUsize::new(0);
static CURRENT_TASK_TID: AtomicU32 = AtomicU32::new(0);

/// The current task's program break — see [`update_user_brk`].
static USER_BRK: AtomicU64 = AtomicU64::new(0);

/// Test-only control surface — not part of the real `azos_sched` API.
pub fn set_current_user_pt(pt: usize) {
    CURRENT_USER_PT.store(pt, Ordering::SeqCst);
}

/// Test-only control surface — not part of the real `azos_sched` API.
pub fn set_current_task_tid(tid: u32) {
    CURRENT_TASK_TID.store(tid, Ordering::SeqCst);
}

/// Test-only control surface — not part of the real `azos_sched` API.
/// Sets the break directly, including to `0`, which `update_user_brk`
/// itself cannot express (it reads on `0`). A never-initialised task really
/// does report a break of 0 — `scheduler.rs` zeroes `user_brk` at task
/// creation — which is exactly the null-base case `sys_mmap` refuses.
pub fn shim_set_brk(v: u64) {
    USER_BRK.store(v, Ordering::SeqCst);
}

/// Owner decision 102 — the per-task frame budget, mirrored from
/// `scheduler.rs`'s `mm_charge`/`mm_discharge`.
///
/// State, not behaviour, like `CURRENT_USER_PT` above: one counter and one
/// limit for "the current task", because this crate runs one task at a time.
/// The SEMANTICS are copied deliberately and must not drift — `0` means no
/// limit, a charge that would exceed the limit charges nothing, and the
/// discharge saturates at 0 rather than wrapping.
///
/// What the tests here can therefore prove is the WIRING in the pulled
/// `handlers.rs`: that `sys_mmap` charges before allocating and refuses over
/// budget, and that `sys_munmap` gives back what it actually freed. The real
/// counter lives on `Task`; this stands in for it.
static USER_PAGES: AtomicU32 = AtomicU32::new(0);
static USER_PAGE_LIMIT: AtomicU32 = AtomicU32::new(0);

/// Test-only control surface — not part of the real `azos_sched` API.
pub fn shim_set_page_limit(limit: u32) {
    USER_PAGE_LIMIT.store(limit, Ordering::SeqCst);
    USER_PAGES.store(0, Ordering::SeqCst);
}

/// Test-only control surface: frames charged to the current task.
pub fn shim_user_pages() -> u32 {
    USER_PAGES.load(Ordering::SeqCst)
}

pub fn mm_charge(pages: u32) -> bool {
    if pages == 0 { return true; }
    let limit = USER_PAGE_LIMIT.load(Ordering::SeqCst);
    let next = USER_PAGES.load(Ordering::SeqCst).saturating_add(pages);
    if limit != 0 && next > limit {
        return false;
    }
    USER_PAGES.store(next, Ordering::SeqCst);
    true
}

pub fn mm_discharge(pages: u32) {
    if pages == 0 { return; }
    let cur = USER_PAGES.load(Ordering::SeqCst);
    USER_PAGES.store(cur.saturating_sub(pages), Ordering::SeqCst);
}

/// RFC-0049 M1: a discharge posted for `tid` from another task. The stand-in
/// has one budget, the current task's; a posting for that TID lands on it.
pub fn mm_discharge_tid(tid: u32, pages: u32) {
    if tid == current_task_tid() { mm_discharge(pages); }
}

// ── Wave 14 (DEMANDPAGE) ─────────────────────────────────────────────────
static SCHED_CLASS: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(3);
static OTHER_PT: std::sync::Mutex<Vec<(u32, usize)>> = std::sync::Mutex::new(Vec::new());
static OTHER_PAGES: AtomicU32 = AtomicU32::new(0);
static OTHER_LIMIT: AtomicU32 = AtomicU32::new(0);

/// Test-only control surface: the current task's scheduling class
/// (`SchedClass` discriminant; 3 = BestEffort, the default here).
pub fn shim_set_sched_class(class: u8) {
    SCHED_CLASS.store(class, Ordering::SeqCst);
}

pub fn current_sched_params() -> (u32, u8) {
    (0, SCHED_CLASS.load(Ordering::SeqCst))
}

/// Test-only control surface: give task `tid` (not the current one) a
/// page-table root, and a budget of `limit` pages (0 = none) for
/// `mm_charge_tid`; resets its charge.
pub fn shim_set_other_task(tid: u32, pt: usize, limit: u32) {
    let mut v = OTHER_PT.lock().unwrap();
    v.retain(|&(t, _)| t != tid);
    v.push((tid, pt));
    OTHER_LIMIT.store(limit, Ordering::SeqCst);
    OTHER_PAGES.store(0, Ordering::SeqCst);
}

/// Test-only control surface: pages charged to the other task.
pub fn shim_other_pages() -> u32 {
    OTHER_PAGES.load(Ordering::SeqCst)
}

pub fn task_user_pt(tid: u32) -> Option<usize> {
    if tid == current_task_tid() {
        return Some(current_user_pt());
    }
    OTHER_PT.lock().unwrap().iter().find(|&&(t, _)| t == tid).map(|&(_, pt)| pt)
}

pub fn mm_charge_tid(tid: u32, pages: u32) -> bool {
    if tid == current_task_tid() {
        return mm_charge(pages);
    }
    if task_user_pt(tid).is_none() {
        return false;
    }
    let limit = OTHER_LIMIT.load(Ordering::SeqCst);
    let next = OTHER_PAGES.load(Ordering::SeqCst).saturating_add(pages);
    if limit != 0 && next > limit {
        return false;
    }
    OTHER_PAGES.store(next, Ordering::SeqCst);
    true
}

static MEM_LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static MM_REFUSALS: AtomicU32 = AtomicU32::new(0);

/// Test-only control surface: mark the current task `mem = "locked"`.
pub fn shim_set_mem_locked(locked: bool) {
    MEM_LOCKED.store(locked, Ordering::SeqCst);
}

/// Test-only control surface: budget refusals counted outside `mm_charge`.
pub fn shim_mm_refusals() -> u32 {
    MM_REFUSALS.load(Ordering::SeqCst)
}

pub fn current_mem_locked() -> bool {
    MEM_LOCKED.load(Ordering::SeqCst)
}

pub fn note_mm_quota_refusal() {
    MM_REFUSALS.fetch_add(1, Ordering::SeqCst);
}

/// Mirror of `azos_sched::MemSpec` (`crates/core/sched/src/process.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemSpec {
    pub limit: u32,
    pub locked: bool,
    pub row: u16,
    pub instances: u16,
    pub huge_mib: u16,
}

pub fn current_user_pt() -> usize {
    CURRENT_USER_PT.load(Ordering::SeqCst)
}

/// Stand-ins for the scheduler facts `sys_taskinfo` reports.
///
/// Fixed values, not `todo!()`: this crate's tests DO reach `sys_taskinfo`
/// (it is on the ABI-conformance surface), and what they check is the blob
/// LAYOUT and the short-buffer refusal — neither of which depends on the
/// numbers. A `todo!()` here would make a layout test panic for a reason that
/// has nothing to do with layout.
pub fn current_task_switches() -> (u64, u64) { (7, 3) }

/// Mirrors `azos_sched::current_task_hart`. Not 0, so a slot left unwritten
/// cannot pass for the answer.
pub fn current_task_hart() -> usize { 2 }

/// Mirrors `azos_sched::task_priority`. `Some`, so the `unwrap_or(0)` in
/// the handler is not the path under test by accident.
pub fn task_priority(_tid: u32) -> Option<u32> { Some(16) }

pub fn current_task_tid() -> u32 {
    CURRENT_TASK_TID.load(Ordering::SeqCst)
}

/// Mirrors `azos_sched::current_task_name` (wave 11, LEASE3: the sealed
/// grant asks the topology about the caller's row by name). Set with
/// [`shim_set_task_name`]; "" by default.
static CURRENT_TASK_NAME: std::sync::Mutex<&'static str> = std::sync::Mutex::new("");

pub fn current_task_name() -> &'static str {
    *CURRENT_TASK_NAME.lock().unwrap()
}

/// Name the calling task for [`current_task_name`].
pub fn shim_set_task_name(name: &'static str) {
    *CURRENT_TASK_NAME.lock().unwrap() = name;
}

/// The real per-task window allocator, pulled unmodified — see
/// [`process::shm_map_user`].
#[path = "../../../../../../crates/core/sched/src/user_window.rs"]
mod user_window;

/// Each task's window reservations, keyed by [`current_task_tid`], as the
/// kernel keeps them on `Task::user_window`.
static USER_WINDOWS: std::sync::Mutex<Vec<(u32, [[usize; 2]; user_window::USER_WINDOW_RANGES])>> =
    std::sync::Mutex::new(Vec::new());

fn with_user_window<R>(f: impl FnOnce(&mut [[usize; 2]]) -> R) -> R {
    let tid = current_task_tid();
    let mut all = USER_WINDOWS.lock().unwrap_or_else(|e| e.into_inner());
    let i = match all.iter().position(|(t, _)| *t == tid) {
        Some(i) => i,
        None => {
            all.push((tid, [[0; 2]; user_window::USER_WINDOW_RANGES]));
            all.len() - 1
        }
    };
    f(&mut all[i].1)
}

/// Test-only control surface: forget every task's window reservations, what
/// slot reuse does for one task.
pub fn shim_reset_user_windows() {
    USER_WINDOWS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Transcribed from `crates/core/sched/src/process.rs:752`. See the module doc:
/// the permission decision is delegated to the real
/// `azos_mm::vmm::translate_user`, only the guard and the chunking loop
/// are local.
pub fn copy_from_user(kernel_dst: *mut u8, user_src: usize, len: usize) -> bool {
    use azos_arch::mmu::PAGE_SIZE;
    if len == 0 { return true; }
    if user_src.checked_add(len).is_none() { return false; }
    let user_pt = current_user_pt();
    if user_pt == 0 {
        unsafe { core::ptr::copy_nonoverlapping(user_src as *const u8, kernel_dst, len); }
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let va = user_src + done;
        let Some(pa) = azos_mm::vmm::translate_user(user_pt, va, false) else { return false; };
        let chunk = (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
        unsafe { core::ptr::copy_nonoverlapping(pa as *const u8, kernel_dst.add(done), chunk); }
        done += chunk;
    }
    true
}

/// Transcribed from `crates/core/sched/src/process.rs:792`; same caveat as
/// [`copy_from_user`]. It uses the PROBE, not `translate_user(.., true)`:
/// asking whether a write would be permitted must not break a COW page, which
/// is what production does since owner decision 100c.
/// Mirrors `process.rs`'s `user_range_writable`: the same walk `copy_to_user`
/// does, with the same write permission, but without writing anything.
///
/// Not a stand-in — it goes through the real `vmm::translate_user` against the
/// real page table this harness builds, which is the whole point. The two
/// handlers it guards consume something before copying, and a model walker
/// would let a test claim they are safe without ever touching a page table.
pub fn user_range_writable(user_dst: usize, len: usize) -> bool {
    use azos_arch::mmu::PAGE_SIZE;
    if len == 0 { return true; }
    if user_dst.checked_add(len).is_none() { return false; }
    let user_pt = current_user_pt();
    if user_pt == 0 { return true; }
    let mut done = 0usize;
    while done < len {
        let va = user_dst + done;
        if !azos_mm::vmm::user_write_would_be_permitted(user_pt, va) { return false; }
        done += (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
    }
    true
}

/// Mirrors `process.rs`'s `user_range_prepare_write`. The difference from the
/// probe above is the whole point and must survive transcription: this one
/// goes through `translate_user(.., true)`, so a COW leaf is BROKEN here — and
/// the physical address the VA resolves to moves, which is what lets a test
/// tell the two apart without a PTE-flags accessor.
pub fn user_range_prepare_write(user_dst: usize, len: usize) -> bool {
    use azos_arch::mmu::PAGE_SIZE;
    if len == 0 { return true; }
    if user_dst.checked_add(len).is_none() { return false; }
    let user_pt = current_user_pt();
    if user_pt == 0 { return true; }
    let mut done = 0usize;
    while done < len {
        let va = user_dst + done;
        if azos_mm::vmm::translate_user(user_pt, va, true).is_none() { return false; }
        done += (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
    }
    true
}

pub fn copy_to_user(user_dst: usize, kernel_src: *const u8, len: usize) -> bool {
    use azos_arch::mmu::PAGE_SIZE;
    if len == 0 { return true; }
    if user_dst.checked_add(len).is_none() { return false; }
    let user_pt = current_user_pt();
    if user_pt == 0 {
        unsafe { core::ptr::copy_nonoverlapping(kernel_src, user_dst as *mut u8, len); }
        return true;
    }
    let mut done = 0usize;
    while done < len {
        let va = user_dst + done;
        let Some(pa) = azos_mm::vmm::translate_user(user_pt, va, true) else { return false; };
        let chunk = (PAGE_SIZE - (va & (PAGE_SIZE - 1))).min(len - done);
        unsafe { core::ptr::copy_nonoverlapping(kernel_src.add(done), pa as *mut u8, chunk); }
        done += chunk;
    }
    true
}

/// Transcribed from `crates/core/sched/src/process.rs`, for the same reason
/// `copy_from_user`/`copy_to_user` above are: it reads the current task's page
/// table through a module of RV64 assembly, but the decision that matters —
/// whether a user VA resolves at all — is delegated to the real
/// `vmm::translate_user`, exactly as the original does.
///
/// This was `todo!()` until `file_ops_seam.rs` became the first test in the
/// crate to drive a ring-3 path through it. The stub was honest: the note said
/// "not reached by any test in this crate", and it was true, because the file
/// syscalls had no host coverage at all.
pub fn copy_cstr_from_user(dst: &mut [u8], user_ptr: usize) -> Option<usize> {
    use azos_arch::mmu::PAGE_SIZE;
    let user_pt = current_user_pt();
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
        let pa = azos_mm::vmm::translate_user(user_pt, va, false)?;
        let page_remaining = PAGE_SIZE - (va & (PAGE_SIZE - 1));
        let mut off = 0usize;
        while off < page_remaining {
            if len >= dst.len() { return None; }
            let b = unsafe { *((pa + off) as *const u8) };
            dst[len] = b;
            if b == 0 { return Some(len); }
            len += 1;
            off += 1;
        }
    }
}

pub fn sys_brk_impl(_addr: u64) -> i64 {
    todo!("not reached by any test in this crate")
}

/// Marker every panic from here carries — V1.8's kill path is the first
/// caller in this crate — so a test can tell "the task was killed here" from
/// any other panic (`#[should_panic(expected = ...)]`, or a
/// `catch_unwind` that inspects [`shim_take_exit_codes`] afterwards to prove
/// ordering against another recorder, e.g. the trace ring in `shims/ipc`).
pub const TASK_EXIT_MARKER: &str = "SHIM_TASK_EXIT_WITH_CODE";

static EXIT_CODES: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

/// The real function is `-> !`: it never returns, whether by switching to
/// another task (production) or, here, by panicking. A `todo!()` would have
/// worked too (it also diverges) but would not let a test tell "reached
/// here with the right code" from "reached a `todo!()` somewhere else
/// entirely" — see `st/src/unit6_contain.rs`'s `MMIO stand-in` tests
/// (U14-11) for exactly that ambiguity, which this avoids with its own
/// distinct marker and a recorded code.
pub fn task_exit_with_code(code: i32) -> ! {
    EXIT_CODES.lock().unwrap_or_else(|e| e.into_inner()).push(code);
    panic!("{TASK_EXIT_MARKER}: code={code}");
}

/// Test-only control surface: every code passed to [`task_exit_with_code`]
/// since the last call.
pub fn shim_take_exit_codes() -> Vec<i32> {
    std::mem::take(&mut *EXIT_CODES.lock().unwrap_or_else(|e| e.into_inner()))
}

/// `todo!()` unless a test armed it with [`shim_arm_yield`]; armed, it only
/// counts. Unarmed stays the default so that a handler which yields where a
/// test did not expect it still panics instead of quietly looping.
pub fn task_yield() {
    let mut g = YIELDS.lock().unwrap_or_else(|e| e.into_inner());
    match g.as_mut() {
        Some(n) => *n += 1,
        None => todo!("not reached by any test in this crate"),
    }
}

static YIELDS: std::sync::Mutex<Option<u64>> = std::sync::Mutex::new(None);

/// Test-only control surface: make [`task_yield`] count instead of panic.
pub fn shim_arm_yield() {
    *YIELDS.lock().unwrap_or_else(|e| e.into_inner()) = Some(0);
}

/// Test-only control surface: back to `todo!()`.
pub fn shim_disarm_yield() {
    *YIELDS.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Test-only control surface: yields counted since [`shim_arm_yield`]
/// (`None` when unarmed).
pub fn shim_yields() -> Option<u64> {
    *YIELDS.lock().unwrap_or_else(|e| e.into_inner())
}

/// One exit notice as the real `exit_note.rs` table keeps it: which parent
/// may reap it, which child it names, and the child's exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShimExitNote {
    pub parent: u32,
    pub child: u32,
    pub code: i32,
}

/// The notice table [`take_exit_note`] and [`take_exit_note_for`] read, plus
/// the (parent, child) pairs that exist but have not exited. `None` means no
/// test programmed it, and then both readers are `todo!()` as before: a
/// handler test that reached the table without meaning to must still panic.
struct ExitTable {
    notes: Vec<ShimExitNote>,
    alive: Vec<(u32, u32)>,
    asked: Vec<(u32, Option<u32>)>,
}

static EXIT_TABLE: std::sync::Mutex<Option<ExitTable>> = std::sync::Mutex::new(None);

/// Test-only control surface: program the notice table.
pub fn shim_program_exit_notes(notes: &[ShimExitNote], alive: &[(u32, u32)]) {
    *EXIT_TABLE.lock().unwrap_or_else(|e| e.into_inner()) = Some(ExitTable {
        notes: notes.to_vec(),
        alive: alive.to_vec(),
        asked: Vec::new(),
    });
}

/// Test-only control surface: forget the table (back to `todo!()`), and
/// return the notices still unread plus every `(parent, child?)` the readers
/// were asked for, in order.
pub fn shim_take_exit_table() -> Option<(Vec<ShimExitNote>, Vec<(u32, Option<u32>)>)> {
    EXIT_TABLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .map(|t| (t.notes, t.asked))
}

/// Destructive read of the first notice `parent_tid` may reap — the real
/// function's contract (`crates/core/sched/src/exit_note.rs`).
pub fn take_exit_note(parent_tid: u32) -> Option<(u32, i32)> {
    let mut g = EXIT_TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(t) = g.as_mut() else { todo!("not reached by any test in this crate") };
    t.asked.push((parent_tid, None));
    let i = t.notes.iter().position(|n| n.parent == parent_tid)?;
    let n = t.notes.remove(i);
    Some((n.child, n.code))
}

/// Mirrors `azos_sched::exit_stat` (`SYS_EXIT_STATS`, 605): the three
/// selectors answer 0 on the host, anything else `None`.
pub fn exit_stat(which: u64) -> Option<u32> {
    if which <= 2 { Some(0) } else { None }
}

/// Mirrors `azos_sched::WaitpidMiss`. `handlers.rs`'s `sys_waitpid`
/// matches on it, so the shape must exist even though no test in this crate
/// reaches the function that produces it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitpidMiss {
    NotYet,
    NotOurs,
}

/// Destructive read of `child_tid`'s notice: `NotYet` for a child of this
/// parent that has not exited, `NotOurs` for anything else — a notice owned by
/// another parent included.
pub fn take_exit_note_for(
    parent_tid: u32,
    child_tid: u32,
) -> Result<(u32, i32), WaitpidMiss> {
    let mut g = EXIT_TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(t) = g.as_mut() else { todo!("not reached by any test in this crate") };
    t.asked.push((parent_tid, Some(child_tid)));
    if let Some(i) = t.notes.iter().position(|n| n.child == child_tid) {
        if t.notes[i].parent != parent_tid {
            return Err(WaitpidMiss::NotOurs);
        }
        let n = t.notes.remove(i);
        return Ok((n.child, n.code));
    }
    if t.alive.contains(&(parent_tid, child_tid)) {
        return Err(WaitpidMiss::NotYet);
    }
    Err(WaitpidMiss::NotOurs)
}

/// The kernel's semantics verbatim (`scheduler.rs:3147`): `addr == 0` reads
/// the current break; anything else stores it and echoes it back.
pub fn update_user_brk(addr: u64) -> u64 {
    if addr == 0 {
        USER_BRK.load(Ordering::SeqCst)
    } else {
        USER_BRK.store(addr, Ordering::SeqCst);
        addr
    }
}

/// What `exec_user` returns here: a value no real exec path produces, so a test
/// can tell "the handler handed the image to the loader" from any refusal.
pub const SHIM_EXEC_RET: i64 = -77;

static EXEC_LOADS: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

/// What [`exec_user`] returns, settable per test via [`set_exec_user_ret`].
/// Defaults to [`SHIM_EXEC_RET`] so every test written before U07-3 (the
/// handler now branches on `exec_user`'s return, installing the executed
/// image's own filter only when it is exactly `0` — real `exec_user`'s own
/// success code, `process.rs::exec_user`) keeps seeing the same sentinel.
static EXEC_RET: AtomicI64 = AtomicI64::new(SHIM_EXEC_RET);

/// Test-only control surface: make [`exec_user`] return `ret` instead of
/// [`SHIM_EXEC_RET`] — `0` to simulate a successful load (the only value the
/// U07-3 filter-install branch in `exec_bound_image` acts on), `-1` to
/// simulate a failed one, without touching what `shim_take_exec_loads`
/// records (that stays independent of the return value).
pub fn set_exec_user_ret(ret: i64) {
    EXEC_RET.store(ret, Ordering::SeqCst);
}

/// A recording stand-in, not the ELF loader: `exec_binding.rs` reaches it with
/// an image a seccomp profile is bound to, and checks it received exactly the
/// bytes that were hashed. It loads nothing.
pub fn exec_user(elf: &[u8]) -> i64 {
    EXEC_LOADS.lock().unwrap_or_else(|e| e.into_inner()).push(elf.to_vec());
    EXEC_RET.load(Ordering::SeqCst)
}

/// `exec_user` with the row's budget (RFC-0049 M1). Records like
/// [`exec_user`]; the budget is not modelled here.
pub fn exec_user_mem(elf: &[u8], _mem: Option<MemSpec>) -> i64 {
    exec_user(elf)
}

/// Test-only control surface: every image handed to `exec_user` since the last
/// call, oldest first.
pub fn shim_take_exec_loads() -> Vec<Vec<u8>> {
    std::mem::take(&mut *EXEC_LOADS.lock().unwrap_or_else(|e| e.into_inner()))
}

// ── The seccomp image table, real ───────────────────────────────────────────
//
// `handlers.rs` calls `azos_sched::seccomp::image_digest` and
// `image_for_digest` before every ring-3 exec. Those are pulled in whole from
// `crates/core/sched/src/seccomp.rs`, with the table it `include!`s from build/, so
// a test here refuses and accepts exactly the images the kernel does. The two
// modules below are what that file reaches for: `filter.rs` itself, and the
// current task's filter held in a static instead of a TCB slot.

#[allow(dead_code)]
#[path = "../../../../../../crates/core/sched/src/filter.rs"]
pub mod filter;

pub mod task {
    pub use crate::filter::{SyscallFilter, TaskInit, SYSCALL_FILTER_MAX};
}

/// `SYS_TASKINFO` calls the switch census's dump (`crates/core/sched/src/
/// swcensus.rs`), which compiles to nothing without `SWITCH_CENSUS`.
pub mod swcensus {
    #[inline(always)]
    pub fn dump_window() {}
}

pub mod scheduler {
    use crate::filter::SyscallFilter;
    use std::sync::Mutex;

    /// Mirrors `scheduler::task_exit_by_signal` (wave 13): the same exit as
    /// [`crate::task_exit_with_code`] (the signal it records only matters to
    /// a Linux parent's `wait4`, which no test here has).
    pub fn task_exit_by_signal(code: i32) -> ! {
        crate::task_exit_with_code(code)
    }

    /// Mirrors `scheduler::ExecDethreadError` (wave 15, plan 4a).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ExecDethreadError {
        Ending,
    }

    /// Mirrors `scheduler::exec_end_other_threads`: a host task has no
    /// threads, so there is nothing to end.
    pub fn exec_end_other_threads() -> Result<u32, ExecDethreadError> {
        Ok(0)
    }

    /// Mirrors `scheduler::take_current_forced_exit` (RFC-0055): the exit code
    /// of a forced stop pending for the current task. A test arms one with
    /// [`shim_set_forced_exit`]; consumed on read, as the real one is.
    pub fn take_current_forced_exit() -> Option<i32> {
        FORCED_EXIT.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    static FORCED_EXIT: Mutex<Option<i32>> = Mutex::new(None);

    /// Test-only: a forced stop with exit code `code` is pending for the
    /// current task.
    pub fn shim_set_forced_exit(code: Option<i32>) {
        *FORCED_EXIT.lock().unwrap_or_else(|e| e.into_inner()) = code;
    }

    /// Mirror of `scheduler::VdsoFacts` (wave 6), field for field.
    #[derive(Clone, Copy)]
    pub struct VdsoFacts {
        pub idx: usize,
        pub tid: u32,
        pub switches_voluntary: u64,
        pub switches_preempted: u64,
        pub ready_site: u8,
        pub hart: usize,
    }

    /// Mirrors `scheduler::wake_task_by_tid`'s signature for
    /// `crate::vdso_notify::KernelNotifyEnv`. No test reaches it: the notify
    /// wake is proved against a scripted env in `tests/host/ipc-lease-tests`.
    pub fn wake_task_by_tid(_tid: u32, _pred: &dyn Fn(&crate::WaitReason) -> bool) -> bool {
        todo!("not reached by any test in this crate")
    }

    /// Mirrors `scheduler::current_task_vdso_facts`: slot 0, the shim's
    /// current TID, the shim's fixed switch counts.
    pub fn current_task_vdso_facts() -> Option<VdsoFacts> {
        let (v, p) = crate::current_task_switches();
        Some(VdsoFacts {
            idx: 0,
            tid: crate::current_task_tid(),
            switches_voluntary: v,
            switches_preempted: p,
            ready_site: 4,
            hart: crate::current_task_hart(),
        })
    }

    static CURRENT: Mutex<SyscallFilter> = Mutex::new(SyscallFilter::disabled());

    pub fn current_syscall_filter() -> SyscallFilter {
        *CURRENT.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_current_syscall_filter(f: SyscallFilter) {
        *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = f;
    }

    /// Mirrors `scheduler::current_syscall_verdict`: the real
    /// `SyscallFilter::verdict_for` on the current task's filter.
    pub fn current_syscall_verdict(num: u64) -> crate::filter::FilterVerdict {
        current_syscall_filter().verdict_for(num)
    }

    /// Filters of tasks other than the current one, by TID.
    static BY_TID: Mutex<Vec<(u32, SyscallFilter)>> = Mutex::new(Vec::new());

    /// Test-only: give task `tid` the filter `f` (replacing any), for
    /// [`task_syscall_verdict`]; `None` forgets the task.
    pub fn shim_set_task_filter(tid: u32, f: Option<SyscallFilter>) {
        let mut v = BY_TID.lock().unwrap_or_else(|e| e.into_inner());
        v.retain(|(t, _)| *t != tid);
        if let Some(f) = f {
            v.push((tid, f));
        }
    }

    /// Mirrors `scheduler::task_syscall_verdict`: `None` for a TID the shim
    /// was given no filter for (no live task).
    pub fn task_syscall_verdict(tid: u32, num: u64) -> Option<crate::filter::FilterVerdict> {
        let v = BY_TID.lock().unwrap_or_else(|e| e.into_inner());
        v.iter().find(|(t, _)| *t == tid).map(|(_, f)| f.verdict_for(num))
    }
}

#[allow(dead_code)]
#[path = "../../../../../../crates/core/sched/src/seccomp.rs"]
pub mod seccomp;

/// Mirror of `azos_sched::BlockOutcome` (`crates/core/sched/src/wait.rs`).
///
/// **This is a transcribed two-variant tag, not the real type**, because
/// `wait.rs` now pulls `azos_sync::preempt`, which reads `sstatus` and
/// `tp` — see `tests/host/sync-tests` for why that module needs its own arch
/// shim. Pulling it here would drag the whole preemption mechanism into a
/// crate that tests syscall handlers.
///
/// What this crate proves with it is only the *mapping*: `handlers.rs`'s
/// `irq_wait_ret` is the real function, pulled whole, and the test drives it
/// with both variants. Which outcome the kernel actually produces for a given
/// hart state is proved in `tests/host/sched-wake-tests` against the real
/// `task_block_outcome`, not here. If a variant is ever added to the real
/// enum, `irq_wait_ret`'s match stops compiling in the kernel build, which is
/// the backstop for this copy going stale.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockOutcome {
    Returned,
    Refused,
}

/// `todo!()` unless a test armed it with [`shim_arm_block_outcome`]; armed,
/// it does what [`task_block`] does (records the reason, runs the hook) and
/// answers the programmed outcome. Which outcome the real scheduler produces
/// is proved in `tests/host/sched-wake-tests`; this only lets a test see what the
/// handler does with each one. `harness.rs::reset_state` disarms it.
pub fn task_block_outcome(reason: WaitReason) -> BlockOutcome {
    let armed = *BLOCK_OUTCOME.lock().unwrap_or_else(|e| e.into_inner());
    match armed {
        Some(o) => {
            task_block(reason);
            o
        }
        None => todo!("not reached by any test in this crate"),
    }
}

static BLOCK_OUTCOME: std::sync::Mutex<Option<BlockOutcome>> = std::sync::Mutex::new(None);

/// Test-only control surface: make [`task_block_outcome`] answer `o`.
pub fn shim_arm_block_outcome(o: BlockOutcome) {
    *BLOCK_OUTCOME.lock().unwrap_or_else(|e| e.into_inner()) = Some(o);
}

/// Test-only control surface: back to `todo!()`.
pub fn shim_disarm_block_outcome() {
    *BLOCK_OUTCOME.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Mirror of the one `azos_sched::WaitReason` variant the pulled handlers
/// name: `Port`, the reason `SYS_PORT_WAIT_TYPED` (577) blocks on
/// (`crates/core/sched/src/task.rs`). A transcribed tag, not the real enum, for the
/// reason [`BlockOutcome`] above is one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitReason {
    Port(u32),
    /// `SYS_NOTIFY_WAIT` (592, wave 6) blocks on the timer reason with its
    /// deadline; `crate::vdso_notify::KernelNotifyEnv` names it.
    Timer(u64),
    /// `SYS_DRV_IRQ_WAIT` (304) blocks on the IRQ line.
    Irq(u32),
    /// `SYS_IPC_LEASE_ACCEPT` (112) blocks on `(lessee, lessor)`.
    LeaseAccept(u32, u32),
}

/// What a test runs inside [`task_block`]: what other tasks did while the
/// caller slept.
pub type BlockHook = Box<dyn FnMut(WaitReason) + Send>;

/// Stand-in for `azos_sched::UserRegs` (`crates/core/sched/src/task.rs`):
/// `handlers.rs`'s `sys_fork`/`sys_fork_cow` signatures name it, so this shim
/// needs SOME type there to keep those two functions type-checking, even
/// though `process::sys_fork_impl` below is `todo!()` and no test in this
/// crate exercises fork. The real type is ISA-shaped (`[u64; 32]` on
/// riscv64, `azos_arch::fork_regs::ForkRegs` on aarch64 — see its own
/// doc); this host shim has no ISA at all, so it uses the same `[u64; 32]`
/// fallback `task.rs` itself falls back to for every non-kernel-target build.
pub type UserRegs = [u64; 32];

static BLOCKS: std::sync::Mutex<Vec<WaitReason>> = std::sync::Mutex::new(Vec::new());
static BLOCK_HOOK: std::sync::Mutex<Option<BlockHook>> = std::sync::Mutex::new(None);

/// A recording stand-in for `azos_sched::task_block`, not a scheduler. It
/// records the reason, runs the hook a test installed, and returns at once, as
/// a wake would. With no hook every block is a wake that brings nothing, which
/// is what drives 577's loop to its bound. Which task sleeps and what wakes it
/// is proved in `tests/host/sched-wake-tests` against the real scheduler, not here.
pub fn task_block(reason: WaitReason) {
    BLOCKS.lock().unwrap_or_else(|e| e.into_inner()).push(reason);
    // Taken out while it runs, so a hook may itself install another.
    let hook = BLOCK_HOOK.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(mut f) = hook {
        f(reason);
        let mut slot = BLOCK_HOOK.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(f);
        }
    }
}

/// Test-only control surface: install, or clear with `None`, the hook
/// [`task_block`] runs.
pub fn shim_set_block_hook(hook: Option<BlockHook>) {
    *BLOCK_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = hook;
}

/// Test-only control surface: every reason [`task_block`] saw since the last
/// call, oldest first.
pub fn shim_take_blocks() -> Vec<WaitReason> {
    std::mem::take(&mut *BLOCKS.lock().unwrap_or_else(|e| e.into_inner()))
}

pub mod process {
    /// Mirrors `process::PreparedExec` (wave 15, plan 4a): carries what the
    /// recording loader was told to answer.
    pub struct PreparedExec {
        ret: i64,
    }

    /// Mirrors `process::exec_prepare_mem`: records the image like
    /// [`crate::exec_user`]; a loader answer of `-1` is a refused admission
    /// (`None`), any other one is admitted and returned by the commit.
    pub fn exec_prepare_mem(elf: &[u8], mem: Option<crate::MemSpec>) -> Option<PreparedExec> {
        let ret = crate::exec_user_mem(elf, mem);
        (ret != -1).then_some(PreparedExec { ret })
    }

    /// Mirrors `process::exec_commit`.
    pub fn exec_commit(p: PreparedExec) -> i64 {
        p.ret
    }

    /// Mirrors `process::exec_abort`: nothing was built.
    pub fn exec_abort(_p: PreparedExec) {}

    /// `todo!()` unless a test programmed a return with
    /// [`shim_program_fork`]; programmed, it records `(sepc, user_sp, regs
    /// address)` and returns that value.
    pub fn sys_fork_impl(sepc: u64, user_sp: u64, regs: &super::UserRegs) -> i64 {
        let mut g = FORK.lock().unwrap_or_else(|e| e.into_inner());
        let Some((ret, calls)) = g.as_mut() else { todo!("not reached by any test in this crate") };
        calls.push((sepc, user_sp, regs as *const super::UserRegs as usize));
        *ret
    }

    /// [`sys_fork_impl`]'s record and answer; `before_release` is never
    /// run (no child exists here), so the native fork's child setup is not
    /// reached by any test in this crate.
    pub fn sys_fork_impl_hooked(
        sepc: u64,
        user_sp: u64,
        regs: &super::UserRegs,
        _before_release: &mut dyn FnMut(u32) -> bool,
    ) -> i64 {
        sys_fork_impl(sepc, user_sp, regs)
    }

    static FORK: std::sync::Mutex<Option<(i64, Vec<(u64, u64, usize)>)>> =
        std::sync::Mutex::new(None);

    /// Test-only control surface: make [`sys_fork_impl`] answer `ret`.
    pub fn shim_program_fork(ret: i64) {
        *FORK.lock().unwrap_or_else(|e| e.into_inner()) = Some((ret, Vec::new()));
    }

    /// Test-only control surface: forget the programmed answer (back to
    /// `todo!()`) and return every call recorded since it was programmed.
    pub fn shim_take_fork_calls() -> Option<Vec<(u64, u64, usize)>> {
        FORK.lock().unwrap_or_else(|e| e.into_inner()).take().map(|(_, c)| c)
    }

    /// Restated, not pulled — same reason as `user_shm_window` below:
    /// `process.rs` does not build on the host. `handlers.rs` now imports the
    /// real `USER_STACK_TOP` as `USER_VA_TOP` (see its comment) instead of
    /// carrying a second hardcoded `0x8000_0000` literal, so this shim has to
    /// supply the value that import resolves to when `azos_sched` here is
    /// this crate, not the real one. Tests in this crate build with no
    /// platform feature selected (there is no vf2/k1 concept on the host), so
    /// this always matches the real crate's QEMU-`RAM_BASE` value — the one
    /// value that was never wrong before this fix either.
    pub const USER_STACK_TOP: usize = 0x0000_0000_8000_0000; // 2 GiB

    /// Transcribed from `crates/core/sched/src/process.rs` (`shm_map_user` and the
    /// `reserve_window_va` it calls), for `SYS_SHM_MAP_TYPED` (574): the same
    /// refusals (a kernel caller, no pages, no room in the window) and the same
    /// flags, with every PTE installed by the real `azos_mm::vmm::map`, so a
    /// test reads the mapping back through the real `translate_user`. The
    /// addresses come from the real `crates/core/sched/src/user_window.rs`, kept per
    /// task as the kernel keeps them, inside [`super::user_shm_window`].
    pub fn shm_map_user(phys_pages: &[usize], rw: bool) -> Option<usize> {
        use azos_arch::mmu::PAGE_SIZE;
        use azos_arch_api::PagePerms;
        let user_pt = super::current_user_pt();
        if user_pt == 0 || phys_pages.is_empty() {
            return None;
        }
        let (window_base, window_limit) = super::user_shm_window();
        let span = phys_pages.len().checked_mul(PAGE_SIZE)?;
        let base = super::with_user_window(|w| {
            super::user_window::reserve(w, window_base, window_limit, span)
        })?;
        let flags = if rw {
            PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW }
        } else {
            PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RO }
        };
        for (i, &phys) in phys_pages.iter().enumerate() {
            if azos_mm::vmm::map(user_pt, base + i * PAGE_SIZE, phys, flags).is_err() {
                return None;
            }
        }
        Some(base)
    }

    /// `process.rs`'s bound on one user MMIO mapping (1 MiB).
    pub const USER_MMIO_MAX_SIZE: usize = 1024 * 1024;

    /// Transcribed from `crates/core/sched/src/process.rs` (`mmio_map_user`), for
    /// `SYS_MMIO_MAP` (509): the same refusals (empty, above the bound,
    /// misaligned, wrapping, a kernel caller), the same window, the same
    /// flags, the same roll-back, with every PTE installed by the real
    /// `azos_mm::vmm::map`. Nothing here reads the device frames: they are
    /// only written into PTEs, as in the kernel.
    pub fn mmio_map_user(phys_base: usize, size: usize, writable: bool) -> Option<usize> {
        use azos_arch::mmu::PAGE_SIZE;
        use azos_arch_api::PagePerms;
        if size == 0 || size > USER_MMIO_MAX_SIZE {
            return None;
        }
        if phys_base & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
            return None;
        }
        phys_base.checked_add(size)?;
        let user_pt = super::current_user_pt();
        if user_pt == 0 {
            return None;
        }
        let size_pages = size / PAGE_SIZE;
        let (window_base, window_limit) = super::user_shm_window();
        let va_base = super::with_user_window(|w| {
            super::user_window::reserve(w, window_base, window_limit, size)
        })?;
        let flags = PagePerms {
            accessed: true,
            dirty: true,
            ..(if writable { PagePerms::USER_RW } else { PagePerms::USER_RO })
        };
        for i in 0..size_pages {
            let va = va_base + i * PAGE_SIZE;
            if azos_mm::vmm::map(user_pt, va, phys_base + i * PAGE_SIZE, flags).is_err() {
                for j in 0..i {
                    azos_mm::vmm::unmap(user_pt, va_base + j * PAGE_SIZE);
                }
                release_user_window(va_base, size_pages);
                return None;
            }
        }
        Some(va_base)
    }

    /// Mirrors `process.rs`'s `release_user_window`: the same allocator and the
    /// same exact-pair rule, on the current task's reservations.
    pub fn release_user_window(va: usize, pages: usize) -> bool {
        match pages.checked_mul(azos_arch::mmu::PAGE_SIZE) {
            Some(span) => super::with_user_window(|w| super::user_window::release(w, va, span)),
            None => false,
        }
    }
}

/// The shared-memory / MMIO VA window, matching `process.rs`'s
/// `USER_MMIO_BASE` (`USER_STACK_TOP` minus the 512 MiB window) and
/// `USER_MMIO_LIMIT` (`USER_STACK_TOP` minus the 16 KiB user stack,
/// `CONFIG_USER_STACK_SIZE_KB`).
///
/// Restated rather than pulled: `process.rs` is a 4,000-line RV64 module that
/// does not build on the host. Both bounds are exact because tests assert at
/// them: the mmap and demand-allocation ceilings sit at the base, and a
/// released-mapping test cycles through more than the whole window.
pub fn user_shm_window() -> (usize, usize) {
    (process::USER_STACK_TOP - 0x2000_0000, process::USER_STACK_TOP - 16 * 1024)
}

// exec installs the image filter through the crate root (2026-09-26)
pub use scheduler::set_current_syscall_filter;

// The F06 driver registry, real: `crates/core/sched/src/driver.rs` pulled whole, as
// the kernel's `azos_sched` re-exports it. `SYS_DRV_REGISTER` (300),
// `SYS_DRV_HEARTBEAT` (309) and `SYS_DRV_GET_DEVICE` (310) reach it. It is a
// 16-slot process-global table with no reset, so the tests that use it
// register only what they need and read back by the id they were given.
#[allow(dead_code)]
#[path = "../../../../../../crates/core/sched/src/driver.rs"]
pub mod driver;

// The RFC-0049 M4 supervisor table, real, beside the AQ2 table whose restart
// budget it shares. `SYS_DRIVER_REGISTER_TYPED` (556) binds a task to it.
#[path = "../../../../../../crates/core/sched/src/supervisor.rs"]
pub mod supervisor;
pub use driver::{driver_register, driver_start, driver_heartbeat_with_time, driver_info};

/// Wave 13 (THREADS): `azos_sched::group` as host tests see it: a world
/// with no thread groups, every task its own process.
pub mod group {
    pub fn lead_of_idx(_idx: usize) -> u32 { 0 }
    pub fn table_lead_of_idx(_idx: usize) -> u32 { 0 }
    pub fn any_groups() -> bool { false }
    pub fn proc_of(_idx: usize, tid: u32) -> u32 { tid }
    pub fn proc_tid(tid: u32) -> u32 { tid }
    pub fn shares_tables(_tid: u32) -> bool { false }
    pub fn live_members(_leader: u32) -> u32 { 1 }
    pub fn current_group_ending() -> bool { false }
    pub fn set_current_clear_tid(_addr: u64) {}
    pub struct MmGuard;
    pub fn mm_lock() -> MmGuard { MmGuard }
}

/// Wave 13: the process id; with no thread groups, the task's own.
pub fn current_proc_tid() -> u32 { current_task_tid() }
