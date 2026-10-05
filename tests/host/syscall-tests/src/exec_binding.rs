// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Ring-3 `SYS_EXEC` / `SYS_EXECPATH` load only images a seccomp image profile
// is bound to (owner decision 2026-09-14: the table is a whitelist of user
// images, on every exec path).
//
// `azos_sched::seccomp` here is the REAL `crates/core/sched/src/seccomp.rs`,
// with the table the build generated (`shims/sched` pulls it in by `#[path]`),
// and `exec_user` is a recorder that loads nothing. So these tests refuse and
// accept exactly the images the kernel does, and see exactly which bytes
// reached the loader.
//
// `sys_execpath` is covered by source, not driven: reaching its check needs a
// `FileOps` installed, and that seam is a process-wide static whose
// nothing-installed half `file_ops_seam.rs` asserts. Both handlers load through
// the one helper, `exec_bound_image`, which the `sys_exec` tests drive.

use super::harness::serial;
use azos_abi::error::Errno;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A VA clear of what the other test files use.
const SCRATCH: usize = 0x0080_0000;

/// Bytes that are no shipped image: refused.
const NOT_SHIPPED: &[u8] = b"\x7fELF bytes that no image profile is bound to";

fn fresh_user_pt(tid: u32) -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    pt
}

/// Map whole pages at `SCRATCH` and copy `bytes` there, as a ring-3 program's
/// buffer would sit.
fn place(pt: usize, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
        azos_mm::vmm::map(pt, SCRATCH + off, phys, PagePerms::USER_RW).expect("map");
        let n = (bytes.len() - off).min(PAGE_SIZE);
        unsafe { core::ptr::copy_nonoverlapping(bytes[off..].as_ptr(), phys as *mut u8, n) };
        off += PAGE_SIZE;
    }
}

/// uhello's bytes, compiled in from the same `build/` the image table
/// (`build/image_hashes.rs`, `include!`d by `seccomp.rs`) is compiled from.
///
/// Read at compile time, not at run time (wave 11 fix). The file used to be
/// read when the test ran, the table when the crate was compiled, so a
/// `make` that rewrote `build/` in between (a gate or another worktree's
/// build, a libsys change) left uhello's digest in no row of the compiled
/// table, and the three shipped-image tests below failed together as if the
/// binding had refused a shipped image: "3 tests in 1 of 8 runs". Compiled in,
/// both come from one instant, and cargo rebuilds the crate when either file
/// changes. A missing file is a compile error, as a missing table already is.
const SHIPPED_UHELLO: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../build/uhello.elf"));

/// [`SHIPPED_UHELLO`], after checking that the table compiled beside it binds
/// it. The one window left is a compile in the middle of a `make` (uhello
/// rewritten, the table not yet): that is named as what it is rather than
/// failing the exec assertions.
fn shipped_uhello() -> Vec<u8> {
    let d = azos_sched::seccomp::image_digest(SHIPPED_UHELLO);
    assert!(
        azos_sched::seccomp::image_for_digest(&d).is_some(),
        "build/uhello.elf (sha256 {:02x}{:02x}{:02x}{:02x}..) is in no row of build/image_hashes.rs: \
         the two were compiled from different `make` runs (build/ was rewritten while this crate \
         compiled). Run `make build/image_hashes.rs`, then the tests again; this is not an \
         exec-binding failure.",
        d[0], d[1], d[2], d[3]
    );
    SHIPPED_UHELLO.to_vec()
}

static REFUSALS: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());
static SUMMARIES: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());
static NOW: AtomicU64 = AtomicU64::new(0);
const WINDOW: u64 = 1_000;

fn refusal_hook(action_code: u8, digest_head: u32) {
    REFUSALS.lock().unwrap_or_else(|e| e.into_inner()).push((action_code, digest_head));
}

fn summary_hook(kind: u8, count: u32) {
    SUMMARIES.lock().unwrap_or_else(|e| e.into_inner()).push((kind, count));
}

fn clock() -> u64 {
    NOW.load(Ordering::SeqCst)
}

fn refusals() -> Vec<(u8, u32)> {
    REFUSALS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn summaries() -> Vec<(u8, u32)> {
    SUMMARIES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The recorder and the per-task bound installed, both logs empty, the clock
/// at 0, the loader's log drained, the current filter off.
fn arm() {
    __cap_deny_limiter_clear_for_tests();
    REFUSALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    SUMMARIES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    NOW.store(0, Ordering::SeqCst);
    set_cap_deny_limiter(clock, WINDOW, summary_hook);
    set_exec_refused_recorder(refusal_hook);
    let _ = azos_sched::shim_take_exec_loads();
    azos_sched::scheduler::set_current_syscall_filter(azos_sched::filter::SyscallFilter::disabled());
    azos_sched::set_exec_user_ret(azos_sched::SHIM_EXEC_RET);
}

fn disarm() {
    __exec_refused_recorder_clear_for_tests();
    __cap_deny_limiter_clear_for_tests();
    azos_sched::scheduler::set_current_syscall_filter(azos_sched::filter::SyscallFilter::disabled());
    azos_sched::set_exec_user_ret(azos_sched::SHIM_EXEC_RET);
}

fn digest_head(bytes: &[u8]) -> u32 {
    let d = azos_sched::seccomp::image_digest(bytes);
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// **Refused, recorded, never loaded, filter untouched.** An image no profile
/// is bound to gets `EACCES`, one `SAFETY_EXEC_REFUSED` record with the ring-3
/// action and the digest's first four bytes, no call into the loader, and the
/// caller keeps exactly the filter it had.
///
/// **Canary.** Call `azos_sched::exec_user(elf)` without the
/// `exec_image_is_bound` check in `exec_bound_image`: the loader receives the
/// image and the return is the shim's.
#[test]
fn exec_of_an_image_no_profile_is_bound_to_is_refused_and_recorded() {
    let _g = serial();
    arm();
    let pt = fresh_user_pt(41);
    place(pt, NOT_SHIPPED);

    let mut mine = azos_sched::filter::SyscallFilter::disabled();
    mine.enabled = true;
    mine.allow(221);
    azos_sched::scheduler::set_current_syscall_filter(mine);

    let rc = sys_exec(SCRATCH as u64, NOT_SHIPPED.len() as u64);
    assert_eq!(rc, Errno::EACCES.to_syscall_ret(), "an unbound image was not refused with EACCES");
    assert!(azos_sched::shim_take_exec_loads().is_empty(), "the refused image reached the loader");
    assert_eq!(refusals(), vec![(EXEC_REFUSED_ACTION_RING3, digest_head(NOT_SHIPPED))]);

    let after = azos_sched::scheduler::current_syscall_filter();
    assert!(
        after.enabled && !after.audit && after.count == 1 && after.is_allowed(221) && !after.is_allowed(222),
        "the refusal changed the caller's filter",
    );
    disarm();
}

/// **A shipped image goes through, byte for byte.** uhello's bytes, as the
/// build left them, reach the loader unchanged, and nothing is recorded.
///
/// **Canary.** Make `exec_image_is_bound` return `false` unconditionally: the
/// shipped image is refused.
#[test]
fn exec_of_a_shipped_image_reaches_the_loader_with_the_bytes_hashed() {
    let _g = serial();
    arm();
    let pt = fresh_user_pt(42);
    let uhello = shipped_uhello();
    place(pt, &uhello);

    let rc = sys_exec(SCRATCH as u64, uhello.len() as u64);
    assert_eq!(rc, azos_sched::SHIM_EXEC_RET, "a shipped image did not reach the loader");
    assert_eq!(azos_sched::shim_take_exec_loads(), vec![uhello]);
    assert!(refusals().is_empty(), "a shipped image was recorded as refused: {:?}", refusals());
    disarm();
}

/// **U07-3 / U14-4.** A ring-3 exec that reaches the loader and SUCCEEDS
/// (`exec_user` returns `0`, real `process.rs::exec_user`'s own success code)
/// must land on the EXECUTED image's own row, not keep whatever filter the
/// caller had — the exact gap the audit named: ABITEST's row grants
/// `SYS_EXEC`/`SYS_EXECPATH` with 53 syscalls (`seccomp.rs:581`), and before
/// this fix any bound image it exec'd ran under that wide row forever.
///
/// The pre-exec filter here (`mine`, `allow(921)`) stands in for such a wide
/// row: `921` is not a real syscall number any shipped profile grants, so it
/// surviving into `after` would prove the swap did not happen.
///
/// **Canary.** Delete the `if r == 0 { ... set_current_syscall_filter ... }`
/// block from `exec_bound_image`: `after` stays `mine`, `921` is still
/// allowed, and the assertion on uhello's own syscalls goes red.
#[test]
fn exec_of_a_shipped_image_that_succeeds_installs_the_images_own_filter() {
    let _g = serial();
    arm();
    let pt = fresh_user_pt(44);
    let uhello = shipped_uhello();
    place(pt, &uhello);

    let mut mine = azos_sched::filter::SyscallFilter::disabled();
    mine.enabled = true;
    mine.allow(921);
    azos_sched::scheduler::set_current_syscall_filter(mine);
    azos_sched::set_exec_user_ret(0); // simulate the real `exec_user`'s success code

    let rc = sys_exec(SCRATCH as u64, uhello.len() as u64);
    assert_eq!(rc, 0, "a successful exec did not return the loader's 0");
    assert_eq!(azos_sched::shim_take_exec_loads(), vec![uhello.clone()]);

    let digest = azos_sched::seccomp::image_digest(&uhello);
    let profile = azos_sched::seccomp::image_for_digest(&digest)
        .expect("uhello.elf is a shipped image with a bound profile");
    let want = azos_sched::seccomp::image_filter(profile);

    let after = azos_sched::scheduler::current_syscall_filter();
    assert!(after.enabled, "the executed image's filter must stay enabled");
    assert!(
        !after.is_allowed(921),
        "the caller's OLD filter (mine, allow(921)) survived a successful exec",
    );
    assert_eq!(
        after.count, want.count,
        "the installed filter is not the executed image's own row",
    );
    for n in 0u16..1024 {
        assert_eq!(
            after.is_allowed(n), want.is_allowed(n),
            "syscall {n}: installed filter disagrees with the image's own row",
        );
    }
    disarm();
}

/// **U07-3, the failure half.** `exec_user` returning `-1` (a real failure —
/// `load_elf` found no valid ELF) must leave the caller's OWN filter and its
/// own still-running image alone: there is no new image to confine, and
/// installing one anyway would drop the confinement the caller had.
///
/// **Canary.** Move the `if r == 0` check so the filter installs
/// unconditionally: `after` becomes uhello's row even though the exec did
/// not happen, and `921` — the caller's own marker syscall — goes missing.
#[test]
fn exec_of_a_shipped_image_that_fails_does_not_touch_the_callers_filter() {
    let _g = serial();
    arm();
    let pt = fresh_user_pt(45);
    let uhello = shipped_uhello();
    place(pt, &uhello);

    let mut mine = azos_sched::filter::SyscallFilter::disabled();
    mine.enabled = true;
    mine.allow(921);
    azos_sched::scheduler::set_current_syscall_filter(mine);
    azos_sched::set_exec_user_ret(-1); // simulate a real `exec_user` failure

    let rc = sys_exec(SCRATCH as u64, uhello.len() as u64);
    assert_eq!(rc, -1, "a failed exec did not propagate the loader's -1");

    let after = azos_sched::scheduler::current_syscall_filter();
    assert!(after.is_allowed(921), "a failed exec replaced the caller's own filter");
    assert_eq!(after.count, mine.count, "a failed exec changed the caller's filter shape");
    disarm();
}

/// **Bounded.** A ring-3 loop of refused execs writes at most
/// `DENIAL_RECORDS_PER_WINDOW` records per window; the rest come out as one
/// summary under `DENIAL_KIND_EXEC_REFUSED`. Every call is still refused.
///
/// **Canary.** Call the recorder without `admit_denial_record` in
/// `exec_image_is_bound`: twenty records.
#[test]
fn a_loop_of_refused_execs_is_bounded_under_its_own_kind() {
    let _g = serial();
    arm();
    let pt = fresh_user_pt(43);
    place(pt, NOT_SHIPPED);

    for _ in 0..20 {
        assert_eq!(sys_exec(SCRATCH as u64, NOT_SHIPPED.len() as u64), Errno::EACCES.to_syscall_ret());
    }
    assert_eq!(refusals().len(), DENIAL_RECORDS_PER_WINDOW as usize, "the refusal loop was not bounded");
    NOW.store(WINDOW, Ordering::SeqCst);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(DENIAL_KIND_EXEC_REFUSED, 16)]);
    assert!(azos_sched::shim_take_exec_loads().is_empty());
    disarm();
}

/// **Both handlers, one door.** `sys_exec` and `sys_execpath` hand the bounce
/// buffer to `exec_bound_image`, and neither calls the loader itself.
///
/// **Canary.** In `sys_execpath`, replace
/// `exec_bound_image_digest(&buf[..v.total], &v.digest)` with
/// `azos_sched::exec_user(&buf[..v.total])`. (Wave 14: `sys_execpath` reads
/// through `image_cache::read_verified`, whose digest is of those bytes.)
#[test]
fn both_exec_handlers_load_only_through_the_bound_image_check() {
    const HANDLERS: &str = include_str!("../../../../crates/core/syscall/src/handlers.rs");
    for (name, call) in [
        ("pub fn sys_exec(", "exec_bound_image(&buf[..len])"),
        ("pub fn sys_execpath(", "exec_bound_image_digest(&buf[..v.total], &v.digest)"),
    ] {
        let at = HANDLERS.find(name).unwrap_or_else(|| panic!("{name} not found"));
        let end = at + HANDLERS[at..].find("\n}\n").expect("end of the function");
        let body = &HANDLERS[at..end];
        assert!(body.contains(call), "{name} does not load through `{call}`:\n{body}");
        assert!(!body.contains("exec_user("), "{name} calls the loader directly:\n{body}");
    }
}

/// A file system whose one file is [`NOT_SHIPPED`], with a content stamp, so
/// `sys_execpath` reads it through the verified-image cache (wave 14).
struct StampedDisk { hashed: std::sync::atomic::AtomicU32 }
impl crate::file_ops::FileOps for StampedDisk {
    fn open(&self, _: &[u8], _: u32) -> i64 { -1 }
    fn close(&self, _: i32) -> i64 { -1 }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { -1 }
    fn write(&self, _: i32, _: &[u8]) -> i64 { -1 }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { -1 }
    fn dup(&self, _: i32) -> i64 { -1 }
    fn dup2(&self, _: i32, _: i32) -> i64 { -1 }
    fn mkdir(&self, _: &[u8]) -> i64 { -1 }
    fn unlink(&self, _: &[u8]) -> i64 { -1 }
    fn readdir(&self, _: &[u8], _: u32) -> Option<([u8; 64], u32, bool)> { None }
    fn release_all(&self, _: u32) -> usize { 0 }
    fn read_whole(&self, _: &[u8], dst: &mut [u8]) -> usize {
        dst[..NOT_SHIPPED.len()].copy_from_slice(NOT_SHIPPED);
        NOT_SHIPPED.len()
    }
    fn read_whole_with(&self, p: &[u8], dst: &mut [u8], sink: &mut dyn FnMut(&[u8])) -> usize {
        self.hashed.fetch_add(1, Ordering::SeqCst);
        let n = self.read_whole(p, dst);
        sink(&dst[..n]);
        n
    }
    fn content_stamp(&self, _: &[u8]) -> Option<crate::file_ops::ContentStamp> {
        Some(crate::file_ops::ContentStamp { fs: 7, epoch: 1, id: 3, size: NOT_SHIPPED.len() as u64 })
    }
}
static STAMPED: StampedDisk = StampedDisk { hashed: std::sync::atomic::AtomicU32::new(0) };

/// **A cached digest changes no refusal (wave 14, SPAWNCACHE).** An image no
/// profile is bound to, exec'd by path twice: the second exec takes its
/// digest from the verified-image cache (no hash pass) and is refused and
/// recorded exactly as the first, under the same digest, and nothing reaches
/// the loader.
#[test]
fn a_cached_digest_of_an_unbound_image_is_refused_again() {
    let _g = serial();
    arm();
    crate::image_cache::clear();
    STAMPED.hashed.store(0, Ordering::SeqCst);
    crate::file_ops::set_file_ops(&STAMPED);
    let pt = fresh_user_pt(44);
    place(pt, b"/fat/NOPE.ELF\0");
    for _ in 0..2 {
        assert_eq!(sys_execpath(SCRATCH as u64), Errno::EACCES.to_syscall_ret());
    }
    crate::file_ops::__file_ops_clear_for_tests();
    assert_eq!(STAMPED.hashed.load(Ordering::SeqCst), 1, "the second exec was a cache hit");
    let head = digest_head(NOT_SHIPPED);
    assert_eq!(refusals(), vec![(EXEC_REFUSED_ACTION_RING3, head); 2]);
    assert!(azos_sched::shim_take_exec_loads().is_empty());
    crate::image_cache::clear();
    disarm();
}
