// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Front mmap-file (storage L11, part B): `NODE_MMAP`, the first user of the
// page cache, against the REAL `file_map.rs`, `handlers.rs` (munmap, mprotect,
// fsync), `pager.rs`, `region.rs`, `vmm.rs` and `memobj.rs` on the shim arena.
// The file is a byte vector behind the real `PageBacking` seam, which counts
// what the cache asked of it.
//
// What each row pins, and the mutation that turns it red (by hand, 2026-10-16;
// discriminates / does not / did not compile):
//
// * `shared_mappers_get_one_frame`: two tasks map the same file and the frame
//   each page table holds is the cache's own, equal in both; a store by one is
//   read by the other. Mutation: `object_of` always making a new object ->
//   the frames differ: red.
// * `a_shared_store_reaches_the_file_at_fsync_and_at_unmap`: the file changes
//   only at the sync or the unmap, never lengthens, and the booking, the
//   reference and the window go with the mapping. Mutation: `unmap_finish`
//   not writing back -> the unmap half red; `flush_fd` a no-op -> the sync
//   half red.
// * `a_private_mapping_copies_the_page_and_never_writes`: the private page is
//   not the cache's frame, a store to it is invisible to the shared mapper and
//   to the file, and unmapping gives its frame and charge back. Mutation:
//   `resolve_file_fault` mapping the cache frame for a private region -> red.
// * `a_mapping_across_windows_is_one_range_of_two_objects`.
// * `a_cut_through_a_file_mapping_is_refused`, `mprotect_leaves_a_file_mapping_alone`.
// * `a_window_is_mapped_once_per_task`.
// * `refusals`: the seam's `None`, a read-only descriptor, a bad range, flags.
// * `the_exit_of_a_mapper_writes_its_stores_to_the_file`, `a_store_after_the_last_sync_still_reaches_the_file_at_exit`, `the_exit_of_a_mapper_writes_back_only_its_own_windows`.
// * `a_fork_child_gets_the_private_regions_only`.
//
// Canaries (by hand, 2026-10-17; discriminates / does not / did not compile):
// * `exit_writeback` doing nothing: the three exit rows red.
// * `exit_writeback` after `memobj_release_all` (the booking gone):
//   `a_store_after_the_last_sync_still_reaches_the_file_at_exit` red, the
//   others green (their stores were marked dirty by the fault).
// * `exit_writeback` writing back every window, not the task's own:
//   `the_exit_of_a_mapper_writes_back_only_its_own_windows` red.
// * Does not discriminate: the once-per-object dedupe (a second write of a
//   clean page writes nothing); the `Full` fallback (no row maps 33 windows).
//
// Included into `mod handlers` (see `lib.rs`), so `sys_*` resolve directly.

use super::harness::serial;
use crate::file_ops::FileMapSource;
use azos_abi::error::Errno;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;
use azos_ipc::cap::CapPerms;
use azos_mm::pager::{PageBacking, PageIoError, PageKey, PAGE_KEY_LEN};
use std::sync::Mutex;

const SHARED: u64 = crate::file_map::MAP_SHARED;
const PRIVATE: u64 = crate::file_map::MAP_PRIVATE;
const RW: u64 = 3;
const RO: u64 = 1;
const O_RDONLY: u64 = 0;
const O_RDWR: u64 = 2;

/// Pages of a cache window (`MAX_MEMOBJ_PAGES`).
const WINDOW: usize = 64;

// ── The files ─────────────────────────────────────────────────────────────

/// A file: its bytes and what the cache asked of it.
struct TFile {
    data: Mutex<Vec<u8>>,
    reads: Mutex<Vec<(u64, usize)>>,
    writes: Mutex<Vec<(u64, usize)>>,
}

const EMPTY_FILE: TFile =
    TFile { data: Mutex::new(Vec::new()), reads: Mutex::new(Vec::new()), writes: Mutex::new(Vec::new()) };

/// Files `A`, `B` and `C` (the key's first byte is their index).
static FILES: [TFile; 3] = [EMPTY_FILE; 3];

fn pattern(i: usize) -> u8 {
    (i % 251 + 1) as u8
}

/// Put `len` bytes of the pattern in file `idx` and forget what was asked of it.
fn fill_file(idx: usize, len: usize) {
    *FILES[idx].data.lock().unwrap() = (0..len).map(pattern).collect();
    FILES[idx].reads.lock().unwrap().clear();
    FILES[idx].writes.lock().unwrap().clear();
}

fn bytes_of(idx: usize) -> Vec<u8> {
    FILES[idx].data.lock().unwrap().clone()
}

fn writes_of(idx: usize) -> Vec<(u64, usize)> {
    FILES[idx].writes.lock().unwrap().clone()
}

/// The filesystem's backing: one value for every file (as in the kernel).
struct Backing;

impl PageBacking for Backing {
    fn read_page(&self, key: &PageKey, off: u64, dst: &mut [u8]) -> Result<usize, PageIoError> {
        let f = &FILES[key.0[0] as usize];
        f.reads.lock().unwrap().push((off, dst.len()));
        let d = f.data.lock().unwrap();
        let off = off as usize;
        let n = dst.len().min(d.len().saturating_sub(off));
        dst[..n].copy_from_slice(&d[off..off + n]);
        Ok(n)
    }

    fn write_page(&self, key: &PageKey, off: u64, src: &[u8]) -> Result<(), PageIoError> {
        let f = &FILES[key.0[0] as usize];
        f.writes.lock().unwrap().push((off, src.len()));
        let mut d = f.data.lock().unwrap();
        let off = off as usize;
        assert!(off + src.len() <= d.len(), "a write-back lengthened the file");
        d[off..off + src.len()].copy_from_slice(src);
        Ok(())
    }
}

static BACKING: Backing = Backing;

fn key_of(idx: usize) -> PageKey {
    let mut k = [0u8; PAGE_KEY_LEN];
    k[0] = idx as u8;
    PageKey(k)
}

// ── The stand-in filesystem ───────────────────────────────────────────────

/// Open descriptors: `(fd, file, opened for writing)`; file 9 is a ramfs file
/// the cache cannot serve.
static OPEN: Mutex<Vec<(i32, usize, bool)>> = Mutex::new(Vec::new());

struct Disk;

impl crate::file_ops::FileOps for Disk {
    fn open_at(&self, _root: &[u8], rel: &[u8], flags: u32) -> i64 {
        let idx = match rel.first() {
            Some(b'A') => 0,
            Some(b'B') => 1,
            Some(b'C') => 2,
            Some(b'N') => 9,
            _ => return -1,
        };
        let mut open = OPEN.lock().unwrap();
        let fd = (3..).find(|fd| !open.iter().any(|o| o.0 == *fd)).unwrap();
        open.push((fd, idx, flags & 3 != 0));
        fd as i64
    }
    fn close(&self, fd: i32) -> i64 {
        OPEN.lock().unwrap().retain(|o| o.0 != fd);
        0
    }
    fn read(&self, _fd: i32, _dst: &mut [u8]) -> i64 { -1 }
    fn write(&self, _fd: i32, _src: &[u8]) -> i64 { -1 }
    fn lseek(&self, _fd: i32, _offset: i64, _whence: i32) -> i64 { -1 }
    fn dup(&self, _fd: i32) -> i64 { -1 }
    fn mkdir(&self, _path: &[u8]) -> i64 { -1 }
    fn unlink(&self, _path: &[u8]) -> i64 { -1 }
    fn readdir(&self, _path: &[u8], _index: u32) -> Option<([u8; 64], u32, bool)> { None }
    fn release_all(&self, _tid: u32) -> usize { 0 }
    fn read_whole(&self, _path: &[u8], _dst: &mut [u8]) -> usize { 0 }
    fn fsync(&self, _fd: i32) -> i64 { 0 }
    fn map_source(&self, fd: i32) -> Option<FileMapSource> {
        let (_, idx, w) = *OPEN.lock().unwrap().iter().find(|o| o.0 == fd)?;
        if idx == 9 {
            return None;
        }
        let size = FILES[idx].data.lock().unwrap().len() as u64;
        Some(FileMapSource { backing: &BACKING, key: key_of(idx), size, writable: w })
    }
}

static DISK: Disk = Disk;

// ── The tasks ─────────────────────────────────────────────────────────────

/// A scratch VA the path of an open is read from.
const SCRATCH: usize = 0x0070_0000;

/// A ring-3 task: an address space, its capability table and a directory
/// capability to open beneath.
struct Task {
    tid: u32,
    pt: usize,
    path_page: usize,
    dir: u64,
}

impl Drop for Task {
    fn drop(&mut self) {
        azos_mm::pager::forget(self.pt);
        azos_ipc::memobj::memobj_release_all(self.tid);
        crate::file_ops::__file_ops_clear_for_tests();
    }
}

fn task(tid: u32, slot: usize) -> Task {
    ipc_task_pool::shim_bind(tid, slot);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let path_page = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::pager::forget(pt);
    azos_mm::vmm::map(pt, SCRATCH, path_page, PagePerms::USER_RW).expect("map");
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    azos_sched::shim_set_page_limit(0);
    azos_sched::shim_set_mem_locked(false);
    azos_sched::shim_set_sched_class(3);
    azos_sched::shim_set_brk(0x10_0000);
    crate::file_ops::set_file_ops(&DISK);
    azos_ipc::file_cap::reset_for_tests();
    let dir = azos_ipc::file_cap::file_tree_grant_cap(tid, "/fat", CapPerms::RW).expect("tree grant");
    Task { tid, pt, path_page, dir: dir.raw().as_raw() as u64 }
}

/// Make `t` the running task.
fn enter(t: &Task) {
    azos_sched::set_current_user_pt(t.pt);
    azos_sched::set_current_task_tid(t.tid);
    azos_sched::shim_set_brk(azos_sched::update_user_brk(0).max(0x10_0000));
}

/// Open file `name` ('A', 'B', 'C', 'N') as `t`.
fn open_as(t: &Task, name: u8, flags: u64) -> u64 {
    enter(t);
    unsafe { core::ptr::copy_nonoverlapping([name, 0].as_ptr(), t.path_page as *mut u8, 2) };
    let r = super::sys_file_openat_typed(t.dir, SCRATCH as u64, flags);
    assert!(r >= 0, "open {} failed: {r}", name as char);
    r as u64
}

fn mmap_as(t: &Task, cap: u64, len: usize, off: usize, prot: u64, flags: u64) -> i64 {
    enter(t);
    crate::file_map::sys_file_mmap(cap, len as u64, off as u64, prot, flags)
}

fn mmap_ok(t: &Task, cap: u64, len: usize, off: usize, prot: u64, flags: u64) -> usize {
    let r = mmap_as(t, cap, len, off, prot, flags);
    assert!(r > 0, "NODE_MMAP failed: {r}");
    r as usize
}

fn fault(t: &Task, va: usize) {
    enter(t);
    assert!(azos_mm::vmm::handle_demand_fault(t.pt, va).is_ok(), "fault at {va:#x}");
}

/// The frame under `va`, which must be mapped.
fn frame(t: &Task, va: usize) -> usize {
    azos_mm::vmm::translate_user(t.pt, va, false).expect("mapped") & !(PAGE_SIZE - 1)
}

fn page_bytes(phys: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, PAGE_SIZE) }
}

fn munmap_as(t: &Task, va: usize, len: usize) -> i64 {
    enter(t);
    super::sys_munmap(va as u64, len as u64)
}

/// The file region of `t` that holds `va`.
fn region_at(t: &Task, va: usize) -> azos_mm::pager::FileRegion {
    let mut out = [azos_mm::pager::FileRegion::NONE; 8];
    let n = azos_mm::pager::file_regions_in(t.pt, 0, azos_sched::user_shm_window().1, &mut out).expect("regions");
    *out[..n].iter().find(|r| r.start <= va && va < r.end).expect("a file region holds the address")
}

/// The cache object of the file region at `va`.
fn obj_at(t: &Task, va: usize) -> u32 {
    region_at(t, va).obj
}

/// Empty the registry and the object table of what a test left, and the
/// cache's use counts with them.
fn clean() {
    crate::file_map::__reset_for_tests();
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[test]
fn shared_mappers_get_one_frame() {
    let _g = serial();
    clean();
    fill_file(0, 3 * PAGE_SIZE + 100);
    let (a, b) = (task(7101, 51), task(7102, 52));
    let (fa, fb) = (open_as(&a, b'A', O_RDWR), open_as(&b, b'A', O_RDWR));
    // Something charged already, so that a discharge of what was never charged
    // cannot hide at zero.
    enter(&a);
    assert!(super::sys_mmap(0, (8 * PAGE_SIZE) as u64, RW, 0, u64::MAX, 0) > 0);
    let charged = azos_sched::shim_user_pages();
    assert_eq!(charged, 8);
    let va = mmap_ok(&a, fa, 4 * PAGE_SIZE, 0, RW, SHARED);
    assert_eq!(azos_sched::shim_user_pages(), charged, "a shared mapping is the cache's memory: no charge");
    let vb = mmap_ok(&b, fb, 4 * PAGE_SIZE, 0, RW, SHARED);

    // Nothing is read until a page is touched.
    assert!(FILES[0].reads.lock().unwrap().is_empty(), "a map reads nothing");
    fault(&a, va + PAGE_SIZE);
    fault(&b, vb + PAGE_SIZE);
    let (pa, pb) = (frame(&a, va + PAGE_SIZE), frame(&b, vb + PAGE_SIZE));
    assert_eq!(pa, pb, "two mappers of one file must hold one frame");
    assert_eq!(FILES[0].reads.lock().unwrap().len(), 1, "one fill for two mappers");
    // It is the cache's frame: the object names it.
    let obj = obj_at(&a, va);
    assert_eq!(azos_ipc::memobj::memobj_page_phys_ref(obj, 1), Ok(Some(pa)));
    assert_eq!(&page_bytes(pa)[..4], &bytes_of(0)[PAGE_SIZE..PAGE_SIZE + 4], "the page is the file's");

    // A store by one is read by the other, with no file write between.
    page_bytes(pa)[7] = 0xEE;
    assert_eq!(page_bytes(pb)[7], 0xEE);
    assert!(writes_of(0).is_empty());

    // The short last page: the file's 100 bytes, zeros after them.
    fault(&a, va + 3 * PAGE_SIZE);
    let last = page_bytes(frame(&a, va + 3 * PAGE_SIZE));
    assert_eq!(&last[..100], &bytes_of(0)[3 * PAGE_SIZE..]);
    assert!(last[100..].iter().all(|&x| x == 0), "past the end of the file is zeros");

    // Both unmap (most of the pages never touched): nothing is discharged that
    // was not charged. The cache goes with the last user, and its frame with it.
    assert_eq!(munmap_as(&a, va, 4 * PAGE_SIZE), 0);
    assert_eq!(azos_sched::shim_user_pages(), charged, "unmapping a shared mapping discharged pages it never paid");
    assert_eq!(munmap_as(&b, vb, 4 * PAGE_SIZE), 0);
    drop((a, b));
    let open = azos_mm::shim_pages_in_use();
    clean();
    assert!(azos_mm::shim_pages_in_use() < open, "closing the cache gave its frames back");
}

#[test]
fn a_shared_store_reaches_the_file_at_fsync_and_at_unmap() {
    let _g = serial();
    clean();
    fill_file(0, 2 * PAGE_SIZE + 10);
    let a = task(7103, 53);
    let fa = open_as(&a, b'A', O_RDWR);
    let va = mmap_ok(&a, fa, 3 * PAGE_SIZE, 0, RW, SHARED);
    fault(&a, va);
    fault(&a, va + 2 * PAGE_SIZE);
    page_bytes(frame(&a, va))[1] = 0xA1;
    page_bytes(frame(&a, va + 2 * PAGE_SIZE))[3] = 0xA3;
    assert!(writes_of(0).is_empty(), "a store alone writes nothing");

    // The sync of the file: its mapped pages are part of it.
    enter(&a);
    assert_eq!(super::sys_fsync_typed(fa), 0);
    let file = bytes_of(0);
    assert_eq!(file.len(), 2 * PAGE_SIZE + 10, "a write-back never lengthens the file");
    assert_eq!(file[1], 0xA1);
    assert_eq!(file[2 * PAGE_SIZE + 3], 0xA3);
    assert!(writes_of(0).iter().all(|&(off, len)| off + len as u64 <= file.len() as u64));

    // A store after the sync is still written back at the unmap.
    page_bytes(frame(&a, va))[2] = 0xB2;
    assert_eq!(munmap_as(&a, va, 3 * PAGE_SIZE), 0);
    assert_eq!(bytes_of(0)[2], 0xB2, "the unmap writes the page back");

    // The mapping's booking, reference and window went with it: the same
    // window maps again, and nothing of the task is left in the object.
    let again = mmap_ok(&a, fa, PAGE_SIZE, 0, RO, SHARED);
    assert_eq!(munmap_as(&a, again, PAGE_SIZE), 0);
    drop(a);
    clean();
}

#[test]
fn a_private_mapping_copies_the_page_and_never_writes() {
    let _g = serial();
    clean();
    fill_file(0, 2 * PAGE_SIZE);
    let (a, b) = (task(7104, 54), task(7105, 55));
    let fa = open_as(&a, b'A', O_RDWR);
    let fb = open_as(&b, b'A', O_RDWR);
    let charged = azos_sched::shim_user_pages();

    let vp = mmap_ok(&a, fa, 2 * PAGE_SIZE, 0, RW, PRIVATE);
    assert_eq!(azos_sched::shim_user_pages(), charged + 2, "a private mapping is charged like anonymous memory");
    // Read-only: a writable shared mapping makes its pages dirty by itself.
    let vs = mmap_ok(&b, fb, 2 * PAGE_SIZE, 0, RO, SHARED);

    fault(&a, vp);
    fault(&b, vs);
    let (own, cache) = (frame(&a, vp), frame(&b, vs));
    assert_ne!(own, cache, "a private page is a copy, not the cache's frame");
    assert_eq!(page_bytes(own)[..8], page_bytes(cache)[..8], "the copy holds the file's bytes");

    // Stores to the copy are seen by nobody: not the shared mapper, not the file.
    page_bytes(own)[0] = 0x77;
    assert_ne!(page_bytes(cache)[0], 0x77);
    enter(&a);
    assert_eq!(super::sys_fsync_typed(fa), 0);
    assert!(writes_of(0).is_empty(), "a private store reached the file");
    assert_ne!(bytes_of(0)[0], 0x77);

    // The copy is the task's own: unmapping frees it and gives the charge back.
    let in_use = azos_mm::shim_pages_in_use();
    assert_eq!(munmap_as(&a, vp, 2 * PAGE_SIZE), 0);
    assert!(azos_mm::shim_pages_in_use() < in_use, "the private copy's frame went back");
    assert_eq!(azos_sched::shim_user_pages(), charged, "and its charge");
    assert_eq!(munmap_as(&b, vs, 2 * PAGE_SIZE), 0);
    drop((a, b));
    clean();
}

#[test]
fn a_mapping_across_windows_is_one_range_of_two_objects() {
    let _g = serial();
    clean();
    fill_file(0, (WINDOW + 8) * PAGE_SIZE);
    let a = task(7106, 56);
    let fa = open_as(&a, b'A', O_RDWR);
    // Eight pages starting four before the end of the first window.
    let off = (WINDOW - 4) * PAGE_SIZE;
    let va = mmap_ok(&a, fa, 8 * PAGE_SIZE, off, RW, SHARED);
    for k in [0usize, 3, 4, 7] {
        fault(&a, va + k * PAGE_SIZE);
        let want = &bytes_of(0)[off + k * PAGE_SIZE..off + k * PAGE_SIZE + 4];
        assert_eq!(&page_bytes(frame(&a, va + k * PAGE_SIZE))[..4], want, "page {k} of the mapping");
    }
    let (o1, o2) = (obj_at(&a, va), obj_at(&a, va + 4 * PAGE_SIZE));
    assert_ne!(o1, o2, "two windows, two cache objects");

    // Only a whole piece goes: a cut through one is refused, nothing changes.
    assert_eq!(munmap_as(&a, va + PAGE_SIZE, PAGE_SIZE), Errno::ENOMEM.to_syscall_ret());
    assert_eq!(munmap_as(&a, va, 5 * PAGE_SIZE), Errno::ENOMEM.to_syscall_ret());
    assert_eq!(obj_at(&a, va), o1);
    // The whole mapping goes in one call.
    assert_eq!(munmap_as(&a, va, 8 * PAGE_SIZE), 0);
    // Both windows can be mapped again.
    let again = mmap_ok(&a, fa, 8 * PAGE_SIZE, off, RO, SHARED);
    assert_eq!(munmap_as(&a, again, 8 * PAGE_SIZE), 0);
    drop(a);
    clean();
}

#[test]
fn mprotect_leaves_a_file_mapping_alone() {
    let _g = serial();
    clean();
    fill_file(0, 2 * PAGE_SIZE);
    let a = task(7107, 57);
    let fa = open_as(&a, b'A', O_RDWR);
    for flags in [SHARED, PRIVATE] {
        let va = mmap_ok(&a, fa, 2 * PAGE_SIZE, 0, RO, flags);
        enter(&a);
        // A shared mapping lies in the shm window, which mprotect never touches.
        let refused = if flags == SHARED { Errno::ENOMEM } else { Errno::EINVAL }.to_syscall_ret();
        assert_eq!(super::sys_mprotect(va as u64, PAGE_SIZE as u64, RW), refused);
        assert_eq!(super::sys_mprotect(va as u64, 2 * PAGE_SIZE as u64, 0), refused);
        assert_eq!(munmap_as(&a, va, 2 * PAGE_SIZE), 0);
    }
    drop(a);
    clean();
}

#[test]
fn a_window_is_mapped_once_per_task() {
    let _g = serial();
    clean();
    fill_file(0, 4 * PAGE_SIZE);
    let a = task(7108, 58);
    let fa = open_as(&a, b'A', O_RDWR);
    let first = mmap_ok(&a, fa, 2 * PAGE_SIZE, 0, RW, SHARED);
    assert_eq!(mmap_as(&a, fa, PAGE_SIZE, 2 * PAGE_SIZE, RW, SHARED), Errno::EBUSY.to_syscall_ret());
    // A private mapping of the same window books nothing.
    let p = mmap_ok(&a, fa, 2 * PAGE_SIZE, 0, RW, PRIVATE);
    assert_eq!(munmap_as(&a, p, 2 * PAGE_SIZE), 0);
    assert_eq!(munmap_as(&a, first, 2 * PAGE_SIZE), 0);
    drop(a);
    clean();
}

#[test]
fn refusals() {
    let _g = serial();
    clean();
    fill_file(0, 2 * PAGE_SIZE);
    let a = task(7109, 59);
    let (rw, ro, ram) = (open_as(&a, b'A', O_RDWR), open_as(&a, b'A', O_RDONLY), open_as(&a, b'N', O_RDONLY));
    let e = |x: Errno| x.to_syscall_ret();
    // A file the cache cannot serve.
    assert_eq!(mmap_as(&a, ram, PAGE_SIZE, 0, RO, SHARED), e(Errno::ENODEV));
    // A read-only descriptor makes no shared writable mapping (the capability
    // itself lacks WRITE), but a private writable one is fine.
    assert_eq!(mmap_as(&a, ro, PAGE_SIZE, 0, RW, SHARED), e(Errno::ECAPPERMS));
    let p = mmap_ok(&a, ro, PAGE_SIZE, 0, RW, PRIVATE);
    assert_eq!(munmap_as(&a, p, PAGE_SIZE), 0);
    // Bad arguments.
    assert_eq!(mmap_as(&a, rw, PAGE_SIZE, 0, 4 | 1, SHARED), e(Errno::EINVAL), "PROT_EXEC");
    assert_eq!(mmap_as(&a, rw, PAGE_SIZE, 0, 0, SHARED), e(Errno::EINVAL), "PROT_NONE");
    assert_eq!(mmap_as(&a, rw, PAGE_SIZE, 0, RW, 0), e(Errno::EINVAL), "neither flag");
    assert_eq!(mmap_as(&a, rw, PAGE_SIZE, 0, RW, SHARED | PRIVATE), e(Errno::EINVAL), "both flags");
    assert_eq!(mmap_as(&a, rw, 0, 0, RW, SHARED), e(Errno::EINVAL), "empty");
    assert_eq!(mmap_as(&a, rw, PAGE_SIZE, 1, RW, SHARED), e(Errno::EINVAL), "unaligned offset");
    assert_eq!(mmap_as(&a, rw, PAGE_SIZE, 2 * PAGE_SIZE, RW, SHARED), e(Errno::EINVAL), "offset at the end");
    assert_eq!(mmap_as(&a, rw, 10 * WINDOW * PAGE_SIZE, 0, RW, SHARED), e(Errno::ENOMEM), "more windows than a call maps");
    // Nothing was left behind by the refusals: the window still maps.
    let ok = mmap_ok(&a, rw, PAGE_SIZE, 0, RW, SHARED);
    assert_eq!(munmap_as(&a, ok, PAGE_SIZE), 0);
    drop(a);
    clean();
}

/// The exit path as the kernel runs it: the exit hook's write-back first, then
/// the references given back, then the address space's end.
fn exit_of(t: &Task) {
    enter(t);
    crate::file_map::exit_writeback(t.tid);
    azos_ipc::memobj::memobj_release_all(t.tid);
    azos_mm::pager::forget(t.pt);
}

#[test]
fn the_exit_of_a_mapper_writes_its_stores_to_the_file() {
    let _g = serial();
    clean();
    fill_file(0, 2 * PAGE_SIZE);
    fill_file(1, 2 * PAGE_SIZE);
    let a = task(7110, 60);
    let fa = open_as(&a, b'A', O_RDWR);
    let va = mmap_ok(&a, fa, 2 * PAGE_SIZE, 0, RW, SHARED);
    fault(&a, va);
    page_bytes(frame(&a, va))[5] = 0xD5;
    assert_ne!(bytes_of(0)[5], 0xD5, "nothing wrote the page yet");

    // No munmap, no sync: the task ends, and no mapping call follows.
    exit_of(&a);
    assert_eq!(bytes_of(0)[5], 0xD5, "the exit wrote the dead mapper's page to the file");
    drop(a);
    clean();
}

#[test]
fn a_store_after_the_last_sync_still_reaches_the_file_at_exit() {
    let _g = serial();
    clean();
    fill_file(0, PAGE_SIZE);
    let a = task(7110, 60);
    let fa = open_as(&a, b'A', O_RDWR);
    let va = mmap_ok(&a, fa, PAGE_SIZE, 0, RW, SHARED);
    fault(&a, va);
    page_bytes(frame(&a, va))[9] = 0x11;
    enter(&a);
    assert_eq!(super::sys_fsync_typed(fa), 0);
    assert_eq!(bytes_of(0)[9], 0x11);
    // The sync cleared the page's dirty mark; the PTE is still writable, so this
    // store leaves no mark of its own: only the booking, which the exit must
    // read before it ends, says the page is not clean.
    page_bytes(frame(&a, va))[9] = 0x22;
    exit_of(&a);
    assert_eq!(bytes_of(0)[9], 0x22, "a store after the last sync was lost at exit");
    drop(a);
    clean();
}

#[test]
fn the_exit_of_a_mapper_writes_back_only_its_own_windows() {
    let _g = serial();
    clean();
    fill_file(0, PAGE_SIZE);
    fill_file(1, PAGE_SIZE);
    let (a, b) = (task(7110, 60), task(7111, 61));
    let (fa, fb) = (open_as(&a, b'A', O_RDWR), open_as(&b, b'B', O_RDWR));
    let (va, vb) = (mmap_ok(&a, fa, PAGE_SIZE, 0, RW, SHARED), mmap_ok(&b, fb, PAGE_SIZE, 0, RW, SHARED));
    fault(&a, va);
    fault(&b, vb);
    page_bytes(frame(&a, va))[1] = 0xA1;
    page_bytes(frame(&b, vb))[1] = 0xB1;
    exit_of(&a);
    assert_eq!(bytes_of(0)[1], 0xA1);
    assert_ne!(bytes_of(1)[1], 0xB1, "a task's exit wrote another task's mapping");
    assert!(writes_of(1).is_empty());
    assert_eq!(munmap_as(&b, vb, PAGE_SIZE), 0);
    assert_eq!(bytes_of(1)[1], 0xB1);
    drop((a, b));
    clean();
}

#[test]
fn a_fork_child_gets_the_private_regions_only() {
    let _g = serial();
    clean();
    fill_file(0, 4 * PAGE_SIZE);
    let (parent, child) = (task(7112, 62), task(7113, 63));
    let fp = open_as(&parent, b'A', O_RDWR);
    let shared = mmap_ok(&parent, fp, 2 * PAGE_SIZE, 0, RW, SHARED);
    let private = mmap_ok(&parent, fp, 2 * PAGE_SIZE, 2 * PAGE_SIZE, RW, PRIVATE);
    let _ = shared;

    let owed = azos_mm::pager::fork_clone(parent.pt, child.pt).expect("fork_clone");
    assert_eq!(owed, 2, "the child owes the private region's pages, nothing for the shared one");
    let mut out = [azos_mm::pager::FileRegion::NONE; 8];
    let n = azos_mm::pager::file_regions_in(child.pt, 0, azos_sched::user_shm_window().1, &mut out).unwrap();
    assert_eq!(n, 1, "the shared mapping is not inherited");
    assert_eq!((out[0].start, out[0].shared), (private, false));

    // The child's copy keeps the object alive after the parent unmaps, and its
    // pages are the file's.
    assert_eq!(munmap_as(&parent, private, 2 * PAGE_SIZE), 0);
    fault(&child, private);
    assert_eq!(&page_bytes(frame(&child, private))[..4], &bytes_of(0)[2 * PAGE_SIZE..2 * PAGE_SIZE + 4]);
    drop((parent, child));
    clean();
}
