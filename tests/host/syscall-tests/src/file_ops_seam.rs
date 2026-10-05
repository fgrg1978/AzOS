// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// First runtime coverage of the file syscalls.
//
// Before the `FileOps` seam these handlers had NONE. The gate's only ring-3
// program that touches them is `abitest`, and both of its `open` calls are
// failure paths — one rejected inside libsys for an unterminated string, one
// that reaches the kernel and fails there. Its `close` calls are all on
// sockets, which never go near the descriptor table. The one program that
// opens a real file and reads it, `brain_client`, is deliberately outside the
// gate because it needs a live brain server on the host. And on the host side,
// `shims/fs` made every filesystem function `todo!()`, so nothing could be
// driven through them there either.
//
// So the commit that moved the descriptor table out of the TCB moved seven
// handlers that nothing in the gate would have noticed breaking. The seam is
// what makes them testable: a `FileOps` written in this file records exactly
// what each handler passed down, which is the half the move could get wrong.

use super::harness::serial;
use azos_arch_api::PagePerms;
use std::sync::Mutex;

/// Everything the handlers asked the filesystem to do, in order.
#[derive(Debug, PartialEq, Eq)]
enum Call {
    Open  { path: Vec<u8>, flags: u32 },
    Close { fd: i32 },
    Read  { fd: i32, len: usize },
    Write { fd: i32, bytes: Vec<u8> },
    Lseek { fd: i32, offset: i64, whence: i32 },
    Dup   { fd: i32 },
    Dup2  { oldfd: i32, newfd: i32 },
    Mkdir { path: Vec<u8> },
    Unlink{ path: Vec<u8> },
    Readdir { path: Vec<u8>, index: u32 },
    ReadWhole { path: Vec<u8>, cap: usize },
}

static LOG: Mutex<Vec<Call>> = Mutex::new(Vec::new());

struct Recorder;

impl crate::file_ops::FileOps for Recorder {
    fn open(&self, path: &[u8], flags: u32) -> i64 {
        LOG.lock().unwrap().push(Call::Open { path: path.to_vec(), flags });
        7 // a descriptor number nothing else would produce by accident
    }
    fn close(&self, fd: i32) -> i64 {
        LOG.lock().unwrap().push(Call::Close { fd });
        0
    }
    fn read(&self, fd: i32, dst: &mut [u8]) -> i64 {
        LOG.lock().unwrap().push(Call::Read { fd, len: dst.len() });
        // Fill with a pattern the caller can check byte-for-byte, so a handler
        // that returned the right COUNT while copying the wrong bytes fails.
        for (i, b) in dst.iter_mut().enumerate() { *b = (i as u8).wrapping_add(0xA0); }
        dst.len() as i64
    }
    fn write(&self, fd: i32, src: &[u8]) -> i64 {
        LOG.lock().unwrap().push(Call::Write { fd, bytes: src.to_vec() });
        src.len() as i64
    }
    fn lseek(&self, fd: i32, offset: i64, whence: i32) -> i64 {
        LOG.lock().unwrap().push(Call::Lseek { fd, offset, whence });
        4242
    }
    fn dup(&self, fd: i32) -> i64 {
        LOG.lock().unwrap().push(Call::Dup { fd });
        11
    }
    fn dup2(&self, oldfd: i32, newfd: i32) -> i64 {
        LOG.lock().unwrap().push(Call::Dup2 { oldfd, newfd });
        newfd as i64
    }
    fn mkdir(&self, path: &[u8]) -> i64 {
        LOG.lock().unwrap().push(Call::Mkdir { path: path.to_vec() });
        0
    }
    fn unlink(&self, path: &[u8]) -> i64 {
        LOG.lock().unwrap().push(Call::Unlink { path: path.to_vec() });
        0
    }
    fn readdir(&self, path: &[u8], index: u32) -> Option<([u8; 64], u32, bool)> {
        LOG.lock().unwrap().push(Call::Readdir { path: path.to_vec(), index });
        let mut name = [0u8; 64];
        name[..5].copy_from_slice(b"HELLO");
        Some((name, 1234, true))
    }
    fn release_all(&self, _tid: u32) -> usize { 0 }
    fn read_whole(&self, path: &[u8], dst: &mut [u8]) -> usize {
        LOG.lock().unwrap().push(Call::ReadWhole { path: path.to_vec(), cap: dst.len() });
        0
    }
}

static RECORDER: Recorder = Recorder;

fn drain() -> Vec<Call> { std::mem::take(&mut *LOG.lock().unwrap()) }

/// A VA clear of what the other guard files use.
const SCRATCH: usize = 0x0060_0000;

fn fresh_user_pt() -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    pt
}

/// Map one arena page at `va`; the "physical" address doubles as a host
/// pointer, the same trick `driver_server_guards.rs` uses.
fn map_scratch(pt: usize, va: usize) -> *mut u8 {
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, va, phys, PagePerms::USER_RW).expect("map");
    phys as *mut u8
}

/// One test, holding `serial()` for its whole body, for two reasons. The
/// installed `FileOps` is a process-wide `static`, so the "nothing installed"
/// half can only ever be observed before the first install. And the handlers
/// branch on `current_user_pt()`, which is shared mutable state: the first
/// version of this test asserted nothing about it, passed alone, and failed
/// under the full suite because another test had left a user page table
/// installed. `serial()` resets it to kernel context on entry, and the
/// user-context half below sets it deliberately.
#[test]
fn the_file_syscalls_route_through_the_seam() {
    let _g = serial();

    // ── Nothing installed ──────────────────────────────────────────────────
    //
    // A kernel built without a filesystem must have file syscalls that are
    // genuinely absent, not ones that fall through to something. -1 is what
    // ring 3 already gets for a missing file, so no caller learns a new
    // failure mode. This is the property roadmap step 3 is after, and it is a
    // property of the linked binary rather than of `tcb_check.sh`.
    let path = b"/fat/CONFIG.INI\0";
    let p = path.as_ptr() as u64;
    let mut buf = [0u8; 32];

    assert_eq!(super::sys_open(p, 0), -1, "open answered with no filesystem installed");
    assert_eq!(super::sys_close(3), -1, "close answered with no filesystem installed");
    assert_eq!(super::sys_read(3, buf.as_mut_ptr() as u64, 8), -1, "read answered");
    assert_eq!(super::sys_write(3, buf.as_ptr() as u64, 8), -1, "write answered");
    assert_eq!(super::sys_lseek(3, 0, 0), -1, "lseek answered");
    assert_eq!(super::sys_dup(3), -1, "dup answered");
    assert_eq!(super::sys_dup2(3, 4), -1, "dup2 answered");
    assert_eq!(super::sys_mkdir(p), -1, "mkdir answered");
    assert_eq!(super::sys_unlink(p), -1, "unlink answered");
    assert!(drain().is_empty(), "something was called with nothing installed");

    // ── Installed ──────────────────────────────────────────────────────────
    crate::file_ops::set_file_ops(&RECORDER);

    // `open`: the path must arrive trimmed at its NUL, without the terminator,
    // and the flags must arrive unchanged. A handler that passed the whole
    // 256-byte buffer, or kept the NUL, would open a different file.
    assert_eq!(super::sys_open(p, 0x241), 7, "open did not return the seam's fd");
    assert_eq!(
        drain(),
        vec![Call::Open { path: b"/fat/CONFIG.INI".to_vec(), flags: 0x241 }],
    );

    // `read` in kernel context: the seam must be handed a slice of exactly
    // `count` bytes aimed at the caller's buffer. This is the call the move
    // was most able to break — it used to pass a raw pointer and a length,
    // and it now builds the slice at the call site.
    let mut dst = [0u8; 16];
    let n = super::sys_read(7, dst.as_mut_ptr() as u64, 16);
    assert_eq!(n, 16, "read returned {n}, want 16");
    assert_eq!(drain(), vec![Call::Read { fd: 7, len: 16 }]);
    for (i, b) in dst.iter().enumerate() {
        assert_eq!(*b, (i as u8).wrapping_add(0xA0),
            "byte {i} of the read landed wrong: the slice did not point at the caller's buffer");
    }

    // A short read must narrow the slice, not the return value alone: passing
    // the full buffer length would let the filesystem write past what the
    // caller asked for.
    let _ = super::sys_read(7, dst.as_mut_ptr() as u64, 4);
    assert_eq!(drain(), vec![Call::Read { fd: 7, len: 4 }]);

    // `write`: the exact bytes, not a prefix and not the whole buffer.
    let src = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x55];
    assert_eq!(super::sys_write(7, src.as_ptr() as u64, 5), 5);
    assert_eq!(drain(), vec![Call::Write { fd: 7, bytes: src.to_vec() }]);

    // Argument order and sign for the rest. `lseek`'s offset is signed and a
    // negative seek is legitimate. Since RFC-0048 P2 it is the WHOLE 64-bit
    // register (a two's-complement `i64`): a 5 GiB offset arrives intact,
    // where the old `as i32` cast cut it to 1 GiB. A caller that passes a
    // 32-bit value zero-extended now means that positive value, as the
    // 64-bit ABI says.
    assert_eq!(super::sys_lseek(7, (-9i64) as u64, 2), 4242);
    assert_eq!(drain(), vec![Call::Lseek { fd: 7, offset: -9, whence: 2 }]);
    assert_eq!(super::sys_lseek(7, 5u64 << 30, 0), 4242);
    assert_eq!(drain(), vec![Call::Lseek { fd: 7, offset: 5 << 30, whence: 0 }]);

    assert_eq!(super::sys_dup(7), 11);
    assert_eq!(drain(), vec![Call::Dup { fd: 7 }]);

    assert_eq!(super::sys_dup2(7, 9), 9);
    assert_eq!(drain(), vec![Call::Dup2 { oldfd: 7, newfd: 9 }]);

    assert_eq!(super::sys_close(7), 0);
    assert_eq!(drain(), vec![Call::Close { fd: 7 }]);

    // Path-taking calls, all trimmed the same way.
    assert_eq!(super::sys_mkdir(p), 0);
    assert_eq!(drain(), vec![Call::Mkdir { path: b"/fat/CONFIG.INI".to_vec() }]);

    assert_eq!(super::sys_unlink(p), 0);
    assert_eq!(drain(), vec![Call::Unlink { path: b"/fat/CONFIG.INI".to_vec() }]);

    // `readdir` writes three separate outputs and the name is NUL-padded to
    // the full 64 bytes it promises. Before the seam this handler resolved the
    // path itself and then asked for an entry by inode index, which is what
    // put the filesystem's vocabulary in the syscall crate.
    let mut name_out = [0xFFu8; 64];
    let mut size_out = 0u32;
    let mut dir_out  = 0u32;
    let rc = super::sys_readdir(
        p, 3,
        name_out.as_mut_ptr() as u64,
        &mut size_out as *mut u32 as u64,
        &mut dir_out  as *mut u32 as u64,
        // The declared name-buffer length (owner decision 100b). `name_out`
        // is a 64-byte array, so this is the true size, not a placeholder.
        azos_abi::syscall_nr::READDIR_NAME_BYTES as u64,
    );
    assert_eq!(rc, 0, "readdir failed");

    // **The name-buffer length gate** (owner decision 100b). `SYS_READDIR`
    // writes `READDIR_NAME_BYTES` bytes ALWAYS, and until 2026-09-19 it
    // received no length: the size was enforced only by `libsys::readdir`
    // typing its parameter as `&mut [u8; 64]`, which holds for a Rust caller
    // through libsys and for nothing else.
    //
    // Asserted HERE, inside the test that already has the recorder installed,
    // and through the SEAM rather than the return code. Two earlier attempts
    // were wrong and both are worth remembering: asserting only `-1` did not
    // discriminate, because without the gate the call falls through to the
    // path lookup which also answers -1; and putting it in a test of its own
    // left the recorder installed for whatever ran next, which broke the
    // "nothing was called with nothing installed" assertion above.
    //
    // What separates the two worlds is whether the filesystem was CALLED.
    let _ = drain();
    for declared in [0u64, 1, 16, 63] {
        assert_eq!(
            super::sys_readdir(
                p, 3,
                name_out.as_mut_ptr() as u64,
                &mut size_out as *mut u32 as u64,
                &mut dir_out as *mut u32 as u64,
                declared,
            ),
            -1,
            "a name buffer declared {declared} must be refused",
        );
        assert!(
            drain().is_empty(),
            "declared {declared}: the refusal still reached the filesystem",
        );
    }
    // And at the full length it DOES reach the filesystem — without this the
    // loop above would hold for a `sys_readdir` that refused everything.
    assert_eq!(
        super::sys_readdir(
            p, 3,
            name_out.as_mut_ptr() as u64,
            &mut size_out as *mut u32 as u64,
            &mut dir_out as *mut u32 as u64,
            azos_abi::syscall_nr::READDIR_NAME_BYTES as u64,
        ),
        0,
    );
    assert_eq!(drain(), vec![Call::Readdir { path: b"/fat/CONFIG.INI".to_vec(), index: 3 }]);
    assert_eq!(&name_out[..5], b"HELLO");
    assert!(name_out[5..].iter().all(|&b| b == 0),
        "readdir left the tail of the 64-byte name buffer unwritten");
    assert_eq!(size_out, 1234);
    assert_eq!(dir_out, 1);

    // ── User context: the path must be trimmed at its NUL ──────────────────
    //
    // Everything above ran with `user_pt == 0`, where the path comes through
    // `cstr_to_bytes` and is trimmed by construction. The ring-3 branch is the
    // one that copies a fixed 256-byte buffer out of user space and has to
    // trim it itself, and it is the branch a real program takes. Getting it
    // wrong opens a different file — which is exactly what `sys_readdir` used
    // to do before this seam normalised it.
    let pt = fresh_user_pt();
    let up = map_scratch(pt, SCRATCH);
    unsafe {
        core::ptr::write_bytes(up, 0, 4096);
        core::ptr::copy_nonoverlapping(b"/fat/CONFIG.INI\0".as_ptr(), up, 16);
    }
    let _ = drain();

    // From ring 3 a mkdir (wave 10) and an open that creates, truncates or
    // writes (2026-09-29) need a tree capability covering the path.
    ipc_task_pool::shim_bind(1, 58);
    azos_ipc::cap_store::reset(1);
    azos_ipc::file_cap::file_tree_grant_cap(1, "/fat", azos_abi::cap::CapPerms::RW)
        .expect("tree grant");

    assert_eq!(super::sys_open(SCRATCH as u64, 0x241), 7);
    assert_eq!(
        drain(),
        vec![Call::Open { path: b"/fat/CONFIG.INI".to_vec(), flags: 0x241 }],
        "the ring-3 open path did not trim its 256-byte buffer at the NUL"
    );

    assert_eq!(super::sys_mkdir(SCRATCH as u64), 0);
    assert_eq!(drain(), vec![Call::Mkdir { path: b"/fat/CONFIG.INI".to_vec() }]);

    let mut name_out2 = [0u8; 64];
    let mut size2 = 0u32;
    let mut dir2 = 0u32;
    // Point the outputs at mapped user memory: this branch writes them with
    // `copy_to_user`, not a raw store.
    let out = map_scratch(pt, SCRATCH + 0x1000);
    let _ = (&mut name_out2, &mut size2, &mut dir2, out);
    assert_eq!(
        super::sys_readdir(
            SCRATCH as u64, 3,
            (SCRATCH + 0x1000) as u64,
            (SCRATCH + 0x1000 + 64) as u64,
            (SCRATCH + 0x1000 + 68) as u64,
    azos_abi::syscall_nr::READDIR_NAME_BYTES as u64,
        ),
        0,
    );
    assert_eq!(
        drain(),
        vec![Call::Readdir { path: b"/fat/CONFIG.INI".to_vec(), index: 3 }],
        "the ring-3 readdir path did not trim its buffer at the NUL"
    );
    unsafe {
        assert_eq!(core::slice::from_raw_parts(out, 5), b"HELLO");
        assert_eq!(*(out.add(64) as *const u32), 1234);
        assert_eq!(*(out.add(68) as *const u32), 1);
    }
}

// ── Descriptor ownership ────────────────────────────────────────────────────
//
// The rule that decides whether a caller may touch a descriptor. It is applied
// in `KernelFileOps`, which no host test can enter, so the DECISION lives in
// `file_ops.rs` and is tested here. What that costs: these tests prove the
// rule, not that all six operations apply it — the six call sites are checked
// by reading them, and `sys_write(1)`/`(2)` never reach the seam at all
// because the console is intercepted before it.

/// Sentinel matching `azos_fs::FD_NO_OWNER`, restated rather than imported
/// because `crates/fs/fs` is not in this suite's dependency graph — the seam
/// exists precisely so it is not.
const NO_OWNER: u32 = 0;

#[test]
fn a_task_may_use_the_descriptors_it_owns() {
    // The positive half. Without it, refusing everything would pass every
    // other test in this section.
    assert!(super::super::file_ops::fd_access_allowed(Some(7), 7, false, NO_OWNER));
}

#[test]
fn a_task_may_not_use_another_tasks_descriptor() {
    // The hole this closed: one machine-wide table of 16 slots, an opt-in
    // syscall filter, and no check between the stamp at `open` and the sweep
    // at task death.
    assert!(!super::super::file_ops::fd_access_allowed(Some(7), 8, false, NO_OWNER));
}

#[test]
fn ring_three_may_not_use_an_unowned_descriptor() {
    // `None` is out of range, not in use, OR opened by a kernel task. All
    // three must fail closed for a user caller — a kernel descriptor is
    // deliberately unowned so ring 3 cannot reach it by matching.
    assert!(!super::super::file_ops::fd_access_allowed(None, 7, false, NO_OWNER));
}

#[test]
fn a_caller_whose_tid_is_the_vacant_marker_is_refused() {
    // Otherwise "no owner" would match "no caller" and every unowned
    // descriptor in the table would be open to it.
    assert!(!super::super::file_ops::fd_access_allowed(Some(NO_OWNER), NO_OWNER, false, NO_OWNER));
    assert!(!super::super::file_ops::fd_access_allowed(None, NO_OWNER, false, NO_OWNER));
}

#[test]
fn a_kernel_caller_passes_regardless_of_the_owner() {
    // The kernel reads and writes descriptors it did not open — the loader and
    // the flight recorder among them. Refusing it here would break boot, and
    // the check is not for it: ring 3 is what the table needs protecting from.
    assert!(super::super::file_ops::fd_access_allowed(None, 0, true, NO_OWNER));
    assert!(super::super::file_ops::fd_access_allowed(Some(9), 7, true, NO_OWNER));
}
