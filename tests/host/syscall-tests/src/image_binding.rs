// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Ring 3 starts only images a seccomp image profile is bound to (owner
// decision 2026-09-14: the table is a whitelist of user images, on every
// path that starts one). `SYS_SPAWN_EX` (`spawn.rs`) and the Linux `execve`
// (`linux.rs`) both ask `exec_image_is_bound_by_digest` about the digest of the
// bytes they are about to load; neither is compiled here, so these tests drive
// the check they share.
//
// `azos_sched::seccomp` here is the REAL `crates/core/sched/src/seccomp.rs`,
// with the table the build generated (`shims/sched` pulls it in by `#[path]`),
// so these tests refuse and accept exactly the images the kernel does.

use super::harness::serial;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Bytes that are no shipped image: refused.
const NOT_SHIPPED: &[u8] = b"\x7fELF bytes that no image profile is bound to";

/// uhello's bytes, compiled in from the same `$AZOS_OUT/build/` the image table
/// (`$AZOS_OUT/build/image_hashes.rs`, `include!`d by `seccomp.rs`) is compiled from.
///
/// Read at compile time, not at run time (wave 11 fix). The file used to be
/// read when the test ran, the table when the crate was compiled, so a
/// `make` that rewrote `$AZOS_OUT/build/` in between (a gate or another worktree's
/// build, a libsys change) left uhello's digest in no row of the compiled
/// table, and the shipped-image test failed as if the binding had refused a
/// shipped image. Compiled in, both come from one instant, and cargo rebuilds
/// the crate when either file changes. A missing file is a compile error, as a
/// missing table already is.
const SHIPPED_UHELLO: &[u8] =
    include_bytes!(concat!(env!("AZOS_OUT"), "/build/uhello.elf"));

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
/// at 0.
fn arm() {
    __cap_deny_limiter_clear_for_tests();
    REFUSALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    SUMMARIES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    NOW.store(0, Ordering::SeqCst);
    set_cap_deny_limiter(clock, WINDOW, summary_hook);
    set_exec_refused_recorder(refusal_hook);
}

fn disarm() {
    __exec_refused_recorder_clear_for_tests();
    __cap_deny_limiter_clear_for_tests();
}

fn digest_head(bytes: &[u8]) -> u32 {
    let d = azos_sched::seccomp::image_digest(bytes);
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// **Refused and recorded.** An image no profile is bound to is not bound,
/// and one `SAFETY_EXEC_REFUSED` record carries the ring-3 action and the
/// digest's first four bytes.
///
/// **Canary.** Make `exec_image_is_bound_by_digest` return `true` first: the
/// image is bound and nothing is recorded.
#[test]
fn an_image_no_profile_is_bound_to_is_refused_and_recorded() {
    let _g = serial();
    arm();
    assert!(!exec_image_is_bound(NOT_SHIPPED), "an unbound image was taken for a shipped one");
    assert_eq!(refusals(), vec![(EXEC_REFUSED_ACTION_RING3, digest_head(NOT_SHIPPED))]);
    disarm();
}

/// **A shipped image is bound, byte for byte.** uhello's bytes, as the build
/// left them, are bound and nothing is recorded.
///
/// **Canary.** Make `exec_image_is_bound_by_digest` return `false`
/// unconditionally: the shipped image is refused.
#[test]
fn a_shipped_image_is_bound_and_nothing_is_recorded() {
    let _g = serial();
    arm();
    let d = azos_sched::seccomp::image_digest(SHIPPED_UHELLO);
    assert!(
        azos_sched::seccomp::image_for_digest(&d).is_some(),
        "$AZOS_OUT/build/uhello.elf (sha256 {:02x}{:02x}{:02x}{:02x}..) is in no row of $AZOS_OUT/build/image_hashes.rs: \
         the two were compiled from different `make` runs ($AZOS_OUT/build/ was rewritten while this crate \
         compiled). Run `make $AZOS_OUT/build/image_hashes.rs`, then the tests again; this is not a \
         binding failure.",
        d[0], d[1], d[2], d[3]
    );
    assert!(exec_image_is_bound(SHIPPED_UHELLO), "a shipped image was refused");
    assert!(refusals().is_empty(), "a shipped image was recorded as refused: {:?}", refusals());
    disarm();
}

/// **Bounded.** A ring-3 loop of refused images writes at most
/// `DENIAL_RECORDS_PER_WINDOW` records per window; the rest come out as one
/// summary under `DENIAL_KIND_EXEC_REFUSED`. Every image is still refused.
///
/// **Canary.** Call the recorder without `admit_denial_record` in
/// `record_exec_refused_recorded`: twenty records.
#[test]
fn a_loop_of_refused_images_is_bounded_under_its_own_kind() {
    let _g = serial();
    arm();
    for _ in 0..20 {
        assert!(!exec_image_is_bound(NOT_SHIPPED));
    }
    assert_eq!(refusals().len(), DENIAL_RECORDS_PER_WINDOW as usize, "the refusal loop was not bounded");
    NOW.store(WINDOW, Ordering::SeqCst);
    cap_denial_flush_pending();
    assert_eq!(summaries(), vec![(DENIAL_KIND_EXEC_REFUSED, 16)]);
    disarm();
}

/// A file system whose one file is [`NOT_SHIPPED`], with a content stamp, so
/// the image is read through the verified-image cache (wave 14).
struct StampedDisk { hashed: std::sync::atomic::AtomicU32 }
impl crate::file_ops::FileOps for StampedDisk {
    fn open_at(&self, _: &[u8], _: &[u8], _: u32) -> i64 { -1 }
    fn close(&self, _: i32) -> i64 { -1 }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { -1 }
    fn write(&self, _: i32, _: &[u8]) -> i64 { -1 }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { -1 }
    fn dup(&self, _: i32) -> i64 { -1 }
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
/// profile is bound to, read by path twice: the second read takes its digest
/// from the verified-image cache (no hash pass), and the digest is refused and
/// recorded exactly as the first, under the same head.
#[test]
fn a_cached_digest_of_an_unbound_image_is_refused_again() {
    let _g = serial();
    arm();
    crate::image_cache::clear();
    STAMPED.hashed.store(0, Ordering::SeqCst);
    let mut buf = [0u8; 256];
    for _ in 0..2 {
        let v = crate::image_cache::read_verified(&STAMPED, b"/fat/NOPE.ELF", &mut buf).expect("read");
        assert!(!exec_image_is_bound_by_digest(&v.digest));
    }
    assert_eq!(STAMPED.hashed.load(Ordering::SeqCst), 1, "the second read was a cache hit");
    let head = digest_head(NOT_SHIPPED);
    assert_eq!(refusals(), vec![(EXEC_REFUSED_ACTION_RING3, head); 2]);
    crate::image_cache::clear();
    disarm();
}
