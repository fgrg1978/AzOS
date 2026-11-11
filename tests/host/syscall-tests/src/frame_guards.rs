// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Frame` interface --
// `crates/core/syscall/src/frame_host.rs::Server`: the frames a producer
// commits into the pool reach a task's buffer as copies, whose reader slot is
// the task's for as long as it lives. The pool itself (references, both
// policies, fan-out) is `tests/host/cam-ring-tests`.
//
// Included inside `mod handlers { .. }` like `volume_guards.rs`.

use super::harness::serial;
use azos_abi::cap::{CapHandle, CapPerms};
use azos_cam_ring::FrameInfo;
use azos_devif::frame::{self, FrameBuf, Meta};
use azos_decision::{Rule, Verdict};
use azos_devif::{outcome, Cap as WireCap, Frame, Out};
use azos_topology::EffectKind;
use azos_ipc::memobj::{memobj_create_cap, memobj_with_span_ref, MemPerms, MemSpec};
use crate::frame_host::{Lender, Server, BYTES, LEND_TRIES, LINK, POOL, RING3_READERS};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Once;

/// TIDs no other file in this crate uses, and the task slots 47..=56.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e46_0001);
static NEXT_SLOT: AtomicU32 = AtomicU32::new(47);

/// The pool gets its buffers once, as the boot lends it memory objects.
fn lend() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let buffers: Vec<usize> = (0..crate::frame_host::SLOTS)
            .map(|_| Box::leak(vec![0u8; BYTES].into_boxed_slice()).as_mut_ptr() as usize)
            .collect();
        POOL.install(&buffers).expect("buffers for the pool");
    });
}

/// A task with a capability table, ending as a task does.
struct Task {
    tid: u32,
}

impl Task {
    fn new() -> Task {
        lend();
        crate::effect::grant_all(EffectKind::Cam);
        let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
        let slot = NEXT_SLOT.fetch_add(1, Ordering::SeqCst);
        ipc_task_pool::shim_bind(tid, slot as usize);
        azos_ipc::cap_store::reset(tid);
        azos_sched::set_current_task_tid(tid);
        Task { tid }
    }

    fn server(&self, badge: u32, rights: CapPerms) -> Server {
        Server(Caller { tid: self.tid, badge, rights })
    }

    fn reader(&self) -> Server {
        self.server(0, CapPerms::READ)
    }

    /// A memory object of `bytes` bytes of this task's: its capability handle.
    fn buffer(&self, bytes: usize, spec: MemSpec) -> u32 {
        memobj_create_cap(self.tid, bytes.div_ceil(azos_arch::PAGE_SIZE), &spec).expect("a buffer").raw().0
    }

    /// The buffer a reader makes: anonymous, read-write, `BYTES` long.
    fn frame_buffer(&self) -> u32 {
        self.buffer(BYTES, MemSpec::anon(MemPerms::ReadWrite))
    }

    fn next(&self, buf: u32) -> Out<Meta> {
        self.reader().next(WireCap::<FrameBuf>::from_raw(buf))
    }

    fn region(&self, cap: u32) -> u32 {
        azos_ipc::cap_store::read_table(self.tid, |t| t.peek_raw(CapHandle(cap))).flatten().expect("in the table").2
    }

    fn get(&self, cap: u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let ok = memobj_with_span_ref(self.region(cap), len, |base| {
            // SAFETY: `base` addresses `len` bytes of the object, held under the table's lock.
            unsafe { core::ptr::copy_nonoverlapping(base as *const u8, out.as_mut_ptr(), len) }
        });
        assert_eq!(ok.unwrap(), Some(()));
        out
    }

    /// The first `len` bytes of the buffer, page by page (its frames may be in any order).
    fn get_by_pages(&self, cap: u32, len: usize) -> Vec<u8> {
        let page = azos_arch::PAGE_SIZE;
        let r = self.region(cap);
        let mut out = Vec::new();
        for k in 0..len.div_ceil(page) {
            let pa = azos_ipc::memobj::memobj_page_phys_ref(r, k).unwrap().unwrap();
            let va = azos_mm::addr::phys_to_virt(pa) as *const u8;
            // SAFETY: the page of an object this task holds, in the direct map.
            out.extend_from_slice(unsafe { core::slice::from_raw_parts(va, page.min(len - k * page)) });
        }
        out
    }

    fn put(&self, cap: u32, byte: u8) {
        let ok = memobj_with_span_ref(self.region(cap), BYTES, |base| {
            // SAFETY: as in `get`.
            unsafe { core::ptr::write_bytes(base as *mut u8, byte, BYTES) }
        });
        assert_eq!(ok.unwrap(), Some(()));
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        crate::frame_host::release_all(self.tid);
        ipc_task_pool::shim_kill(self.tid);
        azos_ipc::memobj::memobj_release_all(self.tid);
    }
}

/// The producer commits a frame of `len` bytes that derive from `tag`.
fn commit(tag: u8, len: usize, stamp: u64, info: FrameInfo) -> u64 {
    let slot = POOL.claim().expect("the pool has a buffer");
    for (i, b) in slot[..len].iter_mut().enumerate() {
        *b = tag.wrapping_add(i as u8);
    }
    POOL.commit_info(len, stamp, info)
}

fn pattern(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag.wrapping_add(i as u8)).collect()
}

/// **The frame a producer committed is the frame a task reads, with what it
/// is and when it was taken.** The first `next` makes the task a reader and
/// takes nothing (`NOT_READY`: only frames committed afterwards are owed); then
/// each committed frame arrives once, its bytes in the buffer, its sequence
/// number, stamp, format and size in the reply; the reference the read took
/// is gone when it returns.
///
/// **Canary.** `frame-copy-skip-canary` (a read copies nothing): the bytes
/// are zeros.
#[test]
fn the_frame_a_producer_committed_is_the_frame_a_task_reads() {
    let _g = serial();
    let t = Task::new();
    let buf = t.frame_buffer();
    assert_eq!(t.next(buf), Out::err(outcome::NOT_READY), "a reader is made, no frame is owed yet");
    let seq = commit(0x21, 9_000, 5_000, FrameInfo::JPEG);
    let m = t.next(buf);
    assert!(m.is_ok(), "{m:?}");
    assert_eq!(
        m.value,
        Meta { len: 9_000, skipped: 0, seq, acq_ns: 5_000, format: frame::format::JPEG, size: 0 }
    );
    assert_eq!(t.get(buf, 9_000), pattern(0x21, 9_000), "the bytes the producer wrote, across pages");
    assert_eq!(POOL.references(), 0, "the read's reference ended with the call");
    assert_eq!(t.next(buf), Out::err(outcome::NOT_READY), "a frame is taken once");
    let seq2 = commit(0x33, 24, 6_000, FrameInfo::yuyv(4, 3));
    let m = t.next(buf).value;
    assert_eq!((m.seq, m.format, m.size, m.len), (seq2, frame::format::YUYV, 4 << 16 | 3, 24));
    assert_eq!(t.get(buf, 24), pattern(0x33, 24));
}

/// **The frame goes into the frames the buffer has, in the order it has them,
/// and the region table is free while it does.** A buffer of three pages whose
/// first and last frames are swapped gets a nine-thousand-byte frame page by
/// page; the table was not locked during the copy.
///
/// **Canaries.** `memobj-write-first-frame-canary` (page `k` at the first
/// frame plus `k` pages): the bytes are in the wrong frames.
/// `frame-copy-under-lock-canary` (the copy runs with the table locked): the
/// table was not free.
#[test]
fn a_frame_goes_page_by_page_into_scattered_frames_with_the_table_free() {
    let _g = serial();
    let t = Task::new();
    let b = t.frame_buffer();
    azos_ipc::memobj::__memobj_swap_pages_for_tests(t.region(b), 0, 2);
    assert_eq!(t.next(b), Out::err(outcome::NOT_READY));
    commit(0x61, 9_000, 3, FrameInfo::JPEG);
    assert!(t.next(b).is_ok());
    assert!(crate::khost::COPY_WITH_TABLE_FREE.load(std::sync::atomic::Ordering::SeqCst), "the copy held the region table");
    assert_eq!(t.get_by_pages(b, 9_000), pattern(0x61, 9_000));
}

/// **A buffer that cannot take the frame takes no frame.** A buffer below the
/// pool's size, a handle that is no memory object and one the task may only
/// read are each refused with their own outcome, and the frame is still owed
/// to the next call.
///
/// **Canary.** `frame-check-late-canary` (the buffer is looked at after the
/// frame is taken): the last line finds the frame gone.
#[test]
fn a_buffer_that_cannot_take_the_frame_takes_no_frame() {
    let _g = serial();
    let t = Task::new();
    let good = t.frame_buffer();
    assert_eq!(t.next(good), Out::err(outcome::NOT_READY));
    let seq = commit(0x50, 300, 7_000, FrameInfo::JPEG);
    let small = t.buffer(1, MemSpec::anon(MemPerms::ReadWrite));
    if BYTES > azos_arch::PAGE_SIZE {
        assert_eq!(t.next(small), Out::err(outcome::BAD_ARGUMENT), "below the pool's buffer");
    }
    assert_eq!(t.next(0x00ff_ffff), Out::err(outcome::BAD_ARGUMENT), "not a memory object");
    let read_only = t.buffer(BYTES, MemSpec::anon(MemPerms::ReadOnly));
    assert!(matches!(t.next(read_only).code, outcome::DENIED | outcome::UNSUPPORTED | outcome::BAD_ARGUMENT));
    let m = t.next(good);
    assert_eq!(m.value.seq, seq, "the refused calls took nothing: {m:?}");
}

/// **Nothing but the right gets a frame.** A capability without `READ`, and a
/// badge that names no camera, are refused before anything is touched: no
/// reader slot is taken and no frame.
///
/// **Canary.** Drop the `gate` in `Server::next` or the badge test: the
/// refusal here is `NOT_READY` or `OK`.
#[test]
fn the_right_and_the_camera_are_checked_before_anything_is_touched() {
    let _g = serial();
    let t = Task::new();
    let buf = t.frame_buffer();
    commit(0x01, 8, 1, FrameInfo::JPEG);
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        let mut s = t.server(0, rights);
        assert_eq!(s.buffer_bytes(), Out::err(outcome::DENIED), "{rights:?}");
        assert_eq!(s.next(WireCap::<FrameBuf>::from_raw(buf)), Out::err(outcome::DENIED), "{rights:?}");
        assert_eq!(s.close(), Out::err(outcome::DENIED), "{rights:?}");
    }
    let mut s = t.server(frame::CAMERAS, CapPerms::READ);
    assert_eq!(s.buffer_bytes(), Out::err(outcome::NO_RESOURCE));
    assert_eq!(s.next(WireCap::<FrameBuf>::from_raw(buf)), Out::err(outcome::NO_RESOURCE));
    assert_eq!(s.close(), Out::err(outcome::NO_RESOURCE));
    assert_eq!(t.reader().buffer_bytes(), Out::ok(BYTES as u32));
    // None of it took a slot: every one of the readers' slots is still free.
    let others: Vec<Task> = (0..RING3_READERS).map(|_| Task::new()).collect();
    for o in &others {
        assert_ne!(o.next(o.frame_buffer()).code, outcome::BUSY);
    }
}

/// **A reader slot is a task's, the same task keeps one, and a full table is
/// `BUSY` until a reader closes.** `FRAME_READERS` tasks read; the same task
/// reading again takes no second slot; one more is refused without a slot
/// and gets one when a reader closes; `close` twice is not an error.
///
/// **Canary.** `frame-slot-per-call-canary` (every call takes a slot): the
/// first task's second call is `BUSY`.
#[test]
fn a_reader_slot_is_a_tasks_and_a_full_table_is_busy() {
    let _g = serial();
    let holders: Vec<Task> = (0..RING3_READERS).map(|_| Task::new()).collect();
    for h in &holders {
        let b = h.frame_buffer();
        for _ in 0..2 {
            assert_eq!(h.next(b), Out::err(outcome::NOT_READY));
        }
    }
    let late = Task::new();
    let lb = late.frame_buffer();
    assert_eq!(late.next(lb), Out::err(outcome::BUSY));
    assert_eq!(late.next(lb), Out::err(outcome::BUSY), "refusing took nothing");
    assert_eq!(holders[0].reader().close(), Out::ok(()));
    assert_eq!(holders[0].reader().close(), Out::ok(()), "nothing to end is not an error");
    assert_eq!(late.next(lb), Out::err(outcome::NOT_READY), "the freed slot");
}

/// **A task that exits reads no more.** The pool has a reader while the task
/// lives and none after the exit hook: under back-pressure it would hold
/// capture back for good.
///
/// **Canary.** `frame-exit-keeps-canary` (the exit hook ends nothing): the
/// pool still has a reader.
#[test]
fn a_task_that_exits_reads_no_more() {
    let _g = serial();
    {
        let t = Task::new();
        let b = t.frame_buffer();
        assert_eq!(t.next(b), Out::err(outcome::NOT_READY));
        assert!(POOL.any_attached());
    }
    assert!(!POOL.any_attached(), "the exit left a reader behind");
}

/// **What a task does to its buffer never reaches another reader.** The task
/// scribbles over the copy it got; the companion link's sender, a reader of the same
/// frame, still gets the bytes the producer wrote.
///
/// **Canary.** `frame-reader-writes-canary` (the pool's view of a frame
/// writes into it): the sender reads a changed first byte.
#[test]
fn what_a_task_writes_to_its_buffer_never_reaches_another_reader() {
    let _g = serial();
    let t = Task::new();
    let b = t.frame_buffer();
    assert!(crate::frame_host::attach(LINK));
    assert_eq!(t.next(b), Out::err(outcome::NOT_READY));
    let seq = commit(0x70, 400, 9_000, FrameInfo::JPEG);
    assert_eq!(t.next(b).value.seq, seq);
    t.put(b, 0xEE);
    {
        let f = POOL.acquire_latest(LINK).expect("the sender's frame");
        assert_eq!(f.seq(), seq);
        assert_eq!(f.bytes(), &pattern(0x70, 400)[..]);
    }
    POOL.detach(LINK);
}

/// The `cam-capture` records of `tid`, oldest first: `(verdict, seq, reason)`.
fn records(tid: u32) -> Vec<(u8, u64, u64)> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::CamCapture as u8 && r.subject == tid {
            v.push((r.verdict, r.n[1], r.n[2]));
        }
    });
    v
}

const ADMIT: u8 = Verdict::Admit as u8;
const REFUSE: u8 = Verdict::Refuse as u8;

/// **A class without the `cam` effect reads nothing, learns nothing and is
/// recorded.** The refusal comes before the pool, the buffer and the slot: it
/// is `REFUSED` even for a bad buffer, takes no slot, and is a `Refuse`
/// record with the reason `NO_EFFECT`. A task that already reads is not asked
/// again.
///
/// **Canary.** `frame-effect-ignored-canary` (the effect is not asked): the
/// task gets `NOT_READY`, a slot and a grant.
#[test]
fn a_class_without_the_cam_effect_is_refused_and_recorded() {
    let _g = serial();
    let t = Task::new();
    let b = t.frame_buffer();
    crate::effect::withhold(EffectKind::Cam, t.tid);
    assert_eq!(t.next(b), Out::err(outcome::REFUSED));
    assert_eq!(t.next(0x00ff_ffff), Out::err(outcome::REFUSED), "it learns nothing of the buffer or the pool");
    crate::effect::clear_withheld();
    assert!(!POOL.any_attached(), "a refused task took no slot");
    assert_eq!(records(t.tid), vec![(REFUSE, 0, frame::reason::NO_EFFECT as u64); 2]);
    // A mic withheld is no cam withheld.
    crate::effect::grant_all(EffectKind::Cam);
    crate::effect::withhold(EffectKind::Mic, t.tid);
    assert_eq!(t.next(b), Out::err(outcome::NOT_READY));
    crate::effect::clear_withheld();
}

/// **The camera effect is default-deny.** With nothing granting it (no row, no
/// topology: the host's case) a task is `REFUSED`, takes no slot and the
/// refusal is a record; the pure rule agrees: only a `cam` row that does not
/// contain the class grants it.
///
/// **Canary.** `effect-default-allow-canary` (a class with no row has the
/// effect): the row lines fail.
#[test]
fn a_task_nothing_grants_the_camera_is_refused_and_recorded() {
    use azos_topology::{EnvelopeSpec, Envelope, MaybeStr};
    let _g = serial();
    let t = Task::new();
    let b = t.frame_buffer();
    crate::effect::clear_withheld();
    assert_eq!(t.next(b), Out::err(outcome::REFUSED));
    assert!(!POOL.any_attached());
    assert_eq!(records(t.tid), vec![(REFUSE, 0, frame::reason::NO_EFFECT as u64)]);
    let row = |kind, class: &'static str, level| EnvelopeSpec {
        name: MaybeStr::from_bytes(b"r"),
        kind,
        class: MaybeStr::from_bytes(class.as_bytes()),
        level,
    };
    let class = |c: &'static str| MaybeStr::from_bytes(c.as_bytes());
    let rows = [row(EffectKind::Cam, "granted", Envelope::Full), row(EffectKind::Cam, "denied", Envelope::Contained)];
    assert!(crate::effect::admitted(EffectKind::Cam, &rows, &class("granted")));
    assert!(!crate::effect::admitted(EffectKind::Cam, &rows, &class("denied")));
    assert!(!crate::effect::admitted(EffectKind::Cam, &rows, &class("unnamed")), "no row, no effect");
    assert!(!crate::effect::admitted(EffectKind::Mic, &rows, &class("granted")), "a cam row grants no mic");
}

/// **Every grant and a reader's first frame are records, once each.** The
/// first `next` is a `Admit` record `GRANTED`; the first frame it gets is an
/// `Admit` `FIRST_FRAME` naming the frame; later frames and later calls write
/// nothing. A full reader table is a `Refuse` `NO_SLOT`, and a pool that could
/// not be made is a `Refuse` `POOL` of the pool (subject 0).
///
/// **Canaries.** `frame-unrecorded-canary` (nothing is written): no record.
/// `frame-first-read-always-canary` (every frame is a first): two.
#[test]
fn the_grant_the_first_frame_and_the_refusals_are_recorded() {
    let _g = serial();
    let t = Task::new();
    let b = t.frame_buffer();
    assert_eq!(t.next(b), Out::err(outcome::NOT_READY));
    assert_eq!(t.next(b), Out::err(outcome::NOT_READY));
    assert_eq!(records(t.tid), vec![(ADMIT, 0, frame::reason::GRANTED as u64)], "one grant, however many calls");
    let s1 = commit(0x11, 40, 1, FrameInfo::JPEG);
    assert!(t.next(b).is_ok());
    let s2 = commit(0x12, 40, 2, FrameInfo::JPEG);
    assert!(t.next(b).is_ok());
    assert_ne!(s1, s2);
    assert_eq!(
        records(t.tid),
        vec![(ADMIT, 0, frame::reason::GRANTED as u64), (ADMIT, s1, frame::reason::FIRST_FRAME as u64)],
        "the second frame is no first"
    );
    // The table: every slot held, one more asks.
    let others: Vec<Task> = (0..RING3_READERS.saturating_sub(1)).map(|_| Task::new()).collect();
    for o in &others {
        let ob = o.frame_buffer();
        assert_ne!(o.next(ob).code, outcome::BUSY);
    }
    let late = Task::new();
    let lb = late.frame_buffer();
    assert_eq!(late.next(lb), Out::err(outcome::BUSY));
    assert_eq!(records(late.tid), vec![(REFUSE, 0, frame::reason::NO_SLOT as u64)]);
    crate::frame_host::refuse_pool(2);
    assert_eq!(records(0).last(), Some(&(REFUSE, 2, frame::reason::POOL as u64)));
}

/// **One failed lend of the pool's buffers does not end the camera:** the next
/// attach tries again, a lend that succeeds is not repeated, and the retries
/// are bounded and counted.
///
/// **Canary.** `frame-lend-once-canary`: one try per boot.
#[test]
fn a_failed_buffer_lend_is_tried_again_by_the_next_attach_within_a_bound() {
    use std::cell::Cell;
    let ready = Cell::new(false);
    let lends = Cell::new(0u32);
    let lender = Lender::new();
    let try_once = |works: bool| {
        lender.ensure(|| ready.get(), || {
            lends.set(lends.get() + 1);
            ready.set(works);
        })
    };
    assert!(!try_once(false));
    assert!(try_once(true), "the next attach lends again and the pool has its buffers");
    assert_eq!((lends.get(), lender.failures()), (2, 1));
    assert!(try_once(false), "a pool that has its buffers is not lent again");
    assert_eq!(lends.get(), 2);

    let ready = Cell::new(false);
    let lender = Lender::new();
    for _ in 0..LEND_TRIES + 5 {
        lender.ensure(|| ready.get(), || lends.set(lends.get() + 1));
    }
    assert_eq!(lender.failures(), LEND_TRIES, "the retries stop at the bound");
}
