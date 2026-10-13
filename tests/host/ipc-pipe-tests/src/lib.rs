// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for `crates/core/ipc/src/pipe.rs`.
//!
//! The kernel `azos_ipc` crate cannot be compiled for the host (it pulls
//! in `azos_drv_*` / `azos_sched`, which are RV64-only). The three
//! module audited in this lane is pure pool manipulation once two things
//! are stood in for:
//!
//!  * **`azos_sync::SpinLock`** — the real one calls `azos_arch::csr`
//!    (`crates/core/sync/src/spinlock.rs:15`) to save/restore `sstatus.SIE`, which
//!    does not exist off RISC-V. `shims/sync` provides the same API
//!    (`const fn new`, `lock`, `lock_irqsave`, `Deref`/`DerefMut` guard) over
//!    a `std::sync::Mutex` under the same *library* name, so the modules
//!    compile unmodified. Mutual exclusion semantics match; only the IRQ
//!    discipline is absent, and nothing under test depends on it.
//!  * **Caller identity** — `current_task_tid()` / `current_user_pt()` live in
//!    `azos_sched`. Each module has a `#[cfg(test)] mod test_ctx` shim
//!    (compiled *only* here, never into the kernel) that drives the identity
//!    from atomics, so a test can say "now I am ring-3 task 7".
//!
//! Everything else — the pools, the ownership fields, the bounds checks — is
//! the real kernel source, byte for byte.
//!
//! Run with:  `cd tests/host/ipc-pipe-tests && cargo test`

// `cap.rs` carries `#[cfg(kani)]` proof harnesses for the model checker; that
// cfg is unknown to plain cargo and would otherwise warn on every build.
#![allow(unexpected_cfgs)]

// ---------------------------------------------------------------------------
// The modules under test
// ---------------------------------------------------------------------------

// `pipe.rs` references `crate::cap` for the typed `Cap<Pipe>` path, so cap.rs
// comes along. Its own embedded suite (also run by `tests/host/cap-tests`)
// therefore executes here too; those tests are not part of this lane's count.
#[path = "../../../../crates/core/ipc/src/cap.rs"]
pub mod cap;

// `cap.rs` declares `objref`, whose minter reaches the per-task tables through
// `crate::cap_store`, so the table module comes along. Its behaviour is
// tested in `tests/host/cap-tests`, not here.
#[path = "../../../../crates/core/ipc/src/cap_store.rs"]
pub mod cap_store;

// The link an object bound to an event port stores (wave 11, PORTWAIT).
#[path = "../../../../crates/core/ipc/src/port_link.rs"]
pub mod port_link;

/// Host stand-in for the `crates/core/ipc/src/port.rs` entries the pulled-in
/// modules name. The real port table is tested in `tests/host/ipc-lease-tests`;
/// nothing is bound in this harness.
pub mod port {
    /// The kinds the pulled-in modules name (wave 15 N5b).
    #[allow(dead_code)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum PortSourceKind {
        Ring(u32),
        Irq(u32),
        Endpoint(u32),
    }

    /// A gone source: nothing is bound in this harness.
    #[allow(dead_code)]
    pub fn port_source_gone(_link: crate::port_link::PortLink, _kind: PortSourceKind, _code: u16) -> bool {
        false
    }

    /// An endpoint's notice: nothing is bound in this harness.
    #[allow(dead_code)]
    pub fn port_signal(_link: crate::port_link::PortLink, _kind: PortSourceKind) -> bool {
        false
    }
}

#[path = "../../../../crates/core/ipc/src/pipe.rs"]
pub mod pipe;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

#[cfg(test)]
mod harness {
    use std::sync::Mutex;

    /// The pipe module keeps its state in a `static` pool, and
    /// `cargo test` runs tests on parallel threads. Every test takes this
    /// lock and starts from a wiped pool, so one test can never observe
    /// another's channels/pipes/signal entries. Reset-without-serialize
    /// (the shape `zerocopy.rs` used before it was deleted, U04-7) is not
    /// enough here, with a shared global pool.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    pub struct Guard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    /// Serialize, wipe the pool, and start as "kernel task, tid 0".
    pub fn begin() -> Guard {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::pipe::__pipe_reset_for_tests();
        as_kernel();
        Guard(g)
    }

    /// Become ring-3 task `tid`.
    pub fn as_user(tid: u32) {
        crate::pipe::test_ctx::set(tid, false);
    }

    /// Become a kernel task (`user_pt == 0` ⇒ privileged bypass).
    pub fn as_kernel() {
        crate::pipe::test_ctx::set(0, true);
    }
}

// ---------------------------------------------------------------------------
// pipe.rs
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pipe_tests {
    use crate::harness::{as_kernel, as_user, begin};
    use crate::pipe::*;

    const OWNER: u32 = 33;
    const STRANGER: u32 = 44;

    fn create_as(tid: u32, n: usize) -> Vec<usize> {
        as_user(tid);
        (0..n)
            .map(|i| pipe_create().unwrap_or_else(|| panic!("create #{i} failed")).0)
            .collect()
    }

    // ── Ownership ────────────────────────────────────────────────────────

    #[test]
    fn create_records_owner_and_round_trips() {
        let _g = begin();
        for idx in create_as(OWNER, 4) {
            assert_eq!(pipe_owner(idx), Some(OWNER), "pipe {idx}");
            as_user(OWNER);
            assert_eq!(pipe_write_buf(idx, b"hello"), 5);
            assert_eq!(pipe_available(idx), 5);
            let mut buf = [0u8; 16];
            assert_eq!(pipe_read_buf(idx, &mut buf), 5);
            assert_eq!(&buf[..5], b"hello");
        }
    }

    #[test]
    fn stranger_cannot_read_write_or_close_any_index() {
        let _g = begin();
        let pipes = create_as(OWNER, 4);
        for &idx in &pipes {
            as_user(OWNER);
            assert_eq!(pipe_write_buf(idx, b"private"), 7);
        }

        as_user(STRANGER);
        for idx in 0..MAX_PIPES {
            let mut buf = [0u8; 16];
            assert_eq!(pipe_read_buf(idx, &mut buf), -1, "read {idx}");
            assert_eq!(buf, [0u8; 16], "stranger got bytes out of pipe {idx}");
            assert_eq!(pipe_write_buf(idx, b"poison"), -1, "write {idx}");
            assert_eq!(pipe_close_read(idx), -1, "close_read {idx}");
            assert_eq!(pipe_close_write(idx), -1, "close_write {idx}");
            assert_eq!(pipe_available(idx), 0, "available {idx} leaked occupancy");
            assert_eq!(pipe_space(idx), 0, "space {idx} leaked occupancy");
        }

        // Nothing the stranger did took effect.
        as_user(OWNER);
        for &idx in &pipes {
            assert_eq!(pipe_available(idx), 7, "pipe {idx} was tampered with");
            let mut buf = [0u8; 16];
            assert_eq!(pipe_read_buf(idx, &mut buf), 7);
            assert_eq!(&buf[..7], b"private");
        }
    }

    #[test]
    fn kernel_bypasses_the_owner_check() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_kernel();
        assert_eq!(pipe_write_buf(idx, b"kernel"), 6);
        let mut buf = [0u8; 16];
        assert_eq!(pipe_read_buf(idx, &mut buf), 6);
        assert!(pipe_space(idx) > 0);
        assert_eq!(pipe_close_write(idx), 0);
        assert_eq!(pipe_close_read(idx), 0);
    }

    /// The block copies wrap at the ring's end: bytes come back in order
    /// across the wrap, and a write takes only what fits (PIPE_BUF_SIZE - 1).
    #[test]
    fn bytes_survive_the_ring_wrap_in_order() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut buf = vec![0u8; 5000];
        assert_eq!(pipe_write_buf(idx, &data[..3000]), 3000);
        assert_eq!(pipe_read_buf(idx, &mut buf[..3000]), 3000);
        assert_eq!(&buf[..3000], &data[..3000]);
        // Starts at 3000 of 4096: 1096 to the end, the rest from the start.
        assert_eq!(pipe_write_buf(idx, &data[..2000]), 2000);
        assert_eq!(pipe_read_buf(idx, &mut buf[..2000]), 2000);
        assert_eq!(&buf[..2000], &data[..2000]);
        assert_eq!(pipe_write_buf(idx, &data), (crate::pipe::PIPE_BUF_SIZE - 1) as i32);
        assert_eq!(pipe_read_buf(idx, &mut buf), (crate::pipe::PIPE_BUF_SIZE - 1) as i32);
        assert_eq!(&buf[..crate::pipe::PIPE_BUF_SIZE - 1], &data[..crate::pipe::PIPE_BUF_SIZE - 1]);
        assert_eq!(pipe_close_write(idx), 0);
        assert_eq!(pipe_close_read(idx), 0);
    }

    #[test]
    fn owner_can_close_each_end_once() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(pipe_write_buf(idx, b"last"), 4);
        assert_eq!(pipe_close_write(idx), 0);
        // Data written before the close is still readable...
        let mut buf = [0u8; 8];
        assert_eq!(pipe_read_buf(idx, &mut buf), 4);
        // ...then EOF, not EAGAIN, because the writer is gone.
        assert_eq!(pipe_read_buf(idx, &mut buf), 0);
        // And writing after the read end closes is EPIPE.
        assert_eq!(pipe_close_read(idx), 0);
        assert_eq!(pipe_write_buf(idx, b"x"), -1);
    }

    #[test]
    fn empty_pipe_with_live_writer_is_eagain() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let mut buf = [0u8; 8];
        assert_eq!(pipe_read_buf(idx, &mut buf), -2, "EAGAIN while writer alive");
    }

    // ── Raw pointers and bounds: no panic, no over-read ──────────────────

    #[test]
    fn null_pointers_are_refused() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(pipe_read(idx, core::ptr::null_mut(), 16), -1);
        assert_eq!(pipe_write(idx, core::ptr::null(), 16), -1);
        // ...and with count 0 as well, since 0 is the other way a caller
        // says "no buffer".
        assert_eq!(pipe_read(idx, core::ptr::null_mut(), 0), -1);
        assert_eq!(pipe_write(idx, core::ptr::null(), 0), -1);
    }

    #[test]
    fn out_of_range_indices_never_panic() {
        let _g = begin();
        let bad = [MAX_PIPES, MAX_PIPES + 1, usize::MAX, usize::MAX / 2];
        let mut buf = [0u8; 8];
        for who in [true, false] {
            if who { as_kernel() } else { as_user(STRANGER) }
            for &idx in &bad {
                assert_eq!(pipe_read_buf(idx, &mut buf), -1, "read {idx}");
                assert_eq!(pipe_write_buf(idx, b"x"), -1, "write {idx}");
                assert_eq!(pipe_close_read(idx), -1, "close_read {idx}");
                assert_eq!(pipe_close_write(idx), -1, "close_write {idx}");
                assert_eq!(pipe_available(idx), 0, "available {idx}");
                assert_eq!(pipe_space(idx), 0, "space {idx}");
                assert_eq!(pipe_owner(idx), None, "owner {idx}");
            }
        }
    }

    #[test]
    fn free_slot_is_rejected() {
        let _g = begin();
        as_kernel();
        let mut buf = [0u8; 8];
        for idx in 0..MAX_PIPES {
            assert_eq!(pipe_read_buf(idx, &mut buf), -1, "read free {idx}");
            assert_eq!(pipe_write_buf(idx, b"x"), -1, "write free {idx}");
            assert_eq!(pipe_close_read(idx), -1, "close free {idx}");
            assert_eq!(pipe_owner(idx), None);
        }
    }

    #[test]
    fn empty_slices_are_a_no_op() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let mut empty: [u8; 0] = [];
        assert_eq!(pipe_write_buf(idx, &[]), 0);
        assert_eq!(pipe_read_buf(idx, &mut empty), 0);
        assert_eq!(pipe_available(idx), 0);
    }

    /// `count` larger than the buffer is the caller's bug, but the pipe must
    /// still clamp to its own free space and never walk off its ring. The
    /// buffer here is a real `PIPE_BUF_SIZE` array, so the clamped copy stays
    /// inside it — which is exactly the safety contract documented on
    /// `pipe_write`.
    #[test]
    fn oversized_count_clamps_to_ring_capacity() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let src = [0x5Au8; PIPE_BUF_SIZE];
        // Ask for twice the ring; the ring keeps one byte free as the
        // full/empty discriminator.
        let n = pipe_write(idx, src.as_ptr(), PIPE_BUF_SIZE * 2);
        assert_eq!(n, (PIPE_BUF_SIZE - 1) as i32);
        assert_eq!(pipe_space(idx), 0, "ring should now be full");
        // A second write finds no space and writes nothing.
        assert_eq!(pipe_write(idx, src.as_ptr(), PIPE_BUF_SIZE), 0);

        let mut dst = [0u8; PIPE_BUF_SIZE];
        let r = pipe_read(idx, dst.as_mut_ptr(), PIPE_BUF_SIZE * 2);
        assert_eq!(r, (PIPE_BUF_SIZE - 1) as i32);
        assert!(dst[..PIPE_BUF_SIZE - 1].iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn ring_wraps_without_losing_bytes() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let chunk = [0u8; 512];
        let mut out = [0u8; 512];
        // 20 × 512 = 10240 bytes through a 4096-byte ring ⇒ several wraps.
        for round in 0..20u8 {
            let payload: Vec<u8> = chunk.iter().map(|_| round).collect();
            assert_eq!(pipe_write_buf(idx, &payload), 512, "round {round}");
            assert_eq!(pipe_read_buf(idx, &mut out), 512, "round {round}");
            assert!(out.iter().all(|&b| b == round), "round {round} corrupted");
        }
    }

    #[test]
    fn pool_exhaustion_returns_none_not_panic() {
        let _g = begin();
        as_user(OWNER);
        for i in 0..MAX_PIPES {
            assert!(pipe_create().is_some(), "create #{i}");
        }
        for _ in 0..4 {
            assert!(pipe_create().is_none(), "pool must refuse past capacity");
        }
    }

    // ── Slot reuse ───────────────────────────────────────────────────────

    #[test]
    fn closing_both_ends_gives_the_slot_back() {
        let _g = begin();
        as_user(OWNER);
        // Three times the pool: no slot survives its own close.
        for i in 0..3 * MAX_PIPES {
            let (r, w) = pipe_create().unwrap_or_else(|| panic!("create #{i} failed"));
            assert_eq!(pipe_close_write(w), 0, "close_write #{i}");
            assert_eq!(pipe_close_read(r), 0, "close_read #{i}");
        }
    }

    #[test]
    fn an_exhausted_pool_recovers_when_a_pipe_closes() {
        let _g = begin();
        let pipes = create_as(OWNER, MAX_PIPES);
        assert!(pipe_create().is_none(), "pool must be full");
        let idx = pipes[MAX_PIPES / 2];
        assert_eq!(pipe_close_read(idx), 0);
        assert!(pipe_create().is_none(), "an open write end still holds the slot");
        assert_eq!(pipe_close_write(idx), 0);
        let (again, _) = pipe_create().expect("the closed slot must be reusable");
        assert_eq!(again, idx);
    }

    #[test]
    fn a_reused_slot_starts_empty() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        assert_eq!(pipe_write_buf(idx, b"stale"), 5);
        assert_eq!(pipe_close_write(idx), 0);
        assert_eq!(pipe_close_read(idx), 0);
        let (again, _) = pipe_create().expect("slot reusable");
        assert_eq!(again, idx);
        assert_eq!(pipe_available(again), 0, "bytes of the closed pipe leaked into the new one");
    }

    #[test]
    fn release_all_frees_only_the_dead_tasks_pipes() {
        let _g = begin();
        let mine = create_as(OWNER, 3);
        let theirs = create_as(STRANGER, 2);
        pipe_release_all(OWNER);
        for &idx in &mine {
            assert_eq!(pipe_owner(idx), None, "pipe {idx} of the dead task");
        }
        for &idx in &theirs {
            assert_eq!(pipe_owner(idx), Some(STRANGER), "pipe {idx} of a live task");
        }
        // Every freed slot is creatable again, and not one more.
        as_user(STRANGER);
        for i in 0..MAX_PIPES - theirs.len() {
            assert!(pipe_create().is_some(), "refill #{i}");
        }
        assert!(pipe_create().is_none());
    }
}

// ---------------------------------------------------------------------------
// pipe.rs — capability pipes (RFC-0055, wave 11)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod typed_pipes {
    use crate::harness::begin;
    use crate::pipe::*;

    fn read_all(res: u32, me: u32) -> (PipeIo, Vec<u8>) {
        let mut b = vec![0u8; PIPE_BUF_SIZE];
        let (io, _) = pipe_typed_read(res, &mut b, me);
        if let PipeIo::Done(n) = io {
            b.truncate(n);
            (io, b)
        } else {
            (io, Vec::new())
        }
    }

    #[test]
    fn bytes_flow_and_end_of_file_follows_the_last_write_end() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert_eq!(pipe_typed_write(r, b"hello", 7), (PipeIo::Done(5), 0));
        assert_eq!(read_all(r, 8), (PipeIo::Done(5), b"hello".to_vec()));
        assert_eq!(read_all(r, 8).0, PipeIo::WouldBlock, "empty with a live writer blocks");
        // The writer's handle goes (close, move-and-exit, its task's exit):
        // the parked reader is the one to wake, and it now sees EOF.
        assert_eq!(pipe_typed_drop_end(r, true), 8);
        assert_eq!(read_all(r, 8).0, PipeIo::Eof);
    }

    /// Wave 13: the ring is copied in at most two slices. Bytes that wrap
    /// past the end of the 4 KiB buffer, in both directions, come out in
    /// order, and a partial read leaves the rest for the next.
    #[test]
    fn bytes_wrapping_the_ring_come_out_in_order() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let fill = vec![0xEEu8; PIPE_BUF_SIZE - 10];
        assert_eq!(pipe_typed_write(r, &fill, 7), (PipeIo::Done(fill.len()), 0));
        assert_eq!(read_all(r, 8), (PipeIo::Done(fill.len()), fill));
        // Positions are now 10 bytes short of the end: 100 bytes wrap.
        let data: Vec<u8> = (0..100u8).collect();
        assert_eq!(pipe_typed_write(r, &data, 7), (PipeIo::Done(100), 0));
        let mut part = [0u8; 7];
        assert_eq!(pipe_typed_read(r, &mut part, 8).0, PipeIo::Done(7));
        assert_eq!(&part[..], &data[..7]);
        assert_eq!(read_all(r, 8), (PipeIo::Done(93), data[7..].to_vec()));
        // Full ring, all of it, across the wrap point.
        let full: Vec<u8> = (0..PIPE_BUF_SIZE).map(|i| (i * 7) as u8).collect();
        assert_eq!(pipe_typed_write(r, &full, 7), (PipeIo::Done(PIPE_BUF_SIZE), 0));
        assert_eq!(pipe_typed_write(r, b"x", 7).0, PipeIo::WouldBlock, "full");
        assert_eq!(read_all(r, 8), (PipeIo::Done(PIPE_BUF_SIZE), full));
    }

    /// An inherited or duplicated end is one more reference (RFC-0047 fork,
    /// round 48): closing the original write end leaves the pipe open, data
    /// still flows through the copy, and EOF follows only the last write end.
    #[test]
    fn an_added_end_keeps_the_pipe_open_until_the_last_close() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert!(pipe_typed_add_end(r, true));
        assert_eq!(pipe_typed_state(r).unwrap().1, 2, "two write ends");
        assert_eq!(pipe_typed_drop_end(r, true), 0, "one write end left: nobody to wake");
        assert_eq!(pipe_typed_write(r, b"ab", 9), (PipeIo::Done(2), 0));
        assert_eq!(read_all(r, 8), (PipeIo::Done(2), b"ab".to_vec()));
        assert_eq!(read_all(r, 8).0, PipeIo::WouldBlock, "a write end is still held");
        pipe_typed_drop_end(r, true);
        assert_eq!(read_all(r, 8).0, PipeIo::Eof, "the last write end closed");
    }

    #[test]
    fn a_write_with_no_reader_left_is_broken() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert_eq!(pipe_typed_drop_end(r, false), 0);
        assert_eq!(pipe_typed_write(r, b"x", 7).0, PipeIo::Broken);
    }

    /// The ring holds PIPE_BUF_SIZE bytes (not one fewer), and a write of at
    /// most that size goes in whole or not at all.
    ///
    /// **Canary.** Make `pipe_typed_write` write what fits for a small
    /// write: the 10-byte write into 6 bytes of room returns `Done(6)`.
    #[test]
    fn a_small_write_is_atomic_and_the_ring_is_full_size() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let big = vec![b'a'; PIPE_BUF_SIZE - 6];
        assert_eq!(pipe_typed_write(r, &big, 7).0, PipeIo::Done(PIPE_BUF_SIZE - 6));
        assert_eq!(pipe_typed_write(r, &[b'b'; 10], 7).0, PipeIo::WouldBlock, "10 bytes do not fit in 6");
        assert_eq!(pipe_typed_state(r).unwrap().2, PIPE_BUF_SIZE - 6, "nothing was written");
        assert_eq!(pipe_typed_write(r, &[b'c'; 6], 7).0, PipeIo::Done(6));
        assert_eq!(pipe_typed_state(r).unwrap().2, PIPE_BUF_SIZE, "the ring is full at its size");
        // The writer parked on a full ring is woken by the read that makes room.
        assert_eq!(pipe_typed_write(r, b"d", 9).0, PipeIo::WouldBlock);
        let mut one = [0u8; 1];
        assert_eq!(pipe_typed_read(r, &mut one, 8), (PipeIo::Done(1), 9));
    }

    #[test]
    fn a_large_write_writes_what_fits() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let big = vec![b'z'; PIPE_BUF_SIZE + 100];
        assert_eq!(pipe_typed_write(r, &big, 7).0, PipeIo::Done(PIPE_BUF_SIZE));
    }

    /// Lifetime follows the handles: the creator's exit does not free a pipe
    /// whose ends were moved on; the last end does, and its resource is stale
    /// from then on, also after the slot is reused.
    #[test]
    fn the_last_end_frees_the_slot_and_old_handles_go_stale() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        pipe_release_all(7); // the untyped per-creator release must not touch it
        assert!(pipe_typed_state(r).is_some());
        pipe_typed_drop_end(r, true);
        assert!(pipe_typed_state(r).is_some(), "one end is still held");
        pipe_typed_drop_end(r, false);
        assert!(pipe_typed_state(r).is_none(), "both ends gone: freed");
        let r2 = pipe_create_typed(7).unwrap();
        assert_eq!(r2 & 0xffff, r & 0xffff, "the same slot comes back");
        assert_ne!(r2, r, "with a new generation");
        assert_eq!(pipe_typed_write(r, b"x", 7).0, PipeIo::Stale);
        assert_eq!(read_all(r, 7).0, PipeIo::Stale);
    }

    #[test]
    fn a_task_holds_at_most_its_quota_of_pipes() {
        let _g = begin();
        for _ in 0..PIPE_QUOTA {
            pipe_create_typed(7).unwrap();
        }
        assert_eq!(pipe_create_typed(7), Err(PipeCreateError::Quota));
        assert!(pipe_create_typed(8).is_ok(), "another task is not charged");
        assert_eq!(pipe_typed_held_by(7), PIPE_QUOTA);
    }

    #[test]
    fn the_untyped_calls_cannot_reach_a_capability_pipe() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let idx = (r & 0xffff) as usize;
        pipe_typed_write(r, b"secret", 7);
        let mut b = [0u8; 8];
        // Even the kernel's privileged untyped path is refused.
        assert_eq!(pipe_read(idx, b.as_mut_ptr(), b.len()), -1);
        assert_eq!(pipe_close_read(idx), -1);
        assert_eq!(pipe_typed_state(r).unwrap().2, 6);
    }

    #[test]
    fn an_abandoned_waiter_is_forgotten() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert_eq!(read_all(r, 8).0, PipeIo::WouldBlock);
        pipe_typed_unwait(r, 8);
        assert_eq!(pipe_typed_write(r, b"x", 7), (PipeIo::Done(1), 0), "no stale waiter to wake");
    }
}
