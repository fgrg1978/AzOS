// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_rings`.
//!
//! One writer is a property of the type. This must not compile, because
//! `Writer` is not `Clone`:
//!
//! ```compile_fail
//! use azos_rings::Log;
//! let log = Log::<u32, 1>::new(0);
//! let w = log.writer().unwrap();
//! let _second = w.clone();
//! ```
//!
//! Neither is the producer or the consumer of a queue:
//!
//! ```compile_fail
//! use azos_rings::{Full, Queue};
//! let q = Queue::<u32, 4>::new(Full::Backpressure);
//! let p = q.producer().unwrap();
//! let _second = p.clone();
//! ```
//!
//! A handle is not `Copy` either: using it after a move is an error.
//!
//! ```compile_fail
//! use azos_rings::Log;
//! let log = Log::<u32, 1>::new(0);
//! let mut w = log.writer().unwrap();
//! let moved = w;
//! w.publish(1);
//! let _ = moved;
//! ```
//!
//! The control for all three: the same programs, with the offending line
//! removed, build and run.
//!
//! ```
//! use azos_rings::{Full, Log, Queue};
//! let log = Log::<u32, 1>::new(0);
//! let mut w = log.writer().unwrap();
//! let moved = w;
//! drop(moved);
//! let q = Queue::<u32, 4>::new(Full::Backpressure);
//! let mut p = q.producer().unwrap();
//! let mut c = q.consumer().unwrap();
//! p.push(1);
//! assert_eq!(c.pop(), Some(1));
//! ```

#[cfg(test)]
mod tests {
    use azos_rings::region::RingSleep;
    use azos_rings::{Doorbell, Full, Log, Next, Push, Queue};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

    // ---------------------------------------------------------------- Queue

    #[test]
    fn queue_fifo_order_and_each_item_once() {
        let q = Queue::<u32, 8>::new(Full::Backpressure);
        let mut p = q.producer().unwrap();
        let mut c = q.consumer().unwrap();
        for i in 0..5 {
            assert_eq!(p.push(i), Push::Pushed);
        }
        for i in 0..5 {
            assert_eq!(c.pop(), Some(i));
        }
        assert_eq!(c.pop(), None, "an item is consumed exactly once");
    }

    #[test]
    fn queue_empty_and_full() {
        let q = Queue::<u32, 4>::new(Full::Backpressure);
        let mut p = q.producer().unwrap();
        let mut c = q.consumer().unwrap();
        assert!(q.is_empty());
        assert_eq!(c.pop(), None);
        for i in 0..4 {
            assert_eq!(p.push(i), Push::Pushed);
        }
        assert_eq!(q.len(), 4);
        // Backpressure hands the item back and loses nothing already queued.
        assert_eq!(p.push(99), Push::Full(99));
        assert_eq!(q.dropped(), 0);
        assert_eq!(c.pop(), Some(0));
        assert_eq!(p.push(99), Push::Pushed, "room again after a pop");
        assert_eq!((c.pop(), c.pop(), c.pop(), c.pop()), (Some(1), Some(2), Some(3), Some(99)));
    }

    #[test]
    fn queue_drop_newest_is_the_flag() {
        let q = Queue::<u32, 2>::new(Full::DropNewest);
        let mut p = q.producer().unwrap();
        let mut c = q.consumer().unwrap();
        assert_eq!(p.push(1), Push::Pushed);
        assert_eq!(p.push(2), Push::Pushed);
        assert_eq!(p.push(3), Push::Dropped);
        assert_eq!(p.push(4), Push::Dropped);
        assert_eq!(q.dropped(), 2);
        assert_eq!((c.pop(), c.pop(), c.pop()), (Some(1), Some(2), None));
    }

    #[test]
    fn queue_wraps_many_times() {
        let q = Queue::<u64, 4>::new(Full::Backpressure);
        let mut p = q.producer().unwrap();
        let mut c = q.consumer().unwrap();
        for i in 0..1000u64 {
            assert_eq!(p.push(i), Push::Pushed);
            assert_eq!(c.pop(), Some(i));
        }
    }

    #[test]
    fn queue_producer_blocks_until_the_consumer_makes_room() {
        let q = Queue::<u32, 1>::new(Full::Backpressure);
        let mut p = q.producer().unwrap();
        let mut c = q.consumer().unwrap();
        p.push(1);
        let mut waits = 0;
        // The wait callback is where the producer would sleep; here it pops.
        let r = p.push_wait(2, || {
            waits += 1;
            assert_eq!(c.pop(), Some(1));
        });
        assert_eq!(r, Push::Pushed);
        assert_eq!(waits, 1);
        assert_eq!(c.pop(), Some(2));
    }

    #[test]
    fn queue_threads_in_order_none_lost() {
        const N: u64 = 200_000;
        let q = Queue::<u64, 64>::new(Full::Backpressure);
        std::thread::scope(|s| {
            let mut p = q.producer().unwrap();
            let mut c = q.consumer().unwrap();
            s.spawn(move || {
                for i in 0..N {
                    p.push_wait(i, std::hint::spin_loop);
                }
            });
            s.spawn(move || {
                let mut next = 0;
                while next < N {
                    if let Some(v) = c.pop() {
                        assert_eq!(v, next, "order or duplicate");
                        next += 1;
                    }
                }
            });
        });
    }

    // ------------------------------------------------------------------ Log

    #[test]
    fn log_one_is_latest_value() {
        let log = Log::<u32, 1>::new(5);
        assert_eq!(log.latest(), (0, 5), "before any publish: the initial value");
        let mut w = log.writer().unwrap();
        assert_eq!(w.publish(10), 1);
        assert_eq!(w.publish(11), 2);
        assert_eq!(log.latest(), (2, 11));
        assert_eq!(log.head(), 2);
    }

    #[test]
    fn log_second_writer_is_refused_until_the_first_drops() {
        let log = Log::<u32, 4>::new(0);
        let w = log.writer().unwrap();
        assert!(log.writer().is_none());
        drop(w);
        assert!(log.writer().is_some());
        let q = Queue::<u32, 4>::new(Full::Backpressure);
        let _p = q.producer().unwrap();
        let _c = q.consumer().unwrap();
        assert!(q.producer().is_none() && q.consumer().is_none());
    }

    #[test]
    fn log_readers_have_independent_cursors() {
        let log = Log::<u32, 8>::new(0);
        let mut w = log.writer().unwrap();
        let mut a = log.reader();
        let mut b = log.reader();
        for i in 1..=3 {
            w.publish(i * 10);
        }
        assert_eq!(a.next(), Next::Item(10));
        assert_eq!(a.next(), Next::Item(20));
        // b has not moved: a's reads did not consume anything.
        assert_eq!(b.next(), Next::Item(10));
        assert_eq!(a.next(), Next::Item(30));
        assert_eq!(a.next(), Next::Empty);
        assert_eq!((b.next(), b.next(), b.next()), (Next::Item(20), Next::Item(30), Next::Empty));
        // A reader made late sees only what comes after, or from the oldest.
        let mut late = log.reader();
        let mut old = log.reader_oldest();
        assert_eq!(late.next(), Next::Empty);
        assert_eq!(old.next(), Next::Item(10));
        w.publish(40);
        assert_eq!(late.next(), Next::Item(40));
    }

    #[test]
    fn log_overrun_counts_and_jumps_ahead() {
        let log = Log::<u32, 4>::new(0);
        let mut w = log.writer().unwrap();
        let mut slow = log.reader();
        let mut keen = log.reader();
        for i in 1..=10 {
            w.publish(i);
            assert_eq!(keen.next(), Next::Item(i), "a reader that keeps up never overruns");
        }
        // Items 1..=6 were overwritten; 7..=10 are retained.
        assert_eq!(slow.next(), Next::Overrun(6));
        assert_eq!(slow.cursor(), 7);
        assert_eq!((slow.next(), slow.next()), (Next::Item(7), Next::Item(8)));
        assert_eq!((slow.next(), slow.next(), slow.next()), (Next::Item(9), Next::Item(10), Next::Empty));
    }

    #[test]
    fn log_exactly_full_is_not_an_overrun() {
        let log = Log::<u32, 4>::new(0);
        let mut w = log.writer().unwrap();
        let mut r = log.reader();
        for i in 1..=4 {
            w.publish(i);
        }
        for i in 1..=4 {
            assert_eq!(r.next(), Next::Item(i));
        }
        w.publish(5);
        w.publish(6);
        w.publish(7);
        w.publish(8);
        w.publish(9);
        assert_eq!(r.next(), Next::Overrun(1), "one item, 5, was overwritten");
        assert_eq!(r.next(), Next::Item(6));
    }

    #[test]
    fn queue_is_a_region_ring() {
        use azos_rings::region::{RingStep, SpscRing};
        // The queue's own address is a ring base: the region's view reads what
        // the queue pushed and the queue pops what the region view pushed, so
        // the two forms are one protocol over one layout, not two look-alikes.
        let q = Queue::<u64, 8>::new(Full::Backpressure);
        let ring = SpscRing { base: &q as *const _ as usize, cap: 8 };
        let mut p = q.producer().unwrap();
        let mut c = q.consumer().unwrap();
        assert_eq!(p.push(7), Push::Pushed);
        assert_eq!(p.push(8), Push::Pushed);
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.try_pop(), (RingStep::Done, 7));
        assert_eq!(c.pop(), Some(8));
        for i in 0..8 {
            assert_eq!(ring.try_push(i), RingStep::Done);
        }
        assert_eq!(ring.try_push(9), RingStep::Blocked);
        assert_eq!(p.push(9), Push::Full(9), "the queue sees the region's fill level");
        assert_eq!(c.pop(), Some(0));
    }

    // ------------------------------------------------------------- Doorbell

    struct Counting<'a>(&'a AtomicU64, &'a AtomicU64);
    impl Doorbell for Counting<'_> {
        fn ring(&self, head: u64) {
            self.0.fetch_add(1, Ordering::Relaxed);
            self.1.store(head, Ordering::Relaxed);
        }
    }

    #[test]
    fn doorbell_rings_once_per_head_advance_with_the_new_head() {
        let (rings, last) = (AtomicU64::new(0), AtomicU64::new(0));
        let log = Log::<u32, 2, _>::with_bell(0, Counting(&rings, &last));
        let mut w = log.writer().unwrap();
        w.publish(1);
        w.publish(2);
        w.publish(3);
        assert_eq!((rings.load(Ordering::Relaxed), last.load(Ordering::Relaxed)), (3, 3));
        // A queue rings only for a consumer that announced it may be asleep,
        // and the announcement is consumed by the ring that answers it.
        let q = Queue::<u32, 2, _>::with_bell(Full::DropNewest, Counting(&rings, &last));
        let mut p = q.producer().unwrap();
        let mut c = q.consumer().unwrap();
        p.push(1); // nobody asleep: no ring
        assert_eq!(rings.load(Ordering::Relaxed), 3);
        assert_eq!(c.pop(), Some(1));
        assert!(matches!(c.sleep(), RingSleep::Wait { .. }), "empty: the consumer sleeps");
        p.push(2); // the head moves to 2 and the sleeper is woken
        assert_eq!((rings.load(Ordering::Relaxed), last.load(Ordering::Relaxed)), (4, 2));
        p.push(3); // the announcement was spent: no second ring
        assert_eq!(rings.load(Ordering::Relaxed), 4);
        assert_eq!(c.sleep(), RingSleep::Retry, "items waiting: retry, do not sleep");
        c.woke();
        p.push(4); // full, dropped: the head did not move
        assert_eq!(q.dropped(), 1);
        assert_eq!(rings.load(Ordering::Relaxed), 4);
    }

    // ------------------------------------------------------------ Torn read

    /// A payload whose eight words are always equal. A copy that mixes two
    /// stores shows two different words.
    #[derive(Clone, Copy)]
    struct Wide([u64; 8]);

    fn uniform(w: &Wide) -> bool {
        w.0.iter().all(|x| *x == w.0[0])
    }

    /// One writer storing `Wide(s)` flat out, readers asserting no tear and
    /// that sequence numbers never go backwards. Returns how many reads each
    /// reader completed, so a run that read nothing cannot pass.
    fn stress(slots_one: bool) -> u64 {
        let log1 = Log::<Wide, 1>::new(Wide([0; 8]));
        let log4 = Log::<Wide, 4>::new(Wide([0; 8]));
        let stop = AtomicBool::new(false);
        let reads = AtomicU64::new(0);
        // Readers that have finished or panicked: the writer stops only when
        // all three are out, whatever way they left.
        let out = AtomicU64::new(0);
        struct Out<'a>(&'a AtomicU64);
        impl Drop for Out<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        std::thread::scope(|s| {
            // Each arm owns its log; the closure is generic over the shape by
            // way of two helper fns below.
            if slots_one {
                let mut w = log1.writer().unwrap();
                let stop = &stop;
                s.spawn(move || {
                    let mut i = 1u64;
                    while !stop.load(Ordering::Relaxed) {
                        w.publish(Wide([i; 8]));
                        i += 1;
                    }
                });
                for _ in 0..3 {
                    s.spawn(|| {
                        let _out = Out(&out);
                        let mut last = 0;
                        for _ in 0..2_000_000 {
                            let (seq, v) = log1.latest();
                            assert!(uniform(&v), "TORN READ at seq {seq}: {:?}", v.0);
                            assert_eq!(v.0[0], seq, "value does not belong to its sequence");
                            assert!(seq >= last, "latest went backwards");
                            last = seq;
                            reads.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                }
            } else {
                let mut w = log4.writer().unwrap();
                let stop = &stop;
                s.spawn(move || {
                    let mut i = 1u64;
                    while !stop.load(Ordering::Relaxed) {
                        w.publish(Wide([i; 8]));
                        i += 1;
                    }
                });
                for _ in 0..3 {
                    s.spawn(|| {
                        let _out = Out(&out);
                        let mut r = log4.reader_oldest();
                        let mut want = r.cursor();
                        for _ in 0..2_000_000 {
                            match r.next() {
                                Next::Item(v) => {
                                    assert!(uniform(&v), "TORN READ: {:?}", v.0);
                                    assert_eq!(v.0[0], want, "gap without an Overrun report");
                                    want += 1;
                                    reads.fetch_add(1, Ordering::Relaxed);
                                }
                                Next::Overrun(n) => want += n,
                                Next::Empty => std::hint::spin_loop(),
                            }
                        }
                    });
                }
            }
            s.spawn(|| {
                while out.load(Ordering::Relaxed) < 3 {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                stop.store(true, Ordering::Relaxed);
            });
        });
        reads.load(Ordering::Relaxed)
    }

    #[test]
    fn torn_read_latest_value() {
        assert!(stress(true) > 100_000);
    }

    #[test]
    fn torn_read_and_gaps_in_a_four_slot_log() {
        assert!(stress(false) > 100_000);
    }

    // ------------------------------------------------------- byte ring

    /// A 64-byte-aligned region for a byte ring of `cap` bytes.
    fn stream(cap: u32) -> (Vec<u64>, azos_rings::region::SpscStream) {
        let mem = vec![0u64; (azos_rings::region::SpscStream::bytes(cap) + 64) / 8];
        let base = (mem.as_ptr() as usize + 63) & !63;
        let r = azos_rings::region::SpscStream { base, cap };
        r.init();
        (mem, r)
    }

    #[test]
    fn stream_moves_any_number_of_bytes_across_the_wrap() {
        use azos_rings::region::RingStep;
        let (_m, r) = stream(16);
        assert_eq!(r.write(&[]), (0, RingStep::Blocked), "nothing to write");
        let mut out = [0u8; 32];
        assert_eq!(r.read(&mut out), (0, RingStep::Blocked), "empty");
        // 12 in, 10 out, 12 in: the second write wraps the 16-byte ring.
        assert_eq!(r.write(&[1u8; 12]).0, 12);
        assert_eq!(r.read(&mut out[..10]).0, 10);
        let src: Vec<u8> = (100..112).collect();
        assert_eq!(r.write(&src).0, 12);
        assert_eq!(r.len(), 14);
        assert_eq!(r.read(&mut out).0, 14, "a read takes everything there is");
        assert_eq!(&out[..2], &[1, 1]);
        assert_eq!(&out[2..14], &src[..]);
    }

    #[test]
    fn stream_write_takes_what_fits_and_read_frees_the_room() {
        let (_m, r) = stream(16);
        assert_eq!(r.write(&[7u8; 40]).0, 16, "the room, no more");
        assert_eq!(r.free(), 0);
        assert_eq!(r.write(&[7u8; 1]).0, 0, "full");
        let mut b = [0u8; 4];
        assert_eq!(r.read(&mut b).0, 4);
        assert_eq!(r.free(), 4);
        assert_eq!(r.write(&[8u8; 9]).0, 4);
    }

    #[test]
    fn stream_rings_only_a_side_that_announced_a_sleep() {
        use azos_rings::region::RingStep;
        let (_m, r) = stream(16);
        assert!(matches!(r.write(&[1]).1, RingStep::Done), "nobody asleep: no doorbell");
        let mut b = [0u8; 4];
        assert!(matches!(r.read(&mut b).1, RingStep::Done));
        r.announce_consumer();
        assert!(matches!(r.write(&[2]).1, RingStep::DoneWake { .. }), "a sleeper was announced");
        assert!(matches!(r.write(&[3]).1, RingStep::Done), "and the announcement was spent");
        // A reader frees room: that wakes an announced writer.
        let _ = r.write(&[0u8; 16]);
        r.announce_producer();
        assert!(matches!(r.read(&mut b).1, RingStep::DoneWake { .. }));
    }

    #[test]
    fn stream_survives_free_running_index_wrap() {
        // The indices are u32 byte counters: push the head past 2^32 worth of
        // bytes in small steps by pre-setting both near the limit.
        let (_m, r) = stream(16);
        let w = |off: usize, v: u32| unsafe { (*((r.base + off) as *const AtomicU32)).store(v, Ordering::Relaxed) };
        w(azos_rings::region::RING_HEAD, u32::MAX - 5);
        w(azos_rings::region::RING_TAIL, u32::MAX - 5);
        assert_eq!(r.write(&[9u8; 12]).0, 12, "crosses u32::MAX");
        let mut b = [0u8; 12];
        assert_eq!(r.read(&mut b).0, 12);
        assert_eq!(b, [9u8; 12]);
        assert_eq!(r.len(), 0);
    }
}
