// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! An SMP model of the x86_64 IPI shootdown against a lock waiter that has
//! interrupts masked (`arch/x86_64/src/tlb.rs`, the request and
//! its acks; `arch/api/src/spin.rs`, the lock's wait loop).
//!
//! Two host threads are two CPUs. CPU 0 holds a lock word and posts a
//! shootdown for CPU 1, then waits for the ack, as `tlb::remote` does with
//! the lock still held (MEMOBJS across `unmap_range`, text_poke's `LOCK`
//! across `sync_all`). CPU 1 waits for the same word in the real contended
//! half of the test-and-set lock (`spin::tas_slow32`) with interrupts
//! masked: no interrupt handler runs on it, so the only way its bit can
//! clear is the lock's wait loop serving it (`SpinWait::wait_service`, which
//! x86_64 implements with `tlb::serve_with`). CPU 0's wait is bounded here so
//! the deadlock is a failed assertion, not a hung test.
//!
//! Canary: `--features spin-service-canary` (the wait loop skips the
//! service): CPU 1 never acks and `a_masked_lock_waiter_acks_the_holders_shootdown`
//! fails on its first assertion.

#[cfg(test)]
mod tests {
    use crate::x86_paging::tlb::{self, LocalFlush};
    use azos_arch_api::spin::tas_slow32;
    use azos_arch_api::SpinWait;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// The request words are the module's statics: one test at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    const ROOT: usize = 0x1234_5000;
    const VA: usize = 0x7f00_0000_3000;

    /// A CPU with interrupts masked: it never takes the shootdown vector; its
    /// lock wait serves the request through the same `serve_with` the vector's
    /// handler runs, recording the flush instead of executing it.
    struct MaskedCpu {
        cpu: usize,
        flushes: Arc<Mutex<Vec<LocalFlush>>>,
    }

    impl SpinWait for MaskedCpu {
        fn wait_service(&self) {
            let flushes = &self.flushes;
            tlb::serve_with(self.cpu, |f| flushes.lock().unwrap().push(f));
        }
    }

    /// CPU 0's wait for every ack, bounded: true when the mask cleared.
    fn acked_within(d: Duration) -> bool {
        let t = Instant::now();
        while tlb::pending() != 0 {
            if t.elapsed() > d {
                return false;
            }
            std::hint::spin_loop();
        }
        true
    }

    /// The deadlock the wait service exists for: the holder's shootdown is
    /// answered by a CPU that is spinning, interrupts masked, for the lock the
    /// holder keeps until the answer comes; then the waiter gets the lock.
    #[test]
    fn a_masked_lock_waiter_acks_the_holders_shootdown() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let word = Arc::new(AtomicU32::new(1)); // held by CPU 0
        let in_wait = Arc::new(AtomicUsize::new(0));
        let flushes = Arc::new(Mutex::new(Vec::new()));
        let waiter = {
            let (word, in_wait, flushes) = (word.clone(), in_wait.clone(), flushes.clone());
            std::thread::spawn(move || {
                in_wait.store(1, Ordering::Release);
                tas_slow32(&MaskedCpu { cpu: 1, flushes }, &word);
                in_wait.store(2, Ordering::Release);
            })
        };
        while in_wait.load(Ordering::Acquire) == 0 {
            std::hint::spin_loop();
        }
        // Past the relaxed polls, into the waits that serve.
        std::thread::sleep(Duration::from_millis(20));
        tlb::post(1 << 1, ROOT, VA, 4096);
        let acked = acked_within(Duration::from_secs(5));
        // The lock goes back either way, so a red run does not leave a
        // spinning thread behind; the verdict is taken after.
        word.store(0, Ordering::Release);
        waiter.join().unwrap();
        if !acked {
            // Clear the request the waiter never served, for the next test.
            tlb::serve_with(1, |_| ());
        }
        assert!(acked, "the masked lock waiter never acked the holder's shootdown: deadlock");
        assert_eq!(in_wait.load(Ordering::Acquire), 2, "the waiter took the lock once it was released");
        assert_eq!(word.load(Ordering::Acquire), 1, "the waiter holds the word");
        assert_eq!(*flushes.lock().unwrap(), vec![LocalFlush::Pages { start: VA, pages: 1 }],
            "one flush, of the page the request named");
    }

    /// A waiter acks its own bit only, once, and for the flush the request
    /// needs: the bit of a CPU that has not flushed stays set, and a second
    /// poll of a served request is a no-op (what the vector's handler, taken
    /// later on the same CPU, finds).
    #[test]
    fn a_waiter_acks_only_its_own_bit_once() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut seen = Vec::new();
        tlb::post(1 << 1 | 1 << 2, ROOT, VA, 2 * 4096);
        assert_eq!(tlb::serve_with(3, |f| seen.push(f)), None, "CPU 3 was not asked");
        assert_eq!(tlb::serve_with(1, |f| seen.push(f)), Some(LocalFlush::Pages { start: VA, pages: 2 }));
        assert_eq!(tlb::pending(), 1 << 2, "CPU 2 has not flushed yet");
        assert_eq!(tlb::serve_with(1, |f| seen.push(f)), None, "served once");
        assert_eq!(tlb::serve_with(2, |f| seen.push(f)), Some(LocalFlush::Pages { start: VA, pages: 2 }));
        assert_eq!(tlb::pending(), 0);
        assert_eq!(seen.len(), 2);
    }

    /// `icache_sync_all`'s empty request asks for no flush (the IPI path's
    /// serialization is its `iretq`): a waiter that serves it is told so by the
    /// empty page run, and must serialize itself.
    #[test]
    fn the_empty_request_is_an_empty_page_run() {
        let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        tlb::post(1 << 1, usize::MAX, 0, 0);
        assert_eq!(tlb::serve_with(1, |_| ()), Some(LocalFlush::Pages { start: 0, pages: 0 }));
        assert_eq!(tlb::pending(), 0);
    }
}
