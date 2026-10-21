// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_bytepipe`: the four things POSIX asks of a pipe (end
//! of file on the last writer's close, EPIPE with no reader, `O_NONBLOCK`,
//! `PIPE_BUF` atomic writes) over the byte ring, the end-count protocol (a
//! model of what the kernel does for a `Cap<Shm>`: a fork's child shares the
//! mapping and the kernel counts its ends in the fork), and the recovery of a
//! lock word a dying process owned.
//!
//! The doorbell is a model of the kernel futex: a wait compares the word under
//! the lock a wake takes. Each canary feature of the crate breaks one point
//! on purpose, and the test named for it must go red. The kernel's own side
//! (the holder record, the hooks) is tested where it lives, in
//! `tests/host/ipc-tests/tests/pipe_ends.rs`.

#[cfg(test)]
mod tests {
    use azos_bytepipe::{BytePipe, End, PipeError, Slept, Sys, PIPE_BUF};

    /// The ring of most tests: the smallest one allowed (`PIPE_BUF` bytes).
    const DEFAULT_CAP: u32 = 4096;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;
    use std::time::Duration;

    /// A futex model shared by every "process" of a test.
    #[derive(Default)]
    struct Futex {
        m: Mutex<u64>,
        cv: Condvar,
        waits: AtomicU32,
        wakes: AtomicU32,
    }

    impl Sys for Futex {
        fn wait(&self, addr: usize, expected: u32) -> Slept {
            self.waits.fetch_add(1, Ordering::Relaxed);
            let g = self.m.lock().unwrap();
            // SAFETY: `addr` is a word of a live test region.
            let cur = unsafe { &*(addr as *const AtomicU32) }.load(Ordering::SeqCst);
            if cur != expected {
                return Slept::Again;
            }
            // The backstop of the real doorbell: a lost wake shows up as a
            // slow test, not a hang.
            let _ = self.cv.wait_timeout(g, Duration::from_millis(2000)).unwrap();
            Slept::Again
        }
        fn wake(&self, _addr: usize) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
            let _g = self.m.lock().unwrap();
            self.cv.notify_all();
        }
        fn me(&self) -> u32 {
            ME.with(|m| m.get())
        }
    }

    thread_local! {
        /// The process id the thread plays (the lock words record it).
        static ME: std::cell::Cell<u32> = const { std::cell::Cell::new(1) };
    }

    fn play(pid: u32) {
        ME.with(|m| m.set(pid));
    }

    // What the kernel does on a pipe region's header (`azos_ipc::memobj`'s pipe
    // section runs these same `Header` calls under its table lock); the model
    // wakes through the futex model where the kernel wakes through the futex.

    /// A hand-over counts an end for the receiver.
    fn add_end(p: &BytePipe, end: End) -> bool {
        p.header().add_end(end)
    }

    /// A holder's `MEMOBJ_END_DROP`, or its death.
    fn drop_end(p: &BytePipe, f: &Futex, end: End) {
        p.header().drop_end(end, |_| f.wake(0));
    }

    /// The death of the process `pid`: its locks are opened.
    fn recover(p: &BytePipe, f: &Futex, pid: u32) {
        p.header().recover_locks(pid, |_| f.wake(0));
    }

    /// A 64-byte-aligned region.
    struct Region {
        mem: Vec<u64>,
    }

    impl Region {
        fn new(cap: u32) -> Region {
            let words = BytePipe::region_bytes(cap).div_ceil(8) + 16;
            Region { mem: vec![0u64; words] }
        }
        fn base(&self) -> usize {
            (self.mem.as_ptr() as usize + 63) & !63
        }
        fn pipe(&self, cap: u32) -> BytePipe {
            // SAFETY: the region outlives the pipe in every test below.
            unsafe { BytePipe::init(self.base(), cap).unwrap() }
        }
    }

    /// A test that blocks for good (a canary broke a wake or the end of
    /// file) ends the whole run, red, instead of stalling it.
    struct Watchdog(Arc<std::sync::atomic::AtomicBool>);

    fn wd() -> Watchdog {
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d = done.clone();
        thread::spawn(move || {
            for _ in 0..300 {
                if d.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            eprintln!("watchdog: a test blocked for good");
            std::process::exit(101);
        });
        Watchdog(done)
    }

    impl Drop for Watchdog {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    /// Run `f` on a thread and fail, instead of hanging, if it does not finish
    /// in a few seconds (a canary that breaks a wake makes a call block for
    /// good; the test must go red, not stall the suite).
    fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(4)).expect("the call did not return")
    }

    fn read_in(p: BytePipe, f: &Arc<Futex>, n: usize, nonblock: bool) -> Result<usize, PipeError> {
        let f = f.clone();
        within(move || p.read(&*f, &mut vec![0u8; n], nonblock))
    }

    fn write_in(p: BytePipe, f: &Arc<Futex>, data: Vec<u8>, nonblock: bool) -> Result<usize, PipeError> {
        let f = f.clone();
        within(move || p.write(&*f, &data, nonblock))
    }

    fn mk(cap: u32) -> (Region, BytePipe, Arc<Futex>) {
        let r = Region::new(cap);
        let p = r.pipe(cap);
        (r, p, Arc::new(Futex::default()))
    }

    // ------------------------------------------------------------ basics

    #[test]
    fn bytes_come_out_in_order_across_the_wrap() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let mut out = vec![0u8; 4096];
        let mut next = 0u8;
        // Chunks of 1000 bytes: the ring wraps every few rounds.
        for round in 0..20u32 {
            let chunk: Vec<u8> = (0..1000u32).map(|i| (round * 7 + i) as u8).collect();
            assert_eq!(p.write(&*f, &chunk, false), Ok(1000));
            let n = p.read(&*f, &mut out[..600], false).unwrap();
            assert_eq!(n, 600);
            let m = p.read(&*f, &mut out[600..], false).unwrap();
            assert_eq!(m, 400, "the rest of the chunk and nothing else");
            assert_eq!(&out[..1000], &chunk[..]);
            next = next.wrapping_add(1);
        }
        let _ = next;
    }

    #[test]
    fn open_validates_the_header() {
        let _w = wd();
        let r = Region::new(DEFAULT_CAP);
        let _p = r.pipe(DEFAULT_CAP);
        let bytes = BytePipe::region_bytes(DEFAULT_CAP);
        // SAFETY: the region is live and big enough.
        unsafe {
            assert!(BytePipe::open(r.base(), bytes).is_some());
            assert!(BytePipe::open(r.base(), bytes - 1).is_none(), "a mapping shorter than the geometry");
            assert!(BytePipe::open(r.base() + 8, bytes).is_none(), "misaligned");
        }
        let z = Region::new(DEFAULT_CAP);
        // SAFETY: as above; a zeroed region is not a pipe.
        assert!(unsafe { BytePipe::open(z.base(), bytes) }.is_none());
        assert_eq!(BytePipe::cap_for(8192), Some(4096));
        assert_eq!(BytePipe::cap_for(256 + 65536), Some(65536));
        assert_eq!(BytePipe::cap_for(256 + 4095), None);
    }

    // ------------------------------------------------- point 1: EOF

    #[test]
    fn eof_when_the_last_writer_closes() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        assert!(add_end(&p, End::Write), "a second writer: a fork's child");
        assert_eq!(p.write(&*f, b"abc", false), Ok(3));
        drop_end(&p, &*f, End::Write);
        let mut b = [0u8; 8];
        assert_eq!(p.read(&*f, &mut b, false), Ok(3), "bytes first");
        assert_eq!(p.writers(), 1);
        assert_eq!(read_in(p, &f, 8, true), Err(PipeError::WouldBlock), "one writer left: not end of file");
        drop_end(&p, &*f, End::Write);
        assert_eq!(read_in(p, &f, 8, false), Ok(0), "end of file");
        assert_eq!(read_in(p, &f, 8, true), Ok(0), "and it stays so, blocking or not");
    }

    #[test]
    fn eof_comes_after_the_bytes_a_dying_writer_left() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        assert_eq!(p.write(&*f, b"last words", false), Ok(10));
        drop_end(&p, &*f, End::Write);
        let mut b = [0u8; 64];
        assert_eq!(p.read(&*f, &mut b, false), Ok(10));
        assert_eq!(read_in(p, &f, 64, false), Ok(0));
    }

    #[test]
    fn a_reader_asleep_is_woken_by_the_last_writer_closing() {
        let _w = wd();
        let (r, p, f) = mk(DEFAULT_CAP);
        let (p2, f2) = (p, f.clone());
        let reader = thread::spawn(move || {
            let mut b = [0u8; 16];
            p2.read(&*f2, &mut b, false)
        });
        // Let the reader reach its sleep (the model's backstop is 2 s: a
        // lost wake would make this test take that long and fail the bound).
        thread::sleep(Duration::from_millis(100));
        let t0 = std::time::Instant::now();
        drop_end(&p, &*f, End::Write);
        assert_eq!(reader.join().unwrap(), Ok(0));
        assert!(t0.elapsed() < Duration::from_millis(1500), "woken by the close, not by the backstop");
        drop(r);
    }

    // ------------------------------------------------- point 2: EPIPE

    #[test]
    fn write_with_no_reader_is_broken() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        drop_end(&p, &*f, End::Read);
        assert_eq!(write_in(p, &f, b"x".to_vec(), false), Err(PipeError::Broken));
        assert_eq!(write_in(p, &f, b"x".to_vec(), true), Err(PipeError::Broken), "non-blocking too");
        assert_eq!(p.write(&*f, b"", false), Ok(0), "a write of nothing is nothing");
        assert_eq!(p.len(), 0, "nothing was stored");
    }

    #[test]
    fn a_writer_asleep_on_a_full_pipe_is_woken_by_the_last_reader_closing() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        assert_eq!(p.write(&*f, &vec![1u8; DEFAULT_CAP as usize], false), Ok(DEFAULT_CAP as usize));
        let (p2, f2) = (p, f.clone());
        let writer = thread::spawn(move || p2.write(&*f2, &[2u8; 100], false));
        thread::sleep(Duration::from_millis(100));
        let t0 = std::time::Instant::now();
        drop_end(&p, &*f, End::Read);
        assert_eq!(writer.join().unwrap(), Err(PipeError::Broken));
        assert!(t0.elapsed() < Duration::from_millis(1500));
    }

    #[test]
    fn a_large_write_that_loses_its_reader_reports_what_it_wrote() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let big = vec![7u8; DEFAULT_CAP as usize * 2];
        let (p2, f2) = (p, f.clone());
        let w = thread::spawn(move || p2.write(&*f2, &big, false));
        thread::sleep(Duration::from_millis(100));
        // The first half is in; nobody will ever read the second.
        drop_end(&p, &*f, End::Read);
        assert_eq!(w.join().unwrap(), Ok(DEFAULT_CAP as usize), "the bytes stored, then the break on the next call");
        assert_eq!(p.write(&*f, b"x", false), Err(PipeError::Broken));
    }

    // ------------------------------------------------- point 3: O_NONBLOCK

    #[test]
    fn nonblocking_read_of_an_empty_pipe_would_block() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        assert_eq!(read_in(p, &f, 4, true), Err(PipeError::WouldBlock));
        assert_eq!(f.waits.load(Ordering::Relaxed), 0, "and it did not sleep");
        p.write(&*f, b"hi", false).unwrap();
        assert_eq!(read_in(p, &f, 4, true), Ok(2));
    }

    #[test]
    fn nonblocking_write_to_a_full_pipe_writes_what_fits() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let cap = DEFAULT_CAP as usize;
        assert_eq!(p.write(&*f, &vec![0u8; cap - 10], true), Ok(cap - 10));
        // Larger than PIPE_BUF: partial, the count of what fitted.
        assert_eq!(write_in(p, &f, vec![1u8; cap * 2], true), Ok(10));
        assert_eq!(write_in(p, &f, vec![2u8; 1], true), Err(PipeError::WouldBlock));
        assert_eq!(f.waits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn nonblocking_atomic_write_that_does_not_fit_writes_nothing() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let cap = DEFAULT_CAP as usize;
        assert_eq!(p.write(&*f, &vec![0u8; cap - 10], true), Ok(cap - 10));
        assert_eq!(write_in(p, &f, vec![9u8; 100], true), Err(PipeError::WouldBlock), "100 <= PIPE_BUF: whole or nothing");
        assert_eq!(p.len() as usize, cap - 10, "nothing of it was stored");
    }

    // ------------------------------------------------- point 4: PIPE_BUF

    #[test]
    fn atomic_writes_are_never_split_around_another_writers_bytes() {
        let _w = wd();
        // Two writers, records of 3000 bytes (<= PIPE_BUF), a ring that holds
        // one record and a bit: every record has to wait for the reader, so
        // the room appears in pieces a splitting write would use.
        let cap = DEFAULT_CAP;
        let (r, p, f) = mk(cap);
        const REC: usize = 3000;
        const N: usize = 40;
        let mut writers = Vec::new();
        for tag in [0xA1u8, 0xB2u8] {
            assert!(add_end(&p, End::Write));
            let (pw, fw) = (p, f.clone());
            writers.push(thread::spawn(move || {
                for _ in 0..N {
                    assert_eq!(pw.write(&*fw, &[tag; REC], false), Ok(REC));
                }
                drop_end(&pw, &*fw, End::Write);
            }));
        }
        drop_end(&p, &*f, End::Write); // the creator's own writer end
        let mut got = Vec::new();
        let mut buf = vec![0u8; 700];
        loop {
            match p.read(&*f, &mut buf, false) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => panic!("{e:?}"),
            }
        }
        for w in writers {
            w.join().unwrap();
        }
        assert_eq!(got.len(), 2 * N * REC);
        for (i, rec) in got.chunks(REC).enumerate() {
            assert!(rec.iter().all(|&b| b == rec[0]), "record {i} mixes two writers");
        }
        drop(r);
    }

    #[test]
    fn a_blocked_atomic_write_stores_nothing_while_it_waits_for_room() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let cap = DEFAULT_CAP as usize;
        p.write(&*f, &vec![0u8; cap - 1000], false).unwrap();
        let (p2, f2) = (p, f.clone());
        let a = thread::spawn(move || p2.write(&*f2, &[0xAAu8; 3000], false));
        thread::sleep(Duration::from_millis(100));
        assert_eq!(p.len() as usize, cap - 1000, "1000 bytes of room, 3000 wanted: none of them used yet");
        // Another writer's bytes land first, whole; then the room appears and
        // the big record follows whole.
        assert_eq!(p.write(&*f, &[0xBBu8; 100], false), Ok(100));
        let mut sink = vec![0u8; cap - 1000];
        assert_eq!(p.read(&*f, &mut sink, false), Ok(cap - 1000));
        assert_eq!(a.join().unwrap(), Ok(3000));
        let mut rest = vec![0u8; 4000];
        let mut got = 0;
        while got < 3100 {
            got += p.read(&*f, &mut rest[got..], false).unwrap();
        }
        assert!(rest[..100].iter().all(|&b| b == 0xBB));
        assert!(rest[100..3100].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn a_write_larger_than_the_ring_completes_through_a_draining_reader() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let big: Vec<u8> = (0..100_000u32).map(|i| (i * 31) as u8).collect();
        let (p2, f2, b2) = (p, f.clone(), big.clone());
        let w = thread::spawn(move || {
            let n = p2.write(&*f2, &b2, false);
            drop_end(&p2, &*f2, End::Write);
            n
        });
        let mut got = Vec::new();
        let mut buf = vec![0u8; 1500];
        while let Ok(n) = p.read(&*f, &mut buf, false) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(w.join().unwrap(), Ok(big.len()));
        assert_eq!(got, big);
    }

    #[test]
    fn pipe_buf_is_what_the_old_kernel_pipe_promised() {
        let _w = wd();
        assert_eq!(PIPE_BUF, 4096);
        assert!(BytePipe::cap_for(256 + PIPE_BUF).is_some());
    }

    // ------------------------------------------------- the doorbell

    #[test]
    fn no_kernel_entry_while_the_ring_is_neither_empty_nor_full() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let mut b = [0u8; 64];
        for _ in 0..100 {
            p.write(&*f, &[5u8; 64], false).unwrap();
            p.read(&*f, &mut b, false).unwrap();
        }
        assert_eq!(f.waits.load(Ordering::Relaxed), 0);
        assert_eq!(f.wakes.load(Ordering::Relaxed), 0, "nobody announced a sleep: no doorbell");
    }

    #[test]
    fn a_reader_asleep_is_woken_by_a_write() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let (p2, f2) = (p, f.clone());
        let reader = thread::spawn(move || {
            let mut b = [0u8; 16];
            let n = p2.read(&*f2, &mut b, false).unwrap();
            b[..n].to_vec()
        });
        thread::sleep(Duration::from_millis(100));
        let t0 = std::time::Instant::now();
        p.write(&*f, b"wake up", false).unwrap();
        assert_eq!(reader.join().unwrap(), b"wake up");
        assert!(t0.elapsed() < Duration::from_millis(1500));
        assert!(f.wakes.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn many_round_trips_between_two_threads_lose_no_wakeup() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let (p2, f2) = (p, f.clone());
        let t0 = std::time::Instant::now();
        let prod = thread::spawn(move || {
            for i in 0..20_000u32 {
                p2.write(&*f2, &i.to_le_bytes(), false).unwrap();
            }
            drop_end(&p2, &*f2, End::Write);
        });
        let mut next = 0u32;
        let mut buf = [0u8; 4];
        let mut have = 0usize;
        loop {
            match p.read(&*f, &mut buf[have..], false) {
                Ok(0) => break,
                Ok(n) => {
                    have += n;
                    if have == 4 {
                        assert_eq!(u32::from_le_bytes(buf), next);
                        next += 1;
                        have = 0;
                    }
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        prod.join().unwrap();
        assert_eq!(next, 20_000);
        assert!(t0.elapsed() < Duration::from_secs(20), "a lost wake costs the 2 s backstop each time");
    }

    // ------------------------------------------------- fork (the model)

    /// What a process holds of one pipe: its description of each end (a
    /// count of the dup'd fds that name it) and the mapping, which is the
    /// *same* memory in every process (the fork rule: shared, not
    /// copy-on-write).
    #[derive(Clone)]
    struct Proc {
        pipe: BytePipe,
        read_fds: u32,
        write_fds: u32,
    }

    impl Proc {
        /// The kernel's fork: it counts the child's ends in the step that gives
        /// it the region, and counts nothing if the fork fails.
        fn fork(&self, fails: bool, f: &Futex) -> Option<Proc> {
            let r = self.read_fds > 0 && add_end(&self.pipe, End::Read);
            let w = self.write_fds > 0 && add_end(&self.pipe, End::Write);
            if fails {
                if r {
                    drop_end(&self.pipe, f, End::Read);
                }
                if w {
                    drop_end(&self.pipe, f, End::Write);
                }
                return None;
            }
            Some(self.clone())
        }
        fn close_write(&mut self, f: &Futex) {
            self.write_fds -= 1;
            if self.write_fds == 0 {
                drop_end(&self.pipe, f, End::Write);
            }
        }
        fn close_read(&mut self, f: &Futex) {
            self.read_fds -= 1;
            if self.read_fds == 0 {
                drop_end(&self.pipe, f, End::Read);
            }
        }
    }

    #[test]
    fn fork_child_shares_the_ring_and_both_processes_hold_the_ends() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let mut parent = Proc { pipe: p, read_fds: 1, write_fds: 1 };
        let mut child = parent.fork(false, &f).unwrap();
        assert_eq!((p.readers(), p.writers()), (2, 2));
        // The child writes; the parent reads it: one memory, not two copies.
        child.pipe.write(&*f, b"from the child", false).unwrap();
        let mut b = [0u8; 32];
        assert_eq!(parent.pipe.read(&*f, &mut b, false), Ok(14));
        assert_eq!(&b[..14], b"from the child");
        // The classic shape: the parent reads, so it closes its write end;
        // the child writes, so it closes its read end.
        parent.close_write(&f);
        child.close_read(&f);
        assert_eq!((p.readers(), p.writers()), (1, 1));
        child.pipe.write(&*f, b"bye", false).unwrap();
        child.close_write(&f); // the child exits
        assert_eq!(parent.pipe.read(&*f, &mut b, false), Ok(3));
        assert_eq!(read_in(parent.pipe, &f, 32, false), Ok(0), "end of file only after the child's end closed");
        parent.close_read(&f);
        assert_eq!((p.readers(), p.writers()), (0, 0));
    }

    /// The two kinds of page a fork meets, as a model of the kernel rule
    /// (`natfork::inherit_shm`, `cow::fork_share_range`): private memory is
    /// copy-on-write (the child's later stores are its own), a `Cap<Shm>`
    /// mapping the parent holds is the same frames in both.
    struct Space {
        private: Vec<u8>,
        shared: Option<BytePipe>,
    }

    impl Space {
        fn fork(&self) -> Space {
            Space { private: self.private.clone(), shared: self.shared }
        }
    }

    #[test]
    fn fork_copies_private_memory_and_shares_the_pipe_region() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let parent = Space { private: vec![1, 2, 3], shared: Some(p) };
        let mut child = parent.fork();
        child.private[0] = 99;
        assert_eq!(parent.private[0], 1, "private pages are copy-on-write: the child's store is its own");
        child.shared.unwrap().write(&*f, b"through the ring", false).unwrap();
        assert_eq!(parent.shared.unwrap().len(), 16, "the region is the same frames: the parent sees the bytes");
        // A region the parent has not mapped is not inherited (nothing to share).
        let loner = Space { private: vec![], shared: None };
        assert!(loner.fork().shared.is_none());
    }

    #[test]
    fn a_parent_that_closes_first_does_not_end_the_childs_pipe() {
        let _w = wd();
        // The ends are counted BEFORE the fork returns: the parent may close
        // its own the instant after, and the count never reads zero.
        let (_r, p, f) = mk(DEFAULT_CAP);
        let mut parent = Proc { pipe: p, read_fds: 1, write_fds: 1 };
        let child = parent.fork(false, &f).unwrap();
        parent.close_write(&f);
        parent.close_read(&f);
        assert_eq!((p.readers(), p.writers()), (1, 1), "the child's ends are alive");
        assert_eq!(child.pipe.write(&*f, b"still open", false), Ok(10));
    }

    #[test]
    fn a_failed_fork_gives_the_counts_back() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let parent = Proc { pipe: p, read_fds: 1, write_fds: 1 };
        assert!(parent.fork(true, &f).is_none());
        assert_eq!((p.readers(), p.writers()), (1, 1), "nothing is left counted for a child that never ran");
    }

    #[test]
    fn an_end_the_process_does_not_hold_is_not_counted_for_the_child() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        // A process that holds only the read end (it closed the write end).
        let mut parent = Proc { pipe: p, read_fds: 1, write_fds: 1 };
        parent.close_write(&f);
        let child = parent.fork(false, &f).unwrap();
        assert_eq!((p.readers(), p.writers()), (2, 0));
        let _ = child;
    }

    #[test]
    fn dup_names_one_end_and_only_the_last_close_counts() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        let mut me = Proc { pipe: p, read_fds: 1, write_fds: 2 }; // `2>&1` onto the pipe
        me.close_write(&f);
        assert_eq!(p.writers(), 1, "one fd still names the end");
        assert_eq!(read_in(p, &f, 4, true), Err(PipeError::WouldBlock));
        me.close_write(&f);
        assert_eq!(read_in(p, &f, 4, true), Ok(0));
    }

    #[test]
    fn a_double_close_cannot_wrap_the_count() {
        let _w = wd();
        let (_r, p, f) = mk(DEFAULT_CAP);
        drop_end(&p, &*f, End::Write);
        drop_end(&p, &*f, End::Write); // a holder bug
        assert_eq!(p.writers(), 0);
        assert!(add_end(&p, End::Write), "and the count is still usable");
        assert_eq!(p.writers(), 1);
    }

    // ------------------------------------------------- the owner of a lock

    // The two lock words sit at these header offsets (`H_WLOCK`, `H_RLOCK`);
    // a test that plays a process dead inside the lock writes one directly.
    const WLOCK: usize = 32;
    const RLOCK: usize = 36;

    fn lock_word(r: &Region, off: usize) -> &AtomicU32 {
        // SAFETY: a word of the live test region.
        unsafe { &*((r.base() + off) as *const AtomicU32) }
    }

    /// A lock word as the owner `pid` leaves it: locked, owner above the flags.
    fn held_by(pid: u32) -> u32 {
        (pid << 2) | 1
    }

    #[test]
    fn a_writer_killed_inside_the_lock_does_not_stall_the_others() {
        let _w = wd();
        let (r, p, f) = mk(DEFAULT_CAP);
        // Process 7 died holding the writer lock.
        lock_word(&r, WLOCK).store(held_by(7), Ordering::SeqCst);
        let (p2, f2) = (p, f.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            play(8);
            let _ = tx.send(p2.write(&*f2, b"after the death", false));
        });
        thread::sleep(Duration::from_millis(100));
        assert_eq!(p.len(), 0, "the lock is held by a dead owner: the writer waits");
        // The kernel's death hook opens what 7 owned.
        recover(&p, &f, 7);
        let wrote = rx.recv_timeout(Duration::from_secs(4)).expect("the writer got the lock back");
        assert_eq!(wrote, Ok(15));
        assert_eq!(lock_word(&r, WLOCK).load(Ordering::SeqCst), 0, "and the writer left it open");
    }

    #[test]
    fn a_reader_killed_inside_the_lock_does_not_stall_the_others() {
        let _w = wd();
        let (r, p, f) = mk(DEFAULT_CAP);
        p.write(&*f, b"kept", false).unwrap();
        lock_word(&r, RLOCK).store(held_by(7), Ordering::SeqCst);
        let (p2, f2) = (p, f.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            play(8);
            let mut b = [0u8; 8];
            let _ = tx.send(p2.read(&*f2, &mut b, false).map(|n| b[..n].to_vec()));
        });
        thread::sleep(Duration::from_millis(100));
        assert_eq!(p.len(), 4, "nothing was read past the dead owner's lock");
        recover(&p, &f, 7);
        let read = rx.recv_timeout(Duration::from_secs(4)).expect("the reader got the lock back");
        assert_eq!(read, Ok(b"kept".to_vec()));
    }

    #[test]
    fn recovery_opens_only_the_locks_the_dead_process_owned() {
        let _w = wd();
        let (r, p, f) = mk(DEFAULT_CAP);
        lock_word(&r, WLOCK).store(held_by(9), Ordering::SeqCst);
        lock_word(&r, RLOCK).store(held_by(7) | 2, Ordering::SeqCst); // with sleepers
        recover(&p, &f, 8);
        assert_eq!(lock_word(&r, WLOCK).load(Ordering::SeqCst), held_by(9), "another process's lock stays");
        recover(&p, &f, 0);
        assert_eq!(lock_word(&r, RLOCK).load(Ordering::SeqCst), held_by(7) | 2, "owner 0 names nobody");
        let wakes = f.wakes.load(Ordering::Relaxed);
        recover(&p, &f, 7);
        assert_eq!(lock_word(&r, RLOCK).load(Ordering::SeqCst), 0);
        assert_eq!(f.wakes.load(Ordering::Relaxed), wakes + 1, "and its sleepers were woken");
        assert_eq!(lock_word(&r, WLOCK).load(Ordering::SeqCst), held_by(9));
    }

    #[test]
    fn a_lock_records_the_process_that_holds_it() {
        let _w = wd();
        let (r, p, f) = mk(DEFAULT_CAP);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (p2, f2, stop2) = (p, f.clone(), stop.clone());
        // Process 7 writes and reads without pause; the lock words are held
        // for a few instructions each time.
        let worker = thread::spawn(move || {
            play(7);
            let mut b = [0u8; 8];
            while !stop2.load(Ordering::Relaxed) {
                p2.write(&*f2, &[1u8; 8], false).unwrap();
                p2.read(&*f2, &mut b, false).unwrap();
            }
        });
        let (mut seen, mut wrong) = (0u32, 0u32);
        let t0 = std::time::Instant::now();
        while seen < 20 && t0.elapsed() < Duration::from_secs(3) {
            for off in [WLOCK, RLOCK] {
                let v = lock_word(&r, off).load(Ordering::SeqCst);
                if v & 1 != 0 {
                    seen += 1;
                    if v >> 2 != 7 {
                        wrong += 1;
                    }
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        assert!(seen > 0, "the sampler never saw a lock held");
        assert_eq!(wrong, 0, "a held lock names its owner");
        // Nothing of a finished process is left to recover.
        recover(&p, &f, 7);
        assert_eq!(lock_word(&r, WLOCK).load(Ordering::SeqCst), 0);
        assert_eq!(lock_word(&r, RLOCK).load(Ordering::SeqCst), 0);
    }

    // ------------------------------------------------- the header the kernel reads

    #[test]
    fn the_kernels_view_needs_the_magic_and_alignment() {
        let _w = wd();
        let (r, p, _f) = mk(DEFAULT_CAP);
        // SAFETY: the region is live; a zeroed one is not a pipe.
        unsafe {
            assert!(azos_bytepipe::Header::at(r.base()).is_some());
            assert!(azos_bytepipe::Header::at(r.base() + 8).is_none(), "misaligned");
            let z = Region::new(DEFAULT_CAP);
            assert!(azos_bytepipe::Header::at(z.base()).is_none(), "no magic: no pipe");
        }
        assert_eq!(p.header().readers(), 1);
        assert_eq!(p.header().writers(), 1);
    }

    #[test]
    fn dropping_the_last_end_wakes_once_and_never_below_zero() {
        let _w = wd();
        let (_r, p, _f) = mk(DEFAULT_CAP);
        let mut rung = 0;
        p.header().drop_end(End::Write, |_| rung += 1);
        p.header().drop_end(End::Write, |_| rung += 1); // a holder bug
        assert_eq!(rung, 1, "only the drop that reached zero rings");
        assert_eq!(p.writers(), 0);
        let mut again = 0;
        assert!(p.header().add_end(End::Read));
        p.header().drop_end(End::Read, |_| again += 1);
        assert_eq!(again, 0, "a second reader remained: not the last");
    }

    // ---- a region the kernel reaches one frame at a time -------------------

    #[repr(align(4096))]
    struct Page([u8; 4096]);

    /// Five separate pages, in descending address order so that no flat view
    /// from the first one reaches the others: the shape of a ring-3 region
    /// (one frame per page) in the kernel's direct map.
    fn frames() -> (Vec<Box<Page>>, Vec<usize>) {
        let mut pages: Vec<Box<Page>> = (0..5).map(|_| Box::new(Page([0; 4096]))).collect();
        pages.sort_by_key(|p| core::cmp::Reverse(p.0.as_ptr() as usize));
        let addrs = pages.iter().map(|p| p.0.as_ptr() as usize).collect();
        (pages, addrs)
    }

    /// The kernel's view of a pipe whose pages are not one run
    /// (`open_scattered`) moves the bytes where the ring-3 view of the same
    /// region would, across the page edges and the wrap of the ring.
    ///
    /// **Canary.** In `Scatter::put` or `get` (azos_rings) address the frame
    /// as `frames[0] + off` (a flat view): the bytes land outside the pages
    /// and the frame checks fail.
    #[test]
    fn a_scattered_region_carries_the_bytes_where_a_flat_one_would() {
        use azos_bytepipe::Scatter;
        let (_keep, addrs) = frames();
        let cap = BytePipe::cap_for(5 * 4096).unwrap();
        assert_eq!(cap, 16384);
        // SAFETY: the first page, 4096 bytes, nobody else holds it; `init`
        // writes the header only.
        unsafe { BytePipe::init(addrs[0], cap) }.unwrap();
        let sc = Scatter::new(4096, &addrs).unwrap();
        // SAFETY: five live pages of one region.
        let p = unsafe { BytePipe::open_scattered(sc) }.expect("the header names a pipe");
        let f = Futex::default();
        let pattern = |seed: usize, n: usize| (0..n).map(|i| (seed + i * 7) as u8).collect::<Vec<u8>>();
        let mut at = 0usize; // bytes written so far = the stream position
        for round in 0..3 {
            let src = pattern(round * 31, 12000);
            assert_eq!(p.write(&f, &src, true), Ok(12000));
            // The stream byte `at + i` is at region offset 256 + ((at + i) % cap).
            for i in [0usize, 3839, 3840, 8000, 11999] {
                let off = 256 + (at + i) % cap as usize;
                assert_eq!(_keep[off / 4096].0[off % 4096], src[i]);
            }
            let mut out = vec![0u8; 12000];
            assert_eq!(p.read(&f, &mut out, true), Ok(12000));
            assert_eq!(out, src, "round {round}: bytes in = bytes out across frames and the wrap");
            at += 12000;
        }
    }

    /// A region that is no pipe, or that is shorter than the geometry its
    /// header states, is refused by the scattered view as the flat one does.
    #[test]
    fn a_scattered_view_refuses_what_a_flat_one_refuses() {
        use azos_bytepipe::Scatter;
        let (_keep, addrs) = frames();
        let sc = Scatter::new(4096, &addrs).unwrap();
        // SAFETY: five live pages of one region (all zero: no magic).
        assert!(unsafe { BytePipe::open_scattered(sc) }.is_none(), "no magic, no pipe");
        let cap = BytePipe::cap_for(5 * 4096).unwrap();
        // SAFETY: the header page only.
        unsafe { BytePipe::init(addrs[0], cap) }.unwrap();
        let short = Scatter::new(4096, &addrs[..2]).unwrap();
        // SAFETY: two live pages.
        assert!(unsafe { BytePipe::open_scattered(short) }.is_none(), "the geometry needs more pages");
        assert!(Scatter::new(4096, &[]).is_none() && Scatter::new(4000, &addrs).is_none());
    }
}
