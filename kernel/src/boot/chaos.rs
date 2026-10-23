// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fault injection (Kconfig CHAOS) and decision records (Kconfig
//! DECISION_RECORDS_DEV): the kernel's side, which reads the command line, arms
//! the gate canaries of both, makes the command line's points live at the
//! end of boot init, and holds their ktests.
//!
//! Off (both features absent): [`arm_from_cmdline`] and [`go_live`] are
//! empty and nothing here is linked.

#[cfg(feature = "chaos")]
use azos_drv_sys::kprintln;

#[cfg(all(feature = "chaos", feature = "secure-boot-enforced"))]
compile_error!("Kconfig CHAOS must not reach a signed image: a command line would fail its allocations");
#[cfg(feature = "chaos")]
const _: () = assert!(
    azos_limits::BUILD_TYPE_DEV,
    "Kconfig CHAOS must not reach a release or certifiable build (BUILD_TYPE): drop the `chaos` feature"
);

/// Read `chaos=` / `chaos_seed=` (held until [`go_live`]) and arm the
/// runtime canaries of both subsystems. `early_main`, after the canaries
/// themselves are armed; `read` is the ISA's `ArchEntry::kernel_cmdline`.
pub(crate) fn arm_from_cmdline(read: impl FnOnce(&mut [u8]) -> Option<usize>) {
    #[cfg(feature = "chaos")]
    {
        if canary!("chaos-inert") {
            azos_chaos::set_inert();
        }
        if canary!("chaos-leak") {
            azos_chaos::set_leak_canary();
        }
        let mut line = [0u8; azos_limits::KERNEL_CMDLINE_MAX as usize];
        if let Some(n) = read(&mut line) {
            use azos_chaos::CmdlineIssue;
            let n = n.min(line.len());
            let armed = azos_chaos::parse_cmdline(&line[..n], |i| match i {
                CmdlineIssue::Malformed(w) => azos_drv_sys::kwarn!(
                    "[CHAOS] {} ignored: not <point>:<rate>[:<times>] (points: {:?})",
                    core::str::from_utf8(w).unwrap_or("?"), azos_chaos::NAMES),
                CmdlineIssue::HeapRefused => azos_drv_sys::kwarn!(
                    "[CHAOS] heap-alloc refused from the command line: the kernel's heap allocations are infallible"),
                CmdlineIssue::BadSeed(w) => azos_drv_sys::kwarn!(
                    "[CHAOS] chaos_seed={} ignored: not a decimal number", core::str::from_utf8(w).unwrap_or("?")),
            });
            if armed != 0 {
                azos_drv_sys::kwarn!("[CHAOS] {} point(s) armed from the command line, live after boot init (seed {})",
                    armed, azos_chaos::seed());
            }
        }
    }
    #[cfg(not(feature = "chaos"))]
    let _ = read;
    #[cfg(feature = "decisions")]
    if canary!("decision-skip") {
        azos_decision::set_skip();
    }
}

/// Boot init is done: the command line's points fire from here on.
pub(crate) fn go_live() {
    #[cfg(feature = "chaos")]
    for p in azos_chaos::POINTS {
        let r = azos_chaos::pending(p);
        match azos_chaos::pending_times(p) {
            _ if r == 0 => {}
            0 => kprintln!("[CHAOS] live: {} fails 1 call in {}", p.name(), r),
            t => kprintln!("[CHAOS] live: {} fails 1 call in {}, {} time(s) at most", p.name(), r, t),
        }
    }
    #[cfg(feature = "chaos")]
    azos_chaos::go_live();
}

// Kconfig KTEST + CHAOS: each injected fault is refused the way the real one
// is, leaves nothing behind, and is counted. Canaries: `canary=chaos-inert`
// (nothing arms: every test below but the parser's reports `not ok`) and
// `canary=chaos-leak` (an injected frame failure loses a frame:
// `chaos_frame_alloc_no_leak`).
#[cfg(all(feature = "ktest", feature = "chaos"))]
mod chaos_ktests {
    use azos_chaos::{arm, disarm, fired, stats, Point};

    /// Arm `p` for `f`, then put back the arming it had (a command-line
    /// rate stays armed for the rest of the boot).
    fn armed<T>(p: Point, rate: u32, skip: u32, f: impl FnOnce() -> T) -> T {
        let prev = stats(p).0;
        arm(p, rate, skip);
        let r = f();
        if prev != 0 { arm(p, prev, 0) } else { disarm(p) }
        r
    }

    azos_ktest::ktest! {
        fn chaos_cmdline_parsed() {
            let seed = azos_chaos::seed();
            let keep: [(u32, u32); azos_chaos::N] = core::array::from_fn(|i| {
                let p = azos_chaos::POINTS[i];
                (azos_chaos::pending(p), azos_chaos::pending_times(p))
            });
            // From nothing armed: a soak boot's own chaos= (spurious-irq:4)
            // would otherwise read as what this line set.
            for p in azos_chaos::POINTS {
                azos_chaos::set_pending(p, 0, 0);
            }
            let (mut bad, mut heap, mut bad_seed) = (0, 0, 0);
            let n = azos_chaos::parse_cmdline(
                b"x=1 chaos=ipc-send:3,heap-alloc:2,nope:1,disk-io:x,timer-wake:0,xhci-command-drop:1:2,spurious-irq:1:0 chaos_seed=42",
                |i| match i {
                    azos_chaos::CmdlineIssue::Malformed(_) => bad += 1,
                    azos_chaos::CmdlineIssue::HeapRefused => heap += 1,
                    azos_chaos::CmdlineIssue::BadSeed(_) => bad_seed += 1,
                });
            let got = (n, azos_chaos::pending(Point::IpcSend), azos_chaos::pending(Point::HeapAlloc), azos_chaos::seed());
            let capped = (azos_chaos::pending(Point::XhciCommandDrop), azos_chaos::pending_times(Point::XhciCommandDrop),
                azos_chaos::pending_times(Point::IpcSend), azos_chaos::pending(Point::SpuriousIrq));
            for (i, (r, t)) in keep.iter().enumerate() {
                azos_chaos::set_pending(azos_chaos::POINTS[i], *r, *t);
            }
            azos_chaos::set_seed(seed);
            if got != (2, 3, 0, 42) || capped != (1, 2, 0, 0) || (bad, heap, bad_seed) != (4, 1, 0) {
                return Err("chaos= parsed to the wrong points, rates, caps or seed");
            }
            Ok(())
        }
    }

    azos_ktest::ktest! {
        fn chaos_frame_alloc_no_leak() {
            use azos_mm::{pmm, vmm};
            const PAGES: usize = 4;
            let stride = vmm::MEGA_SIZE;
            let mut completed = false;
            // Fail the first, second, ... frame of the sequence in turn, until
            // the sequence completes without a failure (every step was hit).
            for skip in 0..(4 * PAGES as u32 + 8) {
                let free0 = pmm::free_pages();
                let f0 = fired(Point::FrameAlloc);
                let ok = armed(Point::FrameAlloc, 1, skip, || {
                    let Ok(pt) = vmm::create_pagetable() else { return false };
                    let mut all = true;
                    for k in 0..PAGES {
                        let Ok(f) = pmm::alloc_page() else { all = false; break };
                        if vmm::map(pt, 0x4000_0000 + k * stride, f.as_usize(), azos_arch_api::PagePerms::USER_RW).is_err() {
                            let _ = pmm::free_page(f);
                            all = false;
                            break;
                        }
                    }
                    vmm::destroy_user_pagetable(pt);
                    all
                });
                let hit = fired(Point::FrameAlloc) != f0;
                if skip == 0 && (!hit || ok) {
                    return Err("an armed frame-alloc point did not fail the first allocation");
                }
                if pmm::free_pages() != free0 {
                    return Err("a frame leaked on an injected allocation failure");
                }
                if !hit {
                    completed = ok;
                    break;
                }
            }
            if !completed { Err("the sequence never completed past the injected failures") } else { Ok(()) }
        }
    }

    azos_ktest::ktest! {
        fn chaos_heap_alloc_refused() {
            let used0 = azos_mm::kheap::used();
            let f0 = fired(Point::HeapAlloc);
            let r = armed(Point::HeapAlloc, 1, 0, || alloc::vec::Vec::<u8>::new().try_reserve(4096).is_err());
            if !r || fired(Point::HeapAlloc) == f0 {
                return Err("an armed heap-alloc point did not refuse the allocation");
            }
            if azos_mm::kheap::used() != used0 {
                return Err("the refused allocation changed the heap's use");
            }
            let mut v = alloc::vec::Vec::<u8>::new();
            if v.try_reserve(4096).is_err() { Err("the heap refused once disarmed") } else { Ok(()) }
        }
    }

    // Late: the pipe's region is a capability, and a capability table belongs
    // to a task's Domain; the early phase runs on the boot hart with no task
    // (`current_proc_tid()` is 0, which has no table).
    azos_ktest::ktest_late! {
        fn chaos_ipc_send_refused() {
            use azos_bytepipe::PipeError;
            use azos_ipc::kpipe::{create, KPipe};
            let tid = azos_sched::current_proc_tid();
            let Ok(cap) = create(tid) else { return Err("no pipe") };
            let Ok(r) = azos_ipc::cap_store::get(tid, cap, azos_abi::cap::CapPerms::READ) else { return Err("no region") };
            let Ok(pipe) = KPipe::open(r) else { return Err("no view of the pipe") };
            let f0 = fired(Point::IpcSend);
            let rc = armed(Point::IpcSend, 1, 0, || pipe.write(b"x", true));
            let mut buf = [0u8; 8];
            let empty = pipe.read(&mut buf, true) == Err(PipeError::WouldBlock);
            let resent = pipe.write(b"y", true) == Ok(1) && pipe.read(&mut buf, true) == Ok(1) && buf[0] == b'y';
            drop(pipe);
            let _ = azos_ipc::memobj::memobj_pipe_drop(
                tid, r, azos_ipc::memobj::PIPE_END_READ | azos_ipc::memobj::PIPE_END_WRITE,
            );
            let _ = azos_ipc::cap_store::with_table(tid, |t| azos_ipc::memobj::memobj_release_cap(tid, t, cap));
            if rc != Err(PipeError::WouldBlock) || fired(Point::IpcSend) == f0 {
                return Err("an armed ipc-send point did not refuse the write");
            }
            if !empty { return Err("the refused write put a byte in the pipe") }
            if !resent { Err("the pipe did not work once disarmed") } else { Ok(()) }
        }
    }

    azos_ktest::ktest! {
        #[cfg(feature = "qemu")]
        fn chaos_disk_io_error_recorded() {
            let e0 = azos_drv_block::blkdev::io_errors();
            let f0 = fired(Point::DiskIo);
            let mut sector = [0u8; 512];
            let r = armed(Point::DiskIo, 1, 0, || azos_drv_block::blkdev::read(0, 1, &mut sector));
            if r.is_ok() || fired(Point::DiskIo) != f0 + 1 {
                return Err("an armed disk-io point did not fail the read");
            }
            if azos_drv_block::blkdev::io_errors() != e0 + 1 {
                Err("the injected I/O error was not counted")
            } else {
                Ok(())
            }
        }
    }

    azos_ktest::ktest_late! {
        fn chaos_timer_wake_late_not_lost() {
            use azos_drv_sys::timebase::{now, TIMER_FREQ};
            const SLEEP_MS: u64 = 5;
            let per_us = (TIMER_FREQ / 1_000_000).max(1);
            let f0 = fired(Point::TimerWake);
            let (t0, t1) = armed(Point::TimerWake, 1, 0, || {
                let t0 = now();
                azos_syscall::sleep::sleep_ms(SLEEP_MS);
                (t0, now())
            });
            if fired(Point::TimerWake) == f0 {
                return Err("an armed timer-wake point never fired");
            }
            // Woken (the sleep returned), and late by the configured delay.
            let want = SLEEP_MS * 1000 * per_us + azos_limits::CHAOS_TIMER_DELAY_US * per_us;
            if t1.saturating_sub(t0) < want { Err("the sleeper was not woken late") } else { Ok(()) }
        }
    }

    azos_ktest::ktest_late! {
        fn chaos_spurious_irq_tolerated() {
            let f0 = fired(Point::SpuriousIrq);
            armed(Point::SpuriousIrq, 1, 0, || azos_syscall::sleep::sleep_ms(20));
            // Every CPU took unsolicited doorbells for 20 ms, and the sweep
            // that woke this task still ran.
            if azos_percpu::nr_cpu_ids() > 1 && fired(Point::SpuriousIrq) == f0 {
                Err("an armed spurious-irq point never fired")
            } else {
                Ok(())
            }
        }
    }
}

// Kconfig KTEST + DECISION_RECORDS_DEV: the boot's admission was explained, and a
// capability denial is. Canary `canary=decision-skip` (no record is
// written): both report `not ok`.
#[cfg(all(feature = "ktest", feature = "decisions"))]
mod decision_ktests {
    use azos_decision::{for_each, total, Record, Rule, Verdict};

    fn find(after: u64, mut want: impl FnMut(&Record) -> bool) -> Option<Record> {
        let mut hit = None;
        for_each(|r| {
            if r.seq > after && hit.is_none() && want(r) {
                hit = Some(*r);
            }
        });
        hit
    }

    azos_ktest::ktest! {
        fn decision_admission_recorded() {
            // Early: no task has woken yet, so the boot's records are still
            // in the ring.
            let Some(topo) = azos_topology::get() else { return Err("no topology was installed") };
            let rows = topo.tasks().len() as u64;
            let Some(d) = find(0, |r| r.rule == Rule::DeadlineAdmission as u8) else {
                return Err("deadline admission wrote no record");
            };
            if d.verdict != Verdict::Admit as u8 || d.n[1] != rows || d.subject == 0 {
                return Err("the deadline admission record does not match the installed topology");
            }
            if let Some(m) = find(0, |r| r.rule == Rule::MemoryAdmission as u8) {
                if m.verdict != Verdict::Admit as u8 || m.n[0] > m.n[1] {
                    return Err("the memory admission record admits more than was free");
                }
            }
            let mut line = Line { b: [0; 256], n: 0 };
            let _ = azos_decision::ProvenanceRecord::from_record(&d).write_line(&mut line);
            let s = &line.b[..line.n];
            let has = |pat: &[u8]| s.windows(pat.len()).any(|w| w == pat);
            if !has(b" deadline-admission admit cpus=") || !has(b" rejected=\"refuse the topology") {
                return Err("the deadline admission record does not render");
            }
            Ok(())
        }
    }

    struct Line { b: [u8; 256], n: usize }
    impl core::fmt::Write for Line {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let s = s.as_bytes();
            if self.n + s.len() > self.b.len() { return Err(core::fmt::Error) }
            self.b[self.n..self.n + s.len()].copy_from_slice(s);
            self.n += s.len();
            Ok(())
        }
    }

    azos_ktest::ktest_late! {
        fn decision_cap_denial_recorded() {
            let seq0 = total();
            let tid = azos_sched::current_task_tid();
            // A handle nothing minted: a stale-capability denial.
            let rc = azos_syscall::ipc_handlers::sys_port_destroy_typed(0x00ff_fff0);
            if rc >= 0 {
                return Err("a forged port handle was not refused");
            }
            let kind = azos_abi::cap::CapKind::Port.denial_code() as u64;
            let stale = azos_ipc::cap::CapError::Stale.code() as u64;
            match find(seq0, |r| r.rule == Rule::CapDenial as u8) {
                None => Err("the capability denial wrote no record"),
                Some(r) if r.verdict != Verdict::Deny as u8 || r.subject != tid || r.n[0] != kind || r.n[1] != stale => {
                    Err("the denial record names the wrong task, kind or reason")
                }
                Some(_) => {
                    // Every migration explained so far names two online CPUs.
                    let ncpu = azos_percpu::nr_cpu_ids() as u64;
                    let mut bad = false;
                    for_each(|r| {
                        if r.rule == Rule::WakePlacement as u8 && (r.n[0] == r.n[1] || r.n[0] >= ncpu || r.n[1] >= ncpu) {
                            bad = true;
                        }
                    });
                    if bad { Err("a wake-placement record does not name a move between online CPUs") } else { Ok(()) }
                }
            }
        }
    }
}

// Kconfig KTEST + DECISION_REFUSALS_DURABLE: `why` resolves a refusal. A
// run-time reservation `rt::reserve` refuses (no online hart in its mask, so
// no room) leaves a durable decision; the query finds it by rule, verdict
// and subject, and its chain is the numbers the rule compared. Gated on
// `ktest` alone, not on `decisions-durable`: a kernel built with
// `DECISION_REFUSALS_DURABLE=n` leaves no receipt, and this row must report
// `not ok` there (gate row `ktest why durable-off canary`), not vanish.
#[cfg(feature = "ktest")]
mod why_ktests {
    use azos_decision::{Filter, Rule, Verdict};

    struct Chain {
        b: [u8; 1024],
        n: usize,
    }
    impl core::fmt::Write for Chain {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let s = s.as_bytes();
            if self.n + s.len() > self.b.len() {
                return Err(core::fmt::Error);
            }
            self.b[self.n..self.n + s.len()].copy_from_slice(s);
            self.n += s.len();
            Ok(())
        }
    }

    azos_ktest::ktest_late! {
        fn why_resolves_a_refused_reservation() {
            if !azos_decision::DURABLE {
                return Err("DECISION_REFUSALS_DURABLE is off: a refusal leaves no receipt for `why` to resolve");
            }
            // A mask no online hart is in: admission has nowhere to look and
            // refuses `no-room` without touching any state. (Past 31 harts
            // the mask could name an online one.)
            if azos_percpu::nr_cpu_ids() > 31 {
                return Ok(());
            }
            let tid = azos_sched::current_task_tid();
            let Some(idx) = azos_sched::idx_for_tid(tid) else { return Err("the test task has no slot") };
            let before = azos_decision::total();
            let ask = azos_sched::rt::Reservation {
                runtime_us: 500,
                period_us: 1000,
                deadline_us: 0,
                hard: true,
                cpu_mask: 1 << 31,
                band: false,
                level: 0,
            };
            if azos_sched::rt::reserve(idx, ask).is_ok() {
                return Err("a reservation on a hart that is not online was admitted");
            }
            let f = Filter {
                rule: Some(Rule::DeadlineAdmission as u8),
                verdict: Some(Verdict::Refuse as u8),
                subject: Some(tid),
                after: before,
            };
            let mut ids = [0u64; 2];
            if azos_decision::query(&f, &mut ids) != 1 {
                return Err("the query did not find exactly the one refusal");
            }
            let Some(p) = azos_decision::lookup(ids[0]) else { return Err("the refusal's id does not resolve") };
            // The budget and the period asked, and no room available (no hart
            // in the mask), with reason no-room (2); a kernel built without
            // the deadline class (`SCHED_CLASS_DL=n`) refuses `class-off` (6)
            // before it looks at a hart.
            let reason = p.n[2] >> 32;
            if p.seq != ids[0]
                || p.n[0] != 500
                || p.n[1] != 1000
                || p.n[2] as u32 != 0
                || !(reason == 2 || reason == 6)
            {
                return Err("the record does not carry the numbers the rule compared");
            }
            let mut c = Chain { b: [0; 1024], n: 0 };
            if p.write_chain(&mut c).is_err() {
                return Err("the chain does not fit its buffer");
            }
            let s = &c.b[..c.n];
            let has = |pat: &[u8]| s.windows(pat.len()).any(|w| w == pat);
            if !has(b"deadline-admission refuse")
                || !has(b"numbers   runtime_us=500 period_us=1000 available_us=0 reason=")
            {
                return Err("the chain does not name the rule and its numbers");
            }
            Ok(())
        }
    }
}
