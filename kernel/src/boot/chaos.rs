// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fault injection (Kconfig CHAOS) and decision records (Kconfig
//! DECISION_RECORDS): the kernel's side, which reads the command line, arms
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
    !azos_limits::BUILD_TYPE_RELEASE,
    "Kconfig CHAOS must not reach a release build (BUILD_TYPE_RELEASE): drop the `chaos` feature"
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
                    "[CHAOS] {} ignored: not <point>:<rate> (points: {:?})",
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
        if r != 0 {
            kprintln!("[CHAOS] live: {} fails 1 call in {}", p.name(), r);
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
            let keep: [u32; azos_chaos::N] = core::array::from_fn(|i| azos_chaos::pending(azos_chaos::POINTS[i]));
            let (mut bad, mut heap, mut bad_seed) = (0, 0, 0);
            let n = azos_chaos::parse_cmdline(b"x=1 chaos=ipc-send:3,heap-alloc:2,nope:1,disk-io:x,timer-wake:0 chaos_seed=42",
                |i| match i {
                    azos_chaos::CmdlineIssue::Malformed(_) => bad += 1,
                    azos_chaos::CmdlineIssue::HeapRefused => heap += 1,
                    azos_chaos::CmdlineIssue::BadSeed(_) => bad_seed += 1,
                });
            let got = (n, azos_chaos::pending(Point::IpcSend), azos_chaos::pending(Point::HeapAlloc), azos_chaos::seed());
            for (i, r) in keep.iter().enumerate() {
                azos_chaos::set_pending(azos_chaos::POINTS[i], *r);
            }
            azos_chaos::set_seed(seed);
            if got != (1, 3, 0, 42) || (bad, heap, bad_seed) != (3, 1, 0) {
                return Err("chaos= parsed to the wrong points, rates or seed");
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

    azos_ktest::ktest! {
        fn chaos_ipc_send_refused() {
            use azos_ipc::channel::{channel_create, channel_destroy, channel_recv, channel_send};
            let Some(ch) = channel_create() else { return Err("no channel") };
            let f0 = fired(Point::IpcSend);
            let rc = armed(Point::IpcSend, 1, 0, || channel_send(ch, b"x"));
            let mut buf = [0u8; 8];
            let empty = channel_recv(ch, &mut buf) == 0;
            let resent = channel_send(ch, b"y") == 0 && channel_recv(ch, &mut buf) == 1 && buf[0] == b'y';
            channel_destroy(ch);
            if rc != -1 || fired(Point::IpcSend) == f0 {
                return Err("an armed ipc-send point did not refuse the send");
            }
            if !empty { return Err("the refused send enqueued a message") }
            if !resent { Err("the channel did not work once disarmed") } else { Ok(()) }
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

// Kconfig KTEST + DECISION_RECORDS: the boot's admission was explained, and a
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
            let mut line = Line { b: [0; 192], n: 0 };
            let _ = crate::boot::decision_line(&mut line, &d);
            let s = &line.b[..line.n];
            let has = |pat: &[u8]| s.windows(pat.len()).any(|w| w == pat);
            if !has(b" deadline-admission admit cpus=") || !has(b" rejected=\"refuse the topology") {
                return Err("the deadline admission record does not render");
            }
            Ok(())
        }
    }

    struct Line { b: [u8; 192], n: usize }
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
            let rc = azos_syscall::entropy::sys_entropy_read_typed(0x00ff_fff0, 0, 0);
            if rc >= 0 {
                return Err("a forged entropy handle was not refused");
            }
            let kind = azos_abi::cap::CapKind::Entropy.denial_code() as u64;
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
