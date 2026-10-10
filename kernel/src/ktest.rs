// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The in-kernel test runner (Kconfig `KTEST`, cargo feature `ktest`).
//!
//! `kernel_main` calls [`run`] after boot init, before the secondary harts
//! wake and before the scheduler starts, so no task has run yet. Every test
//! registered with `azos_ktest::ktest!` (the early phase) runs in name order
//! on the boot hart. Tests registered with `azos_ktest::ktest_late!` (the
//! late phase, KUnit's late-init counterpart) run afterwards in the
//! `ktest-late` kernel task, once the scheduler runs on every hart; a late
//! test usually starts a probe task with [`probe`] and reads its verdict.
//! The console gets one TAP plan for both phases:
//!
//! ```text
//! 1..N
//! # ktest phase early: E tests, ...
//! # ktest 1 <name>          (printed before the test runs)
//! ok 1 - <name>
//! not ok 2 - <name> # <reason>
//! # ktest phase late: N-E tests, ...
//! ok E+1 - <name>
//! # ktest: N tests, P passed, F failed (<isa>)
//! ```
//!
//! then the machine powers off, QEMU's exit status carrying the verdict on
//! every ISA (see [`power_off`]). A test that panics cannot be resumed (the
//! kernel does not unwind): the panic handler calls [`on_panic`], which
//! prints that test's `not ok ... # panic at <file>:<line>` and a `Bail out!`
//! line, so the run reads as failed and the tests after it as not run.
//!
//! The tests themselves live next to the code they check; the few that need
//! boot-time values (the image layout, which only the ISA boot hook knows)
//! read them from [`note_image`].
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// Kconfig KTEST depends on BUILD_TYPE_DEV; the cargo feature alone must not
// put the tests (and their power-off) into a release image either.
const _: () = assert!(
    !azos_limits::BUILD_TYPE_RELEASE,
    "Kconfig KTEST must not reach a release build (BUILD_TYPE_RELEASE): drop the `ktest` feature"
);

use azos_drv_sys::kprintln;

fn isa() -> &'static str {
    if cfg!(target_arch = "riscv64") { "riscv64" } else if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" }
}

/// Power off, with the verdict in QEMU's exit status on every ISA: a failed
/// run must never end the machine with the status of a clean one.
///
/// - riscv64: the `sifive_test` finisher, `FAIL` with code 1 (QEMU exits 1).
///   QEMU only *requests* the exit on that write, and a later finisher write
///   overwrites the code: OpenSBI's SRST shutdown writes `PASS` (code 0).
///   Falling through to `shutdown` after the `FAIL` write therefore ended a
///   failed run with status 0 whenever the vCPU reached OpenSBI's write
///   before QEMU's main loop took the first request (1 run in about 7 of
///   `ktest IMU frozen-stamp canary (rv)` on a loaded host). So a failed run
///   writes the finisher once and halts with interrupts off; a clean one
///   goes through SRST (status 0).
/// - aarch64: PSCI `SYSTEM_OFF` has no status, so with Kconfig
///   KTEST_SEMIHOSTING_EXIT the runner leaves through semihosting `SYS_EXIT`
///   (QEMU `-semihosting-config enable=on,target=native` exits 1 or 0).
/// - x86_64: isa-debug-exit, 3 on a failed run, 1 on a clean one.
///
/// Runtime canary `ktest-exit-pass`: the verdict is dropped here, so a failed
/// run powers off as a clean one would; the gate's ktest rows must then read
/// the status against the TAP summary and fail.
fn power_off(failed: bool) -> ! {
    let failed = failed && !canary!("ktest-exit-pass");
    // Once the scheduler runs, kernel output may sit in the console's TX
    // ring or deferred buffer: put it on the wire first, or the summary
    // line is cut by the power-off (seen on a late run).
    azos_drv_sys::uart::console_flush_for_reboot();
    // arch-only: QEMU riscv64 virt's sifive_test finisher; aarch64 and x86_64
    // carry the status below.
    #[cfg(all(target_arch = "riscv64", feature = "qemu"))]
    if failed {
        const FINISHER_FAIL: u32 = 0x3333;
        let base = azos_drv_base::platform::hw::TEST_FINISHER_BASE;
        // `map_mmio_region` maps into the kernel table this task runs on.
        let _ = azos_mm::vmm::map_mmio_region(base, 4);
        use azos_arch::{Cpu, Interrupts};
        let _ = azos_arch::ARCH.disable_all();
        // SAFETY: QEMU virt's test device, identity-mapped just above; the
        // write requests the exit with status 1.
        unsafe { core::ptr::write_volatile(base as *mut u32, FINISHER_FAIL | (1 << 16)) };
        // Never on to `shutdown`: its finisher write would replace the 1.
        azos_arch::ARCH.halt()
    }
    // arch-only: QEMU aarch64 virt's only exit that carries a status.
    #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "qemu"))]
    if azos_limits::KTEST_SEMIHOSTING_EXIT {
        azos_arch::semihosting::exit(failed as u32)
    }
    // x86_64 QEMU: the isa-debug-exit port carries a status (QEMU exits with
    // 2 * value + 1): a failed run exits 3, a clean one 1. Written ONCE, then
    // halt: the write only requests the exit, and a second one (`shutdown`'s
    // own 0) could land first and turn a failed run's 3 into 1.
    // arch-only: no other ISA's QEMU machine has this port.
    #[cfg(all(target_arch = "x86_64", target_os = "none", feature = "qemu"))]
    {
        azos_arch::hw::outl(azos_arch::hw::DEBUG_EXIT_PORT, failed as u32);
        azos_arch::hw::halt_forever()
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none", feature = "qemu")))]
    {
        let _ = failed;
        use azos_arch::Boot;
        azos_arch::ARCH.shutdown()
    }
}

/// Early tests that failed, carried to the late runner's summary.
static EARLY_FAILED: AtomicUsize = AtomicUsize::new(0);

/// Lockdep violations counted while a test ran (each failed that test). The
/// rest, at the summary, happened outside any test and fail the run.
static LOCKDEP_IN_TESTS: AtomicUsize = AtomicUsize::new(0);

/// Print the lockdep reports queued since the last call, one line each.
fn lockdep_print() {
    crate::lockdep_log::reports("# ");
}

/// Run every early test (boot hart, no task has run) and print TAP. With no
/// late test, print the summary and power off. Otherwise create the late
/// runner task ([`late_run`]) and return: boot goes on, the scheduler starts,
/// and that task runs the late tests, prints the summary and powers off.
///
/// One TAP plan covers both phases: `1..N` with N = early + late; the early
/// tests are 1..E, the late ones E+1..N, each phase in name order, and a
/// `# ktest phase late` comment separates them. A test dropped from either
/// phase changes N.
pub(crate) fn run() {
    let tests = azos_ktest::all();
    let early = azos_ktest::count(tests, azos_ktest::EARLY);
    let late = azos_ktest::count(tests, azos_ktest::LATE);
    if let Some(name) = azos_ktest::duplicate(tests) {
        kprintln!("Bail out! ktest: the name {} is registered twice", name);
        power_off(true);
    }
    kprintln!("1..{}", early + late);
    // Kconfig LOCKDEP (N1): what boot did before the first test.
    lockdep_print();
    kprintln!("# ktest phase early: {} tests, boot hart, before the scheduler ({})", early, isa());
    let failed = run_phase(azos_ktest::EARLY, 0);
    if late == 0 {
        summary(early, failed);
    }
    EARLY_FAILED.store(failed, Ordering::Relaxed);
    let _ = azos_sched::task_create_affinity("ktest-late", late_run, 0, azos_limits::KTEST_LATE_PRIORITY as u32, 0);
}

/// Run every test of `phase`; TAP numbers start after `first`. Returns how
/// many failed. In the late phase every TAP line starts on a fresh line: a
/// ring-3 program (the shell's prompt) may have left a partial line on the
/// console, and a TAP line must start at column 0.
fn run_phase(phase: usize, first: usize) -> usize {
    let nl = if phase == azos_ktest::LATE { "\n" } else { "" };
    let tests = azos_ktest::all();
    let mut failed = 0usize;
    for r in 0..azos_ktest::count(tests, phase) {
        let Some(t) = azos_ktest::nth(tests, phase, r) else { break };
        let i = first + r + 1;
        kprintln!("{}# ktest {} {}", nl, i, t.name);
        azos_ktest::set_current(Some((i, t)));
        let before = azos_sync::lockdep::violations();
        let mut verdict = (t.run)();
        azos_ktest::set_current(None);
        // Any lockdep violation during the test fails it (Kconfig LOCKDEP).
        let found = azos_sync::lockdep::violations().wrapping_sub(before) as usize;
        if found != 0 {
            LOCKDEP_IN_TESTS.fetch_add(found, Ordering::Relaxed);
            lockdep_print();
            if verdict.is_ok() {
                verdict = Err("lockdep violation (the `# lockdep:` line above)");
            }
        }
        match verdict {
            Ok(()) => kprintln!("{}ok {} - {}", nl, i, t.name),
            Err(why) => {
                failed += 1;
                kprintln!("{}not ok {} - {} # {}", nl, i, t.name, why);
            }
        }
    }
    failed
}

fn summary(n: usize, failed: usize) -> ! {
    // Kconfig CHAOS: what the injection points did over the whole boot (a
    // command-line soak row reads that its points fired).
    #[cfg(feature = "chaos")]
    for p in azos_chaos::POINTS {
        let (rate, checked, fired) = azos_chaos::stats(p);
        if checked != 0 {
            kprintln!("\n# chaos: {} rate={} checked={} fired={}", p.name(), rate, checked, fired);
        }
    }
    let outside = lockdep_summary();
    kprintln!("\n# ktest: {} tests, {} passed, {} failed ({})", n, n - failed, failed, isa());
    if outside != 0 {
        kprintln!("Bail out! lockdep: {} violation(s) outside any test ({})", outside, isa());
    }
    power_off(failed != 0 || outside != 0)
}

/// The late runner: a kernel task (Kconfig `KTEST_LATE_PRIORITY`, pinned to
/// CPU 0) created by [`run`] before the scheduler starts. Every hart is
/// online when it runs, and so is every boot task (the same system the
/// smokes these tests replace booted next to).
/// Kconfig LOCKDEP: print what is still queued and the counters; the number
/// of violations no test was running for.
fn lockdep_summary() -> usize {
    if !azos_sync::lockdep::ON {
        return 0;
    }
    lockdep_print();
    let st = azos_sync::lockdep::stats();
    kprintln!("\n# lockdep: violations={} notes={} edges={} chains={} unmatched-releases={} unprinted={} checked: switches={} sleeps={} user-returns={} scopes={} contended={} classes={} classes-full={} hold-bound={}us{}",
        st.violations, st.notes, st.edges, st.chains, st.unmatched, azos_sync::lockdep::dropped(),
        st.switches, st.sleep_checks, st.user_returns, st.scope_checks, st.contended, st.classes,
        st.classes_full, azos_sync::lockdep::MAX_HOLD_US,
        if azos_sync::lockdep::HOLD_ENFORCE { "" } else { " (not enforced)" });
    crate::lockdep_log::holds("# ");
    (st.violations as usize).saturating_sub(LOCKDEP_IN_TESTS.load(Ordering::Relaxed))
}

fn late_run(_: usize) {
    let tests = azos_ktest::all();
    let early = azos_ktest::count(tests, azos_ktest::EARLY);
    let late = azos_ktest::count(tests, azos_ktest::LATE);
    kprintln!("\n# ktest phase late: {} tests, kernel task, {} CPUs online ({})", late, azos_percpu::nr_cpu_ids(), isa());
    let failed = run_phase(azos_ktest::LATE, early);
    summary(early + late, EARLY_FAILED.load(Ordering::Relaxed) + failed)
}

/// Set by a probe task when it is done ([`probe_done`]); read by [`probe`].
static PROBE_DONE: AtomicBool = AtomicBool::new(false);
static PROBE_ENTRY: AtomicUsize = AtomicUsize::new(0);

/// Called by a late test's probe task when its scenario is over (its
/// verdict statics are final).
pub(crate) fn probe_done() {
    PROBE_DONE.store(true, Ordering::Release);
}

fn probe_trampoline(arg: usize) {
    // SAFETY: `probe` stored a `fn(usize)` just before creating this task.
    let entry: fn(usize) = unsafe { core::mem::transmute(PROBE_ENTRY.load(Ordering::Acquire)) };
    entry(arg);
    probe_done();
}

/// Wait, sleeping 10 ms at a time, until `ready()` holds, at most Kconfig
/// `KTEST_LATE_TIMEOUT_MS`; `Err(why)` on timeout. A late test's wait on the
/// tasks it started: a timer wait on the counter, never a yield count.
pub(crate) fn wait(why: &'static str, ready: impl FnMut() -> bool) -> Result<(), &'static str> {
    if azos_syscall::sleep::wait_until_ms(azos_limits::KTEST_LATE_TIMEOUT_MS as u64, 10, ready) {
        Ok(())
    } else {
        Err(why)
    }
}

/// Create `entry(arg)` as a kernel task (`prio`, pinned to `cpu`) and wait
/// ([`wait`]) until it returns or calls [`probe_done`]. The scenario's
/// verdict is then the caller's to read from the probe's statics.
pub(crate) fn probe(name: &str, entry: fn(usize), arg: usize, prio: u32, cpu: i8) -> Result<(), &'static str> {
    PROBE_DONE.store(false, Ordering::Release);
    PROBE_ENTRY.store(entry as usize, Ordering::Release);
    azos_sched::task_create_affinity(name, probe_trampoline, arg, prio, cpu);
    wait("the probe task did not finish within KTEST_LATE_TIMEOUT_MS", || PROBE_DONE.load(Ordering::Acquire))
}

/// The panic handler's hook: a panic during a test is that test's failure.
/// Returns when no test is running.
pub(crate) fn on_panic(info: &core::panic::PanicInfo) {
    let Some((i, t)) = azos_ktest::current() else { return };
    azos_ktest::set_current(None);
    match info.location() {
        Some(l) => kprintln!("\nnot ok {} - {} # panic at {}:{}", i, t.name, l.file(), l.line()),
        None => kprintln!("\nnot ok {} - {} # panic", i, t.name),
    }
    kprintln!("Bail out! ktest: {} panicked; tests {}.. did not run ({})", t.name, i + 1, isa());
    power_off(true)
}

/// The kernel image's layout and the RAM range, as the ISA boot hook
/// enforced and verified them (`[MM] W^X ok` / `[MM] NX outside the image`).
pub(crate) struct Image {
    pub text: (usize, usize),
    pub ro: (usize, usize),
    pub data: (usize, usize),
    pub mem: (usize, usize),
}

static IMAGE: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

pub(crate) fn note_image(i: Image) {
    let v = [i.text.0, i.text.1, i.ro.0, i.ro.1, i.data.0, i.data.1, i.mem.0, i.mem.1];
    for (slot, x) in IMAGE.iter().zip(v) {
        slot.store(x, Ordering::Relaxed);
    }
}

fn image() -> Result<[usize; 8], &'static str> {
    let v: [usize; 8] = core::array::from_fn(|k| IMAGE[k].load(Ordering::Relaxed));
    if v[1] == 0 { Err("the boot hook did not record the image layout") } else { Ok(v) }
}

// Every kernel-image page carries the permissions planned for its section:
// .text RX, .rodata RO, data/bss RW, none W+X, all 4 KiB leaves, the only
// unmapped ones the task-stack guards. The page table is read back, not the enforcement call's own claim. Canary
// `wx-skip-canary` (the boot skips `enforce_wx`).
azos_ktest::ktest! {
    #[cfg(not(feature = "no-mmu"))]
    fn mm_wx_image() {
        let v = image()?;
        let rep = azos_mm::vmm::verify_wx(v[0], v[1], v[2], v[3], v[4], v[5]);
        // After the boot hook's check, `azos_sched::init` unmapped one guard
        // page at the bottom of every task stack (in .bss): exactly those may
        // read back unmapped, no other page.
        let guards = if azos_sched::scheduler::stack_guard_pages_active() { azos_sched::scheduler::stack_guard_readback().0 } else { 0 };
        if !rep.is_clean() && rep.unmapped != guards {
            kprintln!("# mm_wx_image: {} checked, {} W+X, {} wrong-flags, {} unmapped, {} unsplit-mega, first bad {:#x}",
                rep.checked, rep.write_exec, rep.wrong_flags, rep.unmapped, rep.unsplit_megapage, rep.first_bad);
        }
        if rep.checked == 0 {
            Err("no image page checked")
        } else if rep.write_exec != 0 {
            Err("an image page is writable and executable")
        } else if rep.wrong_flags != 0 {
            Err("an image page has the wrong permissions for its section")
        } else if rep.unsplit_megapage != 0 {
            Err("an image page is still in a megapage")
        } else if rep.unmapped != guards {
            Err("an image page other than a task-stack guard is unmapped")
        } else {
            Ok(())
        }
    }
}

// Nothing executable is mapped outside the kernel image in the kernel's own
// table (heap, frames, task stacks). Canary `nx-skip-canary` (the boot strips
// nothing).
azos_ktest::ktest! {
    #[cfg(not(feature = "no-mmu"))]
    fn mm_nx_outside_image() {
        let v = image()?;
        let left = azos_mm::vmm::verify_no_exec_outside_image(v[6], v[7], v[0], v[5]);
        if left.is_empty() { Ok(()) } else { Err("RAM outside the image is still executable") }
    }
}

// The heap's size-class cache in the kernel's own environment: every class
// through its magazines, the depot and a new slab, tags at both ends, half
// freed and reclaimed, reallocated, re-read, a final reclaim leaving no
// magazine holding an object (`azos_mm::kheap::slab_selftest`). Canary
// `slab-freelist-canary` (a slab hands out a freed object without unlinking
// it): the poison check panics, or the self-test returns an error.
azos_ktest::ktest! {
    fn kheap_slab_selftest() {
        if !(azos_limits::KHEAP_SLAB && azos_limits::KHEAP_SLAB_DEBUG) {
            return Err("KHEAP_SLAB and KHEAP_SLAB_DEBUG are not both on in this configuration");
        }
        match azos_mm::kheap::slab_selftest() {
            Ok((objects, _)) if objects > 0 => Ok(()),
            Ok(_) => Err("the self-test allocated no object"),
            Err(e) => Err(e),
        }
    }
}

// Every task stack's bottom page is unmapped in the kernel's table, read
// back through a fresh walk (`[MM] Stack guard readback`), so an overflow
// faults instead of running into the next stack.
azos_ktest::ktest! {
    #[cfg(not(feature = "no-mmu"))]
    fn sched_stack_guards_unmapped() {
        let (unmapped, total) = azos_sched::scheduler::stack_guard_readback();
        if total == 0 {
            Err("no task stack slot")
        } else if !azos_sched::scheduler::stack_guard_pages_active() {
            Err("the stack guard pages were never set up")
        } else if unmapped != total {
            Err("a task stack's guard page is mapped")
        } else {
            Ok(())
        }
    }
}

// riscv64: the boot's Zicboz choice and its zero-fill content. QEMU's
// `virt` CPU declares Zicboz and the probe confirms it, so the fast path
// must be on (`[MM] Zicboz cbo.zero fast path: enabled`) with a validated
// block size; then a page poisoned with 0xAA, freed and reallocated (the
// first-fit allocator hands back the same frame) must read back all zero:
// the zero-fill `alloc_page` runs is `cbo.zero` here, not the host tests'
// scalar stand-in. Canary `zicboz-skip-canary` (the boot ignores the DTB's
// Zicboz): the scalar fallback is chosen and this test is `not ok`. With
// Kconfig RV_ZICBOZ = n it asserts the opposite: the fast path stays off.
azos_ktest::ktest! {
    // arch-only: Zicboz is a RISC-V extension; aarch64's counterpart,
    // DC ZVA, is not wired (its pages are zeroed with plain stores).
    #[cfg(target_arch = "riscv64")]
    fn mm_zicboz_zero_fill() {
        use azos_arch::mmu::PAGE_SIZE;
        // Kconfig RV_ZICBOZ = n: the fast path must stay off although this
        // CPU declares Zicboz (the `[ISA]` line reads `zicboz=n`).
        if !azos_arch_api::isa::riscv64::ZICBOZ.allowed() {
            return if azos_arch::cbo::zicboz_available() {
                Err("RV_ZICBOZ is n but the Zicboz fast path was selected")
            } else {
                Ok(())
            };
        }
        if !azos_arch::cbo::zicboz_available() {
            return Err("the Zicboz fast path is off (scalar fallback) on a CPU that has Zicboz");
        }
        if azos_arch::cbo::zicboz_block_size() == 0 {
            return Err("the Zicboz fast path has no block size");
        }
        let p = azos_mm::pmm::alloc_page().map_err(|_| "alloc_page failed")?;
        let addr = p.as_usize();
        // SAFETY: a frame this test owns until it frees it.
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0xAA, PAGE_SIZE) };
        azos_mm::pmm::free_page(p).map_err(|_| "free_page failed")?;
        let again = azos_mm::pmm::alloc_page().map_err(|_| "alloc_page failed")?;
        let same = again.as_usize() == addr;
        // SAFETY: the reallocated frame, owned until freed below.
        let zero = unsafe { core::slice::from_raw_parts(again.as_usize() as *const u8, PAGE_SIZE) }
            .iter()
            .all(|&b| b == 0);
        let _ = azos_mm::pmm::free_page(again);
        if !same {
            Err("the freed frame was not handed back (the poison check reads nothing)")
        } else if !zero {
            Err("a reallocated page is not all zero")
        } else {
            Ok(())
        }
    }
}

// ── Lockdep (Kconfig LOCKDEP, N1) ───────────────────────────────────────────
//
// Two runtime canaries plant what lockdep exists to catch; the runner turns
// the violation into `not ok`. Unarmed, each test does the legal half.

static LD_A: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);
static LD_B: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);
static LD_IO: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);

azos_ktest::ktest! {
    fn lockdep_lock_order_consistent() {
        if !azos_sync::lockdep::ON {
            return Err("LOCKDEP is not on in this ktest kernel (Kconfig LOCKDEP_KTEST or LOCKDEP_Y)");
        }
        let edges = azos_sync::lockdep::stats().edges;
        {
            let mut a = LD_A.lock();
            let mut b = LD_B.lock();
            *a += 1;
            *b += 1;
        }
        // `canary=lockdep-abba`: the other order, in the same task (an
        // inversion needs no second CPU to be one).
        if canary!("lockdep-abba") {
            let mut b = LD_B.lock();
            let mut a = LD_A.lock();
            *a += 1;
            *b += 1;
        }
        if azos_sync::lockdep::stats().edges == edges {
            return Err("taking A then B recorded no lockdep edge");
        }
        Ok(())
    }
}

azos_ktest::ktest_late! {
    fn lockdep_no_spinlock_across_block_io() {
        if !azos_sync::lockdep::ON {
            return Err("LOCKDEP is not on in this ktest kernel (Kconfig LOCKDEP_KTEST or LOCKDEP_Y)");
        }
        // A one-sector read through the block layer (an error without a
        // disk: the check is at the layer's entry). `canary=lockdep-spin-blk`
        // holds a SpinLock across it, the rt7 shape.
        let mut sector = [0u8; 512];
        let held = if canary!("lockdep-spin-blk") { Some(LD_IO.lock()) } else { None };
        let _ = azos_drv_block::blkdev::read(0, 1, &mut sector);
        drop(held);
        Ok(())
    }
}

// ── Lockdep, part b (N1b): scopes, IRQ safety, hold times, rule F7 ──────────
//
// Each test does the legal half; its runtime canary plants the violation the
// check exists for, and the runner turns the report into `not ok`. Interrupt
// context is simulated with `isr_depth::enter`/`exit` under `IrqOff`: what
// lockdep reads, without a canary on the tick path.

fn ld_on(what: &'static str, on: bool) -> Result<(), &'static str> {
    if azos_sync::lockdep::ON && on { Ok(()) } else { Err(what) }
}

/// `f` as if in an interrupt handler on this CPU (interrupts off, the ISR
/// depth this CPU's trap arm keeps raised).
fn ld_as_irq<R>(f: impl FnOnce(usize) -> R) -> R {
    use azos_arch::Cpu as _;
    let _irq = azos_sync::scope::IrqOff::new();
    let me = azos_arch::ARCH.hart_id();
    azos_sync::isr_depth::enter(me);
    let r = f(me);
    azos_sync::isr_depth::exit(me);
    r
}

pub(crate) static LD_OWNED: azos_sync::scope::CpuOwned<u32> = azos_sync::scope::CpuOwned::with_init(ld_owned_init);
unsafe fn ld_owned_init(p: *mut azos_sync::SpinLock<u32>) {
    // SAFETY: `PerCpuVar::attach`'s contract: zeroed, aligned, ours.
    unsafe { p.write(azos_sync::SpinLock::new(0)) };
}
// SAFETY: all-zero is a valid u32.
pub(crate) static LD_PERCPU: azos_sync::scope::PerCpu<u32> = unsafe { azos_sync::scope::PerCpu::zeroed() };

/// The per-CPU variables the tests below keep in the areas.
pub(crate) fn for_each_percpu_var(f: &mut dyn FnMut(&'static dyn azos_percpu::PerCpuVar)) {
    f(&LD_OWNED);
    f(&LD_PERCPU);
}

static LD_OBJ_AS: azos_sync::scope::Object<u32, 1> = azos_sync::scope::Object::new(0);
static LD_OBJ_F1: azos_sync::scope::Object<u32, 2> = azos_sync::scope::Object::new(0);
static LD_OBJ_F2: azos_sync::scope::Object<u32, 2> = azos_sync::scope::Object::new(0);

azos_ktest::ktest_late! {
    fn lockdep_scope_rules() {
        ld_on("LOCKDEP or LOCKDEP_SCOPE_CHECKS is off in this ktest kernel", azos_sync::lockdep::SCOPE_CHECKS)?;
        use azos_arch::Cpu as _;
        let n = azos_percpu::nr_cpu_ids();
        let checks = azos_sync::lockdep::stats().scope_checks;
        // CpuOwned: another CPU's from task context, this CPU's from an
        // interrupt; PerCpu with earned tokens; Objects in level order.
        let me = { let _irq = azos_sync::scope::IrqOff::new(); azos_arch::ARCH.hart_id() };
        let other = (me + 1) % n;
        *LD_OWNED.lock_on(other) += 1;
        ld_as_irq(|me| *LD_OWNED.lock_on(me) += 1);
        {
            let irq = azos_sync::scope::IrqOff::new();
            LD_PERCPU.with_mut(&irq, |v| *v += 1);
            let p = azos_sync::critical_section();
            LD_PERCPU.with(&p, |v| { let _ = *v; });
        }
        {
            let a = LD_OBJ_AS.lock();
            let _f = LD_OBJ_F1.lock_under(&a);
        }
        {
            let (mut x, mut y) = azos_sync::scope::Object::lock_pair(&LD_OBJ_F1, &LD_OBJ_F2);
            *x += 1;
            *y += 1;
        }
        // `canary=lockdep-scope-irq`: another CPU's CpuOwned from interrupt
        // context. `canary=lockdep-scope-preempt`: a PerCpu reached with a
        // token assumed while interrupts and preemption are on.
        if canary!("lockdep-scope-irq") && n > 1 {
            ld_as_irq(|_| *LD_OWNED.lock_on(other) += 1);
        }
        if canary!("lockdep-scope-preempt") {
            // SAFETY: deliberately false (the canary): interrupts are on.
            let tok = unsafe { azos_sync::scope::IrqOff::assume() };
            LD_PERCPU.with_mut(&tok, |v| *v += 1);
        }
        if azos_sync::lockdep::stats().scope_checks == checks {
            return Err("no scoped access reached lockdep's scope check");
        }
        Ok(())
    }
}

static LD_IRQ: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);

azos_ktest::ktest_late! {
    fn lockdep_irq_safe_class_taken_irqsave() {
        ld_on("LOCKDEP or LOCKDEP_IRQ_INFERENCE is off in this ktest kernel", azos_sync::lockdep::IRQ_INFERENCE)?;
        if !azos_sync::preempt::irqs_enabled() {
            return Err("the late runner runs with interrupts off: the task-side half tests nothing");
        }
        // Taken in interrupt context: the class is IRQ-safe from here.
        ld_as_irq(|_| *LD_IRQ.lock() += 1);
        // The legal task-side use: interrupts off while held.
        *LD_IRQ.lock_irqsave() += 1;
        // `canary=lockdep-irq-inversion`: with interrupts on, where the
        // interrupt that takes it would spin on this CPU forever.
        if canary!("lockdep-irq-inversion") {
            *LD_IRQ.lock() += 1;
        }
        Ok(())
    }
}

static LD_HOLD: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);

azos_ktest::ktest_late! {
    fn lockdep_spinlock_hold_bounded() {
        ld_on("LOCKDEP is off in this ktest kernel", true)?;
        use azos_arch::Cpu as _;
        let limit = azos_sync::lockdep::hold_limit_ticks();
        if limit == 0 {
            return Err("lockdep has no timebase (set_timebase_hz): holds are not timed");
        }
        let key = LD_HOLD.lockdep_key();
        let holds = azos_sync::lockdep::class_info(key).map_or(0, |c| c.holds);
        *LD_HOLD.lock() += 1;
        if azos_sync::lockdep::class_info(key).map_or(0, |c| c.holds) != holds + 1 {
            return Err("a SpinLock hold was not added to its class's histogram");
        }
        // `canary=lockdep-hold`: hold it twice LOCK_MAX_HOLD_US (an
        // iteration cap backs the timer up).
        if canary!("lockdep-hold") {
            let mut g = LD_HOLD.lock();
            let t0 = azos_arch::ARCH.now_ticks();
            let mut spins = 0u64;
            while azos_arch::ARCH.now_ticks().wrapping_sub(t0) <= 2 * limit && spins < 1 << 32 {
                core::hint::spin_loop();
                spins += 1;
            }
            *g += 1;
            drop(g);
            // With LOCKDEP_HOLD_ENFORCE the runner fails this test on
            // lockdep's report alone (the `ktest hold bound, -icount` rows:
            // this check stays out of it, so the row's canary proves the
            // enforcement, not this test); without it (the QEMU board's
            // default: emulated wall time is host load) the report is a note,
            // and this check fails it. Not asserted unarmed: one increment
            // under an emulator is not guaranteed to stay under the bound.
            if !azos_sync::lockdep::HOLD_ENFORCE
                && azos_sync::lockdep::class_info(key).map_or(0, |c| c.max_ticks) > limit {
                return Err("LD_HOLD was held past LOCK_MAX_HOLD_US (lockdep's hold histogram)");
            }
        }
        Ok(())
    }
}

// Rule F7: a holder on CPU 1 and a contender on CPU 2, both kernel tasks;
// the holder is real-time, and so is the contender only under the canary.
static LD_PI: azos_sync::PiMutex<u32> = azos_sync::PiMutex::new(0);
static LD_PI_HELD: AtomicBool = AtomicBool::new(false);
static LD_PI_DONE: AtomicUsize = AtomicUsize::new(0);
static LD_PI_CONTENDED0: AtomicUsize = AtomicUsize::new(0);

fn ld_pi_holder(_: usize) {
    use azos_arch::Cpu as _;
    let mut g = LD_PI.lock();
    LD_PI_HELD.store(true, Ordering::Release);
    // Until the contender has reached the contended path (bounded).
    let t0 = azos_arch::ARCH.now_ticks();
    let cap = azos_sync::lockdep::hold_limit_ticks().max(1) * 10_000;
    let mut spins = 0u64;
    while (azos_sync::lockdep::stats().contended as usize) == LD_PI_CONTENDED0.load(Ordering::Acquire)
        && azos_arch::ARCH.now_ticks().wrapping_sub(t0) < cap
        && spins < 1 << 32
    {
        core::hint::spin_loop();
        spins += 1;
    }
    *g += 1;
    drop(g);
    LD_PI_DONE.fetch_add(1, Ordering::Release);
}

fn ld_pi_contender(_: usize) {
    while !LD_PI_HELD.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    *LD_PI.lock() += 1;
    LD_PI_DONE.fetch_add(1, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn lockdep_rt_tasks_share_only_spinlocks() {
        ld_on("LOCKDEP or LOCKDEP_RT_CROSS_CPU is off in this ktest kernel", azos_sync::lockdep::RT_CROSS_CPU)?;
        if azos_percpu::nr_cpu_ids() < 3 {
            return Err("needs 3 CPUs (the runner on 0, a holder on 1, a contender on 2)");
        }
        let rt = azos_sched::RT_PRIORITY_THRESHOLD - 2;
        let contender = if canary!("lockdep-rt-pi") { rt } else { azos_sched::DEFAULT_PRIORITY };
        LD_PI_HELD.store(false, Ordering::Release);
        LD_PI_DONE.store(0, Ordering::Release);
        let c0 = azos_sync::lockdep::stats().contended as usize;
        LD_PI_CONTENDED0.store(c0, Ordering::Release);
        azos_sched::task_create_affinity("ld-pi-holder", ld_pi_holder, 0, rt, 1);
        azos_sched::task_create_affinity("ld-pi-contender", ld_pi_contender, 0, contender, 2);
        wait("the PiMutex holder and contender did not both finish", || LD_PI_DONE.load(Ordering::Acquire) == 2)?;
        if azos_sync::lockdep::stats().contended as usize == c0 {
            return Err("the PiMutex was never contended: rule F7 was not exercised");
        }
        Ok(())
    }
}


// ── Spin-wait and CAS (wave 15, N2) ─────────────────────────────────────────
//
// `SpinWait` (crates/core/arch-api spin.rs) on the path this boot selected:
// the extension (Zacas/Zawrs, LSE, WAITPKG) or the fallback, whichever the
// `[SPIN]` boot line names. The same tests pass on both.

static SPIN_L: azos_sync::SpinLock<u64> = azos_sync::SpinLock::new(0);

azos_ktest::ktest! {
    fn spin_wait_cas_semantics() {
        use azos_arch::{CasOrder, SpinWait as _, ARCH};
        use core::sync::atomic::{AtomicU32, AtomicU64};
        let r = Ordering::Relaxed;
        let w = AtomicU32::new(5);
        if ARCH.cas32(&w, 5, 9, CasOrder::Acquire) != Ok(5) || w.load(r) != 9 {
            return Err("cas32 on a matching word did not swap");
        }
        if ARCH.cas32(&w, 5, 7, CasOrder::AcqRel) != Err(9) || w.load(r) != 9 {
            return Err("cas32 on a different word swapped or misreported");
        }
        // Bit 31 set: `amocas.w`/`lr.w` sign-extend; the compare must not.
        let s = AtomicU32::new(0xFFFF_FFFF);
        if ARCH.cas32(&s, 0xFFFF_FFFF, 0x8000_0000, CasOrder::Release) != Ok(0xFFFF_FFFF)
            || s.load(r) != 0x8000_0000
            || ARCH.cas32(&s, 0x8000_0000, 1, CasOrder::Relaxed) != Ok(0x8000_0000)
        {
            return Err("cas32 mishandled a word with bit 31 set");
        }
        let d = AtomicU64::new(0xFFFF_FFFF_0000_0001);
        if ARCH.cas64(&d, 0x0000_0000_0000_0001, 2, CasOrder::Acquire).is_ok()
            || ARCH.cas64(&d, 0xFFFF_FFFF_0000_0001, 3, CasOrder::AcqRel) != Ok(0xFFFF_FFFF_0000_0001)
            || d.load(r) != 3
        {
            return Err("cas64 compared or swapped only the low half");
        }
        // Exchange: the old value back, the new one stored, all 64 bits.
        let x = AtomicU32::new(0x8000_0001);
        if ARCH.swap32(&x, 7, CasOrder::Acquire) != 0x8000_0001 || ARCH.swap32(&x, 0, CasOrder::Release) != 7
            || x.load(r) != 0
        {
            return Err("swap32 did not exchange");
        }
        let y = AtomicU64::new(0xFFFF_FFFF_0000_0005);
        if ARCH.swap64(&y, 9, CasOrder::AcqRel) != 0xFFFF_FFFF_0000_0005 || y.load(r) != 9 {
            return Err("swap64 did not exchange all 64 bits");
        }
        // A word that already differs: no wait at all, the value back.
        if ARCH.wait_while32(&s, 0x8000_0001) != 1 || ARCH.wait_while64(&d, 0) != 3 {
            return Err("wait_while did not return the differing value");
        }
        // One hint step on a word that differs must return (no stall).
        ARCH.wait_hint32(&s, 0xFFFF_FFFF);
        ARCH.wait_hint64(&d, 4);
        ARCH.cpu_relax();
        // The lock's own word: acquire, release, then it is free.
        azos_sync::spinlock::azos_spin_acquire_release(&SPIN_L);
        if SPIN_L.try_lock().is_none() {
            return Err("SpinLock still held after acquire and release");
        }
        Ok(())
    }
}

static SPIN_DONE: AtomicUsize = AtomicUsize::new(0);

/// Rounds per contender: a test parameter (enough to interleave under TCG).
const SPIN_ROUNDS: u64 = 20_000;

fn spin_contender(_: usize) {
    for _ in 0..SPIN_ROUNDS {
        let mut g = SPIN_L.lock();
        // A read-modify-write the lock alone protects, with a window.
        let v = *g;
        core::hint::black_box(());
        *g = v + 1;
    }
    SPIN_DONE.fetch_add(1, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn spin_lock_contended_cross_cpu() {
        if azos_percpu::nr_cpu_ids() < 3 {
            return Err("needs 3 CPUs (the runner on 0, contenders on 1 and 2)");
        }
        *SPIN_L.lock() = 0;
        SPIN_DONE.store(0, Ordering::Release);
        let p = azos_sched::DEFAULT_PRIORITY;
        azos_sched::task_create_affinity("spin-c1", spin_contender, 0, p, 1);
        azos_sched::task_create_affinity("spin-c2", spin_contender, 0, p, 2);
        wait("the two SpinLock contenders did not finish", || SPIN_DONE.load(Ordering::Acquire) == 2)?;
        if *SPIN_L.lock() != 2 * SPIN_ROUNDS {
            return Err("two CPUs lost an increment under the SpinLock");
        }
        Ok(())
    }
}

// ── SpinLock fairness: FIFO and a bounded wait (wave 15, N3) ────────────────
//
// Four contenders, one per CPU, take one SpinLock back to back with
// interrupts off. Each counts, per acquisition, the acquisitions by others
// between its arrival (a read of the shared count just before the spin,
// `lock_marked`) and
// its own: the queued lock (Kconfig SPINLOCK_IMPL = mcs) serves waiters in
// arrival order, so at most the other three go first; a test-and-set lock
// lets the CPU that just released retake it, and a waiter is passed over
// for as long as that CPU keeps winning. The bound is in acquisitions, not
// time: under TCG a vCPU's host slice decides how long a hold lasts, not
// how many others precede a waiter. The wait (ticks, printed in ns: under
// `-icount shift=0` one ns is one guest instruction) is printed, not judged.
// A waiter descheduled (by the host, or at a vCPU slice end under
// -icount) between its arrival read and its enqueue is passed by
// acquisitions it was not yet queued for; those count as `late` and are
// allowed up to 0.25% of the acquisitions. Measured, rv64 (late of 8000):
// mcs 1 (MTTCG) and 0 (-icount -smp 4); ttas 1151 (MTTCG) and 37 (-icount,
// where a vCPU reacquires within its own slice and the others see the
// lock free only across a slice switch).

const FIFO_CONTENDERS: usize = 4;
const FIFO_ROUNDS: u64 = 2_000;
/// Late acquisitions (passed by more than the other contenders) the test
/// tolerates: 0.25% of them; a test parameter.
const FIFO_LATE_MAX: u64 = FIFO_CONTENDERS as u64 * FIFO_ROUNDS / 400;

static FIFO_L: azos_sync::SpinLock<u64> = azos_sync::SpinLock::new(0);
static FIFO_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FIFO_READY: AtomicUsize = AtomicUsize::new(0);
static FIFO_DONE: AtomicUsize = AtomicUsize::new(0);
static FIFO_MAX_OVER: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_LATE: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_MAX_WAIT: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_SUM_WAIT: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];

fn fifo_contender(c: usize) {
    use azos_arch::{Cpu as _, Interrupts as _, SpinWait as _, ARCH};
    let r = Ordering::Relaxed;
    // Start together: a contender that ran alone would measure nothing.
    FIFO_READY.fetch_add(1, Ordering::AcqRel);
    while FIFO_READY.load(Ordering::Acquire) < FIFO_CONTENDERS {
        ARCH.cpu_relax();
    }
    let (mut max_over, mut late, mut max_wait, mut sum_wait) = (0u64, 0u64, 0u64, 0u64);
    for _ in 0..FIFO_ROUNDS {
        let s = ARCH.disable_all();
        let (mut c0, mut t0) = (0, 0);
        // The counter read last: under MTTCG an aarch64 timer read can wait
        // on QEMU's global lock, which would widen the arrival window.
        let mut g = FIFO_L.lock_marked(|| {
            t0 = ARCH.now_ticks();
            c0 = FIFO_COUNT.load(r);
        });
        let t1 = ARCH.now_ticks();
        let c1 = FIFO_COUNT.load(r);
        FIFO_COUNT.store(c1 + 1, r);
        *g += 1;
        core::hint::black_box(&mut *g);
        drop(g);
        ARCH.restore(s);
        let over = c1 - c0;
        max_over = max_over.max(over);
        if over > (FIFO_CONTENDERS - 1) as u64 {
            late += 1;
        }
        let w = t1.wrapping_sub(t0);
        max_wait = max_wait.max(w);
        sum_wait += w;
    }
    FIFO_MAX_OVER[c].store(max_over, r);
    FIFO_LATE[c].store(late, r);
    FIFO_MAX_WAIT[c].store(max_wait, r);
    FIFO_SUM_WAIT[c].store(sum_wait, r);
    FIFO_DONE.fetch_add(1, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn spin_lock_fifo_bounded() {
        if azos_percpu::nr_cpu_ids() < FIFO_CONTENDERS {
            return Err("needs 4 CPUs (one contender per CPU)");
        }
        let r = Ordering::Relaxed;
        *FIFO_L.lock() = 0;
        FIFO_COUNT.store(0, r);
        FIFO_READY.store(0, r);
        FIFO_DONE.store(0, Ordering::Release);
        let p = azos_sched::DEFAULT_PRIORITY;
        for c in 0..FIFO_CONTENDERS {
            azos_sched::task_create_affinity("spin-fifo", fifo_contender, c, p, c as i8);
        }
        wait("the four SpinLock contenders did not finish", || FIFO_DONE.load(Ordering::Acquire) == FIFO_CONTENDERS)?;
        let n = FIFO_CONTENDERS as u64 * FIFO_ROUNDS;
        if *FIFO_L.lock() != n {
            return Err("four CPUs lost an increment under the SpinLock");
        }
        let (mut over, mut late, mut wmax, mut wsum) = (0u64, 0u64, 0u64, 0u64);
        for c in 0..FIFO_CONTENDERS {
            over = over.max(FIFO_MAX_OVER[c].load(r));
            late += FIFO_LATE[c].load(r);
            wmax = wmax.max(FIFO_MAX_WAIT[c].load(r));
            wsum += FIFO_SUM_WAIT[c].load(r);
        }
        let ns = |t: u64| azos_sync::lockdep::ticks_to_us(t.saturating_mul(1000));
        kprintln!("# spin_lock_fifo_bounded: impl={} contenders={} acquisitions={} passed-by max={} late={} wait ns max={} avg={}",
            if azos_sync::qspinlock::ON { "mcs" } else { "ttas" }, FIFO_CONTENDERS, n, over, late, ns(wmax), ns(wsum) / n);
        if late > FIFO_LATE_MAX {
            return Err("waiters were passed over by more acquisitions than the CPUs ahead of them (not FIFO)");
        }
        Ok(())
    }
}
