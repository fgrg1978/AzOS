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
// put the tests (and their power-off) into a release or certifiable image
// either.
const _: () = assert!(
    azos_limits::BUILD_TYPE_DEV,
    "Kconfig KTEST must not reach a release or certifiable build (BUILD_TYPE): drop the `ktest` feature"
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
        unsafe { azos_arch_api::mmio::write32(base, FINISHER_FAIL | (1 << 16)) };
        // Never on to `shutdown`: its finisher write would replace the 1.
        azos_arch::ARCH.halt()
    }
    // arch-only: QEMU aarch64 virt's only exit that carries a status.
    #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "qemu"))]
    if azos_limits::KTEST_SEMIHOSTING_EXIT {
        azos_arch::firmware::semihosting_exit(failed as u32)
    }
    // x86_64 QEMU: the isa-debug-exit port carries a status (QEMU exits with
    // 2 * value + 1): a failed run exits 3, a clean one 1. Written ONCE, then
    // halt: the write only requests the exit, and a second one (`shutdown`'s
    // own 0) could land first and turn a failed run's 3 into 1.
    // arch-only: no other ISA's QEMU machine has this port.
    #[cfg(all(target_arch = "x86_64", target_os = "none", feature = "qemu"))]
    {
        azos_arch::cpu::outl(azos_arch::cpu::DEBUG_EXIT_PORT, failed as u32);
        azos_arch::cpu::halt_forever()
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

/// Lockdep violations counted before the first test ([`run`]): boot's. The
/// early test `lockdep_boot_phase_clean` fails on them and claims them, so
/// a boot-phase violation is a named `not ok`, not the summary's bail-out.
static LOCKDEP_BOOT: AtomicUsize = AtomicUsize::new(0);

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
    LOCKDEP_BOOT.store(azos_sync::lockdep::violations() as usize, Ordering::Relaxed);
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
    kprintln!("\n# lockdep: violations={} notes={} edges={} chains={} unmatched-releases={} unprinted={} checked: switches={} sleeps={} user-returns={} scopes={} contended={} rt-cross-cpu={} classes={} classes-full={} hold-bound={}us{}",
        st.violations, st.notes, st.edges, st.chains, st.unmatched, azos_sync::lockdep::dropped(),
        st.switches, st.sleep_checks, st.user_returns, st.scope_checks, st.contended, st.rt_cross_cpu, st.classes,
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

/// Sleep 10 ms at a time until `ready()` holds; false after as many sleeps as
/// Kconfig `KTEST_LATE_TIMEOUT_MS` holds. The bound is a hang detector counted
/// in sleeps, not a deadline on the clock: the clock runs on while the host
/// keeps the vCPUs off, a sleep this CPU never finished does not count, and
/// each one lasts at least its 10 ms.
pub(crate) fn until(mut ready: impl FnMut() -> bool) -> bool {
    const STEP_MS: u64 = 10;
    for _ in 0..azos_limits::KTEST_LATE_TIMEOUT_MS as u64 / STEP_MS {
        if ready() {
            return true;
        }
        azos_syscall::sleep::sleep_ms(STEP_MS);
    }
    ready()
}

/// [`until`], with `Err(why)` when it gives up: a late test's wait on the tasks
/// it started.
pub(crate) fn wait(why: &'static str, ready: impl FnMut() -> bool) -> Result<(), &'static str> {
    if until(ready) {
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

/// The device tree blob's physical `[start, end)`, as `early_main` reserved
/// it; `(0, 0)` when the firmware handed none.
static FDT: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];

pub(crate) fn note_fdt(range: Option<(usize, usize)>) {
    let (start, end) = range.unwrap_or((0, 0));
    FDT[0].store(start, Ordering::Relaxed);
    FDT[1].store(end, Ordering::Relaxed);
}

// The device tree blob is out of the page allocator: every page of it is
// reserved, or outside the managed range where nothing can hand it out.
// `kernel_main` parses it again long after `pmm::init` (the SoC frameworks,
// hwbus, entropy, energy, thermal, the CPU topology), so a free page of it
// is one the allocator may give away under those readers. Runtime canary
// `fdt-reserve-skip` (the boot reserves nothing).
azos_ktest::ktest! {
    // arch-only: x86_64 boots with PVH start_info and an E820 map, which its
    // own `reserve_firmware_table` keeps out of the allocator.
    #[cfg(not(target_arch = "x86_64"))]
    fn mm_fdt_reserved() {
        use azos_mm::frame::F_RESERVED;
        let (start, end) = (FDT[0].load(Ordering::Relaxed), FDT[1].load(Ordering::Relaxed));
        if end == 0 {
            return Err("the boot recorded no device tree");
        }
        let mut page = start & !(azos_arch::PAGE_SIZE - 1);
        while page < end {
            match azos_mm::pmm::frame_state(page) {
                None => {}
                Some(F_RESERVED) => {}
                Some(_) => return Err("a page of the device tree is free or allocated in the page allocator"),
            }
            page += azos_arch::PAGE_SIZE;
        }
        Ok(())
    }
}

// Every kernel-image page carries the permissions planned for its section:
// .text RX, .rodata RO, data/bss RW, none W+X, all 4 KiB leaves, the only
// unmapped ones the task-stack guards. The page table is read back, not the enforcement call's own claim. Canary
// `canary=wx-skip` (the boot skips `enforce_wx`).
azos_ktest::ktest! {
    // REQ-013
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

// The set-once hooks and the x86_64 IDT (`.data.ro_after_init`) are sealed
// before the ktests run: the flag is set, a hook refuses a late installer, and
// every mapping of the section reads back read-only (the page table is read,
// not the seal's own claim). Canary `canary=ro-seal-skip` (the boot never
// seals): the first check fails.
azos_ktest::ktest! {
    fn mm_ro_after_init_sealed() {
        use azos_common::hook::{is_sealed, Hook, SetError};
        fn late() {}
        if !is_sealed() {
            return Err("the boot never sealed the hooks");
        }
        let probe: Hook<fn()> = Hook::new("ktest probe");
        if probe.try_set(late) != Err(SetError::Sealed) {
            return Err("a hook accepted an installer after the seal");
        }
        let rep = azos_mm::vmm::verify_ro_after_init();
        if rep.checked == 0 {
            Err("no .data.ro_after_init page checked")
        } else if !rep.is_clean() {
            Err(".data.ro_after_init has a page that is not read-only")
        } else {
            Ok(())
        }
    }
}

// Virtual KASLR: a pointer the linker stored in data (one `R_*_RELATIVE` entry,
// zero until the boot's walk) and the same function's address as the code
// computes it (PC-relative, right wherever the image runs) must be one number.
// A walk that applied the wrong delta, skipped an entry or ran after the
// pointer was used makes them differ. With the policy `n` it is trivially true.
// The slid image's own address is also in the ISA's window, and a boot that
// reports sliding agrees with `is_image_va`.
azos_ktest::ktest! {
    fn kaslr_stored_pointers_follow_the_image() {
        #[inline(never)]
        fn probe() -> usize {
            0x4B41_534C_5232
        }
        static TABLE: [fn() -> usize; 1] = [probe];
        // SAFETY: a volatile read of a live static, so the load is not folded
        // into the constant the code would compute.
        let stored = unsafe { core::ptr::read_volatile(&TABLE[0]) };
        let direct = core::hint::black_box(probe as fn() -> usize);
        if stored as usize != direct as usize {
            return Err("a function pointer stored in data differs from its PC-relative address");
        }
        if stored() != 0x4B41_534C_5232 {
            return Err("the relocated function pointer does not reach the function");
        }
        // SAFETY: a linker symbol's address, not dereferenced.
        let text = unsafe { &crate::_text_start as *const u8 as usize };
        if azos_arch::mmu::kaslr::image_slid() && !azos_mm::addr::is_image_va(text) {
            return Err("the boot reports a slid image, but its text is not in the image window");
        }
        Ok(())
    }
}

// Virtual KASLR (Kconfig `KASLR`, every ISA): a separate image is one set of frames
// at two addresses. A static read through its image address and through the
// linear-map alias of its frame (`phys_to_virt(virt_to_phys(..))`) is the same
// word, the image address is in the image window when the boot slid, and
// `virt_to_phys` of an image address is the frame the loader put it in (the
// image's first byte, `_text_start`, is `image_phys` of its own address).
// Elsewhere, and where the boot did not slide, the two addresses are equal.
azos_ktest::ktest! {
    fn mm_kaslr_image_alias() {
        static PROBE: AtomicUsize = AtomicUsize::new(0x4B41_534C_5231);
        let va = &PROBE as *const AtomicUsize as usize;
        let pa = azos_mm::addr::virt_to_phys(va);
        let alias = azos_mm::addr::phys_to_virt(pa);
        if azos_mm::addr::image_is_separate() {
            if va == alias {
                return Err("a slid image address equals its linear-map alias");
            }
            if !azos_mm::addr::is_image_va(va) {
                return Err("a separate image is outside the image region");
            }
        }
        // SAFETY: the alias maps the frame of a live static, readable.
        let seen = unsafe { core::ptr::read_volatile(alias as *const usize) };
        if seen != 0x4B41_534C_5231 {
            return Err("the linear-map alias of a static does not read the static");
        }
        Ok(())
    }
}

// Nothing executable is mapped outside the kernel image in the kernel's own
// table (heap, frames, task stacks). Canary `canary=nx-skip` (the boot strips
// nothing).
azos_ktest::ktest! {
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

// Type zones of physical frames (Kconfig `PMM_TYPE_ZONES`, `crates/core/mm/src/zone.rs`):
// a page-table frame, once freed, is held by its zone: tagged, and none of a
// run of general allocations is handed it. The tag is read back from the
// frame descriptor, which does not depend on which hart the free landed on;
// the run of general pages is the behaviour. Canary `zone-share-canary`
// (`pmm::free` drops the tag and gives the frame to the cache and the buddy
// lists): the descriptor check fails, and the frame is usually the first
// general page handed out.
azos_ktest::ktest! {
    fn mm_zone_no_cross_type_reuse() {
        use azos_mm::{pmm, zone::Zone};
        if !pmm::zones_on() {
            return Err("the frame zones are off in this configuration");
        }
        let pt = pmm::alloc_page_zone(Zone::PageTable).map_err(|_| "a zoned allocation was refused")?;
        let phys = pt.as_usize();
        pmm::free_page(pt).map_err(|_| "a zoned frame was refused by free")?;
        let mut verdict = Ok(());
        if pmm::frame_zone(phys) != Some(Zone::PageTable) {
            verdict = Err("a freed page-table frame lost its zone");
        }
        // More than a hart's cache and a refill hold, so the frame would be
        // among them were it on the general lists.
        const RUN: usize = 192;
        let mut got = [0usize; RUN];
        let mut n = 0;
        while n < RUN {
            let Ok(p) = pmm::alloc_page() else { break };
            got[n] = p.as_usize();
            if got[n] == phys && verdict.is_ok() {
                verdict = Err("a freed page-table frame was handed out as a general page");
            }
            n += 1;
        }
        for &p in &got[..n] {
            let _ = pmm::free_page(azos_mm::addr::PhysAddr::new(p));
        }
        if verdict.is_ok() && pmm::zone_pages(Zone::PageTable).0 == 0 {
            verdict = Err("the zone holds no free frame after a free");
        }
        verdict
    }
}

// Every task stack's bottom page is unmapped in the kernel's table, read
// back through a fresh walk (`[MM] Stack guard readback`), so an overflow
// faults instead of running into the next stack.
azos_ktest::ktest! {
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
// per-hart cache hands back the newest frame, the same one) must read back all zero:
// the zero-fill `alloc_page` runs is `cbo.zero` here, not the host tests'
// scalar stand-in. Canary `canary=zicboz-skip` (the boot ignores the DTB's
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
            return if azos_arch::cache::zicboz_available() {
                Err("RV_ZICBOZ is n but the Zicboz fast path was selected")
            } else {
                Ok(())
            };
        }
        if !azos_arch::cache::zicboz_available() {
            return Err("the Zicboz fast path is off (scalar fallback) on a CPU that has Zicboz");
        }
        if azos_arch::cache::zicboz_block_size() == 0 {
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

// `canary=lockdep-early-abba` (from `early_main`, before the scheduler and
// before this runner): the ABBA `lockdep_lock_order_consistent` plants, on
// two other classes, from boot. Lockdep checks order from the first lock;
// this is the proof, and `lockdep_boot_phase_clean` the verdict.
static LD_EARLY_A: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);
static LD_EARLY_B: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);

/// Called once by `early_main` (boot hart, interrupts off, one CPU): with
/// the canary armed, A then B, then B then A. Single-threaded, so the
/// second order cannot deadlock; lockdep reports it before the spin.
pub(crate) fn lockdep_early_abba() {
    if azos_sync::lockdep::ON && canary!("lockdep-early-abba") {
        for first in [true, false] {
            let (x, y) = if first { (&LD_EARLY_A, &LD_EARLY_B) } else { (&LD_EARLY_B, &LD_EARLY_A) };
            let mut gx = x.lock();
            let mut gy = y.lock();
            *gx += 1;
            *gy += 1;
        }
    }
}

azos_ktest::ktest! {
    fn lockdep_boot_phase_clean() {
        if !azos_sync::lockdep::ON {
            return Err("LOCKDEP is not on in this ktest kernel (Kconfig LOCKDEP_KTEST or LOCKDEP_Y)");
        }
        // Claimed once (the runner counts a violation outside any test).
        let n = LOCKDEP_BOOT.swap(0, Ordering::Relaxed);
        if n != 0 {
            LOCKDEP_IN_TESTS.fetch_add(n, Ordering::Relaxed);
            kprintln!("# lockdep: {} violation(s) before the first test (the `# lockdep:` lines above)", n);
            return Err("lockdep violation during boot, before the scheduler");
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

// The ring-3 link-key read (the `linkkey` endpoint) runs its reader, a
// block-layer read of the reserved sector, with no SpinLock held: the hook
// is copied out of its lock first. The boot's reader returns before the
// block layer on a kernel without a disk, and no ktest reached the syscall,
// so lockdep never saw the guard that used to live through the call. This
// probe reader enters the block layer unconditionally (an error without a
// disk; the lockdep check is at the layer's entry). A late test: lockdep's
// sleep and device-wait checks start at a CPU's first context switch.
fn link_key_probe_reader(out: &mut [u8; azos_syscall::link_key::LINK_KEY_BYTES]) -> bool {
    let mut sector = [0u8; 512];
    let _ = azos_drv_block::blkdev::read(0, 1, &mut sector);
    out[0] = 1;
    true
}

azos_ktest::ktest_late! {
    fn link_key_hook_runs_unlocked() {
        use azos_syscall::link_key::{read_key_via_hook, replace_link_key_read_hook, LINK_KEY_BYTES};
        if !azos_sync::lockdep::ON {
            return Err("LOCKDEP is not on in this ktest kernel (Kconfig LOCKDEP_KTEST or LOCKDEP_Y)");
        }
        let prev = replace_link_key_read_hook(Some(link_key_probe_reader));
        let mut key = [0u8; LINK_KEY_BYTES];
        let got = read_key_via_hook(&mut key);
        replace_link_key_read_hook(prev);
        if !got || key[0] != 1 {
            return Err("the installed link-key reader did not run");
        }
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
// The holder keeps the lock until lockdep counts the contender's contended
// path on THIS lock (`watch_contended`): the global `Stats::contended` moves
// with every lock in the kernel, and releasing on it let the contender take
// LD_PI on its fast path, no F7 check, a canary boot that stayed `ok`.
static LD_PI: azos_sync::kmutex::Mutex<u32> = azos_sync::kmutex::Mutex::new(0);
static LD_PI_HELD: AtomicBool = AtomicBool::new(false);
/// Set by the contender just before its `lock()`: diagnostics only.
static LD_PI_WAITING: AtomicBool = AtomicBool::new(false);
static LD_PI_DONE: AtomicUsize = AtomicUsize::new(0);

/// The holder's deadline: a quarter of the runner's wait, so a contender
/// that never arrives ends in the runner's checks, not its timeout.
const LD_PI_HOLD_MS: u64 = azos_limits::KTEST_LATE_TIMEOUT_MS as u64 / 4;

fn ld_pi_holder(_: usize) {
    let mut g = LD_PI.lock();
    LD_PI_HELD.store(true, Ordering::Release);
    let deadline = azos_drv_sys::timebase::now()
        .saturating_add(azos_syscall::sleep::ms_to_ticks(LD_PI_HOLD_MS));
    while azos_sync::lockdep::watched_contended_hits() == 0 {
        if azos_drv_sys::timebase::now() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
    *g += 1;
    drop(g);
    LD_PI_DONE.fetch_add(1, Ordering::Release);
}

fn ld_pi_contender(_: usize) {
    while !LD_PI_HELD.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    LD_PI_WAITING.store(true, Ordering::Release);
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
        LD_PI_WAITING.store(false, Ordering::Release);
        LD_PI_DONE.store(0, Ordering::Release);
        azos_sync::lockdep::watch_contended(&LD_PI as *const _ as usize);
        azos_sched::task_create_affinity("ld-pi-holder", ld_pi_holder, 0, rt, 1);
        azos_sched::task_create_affinity("ld-pi-contender", ld_pi_contender, 0, contender, 2);
        let done = wait("the Mutex holder and contender did not both finish", || LD_PI_DONE.load(Ordering::Acquire) == 2);
        let hits = azos_sync::lockdep::watched_contended_hits();
        let f7 = azos_sync::lockdep::watched_rt_cross_hits();
        azos_sync::lockdep::watch_contended(0);
        done?;
        if hits == 0 {
            return Err(if LD_PI_WAITING.load(Ordering::Acquire) {
                "the Mutex was never contended (holder timed out): rule F7 was not exercised"
            } else {
                "the contender never reached the Mutex: rule F7 was not exercised"
            });
        }
        // F7 is report-only (owner decision 10-10): lockdep notes it and the
        // runner fails nothing, so the test reads the rule's own counter.
        // Its pass side has a fair contender (no hit); `lockdep-rt-pi` makes
        // it RT, and a lockdep that misses the hit leaves this `ok`. Only a
        // hit on this test's lock counts (an RT task elsewhere may hit F7
        // meanwhile, a note of its own: one on seams.rs's lock, right after
        // this one, left `rt_cross_cpu_last` naming that lock).
        if f7 != 0 {
            return Err("lockdep noted RT tasks on CPUs 1 and 2 contending one Mutex (rule F7)");
        }
        Ok(())
    }
}


// ── Spin-wait and CAS (wave 15, N2) ─────────────────────────────────────────
//
// `SpinWait` (arch/api spin.rs) on the path this boot selected:
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
// acquisitions it was not yet queued for. Under the queued lock the count
// is therefore re-read where the lock fixes the waiter's turn
// (`qspinlock::order_mark`: its pending bit or its tail CAS), and an
// acquisition that took the fast path (a word of 0: nobody held or waited)
// passed nobody; the arrival read stays for the test-and-set lock, which
// has no such point. Gate 8cd61b5a (`ktest futex canary (rv)`): mcs, one
// waiter passed by 2780 in a 4.2 ms host pause before its enqueue (late=3).
// `marked` counts the acquisitions the hook saw: 0 under mcs means the
// hook is dead and the verdict would be vacuous, so the test fails.
// The test sums every bypass past the bound (`excess`) and fails above an
// eighth of the acquisitions.
// Measured on rv64, 8000 acquisitions, gate MTTCG: mcs excess 0-49 (late
// 0-6; 21 late at host load 22), ttas 8140-11820 (passed-by max
// 2176-4125). Under -icount -smp 4: mcs passed-by max 3, ttas 1486.

const FIFO_CONTENDERS: usize = 4;
const FIFO_ROUNDS: u64 = 2_000;
/// A host that never runs two contenders at once queues nobody in
/// `FIFO_ROUNDS`: they go on until the hook has fired, up to this many.
const FIFO_ROUNDS_MAX: u64 = 16 * FIFO_ROUNDS;

static FIFO_L: azos_sync::SpinLock<u64> = azos_sync::SpinLock::new(0);
static FIFO_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FIFO_READY: AtomicUsize = AtomicUsize::new(0);
static FIFO_DONE: AtomicUsize = AtomicUsize::new(0);
static FIFO_ABORT: AtomicBool = AtomicBool::new(false);
/// The arrivals the contender that gave up saw (the start barrier's count).
static FIFO_ABORT_SEEN: AtomicUsize = AtomicUsize::new(0);
static FIFO_MAX_OVER: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_LATE: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_EXCESS: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_MAX_WAIT: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_SUM_WAIT: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_MARKED: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_ROUNDS_RUN: [core::sync::atomic::AtomicU64; FIFO_CONTENDERS] = [const { core::sync::atomic::AtomicU64::new(0) }; FIFO_CONTENDERS];
static FIFO_ANY_MARK: AtomicBool = AtomicBool::new(false);
/// The count each CPU read where the queued lock fixed its turn (by
/// `ARCH.hart_id()`, the index `qspinlock` keys its nodes by).
const FIFO_NO_MARK: u64 = u64::MAX;
static FIFO_MARK: [core::sync::atomic::AtomicU64; azos_limits::NR_CPUS as usize] =
    [const { core::sync::atomic::AtomicU64::new(FIFO_NO_MARK) }; azos_limits::NR_CPUS as usize];

/// `qspinlock::order_mark`'s hook for `FIFO_L`.
fn fifo_order_mark() {
    use azos_arch::{Cpu as _, ARCH};
    if let Some(m) = FIFO_MARK.get(ARCH.hart_id()) {
        m.store(FIFO_COUNT.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

fn fifo_contender(c: usize) {
    use azos_arch::{Cpu as _, Interrupts as _, ARCH};
    let r = Ordering::Relaxed;
    // Start together: a contender that ran alone would measure nothing.
    // Bounded, and yielding: a contender whose sibling never starts gives
    // up (the test fails) instead of holding its CPU.
    FIFO_READY.fetch_add(1, Ordering::AcqRel);
    let start = ARCH.now_ticks();
    while FIFO_READY.load(Ordering::Acquire) < FIFO_CONTENDERS {
        let waited_us = azos_sync::lockdep::ticks_to_us(ARCH.now_ticks().wrapping_sub(start));
        if waited_us > azos_limits::KTEST_LATE_TIMEOUT_MS as u64 * 1000 / 2 {
            FIFO_ABORT_SEEN.store(FIFO_READY.load(Ordering::Acquire), Ordering::Relaxed);
            FIFO_ABORT.store(true, Ordering::Release);
            FIFO_DONE.fetch_add(1, Ordering::Release);
            return;
        }
        azos_sched::task_yield();
    }
    let (mut max_over, mut late, mut excess, mut max_wait, mut sum_wait, mut marked) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut rounds = 0u64;
    while rounds < FIFO_ROUNDS
        || (azos_sync::qspinlock::ON && rounds < FIFO_ROUNDS_MAX && !FIFO_ANY_MARK.load(r))
    {
        rounds += 1;
        let s = ARCH.disable_all();
        let mark = FIFO_MARK.get(ARCH.hart_id());
        if let Some(m) = mark {
            m.store(FIFO_NO_MARK, r);
        }
        let (mut c0, mut t0) = (0, 0);
        // The counter read last: under MTTCG an aarch64 timer read can wait
        // on QEMU's global lock, which would widen the arrival window.
        let mut g = FIFO_L.lock_marked(|| {
            t0 = ARCH.now_ticks();
            c0 = FIFO_COUNT.load(r);
        });
        let t1 = ARCH.now_ticks();
        let c1 = FIFO_COUNT.load(r);
        if azos_sync::qspinlock::ON {
            match mark.map_or(FIFO_NO_MARK, |m| m.load(r)) {
                FIFO_NO_MARK => c0 = c1,
                m => {
                    c0 = m;
                    marked += 1;
                    FIFO_ANY_MARK.store(true, r);
                }
            }
        }
        FIFO_COUNT.store(c1 + 1, r);
        *g += 1;
        core::hint::black_box(&mut *g);
        drop(g);
        ARCH.restore(s);
        let over = c1 - c0;
        max_over = max_over.max(over);
        if over > (FIFO_CONTENDERS - 1) as u64 {
            late += 1;
            excess += over - (FIFO_CONTENDERS - 1) as u64;
        }
        let w = t1.wrapping_sub(t0);
        max_wait = max_wait.max(w);
        sum_wait += w;
    }
    FIFO_MAX_OVER[c].store(max_over, r);
    FIFO_LATE[c].store(late, r);
    FIFO_EXCESS[c].store(excess, r);
    FIFO_MAX_WAIT[c].store(max_wait, r);
    FIFO_SUM_WAIT[c].store(sum_wait, r);
    FIFO_MARKED[c].store(marked, r);
    FIFO_ROUNDS_RUN[c].store(rounds, r);
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
        FIFO_ABORT.store(false, Ordering::Release);
        azos_sync::qspinlock::order_mark::set(FIFO_L.word_addr(), Some(fifo_order_mark));
        // DEFAULT_PRIORITY, above the runner's: the contenders must not be
        // preempted by ordinary kernel tasks, or they stop contending. The
        // one on CPU 0 holds the runner off until it finishes or its bounded
        // start barrier gives up, so it is created LAST: the runner is
        // pinned to CPU 0 (`late_run`), and `task_yield` never cedes to a
        // lower priority. Created first, a tick between two creations (a
        // host pause stretches the loop past one) ran it, and it yielded
        // to itself for the whole barrier while the runner, holding the
        // other creations, never ran: "a contender did not start" (gate
        // 8cd61b5a, `ktest exit status canary (rv)`).
        let p = azos_sched::DEFAULT_PRIORITY;
        for c in (0..FIFO_CONTENDERS).rev() {
            azos_sched::task_create_affinity("spin-fifo", fifo_contender, c, p, c as i8);
        }
        let done = wait("the four SpinLock contenders did not finish", || FIFO_DONE.load(Ordering::Acquire) == FIFO_CONTENDERS);
        azos_sync::qspinlock::order_mark::set(0, None);
        done?;
        if FIFO_ABORT.load(Ordering::Acquire) {
            kprintln!("# spin_lock_fifo_bounded: start barrier gave up with {} of {} contenders arrived",
                FIFO_ABORT_SEEN.load(Ordering::Relaxed), FIFO_CONTENDERS);
            return Err("a contender did not start (the four never ran together)");
        }
        let n: u64 = FIFO_ROUNDS_RUN.iter().map(|a| a.load(r)).sum();
        if *FIFO_L.lock() != n {
            return Err("four CPUs lost an increment under the SpinLock");
        }
        let (mut over, mut late, mut excess, mut wmax, mut wsum, mut marked) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        for c in 0..FIFO_CONTENDERS {
            over = over.max(FIFO_MAX_OVER[c].load(r));
            late += FIFO_LATE[c].load(r);
            excess += FIFO_EXCESS[c].load(r);
            wmax = wmax.max(FIFO_MAX_WAIT[c].load(r));
            wsum += FIFO_SUM_WAIT[c].load(r);
            marked += FIFO_MARKED[c].load(r);
        }
        let ns = |t: u64| azos_sync::lockdep::ticks_to_us(t.saturating_mul(1000));
        kprintln!("# spin_lock_fifo_bounded: impl={} contenders={} acquisitions={} marked={} passed-by max={} late={} excess={} wait ns max={} avg={}",
            if azos_sync::qspinlock::ON { "mcs" } else { "ttas" }, FIFO_CONTENDERS, n, marked, over, late, excess, ns(wmax), ns(wsum) / n);
        if azos_sync::qspinlock::ON && marked == 0 {
            return Err("the queued lock never fixed a waiter's turn (order_mark dead: the FIFO verdict would be vacuous)");
        }
        // An eighth of the acquisitions; a test parameter.
        if excess > n / 8 {
            return Err("waiters were passed over by more acquisitions than the CPUs ahead of them (not FIFO)");
        }
        Ok(())
    }
}

// ── A shootdown reaches a lock waiter with interrupts masked ───────────────
//
// The runner (CPU 0) holds a SpinLock with interrupts masked and shoots a
// kernel page down on every CPU while a task on CPU 1 waits for the same lock
// in `lock_irqsave`: the shape of any shootdown issued under an irqsave lock
// (text_poke's, a page-table lock's; a MemObj revoke's while MEMOBJS was one,
// before it became a preempt-off lock) against a waiter on another CPU. On x86_64
// without INVLPGB the shootdown is an IPI the runner waits for, the waiter
// cannot take it, and only the lock's wait loop answering it
// (`SpinWait::wait_service`) lets the flush return. riscv64's SBI fences and
// aarch64's broadcast TLBI never wait for the waiter: there the test passes by
// construction and keeps the property on every ISA. The waiter is known to be
// in the lock's wait before the flush under the queued lock (its pending bit
// or queue tail is in the word); under the test-and-set lock it is given
// SD_WAIT_SPINS polls to get there. The waiter's CPU is a target whatever it
// ran before: every online CPU publishes its root when it comes online
// (x86_64 `tlb::join`; ktest `tlb_kernel_shootdown_names_every_online_cpu`).
// Canary `spin-service-canary` (by hand, x86_64 -smp 4): the flush never
// returns and the run hangs at this test, CPU 0 masked.

/// Polls the runner gives a test-and-set waiter to reach its wait steps.
const SD_WAIT_SPINS: u32 = 100_000;

static SD_L: azos_sync::SpinLock<u64> = azos_sync::SpinLock::new(0);
/// 0 idle, 1 the runner holds the lock, 2 the waiter is at the lock, 3 it took it.
static SD_STAGE: AtomicUsize = AtomicUsize::new(0);

fn sd_waiter(_: usize) {
    while SD_STAGE.load(Ordering::Acquire) == 0 {
        azos_sched::task_yield();
    }
    SD_STAGE.store(2, Ordering::Release);
    let mut g = SD_L.lock_irqsave();
    *g += 1;
    drop(g);
    SD_STAGE.store(3, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn shootdown_reaches_a_masked_lock_waiter() {
        use azos_arch::{ArchPlatform as _, Cpu as _, ARCH};
        if azos_percpu::nr_cpu_ids() < 2 {
            return Err("needs 2 CPUs (the holder and the waiter)");
        }
        *SD_L.lock() = 0;
        SD_STAGE.store(0, Ordering::Release);
        azos_sched::task_create_affinity("sd-waiter", sd_waiter, 0, azos_sched::DEFAULT_PRIORITY, 1);
        let g = SD_L.lock_irqsave();
        SD_STAGE.store(1, Ordering::Release);
        // SAFETY: the lock word is an aligned `u32` of a static lock.
        let word = unsafe { &*(SD_L.word_addr() as *const core::sync::atomic::AtomicU32) };
        let start = ARCH.now_ticks();
        let limit_us = azos_limits::KTEST_LATE_TIMEOUT_MS as u64 * 1000 / 2;
        let mut spins = 0u32;
        let waiting = loop {
            let at_lock = SD_STAGE.load(Ordering::Acquire) == 2;
            if at_lock && azos_sync::qspinlock::ON && word.load(Ordering::Relaxed) & !0xff != 0 {
                break true;
            }
            if at_lock && !azos_sync::qspinlock::ON {
                spins += 1;
                if spins >= SD_WAIT_SPINS {
                    break true;
                }
            }
            if azos_sync::lockdep::ticks_to_us(ARCH.now_ticks().wrapping_sub(start)) > limit_us {
                break false;
            }
            core::hint::spin_loop();
        };
        if waiting {
            ARCH.flush_tlb_page_all(&SD_L as *const _ as usize & !(azos_arch::PAGE_SIZE - 1));
        }
        drop(g);
        wait("the masked waiter never took the lock", || SD_STAGE.load(Ordering::Acquire) == 3)?;
        if !waiting {
            return Err("the waiter never reached the lock's wait (the flush would test nothing)");
        }
        if *SD_L.lock() != 1 {
            return Err("the waiter's increment is missing");
        }
        Ok(())
    }
}

// ── FAT32 claim priority donation (FX12) ────────────────────────────────────
//
// A claim owner at fs-wb's priority and a waiter at log-flush's priority,
// both on CPU 1. The waiter lends its priority to the owner, which watches
// its own live priority while it holds the claim and must see the waiter's.
// The fair class is EEVDF: a fair priority is a weight, not a rank, so a
// busy task between the two no longer starves an unboosted owner and the
// wait time could not tell a donation from none; the lent priority (the
// owner's weight while it holds) is read directly instead. Without the
// donation (`canary=claim-no-donate`) the owner keeps its own priority until
// it gives up, CLAIM_PI_GIVE_UP_MS later.

/// How long the owner holds the claim waiting to be lent a priority, in ms.
const CLAIM_PI_GIVE_UP_MS: u64 = 1000;

static CLAIM_PI_HELD: AtomicBool = AtomicBool::new(false);
static CLAIM_PI_DONE: AtomicUsize = AtomicUsize::new(0);
/// The most urgent priority the owner saw itself at while holding.
static CLAIM_PI_SEEN: AtomicUsize = AtomicUsize::new(0);

fn claim_pi_now_ms() -> u64 {
    azos_drv_sys::timebase::now() / (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1)
}

fn claim_pi_owner(_: usize) {
    let me = azos_sync::waitqueue::caller_tid();
    let base = azos_limits::FS_WRITEBACK_PRIORITY as u32;
    azos_fs::fat32_ktest_with_wb_claim(|| {
        CLAIM_PI_HELD.store(true, Ordering::Release);
        let t0 = claim_pi_now_ms();
        let mut seen = base;
        while seen >= base && claim_pi_now_ms().wrapping_sub(t0) < CLAIM_PI_GIVE_UP_MS {
            seen = seen.min(azos_sched::task_priority(me).unwrap_or(base));
            core::hint::spin_loop();
        }
        CLAIM_PI_SEEN.store(seen as usize, Ordering::Release);
    });
    CLAIM_PI_DONE.fetch_add(1, Ordering::Release);
}

fn claim_pi_waiter(_: usize) {
    azos_fs::fat32_ktest_with_wb_claim(|| {});
    CLAIM_PI_DONE.fetch_add(1, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn fat_claim_waiter_donates_to_owner() {
        if azos_percpu::nr_cpu_ids() < 2 {
            return Err("needs 2 CPUs (the runner on 0, owner and waiter on 1)");
        }
        let owner = azos_limits::FS_WRITEBACK_PRIORITY as u32;
        let waiter = azos_limits::LOG_FLUSHER_PRIORITY as u32;
        if waiter >= owner {
            return Err("LOG_FLUSHER_PRIORITY is not more urgent than FS_WRITEBACK_PRIORITY: nothing to lend");
        }
        CLAIM_PI_HELD.store(false, Ordering::Release);
        CLAIM_PI_DONE.store(0, Ordering::Release);
        CLAIM_PI_SEEN.store(usize::MAX, Ordering::Release);
        azos_sched::task_create_affinity("claim-pi-owner", claim_pi_owner, 0, owner, 1);
        wait("the claim owner never took the write-back claim", || CLAIM_PI_HELD.load(Ordering::Acquire))?;
        azos_sched::task_create_affinity("claim-pi-waiter", claim_pi_waiter, 0, waiter, 1);
        wait("owner and waiter did not both finish", || CLAIM_PI_DONE.load(Ordering::Acquire) == 2)?;
        let seen = CLAIM_PI_SEEN.load(Ordering::Acquire);
        kprintln!("# fat_claim_waiter_donates_to_owner: owner prio {} waiter {}: owner ran at {} while holding",
            owner, waiter, seen);
        if seen != waiter as usize {
            return Err("the claim owner did not run at its waiter's priority (no donation)");
        }
        Ok(())
    }
}

/// How long `preempt_count_survives_irq_nesting` waits for three ticks, in ms.
const PREEMPT_NEST_MS: u64 = 500;

azos_ktest::ktest_late! {
    fn preempt_count_survives_irq_nesting() {
        use azos_sync::preempt;
        // Chain E commit 7: the per-hart depth moves by a load and a store,
        // not an RMW. Sound only if every interrupt that lands between the
        // two leaves the slot as it found it. Here a real timer interrupt
        // takes a guard (`preempt::ktest_probe`, from `wake_expired_timers`)
        // on top of an outer guard this task holds, while this task takes
        // and drops an inner one in a tight loop, so some ticks land inside
        // a load-to-store window. `canary=preempt-isr-leak`: the interrupt
        // keeps its guard (a handler that is not depth-balanced); the count
        // must then come out wrong and this test fail.
        if !preempt::irqs_enabled() {
            return Err("the late runner runs with interrupts off: no tick can nest");
        }
        let d0 = preempt::depth();
        let (u0, _) = preempt::audit_counters();
        let fired0 = preempt::fired();
        let outer = azos_sync::critical_section();
        // Taken after the guard: this task cannot move harts from here on.
        let me = azos_arch::Cpu::hart_id(&azos_arch::ARCH);
        preempt::ktest_probe::arm(me, canary!("preempt-isr-leak"));
        let t0 = claim_pi_now_ms();
        let mut wrong = None;
        loop {
            let g = azos_sync::critical_section();
            let inside = preempt::depth();
            drop(g);
            let after = preempt::depth();
            if inside != d0 + 2 || after != d0 + 1 {
                wrong = Some((inside, after));
                break;
            }
            if preempt::ktest_probe::hits() >= 3
                || claim_pi_now_ms().wrapping_sub(t0) >= PREEMPT_NEST_MS {
                break;
            }
        }
        let (hits, deepest) = preempt::ktest_probe::disarm();
        let owed = preempt::need_resched();
        drop(outer);
        let end = preempt::depth();
        if end != d0 && d0 == 0 {
            // Only the canary gets here: put the leaked count back, or the
            // hart never preempts again.
            preempt::force_zero_depth();
        }
        kprintln!("# preempt_count_survives_irq_nesting: {} ticks took a guard, deepest {}, wrong {:?}, end {}",
            hits, deepest, wrong, end);
        if wrong.is_some() || end != d0 {
            return Err("the preempt count moved across a timer interrupt: a handler was not depth-balanced");
        }
        if hits == 0 {
            return Err("no timer interrupt took a guard on this hart while the outer one was held");
        }
        if deepest < d0 + 2 {
            return Err("the interrupt's guard did not nest on the outer one");
        }
        if !owed || preempt::fired() == fired0 {
            return Err("the ticks inside the section were not deferred and paid at its end");
        }
        if preempt::audit_counters().0 != u0 {
            return Err("an unbalanced release was counted");
        }
        Ok(())
    }
}

/// The probe of `sched_wake_preempts_a_worse_class_on_the_same_cpu`: the RT
/// task that sleeps until the fair task wakes it, and the facts the fair task
/// records right after.
static WP_HI_TID: AtomicUsize = AtomicUsize::new(0);
static WP_HI_ARMED: AtomicBool = AtomicBool::new(false);
static WP_GO: AtomicBool = AtomicBool::new(false);
static WP_HI_RAN: AtomicBool = AtomicBool::new(false);
/// Seen by the fair task: `need_resched` right after the wake, and whether
/// the RT task had run by the first preemption point after it.
static WP_OWED: AtomicBool = AtomicBool::new(false);
static WP_RAN_AT_POINT: AtomicBool = AtomicBool::new(false);

fn wp_hi(_: usize) {
    WP_HI_TID.store(azos_sync::waitqueue::caller_tid() as usize, Ordering::Release);
    while !WP_GO.load(Ordering::Acquire) {
        WP_HI_ARMED.store(true, Ordering::Release);
        azos_sched::wq_block_current();
    }
    WP_HI_RAN.store(true, Ordering::Release);
}

fn wp_lo(cpu: usize) {
    use azos_sync::preempt;
    // Same hart as the fair task, a band level (never the exempt loops').
    azos_sched::task_create_affinity("wp-hi", wp_hi, 0, 5, cpu as i8);
    if wait("the RT task never reached its sleep", || WP_HI_ARMED.load(Ordering::Acquire)).is_err() {
        return;
    }
    // Armed is set just before the block: let it commit before waking it, or
    // the wake is only stamped and nothing is enqueued to preempt for.
    let _ = azos_syscall::sleep::wait_until_ms(20, 5, || false);
    WP_GO.store(true, Ordering::Release);
    // No debt of an earlier tick: what is owed after the wake is the wake's.
    preempt::clear_need_resched();
    azos_sched::wq_wake_by_tid(WP_HI_TID.load(Ordering::Acquire) as u32);
    WP_OWED.store(preempt::need_resched(), Ordering::Release);
    // The first preemption point after the wake: an empty critical section
    // pays a debt `need_resched` recorded, with interrupts on.
    drop(azos_sync::critical_section());
    WP_RAN_AT_POINT.store(WP_HI_RAN.load(Ordering::Acquire), Ordering::Release);
}

azos_ktest::ktest_late! {
    fn sched_wake_preempts_a_worse_class_on_the_same_cpu() {
        // A fair task wakes an RT task pinned to its own hart. Before the
        // wake-up check the RT task waited for that hart's next tick; now the
        // wake records the debt (`need_resched`) and the first preemption
        // point pays it. Revert `wake_enqueue_preempting` in
        // crates/core/sched/src/scheduler/wake.rs to `wake_enqueue_locked`
        // and this test must fail (Kconfig SCHED_WAKE_PREEMPT_CANARY). This
        // covers the same-CPU half only: a wake onto another CPU adds no code
        // here, it relies on the doorbell the enqueue already rings
        // (`ring_doorbell`), and has no test or canary of its own.
        if !azos_sync::preempt::irqs_enabled() {
            return Err("the late runner runs with interrupts off: no preemption point can fire");
        }
        WP_HI_TID.store(0, Ordering::Release);
        WP_HI_ARMED.store(false, Ordering::Release);
        WP_GO.store(false, Ordering::Release);
        WP_HI_RAN.store(false, Ordering::Release);
        WP_OWED.store(false, Ordering::Release);
        WP_RAN_AT_POINT.store(false, Ordering::Release);
        let cpu = {
            let _g = azos_sync::critical_section();
            azos_arch::Cpu::hart_id(&azos_arch::ARCH) as usize
        };
        probe("wp-lo", wp_lo, cpu, azos_sched::DEFAULT_PRIORITY, cpu as i8)?;
        wait("the RT task never ran after its wake", || WP_HI_RAN.load(Ordering::Acquire))?;
        let (owed, ran) = (WP_OWED.load(Ordering::Acquire), WP_RAN_AT_POINT.load(Ordering::Acquire));
        kprintln!("# sched_wake_preempts_a_worse_class_on_the_same_cpu: hart {}: owed after wake {}, RT task ran by the first preemption point {}",
            cpu, owed, ran);
        if !owed {
            return Err("the wake of an RT task by a fair task on its hart left no reschedule owed");
        }
        if !ran {
            return Err("the RT task woken by a fair task on its hart did not run at the first preemption point");
        }
        Ok(())
    }
}
