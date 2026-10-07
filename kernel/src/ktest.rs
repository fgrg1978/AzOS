// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The in-kernel test runner (Kconfig `KTEST`, cargo feature `ktest`).
//!
//! `kernel_main` calls [`run`] after boot init, before the secondary harts
//! wake and before the scheduler starts, so no task has run yet. Every test
//! registered with `azos_ktest::ktest!` runs in name order on the boot hart,
//! and the console gets TAP:
//!
//! ```text
//! 1..N
//! # ktest 1 <name>          (printed before the test runs)
//! ok 1 - <name>
//! not ok 2 - <name> # <reason>
//! # ktest: N tests, P passed, F failed (<isa>)
//! ```
//!
//! then the machine powers off (on riscv64 QEMU, with exit status 1 when a
//! test failed; see [`power_off`]). A test that panics cannot be resumed (the
//! kernel does not unwind): the panic handler calls [`on_panic`], which
//! prints that test's `not ok ... # panic at <file>:<line>` and a `Bail out!`
//! line, so the run reads as failed and the tests after it as not run.
//!
//! The tests themselves live next to the code they check; the few that need
//! boot-time values (the image layout, which only the ISA boot hook knows)
//! read them from [`note_image`].
use core::sync::atomic::{AtomicUsize, Ordering};

use azos_drv_sys::kprintln;

fn isa() -> &'static str {
    if cfg!(target_arch = "riscv64") { "riscv64" } else if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" }
}

/// Power off. On riscv64 QEMU a failed run exits through the `sifive_test`
/// finisher with status 1 (OpenSBI's SRST shutdown writes the finisher 16
/// bits wide, so a failure reason there still reaches the host as 0, which
/// was measured). aarch64's PSCI `SYSTEM_OFF` has no reason field, so QEMU
/// exits 0 either way there; the gate reads the TAP lines on both ISAs.
fn power_off(failed: bool) -> ! {
    // arch-only: QEMU riscv64 virt's sifive_test finisher; no other ISA's
    // QEMU machine has a power-off that carries a status.
    #[cfg(all(target_arch = "riscv64", feature = "qemu"))]
    if failed {
        const FINISHER_FAIL: u32 = 0x3333;
        let base = azos_drv_base::platform::hw::TEST_FINISHER_BASE;
        if azos_mm::vmm::map_mmio_region(base, 4).is_ok() {
            // SAFETY: QEMU virt's test device, identity-mapped just above;
            // the write ends the machine.
            unsafe { core::ptr::write_volatile(base as *mut u32, FINISHER_FAIL | (1 << 16)) };
        }
    }
    let _ = failed;
    use azos_arch::Boot;
    azos_arch::ARCH.shutdown()
}

/// Run every registered test, print TAP, power off.
pub(crate) fn run() {
    let tests = azos_ktest::all();
    let n = tests.len();
    if let Some(name) = azos_ktest::duplicate(tests) {
        kprintln!("Bail out! ktest: the name {} is registered twice", name);
        power_off(true);
    }
    kprintln!("1..{}", n);
    let mut failed = 0usize;
    for r in 0..n {
        let Some(t) = azos_ktest::nth(tests, r) else { break };
        kprintln!("# ktest {} {}", r + 1, t.name);
        azos_ktest::set_current(r + 1);
        let verdict = (t.run)();
        azos_ktest::set_current(0);
        match verdict {
            Ok(()) => kprintln!("ok {} - {}", r + 1, t.name),
            Err(why) => {
                failed += 1;
                kprintln!("not ok {} - {} # {}", r + 1, t.name, why);
            }
        }
    }
    kprintln!("# ktest: {} tests, {} passed, {} failed ({})", n, n - failed, failed, isa());
    power_off(failed != 0)
}

/// The panic handler's hook: a panic during a test is that test's failure.
/// Returns when no test is running.
pub(crate) fn on_panic(info: &core::panic::PanicInfo) {
    let Some((i, t)) = azos_ktest::current() else { return };
    azos_ktest::set_current(0);
    match info.location() {
        Some(l) => kprintln!("not ok {} - {} # panic at {}:{}", i, t.name, l.file(), l.line()),
        None => kprintln!("not ok {} - {} # panic", i, t.name),
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
// Zicboz): the scalar fallback is chosen and this test is `not ok`.
azos_ktest::ktest! {
    // arch-only: Zicboz is a RISC-V extension; aarch64's counterpart,
    // DC ZVA, is not wired (its pages are zeroed with plain stores).
    #[cfg(target_arch = "riscv64")]
    fn mm_zicboz_zero_fill() {
        use azos_arch::mmu::PAGE_SIZE;
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
