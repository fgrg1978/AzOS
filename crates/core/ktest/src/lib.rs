// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The in-kernel test registry (Kconfig `KTEST`, kernel cargo feature `ktest`).
//!
//! [`ktest!`] defines a test, `fn() -> Result<(), &'static str>`, and places
//! one [`KTest`] entry for it in the `.azos_ktest` link section. Every kernel
//! linker script brackets that section with `__azos_ktest_start` /
//! `__azos_ktest_end`, right after the static-key table in `.rodata`, so the
//! entries are read-only data and [`all`] is a slice over them: no
//! constructor, no allocation, no fixed-size table to configure.
//!
//! The kernel depends on this crate only with its `ktest` feature
//! (`dep:azos_ktest`), and every `ktest!` site sits in a
//! `#[cfg(feature = "ktest")]` module: with the feature off the crate is not
//! in the kernel's dependency graph at all, so the image is the same bytes as
//! a kernel that never heard of it (the `.azos_ktest` section is empty). The
//! macro's own `#[cfg(feature = "ktest")]`, evaluated in the invoking crate,
//! is a second guard.
//!
//! Two phases share the section, told apart by [`KTest::phase`]:
//! [`EARLY`] tests ([`ktest!`]) run on the boot hart before the scheduler
//! starts; [`LATE`] tests ([`ktest_late!`]) run in a kernel task after it
//! started, with every hart online, so they may create tasks and block.
//!
//! Order is by phase, then by name ([`nth`]), not link order, so adding a
//! test in one file does not renumber the TAP lines of the others. The
//! kernel's runner (`kernel/src/ktest.rs`) records the running test with
//! [`set_current`]; the panic handler reads it back with [`current`] to
//! report that test as failed, because the kernel does not unwind: a panic
//! still ends the run.
#![no_std]

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

/// A registered test: its name and its body. `Err` carries the reason that
/// the TAP line prints after `#`.
pub type TestFn = fn() -> Result<(), &'static str>;

/// The phase of a test registered with [`ktest!`]: boot hart, before the
/// scheduler starts.
pub const EARLY: usize = 0;
/// The phase of a test registered with [`ktest_late!`]: a kernel task, after
/// the scheduler started.
pub const LATE: usize = 1;

/// One `.azos_ktest` entry (32 bytes on a 64-bit target).
#[repr(C)]
pub struct KTest {
    pub name: &'static str,
    pub run: TestFn,
    /// [`EARLY`] or [`LATE`].
    pub phase: usize,
}

/// Define and register an in-kernel test.
///
/// ```ignore
/// azos_ktest::ktest! {
///     #[cfg(target_arch = "riscv64")]
///     fn mm_example() {
///         if 1 + 1 == 2 { Ok(()) } else { Err("arithmetic") }
///     }
/// }
/// ```
///
/// The body returns `Result<(), &'static str>`. Only `#[cfg(...)]`
/// attributes are accepted; they apply to the function and to its entry.
#[macro_export]
macro_rules! ktest {
    ($(#[cfg($c:meta)])* fn $name:ident() $body:block) => {
        $crate::__ktest_entry!($crate::EARLY; $(#[cfg($c)])* fn $name() $body);
    };
}

/// Define and register a late in-kernel test: same form as [`ktest!`], run
/// by the kernel's late runner task after the scheduler started, every hart
/// online. The body may create tasks and block (a timer sleep, a wait
/// queue); it must not return before the tasks it created stopped touching
/// state the next test reads.
#[macro_export]
macro_rules! ktest_late {
    ($(#[cfg($c:meta)])* fn $name:ident() $body:block) => {
        $crate::__ktest_entry!($crate::LATE; $(#[cfg($c)])* fn $name() $body);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ktest_entry {
    ($phase:expr; $(#[cfg($c:meta)])* fn $name:ident() $body:block) => {
        #[cfg(all(feature = "ktest" $(, $c)*))]
        fn $name() -> ::core::result::Result<(), &'static str> $body

        #[cfg(all(feature = "ktest" $(, $c)*))]
        const _: () = {
            #[used]
            #[link_section = ".azos_ktest"]
            static ENTRY: $crate::KTest = $crate::KTest {
                name: ::core::stringify!($name),
                run: $name,
                phase: $phase,
            };
        };
    };
}

/// Every test the kernel links, in link order (empty on the host).
pub fn all() -> &'static [KTest] {
    #[cfg(target_os = "none")]
    {
        unsafe extern "C" {
            static __azos_ktest_start: u8;
            static __azos_ktest_end: u8;
        }
        let align = core::mem::align_of::<KTest>();
        let size = core::mem::size_of::<KTest>();
        // Linker-script symbols; only their addresses are taken.
        let (s, e) = (&raw const __azos_ktest_start as usize, &raw const __azos_ktest_end as usize);
        // The input sections are placed at their own alignment, so the first
        // entry is at `s` rounded up even if the symbol were not aligned.
        let first = (s + align - 1) & !(align - 1);
        if e <= first {
            return &[];
        }
        // SAFETY: the section holds only `KTest` statics emitted by `ktest!`.
        unsafe { core::slice::from_raw_parts(first as *const KTest, (e - first) / size) }
    }
    #[cfg(not(target_os = "none"))]
    {
        &[]
    }
}

/// How many tests of `phase` are registered.
pub fn count(tests: &'static [KTest], phase: usize) -> usize {
    tests.iter().filter(|t| t.phase == phase).count()
}

/// The test of rank `r` among the tests of `phase`, in name order (ties,
/// which [`duplicate`] reports, broken by link order so every rank names
/// exactly one entry). O(N^2) over a few dozen entries, and allocation-free.
pub fn nth(tests: &'static [KTest], phase: usize, r: usize) -> Option<&'static KTest> {
    tests.iter().enumerate().filter(|(_, t)| t.phase == phase).find_map(|(i, t)| {
        let rank = tests
            .iter()
            .enumerate()
            .filter(|&(j, u)| u.phase == phase && (u.name < t.name || (u.name == t.name && j < i)))
            .count();
        (rank == r).then_some(t)
    })
}

/// A name registered twice (in either phase), if any.
pub fn duplicate(tests: &'static [KTest]) -> Option<&'static str> {
    tests
        .iter()
        .enumerate()
        .find(|&(i, t)| tests[..i].iter().any(|u| u.name == t.name))
        .map(|(_, t)| t.name)
}

/// 1-based TAP number of the test now running, 0 when none, and its entry.
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static CURRENT_TEST: AtomicPtr<KTest> = AtomicPtr::new(core::ptr::null_mut());

/// Record that test `t`, TAP number `n` (1-based), is running; `None` clears.
pub fn set_current(running: Option<(usize, &'static KTest)>) {
    let (n, p) = match running {
        Some((n, t)) => (n, t as *const KTest as *mut KTest),
        None => (0, core::ptr::null_mut()),
    };
    CURRENT_TEST.store(p, Ordering::Release);
    CURRENT.store(n, Ordering::Release);
}

/// The running test's TAP number and entry, if a run is in progress. A late
/// test's panic may come from a task it created, on another hart: the test
/// that was running is still the one that failed.
pub fn current() -> Option<(usize, &'static KTest)> {
    let n = CURRENT.load(Ordering::Acquire);
    let p = CURRENT_TEST.load(Ordering::Acquire);
    if n == 0 || p.is_null() {
        return None;
    }
    // SAFETY: only `set_current` stores it, from a `&'static KTest`.
    Some((n, unsafe { &*p }))
}
