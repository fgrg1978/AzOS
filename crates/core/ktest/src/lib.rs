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
//! Order is by name ([`nth`]), not link order, so adding a test in one file
//! does not renumber the TAP lines of the others. The kernel's runner
//! (`kernel/src/ktest.rs`) records the running test with [`set_current`]; the
//! panic handler reads it back with [`current`] to report that test as
//! failed, because the kernel does not unwind: a panic still ends the run.
#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};

/// A registered test: its name and its body. `Err` carries the reason that
/// the TAP line prints after `#`.
pub type TestFn = fn() -> Result<(), &'static str>;

/// One `.azos_ktest` entry (24 bytes on a 64-bit target).
#[repr(C)]
pub struct KTest {
    pub name: &'static str,
    pub run: TestFn,
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
        #[cfg(all(feature = "ktest" $(, $c)*))]
        fn $name() -> ::core::result::Result<(), &'static str> $body

        #[cfg(all(feature = "ktest" $(, $c)*))]
        const _: () = {
            #[used]
            #[link_section = ".azos_ktest"]
            static ENTRY: $crate::KTest = $crate::KTest {
                name: ::core::stringify!($name),
                run: $name,
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

/// The test of rank `r` in name order (ties, which [`duplicate`] reports,
/// broken by link order so every rank names exactly one entry). O(N^2) over
/// a handful of entries, and allocation-free.
pub fn nth(tests: &'static [KTest], r: usize) -> Option<&'static KTest> {
    tests.iter().enumerate().find_map(|(i, t)| {
        let rank = tests
            .iter()
            .enumerate()
            .filter(|&(j, u)| u.name < t.name || (u.name == t.name && j < i))
            .count();
        (rank == r).then_some(t)
    })
}

/// A name registered twice, if any.
pub fn duplicate(tests: &'static [KTest]) -> Option<&'static str> {
    tests
        .iter()
        .enumerate()
        .find(|&(i, t)| tests[..i].iter().any(|u| u.name == t.name))
        .map(|(_, t)| t.name)
}

/// 1-based TAP number of the test now running, 0 when none.
static CURRENT: AtomicUsize = AtomicUsize::new(0);

/// Record that the test with TAP number `n` (1-based) is running; 0 clears.
pub fn set_current(n: usize) {
    CURRENT.store(n, Ordering::Release);
}

/// The running test's TAP number and entry, if a run is in progress.
pub fn current() -> Option<(usize, &'static KTest)> {
    let n = CURRENT.load(Ordering::Acquire);
    if n == 0 {
        return None;
    }
    nth(all(), n - 1).map(|t| (n, t))
}
