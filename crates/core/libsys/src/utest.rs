// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The test harness of user code: `azos_ktest`'s registry in ring 3.
//!
//! A test is `#[azos::test] fn name()` (or `-> Result<(), &'static str>`); it is
//! registered in the `azos_ktest` link section, which the linker brackets with
//! `__start_azos_ktest` and `__stop_azos_ktest` (no linker script: the name is
//! a C identifier).
//! A program's `main` calls [`run`], which runs them in name order and prints
//! TAP on the console (`azos_ktest::tap`); its result is the exit status:
//!
//! ```ignore
//! fn main() -> std::process::ExitCode {
//!     std::process::ExitCode::from(azos_libsys::utest::run())
//! }
//! ```
//!
//! The kernel does not unwind and neither does a ring-3 program built with
//! `panic = "abort"`: a test that panics ends the process, and the `# running
//! NAME` line printed before it is what names the culprit.

pub use azos_ktest::{all, KTest, TestFn, EARLY, LATE};

/// Run every registered test and print TAP on the console. Returns the number
/// of failed tests, clamped to 255 (an exit status).
pub fn run() -> u8 {
    let failed = azos_ktest::tap::run(
        all(),
        &mut |line| {
            let _ = crate::console_write(crate::STDOUT, line.as_bytes());
        },
        |t| (t.run)(),
    );
    failed.min(255) as u8
}
