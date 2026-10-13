// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The runner of ring 3: the registered tests in name order, reported as TAP.
//!
//! ```text
//! TAP version 14
//! 1..3
//! # running alloc_grows
//! ok 1 - alloc_grows
//! # running threads_join
//! not ok 2 - threads_join # joined 3 of 4
//! ok 3 - time_is_monotonic
//! # 3 tests, 1 failed
//! ```
//!
//! The `# running` line comes first so that a test which ends the process
//! (a panic is an abort) still names itself in the log. Generic over the
//! output and over how a test is run, so the host suite drives it with a
//! string and a closure; `azos_libsys::utest::run` gives it the console.

use core::fmt::Write;

use crate::{count, duplicate, nth, KTest, EARLY};

/// A line, built on the stack and handed to the output in one piece. One byte
/// is kept back for the newline.
struct Line {
    b: [u8; 192],
    n: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        // A reason too long for the line is cut (at a character), not refused.
        let mut take = s.len().min(self.b.len() - 1 - self.n);
        while !s.is_char_boundary(take) {
            take -= 1;
        }
        self.b[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
        self.n += take;
        Ok(())
    }
}

fn emit(out: &mut dyn FnMut(&str), args: core::fmt::Arguments<'_>) {
    let mut l = Line { b: [0; 192], n: 0 };
    let _ = l.write_fmt(args);
    l.b[l.n] = b'\n';
    l.n += 1;
    // Only whole characters were copied, so this holds.
    if let Ok(s) = core::str::from_utf8(&l.b[..l.n]) {
        out(s);
    }
}

/// Run every [`EARLY`] test of `tests` in name order, `exec` being how one is
/// run, and report TAP to `out`. Returns how many failed (a duplicate name
/// bails out with 1 before anything runs).
pub fn run(tests: &'static [KTest], out: &mut dyn FnMut(&str), mut exec: impl FnMut(&'static KTest) -> Result<(), &'static str>) -> usize {
    emit(out, format_args!("TAP version 14"));
    if let Some(name) = duplicate(tests) {
        emit(out, format_args!("Bail out! test {name} is registered twice"));
        return 1;
    }
    let total = count(tests, EARLY);
    emit(out, format_args!("1..{total}"));
    let mut failed = 0;
    for r in 0..total {
        let Some(t) = nth(tests, EARLY, r) else { break };
        emit(out, format_args!("# running {}", t.name));
        match exec(t) {
            Ok(()) => emit(out, format_args!("ok {} - {}", r + 1, t.name)),
            Err(why) => {
                failed += 1;
                emit(out, format_args!("not ok {} - {} # {}", r + 1, t.name, why));
            }
        }
    }
    emit(out, format_args!("# {total} tests, {failed} failed"));
    failed
}
