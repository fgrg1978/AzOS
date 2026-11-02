// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The CPU-time charge of the timer interrupt (`vdso_notify::tick_interval`) is
// kept for every CPU the kernel is built for, not for the first eight.

#[test]
fn tick_interval_covers_every_cpu() {
    let last = azos_limits::NR_CPUS - 1;
    assert_eq!(crate::vdso_notify::tick_interval(last, 1_000), 0, "the first interrupt of a hart charges nothing");
    assert_eq!(crate::vdso_notify::tick_interval(last, 1_250), 250, "the last CPU's tasks are charged");
    assert_eq!(crate::vdso_notify::tick_interval(last, 1_100), 0, "a clock that went back charges nothing");
}
