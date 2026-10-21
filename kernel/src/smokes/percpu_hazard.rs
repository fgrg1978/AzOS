// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest `percpu_hazard_reads_are_masked`: a representative site of the
//! hart-id-then-table audit (`classes::current`, found by the front
//! `percpu-hazard-b`) reads the hart id and its slot with interrupts masked.
//!
//! The race itself (a tick between the two reads moves the task) cannot be
//! won on demand, so the test observes the window instead: the site reports
//! whether interrupts were on between the two reads
//! (`azos_sched::percpu_audit`). Canary: cargo feature `percpu-hazard-canary`
//! takes the mask off, the test is `not ok`.

azos_ktest::ktest_late! {
    fn percpu_hazard_reads_are_masked() {
        azos_sched::percpu_audit::ktest_current_reads_masked()
    }
}
