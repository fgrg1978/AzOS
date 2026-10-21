// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The DTB idle-state mistake the model corrects and the boot reports: a
//! `min-residency-us` below the state's exit latency (`dt::residencies_raised`).
//! The model keeps raising the residency to the exit latency; this checks the
//! list the boot warns from agrees with what the model did, state for state.
//!
//! Canary (by hand): drop the `min_residency_us < exit` filter in
//! `residencies_raised` and `only_the_states_the_model_raised_are_reported` fails.

use azos_dtb::{dtb_energy, DtEnergy};
use azos_energy::dt::{from_dt, residencies_raised};

fn fixture() -> DtEnergy {
    let p = format!("{}/fixtures/energy-2cluster.dtb", env!("CARGO_MANIFEST_DIR"));
    let mut v = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
    v.extend_from_slice(&[0; 8]);
    unsafe { dtb_energy(v.as_ptr()) }.expect("readable blob")
}

/// The two listed states of the fixture: `retention` (exit 20+40, residency
/// 100 in the model) and a nameless one (250+500, 3000; the model calls it `state2`).
fn model_idle(dt: &DtEnergy) -> Vec<(u32, u32)> {
    let m = from_dt(dt).unwrap().unwrap();
    m.domains()[0].idle_states().iter().skip(1).map(|s| (s.exit_latency_us, s.target_residency_us)).collect()
}

#[test]
fn a_dtb_that_is_right_raises_nothing() {
    let dt = fixture();
    assert_eq!(residencies_raised(&dt).count(), 0);
    assert_eq!(model_idle(&dt), [(60, 100), (750, 3000)]);
}

#[test]
fn a_residency_below_the_exit_latency_is_raised_and_reported() {
    let mut dt = fixture();
    // `state2`: exit 750, the DTB says 300.
    dt.idle[1].min_residency_us = 300;
    assert_eq!(model_idle(&dt), [(60, 100), (750, 750)], "the model raises it to the exit latency");
    let got: Vec<_> = residencies_raised(&dt).collect();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].name(), got[0].min_residency_us, got[0].exit_latency_us), (&b""[..], 300, 750));
    assert_eq!(got[0].phandle, dt.idle[1].phandle);
}

#[test]
fn an_absent_residency_counts_and_an_equal_one_does_not() {
    let mut dt = fixture();
    dt.idle[0].min_residency_us = 0; // exit 60: absent
    dt.idle[1].min_residency_us = 750; // exit 750: exactly enough
    let got: Vec<_> = residencies_raised(&dt).map(|r| (r.min_residency_us, r.exit_latency_us)).collect();
    assert_eq!(got, [(0, 60)]);
    assert_eq!(model_idle(&dt), [(60, 60), (750, 750)]);
}

#[test]
fn only_the_states_the_model_raised_are_reported() {
    // A state no CPU lists is not in the model, so there is nothing to warn about.
    let mut dt = fixture();
    for c in dt.cpus.iter_mut() {
        c.n_idle = 0;
    }
    dt.idle[0].min_residency_us = 1;
    dt.idle[1].min_residency_us = 1;
    assert_eq!(residencies_raised(&dt).count(), 0);
    // Listed by one CPU only: reported once, not once per CPU.
    dt.cpus[2].n_idle = 2;
    dt.cpus[2].idle_states[0] = dt.idle[0].phandle;
    dt.cpus[2].idle_states[1] = dt.idle[1].phandle;
    dt.cpus[3].n_idle = 2;
    dt.cpus[3].idle_states[0] = dt.idle[0].phandle;
    dt.cpus[3].idle_states[1] = dt.idle[1].phandle;
    assert_eq!(residencies_raised(&dt).count(), 2);
}
