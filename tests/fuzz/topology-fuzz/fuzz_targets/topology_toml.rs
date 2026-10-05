// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: SCHED.TOML + CAPS.TOML through the parser, then the
//! install-time checks the kernel runs on any topology (`admission_check`,
//! `deadline_admission`), and the Ed25519 sidecar check over the same bytes.
//!
//! Input layout: `flags NUL sched NUL caps`. With fewer NULs the missing
//! parts are empty. `flags & 1` also runs `verify_signature` with the last 64
//! bytes as the signature against the shipped key (the signature check runs
//! before any parse in the documented order, so it must take any bytes).
//!
//! Built with `profile-actuation`: the robot deployment's parser, which
//! accepts the motor words the generic one refuses (a superset of paths).
#![no_main]

use libfuzzer_sys::fuzz_target;
use azos_topology::{parse_caps, parse_sched, verify_signature, Topology, TRUSTED_PUBKEY};

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |&b| b == 0);
    let flags = parts.next().and_then(|f| f.first().copied()).unwrap_or(0);
    let sched = parts.next().unwrap_or(&[]);
    let caps = parts.next().unwrap_or(&[]);

    if flags & 1 != 0 && data.len() >= 64 {
        let (msg, sig) = data.split_at(data.len() - 64);
        let _ = verify_signature(msg, sig, &TRUSTED_PUBKEY);
    }

    let mut topo = Box::new(Topology::empty());
    let s = parse_sched(sched, &mut topo);
    let c = parse_caps(caps, &mut topo);
    if s.is_ok() && c.is_ok() {
        let _ = topo.admission_check();
        for ncpus in [1usize, 4] {
            let _ = topo.deadline_admission(ncpus);
        }
    }
    // Whatever was parsed, the accessors must stay in bounds.
    assert_eq!(topo.tasks().len(), topo.tasks_len());
    assert_eq!(topo.classes().len(), topo.classes_len());
    let _ = topo.pipelines().len();
});
