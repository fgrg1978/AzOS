// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The monitor ABI (crates/core/hyp-api): ring cursor rules and id ranges.

use azos_hyp_api::*;

fn v(n: u64) -> Violation {
    Violation { kind: Kind::Stage2Fault as u32, pe: 1, syndrome: n, addr: n, aux: 0 }
}

#[test]
fn ring_reads_in_order_and_ends() {
    let mut r: Ring<4> = Ring::new();
    assert_eq!(r.read(0), None);
    r.push(v(1));
    r.push(v(2));
    assert_eq!(r.read(0), Some((1, v(1))));
    assert_eq!(r.read(1), Some((2, v(2))));
    assert_eq!(r.read(2), None);
}

#[test]
fn overwritten_cursor_jumps_to_oldest() {
    let mut r: Ring<4> = Ring::new();
    for n in 0..6 {
        r.push(v(n));
    }
    assert_eq!(r.read(0), Some((3, v(2))));
    assert_eq!(r.read(5), Some((6, v(5))));
}

#[test]
fn ids_and_words_round_trip() {
    assert!(is_monitor_call(CALL_PROBE) && is_monitor_call(CALL_VIOLATION_READ));
    assert!(!is_monitor_call(0xC400_0003) && !is_monitor_call(0x8400_0000));
    let x = v(7);
    assert_eq!(Violation::from_words(x.word1(), x.syndrome, x.addr, x.aux), x);
    assert_eq!(Kind::from_u32(3), Some(Kind::EntryRefused));
    assert_eq!(Kind::from_u32(9), None);
}
