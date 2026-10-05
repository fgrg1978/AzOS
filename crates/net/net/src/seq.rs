// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure TCP sequence-number arithmetic.
//!
//! **Split out so it can be tested.** Sequence numbers are modulo 2^32, and
//! every comparison on them has to be a wrapping difference rather than an
//! ordinary `<` — a connection that runs long enough crosses the wrap point,
//! and with `overflow-checks = true` a bare `+` there is not a wrong answer,
//! it is a panic and therefore a board reset. None of that is reachable from a
//! host test while these live inside `tcp.rs`, which pulls in the whole
//! network stack.
//!
//! `tests/host/net-tests` pulls this file in with `#[path]`, so what is tested is
//! what ships.

/// Check if a sequence number falls within the receive window.
/// Window is [win_start, win_start + win_size) using wrapping arithmetic.
pub fn seq_in_window(seq_num: u32, win_start: u32, win_size: u32) -> bool {
    // seq_num - win_start (wrapping) should be < win_size
    let offset = seq_num.wrapping_sub(win_start);
    offset < win_size
}

/// Next expected sequence number after accepting a segment that carries FIN.
///
/// A FIN occupies one sequence number of its own, immediately after any
/// payload the same segment carried — so the acknowledgement the peer expects
/// is `seq + payload_len + 1`, not `seq + payload_len`. Getting this wrong by
/// one leaves the peer retransmitting a FIN we believe we already
/// acknowledged, and the connection sits in TimeWait on our side while the
/// peer never reaches CLOSED.
///
/// Wrapping throughout: sequence numbers are modulo 2^32, and with
/// `overflow-checks = true` a bare `+` here would turn a connection that
/// happens to straddle the wrap point into a board reset.
pub fn fin_next_ack(seq: u32, payload_len: usize) -> u32 {
    seq.wrapping_add(payload_len as u32).wrapping_add(1)
}

/// `a` comes strictly before `b` in sequence space.
///
/// "Before" is only meaningful within half the space: two numbers 2^31 apart
/// have no order, and that one ambiguous distance is read as "not before" so
/// neither `seq_lt(a, b)` nor `seq_lt(b, a)` holds. Every range this is used on
/// — the send queue, a receive window, a SACK block — is far smaller.
pub fn seq_lt(a: u32, b: u32) -> bool {
    let d = b.wrapping_sub(a);
    d != 0 && d < 1 << 31
}

/// `a` is `b` or comes before it in sequence space.
pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

pub fn is_ack_advancing(ack_num: u32, retx_seq: u32, retx_len: usize) -> bool {
    if retx_len == 0 { return false; }
    let end = retx_seq.wrapping_add(retx_len as u32);
    // ack_num should be > retx_seq (wrapping) and <= end (wrapping)
    let past_start = ack_num.wrapping_sub(retx_seq) > 0
        && ack_num.wrapping_sub(retx_seq) <= retx_len as u32;
    // Or exactly at end
    past_start || ack_num == end
}
