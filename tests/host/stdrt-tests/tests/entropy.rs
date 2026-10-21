// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_stdrt::entropy::fill` is the hand-written client of the `Entropy`
//! interface (the generated one needs the IDL proc-macro, which cannot be in
//! the std build graph). It is run here against the generated dispatcher, so
//! a change of the interface's wire form, id or key fails this file.

use azos_devif::entropy::{Entropy, EntropyIdl, DRAW_WORDS};
use azos_devif::outcome::{Out, NOT_READY, OK};
use azos_idl::MsgDesc;

/// A pool that returns a counter: `n`-th word drawn is `base + n`.
struct Pool {
    next: u64,
    ready: bool,
    calls: usize,
}

impl Entropy for Pool {
    fn draw(&mut self, words: u32) -> Out<[u64; DRAW_WORDS]> {
        self.calls += 1;
        if !self.ready {
            return Out::err(NOT_READY);
        }
        let mut v = [0u64; DRAW_WORDS];
        for w in v.iter_mut().take(words as usize) {
            *w = self.next;
            self.next += 1;
        }
        Out::new(OK, v)
    }
}

fn through(pool: &mut Pool) -> impl FnMut(&mut MsgDesc) -> isize + '_ {
    move |m: &mut MsgDesc| {
        let req = *m;
        let mut reply = MsgDesc::default();
        EntropyIdl::dispatch(pool, &req, &mut reply).unwrap();
        *m = reply;
        0
    }
}

#[test]
fn ids_are_the_generated_ones() {
    assert_eq!(azos_stdrt::entropy::ENTROPY_ID, azos_devif::ENTROPY_ID);
    assert_eq!(azos_stdrt::entropy::ENTROPY_KEY, azos_devif::key::ENTROPY);
    assert_eq!(azos_stdrt::entropy::DRAW_WORDS, DRAW_WORDS);
}

/// The bytes are the pool's words, little endian, in order; a request longer
/// than one draw takes several.
#[test]
fn fills_from_the_pool_in_order() {
    for len in [0usize, 1, 7, 8, 9, 48, 49, 100] {
        let mut pool = Pool { next: 0x0102_0304_0506_0708, ready: true, calls: 0 };
        let mut buf = vec![0u8; len];
        assert!(azos_stdrt::entropy::fill(&mut through(&mut pool), &mut buf), "len {len}");
        let mut want = Vec::new();
        for i in 0..len.div_ceil(8) {
            want.extend_from_slice(&(0x0102_0304_0506_0708u64 + i as u64).to_le_bytes());
        }
        want.truncate(len);
        assert_eq!(buf, want, "len {len}");
        assert_eq!(pool.calls, len.div_ceil(DRAW_WORDS * 8), "len {len}");
    }
}

/// **Canary.** An unseeded pool is a refusal, not zeros: `fill` returns false
/// and leaves the buffer untouched.
#[test]
fn an_unseeded_pool_is_refused() {
    let mut pool = Pool { next: 1, ready: false, calls: 0 };
    let mut buf = [0xAAu8; 16];
    assert!(!azos_stdrt::entropy::fill(&mut through(&mut pool), &mut buf));
    assert_eq!(buf, [0xAA; 16]);
}

/// A call that did not reach the interface is a refusal too.
#[test]
fn a_failed_call_is_refused() {
    let mut buf = [0u8; 8];
    assert!(!azos_stdrt::entropy::fill(&mut |_m: &mut MsgDesc| -1, &mut buf));
}

/// A reply that is not served (status word) is refused.
#[test]
fn a_bad_status_is_refused() {
    let mut buf = [0u8; 8];
    assert!(!azos_stdrt::entropy::fill(
        &mut |m: &mut MsgDesc| {
            m.words[0] = 2;
            0
        },
        &mut buf
    ));
}
