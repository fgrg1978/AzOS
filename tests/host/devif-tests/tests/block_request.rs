// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Block` interface's request descriptor: its wire form and the one
//! refusal both sides of an endpoint apply (`BlockRequest::check`).

use azos_devif::block::*;
use azos_devif::{outcome, Reader, Wire, Writer};
use azos_abi::ipc_msg::{MsgDesc, MSG_VERSION};

fn full() -> BlockRequest {
    BlockRequest {
        op: REQ_WRITE,
        flags: FLAG_FUA | FLAG_PREFLUSH,
        sector: 0x1_2345_6789,
        count: 77,
        deadline_ns: 5_000_000,
        owner: 0x0003_0004,
        mem: 9,
        mem_off: 4096,
    }
}

#[test]
fn request_crosses_as_its_eight_words_and_back() {
    let mut m = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut m);
        full().put(&mut w);
        w.finish();
    }
    assert_eq!(m.n_words as usize, <BlockRequest as Wire>::WORDS);
    assert_eq!(<BlockRequest as Wire>::WORDS, 8);
    assert_eq!(m.words[2], 0x1_2345_6789, "the sector is a whole word, not folded into 32 bits");
    let mut r = Reader::new(&m);
    assert_eq!(<BlockRequest as Wire>::get(&mut r), full());
    assert!(r.finish().is_ok());
}

/// A word that does not fit its field is a malformed message, not a wrapped
/// value (a count of 2^32 + 1 must not read as 1).
#[test]
fn request_word_wider_than_its_field_is_malformed() {
    let mut m = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut m);
        full().put(&mut w);
        w.finish();
    }
    m.words[3] = (1 << 32) | 1;
    let mut r = Reader::new(&m);
    let _ = <BlockRequest as Wire>::get(&mut r);
    assert!(r.finish().is_err());
}

/// CANARY of the layer: a request that belongs to nobody is refused, before
/// its shape is looked at.
#[test]
fn request_without_an_owner_is_refused() {
    let mut r = BlockRequest::rw(false, 8, 1, OWNER_NONE);
    assert_eq!(r.check(), Err(outcome::REFUSED));
    r.owner = 7;
    assert_eq!(r.check(), Ok(()));
    // Not even a nonsense shape hides the missing owner.
    let nonsense = BlockRequest { op: 99, owner: OWNER_NONE, ..BlockRequest::default() };
    assert_eq!(nonsense.check(), Err(outcome::REFUSED));
    assert_eq!(BlockRequest::rw(true, 0, 1, OWNER_KERNEL).check(), Ok(()));
}

#[test]
fn request_shapes_that_mean_nothing_are_bad_arguments() {
    let ok = |r: BlockRequest| assert_eq!(r.check(), Ok(()), "{r:?}");
    let bad = |r: BlockRequest| assert_eq!(r.check(), Err(outcome::BAD_ARGUMENT), "{r:?}");
    let w = BlockRequest::rw(true, 100, 8, 5);
    ok(w);
    ok(BlockRequest { flags: FLAG_FUA, ..w });
    ok(BlockRequest { flags: FLAG_PREFLUSH, ..w });
    ok(BlockRequest::rw(false, 100, 8, 5));
    ok(BlockRequest::flush(5));
    ok(BlockRequest { op: REQ_DISCARD, ..BlockRequest::rw(false, 100, 8, 5) });
    ok(BlockRequest { mem: 3, mem_off: 512, ..w });
    // An unknown op or flag.
    bad(BlockRequest { op: 4, ..w });
    bad(BlockRequest { flags: 1 << 2, ..w });
    // No sectors; sectors on a flush; flags on what cannot carry them.
    bad(BlockRequest { count: 0, ..w });
    bad(BlockRequest { count: 1, ..BlockRequest::flush(5) });
    bad(BlockRequest { sector: 1, ..BlockRequest::flush(5) });
    bad(BlockRequest { flags: FLAG_FUA, ..BlockRequest::rw(false, 0, 1, 5) });
    bad(BlockRequest { flags: FLAG_FUA, ..BlockRequest::flush(5) });
    bad(BlockRequest { flags: FLAG_FUA, op: REQ_DISCARD, ..w });
    // A range that wraps the sector space.
    bad(BlockRequest { sector: u64::MAX, count: 1, ..w });
    // A MemObj offset with no MemObj, and a MemObj on a request with no data.
    bad(BlockRequest { mem_off: 8, ..w });
    bad(BlockRequest { mem: 3, ..BlockRequest::flush(5) });
    bad(BlockRequest { mem: 3, op: REQ_DISCARD, ..w });
}
