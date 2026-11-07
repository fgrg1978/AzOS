// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Frame` interface: its registry row, the badge that names a camera,
//! and the wire form of its reply.

use azos_devif::frame::{format, Meta, CAMERAS, FRAME_ID};
use azos_devif::{by_key, by_name, key, outcome, parse_target, FrameIdl, Out};
use azos_idl::{MsgDesc, Reader, Wire, Writer, MSG_VERSION};

/// The row: key 29, after `volume`, the id "FRAM".
///
/// **Canary.** Move the key: red.
#[test]
fn the_frame_row_is_registered_after_volume() {
    assert_eq!((key::VOLUME, key::FRAME), (28, 29));
    assert_eq!(FRAME_ID.to_be_bytes(), *b"FRAM");
    let i = by_name("frame").expect("no row frame");
    assert_eq!((i.key, i.id), (key::FRAME, FRAME_ID));
    assert_eq!(by_key(key::FRAME).map(|x| x.name), Some("frame"));
}

/// `frame.<n>` names camera `n` below the interface's bound; a bare `frame`
/// names none, so an endpoint must.
///
/// **Canary.** Make the resource optional (`no_resource`): red.
#[test]
fn a_camera_is_named_by_its_index() {
    let b = |t: &str| parse_target(t).map(|(i, b)| (i.key, b));
    assert_eq!(CAMERAS, 1);
    assert_eq!(b("frame.0"), Some((key::FRAME, 0)));
    for bad in ["frame", "frame.1", "frame.-1", "frame.0.0", "frame.cam"] {
        assert!(parse_target(bad).is_none(), "{bad}");
    }
}

/// The three ops, and a reply of the outcome and the metadata's six words:
/// inside a message.
#[test]
fn the_ops_and_the_reply_fit_the_message() {
    let names: Vec<&str> = FrameIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["buffer_bytes", "next", "close"]);
    assert_eq!(<Out<Meta> as Wire>::WORDS, 7);
    assert!(<Out<Meta> as Wire>::WORDS <= azos_abi::ipc_msg::MSG_WORDS_MAX);
}

/// The metadata crosses unchanged.
#[test]
fn the_metadata_round_trips() {
    let m = Meta { len: 19_200, skipped: 3, seq: 1 << 40, acq_ns: 123_456_789_012, format: format::YUYV, size: 160 << 16 | 120 };
    let mut msg = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut msg);
        Out::ok(m).put(&mut w);
        w.finish();
    }
    let mut rd = Reader::new(&msg);
    assert_eq!(<Out<Meta> as Wire>::get(&mut rd), Out::new(outcome::OK, m));
    assert!(rd.finish().is_ok());
}
