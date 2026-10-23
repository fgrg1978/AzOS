// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Volume` interface: its registry row, the badge that names a volume,
//! and the wire form of its one op.

use azos_devif::volume::{badge, FLAG_COMPLETE, FLAG_READ_ONLY, VOLUMES, VOLUME_ID};
use azos_devif::{block, by_key, by_name, key, outcome, parse_target, Out, VolumeIdl, VolumeReport};
use azos_idl::{MsgDesc, Reader, Wire, Writer, MSG_VERSION};

/// The row: key 27, after `sound`, the id "VOLU".
///
/// **Canary.** Move the key: red.
#[test]
fn the_volume_row_is_registered_after_sound() {
    assert_eq!((key::SOUND, key::VOLUME), (26, 28));
    assert_eq!(VOLUME_ID.to_be_bytes(), *b"VOLU");
    let i = by_name("volume").expect("no row volume");
    assert_eq!((i.key, i.id), (key::VOLUME, VOLUME_ID));
    assert_eq!(by_key(key::VOLUME).map(|x| x.name), Some("volume"));
}

/// `volume.<n>` names volume `n` by the badge `n + 1`: 0 the boot volume, up
/// to the last partition of the block table; a bare `volume` names none (no
/// request names a volume, so an endpoint must).
///
/// **Canary.** Make the resource optional (`no_resource`): red.
#[test]
fn a_volume_is_named_by_its_badge() {
    let b = |t: &str| parse_target(t).map(|(i, b)| (i.key, b));
    assert_eq!(VOLUMES, block::PARTS + 1);
    assert_eq!(b("volume.0"), Some((key::VOLUME, badge(0))));
    assert_eq!(badge(0), 1, "an unbadged capability names no volume");
    assert_eq!(b("volume.16"), Some((key::VOLUME, 17)));
    for bad in ["volume", "volume.17", "volume.-1", "volume.0.0", "volume.boot"] {
        assert!(parse_target(bad).is_none(), "{bad}");
    }
}

/// The request is the scrub flag; the reply is the outcome and the report's
/// six words.
#[test]
fn the_check_fits_the_message() {
    assert_eq!(VolumeIdl::OPS.len(), 1);
    assert_eq!(VolumeIdl::OPS[0].name, "check");
    assert_eq!(<Out<VolumeReport> as Wire>::WORDS, 7);
}

/// A report crosses unchanged.
#[test]
fn a_report_round_trips() {
    let r = VolumeReport { problems: 2, leaked: 9, mismatched: 1, items: 40, scrubbed: 700, flags: FLAG_COMPLETE | FLAG_READ_ONLY };
    let mut m = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut m);
        Out::ok(r).put(&mut w);
        w.finish();
    }
    let mut rd = Reader::new(&m);
    assert_eq!(<Out<VolumeReport> as Wire>::get(&mut rd), Out::new(outcome::OK, r));
    assert!(rd.finish().is_ok());
}
