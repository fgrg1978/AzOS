// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The structured kernel log's payload and text line (`klog/wire.rs`), in the
//! record substrate's kernel-log ring (the ring protocol itself is
//! `tests/host/rings-tests`).
//!
//! Each test names the change that turns it red (a canary), in the three
//! buckets the project uses: it discriminates, it does not, or it did not
//! compile. The ones that do not discriminate say so.

use super::klog_wire::*;
use azos_rings::region::record::{self as rec, Envelope, Head, Read, RingSpec, SOURCE_KLOG};

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct Line([u8; 64]);

/// A record region holding one kernel-log ring of `entries` slots.
struct Region {
    _mem: Vec<Line>,
    r: rec::Region,
}

impl Region {
    fn new(entries: u32) -> Region {
        let spec = [RingSpec { source: SOURCE_KLOG, slot_bytes: (rec::ENV_BYTES + PAYLOAD_BYTES) as u32, entries }];
        let bytes = rec::region_bytes(&spec);
        let mut mem = vec![Line([0; 64]); bytes.div_ceil(64)];
        // SAFETY: a zeroed, 64-aligned, private buffer of the right size.
        let r = unsafe {
            rec::format(mem.as_mut_ptr() as *mut u8, &spec, 1_000_000);
            rec::Region::open(mem.as_ptr() as *const u8, bytes).unwrap()
        };
        Region { _mem: mem, r }
    }
    /// What `klog::record` does: the payload through `encode`.
    fn push(&self, ts: u64, level: u8, module: &str, msg: &[u8]) -> u64 {
        let (len, flags) = encoded(msg, 0);
        let h = Head { ts, clock: rec::CLOCK_TIMEBASE, kind: level as u16, len, cpu: 1, flags };
        // SAFETY: the test owns the region.
        unsafe { self.r.writer(0).unwrap() }.publish(&h, |p| {
            encode(module, msg, 0, |off, b| p.bytes(off, b));
        })
    }
    /// What `logd` does: the ring's read, then `Record::decode`.
    fn read(&self, cursor: &mut u64) -> Option<Record> {
        let (mut env, mut payload) = (Envelope::default(), [0u8; PAYLOAD_BYTES]);
        (self.r.ring(0).unwrap().read(cursor, &mut env, &mut payload) == Read::Record)
            .then(|| Record::decode(env.seq, env.ts, env.kind as u8, env.flags, env.cpu, env.len, &payload))
    }
}

#[test]
fn a_record_reads_back_whole() {
    let r = Region::new(8);
    r.push(42, LEVEL_WARN, "azos_ipc::trace", b"[TRACE] tracer on");
    let mut c = 0u64;
    let rec = r.read(&mut c).expect("the record");
    assert_eq!((rec.seq, rec.ts, rec.level, rec.cpu), (0, 42, LEVEL_WARN, 1));
    assert_eq!(rec.module(), b"ipc::trace", "the crate's azos_ is trimmed");
    assert_eq!(rec.msg(), b"[TRACE] tracer on");
    assert_eq!(c, 1);
    assert!(r.read(&mut c).is_none());
    // Canary: store the module at `P_MSG` in `encode` and the module and the
    // message both come back wrong (discriminates).
}

#[test]
fn module_and_message_are_cut_to_their_fields() {
    let r = Region::new(8);
    let long = [b'x'; MSG_BYTES + 40];
    r.push(1, LEVEL_INFO, "azos_a_very_long_crate_name::and::a::deep::module", &long);
    let mut c = 0u64;
    let rec = r.read(&mut c).expect("the record");
    assert_eq!(rec.module().len(), MODULE_BYTES);
    assert_eq!(rec.msg().len(), MSG_BYTES);
    assert_ne!(rec.flags & FLAG_TRUNC, 0, "a cut message says so");
    // Canary: drop the `min(MSG_BYTES)` cut in `encode` and the message runs
    // past the payload (the slot's store clamps it, but `len` lies: red).
}

#[test]
fn decode_takes_no_length_on_trust() {
    // A payload whose lengths name more than it holds (a region another
    // writer scribbled): the fields are cut, nothing is read past them.
    let mut payload = [b'z'; PAYLOAD_BYTES];
    payload[P_MODULE_LEN] = 200;
    let rec = Record::decode(3, 4, LEVEL_ERR, 0, 0, u16::MAX, &payload);
    assert_eq!(rec.module().len(), MODULE_BYTES);
    assert_eq!(rec.msg().len(), MSG_BYTES);
    let short = Record::decode(3, 4, LEVEL_ERR, 0, 0, u16::MAX, &payload[..40]);
    assert_eq!(short.msg().len(), 40 - P_MSG, "a short payload is cut, not overrun");
    // Canary: drop the `payload.len()` bound and the second decode panics on
    // the slice (red).
}

#[test]
fn the_text_line_round_trips_with_escapes() {
    let r = Region::new(8);
    r.push(3_000_000, LEVEL_ERR, "azos_kernel::boot", b"a\\b\nc\x01\td\x7f \xc3\xa9");
    let mut c = 0u64;
    let rec = r.read(&mut c).expect("the record");
    let mut out = [0u8; LINE_MAX];
    let n = line(&rec, 2_000_000, &mut out);
    let text = &out[..n];
    assert!(text.ends_with(b"\n") && text.iter().filter(|&&b| b == b'\n').count() == 1, "one record, one line");
    assert!(text.starts_with(b"0 1500000 1 E kernel::boot "), "{}", String::from_utf8_lossy(text));
    let p = parse(text).expect("parses");
    assert_eq!((p.seq, p.ts_us, p.cpu, p.level, p.partial), (0, 1_500_000, 1, LEVEL_ERR, false));
    assert_eq!(p.module, b"kernel::boot");
    let mut back = [0u8; MSG_BYTES];
    let m = unescape(p.msg, &mut back);
    assert_eq!(&back[..m], rec.msg());
    // Canary: leave `\n` unescaped in `line` and the one-line assertion goes red.
}

#[test]
fn a_fragment_and_a_missing_module_have_their_marks() {
    let mut rec = Record::empty();
    rec.seq = 7;
    rec.flags = FLAG_PARTIAL;
    rec.level = LEVEL_INFO;
    let mut out = [0u8; LINE_MAX];
    let n = line(&rec, 0, &mut out);
    assert_eq!(&out[..n], b"7 0 0 I+ - \n");
    let p = parse(&out[..n]).unwrap();
    assert!(p.partial && p.module == b"-" && p.msg.is_empty());
}

#[test]
fn parse_refuses_what_line_never_writes() {
    for bad in [&b""[..], b"x 1 0 I m msg", b"1 2 300 I m msg", b"1 2 0 Q m msg", b"1 2 0 I", b"1 2 0 Ixx m msg", b"-1 2 0 I m a"] {
        assert!(parse(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
    }
    // A message with spaces is whole: splitn(6) keeps the rest.
    assert_eq!(parse(b"1 2 0 W m a b  c").unwrap().msg, b"a b  c");
}

#[test]
fn unescape_leaves_a_stray_backslash_alone() {
    let mut out = [0u8; 16];
    let n = unescape(b"a\\qb\\x4", &mut out);
    assert_eq!(&out[..n], b"a\\qb\\x4");
    let n = unescape(b"\\x41\\\\", &mut out);
    assert_eq!(&out[..n], b"A\\");
}
