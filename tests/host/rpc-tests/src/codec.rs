// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The frame format, the message body, reassembly, the dedupe window and the
//! policy text: the pieces below the engine.

use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_MOVE, MSG_VERSION};
use azos_rpc::policy::Name;
use azos_rpc::session::{Dedupe, Seen};
use azos_rpc::wire::*;
use azos_rpc::{Policy, DEDUPE_CAP, REPLY_KEEP};

fn hdr(kind: Kind) -> Header {
    Header { remaining_ns: 5, clock: 0, ctr: 0x1112_1314_1516_1718, ..Header::new(kind, 9, 0x0102_0304_0506_0708, 3, 77) }
}

/// A frame of `h` with `body` as its fragment: a sealed kind ends in a tag (its
/// bytes are not checked here, the channel's tests do that), a Hello does not.
fn frame(h: &Header, body: &[u8]) -> Vec<u8> {
    let tag = if is_hello(h.kind) { 0 } else { TAG_BYTES };
    let mut f = vec![0u8; HEADER_BYTES + body.len() + tag];
    put_header(h, &mut f);
    f[HEADER_BYTES..HEADER_BYTES + body.len()].copy_from_slice(body);
    f
}

/// The fragment of a sealed frame, without its tag.
fn plain(rest: &[u8]) -> &[u8] {
    &rest[..rest.len() - TAG_BYTES]
}

/// The header survives a round trip, byte for byte at the documented offsets.
#[test]
fn a_header_round_trips_at_its_documented_offsets() {
    let h = hdr(Kind::Req);
    let f = frame(&h, b"xyz");
    assert_eq!(&f[0..2], b"RZ");
    assert_eq!((f[2], f[3]), (2, 3), "version, kind");
    assert_eq!(u32::from_le_bytes(f[4..8].try_into().unwrap()), 9, "session");
    assert_eq!(u64::from_le_bytes(f[8..16].try_into().unwrap()), 0x0102_0304_0506_0708, "seq");
    assert_eq!(u64::from_le_bytes(f[16..24].try_into().unwrap()), 5, "remaining ns");
    assert_eq!(u32::from_le_bytes(f[24..28].try_into().unwrap()), 3, "node");
    assert_eq!(u32::from_le_bytes(f[28..32].try_into().unwrap()), 77, "epoch");
    assert_eq!(u64::from_le_bytes(f[40..48].try_into().unwrap()), 0x1112_1314_1516_1718, "packet counter");
    let (g, rest) = get_header(&f).unwrap();
    assert_eq!(g, h);
    assert_eq!(plain(rest), b"xyz");
    assert_eq!(rest.len(), 3 + TAG_BYTES, "a sealed frame ends in its tag");
}

/// Anything that is not a frame of this format is dropped, not guessed at.
#[test]
fn a_frame_that_is_not_one_is_refused() {
    let good = frame(&hdr(Kind::Ping), b"");
    assert!(get_header(&good).is_some());
    assert!(get_header(&good[..HEADER_BYTES - 1]).is_none(), "short");
    assert!(get_header(&good[..HEADER_BYTES + TAG_BYTES - 1]).is_none(), "no room for the tag");
    let mut f = good.clone();
    f[0] ^= 1;
    assert!(get_header(&f).is_none(), "magic");
    let mut f = good.clone();
    f[2] = 1;
    assert!(get_header(&f).is_none(), "version");
    for k in [0u8, 10, 255] {
        let mut f = good.clone();
        f[3] = k;
        assert!(get_header(&f).is_none(), "kind {k}");
    }
    // A fragment index outside its count, a zero count, a count past the largest message.
    for (idx, cnt) in [(1u16, 1u16), (0, 0), (0, FRAGS_MAX as u16 + 1)] {
        let mut h = hdr(Kind::Req);
        h.frag_idx = idx;
        h.frag_cnt = cnt;
        assert!(get_header(&frame(&h, b"")).is_none(), "{idx}/{cnt}");
    }
    // A non-final fragment must be full; a frame may not exceed FRAME_MAX.
    let mut h = hdr(Kind::Req);
    h.frag_cnt = 2;
    assert!(get_header(&frame(&h, &[0; FRAG_BODY - 1])).is_none());
    assert!(get_header(&frame(&h, &[0; FRAG_BODY])).is_some());
    h.frag_cnt = 1;
    assert!(get_header(&frame(&h, &vec![0; FRAG_BODY + 1])).is_none());
    assert_eq!(FRAG_BODY + TAG_BYTES + HEADER_BYTES, FRAME_MAX, "a full fragment fills the frame");
}

/// A Hello and its answer are one Noise message each, in one frame: not
/// fragmented, not sealed, not larger than a Noise IK message can be.
#[test]
fn a_handshake_frame_is_one_unsealed_message() {
    for kind in [Kind::Hello, Kind::HelloAck] {
        let h = Header { ctr: 0, ..hdr(kind) };
        let f = frame(&h, &[7; 100]);
        let (g, msg) = get_header(&f).unwrap();
        assert_eq!((g, msg), (h, &[7u8; 100][..]), "the message as it is");
        assert!(get_header(&frame(&h, &[7; HELLO_MAX])).is_some());
        assert!(get_header(&frame(&h, &[7; HELLO_MAX + 1])).is_none(), "longer than a message");
        let mut two = h;
        two.frag_cnt = 2;
        assert!(get_header(&frame(&two, &[7; 100])).is_none(), "never fragmented");
    }
}

fn desc() -> MsgDesc {
    let mut d = MsgDesc { version: MSG_VERSION, n_words: 3, n_caps: 2, ..MsgDesc::default() };
    d.words[..3].copy_from_slice(&[0x1122_3344_5566_7788, 2, u64::MAX]);
    d.caps[0] = CapDesc { handle: 41, mode: CAP_MODE_MOVE, _pad: 0, rights: 3, expiry_ns: 1234 };
    d.caps[1] = CapDesc { handle: 42, mode: CAP_MODE_MOVE, _pad: 0, rights: 0, expiry_ns: 0 };
    d
}

/// The message body is the descriptor as it is, then each capability's pages.
#[test]
fn a_message_is_the_descriptor_and_the_pages_of_its_objects() {
    let d = desc();
    let mut out = vec![0u8; 512];
    let mut at = 0;
    put_desc(&d, &mut out, &mut at).unwrap();
    assert_eq!(at, 4 + 3 * 8 + 2 * 16, "counts, words, 16-byte capability entries");
    assert_eq!(&out[..4], &[3, 2, 0, 0]);
    assert_eq!(&out[4..12], &0x1122_3344_5566_7788u64.to_le_bytes());
    // The entry is the CapDesc layout: handle, mode, pad, rights, expiry.
    let c0 = 4 + 24;
    assert_eq!(&out[c0..c0 + 4], &41u32.to_le_bytes());
    assert_eq!(out[c0 + 4], CAP_MODE_MOVE);
    assert_eq!(&out[c0 + 6..c0 + 8], &3u16.to_le_bytes());
    assert_eq!(&out[c0 + 8..c0 + 16], &1234u64.to_le_bytes());
    // Data: len then bytes, per capability.
    for data in [&b"abcd"[..], &b""[..]] {
        out[at..at + 4].copy_from_slice(&(data.len() as u32).to_le_bytes());
        out[at + 4..at + 4 + data.len()].copy_from_slice(data);
        at += 4 + data.len();
    }
    let body = &out[..at];
    let mut p = 0;
    let back = get_desc(body, &mut p).unwrap();
    assert_eq!((back.n_words, back.n_caps, back.version), (3, 2, MSG_VERSION));
    assert_eq!(back.words[..3], d.words[..3]);
    assert_eq!(back.caps[..2], d.caps[..2]);
    assert_eq!(get_data(body, &mut p), Some(&b"abcd"[..]));
    assert_eq!(get_data(body, &mut p), Some(&b""[..]));
    assert_eq!(get_data(body, &mut p), None, "nothing left");
    assert_eq!(p, body.len());
}

/// A body that does not have the shape is refused: counts above the ABI
/// ceilings, a short body, a non-zero reserved half-word or pad, data that
/// runs past the end.
#[test]
fn a_malformed_body_is_refused() {
    let mut out = vec![0u8; 512];
    let mut at = 0;
    put_desc(&desc(), &mut out, &mut at).unwrap();
    let body = out[..at].to_vec();
    let mut p = 0;
    assert!(get_desc(&body, &mut p).is_some());
    assert!(get_desc(&body[..at - 1], &mut 0).is_none(), "short");
    for (i, v) in [(2usize, 1u8), (3, 1), (4 + 24 + 5, 1)] {
        let mut b = body.clone();
        b[i] = v;
        assert!(get_desc(&b, &mut 0).is_none(), "byte {i}");
    }
    let mut b = body.clone();
    b[0] = 9;
    assert!(get_desc(&b, &mut 0).is_none(), "nine words");
    let mut b = body.clone();
    b[1] = 9;
    assert!(get_desc(&b, &mut 0).is_none(), "nine capabilities");
    let data = [255u8, 255, 255, 255, 1];
    assert_eq!(get_data(&data, &mut 0), None, "a length past the end");
    assert_eq!(get_data(&[1, 0, 0], &mut 0), None, "no room for a length");
    // The encoder refuses a descriptor that does not fit.
    assert!(put_desc(&desc(), &mut [0u8; 10], &mut 0).is_none());
}

fn msg_frames(session: u32, seq: u64, body: &[u8]) -> Vec<Vec<u8>> {
    let cnt = frags_for(body.len());
    (0..cnt)
        .map(|i| {
            let (lo, hi) = (i * FRAG_BODY, ((i + 1) * FRAG_BODY).min(body.len()));
            let mut h = Header::new(Kind::Req, session, seq, 3, 1);
            h.frag_idx = i as u16;
            h.frag_cnt = cnt as u16;
            frame(&h, &body[lo..hi])
        })
        .collect()
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// A message larger than a frame is cut and put together again, in any order.
#[test]
fn fragments_reassemble_in_any_order() {
    for len in [0usize, 1, FRAG_BODY - 1, FRAG_BODY, FRAG_BODY + 1, 5 * FRAG_BODY + 17, 16 * 1024] {
        let body = pattern(len);
        let frames = msg_frames(1, 10, &body);
        assert_eq!(frames.len(), frags_for(len));
        for reversed in [false, true] {
            let mut asm = Asm::new();
            let mut idx: Vec<usize> = (0..frames.len()).collect();
            if reversed {
                idx.reverse();
            }
            let mut done = None;
            for (n, &i) in idx.iter().enumerate() {
                let (h, frag) = get_header(&frames[i]).unwrap();
                let r = asm.push(&h, plain(frag));
                assert_eq!(r.is_some(), n + 1 == idx.len(), "complete only at the last fragment ({len} bytes)");
                done = r.or(done);
            }
            let slot = done.unwrap();
            let (head, got) = asm.message(slot);
            assert_eq!(got, &body[..], "{len} bytes, reversed {reversed}");
            assert_eq!(head.seq, 10);
            asm.done(slot);
        }
    }
}

/// A lost fragment loses its message and nothing else: a second message in
/// flight is not disturbed, and when a third crowds the two slots the oldest
/// is the one that goes.
#[test]
fn a_lost_fragment_costs_its_message_only() {
    let m1 = pattern(3 * FRAG_BODY + 5);
    let m2 = pattern(2 * FRAG_BODY + 9);
    let (f1, f2) = (msg_frames(1, 1, &m1), msg_frames(1, 2, &m2));
    let mut asm = Asm::new();
    // m1 loses its fragment 1; m2 arrives whole, interleaved with it.
    let mut got = vec![];
    for f in [&f1[0], &f2[0], &f1[2], &f2[1], &f1[3], &f2[2]] {
        let (h, frag) = get_header(f).unwrap();
        if let Some(s) = asm.push(&h, plain(frag)) {
            got.push((h.seq, asm.message(s).1.to_vec()));
            asm.done(s);
        }
    }
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0, &got[0].1[..]), (2, &m2[..]));
    // m1's slot is still held, half done. A third and fourth message crowd it out.
    for seq in [3u64, 4] {
        let f = msg_frames(1, seq, &pattern(2 * FRAG_BODY));
        let (h, frag) = get_header(&f[0]).unwrap();
        assert!(asm.push(&h, plain(frag)).is_none());
    }
    // m1's missing fragment arriving now completes nothing: its slot was taken.
    let (h, frag) = get_header(&f1[1]).unwrap();
    assert!(asm.push(&h, plain(frag)).is_none());
}

/// The same message named with two fragment counts is not put together.
#[test]
fn a_fragment_count_that_changes_discards_the_message() {
    let f = msg_frames(1, 1, &pattern(2 * FRAG_BODY));
    let mut asm = Asm::new();
    let (h, frag) = get_header(&f[0]).unwrap();
    assert!(asm.push(&h, plain(frag)).is_none());
    let mut h2 = h;
    h2.frag_cnt = 3;
    h2.frag_idx = 1;
    assert!(asm.push(&h2, &[0; FRAG_BODY]).is_none());
    let (h1, frag1) = get_header(&f[1]).unwrap();
    assert!(asm.push(&h1, plain(frag1)).is_none(), "the discarded message does not come back");
}

/// The dedupe window answers a repeat from the answer it kept, runs nothing
/// twice, and says "unknown" for what it can no longer tell.
#[test]
fn the_dedupe_window_keeps_answers_and_remembers_what_it_forgot() {
    let mut d = Dedupe::new(3);
    assert_eq!(d.lookup(1), Seen::Fresh);
    d.record(1, Some(b"one"));
    d.record(2, Some(b"two"));
    d.record(3, None);
    assert_eq!(d.lookup(1), Seen::Cached(b"one"));
    assert_eq!(d.lookup(2), Seen::Cached(b"two"));
    assert_eq!(d.lookup(3), Seen::Unknown, "ran, answer too large to keep");
    assert_eq!(d.lookup(4), Seen::Fresh);
    // The fourth pushes out the oldest, and the floor rises over it.
    d.record(4, Some(b"four"));
    assert_eq!(d.lookup(1), Seen::Unknown, "pushed out: it may have run");
    assert_eq!(d.lookup(2), Seen::Cached(b"two"));
    assert_eq!(d.lookup(5), Seen::Fresh);
    // An answer larger than a window slot is not kept.
    d.record(5, Some(&vec![1u8; REPLY_KEEP + 1]));
    assert_eq!(d.lookup(5), Seen::Unknown);
    // A reset forgets everything; the size is clamped.
    d.reset(1000);
    assert_eq!(d.lookup(1), Seen::Fresh);
    for s in 1..=DEDUPE_CAP as u64 + 1 {
        d.record(s, Some(b"x"));
    }
    assert_eq!(d.lookup(1), Seen::Unknown);
    assert_eq!(d.lookup(2), Seen::Cached(b"x"));
}

/// The view of `/proc/rpc`: classes and exports, malformed lines skipped, and
/// a policy only ever has less in it than the text said.
#[test]
fn the_policy_reads_the_view_and_skips_what_is_not_a_line() {
    let k = |b: u8| format!("{:02x}", b).repeat(32);
    let text = format!(
        "peer fleet 2 {}\npeer fleet 3 {}\npeer lab 9 {}\npeer zero 0 {}\nexport probe 7 fleet\nexport names 3 lab\n\
         export short 1\nexport probe x fleet\nbogus line here\npeer toolongxxxxxxxxxxxxxxxxxxxxxxxxx 4 {}\n\
         peer nokey 5\npeer shortkey 6 abcd\npeer nothex 7 {}\npeer nullkey 8 {}\n",
        k(0x12),
        k(0x34),
        k(0x56),
        k(0x78),
        k(0x9a),
        "zz".repeat(32),
        k(0),
    );
    let p = Policy::parse(text.as_bytes());
    assert_eq!(p.class_of(2), Name::new(b"fleet"));
    assert_eq!(p.class_of(3), Name::new(b"fleet"));
    assert_eq!(p.class_of(9), Name::new(b"lab"));
    assert_eq!(p.class_of(0), None, "node 0 is this node");
    assert_eq!(p.class_of(4), None, "a name past the limit is no class");
    assert_eq!(p.nodes().collect::<Vec<_>>(), [2, 3, 9]);
    // The key the topology pins is the node's, and a peer line without a usable one is no peer.
    assert_eq!(p.noise_pk(2), Some(&[0x12; 32]));
    assert_eq!(p.noise_pk(3), Some(&[0x34; 32]));
    assert_eq!(p.noise_pk(9), Some(&[0x56; 32]));
    for n in [4, 5, 6, 7, 8] {
        assert_eq!((p.class_of(n), p.noise_pk(n)), (None, None), "node {n}");
    }
    let fleet = Name::new(b"fleet").unwrap();
    let lab = Name::new(b"lab").unwrap();
    assert_eq!(p.export(b"probe", &fleet).map(|e| e.index), Some(7));
    assert_eq!(p.export(b"probe", &lab), None, "exported to fleet, not to lab");
    assert_eq!(p.export(b"names", &lab).map(|e| e.index), Some(3));
    assert_eq!(p.export(b"short", &fleet), None);
    // Nothing is allowed by default.
    assert_eq!(Policy::NONE.class_of(2), None);
    assert_eq!(Policy::NONE.nodes().count(), 0);
}

/// **A frame whose fragment would end past `MSG_CAP` is dropped**, not copied
/// into the reassembly slot: `FRAGS_MAX` fragments of `FRAG_BODY` bytes are
/// more than `MSG_CAP`, so the last fragment of the largest count can carry
/// only what is left. One datagram from anyone must not stop the server.
///
/// **Canary.** Drop the bound from `get_header`: the 9-byte frame is accepted
/// and `Asm::push`, left with its own bound removed too, indexes past the
/// slot (the host test panics, as `rpcsrv` would exit(70)).
#[test]
fn a_fragment_that_ends_past_the_message_cap_is_refused() {
    use azos_rpc::wire::{FRAGS_MAX, MSG_CAP};
    let last = FRAGS_MAX - 1;
    let room = MSG_CAP - last * FRAG_BODY;
    assert!(room < FRAG_BODY, "the premise: the last fragment of the largest count is short");
    let mut h = hdr(Kind::Req);
    h.frag_cnt = FRAGS_MAX as u16;
    h.frag_idx = last as u16;
    let at_cap = frame(&h, &vec![0xAA; room]);
    assert!(get_header(&at_cap).is_some(), "exactly MSG_CAP is the largest message");
    let past = frame(&h, &vec![0xAA; room + 1]);
    assert!(get_header(&past).is_none(), "one byte more is refused");
    let full = frame(&h, &vec![0xAA; FRAG_BODY]);
    assert!(get_header(&full).is_none(), "a full-size last fragment is refused");
    // The reassembler holds the same line for a caller that skipped the check.
    let mut asm = Asm::new();
    assert!(asm.push(&h, &vec![0xAA; FRAG_BODY]).is_none());
    // And a whole largest message still goes through.
    let mut asm = Asm::new();
    let body = pattern(MSG_CAP);
    let mut done = None;
    for f in msg_frames(1, 1, &body) {
        let (h, frag) = get_header(&f).expect("every fragment of a MSG_CAP message is well-formed");
        done = asm.push(&h, plain(frag)).or(done);
    }
    assert_eq!(asm.message(done.unwrap()).1, &body[..]);
}
