// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The structured kernel log's ring and text line (`klog/wire.rs`).
//!
//! Each test names the change that turns it red (a canary), in the three
//! buckets the project uses: it discriminates, it does not, or it did not
//! compile. The ones that do not discriminate say so.

use super::klog_wire::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A formatted ring of `entries` slots; the words keep it 8-aligned.
struct Region {
    mem: Vec<u64>,
    entries: u32,
}

impl Region {
    fn new(entries: u32, ts_hz: u64) -> Region {
        let mut mem = vec![0u64; region_bytes(entries) / 8];
        // SAFETY: a zeroed, aligned, private buffer of the right size.
        unsafe { format(mem.as_mut_ptr() as *mut u8, entries, ts_hz) };
        Region { mem, entries }
    }
    fn base(&self) -> *mut u8 {
        self.mem.as_ptr() as *mut u8
    }
    fn reader(&self) -> Reader {
        // SAFETY: the buffer is live for the test.
        unsafe { Reader::open(self.base(), region_bytes(self.entries)) }.expect("a formatted ring opens")
    }
    fn push(&self, ts: u64, level: u8, module: &str, msg: &[u8]) -> u64 {
        // SAFETY: the buffer is a formatted ring.
        unsafe { push(self.base(), &New { ts, level, flags: 0, cpu: 1, module, msg }) }
    }
}

#[test]
fn a_record_reads_back_whole() {
    let r = Region::new(8, 1_000_000);
    r.push(42, LEVEL_WARN, "azos_ipc::trace", b"[TRACE] tracer on");
    let rd = r.reader();
    let (mut c, mut rec) = (0u64, Record::empty());
    assert_eq!(rd.next(&mut c, &mut rec), Next::Record);
    assert_eq!((rec.seq, rec.ts, rec.level, rec.cpu), (0, 42, LEVEL_WARN, 1));
    assert_eq!(rec.module(), b"ipc::trace", "the crate's azos_ is trimmed");
    assert_eq!(rec.msg(), b"[TRACE] tracer on");
    assert_eq!(c, 1);
    assert_eq!(rd.next(&mut c, &mut rec), Next::Empty);
    // Canary: store `r.level` in the flags byte instead and the first
    // assertion goes red (discriminates).
}

#[test]
fn module_and_message_are_cut_to_their_fields() {
    let r = Region::new(8, 1);
    let long = [b'x'; MSG_BYTES + 40];
    r.push(1, LEVEL_INFO, "azos_a_very_long_crate_name::and::a::deep::module", &long);
    let rd = r.reader();
    let (mut c, mut rec) = (0u64, Record::empty());
    assert_eq!(rd.next(&mut c, &mut rec), Next::Record);
    assert_eq!(rec.module().len(), MODULE_BYTES);
    assert_eq!(rec.msg().len(), MSG_BYTES);
    assert_ne!(rec.flags & FLAG_TRUNC, 0, "a cut message says so");
    // Canary: drop the `n = min(MSG_BYTES)` cut and the push writes past its
    // slot into the next one (the following test would read garbage).
}

#[test]
fn a_full_ring_overwrites_its_oldest_and_the_reader_counts_the_loss() {
    let r = Region::new(8, 1);
    for i in 0..20u64 {
        r.push(i, LEVEL_INFO, "m", format!("line {i}").as_bytes());
    }
    let rd = r.reader();
    assert_eq!((rd.head(), rd.oldest()), (20, 12));
    let (mut c, mut rec) = (0u64, Record::empty());
    assert_eq!(rd.next(&mut c, &mut rec), Next::Lost(12), "12 records were overwritten");
    assert_eq!(c, 12);
    let mut got = Vec::new();
    while rd.next(&mut c, &mut rec) == Next::Record {
        got.push(String::from_utf8(rec.msg().to_vec()).unwrap());
    }
    assert_eq!(got.len(), 8);
    assert_eq!(got[0], "line 12");
    assert_eq!(got[7], "line 19");
    // Canary: make `oldest` return 0 and the loss goes uncounted and the
    // reader returns slots of a newer lap as if they were its own (red).
}

#[test]
fn a_record_still_being_stored_is_pending_not_lost() {
    let r = Region::new(8, 1);
    r.push(0, LEVEL_INFO, "m", b"first");
    // A producer that claimed record 1 and has not published it: bump head.
    // SAFETY: the head word is the first u64 of its line, inside the header.
    unsafe { (r.base().add(64) as *const std::sync::atomic::AtomicU64).as_ref().unwrap().fetch_add(1, Ordering::Relaxed) };
    let rd = r.reader();
    let (mut c, mut rec) = (0u64, Record::empty());
    assert_eq!(rd.next(&mut c, &mut rec), Next::Record);
    assert_eq!(rd.next(&mut c, &mut rec), Next::Pending);
    assert_eq!(c, 1, "the cursor stays on the unfinished record");
    rd.skip(&mut c);
    assert_eq!(c, 2);
    // Canary: treat Pending as Empty in the reader and `skip` is never
    // offered a reason; this asserts the distinction exists (discriminates).
}

#[test]
fn open_refuses_what_it_does_not_know() {
    let good = Region::new(8, 1);
    let len = region_bytes(8);
    // SAFETY: the buffer is live and 8-aligned.
    let open = |base: *const u8, len| unsafe { Reader::open(base, len) }.is_some();
    assert!(open(good.base(), len));
    assert!(!open(good.base(), len - 1), "a region shorter than its entries");
    assert!(!open(good.base(), HDR_BYTES - 8));
    for (off, val, why) in [(0usize, 0u32, "magic"), (4, 2, "version"), (8, 64, "slot size"), (12, 0, "no entries"), (12, 6, "entries not a power of two")] {
        let mut bad = Region::new(8, 1);
        // SAFETY: the header word is inside the buffer.
        unsafe { core::ptr::write(bad.base().add(off) as *mut u32, val) };
        assert!(!open(bad.base(), len), "{why}");
        bad.mem.clear();
    }
}

#[test]
fn replay_keeps_order_timestamps_and_counts_what_the_early_ring_lost() {
    // The early ring: header from the const form, as the kernel builds it.
    let mut early = vec![0u64; region_bytes(4) / 8];
    let h = header(4, 0);
    // SAFETY: the buffer is at least a header long.
    unsafe { core::ptr::copy_nonoverlapping(h.as_ptr(), early.as_mut_ptr() as *mut u8, HDR_BYTES) };
    for i in 0..6u64 {
        // SAFETY: a formatted ring.
        unsafe { push(early.as_mut_ptr() as *mut u8, &New { ts: 100 + i, level: LEVEL_INFO, flags: if i == 5 { FLAG_PARTIAL } else { 0 }, cpu: 0, module: "kernel", msg: format!("early {i}").as_bytes() }) };
    }
    // SAFETY: as above.
    let from = unsafe { Reader::open(early.as_ptr() as *const u8, region_bytes(4)) }.unwrap();
    assert_eq!(from.oldest(), 2, "two of six did not fit four slots");
    let to = Region::new(16, 1);
    to.push(500, LEVEL_ERR, "k", b"after");
    // The handover pushes the early records FIRST in the kernel; here the
    // destination already holds one, so the order asserted is replay's own.
    // SAFETY: both are formatted rings nobody else touches.
    unsafe { replay(&from, to.base()) };
    let rd = to.reader();
    let (mut c, mut rec) = (0u64, Record::empty());
    let mut seen = Vec::new();
    while rd.next(&mut c, &mut rec) == Next::Record {
        seen.push((rec.ts, rec.flags & FLAG_PARTIAL != 0, String::from_utf8_lossy(rec.msg()).into_owned()));
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(seen[1], (102, false, "early 2".to_string()));
    assert_eq!(seen[4], (105, true, "early 5".to_string()), "flags travel with the record");
    // Canary: replay from cursor 0 instead of `oldest()` and the reader
    // reports Lost on its first call, so `seen` loses its first entry (red).
}

#[test]
fn the_text_line_round_trips_with_escapes() {
    let r = Region::new(8, 2_000_000);
    r.push(3_000_000, LEVEL_ERR, "azos_kernel::boot", b"a\\b\nc\x01\td\x7f \xc3\xa9");
    let rd = r.reader();
    let (mut c, mut rec) = (0u64, Record::empty());
    assert_eq!(rd.next(&mut c, &mut rec), Next::Record);
    let mut out = [0u8; LINE_MAX];
    let n = line(&rec, rd.ts_hz(), &mut out);
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

/// Four producers, one reader: no record is ever torn, and every one the
/// reader does not see is counted as lost. Each record's message is its own
/// producer and counter written three times, so a mix of two records shows.
#[test]
fn concurrent_producers_never_tear_a_record() {
    const PER: u64 = 20_000;
    let region = Arc::new(Region::new(64, 1));
    let done = Arc::new(AtomicBool::new(false));
    let mut producers = Vec::new();
    for p in 0..4u64 {
        let region = region.clone();
        producers.push(std::thread::spawn(move || {
            for i in 0..PER {
                let s = format!("{p}:{i}|{p}:{i}|{p}:{i}");
                region.push(i, LEVEL_INFO, "m", s.as_bytes());
            }
        }));
    }
    let reader = {
        let (region, done) = (region.clone(), done.clone());
        std::thread::spawn(move || {
            let rd = region.reader();
            let (mut c, mut rec) = (0u64, Record::empty());
            let (mut seen, mut lost, mut torn) = (0u64, 0u64, 0u64);
            loop {
                match rd.next(&mut c, &mut rec) {
                    Next::Record => {
                        seen += 1;
                        let m = String::from_utf8_lossy(rec.msg()).into_owned();
                        let parts: Vec<&str> = m.split('|').collect();
                        if parts.len() != 3 || parts[0] != parts[1] || parts[1] != parts[2] || rec.seq != c - 1 {
                            torn += 1;
                        }
                    }
                    Next::Lost(n) => lost += n,
                    Next::Pending => std::thread::yield_now(),
                    Next::Empty => {
                        if done.load(Ordering::Acquire) && c >= rd.head() {
                            break;
                        }
                        std::thread::yield_now();
                    }
                }
            }
            (seen, lost, torn)
        })
    };
    for p in producers {
        p.join().unwrap();
    }
    done.store(true, Ordering::Release);
    let (seen, lost, torn) = reader.join().unwrap();
    assert_eq!(torn, 0, "no torn record");
    assert_eq!(seen + lost, 4 * PER, "every record is either read or counted lost");
    // Canary: publish the stamp BEFORE the data in `push` and `torn` climbs;
    // drop the stamp re-check in `next` and it climbs too (both red).
}
