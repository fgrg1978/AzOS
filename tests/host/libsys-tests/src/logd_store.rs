// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `logd`'s file ring (`userspace/services/logd/src/store.rs`) over a scripted
//! volume: rotation, retention, which file is newest, and the resume test.
//!
//! Each test names the change that turns it red.

use crate::store::{Store, Tail, Vol};
use crate::wire::{self, Record, LINE_MAX};
use std::collections::HashMap;

#[derive(Default)]
struct Mem {
    files: HashMap<Vec<u8>, Vec<u8>>,
    /// Refuse every append while set.
    down: bool,
    /// Appends that reached the volume.
    appends: usize,
}

impl Vol for Mem {
    fn read_file(&mut self, name: &[u8], f: &mut dyn FnMut(&[u8])) -> bool {
        let Some(data) = self.files.get(name) else { return false };
        // Chunks that do not align with lines, as the real volume's do.
        for c in data.chunks(7) {
            f(c);
        }
        true
    }
    fn append(&mut self, name: &[u8], truncate: bool, data: &[u8]) -> bool {
        if self.down {
            return false;
        }
        self.appends += 1;
        let f = self.files.entry(name.to_vec()).or_default();
        if truncate {
            f.clear();
        }
        f.extend_from_slice(data);
        true
    }
}

fn rec_line(seq: u64, msg: &str) -> Vec<u8> {
    let r = Record::make(seq, seq * 10, wire::LEVEL_INFO, 0, 0, "kernel", msg.as_bytes());
    let mut b = [0u8; LINE_MAX];
    let n = wire::line(&r, 1_000_000, &mut b);
    b[..n].to_vec()
}

fn batch(from: u64, to: u64) -> Vec<u8> {
    (from..to).flat_map(|s| rec_line(s, &format!("line {s}"))).collect()
}

fn name(slot: u8) -> Vec<u8> {
    wire::file_name(slot).to_vec()
}

#[test]
fn an_empty_volume_starts_a_first_file_with_its_serial() {
    let mut v = Mem::default();
    let (mut s, tail) = Store::recover(&mut v, 4, 1024);
    assert!(tail.is_none());
    assert!(s.write(&mut v, &batch(0, 3), 5, 1_000_000));
    let f = &v.files[&name(0)];
    let first = f.split(|&b| b == b'\n').next().unwrap();
    let l = wire::parse(first).unwrap();
    assert_eq!(wire::head_serial(&l), Some(1), "the file opens with `file 1`");
    assert_eq!(f.iter().filter(|&&b| b == b'\n').count(), 4, "head and three records");
    // Canary: skip the head line in `write` and `recover` finds no serial, so
    // the next test's newest-file choice goes red.
}

#[test]
fn a_full_file_rotates_and_the_ring_stays_within_its_bound() {
    let mut v = Mem::default();
    let (mut s, _) = Store::recover(&mut v, 3, 400);
    for i in 0..40u64 {
        assert!(s.write(&mut v, &batch(i * 2, i * 2 + 2), i, 1_000_000));
    }
    assert!(v.files.len() <= 3, "never more files than LOGD_FILES_KEEP: {}", v.files.len());
    let biggest = v.files.values().map(|f| f.len()).max().unwrap();
    // A batch is not split, so a file may pass the limit by at most one.
    assert!(biggest <= 400 + batch(0, 2).len(), "a file holds {biggest} bytes");
    // The newest records are in the files; the oldest were overwritten.
    let all: Vec<u8> = v.files.values().flatten().copied().collect();
    let text = String::from_utf8_lossy(&all);
    assert!(text.contains("line 79"));
    assert!(!text.contains("line 0\n"));
    // Canary: rotate on `>=` against `keep + 1` slots and the file count
    // assertion goes red.
}

#[test]
fn recover_picks_the_highest_serial_not_the_highest_slot_or_sequence() {
    let mut v = Mem::default();
    let (mut s, _) = Store::recover(&mut v, 3, 300);
    // Enough writes to wrap the ring of three files at least once.
    for i in 0..30u64 {
        assert!(s.write(&mut v, &batch(1000 + i, 1001 + i), i, 1_000_000));
    }
    let newest_slot = (0..3u8)
        .max_by_key(|&slot| {
            let f = &v.files[&name(slot)];
            let first = f.split(|&b| b == b'\n').next().unwrap();
            wire::head_serial(&wire::parse(first).unwrap()).unwrap()
        })
        .unwrap();
    // A new boot: sequence numbers start at 0 again, and the next writes land
    // in the newest file; a recovery by sequence number would pick another.
    let (mut s2, tail) = Store::recover(&mut v, 3, 300);
    assert!(s2.write(&mut v, &batch(0, 1), 0, 1_000_000));
    let tail = tail.expect("the newest file has records");
    assert_eq!(tail.last_seq, 1029, "the newest file's last record");
    let f = &v.files[&name(newest_slot)];
    assert!(String::from_utf8_lossy(f).ends_with("line 0\n"), "the new boot's line was appended to the newest file");
    // Canary: choose the slot with the greatest `last_seq` in `recover` and
    // this goes red as soon as a boot's sequence numbers restart.
}

#[test]
fn the_resume_test_is_byte_for_byte() {
    let mut v = Mem::default();
    let (mut s, _) = Store::recover(&mut v, 4, 4096);
    let mut b = batch(10, 13);
    // A notice of the sink's own after the last kernel record.
    let r = Record::make(12, 99, wire::LEVEL_INFO, 0, 0, "logd", b"start: resumed");
    let mut nb = [0u8; LINE_MAX];
    let n = wire::line(&r, 1_000_000, &mut nb);
    b.extend_from_slice(&nb[..n]);
    assert!(s.write(&mut v, &b, 0, 1_000_000));
    let (_, tail) = Store::recover(&mut v, 4, 4096);
    let tail: Tail = tail.unwrap();
    assert_eq!(tail.rec_seq(), Some(12), "the sink's own lines are not kernel records");
    assert_eq!(tail.last_seq, 12);
    let same = rec_line(12, "line 12");
    assert!(tail.matches(12, &same[..same.len() - 1]));
    let other = rec_line(12, "line 12 but another boot");
    assert!(!tail.matches(12, &other[..other.len() - 1]), "same sequence, other content: another stream");
    assert!(!tail.matches(11, &same[..same.len() - 1]));
    // Canary: compare only the sequence number and the second assertion goes red.
}

#[test]
fn a_refused_write_changes_nothing() {
    let mut v = Mem::default();
    let (mut s, _) = Store::recover(&mut v, 2, 200);
    assert!(s.write(&mut v, &batch(0, 2), 0, 1_000_000));
    v.down = true;
    assert!(!s.write(&mut v, &batch(2, 4), 0, 1_000_000), "a refusal is reported");
    assert!(!s.write(&mut v, &batch(2, 40), 0, 1_000_000), "also one that would rotate");
    v.down = false;
    assert!(s.write(&mut v, &batch(2, 4), 0, 1_000_000));
    let all: Vec<u8> = v.files.values().flatten().copied().collect();
    let text = String::from_utf8_lossy(&all);
    assert_eq!(text.matches("line 2\n").count(), 1, "the refused batch left nothing behind");
    // Canary: update `size` before the append in `write` and a later rotation
    // happens early (the file assertion in the rotation test) or the count
    // here is two.
}

#[test]
fn a_batch_bigger_than_a_file_is_still_written() {
    let mut v = Mem::default();
    let (mut s, _) = Store::recover(&mut v, 2, 100);
    assert!(s.write(&mut v, &batch(0, 20), 0, 1_000_000));
    assert!(s.write(&mut v, &batch(20, 40), 0, 1_000_000));
    let all: Vec<u8> = v.files.values().flatten().copied().collect();
    assert!(String::from_utf8_lossy(&all).contains("line 39"));
}

#[test]
fn files_that_are_not_ours_are_ignored() {
    let mut v = Mem::default();
    v.files.insert(name(0), b"garbage\nmore garbage\n".to_vec());
    v.files.insert(name(1), Vec::new());
    let (mut s, tail) = Store::recover(&mut v, 4, 1024);
    assert!(tail.is_none());
    assert!(s.write(&mut v, &batch(0, 1), 0, 1_000_000));
    assert!(String::from_utf8_lossy(&v.files[&name(0)]).starts_with("0 0 0 I logd file 1"), "slot 0 is rewritten");
}
