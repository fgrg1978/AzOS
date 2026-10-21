// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of azvol snapshots and change groups
//! (`crates/fs/fs/src/azvol/{snap,group}.rs`) over a device that can replay a
//! power cut: the writes since the last `flush` land in any subset, any of
//! them torn at a sector boundary. The format and the plain engine are in
//! `azvol_format.rs`; this file leans on what it proved and asks:
//!
//! * a snapshot keeps its content through any later write, truncate, unlink,
//!   remount and bitmap rebuild;
//! * blocks are counted by the generations that name them: they are freed
//!   when the last snapshot naming them goes, not before, not never;
//! * a power cut at any write of a snapshot create, a snapshot delete, a
//!   write after a snapshot or a change group leaves exactly the old or the
//!   new state, snapshots included, and the volume checks clean;
//! * a group is all or nothing, across files and directories, and abort
//!   gives everything back.
//!
//! Wired into the suite by `mod azvol_cow;` in `src/lib.rs`.

#![cfg(test)]

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/fs/fs/src/azvol/mod.rs"]
mod azvol;

use azvol::layout::{self, sbo, Kind, SB_SLOTS};
use azvol::{BlockDev, DevError, Error, FormatOptions, SnapView, Volume, BLOCK_SIZE};
use std::collections::BTreeMap;

const SECTOR: usize = 512;
const BS: u64 = BLOCK_SIZE as u64;

// ── the device ────────────────────────────────────────────────────

#[derive(Clone)]
enum Op {
    Write { blk: u64, data: Vec<u8> },
    Flush,
}

struct MemDev {
    img: Vec<u8>,
    log: Vec<Op>,
}

impl MemDev {
    fn new(blocks: u64) -> MemDev {
        MemDev { img: vec![0u8; blocks as usize * BLOCK_SIZE], log: Vec::new() }
    }
    fn from_image(img: Vec<u8>) -> MemDev {
        MemDev { img, log: Vec::new() }
    }
}

impl BlockDev for MemDev {
    fn block_count(&self) -> u64 {
        (self.img.len() / BLOCK_SIZE) as u64
    }
    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > self.img.len() {
            return Err(DevError);
        }
        buf.copy_from_slice(&self.img[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > self.img.len() {
            return Err(DevError);
        }
        self.img[o..o + buf.len()].copy_from_slice(buf);
        for (i, c) in buf.chunks(BLOCK_SIZE).enumerate() {
            self.log.push(Op::Write { blk: first + i as u64, data: c.to_vec() });
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), DevError> {
        self.log.push(Op::Flush);
        Ok(())
    }
}

/// How a block written but not yet behind a flush looks after the cut.
#[derive(Clone, Copy)]
enum Fate {
    Lost,
    Whole,
    /// Only the first `n` sectors of the new content landed.
    Torn(usize),
}

/// The disk after a cut before log op `cut`: everything up to the last flush
/// barrier before it is durable, the writes after it get their `fate`.
fn crash_image(base: &[u8], log: &[Op], cut: usize, fate: &dyn Fn(usize) -> Fate) -> Vec<u8> {
    let mut img = base.to_vec();
    let barrier = log[..cut].iter().rposition(|o| matches!(o, Op::Flush)).map_or(0, |i| i + 1);
    for (i, op) in log[..cut].iter().enumerate() {
        if let Op::Write { blk, data } = op {
            let dst = &mut img[*blk as usize * BLOCK_SIZE..(*blk as usize + 1) * BLOCK_SIZE];
            if i < barrier {
                dst.copy_from_slice(data);
            } else {
                match fate(i) {
                    Fate::Lost => {}
                    Fate::Whole => dst.copy_from_slice(data),
                    Fate::Torn(n) => dst[..n * SECTOR].copy_from_slice(&data[..n * SECTOR]),
                }
            }
        }
    }
    img
}

// ── helpers ───────────────────────────────────────────────────────

fn fresh(blocks: u64) -> Volume<MemDev> {
    let o = FormatOptions { block_count: None, label: b"cowvol", uuid: [9; 16], time_ns: 1_000 };
    Volume::format(MemDev::new(blocks), &o).expect("format")
}

fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn put(v: &mut Volume<MemDev>, dir: u64, name: &str, data: &[u8]) -> u64 {
    let ino = v.create(dir, name.as_bytes(), Kind::File, 0o644).expect("create");
    assert_eq!(v.write(ino, 0, data).expect("write"), data.len());
    ino
}

fn ino_of(v: &mut Volume<MemDev>, path: &str) -> u64 {
    v.lookup_path(path.as_bytes()).unwrap_or_else(|e| panic!("{path}: {e:?}"))
}

/// Replace a file's whole content (the shape of "write a new version").
fn replace(v: &mut Volume<MemDev>, ino: u64, data: &[u8]) {
    v.truncate(ino, 0).unwrap();
    assert_eq!(v.write(ino, 0, data).unwrap(), data.len());
}

type Tree = BTreeMap<String, Option<Vec<u8>>>;

/// Read access to the live volume or to one snapshot, so one walker serves both.
trait Rd {
    fn readdir(&mut self, dir: u64) -> Vec<azvol::DirEntry>;
    fn size(&mut self, ino: u64) -> usize;
    fn read(&mut self, ino: u64, off: u64, buf: &mut [u8]) -> usize;
}

struct Live<'a>(&'a mut Volume<MemDev>);
struct Snap<'a>(&'a mut Volume<MemDev>, &'a mut SnapView);

impl Rd for Live<'_> {
    fn readdir(&mut self, dir: u64) -> Vec<azvol::DirEntry> {
        self.0.readdir(dir).expect("readdir")
    }
    fn size(&mut self, ino: u64) -> usize {
        self.0.stat(ino).expect("stat").size as usize
    }
    fn read(&mut self, ino: u64, off: u64, buf: &mut [u8]) -> usize {
        self.0.read(ino, off, buf).expect("read")
    }
}

impl Rd for Snap<'_> {
    fn readdir(&mut self, dir: u64) -> Vec<azvol::DirEntry> {
        self.1.readdir(self.0, dir).expect("snapshot readdir")
    }
    fn size(&mut self, ino: u64) -> usize {
        self.1.stat(self.0, ino).expect("snapshot stat").size as usize
    }
    fn read(&mut self, ino: u64, off: u64, buf: &mut [u8]) -> usize {
        self.1.read(self.0, ino, off, buf).expect("snapshot read")
    }
}

fn dump_rd(r: &mut dyn Rd) -> Tree {
    fn walk(r: &mut dyn Rd, dir: u64, prefix: &str, out: &mut Tree) {
        for e in r.readdir(dir) {
            let path = format!("{}/{}", prefix, String::from_utf8(e.name.clone()).unwrap());
            if e.kind == Kind::Dir {
                out.insert(path.clone(), None);
                walk(r, e.ino, &path, out);
            } else {
                let size = r.size(e.ino);
                let mut data = vec![0u8; size];
                let mut done = 0;
                while done < size {
                    let n = r.read(e.ino, done as u64, &mut data[done..]);
                    assert!(n > 0);
                    done += n;
                }
                out.insert(path, Some(data));
            }
        }
    }
    let mut out = Tree::new();
    walk(r, 1, "", &mut out);
    out
}

fn dump(v: &mut Volume<MemDev>) -> Tree {
    dump_rd(&mut Live(v))
}

fn dump_snap(v: &mut Volume<MemDev>, id: u64) -> Tree {
    let mut view = v.snapshot_open(id).expect("snapshot_open");
    dump_rd(&mut Snap(v, &mut view))
}

/// Everything a mounted volume shows: the live tree and each snapshot.
#[derive(Clone, PartialEq, Eq)]
struct Full {
    live: Tree,
    snaps: BTreeMap<u64, Tree>,
}

impl std::fmt::Debug for Full {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn t(x: &Tree) -> String {
            x.iter()
                .map(|(k, v)| match v {
                    None => format!("{k}/"),
                    Some(d) => format!("{k}[{}:{:08x}]", d.len(), d.iter().fold(0u32, |a, &b| a.wrapping_mul(31).wrapping_add(b as u32))),
                })
                .collect::<Vec<_>>()
                .join(" ")
        }
        write!(f, "live: {}", t(&self.live))?;
        for (id, s) in &self.snaps {
            write!(f, " | snap {id}: {}", t(s))?;
        }
        Ok(())
    }
}

fn full(v: &mut Volume<MemDev>) -> Full {
    let live = dump(v);
    let mut snaps = BTreeMap::new();
    for s in v.snapshots() {
        snaps.insert(s.id, dump_snap(v, s.id));
    }
    Full { live, snaps }
}

fn remount(v: Volume<MemDev>) -> Volume<MemDev> {
    let dev = v.into_device();
    Volume::mount(MemDev::from_image(dev.img)).expect("remount")
}

fn assert_clean(v: &mut Volume<MemDev>) {
    let r = v.check(true).expect("check");
    assert!(r.is_clean(), "check found {:?}", r.problems);
}

/// Start logging: the image as it is now, and a volume over a cleared log.
fn begin_log(v: Volume<MemDev>) -> (Volume<MemDev>, Vec<u8>) {
    let mut dev = v.into_device();
    let base = dev.img.clone();
    dev.log.clear();
    (Volume::mount(dev).expect("mount"), base)
}

/// Replay `log` cut at every op under several fates for the writes not yet
/// behind a flush. Every crashed disk must mount, show one of the `allowed`
/// states (live tree and snapshots together) and check clean. `Err` names
/// the first case that does not.
fn try_sweep(base: &[u8], log: &[Op], allowed: &[Full]) -> Result<usize, String> {
    let mut cases = 0;
    let fates: Vec<(&str, Box<dyn Fn(usize) -> Fate>)> = vec![
        ("none", Box::new(|_| Fate::Lost)),
        ("all", Box::new(|_| Fate::Whole)),
        ("odd", Box::new(|i| if i % 2 == 1 { Fate::Whole } else { Fate::Lost })),
        ("even", Box::new(|i| if i % 2 == 0 { Fate::Whole } else { Fate::Lost })),
        ("third", Box::new(|i| if i % 3 == 0 { Fate::Whole } else { Fate::Lost })),
        ("torn", Box::new(|i| if i % 2 == 0 { Fate::Torn(1 + i % 7) } else { Fate::Whole })),
        ("torn2", Box::new(|i| if i % 3 == 1 { Fate::Torn(i % 8) } else { Fate::Lost })),
    ];
    for cut in 0..=log.len() {
        for (name, fate) in &fates {
            let img = crash_image(base, log, cut, fate.as_ref());
            let mut v = Volume::mount(MemDev::from_image(img)).map_err(|e| format!("cut {cut}/{} fate {name}: mount {e:?}", log.len()))?;
            let f = full(&mut v);
            if !allowed.contains(&f) {
                return Err(format!("cut {cut}/{} fate {name}: neither old nor new: {f:?}", log.len()));
            }
            let r = v.check(true).map_err(|e| format!("cut {cut} fate {name}: check {e:?}"))?;
            if !r.is_clean() {
                return Err(format!("cut {cut} fate {name}: {:?}", r.problems));
            }
            cases += 1;
        }
    }
    Ok(cases)
}

fn sweep(base: &[u8], log: &[Op], allowed: &[Full]) -> usize {
    let n = try_sweep(base, log, allowed).unwrap_or_else(|e| panic!("{e}"));
    // a delete is one small commit; every other scenario writes much more
    assert!(n >= 7 * 5, "swept only {n} cases");
    n
}

// ── snapshots ─────────────────────────────────────────────────────

/// A small tree with a directory, a multi-block file and a small one.
fn populate(v: &mut Volume<MemDev>) {
    let d = v.create(1, b"d", Kind::Dir, 0o755).unwrap();
    put(v, 1, "big", &pattern(1, 40 * BLOCK_SIZE + 123));
    put(v, 1, "small", b"hello snapshot");
    put(v, d, "inner", &pattern(2, 9000));
}

#[test]
fn a_snapshot_keeps_its_content_through_overwrite_truncate_unlink_and_create() {
    let mut v = fresh(2048);
    populate(&mut v);
    v.commit().unwrap();
    let before = dump(&mut v);
    let id = v.snapshot_create(b"first").unwrap();
    assert_eq!(v.snapshots().len(), 1);
    assert_eq!(v.snapshots()[0].label, b"first");
    assert_eq!(dump_snap(&mut v, id), before);

    // every kind of change to the live tree
    let big = ino_of(&mut v, "/big");
    v.write(big, 5000, &pattern(10, 70_000)).unwrap();
    let inner = ino_of(&mut v, "/d/inner");
    v.truncate(inner, 100).unwrap();
    let small = ino_of(&mut v, "/small");
    replace(&mut v, small, &pattern(11, 3 * BLOCK_SIZE));
    put(&mut v, 1, "new", &pattern(12, 20_000));
    let d = ino_of(&mut v, "/d");
    v.unlink(d, b"inner").unwrap();
    v.commit().unwrap();
    let after = dump(&mut v);
    assert_ne!(after, before);
    assert_eq!(dump_snap(&mut v, id), before, "the snapshot moved");
    assert_clean(&mut v);

    // and across a remount
    let mut v = remount(v);
    assert_eq!(dump(&mut v), after);
    assert_eq!(dump_snap(&mut v, id), before);
    assert_eq!(v.snapshots()[0].id, id);
    assert_clean(&mut v);
}

#[test]
fn a_snapshot_names_the_state_that_was_written_not_the_last_commit() {
    // snapshot_create commits first: the snapshot holds the pending writes
    let mut v = fresh(2048);
    put(&mut v, 1, "a", b"committed");
    v.commit().unwrap();
    put(&mut v, 1, "b", b"pending, not committed yet");
    let id = v.snapshot_create(b"").unwrap();
    let a = ino_of(&mut v, "/a");
    v.truncate(a, 0).unwrap();
    v.commit().unwrap();
    let snap = dump_snap(&mut v, id);
    assert_eq!(snap["/a"].as_deref(), Some(&b"committed"[..]));
    assert_eq!(snap["/b"].as_deref(), Some(&b"pending, not committed yet"[..]));
    assert_eq!(dump(&mut v)["/a"].as_deref(), Some(&b""[..]));
}

#[test]
fn a_snapshot_view_is_lent_to_the_volume_one_call_at_a_time() {
    let mut v = fresh(2048);
    populate(&mut v);
    let id = v.snapshot_create(b"s").unwrap();
    let mut view = v.snapshot_open(id).unwrap();
    // writes to the live volume between reads through the view
    let ino = view.lookup_path(&mut v, b"/big").unwrap();
    let mut got = vec![0u8; 100];
    view.read(&mut v, ino, 4000, &mut got).unwrap();
    let want = pattern(1, 40 * BLOCK_SIZE + 123);
    assert_eq!(&got[..], &want[4000..4100]);
    let live_big = ino_of(&mut v, "/big");
    v.write(live_big, 4000, &[0xEE; 100]).unwrap();
    put(&mut v, 1, "later", b"x");
    v.commit().unwrap();
    let mut got = vec![0u8; 100];
    view.read(&mut v, ino, 4000, &mut got).unwrap();
    assert_eq!(&got[..], &want[4000..4100], "the view sees the live write");
    assert!(view.lookup(&mut v, 1, b"later").is_err());
    assert_eq!(view.readdir(&mut v, 1).unwrap().len(), 3);
    assert_eq!(view.stat(&mut v, ino).unwrap().size, want.len() as u64);
    let mut live = vec![0u8; 100];
    v.read(live_big, 4000, &mut live).unwrap();
    assert_eq!(live, vec![0xEE; 100]);
    // the volume is whole after the swaps
    assert_clean(&mut v);
    // deleting the snapshot invalidates the view; nothing stale is served
    v.snapshot_delete(id).unwrap();
    assert_eq!(view.lookup(&mut v, 1, b"big").err(), Some(Error::NoSnapshot));
    assert_eq!(v.snapshot_open(id).err(), Some(Error::NoSnapshot));
    assert_clean(&mut v);
}

/// Scenario for the reference counts: one file rewritten three times with a
/// snapshot taken before the second and before the third rewrite.
struct Rounds {
    v: Volume<MemDev>,
    ino: u64,
    ids: Vec<u64>,
    versions: Vec<Vec<u8>>,
}

const FILE_BLOCKS: usize = 64;

fn rounds(snapshots: bool) -> Rounds {
    let mut v = fresh(2048);
    let versions: Vec<Vec<u8>> = (0..3).map(|i| pattern(100 + i, FILE_BLOCKS * BLOCK_SIZE)).collect();
    let ino = put(&mut v, 1, "f", &versions[0]);
    v.commit().unwrap();
    let mut ids = Vec::new();
    for i in 1..3 {
        if snapshots {
            ids.push(v.snapshot_create(format!("v{i}").as_bytes()).unwrap());
        }
        // a whole-file overwrite: every block of version i-1 is dropped
        assert_eq!(v.write(ino, 0, &versions[i]).unwrap(), versions[i].len());
        v.commit().unwrap();
    }
    Rounds { v, ino, ids, versions }
}

fn file_of(v: &mut Volume<MemDev>, id: u64) -> Vec<u8> {
    dump_snap(v, id).remove("/f").unwrap().unwrap()
}

#[test]
fn blocks_are_freed_when_the_last_snapshot_naming_them_goes() {
    let reference = rounds(false).v.statfs().blocks_used;
    for order in [[0usize, 1], [1, 0]] {
        let mut r = rounds(true);
        let [a, b] = [r.ids[0], r.ids[1]];
        let st = r.v.statfs();
        assert_eq!(st.snapshots, 2);
        // version 0 is held by the first snapshot, version 1 by the second
        assert!(st.blocks_retained >= 2 * FILE_BLOCKS as u64, "retained {}", st.blocks_retained);
        assert!(st.blocks_used >= reference + 2 * FILE_BLOCKS as u64);
        assert_eq!(file_of(&mut r.v, a), r.versions[0]);
        assert_eq!(file_of(&mut r.v, b), r.versions[1]);
        assert_clean(&mut r.v);

        let ids = [a, b];
        let first = ids[order[0]];
        let second = ids[order[1]];
        let used0 = r.v.statfs().blocks_used;
        r.v.snapshot_delete(first).unwrap();
        let st = r.v.statfs();
        assert_eq!(st.snapshots, 1);
        // exactly the first-deleted snapshot's version went; the other stays
        assert!(used0 - st.blocks_used >= FILE_BLOCKS as u64, "freed {}", used0 - st.blocks_used);
        assert!(st.blocks_used >= reference + FILE_BLOCKS as u64, "the other snapshot's version was freed too");
        let idx = ids.iter().position(|&x| x == second).unwrap();
        assert_eq!(file_of(&mut r.v, second), r.versions[idx], "order {order:?}");
        assert_clean(&mut r.v);

        r.v.snapshot_delete(second).unwrap();
        let st = r.v.statfs();
        assert_eq!((st.snapshots, st.blocks_retained), (0, 0));
        assert_eq!(st.blocks_used, reference, "order {order:?}: blocks leaked or lost");
        assert_clean(&mut r.v);
        // live data is the last version, and a remount agrees
        let mut v = remount(r.v);
        assert_eq!(dump(&mut v)["/f"].as_deref(), Some(&r.versions[2][..]));
        assert_eq!(v.statfs().blocks_used, reference);
        assert_clean(&mut v);
        let _ = r.ino;
    }
}

#[test]
fn a_block_both_snapshots_name_is_freed_with_the_second_one() {
    // the version overwritten after BOTH snapshots exist is named by both
    let mut v = fresh(2048);
    let v0 = pattern(1, 32 * BLOCK_SIZE);
    let ino = put(&mut v, 1, "f", &v0);
    let a = v.snapshot_create(b"a").unwrap();
    v.write(ino, 0, &pattern(2, 8 * BLOCK_SIZE)).unwrap(); // a's blocks 0..8 go dead for a only
    let b = v.snapshot_create(b"b").unwrap();
    v.write(ino, 0, &pattern(3, 32 * BLOCK_SIZE)).unwrap(); // blocks dead for b; the unwritten rest of v0 for both
    v.commit().unwrap();
    let both = |v: &mut Volume<MemDev>| v.statfs().blocks_retained;
    let r_all = both(&mut v);
    v.snapshot_delete(a).unwrap();
    let r_after_a = both(&mut v);
    assert!(r_after_a < r_all, "deleting a freed nothing");
    // the first 8 blocks of v0 were named by a only: gone; the rest by a and b
    assert_eq!(&dump_snap(&mut v, b)["/f"].as_deref().unwrap()[8 * BLOCK_SIZE..], &v0[8 * BLOCK_SIZE..]);
    assert_clean(&mut v);
    v.snapshot_delete(b).unwrap();
    assert_eq!(both(&mut v), 0);
    assert_clean(&mut v);
}

#[test]
fn snapshots_keep_their_tree_nodes_too() {
    // interleaved appends give two files many extents (index and leaf nodes);
    // a later rewrite of the extent list releases the old nodes
    let mut v = fresh(8192);
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    for i in 0..40u64 {
        v.write(a, i * BS, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BS, &pattern(100 + i, BLOCK_SIZE)).unwrap();
    }
    v.commit().unwrap();
    assert!(v.stat(a).unwrap().tree_nodes > 0, "setup: the tree did not grow nodes");
    let before = dump(&mut v);
    let id = v.snapshot_create(b"deep").unwrap();
    for i in 0..40u64 {
        v.write(a, i * BS, &pattern(200 + i, BLOCK_SIZE)).unwrap();
    }
    v.truncate(b, BS * 5).unwrap();
    v.commit().unwrap();
    assert_eq!(dump_snap(&mut v, id), before);
    assert_clean(&mut v);
    let mut v = remount(v);
    assert_eq!(dump_snap(&mut v, id), before);
    v.snapshot_delete(id).unwrap();
    assert_clean(&mut v);
    assert_eq!(v.statfs().blocks_retained, 0);
}

#[test]
fn a_rebuilt_bitmap_still_holds_the_snapshot_blocks() {
    let mut v = fresh(2048);
    populate(&mut v);
    let before = dump(&mut v);
    let id = v.snapshot_create(b"s").unwrap();
    let big = ino_of(&mut v, "/big");
    replace(&mut v, big, &pattern(20, 30 * BLOCK_SIZE));
    let inner = ino_of(&mut v, "/d/inner");
    v.truncate(inner, 0).unwrap();
    v.commit().unwrap();
    let live_after = dump(&mut v);
    let used = v.statfs().blocks_used;
    let mut img = v.into_device().img;
    // damage the stored bitmap: the trees are the truth
    let g = layout::Geometry::new(2048).unwrap();
    img[g.bitmap_start as usize * BLOCK_SIZE + 17] ^= 0xFF;
    let mut v = Volume::mount(MemDev::from_image(img)).unwrap();
    assert!(v.report().bitmap_rebuilt);
    assert_eq!(v.statfs().blocks_used, used, "the rebuilt map dropped or added blocks");
    assert_clean(&mut v);
    // heavy writing must not land on a block the snapshot still names
    for round in 0..6u64 {
        put(&mut v, 1, &format!("fill{round}"), &pattern(300 + round, 100 * BLOCK_SIZE));
        v.commit().unwrap();
    }
    assert_eq!(dump_snap(&mut v, id), before);
    assert_eq!(dump(&mut v).get("/big"), live_after.get("/big"));
    assert_clean(&mut v);
}

#[test]
fn deleting_every_snapshot_returns_the_volume_to_the_plain_format() {
    let mut v = fresh(2048);
    populate(&mut v);
    v.commit().unwrap();
    let incompat = |v: &Volume<MemDev>| {
        // the newest superblock copy
        let img = &v.device().img;
        SB_SLOTS
            .iter()
            .map(|s| {
                let o = *s as usize * BLOCK_SIZE;
                (layout::rd64(img, o + sbo::GENERATION), layout::rd32(img, o + sbo::INCOMPAT))
            })
            .max()
            .unwrap()
            .1
    };
    assert_eq!(incompat(&v), 0);
    let a = v.snapshot_create(b"a").unwrap();
    assert_eq!(incompat(&v), layout::INCOMPAT_SNAPSHOTS);
    let big = ino_of(&mut v, "/big");
    replace(&mut v, big, &pattern(5, BLOCK_SIZE));
    v.commit().unwrap();
    let b = v.snapshot_create(b"b").unwrap();
    v.snapshot_delete(a).unwrap();
    assert_eq!(incompat(&v), layout::INCOMPAT_SNAPSHOTS);
    v.snapshot_delete(b).unwrap();
    // no snapshot, no dead list: the feature bit and both records are gone
    assert_eq!(incompat(&v), 0);
    let img = &v.device().img;
    let newest = SB_SLOTS.iter().map(|s| (layout::rd64(img, *s as usize * BLOCK_SIZE + sbo::GENERATION), *s)).max().unwrap().1;
    let sb = &img[newest as usize * BLOCK_SIZE..(newest as usize + 1) * BLOCK_SIZE];
    assert!(sb[sbo::SNAPTAB..sbo::SNAPTAB + 2 * layout::INODE_SIZE].iter().all(|&x| x == 0));
    assert_clean(&mut v);
    assert_eq!(v.snapshot_delete(a).err(), Some(Error::NoSnapshot));
}

#[test]
fn a_damaged_snapshot_table_or_dead_list_is_an_error_not_a_lost_snapshot() {
    let mut v = fresh(2048);
    populate(&mut v);
    v.snapshot_create(b"s").unwrap();
    let big = ino_of(&mut v, "/big");
    replace(&mut v, big, &pattern(5, 4 * BLOCK_SIZE));
    v.commit().unwrap();
    let img = v.into_device().img;
    let newest = SB_SLOTS.iter().map(|s| (layout::rd64(&img, *s as usize * BLOCK_SIZE + sbo::GENERATION), *s)).max().unwrap().1;
    let sb = layout::Superblock::decode(&img[newest as usize * BLOCK_SIZE..(newest as usize + 1) * BLOCK_SIZE]).unwrap();
    for (name, rec) in [("snapshot table", sb.snaptab), ("dead list", sb.deadlist)] {
        assert_eq!(rec.level, 0);
        let e = layout::Extent::decode(&rec.root[..layout::ENTRY_SIZE]);
        let mut bad = img.clone();
        bad[e.disk_blk as usize * BLOCK_SIZE + 5] ^= 0x40;
        assert!(matches!(Volume::mount(MemDev::from_image(bad)), Err(Error::Checksum(b)) if b == e.disk_blk), "{name}");
    }
}

#[test]
fn refs_counts_the_generations_between_born_and_died() {
    use azvol::snap::{refs, SnapRec};
    let rec = |gen| SnapRec {
        gen,
        created_ns: 0,
        inode_slots: 2,
        label: [0; layout::LABEL_LEN],
        itable: layout::InodeDisk::empty_aux(0),
    };
    let s = [rec(4), rec(7), rec(9)];
    assert_eq!(refs(&s, 1, 4), 0, "died the commit the snapshot retains: not named");
    assert_eq!(refs(&s, 1, 5), 1);
    assert_eq!(refs(&s, 4, 5), 1, "born the retained generation: named");
    assert_eq!(refs(&s, 5, 7), 0);
    assert_eq!(refs(&s, 5, 8), 1);
    assert_eq!(refs(&s, 1, 100), 3);
    assert_eq!(refs(&s, 10, 100), 0);
    assert_eq!(refs(&[], 1, 100), 0);
}

// ── power cuts ────────────────────────────────────────────────────

#[test]
fn power_cut_during_snapshot_create_leaves_the_old_state_or_the_snapshot() {
    let mut v = fresh(2048);
    populate(&mut v);
    v.commit().unwrap();
    let s0 = full(&mut v);
    let (mut v, base) = begin_log(v);
    // work not yet committed: it joins the snapshot's first commit
    let big = ino_of(&mut v, "/big");
    v.write(big, 100, &pattern(30, 20_000)).unwrap();
    put(&mut v, 1, "late", b"written just before the snapshot");
    // state with the pending work committed and no snapshot yet
    let id = v.snapshot_create(b"cut").unwrap();
    let s2 = full(&mut v);
    assert_eq!(s2.snaps.len(), 1);
    assert_eq!(s2.snaps[&id], s2.live, "the snapshot is of the state just written");
    let s1 = Full { live: s2.live.clone(), snaps: BTreeMap::new() };
    let log = v.device().log.clone();
    assert!(log.iter().filter(|o| matches!(o, Op::Flush)).count() >= 4, "two commits expected");
    sweep(&base, &log, &[s0, s1, s2]);
}

#[test]
fn power_cut_during_snapshot_delete_leaves_the_snapshot_whole_or_gone() {
    let mut v = fresh(2048);
    populate(&mut v);
    let a = v.snapshot_create(b"a").unwrap();
    let big = ino_of(&mut v, "/big");
    replace(&mut v, big, &pattern(40, 50 * BLOCK_SIZE));
    let b = v.snapshot_create(b"b").unwrap();
    replace(&mut v, big, &pattern(41, 50 * BLOCK_SIZE));
    v.commit().unwrap();
    let with = full(&mut v);
    assert_eq!(with.snaps.len(), 2);
    let (mut v, base) = begin_log(v);
    v.snapshot_delete(a).unwrap();
    let without = full(&mut v);
    assert!(!without.snaps.contains_key(&a) && without.snaps.contains_key(&b));
    let log = v.device().log.clone();
    sweep(&base, &log, &[with.clone(), without.clone()]);
    // and the last one, which frees every dead run
    let (mut v, base) = begin_log(v);
    v.snapshot_delete(b).unwrap();
    let none = Full { live: without.live.clone(), snaps: BTreeMap::new() };
    assert_eq!(full(&mut v), none);
    let log = v.device().log.clone();
    sweep(&base, &log, &[without, none]);
}

#[test]
fn power_cut_during_writes_after_a_snapshot_never_touches_the_snapshot() {
    let mut v = fresh(2048);
    populate(&mut v);
    v.snapshot_create(b"keep").unwrap();
    v.commit().unwrap();
    // two rounds, so the second reuses blocks the first one freed
    for round in 0..2u64 {
        let s_old = full(&mut v);
        let (mut w, base) = begin_log(v);
        let big = ino_of(&mut w, "/big");
        w.write(big, 3000, &pattern(50 + round, 60_000)).unwrap();
        let inner = ino_of(&mut w, "/d/inner");
        w.truncate(inner, 4000 * (round + 1)).unwrap();
        put(&mut w, 1, &format!("r{round}"), &pattern(60 + round, 15_000));
        w.commit().unwrap();
        let s_new = full(&mut w);
        assert_eq!(s_new.snaps, s_old.snaps);
        let log = w.device().log.clone();
        sweep(&base, &log, &[s_old, s_new]);
        v = w;
    }
}

/// The write set of one change group, over `populate`: replace one file,
/// shrink another, create across directories, unlink, make a directory.
fn group_work(v: &mut Volume<MemDev>) {
    let big = ino_of(v, "/big");
    replace(v, big, &pattern(70, 25 * BLOCK_SIZE + 17));
    let small = ino_of(v, "/small");
    v.write(small, 5, b"XX").unwrap();
    let d = ino_of(v, "/d");
    put(v, d, "second", &pattern(71, 7000));
    v.unlink(d, b"inner").unwrap();
    let e = v.create(1, b"e", Kind::Dir, 0o755).unwrap();
    put(v, e, "deep", &pattern(72, 3 * BLOCK_SIZE));
}

#[test]
fn a_change_group_is_atomic_across_files_and_directories() {
    for with_snapshot in [false, true] {
        let mut v = fresh(2048);
        populate(&mut v);
        if with_snapshot {
            v.snapshot_create(b"under").unwrap();
        }
        v.commit().unwrap();
        let old = full(&mut v);
        let (mut v, base) = begin_log(v);
        v.begin_group().unwrap();
        assert!(v.in_group());
        group_work(&mut v);
        v.commit_group().unwrap();
        assert!(!v.in_group());
        let new = full(&mut v);
        assert_ne!(old.live, new.live);
        assert_eq!(old.snaps, new.snaps);
        let log = v.device().log.clone();
        // the writes of the group come before its commit, so cuts inside the
        // group show the old state and cuts inside the commit old or new
        sweep(&base, &log, &[old, new]);
        assert_clean(&mut v);
    }
}

#[test]
fn the_same_work_in_separate_commits_does_show_in_between_states() {
    // canary: the sweep above would accept ANY state sequence if it were
    // blind; here the work is committed step by step and the sweep, given
    // only the first and the last state, must find the steps in between
    let mut v = fresh(2048);
    populate(&mut v);
    v.commit().unwrap();
    let old = full(&mut v);
    let (mut v, base) = begin_log(v);
    let big = ino_of(&mut v, "/big");
    replace(&mut v, big, &pattern(70, 25 * BLOCK_SIZE + 17));
    v.commit().unwrap();
    let small = ino_of(&mut v, "/small");
    v.write(small, 5, b"XX").unwrap();
    v.commit().unwrap();
    let new = full(&mut v);
    let log = v.device().log.clone();
    let r = try_sweep(&base, &log, &[old, new]);
    assert!(r.is_err(), "the in-between commits were not seen");
}

#[test]
fn power_cut_during_a_group_that_runs_over_a_deep_tree_and_a_snapshot() {
    let mut v = fresh(8192);
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    for i in 0..30u64 {
        v.write(a, i * BS, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BS, &pattern(100 + i, BLOCK_SIZE)).unwrap();
    }
    v.snapshot_create(b"deep").unwrap();
    let old = full(&mut v);
    let (mut v, base) = begin_log(v);
    v.begin_group().unwrap();
    for i in 0..30u64 {
        v.write(a, i * BS, &pattern(500 + i, BLOCK_SIZE)).unwrap();
    }
    v.truncate(b, 3 * BS).unwrap();
    v.commit_group().unwrap();
    let new = full(&mut v);
    let log = v.device().log.clone();
    sweep(&base, &log, &[old, new]);
}

// ── change groups ─────────────────────────────────────────────────

#[test]
fn abort_gives_everything_back() {
    let mut v = fresh(2048);
    populate(&mut v);
    v.commit().unwrap();
    let before = full(&mut v);
    let used = v.statfs();
    let gen = v.generation();
    v.begin_group().unwrap();
    group_work(&mut v);
    assert_ne!(dump(&mut v), before.live, "setup: the group changed nothing");
    v.abort_group().unwrap();
    assert!(!v.in_group());
    assert_eq!(full(&mut v), before);
    let st = v.statfs();
    assert_eq!((st.blocks_used, st.blocks_pending_free, st.inode_slots), (used.blocks_used, 0, used.inode_slots));
    assert_eq!(v.generation(), gen, "an abort committed something");
    assert_clean(&mut v);
    // the same work again, committed this time, lands
    v.begin_group().unwrap();
    group_work(&mut v);
    v.commit_group().unwrap();
    let after = dump(&mut v);
    assert_ne!(after, before.live);
    assert_clean(&mut v);
    let mut v = remount(v);
    assert_eq!(dump(&mut v), after);
    assert_clean(&mut v);
}

#[test]
fn abort_restores_the_free_inode_list_and_the_blocks_of_a_snapshot() {
    let mut v = fresh(2048);
    populate(&mut v);
    // free an inode so the list is not empty
    let d = ino_of(&mut v, "/d");
    v.unlink(d, b"inner").unwrap();
    let id = v.snapshot_create(b"s").unwrap();
    let before = full(&mut v);
    let used = v.statfs().blocks_used;
    v.begin_group().unwrap();
    // reuses the freed inode slot, drops blocks the snapshot names (they go
    // to the dead list inside the group), allocates fresh ones
    put(&mut v, d, "reborn", &pattern(80, 5000));
    let big = ino_of(&mut v, "/big");
    replace(&mut v, big, &pattern(81, 10 * BLOCK_SIZE));
    v.abort_group().unwrap();
    assert_eq!(full(&mut v), before);
    assert_eq!(v.statfs().blocks_used, used);
    assert_eq!(dump_snap(&mut v, id), before.snaps[&id]);
    assert_clean(&mut v);
    // the inode slot is still the first one a create takes
    let again = put(&mut v, d, "reborn", b"x");
    v.commit().unwrap();
    let mut w = remount(v);
    assert_eq!(ino_of(&mut w, "/d/reborn"), again);
    assert_clean(&mut w);
}

#[test]
fn a_group_that_runs_out_of_space_is_aborted_cleanly() {
    let mut v = fresh(512);
    put(&mut v, 1, "keep", &pattern(90, 20 * BLOCK_SIZE));
    v.commit().unwrap();
    let before = full(&mut v);
    let used = v.statfs().blocks_used;
    v.begin_group().unwrap();
    let mut failed = false;
    for i in 0..40u64 {
        let ino = match v.create(1, format!("f{i}").as_bytes(), Kind::File, 0o644) {
            Ok(x) => x,
            Err(Error::NoSpace) => {
                failed = true;
                break;
            }
            Err(e) => panic!("{e:?}"),
        };
        match v.write(ino, 0, &pattern(i, 20 * BLOCK_SIZE)) {
            Ok(n) if n == 20 * BLOCK_SIZE => {}
            Ok(_) | Err(Error::NoSpace) => {
                failed = true;
                break;
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(failed, "setup: the volume never filled");
    v.abort_group().unwrap();
    assert_eq!(full(&mut v), before);
    assert_eq!(v.statfs().blocks_used, used);
    assert_clean(&mut v);
    // all the space is usable again
    put(&mut v, 1, "after", &pattern(91, 100 * BLOCK_SIZE));
    v.commit().unwrap();
    assert_clean(&mut v);
}

#[test]
fn a_group_excludes_what_would_end_it_early() {
    let mut v = fresh(2048);
    put(&mut v, 1, "a", b"a");
    // the pending write is committed when the group opens: it is not part of it
    v.begin_group().unwrap();
    assert_eq!(v.begin_group().err(), Some(Error::GroupOpen));
    assert_eq!(v.commit().err(), Some(Error::GroupOpen));
    assert_eq!(v.check(false).err(), Some(Error::GroupOpen));
    assert_eq!(v.snapshot_create(b"x").err(), Some(Error::GroupOpen));
    assert_eq!(v.snapshot_delete(1).err(), Some(Error::GroupOpen));
    put(&mut v, 1, "b", b"b");
    v.abort_group().unwrap();
    let names: Vec<_> = dump(&mut v).keys().cloned().collect();
    assert_eq!(names, vec!["/a"], "the pending write before the group was lost or the group's was kept");
    let mut v = remount(v);
    assert_eq!(dump(&mut v).keys().cloned().collect::<Vec<_>>(), vec!["/a"], "the pre-group write was not durable");
    assert_eq!(v.commit_group().err(), Some(Error::NoGroup));
    assert_eq!(v.abort_group().err(), Some(Error::NoGroup));
    // an empty group commits nothing
    let gen = v.generation();
    v.begin_group().unwrap();
    v.commit_group().unwrap();
    assert_eq!(v.generation(), gen);
    // reads inside a group see its own writes
    v.begin_group().unwrap();
    let ino = put(&mut v, 1, "c", b"seen");
    let mut b = [0u8; 4];
    assert_eq!(v.read(ino, 0, &mut b).unwrap(), 4);
    assert_eq!(&b, b"seen");
    v.commit_group().unwrap();
    assert_clean(&mut v);
}

// ── a model-checked mix of everything ──────────────────────────────

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

type Model = BTreeMap<String, Vec<u8>>;

fn as_model(t: Tree) -> Model {
    t.into_iter().map(|(k, v)| (k.trim_start_matches('/').to_string(), v.expect("flat tree"))).collect()
}

fn verify(v: &mut Volume<MemDev>, live: &Model, snaps: &[(u64, Model)], when: &str) {
    assert_eq!(&as_model(dump(v)), live, "{when}: live tree");
    for (id, m) in snaps {
        assert_eq!(&as_model(dump_snap(v, *id)), m, "{when}: snapshot {id}");
    }
    assert_eq!(v.snapshots().len(), snaps.len(), "{when}");
}

fn model_run(seed: u64, steps: usize) {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut v = fresh(4096);
    let mut live = Model::new();
    let mut snaps: Vec<(u64, Model)> = Vec::new();
    let mut group_base: Option<Model> = None;
    for step in 0..steps {
        let name = format!("f{}", rng.below(5));
        match rng.below(100) {
            0..=34 => {
                let off = rng.below(20_000);
                let data = pattern(rng.next(), rng.below(9000) as usize + 1);
                let ino = match v.lookup(1, name.as_bytes()) {
                    Ok(e) => e.ino,
                    Err(Error::NotFound) => v.create(1, name.as_bytes(), Kind::File, 0o644).unwrap(),
                    Err(e) => panic!("{e:?}"),
                };
                assert_eq!(v.write(ino, off, &data).unwrap(), data.len(), "seed {seed} step {step}");
                let f = live.entry(name).or_default();
                if f.len() < off as usize + data.len() {
                    f.resize(off as usize + data.len(), 0);
                }
                f[off as usize..off as usize + data.len()].copy_from_slice(&data);
            }
            35..=44 => {
                if let Some(f) = live.get_mut(&name) {
                    let size = rng.below(30_000);
                    let ino = v.lookup(1, name.as_bytes()).unwrap().ino;
                    v.truncate(ino, size).unwrap();
                    f.resize(size as usize, 0);
                }
            }
            45..=52 => {
                if live.remove(&name).is_some() {
                    v.unlink(1, name.as_bytes()).unwrap();
                }
            }
            53..=59 => {
                if group_base.is_none() && snaps.len() < 4 {
                    let id = v.snapshot_create(b"m").unwrap();
                    snaps.push((id, live.clone()));
                }
            }
            60..=65 => {
                if group_base.is_none() && !snaps.is_empty() {
                    let (id, _) = snaps.remove(rng.below(snaps.len() as u64) as usize);
                    v.snapshot_delete(id).unwrap();
                }
            }
            66..=71 => {
                if group_base.is_none() {
                    v.commit().unwrap();
                }
            }
            72..=77 => {
                if group_base.is_none() {
                    v.begin_group().unwrap();
                    group_base = Some(live.clone());
                }
            }
            78..=83 => {
                if group_base.take().is_some() {
                    v.commit_group().unwrap();
                }
            }
            84..=88 => {
                if let Some(b) = group_base.take() {
                    v.abort_group().unwrap();
                    live = b;
                }
            }
            89..=92 => {
                if group_base.is_none() {
                    v.commit().unwrap();
                    v = remount(v);
                }
            }
            _ => verify(&mut v, &live, &snaps, &format!("seed {seed} step {step}")),
        }
    }
    if group_base.take().is_some() {
        v.commit_group().unwrap();
    }
    verify(&mut v, &live, &snaps, &format!("seed {seed} end"));
    assert_clean(&mut v);
    let mut v = remount(v);
    verify(&mut v, &live, &snaps, &format!("seed {seed} remounted"));
    for (id, _) in &snaps {
        v.snapshot_delete(*id).unwrap();
    }
    assert_eq!(v.statfs().blocks_retained, 0);
    assert_clean(&mut v);
    assert_eq!(&as_model(dump(&mut v)), &live);
}

#[test]
fn random_mixes_of_writes_snapshots_and_groups_match_a_model() {
    for seed in 1..=8 {
        model_run(seed, 350);
    }
}

/// The engine asks the delete gate before it drops a snapshot (`storage_delete`
/// of the effect gate): a refusal is `Error::Denied` and the snapshot stays,
/// whole and openable; an answer of yes drops it as before. **Canary.**
/// `envelope-delete-canary`: the engine never asks, the drop goes, red.
#[test]
fn a_refused_snapshot_drop_leaves_the_snapshot() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static ASKED: AtomicU32 = AtomicU32::new(0);
    static YES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    fn gate(op: azos_common::envelope::DeleteOp, volume: u64) -> bool {
        assert_eq!(op, azos_common::envelope::DeleteOp::SnapshotDrop);
        assert_ne!(volume, 0, "the volume's uuid names it");
        ASKED.fetch_add(1, Ordering::SeqCst);
        YES.load(Ordering::SeqCst)
    }
    let mut v = fresh(2048);
    populate(&mut v);
    v.commit().unwrap();
    let id = v.snapshot_create(b"keep").unwrap();
    v.set_delete_gate(gate);
    assert_eq!(v.snapshot_delete(id), Err(Error::Denied));
    assert_eq!(ASKED.load(Ordering::SeqCst), 1);
    assert_eq!(v.snapshots().len(), 1, "still retained");
    v.snapshot_open(id).expect("and still openable");
    assert_clean(&mut v);
    YES.store(true, Ordering::SeqCst);
    v.snapshot_delete(id).unwrap();
    assert!(v.snapshots().is_empty());
    assert_clean(&mut v);
    // A missing id is the engine's NoSnapshot, after the gate's yes.
    assert_eq!(v.snapshot_delete(id), Err(Error::NoSnapshot));
}
