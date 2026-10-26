// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the azvol on-disk format and its read/write engine
//! (`crates/fs/src/azvol/`), pulled whole with `#[path]` and driven over
//! an in-memory device that can replay a power cut: the writes since the
//! last `flush` land in any subset, any of them torn at a sector boundary.
//!
//! Wired into the suite by `mod azvol_format;` in `src/lib.rs`.

#![cfg(test)]

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/fs/src/azvol/mod.rs"]
mod azvol;

use azvol::layout::{self, sbo, Kind, SB_SLOTS};
use azvol::{BlockDev, DevError, Error, FormatOptions, Volume, BLOCK_SIZE};
use std::collections::BTreeMap;

const SECTOR: usize = 512;

// ── the device ─────────────────────────────────────────────────────

#[derive(Clone)]
enum Op {
    /// One block written (multi-block writes are logged block by block).
    Write { blk: u64, data: Vec<u8> },
    Flush,
}

#[derive(Clone)]
struct MemDev {
    img: Vec<u8>,
    log: Vec<Op>,
    /// Fail every call from the `n`-th write on (`None` = never).
    fail_after_writes: Option<usize>,
    writes: usize,
}

impl MemDev {
    fn new(blocks: u64) -> MemDev {
        MemDev { img: vec![0u8; blocks as usize * BLOCK_SIZE], log: Vec::new(), fail_after_writes: None, writes: 0 }
    }

    fn from_image(img: Vec<u8>) -> MemDev {
        MemDev { img, log: Vec::new(), fail_after_writes: None, writes: 0 }
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
        if let Some(n) = self.fail_after_writes {
            if self.writes >= n {
                return Err(DevError);
            }
        }
        self.writes += 1;
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

/// How a block written but not yet covered by a flush looks after the cut.
#[derive(Clone, Copy)]
enum Fate {
    Lost,
    Whole,
    /// Only the first `n` sectors of the new content landed.
    Torn(usize),
}

/// The disk after a power cut at `cut` (the log index of the first op that
/// did not happen): everything up to the last flush barrier before it is
/// durable, the writes after that barrier get their `fate`.
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

// ── helpers ────────────────────────────────────────────────────────

fn opts(blocks: Option<u64>) -> FormatOptions<'static> {
    FormatOptions { block_count: blocks, label: b"testvol", uuid: [7; 16], time_ns: 1_000 }
}

fn fresh(blocks: u64) -> Volume<MemDev> {
    Volume::format(MemDev::new(blocks), &opts(None)).expect("format")
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

fn read_all(v: &mut Volume<MemDev>, ino: u64) -> Vec<u8> {
    let size = v.stat(ino).expect("stat").size as usize;
    let mut out = vec![0u8; size];
    let mut done = 0;
    while done < size {
        let n = v.read(ino, done as u64, &mut out[done..]).expect("read");
        assert!(n > 0);
        done += n;
    }
    out
}

/// Every path of the volume with its content (`None` for a directory).
fn dump(v: &mut Volume<MemDev>) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(v: &mut Volume<MemDev>, dir: u64, prefix: &str, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for e in v.readdir(dir).expect("readdir") {
            let path = format!("{}/{}", prefix, String::from_utf8(e.name.clone()).unwrap());
            if e.kind == Kind::Dir {
                out.insert(path.clone(), None);
                walk(v, e.ino, &path, out);
            } else {
                let data = read_all(v, e.ino);
                out.insert(path, Some(data));
            }
        }
    }
    let mut out = BTreeMap::new();
    let root = v.root();
    walk(v, root, "", &mut out);
    out
}

fn remount(v: Volume<MemDev>) -> Volume<MemDev> {
    let dev = v.into_device();
    Volume::mount(MemDev::from_image(dev.img)).expect("remount")
}

fn assert_clean(v: &mut Volume<MemDev>) {
    let r = v.check(true).expect("check");
    assert!(r.is_clean(), "check found {:?}", r.problems);
}

// ── checksum, geometry, superblock ──────────────────────────────

#[test]
fn crc32c_known_vectors() {
    use azvol::crc32c::{crc32c, crc32c_update};
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(crc32c(&[]), 0);
    assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
    let asc: Vec<u8> = (0u8..32).collect();
    assert_eq!(crc32c(&asc), 0x46DD_794E);
    let desc: Vec<u8> = (0u8..32).rev().collect();
    assert_eq!(crc32c(&desc), 0x113F_DB5C);
    assert_eq!(crc32c_update(crc32c(b"1234"), b"56789"), 0xE306_9283);
}

#[test]
fn geometry_follows_the_block_count() {
    let g = layout::Geometry::new(4096).unwrap();
    assert_eq!((g.bitmap_start, g.bitmap_blocks), (128, 1));
    assert_eq!((g.csum_start, g.csum_blocks), (129, 4));
    assert_eq!(g.data_start, 133);
    // one bitmap block and one checksum block: data starts at 130
    assert_eq!(layout::Geometry::new(146).unwrap().data_start, 130);
    assert!(layout::Geometry::new(145).is_none());
    // a bitmap block holds 32736 bits
    assert_eq!(layout::Geometry::new(32737 + 200).unwrap().bitmap_blocks, 2);
}

#[test]
fn format_mount_empty_volume() {
    let mut v = fresh(4096);
    assert_eq!(v.generation(), 2);
    assert_eq!(v.label(), b"testvol");
    assert_eq!(v.uuid(), [7; 16]);
    assert!(v.readdir(1).unwrap().is_empty());
    let st = v.stat(1).unwrap();
    assert_eq!((st.kind, st.mode, st.ctime_ns), (Kind::Dir, 0o755, 1_000));
    assert_clean(&mut v);
    let mut v = remount(v);
    let r = v.report();
    assert_eq!((r.generation, r.slot, r.other_valid, r.bitmap_rebuilt), (2, 0, true, false));
    assert!(v.readdir(1).unwrap().is_empty());
    assert_clean(&mut v);
}

#[test]
fn format_refuses_a_device_that_is_too_small() {
    let dev = MemDev::new(100);
    assert_eq!(Volume::format(dev, &opts(None)).err(), Some(Error::TooSmall));
    let dev = MemDev::new(4096);
    assert_eq!(Volume::format(dev, &opts(Some(8192))).err(), Some(Error::TooSmall));
}

#[test]
fn format_clears_what_was_there_before() {
    let mut dev = MemDev::new(4096);
    for b in dev.img.iter_mut() {
        *b = 0xA5;
    }
    let mut v = Volume::format(dev, &opts(None)).unwrap();
    assert!(v.readdir(1).unwrap().is_empty());
    assert_clean(&mut v);
}

#[test]
fn a_blank_device_is_not_a_volume() {
    assert_eq!(Volume::mount(MemDev::new(4096)).err(), Some(Error::BadMagic));
}

#[test]
fn unknown_features_and_a_key_slot_without_its_geometry_are_refused() {
    let v = fresh(4096);
    let img = v.into_device().img;
    // find the newest copy (generation 2 lives in slot 0)
    let patch = |f: &dyn Fn(&mut [u8])| -> Vec<u8> {
        let mut img = img.clone();
        for s in SB_SLOTS {
            let blk = &mut img[s as usize * BLOCK_SIZE..(s as usize + 1) * BLOCK_SIZE];
            f(blk);
            let c = azvol::crc32c::crc32c_update(0, &blk[..sbo::CRC]);
            let c = azvol::crc32c::crc32c_update(c, &[0; 4]);
            let c = azvol::crc32c::crc32c_update(c, &blk[sbo::CRC + 4..]);
            layout::wr32(blk, sbo::CRC, c);
        }
        img
    };
    let incompat = patch(&|b| layout::wr32(b, sbo::INCOMPAT, 1));
    assert_eq!(Volume::mount(MemDev::from_image(incompat)).err(), Some(Error::NoSuperblock));
    let keyed = patch(&|b| layout::wr32(b, sbo::KEY_ALG, 1));
    assert_eq!(Volume::mount(MemDev::from_image(keyed)).err(), Some(Error::NoSuperblock));
    let geo = patch(&|b| layout::wr64(b, sbo::DATA_START, 134));
    assert_eq!(Volume::mount(MemDev::from_image(geo)).err(), Some(Error::NoSuperblock));
    // and the decoder says why
    let mut blk = vec![0u8; BLOCK_SIZE];
    blk.copy_from_slice(&patch(&|b| layout::wr32(b, sbo::KEY_ALG, 2))[..BLOCK_SIZE]);
    assert_eq!(layout::Superblock::decode(&blk).err(), Some(Error::Unsupported("key algorithm")));
}

// ── create, write, read back ───────────────────────────────────────

#[test]
fn create_write_read_back_across_sizes() {
    let mut v = fresh(4096);
    let sizes = [0usize, 1, 511, 4095, 4096, 4097, 8192, 100_000, 3 << 20];
    let mut inos = Vec::new();
    for (i, &n) in sizes.iter().enumerate() {
        let name = format!("f{i}");
        inos.push((put(&mut v, 1, &name, &pattern(i as u64 + 1, n)), n));
    }
    for (i, (ino, n)) in inos.iter().enumerate() {
        assert_eq!(read_all(&mut v, *ino), pattern(i as u64 + 1, *n), "size {n} before commit");
    }
    v.commit().unwrap();
    let mut v = remount(v);
    for (i, &n) in sizes.iter().enumerate() {
        let ino = v.lookup_path(format!("/f{i}").as_bytes()).unwrap();
        assert_eq!(read_all(&mut v, ino), pattern(i as u64 + 1, n), "size {n} after remount");
    }
    assert_clean(&mut v);
}

#[test]
fn unaligned_overwrite_append_and_short_read() {
    let mut v = fresh(4096);
    let f = put(&mut v, 1, "f", &pattern(1, 10_000));
    v.commit().unwrap();
    let mut model = pattern(1, 10_000);
    // overwrite across a block boundary, then append, then overwrite again
    for (off, len, seed) in [(4090usize, 20usize, 2u64), (10_000, 7000, 3), (3, 17_000, 4), (16_990, 9, 5)] {
        let d = pattern(seed, len);
        assert_eq!(v.write(f, off as u64, &d).unwrap(), len);
        if model.len() < off + len {
            model.resize(off + len, 0);
        }
        model[off..off + len].copy_from_slice(&d);
        assert_eq!(read_all(&mut v, f), model);
        v.commit().unwrap();
    }
    let mut v = remount(v);
    let f = v.lookup_path(b"/f").unwrap();
    assert_eq!(read_all(&mut v, f), model);
    // a read past the end is short, at the end empty
    let mut b = [0u8; 100];
    assert_eq!(v.read(f, model.len() as u64 - 10, &mut b).unwrap(), 10);
    assert_eq!(v.read(f, model.len() as u64, &mut b).unwrap(), 0);
    assert_eq!(v.read(f, 1 << 40, &mut b).unwrap(), 0);
    assert_clean(&mut v);
}

#[test]
fn holes_read_as_zeros_and_cost_nothing() {
    let mut v = fresh(4096);
    let f = v.create(1, b"sparse", Kind::File, 0o600).unwrap();
    v.write(f, 1 << 20, b"tail").unwrap();
    v.write(f, 0, b"head").unwrap();
    let st = v.stat(f).unwrap();
    assert_eq!(st.size, (1 << 20) + 4);
    assert_eq!(st.blocks, 2);
    let all = read_all(&mut v, f);
    assert_eq!(&all[..4], b"head");
    assert!(all[4..(1 << 20)].iter().all(|&b| b == 0));
    assert_eq!(&all[1 << 20..], b"tail");
    v.commit().unwrap();
    assert_clean(&mut v);
}

#[test]
fn truncate_shrinks_zeroes_the_tail_and_grows_with_zeros() {
    let mut v = fresh(4096);
    let f = put(&mut v, 1, "f", &pattern(9, 20_000));
    v.commit().unwrap();
    v.truncate(f, 5000).unwrap();
    assert_eq!(read_all(&mut v, f), pattern(9, 20_000)[..5000].to_vec());
    v.commit().unwrap();
    // grow again: the bytes between 5000 and the new size are zeros, not
    // the old tail of the block
    v.truncate(f, 12_000).unwrap();
    let all = read_all(&mut v, f);
    assert_eq!(&all[..5000], &pattern(9, 20_000)[..5000]);
    assert!(all[5000..].iter().all(|&b| b == 0), "truncate resurrected old bytes");
    v.commit().unwrap();
    let mut v = remount(v);
    let f = v.lookup_path(b"/f").unwrap();
    assert_eq!(read_all(&mut v, f), all);
    v.truncate(f, 0).unwrap();
    v.commit().unwrap();
    assert_eq!(v.stat(f).unwrap().blocks, 0);
    assert_clean(&mut v);
}

#[test]
fn directories_nest_grow_and_refuse_bad_names() {
    let mut v = fresh(8192);
    let a = v.create(1, b"a", Kind::Dir, 0o755).unwrap();
    let b = v.create(a, b"b", Kind::Dir, 0o755).unwrap();
    let f = put(&mut v, b, "leaf.txt", b"hello");
    assert_eq!(v.lookup_path(b"/a/b/leaf.txt").unwrap(), f);
    assert_eq!(v.lookup(1, b"nope").err(), Some(Error::NotFound));
    assert_eq!(v.create(1, b"a", Kind::Dir, 0).err(), Some(Error::Exists));
    assert_eq!(v.create(f, b"x", Kind::File, 0).err(), Some(Error::NotDir));
    assert_eq!(v.read(a, 0, &mut [0u8; 4]).err(), Some(Error::IsDir));
    assert_eq!(v.write(a, 0, b"x").err(), Some(Error::IsDir));
    for bad in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
        assert_eq!(v.create(1, bad, Kind::File, 0).err(), Some(Error::NameInvalid), "{bad:?}");
    }
    assert_eq!(v.create(1, &[b'x'; 256], Kind::File, 0).err(), Some(Error::NameInvalid));
    v.create(1, &[b'y'; 255], Kind::File, 0).unwrap();
    // 600 entries: the directory spans several blocks
    let big = v.create(1, b"big", Kind::Dir, 0o755).unwrap();
    for i in 0..600 {
        put(&mut v, big, &format!("entry-with-a-longish-name-{i:05}"), format!("{i}").as_bytes());
    }
    assert!(v.stat(big).unwrap().size > BLOCK_SIZE as u64);
    v.commit().unwrap();
    let mut v = remount(v);
    for i in (0..600).step_by(37) {
        let ino = v.lookup_path(format!("/big/entry-with-a-longish-name-{i:05}").as_bytes()).unwrap();
        assert_eq!(read_all(&mut v, ino), format!("{i}").as_bytes());
    }
    assert_eq!(v.readdir(big).unwrap().len(), 600);
    // remove two thirds and add some back: freed record slots are reused
    for i in 0..600 {
        if i % 3 != 0 {
            v.unlink(big, format!("entry-with-a-longish-name-{i:05}").as_bytes()).unwrap();
        }
    }
    let size_before = v.stat(big).unwrap().size;
    for i in 0..390 {
        put(&mut v, big, &format!("again-{i:05}"), b"x");
    }
    assert_eq!(v.stat(big).unwrap().size, size_before, "freed directory records were not reused");
    assert_eq!(v.readdir(big).unwrap().len(), 200 + 390);
    v.commit().unwrap();
    assert_clean(&mut v);
}

#[test]
fn unlink_rules_and_inode_reuse() {
    let mut v = fresh(4096);
    let d = v.create(1, b"d", Kind::Dir, 0o755).unwrap();
    let f = put(&mut v, d, "f", b"data");
    assert_eq!(v.unlink(1, b"d").err(), Some(Error::NotEmpty));
    assert_eq!(v.unlink(1, b"missing").err(), Some(Error::NotFound));
    let igen = v.stat(f).unwrap().igen;
    v.unlink(d, b"f").unwrap();
    assert_eq!(v.stat(f).err(), Some(Error::NotFound));
    v.unlink(1, b"d").unwrap();
    v.commit().unwrap();
    assert_clean(&mut v);
    // the newest freed slot is handed out first, with a new igen
    let again = v.create(1, b"g", Kind::File, 0o600).unwrap();
    assert_eq!(again, d, "free list is LIFO: d was freed last");
    let next = v.create(1, b"h", Kind::File, 0o600).unwrap();
    assert_eq!(next, f);
    assert_eq!(v.stat(next).unwrap().igen, igen + 1);
    v.commit().unwrap();
    let mut v = remount(v);
    assert_eq!(v.lookup_path(b"/g").unwrap(), again);
    assert_clean(&mut v);
}

#[test]
fn unlink_returns_every_block() {
    let mut v = fresh(8192);
    v.commit().unwrap();
    let base = v.statfs().blocks_used;
    let d = v.create(1, b"d", Kind::Dir, 0o755).unwrap();
    for i in 0..20 {
        put(&mut v, d, &format!("f{i}"), &pattern(i, 200_000));
    }
    v.commit().unwrap();
    assert!(v.statfs().blocks_used > base + 900);
    for i in 0..20 {
        v.unlink(d, format!("f{i}").as_bytes()).unwrap();
    }
    v.unlink(1, b"d").unwrap();
    v.commit().unwrap();
    // the inode table and root directory grew by a block or two; the data
    // and the trees are all back
    let st = v.statfs();
    assert!(st.blocks_used <= base + 3, "used {} base {}", st.blocks_used, base);
    assert_eq!(st.blocks_pending_free, 0);
    assert_clean(&mut v);
}

// ── copy on write ──────────────────────────────────────────────────

#[test]
fn a_committed_block_is_never_overwritten() {
    let mut v = fresh(4096);
    let f = put(&mut v, 1, "f", &pattern(1, 64 * 1024));
    v.commit().unwrap();
    let snapshot = v.device().img.clone();
    // rewrite every block and add more, without committing
    v.write(f, 0, &pattern(2, 96 * 1024)).unwrap();
    let after = v.into_device().img;
    // the uncommitted state is invisible: mounting the device as it is now
    // shows the committed file
    let mut m = Volume::mount(MemDev::from_image(after.clone())).unwrap();
    let f = m.lookup_path(b"/f").unwrap();
    assert_eq!(read_all(&mut m, f), pattern(1, 64 * 1024));
    // and none of the committed data blocks changed
    let g = layout::Geometry::new(4096).unwrap();
    let mut changed = 0;
    for b in g.data_start..4096 {
        let (a, s) = (&after[b as usize * BLOCK_SIZE..][..BLOCK_SIZE], &snapshot[b as usize * BLOCK_SIZE..][..BLOCK_SIZE]);
        if a != s && s.iter().any(|&x| x != 0) {
            changed += 1;
        }
    }
    assert_eq!(changed, 0, "{changed} committed blocks were overwritten");
}

#[test]
fn blocks_of_the_open_transaction_are_rewritten_in_place() {
    let mut v = fresh(4096);
    v.commit().unwrap();
    let f = v.create(1, b"f", Kind::File, 0o644).unwrap();
    v.write(f, 0, &pattern(1, 256 * 1024)).unwrap();
    let used = v.statfs().blocks_used;
    for round in 2..30 {
        v.write(f, 0, &pattern(round, 256 * 1024)).unwrap();
        v.write(f, 1000, &pattern(round + 100, 30_000)).unwrap();
    }
    assert_eq!(v.statfs().blocks_used, used, "rewrites inside one transaction allocated");
    // after the commit the same rewrite is copy on write, and the old
    // blocks are only reusable once the commit is durable
    v.commit().unwrap();
    let base = v.statfs().blocks_used;
    v.write(f, 0, &pattern(77, 256 * 1024)).unwrap();
    let st = v.statfs();
    assert_eq!(st.blocks_used, base + 64);
    assert_eq!(st.blocks_pending_free, 64);
    v.commit().unwrap();
    assert_eq!(v.statfs().blocks_used, base);
    assert_clean(&mut v);
}

// ── checksums ──────────────────────────────────────────────────────

/// Disk block holding the first data block of a file: found by scanning the
/// image for the file's distinctive content.
fn find_block(img: &[u8], needle: &[u8]) -> u64 {
    let g = layout::Geometry::new((img.len() / BLOCK_SIZE) as u64).unwrap();
    (g.data_start..(img.len() / BLOCK_SIZE) as u64)
        .find(|&b| &img[b as usize * BLOCK_SIZE..][..needle.len()] == needle)
        .expect("block not found")
}

#[test]
fn a_flipped_data_byte_is_an_error_not_wrong_data() {
    let mut v = fresh(4096);
    let data = pattern(5, 4 * BLOCK_SIZE);
    put(&mut v, 1, "f", &data);
    v.commit().unwrap();
    let mut img = v.into_device().img;
    let b = find_block(&img, &data[..64]);
    img[b as usize * BLOCK_SIZE + 1234] ^= 0x01;
    let mut v = Volume::mount(MemDev::from_image(img)).unwrap();
    let f = v.lookup_path(b"/f").unwrap();
    let mut buf = vec![0u8; 4 * BLOCK_SIZE];
    assert_eq!(v.read(f, 0, &mut buf).err(), Some(Error::Checksum(b)));
    // the other blocks of the file still read
    let mut one = vec![0u8; BLOCK_SIZE];
    assert_eq!(v.read(f, BLOCK_SIZE as u64, &mut one).unwrap(), BLOCK_SIZE);
    assert_eq!(&one[..], &data[BLOCK_SIZE..2 * BLOCK_SIZE]);
    // the scrub finds it
    let r = v.check(true).unwrap();
    assert!(r.problems.iter().any(|p| p.what == "data block fails its checksum"), "{:?}", r.problems);
}

#[test]
fn a_damaged_checksum_table_entry_is_detected() {
    let mut v = fresh(4096);
    let data = pattern(6, BLOCK_SIZE);
    put(&mut v, 1, "f", &data);
    v.commit().unwrap();
    let mut img = v.into_device().img;
    let b = find_block(&img, &data[..64]);
    let g = layout::Geometry::new(4096).unwrap();
    let o = (g.csum_start + b / layout::CSUMS_PER_BLOCK) as usize * BLOCK_SIZE + (b % layout::CSUMS_PER_BLOCK) as usize * 4;
    img[o] ^= 0xFF;
    let mut v = Volume::mount(MemDev::from_image(img)).unwrap();
    let f = v.lookup_path(b"/f").unwrap();
    assert_eq!(v.read(f, 0, &mut [0u8; 16]).err(), Some(Error::Checksum(b)));
}

#[test]
fn a_damaged_directory_or_inode_table_block_is_refused() {
    let mut v = fresh(4096);
    put(&mut v, 1, "marker-file-name", b"x");
    v.commit().unwrap();
    let img = v.into_device().img;
    let g = layout::Geometry::new(4096).unwrap();
    // the root directory block is the one that holds the name
    let needle = b"marker-file-name";
    let dir_blk = (g.data_start..4096u64)
        .find(|&b| img[b as usize * BLOCK_SIZE..][..BLOCK_SIZE].windows(needle.len()).any(|w| w == needle))
        .expect("directory block");
    let mut bad = img.clone();
    bad[dir_blk as usize * BLOCK_SIZE + 40] ^= 0x40;
    let mut v = Volume::mount(MemDev::from_image(bad)).unwrap();
    assert!(matches!(v.lookup(1, needle), Err(Error::Checksum(_))));
    // the inode table block holds the root's record (inode 1 at +256, kind 2)
    let tbl = (g.data_start..4096u64)
        .rev()
        .find(|&b| {
            let blk = &img[b as usize * BLOCK_SIZE..][..BLOCK_SIZE];
            blk[256..264] == 1u64.to_le_bytes() && blk[256 + 52] == 2
        })
        .expect("inode table block");
    let mut bad = img.clone();
    bad[tbl as usize * BLOCK_SIZE + 300] ^= 0x01;
    assert_eq!(Volume::mount(MemDev::from_image(bad)).err(), Some(Error::Checksum(tbl)));
}

#[test]
fn a_damaged_tree_node_is_detected_when_the_inode_loads() {
    let mut v = fresh(16384);
    // two files appended alternately: one block extents, interleaved on disk
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    for i in 0..40u64 {
        v.write(a, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BLOCK_SIZE as u64, &pattern(1000 + i, BLOCK_SIZE)).unwrap();
    }
    v.commit().unwrap();
    let st = v.stat(a).unwrap();
    assert_eq!((st.extents, st.tree_nodes), (40, 1));
    let img = v.into_device().img;
    // the node is the block whose first word is the node magic
    let magic = 0x4E58_5A41u32.to_le_bytes();
    let nodes: Vec<u64> = (133..16384u64).filter(|&b| img[b as usize * BLOCK_SIZE..][..4] == magic).collect();
    assert_eq!(nodes.len(), 2, "one node per file");
    let mut bad = img.clone();
    bad[nodes[0] as usize * BLOCK_SIZE + 100] ^= 1;
    let mut v = Volume::mount(MemDev::from_image(bad)).unwrap();
    let hits = [b"a", b"b"].iter().filter(|n| matches!(v.lookup(1, &n[..]).and_then(|e| v.stat(e.ino)), Err(Error::Checksum(_)))).count();
    assert_eq!(hits, 1, "exactly the file that owns the damaged node refuses to load");
}

#[test]
fn an_index_entry_pointing_at_another_files_node_is_refused() {
    // Both nodes are intact and checksum-clean; the record of file b is made
    // to name file a's node (a stale or misdirected pointer).
    let mut v = fresh(16384);
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    for i in 0..40u64 {
        v.write(a, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BLOCK_SIZE as u64, &pattern(1000 + i, BLOCK_SIZE)).unwrap();
    }
    v.commit().unwrap();
    let img = v.into_device().img;
    let g = layout::Geometry::new(16384).unwrap();
    let magic = 0x4E58_5A41u32.to_le_bytes();
    let nodes: Vec<u64> = (g.data_start..16384u64).filter(|&b| img[b as usize * BLOCK_SIZE..][..4] == magic).collect();
    // the node whose owner field is inode 2 is a's
    let owner = |blk: u64| u64::from_le_bytes(img[blk as usize * BLOCK_SIZE + 24..][..8].try_into().unwrap());
    let a_node = *nodes.iter().find(|&&n| owner(n) == a).unwrap();
    let a_gen = u64::from_le_bytes(img[a_node as usize * BLOCK_SIZE + 16..][..8].try_into().unwrap());
    // the inode table block holding b's record: ino at +768, kind file, level 1
    let off = (b % layout::INODES_PER_BLOCK) as usize * layout::INODE_SIZE;
    let tbl = (g.data_start..16384u64)
        .find(|&t| {
            let blk = &img[t as usize * BLOCK_SIZE..][..BLOCK_SIZE];
            blk[off..off + 8] == b.to_le_bytes() && blk[off + 52] == 1 && blk[off + 53] == 1
        })
        .expect("inode table block");
    let mut bad = img.clone();
    let base = tbl as usize * BLOCK_SIZE + off + 64;
    bad[base + 8..base + 16].copy_from_slice(&a_node.to_le_bytes());
    bad[base + 16..base + 24].copy_from_slice(&a_gen.to_le_bytes());
    // keep the table block's checksum honest
    let c = azvol::crc32c::crc32c(&bad[tbl as usize * BLOCK_SIZE..][..BLOCK_SIZE]);
    let o = (g.csum_start + tbl / layout::CSUMS_PER_BLOCK) as usize * BLOCK_SIZE + (tbl % layout::CSUMS_PER_BLOCK) as usize * 4;
    layout::wr32(&mut bad[o..], 0, c);
    let mut v = Volume::mount(MemDev::from_image(bad)).unwrap();
    assert!(v.stat(a).is_ok());
    assert_eq!(v.stat(b).err(), Some(Error::Corrupt("tree node header")));
}

#[test]
fn a_damaged_bitmap_is_rebuilt_from_the_trees() {
    let mut v = fresh(4096);
    for i in 0..10 {
        put(&mut v, 1, &format!("f{i}"), &pattern(i, 50_000));
    }
    v.commit().unwrap();
    let used = v.statfs().blocks_used;
    let mut img = v.into_device().img;
    // checksum failure of the bitmap block
    img[128 * BLOCK_SIZE + 500] ^= 0xFF;
    let mut v = Volume::mount(MemDev::from_image(img.clone())).unwrap();
    assert!(v.report().bitmap_rebuilt);
    assert_eq!(v.statfs().blocks_used, used);
    assert_clean(&mut v);
    // a bitmap that is self-consistent but disagrees with the superblock
    let mut img2 = img;
    img2[128 * BLOCK_SIZE + 500] ^= 0xFF; // undo
    let g = layout::Geometry::new(4096).unwrap();
    let i = (g.data_start as usize + 300) / 8;
    img2[128 * BLOCK_SIZE + i] |= 1 << ((g.data_start as usize + 300) % 8);
    let c = azvol::crc32c::crc32c(&img2[128 * BLOCK_SIZE..128 * BLOCK_SIZE + layout::BITMAP_PAYLOAD]);
    layout::wr32(&mut img2[128 * BLOCK_SIZE..], layout::BITMAP_PAYLOAD, c);
    let mut v = Volume::mount(MemDev::from_image(img2)).unwrap();
    assert!(v.report().bitmap_rebuilt, "a leaked block must be noticed through the count");
    assert_eq!(v.statfs().blocks_used, used);
    assert_clean(&mut v);
}

// ── superblocks ────────────────────────────────────────────────────

#[test]
fn the_newest_valid_superblock_wins_and_commits_alternate_slots() {
    // generation 1 is in both copies; the root commit (2) replaced slot 0
    let mut v = remount(fresh(4096));
    assert_eq!(v.report().slot, 0);
    for i in 0..4 {
        put(&mut v, 1, &format!("f{i}"), b"x");
        v.commit().unwrap();
        let g = v.generation();
        let img = &v.device().img;
        let at = |s: u64| layout::Superblock::decode(&img[s as usize * BLOCK_SIZE..][..BLOCK_SIZE]).unwrap().generation;
        assert_eq!(at(SB_SLOTS[(g & 1) as usize]), g, "generation {g} goes to slot {}", g & 1);
        assert_eq!(at(SB_SLOTS[1 - (g & 1) as usize]), g - 1, "the other copy keeps the previous generation");
    }
    let v = remount(v);
    assert_eq!((v.report().generation, v.report().slot), (6, 0));
}

#[test]
fn a_torn_newest_superblock_falls_back_to_the_previous_generation() {
    let mut v = fresh(4096);
    put(&mut v, 1, "old", b"old content");
    v.commit().unwrap();
    let old_dump = dump(&mut v);
    // the copy the next commit will overwrite holds generation - 1 now
    let prior_gen = v.generation();
    let prior_slot = SB_SLOTS[((prior_gen + 1) & 1) as usize];
    let prior_copy = v.device().img[prior_slot as usize * BLOCK_SIZE..][..BLOCK_SIZE].to_vec();
    put(&mut v, 1, "new", b"new content");
    v.commit().unwrap();
    let new_dump = dump(&mut v);
    assert_ne!(old_dump, new_dump);
    let gen = v.generation();
    assert_eq!(gen, prior_gen + 1);
    let newest = SB_SLOTS[(gen & 1) as usize];
    assert_eq!(newest, prior_slot);
    let img = v.into_device().img;
    // Every way of tearing the newest copy. The superblock lives in the
    // first sector (a sector is the unit a device writes atomically), so the
    // tear is modelled inside it: the first `cut` bytes are the new
    // superblock, the rest is what the slot held before.
    let o = newest as usize * BLOCK_SIZE;
    let (mut old_wins, mut new_wins) = (0, 0);
    for cut in (0..=SECTOR).step_by(4) {
        let mut torn = img.clone();
        torn[o + cut..o + BLOCK_SIZE].copy_from_slice(&prior_copy[cut..]);
        let whole = torn[o..o + BLOCK_SIZE] == img[o..o + BLOCK_SIZE];
        let mut v = Volume::mount(MemDev::from_image(torn)).unwrap();
        let r = v.report();
        if whole {
            // the tear fell after the last byte that differs
            assert_eq!(r.generation, gen, "cut {cut}");
            assert_eq!(dump(&mut v), new_dump);
            new_wins += 1;
        } else {
            assert_eq!(r.generation, gen - 1, "cut {cut}");
            assert_eq!(dump(&mut v), old_dump, "cut {cut}");
            old_wins += 1;
        }
        assert_clean(&mut v);
    }
    assert!(old_wins > 50 && new_wins >= 1, "old {old_wins} new {new_wins}");
    // a flipped bit in the newest copy
    let mut flip = img.clone();
    flip[newest as usize * BLOCK_SIZE + 3000] ^= 0x10;
    let mut v = Volume::mount(MemDev::from_image(flip)).unwrap();
    assert_eq!(v.report().generation, gen - 1);
    assert_eq!(dump(&mut v), old_dump);
    // the older copy damaged instead: the newest still mounts
    let mut flip = img.clone();
    let other = SB_SLOTS[1 - (gen & 1) as usize];
    flip[other as usize * BLOCK_SIZE + 3000] ^= 0x10;
    let mut v = Volume::mount(MemDev::from_image(flip)).unwrap();
    assert_eq!(v.report().generation, gen);
    assert_eq!(dump(&mut v), new_dump);
    // both damaged
    let mut both = img.clone();
    for s in SB_SLOTS {
        both[s as usize * BLOCK_SIZE + 3000] ^= 0x10;
    }
    assert_eq!(Volume::mount(MemDev::from_image(both)).err(), Some(Error::NoSuperblock));
    // after the fallback the next commit takes the torn slot again
    let mut torn = img.clone();
    torn[newest as usize * BLOCK_SIZE + 3000] ^= 0x10;
    let mut v = Volume::mount(MemDev::from_image(torn)).unwrap();
    put(&mut v, 1, "after", b"after the fall back");
    v.commit().unwrap();
    assert_eq!(v.generation(), gen);
    let mut v = remount(v);
    assert_eq!(v.report().generation, gen);
    assert_eq!(v.report().slot as u64, gen & 1);
    assert!(dump(&mut v).contains_key("/after"));
    assert!(!dump(&mut v).contains_key("/new"));
}

// ── power cuts ─────────────────────────────────────────────────────

/// Replay a scenario's I/O log and cut it at every op, under several fates
/// for the writes not yet behind a flush. Each crashed disk must mount, show
/// exactly one of the `allowed` states, and check clean.
fn sweep(base: &[u8], log: &[Op], allowed: &[BTreeMap<String, Option<Vec<u8>>>]) -> usize {
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
            let mut v = match Volume::mount(MemDev::from_image(img)) {
                Ok(v) => v,
                Err(e) => panic!("cut {cut}/{} fate {name}: mount failed: {e:?}", log.len()),
            };
            let d = dump(&mut v);
            assert!(allowed.contains(&d), "cut {cut}/{} fate {name}: state is neither old nor new: {:?}", log.len(), d.keys().collect::<Vec<_>>());
            let r = v.check(true).unwrap_or_else(|e| panic!("cut {cut} fate {name}: check failed {e:?}"));
            assert!(r.is_clean(), "cut {cut} fate {name}: {:?}", r.problems);
            cases += 1;
        }
    }
    cases
}

/// Mutate a volume the way a busy day would: new files, overwrites,
/// appends, an unlink, a directory.
fn busy_day(v: &mut Volume<MemDev>, round: u64) {
    let root = v.root();
    let d = match v.lookup(root, b"dir") {
        Ok(e) => e.ino,
        Err(_) => v.create(root, b"dir", Kind::Dir, 0o755).unwrap(),
    };
    put(v, d, &format!("n{round}"), &pattern(round, 30_000 + round as usize * 1000));
    if let Ok(e) = v.lookup(root, b"shared") {
        v.write(e.ino, 5000, &pattern(round + 50, 20_000)).unwrap();
        v.write(e.ino, 60_000, &pattern(round + 60, 5_000)).unwrap();
    } else {
        put(v, root, "shared", &pattern(1, 70_000));
    }
    if round > 1 {
        v.unlink(d, format!("n{}", round - 1).as_bytes()).unwrap();
    }
}

#[test]
fn power_cut_at_every_write_leaves_the_old_or_the_new_state() {
    let mut v = fresh(4096);
    busy_day(&mut v, 1);
    v.commit().unwrap();
    busy_day(&mut v, 2);
    v.commit().unwrap();
    let s2 = dump(&mut v);
    // from here: log everything
    let mut dev = v.into_device();
    let base = dev.img.clone();
    dev.log.clear();
    let mut v = Volume::mount(dev).unwrap();
    busy_day(&mut v, 3);
    // the state before the commit is still s2 on disk
    v.commit().unwrap();
    let s3 = dump(&mut v);
    let log = v.device().log.clone();
    assert!(log.iter().filter(|o| matches!(o, Op::Flush)).count() >= 2);
    let cases = sweep(&base, &log, &[s2.clone(), s3.clone()]);
    assert!(cases > 100, "swept only {cases} cases");
    // a second day on top, so blocks freed by day 3 are reused on day 4
    let mut dev = v.into_device();
    let base = dev.img.clone();
    dev.log.clear();
    let mut v = Volume::mount(dev).unwrap();
    busy_day(&mut v, 4);
    v.commit().unwrap();
    let s4 = dump(&mut v);
    let log = v.device().log.clone();
    let _ = sweep(&base, &log, &[s3, s4]);
}

#[test]
fn power_cut_during_the_first_commit_of_a_file_tree_with_deep_extents() {
    // interleaved appends give the files many extents, so the commit writes
    // tree nodes too
    let mut v = fresh(16384);
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    v.commit().unwrap();
    let s0 = dump(&mut v);
    let mut dev = v.into_device();
    let base = dev.img.clone();
    dev.log.clear();
    let mut v = Volume::mount(dev).unwrap();
    for i in 0..30u64 {
        v.write(a, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BLOCK_SIZE as u64, &pattern(100 + i, BLOCK_SIZE)).unwrap();
    }
    v.commit().unwrap();
    assert!(v.stat(a).unwrap().tree_nodes >= 1);
    let s1 = dump(&mut v);
    let log = v.device().log.clone();
    sweep(&base, &log, &[s0, s1]);
}

#[test]
fn a_cut_between_the_superblock_and_the_deferred_frees_is_repaired_at_mount() {
    let mut v = fresh(4096);
    put(&mut v, 1, "f", &pattern(1, 400_000));
    v.commit().unwrap();
    let mut dev = v.into_device();
    let base = dev.img.clone();
    dev.log.clear();
    let mut v = Volume::mount(dev).unwrap();
    let f = v.lookup_path(b"/f").unwrap();
    v.write(f, 0, &pattern(2, 400_000)).unwrap();
    v.commit().unwrap();
    let log = v.device().log.clone();
    // the last flush is the one after the superblock; what follows is the
    // deferred bitmap write only
    let last_flush = log.iter().rposition(|o| matches!(o, Op::Flush)).unwrap();
    let img = crash_image(&base, &log, last_flush + 1, &|_| Fate::Lost);
    let mut m = Volume::mount(MemDev::from_image(img)).unwrap();
    assert_eq!(m.report().generation, v.generation());
    assert!(m.report().bitmap_rebuilt, "frees still pending in the stored bitmap must be noticed");
    assert_eq!(read_all(&mut m, f), pattern(2, 400_000));
    assert_clean(&mut m);
    // the rebuilt map is persisted by the next commit; after it, no rebuild
    m.create(1, b"g", Kind::File, 0).unwrap();
    m.commit().unwrap();
    let m = remount(m);
    assert!(!m.report().bitmap_rebuilt);
}

#[test]
fn a_failed_commit_poisons_the_handle() {
    let mut v = fresh(4096);
    put(&mut v, 1, "f", &pattern(1, 10_000));
    let w = v.device().writes;
    v.device_mut().fail_after_writes = Some(w + 3);
    assert!(v.commit().is_err());
    assert_eq!(v.commit().err(), Some(Error::Poisoned));
    assert_eq!(v.create(1, b"g", Kind::File, 0).err(), Some(Error::Poisoned));
    // the device holds the old state
    let mut dev = v.into_device();
    dev.fail_after_writes = None;
    let mut m = Volume::mount(dev).unwrap();
    assert!(m.readdir(1).unwrap().is_empty());
    assert_clean(&mut m);
}

// ── extent trees ───────────────────────────────────────────────────

#[test]
fn many_extents_build_index_levels_and_survive_a_remount() {
    let mut v = fresh(16384);
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    // 1 block at a time, alternating: no two blocks of a file are adjacent
    let n = 2000u64;
    for i in 0..n {
        v.write(a, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BLOCK_SIZE as u64, &pattern(5000 + i, BLOCK_SIZE)).unwrap();
    }
    v.commit().unwrap();
    // 2000 extents: 16 leaves + 1 index node under an inline index entry
    let st = v.stat(a).unwrap();
    assert_eq!((st.extents, st.blocks, st.tree_nodes), (n, n, 17));
    let mut v = remount(v);
    let a = v.lookup_path(b"/a").unwrap();
    let b = v.lookup_path(b"/b").unwrap();
    assert_eq!(v.stat(a).unwrap().tree_nodes, 17);
    for i in (0..n).step_by(97) {
        let mut buf = vec![0u8; BLOCK_SIZE];
        v.read(a, i * BLOCK_SIZE as u64, &mut buf).unwrap();
        assert_eq!(buf, pattern(i, BLOCK_SIZE));
        v.read(b, i * BLOCK_SIZE as u64, &mut buf).unwrap();
        assert_eq!(buf, pattern(5000 + i, BLOCK_SIZE));
    }
    // overwrite in the middle: the tree is rewritten, the old nodes freed
    v.write(a, 1000 * BLOCK_SIZE as u64, &pattern(99, 5 * BLOCK_SIZE)).unwrap();
    v.commit().unwrap();
    let used = v.statfs().blocks_used;
    assert_clean(&mut v);
    v.unlink(1, b"a").unwrap();
    v.unlink(1, b"b").unwrap();
    v.commit().unwrap();
    assert!(v.statfs().blocks_used + 4000 <= used + 6, "the trees' blocks came back");
    assert_clean(&mut v);
}

#[test]
fn a_file_with_more_than_six_extents_but_one_leaf() {
    let mut v = fresh(4096);
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    for i in 0..7u64 {
        v.write(a, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
    }
    v.commit().unwrap();
    let st = v.stat(a).unwrap();
    assert_eq!((st.extents, st.tree_nodes), (7, 1));
    let mut v = remount(v);
    let a = v.lookup_path(b"/a").unwrap();
    assert_eq!(read_all(&mut v, a).len(), 7 * BLOCK_SIZE);
    assert_clean(&mut v);
}

// ── space ──────────────────────────────────────────────────────────

#[test]
fn a_full_volume_reports_no_space_and_can_still_delete() {
    let mut v = fresh(2048);
    let mut made = Vec::new();
    let mut i = 0u64;
    let err = loop {
        let name = format!("f{i}");
        let ino = match v.create(1, name.as_bytes(), Kind::File, 0o644) {
            Ok(n) => n,
            Err(e) => break e,
        };
        match v.write(ino, 0, &pattern(i, 64 * 1024)) {
            Ok(n) if n == 64 * 1024 => made.push(name),
            Ok(_) => {
                made.push(name);
                break Error::NoSpace;
            }
            Err(e) => {
                made.push(name);
                break e;
            }
        }
        i += 1;
    };
    assert_eq!(err, Error::NoSpace);
    assert!(made.len() > 10);
    // the commit of a full volume works (the reserve), and so does a delete
    v.commit().unwrap();
    assert_clean(&mut v);
    for name in made.iter().take(made.len() / 2) {
        v.unlink(1, name.as_bytes()).unwrap();
    }
    v.commit().unwrap();
    assert_clean(&mut v);
    // and the freed space is writable again
    let g = v.create(1, b"again", Kind::File, 0o644).unwrap();
    assert_eq!(v.write(g, 0, &pattern(1, 200_000)).unwrap(), 200_000);
    v.commit().unwrap();
    assert_clean(&mut v);
}

#[test]
fn a_write_that_runs_out_of_space_is_short_and_leaves_the_file_sound() {
    let mut v = fresh(1024);
    let f = v.create(1, b"f", Kind::File, 0o644).unwrap();
    v.write(f, 0, &pattern(1, 100_000)).unwrap();
    v.commit().unwrap();
    let old = pattern(1, 100_000);
    // far more than the volume holds: the write reports how far it got
    let want = vec![7u8; 8 << 20];
    let got = v.write(f, 0, &want).unwrap();
    assert!(got > 0 && got < want.len(), "wrote {got}");
    let now = read_all(&mut v, f);
    assert_eq!(now.len(), got.max(old.len()));
    assert!(now[..got].iter().all(|&b| b == 7));
    if old.len() > got {
        assert_eq!(now[got..], old[got..]);
    }
    // nothing is left half-allocated: the commit and the check are clean
    v.commit().unwrap();
    assert_clean(&mut v);
    // a write that cannot place its first chunk is an error, not a short count
    let hog = v.create(1, b"hog", Kind::File, 0o644).unwrap();
    loop {
        let at = v.stat(hog).unwrap().size;
        match v.write(hog, at, &vec![1u8; 1 << 20]) {
            Ok(n) if n == 1 << 20 => {}
            _ => break,
        }
    }
    assert_eq!(v.write(hog, 1 << 30, &vec![1u8; 1 << 20]).err(), Some(Error::NoSpace));
    v.commit().unwrap();
    assert_clean(&mut v);
}

#[test]
fn a_failed_write_leaves_nothing_mapped_past_the_size() {
    // Core level: the state a multi-segment write can leave when a later
    // segment fails after an earlier one was swapped in. A block of the
    // open transaction sits at file block 8; the write spans 0..12 and the
    // device fails on its third segment.
    use azvol::engine::{Core, Inode};
    use azvol::freemap::FreeMap;
    let geo = layout::Geometry::new(2048).unwrap();
    let mut map = FreeMap::new(&geo);
    map.set_static(&geo);
    let used = map.count();
    let mut core = Core::new(MemDev::new(2048), geo, 1, map, used);
    let mut ino = Inode::blank(5, Kind::File);
    let bs = BLOCK_SIZE as u64;
    core.write_range(&mut ino, 8 * bs, &pattern(1, BLOCK_SIZE)).unwrap();
    let used = core.used;
    let writes = core.dev.writes;
    core.dev.fail_after_writes = Some(writes + 2);
    let data = pattern(2, 12 * BLOCK_SIZE);
    assert!(core.write_range(&mut ino, 0, &data).is_err());
    core.dev.fail_after_writes = None;
    // the earlier segments are mapped although the file size is still 0 and
    // 2.5 blocks is the size it keeps: everything past it must go
    assert!(ino.extents.iter().any(|e| e.file_end() > 3), "scenario did not reach the swapped segments");
    core.discard_past(&mut ino, 2 * bs + bs / 2).unwrap();
    assert!(ino.extents.iter().all(|e| e.file_end() <= 3), "{:?}", ino.extents);
    // the kept block's tail reads as zeros
    let mut b = vec![0xAAu8; BLOCK_SIZE];
    core.read_range(&ino.extents, 2 * bs, &mut b).unwrap();
    assert!(b[BLOCK_SIZE / 2..].iter().all(|&x| x == 0));
    assert!(b[..BLOCK_SIZE / 2] == data[2 * BLOCK_SIZE..2 * BLOCK_SIZE + BLOCK_SIZE / 2]);
    assert!(core.used <= used + 3, "blocks of the failed write were not given back");
}

#[test]
fn a_write_that_fails_on_the_device_never_exposes_its_bytes_later() {
    // Sweep the failure over every device write of a write that starts past
    // the end, then grow the file: the gap must read as zeros.
    for fail in 0..24usize {
        let mut v = fresh(4096);
        let f = v.create(1, b"f", Kind::File, 0o644).unwrap();
        v.write(f, 0, &pattern(1, 10_000)).unwrap();
        v.commit().unwrap();
        let at = v.device().writes;
        v.device_mut().fail_after_writes = Some(at + fail);
        let r = v.write(f, 3 * BLOCK_SIZE as u64 + 100, &pattern(2, 700_000));
        v.device_mut().fail_after_writes = None;
        let kept = v.stat(f).unwrap().size;
        if r.is_ok() {
            assert_eq!(kept, 3 * BLOCK_SIZE as u64 + 100 + 700_000);
        } else {
            assert_eq!(kept, 10_000, "a failed write keeps the old size");
        }
        let end = 3 * BLOCK_SIZE as u64 + 100 + 700_000;
        let n = r.as_ref().map_or(0, |n| *n);
        v.truncate(f, end).unwrap();
        let now = read_all(&mut v, f);
        assert_eq!(now.len() as u64, end);
        // below the kept size and below the bytes the call reports written,
        // the content is the old or new data; every other byte is zero
        let written_to = if n > 0 { 3 * BLOCK_SIZE + 100 + n } else { 0 };
        for (i, b) in now.iter().enumerate() {
            if i >= 10_000 && i < 3 * BLOCK_SIZE + 100 && *b != 0 {
                panic!("fail={fail}: byte {i} of the gap is {b}");
            }
            if i >= written_to.max(10_000) && *b != 0 {
                panic!("fail={fail}: byte {i} past the write is {b}");
            }
        }
        v.commit().unwrap();
        assert_clean(&mut v);
    }
}

#[test]
fn an_extent_or_node_from_the_open_generation_is_refused() {
    // A committed tree never carries generation + 1: that generation names
    // blocks the engine overwrites in place and frees at once.
    let g = layout::Geometry::new(16384).unwrap();
    let refresh = |img: &mut Vec<u8>, blk: u64| {
        let c = azvol::crc32c::crc32c(&img[blk as usize * BLOCK_SIZE..][..BLOCK_SIZE]);
        let o = (g.csum_start + blk / layout::CSUMS_PER_BLOCK) as usize * BLOCK_SIZE + (blk % layout::CSUMS_PER_BLOCK) as usize * 4;
        layout::wr32(&mut img[o..], 0, c);
    };
    let table_block = |img: &[u8], ino: u64, level: u8| {
        let off = (ino % layout::INODES_PER_BLOCK) as usize * layout::INODE_SIZE;
        let t = (g.data_start..16384u64)
            .find(|&t| {
                let blk = &img[t as usize * BLOCK_SIZE..][..BLOCK_SIZE];
                blk[off..off + 8] == ino.to_le_bytes() && blk[off + 52] == 1 && blk[off + 53] == level
            })
            .expect("inode table block");
        (t, off)
    };
    // inline extent
    let mut v = fresh(16384);
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    v.write(a, 0, &pattern(1, 4 * BLOCK_SIZE)).unwrap();
    v.commit().unwrap();
    let open = v.generation() + 1;
    let img = v.into_device().img;
    let (tbl, off) = table_block(&img, a, 0);
    let mut bad = img.clone();
    bad[tbl as usize * BLOCK_SIZE + off + 64 + 24..][..8].copy_from_slice(&open.to_le_bytes());
    refresh(&mut bad, tbl);
    let mut v = Volume::mount(MemDev::from_image(bad)).unwrap();
    assert_eq!(v.stat(a).err(), Some(Error::Corrupt("extent from the future")));
    // the committed generation itself is fine
    let mut ok = img.clone();
    ok[tbl as usize * BLOCK_SIZE + off + 64 + 24..][..8].copy_from_slice(&(open - 1).to_le_bytes());
    refresh(&mut ok, tbl);
    assert!(Volume::mount(MemDev::from_image(ok)).unwrap().stat(a).is_ok());
    // tree node: header generation and the index entry naming it
    let mut v = fresh(16384);
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    for i in 0..40u64 {
        v.write(b, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, (100 + i) * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
    }
    v.commit().unwrap();
    let open = v.generation() + 1;
    let img = v.into_device().img;
    let (tbl, off) = table_block(&img, b, 1);
    let ent = tbl as usize * BLOCK_SIZE + off + 64;
    let node = u64::from_le_bytes(img[ent + 8..ent + 16].try_into().unwrap());
    let mut bad = img.clone();
    bad[ent + 16..ent + 24].copy_from_slice(&open.to_le_bytes());
    bad[node as usize * BLOCK_SIZE + 16..][..8].copy_from_slice(&open.to_le_bytes());
    refresh(&mut bad, tbl);
    refresh(&mut bad, node);
    let mut v = Volume::mount(MemDev::from_image(bad)).unwrap();
    assert_eq!(v.stat(b).err(), Some(Error::Corrupt("tree node header")));
}

// ── hostile images ─────────────────────────────────────────────────

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Flip bytes anywhere in the metadata and in the used blocks of a busy
/// volume, then mount and walk it. Nothing may panic (this crate runs with
/// overflow checks on); every outcome is a value.
#[test]
fn corrupted_images_never_panic() {
    let mut v = fresh(4096);
    for r in 1..4 {
        busy_day(&mut v, r);
        v.commit().unwrap();
    }
    let img = v.into_device().img;
    let g = layout::Geometry::new(4096).unwrap();
    let used: Vec<u64> = (0..4096u64).filter(|&b| img[b as usize * BLOCK_SIZE..][..BLOCK_SIZE].iter().any(|&x| x != 0)).collect();
    let mut rng = 0x1234_5678_9ABC_DEF1u64;
    let (mut mounted, mut refused) = (0, 0);
    for round in 0..600 {
        let mut bad = img.clone();
        for _ in 0..1 + round % 3 {
            let blk = used[(xorshift(&mut rng) % used.len() as u64) as usize];
            let off = (xorshift(&mut rng) % BLOCK_SIZE as u64) as usize;
            let mask = (xorshift(&mut rng) % 255 + 1) as u8;
            bad[blk as usize * BLOCK_SIZE + off] ^= mask;
            // half the time keep the block's checksum honest, so the damage
            // reaches the parsers instead of the checksum gate
            if blk >= g.data_start && round % 2 == 0 {
                let c = azvol::crc32c::crc32c(&bad[blk as usize * BLOCK_SIZE..][..BLOCK_SIZE]);
                let o = (g.csum_start + blk / layout::CSUMS_PER_BLOCK) as usize * BLOCK_SIZE
                    + (blk % layout::CSUMS_PER_BLOCK) as usize * 4;
                layout::wr32(&mut bad[o - o % 4..], 0, c);
            }
        }
        match Volume::mount(MemDev::from_image(bad)) {
            Ok(mut m) => {
                mounted += 1;
                let _ = m.check(true);
                let _ = m.lookup_path(b"/dir/n3");
                let _ = m.readdir(1);
                let _ = m.stat(2);
                let _ = m.create(1, b"probe", Kind::File, 0);
                let _ = m.write(2, 0, b"probe");
                let _ = m.commit();
            }
            Err(_) => refused += 1,
        }
    }
    assert!(mounted > 50 && refused > 5, "mounted {mounted} refused {refused}");
}

// ── tools/image/mkazvol.py ───────────────────────────────────────────────

fn tool() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/image/mkazvol.py")
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("azvol-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn python(args: &[&str]) -> String {
    let out = std::process::Command::new("python3").arg(tool()).args(args).output().expect("python3 must be on PATH");
    assert!(out.status.success(), "mkazvol.py {args:?}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn mkazvol_images_mount_and_hold_what_was_put_in() {
    let t = TempDir::new("mk");
    let root = t.0.join("tree");
    std::fs::create_dir_all(root.join("etc/sub")).unwrap();
    std::fs::create_dir_all(root.join("empty")).unwrap();
    let mut want: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    for (p, len, seed) in [("hello.txt", 12usize, 1u64), ("etc/conf", 5000, 2), ("etc/sub/big.bin", 1_300_000, 3), ("etc/sub/zero", 0, 4), ("etc/sub/exact", 8192, 5)] {
        let data = pattern(seed, len);
        std::fs::write(root.join(p), &data).unwrap();
        want.insert(format!("/{p}"), Some(data));
    }
    for d in ["/etc", "/etc/sub", "/empty"] {
        want.insert(d.to_string(), None);
    }
    let img = t.0.join("vol.img");
    python(&["create", img.to_str().unwrap(), "--size", "16M", "--root", root.to_str().unwrap(), "--label", "built", "--time-ns", "42"]);
    let bytes = std::fs::read(&img).unwrap();
    assert_eq!(bytes.len(), 16 << 20);
    let mut v = Volume::mount(MemDev::from_image(bytes.clone())).expect("mount the python image");
    assert_eq!(v.label(), b"built");
    assert_eq!(v.report().generation, 1);
    assert_eq!(dump(&mut v), want);
    assert_eq!(v.stat(v.root()).unwrap().mtime_ns, 42);
    assert_clean(&mut v);
    // it is a normal volume: write to it, commit, remount
    let extra = put(&mut v, 1, "added-by-the-kernel", b"later");
    v.commit().unwrap();
    assert_eq!(v.generation(), 2);
    let mut v = remount(v);
    assert_eq!(read_all(&mut v, extra), b"later");
    let big = v.lookup_path(b"/etc/sub/big.bin").unwrap();
    assert_eq!(read_all(&mut v, big), want["/etc/sub/big.bin"].clone().unwrap());
    assert_clean(&mut v);
    // the tool is deterministic
    let img2 = t.0.join("vol2.img");
    python(&["create", img2.to_str().unwrap(), "--size", "16M", "--root", root.to_str().unwrap(), "--label", "built", "--time-ns", "42"]);
    assert!(std::fs::read(&img2).unwrap() == bytes, "same inputs, different image");
}

#[test]
fn mkazvol_reads_back_what_the_engine_wrote() {
    let t = TempDir::new("rd");
    let mut v = fresh(16384);
    let d = v.create(1, b"d", Kind::Dir, 0o755).unwrap();
    put(&mut v, d, "small", b"abc");
    put(&mut v, 1, "big", &pattern(3, 700_000));
    // a file with a deep extent tree, for the tool's node walker
    let a = v.create(1, b"a", Kind::File, 0o644).unwrap();
    let b = v.create(1, b"b", Kind::File, 0o644).unwrap();
    for i in 0..900u64 {
        v.write(a, i * BLOCK_SIZE as u64, &pattern(i, BLOCK_SIZE)).unwrap();
        v.write(b, i * BLOCK_SIZE as u64, &pattern(i + 1, BLOCK_SIZE)).unwrap();
    }
    put(&mut v, 1, "gone", b"x");
    v.unlink(1, b"gone").unwrap();
    v.commit().unwrap();
    let want = dump(&mut v);
    assert!(v.stat(a).unwrap().tree_nodes >= 7);
    let img = t.0.join("rust.img");
    std::fs::write(&img, &v.into_device().img).unwrap();
    let listing = python(&["verify", img.to_str().unwrap()]);
    let mut got: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut summary = String::new();
    for line in listing.lines() {
        if let Some(rest) = line.strip_prefix("ok ") {
            summary = rest.to_string();
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 3, "{line}");
        got.insert(f[0].to_string(), if f[1] == "dir" { None } else { Some(format!("{} {}", f[1], f[2])) });
    }
    assert!(summary.contains("generation 3"), "{summary}");
    assert_eq!(got.len(), want.len());
    for (p, c) in want {
        match c {
            None => assert_eq!(got[&p], None, "{p}"),
            Some(data) => {
                let sha = sha256_hex(&data);
                assert_eq!(got[&p], Some(format!("{} {}", data.len(), sha)), "{p}");
            }
        }
    }
}

#[test]
fn mkazvol_verify_rejects_a_damaged_image() {
    let t = TempDir::new("bad");
    let mut v = fresh(4096);
    let data = pattern(4, 8 * BLOCK_SIZE);
    put(&mut v, 1, "f", &data);
    v.commit().unwrap();
    let mut img = v.into_device().img;
    let b = find_block(&img, &data[..64]);
    img[b as usize * BLOCK_SIZE + 9] ^= 1;
    let p = t.0.join("bad.img");
    std::fs::write(&p, &img).unwrap();
    let out = std::process::Command::new("python3").arg(tool()).args(["verify", p.to_str().unwrap()]).output().unwrap();
    assert!(!out.status.success(), "verify accepted a flipped data byte");
    assert!(String::from_utf8_lossy(&out.stderr).contains("checksum"), "{}", String::from_utf8_lossy(&out.stderr));
}

fn sha256_hex(data: &[u8]) -> String {
    // The host suite has no hashing crate; ask the same tool (python's
    // hashlib) through its own `sha256` helper command.
    use std::io::Write;
    let mut c = std::process::Command::new("python3")
        .arg(tool())
        .arg("sha256")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(data).unwrap();
    let o = c.wait_with_output().unwrap();
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

// ── verity: the hash tree over a read-only volume ───────────────────
//
// Three buckets, as everywhere. DISCRIMINATING (each turns red if
// `VerityDev::read` stops comparing the block with its slot, or stops walking
// the slot up to the header's top): every flip test, and the cross-check with
// the tool. SHAPE (does not discriminate; pins the arithmetic both
// implementations share): `the_tree_shape_follows_the_block_count_alone`.

use azvol::verity::{self, Fail, Hash, OpenError, Record, Shape, Tamper, VerityDev};
use std::sync::{Arc, Mutex};

/// Where failures go in these tests.
#[derive(Clone, Default)]
struct Rec(Arc<Mutex<Vec<Tamper>>>);

impl Record for Rec {
    fn tampered(&self, t: &Tamper) {
        self.0.lock().unwrap().push(*t);
    }
}

impl Rec {
    fn all(&self) -> Vec<Tamper> {
        self.0.lock().unwrap().clone()
    }
}

/// A device that counts the calls the layer above makes.
struct Counting {
    inner: MemDev,
    calls: Arc<Mutex<Vec<(u64, usize)>>>,
}

impl BlockDev for Counting {
    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }
    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        self.calls.lock().unwrap().push((first, buf.len() / BLOCK_SIZE));
        self.inner.read(first, buf)
    }
    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        self.inner.write(first, buf)
    }
    fn flush(&mut self) -> Result<(), DevError> {
        self.inner.flush()
    }
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_tree_shape_follows_the_block_count_alone() {
    let s = Shape::new(1).unwrap();
    assert_eq!((s.levels, s.count[0], s.start[0], s.total, s.blocks_after()), (1, 1, 2, 1, 2));
    assert_eq!(Shape::new(128).unwrap().levels, 1, "128 hashes fill one hash block");
    let s = Shape::new(129).unwrap();
    assert_eq!((s.levels, s.count[0], s.count[1], s.start[0], s.start[1], s.total), (2, 2, 1, 130, 132, 3));
    let s = Shape::new(128 * 128).unwrap();
    assert_eq!((s.levels, s.count[0], s.count[1]), (2, 128, 1));
    let s = Shape::new(128 * 128 + 1).unwrap();
    assert_eq!((s.levels, s.count[0], s.count[1], s.count[2]), (3, 129, 2, 1));
    assert_eq!((s.start[1], s.start[2]), (s.start[0] + 129, s.start[0] + 131));
    let s = Shape::new(1 << 40).unwrap();
    assert_eq!((s.levels, s.count[s.levels - 1]), (6, 1), "the largest volume still has a tree");
    assert!(Shape::new(0).is_none() && Shape::new((1 << 40) + 1).is_none());
}

/// A volume-shaped image of `n` blocks with a different content in every
/// block and the tree after it: only the two things `open` reads before the
/// header (the superblock magic and the block-count hint) are real.
fn crafted(n: u64) -> (Vec<u8>, Hash) {
    let s = Shape::new(n).unwrap();
    let mut img = vec![0u8; (n + s.blocks_after()) as usize * BLOCK_SIZE];
    for b in 0..n as usize {
        img[b * BLOCK_SIZE..][..8].copy_from_slice(&(b as u64 + 1).to_le_bytes());
    }
    for slot in SB_SLOTS {
        let o = slot as usize * BLOCK_SIZE;
        img[o..o + 8].copy_from_slice(&layout::MAGIC);
        img[o + sbo::BLOCK_COUNT..][..8].copy_from_slice(&n.to_le_bytes());
    }
    let root = verity::build::build_in(&mut img, n);
    (img, root)
}

fn block_of(img: &[u8], b: u64) -> Vec<u8> {
    img[b as usize * BLOCK_SIZE..][..BLOCK_SIZE].to_vec()
}

#[test]
fn a_three_level_tree_checks_every_level_and_names_the_one_that_failed() {
    const N: u64 = 128 * 128 + 1;
    let (img, root) = crafted(N);
    let s = Shape::new(N).unwrap();
    let open = |flip: Option<u64>| {
        let mut i = img.clone();
        if let Some(b) = flip {
            i[b as usize * BLOCK_SIZE + 100] ^= 0x40;
        }
        let rec = Rec::default();
        (VerityDev::open(MemDev::from_image(i), &root, rec.clone()).expect("opens"), rec)
    };
    let mut buf = vec![0u8; BLOCK_SIZE];
    // clean: the first, a block either side of a hash-block boundary, the last
    let (mut d, rec) = open(None);
    assert_eq!(d.block_count(), N, "the engine sees the volume, not the tree");
    for b in [0, 5, 127, 128, 16383, 16384] {
        d.read(b, &mut buf).unwrap_or_else(|_| panic!("block {b}"));
        assert_eq!(buf, block_of(&img, b), "block {b}");
    }
    assert!(rec.all().is_empty());
    // a data block
    let (mut d, rec) = open(Some(16384));
    assert!(d.read(16384, &mut buf).is_err());
    assert!(buf.iter().all(|&x| x == 0), "a failed read returns no byte");
    assert_eq!(rec.all(), vec![Tamper { block: 16384, what: Fail::Data, count: 1 }]);
    assert!(d.read(16384, &mut buf).is_err());
    assert_eq!(rec.all()[1].count, 2, "failures are counted, a bad block is not trusted twice");
    d.read(0, &mut buf).expect("a neighbour is untouched");
    // a level-0 hash block: only the blocks it covers
    let (mut d, rec) = open(Some(s.start[0] + 128));
    assert!(d.read(16384, &mut buf).is_err());
    assert_eq!(rec.all(), vec![Tamper { block: s.start[0] + 128, what: Fail::Hash(0), count: 1 }]);
    d.read(16383, &mut buf).expect("the blocks of other hash blocks read");
    // a level-1 hash block: the 128 hash blocks under it
    let (mut d, rec) = open(Some(s.start[1] + 1));
    assert!(d.read(16384, &mut buf).is_err());
    assert_eq!(rec.all(), vec![Tamper { block: s.start[1] + 1, what: Fail::Hash(1), count: 1 }]);
    d.read(5, &mut buf).expect("the other level-1 block's subtree reads");
    // the top: everything
    let (mut d, rec) = open(Some(s.start[2]));
    assert!(d.read(5, &mut buf).is_err() && d.read(16384, &mut buf).is_err());
    assert_eq!(rec.all()[0], Tamper { block: s.start[2], what: Fail::Hash(2), count: 1 });
    // and the header, at open
    let mut i = img.clone();
    i[N as usize * BLOCK_SIZE + 40] ^= 1;
    let rec = Rec::default();
    assert_eq!(VerityDev::open(MemDev::from_image(i), &root, rec.clone()).err(), Some(OpenError::RootMismatch));
    assert_eq!(rec.all(), vec![Tamper { block: N, what: Fail::Header, count: 1 }]);
}

#[test]
fn a_run_with_one_bad_block_fails_whole_and_a_verified_hash_block_is_kept() {
    const N: u64 = 1024;
    let (mut img, root) = crafted(N);
    img[700 * BLOCK_SIZE + 9] ^= 1;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let rec = Rec::default();
    let mut d = VerityDev::open(Counting { inner: MemDev::from_image(img), calls: calls.clone() }, &root, rec.clone()).unwrap();
    let mut run = vec![0xAAu8; 8 * BLOCK_SIZE];
    assert!(d.read(696, &mut run).is_err());
    assert!(run.iter().all(|&x| x == 0), "the good blocks of a failed run are not returned either");
    assert_eq!(rec.all().len(), 1);
    assert_eq!(rec.all()[0].block, 700);
    // a repeat costs the data block alone: its hash block was checked before
    let mut one = vec![0u8; BLOCK_SIZE];
    d.read(5, &mut one).unwrap();
    calls.lock().unwrap().clear();
    d.read(5, &mut one).unwrap();
    d.read(6, &mut one).unwrap();
    assert_eq!(*calls.lock().unwrap(), vec![(5, 1), (6, 1)]);
    // out of range, empty, ragged, and write: refused, no record
    let before = rec.all().len();
    assert!(d.read(N, &mut one).is_err(), "the header is not the engine's block");
    assert!(d.read(N - 1, &mut run[..2 * BLOCK_SIZE]).is_err());
    assert!(d.read(0, &mut []).is_err());
    assert!(d.read(0, &mut one[..100]).is_err());
    assert!(d.write(0, &one).is_err(), "a verity device is never written");
    assert_eq!(rec.all().len(), before);
    d.flush().unwrap();
}

#[test]
fn a_device_that_is_not_the_volume_of_the_root_is_not_opened() {
    const N: u64 = 256;
    let (img, root) = crafted(N);
    let open = |img: Vec<u8>, root: &Hash| {
        let rec = Rec::default();
        (VerityDev::open(MemDev::from_image(img), root, rec.clone()).err(), rec.all())
    };
    // another root
    let mut other = root;
    other[0] ^= 1;
    assert_eq!(open(img.clone(), &other), (Some(OpenError::RootMismatch), vec![Tamper { block: N, what: Fail::Header, count: 1 }]));
    // no superblock to place the header
    let mut i = img.clone();
    for slot in SB_SLOTS {
        i[slot as usize * BLOCK_SIZE] ^= 1;
    }
    assert_eq!(open(i, &root), (Some(OpenError::NoHeader), vec![Tamper { block: 0, what: Fail::Header, count: 1 }]));
    // a plain volume, no tree after it
    let mut plain = img.clone();
    plain.truncate(N as usize * BLOCK_SIZE);
    assert_eq!(open(plain, &root).0, Some(OpenError::NoHeader), "a volume with no tree is not a verity volume");
    // one superblock copy that lies about the size does not hide the other
    let mut lie = img.clone();
    lie[sbo::BLOCK_COUNT..sbo::BLOCK_COUNT + 8].copy_from_slice(&100u64.to_le_bytes());
    assert_eq!(open(lie, &root).0, None);
    // the tree cut short by the end of the device
    let s = Shape::new(N).unwrap();
    let mut short = img;
    short.truncate((N + s.blocks_after() - 1) as usize * BLOCK_SIZE);
    assert_eq!(open(short, &root).0, Some(OpenError::Malformed("verity tree past the end of the device")));
}

#[test]
fn mkazvol_builds_the_tree_the_engine_checks() {
    let t = TempDir::new("vy");
    let root_dir = t.0.join("tree");
    std::fs::create_dir_all(root_dir.join("etc")).unwrap();
    let conf = pattern(11, 5000);
    let big = pattern(12, 700_000);
    std::fs::write(root_dir.join("etc/conf"), &conf).unwrap();
    std::fs::write(root_dir.join("big"), &big).unwrap();
    let args = |img: &std::path::Path, extra: &[&'static str]| {
        let mut a: Vec<String> = vec!["create".into(), img.to_str().unwrap().into(), "--size".into(), "8M".into()];
        a.extend(["--root".into(), root_dir.to_str().unwrap().into(), "--label".into(), "sys".into(), "--time-ns".into(), "7".into()]);
        a.extend(extra.iter().map(|s| s.to_string()));
        a
    };
    let run = |a: Vec<String>| python(&a.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    let (plain_p, tree_p) = (t.0.join("plain.img"), t.0.join("tree.img"));
    assert_eq!(run(args(&plain_p, &[])), "");
    let printed = run(args(&tree_p, &["--verity"]));
    let n = (8u64 << 20) / BLOCK_SIZE as u64;
    let after = Shape::new(n).unwrap().blocks_after();
    let tree = std::fs::read(&tree_p).unwrap();
    assert_eq!(tree.len() as u64, (n + after) * BLOCK_SIZE as u64, "--size stays the size of the volume");
    // the Rust builder lays the same bytes down and names the same root
    let mut ours = std::fs::read(&plain_p).unwrap();
    assert_eq!(ours.len() as u64, n * BLOCK_SIZE as u64);
    ours.resize(tree.len(), 0);
    let root = verity::build::build_in(&mut ours, n);
    assert!(ours == tree, "the two builders disagree on the tree");
    assert_eq!(printed.trim(), format!("verity_root {}", hex(&root)));
    // the engine mounts the tool's volume through it and reads what was put in
    let rec = Rec::default();
    let dev = VerityDev::open(MemDev::from_image(tree.clone()), &root, rec.clone()).expect("opens");
    let mut v = Volume::mount(dev).expect("mounts through the tree");
    for (p, want) in [("/etc/conf", &conf), ("/big", &big)] {
        let ino = v.lookup_path(p.as_bytes()).unwrap();
        let mut got = vec![0u8; want.len()];
        assert_eq!(v.read(ino, 0, &mut got).unwrap(), want.len());
        assert!(&got == want, "{p}");
    }
    assert!(rec.all().is_empty());
    // the tool checks a tree too, and a changed block fails it
    let ok = python(&["verify", tree_p.to_str().unwrap(), "--verity-root", &hex(&root)]);
    assert!(ok.contains("verity ok"), "{ok}");
    let mut bad = tree;
    bad[(n as usize - 3) * BLOCK_SIZE] ^= 1;
    let bad_p = t.0.join("bad.img");
    std::fs::write(&bad_p, &bad).unwrap();
    let out = std::process::Command::new("python3")
        .arg(tool())
        .args(["verify", bad_p.to_str().unwrap(), "--verity-root", &hex(&root)])
        .output()
        .unwrap();
    assert!(!out.status.success(), "verify accepted a volume that is not the one the tree was built from");
    assert!(String::from_utf8_lossy(&out.stderr).contains("hash tree"), "{}", String::from_utf8_lossy(&out.stderr));
}
