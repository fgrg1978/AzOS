// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of azvol's sealing (`crates/fs/fs/src/azvol/seal.rs`): every
//! block of the data area is ChaCha20-Poly1305 at rest.
//!
//! * a sealed volume round-trips through unmount and mount, checks clean,
//!   and no plaintext reaches the medium;
//! * a block whose bytes, tag or sequence number were touched is an error
//!   naming the block, never data;
//! * a wrong key, no key, or a key for a plain volume is refused before any
//!   data is read;
//! * a nonce is never used twice: not across copy-on-write generations, not
//!   for a block rewritten inside one transaction, not after an aborted
//!   group, not after a cut that lost a transaction (a mount opens a new
//!   generation), and the nonce layout is the documented one;
//! * a power cut at any point of a sealed commit leaves the old or the new
//!   state, and the volume checks clean.
//!
//! Wired into the suite by `mod azvol_aead;` in `src/lib.rs`.

#![cfg(test)]

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/fs/fs/src/azvol/mod.rs"]
mod azvol;

use azos_crypto::{chachapoly, hkdf};
use azvol::layout::{self, Kind, SB_SLOTS};
use azvol::seal::{self, Sealer};
use azvol::{BlockDev, DevError, Error, FormatOptions, Volume, VolumeKey, BLOCK_SIZE};
use std::collections::BTreeMap;

const SECTOR: usize = 512;
const BLOCKS: u64 = 4096;
const UUID: [u8; 16] = [7; 16];
const MASTER: [u8; 32] = [0x5A; 32];

// ── the device ─────────────────────────────────────────────────────

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

/// The disk after a cut at `cut` (the log index of the first op that did not
/// happen): writes up to the last flush barrier are durable, the ones after
/// it land torn at a sector boundary, or whole, or not at all.
fn crash_image(base: &[u8], log: &[Op], cut: usize, fate: &dyn Fn(usize) -> Option<usize>) -> Vec<u8> {
    let mut img = base.to_vec();
    let barrier = log[..cut].iter().rposition(|o| matches!(o, Op::Flush)).map_or(0, |i| i + 1);
    for (i, op) in log[..cut].iter().enumerate() {
        if let Op::Write { blk, data } = op {
            let dst = &mut img[*blk as usize * BLOCK_SIZE..(*blk as usize + 1) * BLOCK_SIZE];
            let sectors = if i < barrier { Some(BLOCK_SIZE / SECTOR) } else { fate(i) };
            if let Some(n) = sectors {
                dst[..n * SECTOR].copy_from_slice(&data[..n * SECTOR]);
            }
        }
    }
    img
}

// ── helpers ────────────────────────────────────────────────────────

fn key() -> VolumeKey {
    VolumeKey::from_bytes(&MASTER)
}

fn other_key() -> VolumeKey {
    let mut k = MASTER;
    k[31] ^= 1;
    VolumeKey::from_bytes(&k)
}

fn opts() -> FormatOptions<'static> {
    FormatOptions { block_count: None, label: b"sealed", uuid: UUID, time_ns: 1_000 }
}

fn fresh() -> Volume<MemDev> {
    Volume::format_sealed(MemDev::new(BLOCKS), &opts(), &key()).expect("format")
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

fn put(v: &mut Volume<MemDev>, name: &str, data: &[u8]) -> u64 {
    let root = v.root();
    let ino = v.create(root, name.as_bytes(), Kind::File, 0o644).expect("create");
    assert_eq!(v.write(ino, 0, data).expect("write"), data.len());
    ino
}

fn read_all(v: &mut Volume<MemDev>, ino: u64) -> Result<Vec<u8>, Error> {
    let size = v.stat(ino)?.size as usize;
    let mut out = vec![0u8; size];
    let mut done = 0;
    while done < size {
        let n = v.read(ino, done as u64, &mut out[done..])?;
        assert!(n > 0);
        done += n;
    }
    Ok(out)
}

fn mount(img: Vec<u8>) -> Result<Volume<MemDev>, Error> {
    Volume::mount_sealed(MemDev::from_image(img), &key())
}

fn remount(v: Volume<MemDev>) -> Volume<MemDev> {
    mount(v.into_device().img).expect("remount")
}

/// Every path with its content (`None` for a directory).
fn dump(v: &mut Volume<MemDev>) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(v: &mut Volume<MemDev>, dir: u64, prefix: &str, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for e in v.readdir(dir).expect("readdir") {
            let path = format!("{}/{}", prefix, String::from_utf8(e.name.clone()).unwrap());
            if e.kind == Kind::Dir {
                out.insert(path.clone(), None);
                walk(v, e.ino, &path, out);
            } else {
                let data = read_all(v, e.ino).expect("read");
                out.insert(path, Some(data));
            }
        }
    }
    let mut out = BTreeMap::new();
    let root = v.root();
    walk(v, root, "", &mut out);
    out
}

fn geo() -> layout::Geometry {
    layout::Geometry::for_volume(BLOCKS, true).unwrap()
}

/// The table entry of `blk` in an image: tag and sequence number.
fn entry(img: &[u8], blk: u64) -> ([u8; 16], u64) {
    let (idx, off) = geo().table_loc(blk);
    let o = (geo().csum_start + idx) as usize * BLOCK_SIZE + off;
    seal::decode_entry(&img[o..o + layout::SEAL_ENTRY_SIZE])
}

fn entry_offset(blk: u64) -> usize {
    let (idx, off) = geo().table_loc(blk);
    (geo().csum_start + idx) as usize * BLOCK_SIZE + off
}

fn block(img: &[u8], blk: u64) -> &[u8] {
    &img[blk as usize * BLOCK_SIZE..(blk as usize + 1) * BLOCK_SIZE]
}

/// Data-area blocks the free-space map of `img` holds allocated.
fn allocated(img: &[u8]) -> Vec<u64> {
    let g = geo();
    let mut map = azvol::freemap::FreeMap::new(&g);
    for i in 0..g.bitmap_blocks {
        assert!(map.decode_block(i, block(img, g.bitmap_start + i)));
    }
    (g.data_start..BLOCKS).filter(|&k| map.is_set(k)).collect()
}

/// Live data-area blocks sealed between two images (their table entry
/// differs and the newer map still holds them).
fn changed_blocks(a: &[u8], b: &[u8]) -> Vec<u64> {
    allocated(b).into_iter().filter(|&k| entry(a, k) != entry(b, k)).collect()
}

/// The data-area block writes logged from `mark` (a log length) on.
fn data_writes(dev: &MemDev, mark: usize) -> Vec<(u64, Vec<u8>)> {
    dev.log[mark..]
        .iter()
        .filter_map(|o| match o {
            Op::Write { blk, data } if *blk >= geo().data_start => Some((*blk, data.clone())),
            _ => None,
        })
        .collect()
}

// ── round trip, and what the medium sees ───────────────────────────

#[test]
fn a_sealed_volume_round_trips_and_checks_clean() {
    let mut v = fresh();
    let root = v.root();
    let dir = v.create(root, b"d", Kind::Dir, 0o755).unwrap();
    let sizes = [0usize, 1, 4095, 4096, 4097, 100_000, 1 << 20];
    for (i, &n) in sizes.iter().enumerate() {
        let ino = v.create(dir, format!("f{i}").as_bytes(), Kind::File, 0o644).unwrap();
        assert_eq!(v.write(ino, 0, &pattern(i as u64 + 1, n)).unwrap(), n);
    }
    v.commit().unwrap();
    let want = dump(&mut v);
    let r = v.check(true).unwrap();
    assert!(r.is_clean(), "{:?}", r.problems);
    let mut v = remount(v);
    assert_eq!(dump(&mut v), want);
    let r = v.check(true).unwrap();
    assert!(r.is_clean(), "{:?}", r.problems);
    // and it is still a working volume after the mount opened a generation
    let ino = put(&mut v, "after", b"written after the remount");
    v.commit().unwrap();
    let mut v = remount(v);
    assert_eq!(read_all(&mut v, ino).unwrap(), b"written after the remount");
}

#[test]
fn no_plaintext_reaches_the_medium_and_a_plain_volume_shows_it() {
    let marker: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 251) as u8 ^ 0xA5).collect();
    let find = |img: &[u8]| img.windows(64).any(|w| w == &marker[..64]);
    let mut v = fresh();
    put(&mut v, "secret-file-name", &marker);
    v.commit().unwrap();
    let img = v.into_device().img;
    assert!(!find(&img));
    assert!(!img.windows(16).any(|w| w == b"secret-file-name"));
    // the control: the same write on a plain volume does show up
    let mut p = Volume::format(MemDev::new(BLOCKS), &opts()).unwrap();
    put(&mut p, "secret-file-name", &marker);
    p.commit().unwrap();
    let img = p.into_device().img;
    assert!(find(&img));
    assert!(img.windows(16).any(|w| w == b"secret-file-name"));
}

#[test]
fn the_geometry_follows_the_superblock_and_the_table_is_bigger() {
    let plain = layout::Geometry::new(BLOCKS).unwrap();
    let sealed = geo();
    assert!(sealed.sealed && !plain.sealed);
    assert_eq!(plain.csum_blocks, 4);
    // 170 entries of 24 bytes a table block
    assert_eq!(sealed.csum_blocks, (BLOCKS + 169) / 170);
    assert_eq!(layout::SEALS_PER_BLOCK, 170);
    // fewer than 2^32 blocks: the block number is a 32-bit nonce field
    assert!(layout::Geometry::for_volume(u32::MAX as u64, true).is_some());
    assert!(layout::Geometry::for_volume(u32::MAX as u64 + 1, true).is_none());
    assert!(layout::Geometry::for_volume(u32::MAX as u64 + 1, false).is_some());
    // the superblock carries the key slot
    let v = fresh();
    let img = v.into_device().img;
    let sb = SB_SLOTS
        .iter()
        .map(|&s| layout::Superblock::decode(block(&img, s)).unwrap())
        .max_by_key(|s| s.generation)
        .unwrap();
    assert_eq!(sb.key_alg, seal::ALG_CHACHA20_POLY1305);
    assert_eq!(sb.key_id, key().key_id(&UUID));
    assert_eq!(sb.wrapped_key, [0u8; 40]);
    assert_eq!(sb.geo, sealed);
}

// ── a block whose tag fails is an error ────────────────────────────

/// What a fresh mount makes of `img`: the content of the file, or the
/// error that stopped it.
fn outcome(img: Vec<u8>, name: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = mount(img)?;
    let ino = v.lookup_path(name)?;
    read_all(&mut v, ino)
}

#[test]
fn a_touched_block_tag_or_sequence_is_an_error_never_data() {
    let mut v = fresh();
    v.commit().unwrap();
    let before = v.device().img.clone();
    let content = pattern(9, 3 * BLOCK_SIZE + 17);
    put(&mut v, "file", &content);
    v.commit().unwrap();
    let after = v.into_device().img;
    let touched = changed_blocks(&before, &after);
    // file data, the directory block, the inode table block, at least
    assert!(touched.len() >= 4, "{touched:?}");
    assert_eq!(outcome(after.clone(), b"/file").unwrap(), content);
    let mut data_blocks_failing = 0;
    for &b in &touched {
        for what in ["data", "tag", "seq"] {
            let mut img = after.clone();
            match what {
                "data" => img[b as usize * BLOCK_SIZE + 100] ^= 1,
                "tag" => img[entry_offset(b) + 3] ^= 0x80,
                _ => img[entry_offset(b) + 16] ^= 1,
            }
            match outcome(img, b"/file") {
                // the failing block is named, and nothing else comes back
                Err(Error::Auth(x)) => {
                    assert_eq!(x, b, "{what} of block {b}");
                    if what == "data" {
                        data_blocks_failing += 1;
                    }
                }
                other => panic!("{what} of block {b}: {other:?}"),
            }
        }
    }
    assert_eq!(data_blocks_failing, touched.len());
}

#[test]
fn a_block_moved_to_another_place_fails_its_tag() {
    let mut v = fresh();
    v.commit().unwrap();
    let before = v.device().img.clone();
    let a = pattern(1, BLOCK_SIZE);
    put(&mut v, "a", &a);
    v.commit().unwrap();
    let after = v.into_device().img;
    // the file's data block is the one the file reads through: tamper-free
    // copy of any changed block onto another one (ciphertext, tag, sequence
    // number all moved) is refused, because the block number is in the
    // nonce and the associated data
    let touched = changed_blocks(&before, &after);
    let (src, dst) = (touched[0], touched[1]);
    let mut img = after.clone();
    let (s, d) = (src as usize * BLOCK_SIZE, dst as usize * BLOCK_SIZE);
    let moved = img[s..s + BLOCK_SIZE].to_vec();
    img[d..d + BLOCK_SIZE].copy_from_slice(&moved);
    let e = entry_offset(src);
    let ent = img[e..e + layout::SEAL_ENTRY_SIZE].to_vec();
    img[entry_offset(dst)..entry_offset(dst) + layout::SEAL_ENTRY_SIZE].copy_from_slice(&ent);
    assert_eq!(outcome(img, b"/a"), Err(Error::Auth(dst)));
}

#[test]
fn a_block_from_another_volume_under_the_same_key_fails_its_tag() {
    // two volumes, same master key, different uuid: different volume keys,
    // and the uuid is also in the associated data
    let mk = |uuid: [u8; 16]| {
        let o = FormatOptions { block_count: None, label: b"x", uuid, time_ns: 1 };
        let mut v = Volume::format_sealed(MemDev::new(BLOCKS), &o, &key()).unwrap();
        put(&mut v, "f", &pattern(3, BLOCK_SIZE));
        v.commit().unwrap();
        v.into_device().img
    };
    let a = mk([1; 16]);
    let b = mk([2; 16]);
    // same layout, so graft b's data area and table onto a's superblocks
    let mut img = a.clone();
    let g = geo();
    let from = g.csum_start as usize * BLOCK_SIZE;
    img[from..].copy_from_slice(&b[from..]);
    let r = outcome(img, b"/f");
    assert!(matches!(r, Err(Error::Auth(_))), "{r:?}");
}

// ── keys ───────────────────────────────────────────────────────────

#[test]
fn a_wrong_key_no_key_or_a_key_for_a_plain_volume_is_refused() {
    let mut v = fresh();
    put(&mut v, "f", b"hello");
    v.commit().unwrap();
    let img = v.into_device().img;
    // refused at mount, before any data is read
    let mut d = MemDev::from_image(img.clone());
    d.log.clear();
    assert_eq!(Volume::mount_sealed(d, &other_key()).err(), Some(Error::WrongKey));
    assert_eq!(Volume::mount(MemDev::from_image(img.clone())).err(), Some(Error::KeyRequired));
    // the right key still reads it
    assert_eq!(outcome(img.clone(), b"/f").unwrap(), b"hello");
    // a plain volume has no key to give
    let p = Volume::format(MemDev::new(BLOCKS), &opts()).unwrap().into_device().img;
    assert_eq!(
        Volume::mount_sealed(MemDev::from_image(p), &key()).err(),
        Some(Error::Unsupported("volume is not sealed"))
    );
    // the key id is not the key, and a different volume gets a different id
    let id = key().key_id(&UUID);
    assert_ne!(&id[..], &MASTER[..16]);
    assert_ne!(id, key().key_id(&[8; 16]));
    assert_ne!(id, other_key().key_id(&UUID));
}

#[test]
fn an_unknown_algorithm_or_a_wrapped_key_is_refused() {
    let img = fresh().into_device().img;
    let patch = |f: &dyn Fn(&mut [u8])| -> Vec<u8> {
        let mut img = img.clone();
        for s in SB_SLOTS {
            let blk = &mut img[s as usize * BLOCK_SIZE..(s as usize + 1) * BLOCK_SIZE];
            f(blk);
            let c = azvol::crc32c::crc32c_update(0, &blk[..layout::sbo::CRC]);
            let c = azvol::crc32c::crc32c_update(c, &[0; 4]);
            let c = azvol::crc32c::crc32c_update(c, &blk[layout::sbo::CRC + 4..]);
            layout::wr32(blk, layout::sbo::CRC, c);
        }
        img
    };
    let alg = patch(&|b| layout::wr32(b, layout::sbo::KEY_ALG, 2));
    assert_eq!(layout::Superblock::decode(block(&alg, 0)).err(), Some(Error::Unsupported("key algorithm")));
    let wrapped = patch(&|b| b[layout::sbo::WRAPPED_KEY + 5] = 1);
    assert_eq!(layout::Superblock::decode(block(&wrapped, 0)).err(), Some(Error::Unsupported("wrapped key")));
}

#[test]
fn the_nonce_and_the_derivation_are_the_documented_ones() {
    // an independent reconstruction: HKDF(salt = uuid, ikm = master), nonce =
    // seq (8 bytes LE) then block (4 bytes LE), associated data = block
    // (8 bytes LE) then uuid
    let mut vk = [0u8; 32];
    assert!(hkdf::hkdf(&UUID, &MASTER, b"azvol/chacha20-poly1305/v1 volume key", &mut vk));
    let plain = pattern(5, BLOCK_SIZE);
    let (blk, sq) = (1234u64, seal::seq(77, 5));
    let mut want = plain.clone();
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&sq.to_le_bytes());
    nonce[8..].copy_from_slice(&(blk as u32).to_le_bytes());
    let mut aad = blk.to_le_bytes().to_vec();
    aad.extend_from_slice(&UUID);
    let tag = chachapoly::seal(&vk, &nonce, &aad, &mut want).unwrap();
    let s = key().sealer(&UUID);
    let mut got = plain.clone();
    assert_eq!(s.seal(blk, sq, &mut got), tag);
    assert_eq!(got, want);
    assert_ne!(got, plain);
    assert_eq!(seal::nonce(sq, blk), nonce);
    // and it opens, but not at another place, sequence number or tag
    let mut t = got.clone();
    assert!(s.open(blk, sq, &tag, &mut t));
    assert_eq!(t, plain);
    // (the last: the same 32 low bits, a different block, so the AAD)
    for (b, q) in [(blk + 1, sq), (blk, sq + 1), (blk + (1 << 32), sq)] {
        let mut t = got.clone();
        assert!(!s.open(b, q, &tag, &mut t), "({b},{q})");
    }
    let mut bad = tag;
    bad[0] ^= 1;
    let mut t = got.clone();
    assert!(!s.open(blk, sq, &bad, &mut t));
    assert_eq!(t, got, "a failed open leaves the data as received");
}

// ── nonce uniqueness ───────────────────────────────────────────────

#[test]
fn sequence_numbers_are_injective_at_the_boundaries() {
    let mut seen = std::collections::BTreeSet::new();
    let gens = [0u64, 1, 2, 3, seal::MAX_GENERATION - 1, seal::MAX_GENERATION];
    let ctrs = [0u64, 1, 2, (1 << seal::COUNTER_BITS) - 2, (1 << seal::COUNTER_BITS) - 1];
    for &g in &gens {
        for &c in &ctrs {
            let s = seal::seq(g, c);
            assert!(seen.insert(s), "({g},{c})");
            assert_eq!(seal::seq_generation(s), g);
        }
    }
    // the nonce takes the block as 32 bits; every sealed volume block fits
    assert_ne!(seal::nonce(1, 0), seal::nonce(1, 1));
    assert_ne!(seal::nonce(1, 5), seal::nonce(2, 5));
    assert_eq!(seal::nonce(1, u32::MAX as u64 - 1)[8..], (u32::MAX - 1).to_le_bytes());
}

#[test]
fn a_counter_that_runs_out_is_an_error_not_a_repeat() {
    let mut s: Sealer = key().sealer(&UUID);
    assert_eq!(s.next_seq(5).unwrap(), seal::seq(5, 0));
    assert_eq!(s.next_seq(5).unwrap(), seal::seq(5, 1));
    // a new generation starts its counter again
    assert_eq!(s.next_seq(6).unwrap(), seal::seq(6, 0));
    assert_eq!(s.next_seq(seal::MAX_GENERATION + 1), Err(Error::NonceExhausted));
    let mut s = key().sealer(&UUID);
    for i in 0..(1u64 << seal::COUNTER_BITS) {
        assert_eq!(s.next_seq(9).unwrap(), seal::seq(9, i));
    }
    assert_eq!(s.next_seq(9), Err(Error::NonceExhausted));
    assert_eq!(s.next_seq(10).unwrap(), seal::seq(10, 0));
}

#[test]
fn copy_on_write_never_reuses_a_nonce() {
    let mut v = fresh();
    let content = pattern(11, BLOCK_SIZE);
    let ino = put(&mut v, "f", &content);
    v.commit().unwrap();
    // the same bytes over the same file, generation after generation: each
    // commit moves the data (copy on write) and seals it under a new
    // sequence number, so the ciphertext differs though the plaintext does not
    let mut nonces: BTreeMap<(u64, u64), Vec<u8>> = BTreeMap::new();
    let mut gens = Vec::new();
    for _ in 0..6 {
        v.write(ino, 0, &content).unwrap();
        v.commit().unwrap();
        gens.push(v.generation());
        let img = v.device().img.clone();
        for b in geo().data_start..BLOCKS {
            let (_, sq) = entry(&img, b);
            if sq == 0 {
                continue;
            }
            // the same (seq, block) is the same write, or the nonce repeated
            let c = block(&img, b).to_vec();
            let prev = nonces.entry((sq, b)).or_insert_with(|| c.clone());
            assert_eq!(*prev, c, "nonce (seq {sq:#x}, block {b}) sealed two different blocks");
            assert!(seal::seq_generation(sq) <= v.generation());
        }
    }
    // the same plaintext was sealed at 6 generations: 6 different data blocks
    let mut distinct: Vec<Vec<u8>> = data_writes(v.device(), 0).into_iter().map(|(_, c)| c).collect();
    distinct.sort();
    distinct.dedup();
    assert!(distinct.len() >= 6);
    assert!(gens.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(read_all(&mut v, ino).unwrap(), content);
}

#[test]
fn a_block_rewritten_inside_one_transaction_gets_a_new_nonce() {
    // A block written in the open transaction is overwritten in place, so
    // (generation, block) alone would seal two plaintexts under one nonce.
    let mut v = fresh();
    let ino = put(&mut v, "f", &pattern(1, BLOCK_SIZE));
    v.commit().unwrap();
    let mark = v.device().log.len();
    let same = pattern(2, BLOCK_SIZE);
    v.write(ino, 0, &same).unwrap(); // copy on write: a new block
    v.write(ino, 0, &same).unwrap(); // the same block, in place
    v.write(ino, 0, &same).unwrap();
    let writes = data_writes(v.device(), mark);
    assert_eq!(writes.len(), 3, "three data block writes");
    assert_eq!(writes[0].0, writes[1].0);
    assert_eq!(writes[1].0, writes[2].0);
    // identical plaintext, three different ciphertexts
    assert_ne!(writes[0].1, writes[1].1);
    assert_ne!(writes[1].1, writes[2].1);
    assert_ne!(writes[0].1, writes[2].1);
    v.commit().unwrap();
    let mut v = remount(v);
    assert_eq!(read_all(&mut v, ino).unwrap(), same);
}

#[test]
fn an_aborted_group_does_not_let_the_next_write_repeat_a_nonce() {
    // The allocator is next-fit, so a block given back by an abort is handed
    // out again only after it wraps; fill the volume to make it. The same
    // plaintext goes to every block, so a repeated (generation, block) would
    // show as a repeated ciphertext.
    let mut v = fresh();
    let root = v.root();
    let plain = pattern(4, BLOCK_SIZE);
    // (80 blocks: the write below cannot take the volume's last 24, the
    // reserve, and those are the ones just before the allocator's hint)
    let eighty: Vec<u8> = plain.iter().copied().cycle().take(80 * BLOCK_SIZE).collect();
    let mark0 = v.device().log.len();
    v.begin_group().unwrap();
    let ino = v.create(root, b"g", Kind::File, 0o644).unwrap();
    assert_eq!(v.write(ino, 0, &eighty).unwrap(), eighty.len());
    let aborted = data_writes(v.device(), mark0);
    v.abort_group().unwrap();
    let mark = v.device().log.len();
    v.begin_group().unwrap();
    let ino = v.create(root, b"g", Kind::File, 0o644).unwrap();
    let s = v.statfs();
    let blocks = (s.blocks_total - s.blocks_used) as usize - 40;
    let big: Vec<u8> = plain.iter().copied().cycle().take(blocks * BLOCK_SIZE).collect();
    assert_eq!(v.write(ino, 0, &big).unwrap(), big.len());
    v.commit_group().unwrap();
    let retry = data_writes(v.device(), mark);
    let mut reused = 0;
    for (b, c) in &aborted {
        for (b2, c2) in &retry {
            if b == b2 {
                reused += 1;
                assert_ne!(c, c2, "block {b} sealed twice under one nonce");
            }
        }
    }
    assert!(reused > 0, "the fill must wrap onto a block the abort gave back");
    let mut v = Volume::mount_sealed(MemDev::from_image(v.into_device().img), &key()).unwrap();
    assert_eq!(read_all(&mut v, ino).unwrap(), big);
}

#[test]
fn a_cut_transaction_does_not_leave_its_nonces_to_the_next_mount() {
    // Write, do not commit (the ciphertext is on the medium, the table
    // and superblock are not), lose power, mount, write the same again:
    // the mount opened a new generation, so the retry cannot repeat.
    let mut v = fresh();
    v.commit().unwrap();
    let base = v.device().img.clone();
    let plain = pattern(6, BLOCK_SIZE);
    put(&mut v, "f", &plain);
    let first = data_writes(v.device(), 0);
    // the cut: only the data blocks of the uncommitted transaction landed
    let mut img = base.clone();
    for (b, c) in &first {
        img[*b as usize * BLOCK_SIZE..(*b as usize + 1) * BLOCK_SIZE].copy_from_slice(c);
    }
    assert_ne!(img, base);
    let mut v = mount(img).unwrap();
    let g_mount = v.generation();
    assert!(g_mount >= 3, "the mount opened a generation: {g_mount}");
    let mark = v.device().log.len();
    put(&mut v, "f", &plain);
    let second = data_writes(v.device(), mark);
    let mut hit = 0;
    for (b, c) in &second {
        for (b0, c0) in &first {
            if b == b0 {
                hit += 1;
                assert_ne!(c, c0, "block {b} sealed twice under one nonce");
            }
        }
    }
    assert!(hit > 0, "the retry writes the blocks the lost transaction wrote");
    // and the mount really committed the generation, not only counted it
    v.commit().unwrap();
    let mut again = remount(v);
    assert!(again.generation() > g_mount);
    assert!(again.lookup_path(b"/f").is_ok());
}

#[test]
fn every_mount_opens_a_generation_a_format_does_not() {
    let v = fresh();
    assert_eq!(v.generation(), 2, "format: generation 1, the root's commit 2");
    let g0 = v.generation();
    let img = v.into_device().img;
    let a = mount(img).unwrap();
    assert_eq!(a.generation(), g0 + 1);
    let b = mount(a.into_device().img).unwrap();
    assert_eq!(b.generation(), g0 + 2);
}

// ── power cuts ─────────────────────────────────────────────────────

#[test]
fn a_cut_anywhere_in_a_sealed_commit_leaves_the_old_or_the_new_state() {
    let mut v = fresh();
    let keep = put(&mut v, "keep", &pattern(1, 20_000));
    v.commit().unwrap();
    let base = v.device().img.clone();
    let old = dump(&mut v);
    v.device_mut().log.clear();
    // a commit that rewrites, grows and adds
    v.write(keep, 5000, &pattern(2, 30_000)).unwrap();
    put(&mut v, "new", &pattern(3, 9000));
    v.commit().unwrap();
    let new = dump(&mut v);
    assert_ne!(old, new);
    let log = v.device().log.clone();
    let fates: [&dyn Fn(usize) -> Option<usize>; 3] = [&|_| None, &|_| Some(BLOCK_SIZE / SECTOR), &|i| Some(i % 8)];
    for cut in 0..=log.len() {
        for fate in fates {
            let img = crash_image(&base, &log, cut, fate);
            let mut m = mount(img).unwrap_or_else(|e| panic!("cut {cut}: {e:?}"));
            let got = dump(&mut m);
            assert!(got == old || got == new, "cut {cut}: neither state");
            let r = m.check(true).unwrap();
            assert!(r.is_clean(), "cut {cut}: {:?}", r.problems);
        }
    }
}
