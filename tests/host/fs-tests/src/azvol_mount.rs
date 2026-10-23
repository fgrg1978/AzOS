// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the azvol volume in use (`crates/fs/fs/src/azvol/mount.rs`,
//! `probe.rs`): the probe that recognises it, mounting from a topology row,
//! the volume behind the REAL `vfs.rs`, the transaction fence (one owner; no
//! other task's change or commit lands in it; a dead owner's is discarded), and
//! an atomic rename.
//!
//! The engine is the real one, over an in-memory device that can replay a
//! power cut (the writes since the last `flush` land in any subset, any of
//! them torn at a sector boundary). Three buckets, as everywhere: tests that
//! DISCRIMINATE a property say which change turns them red (`Canary`); the
//! rest check shape.
//!
//! The rows with a `verity_root` are here too (the hash tree itself is tested
//! beside the format, in `azvol_format.rs`): a volume opened through the tree,
//! and the rule that one failed block anywhere refuses the mount or the read.
//!
//! Wired into the suite by `mod azvol_mount;` in `src/lib.rs`.

#![cfg(test)]

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/fs/fs/src/azvol/mod.rs"]
mod azvol;

// `probe.rs` also holds the opt-in inode probe, gated on a feature this suite
// does not declare.
#[allow(dead_code, unexpected_cfgs)]
#[path = "../../../../crates/fs/fs/src/probe.rs"]
mod probe;

#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/azvol/mount.rs"]
mod mount;

use super::vfs::{self, FileSystem as _, FsErr, O_CREAT, O_RDONLY, O_WRONLY};
use azvol::layout::SB_SLOTS;
use azvol::verity::{self, Fail, Hash, OpenError, Tamper};
use azvol::{BlockDev, DevError, FormatOptions, Kind, Volume, VolumeKey, BLOCK_SIZE};
use mount::{AzvolFs, Env, Outcome, Row, Why};
use probe::{probe_volume, VolumeKind};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

const SECTOR: usize = 512;

// ── the device ────────────────────────────────────────────────────

#[derive(Clone)]
enum DevOp {
    Write { blk: u64, data: Vec<u8> },
    Flush,
}

struct Inner {
    img: Vec<u8>,
    log: Vec<DevOp>,
}

/// A device the test keeps a handle on after the volume owns it.
#[derive(Clone)]
struct Dev(Arc<Mutex<Inner>>);

impl Dev {
    fn blank(blocks: u64) -> Dev {
        Dev(Arc::new(Mutex::new(Inner { img: vec![0; blocks as usize * BLOCK_SIZE], log: vec![] })))
    }
    fn from_image(img: Vec<u8>) -> Dev {
        Dev(Arc::new(Mutex::new(Inner { img, log: vec![] })))
    }
    fn image(&self) -> Vec<u8> {
        self.0.lock().unwrap().img.clone()
    }
    fn log(&self) -> Vec<DevOp> {
        self.0.lock().unwrap().log.clone()
    }
    fn clear_log(&self) {
        self.0.lock().unwrap().log.clear();
    }
    /// Change one byte of block `blk` (a second call puts it back).
    fn flip(&self, blk: u64, at: usize) {
        self.0.lock().unwrap().img[blk as usize * BLOCK_SIZE + at] ^= 0x5A;
    }
}

/// The blocks a layer above asked the device for.
struct Spy {
    inner: Dev,
    seen: Arc<Mutex<BTreeSet<u64>>>,
}

impl BlockDev for Spy {
    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }
    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let n = (buf.len() / BLOCK_SIZE) as u64;
        self.seen.lock().unwrap().extend(first..first + n);
        self.inner.read(first, buf)
    }
    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        self.inner.write(first, buf)
    }
    fn flush(&mut self) -> Result<(), DevError> {
        self.inner.flush()
    }
}

impl BlockDev for Dev {
    fn block_count(&self) -> u64 {
        (self.0.lock().unwrap().img.len() / BLOCK_SIZE) as u64
    }
    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let g = self.0.lock().unwrap();
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > g.img.len() {
            return Err(DevError);
        }
        buf.copy_from_slice(&g.img[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        let mut g = self.0.lock().unwrap();
        let o = first as usize * BLOCK_SIZE;
        if buf.is_empty() || buf.len() % BLOCK_SIZE != 0 || o + buf.len() > g.img.len() {
            return Err(DevError);
        }
        g.img[o..o + buf.len()].copy_from_slice(buf);
        for (i, c) in buf.chunks(BLOCK_SIZE).enumerate() {
            g.log.push(DevOp::Write { blk: first + i as u64, data: c.to_vec() });
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), DevError> {
        self.0.lock().unwrap().log.push(DevOp::Flush);
        Ok(())
    }
    /// The device is a partition that starts at the medium's first sector.
    fn raw_sector(&self, block: u64) -> Option<u64> {
        Some(block * (BLOCK_SIZE / SECTOR) as u64)
    }
}

#[derive(Clone, Copy)]
enum Fate {
    Lost,
    Whole,
    Torn(usize),
}

/// The disk after a cut before log op `cut`: everything up to the last flush
/// barrier before it is durable, the writes after it get their `fate`.
fn crash_image(base: &[u8], log: &[DevOp], cut: usize, fate: &dyn Fn(usize) -> Fate) -> Vec<u8> {
    let mut img = base.to_vec();
    let barrier = log[..cut].iter().rposition(|o| matches!(o, DevOp::Flush)).map_or(0, |i| i + 1);
    for (i, op) in log[..cut].iter().enumerate() {
        if let DevOp::Write { blk, data } = op {
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

// ── the system around the mount ───────────────────────────────────

thread_local! {
    static TID: Cell<u32> = const { Cell::new(1) };
}

/// Act as task `t` from here on (the transaction fence tells tasks apart by it).
fn as_task(t: u32) {
    TID.with(|c| c.set(t));
}

/// The clock, and which tasks have exited.
#[derive(Default)]
struct TestEnv {
    dead: Mutex<BTreeSet<u32>>,
    tampered: Mutex<Vec<Tamper>>,
}

impl TestEnv {
    fn leak() -> &'static TestEnv {
        Box::leak(Box::default())
    }
    /// Task `t` has exited.
    fn kill(&self, t: u32) {
        self.dead.lock().unwrap().insert(t);
    }
    /// The verity failures written down so far.
    fn records(&self) -> Vec<Tamper> {
        self.tampered.lock().unwrap().clone()
    }
    fn clear_records(&self) {
        self.tampered.lock().unwrap().clear();
    }
}

impl Env for TestEnv {
    fn now_ns(&self) -> u64 {
        5_000_000_000
    }
    fn tid(&self) -> u32 {
        TID.with(|c| c.get())
    }
    fn alive(&self, tid: u32) -> bool {
        !self.dead.lock().unwrap().contains(&tid)
    }
    fn tampered(&self, t: &Tamper) {
        self.tampered.lock().unwrap().push(*t);
    }
}

// ── helpers ───────────────────────────────────────────────────────

fn formatted(blocks: u64) -> (Dev, Vec<u8>) {
    let dev = Dev::blank(blocks);
    let o = FormatOptions { block_count: None, label: b"mountvol", uuid: [7; 16], time_ns: 1_000 };
    let v = Volume::format(dev.clone(), &o).expect("format");
    drop(v);
    let img = dev.image();
    (dev, img)
}

/// A sealed volume's image, formatted under `key`.
fn sealed_image(blocks: u64, key: &VolumeKey) -> Vec<u8> {
    let dev = Dev::blank(blocks);
    let o = FormatOptions { block_count: None, label: b"sealvol", uuid: [9; 16], time_ns: 1_000 };
    drop(Volume::format_sealed(dev.clone(), &o, key).expect("format sealed"));
    dev.image()
}

/// The key the sealed fixtures are formatted under.
fn the_key() -> VolumeKey {
    VolumeKey::from_bytes(&[0x42; 32])
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

/// A mounted filesystem over a fresh volume, not registered with the VFS.
fn fresh_fs(env: &'static TestEnv, read_only: bool) -> (&'static AzvolFs<Dev>, Dev) {
    let (dev, _) = formatted(2048);
    let vol = Volume::mount(dev.clone()).expect("mount");
    let fs = Box::leak(Box::new(AzvolFs::new(vol, read_only, env)));
    (fs, dev)
}

fn key<D: BlockDev + Send>(fs: &AzvolFs<D>, p: &str) -> vfs::InodeKey {
    fs.key_for(p.as_bytes()).unwrap_or_else(|| panic!("key_for {p}"))
}

fn put(fs: &AzvolFs<Dev>, p: &str, data: &[u8]) {
    let k = key(fs, p);
    fs.create(&k).unwrap();
    assert_eq!(fs.write_at(&k, 0, data), Ok(data.len()));
}

fn get<D: BlockDev + Send>(fs: &AzvolFs<D>, p: &str) -> Option<Vec<u8>> {
    let k = fs.key_for(p.as_bytes())?;
    let st = fs.stat(&k)?;
    assert!(!st.is_dir, "{p} is a directory");
    let mut b = vec![0u8; st.size as usize];
    assert_eq!(fs.read_at(&k, 0, &mut b), b.len());
    Some(b)
}

type Tree = BTreeMap<String, Option<Vec<u8>>>;

/// Every path of the volume in `img` (committed state) with its bytes; `None`
/// is a directory. Read with the engine alone, so it sees only what is durable.
fn dump_image(img: Vec<u8>) -> Tree {
    let mut v = Volume::mount(Dev::from_image(img)).expect("remount");
    fn walk(v: &mut Volume<Dev>, dir: u64, prefix: &str, out: &mut Tree) {
        for e in v.readdir(dir).unwrap() {
            let path = format!("{prefix}/{}", String::from_utf8(e.name.clone()).unwrap());
            if e.kind == Kind::Dir {
                out.insert(path.clone(), None);
                walk(v, e.ino, &path, out);
            } else {
                let size = v.stat(e.ino).unwrap().size as usize;
                let mut data = vec![0u8; size];
                if size > 0 {
                    assert_eq!(v.read(e.ino, 0, &mut data).unwrap(), size);
                }
                out.insert(path, Some(data));
            }
        }
    }
    let mut out = Tree::new();
    let root = v.root();
    walk(&mut v, root, "", &mut out);
    out
}

/// The live tree through the filesystem alone.
fn dump_fs(fs: &AzvolFs<Dev>) -> Tree {
    fn walk(fs: &AzvolFs<Dev>, dir: &str, out: &mut Tree) {
        let mut cookie = 0;
        let mut e = vfs::DirEnt::new();
        while let Some(next) = fs.readdir(dir.as_bytes(), cookie, &mut e).unwrap() {
            cookie = next;
            let name = String::from_utf8(e.name().to_vec()).unwrap();
            let rel = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
            if e.is_dir {
                out.insert(format!("/{rel}"), None);
                walk(fs, &rel, out);
            } else {
                out.insert(format!("/{rel}"), Some(get(fs, &rel).unwrap()));
            }
        }
    }
    let mut out = Tree::new();
    walk(fs, "", &mut out);
    out
}

// ── the probe ─────────────────────────────────────────────────────

fn probe_of(img: &[u8]) -> VolumeKind {
    probe_volume(&mut |blk, buf| {
        let o = blk as usize * BLOCK_SIZE;
        match img.get(o..o + BLOCK_SIZE) {
            Some(b) => {
                buf.copy_from_slice(b);
                true
            }
            None => false,
        }
    })
}

#[test]
fn the_probe_recognises_a_formatted_volume_and_says_its_size_and_generation() {
    let (dev, img) = formatted(2048);
    let VolumeKind::Azvol { blocks, generation } = probe_of(&img) else { panic!("{:?}", probe_of(&img)) };
    assert_eq!(blocks, 2048);
    assert_eq!(generation, Volume::mount(dev).unwrap().generation());
}

#[test]
fn the_probe_takes_the_newest_copy_and_survives_the_loss_of_either() {
    let (_, img) = formatted(2048);
    let mut a = img.clone();
    // Only copy B valid.
    a[..BLOCK_SIZE].fill(0);
    assert!(matches!(probe_of(&a), VolumeKind::Azvol { .. }));
    let mut b = img.clone();
    let o = SB_SLOTS[1] as usize * BLOCK_SIZE;
    b[o..o + BLOCK_SIZE].fill(0);
    assert!(matches!(probe_of(&b), VolumeKind::Azvol { .. }));
    // Both valid with different generations: the higher one is reported.
    let dev = Dev::from_image(img.clone());
    let mut v = Volume::mount(dev.clone()).unwrap();
    let root = v.root();
    v.create(root, b"x", Kind::File, 0o644).unwrap();
    v.commit().unwrap();
    let g = v.generation();
    drop(v);
    let VolumeKind::Azvol { generation, .. } = probe_of(&dev.image()) else { panic!() };
    assert_eq!(generation, g);
}

#[test]
fn the_probe_refuses_damage_and_does_not_take_it_for_a_blank_disk() {
    let (_, img) = formatted(2048);
    // A bit flipped in both copies breaks their checksums: the magic is
    // there, nothing is usable.
    let mut d = img.clone();
    for s in SB_SLOTS {
        d[s as usize * BLOCK_SIZE + 100] ^= 1;
    }
    assert!(matches!(probe_of(&d), VolumeKind::AzvolRefused(_)), "{:?}", probe_of(&d));
    assert_eq!(probe_of(&vec![0u8; 128 * BLOCK_SIZE]), VolumeKind::Unknown);
    assert_eq!(probe_of(&[]), VolumeKind::Unknown, "an unreadable device holds nothing");
}

/// A FAT32 boot sector in the first block of an otherwise empty medium.
fn fat_boot_sector() -> Vec<u8> {
    let mut img = vec![0u8; 128 * BLOCK_SIZE];
    img[11..13].copy_from_slice(&512u16.to_le_bytes());
    img[13] = 8;
    img[36..40].copy_from_slice(&1000u32.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    img
}

#[test]
fn the_probe_tells_the_boot_volume_from_a_native_one() {
    assert_eq!(probe_of(&fat_boot_sector()), VolumeKind::Fat32);
    // A FAT16 parameter block (a fixed root directory, a 16-bit FAT size) is not one.
    let mut f16 = fat_boot_sector();
    f16[17..19].copy_from_slice(&512u16.to_le_bytes());
    assert_eq!(probe_of(&f16), VolumeKind::Unknown);
    // The signature alone is not enough.
    let mut sig = vec![0u8; 128 * BLOCK_SIZE];
    sig[510] = 0x55;
    sig[511] = 0xAA;
    assert_eq!(probe_of(&sig), VolumeKind::Unknown);
}

// ── mounting from rows ────────────────────────────────────────────

/// Row `index` of the test's table: its name is the digit, which is how the
/// outcomes are told apart.
fn row<'a>(index: u8, partition: u8, mount: &'a [u8]) -> Row<'a> {
    const NAMES: [&[u8]; 11] = [b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9", b":"];
    Row { name: NAMES[index as usize], partition, mount, read_only: false, aead: false, verity_root: None }
}

/// The rows of one boot, mounted once for the whole binary (the VFS's mount
/// table is global and holds four): what each came to, and the device of the
/// row that mounted at `/vol`.
struct RowsRun {
    outcomes: BTreeMap<u16, Outcome>,
    dev: Dev,
    /// The device of the sealed row that mounted at `/rows-s`.
    sealed_dev: Dev,
    env: &'static TestEnv,
}

fn rows_run() -> &'static RowsRun {
    use std::sync::OnceLock;
    static RUN: OnceLock<RowsRun> = OnceLock::new();
    RUN.get_or_init(|| {
        super::vfs_root_once();
        let env = TestEnv::leak();
        let (dev, good) = formatted(4096);
        // Partition 1: azvol. 2: blank. 3: FAT32. 4: a plain azvol volume under
        // a sealed row. 5: does not exist. 6: azvol, at the path row 0 took.
        // 7: sealed, and the system holds its key. 8: sealed, and it holds none.
        // 9: sealed under another key. 10: sealed, mounted at the path of 7.
        let mut disks: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
        disks.insert(2, vec![0; 2048 * BLOCK_SIZE]);
        disks.insert(3, fat_boot_sector());
        disks.insert(4, good.clone());
        disks.insert(6, good.clone());
        let sealed_img = sealed_image(2048, &the_key());
        let sealed_dev = Dev::from_image(sealed_img.clone());
        disks.insert(8, sealed_img.clone());
        disks.insert(9, sealed_img);
        let mut sealed = row(3, 4, b"/rows-d");
        sealed.aead = true;
        let (mut sealed_ok, mut sealed_nokey, mut sealed_wrong) = (row(7, 7, b"/rows-s"), row(8, 8, b"/rows-n"), row(9, 9, b"/rows-w"));
        for r in [&mut sealed_ok, &mut sealed_nokey, &mut sealed_wrong] {
            r.aead = true;
        }
        // A plain volume under a row with a root: there is no tree after it.
        let mut hashed = row(4, 6, b"/rows-e");
        hashed.verity_root = Some([0x5A; 32]);
        // Sealed and hash-checked at once: refused before any device is read.
        let mut both = row(10, 1, b"/rows-v");
        both.aead = true;
        both.verity_root = Some([0x5A; 32]);
        let rows = [
            row(0, 1, b"/vol"),
            row(1, 2, b"/rows-b"),
            row(2, 3, b"/rows-c"),
            sealed,
            hashed,
            row(5, 5, b"/rows-f"),
            row(6, 6, b"/vol"),
            sealed_ok,
            sealed_nokey,
            sealed_wrong,
            both,
        ];
        let mut seen: BTreeMap<u16, Outcome> = BTreeMap::new();
        let d1 = dev.clone();
        mount::mount_rows(
            rows,
            &mut |p| match p {
                1 => Some(d1.clone()),
                7 => Some(sealed_dev.clone()),
                _ => disks.get(&p).map(|i| Dev::from_image(i.clone())),
            },
            // The keystore: it holds the key of rows 3, 7 and 9 (9's is not the
            // key its volume was sealed with), and none for row 8.
            &mut |r| match r.name {
                b"3" | b"7" => Some(the_key()),
                b"9" => Some(VolumeKey::from_bytes(&[0x43; 32])),
                _ => None,
            },
            env,
            &mut |r, o| {
                seen.insert(u16::from(r.name[0] - b'0'), o);
            },
        );
        RowsRun { outcomes: seen, dev, sealed_dev, env }
    })
}

#[test]
fn rows_mount_the_partitions_they_name_and_a_bad_row_leaves_the_others_alone() {
    let _g = super::serial();
    let by = &rows_run().outcomes;
    assert!(matches!(by[&0], Outcome::Mounted(_)));
    assert_eq!(by[&1], Outcome::Refused(Why::NotAzvol(VolumeKind::Unknown)), "a blank partition is never formatted");
    assert_eq!(by[&2], Outcome::Refused(Why::NotAzvol(VolumeKind::Fat32)), "the boot volume is not served as azvol");
    assert_eq!(
        by[&3],
        Outcome::Refused(Why::Engine(azvol::Error::Unsupported("volume is not sealed"))),
        "a sealed row is not served from a plain volume, key or no key"
    );
    assert_eq!(
        by[&4],
        Outcome::Refused(Why::Verity(OpenError::NoHeader)),
        "a hash-checked row is not mounted unchecked"
    );
    assert_eq!(by[&5], Outcome::Refused(Why::NoDevice));
    assert_eq!(by[&6], Outcome::Refused(Why::Vfs), "a mount point already served");
    assert!(matches!(by[&7], Outcome::Mounted(_)), "a sealed row mounts with its key: {:?}", by[&7]);
    assert_eq!(by[&8], Outcome::Refused(Why::NoKey), "no key, no mount (and a receipt, the kernel's)");
    assert_eq!(by[&9], Outcome::Refused(Why::Engine(azvol::Error::WrongKey)), "another key opens nothing");
    assert_eq!(by[&10], Outcome::Refused(Why::SealedAndHashed), "sealed and hash-checked together is refused");
    // The good row is reachable through the real VFS, under its mount point.
    let st = vfs::vfs_stat(b"/vol").expect("the mount point answers");
    assert!(st.is_dir);
    let sfs = vfs::vfs_statfs(b"/vol").unwrap();
    assert_eq!(sfs.fs_type, vfs::FS_TYPE_AZVOL);
    assert_eq!(sfs.block_size as usize, BLOCK_SIZE);
    assert_eq!(sfs.blocks, 4096);
    for gone in [&b"/rows-b"[..], b"/rows-c", b"/rows-d", b"/rows-e", b"/rows-f", b"/rows-n", b"/rows-w", b"/rows-v"] {
        assert!(vfs::vfs_stat(gone).is_none(), "a refused row mounted {}", String::from_utf8_lossy(gone));
    }
}

/// **Canary**: a mount that takes the key but opens the volume as a plain one
/// (`Volume::mount` in `mount_volume`) is refused by the engine (`KeyRequired`)
/// and rows 7 fails; one that ignores the row's `aead` mounts row 3's plain
/// volume.
#[test]
fn a_sealed_row_serves_files_and_leaves_no_plaintext_on_the_medium() {
    let _g = super::serial();
    let r = rows_run();
    assert!(matches!(r.outcomes[&7], Outcome::Mounted(_)));
    let secret = b"the volume key opens this and nothing else, 0123456789";
    as_task(1);
    vput("/rows-s/secret.txt", secret);
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/rows-s/secret.txt", O_RDONLY);
    assert!(fd >= 0);
    assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
    assert_eq!(read_fd(&mut t, fd, 200), secret.to_vec());
    vfs::vfs_close(&mut t, fd);
    let img = r.sealed_dev.image();
    assert!(!img.windows(secret.len()).any(|w| w == secret), "the plaintext is on the medium");
    // Mounting the image again with the key finds the file; with another key,
    // nothing is read.
    let again = Volume::mount_sealed(Dev::from_image(img.clone()), &the_key()).expect("mount with the key");
    drop(again);
    assert_eq!(
        Volume::mount_sealed(Dev::from_image(img), &VolumeKey::from_bytes(&[1; 32])).err(),
        Some(azvol::Error::WrongKey)
    );
}

// ── the volume behind the real VFS ────────────────────────────────

/// The device and gate of the volume mounted at `/vol`.
fn vfs_vol() -> (Dev, &'static TestEnv) {
    let r = rows_run();
    (r.dev.clone(), r.env)
}

/// Create (or replace) `path` through the VFS with `data`.
fn vput(path: &str, data: &[u8]) {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path.as_bytes(), O_WRONLY | O_CREAT | vfs::O_TRUNC);
    assert!(fd >= 0, "open {path}");
    if !data.is_empty() {
        assert_eq!(vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), data.len() as i32);
    }
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
}

fn read_fd(t: &mut vfs::ScratchFds, fd: i32, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    let r = vfs::vfs_read(t, fd, b.as_mut_ptr(), n);
    assert!(r >= 0);
    b.truncate(r as usize);
    b
}

#[test]
fn files_made_through_the_vfs_are_durable_only_after_an_fsync() {
    let _g = super::serial();
    let (dev, _) = vfs_vol();
    as_task(1);
    vfs::vfs_mkdir(b"/vol/d1").unwrap();
    let mut t = vfs::ScratchFds::new();
    let data = pattern(3, 150_000);
    let fd = vfs::vfs_open(&mut t, b"/vol/d1/big", O_WRONLY | O_CREAT);
    assert!(fd >= 0);
    assert_eq!(vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), data.len() as i32);
    // Read back through a second descriptor: the streaming open reads the volume.
    let rd = vfs::vfs_open(&mut t, b"/vol/d1/big", O_RDONLY);
    assert_eq!(read_fd(&mut t, rd, data.len() + 10), data);
    vfs::vfs_close(&mut t, rd);
    // Nothing reached a superblock yet: a remount of the device as it is finds
    // neither the file nor the directory.
    let before = dump_image(dev.image());
    assert!(!before.contains_key("/d1/big") && !before.contains_key("/d1"), "{:?}", before.keys());
    // fsync commits.
    assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    let after = dump_image(dev.image());
    assert_eq!(after.get("/d1/big"), Some(&Some(data.clone())));
    // Unlink and rmdir go through the same backend; a non-empty directory stays.
    assert_eq!(vfs::vfs_rmdir(b"/vol/d1"), Err(FsErr::NotEmpty));
    vfs::vfs_unlink(b"/vol/d1/big").unwrap();
    vfs::vfs_rmdir(b"/vol/d1").unwrap();
    assert!(vfs::vfs_stat(b"/vol/d1").is_none());
}

#[test]
fn a_readdir_walk_through_the_vfs_lists_names_sizes_and_kinds() {
    let _g = super::serial();
    let _ = vfs_vol();
    as_task(1);
    vfs::vfs_mkdir(b"/vol/walk").unwrap();
    vfs::vfs_mkdir(b"/vol/walk/sub").unwrap();
    vput("/vol/walk/a", b"12345");
    vput("/vol/walk/b", b"");
    let mut e = vfs::DirEnt::new();
    let mut cookie = 0;
    let mut got = BTreeMap::new();
    while let Some(n) = vfs::vfs_readdir(b"/vol/walk", cookie, &mut e).unwrap() {
        cookie = n;
        got.insert(String::from_utf8(e.name().to_vec()).unwrap(), (e.is_dir, e.size));
    }
    assert_eq!(got.len(), 3);
    assert_eq!(got["a"], (false, 5));
    assert_eq!(got["b"], (false, 0));
    assert_eq!(got["sub"], (true, 0));
    // A path the backend cannot name is not found, never a different file.
    let fs = fresh_fs(TestEnv::leak(), false).0;
    assert!(fs.key_for(b"walk/../walk/a").is_none());
    assert!(fs.key_for(b"/walk/a").is_none());
    assert!(fs.key_for(b"walk//a").is_none());
    assert!(fs.key_for(&[b'x'; 65]).is_none());
    assert!(fs.key_for(&[b'x'; 64]).is_some());
}

// ── read-only rows ────────────────────────────────────────────────

#[test]
fn a_read_only_row_refuses_every_change_and_writes_nothing() {
    let env = TestEnv::leak();
    let (fs, dev) = fresh_fs(env, false);
    put(fs, "keep", b"data");
    fs.sync().unwrap();
    let image = dev.image();
    // Mount the same image read-only.
    let dev2 = Dev::from_image(image.clone());
    let ro = Box::leak(Box::new(AzvolFs::new(Volume::mount(dev2.clone()).unwrap(), true, env)));
    dev2.clear_log();
    let k = key(ro, "keep");
    assert_eq!(get(ro, "keep").as_deref(), Some(&b"data"[..]), "reads work");
    assert_eq!(ro.write_at(&k, 0, b"X"), Err(()));
    assert_eq!(ro.truncate(&k, 0), Err(FsErr::ReadOnly));
    assert_eq!(ro.create(&key(ro, "new")), Err(FsErr::ReadOnly));
    assert_eq!(ro.mkdir(b"d"), Err(FsErr::ReadOnly));
    assert_eq!(ro.rmdir(b"d"), Err(FsErr::ReadOnly));
    assert_eq!(ro.rename(b"keep", b"moved"), Err(FsErr::ReadOnly));
    assert_eq!(ro.unlink(&k), Err(()));
    assert_eq!(ro.write_all(&k, b"zz"), Err(()));
    // fsync/sync of a volume that cannot change are no-ops, not errors.
    assert_eq!(ro.fsync(&k), Ok(()));
    assert!(dev2.log().is_empty(), "a read-only mount wrote to the device: {} ops", dev2.log().len());
    assert_eq!(dev2.image(), image);
}

// ── the transaction fence ─────────────────────────────────────────

/// **Canary.** Take the `fence` out of `commit` (or out of `change`): task 2's
/// `fsync` makes task 1's half-written transaction durable, the image no longer
/// equals `durable`, and task 2's change lands in task 1's transaction.
#[test]
fn the_open_transaction_belongs_to_the_task_that_wrote_it_and_only_its_commit_counts() {
    let env = TestEnv::leak();
    let (fs, dev) = fresh_fs(env, false);
    as_task(1);
    put(fs, "base", b"old");
    fs.sync().unwrap();
    let durable = dump_image(dev.image());

    put(fs, "g1", b"one");
    put(fs, "g2", b"two");
    let k = key(fs, "base");
    fs.write_at(&k, 0, b"NEW").unwrap();
    // Another task with every right on the tree: changes and commits answer
    // Busy, reads see the open transaction.
    as_task(2);
    assert_eq!(fs.create(&key(fs, "intruder")), Err(FsErr::Busy));
    assert_eq!(fs.write_at(&k, 0, b"?"), Err(()));
    assert_eq!(fs.write_all(&k, b"?"), Err(()));
    assert_eq!(fs.unlink(&k), Err(()));
    assert_eq!(fs.truncate(&k, 0), Err(FsErr::Busy));
    assert_eq!(fs.mkdir(b"dd"), Err(FsErr::Busy));
    assert_eq!(fs.rename(b"g1", b"g3"), Err(FsErr::Busy));
    assert_eq!(fs.sync(), Err(()), "a commit by another task would make half of the transaction durable");
    assert_eq!(fs.fsync(&k), Err(FsErr::Busy));
    assert_eq!(get(fs, "g1").as_deref(), Some(&b"one"[..]));
    assert_eq!(get(fs, "intruder"), None);
    assert_eq!(dump_image(dev.image()), durable, "nothing of the transaction is durable before its owner commits");
    // The owner's fsync makes it all durable, whole, and lifts the fence.
    as_task(1);
    fs.fsync(&k).unwrap();
    let t = dump_image(dev.image());
    assert_eq!(t.get("/g1"), Some(&Some(b"one".to_vec())));
    assert_eq!(t.get("/g2"), Some(&Some(b"two".to_vec())));
    assert_eq!(t.get("/base"), Some(&Some(b"NEW".to_vec())));
    as_task(2);
    put(fs, "after", b"x");
    // Task 1 now meets task 2's transaction.
    as_task(1);
    assert_eq!(fs.fsync(&k), Err(FsErr::Busy));
    assert_eq!(fs.mkdir(b"dd"), Err(FsErr::Busy));
    as_task(2);
    fs.sync().unwrap();
    // With nothing pending, a commit by anyone is a no-op that succeeds.
    as_task(3);
    fs.fsync(&k).unwrap();
    fs.sync().unwrap();
    assert_eq!(dump_image(dev.image()).get("/after"), Some(&Some(b"x".to_vec())));
}

/// **Canary.** Make `fence` answer `Busy` for a dead owner too: the restarted
/// writer (a new tid) can neither change nor commit, for good.
#[test]
fn an_owner_that_exited_leaves_a_transaction_the_next_task_discards() {
    let env = TestEnv::leak();
    let (fs, dev) = fresh_fs(env, false);
    as_task(1);
    put(fs, "base", b"old");
    fs.sync().unwrap();
    // Task 3 writes and exits without committing.
    as_task(3);
    put(fs, "half", b"written");
    as_task(4);
    assert_eq!(fs.create(&key(fs, "x")), Err(FsErr::Busy), "while its owner runs");
    env.kill(3);
    // Its work is gone, as at a power cut; the volume is as the last commit left it.
    put(fs, "mine", b"m");
    assert_eq!(get(fs, "half"), None);
    fs.sync().unwrap();
    let t = dump_image(dev.image());
    assert_eq!(t.get("/mine"), Some(&Some(b"m".to_vec())));
    assert_eq!(t.get("/half"), None, "the dead owner's write became durable");
    assert_eq!(t.get("/base"), Some(&Some(b"old".to_vec())));
    // A commit by a bystander after an owner died discards too, and succeeds.
    put(fs, "half2", b"w");
    env.kill(4);
    as_task(5);
    fs.sync().unwrap();
    assert_eq!(get(fs, "half2"), None);
    assert_eq!(dump_image(dev.image()).get("/half2"), None);
}

/// The installer's shape: a package, then its journal record, committed by the
/// record's `fsync`. Another task with write rights tries every change and
/// commit in the middle. A cut at any device write leaves the package and the
/// record together or neither.
///
/// **Canary.** Remove the fence from `commit`: the intruder's `fsync` makes the
/// package durable without its record, the image after the intruder's
/// attempts differs from `before`, and the sweep finds a state that is
/// neither end.
#[test]
fn a_package_and_its_journal_record_stay_atomic_whatever_other_tasks_commit() {
    let env = TestEnv::leak();
    let (fs, dev) = fresh_fs(env, false);
    as_task(1);
    put(fs, "journal", b"record 0\n");
    fs.sync().unwrap();
    let base_img = dev.image();
    let before = dump_image(base_img.clone());
    dev.clear_log();

    // The installer (task 1): the package in pieces, with the intruder (task 2) between them.
    let pkg = pattern(7, 40_000);
    fs.create(&key(fs, "stage")).unwrap();
    let k = key(fs, "stage");
    for (i, piece) in pkg.chunks(10_000).enumerate() {
        as_task(1);
        fs.write_at(&k, (i * 10_000) as u64, piece).unwrap();
        as_task(2);
        assert_eq!(fs.fsync(&key(fs, "journal")), Err(FsErr::Busy));
        assert_eq!(fs.sync(), Err(()));
        assert_eq!(fs.write_at(&key(fs, "journal"), 0, b"forged"), Err(()));
        assert_eq!(fs.rename(b"stage", b"stolen"), Err(FsErr::Busy));
        assert_eq!(dump_image(dev.image()), before, "the intruder made part of the install durable");
    }
    as_task(1);
    let j = key(fs, "journal");
    let end = fs.read_at(&j, 0, &mut [0u8; 64]) as u64;
    fs.write_at(&j, end, b"record 1\n").unwrap();
    fs.fsync(&j).unwrap();
    let after = dump_image(dev.image());
    assert_ne!(before, after);
    assert_eq!(after.get("/stage"), Some(&Some(pkg.clone())));

    let log = dev.log();
    let (mut old, mut new) = (0, 0);
    for cut in 0..=log.len() {
        for fate in [Fate::Lost, Fate::Whole, Fate::Torn(3)] {
            let t = dump_image(crash_image(&base_img, &log, cut, &|_| fate));
            if t == before {
                old += 1;
            } else if t == after {
                new += 1;
            } else {
                panic!("cut {cut}: the package and its record are not together: {:?}", t.keys().collect::<Vec<_>>());
            }
        }
    }
    assert!(old > 0 && new > 0, "the sweep never saw both ends: old {old} new {new}");
}

// ── rename ────────────────────────────────────────────────────────

#[test]
fn rename_moves_files_and_trees_replaces_a_file_and_refuses_the_impossible() {
    let env = TestEnv::leak();
    let (fs, _) = fresh_fs(env, false);
    as_task(1);
    fs.mkdir(b"src").unwrap();
    fs.mkdir(b"src/inner").unwrap();
    put(fs, "src/f", &pattern(4, 70_000));
    put(fs, "src/inner/g", b"deep");
    put(fs, "victim", b"to be replaced");
    put(fs, "other", b"o");
    fs.rename(b"other", b"victim").unwrap();
    assert_eq!(get(fs, "victim").as_deref(), Some(&b"o"[..]));
    assert_eq!(get(fs, "other"), None);
    fs.rename(b"src", b"dst").unwrap();
    let t = dump_fs(fs);
    assert!(!t.keys().any(|k| k.starts_with("/src")));
    assert_eq!(t["/dst/f"], Some(pattern(4, 70_000)));
    assert_eq!(t["/dst/inner/g"], Some(b"deep".to_vec()));
    // A directory cannot go beneath itself; a file cannot replace a directory
    // nor a directory a file; a missing source is not found.
    assert_eq!(fs.rename(b"dst", b"dst/inner/x"), Err(FsErr::Invalid));
    assert_eq!(fs.rename(b"victim", b"dst"), Err(FsErr::IsDir));
    assert_eq!(fs.rename(b"dst", b"victim"), Err(FsErr::NotDir));
    assert_eq!(fs.rename(b"nope", b"x"), Err(FsErr::NotFound));
    fs.mkdir(b"full").unwrap();
    put(fs, "full/z", b"z");
    assert_eq!(fs.rename(b"dst", b"full"), Err(FsErr::NotEmpty));
    // Nothing was lost by the refusals.
    assert_eq!(get(fs, "full/z").as_deref(), Some(&b"z"[..]));
    assert_eq!(get(fs, "dst/f"), Some(pattern(4, 70_000)));
}

/// **Canary.** Make `rename` skip `begin_group` (copy and remove as plain
/// operations): the cut sweep finds a state with both names or neither once a
/// commit lands in the middle — here it cannot, since nothing commits in the
/// middle, so the sweep instead pins what the group buys: the old name or the
/// new, never both, never neither, at every cut.
#[test]
fn a_cut_anywhere_in_a_rename_leaves_the_old_name_or_the_new_never_both() {
    let env = TestEnv::leak();
    let (fs, dev) = fresh_fs(env, false);
    as_task(1);
    fs.mkdir(b"d").unwrap();
    put(fs, "d/old", &pattern(5, 50_000));
    fs.sync().unwrap();
    let base_img = dev.image();
    dev.clear_log();
    fs.rename(b"d/old", b"d/new").unwrap();
    let log = dev.log();
    let mut seen = [0, 0];
    for cut in 0..=log.len() {
        for fate in [Fate::Lost, Fate::Whole, Fate::Torn(5)] {
            let t = dump_image(crash_image(&base_img, &log, cut, &|_| fate));
            let (o, n) = (t.contains_key("/d/old"), t.contains_key("/d/new"));
            assert!(o != n, "cut {cut}: old {o} new {n}");
            let name = if o { "/d/old" } else { "/d/new" };
            assert_eq!(t[name], Some(pattern(5, 50_000)));
            seen[n as usize] += 1;
        }
    }
    assert!(seen[0] > 0 && seen[1] > 0, "{seen:?}");
}

/// **Canary.** Drop the `abort_group` in `rename`'s error arm: the half-made
/// copy stays in the open transaction and the next `fsync` makes it durable.
#[test]
fn a_rename_that_runs_out_of_space_leaves_no_half_made_copy() {
    let env = TestEnv::leak();
    let (fs, dev) = fresh_fs(env, false);
    as_task(1);
    // A file more than half the volume: its copy cannot fit.
    put(fs, "big", &pattern(30, 5 * 1024 * 1024));
    put(fs, "small", b"s");
    fs.sync().unwrap();
    let before = dump_fs(fs);
    assert_eq!(fs.rename(b"big", b"big2"), Err(FsErr::NoSpace));
    assert_eq!(dump_fs(fs), before, "the failed rename left something in the live tree");
    fs.sync().unwrap();
    assert_eq!(dump_image(dev.image()), before, "and in the durable one");
    // The volume is still usable.
    assert_eq!(get(fs, "small").as_deref(), Some(&b"s"[..]));
    fs.rename(b"small", b"small2").unwrap();
}

#[test]
fn replace_file_over_the_volume_is_atomic_and_leaves_no_temp() {
    let _g = super::serial();
    let (dev, _) = vfs_vol();
    as_task(1);
    vfs::vfs_mkdir(b"/vol/cfg").unwrap();
    let old = pattern(40, 3000);
    let new = pattern(41, 9000);
    vfs::vfs_replace_file(b"/vol/cfg/topo", &old).unwrap();
    let t = dump_image(dev.image());
    assert_eq!(t.get("/cfg/topo"), Some(&Some(old.clone())));
    // Cut the second replace at every device op: the old file whole or the new.
    let base_img = dev.image();
    dev.clear_log();
    vfs::vfs_replace_file(b"/vol/cfg/topo", &new).unwrap();
    let log = dev.log();
    let (mut o, mut n) = (0, 0);
    for cut in 0..=log.len() {
        let t = dump_image(crash_image(&base_img, &log, cut, &|_| Fate::Torn(2)));
        match t.get("/cfg/topo") {
            Some(Some(b)) if *b == old => o += 1,
            Some(Some(b)) if *b == new => n += 1,
            other => panic!("cut {cut}: neither version: {:?}", other.map(|x| x.as_ref().map(|b| b.len()))),
        }
    }
    assert!(o > 0 && n > 0, "o {o} n {n}");
    let after = dump_image(dev.image());
    assert_eq!(after.keys().filter(|k| k.contains("AZREPL")).count(), 0, "the temp name was left behind");
}

#[test]
fn statfs_counts_what_the_files_take() {
    let env = TestEnv::leak();
    let (fs, _) = fresh_fs(env, false);
    as_task(1);
    let s0 = fs.statfs().unwrap();
    put(fs, "f", &pattern(50, 100 * 1024));
    let s1 = fs.statfs().unwrap();
    assert_eq!(s0.fs_type, vfs::FS_TYPE_AZVOL);
    assert_eq!(s0.blocks, s1.blocks);
    assert!(s0.blocks_free - s1.blocks_free >= 25, "{} -> {}", s0.blocks_free, s1.blocks_free);
}

// ── rows with a verity root ───────────────────────────────────────
//
// The canary of this section: `Watch`/`VerityDev::read` not comparing a block
// with its hash (every flip test goes green-to-red with it), and `open_verity`
// not reading the failure count back (`one_flipped_superblock_copy_...` turns
// red: the engine mounts from the other copy).

const VN: u64 = 1024;

struct Fixture {
    img: Vec<u8>,
    root: Hash,
    files: Vec<(&'static str, Vec<u8>)>,
}

/// A 1024-block volume holding a few files, and the hash tree after it.
fn fixture() -> Fixture {
    let shape = verity::Shape::new(VN).unwrap();
    let dev = Dev::blank(VN + shape.blocks_after());
    let o = FormatOptions { block_count: Some(VN), label: b"sysimage", uuid: [9; 16], time_ns: 1_000 };
    let mut v = Volume::format(dev.clone(), &o).expect("format");
    let files = vec![
        ("small", pattern(1, 100)),
        ("big", pattern(2, 400 * BLOCK_SIZE)),
        ("d/inner", pattern(3, 5000)),
        ("empty", Vec::new()),
    ];
    let d = v.create(v.root(), b"d", Kind::Dir, 0o755).unwrap();
    for (p, data) in &files {
        let (dir, name) = p.split_once('/').map_or((v.root(), *p), |(_, n)| (d, n));
        let ino = v.create(dir, name.as_bytes(), Kind::File, 0o644).unwrap();
        if !data.is_empty() {
            assert_eq!(v.write(ino, 0, data).unwrap(), data.len());
        }
    }
    v.commit().unwrap();
    drop(v);
    let mut img = dev.image();
    let root = verity::build::build_in(&mut img, VN);
    Fixture { img, root, files }
}

impl Fixture {
    fn data(&self, p: &str) -> &[u8] {
        &self.files.iter().find(|(n, _)| *n == p).unwrap().1
    }
    /// The volume block that holds block `i` of file `p` (found by content).
    fn block_of(&self, p: &str, i: usize) -> u64 {
        let want = &self.data(p)[i * BLOCK_SIZE..][..64];
        (0..VN).find(|&b| &self.img[b as usize * BLOCK_SIZE..][..64] == want).expect("block present")
    }
}

/// What `p` reads as through the filesystem: `None` if it cannot be looked up
/// or its read comes up short.
fn read_whole<D: BlockDev + Send>(fs: &AzvolFs<D>, p: &str) -> Option<Vec<u8>> {
    let k = fs.key_for(p.as_bytes())?;
    let st = fs.stat(&k)?;
    let mut b = vec![0u8; st.size as usize];
    (fs.read_at(&k, 0, &mut b) == b.len()).then_some(b)
}

#[test]
fn a_volume_opens_through_its_tree_and_reads_what_was_put_in_and_writes_nothing() {
    let fx = fixture();
    let dev = Dev::from_image(fx.img.clone());
    let env = TestEnv::leak();
    let fs = mount::open_verity(dev.clone(), &fx.root, env).ok().expect("opens");
    assert!(fs.read_only(), "a verity volume is served read-only");
    for (p, data) in &fx.files {
        assert_eq!(read_whole(&fs, p).as_deref(), Some(&data[..]), "{p}");
    }
    assert_eq!(fs.statfs().unwrap().blocks, VN, "the engine sees the volume, not the tree");
    let k = key(&fs, "small");
    assert_eq!(fs.write_at(&k, 0, b"X"), Err(()));
    assert_eq!(fs.mkdir(b"x"), Err(FsErr::ReadOnly));
    assert_eq!(fs.fsync(&k), Ok(()));
    assert_eq!(fs.sync(), Ok(()));
    assert!(dev.log().is_empty(), "a verity mount wrote to the device: {} ops", dev.log().len());
    assert!(env.records().is_empty());
}

#[test]
fn a_wrong_root_or_a_changed_header_is_refused_and_recorded_before_a_block_is_served() {
    let fx = fixture();
    let env = TestEnv::leak();
    let mut other = fx.root;
    other[31] ^= 1;
    let r = mount::open_verity(Dev::from_image(fx.img.clone()), &other, env).err();
    assert_eq!(r, Some(Why::Verity(OpenError::RootMismatch)));
    assert_eq!(env.records(), vec![Tamper { block: VN, what: Fail::Header, count: 1 }]);
    env.clear_records();
    let dev = Dev::from_image(fx.img.clone());
    dev.flip(VN, 40);
    let r = mount::open_verity(dev, &fx.root, env).err();
    assert_eq!(r, Some(Why::Verity(OpenError::RootMismatch)));
    assert_eq!(env.records().len(), 1);
}

#[test]
fn one_flipped_superblock_copy_refuses_the_mount_although_the_other_would_do() {
    let fx = fixture();
    let dev = Dev::from_image(fx.img.clone());
    dev.flip(SB_SLOTS[0], 100);
    // The engine alone shrugs it off: the second copy is the same generation.
    assert!(Volume::mount(dev.clone()).is_ok(), "the premise: a plain mount takes the other copy");
    let env = TestEnv::leak();
    let r = mount::open_verity(dev, &fx.root, env).err();
    assert_eq!(r, Some(Why::Tampered));
    let rec = env.records();
    assert!(!rec.is_empty() && rec.iter().all(|t| t.block == 0 && t.what == Fail::Data), "{rec:?}");
}

#[test]
fn a_flipped_data_block_fails_the_reads_that_include_it_and_only_those() {
    let fx = fixture();
    let big = fx.data("big").to_vec();
    let at = fx.block_of("big", 200);
    let dev = Dev::from_image(fx.img.clone());
    dev.flip(at, 3);
    let bad_head = dev.image()[at as usize * BLOCK_SIZE..][..64].to_vec();
    let env = TestEnv::leak();
    let fs = mount::open_verity(dev.clone(), &fx.root, env).ok().expect("the mount reads no file data");
    let k = key(&fs, "big");
    // the blocks either side of it read
    let mut head = vec![0xAAu8; 200 * BLOCK_SIZE];
    assert_eq!(fs.read_at(&k, 0, &mut head), head.len());
    assert!(head == big[..200 * BLOCK_SIZE]);
    let mut tail = vec![0xAAu8; 199 * BLOCK_SIZE];
    assert_eq!(fs.read_at(&k, 201 * BLOCK_SIZE as u64, &mut tail), tail.len());
    assert!(tail == big[201 * BLOCK_SIZE..]);
    assert!(env.records().is_empty());
    // a read that includes it is refused, whole, and none of its bytes come back
    let mut all = vec![0xAAu8; big.len()];
    assert_eq!(fs.read_at(&k, 0, &mut all), 0);
    assert!(!all.windows(64).any(|w| w == &bad_head[..]), "the changed block was returned");
    assert!(!all.windows(64).any(|w| w == &big[200 * BLOCK_SIZE..][..64]), "the original block came from nowhere");
    assert_eq!(env.records(), vec![Tamper { block: at, what: Fail::Data, count: 1 }]);
    assert_eq!(fs.read_at(&k, 0, &mut all), 0, "a bad block is not trusted the second time");
    assert_eq!(env.records()[1].count, 2);
    // the rest of the volume is as good as before
    assert_eq!(read_whole(&fs, "small").as_deref(), Some(fx.data("small")));
    assert_eq!(read_whole(&fs, "d/inner").as_deref(), Some(fx.data("d/inner")));
}

#[test]
fn a_flipped_hash_block_fails_what_it_covers_and_says_which_level() {
    let fx = fixture();
    let s = verity::Shape::new(VN).unwrap();
    assert_eq!(s.levels, 2);
    // Two blocks in the middle of "big", under a hash block that covers nothing else.
    let mid = fx.block_of("big", 200);
    assert!(mid / 128 >= 2 && (mid + 1) / 128 == mid / 128, "the fixture moved: block {mid}");
    let leaf = s.start[0] + mid / 128;
    let dev = Dev::from_image(fx.img.clone());
    dev.flip(leaf, 9);
    let env = TestEnv::leak();
    let fs = mount::open_verity(dev.clone(), &fx.root, env).ok().expect("the mount reads nothing under that hash block");
    assert!(env.records().is_empty(), "precondition: the mount did not touch it");
    let k = key(&fs, "big");
    let mut tail = vec![0u8; 2 * BLOCK_SIZE];
    assert_eq!(fs.read_at(&k, 200 * BLOCK_SIZE as u64, &mut tail), 0);
    assert_eq!(env.records(), vec![Tamper { block: leaf, what: Fail::Hash(0), count: 1 }]);
    let mut head = vec![0u8; BLOCK_SIZE];
    assert_eq!(fs.read_at(&k, 0, &mut head), head.len(), "blocks under other hash blocks still read");
    // the top block is read by the first block the mount reads
    dev.flip(leaf, 9);
    dev.flip(s.start[1], 9);
    let env = TestEnv::leak();
    let r = mount::open_verity(dev, &fx.root, env).err();
    assert_eq!(r, Some(Why::Tampered));
    assert_eq!(env.records()[0].what, Fail::Hash(1));
}

#[test]
fn every_block_the_system_reads_is_covered_and_a_flip_of_it_is_never_served() {
    let fx = fixture();
    let total = VN + verity::Shape::new(VN).unwrap().blocks_after();
    let dev = Dev::from_image(fx.img.clone());
    let env = TestEnv::leak();
    // The clean pass: mount, then read every file; note what the device was asked for.
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    {
        let fs = mount::open_verity(Spy { inner: dev.clone(), seen: seen.clone() }, &fx.root, env).ok().expect("clean");
        for (p, data) in &fx.files {
            assert_eq!(read_whole(&fs, p).as_deref(), Some(&data[..]), "{p}");
        }
    }
    let touched = seen.lock().unwrap().clone();
    assert!(env.records().is_empty());
    assert!(touched.len() > 400 && (touched.len() as u64) < total, "touched {} of {total}", touched.len());
    let (mut refused_at_mount, mut refused_at_read, mut never_read) = (0, 0, 0);
    for b in 0..total {
        dev.flip(b, 17);
        env.clear_records();
        let mut failed = false;
        match mount::open_verity(dev.clone(), &fx.root, env) {
            Err(w) => {
                assert!(matches!(w, Why::Verity(_) | Why::Tampered), "block {b}: {w:?}");
                failed = true;
                refused_at_mount += 1;
            }
            Ok(fs) => {
                for (p, data) in &fx.files {
                    match read_whole(&fs, p) {
                        Some(got) => assert!(got == *data, "block {b}: {p} was served with other bytes"),
                        None => failed = true,
                    }
                }
                refused_at_read += failed as u32;
            }
        }
        dev.flip(b, 17);
        if touched.contains(&b) {
            assert!(failed, "block {b} is read by a clean pass and a flip of it went unnoticed");
            assert!(!env.records().is_empty(), "block {b}: refused, but nothing was recorded");
        } else {
            assert!(!failed && env.records().is_empty(), "block {b} is never read: its flip must change nothing");
            never_read += 1;
        }
    }
    // the three outcomes all happened
    assert!(refused_at_mount > 5 && refused_at_read > 100 && never_read > 100, "{refused_at_mount} {refused_at_read} {never_read}");
}

// ── the swap file (Kconfig MM_SWAP_BACKEND_FILE) ──────────────────

/// The sector runs under the first `len` bytes of `k`.
fn swap_runs(fs: &AzvolFs<Dev>, k: &vfs::InodeKey, len: u64) -> Result<Vec<vfs::SectorRun>, FsErr> {
    let mut out = [vfs::SectorRun::default(); 16];
    let n = fs.swap_runs(k, len, &mut out)?;
    Ok(out[..n].to_vec())
}

fn sectors_of(runs: &[vfs::SectorRun]) -> u64 {
    runs.iter().map(|r| r.sectors as u64).sum()
}

/// What `runs` hold on the device, in file order.
fn run_bytes(dev: &Dev, runs: &[vfs::SectorRun]) -> Vec<u8> {
    let img = dev.image();
    runs.iter().flat_map(|r| img[r.lba as usize * SECTOR..(r.lba as usize + r.sectors as usize) * SECTOR].to_vec()).collect()
}

/// Write `data` over `runs` as the swap layer does: straight to the sectors.
fn write_runs(dev: &Dev, runs: &[vfs::SectorRun], data: &[u8]) {
    let mut g = dev.0.lock().unwrap();
    let mut at = 0;
    for r in runs {
        let n = r.sectors as usize * SECTOR;
        g.img[r.lba as usize * SECTOR..r.lba as usize * SECTOR + n].copy_from_slice(&data[at..at + n]);
        at += n;
    }
}

#[test]
fn azvol_swap_blocks_are_fixed_and_the_runs_name_them() {
    let env = TestEnv::leak();
    let (fs, dev) = fresh_fs(env, false);
    as_task(1);
    let k = key(fs, "swapf");
    fs.create(&k).unwrap();
    let len = 16 * BLOCK_SIZE as u64;
    fs.swap_resize(&k, len).unwrap();
    assert_eq!(fs.stat(&k).unwrap().size, len);
    assert_eq!(fs.swap_resize(&k, len + 100), Err(FsErr::Invalid), "whole blocks only: a cut inside one would move it");
    let runs = swap_runs(fs, &k, len).unwrap();
    assert_eq!(sectors_of(&runs), len / SECTOR as u64);
    assert!(runs.iter().all(|r| (r.lba + r.sectors as u64) * SECTOR as u64 <= dev.image().len() as u64));
    assert_eq!(swap_runs(fs, &k, 0).unwrap(), vec![]);
    assert_eq!(fs.swap_runs(&k, len + 1, &mut [vfs::SectorRun::default(); 4]), Err(FsErr::Invalid), "past the file");

    // What the swap layer would write, straight to the sectors; then the
    // volume works on: other files made, changed, removed, committed.
    let swap_data = pattern(77, len as usize);
    write_runs(&dev, &runs, &swap_data);
    put(fs, "other", &pattern(1, 200_000));
    fs.fsync(&k).unwrap();
    let k2 = key(fs, "other");
    assert_eq!(fs.write_at(&k2, 100, &pattern(2, 50_000)), Ok(50_000));
    fs.fsync(&k2).unwrap();
    fs.truncate(&k2, 10_000).unwrap();
    put(fs, "third", &pattern(3, 90_000));
    fs.fsync(&k2).unwrap();
    assert_eq!(swap_runs(fs, &k, len).unwrap(), runs, "copy on write never moved the file's blocks");
    assert_eq!(run_bytes(&dev, &runs), swap_data, "and nothing the volume wrote landed on them");

    // The same on a remount of what is durable.
    let mut v = Volume::mount(Dev::from_image(dev.image())).unwrap();
    let ino = v.lookup_path(b"swapf").unwrap();
    let mut blocks = [(0u64, 0u64); 8];
    let n = v.file_runs(ino, len, &mut blocks).unwrap();
    let from_disk: Vec<_> = blocks[..n].iter().map(|&(b, c)| (b * 8, c * 8)).collect();
    assert_eq!(from_disk, runs.iter().map(|r| (r.lba, r.sectors as u64)).collect::<Vec<_>>());

    // A grow keeps the head and adds zeroed blocks; the swap data is still there.
    let free0 = fs.statfs().unwrap().blocks_free;
    fs.swap_resize(&k, 2 * len).unwrap();
    assert_eq!(fs.statfs().unwrap().blocks_free, free0 - 16);
    let grown = swap_runs(fs, &k, 2 * len).unwrap();
    assert_eq!(sectors_of(&grown), 2 * len / SECTOR as u64);
    assert_eq!(swap_runs(fs, &k, len).unwrap(), runs, "the first half is the same blocks");
    assert_eq!(run_bytes(&dev, &grown)[..len as usize], swap_data[..], "and the same bytes");
    assert!(run_bytes(&dev, &grown)[len as usize..].iter().all(|&b| b == 0), "the new blocks are zeros");

    // A shrink gives the tail back.
    fs.swap_resize(&k, len / 2).unwrap();
    assert_eq!(fs.statfs().unwrap().blocks_free, free0 + 8);
    assert_eq!(sectors_of(&swap_runs(fs, &k, len / 2).unwrap()), len / 2 / SECTOR as u64);
    assert_eq!(run_bytes(&dev, &swap_runs(fs, &k, len / 2).unwrap()), swap_data[..len as usize / 2]);
    fs.swap_resize(&k, 0).unwrap();
    assert_eq!(swap_runs(fs, &k, 0).unwrap(), vec![]);
}

#[test]
fn azvol_swap_runs_refuse_a_hole_and_more_runs_than_the_caller_has_room_for() {
    let env = TestEnv::leak();
    let (fs, _) = fresh_fs(env, false);
    as_task(1);
    // A file with a hole is not a swap file.
    let h = key(fs, "holey");
    fs.create(&h).unwrap();
    assert_eq!(fs.write_at(&h, 3 * BLOCK_SIZE as u64, b"x"), Ok(1));
    fs.fsync(&h).unwrap();
    assert!(fs.swap_runs(&h, 4 * BLOCK_SIZE as u64, &mut [vfs::SectorRun::default(); 4]).is_err());
    // Two stretches of blocks with another file's between them: two runs.
    let (k, o) = (key(fs, "swapf"), key(fs, "gap"));
    fs.create(&k).unwrap();
    fs.swap_resize(&k, 4 * BLOCK_SIZE as u64).unwrap();
    fs.create(&o).unwrap();
    assert_eq!(fs.write_at(&o, 0, &pattern(5, 3 * BLOCK_SIZE)), Ok(3 * BLOCK_SIZE));
    fs.fsync(&o).unwrap();
    fs.swap_resize(&k, 8 * BLOCK_SIZE as u64).unwrap();
    let two = swap_runs(fs, &k, 8 * BLOCK_SIZE as u64).unwrap();
    assert_eq!(two.len(), 2, "{two:?}");
    assert_eq!(fs.swap_runs(&k, 8 * BLOCK_SIZE as u64, &mut [vfs::SectorRun::default(); 1]), Err(FsErr::NoSpace));
    assert_eq!(swap_runs(fs, &k, 4 * BLOCK_SIZE as u64).unwrap().len(), 1, "the head alone is one run");
}

#[test]
fn a_failed_azvol_resize_leaves_no_transaction_open() {
    let env = TestEnv::leak();
    let (fs, _) = fresh_fs(env, false);
    as_task(1);
    let k = key(fs, "swapf");
    fs.create(&k).unwrap();
    // More than the volume has: refused.
    assert_eq!(fs.swap_resize(&k, 1 << 30), Err(FsErr::NoSpace));
    // The task that asked is alive and never commits again, as the reclaim
    // task would not: a transaction it left open would stop every other writer.
    // Another task cuts the file back (the kernel's caller does that itself);
    // it is not told `Busy`.
    as_task(2);
    fs.swap_resize(&k, 4 * BLOCK_SIZE as u64).unwrap();
    put(fs, "after", b"still writable");
    assert_eq!(get(fs, "after").as_deref(), Some(&b"still writable"[..]));
    assert_eq!(sectors_of(&swap_runs(fs, &k, 4 * BLOCK_SIZE as u64).unwrap()), 32);
}

#[test]
fn the_pinned_swap_file_answers_busy_to_every_path_that_would_move_it() {
    let _g = super::serial();
    let (_dev, _) = vfs_vol();
    as_task(1);
    vfs::vfs_mkdir(b"/vol/swpd").unwrap();
    vput("/vol/swpd/OTHERF", b"a neighbour");
    // Before the pin the file is an ordinary one.
    assert_eq!(vfs::vfs_swapfile_resize(0), Err(FsErr::NotFound), "no swap file yet");
    vfs::vfs_swapfile_open(b"/vol/swpd/AZREPL.TMP").unwrap();
    assert_eq!(vfs::vfs_swapfile_open(b"/vol/swpd/ANOTHER"), Err(FsErr::Busy), "one swap file per boot");
    let len = 32 * BLOCK_SIZE as u64;
    vfs::vfs_swapfile_resize(len).unwrap();
    let mut runs = [vfs::SectorRun::default(); 8];
    let n = vfs::vfs_swapfile_runs(len, &mut runs).unwrap();
    assert_eq!(sectors_of(&runs[..n]), len / SECTOR as u64);

    let mut t = vfs::ScratchFds::new();
    assert_eq!(vfs::vfs_open(&mut t, b"/vol/swpd/AZREPL.TMP", O_RDONLY), -1, "no descriptor names it");
    assert_eq!(vfs::vfs_open(&mut t, b"/vol/swpd/AZREPL.TMP", O_WRONLY | O_CREAT | vfs::O_TRUNC), -1);
    assert_eq!(vfs::vfs_unlink(b"/vol/swpd/AZREPL.TMP"), Err(FsErr::Busy));
    assert_eq!(vfs::vfs_truncate(b"/vol/swpd/AZREPL.TMP", 0), Err(FsErr::Busy));
    // The swap file wears the name `vfs_replace_file` stages through: it is
    // not a target (Invalid), and any other file of its directory is not
    // replaced through it either (Busy), or the staging unlink, write and
    // rename would free or move the blocks the swap layer writes directly.
    assert_eq!(vfs::vfs_replace_file(b"/vol/swpd/AZREPL.TMP", b"x"), Err(FsErr::Invalid));
    assert_eq!(vfs::vfs_replace_file(b"/vol/swpd/OTHERF", b"x"), Err(FsErr::Busy), "nor through its name as the stage");
    let fd = vfs::vfs_open(&mut t, b"/vol/swpd/OTHERF", O_RDONLY);
    assert!(fd >= 0);
    assert_eq!(read_fd(&mut t, fd, 64), b"a neighbour", "the refused replace wrote nothing");
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    assert_eq!(vfs::vfs_rename(b"/vol/swpd/AZREPL.TMP", b"/vol/swpd/MOVED"), Err(FsErr::Busy), "it does not move");
    assert_eq!(vfs::vfs_rename(b"/vol/swpd/OTHERF", b"/vol/swpd/AZREPL.TMP"), Err(FsErr::Busy), "nothing replaces it");
    // azvol renames a directory by copying its tree: the blocks would be freed.
    assert_eq!(vfs::vfs_rename(b"/vol/swpd", b"/vol/swpe"), Err(FsErr::Busy), "nor does the directory above it");
    assert_eq!(vfs::vfs_rmdir(b"/vol/swpd"), Err(FsErr::Busy));

    // The neighbours are ordinary files still.
    vput("/vol/swpd/SIBLING", b"fine");
    vfs::vfs_rename(b"/vol/swpd/SIBLING", b"/vol/swpd/SIBLING2").unwrap();
    vfs::vfs_unlink(b"/vol/swpd/SIBLING2").unwrap();
    vfs::vfs_mkdir(b"/vol/swpo").unwrap();
    vput("/vol/swpo/OTHERF", b"elsewhere");
    vfs::vfs_replace_file(b"/vol/swpo/OTHERF", b"replaced").unwrap();
    let mut again = [vfs::SectorRun::default(); 8];
    assert_eq!(vfs::vfs_swapfile_runs(len, &mut again), Ok(n));
    assert_eq!(again[..n], runs[..n], "and the swap file did not move");
    // Shrinking and growing go through the pin's own call.
    vfs::vfs_swapfile_resize(len / 2).unwrap();
    assert_eq!(vfs::vfs_swapfile_runs(len, &mut again), Err(FsErr::Invalid), "past the file");
}

// ── the check after an unclean mount (fs-check-mount) ─────────────

/// A volume with two files whose root directory names the first file twice
/// (the second file's record carries the first's inode, the block's checksum
/// made to match): damage the mount itself does not see and `Volume::check`
/// does ("inode not named exactly once"). With `unclean`, the free-space map
/// fails its checksum too, so the mount rebuilds it and the check runs.
fn misnamed_image(unclean: bool) -> Vec<u8> {
    use azvol::layout::{self, Geometry};
    let (dev, _) = formatted(2048);
    let mut v = Volume::mount(dev.clone()).expect("mount");
    let root = v.root();
    let a = v.create(root, b"aaaa", Kind::File, 0o644).unwrap();
    v.write(a, 0, b"first").unwrap();
    let b = v.create(root, b"bbbb", Kind::File, 0o644).unwrap();
    v.write(b, 0, b"second").unwrap();
    v.commit().unwrap();
    drop(v);
    let mut img = dev.image();
    let g = Geometry::new(2048).unwrap();
    let hdr = azvol::dir::REC_HDR;
    let rec = (g.data_start as usize * BLOCK_SIZE..img.len() - 4)
        .find(|&p| &img[p..p + 4] == b"bbbb" && img[p - hdr..p - hdr + 8] == b.to_le_bytes())
        .expect("the record of bbbb")
        - hdr;
    img[rec..rec + 8].copy_from_slice(&a.to_le_bytes());
    let blk = (rec / BLOCK_SIZE) as u64;
    let c = azvol::crc32c::crc32c(&img[blk as usize * BLOCK_SIZE..][..BLOCK_SIZE]);
    let o = (g.csum_start + blk / layout::CSUMS_PER_BLOCK) as usize * BLOCK_SIZE + (blk % layout::CSUMS_PER_BLOCK) as usize * 4;
    layout::wr32(&mut img[o..], 0, c);
    if unclean {
        img[g.bitmap_start as usize * BLOCK_SIZE + 500] ^= 0xFF;
    }
    img
}

/// **An unclean mount is checked, and damage makes the volume read-only**
/// (Kconfig `FS_CHECK_FAILED`'s default) or refuses it: the outcome names the
/// first problem, the served volume refuses every change and still reads.
///
/// **Canaries.** `azvol-unclean-unchecked-canary` (the check never runs),
/// `azvol-check-never-fails-canary` (damage passes).
#[test]
fn an_unclean_mount_is_checked_and_damage_makes_the_volume_read_only_or_refused() {
    let env = TestEnv::leak();
    let img = misnamed_image(true);
    let fs = mount::open_plain(Dev::from_image(img.clone()), false, env, None, mount::OnDamage::ReadOnly)
        .ok()
        .expect("served read-only");
    assert!(fs.report().bitmap_rebuilt, "premise: the mount was unclean");
    let d = fs.damage().expect("the check found the misnamed inode");
    assert_eq!(d.first, "inode not named exactly once", "{d:?}");
    assert!(d.problems >= 2, "one inode named twice, one named by nothing: {d:?}");
    assert!(fs.read_only());
    assert_eq!(get(fs_ref(&fs), "aaaa").as_deref(), Some(&b"first"[..]), "the volume still reads");
    let k = key(&fs, "cccc");
    assert_eq!(fs.create(&k), Err(FsErr::ReadOnly), "and takes no change");
    let c = fs.check(false).expect("check by hand");
    assert!(c.problems >= 2 && c.read_only, "{c:?}");
    match mount::open_plain(Dev::from_image(img), false, env, None, mount::OnDamage::Refuse) {
        Err(Why::CheckFailed(d)) => assert_eq!(d.first, "inode not named exactly once"),
        other => panic!("refused, not {:?}", other.map(|f| f.report())),
    }
}

fn fs_ref<D: BlockDev + Send>(fs: &AzvolFs<D>) -> &AzvolFs<D> {
    fs
}

/// An unclean mount of a sound volume passes its check and is served
/// read-write; a volume the mount found clean is not checked at all (the
/// format has no clean flag: only what the mount had to work around asks for
/// the walk), so its damage waits for the toolbox `fsck`.
#[test]
fn a_sound_unclean_volume_is_served_and_a_clean_mount_is_not_checked() {
    let env = TestEnv::leak();
    let (dev, mut img) = formatted(2048);
    drop(dev);
    let g = azvol::layout::Geometry::new(2048).unwrap();
    img[g.bitmap_start as usize * BLOCK_SIZE + 500] ^= 0xFF;
    let fs = mount::open_plain(Dev::from_image(img), false, env, None, mount::OnDamage::Refuse).ok().expect("served");
    assert!(fs.report().bitmap_rebuilt && fs.damage().is_none() && !fs.read_only());
    let fs = mount::open_plain(Dev::from_image(misnamed_image(false)), false, env, None, mount::OnDamage::Refuse)
        .ok()
        .expect("a clean mount is not checked");
    assert!(!fs.report().bitmap_rebuilt && fs.damage().is_none() && !fs.read_only());
    let c = fs.check(false).expect("the check by hand finds it");
    assert!(c.problems >= 2 && !c.read_only, "{c:?}");
}

/// The check by hand waits for an open transaction: it would have to commit
/// it first, and the commit is the owner's.
#[test]
fn the_check_by_hand_is_busy_while_a_transaction_is_open() {
    let env = TestEnv::leak();
    let (fs, _dev) = fresh_fs(env, false);
    assert_eq!(fs.check(false).map(|c| c.problems), Ok(0));
    put(fs, "open", b"pending");
    assert_eq!(fs.check(false).err(), Some(FsErr::Busy));
    assert_eq!(fs.sync(), Ok(()));
    let c = fs.check(true).expect("after the commit");
    assert_eq!((c.problems, c.items), (0, 2), "{c:?}");
    assert!(c.scrubbed >= 1, "a scrub reads the data blocks: {c:?}");
}
