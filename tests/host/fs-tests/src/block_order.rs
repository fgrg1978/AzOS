// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Flush and FUA ordering, per request. The device here takes the one block
//! request and models a volatile write cache: a write without FUA is lost in a
//! power cut unless a flush (a flush request, or the PREFLUSH of a later
//! write) came after it; a FUA write is stable when it completes and orders
//! nothing before it. The disk is cut after every request, with any of the
//! not-yet-flushed writes kept (none, all, each alone, all but one).
//!
//! * the write-back cache's epoch rule (`bcache.rs`): a block of a later epoch
//!   never reaches the medium before every block of the earlier ones is
//!   stable;
//! * an azvol commit (data, barrier, superblock, barrier): every cut mounts
//!   clean and shows the old file or the new one, never a mix.
//!
//! Wired into the suite by `mod block_order;` in `src/lib.rs`.

#![cfg(test)]

#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/fs/src/azvol/mod.rs"]
mod azvol;

use super::bcache::{BlockCache, Mode};
use azos_drv_api::block::{BlockData, BlockDev, BlockError, BlockOp, BlockReq, Geometry, FLAG_FUA, FLAG_PREFLUSH, SECTOR};
use azvol::layout::Kind;
use azvol::{FormatOptions, Volume, BLOCK_SIZE};

#[derive(Clone)]
enum Rq {
    Write { sector: u64, data: Vec<u8>, fua: bool },
    Flush,
}

struct Disk {
    img: Vec<u8>,
    log: Vec<Rq>,
    /// What a flush answers instead of doing it (`Unsupported`: no volatile cache).
    flush_fault: Option<BlockError>,
}

impl Disk {
    fn new(sectors: usize) -> Disk {
        Disk { img: vec![0; sectors * SECTOR], log: Vec::new(), flush_fault: None }
    }
}

impl BlockDev for Disk {
    fn geometry(&self) -> Geometry {
        Geometry { sectors: (self.img.len() / SECTOR) as u64, fua: true }
    }

    fn submit(&mut self, req: BlockReq<'_>) -> Result<(), BlockError> {
        req.check(self.geometry().sectors)?;
        match (req.op, req.data) {
            (BlockOp::Read, BlockData::Read(buf)) => {
                let o = req.sector as usize * SECTOR;
                buf.copy_from_slice(&self.img[o..o + buf.len()]);
            }
            (BlockOp::Write, BlockData::Write(buf)) => {
                if req.flags & FLAG_PREFLUSH != 0 {
                    match self.flush_fault {
                        None => self.log.push(Rq::Flush),
                        // The documented contract of `FLAG_PREFLUSH`.
                        Some(BlockError::Unsupported) => {}
                        Some(_) => return Err(BlockError::PreFlush),
                    }
                }
                let o = req.sector as usize * SECTOR;
                self.img[o..o + buf.len()].copy_from_slice(buf);
                self.log.push(Rq::Write { sector: req.sector, data: buf.to_vec(), fua: req.flags & FLAG_FUA != 0 });
            }
            (BlockOp::Flush, _) => match self.flush_fault {
                None => self.log.push(Rq::Flush),
                Some(e) => return Err(e),
            },
            (BlockOp::Discard, _) => {}
            _ => return Err(BlockError::Invalid),
        }
        Ok(())
    }

    fn medium_start(&self) -> Option<u64> {
        Some(0)
    }
}

/// The disk a power cut before request `cut` leaves, with `keep(i)` saying
/// which of the writes not covered by a flush (the `i`-th request) landed.
fn cut_image(base: &[u8], log: &[Rq], cut: usize, keep: &dyn Fn(usize) -> bool) -> Vec<u8> {
    let mut img = base.to_vec();
    let mut volatile: Vec<usize> = Vec::new();
    let put = |img: &mut Vec<u8>, i: usize| {
        if let Rq::Write { sector, data, .. } = &log[i] {
            let o = *sector as usize * SECTOR;
            img[o..o + data.len()].copy_from_slice(data);
        }
    };
    for (i, rq) in log[..cut].iter().enumerate() {
        match rq {
            Rq::Flush => {
                for v in volatile.drain(..) {
                    put(&mut img, v);
                }
            }
            Rq::Write { fua: true, .. } => put(&mut img, i),
            Rq::Write { .. } => volatile.push(i),
        }
    }
    for v in volatile {
        if keep(v) {
            put(&mut img, v);
        }
    }
    img
}

/// Every cut, under the fates of the unflushed writes; `check` sees each disk.
fn sweep(base: &[u8], log: &[Rq], mut check: impl FnMut(usize, &str, &[u8])) {
    for cut in 0..=log.len() {
        let writes: Vec<usize> = (0..cut).filter(|&i| matches!(log[i], Rq::Write { .. })).collect();
        let mut fates: Vec<(String, Box<dyn Fn(usize) -> bool>)> =
            vec![("none".into(), Box::new(|_| false)), ("all".into(), Box::new(|_| true))];
        for &w in &writes {
            fates.push((format!("only {w}"), Box::new(move |i| i == w)));
            fates.push((format!("all but {w}"), Box::new(move |i| i != w)));
        }
        for (name, keep) in &fates {
            check(cut, name, &cut_image(base, log, cut, keep.as_ref()));
        }
    }
}

fn sector_of(img: &[u8], sector: usize) -> &[u8] {
    &img[sector * SECTOR..(sector + 1) * SECTOR]
}

/// **The epoch rule, per request.** Block `A` is written in epoch 1, `B` in
/// epoch 2 (after a barrier); the sync writes them back. In no cut may `B` be
/// on the medium while `A` is not: the write of `B` carries `FLAG_PREFLUSH`.
///
/// **Canary.** `write_line` in `bcache.rs` sends `flags = 0` always: the write
/// of `B` has no flush ahead of it, a cut keeps it and loses `A`, red.
#[test]
fn a_later_epoch_is_never_stable_before_an_earlier_one() {
    let mut dev = Disk::new(64);
    let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteBack);
    c.write(&mut dev, 2, &[0xA1; 512]).unwrap();
    c.barrier();
    c.write(&mut dev, 3, &[0xB2; 512]).unwrap();
    assert!(dev.log.is_empty(), "write-back: nothing reached the device yet");
    c.sync(&mut dev).unwrap();
    let wrote_b_after_flush = dev.log.windows(2).any(|w| {
        matches!((&w[0], &w[1]), (Rq::Flush, Rq::Write { sector: 3, .. }))
    });
    assert!(wrote_b_after_flush, "the write of B is preceded by a flush");
    let base = vec![0u8; 64 * SECTOR];
    let mut seen_b = 0;
    sweep(&base, &dev.log, |cut, fate, img| {
        let b = sector_of(img, 3) == [0xB2; 512];
        let a = sector_of(img, 2) == [0xA1; 512];
        seen_b += b as usize;
        assert!(!b || a, "cut {cut} fate {fate}: B is stable and A is not");
    });
    assert!(seen_b > 0, "some cut keeps B");
}

/// A write with FUA is stable when it completes and orders nothing before it;
/// PREFLUSH | FUA does both. The model the other rows rest on.
#[test]
fn fua_is_stable_alone_and_with_preflush_stable_after_everything() {
    let mut d = Disk::new(8);
    d.write(0, &[1; 512]).unwrap();
    d.write_flagged(1, &[2; 512], FLAG_FUA).unwrap();
    let base = vec![0u8; 8 * SECTOR];
    let (mut fua_without_first, mut broken) = (false, false);
    sweep(&base, &d.log, |_, _, img| {
        if sector_of(img, 1) == [2; 512] && sector_of(img, 0) != [1; 512] {
            fua_without_first = true;
        }
    });
    assert!(fua_without_first, "FUA alone is not a barrier: the first write can be lost behind it");
    let mut d = Disk::new(8);
    d.write(0, &[1; 512]).unwrap();
    d.write_flagged(1, &[2; 512], FLAG_FUA | FLAG_PREFLUSH).unwrap();
    sweep(&base, &d.log, |_, _, img| {
        if sector_of(img, 1) == [2; 512] && sector_of(img, 0) != [1; 512] {
            broken = true;
        }
    });
    assert!(!broken, "PREFLUSH | FUA: stable only after everything before it");
}

fn opts() -> FormatOptions<'static> {
    FormatOptions { block_count: None, label: b"order", uuid: [3; 16], time_ns: 1_000 }
}

fn bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect()
}

fn read_file(v: &mut Volume<Disk>, ino: u64) -> Vec<u8> {
    let size = v.stat(ino).unwrap().size as usize;
    let mut out = vec![0u8; size];
    let mut done = 0;
    while done < size {
        let n = v.read(ino, done as u64, &mut out[done..]).unwrap();
        assert!(n > 0);
        done += n;
    }
    out
}

/// **An azvol commit, per request.** A file is rewritten and committed (data,
/// barrier, superblock, barrier): every cut mounts, checks clean, and shows
/// the old content or the new, never a mix.
///
/// **Canary.** `Blocks::barrier` in `azvol/dev.rs` answers `Ok(())` without
/// sending the flush: the superblock can be stable while the data it names is
/// not, a cut keeps the one and loses the other, red.
#[test]
fn an_azvol_commit_is_old_or_new_at_every_cut_of_every_request() {
    let (old, new) = (bytes(1, 3 * BLOCK_SIZE + 100), bytes(9, 3 * BLOCK_SIZE + 100));
    let mut v = Volume::format(Disk::new(256 * (BLOCK_SIZE / SECTOR)), &opts()).unwrap();
    let f = v.create(1, b"f", Kind::File, 0o644).unwrap();
    v.write(f, 0, &old).unwrap();
    v.commit().unwrap();
    let mut dev = v.into_device();
    let base = dev.img.clone();
    dev.log.clear();
    let mut v = Volume::mount(dev).unwrap();
    v.write(f, 0, &new).unwrap();
    v.commit().unwrap();
    let log = v.device().log.clone();
    assert!(log.iter().filter(|r| matches!(r, Rq::Flush)).count() >= 2, "data barrier and commit barrier");
    let (mut olds, mut news) = (0, 0);
    sweep(&base, &log, |cut, fate, img| {
        let mut dev = Disk::new(0);
        dev.img = img.to_vec();
        let mut m = Volume::mount(dev).unwrap_or_else(|e| panic!("cut {cut} fate {fate}: mount failed: {e:?}"));
        let got = read_file(&mut m, f);
        if got == old {
            olds += 1;
        } else if got == new {
            news += 1;
        } else {
            panic!("cut {cut} fate {fate}: neither the old file nor the new one");
        }
        let r = m.check(true).unwrap();
        assert!(r.is_clean(), "cut {cut} fate {fate}: {:?}", r.problems);
    });
    assert!(olds > 0 && news > 0, "the sweep sees both states");
}

/// **The `FLAG_PREFLUSH` contract on a device that cannot flush.** `Unsupported`
/// (no volatile cache): the write goes, a plain flush request is an error. Any
/// other failure: the write is not made and the cache gets `PreFlush`.
///
/// **Canary.** The device fails the preflush write on `Unsupported`, or writes
/// despite an `Io` flush: one of the two halves goes red.
#[test]
fn a_preflush_write_on_a_device_that_cannot_flush_follows_the_contract() {
    let epochs = |dev: &mut Disk| {
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteBack);
        c.write(dev, 2, &[0xA1; 512]).unwrap();
        c.barrier();
        c.write(dev, 3, &[0xB2; 512]).unwrap();
        c.write_back_all(dev)
    };
    let mut no_cache = Disk::new(64);
    no_cache.flush_fault = Some(BlockError::Unsupported);
    assert_eq!(epochs(&mut no_cache), Ok(()));
    assert_eq!(no_cache.log.len(), 2, "both blocks were written, no flush was possible");
    assert_eq!(no_cache.flush(), Err(BlockError::Unsupported), "a flush request is not tolerated");

    let mut broken = Disk::new(64);
    broken.flush_fault = Some(BlockError::Io);
    assert_eq!(epochs(&mut broken), Err(super::bcache::IoError::Flush(BlockError::PreFlush)));
    assert_eq!(broken.log.len(), 1, "block 3 was not written behind a failed flush");
}
