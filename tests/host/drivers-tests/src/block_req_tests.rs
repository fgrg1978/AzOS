// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The one block request (`azos_drv_api::block`): its shape check, and a
//! partition stacked on a device.

use azos_drv_api::block::{
    BlockData, BlockDev, BlockError, BlockOp, BlockReq, Geometry, Part, FLAG_FUA, FLAG_PREFLUSH, SECTOR,
};

/// What a device saw: op, absolute first sector, count, flags (a discard's runs
/// follow in `runs`).
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    op: BlockOp,
    sector: u64,
    count: u32,
    flags: u32,
    runs: Vec<(u64, u32)>,
}

struct Rec {
    sectors: u64,
    log: Vec<Seen>,
}

impl Rec {
    fn new(sectors: u64) -> Self {
        Rec { sectors, log: Vec::new() }
    }
}

impl BlockDev for Rec {
    fn geometry(&self) -> Geometry {
        Geometry { sectors: self.sectors, fua: true }
    }
    fn submit(&mut self, req: BlockReq<'_>) -> Result<(), BlockError> {
        req.check(self.sectors)?;
        let runs = match req.data {
            BlockData::Runs(r) => r.to_vec(),
            _ => Vec::new(),
        };
        self.log.push(Seen { op: req.op, sector: req.sector, count: req.count, flags: req.flags, runs });
        Ok(())
    }
    fn medium_start(&self) -> Option<u64> {
        Some(0)
    }
}

#[test]
fn a_request_is_checked_for_shape_and_range() {
    let mut buf = vec![0u8; 2 * SECTOR];
    assert_eq!(BlockReq::read(0, &mut buf).check(8), Ok(()));
    assert_eq!(BlockReq::read(7, &mut buf).check(8), Err(BlockError::Range));
    assert_eq!(BlockReq::read(u64::MAX, &mut buf).check(8), Err(BlockError::Range));
    assert_eq!(BlockReq::read(0, &mut []).check(8), Err(BlockError::Invalid));
    // flags ride on a write only
    assert_eq!(BlockReq::read(0, &mut buf).with_flags(FLAG_FUA).check(8), Err(BlockError::Invalid));
    assert_eq!(BlockReq::flush().with_flags(FLAG_PREFLUSH).check(8), Err(BlockError::Invalid));
    let data = vec![0u8; SECTOR];
    assert_eq!(BlockReq::write(1, &data).with_flags(FLAG_FUA | FLAG_PREFLUSH).check(8), Ok(()));
    assert_eq!(BlockReq::write(1, &data).with_flags(1 << 5).check(8), Err(BlockError::Invalid));
    // a buffer that is not `count` sectors
    let odd = BlockReq { count: 3, ..BlockReq::write(0, &data) };
    assert_eq!(odd.check(8), Err(BlockError::Invalid));
    assert_eq!(BlockReq::flush().check(0), Ok(()));
    assert_eq!(BlockReq::discard(&[(2, 2), (6, 2)]).check(8), Ok(()));
    assert_eq!(BlockReq::discard(&[(6, 3)]).check(8), Err(BlockError::Range));
    assert_eq!(BlockReq::discard(&[]).check(8), Err(BlockError::Invalid));
    assert_eq!(BlockReq::discard(&[(1, 0)]).check(8), Err(BlockError::Range));
}

#[test]
fn a_partition_shifts_every_request_and_refuses_what_leaves_it() {
    let mut p = Part::new(Rec::new(100), 10, 20).unwrap();
    assert_eq!(p.geometry().sectors, 20);
    assert_eq!(p.medium_start(), Some(10));
    let mut buf = vec![0u8; 2 * SECTOR];
    p.read(3, &mut buf).unwrap();
    p.write_flagged(18, &buf, FLAG_FUA | FLAG_PREFLUSH).unwrap();
    p.flush().unwrap();
    p.discard(&[(0, 4), (8, 2)]).unwrap();
    assert_eq!(p.write(19, &buf), Err(BlockError::Range));
    assert_eq!(p.discard(&[(19, 2)]), Err(BlockError::Range));
    let seen = &p.device().log;
    assert_eq!(seen.len(), 4, "a refused request never reaches the device");
    assert_eq!((seen[0].op, seen[0].sector, seen[0].count), (BlockOp::Read, 13, 2));
    assert_eq!((seen[1].sector, seen[1].flags), (28, FLAG_FUA | FLAG_PREFLUSH));
    assert_eq!((seen[2].op, seen[2].sector, seen[2].count), (BlockOp::Flush, 0, 0));
    assert_eq!((seen[3].sector, seen[3].runs.clone()), (10, vec![(0, 4), (8, 2)]));
}

#[test]
fn partitions_stack_and_the_window_must_fit() {
    assert!(Part::new(Rec::new(100), 90, 20).is_none());
    assert!(Part::new(Rec::new(100), u64::MAX, 2).is_none());
    let outer = Part::new(Rec::new(100), 10, 50).unwrap();
    let mut inner = Part::new(outer, 5, 10).unwrap();
    assert_eq!(inner.medium_start(), Some(15));
    let buf = vec![0u8; SECTOR];
    inner.write(2, &buf).unwrap();
    assert_eq!(inner.write(10, &buf), Err(BlockError::Range));
}

/// **The SD backends' ordering** (`blkdev::ordered_write`): the flush ahead
/// runs before the write; a device that cannot flush (`Unsupported`) still
/// takes the write; any other flush failure means no write; FUA is refused
/// (no native FUA) before anything runs.
///
/// **Canary.** Run the write before the flush, or let a failed flush through:
/// the order or the `PreFlush` assertion goes red.
#[test]
fn the_sd_ordered_write_flushes_first_and_refuses_what_it_cannot_do() {
    use crate::blkdev::ordered_write;
    use std::cell::RefCell;
    let run = |flags: u32, flush: Result<(), BlockError>| {
        let log = RefCell::new(Vec::new());
        let r = ordered_write(
            flags,
            || {
                log.borrow_mut().push("flush");
                flush
            },
            || {
                log.borrow_mut().push("write");
                Ok(())
            },
        );
        (r, log.into_inner())
    };
    assert_eq!(run(0, Ok(())), (Ok(()), vec!["write"]));
    assert_eq!(run(FLAG_PREFLUSH, Ok(())), (Ok(()), vec!["flush", "write"]));
    assert_eq!(run(FLAG_PREFLUSH, Err(BlockError::Unsupported)), (Ok(()), vec!["flush", "write"]));
    assert_eq!(run(FLAG_PREFLUSH, Err(BlockError::Io)), (Err(BlockError::PreFlush), vec!["flush"]));
    assert_eq!(run(FLAG_FUA, Ok(())), (Err(BlockError::Unsupported), vec![]));
    assert_eq!(run(FLAG_FUA | FLAG_PREFLUSH, Ok(())), (Err(BlockError::Unsupported), vec![]));
}
