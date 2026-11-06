// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Test devices that think in azvol blocks, as the one block device: a mock
// writes its block-unit methods ([`BlkUnit`]) and [`block_dev_of_units!`]
// makes it a [`BlockDev`](azos_drv_api::block::BlockDev) that decodes every
// request into them. Ordering flags are refused: azvol sends none, and a mock
// that models them implements `BlockDev` itself (`block_order.rs`).

pub trait BlkUnit {
    type Err;
    fn unit_count(&self) -> u64;
    fn unit_read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), Self::Err>;
    fn unit_write(&mut self, first: u64, buf: &[u8]) -> Result<(), Self::Err>;
    fn unit_flush(&mut self) -> Result<(), Self::Err>;
    fn unit_discard(&mut self, _runs: &[(u64, u32)]) -> Result<(), Self::Err> {
        Ok(())
    }
    fn unit_raw(&self, _block: u64) -> Option<u64> {
        None
    }
}

macro_rules! block_dev_of_units {
    ($t:ty) => {
        impl azos_drv_api::block::BlockDev for $t {
            fn geometry(&self) -> azos_drv_api::block::Geometry {
                azos_drv_api::block::Geometry {
                    sectors: crate::blk_units::BlkUnit::unit_count(self) * 8,
                    fua: false,
                }
            }
            fn submit(&mut self, req: azos_drv_api::block::BlockReq<'_>) -> Result<(), azos_drv_api::block::BlockError> {
                use azos_drv_api::block::{BlockData, BlockError, BlockOp};
                use crate::blk_units::BlkUnit;
                if req.flags != 0 {
                    return Err(BlockError::Unsupported);
                }
                if req.sector % 8 != 0 {
                    return Err(BlockError::Invalid);
                }
                let first = req.sector / 8;
                let e = |_| BlockError::Io;
                match (req.op, req.data) {
                    (BlockOp::Read, BlockData::Read(buf)) => self.unit_read(first, buf).map_err(e),
                    (BlockOp::Write, BlockData::Write(buf)) => self.unit_write(first, buf).map_err(e),
                    (BlockOp::Flush, _) => self.unit_flush().map_err(e),
                    (BlockOp::Discard, BlockData::Runs(runs)) => {
                        let blocks: Vec<(u64, u32)> = runs.iter().map(|&(s, n)| ((req.sector + s) / 8, n / 8)).collect();
                        self.unit_discard(&blocks).map_err(e)
                    }
                    _ => Err(BlockError::Invalid),
                }
            }
            fn medium_start(&self) -> Option<u64> {
                self.unit_raw(0)
            }
        }
    };
}
