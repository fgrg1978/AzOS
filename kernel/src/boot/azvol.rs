// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! L15: the native volumes the topology declares, mounted.
//!
//! Each `[volume.NAME]` row names a partition of the boot medium and a mount
//! point. [`install_azvol`] reads the partition's first blocks (the probe,
//! `azos_fs::probe::probe_volume`), mounts what is an azvol volume
//! (`azos_fs::azvol_mount::mount_rows`) and serves it through the VFS at the
//! row's mount point, where a task's `Cap<Dir>` on that path reaches it like
//! any tree. FAT32 stays what the boot, the latch and `CRASH.LOG` use; the two
//! do not share a partition (the row's partition is its own, and a FAT32
//! partition is refused by the probe).
//!
//! Everything that decides is in `azos_fs` and host-tested
//! (`tests/host/fs-tests/src/azvol_mount.rs`): which rows are refused (a
//! hash-checked one whose volume does not match its `verity_root`; a sealed
//! one whose key the system does not hold), what the probe accepts, what a
//! read-only row allows, who may change and commit. This file is the seams that
//! need the kernel: the partition as a [`BlockDev`], the system around the
//! mount ([`Env`]: the clock and the tasks, the calling one and whether a
//! transaction's owner still runs), and the key of a sealed row.
//!
//! # The key of a sealed row
//!
//! A `[volume.NAME]` row with `aead = true` is mounted with a key the kernel
//! derives from the board's secret, the same device seed the `LinkKey`
//! endpoint holds in its reserved sector (`azos_syscall::link_key`), and never
//! hands to ring 3: HKDF-SHA256 with the row's name as salt and a fixed label
//! (`azvol_key`). The key of one row is not the key of another, and a board with
//! no seed (an unprovisioned one) has no key for any: such a row is NOT
//! mounted, as a plain volume would be a sealed one served in the clear, and
//! the refusal is a decision record (`Rule::DeviceAdmission`, bus 4, why 3),
//! printed with its receipt. A volume that the key does not open is refused the
//! same way (why 4) before any of its data is read.
//!
//! # Partition numbers
//!
//! The row spells the partition 1-based (`partition = 1` is the first), the
//! block layer's published table is 0-based (`partition::partition(0)`), and a
//! `block` endpoint's badge is `n + 1`. The subtraction is in [`open`], once.

use azos_drv_block::blkdev;
use azos_drv_block::partition;
use azos_drv_sys::{kprintln, kwarn};
use azos_fs::azvol::verity::{Fail, Tamper};
use azos_fs::azvol::{BlockDev, DevError, Error, Volume, VolumeKey, BLOCK_SIZE};
use azos_fs::azvol_mount::{mount_rows, Env, Outcome, Row, Why};
use azos_fs::probe::VolumeKind;

use super::azvol_key;

/// Sectors per azvol block (4096 / 512).
const SECTORS_PER_BLOCK: u64 = (BLOCK_SIZE / 512) as u64;
/// Most sectors moved by one call to the block layer: bounds the staging a
/// driver needs, however long a run the volume asks for.
const RUN_SECTORS: u64 = 256;

/// A partition of the boot medium as a block device: whole azvol blocks at
/// block-relative addresses, mapped to absolute sectors.
pub(super) struct PartDev {
    /// First sector of the partition on the medium.
    start: u64,
    /// Size in azvol blocks (a trailing partial block is not used).
    blocks: u64,
}

impl PartDev {
    /// The absolute sector and sector count of `len` bytes at block `first`,
    /// or `None` when the run leaves the partition.
    fn run(&self, first: u64, len: usize) -> Option<(u64, u64)> {
        if len == 0 || len % BLOCK_SIZE != 0 {
            return None;
        }
        let n = (len / BLOCK_SIZE) as u64;
        if first.checked_add(n)? > self.blocks {
            return None;
        }
        Some((self.start + first * SECTORS_PER_BLOCK, n * SECTORS_PER_BLOCK))
    }
}

impl BlockDev for PartDev {
    fn block_count(&self) -> u64 {
        self.blocks
    }

    fn read(&mut self, first: u64, buf: &mut [u8]) -> Result<(), DevError> {
        let (mut sector, total) = self.run(first, buf.len()).ok_or(DevError)?;
        let (mut at, mut left) = (0usize, total);
        while left > 0 {
            let n = left.min(RUN_SECTORS);
            let bytes = n as usize * 512;
            blkdev::read(sector, n as u32, &mut buf[at..at + bytes]).map_err(|()| DevError)?;
            sector += n;
            at += bytes;
            left -= n;
        }
        Ok(())
    }

    fn write(&mut self, first: u64, buf: &[u8]) -> Result<(), DevError> {
        let (mut sector, total) = self.run(first, buf.len()).ok_or(DevError)?;
        let (mut at, mut left) = (0usize, total);
        while left > 0 {
            let n = left.min(RUN_SECTORS);
            let bytes = n as usize * 512;
            blkdev::write(sector, n as u32, &buf[at..at + bytes]).map_err(|()| DevError)?;
            sector += n;
            at += bytes;
            left -= n;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), DevError> {
        blkdev::flush().map_err(|_| DevError)
    }

    fn raw_sector(&self, block: u64) -> Option<u64> {
        if block >= self.blocks {
            return None;
        }
        Some(self.start + block * SECTORS_PER_BLOCK)
    }

    /// One discard of all the runs (Kconfig `BLK_DISCARD`; `blkdev::discard`
    /// answers at once where it is off or the disk has no discard).
    fn discard(&mut self, runs: &[(u64, u32)]) -> Result<(), DevError> {
        let mut sectors = alloc::vec::Vec::with_capacity(runs.len());
        for &(first, n) in runs {
            let (sector, count) = self.run(first, n as usize * BLOCK_SIZE).ok_or(DevError)?;
            sectors.push((sector, u32::try_from(count).map_err(|_| DevError)?));
        }
        blkdev::discard(&sectors).map_err(|_| DevError)
    }
}

/// The device of the row's partition (`partition` is 1-based, as the row
/// spells it; the published table is 0-based), or `None` when the medium has
/// no such partition or it is smaller than a minimal volume.
pub(super) fn open(partition_1based: u8) -> Option<PartDev> {
    let (start, sectors) = partition::partition(u32::from(partition_1based).checked_sub(1)?)?;
    Some(PartDev { start, blocks: sectors / SECTORS_PER_BLOCK })
}

/// The system around a mounted volume.
struct KernelEnv;

static ENV: KernelEnv = KernelEnv;

/// The wall-ish clock the volumes stamp their files with.
pub(super) fn clock_ns() -> u64 {
    use azos_abi::time::{clock_now_with, posix_clock, ClockId};
    let Some(real) = ClockId::from_posix(posix_clock::REALTIME) else { return 0 };
    clock_now_with(
        real,
        || azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ),
        azos_mm::vdso::clock_offsets,
    )
    .unwrap_or(0)
}

/// The key of sealed row `name`, from the board's seed; `None` when the board
/// holds none (nothing provisioned, or no reserved sector to read it from).
pub(super) fn volume_key(name: &[u8]) -> Option<VolumeKey> {
    let mut seed = [0u8; azos_syscall::link_key::LINK_KEY_BYTES];
    if !azos_syscall::link_key::read_key_via_hook(&mut seed) {
        return None;
    }
    let key = azvol_key::derive(&seed, name);
    azos_crypto::ct::secure_zero(&mut seed);
    key.map(|mut k| {
        let v = VolumeKey::from_bytes(&k);
        azos_crypto::ct::secure_zero(&mut k);
        v
    })
}

/// Open the volume of row `name` on `dev` with the engine itself (not the VFS):
/// sealed with its key when the row is, plain otherwise. For the steps that run
/// before the VFS serves the volume (`pkg_apply`).
pub(super) fn engine_mount(dev: PartDev, name: &[u8], aead: bool) -> Result<Volume<PartDev>, Why> {
    if !aead {
        return Volume::mount(dev).map_err(Why::Engine);
    }
    let key = volume_key(name).ok_or(Why::NoKey)?;
    Volume::mount_sealed(dev, &key).map_err(Why::Engine)
}

impl Env for KernelEnv {
    fn now_ns(&self) -> u64 {
        clock_ns()
    }

    fn tid(&self) -> u32 {
        azos_sync::waitqueue::caller_tid()
    }

    fn alive(&self, tid: u32) -> bool {
        azos_sched::task_row(tid).is_some_and(|r| r.state != b'Z')
    }

    /// A verity failure: a warning line for the first and then each doubling
    /// (a reader that retries a bad block must not flood the console).
    fn tampered(&self, t: &Tamper) {
        if !t.count.is_power_of_two() {
            return;
        }
        let what = match t.what {
            Fail::Header => "the header, or the superblock that places it, does not match the verity root",
            Fail::Data => "a volume block does not match its hash",
            Fail::Hash(_) => "a hash block does not match the hash above it",
        };
        let level = if let Fail::Hash(l) = t.what { l } else { 0 };
        kwarn!("[AZVOL] verity: block {} (level {}): {}; {} failure(s) so far", t.block, level, what, t.count);
    }
}

/// Mount every `[volume.NAME]` row of the installed topology. After
/// `install_topology` (the rows) and `publish_partitions` (the partitions),
/// before any task that opens a path under a mount point can run. A row that
/// is not mounted is printed with the reason and costs nothing else.
pub(crate) fn install_azvol() {
    let Some(topo) = azos_topology::get() else { return };
    let rows = topo.volumes();
    if rows.is_empty() {
        return;
    }
    let table = rows.iter().map(|v| Row {
        name: v.name.as_bytes(),
        partition: v.partition,
        mount: v.mount.as_bytes(),
        read_only: v.read_only,
        aead: v.aead,
        verity_root: v.verity_root,
    });
    mount_rows(table, &mut |p| open(p), &mut |row| volume_key(row.name), &ENV, &mut |row, outcome| {
        let name = core::str::from_utf8(row.name).unwrap_or("?");
        let at = core::str::from_utf8(row.mount).unwrap_or("?");
        // A sealed row that was not served is a decision (`DeviceAdmission`:
        // detected, not admitted), with a receipt.
        let receipt = match outcome {
            Outcome::Refused(Why::NoKey) => Some(admission_receipt(row.partition, REFUSED_NO_KEY)),
            Outcome::Refused(Why::Engine(Error::WrongKey)) => Some(admission_receipt(row.partition, REFUSED_WRONG_KEY)),
            _ => None,
        };
        match outcome {
            Outcome::Mounted(r) => kprintln!(
                "[AZVOL] {}: partition {} mounted at {}{} (generation {}{})",
                name, row.partition, at, if row.read_only { " read-only" } else { "" }, r.generation,
                if r.bitmap_rebuilt { ", free-space map rebuilt" } else { "" },
            ),
            Outcome::Refused(why) => kprintln!(
                "[AZVOL] {}: partition {} NOT mounted at {}: {}{}", name, row.partition, at, refusal(why),
                ReceiptNote(receipt),
            ),
        }
    });
}

/// `DeviceAdmission` `bus` of a volume row (0 PCI, 1 device tree, 2 virtio-mmio, 3 platform).
const BUS_VOLUME_ROW: u64 = 4;
/// `DeviceAdmission` `why` 3: a sealed row, and the system holds no key for it.
const REFUSED_NO_KEY: u64 = 3;
/// `DeviceAdmission` `why` 4: a sealed row whose volume the system's key does not open.
const REFUSED_WRONG_KEY: u64 = 4;

/// The record of a sealed row not mounted: the partition as the subject and as
/// the device's id, and why.
fn admission_receipt(partition: u8, why: u64) -> u64 {
    azos_decision::record_receipt(
        azos_decision::Rule::DeviceAdmission,
        azos_decision::Verdict::Refuse,
        u32::from(partition),
        [BUS_VOLUME_ROW, u64::from(partition), why],
    )
}

/// ` (receipt #N)` for a refusal that left a record, nothing for the others.
struct ReceiptNote(Option<u64>);

impl core::fmt::Display for ReceiptNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(0) => f.write_str(" (receipt not stored: decision records are off in this build)"),
            Some(n) => write!(f, " (receipt #{n})"),
            None => Ok(()),
        }
    }
}

fn refusal(why: Why) -> &'static str {
    match why {
        Why::NoKey => "the row is sealed and the system holds no key for it",
        Why::SealedAndHashed => "the row is both sealed (aead) and hash-checked (verity_root), which is not defined",
        Why::Verity(_) => "the partition does not open as the volume the row's verity root names",
        Why::Tampered => "a block read by the mount does not match the verity root",
        Why::NoDevice => "no such partition on the boot medium",
        Why::NotAzvol(VolumeKind::Fat32) => "the partition holds a FAT32 volume",
        Why::NotAzvol(VolumeKind::Unknown) => "the partition holds no azvol volume (not formatted here)",
        Why::NotAzvol(VolumeKind::AzvolRefused(_)) => "the partition's azvol superblock is damaged or unsupported",
        Why::NotAzvol(VolumeKind::Azvol { .. }) => "the partition holds an azvol volume",
        Why::Engine(Error::WrongKey) => "the system's key does not open the sealed volume",
        Why::Engine(Error::Unsupported(_)) => "the row is sealed and the volume is not (it will not be served as sealed)",
        Why::Engine(Error::KeyRequired) => "the volume is sealed and the row does not say so",
        Why::Engine(_) => "the volume failed its mount checks",
        Why::Vfs => "the mount point is taken or the mount table is full",
    }
}
