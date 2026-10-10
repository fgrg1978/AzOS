// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the driver class crates `crates/fs/fs` names
//! (`azos_drv_block`, `azos_drv_sys`, `azos_drv_base`), reduced to the things
//! `crates/fs/fs/src/fat32.rs` actually calls: `blkdev::{read,write,flush}` and
//! `kprintln!`. The suite aliases each of those crate names to this one.
//!
//! **WHY this exists.** The real driver crates are RV64-only — MMIO,
//! VirtIO queues, PLIC — so the `#[path]` host-test trick cannot pull it in.
//! But the point of these tests is FAT32's behaviour *around* the block
//! device, not the device, so the shim gives the parser a disk it can be fed
//! by hand.
//!
//! It deliberately exposes a control surface a real disk has no reason to
//! offer:
//!
//!   * [`disk_load`] — install an image, so a **malformed** volume can be
//!     mounted on purpose. That is the whole point: a FAT32 volume is
//!     attacker-controlled input the moment the robot accepts an SD card, and
//!     with `panic = "abort"` a bad field is a board reset, not an error.
//!   * [`disk_fail_after`] — make the Nth read fail, so the error paths that
//!     a healthy disk never reaches get executed.
//!   * [`disk_reads`] — how many sectors were fetched, which is how the
//!     sector cache is observed from outside.
//!   * [`disk_writeback`] / [`disk_durable_image`] — a volatile write cache:
//!     writes land in the cache, only a `blkdev::flush` makes them durable,
//!     and the durable image is what a power cut leaves. Off by default (a
//!     write-through disk, where every completed write is durable), so the
//!     tests written before the flush existed see the disk they always saw.
//!   * [`disk_flush_mode`] / [`disk_events`] — make `flush` answer
//!     Unsupported or Io, and read back the ordered write/flush sequence.
//!   * [`disk_take_log`] — the same sequence WITH each sector's bytes, so a
//!     test can rebuild any state a power cut may leave: everything before
//!     a flush, plus ANY subset of the writes after it. `disk_writeback`'s
//!     durable image is one of those states (the empty subset); a device
//!     cache may persist its pending writes in any order, which that single
//!     image never shows.

use std::sync::Mutex;

pub const SHIM_SECTOR: usize = 512;

struct Disk {
    data: Vec<u8>,
    reads: u32,
    writes: u32,
    fail_after: Option<u32>,
    /// Every read that covers this sector fails (a bad block).
    bad_sector: Option<u64>,
    write_fail_after: Option<u32>,
    /// One-shot: fail only the write whose ordinal (`writes` before it) is
    /// this, and let every later write through.
    write_fail_nth: Option<u32>,
    /// `Some` while the write cache is volatile: what survives a power cut.
    durable: Option<Vec<u8>>,
    flush_mode: FlushMode,
    events: Vec<DiskEvent>,
    log: Vec<LogEntry>,
}

/// One device operation with its payload, in issue order: a one-sector
/// write, or a flush the device confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogEntry { Write(u64, Vec<u8>), Flush }

/// How `blkdev::flush` answers. `Ok` is a device that can flush.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushMode { Ok, Unsupported, Io }

/// One device operation, in issue order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskEvent { Write(u64), Flush }

static DISK: Mutex<Option<Disk>> = Mutex::new(None);

/// Install `image` as the block device. Length need not be sector-aligned;
/// reads past the end fail, which is what a short image does on real hardware.
pub fn disk_load(image: Vec<u8>) {
    *DISK.lock().unwrap() = Some(Disk {
        data: image, reads: 0, writes: 0, fail_after: None, bad_sector: None, write_fail_after: None, write_fail_nth: None,
        durable: None, flush_mode: FlushMode::Ok, events: Vec::new(), log: Vec::new(),
    });
}

/// Take the write/flush log (with payloads) issued since the last call (or
/// `disk_load`). A multi-sector write appears as one entry per sector: the
/// device may persist part of it.
pub fn disk_take_log() -> Vec<LogEntry> {
    DISK.lock().unwrap().as_mut().map(|d| core::mem::take(&mut d.log)).unwrap_or_default()
}

/// Turn the volatile write cache on: from now on a write is durable only
/// once a successful `blkdev::flush` follows it. Everything on the disk at
/// this moment counts as durable.
pub fn disk_writeback() {
    if let Some(d) = DISK.lock().unwrap().as_mut() { d.durable = Some(d.data.clone()); }
}

/// What a power cut leaves: the durable image under a volatile cache, the
/// whole disk otherwise. Install it with `disk_load` to "reboot".
pub fn disk_durable_image() -> Vec<u8> {
    let g = DISK.lock().unwrap();
    let d = g.as_ref().expect("no disk loaded");
    d.durable.clone().unwrap_or_else(|| d.data.clone())
}

/// The whole medium as the device holds it now (volatile cache included).
pub fn disk_image() -> Vec<u8> {
    DISK.lock().unwrap().as_ref().expect("no disk loaded").data.clone()
}

/// Set how `blkdev::flush` answers.
pub fn disk_flush_mode(m: FlushMode) {
    if let Some(d) = DISK.lock().unwrap().as_mut() { d.flush_mode = m; }
}

/// Take the write/flush sequence issued since the last call (or `disk_load`).
pub fn disk_events() -> Vec<DiskEvent> {
    DISK.lock().unwrap().as_mut().map(|d| core::mem::take(&mut d.events)).unwrap_or_default()
}

/// Fail every read from the `n`-th onwards (0 = fail immediately).
pub fn disk_fail_after(n: u32) {
    if let Some(d) = DISK.lock().unwrap().as_mut() { d.fail_after = Some(n); }
}

/// Make `sector` a bad block: every read that covers it fails, every other
/// read succeeds. Cleared by the next `disk_load`.
pub fn disk_bad_sector(sector: u64) {
    if let Some(d) = DISK.lock().unwrap().as_mut() { d.bad_sector = Some(sector); }
}

/// Fail every WRITE from the `n`-th onwards (0 = fail immediately), so a test
/// can simulate power loss mid-operation at an exact, counted point — e.g.
/// right after a journal record becomes durable but before the write that
/// was meant to follow it. Mirrors `disk_fail_after` for reads.
///
/// A failed write is modeled as never reaching the device: `d.data` is left
/// untouched, matching how `disk_fail_after` fails a read before handing back
/// any bytes. `writes` is still incremented so callers can reason about which
/// numbered attempt failed.
pub fn disk_write_fail_after(n: u32) {
    if let Some(d) = DISK.lock().unwrap().as_mut() { d.write_fail_after = Some(n); }
}

/// Fail ONLY the `n`-th write from now on (0 = the next one), counted as
/// `disk_write_fail_after` counts, and let every later write through: a
/// single transient I/O error, so a test can watch the code that runs AFTER
/// the failure — a rollback, an undo — actually reach the device. Same
/// failure model as `disk_write_fail_after` (the device is not touched).
pub fn disk_write_fail_nth(n: u32) {
    if let Some(d) = DISK.lock().unwrap().as_mut() { d.write_fail_nth = Some(d.writes + n); }
}

/// Disarm `disk_write_fail_after` — call before "rebooting" (remounting) so
/// that journal recovery's own writes are not also hit by the same injected
/// failure.
pub fn disk_write_fail_clear() {
    if let Some(d) = DISK.lock().unwrap().as_mut() { d.write_fail_after = None; d.write_fail_nth = None; }
}

/// `(reads, writes)` issued to the device since `disk_load`.
pub fn disk_stats() -> (u32, u32) {
    DISK.lock().unwrap().as_ref().map(|d| (d.reads, d.writes)).unwrap_or((0, 0))
}

/// Read back a sector as the device holds it, to assert what was written.
pub fn disk_peek(sector: u64) -> Option<Vec<u8>> {
    let g = DISK.lock().unwrap();
    let d = g.as_ref()?;
    let off = (sector as usize).checked_mul(SHIM_SECTOR)?;
    d.data.get(off..off + SHIM_SECTOR).map(|s| s.to_vec())
}

/// Write a sector directly into the device, bypassing `blkdev::write` (no
/// read/write counters touched, no `write_fail_after` check). Models a
/// WRITER ON ANOTHER HART changing the medium without going through the
/// driver under test — the scenario `mount_tests::
/// a_second_mount_while_already_mounted_does_not_touch_a_concurrent_
/// journal_write` needs: plant a journal record as if another hart just
/// wrote it, then prove a redundant `fat32_mount()` on THIS hart leaves it
/// alone. `disk_peek`'s write-side counterpart.
pub fn disk_poke(sector: u64, bytes: &[u8]) {
    let mut g = DISK.lock().unwrap();
    if let Some(d) = g.as_mut() {
        let off = (sector as usize) * SHIM_SECTOR;
        let end = (off + bytes.len()).min(d.data.len());
        if end > off {
            d.data[off..end].copy_from_slice(&bytes[..end - off]);
        }
    }
}

/// The partition table the kernel publishes (RFC-0048 P3), the real file:
/// the FAT32 driver mounts from it.
#[path = "../../../../../../crates/drivers/block/src/partition.rs"]
pub mod partition;

/// The block layer's write observer, the real file (wave 14): the shim's
/// `blkdev::write` reports through it exactly as the kernel's does.
#[path = "../../../../../../crates/drivers/block/src/write_observer.rs"]
pub mod write_observer;

/// A write another task issues while a read is in flight: the next
/// `blkdev::read` that covers sector `.0` returns the OLD bytes, and then —
/// before its caller can do anything with them — `.2` lands at sector `.1`
/// through the observed `blkdev::write`. Models the race the block cache's
/// install token closes.
static WRITE_DURING_READ: Mutex<Option<(u64, u64, Vec<u8>)>> = Mutex::new(None);

/// Arm [`WRITE_DURING_READ`] for the next read covering `trigger`.
pub fn disk_write_during_read_of(trigger: u64, sector: u64, bytes: &[u8]) {
    *WRITE_DURING_READ.lock().unwrap() = Some((trigger, sector, bytes.to_vec()));
}

/// Called at the start of every device write, before its bytes land (wave
/// 14, SPAWNCACHE): what a reader on another hart would see then.
static BEFORE_WRITE: Mutex<Option<fn()>> = Mutex::new(None);

/// Install (or remove) the [`BEFORE_WRITE`] hook.
pub fn disk_before_write(f: Option<fn()>) {
    *BEFORE_WRITE.lock().unwrap() = f;
}

pub mod blkdev {
    use super::*;

    /// The kernel's `blkdev::read`: the read observer, then the device read.
    pub fn read(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        super::write_observer::before_read(sector, count);
        read_quiet(sector, count, buf)
    }

    /// The kernel's `blkdev::note_external_read`.
    pub fn note_external_read(sector: u64, count: u32) {
        super::write_observer::before_read(sector, count);
    }

    /// The kernel's `blkdev::set_read_observer`.
    pub fn set_read_observer(f: fn(u64, u32)) {
        super::write_observer::set_read(f);
    }

    /// The kernel's `blkdev::read_quiet`: the device read alone.
    /// The kernel's `blkdev::capacity_sectors`: the loaded image's size.
    pub fn capacity_sectors() -> u64 {
        DISK.lock().unwrap().as_ref().map_or(0, |d| (d.data.len() / SHIM_SECTOR) as u64)
    }

    pub fn read_quiet(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        {
            let mut g = DISK.lock().unwrap();
            let d = g.as_mut().ok_or(())?;
            if let Some(n) = d.fail_after {
                if d.reads >= n { d.reads += 1; return Err(()); }
            }
            if let Some(b) = d.bad_sector {
                if (sector..sector + count as u64).contains(&b) { d.reads += 1; return Err(()); }
            }
            let len = (count as usize) * SHIM_SECTOR;
            let off = (sector as usize).checked_mul(SHIM_SECTOR).ok_or(())?;
            let end = off.checked_add(len).ok_or(())?;
            if end > d.data.len() || buf.len() < len { return Err(()); }
            buf[..len].copy_from_slice(&d.data[off..end]);
            d.reads += 1;
        }
        let racing = {
            let mut w = WRITE_DURING_READ.lock().unwrap();
            match w.as_ref() {
                Some((t, _, _)) if (sector..sector + count as u64).contains(t) => w.take(),
                _ => None,
            }
        };
        if let Some((_, s, bytes)) = racing {
            let n = (bytes.len() / SHIM_SECTOR) as u32;
            write(s, n, &bytes)?;
        }
        Ok(())
    }

    /// The kernel's `blkdev::write`: the device write, then the observer.
    pub fn write(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        let r = write_quiet(sector, count, buf);
        super::write_observer::notify(sector, count);
        r
    }

    /// The kernel's `blkdev::note_external_write`.
    pub fn note_external_write(sector: u64, count: u32) {
        super::write_observer::notify(sector, count);
    }

    /// The kernel's `blkdev::set_write_observer`.
    pub fn set_write_observer(f: fn(u64, u32)) {
        super::write_observer::set(f);
    }

    /// The kernel's `blkdev::write_quiet`: the device write alone.
    pub fn write_quiet(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        let hook = *BEFORE_WRITE.lock().unwrap();
        if let Some(f) = hook { f(); }
        let mut g = DISK.lock().unwrap();
        let d = g.as_mut().ok_or(())?;
        if let Some(n) = d.write_fail_after {
            if d.writes >= n { d.writes += 1; return Err(()); }
        }
        if d.write_fail_nth == Some(d.writes) {
            d.write_fail_nth = None;
            d.writes += 1;
            return Err(());
        }
        let len = (count as usize) * SHIM_SECTOR;
        let off = (sector as usize).checked_mul(SHIM_SECTOR).ok_or(())?;
        let end = off.checked_add(len).ok_or(())?;
        if end > d.data.len() || buf.len() < len { return Err(()); }
        d.data[off..end].copy_from_slice(&buf[..len]);
        d.writes += 1;
        d.events.push(DiskEvent::Write(sector));
        for i in 0..count as usize {
            d.log.push(LogEntry::Write(
                sector + i as u64, buf[i * SHIM_SECTOR..(i + 1) * SHIM_SECTOR].to_vec()));
        }
        Ok(())
    }

    /// The block class's own error type, as the kernel's `blkdev` returns it.
    use azos_drv_api::block::FlushError;

    /// Answer per `disk_flush_mode`; on `Ok`, everything written so far
    /// becomes durable. A failed flush makes nothing durable.
    pub fn flush() -> Result<(), FlushError> {
        let mut g = DISK.lock().unwrap();
        let d = g.as_mut().ok_or(FlushError::Io)?;
        match d.flush_mode {
            FlushMode::Unsupported => return Err(FlushError::Unsupported),
            FlushMode::Io => return Err(FlushError::Io),
            FlushMode::Ok => {}
        }
        d.events.push(DiskEvent::Flush);
        d.log.push(LogEntry::Flush);
        if d.durable.is_some() { d.durable = Some(d.data.clone()); }
        Ok(())
    }
}

/// `kprintln!` on the host: the module under test prints diagnostics, and
/// swallowing them silently would hide a message a failing test wants to show.
#[macro_export]
macro_rules! kprintln {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}

/// The leveled forms (`crates/drivers/sys/src/uart.rs`): every level prints
/// on the host.
#[macro_export]
macro_rules! kerr {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kwarn {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kinfo {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kdebug {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kconsoleln {
    () => { println!() };
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[macro_export]
macro_rules! kconsole {
    ($($arg:tt)*) => { print!($($arg)*) };
}

/// `uart::putc` on the host: `vfs.rs`'s `/dev/stdout` device callback writes
/// through it one byte at a time. Nothing in this suite opens `/dev/stdout`,
/// but the callback is installed by `vfs::init()`, so the symbol has to exist.
/// Bytes go to stdout, which the test harness captures per test.
pub mod uart {
    use std::io::Write;

    pub fn putc(c: u8) {
        let _ = std::io::stdout().write_all(&[c]);
    }

    /// `/dev/stdout`'s device callback writes through this (wave 11).
    pub fn console_write_ring3(bytes: &[u8]) {
        let _ = std::io::stdout().write_all(bytes);
    }
}

/// The two platform constants `crates/fs/fs/src/procfs.rs`'s generators read
/// (`/proc/uptime`, `/proc/version`, `/sys/platform`). procfs is pulled into
/// this suite for its key rules; these values are never asserted.
pub mod platform {
    pub mod hw {
        pub const TIMER_FREQ: u64 = 10_000_000;
        pub const PLATFORM_NAME: &str = "host-test";
    }
}
