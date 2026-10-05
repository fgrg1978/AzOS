// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel-produced sensor streams in shared memory (wave 11, SHMRING).
//!
//! A stream is a kernel-owned `Cap<Shm>` region on contiguous frames holding
//! one `azos_spsc::SpscBytes` ring. The kernel is the only producer (a
//! [`BytesProducer`], which keeps its own head and never blocks: a full ring
//! drops the NEWEST item and counts it). One ring-3 task consumes: it is
//! seeded a `Cap<Shm>` by its topology row (`Shm`, target `stream.lidar` or
//! `stream.camera`), maps it with `SYS_SHM_MAP_TYPED`, drains in batches, and
//! sleeps with `SYS_NOTIFY_WAIT` on the head word when the ring is empty. The
//! producer rings the doorbell (`notify` on the head word) only when the
//! consumer said it may be asleep.
//!
//! # Authority (owner decision, 2026-10-03)
//!
//! **Holding the stream's `Cap<Shm>` replaces the per-request capability
//! check.** `SYS_SENSOR_READ_TYPED` checks the caller's `Cap<Sensor>` on every
//! read; a stream checks nothing per frame. The authority question is asked
//! once, when the topology seeds the capability, and the row that declares
//! `Shm stream.<name>` IS the authority to read that sensor. Revoking it means
//! removing the row's grant: an existing mapping keeps receiving frames until
//! the task exits or unmaps.
//!
//! # Trust boundary
//!
//! The consumer maps the region read-write (it must store its tail and its
//! wait flag), so every word it can write is untrusted here: see
//! `azos_spsc::bytes`, "Trust boundary". In short: the head is the
//! producer's own, the tail only ever reads as "full" when it is garbage,
//! every slot address is masked by the producer's own `cap` and the payload
//! clamped to the producer's own slot size, so a hostile consumer can drop or
//! corrupt its own frames and nothing else.
//!
//! # One consumer
//!
//! SPSC: two tasks draining one ring would race each other's tail. The
//! topology grants each stream to one row (the autorun row, whose task is the
//! one program the image runs), and the kernel does not stop a second holder:
//! a second consumer can only break the stream for the two of them.
//!
//! # Fallback
//!
//! Every stream is behind a Kconfig symbol, default off
//! (`STREAM_LIDAR_RING`, `STREAM_CAMERA_RING`). Off, nothing here allocates,
//! the seed of `stream.<name>` is refused, and `SYS_SENSOR_READ_TYPED`
//! remains the path — it is unchanged and stays available with the ring on.

use crate::cap::{CapHandle, CapPerms};
use crate::shm::{self, ShmPerms};
use azos_spsc::{BytesProducer, SpscBytes};
pub use azos_spsc::Publish;
use azos_sync::SpinLock;

/// A kernel stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    /// Full LiDAR revolutions: `SYS_SENSOR_READ`'s `SENSOR_TYPE_LIDAR` record
    /// (`[angle_cdeg u16, distance_mm u16]` per point).
    Lidar = 0,
    /// Camera frames: `SENSOR_TYPE_CAMERA`'s JPEG.
    Camera = 1,
}

const STREAMS: usize = 2;

/// Round `n` up to a 64-byte line, so every slot starts on its own line.
const fn line(n: usize) -> usize { (n + 63) & !63 }

/// Slots per LiDAR ring: 1.6 s of scans at the LD19's 10 Hz.
pub const LIDAR_RING_SLOTS: u32 = 16;
/// Bytes per LiDAR slot: one full revolution and the slot header.
pub const LIDAR_SLOT_BYTES: u32 =
    line(azos_spsc::SLOT_HDR_BYTES + azos_drv_sensor::lidar::SCAN_DATA_MAX_BYTES) as u32;
/// Slots per camera ring.
pub const CAMERA_RING_SLOTS: u32 = 8;
/// Bytes per camera slot: the largest JPEG `csi_capture_jpeg` writes, and
/// the slot header.
pub const CAMERA_SLOT_BYTES: u32 =
    line(azos_spsc::SLOT_HDR_BYTES + azos_drv_sensor::csi::JPEG_MAX_SIZE) as u32;

impl Stream {
    /// The topology target naming it.
    pub const fn target(self) -> &'static str {
        match self {
            Stream::Lidar => "stream.lidar",
            Stream::Camera => "stream.camera",
        }
    }

    /// Is this stream configured in (Kconfig)?
    pub const fn enabled(self) -> bool {
        match self {
            Stream::Lidar => azos_limits::STREAM_LIDAR_RING,
            Stream::Camera => azos_limits::STREAM_CAMERA_RING,
        }
    }

    /// `(slots, slot bytes)`.
    pub const fn geometry(self) -> (u32, u32) {
        match self {
            Stream::Lidar => (LIDAR_RING_SLOTS, LIDAR_SLOT_BYTES),
            Stream::Camera => (CAMERA_RING_SLOTS, CAMERA_SLOT_BYTES),
        }
    }

    fn from_target(t: &str) -> Option<Stream> {
        [Stream::Lidar, Stream::Camera].into_iter().find(|s| s.target() == t)
    }
}

/// A live stream: its region and its producer.
struct Live {
    region: u32,
    producer: BytesProducer,
}

static LIVE: [SpinLock<Option<Live>>; STREAMS] = [SpinLock::new(None), SpinLock::new(None)];

/// The stream's region, created on first use (enabled streams only). The
/// packed `Cap<Shm>` reference, or `None` when disabled or out of memory.
pub fn stream_region(s: Stream) -> Option<u32> {
    if !s.enabled() {
        return None;
    }
    let mut live = LIVE[s as usize].lock_irqsave();
    if let Some(l) = live.as_ref() {
        return Some(l.region);
    }
    let (cap, slot) = s.geometry();
    let page = azos_arch::mmu::PAGE_SIZE;
    let pages = SpscBytes::bytes(cap, slot).div_ceil(page);
    let (region, phys) = shm::shm_create_kernel_contig_ref(pages, ShmPerms::ReadWrite)?;
    let base = azos_mm::addr::phys_to_virt(phys);
    let producer = BytesProducer::new(SpscBytes { base, cap, slot_bytes: slot });
    *live = Some(Live { region, producer });
    Some(region)
}

/// `SYS_CAP_LOOKUP`'s `Shm` resource, translated: a stream key
/// (`azos_abi::cap::SHM_STREAM_*`) becomes the live stream's region
/// INDEX, which is what a `Shm` lookup compares (`CapTable::lookup` matches
/// `objref::resource_index`); any other value is returned as given. A key is
/// above every pool index, so it never shadows a real region.
pub fn stream_lookup_resource(resource: u32) -> u32 {
    use azos_abi::cap::{SHM_STREAM_CAMERA, SHM_STREAM_LIDAR};
    const _: () = assert!(SHM_STREAM_LIDAR as usize >= shm::MAX_SHM_REGIONS && SHM_STREAM_CAMERA as usize >= shm::MAX_SHM_REGIONS);
    let s = match resource {
        SHM_STREAM_LIDAR => Stream::Lidar,
        SHM_STREAM_CAMERA => Stream::Camera,
        _ => return resource,
    };
    match LIVE[s as usize].lock_irqsave().as_ref() {
        Some(l) => crate::objref::resource_index(crate::cap::CapKind::Shm, l.region),
        None => resource,
    }
}

/// The topology minter for `CapKind::Shm` (installed into
/// `crate::cap_seed` by the kernel at boot): `stream.<name>` mints a `READ |
/// WRITE` `Cap<Shm>` to that stream's region into `tid`'s table — the
/// consumer must write its tail and wait flag, so the mapping is RW (see the
/// trust boundary above). Never `DUP`: the row is the authority, and a holder
/// cannot hand the stream on. `None` for an unknown or disabled stream, a
/// grant asking for anything but `READ`/`WRITE`, or a full table.
pub fn stream_seed_mint(tid: u32, target: &str, perms: CapPerms) -> Option<CapHandle> {
    let s = Stream::from_target(target)?;
    if !CapPerms::RW.contains(perms) || !perms.contains(CapPerms::READ) {
        return None;
    }
    let region = stream_region(s)?;
    crate::objref::grant_packed::<crate::cap::targets::Shm>(tid, perms, region).map(|c| c.raw())
}

/// Publish one item into `s`: `fill(dst, room)` writes at most `room` bytes
/// at `dst` (kernel memory inside the ring's slot) and returns how many.
/// Never blocks; callable from an interrupt. `None` when the stream is not
/// live; otherwise what the ring did and, for [`Publish::Wake`], the
/// `(region, offset)` the caller must ring
/// (`azos_syscall::vdso_notify::notify_wake_kernel`).
pub fn stream_publish(
    s: Stream,
    acq_ns: u64,
    fill: impl FnOnce(*mut u8, usize) -> usize,
) -> Option<(Publish, u32, u32)> {
    let mut live = LIVE[s as usize].lock_irqsave();
    let l = live.as_mut()?;
    let p = l.producer.push_with(acq_ns, fill);
    Some((p, l.region, azos_spsc::RING_HEAD as u32))
}

/// `(published + dropped, dropped, doorbells)` of a live stream.
pub fn stream_stats(s: Stream) -> Option<(u32, u32, u32)> {
    let live = LIVE[s as usize].lock_irqsave();
    live.as_ref().map(|l| (l.producer.seq(), l.producer.drops(), l.producer.wakes()))
}

/// Does any task have the stream's region mapped now? A producer whose work
/// costs something (the camera's capture and compression) asks before
/// producing; the LiDAR, which parses its UART anyway, publishes regardless.
pub fn stream_has_consumer(s: Stream) -> bool {
    let region = match LIVE[s as usize].lock_irqsave().as_ref() {
        Some(l) => l.region,
        None => return false,
    };
    shm::shm_is_mapped_by_any_ref(region)
}
