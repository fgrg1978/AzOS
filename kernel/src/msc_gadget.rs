// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DEV03 — USB Mass Storage gadget glue.
//!
//! Ties the three pre-existing layers together so the board appears
//! as a USB flash drive to a connected PC:
//!
//! ```text
//!   USB OTG controller (DWC2, hardware-pending)
//!         ↓ bulk-OUT (31-byte CBW)
//!   azos_msc::dispatch::dispatch_cbw
//!         ↓ SCSI cmd
//!   FAT32BlockDevice (this module)  ←→  azos_drv_block::blkdev
//!         ↓ bulk-IN data + 13-byte CSW
//!   USB OTG controller
//! ```
//!
//! Today the actual USB endpoint reads/writes are stubbed — the
//! VisionFive 2 / SpacemiT K1 DWC2 controller driver does not yet
//! exist on this target. The pure protocol
//! plumbing IS exercised end-to-end by `tests/host/msc-tests`.
//!
//! ## Architectural note
//!
//! All non-trivial decoding (CBW → SCSI → CSW, LBA range checks)
//! lives in `azos_msc::dispatch`, which is host-testable. This
//! module is intentionally thin — it owns the `BlockDevice` impl
//! that delegates to the kernel's block driver and the endpoint
//! pump that will be filled in once we have a DWC2 driver.

use azos_drv_sys::kprintln;
use azos_msc::{
    dispatch_cbw, Action, BlockDevice, MscPhase, MscStateMachine, Sense,
    CBW_TOTAL_LEN, CSW_STATUS_FAIL, CSW_TOTAL_LEN, DISPATCH_IN_BUF_LEN,
};

/// SBC block size in bytes. The MSC SCSI layer always reports
/// this in READ_CAPACITY; FAT32 also uses 512-byte sectors.
const MSC_BLOCK_BYTES: usize = 512;

/// Bulk-IN bounce buffer size for multi-block READ_10. Sized to
/// hold one block — the pump loop iterates blocks one at a time
/// so we never allocate a huge contiguous buffer in the kernel.
const MSC_BLOCK_BUF_BYTES: usize = MSC_BLOCK_BYTES;

/// Capacity (in 512-byte sectors) reported when the underlying
/// block device is unavailable (e.g. no SD card present, or
/// before `blkdev::init()` has been called). A non-
/// zero stub lets host enumeration succeed; any actual read/write
/// will return Err(()) from `blkdev::read/write` and surface a
/// CSW(FAIL) to the host.
const MSC_FALLBACK_CAPACITY_SECTORS: u32 = 0;

/// Sectors reserved at the TAIL of the physical block device, beyond the
/// capacity this gadget reports over USB. U06-9/#30/#29/#26 —
/// `/fat/LINK.KEY` and the entropy seed file (U09-8's fail-closed-unless-
/// seeded fix) used to be ordinary FAT32 files, and `Fat32BlockDevice`
/// exports the FAT32 volume block-for-block with no LUN/LBA restriction
/// beyond simple bounds-checking — so anything reachable through the FAT32
/// filesystem is also reachable, unauthenticated, over `READ_10`/`WRITE_10`
/// the moment the DWC2 controller is wired. A file is not "off the exported
/// LUN" merely by living outside `/fat`'s visible tree; it has to sit at an
/// LBA this gadget never reports as present.
///
/// This reserves the highest `MSC_RESERVED_TAIL_SECTORS` sectors of the
/// PHYSICAL device: `Fat32BlockDevice::new` subtracts them from the
/// capacity handed to `azos_msc::dispatch` (which bounds-checks every
/// `READ_10`/`WRITE_10` LBA against exactly that number), so a USB host on
/// this port cannot address them at all — not "won't find them without the
/// directory entry", genuinely out of the addressable range the SCSI layer
/// will accept. See [`reserved_region_read`]/[`reserved_region_write`].
///
/// 8 sectors (4 KiB) — `LINK.KEY` (32 B) + a seed file with generous
/// headroom for a versioned format, comfortably under one sector each.
///
/// DEPLOYMENT NOTE (left undone here, needs the build/image owner): this
/// only protects anything if the FAT32 filesystem itself is sized to NOT
/// reach these LBAs (`mkfs.fat`'s sector count, `tools/`/`Makefile`'s disk
/// image sizing) — i.e. the physical device must be at least
/// `fat32_tot_sec32 + MSC_RESERVED_TAIL_SECTORS` sectors, with the FAT
/// filesystem occupying only the first part. On an image built without
/// that headroom, [`reserved_region_read`]/[`reserved_region_write`] fail
/// closed (`Err(())`, see below) rather than silently aliasing filesystem
/// data — a missing key/seed is safe; a corrupted-looking read of the FAT
/// volume's tail would not be.
pub const MSC_RESERVED_TAIL_SECTORS: u32 = 8;

/// Adapter from the kernel block driver to the MSC `BlockDevice`
/// trait. The dispatcher uses this to bounds-check LBAs; the
/// endpoint pump uses it to stream READ_10/WRITE_10 payloads.
pub struct Fat32BlockDevice {
    /// Cached capacity (in 512-byte sectors). Captured at init
    /// time so READ_CAPACITY doesn't need to re-query the driver
    /// on every CBW.
    capacity_sectors: u32,
}

impl Fat32BlockDevice {
    /// Snapshot the block-device capacity now and return an
    /// adapter ready to be passed to `dispatch_cbw`.
    pub fn new() -> Self {
        // `blkdev::capacity_sectors` returns u64; SBC READ_CAPACITY(10)
        // is u32. Saturate — anything past 2 TiB needs READ_CAPACITY(16),
        // which the minimal SCSI command set does not implement.
        let raw = azos_drv_block::blkdev::capacity_sectors();
        let capacity_sectors = if raw == 0 {
            MSC_FALLBACK_CAPACITY_SECTORS
        } else if raw > u32::MAX as u64 {
            u32::MAX
        } else {
            raw as u32
        };
        // `saturating_sub` — see `MSC_RESERVED_TAIL_SECTORS`. On a small
        // dev/QEMU image without the reserved headroom this clamps to 0
        // rather than underflowing: the gadget then reports zero capacity
        // (same fail-safe shape as `MSC_FALLBACK_CAPACITY_SECTORS`) instead
        // of a `u32` wraparound that would report a huge, wrong capacity.
        let capacity_sectors = capacity_sectors.saturating_sub(MSC_RESERVED_TAIL_SECTORS);
        Self { capacity_sectors }
    }
}

/// Read `out` (≤ 512 bytes, one sector) from the reserved tail region at
/// `offset_sectors` past the exported capacity — see
/// `MSC_RESERVED_TAIL_SECTORS`. Fails closed (`Err(())`) rather than
/// reading filesystem-owned sectors when the physical device is too small
/// to have the reserved headroom at all, or when `offset_sectors` would run
/// past it.
pub fn reserved_region_read(offset_sectors: u32, out: &mut [u8]) -> Result<(), ()> {
    if out.len() > MSC_BLOCK_BYTES || offset_sectors >= MSC_RESERVED_TAIL_SECTORS {
        return Err(());
    }
    let raw = azos_drv_block::blkdev::capacity_sectors();
    if raw < MSC_RESERVED_TAIL_SECTORS as u64 {
        return Err(()); // no headroom provisioned on this image — fail closed
    }
    let lba = raw - u64::from(MSC_RESERVED_TAIL_SECTORS) + u64::from(offset_sectors);
    let mut sector = [0u8; MSC_BLOCK_BYTES];
    azos_drv_block::blkdev::read(lba, 1, &mut sector)?;
    out.copy_from_slice(&sector[..out.len()]);
    Ok(())
}

/// Write `data` (≤ 512 bytes, one sector) to the reserved tail region.
/// Same fail-closed bounds as [`reserved_region_read`]. The rest of the
/// sector beyond `data.len()` is zero-filled, not left as whatever the
/// medium previously held, so a shorter write cannot leave a stale
/// trailing fragment of a longer previous value on disk.
pub fn reserved_region_write(offset_sectors: u32, data: &[u8]) -> Result<(), ()> {
    if data.len() > MSC_BLOCK_BYTES || offset_sectors >= MSC_RESERVED_TAIL_SECTORS {
        return Err(());
    }
    let raw = azos_drv_block::blkdev::capacity_sectors();
    if raw < MSC_RESERVED_TAIL_SECTORS as u64 {
        return Err(());
    }
    let lba = raw - u64::from(MSC_RESERVED_TAIL_SECTORS) + u64::from(offset_sectors);
    let mut sector = [0u8; MSC_BLOCK_BYTES];
    sector[..data.len()].copy_from_slice(data);
    azos_drv_block::blkdev::write(lba, 1, &sector)
}

/// Reserved-region sector assignment (offsets into `reserved_region_*`).
/// One name per consumer so a second one added later cannot silently
/// collide with an existing sector by picking the same literal.
pub const RESERVED_SECTOR_LINK_KEY: u32 = 0;
/// U09-8 — the persisted entropy seed (owner decision 2026-09-26, V1.2):
/// refuse to derive session keys on an unseeded pool, but persist a seed
/// across boots so a board with no TRNG can be seeded from its second boot on.
/// Format — see `azos_crypto::entropy::{seed_file_encode, seed_file_decode}`
/// (the pure encode/decode; this module only does the raw sector I/O), one
/// sector, `SEED_FILE_BYTES` (73) meaningful:
///   offset 0    4   magic "SEED"
///   offset 4    1   version (1)
///   offset 5   64   seed bytes
///   offset 69   4   integrity tag (first 4 bytes of SHA-256(magic‖version‖seed))
/// A missing sector, bad magic/version, or tag mismatch is treated as "no
/// seed" (mix nothing) — never as zero bytes, which would credit a known,
/// attacker-guessable value as if it were entropy. At every boot
/// (`install_entropy_seed` in `kernel/src/boot/entropy.rs`) the seed is mixed into the pool —
/// credited only when no other source has seeded it — and a FRESH record drawn
/// from the pool replaces it before anything else can draw, so a recorded old
/// seed does not stay valid and a seed is never used twice. It is replaced
/// again at an orderly power-off or reboot, best-effort: a robot's power can
/// also just go away. A first seed for a board with no entropy device is
/// written from the host with `tools/seed_provision.py`.
///
/// Unlike `LINK.KEY` this sector is WRITTEN, on every boot, so the kernel
/// writes it only when `azos_crypto::entropy::seed_tail_check` finds no
/// partition and no FAT32 volume reaching the tail (the `raw < 8` test in
/// [`reserved_region_write`] cannot know where the filesystem ends).
pub const RESERVED_SECTOR_ENTROPY_SEED: u32 = 1;
/// Wave 11 (RFC-0054 finding 7) — the device record: this device's id, which
/// a `CONFIG.SIG` v2 must name, and the lowest `CONFIG.SIG` counter still
/// accepted. Format: `azos_topology::device_record::DeviceRecord` (37
/// bytes meaningful). Written from the host by `tools/device_provision.py`
/// (floor 0) and by the kernel when it accepts a higher counter
/// (`boot::config_auth`), only when `seed_tail_check` finds no filesystem
/// reaching the tail, as for the entropy seed. A USB host cannot address it;
/// a card reader can (only a hardware counter closes that, RFC-0054 §6.3).
pub const RESERVED_SECTOR_DEVICE: u32 = 2;

impl Default for Fat32BlockDevice {
    fn default() -> Self { Self::new() }
}

impl BlockDevice for Fat32BlockDevice {
    fn block_count(&self) -> u32 {
        self.capacity_sectors
    }

    fn read_block(&self, lba: u32, out: &mut [u8]) -> Result<(), ()> {
        if out.len() < MSC_BLOCK_BYTES {
            return Err(());
        }
        // SBC LBA is u32; blkdev API takes u64. The `as u64` here is a
        // widening conversion, never lossy.
        azos_drv_block::blkdev::read(lba as u64, 1, &mut out[..MSC_BLOCK_BYTES])
    }

    fn write_block(&mut self, lba: u32, data: &[u8]) -> Result<(), ()> {
        if data.len() < MSC_BLOCK_BYTES {
            return Err(());
        }
        azos_drv_block::blkdev::write(lba as u64, 1, &data[..MSC_BLOCK_BYTES])
    }

    /// SYNCHRONIZE CACHE(10) → `blkdev::flush()`. `Ok` only on a confirmed
    /// flush: `Unsupported` is an error here too, because the host asked
    /// for durability and this device cannot confirm it (fail closed —
    /// the host sees CHECK CONDITION / MEDIUM ERROR, not GOOD).
    fn sync_cache(&self) -> Result<(), ()> {
        match azos_drv_block::blkdev::flush() {
            Ok(()) => Ok(()),
            Err(e) => {
                azos_drv_sys::kerr!("[msc] SYNCHRONIZE CACHE: flush failed ({:?})", e);
                Err(())
            }
        }
    }
}

/// Kernel-owned MSC gadget state. Holds the BBB state machine, the
/// FAT32-backed LUN, and the per-command scratch buffer used to
/// shuttle inline IN responses (INQUIRY / READ_CAPACITY / etc.) and
/// streamed READ_10/WRITE_10 blocks.
pub struct MscGadget {
    state:     MscStateMachine,
    lun:       Fat32BlockDevice,
    /// Scratch for inline SCSI IN responses. Cleared between CBWs.
    in_scratch: [u8; DISPATCH_IN_BUF_LEN],
    /// One-block bounce buffer for multi-block READ_10/WRITE_10.
    block_buf: [u8; MSC_BLOCK_BUF_BYTES],
    /// Pending SCSI sense data, reported by the host's next REQUEST SENSE
    /// (see `azos_msc::Sense`).
    sense: Sense,
}

impl MscGadget {
    /// Build a gadget bound to the current block device.
    pub fn new() -> Self {
        Self {
            state:      MscStateMachine::new(),
            lun:        Fat32BlockDevice::new(),
            in_scratch: [0u8; DISPATCH_IN_BUF_LEN],
            block_buf:  [0u8; MSC_BLOCK_BUF_BYTES],
            sense:      Sense::NONE,
        }
    }

    /// Reported capacity in 512-byte sectors. Exposed for the boot
    /// banner / future shell `msc status` command.
    pub fn capacity_sectors(&self) -> u32 {
        self.lun.block_count()
    }

    /// Drive the gadget once: parse the next 31-byte CBW arriving
    /// on bulk-OUT, execute, and pump the resulting data + CSW back
    /// out. Returns `true` when a CBW was handled (the endpoint
    /// pump should be re-entered immediately to fetch the next),
    /// `false` when the OUT endpoint is empty.
    ///
    /// In a real DWC2 driver this is called from the USB interrupt
    /// handler or a dedicated MSC task. Today the I/O calls are
    /// stubbed — see `bulk_out_read` / `bulk_in_write` below.
    pub fn pump_once(&mut self) -> bool {
        let mut cbw_buf = [0u8; CBW_TOTAL_LEN];
        let n = match bulk_out_read(&mut cbw_buf) {
            Some(n) => n,
            None => return false,
        };
        if n < CBW_TOTAL_LEN {
            // Short OUT packet — protocol error, recover via reset.
            self.state.set_phase(MscPhase::Reset);
            return true;
        }
        let action = dispatch_cbw(&cbw_buf, &self.lun, &mut self.in_scratch, &mut self.sense);
        match action {
            Action::InlineDone { in_len, csw } => {
                if in_len > 0 {
                    bulk_in_write(&self.in_scratch[..in_len]);
                }
                bulk_in_write(&csw);
                self.state.set_phase(MscPhase::Idle);
            }
            Action::ReadBlocks { start_lba, blocks, mut csw } => {
                // #13 (partially open in the 2026-09-25 audit, closed here):
                // `csw` is the dispatcher's OPTIMISTIC pre-encoded CSW
                // (computed before a single block is read — LBA range
                // validation is all it could check). It is a local array,
                // not yet on the wire: BBB sends the CSW strictly AFTER the
                // data-in phase (`bulk_in_write(&csw)` below runs after
                // `stream_read`), so a mid-transfer block-device error can
                // still flip the byte that matters before it goes out.
                // Without this, a failing SD card/virtio-blk read sent the
                // host zeroed blocks under a status byte that says OK —
                // silent data corruption reported as success.
                if !self.stream_read(start_lba, blocks) {
                    csw[CSW_TOTAL_LEN - 1] = CSW_STATUS_FAIL;
                    self.sense = Sense::READ_ERROR;
                }
                bulk_in_write(&csw);
                self.state.set_phase(MscPhase::Idle);
            }
            Action::WriteBlocks { start_lba, blocks, mut csw } => {
                // Same shape as #13's READ_10 fix above: a block the device
                // did not accept must not go out under CSW(OK). Before this,
                // `stream_write` discarded every `write_block` error, so a
                // host's later SYNCHRONIZE CACHE could answer GOOD over data
                // that never reached the device.
                if !self.stream_write(start_lba, blocks) {
                    csw[CSW_TOTAL_LEN - 1] = CSW_STATUS_FAIL;
                    self.sense = Sense::WRITE_ERROR;
                }
                bulk_in_write(&csw);
                self.state.set_phase(MscPhase::Idle);
            }
            Action::PhaseError => {
                azos_drv_sys::kwarn!("[msc] CBW phase error — stalling endpoints");
                self.state.set_phase(MscPhase::Reset);
            }
        }
        true
    }

    /// Bulk-IN pump for READ_10. Streams `blocks` × 512 bytes from
    /// `start_lba` via the kernel block driver, one block at a time
    /// to avoid kernel stack pressure.
    ///
    /// Returns `false` if ANY block failed to read — the caller (see #13's
    /// fix in `pump_once`) turns that into a CSW(FAIL) instead of CSW(OK).
    /// Still sends zeroed data for a failed block rather than aborting the
    /// data phase early: BBB commits to the transfer length in the CBW, and
    /// sending fewer bytes than declared is itself a protocol violation the
    /// host would have to recover from via reset — worse than "wrong status
    /// on well-formed zeros", which at least a checksum/CRC layer above can
    /// still catch.
    fn stream_read(&mut self, start_lba: u32, blocks: u16) -> bool {
        let mut ok = true;
        for i in 0..blocks {
            let lba = start_lba.wrapping_add(i as u32);
            if self.lun.read_block(lba, &mut self.block_buf).is_err() {
                self.block_buf.fill(0);
                ok = false;
            }
            bulk_in_write(&self.block_buf);
        }
        ok
    }

    /// Bulk-OUT pump for WRITE_10. Drains `blocks` × 512 bytes from
    /// the host into the kernel block driver, one block at a time.
    ///
    /// Returns `false` if any block was not written — a device error or an
    /// underrun — so the caller reports CSW(FAIL) with a MEDIUM ERROR
    /// sense instead of OK. Keeps draining after a device error: the host
    /// has committed to sending the whole transfer.
    fn stream_write(&mut self, start_lba: u32, blocks: u16) -> bool {
        let mut ok = true;
        for i in 0..blocks {
            let lba = start_lba.wrapping_add(i as u32);
            let n = bulk_out_read(&mut self.block_buf).unwrap_or(0);
            if n < MSC_BLOCK_BYTES {
                // Underrun — drop the rest; host will retry.
                return false;
            }
            if self.lun.write_block(lba, &self.block_buf).is_err() {
                ok = false;
            }
        }
        ok
    }
}

impl Default for MscGadget {
    fn default() -> Self { Self::new() }
}

// ── USB endpoint stubs ────────────────────────────────────────────
//
// The real implementation will live in `azos_drv_bus::usb_device`
// (DWC2 controller surface). Until that arrives, every endpoint call
// is a no-op that returns "no data" — pump_once() then short-circuits
// and the kernel idles normally.

/// Read up to `out.len()` bytes from the bulk-OUT endpoint into `out`.
/// Returns `Some(n)` with the number of bytes received (≤ out.len()),
/// or `None` if the endpoint is empty / not yet wired.
///
// TODO(hw): wire DWC2 controller here. Until hardware arrives this
// always returns None so `pump_once()` is a no-op.
fn bulk_out_read(_out: &mut [u8]) -> Option<usize> {
    None
}

/// Write `data.len()` bytes to the bulk-IN endpoint. No-op until
/// the DWC2 controller is wired.
///
// TODO(hw): wire DWC2 controller here.
fn bulk_in_write(_data: &[u8]) {
    // Intentionally empty — see module docs.
}

/// One-shot kernel-boot init. Brings up the USB device controller
/// (today: stubbed), then logs the reported capacity.
///
/// Safe to call even when no block device is present — capacity
/// will simply report 0 sectors and the gadget will respond FAIL
/// to any READ_10 / WRITE_10.
pub fn msc_gadget_init() {
    let g = MscGadget::new();
    kprintln!(
        "[msc] gadget ready: {} sectors x {} bytes (USB controller stubbed)",
        g.capacity_sectors(),
        MSC_BLOCK_BYTES,
    );
    // TODO(hw): register `g` with the DWC2 controller's class-driver
    // hook + start the bulk-OUT endpoint.  Today the gadget is
    // dropped here; pump_once() would be a no-op anyway.
}
