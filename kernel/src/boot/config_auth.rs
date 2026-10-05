// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CONFIG.INI under its signed authority, at boot (Phase G2).
//!
//! `CONFIG.INI` decides whether the kill switch is armed, whether the brain
//! link is encrypted, whether an OTA listener spawns, whether the board halts
//! into `bench_boot`, and which ELF `autorun` hands the drivetrain to — on a
//! USB-exposed FAT volume. It is loaded only if `CONFIG.SIG` (format v2,
//! `azos_topology::verify_config_sig_v2`) verifies against the embedded
//! key for THIS device's id with a counter no lower than the floor in the
//! device record (reserved tail sector `RESERVED_SECTOR_DEVICE`).
//!
//! What happens otherwise is `azos_config::config_authority_decision`'s
//! answer, a pure function the host suite covers:
//!
//! * nothing signed was ever accepted on this device (no record, or floor 0):
//!   factory defaults, kill switch pin forced to the fail-closed value — the
//!   behaviour before wave 11;
//! * a signed CONFIG.INI WAS accepted here before (floor >= 1) and its
//!   authority is gone now — the file or its sidecar deleted, tampered, an
//!   older counter (replay), another device's sidecar, a v1 sidecar: factory
//!   defaults AND the e-stop latched, with a durable `SAFETY_ESTOP` record
//!   (action `ESTOP_ACTION_CONFIG_AUTHORITY`). Deleting `CONFIG.SIG` can no
//!   longer leave a provisioned machine running with an unconfigured kill
//!   switch and nothing but a boot-log line to say so.

use azos_config::{ConfigDecision, ConfigSigCheck, DeviceFloor};
use azos_drv_sys::kprintln;
use azos_topology::device_record::DeviceRecord;

/// Largest CONFIG.SIG read; a v2 sidecar is 96 bytes, so anything longer
/// reads as the wrong length and is refused as malformed.
const SIG_READ_MAX: usize = 128;

/// Is the reserved tail writable on this boot's medium: no partition and no
/// FAT32 volume reaches it (`seed_tail_check`, the test the entropy seed uses
/// before it rewrites its own sector).
fn tail_writable() -> bool {
    use crate::boot::entropy_pool as el;
    let cap = azos_drv_block::blkdev::capacity_sectors();
    if cap == 0 {
        return false;
    }
    let mut s0 = [0u8; 512];
    if azos_drv_block::blkdev::read(0, 1, &mut s0).is_err() {
        return false;
    }
    let mut parts = [(0u64, 0u64); 16];
    let mut np = 0usize;
    for i in 0..azos_drv_block::partition::count().min(parts.len() as u32) {
        if let Some(p) = azos_drv_block::partition::partition(i) {
            parts[np] = p;
            np += 1;
        }
    }
    let tail = u64::from(crate::msc_gadget::MSC_RESERVED_TAIL_SECTORS);
    el::seed_tail_check(cap, tail, &parts[..np], &s0) == el::SeedTail::Clear
}

/// The device record, or `None` (no usable tail, unreadable, or no valid
/// record).
fn read_device_record() -> Option<DeviceRecord> {
    if !tail_writable() {
        return None;
    }
    let mut sector = [0u8; 512];
    crate::msc_gadget::reserved_region_read(crate::msc_gadget::RESERVED_SECTOR_DEVICE, &mut sector).ok()?;
    DeviceRecord::decode(&sector)
}

/// Raise the floor to `counter` and flush. The config is already loaded when
/// this runs; a failed write leaves the old floor, which only means an older
/// signed file stays acceptable until a later boot raises it.
fn write_floor(rec: DeviceRecord, counter: u64) {
    let new = DeviceRecord { floor: counter, ..rec };
    let ok = crate::msc_gadget::reserved_region_write(
        crate::msc_gadget::RESERVED_SECTOR_DEVICE, &new.encode()).is_ok()
        && !matches!(azos_drv_block::blkdev::flush(),
                     Err(e) if e != azos_drv_api::block::FlushError::Unsupported);
    if ok {
        kprintln!("[CFG] config counter floor raised {} -> {}", rec.floor, counter);
    } else {
        azos_drv_sys::kerr!("[CFG] WARNING: config counter floor NOT raised ({} -> {}): the device \
                   record write failed; an older signed CONFIG.INI stays acceptable", rec.floor, counter);
    }
}

/// Latch the e-stop because the config authority this device had is gone, and
/// record it durably. The flight recorder is armed before Phase G2
/// (`install_flight_recorder`), so the record is written here, at once.
fn latch_for_lost_authority(reason: azos_config::AuthorityLoss) {
    azos_actuation::estop::estop_activate();
    azos_drv_sys::kerr!("[CFG] E-STOP LATCHED: config authority lost ({}) on a device that accepted a \
               signed CONFIG.INI before — estop_is_active={}",
        reason.as_str(), azos_actuation::estop::estop_is_active() as u8);
    match azos_actuation::logger::log_safety_violation_durable(
        azos_actuation::logger::SAFETY_ESTOP,
        azos_actuation::estop::ESTOP_ACTION_CONFIG_AUTHORITY,
        reason.code(),
    ) {
        Ok(n) => azos_drv_sys::kwarn!("[CFG] config-authority stop recorded ({} record(s) flushed)", n),
        Err(_) => azos_drv_sys::kerr!("[CFG] config-authority stop NOT recorded: the flight recorder \
                             is unavailable — this line is the only record"),
    }
}

/// The policy's view of a sidecar check.
fn check_of(r: Result<u64, azos_topology::ConfigSigError>) -> ConfigSigCheck {
    use azos_topology::ConfigSigError as E;
    match r {
        Ok(c) => ConfigSigCheck::Valid(c),
        Err(E::V1Format) => ConfigSigCheck::V1,
        Err(E::BadFormat) => ConfigSigCheck::BadFormat,
        Err(E::WrongDevice) => ConfigSigCheck::WrongDevice,
        Err(E::InvalidSignature) => ConfigSigCheck::BadSignature,
    }
}

/// Phase G2's CONFIG.INI load. Leaves the store loaded (verified) or at the
/// factory defaults, and the kill-switch report printed.
pub(crate) fn load_signed_config() {
    static mut CFG_BUF: [u8; 1024] = [0u8; 1024];
    static mut CFG_SIG_BUF: [u8; SIG_READ_MAX] = [0u8; SIG_READ_MAX];
    // SAFETY: Phase G2 runs once, on the boot hart, before any other task.
    let buf = unsafe { &mut *(&raw mut CFG_BUF) };
    let sig_buf = unsafe { &mut *(&raw mut CFG_SIG_BUF) };
    let mut fd_table = azos_fs::ScratchFds::new();

    let rec = read_device_record();
    let floor = match rec {
        Some(r) => {
            kprintln!("[CFG] device {:02x}{:02x}{:02x}{:02x}.. config counter floor {}",
                r.device_id[0], r.device_id[1], r.device_id[2], r.device_id[3], r.floor);
            DeviceFloor::Provisioned(r.floor)
        }
        None => {
            kprintln!("[CFG] no device record in the reserved tail — device not provisioned, \
                       no CONFIG.INI can be trusted (tools/device_provision.py)");
            DeviceFloor::Unprovisioned
        }
    };

    let fd = azos_fs::vfs_open(&mut fd_table, b"/fat/CONFIG.INI", azos_fs::O_RDONLY);
    let mut n = 0usize;
    if fd >= 0 {
        let r = azos_fs::vfs_read(&mut fd_table, fd, buf.as_mut_ptr(), buf.len());
        azos_fs::vfs_close(&mut fd_table, fd);
        n = if r > 0 { r as usize } else { 0 };
    }
    let ini = &buf[..n];

    let check = if n == 0 {
        ConfigSigCheck::NoIni
    } else {
        let sfd = azos_fs::vfs_open(&mut fd_table, b"/fat/CONFIG.SIG", azos_fs::O_RDONLY);
        if sfd < 0 {
            ConfigSigCheck::NoSig
        } else {
            let sn = azos_fs::vfs_read(&mut fd_table, sfd, sig_buf.as_mut_ptr(), sig_buf.len());
            azos_fs::vfs_close(&mut fd_table, sfd);
            let sidecar = &sig_buf[..if sn > 0 { sn as usize } else { 0 }];
            match rec {
                None => ConfigSigCheck::NoDeviceId,
                Some(r) => check_of(azos_topology::verify_config_sig_v2(
                    ini, sidecar, &r.device_id, &azos_topology::TRUSTED_PUBKEY)),
            }
        }
    };

    match azos_config::config_authority_decision(floor, check) {
        ConfigDecision::Load { counter, raise_floor } => {
            match azos_config::cfg_load_verified(ini, true) {
                azos_config::ConfigTrust::Verified => {
                    kprintln!("[CFG] /fat/CONFIG.SIG v2 verified (counter {}) — loaded {} entries",
                        counter, azos_config::cfg_count());
                    if raise_floor {
                        if let Some(r) = rec { write_floor(r, counter); }
                    }
                }
                azos_config::ConfigTrust::Rejected(e) => {
                    azos_drv_sys::kwarn!("[CFG] WARNING: /fat/CONFIG.INI repeats the key '{}' — \
                               refused as ambiguous, fell back to factory \
                               defaults (kill switch forced to pin {}, no OTA \
                               listener, no bench_boot, autorun refused)",
                        core::str::from_utf8(e.key()).unwrap_or("?"),
                        azos_config::ESTOP_GPIO_PIN_FAIL_CLOSED);
                    if let Some(loss) = azos_config::config_after_rejected(floor) {
                        latch_for_lost_authority(loss);
                    }
                }
                azos_config::ConfigTrust::FailClosed => {
                    // Not reachable with non-empty verified bytes; said for
                    // completeness rather than left as a silent arm.
                    azos_drv_sys::kwarn!("[CFG] WARNING: verified CONFIG.INI was empty — factory defaults");
                }
            }
        }
        ConfigDecision::Defaults(azos_config::AuthorityLoss::NoIni) => {
            azos_config::cfg_load_verified(&[], false);
            if fd < 0 {
                kprintln!("[CFG] /fat/CONFIG.INI not found — first boot, generating defaults");
            } else {
                kprintln!("[CFG] /fat/CONFIG.INI empty — generating defaults");
            }
        }
        ConfigDecision::Defaults(reason) => {
            azos_config::cfg_load_verified(&[], false);
            azos_drv_sys::kwarn!("[CFG] WARNING: CONFIG.INI not trusted ({}) — fell back to factory \
                       defaults (kill switch forced to pin {}, no OTA listener, no \
                       bench_boot, autorun refused)",
                reason.as_str(), azos_config::ESTOP_GPIO_PIN_FAIL_CLOSED);
        }
        ConfigDecision::LatchEstop(reason) => {
            azos_config::cfg_load_verified(&[], false);
            azos_drv_sys::kwarn!("[CFG] REFUSED: CONFIG.INI not trusted ({}) — fell back to factory \
                       defaults (kill switch forced to pin {}, no OTA listener, no \
                       bench_boot, autorun refused)",
                reason.as_str(), azos_config::ESTOP_GPIO_PIN_FAIL_CLOSED);
            if let ConfigSigCheck::Valid(c) = check {
                if let DeviceFloor::Provisioned(f) = floor {
                    azos_drv_sys::kwarn!("[CFG] REPLAY: CONFIG.SIG counter {} is below the floor {}", c, f);
                }
            }
            latch_for_lost_authority(reason);
        }
    }
    azos_actuation::kill_switch::report_config();

    if n == 0 && fd < 0 {
        // First boot: write factory defaults so the next boot finds a file.
        // NOTE: written WITHOUT a .SIG — the kernel never holds the signing
        // key. The next boot therefore takes the untrusted branch again,
        // which re-derives the same defaults; on a device that already
        // accepted a signed file it latches, as an absent file does now.
        let w = azos_config::cfg_serialize(buf);
        if w > 0 {
            let wfd = azos_fs::vfs_open(&mut fd_table, b"/fat/CONFIG.INI",
                azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
            if wfd >= 0 {
                let written = azos_fs::vfs_write(&mut fd_table, wfd, buf.as_ptr(), w);
                azos_fs::vfs_close(&mut fd_table, wfd);
                kprintln!("[CFG] Wrote {} bytes to /fat/CONFIG.INI (factory defaults)", written);
            }
        }
    }
}
