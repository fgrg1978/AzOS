// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Storage smokes: FAT32 journal barriers, MMC flush, and the partition row.

use crate::*;

/// Wave 7 (STOR): the FAT32 journal barriers under a power cut. Runs right
/// after mount — journal recovery has already run — and before anything
/// else writes the disk:
///   1. check `BARRIER.DAT`: absent, or exactly the old or the new contents,
///      with a sound chain (`fat32_check_root_chain`) and an idle journal;
///      one `[FATBARRIER] check: ...` line, or `[FATBARRIER] FAIL <why>`;
///   2. create it with the old contents, overwrite it with the new ones
///      (`fat32_write_file`: the create and the overwrite journal paths);
///   3. park, so no later write adds a flush.
/// Boot 1 of the gate row runs all three on a fresh image; every cut image
/// is then booted for step 1's verdict.
#[cfg(feature = "fat-barrier-smoke")]
pub(crate) fn fat_barrier_smoke() {
    const NAME: [u8; 11] = *b"BARRIER DAT";
    const OLD_LEN: usize = 1400; // 3 clusters of 512 B on the gate image
    const NEW_LEN: usize = 900;  // 2
    fn byte(seed: u8, i: usize) -> u8 { seed.wrapping_add((i % 251) as u8) }
    let mut old = [0u8; OLD_LEN];
    let mut new = [0u8; NEW_LEN];
    for (i, b) in old.iter_mut().enumerate() { *b = byte(0x11, i); }
    for (i, b) in new.iter_mut().enumerate() { *b = byte(0x77, i); }

    let journal_idle = azos_fs::fat32_journal_idle();
    match azos_fs::fat32_check_root_chain(&NAME) {
        Err(why) => kprintln!("[FATBARRIER] FAIL BARRIER.DAT chain unsound: {}", why),
        Ok(_) if !journal_idle => kprintln!("[FATBARRIER] FAIL journal record left after mount"),
        Ok(None) => kprintln!("[FATBARRIER] check: BARRIER.DAT absent, chain sound, journal idle"),
        Ok(Some((first, size))) => {
            let mut buf = [0u8; OLD_LEN];
            let n = if (size as usize) <= OLD_LEN {
                azos_fs::fat32_read_chain(first, &mut buf[..size as usize])
            } else { 0 };
            let got = &buf[..n];
            if n == size as usize && got == &old[..] {
                kprintln!("[FATBARRIER] check: BARRIER.DAT old, chain sound, journal idle");
            } else if n == size as usize && got == &new[..] {
                kprintln!("[FATBARRIER] check: BARRIER.DAT new, chain sound, journal idle");
            } else {
                kprintln!("[FATBARRIER] FAIL BARRIER.DAT holds {} of {} bytes, neither old nor new", n, size);
            }
        }
    }

    let a = azos_fs::fat32_write_file(&NAME, &old);
    let b = azos_fs::fat32_write_file(&NAME, &new);
    if a.is_err() || b.is_err() {
        kprintln!("[FATBARRIER] FAIL write: create {:?}, overwrite {:?}", a, b);
    } else {
        kprintln!("[FATBARRIER] wrote old then new");
    }
    kprintln!("[FATBARRIER] parked: no further disk I/O this boot");
    loop { core::hint::spin_loop(); }
}

/// Wave 7 (STOR): `mmc::mmc_flush` against QEMU's `sdhci-pci` + `sd-card`,
/// the only SDHCI-v3 host this tree can run `mmc.rs` on. Binds the driver
/// to the function's BAR 0, runs the SD init flow, then:
///   1. write one sector → flush must be `Ok` AND must have read at least
///      one CMD13 status (the evidence counter moves) → read back equal;
///   2. write a sector past the end of the card → flush must be `Err`;
///   3. flush again → `Ok` (the fault is reported once, then cleared).
/// Prints `[MMCSMOKE] PASS` or one `[MMCSMOKE] FAIL <why>` line.
#[cfg(feature = "mmc-flush-smoke")]
pub(crate) fn mmc_flush_smoke<C: azos_pci::ConfigSpace>(
    cfg: &mut C,
    funcs: &[Option<azos_pci::FunctionInfo>],
    window: &mut azos_pci::BarWindow,
) {
    use azos_drv_block::mmc::{self, MmcSlot};
    const SLOT: MmcSlot = MmcSlot::Sd;
    const LBA: u64 = 64;
    // 512 MiB: past the end of the gate's 64 MiB card, still a valid SDSC
    // byte address (fits the 32-bit CMD24 argument).
    const PAST_END: u64 = 1 << 20;

    let Some(sd) = funcs.iter().flatten().find(|f| f.vendor == 0x1b36 && f.device == 0x0007) else {
        kprintln!("[MMCSMOKE] FAIL no sdhci-pci function (1b36:0007) on bus 0");
        return;
    };
    let bars = match azos_drv_virtio::virtio::pci::msix_selftest::map_bars(cfg, sd, window) {
        Ok(b) if b[0] != 0 => b,
        Ok(_) => { kprintln!("[MMCSMOKE] FAIL sdhci-pci BAR 0 is not a memory BAR"); return; }
        Err(e) => { kprintln!("[MMCSMOKE] FAIL could not map sdhci-pci BARs: {:?}", e); return; }
    };
    kprintln!("[MMCSMOKE] sdhci-pci {} BAR0={:#x}", sd.bdf, bars[0]);
    mmc::mmc_bind_pci_bar(bars[0]);
    if !mmc::mmc_init(SLOT) {
        kprintln!("[MMCSMOKE] FAIL SD init flow did not complete");
        return;
    }

    let mut pat = [0u8; 512];
    for (i, b) in pat.iter_mut().enumerate() { *b = (i as u8) ^ 0x5A; }
    if mmc::mmc_write(SLOT, LBA, 1, &pat).is_err() {
        kprintln!("[MMCSMOKE] FAIL write of lba {} failed", LBA);
        return;
    }
    let (reads0, _) = mmc::mmc_flush_evidence();
    match mmc::mmc_flush(SLOT) {
        Ok(()) => {
            let (reads1, status) = mmc::mmc_flush_evidence();
            if reads1 == reads0 {
                kprintln!("[MMCSMOKE] FAIL flush answered Ok without reading the card status");
                return;
            }
            kprintln!("[MMCSMOKE] flush Ok after {} CMD13 read(s): status {:#010x} state={} ready={}",
                reads1 - reads0, status, (status >> 9) & 0xF, (status >> 8) & 1);
        }
        Err(e) => { kprintln!("[MMCSMOKE] FAIL flush after a good write: {:?}", e); return; }
    }
    let mut back = [0u8; 512];
    if mmc::mmc_read(SLOT, LBA, 1, &mut back).is_err() || back != pat {
        kprintln!("[MMCSMOKE] FAIL read-back of lba {} does not match what was written", LBA);
        return;
    }
    kprintln!("[MMCSMOKE] read-back of lba {} matches", LBA);

    let w = mmc::mmc_write(SLOT, PAST_END, 1, &pat);
    kprintln!("[MMCSMOKE] write past the card end answered {}", if w.is_ok() { "Ok" } else { "Err" });
    match mmc::mmc_flush(SLOT) {
        Ok(()) => {
            kprintln!("[MMCSMOKE] FAIL flush answered Ok over a write the card refused");
            return;
        }
        Err(e) => kprintln!("[MMCSMOKE] flush after the refused write: {:?}", e),
    }
    match mmc::mmc_flush(SLOT) {
        Ok(()) => kprintln!("[MMCSMOKE] flush after the fault was reported: Ok"),
        Err(e) => { kprintln!("[MMCSMOKE] FAIL flush stayed failed after reporting the fault: {:?}", e); return; }
    }
    kprintln!("[MMCSMOKE] PASS");
}

/// disk-part-row: prove a partition capability's out-of-range write is
/// RECORDED, not only refused (RFC-0048 P3's stage-0 row: "refused AND
/// recorded").
///
/// Waits for the refusal to happen (`DISK_SCOPE_REFUSALS` leaves 0 — the
/// counter only the partition-scope path bumps), then polls the flight
/// recorder for a `SAFETY_CAP_DENIED` record under `CapKind::Disk`. Only the
/// scope path can write that record on this boot: no other task holds a disk
/// capability or calls a disk syscall from ring 3.
#[cfg(feature = "disk-part-row")]
pub(crate) fn disk_part_row_task(_arg: usize) {
    const ATTEMPTS: u32 = 120;
    const INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 2;
    let disk = azos_abi::cap::CapKind::Disk.denial_code();
    let code = azos_actuation::logger::SAFETY_CAP_DENIED;
    let mut attempts = 0u32;
    let (mut found, mut records) = (false, 0u32);
    while attempts < ATTEMPTS && !found {
        attempts += 1;
        let dl = azos_drv_sys::timebase::now() + INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
        if azos_syscall::handlers::DISK_SCOPE_REFUSALS
            .load(core::sync::atomic::Ordering::Relaxed) == 0 {
            continue;
        }
        let _ = azos_actuation::logger::logger_flush();
        let (f, n) = find_safety_record_on_disk(code, disk);
        found = f;
        records = n;
    }
    let refusals = azos_syscall::handlers::DISK_SCOPE_REFUSALS
        .load(core::sync::atomic::Ordering::Relaxed);
    if found {
        kprintln!("[DISKPART] RECORDED: a Disk partition-scope refusal is in the persistent \
                   log ({} refusal(s) counted, {} records)", refusals, records);
    } else {
        kprintln!("[DISKPART] NOT RECORDED: {} refusal(s) counted, {} records on disk, none \
                   a Disk capability refusal", refusals, records);
    }
}
