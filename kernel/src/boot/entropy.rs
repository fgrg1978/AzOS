// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot-time entropy: the pool, the stack canary, and the persisted seed.

use crate::*;

/// Seed the kernel's entropy pool from virtio-rng. Shared between both
/// `kernel_main`s (riscv64 had this in place; aarch64 never called it, so
/// on that ISA the pool stayed unseeded on every boot — the TCP ISN secret,
/// DHCP/DNS/NTP ids and link keys fell back to their runtime-counter paths
/// **in silence**, and the stack canary stayed fixed).
///
/// Must run before everything that draws from the pool (and before
/// [`install_entropy_seed`], which adds the persisted seed once the block
/// device is up): the link envelope's send nonce (`auth_envelope::init`, CONFIG phase, riscv64 only today),
/// the TCP ISN secret (`net_init`), the DHCP/DNS/NTP ids, the ephemeral
/// link keys, and the stack canary, which must be set before the first task
/// exists. riscv64 calls this right before `blkdev::init()`; aarch64 calls
/// it in the same relative position — right before ITS `blkdev::init()` —
/// but after `map_mmio_region()`, because on this ISA the VirtIO-MMIO
/// transport window is not live until that call runs (riscv64 has no
/// equivalent runtime mapping step). No device — every board today, and a
/// QEMU run without `-device virtio-rng-device` — leaves the pool unseeded
/// and each consumer on its counter path. A device that answers the probe
/// and then does not deliver is a failure.
pub(crate) fn install_entropy() {
    use azos_drv_virtio::virtio::rng::{read_seed, SeedRead};
    let mut seed = [0u8; crate::boot::entropy_pool::POOL_SEED_BYTES];
    match read_seed(&mut seed) {
        SeedRead::Read(n) => {
            crate::boot::entropy_pool::pool_mix(&seed[..n], true);
            kprintln!("[ENTROPY] pool seeded: {} bytes from virtio-rng", n);
        }
        SeedRead::NotPresent => azos_drv_sys::kwarn!(
            "[ENTROPY] pool unseeded: no entropy device; ids, ISN secret and link keys \
             use runtime counters, stack canary fixed"),
        SeedRead::Failed(why) => azos_drv_sys::kerr!(
            "[ENTROPY] FAILED: virtio-rng present, pool unseeded ({})", why),
    }
    for b in seed.iter_mut() { *b = 0; }
    azos_net::set_random_source(crate::boot::entropy_pool::pool_fill);
    // Wave 9 (P9): ring 3's door onto the same pool (`SYS_ENTROPY_READ_TYPED`,
    // `crates/core/syscall/src/entropy.rs`). Installed here, after the seed read,
    // so the first ring-3 caller sees this boot's final seeded state.
    azos_syscall::entropy::set_entropy_hooks(
        crate::boot::entropy_pool::pool_fill,
        crate::boot::entropy_pool::record_ring3_unseeded_refusal,
    );
}

/// Draw the stack canary from the entropy pool, if it is seeded. Shared
/// between both `kernel_main`s; runs right after [`install_entropy_seed`]
/// (which runs right after `blkdev::init()`), so that on a board whose only
/// entropy is the persisted seed the canary comes from it too. It must still
/// be before the first task exists (`set_stack_canary` refuses otherwise);
/// both `kernel_main`s create their first task well after the block device
/// is up.
pub(crate) fn install_stack_canary() {
    let mut c = [0u8; 8];
    if crate::boot::entropy_pool::pool_fill(&mut c) {
        if azos_sched::scheduler::set_stack_canary(u64::from_le_bytes(c)) {
            kprintln!("[SEC] Stack canary drawn from the entropy pool");
        } else {
            azos_drv_sys::kerr!("[SEC] Stack canary FAILED: pool seeded but the canary was refused \
                       (a task already exists, or it was already set)");
        }
    }
    for b in c.iter_mut() { *b = 0; }
}

/// Whether the persisted-seed sector may be read and written on this boot's
/// medium: set by [`install_entropy_seed`] once the tail check passed, read by
/// the orderly power-off refresh.
static ENTROPY_SEED_STORE_USABLE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Write a seed record to the reserved sector and flush. `Ok(true)`: written
/// and flushed; `Ok(false)`: written, the device cannot confirm a flush;
/// `Err`: the write or the flush failed.
fn entropy_seed_store(rec: &[u8]) -> Result<bool, ()> {
    crate::msc_gadget::reserved_region_write(
        crate::msc_gadget::RESERVED_SECTOR_ENTROPY_SEED, rec)?;
    match azos_drv_block::blkdev::flush() {
        Ok(()) => Ok(true),
        Err(azos_drv_api::block::FlushError::Unsupported) => Ok(false),
        Err(_) => Err(()),
    }
}

/// Persisted entropy seed (U09-8, owner decision 2026-09-26 V1.2; wired in
/// wave 11): read the seed sector from the reserved tail
/// (`msc_gadget::RESERVED_SECTOR_ENTROPY_SEED`), mix it into the pool, and
/// IMMEDIATELY overwrite it with a fresh record drawn from the pool, so a seed
/// is never used twice even if this boot crashes a moment later.
///
/// **Order.** Runs right after `blkdev::init()` in the shared `kernel_main`,
/// before the stack canary, the TCP ISN secret (`net_init`), the link envelope
/// nonce (`auth_envelope::init`) and every handshake draw from the pool. The
/// mix and the derivation of the replacement happen in one lock hold
/// (`pool_apply_persisted_seed`), and the durable line is printed only after the
/// write and the flush returned.
///
/// **Credit.** The seed is credited only when no other source has seeded the
/// pool (see `Pool::apply_persisted_seed`).
///
/// **Where.** The reserved tail, not a FAT file: the tail is not reachable
/// from the USB MSC export, and this seed is the only entropy a board with no
/// TRNG has. The tail is only touched when no partition and no FAT32 volume
/// reaches it (`seed_tail_check`): a rewrite on every boot must not land in
/// filesystem data on an image built without the headroom.
///
/// No block device, no usable tail, or no valid record on an unseeded pool:
/// the boot proceeds exactly as it did before this step existed, and says so
/// on one line.
pub(crate) fn install_entropy_seed() {
    use crate::boot::entropy_pool as el;
    use crate::msc_gadget::{MSC_RESERVED_TAIL_SECTORS, RESERVED_SECTOR_ENTROPY_SEED};

    let cap = azos_drv_block::blkdev::capacity_sectors();
    if cap == 0 {
        kprintln!("[ENTROPY] persisted seed: no block device — pool as before (diskless)");
        return;
    }
    let mut s0 = [0u8; 512];
    if azos_drv_block::blkdev::read(0, 1, &mut s0).is_err() {
        kprintln!("[ENTROPY] persisted seed: skipped — sector 0 unreadable; pool as before");
        return;
    }
    let mut parts = [(0u64, 0u64); 16];
    let mut np = 0usize;
    for i in 0..azos_drv_block::partition::count().min(parts.len() as u32) {
        if let Some(p) = azos_drv_block::partition::partition(i) {
            parts[np] = p;
            np += 1;
        }
    }
    let tail = el::seed_tail_check(cap, u64::from(MSC_RESERVED_TAIL_SECTORS), &parts[..np], &s0);
    if tail != el::SeedTail::Clear {
        kprintln!("[ENTROPY] persisted seed: skipped — reserved tail not usable ({:?}: the \
                   image has no headroom past its filesystem); pool as before", tail);
        return;
    }
    let mut sector = [0u8; 512];
    if crate::msc_gadget::reserved_region_read(RESERVED_SECTOR_ENTROPY_SEED, &mut sector).is_err() {
        kprintln!("[ENTROPY] persisted seed: skipped — reserved sector {} unreadable; pool as before",
                  RESERVED_SECTOR_ENTROPY_SEED);
        return;
    }
    ENTROPY_SEED_STORE_USABLE.store(true, core::sync::atomic::Ordering::Release);

    let mut r = el::pool_apply_persisted_seed(&sector);
    for b in sector.iter_mut() { *b = 0; }
    match r.load {
        el::SeedLoad::Absent => kprintln!(
            "[ENTROPY] persisted seed: no valid record in reserved sector {} (absent, short or \
             corrupt) — nothing mixed", RESERVED_SECTOR_ENTROPY_SEED),
        el::SeedLoad::Credited => kprintln!(
            "[ENTROPY] persisted seed: mixed {} bytes, credited (no other source) — pool seeded",
            el::SEED_FILE_SEED_BYTES),
        el::SeedLoad::Stirred => kprintln!(
            "[ENTROPY] persisted seed: mixed {} bytes, not credited (pool already seeded)",
            el::SEED_FILE_SEED_BYTES),
    }
    match r.fresh.take() {
        None => kprintln!(
            "[ENTROPY] persisted seed: pool unseeded — nothing honest to write; sector left as found"),
        Some(mut rec) => {
            match entropy_seed_store(&rec) {
                Ok(true) => kprintln!(
                    "[ENTROPY] persisted seed: rewritten and flushed ({} bytes) — the seed just \
                     read will not be used again", el::SEED_FILE_BYTES),
                Ok(false) => kprintln!(
                    "[ENTROPY] persisted seed: rewritten, flush unsupported by the device \
                     (durability unconfirmed)"),
                Err(()) => azos_drv_sys::kerr!(
                    "[ENTROPY] persisted seed: REWRITE FAILED — the seed just read is still on \
                     the medium and will be read again"),
            }
            for b in rec.iter_mut() { *b = 0; }
        }
    }
}

/// Orderly power-off / reboot: replace the seed with fresh pool output so the
/// next boot starts from this boot's state. Best-effort, and only when this
/// boot found the tail usable and the pool is seeded. Never called on a crash
/// path (a crashed boot's seed was already replaced at boot).
pub(crate) fn entropy_seed_refresh_at_power_off() {
    if !ENTROPY_SEED_STORE_USABLE.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    match crate::boot::entropy_pool::pool_next_seed_record() {
        None => kprintln!("[ENTROPY] persisted seed: pool unseeded at power-off — not refreshed"),
        Some(mut rec) => {
            match entropy_seed_store(&rec) {
                Ok(true) => kprintln!(
                    "[ENTROPY] persisted seed: refreshed and flushed at orderly power-off"),
                Ok(false) => kprintln!(
                    "[ENTROPY] persisted seed: refreshed at orderly power-off, flush unsupported \
                     (durability unconfirmed)"),
                Err(()) => azos_drv_sys::kerr!(
                    "[ENTROPY] persisted seed: power-off refresh FAILED — the seed written at \
                     boot stays"),
            }
            for b in rec.iter_mut() { *b = 0; }
        }
    }
}
