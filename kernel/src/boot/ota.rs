// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot validation: the crash counter, slot verification (CRC / secure boot),
//! and the hook that confirms a boot good.

use crate::*;

/// U05-5, unified: BOOTMETA's `boot_count` is the crash counter. Load the
/// consecutive unconfirmed boots `ota_boot_validate` read into
/// `wdt::CRASH_COUNTER` and hand the same number to the recovery-mode
/// decision (`azos_ota::recovery`). The count is cleared only by
/// `ota_mark_boot_good` (sys-wdt, after `OTA_BOOT_GOOD_DELAY_S`), which also
/// clears the in-memory copy.
fn boot_count_loaded(v: &azos_ota::BootValidation) {
    azos_drv_sys::wdt::crash_counter_set(v.prior_unconfirmed);
    kprintln!("[BOOTCNT] {} unconfirmed boot(s) before this one ({}); this boot {}",
        v.prior_unconfirmed,
        if v.fresh { "no BOOTMETA.A/.B record on this volume" } else { "BOOTMETA boot_count" },
        if v.recorded { "recorded as unconfirmed" } else { "could not be recorded" });
    // DEV02: the boot-loop trigger reads the running slot's unconfirmed
    // boots AFTER validation (this boot's count minus itself), not the count
    // as read: a rollback restarts the count at 1, so the rollback boot does
    // not arm, and only a slot with nothing left to roll back to does (the
    // sequence is in `crates/core/ota/src/pure.rs`). This board has no recovery
    // button input and BOOTMETA carries no user flag, so those two triggers
    // stay disarmed.
    let slot_crashes = v.meta.boot_count.saturating_sub(1);
    let reason = azos_ota::recovery::recovery_mode_should_enter(
        azos_ota::recovery::RecoveryInputs {
            crash_count: slot_crashes,
            recovery_button_held: None,
            bootmeta_user_flag: None,
        });
    // One decision, checked against the FSM's own verdict: the two share
    // their threshold (`RECOVERY_BOOT_LOOP_THRESHOLD` IS `max_attempts`), so a
    // mismatch means a runtime `max_attempts` other than the default.
    let exhausted = azos_ota::ota_boot_exhausted(&v.meta, v.max_attempts);
    if reason.should_enter() != exhausted {
        azos_drv_sys::kwarn!("[RECOVERY] WARNING: recovery decision {:?} disagrees with the OTA FSM \
                   ({:?}, max {}); entering safe mode on either",
                  reason, v.outcome, v.max_attempts);
    }
    if reason.should_enter() || exhausted {
        // Owner decision 2026-09-28: SAFE MODE. Every actuator path is held
        // from here on (`estop_is_active()` answers true for the whole boot,
        // and nothing clears it); autorun, the topology's ring-3 drivers and
        // the ML service are not started; sys-wdt does not confirm the boot
        // (`install_ota_boot_good_hook`), so the next boot is safe mode again
        // unless an OTA install writes a new active slot. Console and OTA
        // stay alive. Nothing is energised yet at this point in boot.
        azos_actuation::estop::safe_mode_enter();
        azos_drv_sys::kwarn!("[RECOVERY] armed: {:?} ({:?}, slot {} boot_count={}) -- SAFE MODE: actuators \
                   held, no ring-3 program started, console and OTA alive, boot not confirmed; \
                   waiting for a good image",
                  reason, v.outcome, azos_ota::ota_slot_char(v.meta.active_slot),
                  v.meta.boot_count);
    } else {
        kprintln!("[RECOVERY] not armed (crash count {})", slot_crashes);
    }
    // Owner decision 2026-09-28: an orderly reboot or power-off before the
    // boot is confirmed voids this boot's mark instead of counting as a
    // crash (`ota_void_unconfirmed_boot`). The shell calls it directly;
    // `sys_reboot`/`sys_shutdown` reach it through this hook.
    fn orderly_power_off() {
        let _ = azos_ota::ota_void_unconfirmed_boot();
        entropy_seed_refresh_at_power_off();
    }
    azos_syscall::handlers::set_orderly_power_hook(orderly_power_off);
    // Gate row `safe mode: attempts exhausted`: every boot that is NOT safe
    // mode crashes here, after its unconfirmed mark is written, so a fresh
    // volume walks the real sequence (1, 2, 3, then 4 = exhausted) on one
    // image.
    #[cfg(feature = "safe-mode-smoke")]
    if !azos_actuation::estop::safe_mode_active() {
        // A literal: the panic handler prints a message only when it has no
        // arguments to format. The count is on the `[OTA] Boot:` line above.
        panic!("safe-mode-smoke: deliberate crash before the boot is confirmed");
    }
    #[cfg(feature = "orderly-reboot-smoke")]
    ORDERLY_SMOKE_FRESH.store(v.fresh, core::sync::atomic::Ordering::Release);
    // Gate row `boot count: survives a crash`: on a volume with no dual
    // record, stop this boot the way a crashing driver would, after the
    // unconfirmed mark is written and long before sys-wdt could mark the
    // boot good. The next boot of the same volume finds a record and runs
    // on, so one image serves both boots.
    #[cfg(feature = "boot-count-smoke")]
    if v.fresh {
        panic!("boot-count-smoke: deliberate crash before the boot is confirmed clean");
    }
}

/// OTA boot validation + secure boot, shared by BOTH `kernel_main`s.
///
/// A/B slot selection and boot-loop detection (`ota_boot_validate`), the
/// CRC check of the active slot with its retrospective fall-back, the
/// Ed25519 signature gate (`secure_boot_verify_slot_detailed`), owner
/// decision 99's fall to the recovery slot, and the `bad_slots` record
/// for the slots this boot is NOT running.
///
/// This whole block used to live inline in riscv64's `kernel_main` and
/// aarch64's had none of it: an aarch64 board built with
/// `secure-boot-enforced` booted an unsigned slot without a word on the
/// console. Nothing in it is ISA-specific — `crates/core/ota` reads
/// `/fat/KERN_{A,B,R}.BIN`, `/fat/KERN_*.SIG` and `/fat/BOOTMETA` through
/// the VFS, and the one call that was riscv64-only (`sbi::reboot()`, which
/// does not exist on the aarch64 facade) now goes through `arch-api`'s
/// `Boot::reboot` so PSCI `SYSTEM_RESET` answers it on aarch64.
///
/// PRECONDITIONS, both ISAs — the caller owes all three:
///   1. the block device is up and FAT32 is mounted at `/fat` (every read
///      below is a `vfs_open`),
///   2. CONFIG.INI has been loaded/applied (this runs in the same boot
///      step, right after it, on both ISAs),
///   3. secondary harts are NOT running yet and no task has been created
///      — see the `IMG_BUF` note inside.
///
/// Returns nothing: no caller past this point reads the boot trust verdict
/// or the slot, they read the console (and, under `secure-boot-enforced`,
/// a rejected slot never returns from here at all).
pub(crate) fn boot_validate_and_verify_slots() {
    // `Boot::reboot` — owner decision 99's reset below. In scope here
    // rather than at the top of the file so the `#[cfg]`-gated body is
    // the only thing that needs it.
    #[cfg(feature = "secure-boot-enforced")]
    use azos_arch::Boot;

    // ── OTA boot validation (A/B slot + boot loop detection) ──────
    let validation = azos_ota::ota_boot_validate();
    let boot_meta = validation.meta;
    boot_count_loaded(&validation);

    // ── Verify CRC-32 of active firmware slot ─────────────────────
    let active_slot = boot_meta.active_slot;
    let slot_size = boot_meta.slot_size(active_slot);
    if slot_size > 0 {
        if azos_ota::ota_verify_slot(active_slot) {
            kprintln!("[OTA] Slot {} CRC OK (fw={}, size={})",
                azos_ota::ota_slot_char(active_slot),
                boot_meta.slot_version(active_slot), slot_size);
        } else {
            azos_drv_sys::kerr!("[OTA] ERROR: Slot {} CRC MISMATCH",
                azos_ota::ota_slot_char(active_slot));

            // ── Retrospective recovery: steer the NEXT boot away ────
            // from a corrupted active slot. This check runs from
            // inside `kernel_main` with the bootloader-loaded image
            // already executing in RAM — a bad CRC here cannot mean
            // "refuse to load", only "don't pick this slot again".
            // No reset is triggered: this may be a robot mid-motion
            // or a drone mid-flight, and the code that's running
            // right now works fine regardless of what's on disk.
            let last_good = boot_meta.last_good;
            if last_good != active_slot && azos_ota::ota_verify_slot(last_good) {
                // A different, CRC-verified last-known-good slot
                // exists — point the next boot at it and persist.
                let mut new_meta = boot_meta;
                new_meta.active_slot = last_good;
                azos_ota::ota_write_boot_meta(&new_meta);
                azos_ota::ota_apply_meta(&new_meta);
                azos_drv_sys::kerr!("[OTA] ERROR: switching NEXT boot to slot {} \
                           (last_good, CRC verified) — slot {} keeps \
                           running for the rest of this boot but will \
                           not be selected again",
                    azos_ota::ota_slot_char(last_good),
                    azos_ota::ota_slot_char(active_slot));
            } else if azos_ota::ota_verify_slot(azos_ota::SLOT_R) {
                // Neither `active_slot` nor `last_good` verified.
                // Last candidate: the immutable recovery slot R.
                //
                // BOOTMETA's `active_slot`/`last_good` fields can now
                // encode "r" (see `serialize_boot_meta`/
                // `parse_boot_meta` in `crates/core/ota/src/pure.rs`), and
                // `BootMeta` carries `image_size_r`/`image_crc_r` so R
                // can be CRC-verified exactly like A/B. In practice
                // this branch is only reachable once something
                // populates those `_r` fields — R is factory-flashed
                // and nothing in this codebase writes them today — but
                // when it is populated and verifies, steer the NEXT
                // boot at R and persist. As with the `last_good`
                // branch above: the image already running in RAM
                // keeps running for the rest of *this* boot; only the
                // next boot's selection changes. No reset is
                // triggered here either.
                let mut new_meta = boot_meta;
                new_meta.active_slot = azos_ota::SLOT_R;
                azos_ota::ota_write_boot_meta(&new_meta);
                azos_ota::ota_apply_meta(&new_meta);
                azos_drv_sys::kerr!("[OTA] ERROR: switching NEXT boot to slot R \
                           (recovery, CRC verified) — slot {} keeps \
                           running for the rest of this boot but will \
                           not be selected again",
                    azos_ota::ota_slot_char(active_slot));
            } else {
                // No BOOTMETA-selectable replacement exists: neither
                // `last_good` nor R (whose `image_size_r` is 0 on
                // every BOOTMETA in the field today, since nothing
                // populates it — see `SLOT_R` doc in
                // `crates/core/ota/src/pure.rs`) verified.
                //
                // `last_good == active_slot` means the last-known-good
                // pointer IS the corrupt slot — nothing to fall back
                // to. Otherwise `last_good`'s own CRC also failed.
                // Shout loudly and keep booting: the image in RAM is
                // already running.
                let last_good_status = if last_good == active_slot {
                    "== active slot, also corrupt"
                } else {
                    "CRC also failed"
                };
                azos_drv_sys::kerr!("[OTA] ERROR: no verified replacement slot \
                           available (last_good={} {}, R unverified or \
                           empty) — continuing boot on unverified slot \
                           {}; fix via OTA update or manual reflash",
                    azos_ota::ota_slot_char(last_good),
                    last_good_status,
                    azos_ota::ota_slot_char(active_slot));
            }
        }
    } else {
        kprintln!("[OTA] Slot {} — no firmware recorded",
            azos_ota::ota_slot_char(active_slot));
    }

    // ── Secure boot: Ed25519 signature verification (F18) ──────────
    //
    // Policy is fixed at COMPILE TIME by the `secure-boot-enforced`
    // cargo feature (Kconfig `SECURE_BOOT_ENFORCED`), never by a
    // runtime flag. `secure_boot_require_signature()` /
    // `secure_boot_set_require_signature()` exist in `secure_boot.rs`
    // for soft/advisory callers, but this boot gate deliberately does
    // NOT consult them: with the feature on, there must be no runtime
    // variable, debug build, or code path that can relax enforcement
    // — debug and release behave identically. Verification itself
    // always runs (even with the feature off) so the trust state is
    // always visible on the console; only the halt-on-failure part is
    // `#[cfg]`-gated.
    //
    // Single-hart, single-caller context ON BOTH ISAs, which is what
    // lets `secure_boot_verify_slot_detailed()`'s internal `static mut
    // IMG_BUF` (2 MiB, lives in `.bss`) be used without a lock: on
    // riscv64 the secondaries stay parked in OpenSBI HSM until
    // `smp_start_secondary_harts()` ("[SMP] Starting {} secondary
    // harts..."), on aarch64 until `wake_harts()`/PSCI `CPU_ON` — and
    // on both ISAs this function is called from `kernel_main` BEFORE
    // that bring-up and before any `task_create`. Moving either call
    // site past SMP bring-up breaks that invariant, so don't.
    let slot_char = azos_ota::ota_slot_char(active_slot);
    let (boot_trust, boot_trust_reason) =
        azos_ota::secure_boot_verify_slot_detailed(active_slot);
    kprintln!("[SECURE-BOOT] Slot {} signature: {} ({})",
        slot_char, boot_trust.as_str(), boot_trust_reason.as_str());

    #[cfg(feature = "secure-boot-enforced")]
    {
        if boot_trust != azos_ota::BootTrust::Verified {
            azos_drv_sys::kerr!("[SECURE-BOOT] FATAL: slot {} rejected — {} — \
                       secure-boot-enforced is compiled in, refusing to boot",
                slot_char, boot_trust_reason.as_str());

            // OWNER DECISION 99 — a rejected slot must not be the end of
            // the board. Before the fail-closed halt, try the one thing
            // that can still recover it unattended: point the NEXT boot at
            // the immutable recovery slot and reset, so U-Boot's
            // `active_slot = r` branch (tools/boot.cmd:32) loads
            // KERN_R.BIN.
            //
            // The halt below is NOT removed — it is what happens when the
            // fall is impossible. `secure_boot_steer_to_recovery` only
            // answers `Steered` when R carries a signature this build
            // trusts AND the steer read back off the volume, precisely so
            // that this reset cannot become a reset loop. Every other
            // answer lands on the same `wfi` as before, with the reason on
            // the console.
            //
            // A reset here is safe in a way it would not be later in boot:
            // secondary harts are still parked in OpenSBI HSM, no task
            // exists, and the only device touched so far is the FAT32
            // volume this function just flushed.
            match azos_ota::secure_boot_steer_to_recovery(active_slot) {
                azos_ota::RecoverySteer::Steered => {
                    azos_drv_sys::kerr!("[SECURE-BOOT] slot R verified — steering the \
                               next boot to the recovery slot and resetting");
                    azos_drv_sys::uart::console_flush_for_reboot();
                    azos_arch::ARCH.reboot();
                }
                azos_ota::RecoverySteer::AlreadyRecovery => {
                    azos_drv_sys::kerr!("[SECURE-BOOT] already running the recovery \
                               slot — nothing left to fall back to, halting");
                }
                azos_ota::RecoverySteer::RecoveryUnverified(r) => {
                    azos_drv_sys::kerr!("[SECURE-BOOT] recovery slot R unusable — {} \
                               — halting instead of resetting into it",
                        r.as_str());
                }
                azos_ota::RecoverySteer::SteerDidNotPersist => {
                    azos_drv_sys::kerr!("[SECURE-BOOT] recovery steer did not persist \
                               to BOOTMETA — halting instead of resetting \
                               into the same failure");
                }
            }
            loop { azos_arch::Cpu::wfi(&azos_arch::ARCH); }
        }

        // OWNER DECISION, 2026-09-19 — verify the slots we are NOT
        // running, and record the ones that fail so nothing can select
        // them later.
        //
        // The active slot verified, or we would have halted above. The
        // question this answers is a different one: is the slot a future
        // rollback would fall back to signed? `ota_boot_validate_pure`
        // used to roll back to `last_good` unconditionally, so an attacker
        // who writes the inactive slot and then induces a boot loop got
        // their image SELECTED. The verdict now gets written down, and
        // that branch consults it.
        //
        // THIS DOES NOT CLOSE F1 (the confused deputy — U-Boot picks the
        // slot from a file this kernel does not authenticate). An attacker
        // whose payload is executing never runs this code at all. F1
        // closes in the loader or not at all; see the 2c audit.
        //
        // Costs up to two extra image reads and two Ed25519 verifications
        // per boot, which is why it sits inside the enforced `cfg` and
        // runs after the refusal check rather than before it.
        {
            let others = azos_ota::secure_boot_verify_other_slots(active_slot);
            let mut meta = azos_ota::ota_read_boot_meta();
            let before = meta.bad_slots;
            for (i, verdict) in others.iter().enumerate() {
                let slot = i as u8;
                if let Some((trust, reason)) = verdict {
                    kprintln!("[SECURE-BOOT] Slot {} (inactive) signature: {} ({})",
                        azos_ota::ota_slot_char(slot),
                        trust.as_str(), reason.as_str());
                    // Only `Failed` brands a slot. `Unverified` also
                    // covers "no .SIG on the volume", which is what an
                    // *uninstalled* slot looks like — branding that would
                    // condemn a slot nobody has ever written.
                    if *trust == azos_ota::BootTrust::Failed {
                        meta.mark_slot_bad(slot);
                    }
                }
            }
            if meta.bad_slots != before {
                // Write FIRST, then say so, and say it from what the
                // volume returns. The line used to print before the
                // write, and the gate stops QEMU on this line: the pair
                // `records unfit B` / `unfit slot survives reboot` then
                // raced the kill against the write, and gate 143 lost
                // (second boot read `bad_slots=0x00`). A marker that
                // claims durability has to come after it, read back.
                azos_ota::ota_write_boot_meta(&meta);
                azos_ota::ota_apply_meta(&meta);
                let stored = azos_ota::ota_read_boot_meta().bad_slots;
                if stored == meta.bad_slots {
                    kprintln!("[SECURE-BOOT] unfit slot(s) recorded, mask {:#04x} — \
                               a rollback will not select them",
                        stored);
                } else {
                    azos_drv_sys::kerr!("[SECURE-BOOT] FAILED: unfit mask {:#04x} did not \
                               reach the volume (read back {:#04x})",
                        meta.bad_slots, stored);
                }
            }
        }
    }
    #[cfg(not(feature = "secure-boot-enforced"))]
    {
        if boot_trust != azos_ota::BootTrust::Verified {
            azos_drv_sys::kwarn!("[SECURE-BOOT] WARNING: slot {} not verified — {} \
                       (secure-boot-enforced not compiled in — booting anyway)",
                slot_char, boot_trust_reason.as_str());
        }
    }
}

/// Hand `sys-wdt` the OTA boot-good mark. Both ISAs, one call site each.
///
/// `domains/robot/safety-core` is core and `crates/core/ota` is scaffolding, so the
/// watchdog cannot name `ota_mark_boot_good` itself; the kernel links both
/// sides and installs the pair here. Without it the boot is NEVER marked
/// good: `BOOTMETA`'s `boot_count` only climbs, and on the boot after
/// `CFG_OTA_MAX_BOOT_ATTEMPTS` unmarked boots `ota_boot_validate` rolls the
/// active slot back to `last_good` — and then does it again, forever, because
/// the slot it rolls back to cannot mark itself good either.
///
/// Must run BEFORE `create_sys_wdt_task` spawns the task. Not a hard
/// requirement of `sys_wdt` (it re-reads the hook every pass and marks on the
/// first pass after an install), but the ordering is what makes "installed"
/// mean "installed before anything could have needed it".
pub(crate) fn install_ota_boot_good_hook() {
    // Safe mode: the boot is never confirmed. Marking it good would set
    // `last_good` to the image that exhausted its attempts, reset the count
    // and advance the anti-rollback floor — and the next boot would run it
    // normally and crash-loop again. The count stays raised; an OTA install
    // is what clears it.
    if azos_actuation::estop::safe_mode_active() {
        azos_drv_sys::kwarn!("[SAFE-MODE] boot-good mark withheld: sys-wdt will not confirm this boot \
                   (BOOTMETA boot_count stays raised until an OTA install)");
        return;
    }
    azos_actuation::sys_wdt::set_boot_good_hook(
        azos_ota::OTA_BOOT_GOOD_DELAY_S, azos_ota::ota_mark_boot_good);
}
