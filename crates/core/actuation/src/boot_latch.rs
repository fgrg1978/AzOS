// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The e-stop latch restored at boot. The kernel owns the FAT32 replay and
//! `logger_init`; it calls `apply` before `logger_init` and `record` after.

use crate::logger::{BootLatch, BootReplay};
use azos_drv_sys::kprintln;

/// Report the replayed latch, activate the e-stop if it latches, seed the
/// operator-release nonce floor, and seed the serial the new session's
/// `logger_init` will open — all three answers `logger::replay_boot`'s
/// single scan produces (owner decision, 2026-09-26; the nonce floor and
/// the serial used to not exist, and the latch used to be the only thing
/// this scan was for). Call before `logger_init`, same ordering the old
/// latch-only `apply` already required.
pub fn apply(replay: BootReplay) {
    match replay.latch {
        BootLatch::NoRecord =>
            kprintln!("[SAFETY] no flight recorder on this disk — booting released"),
        BootLatch::Released =>
            kprintln!("[SAFETY] the last session ended released — booting released"),
        BootLatch::Armed(action) =>
            azos_drv_sys::kwarn!("[SAFETY] ESTOP restored: the last session ended latched (action {})", action),
        BootLatch::Unreadable =>
            azos_drv_sys::kwarn!("[SAFETY] ESTOP restored: the flight recorder could not be read — failing safe"),
    }
    // A number read back, not just a claim: the gate row for "boot 2 resumes
    // the previous session's serial, not 0" greps this line, and the
    // release-nonce floor is visible here for the same reason — both are
    // otherwise invisible state that only mattered the moment a bug in
    // `replay_boot` or its seeding shipped silently.
    kprintln!(
        "[SAFETY] flight recorder resuming at serial {} (release nonce floor {})",
        replay.next_serial, replay.release_nonce_floor,
    );
    if replay.latch.latches() {
        crate::estop::estop_activate();
    }
    // Seeded BEFORE `operator_authority_init` can accept a key and BEFORE
    // `logger_init` opens anything — see `safety::RELEASE_NONCE_FLOOR`'s and
    // `logger::logger_seed_next_serial`'s docs for why each ordering
    // matters. `fetch_max`-based on the safety side, so seeding here is
    // always safe even if a future caller seeds it again.
    crate::estop::release_nonce_floor_seed(replay.release_nonce_floor);
    crate::logger::logger_seed_next_serial(replay.next_serial);
}

/// Record a restored latch durably. Call after `logger_init`.
pub fn record(boot_latch: BootLatch) {
    // The restore is a stop and is recorded like one: it is the
    // record the NEXT boot reads if nobody clears this one.
    if boot_latch.latches() {
        let detail = match boot_latch {
            BootLatch::Armed(action) => action as u32,
            _ => crate::logger::ESTOP_RESTORED_UNREADABLE,
        };
        let _ = crate::logger::log_safety_violation_durable(
            crate::logger::SAFETY_ESTOP,
            crate::logger::ESTOP_ACTION_RESTORED, detail);
    }
}
