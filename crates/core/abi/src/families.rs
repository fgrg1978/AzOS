// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The privileged families' operation selectors: the
//! recovery console's `flight`, `behavior`, `config` and `ota` commands, which
//! the kernel runs for the ring-3 tools too. The ring-3 form of each is an
//! interface (`azos_devif::{Flight, Behavior, Config, Ota}`) served by the
//! kernel on its own endpoint; the selectors below are what the kernel's
//! family hook ([`FamilyOps`](../../azos_syscall/families/trait.FamilyOps.html))
//! and the console both take.

// ── Flight ───────────────────────────────────────────────────────────────────

/// Arm the flight controller and the ESCs (`flight arm`). Needs `WRITE` on
/// the `flight` endpoint.
pub const FLIGHT_OP_ARM: u64 = 1;
/// Disarm (`flight disarm`). The same right as arming.
pub const FLIGHT_OP_DISARM: u64 = 2;

// ── Behavior ─────────────────────────────────────────────────────────────────

/// Enable subsumption layer `a2` (1..[`BEHAVIOR_LAYERS`]). Needs `WRITE`.
pub const BEHAVIOR_OP_ENABLE: u64 = 1;
/// Disable layer `a2` (1..[`BEHAVIOR_LAYERS`]). Needs `WRITE`.
pub const BEHAVIOR_OP_DISABLE: u64 = 2;
/// Read which layers are enabled: bit `n` for layer `n`; `a2` must be 0.
/// Needs `READ`.
pub const BEHAVIOR_OP_STATUS: u64 = 3;
/// Layers the behavior stack has; layer 0 (the safety reflex) cannot be
/// switched by either op, as on the console.
pub const BEHAVIOR_LAYERS: u64 = 4;

// ── Config ───────────────────────────────────────────────────────────────────

/// Copy the value of key `a2/a3` into the buffer `a4/a5`; returns its length
/// (`-ENOENT` for a key that is not set, `-EINVAL` for a buffer shorter than
/// the value). Needs `READ`.
pub const CONFIG_OP_GET: u64 = 1;
/// Set key `a2/a3` to the value `a4/a5` and apply the configuration, as the
/// console's `config set`. Needs `WRITE` for any key (the console checks only
/// `watchdog_ms`, and only under the lockdown).
pub const CONFIG_OP_SET: u64 = 2;
/// Longest key (bytes), `azos_config::MAX_KEY`.
pub const CONFIG_KEY_MAX: u64 = 24;
/// Longest value (bytes), `azos_config::MAX_VAL`.
pub const CONFIG_VAL_MAX: u64 = 48;

// ── Ota ──────────────────────────────────────────────────────────────────────

/// The boot slot state, packed in the return value: bits 0..8 the active
/// slot, 8..16 the last good slot, 16..32 the boot count, 32..40 the bad
/// slot mask (slots: 0 = A, 1 = B, 2 = recovery). Needs `READ`.
pub const OTA_OP_STATUS: u64 = 1;
/// Roll back to the last good slot (applies at the next boot), as the
/// console's `ota rollback`: 0 rolled back, 1 already on it (nothing done),
/// `-EACCES` when that slot failed secure-boot verification. Needs `WRITE`.
pub const OTA_OP_ROLLBACK: u64 = 2;
/// Switch to the whole-system set staged in the inactive slot (the installer,
/// `pkg update`, stages it; `azos_ota::ota_update_switch` verifies it again and
/// flips the one BOOTMETA record; it applies at the next boot and confirms or
/// rolls back with it). The value is the set's `sec_epoch`. `-EACCES` when the
/// set is not valid, not admissible or no update key is installed, `-EBUSY`
/// while another switch runs, `-EAGAIN` while this boot is not confirmed yet,
/// `-EIO` when the volume failed. Needs `WRITE`.
pub const OTA_OP_SWITCH: u64 = 3;

/// [`OTA_OP_STATUS`]'s word, unpacked: `(active, last_good, boot_count,
/// bad_slots)`.
pub const fn ota_status_unpack(w: u64) -> (u8, u8, u16, u8) {
    (w as u8, (w >> 8) as u8, (w >> 16) as u16, (w >> 32) as u8)
}

/// [`OTA_OP_STATUS`]'s word from its fields (`boot_count` saturates).
pub const fn ota_status_pack(active: u8, last_good: u8, boot_count: u32, bad_slots: u8) -> u64 {
    let bc = if boot_count > u16::MAX as u32 { u16::MAX as u64 } else { boot_count as u64 };
    active as u64 | (last_good as u64) << 8 | bc << 16 | (bad_slots as u64) << 32
}
