// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The privileged families' typed calls (RFC-0055 S5, wave 12): the ring-3
//! forms of the recovery console's `flight`, `behavior`, `config` and `ota`
//! commands, one call per family, each with its tool image (`FLIGHT.ELF`,
//! `BEHAVIOR.ELF`, `CONFIG.ELF`, `OTA.ELF`). The capability is `a0` and is
//! checked FIRST, before the operation is decoded; a refusal is recorded
//! (`SAFETY_CAP_DENIED_TYPED`). What each operation needs is
//! `azos_ipc::authority_policy::{flight,behavior,config,ota}_op_need`,
//! from the same table the console checks its commands against.
//!
//! The scheduler family has no call of its own: `SYS_POWER_TYPED` (614)
//! already carries `sched_hz` (`POWER_OP_SCHED_HZ_GET`/`_SET`).

// ── SYS_FLIGHT_TYPED (615): a0 = Cap<Motor>, a1 = op ─────────────────────────

/// Arm the flight controller and the ESCs (`flight arm`). Needs `WRITE` on
/// the presented `Cap<Motor>` AND the caller's table holding `WRITE` on both
/// wheels of the drivetrain — the console's check, and every pair-wide
/// actuation call's.
pub const FLIGHT_OP_ARM: u64 = 1;
/// Disarm (`flight disarm`). The same capability as arming.
pub const FLIGHT_OP_DISARM: u64 = 2;

// ── SYS_BEHAVIOR_TYPED (616): a0 = Cap<Power>, a1 = op, a2 = layer ──────────

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

// ── SYS_CONFIG_TYPED (617): a0 = Cap<Power>, a1 = op, a2 = key ptr,
//    a3 = key len, a4 = value ptr, a5 = value len ──────────────────────────────

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

// ── SYS_OTA_TYPED (618): a0 = Cap<Power>, a1 = op ────────────────────────────

/// The boot slot state, packed in the return value: bits 0..8 the active
/// slot, 8..16 the last good slot, 16..32 the boot count, 32..40 the bad
/// slot mask (slots: 0 = A, 1 = B, 2 = recovery). Needs `READ`.
pub const OTA_OP_STATUS: u64 = 1;
/// Roll back to the last good slot (applies at the next boot), as the
/// console's `ota rollback`: 0 rolled back, 1 already on it (nothing done),
/// `-EACCES` when that slot failed secure-boot verification. Needs `WRITE`.
pub const OTA_OP_ROLLBACK: u64 = 2;

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
