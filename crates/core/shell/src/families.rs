// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 12 (RFC-0055 S5): the bodies of the console's `flight arm|disarm`,
//! `behavior enable|disable|status`, `config get|set` and `ota
//! status|rollback`, shared by the recovery console's commands and by the
//! ring-3 typed calls (`SYS_FLIGHT_TYPED`..`SYS_OTA_TYPED`, which reach them
//! through the kernel's `FamilyOps` seam, `kernel/src/boot/seams.rs`).
//!
//! **No authority is checked here.** The console checks its own capability
//! table first (`authority.rs`), the syscalls the calling image's
//! (`crates/core/syscall/src/families.rs`); both then run this one body, so
//! what a command does cannot differ between the two consoles. Each function
//! answers as the syscall does: a value or 0, or a negative errno.

use azos_abi::error::Errno;
use azos_abi::families::*;

fn errno(e: Errno) -> i64 {
    e.to_syscall_ret()
}

/// `flight arm` / `flight disarm`: the flight controller's state and the
/// ESCs. Arming while the e-stop latch holds is refused by the controller
/// (`-EAGAIN`); the ESC call runs as the console always made it.
#[cfg(feature = "domain-robot")]
pub fn flight(op: u64) -> i64 {
    match op {
        FLIGHT_OP_ARM => {
            let armed = azos_flight::flight_arm();
            azos_robot_drivers::esc::esc_arm();
            if armed { 0 } else { errno(Errno::EAGAIN) }
        }
        FLIGHT_OP_DISARM => {
            azos_flight::flight_disarm();
            azos_robot_drivers::esc::esc_disarm();
            0
        }
        _ => errno(Errno::EINVAL),
    }
}

/// No Robot domain: no flight controller.
#[cfg(not(feature = "domain-robot"))]
pub fn flight(_op: u64) -> i64 {
    errno(Errno::ENOSYS)
}

/// `behavior enable|disable <layer>` (1..`NUM_LAYERS`; layer 0 cannot be
/// switched) and the enabled-layer mask (`layer` ignored).
#[cfg(feature = "domain-robot")]
pub fn behavior(op: u64, layer: u64) -> i64 {
    match op {
        BEHAVIOR_OP_STATUS => azos_behavior::layer_statuses()
            .iter()
            .filter(|ls| ls.enabled)
            .fold(0i64, |m, ls| m | 1 << ls.layer),
        BEHAVIOR_OP_ENABLE | BEHAVIOR_OP_DISABLE => {
            let l = layer as usize;
            if l == 0 || l >= azos_behavior::NUM_LAYERS {
                return errno(Errno::EINVAL);
            }
            azos_behavior::layer_set_enabled(l, op == BEHAVIOR_OP_ENABLE);
            0
        }
        _ => errno(Errno::EINVAL),
    }
}

/// No Robot domain: no behavior stack.
#[cfg(not(feature = "domain-robot"))]
pub fn behavior(_op: u64, _layer: u64) -> i64 {
    errno(Errno::ENOSYS)
}

/// `config get <key>`: its value into `out`; the length, `-ENOENT` for a key
/// not set, `-EINVAL` when `out` is too short.
pub fn config_get(key: &[u8], out: &mut [u8]) -> i64 {
    match azos_config::cfg_get(key) {
        None => errno(Errno::ENOENT),
        Some(v) if v.len() > out.len() => errno(Errno::EINVAL),
        Some(v) => {
            out[..v.len()].copy_from_slice(v);
            v.len() as i64
        }
    }
}

/// `config set <key> <val>`: store it, then apply the whole configuration
/// to the subsystems, as the console always has. `-ENOSPC` when the key or
/// value is too long or the table is full.
pub fn config_set(key: &[u8], val: &[u8]) -> i64 {
    if azos_config::cfg_set(key, val) {
        azos_config::cfg_apply();
        crate::apply_config_to_subsystems();
        0
    } else {
        errno(Errno::ENOSPC)
    }
}

/// What `ota rollback` did, for the console's message.
pub enum Rollback {
    /// Rolled back from the first slot to the second (applies at the next boot).
    Done(u8, u8),
    /// Already running from the last good slot: nothing done.
    Already(u8),
    /// The last good slot failed secure-boot verification: refused.
    BadSlot(u8, u8),
}

/// `ota rollback`. Same refusal as the automatic boot-loop rollback in
/// `ota_boot_validate_pure`, and for the same reason: `last_good` is only a
/// pointer, not a guarantee that the bytes still there are signed, and a
/// manual rollback is the other door into the same slot.
pub fn ota_rollback() -> Rollback {
    let mut meta = azos_ota::ota_read_boot_meta();
    if meta.active_slot == meta.last_good {
        return Rollback::Already(meta.active_slot);
    }
    if meta.slot_is_bad(meta.last_good) {
        return Rollback::BadSlot(meta.last_good, meta.bad_slots);
    }
    let old = meta.active_slot;
    meta.active_slot = meta.last_good;
    meta.boot_count = 0;
    azos_ota::ota_write_boot_meta(&meta);
    azos_ota::ota_apply_meta(&meta);
    Rollback::Done(old, meta.active_slot)
}

/// `OTA_OP_STATUS` (the packed word) / `OTA_OP_ROLLBACK` (0 rolled back,
/// 1 already on the last good slot, `-EACCES` refused).
pub fn ota(op: u64) -> i64 {
    match op {
        OTA_OP_STATUS => {
            let m = azos_ota::ota_read_boot_meta();
            ota_status_pack(m.active_slot, m.last_good, m.boot_count, m.bad_slots) as i64
        }
        OTA_OP_ROLLBACK => match ota_rollback() {
            Rollback::Done(old, new) => {
                azos_drv_sys::kwarn!("[OTA] Rolled back: {} → {} (reboot to apply)",
                    azos_ota::ota_slot_char(old), azos_ota::ota_slot_char(new));
                0
            }
            Rollback::Already(_) => 1,
            Rollback::BadSlot(_, _) => errno(Errno::EACCES),
        },
        _ => errno(Errno::EINVAL),
    }
}
