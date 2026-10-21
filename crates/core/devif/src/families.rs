// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The privileged families the recovery console used to own, as interfaces
//! (wave 12; endpoint ops since D6 part A): `Flight`, `Behavior`,
//! `Config` and `Ota`. Each has a tool image (`FLIGHT.ELF`, `BEHAVIOR.ELF`,
//! `CONFIG.ELF`, `OTA.ELF`) that holds the endpoint its signed row grants, and
//! runs the console's own command bodies.
//!
//! What each op needs is `azos_ipc::authority_policy`'s table, the one the
//! console checks its commands against: `READ` observes, `WRITE` changes.

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id of `Flight` (ASCII "FLGT").
pub const FLIGHT_ID: u32 = 0x464C_4754;
/// The interface id of `Behavior` (ASCII "BEHV").
pub const BEHAVIOR_ID: u32 = 0x4245_4856;
/// The interface id of `Config` (ASCII "CNFG").
pub const CONFIG_ID: u32 = 0x434E_4647;
/// The interface id of `Ota` (ASCII "OTAU").
pub const OTA_ID: u32 = 0x4F54_4155;

/// Layers the behavior stack has; layer 0 (the safety reflex) cannot be
/// switched by either op, as on the console.
pub const BEHAVIOR_LAYERS: u32 = azos_abi::families::BEHAVIOR_LAYERS as u32;
/// Words of a configuration key: 24 bytes, NUL-padded.
pub const KEY_WORDS: usize = 3;
/// Words of a configuration value: 32 bytes, NUL-padded.
pub const VALUE_WORDS: usize = 4;
/// Longest key (bytes).
pub const KEY_MAX: usize = KEY_WORDS * 8;
const _: () = assert!(KEY_MAX as u64 == azos_abi::families::CONFIG_KEY_MAX);
/// Longest value (bytes).
pub const VALUE_MAX: usize = VALUE_WORDS * 8;

#[azos_interface(id = 0x464C_4754, level = 1)]
pub trait Flight {
    /// Arm the flight controller and the ESCs (`flight arm`). Needs `WRITE`.
    fn arm(&mut self) -> Out<()>;
    /// Disarm (`flight disarm`). Needs `WRITE`.
    fn disarm(&mut self) -> Out<()>;
}

#[azos_interface(id = 0x4245_4856, level = 1)]
pub trait Behavior {
    /// Enable subsumption layer `layer` (`1..BEHAVIOR_LAYERS`, else
    /// `BAD_ARGUMENT`). Needs `WRITE`.
    fn enable(&mut self, layer: u32) -> Out<()>;
    /// Disable layer `layer`. Needs `WRITE`.
    fn disable(&mut self, layer: u32) -> Out<()>;
    /// Which layers are enabled: bit `n` for layer `n`. Needs `READ`.
    #[idempotent]
    fn status(&self) -> Out<u64>;
}

#[azos_interface(id = 0x434E_4647, level = 1)]
pub trait Config {
    /// The value of `key` (text, NUL-padded to [`KEY_MAX`]), NUL-padded to
    /// [`VALUE_MAX`]. `NO_RESOURCE` for a key that is not set, `BAD_ARGUMENT`
    /// for one that is not a key or a value too long for the interface.
    /// Needs `READ`.
    #[idempotent]
    fn get(&self, key: [u64; KEY_WORDS]) -> Out<[u64; VALUE_WORDS]>;
    /// Set `key` to `value` and apply the configuration, as the console's
    /// `config set`. Needs `WRITE`, for any key.
    fn set(&mut self, key: [u64; KEY_WORDS], value: [u64; VALUE_WORDS]) -> Out<()>;
}

#[azos_interface(id = 0x4F54_4155, level = 1)]
pub trait Ota {
    /// The boot slot state packed (`azos_abi::families::ota_status_unpack`).
    /// Needs `READ`.
    #[idempotent]
    fn status(&self) -> Out<u64>;
    /// Roll back to the last good slot (applies at the next boot): value 0
    /// rolled back, 1 already on it. `REFUSED` when that slot failed
    /// secure-boot verification. Needs `WRITE`.
    fn rollback(&mut self) -> Out<u32>;
    /// Switch to the whole-system set staged in the inactive slot (applies at
    /// the next boot): value the set's `sec_epoch`. `REFUSED` when the set is
    /// not valid or admissible, `BUSY` while another switch runs, `NOT_READY`
    /// while this boot is not confirmed. Needs `WRITE`.
    fn switch(&mut self) -> Out<u32>;
}
