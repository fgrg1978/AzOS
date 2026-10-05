// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Authority-checked CONFIG.INI load — W2-B5 (audit U10-2).
//!
//! # The problem
//!
//! `CONFIG.INI` lives on the same USB-exposed FAT volume `msc_gadget.rs`
//! hands to any host that plugs in. Before this module existed,
//! `kernel/src/boot/config_auth.rs` called [`crate::cfg_load`] on whatever bytes it
//! read back — no signature, no authority check — and those bytes decide:
//!
//! - `estop_gpio_pin` — whether the physical kill switch is armed
//!   (`crates/core/actuation/src/kill_switch.rs`).
//! - `link_encrypt` — whether the brain link runs AEAD.
//! - `ota_auto_recv_port` — whether an OTA listener spawns at boot with no
//!   shell command needed.
//! - `bench_boot` — whether the board halts into a synthetic-bench loop
//!   instead of booting at all.
//! - `autorun` — which ELF gets the drivetrain.
//!
//! `crates/core/topology` already signs `CAPS.TOML`/`SCHED.TOML` with an
//! Ed25519 key and a `.SIG` sidecar (`crates/core/topology/src/verify.rs`).
//! This module gives `CONFIG.INI` the SAME authority check — same
//! mechanism, same embedded key (`azos_topology::TRUSTED_PUBKEY`) —
//! without making this crate depend on crypto. See [`cfg_load_verified`].
//!
//! # Division of labour (why this crate stays dependency-free)
//!
//! This crate's header comment has said "Pure no_std — zero external
//! dependencies" since before this module existed, because [`crate::cfg_load`]
//! runs on the single-threaded boot path before the heap exists, and every
//! dependency added here is one more thing that boot path drags in. Ed25519
//! verification (`azos_crypto::ed25519::sig_verify`, wrapped by
//! `azos_topology::verify_signature`) stays in the CALLER (`kernel/src/boot/config_auth.rs`):
//! this module takes the caller's already-computed verdict as a plain
//! `bool` and never sees a signature byte or a key byte. That keeps the
//! dependency-free property intact while still making the fail-closed
//! POLICY — what happens when the verdict is `false` — a single, tested
//! function instead of six scattered `if` statements at the call site.
//!
//! # Fail-closed contract
//!
//! `sig_ok == false` (or the caller passing empty bytes, e.g. no signature
//! file to check at all) means [`cfg_load`](crate::cfg_load) is NEVER
//! called on the untrusted bytes — not even to read a single key out of
//! them. Instead:
//!
//! 1. [`crate::cfg_defaults`] resets the store to the compiled-in factory
//!    defaults and [`crate::cfg_apply`] publishes them to the runtime
//!    atomics, exactly as a fresh SD card with no `CONFIG.INI` at all
//!    already does today.
//! 2. [`crate::CFG_ESTOP_GPIO_PIN`] is additionally forced to
//!    [`ESTOP_GPIO_PIN_FAIL_CLOSED`] (belt-and-suspenders: `cfg_defaults`
//!    already omits the `estop_gpio_pin` key, so step 1 alone already
//!    yields this value today — but that is an absence this policy does
//!    not want to be silently contingent on staying true).
//!
//! `CFG_OTA_AUTO_RECV_PORT` (no listener: `cfg_apply` reads
//! `ota_auto_recv_port` with default `0`, and `cfg_defaults` never sets
//! the key), `CFG_BENCH_BOOT` (no halt-on-boot: same shape, default
//! `false`), and `autorun` ([`crate::cfg_get`]`(b"autorun")` → `None`,
//! since `cfg_defaults` never sets it either) all fall out of the SAME
//! reset for the SAME reason — verified by
//! [`fail_closed_disarms_every_dangerous_key`] below, which is the
//! module's RED→GREEN proof: construct an INI that tries to set all four
//! to their most dangerous values, load it with `sig_ok = false`, and
//! assert every one of them reads back at its safe value.

use core::sync::atomic::Ordering;

/// GPIO pin [`crate::CFG_ESTOP_GPIO_PIN`] is forced to when CONFIG.INI's
/// authority cannot be established (see [`ConfigTrust::FailClosed`]).
///
/// Still the historical "no switch configured" sentinel
/// (`crate::CFG_ESTOP_GPIO_PIN`'s own default, and
/// `crates/core/actuation/src/kill_switch.rs`'s "255 = disabled"): a `grep`
/// across every `config/defconfigs/*.config` in this tree for a literal wired
/// pin finds none, so there is no real hardware fact to fail closed
/// TOWARDS yet. This constant is the seam, not a claim that some board
/// today gets a physically armed switch out of a rejected signature — it
/// does not. The day a board's Kconfig declares the GPIO its kill switch
/// is actually wired to, that literal replaces the sentinel here, and
/// from that point on a tampered or unsigned CONFIG.INI on THAT board
/// arms the switch instead of leaving it exactly as unconfigured as an
/// absent file already does.
pub const ESTOP_GPIO_PIN_FAIL_CLOSED: u32 = 255;

/// Outcome of [`cfg_load_verified`], for the caller's boot log and
/// durable safety record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigTrust {
    /// The caller verified a `CONFIG.SIG` sidecar against the trusted
    /// key before calling in: `ini_bytes` came from someone holding the
    /// signing key, and were loaded and applied normally.
    Verified,
    /// No usable signature — sidecar absent, wrong length, or it did not
    /// verify against the trusted key — so the untrusted bytes were
    /// never parsed. The store now holds compiled-in factory defaults;
    /// see the module doc's "Fail-closed contract".
    FailClosed,
    /// The signature verified but the file is ambiguous: a key appears on two
    /// lines ([`crate::CfgError::DuplicateKey`]). A signed file nobody can read
    /// unambiguously is not a configuration, so this takes the same
    /// fail-closed branch as [`ConfigTrust::FailClosed`] (factory defaults,
    /// kill switch forced to [`ESTOP_GPIO_PIN_FAIL_CLOSED`]) and carries the
    /// reason for the boot log.
    Rejected(crate::CfgError),
}

/// Load CONFIG.INI under an authority decision the CALLER already made.
///
/// `sig_ok` is the result of verifying `CONFIG.SIG` against the
/// project's trusted Ed25519 key — in practice
/// `azos_topology::verify_signature(ini_bytes, &sig_bytes,
/// &azos_topology::TRUSTED_PUBKEY).is_ok()`, the SAME key and `.SIG`
/// mechanism `CAPS.TOML`/`SCHED.TOML` use (this crate does not depend on
/// `azos_topology` or `azos_crypto` — see the module doc).
///
/// - `sig_ok == true` and `ini_bytes` non-empty: [`crate::cfg_load`] then
///   [`crate::cfg_apply`], exactly as before this module existed.
/// - `sig_ok == true` but the file repeats a key: [`crate::cfg_load`]
///   refuses it and this takes the fail-closed branch below, returning
///   [`ConfigTrust::Rejected`].
/// - Otherwise (`sig_ok == false`, OR `sig_ok == true` with empty bytes —
///   an empty file cannot carry a meaningful signature either way):
///   [`crate::cfg_defaults`] then [`crate::cfg_apply`], plus the explicit
///   [`ESTOP_GPIO_PIN_FAIL_CLOSED`] store. See the module doc's
///   "Fail-closed contract" for why the other three dangerous keys need
///   no equivalent explicit line.
///
/// Returns which branch ran.
pub fn cfg_load_verified(ini_bytes: &[u8], sig_ok: bool) -> ConfigTrust {
    let parsed = if sig_ok && !ini_bytes.is_empty() {
        Some(crate::cfg_load(ini_bytes))
    } else {
        None
    };
    if let Some(Ok(())) = parsed {
        crate::cfg_apply();
        ConfigTrust::Verified
    } else {
        crate::cfg_defaults();
        crate::cfg_apply();
        crate::CFG_ESTOP_GPIO_PIN.store(ESTOP_GPIO_PIN_FAIL_CLOSED, Ordering::Release);
        match parsed {
            Some(Err(e)) => ConfigTrust::Rejected(e),
            _ => ConfigTrust::FailClosed,
        }
    }
}

// ── Wave 11: replay protection and a fail-closed that latches ──────────────
//
// RFC-0054 finding 7. A bare signature over the file's bytes could be
// replayed (an older, validly signed CONFIG.INI copied back), and deleting
// CONFIG.SIG left the kill switch at the "unconfigured" sentinel with only a
// boot-log line to say so. `CONFIG.SIG` is now format v2 (device id + a
// counter, `azos_topology::verify_config_sig_v2`) and the device record in
// the reserved tail carries the lowest counter still accepted (the floor).
// The decision below is the whole policy; the kernel (`kernel/src/boot/
// config_auth.rs`) only gathers its two inputs and carries out the answer.

/// What the caller found when it looked at `CONFIG.INI` and `CONFIG.SIG`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigSigCheck {
    /// No `CONFIG.INI`, or an empty one.
    NoIni,
    /// `CONFIG.INI` present, `CONFIG.SIG` absent.
    NoSig,
    /// The device has no record, so there is no id to check a v2 sidecar
    /// against.
    NoDeviceId,
    /// A bare 64-byte signature: the replayable v1 format.
    V1,
    /// Wrong length, magic, version, padding, or counter 0.
    BadFormat,
    /// A v2 sidecar bound to another device's id.
    WrongDevice,
    /// The signature does not verify against the trusted key.
    BadSignature,
    /// Verified for this device; the counter it signs.
    Valid(u64),
}

/// The device record as the caller read it from the reserved tail.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceFloor {
    /// No valid record (or no usable tail on this medium).
    Unprovisioned,
    /// Provisioned; the lowest counter still accepted. 0: no signed
    /// `CONFIG.INI` has been accepted on this device yet.
    Provisioned(u64),
}

/// Why a `CONFIG.INI` was not loaded. `code()` is the `detail` of the durable
/// record a latch writes; never renumber.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthorityLoss {
    /// No `CONFIG.INI`.
    NoIni,
    /// No `CONFIG.SIG`.
    NoSig,
    /// The device is not provisioned.
    Unprovisioned,
    /// A v1 sidecar.
    V1,
    /// A malformed sidecar.
    BadFormat,
    /// Another device's sidecar.
    WrongDevice,
    /// A signature that does not verify.
    BadSignature,
    /// A valid signature with a counter below the floor.
    Replay,
    /// A signed file that repeats a key.
    Ambiguous,
}

impl AuthorityLoss {
    /// The durable record's `detail`.
    pub const fn code(self) -> u32 {
        match self {
            AuthorityLoss::NoIni => 1,
            AuthorityLoss::NoSig => 2,
            AuthorityLoss::Unprovisioned => 3,
            AuthorityLoss::V1 => 4,
            AuthorityLoss::BadFormat => 5,
            AuthorityLoss::WrongDevice => 6,
            AuthorityLoss::BadSignature => 7,
            AuthorityLoss::Replay => 8,
            AuthorityLoss::Ambiguous => 9,
        }
    }

    /// The reason as the boot log prints it.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthorityLoss::NoIni => "CONFIG.INI absent",
            AuthorityLoss::NoSig => "CONFIG.SIG absent",
            AuthorityLoss::Unprovisioned => "device not provisioned",
            AuthorityLoss::V1 => "CONFIG.SIG is the v1 format, refused",
            AuthorityLoss::BadFormat => "CONFIG.SIG malformed",
            AuthorityLoss::WrongDevice => "CONFIG.SIG names another device",
            AuthorityLoss::BadSignature => "CONFIG.SIG did not verify",
            AuthorityLoss::Replay => "CONFIG.SIG counter below the floor (replay)",
            AuthorityLoss::Ambiguous => "CONFIG.INI repeats a key",
        }
    }
}

/// What to do with `CONFIG.INI` this boot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigDecision {
    /// Load it ([`cfg_load_verified`] with `sig_ok = true`); raise the floor
    /// to `counter` afterwards when `raise_floor` (and the load verified).
    Load {
        /// The counter the sidecar signed.
        counter: u64,
        /// `counter` is above the floor.
        raise_floor: bool,
    },
    /// Factory defaults, kill switch pin forced to
    /// [`ESTOP_GPIO_PIN_FAIL_CLOSED`]: nothing signed was ever accepted on
    /// this device, so there is no authority to have lost.
    Defaults(AuthorityLoss),
    /// Factory defaults AND the e-stop latched with a durable record: this
    /// device accepted a signed `CONFIG.INI` before (floor >= 1), and the
    /// authority is gone now.
    LatchEstop(AuthorityLoss),
}

const fn loss_of(check: ConfigSigCheck) -> AuthorityLoss {
    match check {
        ConfigSigCheck::NoIni => AuthorityLoss::NoIni,
        ConfigSigCheck::NoSig => AuthorityLoss::NoSig,
        ConfigSigCheck::NoDeviceId => AuthorityLoss::Unprovisioned,
        ConfigSigCheck::V1 => AuthorityLoss::V1,
        ConfigSigCheck::BadFormat => AuthorityLoss::BadFormat,
        ConfigSigCheck::WrongDevice => AuthorityLoss::WrongDevice,
        ConfigSigCheck::BadSignature => AuthorityLoss::BadSignature,
        ConfigSigCheck::Valid(_) => AuthorityLoss::Replay,
    }
}

/// The policy. Pure: the caller read the device record and checked the
/// sidecar; this decides.
///
/// * Unprovisioned: never load (no id to bind a signature to), never latch
///   (no record says a signed file was ever here) — the pre-wave-11
///   fail-closed defaults.
/// * Floor 0: load a valid sidecar (and raise the floor to its counter);
///   anything else is defaults, as above.
/// * Floor f >= 1: load a valid sidecar whose counter is >= f (raise the floor
///   if above); anything else — absent file or sidecar, tampered, v1, another
///   device's, or a counter below f — latches.
pub const fn config_authority_decision(floor: DeviceFloor, check: ConfigSigCheck) -> ConfigDecision {
    match floor {
        DeviceFloor::Unprovisioned => ConfigDecision::Defaults(match check {
            ConfigSigCheck::NoIni => AuthorityLoss::NoIni,
            ConfigSigCheck::NoSig => AuthorityLoss::NoSig,
            _ => AuthorityLoss::Unprovisioned,
        }),
        DeviceFloor::Provisioned(f) => match check {
            ConfigSigCheck::Valid(c) if c >= f => ConfigDecision::Load { counter: c, raise_floor: c > f },
            _ if f == 0 => ConfigDecision::Defaults(loss_of(check)),
            _ => ConfigDecision::LatchEstop(loss_of(check)),
        },
    }
}

/// After a [`ConfigDecision::Load`] whose file repeated a key
/// ([`ConfigTrust::Rejected`]): latch too when the device had accepted a
/// signed file before, as for any other loss of authority.
pub const fn config_after_rejected(floor: DeviceFloor) -> Option<AuthorityLoss> {
    match floor {
        DeviceFloor::Provisioned(f) if f >= 1 => Some(AuthorityLoss::Ambiguous),
        _ => None,
    }
}

// Host-side tests for this function live in `tests/host/config-tests` (this
// crate's own convention — `azos_config` carries no `#[cfg(test)]`
// module of its own; see `signed_tests.rs` there for the RED→GREEN proof).
