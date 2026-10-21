// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What an `[envelope.NAME]` row of kind `delete`, `egress`, `config`, `ota` or
//! `rt_time` lets a Domain do.
//!
//! The filesystem, the network stack, the configuration store, the updater and
//! the scheduler sit below the effect gate (`azos_actuation::effect_gate`) in
//! the dependency order, and the gate sits below none of them: they all name the
//! same operations and destination classes, so the numbers and the ceiling
//! tables live here, once. The last three kinds are asked through one hook
//! ([`set_ask_gate`], [`asked`]).
//!
//! A row's `level` is a ceiling (`full`, `cautious`, `slow`, `contained`, the
//! numbers 0 to 3 below, the order of `azos_topology::Envelope`):
//!
//! | level       | `delete` lets through                         | `egress` lets through            |
//! |-------------|-----------------------------------------------|----------------------------------|
//! | `full` (0)  | every delete                                  | every destination                |
//! | `cautious`  | every delete but the drop of a snapshot       | loopback, link and private nets  |
//! | `slow`      | a truncate (cut a file, keep its head)        | loopback and the local link      |
//! | `contained` | no delete                                     | loopback only                    |
//!
//! | level       | `config` lets through            | `ota` lets through      | `rt_time` lets through (one reservation's density) |
//! |-------------|----------------------------------|-------------------------|----------------------------------------------------|
//! | `full` (0)  | every key                        | stage and switch        | up to a whole hart                                 |
//! | `cautious`  | every key but those that open a way in or change what boots | stage, no switch | half a hart                    |
//! | `slow`      | only tuning keys                 | nothing                 | a tenth of a hart                                  |
//! | `contained` | no key                           | nothing                 | no reservation                                     |

/// Number of envelope levels: `full`, `cautious`, `slow`, `contained`.
pub const LEVELS: u8 = 4;

/// One way a change to a volume takes stored data away. The number is the
/// op word of the effect gate's record and, in that order, how much the op
/// destroys: a [`DeleteOp::Truncate`] keeps the head of the file, an unlink
/// loses the file, a snapshot drop loses a whole generation of the volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DeleteOp {
    /// A file is cut short (`truncate` to below its size).
    Truncate = 1,
    /// A rename whose target name already holds a file: the target is gone.
    Replace = 2,
    /// A file is unlinked.
    Unlink = 3,
    /// A snapshot of an azvol volume is dropped: every block only it kept is freed.
    SnapshotDrop = 4,
}

impl DeleteOp {
    /// The op for a record's number, if it is one.
    pub const fn from_u8(n: u8) -> Option<DeleteOp> {
        match n {
            1 => Some(DeleteOp::Truncate),
            2 => Some(DeleteOp::Replace),
            3 => Some(DeleteOp::Unlink),
            4 => Some(DeleteOp::SnapshotDrop),
            _ => None,
        }
    }

    /// Does an envelope at `level` let this op through? The most destructive
    /// op each level allows: `full` all four, `cautious` up to an unlink,
    /// `slow` a truncate, `contained` none. A level past `contained` is
    /// `contained`.
    pub const fn permitted(self, level: u8) -> bool {
        let ceiling = match level {
            0 => DeleteOp::SnapshotDrop as u8,
            1 => DeleteOp::Unlink as u8,
            2 => DeleteOp::Truncate as u8,
            _ => 0,
        };
        self as u8 <= ceiling
    }
}

/// How far from this node a destination address is. A destination that is
/// this node itself (loopback, one of its own addresses) has no class: the
/// packet never leaves, and nothing gates it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DestClass {
    /// The local link only: link-local unicast, multicast, broadcast.
    Link = 1,
    /// A private network, reached through a router: RFC 1918, the shared
    /// address space (100.64.0.0/10), IPv6 unique-local addresses.
    Private = 2,
    /// Anything else.
    Public = 3,
}

impl DestClass {
    /// The class for a record's number, if it is one.
    pub const fn from_u8(n: u8) -> Option<DestClass> {
        match n {
            1 => Some(DestClass::Link),
            2 => Some(DestClass::Private),
            3 => Some(DestClass::Public),
            _ => None,
        }
    }

    /// Does an envelope at `level` let a first packet to this class out?
    /// `full` every class, `cautious` up to a private network, `slow` the
    /// local link, `contained` none. A level past `contained` is `contained`.
    pub const fn permitted(self, level: u8) -> bool {
        let reach = match level {
            0 => DestClass::Public as u8,
            1 => DestClass::Private as u8,
            2 => DestClass::Link as u8,
            _ => 0,
        };
        self as u8 <= reach
    }
}

/// The class of an IPv4 destination; `None` for loopback (`127.0.0.0/8`) and
/// the unspecified address, which stay on the node. Whether the address is
/// one of the node's own is the network stack's to say; it holds the
/// interfaces.
pub const fn classify_v4(a: [u8; 4]) -> Option<DestClass> {
    if a[0] == 127 || (a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0) {
        return None;
    }
    // Link-local, multicast, and the limited broadcast.
    if (a[0] == 169 && a[1] == 254) || (a[0] >= 224) {
        return Some(DestClass::Link);
    }
    if a[0] == 10
        || (a[0] == 172 && a[1] >= 16 && a[1] <= 31)
        || (a[0] == 192 && a[1] == 168)
        || (a[0] == 100 && a[1] >= 64 && a[1] <= 127)
    {
        return Some(DestClass::Private);
    }
    Some(DestClass::Public)
}

/// The class of an IPv6 destination; `None` for `::1` and `::`. An
/// IPv4-mapped address (`::ffff:a.b.c.d`) is classed by its IPv4 half.
pub const fn classify_v6(a: [u8; 16]) -> Option<DestClass> {
    let mut i = 0;
    let mut zero_prefix = true;
    while i < 10 {
        if a[i] != 0 {
            zero_prefix = false;
        }
        i += 1;
    }
    if zero_prefix {
        if a[10] == 0xff && a[11] == 0xff {
            return classify_v4([a[12], a[13], a[14], a[15]]);
        }
        if a[10] == 0 && a[11] == 0 && a[12] == 0 && a[13] == 0 && a[14] == 0 && (a[15] == 0 || a[15] == 1) {
            return None;
        }
    }
    // fe80::/10 link-local, ff00::/8 multicast.
    if (a[0] == 0xfe && a[1] & 0xc0 == 0x80) || a[0] == 0xff {
        return Some(DestClass::Link);
    }
    // fc00::/7 unique-local.
    if a[0] & 0xfe == 0xfc {
        return Some(DestClass::Private);
    }
    Some(DestClass::Public)
}

// ── Config, OTA and real-time time ──────────────────────────────────────────

/// What a write of one configuration key changes, by how much it can hurt. The
/// number is the op word of the effect gate's record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ConfigOp {
    /// A key that tunes behaviour (rates, limits, addresses, gains).
    Tune = 1,
    /// A key that arms or disarms a guard: the e-stop pin, the watchdog, the
    /// panic reboot.
    Arm = 2,
    /// A key that opens a way in or changes what boots: the OTA listener, the
    /// bench halt, the autorun image. These are the keys a signed `CONFIG.INI`
    /// protects first (`azos_config::signed`).
    Open = 3,
}

impl ConfigOp {
    /// The op for a record's number, if it is one.
    pub const fn from_u8(n: u8) -> Option<ConfigOp> {
        match n {
            1 => Some(ConfigOp::Tune),
            2 => Some(ConfigOp::Arm),
            3 => Some(ConfigOp::Open),
            _ => None,
        }
    }

    /// The op a write of `key` is. A key this table does not name tunes.
    pub fn of_key(key: &[u8]) -> ConfigOp {
        match key {
            b"ota_auto_recv_port" | b"bench_boot" | b"autorun" => ConfigOp::Open,
            b"estop_gpio_pin" | b"watchdog_ms" | b"panic_reboot_ms" => ConfigOp::Arm,
            _ => ConfigOp::Tune,
        }
    }

    /// Does an envelope at `level` let this write through? The most dangerous
    /// op each level allows: `full` all three, `cautious` up to arming a
    /// guard, `slow` tuning, `contained` none. A level past `contained` is
    /// `contained`.
    pub const fn permitted(self, level: u8) -> bool {
        let ceiling = match level {
            0 => ConfigOp::Open as u8,
            1 => ConfigOp::Arm as u8,
            2 => ConfigOp::Tune as u8,
            _ => 0,
        };
        self as u8 <= ceiling
    }
}

/// The first eight bytes of a configuration key, little-endian, zero padded:
/// what a record carries of the key (enough to read `estop_gpio_pin` and
/// `watchdog_ms` apart in a dump).
pub fn key_word(key: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    let n = key.len().min(8);
    b[..n].copy_from_slice(&key[..n]);
    u64::from_le_bytes(b)
}

/// One step of applying a whole-system update, in the order it destroys the
/// running system's options. The number is the op word of the gate's record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum OtaOp {
    /// The set is written into the inactive slot. The running system is not
    /// touched: a stager that is refused here has changed nothing.
    Stage = 1,
    /// The boot record names the staged slot: the next boot runs it.
    Switch = 2,
}

impl OtaOp {
    /// The op for a record's number, if it is one.
    pub const fn from_u8(n: u8) -> Option<OtaOp> {
        match n {
            1 => Some(OtaOp::Stage),
            2 => Some(OtaOp::Switch),
            _ => None,
        }
    }

    /// Does an envelope at `level` let this step through? `full` both,
    /// `cautious` staging only (a Domain may prepare an update that another
    /// switches), `slow` and `contained` neither. A level past `contained` is
    /// `contained`.
    pub const fn permitted(self, level: u8) -> bool {
        let ceiling = match level {
            0 => OtaOp::Switch as u8,
            1 => OtaOp::Stage as u8,
            _ => 0,
        };
        self as u8 <= ceiling
    }
}

/// Parts per million in a whole hart: the unit of a reservation's density.
pub const RT_PPM: u32 = 1_000_000;

/// The densest single reservation each level lets a Domain make, in parts per
/// million of a hart: `full` a whole hart (the scheduler's own admission is
/// the limit), `cautious` half, `slow` a tenth, `contained` none.
pub const RT_CEILING_PPM: [u32; LEVELS as usize] = [RT_PPM, RT_PPM / 2, RT_PPM / 10, 0];

/// The ceiling of `level` ([`RT_CEILING_PPM`]); a level past `contained` is
/// `contained`.
pub const fn rt_ceiling_ppm(level: u8) -> u32 {
    RT_CEILING_PPM[if level < LEVELS { level as usize } else { LEVELS as usize - 1 }]
}

/// Does an envelope at `level` let a reservation of `density_ppm` through?
pub const fn rt_permitted(level: u8, density_ppm: u32) -> bool {
    density_ppm <= rt_ceiling_ppm(level)
}

/// An effect of the kinds that the scheduler, the updater and the
/// configuration store ask about, as the gate's hook receives it. The first
/// two are the calling task's (the hook finds it); a reservation names the
/// task it admits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ask {
    /// A write of a configuration key: its op and its first eight bytes
    /// ([`key_word`]).
    Config { op: ConfigOp, key: u64 },
    /// A step of applying an update to `slot`.
    Ota { op: OtaOp, slot: u8 },
    /// A real-time reservation for task `tid`, of `density_ppm` parts per
    /// million of a hart.
    RtTime { tid: u32, density_ppm: u32 },
}

/// The effect gate, as these crates see it: `true` lets the effect go ahead,
/// `false` is a refusal the gate has already written down (rule and receipt).
pub type AskGate = fn(Ask) -> bool;

crate::ro_hook! {
    static ASK_GATE: AskGate;
}

/// Install the gate (boot, once). Unset, every ask is let through.
pub fn set_ask_gate(f: AskGate) {
    ASK_GATE.set(f);
}

/// Host tests: forget the installed gate (hooks are process-wide there).
#[cfg(not(target_os = "none"))]
pub fn clear_ask_gate_for_test() {
    ASK_GATE.clear_for_tests();
}

/// May the effect go ahead? `true` with no gate installed (a build without
/// the effect gate, a host suite that wires none).
pub fn asked(a: Ask) -> bool {
    match ASK_GATE.get() {
        Some(f) => f(a),
        None => true,
    }
}

/// May the calling task write configuration key `key`? ([`asked`] for a
/// [`ConfigOp::of_key`] write.)
pub fn config_write_admitted(key: &[u8]) -> bool {
    asked(Ask::Config { op: ConfigOp::of_key(key), key: key_word(key) })
}
