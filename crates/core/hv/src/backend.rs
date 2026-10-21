// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The backends a guest row names, and the envelope's ceiling on their reach.
//!
//! A `[guest.NAME]` row lists its backends by name in `devices = [...]`; the
//! position in that list is the device index every other interface uses
//! (`Vm::window`'s `device`, a trap's window). `Vm::config` tells the ring-3
//! monitor which kind sits at which index ([`pack`]), so the device models are
//! built from the row and not from a table of their own.
//!
//! # The envelope as a ceiling on reach
//!
//! The row's `envelope` is "the ceiling on the effects the guest may cause
//! through its backends". An effect a backend causes goes as far as the
//! backend takes it, and the ladder is by how far that is ([`Reach`]): the
//! monitor's own console, the disk image, the network, a physical pin. The
//! envelope names the farthest reach it allows ([`allows`]); a guest store to
//! a window of a backend past that is **refused** at the trap
//! (`Rule::GuestEgress`), before any device model sees it. Loads are never
//! egress: they cause nothing.
//!
//! | envelope  | farthest reach |
//! |-----------|----------------|
//! | full      | a physical pin |
//! | cautious  | the network |
//! | slow      | the disk image |
//! | contained | none: the guest causes no effect at all |

use azos_topology::Envelope;

/// A backend the guest can be given. The code is its value in [`pack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Backend {
    Blk = 1,
    Net = 2,
    Console = 3,
    Rng = 4,
    Input = 5,
    Gpio = 6,
}

/// How far a backend's effects travel, nearest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Reach {
    /// Causes no effect outside the guest (entropy, input).
    Inert = 0,
    /// The monitor's own console.
    Console = 1,
    /// The guest's disk image.
    Disk = 2,
    /// The network.
    Net = 3,
    /// A physical pin.
    Physical = 4,
}

/// Bits of one kind in [`pack`]: 16 backends per word, the ceiling
/// `TOPOLOGY_GUEST_DEVICES` has.
pub const KIND_BITS: u32 = 4;

impl Backend {
    /// Every backend, in code order.
    pub const ALL: [Backend; 6] =
        [Backend::Blk, Backend::Net, Backend::Console, Backend::Rng, Backend::Input, Backend::Gpio];

    /// The name a row lists it by.
    pub const fn name(self) -> &'static str {
        match self {
            Backend::Blk => "virtio-blk",
            Backend::Net => "virtio-net",
            Backend::Console => "virtio-console",
            Backend::Rng => "virtio-rng",
            Backend::Input => "virtio-input",
            Backend::Gpio => "gpio",
        }
    }

    pub fn from_name(name: &[u8]) -> Option<Backend> {
        Backend::ALL.into_iter().find(|b| b.name().as_bytes() == name)
    }

    pub fn from_code(code: u8) -> Option<Backend> {
        Backend::ALL.into_iter().find(|b| *b as u8 == code)
    }

    pub const fn reach(self) -> Reach {
        match self {
            Backend::Rng | Backend::Input => Reach::Inert,
            Backend::Console => Reach::Console,
            Backend::Blk => Reach::Disk,
            Backend::Net => Reach::Net,
            Backend::Gpio => Reach::Physical,
        }
    }
}

/// The farthest reach `envelope` allows, `None` for the one that allows no
/// effect.
pub const fn ceiling(envelope: Envelope) -> Option<Reach> {
    match envelope {
        Envelope::Full => Some(Reach::Physical),
        Envelope::Cautious => Some(Reach::Net),
        Envelope::Slow => Some(Reach::Disk),
        Envelope::Contained => None,
    }
}

/// May a guest under `envelope` cause the effects of `reach`? What reaches
/// nowhere ([`Reach::Inert`]) is always allowed.
pub fn allows(envelope: Envelope, reach: Reach) -> bool {
    if reach == Reach::Inert {
        return true;
    }
    if cfg!(feature = "canary-egress-open") {
        return true;
    }
    ceiling(envelope).is_some_and(|c| reach <= c)
}

/// The kinds of a row's backends, 4 bits each, device 0 lowest; 0 is a name
/// the table does not know (admission refuses such a row, so none reaches a
/// monitor).
pub fn pack(devices: &[azos_topology::MaybeStr<'_>]) -> u64 {
    devices.iter().take(16).enumerate().fold(0u64, |w, (i, d)| {
        let code = Backend::from_name(d.as_bytes()).map_or(0, |b| b as u8) as u64;
        w | code << (i as u32 * KIND_BITS)
    })
}

/// Device `index`'s kind in a packed word.
pub fn kind_at(packed: u64, index: usize) -> Option<Backend> {
    if index >= 16 {
        return None;
    }
    Backend::from_code(((packed >> (index as u32 * KIND_BITS)) & 0xF) as u8)
}
