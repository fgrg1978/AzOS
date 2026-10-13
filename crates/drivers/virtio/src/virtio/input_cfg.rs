// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-input config space: what a device is (virtio 1.x 5.8.5).
//!
//! The config space is a query. The driver writes `select` (byte 0) and
//! `subsel` (byte 1), reads `size` (byte 2), then reads `size` bytes of the
//! answer at offset 8. Pure (core only): the register access is a closure
//! the caller supplies, so `tests/host/drivers-tests` runs this against a
//! fake device.

/// `select` values.
pub const CFG_ID_NAME: u8 = 0x01;
pub const CFG_EV_BITS: u8 = 0x11;

/// The answer's capacity (the config union is 128 bytes).
pub const CFG_MAX: usize = 128;

/// `EV_KEY` / `EV_REL` / `EV_ABS`, the `subsel` of an `EV_BITS` query.
const EV_KEY: u8 = 0x01;
const EV_REL: u8 = 0x02;
const EV_ABS: u8 = 0x03;
/// Key codes that tell a keyboard from a button box.
const KEY_ENTER: usize = 28;
const KEY_A: usize = 30;

/// What a device is, from its event bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Letters and Enter: feeds the console.
    Keyboard,
    /// Relative axes (a mouse).
    Pointer,
    /// Absolute axes (a tablet, a touch screen).
    Tablet,
    /// Anything else.
    Other,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Keyboard => "keyboard",
            Kind::Pointer => "pointer",
            Kind::Tablet => "tablet",
            Kind::Other => "other",
        }
    }
}

/// Is bit `bit` set in the little-endian bitmap `map`? A bit past the end
/// is clear (the device reports only as many bytes as its highest bit).
pub fn bit_set(map: &[u8], bit: usize) -> bool {
    map.get(bit / 8).is_some_and(|b| b & (1 << (bit % 8)) != 0)
}

/// Query `(select, subsel)`: copies the answer into `out` and returns its
/// length (0 if the device has nothing for that query). `read` is the
/// device: given the two selectors, the answer's bytes and their count.
pub fn query(
    read: &mut dyn FnMut(u8, u8, &mut [u8; CFG_MAX]) -> usize,
    select: u8,
    subsel: u8,
    out: &mut [u8; CFG_MAX],
) -> usize {
    let n = read(select, subsel, out);
    // `size` is device-written: never trust it past the buffer.
    n.min(CFG_MAX)
}

/// Everything the driver keeps from the config queries.
#[derive(Clone, Copy, Debug)]
pub struct Info {
    pub name: [u8; 32],
    pub name_len: usize,
    pub kind: Kind,
}

impl Info {
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }
}

/// Classify from the `EV_KEY` code bitmap and whether the device reports any
/// relative or absolute axis. (A device supports an event type exactly when
/// the `EV_BITS` query for that type answers with a non-empty bitmap: there is
/// no query that lists the types.)
pub fn classify(key_bits: &[u8], has_rel: bool, has_abs: bool) -> Kind {
    if has_abs {
        Kind::Tablet
    } else if has_rel {
        Kind::Pointer
    } else if bit_set(key_bits, KEY_A) && bit_set(key_bits, KEY_ENTER) {
        Kind::Keyboard
    } else {
        Kind::Other
    }
}

/// Run the queries and build the [`Info`]. The name keeps its printable
/// ASCII (device-written text goes to the boot log).
pub fn read_info(read: &mut dyn FnMut(u8, u8, &mut [u8; CFG_MAX]) -> usize) -> Info {
    let mut buf = [0u8; CFG_MAX];
    let mut info = Info { name: [0; 32], name_len: 0, kind: Kind::Other };
    let n = query(read, CFG_ID_NAME, 0, &mut buf);
    for &b in buf[..n].iter().take(info.name.len()) {
        if b == 0 {
            break;
        }
        info.name[info.name_len] = if (0x20..0x7f).contains(&b) { b } else { b'?' };
        info.name_len += 1;
    }
    let mut keys = [0u8; CFG_MAX];
    let n_keys = query(read, CFG_EV_BITS, EV_KEY, &mut keys);
    let mut scratch = [0u8; CFG_MAX];
    let has_rel = query(read, CFG_EV_BITS, EV_REL, &mut scratch) > 0;
    let has_abs = query(read, CFG_EV_BITS, EV_ABS, &mut scratch) > 0;
    info.kind = classify(&keys[..n_keys], has_rel, has_abs);
    info
}
