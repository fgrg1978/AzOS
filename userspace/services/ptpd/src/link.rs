// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the UDP transport needs around a PTP message: the ports and the group,
//! the identity a node gives its clock and the domain its topology row names.
//! Pure functions: the sockets are `main.rs`'s.

/// The UDP port of event messages (Sync, Delay_Req).
pub const PORT_EVENT: u16 = 319;
/// ... and of general ones (Announce, Follow_Up, Delay_Resp).
pub const PORT_GENERAL: u16 = 320;
/// The IPv4 group every PTP port listens on (`PTP-primary`, IEEE 1588 Annex D).
pub const GROUP: [u8; 4] = [224, 0, 1, 129];

/// The identity of a clock whose node has the IPv4 address `ip`: the tag `AzPT`
/// and the address. A clock identity needs only to be unique on the network
/// (IEEE 1588 §7.5.2.2.2), and two nodes of one network have different
/// addresses.
pub fn ip_identity(ip: [u8; 4]) -> [u8; 8] {
    [b'A', b'z', b'P', b'T', ip[0], ip[1], ip[2], ip[3]]
}

/// The domain the node's `[clock]` row declares, from `/proc/clock` (one line,
/// `ptp_domain N`; the file is empty when the row declares none).
pub fn parse_domain(view: &[u8]) -> Option<u8> {
    let rest = view.strip_prefix(b"ptp_domain ")?;
    let end = rest.iter().position(|b| !b.is_ascii_digit()).unwrap_or(rest.len());
    let digits = core::str::from_utf8(&rest[..end]).ok()?;
    digits.parse().ok()
}
