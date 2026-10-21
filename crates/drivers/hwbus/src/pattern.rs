// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a driver's identity looks like: a PCI id or class, a device-tree
//! `compatible`, a virtio device id.
//!
//! This file is compiled twice, as a module of the crate and by `build.rs`
//! (`#[path]`), which checks the two generated tables against each other with
//! the same [`Pattern::overlaps`] the crate's tests use. It names only `core`.
//!
//! # Selector text
//!
//! One spelling serves the sidecar id files of the drivers, the topology's
//! `[device.*]` rows and the `mmio.<selector>` grants:
//!
//! ```text
//! pci:1af4:1041            vendor:device, hex; `*` for any
//! pciclass:010802:ffffff   class code (base, sub, prog-if) and the mask that counts
//! dt:ns16550a              a device-tree compatible string
//! virtio:2                 a virtio device id, decimal
//! ```

/// "Any" in a PCI vendor, device or class field.
pub const ANY: u32 = u32::MAX;

/// A device identity, or the identity a driver answers to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pattern<'a> {
    /// `vendor`/`device` of the function, [`ANY`] for either; `class` is the
    /// 24-bit class code compared under `class_mask` (0 compares nothing).
    Pci { vendor: u32, device: u32, class: u32, class_mask: u32 },
    /// One device-tree `compatible` string.
    Dt(&'a str),
    /// A virtio device id (`VIRTIO_ID_*`), on whichever transport.
    Virtio(u32),
}

const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn field_overlaps(a: u32, b: u32) -> bool {
    a == ANY || b == ANY || a == b
}

impl<'a> Pattern<'a> {
    /// A PCI id with no class condition.
    pub const fn pci(vendor: u32, device: u32) -> Self {
        Pattern::Pci { vendor, device, class: 0, class_mask: 0 }
    }

    /// Every function of a class code (`mask` 0xffffff for the exact class).
    pub const fn pci_class(class: u32, mask: u32) -> Self {
        Pattern::Pci { vendor: ANY, device: ANY, class, class_mask: mask }
    }

    /// Do two patterns claim the same id? Patterns of the same kind overlap
    /// when no field tells them apart. Patterns of different kinds never do:
    /// a device carries one identity of each kind it has, and a table that
    /// wants both spells both. Within PCI an id (vendor and/or device named)
    /// and a class (neither named, a class mask) are different claims: a
    /// function that satisfies both is handed to the id's owner, which is the
    /// decision order's job, not a conflict.
    pub const fn overlaps(&self, other: &Pattern<'_>) -> bool {
        match (self, other) {
            (
                Pattern::Pci { vendor: v1, device: d1, class: c1, class_mask: m1 },
                Pattern::Pci { vendor: v2, device: d2, class: c2, class_mask: m2 },
            ) => {
                let class_only_1 = *v1 == ANY && *d1 == ANY && *m1 != 0;
                let class_only_2 = *v2 == ANY && *d2 == ANY && *m2 != 0;
                class_only_1 == class_only_2
                    && field_overlaps(*v1, *v2)
                    && field_overlaps(*d1, *d2)
                    && (*c1 ^ *c2) & *m1 & *m2 == 0
            }
            (Pattern::Dt(a), Pattern::Dt(b)) => bytes_eq(a.as_bytes(), b.as_bytes()),
            (Pattern::Virtio(a), Pattern::Virtio(b)) => *a == *b,
            _ => false,
        }
    }

    /// Parse the selector text (module doc). `None` for anything else.
    pub fn parse(s: &'a str) -> Option<Pattern<'a>> {
        let (kind, rest) = s.split_once(':')?;
        match kind {
            "pci" => {
                let (v, d) = rest.split_once(':')?;
                Some(Pattern::pci(hex_or_any(v, 0xffff)?, hex_or_any(d, 0xffff)?))
            }
            "pciclass" => {
                let (c, m) = rest.split_once(':')?;
                let class = hex(c, 0x00ff_ffff)?;
                let mask = hex(m, 0x00ff_ffff)?;
                Some(Pattern::pci_class(class, mask))
            }
            "dt" if !rest.is_empty() && !rest.contains(char::is_whitespace) => Some(Pattern::Dt(rest)),
            "virtio" => Some(Pattern::Virtio(dec(rest)?)),
            _ => None,
        }
    }
}

fn hex(s: &str, max: u32) -> Option<u32> {
    if s.is_empty() || s.len() > 8 {
        return None;
    }
    let mut v = 0u32;
    for b in s.bytes() {
        let d = (b as char).to_digit(16)?;
        v = v.checked_mul(16)?.checked_add(d)?;
    }
    (v <= max).then_some(v)
}

fn hex_or_any(s: &str, max: u32) -> Option<u32> {
    if s == "*" { Some(ANY) } else { hex(s, max) }
}

fn dec(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 9 {
        return None;
    }
    let mut v = 0u32;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u32;
    }
    Some(v)
}

/// The first pair `(i, j)` with `pa(&a[i])` overlapping `pb(&b[j])`. The one
/// check behind "an id has one owner": `build.rs` runs it over the parsed
/// id files, [`crate::tables::first_conflict`] over the generated tables and
/// the host rows over fixtures.
pub fn first_overlap<A, B, PA, PB>(a: &[A], b: &[B], pa: PA, pb: PB) -> Option<(usize, usize)>
where
    PA: for<'x> Fn(&'x A) -> Pattern<'x>,
    PB: for<'x> Fn(&'x B) -> Pattern<'x>,
{
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            if pa(x).overlaps(&pb(y)) {
                return Some((i, j));
            }
        }
    }
    None
}
