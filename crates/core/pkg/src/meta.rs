// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The package metadata: who the package is, where it may run, what it needs of
//! the system and which images it carries.
//!
//! A strict subset of TOML, in this order, each key once:
//!
//! ```toml
//! format = 1
//! name = "acme-vision"
//! version = "1.2.0"
//! abi = 7                              # azos_abi::ABI_VERSION it was built for
//! hardware = ["sbc", "desktop"]        # embedded | sbc | desktop | server
//! sbom_sha256 = "<64 hex>"             # the SPDX document that travels beside the package
//!
//! [api]                                # the lowest level it needs of each interface
//! Names = 1
//! Decisions = 1
//!
//! [image.VISION.ELF]                   # one per program; 8.3, upper case, .ELF
//! size = 183264
//! sha256 = "<64 hex>"
//! ```
//!
//! The metadata is parsed only after its signature has verified. It is short
//! and checked to the byte: a name outside its alphabet, a key it does not
//! know, a repeated key, a section out of place or a missing key is a refusal,
//! never a default. The rows (the warrants and scheduling budgets the package
//! asks for) are not here: they are `[task.NAME]` sections in the topology's
//! own syntax, so the parser and the admission that judge a signed CAPS.TOM
//! judge them.

use azos_limits::{PKG_MAX_API, PKG_MAX_IMAGES};

/// The only metadata format.
pub const META_FORMAT: u32 = 1;
/// Interfaces one package may require (Kconfig `PKG_MAX_API`).
pub const MAX_API: usize = PKG_MAX_API as usize;
/// Images one package may carry (Kconfig `PKG_MAX_IMAGES`).
pub const MAX_IMAGES: usize = PKG_MAX_IMAGES as usize;

/// A hardware class, one bit of [`Meta::hardware`]. The device's own class is
/// Kconfig `HWCLASS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum HwClass {
    /// Small boards (`HWCLASS_EMBEDDED`).
    Embedded = 1,
    /// Single-board computers (`HWCLASS_SBC`).
    Sbc = 2,
    /// Desktops and workstations (`HWCLASS_DESKTOP`).
    Desktop = 4,
    /// Servers and gateways (`HWCLASS_SERVER`).
    Server = 8,
}

impl HwClass {
    /// The class Kconfig `HWCLASS` selected.
    pub const THIS: HwClass = if azos_limits::HWCLASS_EMBEDDED {
        HwClass::Embedded
    } else if azos_limits::HWCLASS_DESKTOP {
        HwClass::Desktop
    } else if azos_limits::HWCLASS_SERVER {
        HwClass::Server
    } else {
        HwClass::Sbc
    };

    /// The class a metadata word names.
    pub fn from_word(w: &[u8]) -> Option<Self> {
        Some(match w {
            b"embedded" => HwClass::Embedded,
            b"sbc" => HwClass::Sbc,
            b"desktop" => HwClass::Desktop,
            b"server" => HwClass::Server,
            _ => return None,
        })
    }
}

/// One image of the package.
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    /// The program's file name, 8.3, upper case, `.ELF`: also its row's name.
    pub name: &'a str,
    /// Its length in bytes.
    pub size: u32,
    /// Its SHA-256.
    pub sha256: [u8; 32],
}

/// The metadata, borrowed from its text.
#[derive(Clone, Copy, Debug)]
pub struct Meta<'a> {
    /// The package's name.
    pub name: &'a str,
    /// Its version, opaque text.
    pub version: &'a str,
    /// The ABI version it was built for.
    pub abi: u32,
    /// The classes it runs on (`HwClass` bits).
    pub hardware: u8,
    /// The SHA-256 of its SBOM.
    pub sbom_sha256: [u8; 32],
    api: [(&'a str, u32); MAX_API],
    api_len: usize,
    images: [Image<'a>; MAX_IMAGES],
    images_len: usize,
}

impl<'a> Meta<'a> {
    /// The interface levels it requires, in the order written.
    pub fn api(&self) -> &[(&'a str, u32)] {
        &self.api[..self.api_len]
    }

    /// Its images, in the order they follow one another in the container.
    pub fn images(&self) -> &[Image<'a>] {
        &self.images[..self.images_len]
    }

    /// May it run on `class`?
    pub fn runs_on(&self, class: HwClass) -> bool {
        self.hardware & class as u8 != 0
    }

    /// The total bytes of the images.
    pub fn images_total(&self) -> u64 {
        self.images().iter().map(|i| i.size as u64).sum()
    }
}

/// Why the metadata is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MetaError {
    /// Not UTF-8 text.
    Text,
    /// A line that is not `key = value`, a section header, a comment or blank.
    Syntax,
    /// A key or section this format does not have, or one out of its place.
    Unknown,
    /// A key or section given twice.
    Repeated,
    /// A value outside the alphabet, length or range its key has.
    Value,
    /// A required key is missing, or the package has no image.
    Missing,
    /// More images or interface levels than `PKG_MAX_IMAGES` / `PKG_MAX_API`.
    TooMany,
    /// `format` is not [`META_FORMAT`].
    Format,
}

const K_FORMAT: u8 = 1;
const K_NAME: u8 = 2;
const K_VERSION: u8 = 4;
const K_ABI: u8 = 8;
const K_HARDWARE: u8 = 16;
const K_SBOM: u8 = 32;
const K_ALL: u8 = 63;

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
}

/// A package name: 1..=32 of `[A-Za-z0-9._-]`.
fn name_ok(s: &[u8]) -> bool {
    !s.is_empty() && s.len() <= 32 && s.iter().all(|&b| is_word(b))
}

/// A version: 1..=24 of `[A-Za-z0-9._+-]`.
fn version_ok(s: &[u8]) -> bool {
    !s.is_empty() && s.len() <= 24 && s.iter().all(|&b| is_word(b) || b == b'+')
}

/// An interface name: a letter, then up to 23 letters and digits.
fn iface_ok(s: &[u8]) -> bool {
    !s.is_empty() && s.len() <= 24 && s[0].is_ascii_alphabetic() && s.iter().all(|b| b.is_ascii_alphanumeric())
}

/// An image name: FAT 8.3, upper case, extension `ELF`.
pub fn image_name_ok(s: &[u8]) -> bool {
    let Some(dot) = s.iter().position(|&b| b == b'.') else { return false };
    let (stem, ext) = (&s[..dot], &s[dot + 1..]);
    let up = |b: &u8| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_';
    (1..=8).contains(&stem.len()) && stem.iter().all(up) && ext == b"ELF"
}

fn trim(s: &[u8]) -> &[u8] {
    let a = s.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(s.len());
    let b = s.iter().rposition(|&b| b != b' ' && b != b'\t').map_or(a, |p| p + 1);
    &s[a..b]
}

fn hex32(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let nib = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = nib(s[2 * i])? << 4 | nib(s[2 * i + 1])?;
    }
    Some(out)
}

fn uint(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 10 || (s.len() > 1 && s[0] == b'0') {
        return None;
    }
    let mut n: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (b - b'0') as u64;
    }
    u32::try_from(n).ok()
}

/// `"text"` with nothing after it, no escapes: the text.
fn quoted(v: &[u8]) -> Option<&[u8]> {
    let inner = v.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    (!inner.contains(&b'"') && !inner.contains(&b'\\')).then_some(inner)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sect {
    Top,
    Api,
    Image,
}

impl<'a> Meta<'a> {
    /// Parse the metadata text.
    pub fn parse(text: &'a [u8]) -> Result<Self, MetaError> {
        core::str::from_utf8(text).map_err(|_| MetaError::Text)?;
        let empty = Image { name: "", size: 0, sha256: [0; 32] };
        let mut m = Meta {
            name: "",
            version: "",
            abi: 0,
            hardware: 0,
            sbom_sha256: [0; 32],
            api: [("", 0); MAX_API],
            api_len: 0,
            images: [empty; MAX_IMAGES],
            images_len: 0,
        };
        let (mut seen, mut sect, mut api_seen) = (0u8, Sect::Top, false);
        // The open image: its size and hash are set once each.
        let (mut size_set, mut hash_set) = (false, false);
        for raw in text.split(|&b| b == b'\n') {
            let line = trim(raw.strip_suffix(b"\r").unwrap_or(raw));
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            if line[0] == b'[' {
                let inner = &line.strip_suffix(b"]").ok_or(MetaError::Syntax)?[1..];
                if seen != K_ALL {
                    // Every top-level key comes before the first section.
                    return Err(MetaError::Missing);
                }
                if sect == Sect::Image && !(size_set && hash_set) {
                    return Err(MetaError::Missing);
                }
                if inner == b"api" {
                    if api_seen || m.images_len != 0 {
                        return Err(if api_seen { MetaError::Repeated } else { MetaError::Unknown });
                    }
                    api_seen = true;
                    sect = Sect::Api;
                } else if let Some(name) = inner.strip_prefix(b"image.") {
                    if !image_name_ok(name) {
                        return Err(MetaError::Value);
                    }
                    if m.images_len == MAX_IMAGES {
                        return Err(MetaError::TooMany);
                    }
                    // The name was checked as ASCII text above.
                    let name = core::str::from_utf8(name).map_err(|_| MetaError::Text)?;
                    if m.images().iter().any(|i| i.name == name) {
                        return Err(MetaError::Repeated);
                    }
                    m.images[m.images_len] = Image { name, size: 0, sha256: [0; 32] };
                    m.images_len += 1;
                    (size_set, hash_set) = (false, false);
                    sect = Sect::Image;
                } else {
                    return Err(MetaError::Unknown);
                }
                continue;
            }
            let eq = line.iter().position(|&b| b == b'=').ok_or(MetaError::Syntax)?;
            let (key, val) = (trim(&line[..eq]), trim(&line[eq + 1..]));
            match sect {
                Sect::Top => {
                    let bit = match key {
                        b"format" => K_FORMAT,
                        b"name" => K_NAME,
                        b"version" => K_VERSION,
                        b"abi" => K_ABI,
                        b"hardware" => K_HARDWARE,
                        b"sbom_sha256" => K_SBOM,
                        _ => return Err(MetaError::Unknown),
                    };
                    if seen & bit != 0 {
                        return Err(MetaError::Repeated);
                    }
                    // `format` leads: nothing else is read under a format this
                    // parser does not know.
                    if seen == 0 && bit != K_FORMAT {
                        return Err(MetaError::Format);
                    }
                    seen |= bit;
                    match bit {
                        K_FORMAT => {
                            if uint(val) != Some(META_FORMAT) {
                                return Err(MetaError::Format);
                            }
                        }
                        K_NAME => {
                            let v = quoted(val).filter(|v| name_ok(v)).ok_or(MetaError::Value)?;
                            m.name = core::str::from_utf8(v).map_err(|_| MetaError::Text)?;
                        }
                        K_VERSION => {
                            let v = quoted(val).filter(|v| version_ok(v)).ok_or(MetaError::Value)?;
                            m.version = core::str::from_utf8(v).map_err(|_| MetaError::Text)?;
                        }
                        K_ABI => m.abi = uint(val).ok_or(MetaError::Value)?,
                        K_HARDWARE => m.hardware = hardware(val)?,
                        _ => m.sbom_sha256 = quoted(val).and_then(hex32).ok_or(MetaError::Value)?,
                    }
                }
                Sect::Api => {
                    if !iface_ok(key) || m.api().iter().any(|(n, _)| n.as_bytes() == key) {
                        return Err(if iface_ok(key) { MetaError::Repeated } else { MetaError::Value });
                    }
                    let level = uint(val).filter(|&l| l != 0 && l <= u16::MAX as u32).ok_or(MetaError::Value)?;
                    if m.api_len == MAX_API {
                        return Err(MetaError::TooMany);
                    }
                    m.api[m.api_len] = (core::str::from_utf8(key).map_err(|_| MetaError::Text)?, level);
                    m.api_len += 1;
                }
                Sect::Image => {
                    let img = &mut m.images[m.images_len - 1];
                    match key {
                        b"size" if !size_set => {
                            img.size = uint(val).filter(|&n| n != 0).ok_or(MetaError::Value)?;
                            size_set = true;
                        }
                        b"sha256" if !hash_set => {
                            img.sha256 = quoted(val).and_then(hex32).ok_or(MetaError::Value)?;
                            hash_set = true;
                        }
                        b"size" | b"sha256" => return Err(MetaError::Repeated),
                        _ => return Err(MetaError::Unknown),
                    }
                }
            }
        }
        if seen != K_ALL || m.images_len == 0 || (sect == Sect::Image && !(size_set && hash_set)) {
            return Err(MetaError::Missing);
        }
        Ok(m)
    }
}

/// `["sbc", "desktop"]`: one or more known classes, none twice.
fn hardware(v: &[u8]) -> Result<u8, MetaError> {
    let inner = v.strip_prefix(b"[").and_then(|v| v.strip_suffix(b"]")).ok_or(MetaError::Value)?;
    let mut mask = 0u8;
    for item in inner.split(|&b| b == b',') {
        let item = trim(item);
        let class = quoted(item).and_then(HwClass::from_word).ok_or(MetaError::Value)? as u8;
        if mask & class != 0 {
            return Err(MetaError::Value);
        }
        mask |= class;
    }
    Ok(mask)
}
