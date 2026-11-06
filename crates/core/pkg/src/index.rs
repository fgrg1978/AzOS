// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The repository index: what the configured package source offers, signed.
//!
//! One file, `INDEX.AZX`, next to the package the source rows name. It lists,
//! per package, the newest version, the id of that build and optionally the
//! lowest version still considered secure (`sec_floor`). It is signed by one of
//! the device's signers and verified by the same steps as a package
//! ([`crate::verify::authenticate`]): algorithm, signer, signature, and only
//! then is a byte of the body read.
//!
//! ```text
//! offset size
//!      0    4  magic "AZIX"
//!      4    2  format (1)
//!      6    2  signature algorithm ([`crate::SigAlg`])
//!      8    2  key_len
//!     10    2  sig_len
//!     12    4  body_len
//!     16  key_len | sig_len | body_len        nothing may follow the body
//! ```
//!
//! The signed message is [`DOMAIN`], the algorithm id (2 bytes LE) and the
//! SHA-256 of the body, so a package signature cannot be replayed as an index
//! and the reverse. The body is a strict subset of TOML:
//!
//! ```toml
//! format = 1
//! serial = 7                         # never goes backwards on a device
//!
//! [pkg.acme-vision]                  # names strictly increasing, one section each
//! version = "1.3.0"                  # newest build on offer
//! sec_floor = "1.2.0"                # optional: below this is not secure
//! id = "<64 hex>"                    # Package::id of that build
//! file = "ACMEV130.PKG"              # next to the index; [A-Za-z0-9._-]{1,32}
//! ```
//!
//! # What an index can and cannot do
//!
//! It cannot install anything: `upgrade` fetches the package it names, pins it
//! by `id`, and verifies and admits it exactly as any package, so an index can
//! point at a build but never vouch for one. It can only speak about packages
//! installed under ITS OWN signer: an entry for a name installed from another
//! signer is ignored ([`Availability::OtherSigner`]), so a signer cannot raise
//! the floor of, or push an upgrade onto, another author's package.
//!
//! # Versions
//!
//! An ordering needs a grammar. A version that has one to four dot-separated
//! decimal components (each at most 65535, no leading zero) is a [`Version`]
//! and compares component by component, missing components being 0. Any other
//! package version (`1.0-rc1`) is valid metadata but unordered: it is reported
//! as such, `upgrade` refuses it, and the floor check treats it as below the
//! floor (an unknown cannot be shown secure).

use core::fmt;
use core::ops::ControlFlow;

use azos_crypto::sha256::sha256;
use azos_topology::{SignerSpec, Topology};

use crate::container::{le16, le32, KEY_LEN_MAX, SIG_LEN_MAX};
use crate::meta::{hex32, name_ok, quoted, trim, uint, Meta};
use crate::verify::{authenticate, AuthError};

/// `AZIX`.
pub const MAGIC: [u8; 4] = *b"AZIX";
/// The only container format.
pub const FORMAT: u16 = 1;
/// The only body format.
pub const BODY_FORMAT: u32 = 1;
/// Bytes before the key.
pub const HEADER_LEN: usize = 16;
/// The domain tag of the signed message.
pub const DOMAIN: [u8; 12] = *b"azos-idx-v1\0";
/// Bytes of the signed message: tag, algorithm, SHA-256 of the body.
pub const MESSAGE_LEN: usize = DOMAIN.len() + 2 + 32;
/// Entries one index may list (Kconfig `PKG_INDEX_MAX_ENTRIES`).
pub const MAX_ENTRIES: usize = azos_limits::PKG_INDEX_MAX_ENTRIES as usize;
/// Bytes of body one entry may take at most.
pub const ENTRY_MAX: usize = 256;
/// Longest body: the entries and a small header.
pub const BODY_MAX: usize = 64 + MAX_ENTRIES * ENTRY_MAX;
/// Longest index file.
pub const FILE_MAX: usize = HEADER_LEN + KEY_LEN_MAX + SIG_LEN_MAX + BODY_MAX;
/// Longest file name an entry names.
pub const NAME_FILE_MAX: usize = 32;

/// Is `f` a file name beside the index: one path segment of
/// `[A-Za-z0-9._-]`, at most [`NAME_FILE_MAX`] long, and not made only of dots
/// (`.` and `..` name directories).
pub fn file_name_ok(f: &[u8]) -> bool {
    name_ok(f) && f.len() <= NAME_FILE_MAX && f.iter().any(|&b| b != b'.')
}

/// A package version that has an order: up to four decimal components.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version(pub [u16; 4]);

/// Why a version text has no order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VersionError {
    /// Empty, or a component that is not decimal digits, has a leading zero
    /// or is past 65535.
    Component,
    /// More than four components.
    TooMany,
}

impl Version {
    /// The version `s` spells.
    pub fn parse(s: &str) -> Result<Self, VersionError> {
        let mut v = [0u16; 4];
        let mut n = 0;
        for part in s.split('.') {
            if n == v.len() {
                return Err(VersionError::TooMany);
            }
            let b = part.as_bytes();
            let ok = !b.is_empty() && b.len() <= 5 && b.iter().all(u8::is_ascii_digit) && (b.len() == 1 || b[0] != b'0');
            v[n] = ok.then(|| part.parse::<u32>().ok().and_then(|x| u16::try_from(x).ok())).flatten().ok_or(VersionError::Component)?;
            n += 1;
        }
        Ok(Version(v))
    }

    /// The four components as one number (the first is the most significant),
    /// the form a reply word carries.
    pub const fn packed(self) -> u64 {
        (self.0[0] as u64) << 48 | (self.0[1] as u64) << 32 | (self.0[2] as u64) << 16 | self.0[3] as u64
    }

    /// The inverse of [`packed`](Self::packed).
    pub const fn from_packed(w: u64) -> Self {
        Version([(w >> 48) as u16, (w >> 32) as u16, (w >> 16) as u16, w as u16])
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        if d != 0 {
            write!(f, "{a}.{b}.{c}.{d}")
        } else {
            write!(f, "{a}.{b}.{c}")
        }
    }
}

/// Why an index was refused. One flat code so a decision record can carry it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IndexWhy {
    /// Shorter than its header or the lengths it declares.
    Short = 1,
    /// Not `AZIX`.
    Magic,
    /// A container format this reader does not know.
    Format,
    /// A length past its ceiling, or parts that do not add up to the file.
    Length,
    /// The algorithm is not the device's, or the key or signature has a
    /// length no key or signature of that algorithm has.
    Algorithm,
    /// The signing key is not one of the topology's signers.
    UnknownSigner,
    /// The signature does not verify.
    Signature,
    /// The body is not UTF-8 text.
    Text,
    /// A line that is not `key = value`, a section header, a comment or blank.
    Syntax,
    /// A key or section this format does not have, or one out of its place.
    Unknown,
    /// A key given twice, or package names not strictly increasing.
    Repeated,
    /// A value outside the alphabet, length or range its key has, or a
    /// version that has no order.
    Value,
    /// A required key is missing.
    Missing,
    /// More entries than `PKG_INDEX_MAX_ENTRIES`.
    TooMany,
    /// The body `format` is not [`BODY_FORMAT`].
    BodyFormat,
    /// The serial is below the one this device has already accepted.
    Stale,
}

impl From<AuthError> for IndexWhy {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Algorithm(_) => IndexWhy::Algorithm,
            AuthError::UnknownSigner => IndexWhy::UnknownSigner,
            AuthError::Signature => IndexWhy::Signature,
        }
    }
}

/// The message the signer signs.
pub fn message(alg_id: u16, body: &[u8]) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m[..12].copy_from_slice(&DOMAIN);
    m[12..14].copy_from_slice(&alg_id.to_le_bytes());
    m[14..].copy_from_slice(&sha256(body));
    m
}

/// One package the index lists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry<'a> {
    /// The package's name.
    pub name: &'a str,
    /// The newest version on offer.
    pub version: Version,
    /// The lowest version still considered secure, if the index says.
    pub sec_floor: Option<Version>,
    /// The id of the build on offer ([`crate::Package::id`]).
    pub id: [u8; 32],
    /// The file next to the index that holds it.
    pub file: &'a str,
}

struct Open<'a> {
    name: &'a str,
    version: Option<Version>,
    floor: Option<Version>,
    id: Option<[u8; 32]>,
    file: Option<&'a str>,
}

impl<'a> Open<'a> {
    fn close(self) -> Result<Entry<'a>, IndexWhy> {
        let version = self.version.ok_or(IndexWhy::Missing)?;
        // A floor above the build on offer could never be met by upgrading.
        if self.floor.is_some_and(|f| f > version) {
            return Err(IndexWhy::Value);
        }
        Ok(Entry {
            name: self.name,
            version,
            sec_floor: self.floor,
            id: self.id.ok_or(IndexWhy::Missing)?,
            file: self.file.ok_or(IndexWhy::Missing)?,
        })
    }
}

fn version_value(v: &[u8]) -> Result<Version, IndexWhy> {
    let text = quoted(v).and_then(|t| core::str::from_utf8(t).ok()).ok_or(IndexWhy::Value)?;
    Version::parse(text).map_err(|_| IndexWhy::Value)
}

/// Read the whole body, calling `f` with each entry in turn; `Break` stops the
/// walk (the totals are then partial). The body is checked to the byte on
/// every walk, so the walk that finds an entry is the one that validated it.
fn walk<'a>(
    body: &'a str,
    mut f: impl FnMut(usize, &Entry<'a>) -> ControlFlow<()>,
) -> Result<(u32, usize, bool), IndexWhy> {
    // 0: expect `format`, 1: expect `serial`, 2: sections.
    let (mut top, mut serial, mut count) = (0u8, 0u32, 0usize);
    let mut open: Option<Open<'a>> = None;
    let mut prev: Option<&'a str> = None;

    macro_rules! emit {
        ($o:expr) => {{
            let e = $o.close()?;
            if count == MAX_ENTRIES {
                return Err(IndexWhy::TooMany);
            }
            count += 1;
            if f(count - 1, &e).is_break() {
                return Ok((serial, count, true));
            }
        }};
    }

    for raw in body.as_bytes().split(|&b| b == b'\n') {
        let line = trim(raw.strip_suffix(b"\r").unwrap_or(raw));
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if line[0] == b'[' {
            if top != 2 {
                return Err(IndexWhy::Missing);
            }
            let inner = &line.strip_suffix(b"]").ok_or(IndexWhy::Syntax)?[1..];
            let name = inner.strip_prefix(b"pkg.").ok_or(IndexWhy::Unknown)?;
            if !name_ok(name) {
                return Err(IndexWhy::Value);
            }
            // The name was checked as ASCII above, and sits inside `body`.
            let name = core::str::from_utf8(name).map_err(|_| IndexWhy::Text)?;
            if prev.is_some_and(|p| p >= name) {
                return Err(IndexWhy::Repeated);
            }
            prev = Some(name);
            if let Some(o) = open.take() {
                emit!(o);
            }
            open = Some(Open { name, version: None, floor: None, id: None, file: None });
            continue;
        }
        let eq = line.iter().position(|&b| b == b'=').ok_or(IndexWhy::Syntax)?;
        let (key, val) = (trim(&line[..eq]), trim(&line[eq + 1..]));
        let Some(o) = open.as_mut() else {
            match (top, key) {
                (0, b"format") => {
                    if uint(val) != Some(BODY_FORMAT) {
                        return Err(IndexWhy::BodyFormat);
                    }
                }
                (1, b"serial") => serial = uint(val).ok_or(IndexWhy::Value)?,
                (0, _) => return Err(IndexWhy::BodyFormat),
                _ => return Err(IndexWhy::Unknown),
            }
            top += 1;
            continue;
        };
        match key {
            b"version" if o.version.is_none() => o.version = Some(version_value(val)?),
            b"sec_floor" if o.floor.is_none() => o.floor = Some(version_value(val)?),
            b"id" if o.id.is_none() => o.id = Some(quoted(val).and_then(hex32).ok_or(IndexWhy::Value)?),
            b"file" if o.file.is_none() => {
                let f = quoted(val).filter(|f| file_name_ok(f)).ok_or(IndexWhy::Value)?;
                o.file = Some(core::str::from_utf8(f).map_err(|_| IndexWhy::Text)?);
            }
            b"version" | b"sec_floor" | b"id" | b"file" => return Err(IndexWhy::Repeated),
            _ => return Err(IndexWhy::Unknown),
        }
    }
    if top != 2 {
        return Err(IndexWhy::Missing);
    }
    if let Some(o) = open.take() {
        emit!(o);
    }
    Ok((serial, count, false))
}

/// An index whose signature has verified.
#[derive(Clone, Copy, Debug)]
pub struct Index<'p, 'a> {
    body: &'p str,
    /// The serial the signer gave it.
    pub serial: u32,
    /// Entries it lists.
    pub entries: usize,
    /// The signer the topology admits it under (a copy).
    pub signer: SignerSpec<'a>,
    /// The signer's index in the topology.
    pub signer_index: usize,
    /// SHA-256 of the body: the index's identity.
    pub digest: [u8; 32],
}

/// Verify the index file `bytes` against the signers of `topo`. Nothing of the
/// body is read before the signature has verified.
pub fn verify<'p, 'a>(bytes: &'p [u8], topo: &Topology<'a>) -> Result<Index<'p, 'a>, IndexWhy> {
    if bytes.len() < HEADER_LEN {
        return Err(IndexWhy::Short);
    }
    if bytes[..4] != MAGIC {
        return Err(IndexWhy::Magic);
    }
    if le16(bytes, 4) != FORMAT as usize {
        return Err(IndexWhy::Format);
    }
    let (alg_id, key_len, sig_len, body_len) = (le16(bytes, 6) as u16, le16(bytes, 8), le16(bytes, 10), le32(bytes, 12));
    if key_len > KEY_LEN_MAX || sig_len > SIG_LEN_MAX || body_len > BODY_MAX {
        return Err(IndexWhy::Length);
    }
    let total = HEADER_LEN + key_len + sig_len + body_len;
    if bytes.len() < total {
        return Err(IndexWhy::Short);
    }
    if bytes.len() > total {
        return Err(IndexWhy::Length);
    }
    let (key, rest) = bytes[HEADER_LEN..].split_at(key_len);
    let (sig, body) = rest.split_at(sig_len);
    let (signer, signer_index) = authenticate(alg_id, key, sig, &message(alg_id, body), topo)?;
    let text = core::str::from_utf8(body).map_err(|_| IndexWhy::Text)?;
    let (serial, entries, _) = walk(text, |_, _| ControlFlow::Continue(()))?;
    Ok(Index { body: text, serial, entries, signer, signer_index, digest: sha256(body) })
}

impl<'p> Index<'p, '_> {
    /// The entry for package `name`.
    pub fn find(&self, name: &str) -> Option<Entry<'p>> {
        let mut found = None;
        let _ = walk(self.body, |_, e| {
            if e.name == name {
                found = Some(*e);
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        found
    }

    /// The `i`-th entry, in the order written.
    pub fn get(&self, i: usize) -> Option<Entry<'p>> {
        let mut found = None;
        let _ = walk(self.body, |n, e| {
            if n == i {
                found = Some(*e);
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        found
    }

    /// Is this index no older than the one the device already accepted?
    /// `stored` is that index's serial, `None` when the device has none.
    pub fn check_serial(&self, stored: Option<u32>) -> Result<(), IndexWhy> {
        match stored {
            Some(s) if self.serial < s => Err(IndexWhy::Stale),
            _ => Ok(()),
        }
    }
}

/// A package as installed: what the staged file's signed head says.
#[derive(Clone, Copy, Debug)]
pub struct Installed<'a> {
    /// Its name.
    pub name: &'a str,
    /// Its version text.
    pub version: &'a str,
    /// The index in the topology of the signer it verified under.
    pub signer_index: usize,
    /// Its package id.
    pub id: [u8; 32],
}

/// Where an installed package stands against what the index offers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Availability {
    /// The index does not list the package.
    NotListed,
    /// The index lists it but is signed by another signer than the package's,
    /// so it has no say.
    OtherSigner,
    /// The installed version is the one on offer.
    Current,
    /// A newer version is on offer.
    Behind(Version),
    /// The installed version is newer than the one on offer.
    Ahead(Version),
    /// The installed version has no order ([`Version::parse`] refused it).
    Unordered,
}

/// Where an installed package stands against the index's security floor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Floor {
    /// The index names no floor for it.
    NoFloor,
    /// It is at or above the floor.
    Met(Version),
    /// It is below the floor.
    Below(Version),
    /// It has a floor and the installed version has no order, so it cannot be
    /// shown to meet it.
    Unordered(Version),
}

/// The standing of one installed package.
#[derive(Clone, Copy, Debug)]
pub struct Assessment<'p> {
    /// Against the version on offer.
    pub availability: Availability,
    /// Against the floor.
    pub floor: Floor,
    /// The entry that applies (the signer matched), if any.
    pub entry: Option<Entry<'p>>,
}

impl Assessment<'_> {
    /// Is the package below its floor, or unable to show it meets it? The
    /// launch check refuses both.
    pub fn below_floor(&self) -> bool {
        matches!(self.floor, Floor::Below(_) | Floor::Unordered(_))
    }
}

fn meets(installed: Version, floor: Version) -> bool {
    cfg!(feature = "pkg-floor-canary") || installed >= floor
}

/// Where `installed` stands against `index`.
pub fn assess<'p>(installed: &Installed<'_>, index: &Index<'p, '_>) -> Assessment<'p> {
    let none = |availability| Assessment { availability, floor: Floor::NoFloor, entry: None };
    let Some(e) = index.find(installed.name) else { return none(Availability::NotListed) };
    if index.signer_index != installed.signer_index {
        return none(Availability::OtherSigner);
    }
    let have = Version::parse(installed.version);
    let availability = match have {
        Err(_) => Availability::Unordered,
        Ok(v) if v < e.version => Availability::Behind(e.version),
        Ok(v) if v == e.version => Availability::Current,
        Ok(_) => Availability::Ahead(e.version),
    };
    let floor = match (e.sec_floor, have) {
        (None, _) => Floor::NoFloor,
        (Some(f), Ok(v)) if meets(v, f) => Floor::Met(f),
        (Some(f), Ok(_)) => Floor::Below(f),
        (Some(f), Err(_)) => Floor::Unordered(f),
    };
    Assessment { availability, floor, entry: Some(e) }
}

/// Why an upgrade is refused. Checked in this order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpgradeWhy {
    /// No installed package has that name.
    NotInstalled = 1,
    /// The index does not list it.
    NotListed,
    /// The index is signed by another signer than the installed package's.
    OtherSigner,
    /// The installed version has no order.
    Unordered,
    /// The index offers nothing newer.
    NotNewer,
    /// The file fetched is another package than the entry names (its name).
    NameMismatch,
    /// The file fetched is not the build the entry pins (its id).
    IdMismatch,
    /// The file fetched carries another version than the entry says.
    VersionMismatch,
    /// The file fetched is signed by another signer than the installed package.
    SignerChanged,
    /// The version offered is below the installed one.
    Downgrade,
    /// The version offered is below the package's security floor.
    BelowFloor,
}

/// The entry an upgrade would install, given where the package stands: the
/// index lists a newer version, under the installed package's own signer.
pub fn upgrade_entry<'p>(a: &Assessment<'p>) -> Result<Entry<'p>, UpgradeWhy> {
    match (a.availability, a.entry) {
        (Availability::NotListed, _) => Err(UpgradeWhy::NotListed),
        (Availability::OtherSigner, _) => Err(UpgradeWhy::OtherSigner),
        (Availability::Unordered, _) => Err(UpgradeWhy::Unordered),
        (Availability::Behind(_), Some(e)) => Ok(e),
        _ => Err(UpgradeWhy::NotNewer),
    }
}

/// May `cand` (a package verified under signer `cand_signer`, with id
/// `cand_id`) replace `installed`, given the index's `entry` for it?
///
/// Never decides whether the package is acceptable on this device: the normal
/// verification and admission do, after this.
pub fn check_upgrade(
    installed: &Installed<'_>,
    entry: &Entry<'_>,
    cand: &Meta<'_>,
    cand_id: &[u8; 32],
    cand_signer: usize,
) -> Result<(), UpgradeWhy> {
    if cand.name != entry.name || cand.name != installed.name {
        return Err(UpgradeWhy::NameMismatch);
    }
    if cand_id != &entry.id {
        return Err(UpgradeWhy::IdMismatch);
    }
    let offered = Version::parse(cand.version).map_err(|_| UpgradeWhy::VersionMismatch)?;
    if offered != entry.version {
        return Err(UpgradeWhy::VersionMismatch);
    }
    let have = Version::parse(installed.version).map_err(|_| UpgradeWhy::Unordered)?;
    if cand_signer != installed.signer_index {
        return Err(UpgradeWhy::SignerChanged);
    }
    if !cfg!(feature = "pkg-downgrade-canary") && offered < have {
        return Err(UpgradeWhy::Downgrade);
    }
    if offered == have {
        return Err(UpgradeWhy::NotNewer);
    }
    if entry.sec_floor.is_some_and(|f| !meets(offered, f)) {
        return Err(UpgradeWhy::BelowFloor);
    }
    Ok(())
}
