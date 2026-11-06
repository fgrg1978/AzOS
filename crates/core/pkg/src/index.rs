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

use azos_crypto::sha256::{sha256, Sha256};
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
    /// The serial is the one this device accepted, and the body is another.
    Diverged,
    /// The file kept for this key's slot is another signer's (two keys share
    /// a slot name).
    SlotTaken,
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

    /// Every floor the index names, as the device remembers them: the
    /// [`name_hash`] of the package under `signer` and the floor.
    pub fn floors(&self, signer: &SignerKey) -> impl Iterator<Item = (u64, Version)> + '_ {
        let signer = *signer;
        (0..self.entries).filter_map(move |i| {
            let e = self.get(i)?;
            e.sec_floor.map(|f| (name_hash(&signer, e.name), f))
        })
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

    /// This index as the mark that records it.
    pub fn mark(&self) -> Mark {
        Mark { serial: self.serial, digest: u64::from_be_bytes(self.digest[..8].try_into().unwrap_or([0; 8])) }
    }

    /// Is this index no older than the one the device already accepted, and
    /// the same one when the serial is the same? `seen` is the mark of that
    /// index, `None` when the device has none.
    pub fn check_against(&self, seen: Option<Mark>) -> Result<(), IndexWhy> {
        match seen {
            Some(m) if self.serial < m.serial => Err(IndexWhy::Stale),
            Some(m) if self.serial == m.serial && self.mark().digest != m.digest => Err(IndexWhy::Diverged),
            _ => Ok(()),
        }
    }

    /// The key id of the signer it was verified under.
    pub fn key_id(&self) -> [u8; 32] {
        self.signer.key_id
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
    /// The staged version is itself an upgrade that has not been confirmed yet.
    Pending,
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

// ── One index per signer, and the device's memory of it ──────────────────────

/// The file name, in the staging volume's root, of the index signed by the key
/// whose id is `key_id`: `I`, seven hex digits of the id, `.AZX`. One slot per
/// signer, so one signer's index can neither replace another's nor use up its
/// serial.
pub fn slot_name(key_id: &[u8; 32]) -> [u8; 12] {
    let mut n = *b"I0000000.AZX";
    for (i, c) in n[1..8].iter_mut().enumerate() {
        let nib = if i % 2 == 0 { key_id[i / 2] >> 4 } else { key_id[i / 2] & 15 };
        *c = b"0123456789ABCDEF"[nib as usize];
    }
    n
}

/// Is `name` the file name of an index slot?
pub fn slot_name_ok(name: &[u8]) -> bool {
    name.len() == 12
        && name[0] == b'I'
        && name[8..] == *b".AZX"
        && name[1..8].iter().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c))
}

/// A signer as the device's memory names it: the first sixteen bytes of its key
/// id (the topology refuses two signers whose ids agree on the first four, so
/// the name is unambiguous and cannot be ground against another signer's).
pub type SignerKey = [u8; 16];

/// The memory key of the signer whose key id is `key_id`.
pub fn mark_key(key_id: &[u8; 32]) -> SignerKey {
    let mut k = [0u8; 16];
    k.copy_from_slice(&key_id[..16]);
    k
}

/// A package name as a floor is filed under it: eight bytes of
/// `sha256(signer || name)`.
pub fn name_hash(signer: &SignerKey, name: &str) -> u64 {
    let mut m = [0u8; 16 + 32];
    m[..16].copy_from_slice(signer);
    m[16..16 + name.len()].copy_from_slice(name.as_bytes());
    let d = sha256(&m[..16 + name.len()]);
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// What the device remembers of the newest index it accepted from a signer:
/// the serial and the first eight bytes of the body's SHA-256.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mark {
    /// The index's serial.
    pub serial: u32,
    /// The first eight bytes of the body's digest.
    pub digest: u64,
}

/// Why the memory could not take an index.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MarkErr {
    /// The table has no room for another signer or another floor (raise the
    /// Kconfig `PKG_INDEX_MARK_SECTORS`): nothing was changed.
    Full,
    /// The index names more floors for the signer's staged packages than the
    /// per-signer quota (Kconfig `PKG_INDEX_FLOORS_PER_SIGNER`) holds: nothing
    /// was changed, and no signer can take another's room.
    Quota,
    /// The record could not be made durable.
    Write,
}

/// Where the newest accepted index of each signer is remembered, with the floors
/// it named. The kernel keeps them where no writer of the staging volume reaches
/// (the reserved tail, like the topology counter floor).
pub trait Marks {
    /// The mark of `signer`.
    fn mark(&self, signer: &SignerKey) -> Option<Mark>;
    /// The floor `signer`'s newest accepted index named for package `name`.
    fn floor(&self, signer: &SignerKey, name: &str) -> Option<Version>;
    /// Remember `mark` as `signer`'s newest index and `floors` (by
    /// [`name_hash`]) as the floors it names, replacing the floors remembered
    /// from the signer's earlier index. All or nothing.
    fn accept(&self, signer: &SignerKey, mark: Mark, floors: &[(u64, Version)]) -> Result<(), MarkErr>;
    /// The memory was written before and no copy of it can be read now (media
    /// damage): what it held is gone. Nothing is remembered until the next
    /// [`accept`](Self::accept) writes it again.
    fn lost(&self) -> bool {
        false
    }
}

/// A memory that remembers nothing and takes nothing: a device whose medium has
/// no records store.
pub struct NoMarks;

impl Marks for NoMarks {
    fn mark(&self, _: &SignerKey) -> Option<Mark> {
        None
    }
    fn floor(&self, _: &SignerKey, _: &str) -> Option<Version> {
        None
    }
    fn accept(&self, _: &SignerKey, _: Mark, _: &[(u64, Version)]) -> Result<(), MarkErr> {
        Err(MarkErr::Write)
    }
}

const MARKS_MAGIC: [u8; 4] = *b"KPIX";
const MARKS_VERSION: u8 = 3;
/// Bytes of one table entry on the medium.
pub const ENTRY_LEN: usize = 36;
const SECTOR: usize = 512;
/// magic, version, generation, sector index, sectors in the bank, entries here.
const HEAD: usize = 12;
const BANK_DIGEST: usize = 8;
const TAG: usize = 4;
/// Entries one sector holds.
pub const SECTOR_ENTRIES: usize = (SECTOR - HEAD - BANK_DIGEST - TAG) / ENTRY_LEN;
/// Most sectors a bank spans (the Kconfig `PKG_INDEX_MARK_SECTORS` ceiling).
pub const BANK_SECTORS_MAX: usize = 2;
const ENTRIES_MAX: usize = BANK_SECTORS_MAX * SECTOR_ENTRIES;
const KIND_MARK: u8 = 1;
const KIND_FLOOR: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Slot {
    kind: u8,
    signer: SignerKey,
    a: u64,
    b: u64,
}

const NO_ENTRY: Slot = Slot { kind: 0, signer: [0; 16], a: 0, b: 0 };

/// The marks and floors: per signer one mark entry and at most `quota` floor
/// entries, so a signer takes room only up to its quota and never another's.
#[derive(Clone, Copy)]
pub struct MarkTable {
    entries: [Slot; ENTRIES_MAX],
    n: usize,
    cap: usize,
    quota: usize,
}

impl PartialEq for MarkTable {
    fn eq(&self, other: &Self) -> bool {
        self.cap == other.cap && self.live() == other.live()
    }
}

impl Eq for MarkTable {}

impl core::fmt::Debug for MarkTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MarkTable").field("sectors", &self.sectors()).field("entries", &self.live()).finish()
    }
}

impl MarkTable {
    /// An empty table whose bank spans `sectors` sectors (1 to
    /// [`BANK_SECTORS_MAX`]), holding at most `quota` floors per signer.
    pub const fn new(sectors: usize, quota: usize) -> Self {
        let s = if sectors == 0 { 1 } else if sectors > BANK_SECTORS_MAX { BANK_SECTORS_MAX } else { sectors };
        Self { entries: [NO_ENTRY; ENTRIES_MAX], n: 0, cap: s * SECTOR_ENTRIES, quota }
    }

    /// Sectors a bank of the table spans.
    pub const fn sectors(&self) -> usize {
        self.cap / SECTOR_ENTRIES
    }

    fn live(&self) -> &[Slot] {
        &self.entries[..self.n]
    }

    /// The mark of `signer`.
    pub fn mark(&self, signer: &SignerKey) -> Option<Mark> {
        self.live()
            .iter()
            .find(|e| e.kind == KIND_MARK && e.signer == *signer)
            .map(|e| Mark { serial: e.a as u32, digest: e.b })
    }

    /// The floor remembered for the package whose [`name_hash`] is `hash`.
    pub fn floor_of(&self, signer: &SignerKey, hash: u64) -> Option<Version> {
        self.live().iter().find(|e| e.kind == KIND_FLOOR && e.signer == *signer && e.a == hash).map(|e| Version::from_packed(e.b))
    }

    /// Remember `mark` and `floors` for `signer` in place of what it had. The
    /// table is unchanged when the floors are over the quota or would not fit.
    pub fn accept(&mut self, signer: &SignerKey, mark: Mark, floors: &[(u64, Version)]) -> Result<(), MarkErr> {
        if floors.len() > self.quota {
            return Err(MarkErr::Quota);
        }
        let mut next = *self;
        next.retain(|e| e.signer != *signer);
        if next.n + 1 + floors.len() > next.cap {
            return Err(MarkErr::Full);
        }
        next.push(Slot { kind: KIND_MARK, signer: *signer, a: mark.serial as u64, b: mark.digest });
        for (h, v) in floors {
            next.push(Slot { kind: KIND_FLOOR, signer: *signer, a: *h, b: v.packed() });
        }
        *self = next;
        Ok(())
    }

    fn retain(&mut self, keep: impl Fn(&Slot) -> bool) {
        let mut w = 0;
        for r in 0..self.n {
            if keep(&self.entries[r]) {
                self.entries[w] = self.entries[r];
                w += 1;
            }
        }
        self.n = w;
    }

    fn push(&mut self, e: Slot) {
        self.entries[self.n] = e;
        self.n += 1;
    }

    fn entry_bytes(e: &Slot) -> [u8; ENTRY_LEN] {
        let mut b = [0u8; ENTRY_LEN];
        b[0] = e.kind;
        b[1..17].copy_from_slice(&e.signer);
        b[17..25].copy_from_slice(&e.a.to_le_bytes());
        b[25..33].copy_from_slice(&e.b.to_le_bytes());
        b
    }

    /// The digest of a whole bank: its generation, the sectors it spans and every
    /// entry, in order.
    fn bank_digest(&self, gen: u32) -> [u8; BANK_DIGEST] {
        let mut h = Sha256::new();
        h.update(&gen.to_le_bytes());
        h.update(&[self.sectors() as u8, self.n as u8]);
        for e in self.live() {
            h.update(&Self::entry_bytes(e));
        }
        let d = h.finalize();
        let mut out = [0u8; BANK_DIGEST];
        out.copy_from_slice(&d[..BANK_DIGEST]);
        out
    }

    /// The table as one bank of generation `gen`: [`sectors`](Self::sectors)
    /// sectors, each with the generation, its place in the bank, the digest of the
    /// WHOLE bank and its own tag, so a bank is whole only when every sector is
    /// there, of one generation and agreeing with the digest.
    pub fn encode_bank(&self, gen: u32) -> [[u8; SECTOR]; BANK_SECTORS_MAX] {
        let mut out = [[0u8; SECTOR]; BANK_SECTORS_MAX];
        let digest = self.bank_digest(gen);
        for (i, sec) in out.iter_mut().enumerate().take(self.sectors()) {
            sec[..4].copy_from_slice(&MARKS_MAGIC);
            sec[4] = MARKS_VERSION;
            sec[5..9].copy_from_slice(&gen.to_le_bytes());
            sec[9] = i as u8;
            sec[10] = self.sectors() as u8;
            let from = (i * SECTOR_ENTRIES).min(self.n);
            let es = &self.entries[from..(from + SECTOR_ENTRIES).min(self.n)];
            sec[11] = es.len() as u8;
            for (k, e) in es.iter().enumerate() {
                let at = HEAD + k * ENTRY_LEN;
                sec[at..at + ENTRY_LEN].copy_from_slice(&Self::entry_bytes(e));
            }
            sec[SECTOR - TAG - BANK_DIGEST..SECTOR - TAG].copy_from_slice(&digest);
            let tag = sha256(&sec[..SECTOR - TAG]);
            sec[SECTOR - TAG..].copy_from_slice(&tag[..TAG]);
        }
        out
    }

    /// A bank read from `raw` (its first `sectors` sectors): the table and its
    /// generation, or `None` when any sector is not a valid record, the sectors
    /// disagree on generation or place, or the digest of the whole does not match.
    fn decode_bank(raw: &[[u8; SECTOR]], sectors: usize, quota: usize) -> Option<(Self, u32)> {
        let mut t = Self::new(sectors, quota);
        let (mut gen, mut digest) = (None, [0u8; BANK_DIGEST]);
        for (i, s) in raw.iter().enumerate().take(sectors) {
            if s[..4] != MARKS_MAGIC || s[4] != MARKS_VERSION || s[SECTOR - TAG..] != sha256(&s[..SECTOR - TAG])[..TAG] {
                return None;
            }
            let g = u32::from_le_bytes(s[5..9].try_into().ok()?);
            if s[9] as usize != i || s[10] as usize != sectors || *gen.get_or_insert(g) != g {
                return None;
            }
            let d = &s[SECTOR - TAG - BANK_DIGEST..SECTOR - TAG];
            if i == 0 {
                digest.copy_from_slice(d);
            } else if digest != d {
                return None;
            }
            let n = s[11] as usize;
            if n > SECTOR_ENTRIES || t.n + n > t.cap {
                return None;
            }
            for k in 0..n {
                let at = HEAD + k * ENTRY_LEN;
                if !matches!(s[at], KIND_MARK | KIND_FLOOR) {
                    return None;
                }
                let mut signer = [0u8; 16];
                signer.copy_from_slice(&s[at + 1..at + 17]);
                let a = u64::from_le_bytes(s[at + 17..at + 25].try_into().ok()?);
                let b = u64::from_le_bytes(s[at + 25..at + 33].try_into().ok()?);
                t.push(Slot { kind: s[at], signer, a, b });
            }
        }
        let gen = gen?;
        (t.bank_digest(gen) == digest).then_some((t, gen))
    }
}

/// What the medium holds of the marks.
#[derive(Clone, Copy, Debug)]
pub enum Loaded {
    /// Nothing was ever written (every sector is zero): no marks.
    Pristine(MarkTable),
    /// The valid bank of the highest generation.
    Bank {
        /// Its table.
        table: MarkTable,
        /// Its generation.
        gen: u32,
        /// Which of the two banks it is.
        bank: usize,
    },
    /// Something was written and no bank can be read whole now.
    Lost(MarkTable),
}

/// Read the marks from `raw[bank][sector]`, the two banks of `sectors` sectors.
/// A bank that fails its digest, or any sector of it, is ignored (never read as
/// zeros); the other one stands. Two banks that both fail are [`Loaded::Lost`]
/// unless every sector is zero, which is a medium nothing was written on.
pub fn load_banks(raw: &[[[u8; SECTOR]; BANK_SECTORS_MAX]; 2], sectors: usize, quota: usize) -> Loaded {
    let empty = MarkTable::new(sectors, quota);
    let sectors = empty.sectors();
    if raw.iter().all(|b| b[..sectors].iter().all(|s| s.iter().all(|&x| x == 0))) {
        return Loaded::Pristine(empty);
    }
    let a = MarkTable::decode_bank(&raw[0], sectors, quota).map(|(t, g)| (t, g, 0));
    let b = MarkTable::decode_bank(&raw[1], sectors, quota).map(|(t, g)| (t, g, 1));
    match (a, b) {
        (Some(x), Some(y)) => {
            let (table, gen, bank) = if y.1 > x.1 { y } else { x };
            Loaded::Bank { table, gen, bank }
        }
        (Some((table, gen, bank)), None) | (None, Some((table, gen, bank))) => Loaded::Bank { table, gen, bank },
        (None, None) => Loaded::Lost(empty),
    }
}

/// The reserved tail as the marks need it.
pub trait Tail {
    /// Whether the medium has a records store at all.
    fn writable(&self) -> bool;
    /// Read tail sector `sector` (counted from the first the marks use).
    fn read(&self, sector: usize, out: &mut [u8; 512]) -> bool;
    /// Write tail sector `sector`.
    fn write(&self, sector: usize, data: &[u8; 512]) -> bool;
    /// Make what was written durable.
    fn flush(&self) -> bool;
}

struct State {
    table: MarkTable,
    gen: u32,
    /// The bank that holds `table` on the medium.
    bank: Option<usize>,
    lost: bool,
}

/// The marks over a [`Tail`]: two banks, written one after the other. The bank
/// that holds the newest valid copy is never written; the other one is written
/// whole, and it wins the moment its last sector verifies, so no cut or tear of
/// a write leaves fewer marks than before.
pub struct MarkStore<T: Tail> {
    tail: T,
    sectors: usize,
    state: core::cell::RefCell<State>,
}

impl<T: Tail> MarkStore<T> {
    /// Read the marks from `tail`: banks of `sectors` sectors, `quota` floors per signer.
    pub fn load(tail: T, sectors: usize, quota: usize) -> Self {
        let mut raw = [[[0u8; SECTOR]; BANK_SECTORS_MAX]; 2];
        let n = MarkTable::new(sectors, quota).sectors();
        let usable = tail.writable();
        if usable {
            for (b, bank) in raw.iter_mut().enumerate() {
                for (i, sec) in bank.iter_mut().enumerate().take(n) {
                    // A sector that cannot be read is not zero: it makes its bank invalid.
                    if !tail.read(b * n + i, sec) {
                        *sec = [0xFF; SECTOR];
                    }
                }
            }
        }
        let state = if !usable {
            State { table: MarkTable::new(sectors, quota), gen: 0, bank: None, lost: false }
        } else {
            match load_banks(&raw, sectors, quota) {
                Loaded::Pristine(table) => State { table, gen: 0, bank: None, lost: false },
                Loaded::Bank { table, gen, bank } => State { table, gen, bank: Some(bank), lost: false },
                Loaded::Lost(table) => State { table, gen: 0, bank: None, lost: true },
            }
        };
        Self { tail, sectors: MarkTable::new(sectors, quota).sectors(), state: core::cell::RefCell::new(state) }
    }
}

impl<T: Tail> Marks for MarkStore<T> {
    fn mark(&self, signer: &SignerKey) -> Option<Mark> {
        self.state.borrow().table.mark(signer)
    }

    fn floor(&self, signer: &SignerKey, name: &str) -> Option<Version> {
        self.state.borrow().table.floor_of(signer, name_hash(signer, name))
    }

    fn lost(&self) -> bool {
        self.state.borrow().lost
    }

    fn accept(&self, signer: &SignerKey, mark: Mark, floors: &[(u64, Version)]) -> Result<(), MarkErr> {
        if !self.tail.writable() {
            return Err(MarkErr::Write);
        }
        let mut st = self.state.borrow_mut();
        let mut next = st.table;
        next.accept(signer, mark, floors)?;
        if next == st.table && !st.lost {
            return Ok(());
        }
        let gen = st.gen.checked_add(1).ok_or(MarkErr::Write)?;
        // **Canary** `pkg-bank-canary`: over the bank that holds the newest copy.
        let target = if cfg!(feature = "pkg-bank-canary") { st.bank.unwrap_or(0) } else { st.bank.map_or(0, |b| 1 - b) };
        let bank = next.encode_bank(gen);
        for (i, sec) in bank.iter().enumerate().take(self.sectors) {
            if !self.tail.write(target * self.sectors + i, sec) {
                return Err(MarkErr::Write);
            }
        }
        if !self.tail.flush() {
            return Err(MarkErr::Write);
        }
        *st = State { table: next, gen, bank: Some(target), lost: false };
        Ok(())
    }
}

/// What a signer's floors are, as far as the device can tell.
#[derive(Clone, Copy, Debug)]
pub enum Floors<'p, 'a> {
    /// The signer's newest index, at or above everything the device has seen
    /// from it.
    Known(Index<'p, 'a>),
    /// The device has seen an index from this signer and cannot show one at or
    /// above it (the file was deleted, replaced by an older signed one, or
    /// differs at the same serial): the floors are the ones remembered from the
    /// newest index it accepted ([`Marks::floor`]), and a package without one
    /// has none.
    Remembered,
    /// The device has never seen an index from this signer: no floors.
    None,
}

/// The floors of signer `signer_index` of `topo`, from the bytes of its slot
/// (`None` when the file is not there) and the mark the device holds for it.
/// The second part is the mark to record when the index is newer than the one
/// remembered.
///
/// **Canary** `pkg-mark-canary`: the device remembers nothing, so a replayed or
/// deleted index passes as the first one.
pub fn judge<'p, 'a>(
    bytes: Option<&'p [u8]>,
    topo: &Topology<'a>,
    signer_index: usize,
    seen: Option<Mark>,
) -> (Floors<'p, 'a>, Option<Mark>) {
    let seen = if cfg!(feature = "pkg-mark-canary") { None } else { seen };
    let ix = bytes
        .and_then(|b| verify(b, topo).ok())
        .filter(|ix| ix.signer_index == signer_index && ix.check_against(seen).is_ok());
    match (ix, seen) {
        (Some(ix), seen) => {
            let raise = seen.is_none_or(|m| ix.serial > m.serial).then(|| ix.mark());
            (Floors::Known(ix), raise)
        }
        (None, Some(_)) => (Floors::Remembered, None),
        (None, None) => (Floors::None, None),
    }
}

/// Is a package at `installed` below the remembered `floor`? A version with no
/// order cannot be shown to meet it.
pub fn below_remembered(installed: &str, floor: Version) -> bool {
    match Version::parse(installed) {
        Ok(v) => !meets(v, floor),
        Err(_) => true,
    }
}
