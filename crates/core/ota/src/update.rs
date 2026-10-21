// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Atomic whole-system update: one signed manifest, one slot, one switch.
//!
//! An update is not a kernel: it is a kernel, the userspace images that run on
//! it, the topology that says what they may hold and the configuration they
//! read. Installing them one by one leaves a window in which the device runs a
//! kernel with the wrong topology. This module closes the window by making the
//! slot, not the file, the unit of installation:
//!
//! ```text
//!   manifest (signed)            slot A  (running, confirmed)
//!   ├ sec_epoch   floor         ┌───────────────────────────┐
//!   ├ fw_version  kernel        │ KERN_A.BIN  /fat/PKG/SYS_A│  the set of A
//!   ├ platform                  └───────────────────────────┘
//!   └ parts: kernel, kernel sig  slot B  (inactive: the target)
//!            CAPS.TOM CAPS.SIG   ┌───────────────────────────┐
//!            SCHED.TOM           │ KERN_B.BIN  /fat/PKG/SYS_B│  staged here
//!            CONFIG.INI [.SIG]   └───────────────────────────┘
//!            *.ELF
//! ```
//!
//! 1. **Stage** ([`stage`]): the bundle (manifest, then the parts in table
//!    order) is copied into the inactive slot's set directory. Every byte is
//!    hashed as it is copied and compared with the signed manifest, and the
//!    manifest is written LAST, as the completion marker; then the whole set is
//!    read back and verified ([`verify_set`]). The running system is never
//!    touched: a crash, a full volume or a forged part leaves no marker, and
//!    "no marker" is what the switch reads as "not staged".
//! 2. **Switch**: [`verify_set`] again by whoever holds the authority to
//!    change the boot record (the stager's verdict is not a trust anchor; the
//!    volume can be written by others), the kernel is promoted to the slot's
//!    boot path, and ONE BOOTMETA record names the new slot active
//!    (`pure::ota_switch_pure`). That record is the only step that changes
//!    what boots, and BOOTMETA's dual-record scheme makes it atomic.
//! 3. **Boot** ([`boot_set`]): the slot that is running resolves the userspace
//!    images, the topology and the configuration through its set directory, and
//!    only when BOOTMETA records a non-zero `sec_epoch` for it and the signed
//!    marker in the directory carries that epoch. A kernel-only install zeroes
//!    the epoch, so a slot that took one boots the volume's root files.
//! 4. **Confirm or roll back**: the existing boot machinery. A boot that is
//!    marked good moves `last_good` and the floors
//!    (`pure::ota_mark_boot_good_pure`); one that is not is rolled back after
//!    `max_attempts` boots (`pure::ota_boot_validate_pure`) to `last_good`,
//!    whose set was never touched. Kernel, images, topology and config share
//!    one slot, so they confirm and roll back together by construction.
//!
//! # Anti-rollback
//!
//! `sec_epoch` is the floor of the whole system. A manifest below the floor is
//! refused whatever its signature: the floor is the epoch of the last set that
//! booted and was confirmed, not of the last one installed.
//!
//! # What the signature covers
//!
//! The signature is over a domain tag and the manifest body: the algorithm,
//! the epoch, the kernel version, the platform and, for each part, its kind,
//! its 8.3 name, its size and its SHA-256. The algorithm id and the
//! signature's length are in the head, so any algorithm's signature fits
//! (`azos_crypto::sig`); the manifest of an algorithm other than the device's
//! (`SigAlg::CONFIGURED`) is not a manifest this build reads. Nothing
//! but the head is interpreted before it has verified. The part names are
//! inside the signature, so a part cannot be staged under another name.
//!
//! # Wire form
//!
//! ```text
//!   0   4  magic "AZUM"            24 + n*52  sig_len  signature
//!   4   2  format = 1
//!   6   2  signature algorithm id
//!   8   4  sec_epoch               part (52 bytes):
//!  12   4  kernel fw_version         0  1  kind  1 kernel, 2 kernel signature,
//!  16   1  platform                             3 topology, 4 config, 5 image
//!  17   3  zero                      1  3  zero
//!  20   2  n parts                   4  4  size
//!  22   2  sig_len                   8 12  name, NUL padded
//!  24  .. parts                     20 32  SHA-256
//! ```
//!
//! The bundle is the manifest followed by each part's bytes, in table order.
//!
//! This file is dependency-free apart from `azos_crypto` and `crate::pure`, so
//! the installer service (ring 3) and the host suite `#[path]`-include it
//! beside `pure.rs`, as the suite has always done for `pure.rs`.

#![allow(clippy::indexing_slicing)]

use azos_crypto::sha256::{Digest, Sha256};
use azos_crypto::sig::{Rsig, SigAlg, KEY_LEN, RSIG_FILE_MAX};

use crate::pure::{
    ota_update_allowed_pure, BootMeta, Crc32State, StagedSet, SwitchRefusal, SLOT_A, SLOT_B,
};

/// "AZUM": AzOS update manifest.
pub const MAGIC: [u8; 4] = *b"AZUM";
/// The format version this build reads.
pub const FORMAT: u16 = 1;
/// Bytes of the manifest head.
pub const HEAD_LEN: usize = 24;
/// Bytes of one part entry.
pub const ENTRY_LEN: usize = 52;
/// Bytes of the signature: the configured algorithm's.
pub const SIG_LEN: usize = azos_crypto::sig::SIG_LEN;
/// Parts one manifest holds at most.
pub const MAX_PARTS: usize = 32;
/// Bytes of a part name (8.3, NUL padded).
pub const NAME_LEN: usize = 12;
/// The longest manifest.
pub const MANIFEST_MAX: usize = HEAD_LEN + MAX_PARTS * ENTRY_LEN + SIG_LEN;
/// The file in a set directory whose presence, and valid signature, is what
/// "this set is fully staged" means.
pub const MARKER: &[u8] = b"UPDATE.MAN";
/// The part names the set must carry or may carry, by kind.
pub const KERNEL_NAME: &[u8] = b"KERN.BIN";
/// The kernel signature part.
pub const KERNEL_SIG_NAME: &[u8] = b"KERN.SIG";
/// The signed topology: the three files `azos_topology::signed` reads.
pub const TOPOLOGY_NAMES: [&[u8]; 3] = [b"CAPS.TOM", b"CAPS.SIG", b"SCHED.TOM"];
/// The configuration (and its optional signature).
pub const CONFIG_NAME: &[u8] = b"CONFIG.INI";
/// The configuration's signature.
pub const CONFIG_SIG_NAME: &[u8] = b"CONFIG.SIG";
/// Bytes a path of this module needs.
pub const PATH_MAX: usize = 32;

/// Domain separation: a signature over a manifest is never also one over a
/// kernel manifest (`manifest_message`), a package or a topology.
const DOMAIN: &[u8] = b"AZOS-SYSUPDATE-V1\0";

/// What a part is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// The kernel image, `KERN.BIN`.
    Kernel = 1,
    /// Its signature file, `KERN.SIG`, for the secure-boot gate.
    KernelSig = 2,
    /// `CAPS.TOM`, `CAPS.SIG`, `SCHED.TOM`.
    Topology = 3,
    /// `CONFIG.INI`, `CONFIG.SIG`.
    Config = 4,
    /// A userspace program, `NAME.ELF`.
    Image = 5,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Kind::Kernel,
            2 => Kind::KernelSig,
            3 => Kind::Topology,
            4 => Kind::Config,
            5 => Kind::Image,
            _ => return None,
        })
    }
}

/// One file of the set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Part {
    /// What it is.
    pub kind: Kind,
    /// Its length.
    pub size: u32,
    /// Its name, NUL padded.
    pub name: [u8; NAME_LEN],
    /// Its SHA-256.
    pub sha256: Digest,
}

impl Part {
    /// The entry `e` (exactly [`ENTRY_LEN`] bytes, kind already checked).
    fn decode(e: &[u8], kind: Kind) -> Part {
        let mut name = [0u8; NAME_LEN];
        name.copy_from_slice(&e[8..20]);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&e[20..52]);
        Part { kind, size: u32_at(e, 4), name, sha256 }
    }

    /// The name, without the padding.
    pub fn name(&self) -> &[u8] {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
        &self.name[..n]
    }
}

/// A manifest whose signature verified and whose parts are well formed. The
/// parts stay in the bytes they were read from (`'a`), decoded on demand, so a
/// manifest costs a few words of stack, not its table.
#[derive(Clone, Copy, Debug)]
pub struct Manifest<'a> {
    /// The anti-rollback epoch.
    pub sec_epoch: u32,
    /// The kernel's firmware version (also bound by `KERN.SIG`).
    pub fw_version: u32,
    /// The platform the set is for (`pure::OTA_PLATFORM_*`).
    pub platform: u8,
    n: usize,
    /// The part table, [`ENTRY_LEN`] bytes per part.
    table: &'a [u8],
}

/// Scratch for the signed message: the domain tag and the manifest body.
pub const MSG_MAX: usize = DOMAIN.len() + MANIFEST_MAX;

/// The buffers the manifest work needs, so that a caller with a small stack
/// (the kernel) keeps them in a static and one with a big one (the host suite)
/// keeps them on the stack. Zero-filled: `.bss`.
pub struct Work {
    msg: [u8; MSG_MAX],
    mb: [u8; MANIFEST_MAX + 1],
    id: u64,
}

impl Work {
    /// Empty buffers.
    pub const fn new() -> Self {
        Work { msg: [0; MSG_MAX], mb: [0; MANIFEST_MAX + 1], id: 0 }
    }

    /// The id ([`Manifest::id`]) of the last manifest [`stage`] or
    /// [`verify_set`] verified the signature of, even if it then refused the
    /// update for another reason; 0 if none had verified. A refusal's decision
    /// record names the manifest it was about.
    pub fn last_id(&self) -> u64 {
        self.id
    }
}

impl Default for Work {
    fn default() -> Self {
        Self::new()
    }
}

/// Why an update was refused. The first check that failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Shorter than its own table says, or than the smallest manifest.
    Truncated,
    /// Not a manifest, or a format this build does not read.
    Format,
    /// The signature does not verify under the trusted key.
    Signature,
    /// A reserved field is not zero.
    Reserved,
    /// Part `i` has a kind, a name or a size that is not valid.
    Part(u16),
    /// The parts do not make a bootable set (the detail says which rule).
    Shape(Shape),
    /// The set is for another platform.
    Platform,
    /// An earlier switch is still on trial.
    TrialPending,
    /// `sec_epoch` is below the floor.
    EpochFloor,
    /// The kernel version is below the firmware floor.
    FwFloor,
    /// The slot to switch to is not the inactive one.
    NotInactive,
    /// The bundle is not as long as the manifest says.
    Length,
    /// The kernel is larger than the device accepts.
    TooLarge,
    /// The volume or the bundle failed (the detail says where).
    Io(Io),
    /// Part `i` is not the signed one.
    PartHash(u16),
    /// The set directory holds no valid marker: nothing is staged.
    NotStaged,
    /// The set directory holds a file the manifest does not name.
    Extra,
    /// `KERN.SIG` does not describe the kernel the manifest names.
    KernelSig,
    /// The requester's Domain is held by its `ota` envelope row: the update
    /// may not get this far ([`Store::may_apply`]).
    Envelope,
}

/// Which access failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Io {
    /// Reading the bundle.
    Bundle,
    /// Making or clearing the set directory.
    Dir,
    /// Writing a part or the marker.
    Write,
    /// Reading a staged file back.
    Read,
}

/// The rule a set that is not bootable breaks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    /// Not exactly one kernel and one kernel signature.
    Kernel,
    /// A topology file is missing or not one of the three.
    Topology,
    /// `CONFIG.INI` is missing or a config part has another name.
    Config,
    /// An image is not named `*.ELF`.
    Image,
}

impl Refusal {
    /// The refusal as one number, for a decision record: bits 24.. the step,
    /// bits 0..24 its detail (a part index, the shape rule).
    pub const fn code(&self) -> u64 {
        let (step, low) = match *self {
            Refusal::Truncated => (48u64, 0u64),
            Refusal::Format => (49, 0),
            Refusal::Signature => (50, 0),
            Refusal::Reserved => (51, 0),
            Refusal::Part(i) => (52, i as u64),
            Refusal::Shape(s) => (53, s as u64),
            Refusal::Platform => (54, 0),
            Refusal::TrialPending => (55, 0),
            Refusal::EpochFloor => (56, 0),
            Refusal::FwFloor => (57, 0),
            Refusal::NotInactive => (58, 0),
            Refusal::Length => (59, 0),
            Refusal::TooLarge => (60, 0),
            Refusal::Io(w) => (61, w as u64),
            Refusal::PartHash(i) => (62, i as u64),
            Refusal::NotStaged => (63, 0),
            Refusal::Extra => (64, 0),
            Refusal::KernelSig => (65, 0),
            Refusal::Envelope => (66, 0),
        };
        step << 24 | low
    }
}

/// The step number of the first [`Refusal`] in [`Refusal::code`]; the steps
/// below it are the package installer's, and the installer's own table of step
/// names (`userspace/lib/packages`) carries one name for each from here.
pub const STEP_FIRST: u64 = 48;
/// How many refusal steps there are, from [`STEP_FIRST`].
pub const STEPS: u64 = 19;

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// A valid 8.3 name: 1..8 characters of `A-Z 0-9 _`, then optionally a dot and
/// 1..3 of them. Upper case only, so the name a FAT volume stores is the name
/// the manifest signed.
fn valid_name(n: &[u8]) -> bool {
    let ok = |c: &u8| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_';
    let (base, ext) = match n.iter().position(|&c| c == b'.') {
        Some(d) => (&n[..d], Some(&n[d + 1..])),
        None => (n, None),
    };
    (1..=8).contains(&base.len())
        && base.iter().all(ok)
        && ext.map_or(true, |e| (1..=3).contains(&e.len()) && e.iter().all(ok))
}

impl<'a> Manifest<'a> {
    /// The bytes the manifest takes, from the head (at least [`HEAD_LEN`]
    /// bytes): `None` if it is not a manifest head of a format this build
    /// reads or its table is too long. Reads nothing that is not needed to
    /// find the signature.
    pub fn wire_len(head: &[u8]) -> Option<usize> {
        if head.len() < HEAD_LEN || head[..4] != MAGIC || u16_at(head, 4) != FORMAT {
            return None;
        }
        let alg = SigAlg::accepted(u16_at(head, 6))?;
        let n = u16_at(head, 20) as usize;
        (n <= MAX_PARTS && u16_at(head, 22) as usize == alg.sig_len())
            .then_some(HEAD_LEN + n * ENTRY_LEN + alg.sig_len())
    }

    /// Verify `bytes` (exactly one manifest) under `key` and parse it. The
    /// signature is checked before any field but the head is interpreted.
    /// `msg` is scratch for the signed message.
    pub fn parse(bytes: &'a [u8], key: &[u8; KEY_LEN], msg: &mut [u8; MSG_MAX]) -> Result<Self, Refusal> {
        if bytes.len() < HEAD_LEN + SIG_LEN {
            return Err(Refusal::Truncated);
        }
        if bytes[..4] != MAGIC || u16_at(bytes, 4) != FORMAT {
            return Err(Refusal::Format);
        }
        // The algorithm and the signature's length are in the head, which the
        // signature covers; they are read first only to find the signature,
        // and only the device's own algorithm is read at all.
        let Some(alg) = SigAlg::accepted(u16_at(bytes, 6)) else {
            return Err(Refusal::Format);
        };
        let n = u16_at(bytes, 20) as usize;
        if n > MAX_PARTS || u16_at(bytes, 22) as usize != alg.sig_len() {
            return Err(Refusal::Format);
        }
        let body = HEAD_LEN + n * ENTRY_LEN;
        if bytes.len() != body + alg.sig_len() {
            return Err(Refusal::Truncated);
        }

        msg[..DOMAIN.len()].copy_from_slice(DOMAIN);
        msg[DOMAIN.len()..DOMAIN.len() + body].copy_from_slice(&bytes[..body]);
        if !cfg!(feature = "update-canary-sig") && !alg.verify(key, &msg[..DOMAIN.len() + body], &bytes[body..]) {
            return Err(Refusal::Signature);
        }

        // Signed: now the rest of the head.
        if bytes[17..20] != [0, 0, 0] {
            return Err(Refusal::Reserved);
        }
        // Epochs start at 1: BOOTMETA's 0 means "this slot holds no signed
        // set", which is what the boot reads to decide where its files are.
        if u32_at(bytes, 8) == 0 {
            return Err(Refusal::EpochFloor);
        }
        let m = Manifest {
            sec_epoch: u32_at(bytes, 8),
            fw_version: u32_at(bytes, 12),
            platform: bytes[16],
            n,
            table: &bytes[HEAD_LEN..body],
        };
        for i in 0..n {
            let e = &m.table[i * ENTRY_LEN..(i + 1) * ENTRY_LEN];
            let bad = Refusal::Part(i as u16);
            let kind = Kind::from_u8(e[0]).ok_or(bad)?;
            if e[1..4] != [0, 0, 0] {
                return Err(Refusal::Reserved);
            }
            let part = Part::decode(e, kind);
            // The padding must be NULs only, so one name has one encoding.
            let len = part.name().len();
            if part.size == 0 || !valid_name(part.name()) || part.name[len..].iter().any(|&b| b != 0) {
                return Err(bad);
            }
            if part.name() == MARKER || m.parts().take(i).any(|p| p.name() == part.name()) {
                return Err(bad);
            }
        }
        m.check_shape()?;
        Ok(m)
    }

    /// The parts, in table (and bundle) order.
    pub fn parts(&self) -> impl Iterator<Item = Part> + '_ {
        self.table.chunks_exact(ENTRY_LEN).map(|e| {
            // `parse` checked every kind; the fallback is never taken.
            Part::decode(e, Kind::from_u8(e[0]).unwrap_or(Kind::Image))
        })
    }

    /// The kernel part ([`Manifest::parse`] guarantees there is exactly one).
    pub fn kernel(&self) -> Part {
        self.parts().find(|p| p.kind == Kind::Kernel).unwrap_or(Part::decode(&[0; ENTRY_LEN], Kind::Kernel))
    }

    /// The parts' bytes together: what follows the manifest in the bundle.
    pub fn parts_len(&self) -> u64 {
        self.parts().map(|p| u64::from(p.size)).sum()
    }

    /// An id of the manifest for a decision record: the first eight bytes of
    /// its signature, which is as unique as the manifest and cannot be chosen
    /// without the key.
    pub fn id(bytes: &[u8]) -> u64 {
        let s = &bytes[bytes.len().saturating_sub(SIG_LEN)..];
        u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    }

    fn check_shape(&self) -> Result<(), Refusal> {
        let count = |k: Kind| self.parts().filter(|p| p.kind == k).count();
        let has = |name: &[u8]| self.parts().any(|p| p.name() == name);
        if count(Kind::Kernel) != 1 || count(Kind::KernelSig) != 1 || !has(KERNEL_NAME) || !has(KERNEL_SIG_NAME) {
            return Err(Refusal::Shape(Shape::Kernel));
        }
        for p in self.parts() {
            let ok = match p.kind {
                Kind::Kernel => p.name() == KERNEL_NAME,
                Kind::KernelSig => p.name() == KERNEL_SIG_NAME,
                Kind::Topology => TOPOLOGY_NAMES.contains(&p.name()),
                Kind::Config => p.name() == CONFIG_NAME || p.name() == CONFIG_SIG_NAME,
                Kind::Image => p.name().ends_with(b".ELF"),
            };
            if !ok {
                return Err(Refusal::Shape(match p.kind {
                    Kind::Kernel | Kind::KernelSig => Shape::Kernel,
                    Kind::Topology => Shape::Topology,
                    Kind::Config => Shape::Config,
                    Kind::Image => Shape::Image,
                }));
            }
        }
        if !TOPOLOGY_NAMES.iter().all(|n| has(n)) {
            return Err(Refusal::Shape(Shape::Topology));
        }
        if !has(CONFIG_NAME) {
            return Err(Refusal::Shape(Shape::Config));
        }
        Ok(())
    }
}

/// What the device knows when an update arrives.
#[derive(Clone, Copy, Debug)]
pub struct Device {
    /// This kernel's platform (`pure::OTA_PLATFORM_*`), or `None` where the
    /// caller cannot tell (ring 3 has no notion of the board): the switch, which
    /// runs in the kernel, always knows and checks.
    pub platform: Option<u8>,
    /// The boot record: the slots, the trial state and the floors.
    pub meta: BootMeta,
    /// The largest kernel the slot accepts.
    pub max_kernel_size: u32,
}

/// Is the manifest one this device may install now, and into which slot? The
/// answer is the inactive slot.
pub fn admit(m: &Manifest<'_>, dev: &Device) -> Result<u8, Refusal> {
    admit_numbers(dev, m.platform, m.kernel().size, m.fw_version, m.sec_epoch)
}

/// [`admit`] from the numbers of a manifest, for the switch, which holds a
/// [`Verified`] and not the manifest.
fn admit_numbers(dev: &Device, platform: u8, kernel_size: u32, fw_version: u32, sec_epoch: u32) -> Result<u8, Refusal> {
    if dev.platform.is_some_and(|p| p != platform) {
        return Err(Refusal::Platform);
    }
    if kernel_size > dev.max_kernel_size {
        return Err(Refusal::TooLarge);
    }
    ota_update_allowed_pure(&dev.meta, fw_version, sec_epoch).map_err(refusal_of)
}

/// A switch refusal as an update refusal.
pub fn refusal_of(r: SwitchRefusal) -> Refusal {
    match r {
        SwitchRefusal::NotInactive => Refusal::NotInactive,
        SwitchRefusal::TrialPending => Refusal::TrialPending,
        SwitchRefusal::BelowEpochFloor { .. } => Refusal::EpochFloor,
        SwitchRefusal::BelowFwFloor { .. } => Refusal::FwFloor,
    }
}

// ── The volume ──────────────────────────────────────────────────────────────

/// Why an access failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoErr {
    /// No such file.
    Missing,
    /// Anything else.
    Io,
}

/// Bytes of a directory entry name the store hands back.
pub const NAME_BUF: usize = 64;

/// A step of applying an update that the requester's Domain may be held back
/// from (`ota` envelope row, `azos_common::envelope::OtaOp`: the numbers are
/// the same, `azos_ota` checks it at compile time).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Apply {
    /// The set is written into the inactive slot ([`stage`]).
    Stage = 1,
    /// The staged set is promoted for the boot ([`switch`]).
    Switch = 2,
}

/// What the stager and the switch need of a file system: streams, so a
/// kernel of megabytes is never resident.
pub trait Store {
    /// May the requester apply `step` of an update for `slot`? Asked once per
    /// [`stage`] and once per [`switch`], after the manifest or the staged set
    /// has verified and before the first write, so a refusal changes nothing.
    /// `false` makes the call answer [`Refusal::Envelope`]. The kernel's store
    /// asks the effect gate; a store with no Domain to hold (the installer in
    /// ring 3, the host suites) takes the default and lets every step go.
    fn may_apply(&mut self, _step: Apply, _slot: u8) -> bool {
        true
    }
    /// Open `path` for reading.
    fn open_read(&mut self, path: &[u8]) -> Result<u32, IoErr>;
    /// Read into `buf`; 0 at the end.
    fn read(&mut self, h: u32, buf: &mut [u8]) -> Result<usize, IoErr>;
    /// Create `path`, or empty it, and open it for writing.
    fn open_write(&mut self, path: &[u8]) -> Result<u32, IoErr>;
    /// Append `data`.
    fn write(&mut self, h: u32, data: &[u8]) -> Result<(), IoErr>;
    /// Close. A refused write may only show here (a FAT volume writes the
    /// directory entry and the data at the close), so it is checked.
    fn close(&mut self, h: u32) -> Result<(), IoErr>;
    /// Delete the file at `path`.
    fn remove(&mut self, path: &[u8]) -> Result<(), IoErr>;
    /// The directory `path`, made if it is not there.
    fn ensure_dir(&mut self, path: &[u8]) -> Result<(), IoErr>;
    /// The `index`-th entry of `dir`: its name into `name`, its length; `None`
    /// past the last.
    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; NAME_BUF]) -> Option<usize>;
}

/// The bundle: the bytes the update arrives in. Read in place from wherever the
/// client put them; the stager copies each chunk before it trusts it.
pub trait Source {
    /// Its length.
    fn len(&self) -> u64;
    /// Bytes at `off` into `buf`; fewer only at the end.
    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, IoErr>;
}

/// The directory a slot's set lives in. Slot R has none: recovery is
/// factory-flashed and an update never writes it. The boot resolves the
/// userspace images, topology and configuration of the system it starts
/// through this, with its active slot ([`boot_set`], then the VFS root overlay,
/// `azos_ota::ota_install_boot_set`), so a slot switch is also a switch of every
/// one of those files.
pub const fn set_dir(slot: u8) -> Option<&'static [u8]> {
    match slot {
        SLOT_A => Some(b"/fat/PKG/SYS_A"),
        SLOT_B => Some(b"/fat/PKG/SYS_B"),
        _ => None,
    }
}

struct Path {
    b: [u8; PATH_MAX],
    n: usize,
}

impl Path {
    fn join(dir: &[u8], name: &[u8]) -> Path {
        let mut b = [0u8; PATH_MAX];
        b[..dir.len()].copy_from_slice(dir);
        b[dir.len()] = b'/';
        b[dir.len() + 1..dir.len() + 1 + name.len()].copy_from_slice(name);
        Path { b, n: dir.len() + 1 + name.len() }
    }

    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

fn read_full<R: Source>(src: &mut R, off: u64, buf: &mut [u8]) -> Result<(), IoErr> {
    let mut done = 0;
    while done < buf.len() {
        match src.read(off + done as u64, &mut buf[done..])? {
            0 => return Err(IoErr::Io),
            n => done += n,
        }
    }
    Ok(())
}

/// Hash (and, for the kernel, CRC) the file at `path`: its digest, its length
/// and its CRC-32 (0 unless `crc`).
fn digest_file<S: Store>(store: &mut S, path: &[u8], crc: bool, buf: &mut [u8]) -> Result<(Digest, u64, u32), IoErr> {
    let h = store.open_read(path)?;
    let mut sha = Sha256::new();
    let mut c = Crc32State::new();
    let mut total = 0u64;
    let r = loop {
        match store.read(h, buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                sha.update(&buf[..n]);
                if crc {
                    c.update(&buf[..n]);
                }
                total += n as u64;
            }
            Err(e) => break Err(e),
        }
    };
    let _ = store.close(h);
    r?;
    Ok((sha.finalize(), total, if crc { c.finalize() } else { 0 }))
}

/// Copy the file `from` to `to` (created, or emptied), in `buf`-sized pieces.
/// The kernel's promotion into its boot path; the destination is the inactive
/// slot's, so a copy that fails midway damages nothing that boots.
fn promote<S: Store>(store: &mut S, from: &[u8], to: &[u8], buf: &mut [u8]) -> Result<(), IoErr> {
    let src = store.open_read(from)?;
    let dst = match store.open_write(to) {
        Ok(h) => h,
        Err(e) => {
            let _ = store.close(src);
            return Err(e);
        }
    };
    let r = loop {
        match store.read(src, buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Err(e) = store.write(dst, &buf[..n]) {
                    break Err(e);
                }
            }
            Err(e) => break Err(e),
        }
    };
    let _ = store.close(src);
    let closed = store.close(dst);
    r.and(closed)
}

// ── Stage ───────────────────────────────────────────────────────────────────

/// A set that is fully staged and verified: what the switch and the decision
/// record need of it.
#[derive(Clone, Copy, Debug)]
pub struct Verified {
    /// The slot whose directory holds it.
    pub slot: u8,
    /// The manifest's epoch.
    pub sec_epoch: u32,
    /// The kernel's firmware version.
    pub fw_version: u32,
    /// The platform the set is for.
    pub platform: u8,
    /// The kernel part.
    pub kernel: Part,
    /// How many parts the set has.
    pub parts: u16,
    /// CRC-32 of the kernel as staged.
    pub kernel_crc: u32,
    /// The id of the manifest ([`Manifest::id`]).
    pub id: u64,
}

impl Verified {
    /// The numbers the switch records.
    pub fn set(&self) -> StagedSet {
        StagedSet {
            fw_version: self.fw_version,
            sec_epoch: self.sec_epoch,
            kernel_size: self.kernel.size,
            kernel_crc: self.kernel_crc,
        }
    }
}

fn io(w: Io) -> impl Fn(IoErr) -> Refusal {
    move |_| Refusal::Io(w)
}

/// Remove every entry of `dir`. An entry that cannot be removed (a directory
/// nobody put there) is an error: a set directory holds the set and nothing.
fn clear_dir<S: Store>(store: &mut S, dir: &[u8]) -> Result<(), IoErr> {
    let mut name = [0u8; NAME_BUF];
    // Bounded: a store that keeps listing what it removed must not hang us.
    for _ in 0..4 * MAX_PARTS {
        let Some(len) = store.entry(dir, 0, &mut name) else { return Ok(()) };
        if len == 0 || len > NAME_LEN {
            return Err(IoErr::Io);
        }
        store.remove(Path::join(dir, &name[..len]).bytes())?;
    }
    Err(IoErr::Io)
}

/// Stage the update in `src` into the inactive slot's set directory.
///
/// `key` is the trusted key the manifest must verify under, `w` the manifest
/// buffers and `buf` the copy buffer (any size; larger is faster on FAT).
/// Returns the verified set, or why not. On any refusal the marker is gone, so
/// nothing is staged, and the active slot's set has not been touched: only the
/// inactive slot's directory is written, and it is only written once the
/// manifest has verified and the device has admitted it.
pub fn stage<S: Store, R: Source>(
    store: &mut S,
    src: &mut R,
    dev: &Device,
    key: &[u8; KEY_LEN],
    w: &mut Work,
    buf: &mut [u8],
) -> Result<Verified, Refusal> {
    // 1. The manifest, copied once: the client can change its own mapping, so
    // what is verified must be what is used.
    let avail = src.len().min(MANIFEST_MAX as u64) as usize;
    read_full(src, 0, &mut w.mb[..avail]).map_err(io(Io::Bundle))?;
    let mlen = Manifest::wire_len(&w.mb[..avail]).ok_or(Refusal::Format)?;
    if avail < mlen {
        return Err(Refusal::Truncated);
    }
    w.id = 0;
    let Work { msg, mb, id } = w;
    let m = Manifest::parse(&mb[..mlen], key, msg)?;
    *id = Manifest::id(&mb[..mlen]);
    let slot = admit(&m, dev)?;
    if src.len() != mlen as u64 + m.parts_len() {
        return Err(Refusal::Length);
    }
    let dir = set_dir(slot).ok_or(Refusal::NotInactive)?;
    // The Domain's `ota` row, before the slot is written to.
    if !gate_open(store, Apply::Stage, slot) {
        return Err(Refusal::Envelope);
    }

    // 2. The marker goes first: from here until it is written again, the slot
    // holds no set.
    store.ensure_dir(dir).map_err(io(Io::Dir))?;
    match store.remove(Path::join(dir, MARKER).bytes()) {
        Ok(()) | Err(IoErr::Missing) => {}
        Err(_) => return Err(Refusal::Io(Io::Dir)),
    }
    clear_dir(store, dir).map_err(io(Io::Dir))?;

    // 3. The parts, each hashed as it is copied.
    let mut off = mlen as u64;
    for (i, p) in m.parts().enumerate() {
        copy_part(store, src, off, &p, dir, buf, i as u16)?;
        off += u64::from(p.size);
    }

    // 4. The marker last, and the set read back as the switch will read it.
    let marker = Path::join(dir, MARKER);
    let h = store.open_write(marker.bytes()).map_err(io(Io::Write))?;
    let wrote = store.write(h, &mb[..mlen]);
    let closed = store.close(h);
    if wrote.and(closed).is_err() {
        let _ = unstage(store, slot);
        return Err(Refusal::Io(Io::Write));
    }
    match verify_set(store, slot, key, w, buf) {
        Ok(v) => Ok(v),
        Err(e) => {
            let _ = unstage(store, slot);
            Err(e)
        }
    }
}

/// [`Store::may_apply`], unless the canary skips the question (host suites
/// only: `update-canary-apply-gate`, the step goes ahead whatever the store
/// says).
#[inline]
fn gate_open<S: Store>(store: &mut S, step: Apply, slot: u8) -> bool {
    cfg!(feature = "update-canary-apply-gate") || store.may_apply(step, slot)
}

/// Withdraw the staged set of `slot`: delete its marker, which is what makes a
/// directory of files a set. The files stay until the next stage clears them;
/// without the marker nothing treats them as one. For a caller whose own
/// record of the stage could not be written (the installer's journal).
pub fn unstage<S: Store>(store: &mut S, slot: u8) -> Result<(), IoErr> {
    let dir = set_dir(slot).ok_or(IoErr::Io)?;
    match store.remove(Path::join(dir, MARKER).bytes()) {
        Ok(()) | Err(IoErr::Missing) => Ok(()),
        Err(e) => Err(e),
    }
}

fn copy_part<S: Store, R: Source>(
    store: &mut S,
    src: &mut R,
    at: u64,
    p: &Part,
    dir: &[u8],
    buf: &mut [u8],
    index: u16,
) -> Result<(), Refusal> {
    let path = Path::join(dir, p.name());
    let h = store.open_write(path.bytes()).map_err(io(Io::Write))?;
    let mut sha = Sha256::new();
    let mut done = 0u64;
    let r = loop {
        if done == u64::from(p.size) {
            break Ok(());
        }
        let n = buf.len().min((u64::from(p.size) - done) as usize);
        if let Err(e) = read_full(src, at + done, &mut buf[..n]) {
            break Err((e, Io::Bundle));
        }
        sha.update(&buf[..n]);
        if let Err(e) = store.write(h, &buf[..n]) {
            break Err((e, Io::Write));
        }
        done += n as u64;
    };
    let closed = store.close(h);
    if let Err((_, w)) = r {
        return Err(Refusal::Io(w));
    }
    closed.map_err(io(Io::Write))?;
    if !cfg!(feature = "update-canary-hash") && sha.finalize() != p.sha256 {
        return Err(Refusal::PartHash(index));
    }
    Ok(())
}

/// Read the set directory's marker into `mb`: exactly one whole manifest, or
/// why there is none. A marker that is not a whole manifest is a marker that
/// was never finished (or was cut): nothing is staged.
fn read_marker<S: Store>(store: &mut S, dir: &[u8], mb: &mut [u8; MANIFEST_MAX + 1]) -> Result<usize, Refusal> {
    let marker = Path::join(dir, MARKER);
    let h = match store.open_read(marker.bytes()) {
        Ok(h) => h,
        Err(IoErr::Missing) => return Err(Refusal::NotStaged),
        Err(_) => return Err(Refusal::Io(Io::Read)),
    };
    let mut n = 0;
    let r = loop {
        match store.read(h, &mut mb[n..]) {
            Ok(0) => break Ok(()),
            Ok(k) => n += k,
            Err(e) => break Err(e),
        }
        if n == mb.len() {
            break Ok(());
        }
    };
    let _ = store.close(h);
    r.map_err(io(Io::Read))?;
    let want = Manifest::wire_len(&mb[..n]).ok_or(Refusal::NotStaged)?;
    if n != want {
        return Err(Refusal::NotStaged);
    }
    Ok(n)
}

/// Verify the set staged in `slot`'s directory against `key`: the marker's
/// signature, every part's length and SHA-256 as stored, `KERN.SIG` against the
/// kernel, and that the directory holds nothing else. Whoever switches runs
/// this; the stager's own verdict is not a reason to skip it.
pub fn verify_set<S: Store>(
    store: &mut S,
    slot: u8,
    key: &[u8; KEY_LEN],
    w: &mut Work,
    buf: &mut [u8],
) -> Result<Verified, Refusal> {
    let dir = set_dir(slot).ok_or(Refusal::NotInactive)?;
    let Work { msg, mb, id: last } = w;

    let n = read_marker(store, dir, mb)?;
    let id = Manifest::id(&mb[..n]);
    let m = Manifest::parse(&mb[..n], key, msg)?;
    *last = id;

    let mut kernel_crc = 0;
    for (i, p) in m.parts().enumerate() {
        let path = Path::join(dir, p.name());
        let is_kernel = p.kind == Kind::Kernel;
        let (digest, len, crc) = digest_file(store, path.bytes(), is_kernel, buf).map_err(|e| match e {
            IoErr::Missing => Refusal::PartHash(i as u16),
            IoErr::Io => Refusal::Io(Io::Read),
        })?;
        if !cfg!(feature = "update-canary-hash") && (len != u64::from(p.size) || digest != p.sha256) {
            return Err(Refusal::PartHash(i as u16));
        }
        if is_kernel {
            kernel_crc = crc;
        }
    }

    // The signature file describes the kernel the manifest signed.
    let sp = Path::join(dir, KERNEL_SIG_NAME);
    let h = store.open_read(sp.bytes()).map_err(io(Io::Read))?;
    let mut sb = [0u8; RSIG_FILE_MAX];
    let mut got = 0;
    let read = loop {
        if got == sb.len() {
            break Ok(());
        }
        match store.read(h, &mut sb[got..]) {
            Ok(0) => break Ok(()),
            Ok(k) => got += k,
            Err(e) => break Err(e),
        }
    };
    let _ = store.close(h);
    let sig = if read.is_ok() { Rsig::parse(&sb[..got]) } else { None };
    match sig {
        Some(s) if s.fw_version == m.fw_version && s.payload_size == m.kernel().size => {}
        _ => return Err(Refusal::KernelSig),
    }

    // The directory is the manifest and nothing else.
    let mut name = [0u8; NAME_BUF];
    let mut i = 0;
    while let Some(len) = store.entry(dir, i, &mut name) {
        let nm = &name[..len.min(NAME_BUF)];
        if nm != MARKER && !m.parts().any(|p| p.name() == nm) {
            return Err(Refusal::Extra);
        }
        i += 1;
        if i > 4 * MAX_PARTS {
            return Err(Refusal::Extra);
        }
    }

    Ok(Verified {
        slot,
        sec_epoch: m.sec_epoch,
        fw_version: m.fw_version,
        platform: m.platform,
        kernel: m.kernel(),
        parts: m.n as u16,
        kernel_crc,
        id,
    })
}

/// What the boot of a slot that holds a signed set resolves its files through:
/// the set's directory and the names the signed manifest lists. A root-level
/// file of the volume (`/fat/NAME`) whose name is in the set is the set's file.
#[derive(Clone, Copy, Debug)]
pub struct BootSet {
    /// The set directory ([`set_dir`]).
    pub dir: &'static [u8],
    /// The set's epoch: the one BOOTMETA records for the slot.
    pub sec_epoch: u32,
    n: usize,
    names: [[u8; NAME_LEN]; MAX_PARTS],
}

impl BootSet {
    /// The names the set carries, without padding.
    pub fn names(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.names[..self.n].iter().map(|n| {
            let len = n.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
            &n[..len]
        })
    }
}

/// The set the slot that is booting runs with, if it has one.
///
/// A slot holds a signed set exactly when BOOTMETA gives it a non-zero
/// `sec_epoch` (the switch records it, a kernel-only install zeroes it:
/// [`crate::pure::ota_kernel_install_pure`]). For such a slot the set must be
/// there: its marker is read, its signature verified under `key`, and its epoch
/// must be the one the record names, so a marker left by an earlier stage, or
/// one written by someone who does not hold the key, never stands for the set
/// that was switched to. The parts are not hashed again: the switch did that,
/// and each of them is checked where it is used (the topology and the
/// configuration by their own signatures, an image by its digest-bound filter).
///
/// `Ok(None)`: the slot has no set, the boot uses the volume's root files.
/// `Err`: it should have one and the directory does not hold it. The caller
/// must not let this boot pass for a confirmed one.
pub fn boot_set<S: Store>(store: &mut S, meta: &BootMeta, key: &[u8; KEY_LEN], w: &mut Work) -> Result<Option<BootSet>, Refusal> {
    let slot = meta.active_slot;
    let epoch = meta.slot_sec_epoch(slot);
    let Some(dir) = set_dir(slot).filter(|_| epoch != 0 && !cfg!(feature = "update-canary-root-files")) else {
        return Ok(None);
    };
    let Work { msg, mb, id } = w;
    let n = read_marker(store, dir, mb)?;
    let m = Manifest::parse(&mb[..n], key, msg)?;
    *id = Manifest::id(&mb[..n]);
    // The directory must hold the set whose epoch the record names.
    if m.sec_epoch != epoch {
        return Err(Refusal::NotStaged);
    }
    let mut set = BootSet { dir, sec_epoch: epoch, n: m.n, names: [[0; NAME_LEN]; MAX_PARTS] };
    for (slot_name, p) in set.names.iter_mut().zip(m.parts()) {
        *slot_name = p.name;
    }
    Ok(Some(set))
}

/// The kernel's two boot files, in the file system's own spelling.
pub struct BootPaths<'a> {
    /// `KERN_<slot>.BIN`.
    pub kernel: &'a [u8],
    /// `KERN_<slot>.SIG`.
    pub kernel_sig: &'a [u8],
}

/// Why [`switch`] did not switch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SwitchError {
    /// The staged set is not valid, or not admissible now.
    Refused(Refusal),
    /// Copying the kernel into its boot path failed; BOOTMETA is untouched.
    Promote,
    /// The kernel as copied is not the signed one; BOOTMETA is untouched.
    PromotedHash,
}

/// The switch, up to the one record write: re-verify the staged set of the
/// inactive slot, admit it against the device's boot record, promote the kernel
/// and its signature into the slot's boot paths and check what landed there.
/// Returns the set to record; the caller writes it with
/// `pure::ota_switch_pure` and persists the record, which is the step that
/// changes what boots. Until then the active slot is exactly as it was, and
/// running this again is harmless.
pub fn switch<S: Store>(
    store: &mut S,
    dev: &Device,
    key: &[u8; KEY_LEN],
    boot: &BootPaths<'_>,
    w: &mut Work,
    buf: &mut [u8],
) -> Result<Verified, SwitchError> {
    let slot = crate::pure::ota_inactive_slot_pure(dev.meta.active_slot);
    let v = verify_set(store, slot, key, w, buf).map_err(SwitchError::Refused)?;
    // The device's record decides again: the floors it holds are the ones that
    // count, not whatever the stager could see.
    let allowed = admit_numbers(dev, v.platform, v.kernel.size, v.fw_version, v.sec_epoch)
        .map_err(SwitchError::Refused)?;
    if allowed != slot {
        return Err(SwitchError::Refused(Refusal::NotInactive));
    }
    let dir = set_dir(slot).ok_or(SwitchError::Refused(Refusal::NotInactive))?;
    // The Domain's `ota` row, once the set is known good and before the first
    // byte is promoted.
    if !gate_open(store, Apply::Switch, slot) {
        return Err(SwitchError::Refused(Refusal::Envelope));
    }
    promote(store, Path::join(dir, KERNEL_NAME).bytes(), boot.kernel, buf).map_err(|_| SwitchError::Promote)?;
    promote(store, Path::join(dir, KERNEL_SIG_NAME).bytes(), boot.kernel_sig, buf).map_err(|_| SwitchError::Promote)?;
    // What the boot will load is hashed where it will be loaded from.
    let (digest, len, _) = digest_file(store, boot.kernel, false, buf).map_err(|_| SwitchError::Promote)?;
    if len != u64::from(v.kernel.size) || digest != v.kernel.sha256 {
        return Err(SwitchError::PromotedHash);
    }
    Ok(v)
}
