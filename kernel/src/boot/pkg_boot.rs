// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's side of the boot-time apply of staged packages: where the
//! staged packages are, who the device is, and what the boot knows about itself.
//! The decision is `pkg_apply.rs`'s (host-tested over the real volume engine);
//! the calls are made from the signed topology's candidate
//! (`topology::signed_candidate`), on the boot hart, before the topology is
//! published and so before anything is started, on every ISA.
//!
//! ```text
//!   signed_candidate: fill_signed ─► apply (staged packages) ─► kernel check ─┬─ ok ──► publish, finish (bind)
//!                                                                              └─ refused: the signed topology alone
//!                                                                                 ├─ ok ──► the packages did it: undo
//!                                                                                 └─ refused too: not theirs, keep
//! ```
//!
//! A candidate that the kernel's check refuses with packages merged is tried
//! once more without them. Only when that passes did the packages cause the
//! refusal: the trial is then undone (the packages that were new are removed
//! from the staging directory with a refusal on record). When the signed
//! topology alone is refused as well, the packages are not to blame and are
//! neither undone nor quarantined: the apply stays a trial the A/B rule ends.
//!
//! A merged row that says `start = true` is started by the component manager
//! like a static row because the apply adds to the manager's row a launch grant
//! on it (`pkg_apply`, *Launch grants*), before the candidate is checked.
//!
//! Applied programs start because [`Staged::finish`] binds the SHA-256 of each
//! to its own row (`azos_sched::seccomp::register_package_images`): the exec
//! sites start only an image whose digest is bound, and a program swapped into
//! `APPS/` after the apply has a digest nobody bound.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use azos_decision::{Rule, Verdict};
use azos_fs::azvol::Volume;
use azos_pkg::apply::{APPS_DIR, STAGE_MOUNT};
use azos_pkg::Device;
use azos_topology::Topology;

use super::azvol::{clock_ns, engine_mount, open, PartDev};
use super::pkg_apply::{self, Applied, AppliedImage, Boot, Sink};
use azos_sched::seccomp::PackageImage;
use crate::kprintln;

// A launch grant on a name past the table `azos_ipc::launch_cap` interns cannot be
// minted: the apply's own bound on the names must be that table's.
const _: () = assert!(pkg_apply::LAUNCH_NAMES_MAX == azos_ipc::launch_cap::MAX_LAUNCH_NAMES);

/// `BootValidation::prior_unconfirmed` and `max_attempts`, as `ota.rs` read
/// them: what the trial rule needs of the boot counter.
static PRIOR_UNCONFIRMED: AtomicU32 = AtomicU32::new(0);
static MAX_ATTEMPTS: AtomicU32 = AtomicU32::new(azos_ota::OTA_DEFAULT_MAX_BOOT_ATTEMPTS);

/// Record the boot counter. Called by the OTA boot validation, which runs
/// before the topology is installed.
pub(super) fn note_boot(prior_unconfirmed: u32, max_attempts: u32) {
    PRIOR_UNCONFIRMED.store(prior_unconfirmed, Ordering::Release);
    MAX_ATTEMPTS.store(max_attempts, Ordering::Release);
}

/// The first row a package added to the published topology, `usize::MAX` for
/// none, and how many rows packages added.
static FIRST_ROW: AtomicUsize = AtomicUsize::new(usize::MAX);
static ROWS: AtomicUsize = AtomicUsize::new(0);

/// The decision ring and the console.
struct Kernel;

impl Sink for Kernel {
    fn record(&mut self, p: &azos_decision::ProvenanceRecord) {
        let verdict = match p.verdict {
            v if v == Verdict::Admit as u8 => Verdict::Admit,
            v if v == Verdict::Deny as u8 => Verdict::Deny,
            _ => Verdict::Refuse,
        };
        // The package (its id's prefix) and the first row it adds go with the
        // verdict: the receipt is what `why` explains an install by.
        let origin = azos_decision::Origin { topology_row_id: p.topology_row_id, image_hash_prefix: p.image_hash_prefix };
        azos_decision::record_with(Rule::PackageInstall, verdict, p.subject, p.n, origin);
    }

    fn note(&mut self, line: core::fmt::Arguments<'_>) {
        kprintln!("{}", line);
    }
}

/// An apply whose candidate topology the kernel has yet to check.
pub(super) struct Staged {
    vol: Volume<PartDev>,
    applied: Applied,
}

/// The interface table and the epoch floor, built where the device is judged.
fn judge<R>(f: impl FnOnce(&Boot<'_>) -> R) -> R {
    let api = azos_pkg::api::device_api();
    let floor = azos_ota::floor::lift(azos_ota::ota_read_boot_meta().min_sec_epoch);
    let boot = Boot {
        device: Device::this(&api).with_epoch_floor(floor),
        now_ns: clock_ns(),
        prior_unconfirmed: PRIOR_UNCONFIRMED.load(Ordering::Acquire),
        max_attempts: MAX_ATTEMPTS.load(Ordering::Acquire),
    };
    f(&boot)
}

/// Apply the staged packages to `topo`, the signed candidate. `None` when the
/// topology declares no staging volume or the volume cannot be opened, and
/// nothing was merged; otherwise the apply, to be `finish`ed once the kernel's
/// check passes or `undo`ne when it does not.
pub(super) fn apply(topo: &mut Topology<'static>) -> Option<Staged> {
    let row = topo.volumes().iter().find(|v| v.mount.as_bytes() == STAGE_MOUNT)?;
    let (name, partition, aead) = (row.name.as_bytes(), row.partition, row.aead);
    if row.read_only || row.verity_root.is_some() {
        kprintln!("[PKG] the staging volume {} is read-only or hash-checked: no package is applied", row.name.as_str());
        return None;
    }
    let Some(dev) = open(partition) else {
        kprintln!("[PKG] no partition {} for the staging volume: no package is applied", partition);
        return None;
    };
    let mut vol = match engine_mount(dev, name, aead) {
        Ok(v) => v,
        Err(why) => {
            kprintln!("[PKG] the staging volume cannot be opened ({:?}): no package is applied", why);
            return None;
        }
    };
    let applied = judge(|boot| pkg_apply::apply(&mut vol, topo, boot, &mut Kernel));
    Some(Staged { vol, applied })
}

impl Staged {
    /// The kernel's check refused the candidate: end the trial, if this apply
    /// began one. The caller tries the signed topology again, without packages.
    pub(super) fn undo(mut self) {
        kprintln!("[PKG] the kernel's admission refused the topology with {} package row(s): trial undone", self.applied.rows);
        judge(|boot| pkg_apply::undo(&mut self.vol, &self.applied, boot, &mut Kernel));
    }

    /// The signed topology alone is refused as well as the one with packages:
    /// the packages did not cause it. The volume is left as the apply made it
    /// (its trial ends by the A/B rule at a later boot), and no row is bound.
    pub(super) fn keep(self) {
        kprintln!(
            "[PKG] the signed topology is refused without the {} package row(s) too: the packages stay applied, on trial, and are merged by a boot that accepts it",
            self.applied.rows
        );
    }

    /// The candidate was published: say what it holds, bind the programs to
    /// their rows and let the loader find them. The volume is closed here; the
    /// VFS mounts it next.
    pub(super) fn finish(self) {
        let a = &self.applied;
        if a.rows != 0 {
            FIRST_ROW.store(a.first_row, Ordering::Release);
            ROWS.store(a.rows, Ordering::Release);
        }
        let bound = bind(&a.images);
        kprintln!(
            "[PKG] {} package(s) applied: {} row(s) merged into the topology, {} new{}",
            a.packages, a.rows, a.fresh.len(),
            if a.trial.is_some() { ", on trial until the boot is confirmed" } else { "" },
        );
        if !a.images.is_empty() {
            kprintln!("[PKG] {} of {} package program(s) bound by SHA-256 to their rows", bound, a.images.len());
        }
    }
}

/// Bind each program the apply admitted to the profile its own row gives it.
/// The row is looked up in the published topology by the program's name; its
/// kernel-hosted endpoint grants are the interfaces the profile lists
/// ([`azos_sched::seccomp::package_profile`]). A program whose bytes are
/// already bound by the build's tables (a package carrying a shipped ELF) is
/// left to them: the shipped binding wins. Returns how many were bound.
fn bind(images: &[AppliedImage]) -> usize {
    let Some(topo) = azos_topology::get() else { return 0 };
    let mut table: Vec<PackageImage> = Vec::new();
    for im in images {
        if azos_sched::seccomp::image_for_digest(&im.sha256).is_some() {
            kprintln!("[PKG] {} carries a shipped program: its shipped binding stands", core::str::from_utf8(&im.name).unwrap_or("?"));
            continue;
        }
        let Ok(name) = core::str::from_utf8(&im.name) else { continue };
        // A row named after a shipped image this build has no row for would hand
        // the SHIPPED binary the package's row (the key of its capabilities is
        // the name the build copied it under): not bound.
        if azos_sched::seccomp::profile_named(&im.name).is_some() {
            kprintln!("[PKG] {} is named after a shipped program: not bound", name);
            continue;
        }
        let Some(row) = topo.tasks().iter().find(|r| r.name.as_bytes() == im.name.as_slice()) else { continue };
        let mut ifaces: Vec<u16> = Vec::new();
        for c in topo.caps_of(row).iter().filter(|c| c.kind == azos_abi::cap::CapKind::Endpoint) {
            if let Some((iface, _)) = azos_devif::parse_target(c.target.as_str()) {
                if !ifaces.contains(&iface.key) {
                    ifaces.push(iface.key);
                }
            }
        }
        // Held for the life of the boot, as the topology's own text is.
        let image: &'static str = Box::leak(alloc::string::String::from(name).into_boxed_str());
        let ifaces: &'static [u16] = Box::leak(ifaces.into_boxed_slice());
        table.push(PackageImage { digest: im.sha256, profile: azos_sched::seccomp::package_profile(image, ifaces) });
    }
    let n = table.len();
    if n != 0 && !azos_sched::seccomp::register_package_images(Box::leak(table.into_boxed_slice())) {
        kprintln!("[PKG] the package programs were already bound: none bound again");
        return 0;
    }
    n
}

/// Did a package bring topology row `name`?
fn is_package_row(name: &[u8]) -> bool {
    let Some(topo) = azos_topology::get() else { return false };
    let first = FIRST_ROW.load(Ordering::Acquire);
    let rows = ROWS.load(Ordering::Acquire);
    first != usize::MAX && topo.tasks().iter().skip(first).take(rows).any(|r| r.name.as_bytes() == name)
}

/// The directory of the program of row `name` when it is not on `/fat`: the
/// applied packages' (`/pkg/APPS`), for a row a package brought. The component
/// manager spawns `<dir>/<name>` (`components/<n>/dir` of the `inspect.components` view), the kernel's
/// own launcher the same through [`image_path`].
pub(crate) fn image_dir<'b>(name: &[u8], out: &'b mut [u8; 16]) -> Option<&'b [u8]> {
    if !is_package_row(name) {
        return None;
    }
    let (mount, apps) = (STAGE_MOUNT, APPS_DIR);
    let n = mount.len() + 1 + apps.len();
    if n > out.len() {
        return None;
    }
    out[..mount.len()].copy_from_slice(mount);
    out[mount.len()] = b'/';
    out[mount.len() + 1..n].copy_from_slice(apps);
    Some(&out[..n])
}

/// Where the program of topology row `name` is, when a package brought it:
/// `/pkg/APPS/NAME` on the staging volume. `None` for a row the topology had
/// of its own, whose program is on the boot volume.
pub(crate) fn image_path<'b>(name: &[u8], out: &'b mut [u8; 48]) -> Option<&'b [u8]> {
    let mut dir = [0u8; 16];
    let dir = image_dir(name, &mut dir)?;
    let n = dir.len() + 1 + name.len();
    if n > out.len() {
        return None;
    }
    out[..dir.len()].copy_from_slice(dir);
    out[dir.len()] = b'/';
    out[dir.len() + 1..n].copy_from_slice(name);
    Some(&out[..n])
}
