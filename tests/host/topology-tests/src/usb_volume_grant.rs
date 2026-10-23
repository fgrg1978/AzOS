// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Who may write the USB stick's volume (Kconfig `USB_STORAGE_VOLUME`,
//! mounted at [`USB_VOLUME_PATH`]).

use azos_abi::cap::{CapKind, CapPerms};
use azos_topology::builder::{default_minimal, TASK_SH_IMAGE};
use azos_topology::types::mount_path_ok;
use azos_topology::USB_VOLUME_PATH;

/// The rows of the built-in topology holding a write tree that covers the
/// stick's volume (the tree on `/usb` itself, or one above it).
fn usb_writers() -> Vec<Vec<u8>> {
    let topo = default_minimal();
    topo.tasks()
        .iter()
        .filter(|row| {
            topo.caps_of(row).iter().any(|c| {
                let t = c.target.as_bytes();
                c.kind == CapKind::Node
                    && c.perms.contains(CapPerms::WRITE)
                    && (t == b"/" || t == USB_VOLUME_PATH || USB_VOLUME_PATH.starts_with(&[t, b"/"].concat()))
            })
        })
        .map(|row| row.name.as_bytes().to_vec())
        .collect()
}

/// **The shell writes the stick, and nobody else does.** With
/// `USB_STORAGE_VOLUME` (and outside `CONSOLE_LOCKDOWN`) the shell's row holds
/// the stick's tree read-write, so a redirection writes the crash log out to
/// it; no other row of the built-in topology may change the stick (the
/// package tool reads a package there through the read-only root). Without
/// the volume, or under the lockdown, no row holds the grant: a grant on a
/// tree that is not there is authority nobody asked for.
///
/// **Canary.** Add `USB_RW` to `TOOLBOX_CAPS` in `builder.rs`: the list has a
/// second row and the row goes red.
#[test]
fn only_the_shell_may_write_the_usb_volume() {
    let expect: Vec<Vec<u8>> = if azos_limits::USB_STORAGE_VOLUME && !azos_limits::CONSOLE_LOCKDOWN {
        vec![TASK_SH_IMAGE.to_vec()]
    } else {
        vec![]
    };
    assert_eq!(usb_writers(), expect);
}

/// **No volume row may take the stick's mount point.** A `[volume.NAME]` at
/// `/usb` (or beneath it) would make the stick's mount fail; the topology
/// refuses it as it refuses `/fat`. Its neighbours are still fine.
#[test]
fn a_volume_row_may_not_mount_on_the_usb_volume() {
    assert!(!mount_path_ok(USB_VOLUME_PATH));
    assert!(!mount_path_ok(b"/usb/data"));
    assert!(!mount_path_ok(b"/fat"));
    assert!(!mount_path_ok(b"/fat/vol"));
    assert!(mount_path_ok(b"/usbx"));
    assert!(mount_path_ok(b"/data"));
}
