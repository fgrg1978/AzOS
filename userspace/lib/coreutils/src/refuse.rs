// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Unix commands with no native meaning. Each answers with what the system
//! has instead, and a status of its own, rather than pretending to work.

use crate::host::Host;
use crate::util::say;

/// The status of a refused command (the shell's "found but cannot be run").
pub const REFUSED: i32 = 126;

/// `(command, what the native system has in its place)`.
pub const REFUSALS: &[(&[u8], &[u8])] = &[
    (b"chmod", b"files have no mode bits; what may be written is the write trees of the row (signed topology)"),
    (b"chown", b"files have no owner; a Domain owns what its capabilities cover (signed topology)"),
    (b"chgrp", b"files have no group; a Domain owns what its capabilities cover (signed topology)"),
    (b"umask", b"there are no mode bits to mask; see the write trees of the row (signed topology)"),
    (b"ln", b"the filesystem has no links; copy with cp, or hand the other task a file handle"),
    (b"kill", b"there are no signals; the shell's own `kill JOB` asks a job to stop"),
    (b"mkfifo", b"pipes are made by `|` in the shell; a device or service is an endpoint of the signed topology"),
];

pub fn refuse<H: Host>(h: &mut H, name: &[u8]) -> Option<i32> {
    let (_, why) = REFUSALS.iter().find(|(n, _)| *n == name)?;
    say(h, name, b"", why);
    Some(REFUSED)
}
