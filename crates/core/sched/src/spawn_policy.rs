// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The decisions `SYS_SPAWN` makes before any task exists (RFC-0043), free of
//! the scheduler so the host tests can include this file directly.
//!
//! Every decision here is a function of the image's SHA-256 alone. The path
//! the caller named and the caller's own filter are not inputs: the profile
//! and the capabilities belong to the image, as they do for autorun and exec
//! (owner decisions 59 and 73). `tests/host/seccomp-tests` includes this file with
//! the real `seccomp.rs` and its generated digest table.

use crate::filter::SyscallFilter;
use crate::seccomp::{image_filter, image_for_digest, ImageProfile};
use azos_abi::error::Errno;

/// What `SYS_SPAWN` starts for an image, decided from its digest.
#[derive(Clone, Copy)]
pub struct SpawnPlan {
    /// The row the image's bytes are bound to.
    pub profile: &'static ImageProfile,
    /// The child's filter: that row's, installed on the child's slot when it is
    /// created. Neither the caller's filter nor an intersection of the two.
    pub filter: SyscallFilter,
    /// The topology task whose capabilities the child starts with: the name the
    /// build copied these bytes under. Renaming or copying the file does not
    /// change it. No task of that name means no capabilities.
    pub topology_key: &'static str,
}

/// The plan for the image whose bytes have SHA-256 `digest`.
///
/// `Err(EACCES)` when no image profile is bound to the digest: a file that is
/// not a shipped ELF, or a shipped one changed by a single byte. The caller
/// records the refusal as an exec refusal and creates nothing.
pub fn plan_spawn(digest: &[u8; 32]) -> Result<SpawnPlan, Errno> {
    let profile = image_for_digest(digest).ok_or(Errno::EACCES)?;
    Ok(SpawnPlan {
        profile,
        filter: image_filter(profile),
        topology_key: profile.image,
    })
}
