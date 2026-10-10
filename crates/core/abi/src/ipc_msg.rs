// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The message descriptor of ABI v2 of the call (wave 15 N11).
//!
//! One `repr(C)` layout, the same in a v2 call, its reply, and (later) on
//! the wire to another node: a version, inline words, and capability
//! entries transferred all or nothing. The layout is fixed at the ABI
//! ceilings below; the kernel refuses counts above its Kconfig limits
//! (`IPC_MSG_INLINE_WORDS`, per ISA; `IPC_MSG_MAX_CAPS`). The future IDL
//! generates its stubs against this struct.
//!
//! The badge is not in what a caller writes: it lives in the endpoint
//! capability the call goes through (the slot's extension word) and the
//! kernel fills [`MsgDesc::badge`] in what the server receives.

/// The descriptor's version: a kernel refuses a version it does not know.
pub const MSG_VERSION: u16 = 1;
/// ABI ceiling on inline words (the kernel's Kconfig value is at most this).
pub const MSG_WORDS_MAX: usize = 8;
/// ABI ceiling on capability entries.
pub const MSG_CAPS_MAX: usize = 8;

/// Entry mode: MOVE (the sender's handle goes stale).
pub const CAP_MODE_MOVE: u8 = 1;
/// Entry mode: DUP (the receiver gets a copy, rights possibly lowered; the
/// sender keeps its own).
pub const CAP_MODE_DUP: u8 = 2;

/// Message flag: a refused transfer leaves the sender's MOVE entries in
/// place. Without it they are consumed (revoked) on a refusal.
pub const MSG_KEEP: u32 = 1 << 0;
/// Message flag (kernel-set on receive): [`MsgDesc::badge`] is meaningful
/// (the call came through ABI v2; a v1 call carries no badge).
pub const MSG_BADGED: u32 = 1 << 31;

/// One capability entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapDesc {
    /// The sender's handle; the receiver's handle on receive.
    pub handle: u32,
    /// [`CAP_MODE_MOVE`] or [`CAP_MODE_DUP`].
    pub mode: u8,
    /// Reserved, 0.
    pub _pad: u8,
    /// Rights the receiver gets (`CapPerms` bits), 0 for the sender's own.
    pub rights: u16,
}

/// The descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsgDesc {
    /// [`MSG_VERSION`].
    pub version: u16,
    /// Inline words used, `0..=` the kernel's `IPC_MSG_INLINE_WORDS`.
    pub n_words: u8,
    /// Capability entries used, `0..=` the kernel's `IPC_MSG_MAX_CAPS`.
    pub n_caps: u8,
    /// [`MSG_KEEP`] on send; [`MSG_BADGED`] on receive.
    pub flags: u32,
    /// Kernel-set on receive: the badge of the caller's endpoint capability.
    pub badge: u64,
    /// Inline data.
    pub words: [u64; MSG_WORDS_MAX],
    /// Capabilities.
    pub caps: [CapDesc; MSG_CAPS_MAX],
}

const _: () = assert!(core::mem::size_of::<CapDesc>() == 8);
const _: () = assert!(core::mem::size_of::<MsgDesc>() == 16 + 8 * MSG_WORDS_MAX + 8 * MSG_CAPS_MAX);
const _: () = assert!(core::mem::align_of::<MsgDesc>() == 8);

impl MsgDesc {
    /// The counts are within the ABI ceilings and the version is known.
    pub const fn well_formed(&self) -> bool {
        self.version == MSG_VERSION
            && (self.n_words as usize) <= MSG_WORDS_MAX
            && (self.n_caps as usize) <= MSG_CAPS_MAX
    }
}
