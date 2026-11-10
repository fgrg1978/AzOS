// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AZOS frozen ABI.
//!
//! This crate is the **single source of truth** for everything that crosses
//! the user/kernel boundary:
//!
//! - syscall numbers
//! - error codes (Errno-style)
//! - `#[repr(C)]` data structures shared user↔kernel
//! - capability handle wire format
//!
//! # How it changes
//!
//! There is no tagged release and nothing outside this tree builds against
//! the crate, so a layout or a number changes in place, with every reader in
//! the same commit. What keeps the two sides of the boundary equal:
//!
//! - [`ABI_VERSION`] (below): the loader, the vDSO and `RobotInfo` refuse a
//!   program built against another version.
//! - Sizes of `#[repr(C)]` types: `const` asserts next to the type where a
//!   layout is load-bearing (`ipc_msg`, `ushell`), and the host-side
//!   `abi-tests` crate checks the rest.
//! - Syscall numbers are not re-assigned: a new one takes the next unused
//!   number, and `SYS_NR_RESERVED_UPPER` (the table's end) grows with it.
//! - The `CapHandle` bitfield layout (6-bit kind, 16-bit
//!   generation, 10-bit slot; `cap.rs` says why each width) is the wire format
//!   every handle crosses the boundary in.
//!
//! `crates/core/abi/CHANGELOG.md` records the changes.
//!
//! # Design notes
//!
//! - Pure types only — no kernel internals, no `unsafe`, no allocator.
//! - `no_std` everywhere.
//! - Constants are `u64` to match the syscall-arg width on RV64 / aarch64 /
//!   x86_64.
//! - All `repr(C)` structures must round-trip across the FFI boundary
//!   without alignment surprises (the size asserts above).

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cap;
pub mod error;
pub mod foreign;
pub mod exit_status;
pub mod invoke;
pub mod io_ring;
pub mod ipc_msg;
pub mod nic_queue;
pub mod power;
/// The cross-level admission rule boot and run-time admission share.
pub mod rt_levels;
/// The flight, behavior, config and OTA typed calls (615..=618).
pub mod families;
pub mod fault;
pub mod sensor_sample;
pub mod syscall_nr;
pub mod time;
/// The kernel tracer's control call (632), classes and event ids.
pub mod trace;
pub mod types;
pub mod ushell;
pub mod vdso;

/// AZOS ABI version. Bumps on **major** breaking change only.
///
/// Version 2 was the native ABI of `SYS_INVOKE` and the 33-call table
/// (`syscall_nr`); version 3 is the same table with `SYS_IPC_ACCEPT`'s
/// descriptor form reading `a1` as flags (`IPC_ACCEPT_F_POLL`, any other bit
/// `-EINVAL`), which a version-2 program left as garbage. Three places read it, and a mismatch is refused at each:
///
///  * **The loader.** `libsys` carries an ELF note (`.note.azos.abi`, name
///    `AZOS`, type [`ABI_NOTE_TYPE`], the version as its 4-byte descriptor); the
///    kernel's ELF loader refuses an image whose note names another version.
///    An image with no note (a hand-assembled test, a Linux program) is not
///    refused: it is not built on `libsys`.
///  * **The vDSO.** The kernel publishes the version of the ABI it implements at
///    `vdso::VDSO_ABI_VERSION_OFFSET`; `libsys::abi_matches` compares it with
///    the version the program was built against.
///  * **`RobotInfo`.** The firmware version in `types::RobotInfo`.
pub const ABI_VERSION: u32 = 3;

/// The note type of the `.note.azos.abi` ELF note (name `AZOS`).
pub const ABI_NOTE_TYPE: u32 = 1;
/// The name of that note, with its terminating NUL.
pub const ABI_NOTE_NAME: &[u8; 5] = b"AZOS\0";

/// Re-exports for the most-used items.
pub mod prelude {
    pub use crate::cap::{CapHandle, CapKind, CapPerms, CAP_NULL};
    pub use crate::error::Errno;
    pub use crate::ABI_VERSION;
}
