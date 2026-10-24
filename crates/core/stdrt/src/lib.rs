// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_stdrt`: the layer under Rust's `std` on `*-unknown-azos`.
//!
//! `library/std/src/sys/*/azos.rs` (the overlay in `sdk/std`, applied by
//! `tools/build/sdk_std.py`) is thin: each function there is one call into this
//! crate. What this crate calls is the native ABI and nothing else, with no
//! file descriptor numbering, no `errno` and no signal anywhere:
//!
//! * `sys`: the trap and `invoke(handle, op, words)`.
//! * `start`: the entry (`_azos_entry`), the startup block (arguments,
//!   environment, working directory, fds 0..7 as handles) and the exit.
//! * `time`: the vDSO clock and the absolute sleep.
//! * `mem` and `alloc`: anonymous mappings with guard pages and the
//!   hardened allocator (`azos_ualloc`'s engine, Kconfig `USER_ALLOC_*`).
//! * `thread`: threads over `thread_create` (joined by the exit-cleared
//!   word).
//! * [`tls`]: the thread registry and the keyed thread-local storage.
//! * `futex`: the wait and the wake `std`'s locks are built on.
//! * `console`: the console and the files behind fds 0..2 (no console read).
//! * [`entropy`]: the kernel pool, through the `Entropy` interface.
//! * `net` and [`netpure`]: sockets over the `Node` ops of the native ABI
//!   (the blocking calls are polls with an absolute sleep between looks), and the
//!   address layout, error mapping and back-off they share with the host tests.
//!
//! The modules that issue a trap exist only on `target_os = "azos"`; [`pure`],
//! [`tls`], [`netpure`] and [`entropy`] build anywhere, which is how `tests/host/stdrt-tests`
//! checks them.
#![no_std]

#[path = "../../libsys/src/pure.rs"]
pub mod pure;

pub mod entropy;
pub mod netpure;
pub mod tls;

#[cfg(target_os = "azos")]
pub mod alloc;
#[cfg(target_os = "azos")]
pub mod console;
#[cfg(target_os = "azos")]
pub mod futex;
#[cfg(target_os = "azos")]
pub mod mem;
#[cfg(target_os = "azos")]
pub mod net;
#[cfg(target_os = "azos")]
pub mod start;
#[cfg(target_os = "azos")]
pub mod sys;
#[cfg(target_os = "azos")]
pub mod thread;
#[cfg(target_os = "azos")]
pub mod time;
#[cfg(target_os = "azos")]
mod config;
