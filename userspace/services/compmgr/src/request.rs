// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `SYS_SPAWN_EX` request every child of the manager is started with.
//!
//! No argument, no environment, no handle. The one descriptor lent is the
//! console, on fds 1 and 2: a `std` program (the package installer) writes
//! `println!` through its fd table and the startup block the kernel lays out
//! from the request, which closes every fd the request does not name, so
//! without the lend its banner and its diagnostics went nowhere. Lending the
//! console moves no authority: a child writes through the console
//! capability of its own row (`LOG_CONSOLE_WRITE`), as the programs that call
//! `console_write` directly always have.
//!
//! A child dies with the manager (as an Erlang supervisor's children die with
//! it): the kernel restarts the manager, which starts the rows again;
//! children orphaned and left running would collide with those starts.

use azos_abi::ushell::{Move, SpawnReq, MOVE_CONSOLE, SPAWN_F_DIE_WITH_PARENT, SPAWN_REQ_VERSION};

/// The request that starts one child.
pub fn child_request() -> SpawnReq {
    let mut req = SpawnReq {
        version: SPAWN_REQ_VERSION,
        flags: SPAWN_F_DIE_WITH_PARENT,
        nmoves: 2,
        ..SpawnReq::default()
    };
    // stdout and stderr; stdin stays closed (console input is the terminal
    // server's alone).
    for (slot, fd) in [1u32, 2].into_iter().enumerate() {
        req.moves[slot] = Move { child_fd: fd, handle: MOVE_CONSOLE, perms: 0, _pad: 0 };
    }
    req
}
