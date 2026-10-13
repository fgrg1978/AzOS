// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `time` endpoint: the authority to bind a task to the real-time band or
//! a deadline reservation (`SYS_SCHEDCTL`, N6b).
//!
//! **A warrant, no ops.** The scheduler call stays what it is, and the
//! capability the caller presents in its last argument is a `time` endpoint
//! with `WRITE`. Holding it is the permission a task needs to promote itself
//! above the fair class; a fair priority and a QoS hint need nothing. The
//! endpoint serves no operation (a call through it answers `BadInterface`):
//! the kernel reads the capability (`handlers::time_warrant_recording`), so
//! there is no interface trait. One time authority per kernel, so the
//! endpoint carries no resource (`endpoint = "time"`, `WRITE`).

/// The interface id (ASCII "TIME"): the registry's name for the endpoint.
pub const TIME_ID: u32 = 0x5449_4D45;
