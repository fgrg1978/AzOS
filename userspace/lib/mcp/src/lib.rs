// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Model Context Protocol, minimal and ours: no dependency, no downloaded
//! code.
//!
//! * [`json`]: a strict JSON value, parser and writer.
//! * [`jsonrpc`]: the JSON-RPC 2.0 codec: request, response, notification,
//!   error, batch.
//! * [`mcp`]: the shapes of `initialize`, `ping`, `tools/list` and
//!   `tools/call`.
//!
//! It is only a codec: it reads a transport message (the text of one JSON-RPC
//! message or batch) and writes one. The transport (stdio lines, HTTP bodies),
//! the tools and the session state belong to the daemon.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod json;
pub mod jsonrpc;
pub mod mcp;
