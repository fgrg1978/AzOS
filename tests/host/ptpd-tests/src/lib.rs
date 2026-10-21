// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the PTP daemon: the codec (`wire.rs`), the best master
//! clock algorithm (`bmc.rs`), the slave engine (`port.rs`) and the transport
//! helpers (`link.rs`) of `userspace/services/ptpd`, pulled in with `#[path]`
//! so the code under test is the code `PTPD.ELF` is built from. `main.rs` (the
//! sockets, the kernel's `Clock` endpoint) is the only file left out.
//!
//! **The test is the network.** It plays a grandmaster that sends the bytes a
//! grandmaster sends and answers the slave's Delay_Req and Pdelay_Req from a
//! model of two clocks: the true UTC time, a slave whose wall clock is off by
//! `theta` from it, a master on the TAI scale (UTC plus the leap offset), and
//! a path whose two directions can differ.

#[allow(dead_code)]
#[path = "../../../../userspace/services/ptpd/src/wire.rs"]
pub mod wire;
#[allow(dead_code)]
#[path = "../../../../userspace/services/ptpd/src/bmc.rs"]
pub mod bmc;
#[allow(dead_code)]
#[path = "../../../../userspace/services/ptpd/src/port.rs"]
pub mod port;
#[allow(dead_code)]
#[path = "../../../../userspace/services/ptpd/src/link.rs"]
pub mod link;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod row;
