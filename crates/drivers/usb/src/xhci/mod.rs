// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The xHCI host controller driver (xHCI 1.2 specification).

pub mod context;
pub mod controller;
pub mod regs;
pub mod ring;
pub mod trb;

pub use controller::{Done, Error, EpSpec, Fault, HcEvent, Owner, PortStatus, TdKind, TdSpec, Xhci};
pub use regs::{Caps, Speed};
