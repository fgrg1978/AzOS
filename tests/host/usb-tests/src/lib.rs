// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the USB host (crates/drivers/usb).
//!
//! The driver is built exactly as the kernel builds it, over the three traits
//! of `azos_usb::hw`; behind them is a register-level xHCI controller and a
//! tree of fake devices and hubs ([`mock`], [`devices`]). [`harness::Rig`]
//! wires the pieces; the suites are in `tests`.
//!
//! Every behaviour that has a canary (a feature of this crate that puts the
//! matching driver bug back) is covered by a test that goes red with it:
//!
//! | canary | what it breaks | test |
//! |---|---|---|
//! | `canary-ac64` | DMA above 4 GiB on a 32-bit controller | `controller_without_ac64_gets_low_memory` |
//! | `canary-csz` | 32-byte contexts on a 64-byte controller | `controller_with_64_byte_contexts_enumerates` |
//! | `canary-scratchpad` | scratchpad count read from the low field | `scratchpad_count_is_the_split_field` |
//! | `canary-cycle` | cycle bit kept over a Link TRB | `command_ring_wraps_over_the_link_trb` |
//! | `canary-erdp-ehb` | ERDP written without EHB | `event_handler_busy_is_cleared_after_each_drain` |
//! | `canary-64k` | a TRB crossing a 64 KiB boundary | `transfer_across_a_64k_boundary_is_split` |
//! | `canary-route` | route string of a device behind a hub | `route_string_names_the_hub_ports` |
//! | `canary-unplug` | device kept after the port says gone | `unplug_removes_the_device` |
//! | `canary-dr-mode` | a DWC3 in device or otg mode driven as a host | `a_dwc3_is_a_host_only_when_the_device_tree_says_so` |
//! | `canary-xhci-no-reset` | a command timeout latches the controller, no reset | `a_command_timeout_resets_the_controller_and_the_device_comes_back` |
//! | `canary-xhci-reset-keeps-devices` | the core keeps the devices a reset controller forgot | `a_command_timeout_resets_the_controller_and_the_device_comes_back` |
//! | `canary-xhci-reset-event-ring` | a reset keeps the event ring's old cursor | `a_command_timeout_resets_the_controller_and_the_device_comes_back` |
//! | `canary-xhci-hse-latches` | a host system error latches the controller, no reset | `a_host_system_error_resets_the_controller_and_a_second_latches_it` |
//!
//! `tests/chaos.rs` drives the kernel's injection point (`azos_chaos`,
//! `xhci-command-drop`) instead of the mock, in a process of its own.

pub mod devices;
pub mod harness;
pub mod mock;

#[cfg(test)]
mod msc;
#[cfg(test)]
mod reset;
#[cfg(test)]
mod tests;
