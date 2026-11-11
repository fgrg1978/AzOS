// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the USB host (crates/drivers/usb).
//!
//! The driver is built exactly as the kernel builds it, over the three traits
//! of `azos_usb::hw`; behind them is a register-level xHCI controller and a
//! tree of fake devices and hubs ([`mock`], [`devices`]), or a register-level
//! DWC2 core over the same devices ([`dwc2_mock`]; its suite is `dwc2`). [`harness::Rig`]
//! wires the pieces; the suites are in `tests`.
//!
//! Every behaviour that has a canary (a feature of this crate that puts the
//! matching driver bug back) is covered by a test that goes red with it:
//!
//! | canary | what it breaks | test |
//! |---|---|---|
//! | `canary-admit-all` | every interface is offered to the class drivers whatever the admission rows say | `admission::` (all) |
//! | `canary-ep0-data-endpoint` | an endpoint numbered 0 in a configuration descriptor is kept as a data endpoint | `an_endpoint_numbered_0_is_not_a_data_endpoint` |
//! | `canary-ac64` | DMA above 4 GiB on a 32-bit controller | `controller_without_ac64_gets_low_memory` |
//! | `canary-csz` | 32-byte contexts on a 64-byte controller | `controller_with_64_byte_contexts_enumerates` |
//! | `canary-scratchpad` | scratchpad count read from the low field | `scratchpad_count_is_the_split_field` |
//! | `canary-cycle` | cycle bit kept over a Link TRB | `command_ring_wraps_over_the_link_trb` |
//! | `canary-erdp-ehb` | ERDP written without EHB | `event_handler_busy_is_cleared_after_each_drain` |
//! | `canary-64k` | a TRB crossing a 64 KiB boundary | `transfer_across_a_64k_boundary_is_split` |
//! | `canary-route` | route string of a device behind a hub | `route_string_names_the_hub_ports` |
//! | `canary-unplug` | device kept after the port says gone | `unplug_removes_the_device` |
//! | `canary-msc-no-recovery` | a mass-storage transport error fails the disk (no Reset Recovery) | `msc::a_phase_error_is_recovered_and_the_command_runs_again` |
//! | `canary-dr-mode` | a DWC3 in device or otg mode driven as a host | `a_dwc3_is_a_host_only_when_the_device_tree_says_so` |
//! | `canary-xhci-no-reset` | a command timeout latches the controller, no reset | `a_command_timeout_resets_the_controller_and_the_device_comes_back` |
//! | `canary-xhci-reset-keeps-devices` | the core keeps the devices a reset controller forgot | `a_command_timeout_resets_the_controller_and_the_device_comes_back` |
//! | `canary-xhci-reset-event-ring` | a reset keeps the event ring's old cursor | `a_command_timeout_resets_the_controller_and_the_device_comes_back` |
//! | `canary-xhci-hse-latches` | a host system error latches the controller, no reset | `a_host_system_error_resets_the_controller_and_a_second_latches_it` |
//! | `canary-dwc2-hprt-w1c` | HPRT0 written back as read (the port disabled) | `dwc2::a_full_speed_device_on_the_root_port_is_addressed_and_configured` |
//! | `canary-dwc2-toggle` | the data toggle never read back | `dwc2::consecutive_bulk_transfers_keep_the_data_toggle` |
//! | `canary-dwc2-no-bounce` | an IN tail received in place | `dwc2::an_in_shorter_than_a_packet_is_bounced_and_never_overruns` |
//! | `canary-dwc2-split` | a full-speed device behind a high-speed hub reached without a split | `dwc2::a_full_speed_device_behind_a_high_speed_hub_is_refused_without_a_split` |
//! | `canary-ep0-close-no-abort` | a control pipe closed with its transfer still on endpoint 0 | `abort::closing_a_control_pipe_stops_what_it_has_queued` |
//! | `canary-core-control-no-abort` | a core control transfer that timed out stays on endpoint 0 | `abort::a_core_control_that_times_out_is_taken_off_endpoint_0` |
//! | `canary-xhci-refusal-ignored` | a refused drop or reset endpoint is taken for done | `abort::a_refused_drop_resets_the_controller`, `abort::a_refused_reset_endpoint_resets_the_controller` |
//! | `canary-dead-hc-frees` | the buffers of a dead controller are freed | `abort::a_dead_controller_keeps_the_memory_it_was_given` |
//! | `canary-dwc2-halt-ignored` | a DWC2 channel that never halted is taken for halted | `dwc2::a_channel_that_will_not_halt_kills_the_controller` |
//! | `canary-arena-clean` | an arena page zeroed and never cleaned for a non-coherent controller | `a_noncoherent_controller_enumerates_through_a_hub_and_reuses_its_pages` |
//!
//! `tests/chaos.rs` drives the kernel's injection point (`azos_chaos`,
//! `xhci-command-drop`) instead of the mock, in a process of its own.

pub mod devices;
pub mod dwc2_mock;
pub mod harness;
pub mod mock;

#[cfg(test)]
mod abort;
#[cfg(test)]
mod admission;
#[cfg(test)]
mod counters;
#[cfg(test)]
mod dwc2;

#[cfg(test)]
mod msc;
#[cfg(test)]
mod reset;
#[cfg(test)]
mod tests;
