// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the USB network and serial class drivers
//! (crates/drivers/usb/src/class/cdc.rs, class/smsc95xx.rs) and the kernel's
//! NIC adapter over them (crates/drivers/net/src/usb_net.rs).
//!
//! The NTB-16 parser and builder and the class-specific descriptor parser run
//! on bytes ([`ntb`]); the three functions run over the xHCI mock of
//! tests/host/usb-tests, a fake controller with fake devices behind it
//! ([`net`] for CDC-ECM and CDC-NCM, [`acm`] for CDC-ACM): a test plugs a
//! device in, the driver reads its descriptors and sets it up through the
//! control pipe, and frames and bytes go in and out of the bulk endpoints the
//! way a device would move them.
//!
//! Every behaviour that has a canary (a feature of `azos_usb` that puts the
//! matching bug back) is covered by a test that goes red with it:
//!
//! | canary | what it breaks | test |
//! |---|---|---|
//! | `canary-ntb-bounds` | a datagram is not checked against the end of its block | `a_datagram_past_the_end_of_the_block_ends_the_block` |
//! | `canary-zlp-pad` | a transmission ending on a packet boundary is not padded | `a_frame_ending_on_a_packet_boundary_gets_a_pad_byte` |
//! | `canary-ntb-align` | datagrams of a block sent ignore the device's divisor and remainder | `the_divisor_and_the_remainder_place_each_datagram` |
//! | `canary-no-clear-halt` | a halted bulk pipe is never cleared | `a_halted_bulk_pipe_is_cleared_and_reception_goes_on` |
//! | `canary-mismatch` | a data interface the union does not name is driven | `a_function_that_is_not_what_it_says_is_failed_not_driven` |
//! | `canary-ntb-input-size` | SET_NTB_INPUT_SIZE is not sent | `an_ncm_function_reads_the_block_parameters_and_limits_the_devices_blocks` |
//! | `canary-smsc-zlp` | a LAN95xx transfer ending on a packet boundary is not padded | `a_transfer_ending_on_a_packet_boundary_gets_a_byte_of_padding` |
//! | `canary-smsc-rx-bounds` | a LAN95xx status word is not checked against the end of its transfer | `the_parser_never_reads_past_the_transfer` |

pub mod fixtures;

#[cfg(test)]
mod acm;
#[cfg(test)]
mod net;
#[cfg(test)]
mod nic;
#[cfg(test)]
mod ntb;
#[cfg(test)]
mod smsc;

/// The kernel's NIC adapter over the network function, as the kernel builds it.
#[cfg(test)]
#[path = "../../../../crates/drivers/net/src/usb_net.rs"]
mod usb_net;
