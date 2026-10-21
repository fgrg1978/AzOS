// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the USB video class driver (crates/drivers/usb/src/class/uvc.rs)
//! and the isochronous pipes of the USB core it streams over.
//!
//! The descriptor walker, the PROBE/COMMIT blocks and the payload header run
//! on bytes; the driver and the pipes run over the xHCI mock of
//! tests/host/usb-tests, a fake controller with a fake camera behind it
//! ([`fixtures`]): a test plugs a camera in, the driver reads its descriptors
//! and negotiates a stream through the control pipe, picks the setting that
//! carries it, and the camera's payloads go out of the isochronous (or bulk)
//! endpoint into a frame ring the way a device would send them.

//! Every behaviour that has a canary (a feature of `azos_usb` that puts the
//! matching bug back) is covered by a test that goes red with it:
//!
//! | canary | what it breaks | test |
//! |---|---|---|
//! | `canary-isoch-halt` | a bus error halts an isochronous endpoint | `a_lost_interval_completes_with_its_code_and_the_endpoint_keeps_running` |
//! | `canary-isoch-burst` | the packets of an interval's last burst are not counted | `an_interval_is_one_isoch_trb_with_its_burst_fields` |
//! | `canary-uvc-err` | the camera's error flag on a payload is ignored | `a_payload_flagged_with_the_error_bit_drops_its_frame_and_the_next_one_is_fine` |
//! | `canary-uvc-sync` | the frame the stream starts in is delivered | `a_stream_that_starts_mid_frame_delivers_nothing_of_that_frame` |
//! | `canary-uvc-fid` | a toggle of FID does not end a frame | `a_camera_that_never_sets_eof_ends_its_frames_at_the_toggle` |
//! | `canary-uvc-probe-len` | every camera is sent the 26-byte PROBE block | `a_camera_is_negotiated_and_left_idle_until_somebody_reads` |
//! | `canary-uvc-alt` | the first isochronous setting is selected whatever it carries | `a_reader_starts_the_stream_with_commit_and_the_smallest_setting_that_carries_it` |

pub mod fixtures;

#[cfg(test)]
mod isoch;
#[cfg(test)]
mod stream;
#[cfg(test)]
mod survey;
