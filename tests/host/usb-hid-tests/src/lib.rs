// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the USB HID class driver (crates/drivers/usb-hid).
//!
//! The parser and the decoder run on transcribed report descriptors
//! ([`fixtures`]); the class driver runs over the xHCI mock of
//! tests/host/usb-tests, a fake controller with fake devices behind it, so a
//! test plugs a keyboard in, injects a report on its interrupt endpoint and
//! reads the events that come out of the sink. The events go through the real
//! `azos_drv_input::keymap` (pulled in with `#[path]`, as drivers-tests does)
//! to show what the console would read.
//!
//! Every behaviour that has a canary (a feature of this crate that puts the
//! matching bug back) is covered by a test that goes red with it:
//!
//! | canary | what it breaks | test |
//! |---|---|---|
//! | `canary-rollover` | a key array full of ErrorRollOver is taken for keys | `a_rollover_report_changes_nothing` |
//! | `canary-report-id` | the report ID byte is not skipped | `a_report_with_an_id_is_read_after_the_id` |
//! | `canary-sign` | a relative axis is not sign-extended | `relative_axes_are_signed` |
//! | `canary-modifier-order` | modifiers after the keys of the same report | `modifiers_come_before_the_keys_of_their_report` |
//! | `canary-tier` | the hub tier is not compared | `a_device_behind_too_many_hubs_is_refused` |
//! | `canary-composite` | a keyboard that is also storage is admitted | `a_keyboard_that_is_also_storage_is_refused` |
//! | `canary-no-record` | the decision is not recorded | `every_authorization_is_recorded` |

pub mod fixtures;

/// The console's keymap, as the kernel compiles it.
#[cfg(test)]
#[path = "../../../../crates/drivers/input/src/keymap.rs"]
pub mod keymap;

#[cfg(test)]
mod decoder;
#[cfg(test)]
mod driver;
#[cfg(test)]
mod parser;
