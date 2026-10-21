// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Input devices and what they share.
//!
//! Every keyboard driver ends in the same two places: a console byte in the
//! UART's RX ring (the one owner of console input) and, for
//! everything that is not a console byte, a packed event in [`events`]'
//! ring, which the ring-3 terminal server (`termd`) drains. [`keymap`] decides which
//! (evdev codes in, bytes out); [`events`] is the ring. virtio-input
//! (`azos_drv_virtio::virtio::input`) and the PS/2 controller ([`ps2`]) are
//! the two producers.
//!
//! [`scancode`], [`mouse`], [`stream`] and [`i8042`] are pure and host-tested;
//! [`ps2`] is their I/O and interrupt-side glue.

#![no_std]

pub mod events;
pub mod i8042;
pub mod keymap;
pub mod mouse;
pub mod ps2;
pub mod scancode;
pub mod stream;
