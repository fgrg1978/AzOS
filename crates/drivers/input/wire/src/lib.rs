// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the kernel's input drivers and its framebuffer console share with the
//! terminal server (`userspace/services/termd`), compiled by both sides so the
//! layout is a contract and not two copies of one.
//!
//! * [`event`]: the input event word every producer (PS/2, virtio-input) puts
//!   on the event ring, and the evdev codes it carries.
//! * [`screen`]: the console screen region, a kernel-owned memory object the
//!   terminal server maps: the text on the screen, the lines scrolled off it,
//!   the overlay (pointer cell, selection, view offset) the server asks the
//!   renderer to draw, and the mouse reporting mode the programs asked for.
#![no_std]

pub mod event;
pub mod screen;
