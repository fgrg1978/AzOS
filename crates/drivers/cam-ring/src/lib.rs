// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The frame class's pool ([`FramePool`], module [`pool`]): one producer,
//! many readers, buffers the pool is lent and does not own. A camera driver
//! writes into it through [`FrameSink`] (module [`sink`]).

#![no_std]

pub mod pixels;
pub mod pool;
pub mod sink;
pub use pixels::{jpeg_size, yuyv_luma};
pub use pool::{FrameId, FramePool, FrameRef, NoRoom, Policy};
pub use sink::{FrameFormat, FrameInfo, FrameSink};
