// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_cam_ring`.
//!
//! A reader cannot write a frame. This must not compile, because a frame's
//! bytes are a shared slice:
//!
//! ```compile_fail,E0594
//! use azos_cam_ring::{FramePool, Policy};
//! let pool = FramePool::<4, 8, 1>::new(Policy::OverwriteOldest);
//! let f = pool.acquire_latest(0).unwrap();
//! f.bytes()[0] = 1;
//! ```
//!
//! Nor can it keep a frame past its reference: the frame borrows the pool and
//! ends with the read.
//!
//! ```compile_fail,E0597
//! use azos_cam_ring::{FramePool, Policy};
//! let pool = FramePool::<4, 8, 1>::new(Policy::OverwriteOldest);
//! let bytes = {
//!     let f = pool.acquire_latest(0).unwrap();
//!     f.bytes()
//! };
//! let _ = bytes;
//! ```
//!
//! The control for both: the same calls, reading and not keeping, build.
//!
//! ```
//! use azos_cam_ring::{FramePool, Policy};
//! let pool = FramePool::<4, 8, 1>::new(Policy::OverwriteOldest);
//! let n = pool.acquire_latest(0).map(|f| f.bytes()[0]);
//! assert!(n.is_none());
//! ```

#[cfg(test)]
mod pixel_tests;
#[cfg(test)]
mod pool_tests;
