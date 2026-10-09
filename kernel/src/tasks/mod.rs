// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel tasks that `kernel_main` creates, grouped by subsystem. Everything
//! is re-exported so `kernel_main` names each task entry point directly.

mod system;
pub(crate) use system::*;
mod net_poll;
pub(crate) use net_poll::*;
#[cfg(feature = "domain-robot")]
mod sensors;
#[cfg(feature = "domain-robot")]
pub(crate) use sensors::*;
mod loader;
pub(crate) use loader::*;
mod ina219_host;
mod buzzer_host;
#[cfg(feature = "ina219-kernel")]
pub(crate) use ina219_host::*;
#[cfg(feature = "buzzer-kernel")]
pub(crate) use buzzer_host::*;
// Wave 11 (SHMRING): kernel-produced sensor streams.
mod streams;
pub(crate) use streams::*;
// Wave 15 (B2): the camera's one capture task and its frame ring.
#[cfg(any(feature = "domain-robot", feature = "camera"))]
mod cam_capture;
#[cfg(any(feature = "domain-robot", feature = "camera"))]
pub(crate) use cam_capture::*;
#[cfg(feature = "domain-robot")]
mod camera;
#[cfg(feature = "domain-robot")]
pub(crate) use camera::*;
#[cfg(feature = "domain-robot")]
mod brain_link;
#[cfg(feature = "domain-robot")]
pub(crate) use brain_link::*;
#[cfg(feature = "domain-robot")]
mod behavior;
#[cfg(any(feature = "rc-input", feature = "geofence"))]
pub(crate) mod rc_safety;
#[cfg(feature = "domain-robot")]
pub(crate) use behavior::*;
mod lease_worker;
pub(crate) use lease_worker::*;
