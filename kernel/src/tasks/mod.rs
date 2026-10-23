// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel tasks that `kernel_main` creates, grouped by subsystem. Everything
//! is re-exported so `kernel_main` names each task entry point directly.

// The placement class of each kernel task (Kconfig `TASK_*_PLACE`).
pub(crate) mod place;
mod system;
pub(crate) use system::*;
mod net_poll;
pub(crate) use net_poll::*;
mod net_clients;
pub(crate) use net_clients::*;
#[cfg(feature = "use-robot")]
mod sensors;
#[cfg(feature = "use-robot")]
pub(crate) use sensors::*;
mod loader;
mod loader_admit;
pub(crate) use loader::*;
// Kconfig `MM_RECLAIM_COMPRESS`: the memory reclaim task.
mod reclaim;
pub(crate) use reclaim::*;
mod ina219_host;
mod buzzer_host;
#[cfg(feature = "ina219-kernel")]
pub(crate) use ina219_host::*;
pub(crate) use buzzer_host::*;
// Wave 15 (B2): the camera's one capture task and its frame ring.
#[cfg(feature = "use-robot")]
mod cam_capture;
#[cfg(feature = "use-robot")]
pub(crate) use cam_capture::*;
#[cfg(feature = "use-robot")]
mod camera;
#[cfg(feature = "use-robot")]
pub(crate) use camera::*;
#[cfg(feature = "use-robot")]
mod brain_link;
#[cfg(feature = "use-robot")]
pub(crate) use brain_link::*;
#[cfg(feature = "use-robot")]
mod behavior;
#[cfg(any(feature = "rc-input", feature = "geofence"))]
pub(crate) mod rc_safety;
#[cfg(feature = "use-robot")]
pub(crate) use behavior::*;
