// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The placement class of each kernel task (Kconfig `TASK_*_PLACE`,
//! config/kernel/Kconfig.tasks), read at compile time: a value that is not a class
//! does not build. [`pin`] resolves a class against this boot's CPUs
//! (`azos_percpu::place`); every `task_create_affinity` of a kernel task
//! takes its CPU from there, never from a literal (tools/lint/task_place_lint.py).

use azos_percpu::place::Place;

/// [`azos_percpu::place::pin_avoiding`] the boot's real-time CPUs
/// (`azos_sync::qsbr::rt_cpus`): the cluster, RCU_NOCBS_CPUS and `isolcpus`.
pub(crate) fn pin(p: Place) -> i8 {
    azos_percpu::place::pin_avoiding(p, azos_sync::qsbr::rt_cpus())
}

#[cfg(feature = "net")]
pub(crate) const NET_POLL: Place = Place::of_kconfig(azos_limits::TASK_NET_POLL_PLACE);
#[cfg(feature = "autorun")]
pub(crate) const AUTORUN: Place = Place::of_kconfig(azos_limits::TASK_AUTORUN_PLACE);
pub(crate) const SYS_WDT: Place = Place::of_kconfig(azos_limits::TASK_SYS_WDT_PLACE);
#[cfg(all(feature = "net", feature = "boot-slots"))]
pub(crate) const OTA_RECV: Place = Place::of_kconfig(azos_limits::TASK_OTA_RECV_PLACE);
/// The effect loops a driver registers (`azos_ext_api::EffectLoop`).
pub(crate) const EFFECT_LOOPS: Place = Place::of_kconfig(azos_limits::TASK_CONTROL_PLACE);
/// behavior, brain-tx, camera-tx and ml-infer.
#[cfg(feature = "use-robot")]
pub(crate) const BEHAVIOR: Place = Place::of_kconfig(azos_limits::TASK_BEHAVIOR_PLACE);
