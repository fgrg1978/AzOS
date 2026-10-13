// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
extern crate alloc;

pub mod file_ops;
pub mod numbers;
pub mod handlers;
pub mod ipc_handlers;
pub mod ioring_ops;
pub mod ioring_sqpoll;
pub mod syscall_table;
pub mod syscall_out;
pub mod dispatch;
// Kconfig IPC_FASTPATH (Chain E stage a): the fast call and reply from the
// trap entry.
pub mod fastpath;
#[cfg(feature = "kheap-census")]
pub mod kheap_census;
pub mod mmio;
pub mod sleep;
pub mod spawn;
/// Wave 14 (SPAWNCACHE): the verified-image digest cache.
pub mod image_cache;
/// Wave 13: what a native fork child holds (descriptors, its row's capabilities).
pub mod natfork;
/// Wave 13: the native thread calls (620..=623).
pub mod threads;
pub mod topo_sched;
pub mod motor_host;
pub mod sensor_host;
pub mod block_host;
pub mod link_key;
pub mod entropy;
/// D6 part A: the interfaces the kernel hosts, served from endpoints.
pub mod khost;
pub mod vdso_notify;
pub mod ushell;
// RFC-0047: the Linux personality's translation (Kconfig `LINUX_ABI`).
pub mod linux;
pub mod foreign;
/// D6: `SYS_INVOKE`, the operations on a handle.
pub mod invoke;
pub mod memory;
/// D6: the handle family: `SYS_CAP_INFO`, `_CLOSE`, `_DERIVE`, `_REVOKE`.
pub mod caps;
// RFC-0055 S5: the power family's typed call (614).
pub mod power;
/// D6 part A: the `Gpio`, `I2c` and `Pwm` interfaces the kernel hosts.
pub mod devices;
/// Wave 12: the flight, behavior, config and OTA typed calls (615..=618).
pub mod families;
/// Wave 15: the kernel tracer's control call (632).
pub mod trace_ctl;
/// Wave 15 N11b: ABI v2 of the call (633..=637).
pub mod ipc_v2;
/// The deadline a v2 call carries, checked before it is queued.
pub mod ipc_deadline;
/// The kernel's own calls to an endpoint a task serves (Phase 4 elasticity).
pub mod kcall;
pub mod schedctl;
/// Wave 15: which ring-3 task commands each wheel; its exit stops them.
pub mod motor_commander;
#[cfg(feature = "lx-loader")]
pub mod module_ops;
/// The pure token table `module_ops` keeps (host-tested).
#[cfg(feature = "lx-loader")]
pub mod module_tokens;
// Without the Robot domain: what the motor and robot-sensor syscalls see in
// place of the robot crates (see the module doc).
#[cfg(not(feature = "use-robot"))]
pub mod no_robot;

pub use dispatch::{
    syscall_dispatch, syscall_dispatch_out, syscall_entry_fast, syscall_verdict, syscall_dispatch_checked,
    SyscallEntry, SyscallOut, SYSCALL_OUT_REGS,
};
pub use numbers::*;
