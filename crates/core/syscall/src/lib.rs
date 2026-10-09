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
pub mod dispatch;
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
pub mod motor_cmd;
pub mod link_key;
pub mod entropy;
pub mod vdso_notify;
pub mod ushell;
// RFC-0047: the Linux personality's translation (Kconfig `LINUX_ABI`).
pub mod linux;
// RFC-0055 S5: the power family's typed call (614).
pub mod power;
/// Wave 12: the flight, behavior, config and OTA typed calls (615..=618).
pub mod families;
/// Wave 15: the kernel tracer's control call (632).
pub mod trace_ctl;
/// Wave 15: which ring-3 task commands each wheel; its exit stops them.
pub mod motor_commander;
#[cfg(feature = "lx-loader")]
pub mod module_ops;
/// The pure token table `module_ops` keeps (host-tested).
#[cfg(feature = "lx-loader")]
pub mod module_tokens;
// Without the Robot domain: what the motor and robot-sensor syscalls see in
// place of the robot crates (see the module doc).
#[cfg(not(feature = "domain-robot"))]
pub mod no_robot;

pub use dispatch::{
    syscall_dispatch, syscall_dispatch_out, syscall_entry_fast, syscall_dispatch_checked,
    SyscallEntry, SyscallOut, SYSCALL_OUT_REGS,
};
pub use numbers::*;
