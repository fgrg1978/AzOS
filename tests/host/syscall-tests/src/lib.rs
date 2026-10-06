// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `crates/core/syscall/src/handlers.rs` (2,947 lines, zero
//! host coverage before this crate).
//!
//! **WHY.** About thirty handlers validate a user pointer or a length before
//! touching kernel state, and two of them have already reset the board in
//! production: `sys_munmap` zeroing the UART's PTE (guarded today by one
//! comparison around `handlers.rs:1259`), and `sys_connect` overflowing a u16
//! from an out-of-range fd (fixed with `saturating_add`, never tested).
//!
//! **Both are now reached** (`src/mmap_guards.rs`, `src/connect_guards.rs`),
//! against the real Sv39 walker rather than a model — `shims/mm` pulls
//! `crates/core/mm/src/{addr,pmm,vmm,cow,demand}.rs` in whole and backs them with
//! a leaked, page-aligned host arena, the way `tests/host/mm-tests` already does
//! for `pmm.rs`.
//!
//! **And the munmap guard turns out not to cover the incident it cites.**
//! `USER_VA_TOP` is `0x8000_0000`; the UART is at `0x1000_0000`, below it.
//! Every MMIO window sits in VPN[2] = 0, which
//! `crates/core/sched/src/process.rs:26-40` documents as *shared* between every
//! user page table and the kernel's. `munmap_of_an_mmio_address_still_
//! reaches_the_kernels_own_page_table` reproduces the board reset out of real
//! kernel code and is deliberately written to assert the broken behaviour —
//! read its doc comment before changing it.
//!
//! **The whole file is pulled in with `include!`, real code, not a copy —
//! and `include!` rather than `#[path]` specifically so the tests can sit
//! *inside* `mod handlers` and see its private items.** Three of the targets
//! under test (`errno_for_*_err`, `cap_kind_for_driver`, `socket_access_ok`)
//! are private `fn`s, as is `USER_VA_TOP`, which the mmap/munmap tests read
//! rather than copy. `handlers.rs` is a single 2,947-line module with a
//! dependency footprint spanning essentially every kernel subsystem (159
//! distinct `azos_*::path` references across ipc, sched, drivers, fs,
//! net, mm, arch, robot, service, imu, gps, driver_server, sync). Compiling
//! it means every one of those names must resolve, whether or not a given
//! test exercises it — Rust compiles the whole file as one unit, and nothing
//! here modifies it.
//!
//! Everything `handlers.rs` needs to resolve is satisfied by the `shims/`
//! crates, most of which are `todo!()` stubs matching real signatures, never
//! called from a test in this crate. Several are real production code
//! pulled in with `#[path]`, not stand-ins — see each shim's own doc comment
//! for which and why. In short:
//!
//! - `shims/arch`, `shims/driver_server` are the real `arch-riscv64::mmu`
//!   module and the real `crates/drivers/driver_server` crate (both pure, no
//!   RISC-V-only dependencies).
//! - `shims/net` pulls the real `ethernet`/`arp`/`checksum`/`ip`/`ipv6`/
//!   `igmp`/`dns`/`ntp`/`seq`/`tcp`/`udp`/`socket` modules, the superset
//!   `tests/host/net-tests` already proves compiles together on a host target.
//! - `shims/ipc` pulls the real `cap`/`cap_store`/`channel`/`port`/`shm`/
//!   `gpio_cap`/`i2c_cap`/`pwm_cap`/`motor_cap`/`io_ring` modules
//!   (the same trick `tests/host/cap-tests` uses for `cap.rs`), because the error
//!   enums under test in target 1 are defined inside them.
//! - `shims/mm` is `crates/core/mm` itself — see its own doc for why a model page
//!   table was rejected, and for the one thing that *is* faked on that path
//!   (`sfence.vma` and `satp`, in `shims/arch`).
//! - `shims/sched` is the exception: `copy_from_user`/`copy_to_user` are
//!   transcribed from `crates/core/sched/src/process.rs`, not pulled, because
//!   they live inside a module of RV64 assembly. The permission decision
//!   inside them is still a call into the real `vmm::translate_user`; the
//!   shim's own doc says exactly which half is which.
//!
//! A stub body is `todo!()`, never a plausible return value: a stub that
//! quietly "succeeded" would make some other test's canary un-fireable.

// `handlers.rs` names `crate::file_ops`, so the seam has to sit at this
// crate's root and not inside `mod handlers`. It is the real module: the
// trait, the installed-implementation slot and the local `cstr_to_bytes`
// that replaced the filesystem's.
// `#[path]`, not `include!`, and the exception is deliberate: the note below
// about `include!` applies to modules nested inside an already-included
// module. `file_ops` is a real file at this crate's root, and it opens with
// `//!` inner docs, which `include!` cannot carry into a `mod` block.
// The driver class crates the compiled sources name, all served by the
// one host stand-in `syscall_test_drivers`.
extern crate syscall_test_drivers as azos_drv_actuator;
extern crate syscall_test_drivers as azos_drv_base;
extern crate syscall_test_drivers as azos_drv_block;
extern crate syscall_test_drivers as azos_drv_bus;
extern crate syscall_test_drivers as azos_drv_gpio;
extern crate syscall_test_drivers as azos_drv_irqchip;
extern crate syscall_test_drivers as azos_drv_power;
extern crate syscall_test_drivers as azos_drv_sensor;
extern crate syscall_test_drivers as azos_drv_sys;
extern crate syscall_test_drivers as azos_drv_virtio;

#[path = "../../../../crates/core/syscall/src/file_ops.rs"]
pub mod file_ops;

// Wave 14 (SPAWNCACHE): the verified-image digest cache, the real file;
// `handlers.rs` names it as `crate::image_cache` (`sys_execpath`).
#[path = "../../../../crates/core/syscall/src/image_cache.rs"]
pub mod image_cache;

// The IPC handlers live beside `handlers.rs` in `crates/core/syscall/src/ipc_handlers.rs`,
// and `dispatch.rs` names them through `crate::ipc_handlers`, so this module
// sits at the crate root too; a test module inside `mod handlers` that calls
// them imports `crate::ipc_handlers::*`. `#[path]` for the same reason as
// `file_ops`: the file opens with `//!` inner docs.
#[path = "../../../../crates/core/syscall/src/ipc_handlers.rs"]
#[allow(dead_code, unused_imports)]
pub mod ipc_handlers;

// The kernel's io_ring op table (RFC-0041 §E). At the crate root, where the
// kernel's `lib.rs` declares it, because it names `crate::handlers`; `#[path]`
// for the same reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/ioring_ops.rs"]
pub mod ioring_ops;

// `SYS_MOTOR_MOVE_TYPED` (584, U11-12/W2-B4). At the crate root, same reason
// as `ioring_ops`: it names `crate::handlers::{E_CONTAINED, note_typed_denial}`
// (both `pub(crate)` in `handlers.rs`, visible from any module in this
// crate regardless of the sibling `mod handlers { .. }` below being
// private). `#[path]`, not `include!`, for the same reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/motor_cmd.rs"]
pub mod motor_cmd;

// `SYS_LINK_KEY_READ_TYPED` (591, U06-9). At the crate root, same reason as
// `motor_cmd`: it names `crate::handlers::{E_CONTAINED, note_typed_denial}`
// too. `#[path]`, not `include!`, for the same reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/link_key.rs"]
pub mod link_key;

// `SYS_ENTROPY_READ_TYPED` (596, wave 9 P9). At the crate root, same reason
// as `link_key`: it names `crate::handlers::{E_CONTAINED, note_typed_denial}`.
#[path = "../../../../crates/core/syscall/src/entropy.rs"]
pub mod entropy;
#[path = "../../../../crates/core/syscall/src/power.rs"]
pub mod power;
// Wave 12: the flight/behavior/config/OTA typed calls, the real file.
#[path = "../../../../crates/core/syscall/src/families.rs"]
pub mod families;
// Wave 15: the kernel tracer's control call (632), the real file.
#[path = "../../../../crates/core/syscall/src/trace_ctl.rs"]
pub mod trace_ctl;

// Wave 6 (front V): the per-task vDSO page and notify/wait handlers. A
// sibling of `link_key` for the same reason; `#[path]`, not `include!`.
#[path = "../../../../crates/core/syscall/src/vdso_notify.rs"]
pub mod vdso_notify;

// `SYS_MMIO_MAP` (509, RFC-0043). At the crate root, same reason as
// `motor_cmd`: it names `crate::handlers::*` (`cap_check`). `#[path]`, not
// `include!`, for the same reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/mmio.rs"]
pub mod mmio;

// `SYS_SLEEP` and the kernel-context sleep helpers `handlers.rs` waits with
// (`crate::sleep::wait_until_ms`, wave 11). At the crate root, where the
// kernel's `lib.rs` declares it; `#[path]`, not `include!`, for the same
// reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/sleep.rs"]
#[allow(dead_code)]
pub mod sleep;

// `handlers.rs`'s `sys_fork` names `crate::natfork` (wave 13). The real file
// needs the topology, the pipe pool and the cap store; the sched shim's
// `sys_fork_impl_hooked` never runs its hook, so this is never reached.
pub mod natfork {
    pub(crate) fn native_child_setup(_parent: u32, _child: u32) -> bool {
        todo!("not reached: the sched shim never runs a fork's before_release hook")
    }
}

mod handlers {
    #![allow(dead_code, unused_imports)]
    include!("../../../../crates/core/syscall/src/handlers.rs");

    // `include!`, not `#[path]`: a `mod x;` file-module nested inside a
    // module that itself came from `include!` (not a real file) resolves
    // its directory from the *module path* (`src/handlers/`), which does
    // not exist on disk. `include!`'s path is resolved relative to the
    // physical file it appears in (`src/lib.rs` -> `src/`) regardless of
    // module nesting, so it finds these siblings directly.
    #[cfg(test)]
    mod harness {
        use super::*;
        include!("harness.rs");
    }

    #[cfg(test)]
    mod service_authority {
        use super::*;
        include!("service_authority.rs");
    }

    #[cfg(test)]
    mod mmap_guards {
        use super::*;
        include!("mmap_guards.rs");
    }

    #[cfg(test)]
    mod demand_paging {
        use super::*;
        include!("demand_paging.rs");
    }

    #[cfg(test)]
    mod connect_guards {
        use super::*;
        include!("connect_guards.rs");
    }

    #[cfg(test)]
    mod errno {
        use super::*;
        include!("errno.rs");
    }

    #[cfg(test)]
    mod driver_caps {
        use super::*;
        include!("driver_caps.rs");
    }

    #[cfg(test)]
    mod socket_gate {
        use super::*;
        include!("socket_gate.rs");
    }

    #[cfg(test)]
    mod irq_wait {
        use super::*;
        include!("irq_wait.rs");
    }

    #[cfg(test)]
    mod driver_server_guards {
        use super::*;
        include!("driver_server_guards.rs");
    }

    #[cfg(test)]
    mod driver_reply_wait {
        use super::*;
        include!("driver_reply_wait.rs");
    }

    #[cfg(test)]
    mod raw_input_guards {
        use super::*;
        include!("raw_input_guards.rs");
    }

    #[cfg(test)]
    mod cap_denial_record {
        use super::*;
        include!("cap_denial_record.rs");
    }

    #[cfg(test)]
    mod hw_cap_guards {
        use super::*;
        include!("hw_cap_guards.rs");
    }

    #[cfg(test)]
    mod disk_scope {
        use super::*;
        include!("disk_scope.rs");
    }

    #[cfg(test)]
    mod file_ops_seam {
        use super::*;
        include!("file_ops_seam.rs");
    }

    #[cfg(test)]
    mod gpio_typed_lock {
        use super::*;
        include!("gpio_typed_lock.rs");
    }

    #[cfg(test)]
    mod taskinfo_layout {
        use super::*;
        include!("taskinfo_layout.rs");
    }

    #[cfg(test)]
    mod file_caps {
        use super::*;
        include!("file_caps.rs");
    }

    #[cfg(test)]
    mod socket_caps {
        use super::*;
        include!("socket_caps.rs");
    }

    #[cfg(test)]
    mod mcast_caps {
        use super::*;
        include!("mcast_caps.rs");
    }

    #[cfg(test)]
    mod unit6_contain {
        use super::*;
        include!("unit6_contain.rs");
    }

    #[cfg(test)]
    mod ipc_destroy {
        use super::*;
        include!("ipc_destroy.rs");
    }

    #[cfg(test)]
    mod image_cache_tests {
        use super::*;
        include!("image_cache_tests.rs");
    }

    #[cfg(test)]
    mod image_frames_tests {
        use super::*;
        include!("image_frames_tests.rs");
    }

    #[cfg(test)]
    mod exec_binding {
        use super::*;
        include!("exec_binding.rs");
    }

    #[cfg(test)]
    mod motor_angle_gate {
        use super::*;
        include!("motor_angle_gate.rs");
    }

    #[cfg(test)]
    mod typed_twin_guards {
        use super::*;
        include!("typed_twin_guards.rs");
    }

    #[cfg(test)]
    mod typed_ipc {
        use super::*;
        include!("typed_ipc.rs");
    }

    #[cfg(test)]
    mod ioring_ops_guards {
        use super::*;
        include!("ioring_ops_guards.rs");
    }

    #[cfg(test)]
    mod seccomp_deny_kill {
        use super::*;
        include!("seccomp_deny_kill.rs");
    }

    #[cfg(test)]
    mod link_key_guards {
        use super::*;
        include!("link_key_guards.rs");
    }

    #[cfg(test)]
    mod entropy_guards {
        use super::*;
        include!("entropy_guards.rs");
    }

    #[cfg(test)]
    mod power_guards {
        use super::*;
        include!("power_guards.rs");
    }

    #[cfg(test)]
    mod family_guards {
        use super::*;
        include!("family_guards.rs");
    }

    #[cfg(test)]
    mod process_wait {
        use super::*;
        include!("process_wait.rs");
    }

    #[cfg(test)]
    mod socket_ownership {
        use super::*;
        include!("socket_ownership.rs");
    }

    #[cfg(test)]
    mod service_calls {
        use super::*;
        include!("service_calls.rs");
    }

    #[cfg(test)]
    mod info_forwarders {
        use super::*;
        include!("info_forwarders.rs");
    }

    #[cfg(test)]
    mod fs_stubs {
        use super::*;
        include!("fs_stubs.rs");
    }

    #[cfg(test)]
    mod mmio_map {
        use super::*;
        include!("mmio_map.rs");
    }

    #[cfg(test)]
    mod motor_pid_calls {
        use super::*;
        include!("motor_pid_calls.rs");
    }

    // Wave 7 (front DA): the syscalls whose bodies moved out of
    // `dispatch.rs`'s match into `sys_*` functions in `handlers.rs`.
    #[cfg(test)]
    mod lease_calls {
        use super::*;
        include!("lease_calls.rs");
    }

    #[cfg(test)]
    mod drv_calls {
        use super::*;
        include!("drv_calls.rs");
    }

    #[cfg(test)]
    mod dns_resolve {
        use super::*;
        include!("dns_resolve.rs");
    }

    // RFC-0049 M4: the cold-restart supervisor, and what the driver server
    // and the service registry hold for a restarted driver.
    #[cfg(test)]
    mod driver_supervise {
        use super::*;
        include!("driver_supervise.rs");
    }

    // Wave 10: the tree capability mkdir/unlink/rmdir/rename/truncate need.
    #[cfg(test)]
    mod fs_tree_caps {
        use super::*;
        include!("fs_tree_caps.rs");
    }

    // Wave 11: `sys_accept`/`sys_pause` wait on the counter, not on a count
    // of yields.
    #[cfg(test)]
    mod yield_waits {
        use super::*;
        include!("yield_waits.rs");
    }

    // Wave 11 (SENSORTS): `SYS_SENSOR_READ_TS`, the stamped sensor read.
    #[cfg(test)]
    mod sensor_ts {
        use super::*;
        include!("sensor_ts.rs");
    }
}

// Wave 10: the table `dispatch.rs` builds from its arms. `dispatch.rs` itself
// is never compiled here (U14-8), so the macro is pulled alone and driven on
// arms of every shape the dispatch uses.
#[cfg(test)]
#[path = "../../../../crates/core/syscall/src/syscall_table.rs"]
mod syscall_table;

#[cfg(test)]
mod dispatch_table;
