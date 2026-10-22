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
//! net, mm, arch, robot, imu, gps, driver_server, sync). Compiling
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

// `handlers.rs` takes a disk call's bounce buffer from the heap
// (`alloc::vec::Vec`), as the kernel crate does.
extern crate alloc;

#[path = "../../../../crates/core/syscall/src/file_ops.rs"]
pub mod file_ops;

// Front mmap-file: the file mapping `NODE_MMAP` (and the `munmap` / `fsync`
// hooks of `handlers.rs`) call.
#[path = "../../../../crates/core/syscall/src/file_map.rs"]
pub mod file_map;

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

// The kernel's io_ring op table. At the crate root, where the
// kernel's `lib.rs` declares it, because it names `crate::handlers`; `#[path]`
// for the same reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/ioring_ops.rs"]
pub mod ioring_ops;

// Wave 15: the motor-commander table the `Motor` interface notes into,
// the real file. At the crate root, where the kernel's `lib.rs` declares it.
#[path = "../../../../crates/core/syscall/src/motor_commander.rs"]
pub mod motor_commander;

// The `LinkKey` server (U06-9). At the crate root, same reason as
// the motor server: it names `crate::handlers::{E_CONTAINED, note_typed_denial}`
// too. `#[path]`, not `include!`, for the same reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/link_key.rs"]
pub mod link_key;

#[path = "../../../../crates/core/syscall/src/ipc_deadline.rs"]
pub mod ipc_deadline;
// The interfaces the kernel hosts (D6 part A): the dispatcher and the
// `Entropy` server (wave 9 P9). At the crate root, same reason as
// `link_key`: they name `crate::handlers::{E_CONTAINED, note_typed_denial_for}`.
#[path = "../../../../crates/core/syscall/src/khost.rs"]
pub mod khost;
#[path = "../../../../crates/core/syscall/src/entropy.rs"]
pub mod entropy;
// The clock discipline's kernel side and the `Clock` interface (the dispatcher
// and the timer tick name it).
#[path = "../../../../crates/core/syscall/src/clock.rs"]
pub mod clock;
// The `Net` interface (the resolver and the SNTP client's state).
#[path = "../../../../crates/core/syscall/src/net_host.rs"]
pub mod net_host;
// The `Display` interface (the framebuffer's connector, modes, claim and
// present).
#[path = "../../../../crates/core/syscall/src/display.rs"]
pub mod display;
// The `Sound` interface (the virtio-sound device's streams), over the model
// of the device in `shims/drivers`.
#[path = "../../../../crates/core/syscall/src/sound_host.rs"]
pub mod sound_host;
// The `MemCtl` interface (volatile memory objects).
#[path = "../../../../crates/core/syscall/src/memctl.rs"]
pub mod memctl;
// The `Keys` interface (the keystore the kernel hosts).
#[path = "../../../../crates/core/syscall/src/keys.rs"]
pub mod keys;
#[path = "../../../../crates/core/syscall/src/power.rs"]
pub mod power;
// Wave 12: the flight/behavior/config/OTA typed calls, the real file.
#[path = "../../../../crates/core/syscall/src/families.rs"]
pub mod families;
// D6 part A: the `Gpio`, `I2c` and `Pwm` interfaces, the real file.
#[path = "../../../../crates/core/syscall/src/devices.rs"]
pub mod devices;
// D6 part A: the `Motor` interface, the real file.
#[path = "../../../../crates/core/syscall/src/motor_host.rs"]
pub mod motor_host;
#[path = "../../../../crates/core/syscall/src/sensor_host.rs"]
pub mod sensor_host;
#[path = "../../../../crates/core/syscall/src/block_host.rs"]
pub mod block_host;
// Wave 15: the kernel tracer's control call (632), the real file.
#[path = "../../../../crates/core/syscall/src/trace_ctl.rs"]
pub mod trace_ctl;
// Dead client: the module-token table, the real
// file, and its exit release.
#[path = "../../../../crates/core/syscall/src/module_tokens.rs"]
pub mod module_tokens;

#[cfg(test)]
mod motor_commander_tests {
    use crate::motor_commander::Commanders;

    /// A wheel left turning names its commander; a stop (by anyone) clears
    /// it; a refused write changes nothing; the commander's exit takes
    /// exactly the wheels it still names, once, and never a wheel another
    /// task took over.
    #[test]
    fn an_exiting_commander_takes_only_the_wheels_it_left_turning() {
        let c: Commanders<4> = Commanders::new();
        c.note(0, 40, Some(30));
        c.note(1, 40, Some(50));
        c.note(2, 40, Some(20));
        c.note(3, 40, None);
        assert_eq!(c.commander(3), 0, "a refused write named a commander");
        c.note(1, 41, Some(10));
        c.note(2, 42, Some(0));
        assert_eq!(c.commander(2), 0, "a stopped wheel still names a commander");
        assert_eq!(c.release(40), 0b0001, "wheel 0 only: 1 was taken over, 2 stopped");
        assert_eq!(c.release(40), 0, "a second exit took the wheels again");
        assert_eq!(c.commander(1), 41);
        assert_eq!(c.release(0), 0, "TID 0 names no task");
        c.note(9, 40, Some(30));
        assert_eq!(c.release(40), 0, "an out-of-range wheel was noted");
    }
}

#[cfg(test)]
mod module_tokens_tests {
    use crate::module_tokens::Tokens;

    /// A task that exits holding a token frees its slot at once: the next
    /// four tasks each get a free slot and nobody's token is evicted, and
    /// the dead task's TID, reused, cannot map with the old token. Canary
    /// `module-token-leak-canary` (no release): the dead token still holds
    /// its slot and a fourth live task evicts one of the others.
    #[test]
    fn a_dead_tasks_token_is_released_at_exit() {
        let mut t: Tokens<4> = Tokens::new();
        let dead = t.grant(10, 0x11, 3);
        assert_eq!(t.release_all(10), 1, "the exiting task's token was not released");
        assert_eq!(t.live_of(10), 0);
        // Four live servers verify: with the dead token gone, all four fit.
        let mut slots = [0usize; 4];
        for (k, tid) in [20u32, 21, 22, 23].iter().enumerate() {
            slots[k] = t.grant(*tid, 0x21 + 2 * k as u32, 1);
        }
        for (k, tid) in [20u32, 21, 22, 23].iter().enumerate() {
            assert_eq!(t.live_of(*tid), 1, "tid {} lost its token to an eviction", tid);
            assert_eq!(t.take(slots[k] + 1, *tid, 0x21 + 2 * k as u32), Some(1));
        }
        // A reused TID 10 never inherits the dead token.
        assert_eq!(t.take(dead + 1, 10, 0x11), None);
    }

    /// The token is one-shot and bound to its task and nonce.
    #[test]
    fn a_token_is_one_shot_and_bound_to_its_task() {
        let mut t: Tokens<4> = Tokens::new();
        let s = t.grant(7, 0x31, 2) + 1;
        assert_eq!(t.take(s, 8, 0x31), None, "another task used the token");
        assert_eq!(t.take(s, 7, 0x33), None, "a wrong nonce was accepted");
        assert_eq!(t.take(0, 7, 0x31), None);
        assert_eq!(t.take(5, 7, 0x31), None);
        assert_eq!(t.take(s, 7, 0x31), Some(2));
        assert_eq!(t.take(s, 7, 0x31), None, "the token was used twice");
        assert_eq!(t.release_all(7), 0, "a consumed token is not live");
    }
}

// Wave 6 (front V): the per-task vDSO page and the native futex calls. A
// sibling of `link_key` for the same reason; `#[path]`, not `include!`.
#[path = "../../../../crates/core/syscall/src/vdso_notify.rs"]
pub mod vdso_notify;

// `DOMAIN_MMIO_MAP` (509). At the crate root, same reason as
// `motor_cmd`: it names `crate::handlers::*` (`cap_check`). `#[path]`, not
// `include!`, for the same reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/mmio.rs"]
pub mod mmio;

// `SYS_SLEEP_UNTIL` and the kernel-context sleep helpers `handlers.rs` waits with
// (`crate::sleep::wait_until_ms`, wave 11). At the crate root, where the
// kernel's `lib.rs` declares it; `#[path]`, not `include!`, for the same
// reason as `file_ops`.
#[path = "../../../../crates/core/syscall/src/sleep.rs"]
#[allow(dead_code)]
pub mod sleep;

// `SYS_INVOKE`, the real entry (`crates/core/syscall/src/invoke.rs`), with the
// real `SyscallOut` its replies travel in. The dispatcher it names its output
// type through is not compiled here, so `dispatch` re-exports the output type
// alone; the terminal server's `ushell` ops and the module ops are not reached
// by the refusals the invoke tests drive (`invoke_guards.rs`), and the stubs
// below answer a marker so a test can tell "reached the op" from a refusal.
#[path = "../../../../crates/core/syscall/src/syscall_out.rs"]
pub mod syscall_out;
pub mod dispatch {
    pub use crate::syscall_out::SyscallOut;
}
pub mod ushell {
    /// What every stub answers: a value no refusal produces.
    pub const REACHED: i64 = 777;
    pub fn sys_console_wait(_a: u64, _b: u64, _c: u64, _d: u64) -> i64 { REACHED }
}
#[path = "../../../../crates/core/syscall/src/invoke.rs"]
#[allow(dead_code)]
pub mod invoke;

// `handlers.rs`'s `sys_fork` names `crate::natfork` (wave 13). The real file
// needs the topology and the cap store; the sched shim's
// `sys_fork_impl_hooked` never runs its hook, so this is never reached.
pub mod natfork {
    pub(crate) fn native_child_setup(_parent: u32, _child: u32) -> bool {
        todo!("not reached: the sched shim never runs a fork's before_release hook")
    }

    /// The row a task was seeded from: every task here counts as seeded from
    /// row 0 (`sound_host`'s `mic_effect` asks, but only when another suite of
    /// this crate installed the process-wide topology slot, whose first row
    /// has no `mic` envelope; with the slot empty it is not asked).
    pub fn row_of(_tid: u32) -> Option<usize> {
        Some(0)
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
    mod mmap_file {
        use super::*;
        include!("mmap_file.rs");
    }

    #[cfg(test)]
    mod pagecache_hooks {
        use super::*;
        include!("pagecache_hooks.rs");
    }

    #[cfg(test)]
    mod thp_vmm {
        use super::*;
        include!("thp_vmm.rs");
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

    #[cfg(test)]
    mod invoke_guards {
        use super::*;
        include!("invoke_guards.rs");
    }

    #[cfg(test)]
    mod socket_gate {
        use super::*;
        include!("socket_gate.rs");
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
    mod ipc_deadline_tests {
        use super::*;
        include!("ipc_deadline_tests.rs");
    }

    #[cfg(test)]
    mod b4 {
        use super::*;
        include!("b4.rs");
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
    mod block_guards {
        use super::*;
        include!("block_guards.rs");
    }

    #[cfg(test)]
    mod file_ops_seam {
        use super::*;
        include!("file_ops_seam.rs");
    }

    #[cfg(test)]
    mod motor_guards {
        use super::*;
        include!("motor_guards.rs");
    }

    #[cfg(test)]
    mod device_guards {
        use super::*;
        include!("device_guards.rs");
    }

    #[cfg(test)]
    mod h3_hosts {
        use super::*;
        include!("h3_hosts.rs");
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
    mod endpoint_close {
        use super::*;
        include!("endpoint_close.rs");
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
    mod image_binding {
        use super::*;
        include!("image_binding.rs");
    }

    #[cfg(test)]

    #[cfg(test)]

    #[cfg(test)]
    mod typed_ipc {
        use super::*;
        include!("typed_ipc.rs");
    }

    #[cfg(test)]
    mod rights {
        use super::*;
        include!("rights.rs");
    }

    #[cfg(test)]
    mod subtree_policy {
        use super::*;
        include!("subtree_policy.rs");
    }

    #[cfg(test)]
    mod pledge {
        use super::*;
        include!("pledge.rs");
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
    mod clock_guards {
        use super::*;
        include!("clock_guards.rs");
    }

    #[cfg(test)]
    mod net_guards {
        use super::*;
        include!("net_guards.rs");
    }

    #[cfg(test)]
    mod display_guards {
        use super::*;
        include!("display_guards.rs");
    }

    #[cfg(test)]
    mod sound_guards {
        use super::*;
        include!("sound_guards.rs");
    }

    #[cfg(test)]
    mod keys_guards {
        use super::*;
        include!("keys_guards.rs");
    }

    #[cfg(test)]
    mod memctl_guards {
        use super::*;
        include!("memctl_guards.rs");
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

    // The native futex calls' edge (`vdso_notify.rs`).
    #[cfg(test)]
    mod futex_calls {
        use super::*;
        include!("futex_calls.rs");
    }

    #[cfg(test)]
    mod irq_route {
        use super::*;
        include!("irq_route.rs");
    }

    // The cold-restart supervisor, and what the driver server
    // holds for a restarted driver.
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

    // Wave 11: `sys_accept` waits on the counter, not on a count
    // of yields.
    #[cfg(test)]
    mod yield_waits {
        use super::*;
        include!("yield_waits.rs");
    }

    // The warrant `SYS_SCHEDCTL` checks (D6 part A).
    #[cfg(test)]
    mod time_guards {
        use super::*;
        include!("time_guards.rs");
    }

    // The `Sensor` interface the kernel hosts (D6 part A).
    #[cfg(test)]
    mod sensor_guards {
        use super::*;
        include!("sensor_guards.rs");
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
