// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_ipc`, used only by `tests/host/syscall-tests`.
//!
//! **Real, not stand-ins:** `cap`, `cap_store`, `channel`, `port`, `shm`,
//! `gpio_cap`, `i2c_cap`, `pwm_cap`, `motor_cap` are the actual files from
//! `crates/core/ipc/src`, pulled in with `#[path]` the same way `tests/host/cap-tests`
//! already does for `cap.rs`/`cap_store.rs`. Target 1's `errno_for_*_err`
//! functions are pure matches over the error enums these files define
//! (`ChannelCapError`, `PortCapError`, `ShmCapError`, `GpioCapError`,
//! `I2cCapError`, `PwmCapError`, `MotorCapError`); getting the real enum
//! types means pulling the whole file, so this crate does. Their internal
//! `crate::cap::...` / `crate::cap_store::...` paths resolve correctly
//! because those names are `#[path]`-pulled at this crate's own root, same
//! as `tests/host/cap-tests`.
//!
//! **`io_ring` is pulled too, since 2026-09-03 — the reported blocker was not
//! real.** This doc used to say `io_ring.rs` could not be
//! pulled because its embedded `#[cfg(test)]` module needs
//! `azos_mm::shim_reset` / `shim_free_count` / `shim_pages_in_use` and
//! `azos_sched::shim_set_current`. It does need those — but that module
//! is never compiled here. Cargo passes `--cfg test` only to the crate being
//! tested, never to its dependencies, and `syscall_test_ipc` is a dependency
//! of `azos_syscall_tests`. Pulling the real file changed nothing else:
//! it compiled unmodified on the first try, so `errno_for_ioring_err` is
//! covered like the other seven.
//!
//! **`signal` and `pipe` are still hand-written stand-ins.** Neither the
//! legacy signal syscalls nor `pipe_create` is reached by any test here;
//! every function is `todo!()` rather than a plausible return value, so a
//! future test that does reach one fails loudly instead of quietly observing
//! a fabrication.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `syscall_test_ipc_drivers`.
extern crate syscall_test_ipc_drivers as azos_drv_actuator;
extern crate syscall_test_ipc_drivers as azos_drv_base;
extern crate syscall_test_ipc_drivers as azos_drv_block;
extern crate syscall_test_ipc_drivers as azos_drv_bus;
extern crate syscall_test_ipc_drivers as azos_drv_gpio;
extern crate syscall_test_ipc_drivers as azos_drv_irqchip;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/cap.rs"]
pub mod cap;
// RFC-0055 S5: the authority table `crate::power` asks (dependency-free).
#[path = "../../../../../../crates/core/ipc/src/authority_policy.rs"]
pub mod authority_policy;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/cap_store.rs"]
pub mod cap_store;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/channel.rs"]
pub mod channel;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/port.rs"]
pub mod port;

#[path = "../../../../../../crates/core/ipc/src/port_link.rs"]
pub mod port_link;

// RFC-0040 gap 2. The real module, like every other name here: the authority
// check `SYS_IPC_FAST_CALL_EP` delegates to lives in it, and `unit6_contain`
// asserts that a forged endpoint handle records exactly one denial under
// `CapKind::Endpoint`. A stand-in would assert the stand-in.
#[path = "../../../../../../crates/core/ipc/src/endpoint.rs"]
pub mod endpoint;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/shm.rs"]
pub mod shm;

// Wave 11 (SHMRING): `sys_cap_lookup` translates a kernel-stream key. No
// stream is live on the host, so the key comes back as given — exactly what
// the real `stream_ring::stream_lookup_resource` answers for a stream that is
// not live. A stand-in rather than the file: the real module reaches the
// frame allocator and the drivers crate.
pub mod stream_ring {
    pub fn stream_lookup_resource(resource: u32) -> u32 { resource }
}

// Wave 6: `crate::vdso_notify` names the notify table and its env trait.
#[path = "../../../../../../crates/core/ipc/src/notify.rs"]
pub mod notify;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/gpio_cap.rs"]
pub mod gpio_cap;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/i2c_cap.rs"]
pub mod i2c_cap;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/pwm_cap.rs"]
pub mod pwm_cap;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/motor_cap.rs"]
pub mod motor_cap;

// Real. Needs no driver shim at all — `drvreg_cap.rs` touches only
// `cap_store`, which is why the registry calls live in `crates/core/syscall`
// rather than beside it (see that file's "Why the ops are not here").
#[path = "../../../../../../crates/core/ipc/src/drvreg_cap.rs"]
pub mod drvreg_cap;

// Real, and needs no driver shim: `sensor_cap.rs` touches only `cap_store`.
// The per-type sensor dispatch lives in `handlers.rs`, which this crate
// already includes.
#[path = "../../../../../../crates/core/ipc/src/sensor_cap.rs"]
pub mod sensor_cap;

#[allow(dead_code)]
#[path = "../../../../../../crates/core/ipc/src/io_ring.rs"]
pub mod io_ring;

// `SYS_PORT_BIND_TYPED` (575) stores its binding through the real
// `irq_bind::irq_bind_port`.
#[path = "../../../../../../crates/core/ipc/src/irq_bind.rs"]
pub mod irq_bind;

// The lease calls (112-114, 602, 603). The real
// table, ownership checks, quota and bounded accept wait; its scheduler calls
// resolve to `shims/ipc_sched`, which records the wakes.
#[path = "../../../../../../crates/core/ipc/src/lease.rs"]
pub mod lease;
pub use lease::{lease_return, lease_free};

// `SYS_IRQ_BIND` (510) names these at the crate root, as the kernel's
// `azos_ipc` re-exports them.
pub use irq_bind::{irq_bind, IrqTarget};

// `SYS_MMIO_MAP`'s argument check (RFC-0043), real: `mmio_resolve` and the
// grant rule. It reads the board's region table through
// `azos_drv_base::platform`, which `shims/ipc_drivers` re-exports from
// `shims/drivers` so both sides of the syscall see one table.
#[path = "../../../../../../crates/core/ipc/src/mmio_cap.rs"]
pub mod mmio_cap;

// RFC-0048 P3: the partition-scoped `Cap<Disk>` minter, for `disk_scope.rs`.
#[path = "../../../../../../crates/core/ipc/src/disk_cap.rs"]
pub mod disk_cap;

// Wave 10: the directory-tree `Cap<File>` the tree-modifying calls check.
#[path = "../../../../../../crates/core/ipc/src/file_cap.rs"]
pub mod file_cap;

// RFC-0055 (wave 11): the launch grant `SYS_SPAWN_EX` checks.
#[path = "../../../../../../crates/core/ipc/src/launch_cap.rs"]
pub mod launch_cap;

pub use channel::{channel_create, channel_send, channel_recv, channel_destroy};

// ── Hand-written stand-ins (see module doc) ────────────────────────────────

pub const SIGALRM: u32 = 14;

pub fn signal_send(_tid: u32, _signum: u32) -> i32 {
    todo!("signal stand-in: not reached by any test in this crate")
}
/// `todo!()` unless a test programmed it with [`shim_set_signal_pending`];
/// programmed, it answers that pending set (`sys_pause`'s wait reads it).
pub fn signal_pending() -> u32 {
    match *SIGNAL_PENDING.lock().unwrap_or_else(|e| e.into_inner()) {
        Some(p) => p,
        None => todo!("signal stand-in: not reached by any test in this crate"),
    }
}

static SIGNAL_PENDING: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(None);

/// Test-only control surface: what [`signal_pending`] answers (`None`: back
/// to `todo!()`).
pub fn shim_set_signal_pending(p: Option<u32>) {
    *SIGNAL_PENDING.lock().unwrap_or_else(|e| e.into_inner()) = p;
}
pub fn signal_set_handler(_signum: u32, _handler: usize) -> usize {
    todo!("signal stand-in: not reached by any test in this crate")
}
pub fn signal_get_mask() -> u32 {
    todo!("signal stand-in: not reached by any test in this crate")
}
pub fn signal_set_mask(_mask: u32) -> i32 {
    todo!("signal stand-in: not reached by any test in this crate")
}
pub fn pipe_create() -> Option<(usize, usize)> {
    todo!("pipe stand-in: not reached by any test in this crate")
}

// ── Hand-written stand-in: trace ring (V1.8) ───────────────────────────────
//
// The real `trace_event` (`crates/core/ipc/src/trace.rs`) reads
// `azos_arch::cpu::hart_id()` and `azos_drv_sys::timebase::now()`;
// the former resolves to nothing on this host target at all
// (`crates/core/arch/src/lib.rs`'s own `target_os = "none"` guard — see that
// file's doc for why calling the real thing here would either fail to link
// or execute a privileged instruction). This records category and the four
// data words only, in call order, which is exactly what
// `handlers::seccomp_deny_kill`'s host test needs: that the record exists
// and precedes the kill. It claims nothing about timestamps or hart IDs.
pub const TRACE_SYSCALL: u8 = 3;

static TRACE_EVENTS: std::sync::Mutex<Vec<(u8, u32, u32, u32, u32)>> =
    std::sync::Mutex::new(Vec::new());

pub fn trace_event(category: u8, d0: u32, d1: u32, d2: u32, d3: u32) {
    TRACE_EVENTS.lock().unwrap_or_else(|e| e.into_inner()).push((category, d0, d1, d2, d3));
}

/// Test-only control surface: every trace event recorded since the last call.
pub fn shim_take_trace_events() -> Vec<(u8, u32, u32, u32, u32)> {
    std::mem::take(&mut *TRACE_EVENTS.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Stand-in for `azos_ipc::trace_dump` (`SYS_TRACE_DUMP`, 518): the real
/// one prints the ring through the UART. Records the count it was asked for.
pub fn trace_dump(last_n: usize) {
    TRACE_DUMPS.lock().unwrap_or_else(|e| e.into_inner()).push(last_n);
}

static TRACE_DUMPS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// Test-only control surface: every count `trace_dump` was called with since
/// the last call.
pub fn shim_take_trace_dumps() -> Vec<usize> {
    std::mem::take(&mut *TRACE_DUMPS.lock().unwrap_or_else(|e| e.into_inner()))
}
