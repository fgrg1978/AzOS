// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the driver class crates (`azos_drv_*`), reduced to the handful of
//! functions/constants `crates/core/ipc/src/{gpio_cap,i2c_cap,pwm_cap,motor_cap}.rs`
//! reference.
//!
//! **WHY this exists.** The real `azos_drv_*` is RV64-only (its
//! `azos_arch` MMIO/CSR chain), so it cannot be built for the host. But
//! `tests/host/topology-tests` needs `gpio_cap.rs`/`i2c_cap.rs`/`pwm_cap.rs`/
//! `motor_cap.rs` to compile in order to test the P1 topology→cap_store
//! bridge (`crates/core/ipc/src/cap_seed.rs`) end to end — the bridge's job is
//! `CapSpec.target` string → `resource` id → minted `Cap<T>`, and the only
//! way to prove that without reimplementing the minters is to compile the
//! real ones. This crate is bookkeeping stubs, not a device model: the
//! bridge tests only exercise the `*_grant_cap` minting path (a
//! `cap_store::grant` call plus, for gpio/pwm, a bounds check against the
//! constants below); the read/write/actuation wrappers in those files are
//! compiled for completeness but never called from here — that behaviour
//! is covered on real hardware / QEMU, not by this suite.

pub mod gpio {
    pub const GPIO_MAX_PINS: usize = 64;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum GpioDir {
        Input,
        Output,
    }

    pub fn gpio_read(_pin: u32) -> i32 {
        0
    }

    pub fn gpio_write(_pin: u32, _val: u32) -> i32 {
        0
    }

    pub fn gpio_set_direction(_pin: u32, _dir: GpioDir) -> i32 {
        0
    }
}

pub mod pwm {
    pub const PWM_MAX_CHANNELS: usize = 8;

    pub fn pwm_enable(_ch: u32) -> i32 {
        0
    }

    pub fn pwm_disable(_ch: u32) -> i32 {
        0
    }

    pub fn pwm_set_period(_ch: u32, _period_ns: u32) -> i32 {
        0
    }

    pub fn pwm_set_duty(_ch: u32, _duty_ns: u32) -> i32 {
        0
    }

    pub fn pwm_set_duty_pct(_ch: u32, _pct: u32) -> i32 {
        0
    }
}

pub mod i2c {
    pub fn i2c_read(_bus: u8, _addr: u8, _reg: u8, buf: &mut [u8]) -> i32 {
        buf.len() as i32
    }

    pub fn i2c_write(_bus: u8, _addr: u8, _data: &[u8]) -> i32 {
        0
    }

    pub fn i2c_detect(_bus: u8, _addr: u8) -> bool {
        false
    }
}

pub mod motor_pid {
    pub fn motor_pid_set_target(_speed_l: i16, _speed_r: i16) {}

    pub fn motor_pid_tick(_ticks_l: i64, _ticks_r: i64, _now: u64) -> (i32, i32) {
        (0, 0)
    }

    pub fn motor_pid_enable(_en: bool) {}

    pub fn motor_pid_enabled() -> bool {
        false
    }

    pub fn motor_pid_set_gains(_kp: i32, _ki: i32, _kd: i32) {}

    pub fn motor_pid_reset() {}
}

/// The PWM instance's channel grouping — the REAL module, not a stub.
///
/// `pwm_cap` bounds a grant by `PWM_DOMAIN.channels` rather than by the
/// simulator's array size: the JH7110 has four channels and the simulator
/// eight, so a shim answering 8 would let this suite bless a capability the
/// board cannot back.
#[path = "../../../../../../crates/drivers/actuator/src/pwm_domain.rs"]
pub mod pwm_domain;

/// The board's MMIO region table and its lookups — the REAL module, not a
/// stub. `mmio_cap` mints and resolves against it, and `mmio_table_tests`
/// asserts its invariants on the constants the kernel maps from. It is
/// constants and two `const fn`s, so nothing in it needs a device.
#[path = "../../../../../../crates/drivers/base/src/platform.rs"]
pub mod platform;

/// PLIC line bound for the host `irq_bind` stand-in (QEMU virt has 96 real
/// sources; the kernel constant is the same order of magnitude).
pub mod plic {
    pub const MAX_IRQS: u32 = 1024;
}

/// The partition table parser and the published table `Cap<Disk>` is scoped
/// by (RFC-0048 P3) — the REAL module: it names only `core`.
#[path = "../../../../../../crates/drivers/block/src/partition.rs"]
pub mod partition;
