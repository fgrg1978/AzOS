// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Gpio`, `I2c` and `Pwm` interfaces the kernel hosts: one pin, one device
//! on a bus, one PWM channel, each the badge of the endpoint capability a
//! topology row grants (`endpoint = "gpio.20"`, `"i2c.0.0x68"`, `"pwm.4"`).
//!
//! Each op makes the same three checks, in this order, before it touches a
//! driver: the op class the capability carries (`READ` observes, `WRITE`
//! acts; containment refuses the acting class), the resource the badge names
//! (a pin or a channel the board has), and, for the acting ops, that the
//! resource is not one a motor drives. The motor's H-bridge is reachable only
//! through the `Motor` interface, whose path runs the e-stop latch and the
//! actuation envelope: a duty or a direction pin written below it would
//! bypass both. The drivers run with NO capability-table lock held (the
//! caller's rights were read before the op; a driver transfer under the table's
//! preemption-disabling lock would nest the driver's own).

use azos_abi::cap::CapPerms;
use azos_devif::i2c::{self, Bytes};
use azos_devif::{outcome, Out};

use crate::handlers::{gpio_pin_is_motor_bound, pwm_channel_is_motor_bound, pwm_control_reaches_a_motor};
use crate::khost::Caller;

/// The `Gpio` interface served for one caller.
pub struct GpioServer(pub Caller);

impl GpioServer {
    /// The pin, if the board has it.
    fn pin(&self) -> Result<u32, u32> {
        let pin = self.0.badge;
        if (pin as usize) < azos_drv_gpio::gpio::GPIO_MAX_PINS {
            Ok(pin)
        } else {
            Err(outcome::BAD_ARGUMENT)
        }
    }
}

impl azos_devif::Gpio for GpioServer {
    fn read(&self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        let pin = match self.pin() {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        let v = azos_drv_gpio::gpio::gpio_read(pin);
        if v < 0 {
            Out::err(outcome::FAULT)
        } else {
            Out::ok(v as u32)
        }
    }

    fn write(&mut self, level: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let pin = match self.pin() {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        if gpio_pin_is_motor_bound(pin) {
            return Out::err(outcome::REFUSED);
        }
        if azos_drv_gpio::gpio::gpio_write(pin, level & 1) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }

    fn set_dir(&mut self, dir: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let pin = match self.pin() {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        if gpio_pin_is_motor_bound(pin) {
            return Out::err(outcome::REFUSED);
        }
        let dir = match dir {
            azos_devif::gpio::DIR_INPUT => azos_drv_gpio::gpio::GpioDir::Input,
            azos_devif::gpio::DIR_OUTPUT => azos_drv_gpio::gpio::GpioDir::Output,
            _ => return Out::err(outcome::BAD_ARGUMENT),
        };
        if azos_drv_gpio::gpio::gpio_set_direction(pin, dir) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }
}

/// The `I2c` interface served for one caller.
pub struct I2cServer(pub Caller);

impl azos_devif::I2c for I2cServer {
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        if let Err(o) = self.0.gate::<Bytes>(CapPerms::READ) {
            return o;
        }
        let len = len as usize;
        if reg > 0xFF || len == 0 || len > i2c::MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let (bus, addr) = i2c::unbadge(self.0.badge);
        let mut buf = [0u8; i2c::MAX_BYTES];
        let n = azos_drv_bus::i2c::i2c_read(bus, addr, reg as u8, &mut buf[..len]);
        if n < 0 {
            return Out::err(outcome::FAULT);
        }
        Out::ok(Bytes::from_slice(&buf[..(n as usize).min(len)]))
    }

    fn write(&mut self, data: Bytes) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let n = data.n as usize;
        if n == 0 || n > i2c::MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let (bus, addr) = i2c::unbadge(self.0.badge);
        let mut buf = [0u8; i2c::MAX_BYTES];
        data.copy_to(&mut buf);
        if azos_drv_bus::i2c::i2c_write(bus, addr, &buf[..n]) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }

    fn detect(&mut self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        let (bus, addr) = i2c::unbadge(self.0.badge);
        Out::ok(u32::from(azos_drv_bus::i2c::i2c_detect(bus, addr)))
    }
}

/// What a PWM op reaches, declared by the op: the same declaration the typed
/// calls made, for the same reason (only the op knows).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Writes the control register, which on a part with a shared one reaches
    /// every channel of the instance: enable, disable, set period.
    Control,
    /// Writes this channel's own compare register: duty only.
    DutyOnly,
}

/// The `Pwm` interface served for one caller.
pub struct PwmServer(pub Caller);

impl PwmServer {
    fn run(&self, reach: Reach, op: impl FnOnce(u32) -> i32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let domain = azos_drv_actuator::pwm_domain::PWM_DOMAIN;
        let ch = self.0.badge;
        if ch >= domain.channels {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        // Control ops are refused by REACH, duty by the named channel: a duty
        // write reaches only what it names, a control write reaches every
        // channel of a shared-control part.
        let blocked = match reach {
            Reach::Control => pwm_control_reaches_a_motor(domain, ch),
            Reach::DutyOnly => pwm_channel_is_motor_bound(ch),
        };
        if blocked {
            return Out::err(outcome::REFUSED);
        }
        if op(ch) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }
}

impl azos_devif::Pwm for PwmServer {
    fn enable(&mut self) -> Out<()> {
        self.run(Reach::Control, azos_drv_actuator::pwm::pwm_enable)
    }
    fn disable(&mut self) -> Out<()> {
        self.run(Reach::Control, azos_drv_actuator::pwm::pwm_disable)
    }
    fn set_period(&mut self, ns: u32) -> Out<()> {
        self.run(Reach::Control, |ch| azos_drv_actuator::pwm::pwm_set_period(ch, ns))
    }
    fn set_duty(&mut self, ns: u32) -> Out<()> {
        self.run(Reach::DutyOnly, |ch| azos_drv_actuator::pwm::pwm_set_duty(ch, ns))
    }
    fn set_duty_pct(&mut self, pct: u32) -> Out<()> {
        self.run(Reach::DutyOnly, |ch| azos_drv_actuator::pwm::pwm_set_duty_pct(ch, pct))
    }
}
