// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The driver registry smoke `kernel_main` runs on every boot, after the
//! secondaries are woken: five drivers registered (UART, GPIO, I2C, PWM, the
//! motor PID), and a write through `dyn Driver` found by kind.

use crate::*;

/// The registry smoke (see the module doc). Inlined, as every boot phase (see
/// `boot`'s module doc).
#[inline(always)]
pub(crate) fn driver_registry_smoke() {
    // AZOS Phase 1 A4 — registry smoke. Register the static
    // UartDriver into the driver registry, then look it up by kind
    // and drive a write through `dyn Driver`. Proves the full
    // path (api → registry → lookup → trait dispatch →
    // hardware) end-to-end. Stays InKernel + isolated to this
    // smoke; the legacy `kprint!` macros are unchanged.
    // Trait methods on `&dyn Driver` are accessible through the
    // return type itself — no explicit `use` needed.
    static UART_DRV: azos_drv_sys::uart_driver::UartDriver =
        azos_drv_sys::uart_driver::UartDriver::new();
    // The guard ends with the statement: no print under the registry lock.
    let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&UART_DRV);
    match reg {
        Ok(()) => kprintln!("[REG]  UART registered into driver registry"),
        Err(e) => azos_drv_sys::kerr!("[REG]  UART register FAILED: {:?}", e),
    }
    let probe = azos_drv_base::runtime::registry::REGISTRY
        .lock()
        .find_by_kind(/*DRV_KIND_UART*/ 0x0004);
    if let Some(drv) = probe {
        let _ = drv.init();
        let msg = b"[REG]  dyn Driver write via registry OK\n";
        match drv.handle_request(
            azos_drv_sys::uart_driver::UART_OP_WRITE,
            msg,
            &mut [],
        ) {
            Ok(_) => {} // bytes already printed by the driver
            Err(e) => azos_drv_sys::kerr!("[REG]  dyn Driver write FAILED: {:?}", e),
        }
    } else {
        kprintln!("[REG]  find_by_kind(UART) returned None");
    }

    // A3a.2 — register the second concrete `Driver` impl.
    // Validates that the trait + registry handle two unrelated
    // hardware families side by side (different DRV_KIND_*).
    static GPIO_DRV: azos_drv_gpio::gpio_driver::GpioDriver =
        azos_drv_gpio::gpio_driver::GpioDriver::new();
    let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&GPIO_DRV);
    match reg {
        Ok(()) => kprintln!("[REG]  GPIO registered into driver registry"),
        Err(e) => azos_drv_sys::kerr!("[REG]  GPIO register FAILED: {:?}", e),
    }

    // A3a.3 — register the third concrete `Driver` impl.
    // Bus-oriented family; proves the trait scales across
    // hardware models (char / pin / bus).
    static I2C_DRV: azos_drv_bus::i2c_driver::I2cDriver =
        azos_drv_bus::i2c_driver::I2cDriver::new();
    let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&I2C_DRV);
    match reg {
        Ok(()) => kprintln!("[REG]  I2C  registered into driver registry"),
        Err(e) => azos_drv_sys::kerr!("[REG]  I2C  register FAILED: {:?}", e),
    }

    // A3a.4 — fourth: multi-parameter actuator (PWM).
    static PWM_DRV: azos_drv_actuator::pwm_driver::PwmDriver =
        azos_drv_actuator::pwm_driver::PwmDriver::new();
    let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&PWM_DRV);
    match reg {
        Ok(()) => kprintln!("[REG]  PWM  registered into driver registry"),
        Err(e) => azos_drv_sys::kerr!("[REG]  PWM  register FAILED: {:?}", e),
    }

    // A3a.5 — fifth: closed-loop controller (motor PID).
    // Pure software (no MMIO) — composes PWM + encoders.
    static MOTOR_DRV: azos_drv_actuator::motor_driver::MotorPidDriver =
        azos_drv_actuator::motor_driver::MotorPidDriver::new();
    let reg = azos_drv_base::runtime::registry::REGISTRY.lock().register(&MOTOR_DRV);
    match reg {
        Ok(()) => kprintln!("[REG]  MTR  registered into driver registry"),
        Err(e) => azos_drv_sys::kerr!("[REG]  MTR  register FAILED: {:?}", e),
    }
}
