// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! INA219 current/voltage monitor: the chip logic, for either placement.
//!
//! No syscalls and no statics: the bus is a trait and the time is an
//! argument. The ring-3 host (`userspace/drivers/ina_drv`) implements [`Bus`]
//! over `Cap<I2c>`; the in-kernel host (`crates/drivers/sensor/src/ina219/`,
//! feature `ina219-kernel`) over `azos_drv_bus::i2c` directly.
//! `tests/host/drivers-tests` drives it with a fake bus. Each host owns the
//! one instance.
//!
//! I2C address 0x40 (A0 = A1 = GND). Registers: config (0x00), shunt voltage
//! (0x01), bus voltage (0x02), power (0x03), current (0x04), calibration
//! (0x05). All 16-bit big-endian.

/// Default I2C address.
pub const INA219_ADDR: u8 = 0x40;
/// I2C bus the monitor sits on (shared with the ADS1115).
pub const INA219_BUS: u8 = 1;

const REG_CONFIG: u8 = 0x00;
const REG_BUS_VOLTAGE: u8 = 0x02;
const REG_CURRENT: u8 = 0x04;
const REG_CALIBRATION: u8 = 0x05;

/// 32 V range, +-320 mV shunt, 12-bit, continuous.
const CONFIG_DEFAULT: u16 = 0x399F;
/// Cal = 0.04096 / (current_lsb x R_shunt); 100 mOhm shunt, 0.1 mA LSB.
const CALIBRATION: u16 = 4096;

/// Voltage drop between two samples counted as a sag (mV).
pub const VOLTAGE_SAG_THRESHOLD_MV: u16 = 500;
/// Battery nominal capacity (mAh), 2S3P.
pub const BATTERY_NOMINAL_MAH: u32 = 3600;
/// Rate the driver loop samples the chip at. The mAh integration does not
/// assume it: each sample is weighted by the time the driver's clock measured
/// since the previous one ([`Ina219::poll`]).
pub const INA219_POLL_HZ: u32 = 10;

/// Microseconds in an hour: mA x us to mAh.
const US_PER_HOUR: u64 = 3_600_000_000;

/// Failsafe levels, percentage of capacity.
pub const FAILSAFE_WARNING_PCT: u8 = 25;
/// Return-to-launch level (%).
pub const FAILSAFE_RTL_PCT: u8 = 15;
/// Land level (%).
pub const FAILSAFE_LAND_PCT: u8 = 10;
/// Kill level (%).
pub const FAILSAFE_KILL_PCT: u8 = 5;

/// Bytes [`Ina219::read_power`] writes: voltage_mv u16, current_ma u16,
/// mah_used u32, capacity_pct u8, sag u8, failsafe u8, pad u8 (all LE).
pub const POWER_DATA_SIZE: usize = azos_abi::drv_kind::power_op::POWER_DATA_SIZE;

/// The two transfers the chip needs.
pub trait Bus {
    /// Write `data` (register address first). `true` when it was accepted.
    fn write(&mut self, data: &[u8]) -> bool;
    /// Read `buf.len()` bytes from `reg`. `true` only for a whole transfer.
    fn read(&mut self, reg: u8, buf: &mut [u8]) -> bool;
}

/// One monitor's state. `Copy`: the in-kernel host publishes it whole, as
/// a snapshot its readers copy (no lock held across a device access).
#[derive(Clone, Copy)]
pub struct Ina219 {
    initialized: bool,
    voltage_mv: u16,
    current_ma: u16,
    /// Charge since the first sample, in mA x us: each published sample's
    /// current times the time since the previous published sample. Divided
    /// into mAh at read time, because dividing per sample truncates to 0.
    charge_ma_us: u64,
    /// The clock reading (us) of the last published sample; `None` before
    /// the first, which therefore adds no charge.
    last_sample_us: Option<u64>,
    prev_voltage_mv: u16,
    sag: bool,
    sample_count: u32,
    /// Transfers that did not deliver a whole register. With `sample_count`
    /// it says whether the published sample is fresh or only the last one.
    read_failures: u32,
}

impl Ina219 {
    /// Unconfigured.
    pub const fn new() -> Self {
        Ina219 {
            initialized: false,
            voltage_mv: 0,
            current_ma: 0,
            charge_ma_us: 0,
            last_sample_us: None,
            prev_voltage_mv: 0,
            sag: false,
            sample_count: 0,
            read_failures: 0,
        }
    }

    /// Write calibration and configuration. Marks the chip ready only when
    /// both writes were accepted, so a chip that is not there stays
    /// unconfigured and [`Ina219::read_power`] keeps reporting no data.
    pub fn init<B: Bus>(&mut self, bus: &mut B) -> bool {
        let c = CALIBRATION.to_be_bytes();
        let f = CONFIG_DEFAULT.to_be_bytes();
        let ok = bus.write(&[REG_CALIBRATION, c[0], c[1]])
            && bus.write(&[REG_CONFIG, f[0], f[1]]);
        self.initialized = ok;
        ok
    }

    /// Configured?
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Read voltage and current at `now_us` (the driver's monotonic clock),
    /// update the charge and sag detection.
    ///
    /// The charge grows by this sample's current times `now_us` minus the
    /// previous published sample's time: the measured interval, whatever the
    /// loop's cadence was (a late wake-up, a park cut short, failed reads in
    /// between). A clock that went backwards adds nothing.
    ///
    /// Both registers or neither: a failed transfer publishes nothing, does
    /// not advance `sample_count` or the sample time, and counts one failure.
    /// So the next published sample covers the whole gap. Sequential reads,
    /// so a dead bus costs one failed transfer per poll, not two.
    pub fn poll<B: Bus>(&mut self, bus: &mut B, now_us: u64) {
        if !self.initialized {
            return;
        }
        let Some(raw_v) = self.read_register(bus, REG_BUS_VOLTAGE) else { return };
        let Some(raw_i) = self.read_register(bus, REG_CURRENT) else { return };
        // Bus voltage: bits [15:3] x 4 mV.
        let voltage_mv = ((raw_v >> 3) as u32 * 4) as u16;
        // Current in 0.1 mA units (from the calibration).
        let current_ma = raw_i / 10;

        let prev = self.prev_voltage_mv;
        self.sag = prev > 0 && (voltage_mv as u32) + (VOLTAGE_SAG_THRESHOLD_MV as u32) < prev as u32;
        self.prev_voltage_mv = voltage_mv;
        if let Some(prev_us) = self.last_sample_us {
            let dt_us = now_us.saturating_sub(prev_us);
            self.charge_ma_us = self.charge_ma_us.saturating_add((current_ma as u64).saturating_mul(dt_us));
        }
        self.last_sample_us = Some(now_us);
        self.voltage_mv = voltage_mv;
        self.current_ma = current_ma;
        self.sample_count = self.sample_count.wrapping_add(1);
    }

    fn read_register<B: Bus>(&mut self, bus: &mut B, reg: u8) -> Option<u16> {
        let mut buf = [0u8; 2];
        if !bus.read(reg, &mut buf) {
            self.read_failures = self.read_failures.wrapping_add(1);
            return None;
        }
        Some(u16::from_be_bytes(buf))
    }

    /// Samples published.
    pub fn sample_count(&self) -> u32 {
        self.sample_count
    }
    /// Failed register transfers.
    pub fn read_failures(&self) -> u32 {
        self.read_failures
    }
    /// Last published bus voltage (mV).
    pub fn voltage_mv(&self) -> u16 {
        self.voltage_mv
    }
    /// Last published current (mA).
    pub fn current_ma(&self) -> u16 {
        self.current_ma
    }
    /// Charge since the first sample, in mA x us.
    pub fn charge_ma_us(&self) -> u64 {
        self.charge_ma_us
    }
    /// mAh consumed since the first sample.
    pub fn mah_used(&self) -> u32 {
        (self.charge_ma_us / US_PER_HOUR).min(u32::MAX as u64) as u32
    }
    /// Remaining capacity (%).
    pub fn capacity_pct(&self) -> u8 {
        let used = self.mah_used();
        if used >= BATTERY_NOMINAL_MAH {
            return 0;
        }
        (((BATTERY_NOMINAL_MAH - used) * 100) / BATTERY_NOMINAL_MAH) as u8
    }
    /// Last sample was a sag.
    pub fn sag_detected(&self) -> bool {
        self.sag
    }
    /// 0 = OK, 1 = warning, 2 = RTL, 3 = land, 4 = kill.
    pub fn failsafe_level(&self) -> u8 {
        let pct = self.capacity_pct();
        if pct <= FAILSAFE_KILL_PCT { 4 }
        else if pct <= FAILSAFE_LAND_PCT { 3 }
        else if pct <= FAILSAFE_RTL_PCT { 2 }
        else if pct <= FAILSAFE_WARNING_PCT { 1 }
        else { 0 }
    }

    /// The `SENSOR_TYPE_POWER` record, or 0 bytes.
    ///
    /// Refuses while unconfigured: with nothing polled, `mah_used` is 0, so
    /// `capacity_pct` is 100 and `failsafe_level` is 0 -- a full, healthy
    /// battery reported for a chip nobody configured. Zero bytes is the
    /// sensor dispatch's "no data".
    pub fn read_power(&self, buf: &mut [u8]) -> usize {
        if buf.len() < POWER_DATA_SIZE || !self.initialized {
            return 0;
        }
        buf[0..2].copy_from_slice(&self.voltage_mv.to_le_bytes());
        buf[2..4].copy_from_slice(&self.current_ma.to_le_bytes());
        buf[4..8].copy_from_slice(&self.mah_used().to_le_bytes());
        buf[8] = self.capacity_pct();
        buf[9] = self.sag as u8;
        buf[10] = self.failsafe_level();
        buf[11] = 0;
        POWER_DATA_SIZE
    }
}
