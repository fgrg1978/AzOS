// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// ADS1115 — 16-bit 4-channel I2C ADC driver (Texas Instruments).
///
/// Supports single-ended reads on channels 0-3, configurable gain (PGA)
/// and sample rate.  Default: single-shot mode, gain 4.096 V, 128 SPS.
///
/// QEMU: uses simulated I2C bus (register-level emulation).
/// VF2:  real I2C hardware via DesignWare APB I2C.

use azos_drv_bus::i2c::{i2c_read, i2c_write};
use azos_sync::SpinLock;
use azos_sync::waitqueue::WaitQueue;
use core::sync::atomic::{AtomicU32, Ordering};

// ── I2C addresses (active-low ADDR pin wiring) ─────────────────────────────

/// ADDR pin connected to GND
pub const ADS1115_ADDR_GND: u8 = 0x48;
/// ADDR pin connected to VDD
pub const ADS1115_ADDR_VDD: u8 = 0x49;
/// ADDR pin connected to SDA
pub const ADS1115_ADDR_SDA: u8 = 0x4A;
/// ADDR pin connected to SCL
pub const ADS1115_ADDR_SCL: u8 = 0x4B;

// ── Register pointers ──────────────────────────────────────────────────────

/// Conversion result register (read-only, 16-bit signed)
pub const REG_CONVERSION: u8 = 0x00;
/// Configuration register (read/write, 16-bit)
pub const REG_CONFIG:     u8 = 0x01;
/// Low threshold for comparator
pub const REG_LO_THRESH:  u8 = 0x02;
/// High threshold for comparator
pub const REG_HI_THRESH:  u8 = 0x03;

// ── Config register bit fields ─────────────────────────────────────────────

// Operational status / single-shot start (bit 15)
/// Start a single conversion (write) / conversion ready (read)
const CONFIG_OS_START: u16 = 1 << 15;

// MUX: input multiplexer (bits 14:12) — single-ended readings
/// AIN0 vs GND
const MUX_SINGLE_0: u16 = 0b100 << 12;
/// AIN1 vs GND
const MUX_SINGLE_1: u16 = 0b101 << 12;
/// AIN2 vs GND
const MUX_SINGLE_2: u16 = 0b110 << 12;
/// AIN3 vs GND
const MUX_SINGLE_3: u16 = 0b111 << 12;

// PGA: programmable gain amplifier (bits 11:9)
/// FSR = +/- 6.144 V  (LSB = 187.5 uV)
pub const GAIN_6_144V: u16 = 0b000 << 9;
/// FSR = +/- 4.096 V  (LSB = 125.0 uV)
pub const GAIN_4_096V: u16 = 0b001 << 9;
/// FSR = +/- 2.048 V  (LSB = 62.5 uV) — default
pub const GAIN_2_048V: u16 = 0b010 << 9;
/// FSR = +/- 1.024 V  (LSB = 31.25 uV)
pub const GAIN_1_024V: u16 = 0b011 << 9;
/// FSR = +/- 0.512 V  (LSB = 15.625 uV)
pub const GAIN_0_512V: u16 = 0b100 << 9;
/// FSR = +/- 0.256 V  (LSB = 7.8125 uV)
pub const GAIN_0_256V: u16 = 0b101 << 9;

const GAIN_SHIFT: u16 = 9;
const GAIN_MASK:  u16 = 0b111 << 9;

// Mode (bit 8)
/// Single-shot mode (power down after conversion)
const MODE_SINGLE: u16 = 1 << 8;

// Data rate (bits 7:5)
/// 8 SPS
pub const RATE_8:   u16 = 0b000 << 5;
/// 16 SPS
pub const RATE_16:  u16 = 0b001 << 5;
/// 32 SPS
pub const RATE_32:  u16 = 0b010 << 5;
/// 64 SPS
pub const RATE_64:  u16 = 0b011 << 5;
/// 128 SPS (default)
pub const RATE_128: u16 = 0b100 << 5;
/// 250 SPS
pub const RATE_250: u16 = 0b101 << 5;
/// 475 SPS
pub const RATE_475: u16 = 0b110 << 5;
/// 860 SPS
pub const RATE_860: u16 = 0b111 << 5;

const RATE_MASK: u16 = 0b111 << 5;

// Comparator (bits 4:0) — disabled by default
/// Disable comparator (default, ALERT/RDY pin high-Z)
const COMP_DISABLE: u16 = 0b11 << 0;  // COMP_QUE = 11 (disabled)

// ── Full-scale range in microvolts (for millivolt conversion) ──────────────

/// FSR in microvolts, indexed by PGA bits (0..=5)
const FSR_UV: [i32; 6] = [
    6_144_000,  // GAIN_6_144V
    4_096_000,  // GAIN_4_096V
    2_048_000,  // GAIN_2_048V
    1_024_000,  // GAIN_1_024V
      512_000,  // GAIN_0_512V
      256_000,  // GAIN_0_256V
];

/// Full 16-bit ADC range (signed: -32768..+32767)
const ADC_MAX: i32 = 32767;

// ── Timing constants ───────────────────────────────────────────────────────

/// The blocking read's bound on config-register polls (each one locked I2C
/// read) while a conversion runs: at 8 SPS a conversion takes 125 ms.
/// Kconfig `ADS1115_CONVERSION_POLL_ITERS` (default 150000).
const CONVERSION_POLL_ITERS: u32 = azos_limits::ADS1115_CONVERSION_POLL_ITERS as u32;

// ── Driver state ───────────────────────────────────────────────────────────

struct Ads1115State {
    bus:         u8,
    addr:        u8,
    gain:        u16,
    rate:        u16,
    initialized: bool,
    /// S2: the channel of the single-shot conversion the last queued unit
    /// started and no unit has consumed or replaced since, or `None`.
    inflight:    Option<u8>,
}

impl Ads1115State {
    const fn new() -> Self {
        Ads1115State {
            bus:         0,
            addr:        ADS1115_ADDR_GND,
            gain:        GAIN_4_096V,
            rate:        RATE_128,
            initialized: false,
            inflight:    None,
        }
    }

    /// Build the config word for a single-ended read of `channel`.
    fn config_word(&self, channel: u8) -> u16 {
        let mux = match channel {
            0 => MUX_SINGLE_0,
            1 => MUX_SINGLE_1,
            2 => MUX_SINGLE_2,
            3 => MUX_SINGLE_3,
            _ => MUX_SINGLE_0,
        };
        CONFIG_OS_START | mux | self.gain | MODE_SINGLE | self.rate | COMP_DISABLE
    }

    /// Extract PGA index (0..5) from current gain setting.
    fn pga_index(&self) -> usize {
        ((self.gain >> GAIN_SHIFT) & 0b111) as usize
    }
}

/// The device's settings and the conversion in flight. Held only to copy
/// them in and out of a unit, never across a bus transaction.
static ADC: SpinLock<Ads1115State> = SpinLock::new(Ads1115State::new());

/// The device's transaction queue: every bus access to the chip is one UNIT
/// (select a channel, start its single-shot conversion, read a result) and
/// the units run whole, one at a time, in the order they were queued (a
/// ticket per unit, FIFO: a caller that queued first is never overtaken, so
/// the 10 Hz battery pipeline cannot starve a SYS_SENSOR read, nor the
/// reverse). A waiter sleeps on `wq` (no priority inheritance: a blocking
/// unit waits on the bus; no real-time task reads the ADC).
struct UnitQueue {
    next: AtomicU32,
    serving: AtomicU32,
    wq: WaitQueue,
}

static QUEUE: UnitQueue = UnitQueue { next: AtomicU32::new(0), serving: AtomicU32::new(0), wq: WaitQueue::new() };

impl UnitQueue {
    fn enter(&self) {
        let t = self.next.fetch_add(1, Ordering::SeqCst);
        while self.serving.load(Ordering::SeqCst) != t {
            self.wq.wait_if(|| self.serving.load(Ordering::SeqCst) != t);
        }
    }
    fn leave(&self) {
        self.serving.fetch_add(1, Ordering::SeqCst);
        self.wq.wake_all();
    }
}

/// The MUX field of the config register.
const MUX_MASK: u16 = 0b111 << 12;

fn mux_of(channel: u8) -> u16 {
    match channel {
        1 => MUX_SINGLE_1,
        2 => MUX_SINGLE_2,
        3 => MUX_SINGLE_3,
        _ => MUX_SINGLE_0,
    }
}

/// One queued unit, its channel recorded in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unit {
    /// Select + start + wait for the conversion + read it.
    Blocking(u8),
    /// Read the conversion the previous unit of this channel started (if it
    /// is still the one in flight and done), then select + start the next.
    Pipelined(u8),
}

/// A result is published only when the chip's own config readback (taken
/// with the ready bit, inside the unit) names the unit's channel: a
/// conversion of another channel is never reported as this one.
fn checked(channel: u8, cfg_readback: u16, v: Option<u16>) -> Option<i16> {
    if cfg_readback & MUX_MASK == mux_of(channel) { v.map(|v| v as i16) } else { None }
}

/// Run one unit against `st`, a copy of the device state (its turn in the
/// queue taken).
fn run_unit(st: &mut Ads1115State, unit: Unit) -> Option<i16> {
    let (bus, addr) = (st.bus, st.addr);
    match unit {
        Unit::Blocking(ch) => {
            // This conversion replaces any one a pipelined unit started.
            st.inflight = None;
            if !write_reg(bus, addr, REG_CONFIG, st.config_word(ch)) {
                return None;
            }
            for _ in 0..CONVERSION_POLL_ITERS {
                if let Some(cfg) = read_reg(bus, addr, REG_CONFIG) {
                    if cfg & CONFIG_OS_START != 0 {
                        return checked(ch, cfg, read_reg(bus, addr, REG_CONVERSION));
                    }
                }
            }
            None
        }
        Unit::Pipelined(ch) => {
            let mut out = None;
            if st.inflight.take() == Some(ch) {
                if let Some(cfg) = read_reg(bus, addr, REG_CONFIG) {
                    if cfg & CONFIG_OS_START != 0 {
                        out = checked(ch, cfg, read_reg(bus, addr, REG_CONVERSION));
                    }
                }
            }
            if write_reg(bus, addr, REG_CONFIG, st.config_word(ch)) {
                st.inflight = Some(ch);
            }
            out
        }
    }
}

/// Queue `unit` on the device, run it in its turn, publish its result.
/// `None` before `ads1115_init`.
fn submit(unit: Unit) -> Option<i16> {
    // Gate canary: the unit runs outside the queue (the shape before it):
    // another caller's unit can land between this one's ready check and
    // its result read.
    let queued = !cfg!(feature = "ads1115-queue-canary");
    if queued {
        QUEUE.enter();
    }
    let mut st = { let g = ADC.lock(); Ads1115State { ..*g } };
    let out = if st.initialized {
        let out = run_unit(&mut st, unit);
        ADC.lock().inflight = st.inflight;
        out
    } else {
        None
    };
    if queued {
        QUEUE.leave();
    }
    out
}

// ── I2C helpers ────────────────────────────────────────────────────────────

/// Write a 16-bit value to an ADS1115 register.
fn write_reg(bus: u8, addr: u8, reg: u8, val: u16) -> bool {
    let data: [u8; 3] = [reg, (val >> 8) as u8, val as u8];
    i2c_write(bus, addr, &data) == 0
}

/// Read a 16-bit value from an ADS1115 register.
fn read_reg(bus: u8, addr: u8, reg: u8) -> Option<u16> {
    let mut buf = [0u8; 2];
    if i2c_read(bus, addr, reg, &mut buf) == 2 {
        Some(((buf[0] as u16) << 8) | buf[1] as u16)
    } else {
        None
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Initialize the ADS1115 on the given I2C bus and address.
pub fn ads1115_init(i2c_bus: u8, addr: u8) {
    let mut state = ADC.lock();
    state.bus = i2c_bus;
    state.addr = addr;
    state.gain = GAIN_4_096V;
    state.rate = RATE_128;
    state.initialized = true;
    state.inflight = None;
}

/// Read the raw 16-bit signed ADC value from a single-ended channel (0-3):
/// one blocking unit on the device queue.
pub fn ads1115_read_raw(channel: u8) -> Option<i16> {
    if channel > 3 { return None; }
    submit(Unit::Blocking(channel))
}

/// S2: the pipelined read of `channel`, for a caller that samples it
/// periodically (`sensor_slow_task`, 10 Hz): one unit on the device queue
/// that takes the result of the conversion the previous unit of this
/// channel started, then starts the next. Never polls: at most three I2C
/// transactions (ready bit and MUX, result, next start) instead of the
/// blocking read's start-then-poll loop of up to [`CONVERSION_POLL_ITERS`]
/// reads. The value is one call period older (the conversion takes
/// 1.2-125 ms by rate). `None`: no conversion of this channel in flight
/// (the first call, a channel switch, a blocking unit in between), not done
/// yet, the chip's MUX not this channel's, or the bus failed; the caller's
/// "0 = no reading" stays honest. Never another channel's value.
pub fn ads1115_read_raw_pipelined(channel: u8) -> Option<i16> {
    if channel > 3 { return None; }
    if cfg!(feature = "ads1115-pipeline-canary") {
        // Gate canary: the blocking start-and-poll read this replaced.
        return ads1115_read_raw(channel);
    }
    submit(Unit::Pipelined(channel))
}

/// Raw counts to millivolts at the current gain.
fn raw_to_mv(raw: i16) -> Option<i32> {
    let pga_idx = {
        let state = ADC.lock();
        state.pga_index()
    };
    if pga_idx >= FSR_UV.len() { return None; }
    let fsr_uv = FSR_UV[pga_idx];
    // mv = raw * (FSR_uV / ADC_MAX) / 1000
    // To avoid overflow: (raw * fsr_uv) / ADC_MAX / 1000
    let uv = (raw as i64 * fsr_uv as i64) / ADC_MAX as i64;
    Some((uv / 1000) as i32)
}

/// Read ADC channel and convert to millivolts using current gain setting.
pub fn ads1115_read_mv(channel: u8) -> Option<i32> {
    raw_to_mv(ads1115_read_raw(channel)?)
}

/// Set the PGA gain.  Use one of the `GAIN_*` constants.
pub fn ads1115_set_gain(gain: u16) {
    let mut state = ADC.lock();
    state.gain = gain & GAIN_MASK;
}

/// Set the sample rate.  Use one of the `RATE_*` constants.
pub fn ads1115_set_rate(rate: u16) {
    let mut state = ADC.lock();
    state.rate = rate & RATE_MASK;
}

/// Read battery voltage through a resistor divider.
///
/// `divider_ratio` is the integer ratio (e.g., 2 for a 1:1 divider that halves Vbat).
/// Returns battery voltage in millivolts.
///
/// Kconfig `ADS1115_PIPELINE` (S2): through [`ads1115_read_raw_pipelined`],
/// one call period older and never polling; off, the blocking read.
pub fn ads1115_read_battery_mv(channel: u8, divider_ratio: u32) -> Option<u32> {
    let mv = if azos_limits::ADS1115_PIPELINE {
        raw_to_mv(ads1115_read_raw_pipelined(channel)?)?
    } else {
        ads1115_read_mv(channel)?
    };
    if mv < 0 { return None; }
    Some(mv as u32 * divider_ratio)
}

/// Check whether the ADC has been initialized.
pub fn ads1115_is_initialized() -> bool {
    ADC.lock().initialized
}
