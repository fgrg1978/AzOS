// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// U05-4 (2026-09-26): same class as `gpio.rs`/`pwm.rs` — a `k1` build fell
// through to the QEMU sim below while `i2c_driver.rs`/`platform::hw`
// advertise real K1 I2C MMIO (`spacemit,k1-i2c`, see `platform.rs`).
// `rc.rs`'s compile-time refusal, applied here per U05-4/§5 Q2 [rec].
// Placed before the module doc for the same `unused_doc_comments` reason
// as `gpio.rs`.
#[cfg(feature = "k1")]
compile_error!(
    "crates/drivers/bus/src/i2c.rs: no real K1 I2C driver exists yet — a `k1` \
     build must not silently drive the QEMU simulation while advertising \
     real MMIO. See U05-4."
);

/// I2C driver — port of kernel/drivers/i2c.c + kernel/include/i2c.h
///
/// QEMU: in-memory simulation with fake IMU + barometer.
/// VF2:  DesignWare APB I2C — real MMIO transactions.
pub const I2C_MAX_DEVICES: usize = 16;
pub const I2C_BUS_COUNT:   usize = 4;

/// Which serialisation slot guards `bus`, or `None` if `bus` has no slot.
///
/// # Why this is a function and not an array index at the call site
///
/// `IC_TAR` (offset 0x04) is *bus* state, not transaction state: it names the
/// slave the controller will talk to on its next transfer. Every entry point
/// in the DesignWare path writes `IC_TAR` and then transfers, so two tasks on
/// one bus can interleave as {A writes TAR=IMU}{B writes TAR=BARO}{A
/// transfers} and A silently reads B's device. Nothing in the hardware or the
/// driver reports that; the read simply returns the wrong sensor's bytes.
/// The bring-up plan puts an MPU-6050 and a BMP280 on the same bus, so the
/// two devices that would collide are the two that exist.
///
/// The exclusion therefore has to be **per bus**: two controllers share no
/// `IC_TAR` and serialising them against each other would cost throughput for
/// nothing.
///
/// Kept as a top-level pure function, outside both `cfg` modules, for the
/// same reason `pwm_domain` and `drv_resource` are separate: the MMIO module
/// it serves is `#[cfg(feature = "vf2")]` and names `azos_drv_base::platform::hw`, so
/// a host test cannot compile it, while this mapping is plain arithmetic that
/// `tests/host/drivers-tests` can pull in and check.
///
/// # Contract
///
/// * Distinct buses map to distinct slots — a shared slot would merge two
///   independent controllers into one lock.
/// * Every returned slot is `< I2C_BUS_COUNT`, so it indexes the lock array
///   in bounds. Callers still use `.get()`, so a future change to this
///   function cannot turn into a panic on the sensor path.
/// * `None` for a bus with no slot. This says nothing about whether the bus
///   has *hardware*: `dw_i2c::bus_base` remains the only authority on that,
///   and every caller resolves the base first. Duplicating the hardware map
///   here would create a second truth that could drift.
#[inline]
pub fn i2c_bus_lock_slot(bus: u8) -> Option<usize> {
    let slot = bus as usize;
    if slot < I2C_BUS_COUNT { Some(slot) } else { None }
}


/// The locks themselves, MOVED OUT of `mod dw_i2c` on 2026-09-08 for exactly
/// the reason [`i2c_bus_lock_slot`] above is out here: that module is
/// `#[cfg(feature = "vf2")]` and names MMIO, so a host test cannot compile it
/// — and while the array sat inside it, **nothing tested the exclusion**, only
/// the arithmetic that picks a slot. A mapping test passes just as happily on
/// an array of one lock aliased across every bus.
///
/// The array is plain `SpinLock`s with no MMIO in them, so out here
/// `tests/host/drivers-tests` can hold them under real thread contention.
/// One lock per bus. See [`i2c_bus_lock_slot`] for what it protects
/// and why the granularity is the bus.
///
/// # Why `SpinLock`, and why `PiMutex` was rejected
///
/// `PiMutex` is the better fit on latency and was the first choice, but it
/// cannot be taken here **because its acquire path yields**
/// (`crates/core/sync/src/pi_mutex.rs:234`), and one caller reaches this code
/// holding a `SpinLock`:
///
/// ```text
/// sys_i2c_read_typed / _write_typed / _detect_typed
///   -> cap_store::with_table            (holds CAP_TABLES[i].lock(),
///                                        crates/core/ipc/src/cap_store.rs:210)
///     -> i2c_cap::i2c_read_cap          (crates/core/ipc/src/i2c_cap.rs:82)
///       -> i2c_read                     (here)
/// ```
///
/// Preempt depth is per **hart**, not per task (`crates/core/sync/src/preempt.rs:73`
/// — one `PreemptSlot` per hart), so yielding while a `SpinLockGuard` is
/// live hands the incoming task a hart with preemption already disabled.
/// It then runs un-preemptible on borrowed depth until the outgoing task
/// is scheduled again to drop its guard — and if it spins on any lock that
/// task holds, neither can progress. That is the K-C29 shape, and routing
/// an I2C transfer through a yielding lock would re-create it from a new
/// direction. The tree's own rule is visible at
/// `crates/core/sync/src/waitqueue.rs:110`, which drops the preempt guard
/// *before* blocking for exactly this reason; `PiMutex` has no equivalent
/// precaution, so it is only safe to take with preemption enabled.
///
/// `SpinLock` does not yield, so it introduces no such window.
///
/// # What `SpinLock` costs here, stated rather than hidden
///
/// `SpinLock::lock()` opens a critical section before it spins
/// (`crates/core/sync/src/spinlock.rs:64`) and the guard carries the
/// `PreemptGuard` (`:162`) — K-C29 step 2, already landed. So the holder
/// cannot be evicted by the tick, and **preemption is disabled for the
/// whole transfer**. That window is long: `wait_tfne` polls up to 100_000
/// times and the read collect loop up to 1_000_000, both bare volatile
/// `IC_STATUS` reads, over a 100 kHz bus where a 14-byte IMU read is
/// ~1.35 ms of wire time. On a wedged or absent device it is the full
/// timeout. This is a real cost to the RT band and it is the reason to
/// prefer `PiMutex` once the call site above no longer holds a lock across
/// the transfer.
///
/// Note that the typed syscall path *already* pays this today: `with_table`
/// holds a `SpinLock` across the whole transfer, so preemption is already
/// off for its duration. What this change adds is the same window on the
/// paths that do not go through a cap table (`imu_task`, `sensor_ahrs_task`,
/// the shell).
///
/// # Why this cannot deadlock
///
/// * Same hart: the holder runs with preemption off and no interrupt
///   handler reaches this code (callers are `imu_task`, `sensor_ahrs_task`,
///   the shell and the syscall handlers — no trap handler, and no `*_panic`
///   helper, unlike `gpio`/`pwm`/`esc`), so nothing else on this hart can
///   re-enter and contend. `lock_irqsave` would therefore buy nothing.
/// * Cross hart: a waiter spins only for the length of the holder's
///   transfer, which is bounded by the two loop counts above, and the
///   holder cannot be descheduled. So the holder always reaches release.
/// * Recursion is the one way to hang this, and it is avoided by
///   construction: `i2c_scan` deliberately does **not** take the lock,
///   because it calls `i2c_detect`, which does.
pub static I2C_BUS_LOCKS: [azos_sync::SpinLock<()>; I2C_BUS_COUNT] =
    [const { azos_sync::SpinLock::new(()) }; I2C_BUS_COUNT];

#[derive(Clone, Copy)]
pub struct I2cDevice {
    pub bus:     u8,
    pub addr:    u8,
    pub present: bool,
    pub regs:    [u8; 256],
}

impl I2cDevice {
    pub const fn new() -> Self {
        I2cDevice { bus: 0, addr: 0, present: false, regs: [0u8; 256] }
    }
}

// ── QEMU: in-memory simulation ────────────────────────────────────────────────

#[cfg(not(feature = "vf2"))]
mod sim {
    use super::*;
    use azos_sync::SpinLock;

    struct I2cState {
        devices: [I2cDevice; I2C_MAX_DEVICES],
        count:   usize,
    }

    impl I2cState {
        const fn new() -> Self {
            I2cState { devices: [I2cDevice::new(); I2C_MAX_DEVICES], count: 0 }
        }

        fn find(&self, bus: u8, addr: u8) -> Option<usize> {
            for i in 0..self.count {
                if self.devices[i].bus == bus && self.devices[i].addr == addr {
                    return Some(i);
                }
            }
            None
        }
    }

    /// One lock for every simulated bus, unlike the `vf2` path's per-bus
    /// locks. This is not an oversight and not the same trade-off: the
    /// simulation has no `IC_TAR`, so it has no bus state to corrupt, and its
    /// whole "transfer" is a bounded memcpy inside one `SpinLock` — there is
    /// no window between addressing and transferring for a second caller to
    /// land in. Splitting this per bus would be unsound as written, because
    /// `devices` is one shared array indexed across buses.
    static I2C: SpinLock<I2cState> = SpinLock::new(I2cState::new());

    pub fn i2c_init() {
        let mut state = I2C.lock();
        // Simulated IMU (MPU-6050) at bus 0, address 0x68
        if state.count < I2C_MAX_DEVICES {
            let i = state.count;
            state.devices[i].bus     = 0;
            state.devices[i].addr    = 0x68;
            state.devices[i].present = true;
            state.devices[i].regs[0x75] = 0x68; // WHO_AM_I
            // Phase E2: populate simulated accel/gyro/temp data registers.
            // Simulates the sensor sitting flat: accel = (0, 0, +1g), gyro = 0, temp ≈ 25 °C.
            // Format: big-endian i16, starting at register 0x3B (14 bytes).
            // Accel X = 0
            state.devices[i].regs[0x3B] = 0x00;
            state.devices[i].regs[0x3C] = 0x00;
            // Accel Y = 0
            state.devices[i].regs[0x3D] = 0x00;
            state.devices[i].regs[0x3E] = 0x00;
            // Accel Z = +16384 (= +1g at ±2g range)
            state.devices[i].regs[0x3F] = 0x40; // 16384 >> 8
            state.devices[i].regs[0x40] = 0x00; // 16384 & 0xFF
            // Temp raw = -2198 → (−2198/340)+36.53 ≈ 30.07 °C
            // Use raw = 0 → 0/340 + 36.53 = 36.53 °C (room temp sim)
            state.devices[i].regs[0x41] = 0x00;
            state.devices[i].regs[0x42] = 0x00;
            // Gyro X = 0
            state.devices[i].regs[0x43] = 0x00;
            state.devices[i].regs[0x44] = 0x00;
            // Gyro Y = 0
            state.devices[i].regs[0x45] = 0x00;
            state.devices[i].regs[0x46] = 0x00;
            // Gyro Z = 0
            state.devices[i].regs[0x47] = 0x00;
            state.devices[i].regs[0x48] = 0x00;
            state.count += 1;
        }
        // Simulated barometer (BMP280) at bus 0, address 0x76
        if state.count < I2C_MAX_DEVICES {
            let i = state.count;
            state.devices[i].bus     = 0;
            state.devices[i].addr    = 0x76;
            state.devices[i].present = true;
            state.devices[i].regs[0xD0] = 0x58; // chip_id (BMP280)
            // Phase G1: populate simulated calibration + measurement data.
            // Calibration registers 0x88-0xA1 (26 bytes) — realistic trimming values.
            // dig_T1=27504 dig_T2=26435 dig_T3=-1000
            state.devices[i].regs[0x88] = 0x70; state.devices[i].regs[0x89] = 0x6B; // dig_T1 LE
            state.devices[i].regs[0x8A] = 0x43; state.devices[i].regs[0x8B] = 0x67; // dig_T2 LE
            state.devices[i].regs[0x8C] = 0x18; state.devices[i].regs[0x8D] = 0xFC; // dig_T3 LE
            // dig_P1=36477 dig_P2=-10685 dig_P3=3024 dig_P4=2855
            state.devices[i].regs[0x8E] = 0x7D; state.devices[i].regs[0x8F] = 0x8E; // dig_P1
            state.devices[i].regs[0x90] = 0x43; state.devices[i].regs[0x91] = 0xD6; // dig_P2
            state.devices[i].regs[0x92] = 0xD0; state.devices[i].regs[0x93] = 0x0B; // dig_P3
            state.devices[i].regs[0x94] = 0x27; state.devices[i].regs[0x95] = 0x0B; // dig_P4
            // dig_P5=140 dig_P6=-7 dig_P7=15500 dig_P8=-14600 dig_P9=6000
            state.devices[i].regs[0x96] = 0x8C; state.devices[i].regs[0x97] = 0x00; // dig_P5
            state.devices[i].regs[0x98] = 0xF9; state.devices[i].regs[0x99] = 0xFF; // dig_P6
            state.devices[i].regs[0x9A] = 0x8C; state.devices[i].regs[0x9B] = 0x3C; // dig_P7
            state.devices[i].regs[0x9C] = 0xF8; state.devices[i].regs[0x9D] = 0xC6; // dig_P8
            state.devices[i].regs[0x9E] = 0x70; state.devices[i].regs[0x9F] = 0x17; // dig_P9
            // Measurement registers 0xF7-0xFC (6 bytes).
            // Simulates ~25 C, ~101325 Pa (sea level standard).
            // adc_t = 519888 (0x7EED0) → temp raw: MSB=0x7E LSB=0xED XLSB=0x00
            state.devices[i].regs[0xFA] = 0x7E; // temp MSB
            state.devices[i].regs[0xFB] = 0xED; // temp LSB
            state.devices[i].regs[0xFC] = 0x00; // temp XLSB
            // adc_p = 415148 (0x6572C) → press raw: MSB=0x65 LSB=0x72 XLSB=0xC0
            state.devices[i].regs[0xF7] = 0x65; // press MSB
            state.devices[i].regs[0xF8] = 0x72; // press LSB
            state.devices[i].regs[0xF9] = 0xC0; // press XLSB
            state.count += 1;
        }
        // Simulated INA219 power monitor at bus 1, address 0x40. Listed here
        // so detect and scan see it; its registers are 16-bit and live in
        // `ina219_sim`, not in `regs` (see there).
        if state.count < I2C_MAX_DEVICES {
            let i = state.count;
            state.devices[i].bus     = ina219_sim::BUS;
            state.devices[i].addr    = ina219_sim::ADDR;
            state.devices[i].present = true;
            state.count += 1;
        }
    }

    /// The INA219 model behind bus 1 / 0x40.
    ///
    /// Its own model, not the byte array the other devices use: every INA219
    /// register is 16 bits at its own pointer, so a two-byte read of the
    /// current register (0x04) must not return the high byte of the
    /// calibration register (0x05), which a flat byte array would.
    ///
    /// Fixed readings: 7400 mV on the bus, 1500 mA. The current register reads
    /// 0 until a non-zero calibration is written, as on the chip, so a driver
    /// that never configured it reads no current.
    pub mod ina219_sim {
        use azos_sync::SpinLock;

        /// Bus of the simulated monitor.
        pub const BUS: u8 = 1;
        /// Address of the simulated monitor.
        pub const ADDR: u8 = 0x40;
        /// Bus voltage register for 7400 mV: (7400 / 4) << 3.
        pub const BUS_VOLTAGE_RAW: u16 = (7400 / 4) << 3;
        /// Current register for 1500 mA at the 0.1 mA LSB calibration 4096 sets.
        pub const CURRENT_RAW: u16 = 15_000;

        const REG_BUS_VOLTAGE: u8 = 0x02;
        const REG_CURRENT: u8 = 0x04;
        const REG_CALIBRATION: u8 = 0x05;

        /// config, shunt, bus, power, current, calibration.
        static REGS: SpinLock<[u16; 6]> = SpinLock::new([0x399F, 0, 0, 0, 0, 0]);

        /// Is `(bus, addr)` this device?
        pub fn is(bus: u8, addr: u8) -> bool {
            bus == BUS && addr == ADDR
        }

        /// `[reg, hi, lo]`. Only config and calibration are writable.
        pub fn write(data: &[u8]) -> i32 {
            if data.len() != 3 { return -1; }
            let v = u16::from_be_bytes([data[1], data[2]]);
            match data[0] {
                0x00 | REG_CALIBRATION => { REGS.lock()[data[0] as usize] = v; 0 }
                _ => -1,
            }
        }

        /// One register, big-endian, two bytes.
        pub fn read(reg: u8, buf: &mut [u8]) -> i32 {
            if buf.len() != 2 || reg as usize >= 6 { return -1; }
            let regs = REGS.lock();
            let v = match reg {
                REG_BUS_VOLTAGE => BUS_VOLTAGE_RAW,
                REG_CURRENT if regs[REG_CALIBRATION as usize] != 0 => CURRENT_RAW,
                REG_CURRENT => 0,
                r => regs[r as usize],
            };
            buf.copy_from_slice(&v.to_be_bytes());
            2
        }
    }

    pub fn i2c_write(bus: u8, addr: u8, data: &[u8]) -> i32 {
        if data.is_empty() { return -1; }
        if ina219_sim::is(bus, addr) && i2c_detect(bus, addr) {
            return ina219_sim::write(data);
        }
        let mut state = I2C.lock();
        match state.find(bus, addr) {
            Some(i) => {
                let reg = data[0] as usize;
                for (j, &b) in data[1..].iter().enumerate() {
                    if reg + j < 256 { state.devices[i].regs[reg + j] = b; }
                }
                0
            }
            None => -1,
        }
    }

    pub fn i2c_read(bus: u8, addr: u8, reg: u8, buf: &mut [u8]) -> i32 {
        if ina219_sim::is(bus, addr) && i2c_detect(bus, addr) {
            return ina219_sim::read(reg, buf);
        }
        let state = I2C.lock();
        match state.find(bus, addr) {
            Some(i) => {
                for (j, b) in buf.iter_mut().enumerate() {
                    *b = state.devices[i].regs[(reg as usize + j) & 0xFF];
                }
                buf.len() as i32
            }
            None => -1,
        }
    }

    pub fn i2c_detect(bus: u8, addr: u8) -> bool {
        I2C.lock().find(bus, addr).is_some()
    }

    pub fn i2c_scan(bus: u8) {
        let state = I2C.lock();
        azos_drv_sys::kconsoleln!("[I2C] Scanning bus {}:", bus);
        azos_drv_sys::kconsoleln!("[I2C]      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
        for row in 0..8u8 {
            azos_drv_sys::kconsole!("[I2C] {:02x}: ", row * 16);
            for col in 0..16u8 {
                let addr = row * 16 + col;
                if addr < 8 || addr > 0x77 { azos_drv_sys::kconsole!("   "); }
                else {
                    let found = state.devices[..state.count].iter()
                        .any(|d| d.bus == bus && d.addr == addr && d.present);
                    if found { azos_drv_sys::kconsole!("{:02x} ", addr); }
                    else     { azos_drv_sys::kconsole!("-- "); }
                }
            }
            azos_drv_sys::kconsoleln!();
        }
    }

    pub fn i2c_info() {
        let state = I2C.lock();
        azos_drv_sys::kconsoleln!("[I2C] {} device(s) registered (simulated)", state.count);
        for i in 0..state.count {
            let d = &state.devices[i];
            azos_drv_sys::kconsoleln!("[I2C]   bus={} addr=0x{:02x} present={}", d.bus, d.addr, d.present);
        }
    }
}

#[cfg(not(feature = "vf2"))]
pub use sim::*;

// ── VisionFive 2 / JH7110: DesignWare APB I2C ────────────────────────────────
//
// JH7110 has 6 I2C controllers (i2c0..i2c5, `snps,designware-i2c`).
// We expose I2C0 (0x1003_0000, `i2c0@10030000`) and I2C1 (0x1004_0000,
// `i2c1@10040000`) mapped to bus 0 and 1 — **corrected 2026-09-26 (U05-1)**:
// this comment used to say 0x10010000/0x10020000, which are `uart1`/`uart2`
// per mainline `jh7110.dtsi`; `platform::hw::I2C1_BASE` itself was wrong the
// same way (see that file) and is now fixed to match this comment.
//
// DesignWare APB I2C register map (well-documented, used in Linux dwi2c driver):
//   0x00 IC_CON         — control: master/slave, speed (0=std, 1=fast)
//   0x04 IC_TAR         — 7-bit target address
//   0x10 IC_DATA_CMD    — data + read/write command (bit 8: 1=read, 0=write)
//   0x14 IC_SS_SCL_HCNT — standard speed SCL high count
//   0x18 IC_SS_SCL_LCNT — standard speed SCL low count
//   0x1C IC_FS_SCL_HCNT — fast speed SCL high count
//   0x20 IC_FS_SCL_LCNT — fast speed SCL low count
//   0x3C IC_INTR_STAT   — interrupt status
//   0x6C IC_ENABLE      — 1=enable controller
//   0x70 IC_STATUS      — bit 1: master active, bit 3: TXFIFO not full, bit 6: SDA stalled
//   0x74 IC_TXFLR       — TX FIFO level
//   0x78 IC_RXFLR       — RX FIFO level
//   0x80 IC_CLR_INTR    — clear all interrupts (read)
//   0xA0 IC_COMP_PARAM_1 — parameters
//
// SCL freq = IC_CLK / (HCNT + LCNT + 8)
// At IC_CLK=100 MHz, 100 kHz std-mode: HCNT=487, LCNT=512 (typical Linux values).

#[cfg(feature = "vf2")]
mod dw_i2c {
    use azos_drv_base::platform::hw::{I2C0_BASE, I2C1_BASE};
    use super::{i2c_bus_lock_slot, I2C_BUS_COUNT, I2C_BUS_LOCKS};


    // Register offsets
    const IC_CON:        usize = 0x00;
    const IC_TAR:        usize = 0x04;
    const IC_DATA_CMD:   usize = 0x10;
    const IC_SS_SCL_HCNT: usize = 0x14;
    const IC_SS_SCL_LCNT: usize = 0x18;
    const IC_ENABLE:     usize = 0x6C;
    const IC_STATUS:     usize = 0x70;
    #[allow(dead_code)]
    const IC_RXFLR:      usize = 0x78;
    const IC_CLR_INTR:   usize = 0x80;

    // IC_CON bits
    const CON_MASTER:    u32 = 1 << 0;
    const CON_SPEED_STD: u32 = 1 << 1;
    const CON_10BIT_OFF: u32 = 0;       // 7-bit addressing
    const CON_RESTART:   u32 = 1 << 5;
    const CON_SLAVE_DIS: u32 = 1 << 6;

    // IC_STATUS bits
    const STATUS_TFNF: u32 = 1 << 1;   // TX FIFO not full — safe to push IC_DATA_CMD
    const STATUS_RFNE: u32 = 1 << 3;   // RX FIFO not empty
    const STATUS_TFE:  u32 = 1 << 2;   // TX FIFO empty (transfer done)
    const STATUS_MA:   u32 = 1 << 5;   // master activity

    // IC_DATA_CMD bits
    const CMD_READ: u32 = 1 << 8;
    const CMD_STOP: u32 = 1 << 9;

    fn bus_base(bus: u8) -> Option<usize> {
        match bus {
            0 => Some(I2C0_BASE),
            1 => Some(I2C1_BASE),
            _ => None,
        }
    }

    #[inline(always)]
    fn rd(base: usize, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((base + off) as *const u32) }
    }

    #[inline(always)]
    fn wr(base: usize, off: usize, val: u32) {
        unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) }
    }

    fn wait_tfne(base: usize) -> bool {
        // Wait for TX FIFO empty (transfer complete), with timeout.
        for _ in 0..100_000u32 {
            if rd(base, IC_STATUS) & STATUS_TFE != 0
                && rd(base, IC_STATUS) & STATUS_MA == 0 {
                return true;
            }
        }
        false
    }

    /// U05-6 fix: a DW I2C silently DROPS a write to a full TX FIFO — there
    /// is no queueing behind the wire. Every `wr(base, IC_DATA_CMD, ..)`
    /// below used to fire back-to-back with no `IC_STATUS.TFNF` check, so a
    /// transfer longer than the FIFO (e.g. the 26-byte BMP280 calibration
    /// read the `sim` path seeds — `i2c.rs`'s QEMU module) came back short
    /// and silent. Bounded at 10_000 iterations — the FIFO drains at the
    /// bus clock rate (~100 kHz here), so a real slot opens in far fewer
    /// polls than that; hitting the bound means the bus is stuck, not that
    /// the wait was too short.
    fn wait_tfnf(base: usize) -> bool {
        for _ in 0..10_000u32 {
            if rd(base, IC_STATUS) & STATUS_TFNF != 0 {
                return true;
            }
        }
        false
    }

    fn init_bus(base: usize) {
        // Disable controller before programming
        wr(base, IC_ENABLE, 0);
        // Master mode, standard speed (100 kHz), 7-bit, disable slave
        wr(base, IC_CON, CON_MASTER | CON_SPEED_STD | CON_10BIT_OFF | CON_RESTART | CON_SLAVE_DIS);
        // SCL timing for 100 kHz at 100 MHz IC_CLK: HCNT=487, LCNT=512
        wr(base, IC_SS_SCL_HCNT, 487);
        wr(base, IC_SS_SCL_LCNT, 512);
        // Re-enable
        wr(base, IC_ENABLE, 1);
        // Clear any pending interrupts
        let _ = rd(base, IC_CLR_INTR);
    }

    pub fn i2c_init() {
        // Under the bus lock like every other entry point: `init_bus` writes
        // `IC_ENABLE = 0`, which would abort a transfer in flight. Boot runs
        // this before any sensor task exists, so it is uncontended today; the
        // lock is what keeps that true if it is ever re-run to recover a bus.
        // Driven by bus id rather than by base address so `bus_base` stays the
        // one place that says which controllers exist.
        for bus in 0..I2C_BUS_COUNT {
            let bus = bus as u8;
            let Some(base) = bus_base(bus) else { continue };
            let Some(slot) = i2c_bus_lock_slot(bus) else { continue };
            let Some(m) = I2C_BUS_LOCKS.get(slot) else { continue };
            let _bus_guard = m.lock();
            init_bus(base);
        }
    }

    pub fn i2c_write(bus: u8, addr: u8, data: &[u8]) -> i32 {
        if data.is_empty() { return -1; }
        let base = match bus_base(bus) { Some(b) => b, None => return -1 };
        // Held across {write IC_TAR .. transfer complete}: that whole span is
        // one transaction against shared bus state, not just the TAR write.
        let slot = match i2c_bus_lock_slot(bus) { Some(s) => s, None => return -1 };
        let _bus_guard = match I2C_BUS_LOCKS.get(slot) { Some(m) => m.lock(), None => return -1 };
        wr(base, IC_TAR, addr as u32);
        wr(base, IC_ENABLE, 1);
        for (i, &b) in data.iter().enumerate() {
            let stop = if i + 1 == data.len() { CMD_STOP } else { 0 };
            if !wait_tfnf(base) { return -1; }
            wr(base, IC_DATA_CMD, b as u32 | stop);
        }
        if !wait_tfne(base) { return -1; }
        0
    }

    pub fn i2c_read(bus: u8, addr: u8, reg: u8, buf: &mut [u8]) -> i32 {
        if buf.is_empty() { return -1; }
        let base = match bus_base(bus) { Some(b) => b, None => return -1 };
        // Held across {write IC_TAR, write reg, issue reads, drain RX FIFO}.
        // Releasing after the address write would leave exactly the race this
        // exists to close, with the read half unprotected.
        let slot = match i2c_bus_lock_slot(bus) { Some(s) => s, None => return -1 };
        let _bus_guard = match I2C_BUS_LOCKS.get(slot) { Some(m) => m.lock(), None => return -1 };
        // Write register address
        wr(base, IC_TAR, addr as u32);
        wr(base, IC_ENABLE, 1);
        if !wait_tfnf(base) { return -1; }
        wr(base, IC_DATA_CMD, reg as u32); // write register address
        // Issue read commands
        for i in 0..buf.len() {
            let stop = if i + 1 == buf.len() { CMD_STOP } else { 0 };
            if !wait_tfnf(base) { return -1; }
            wr(base, IC_DATA_CMD, CMD_READ | stop);
        }
        // Collect received bytes
        let mut received = 0usize;
        for _ in 0..1_000_000u32 {
            if rd(base, IC_STATUS) & STATUS_RFNE != 0 {
                buf[received] = (rd(base, IC_DATA_CMD) & 0xFF) as u8;
                received += 1;
                if received == buf.len() { break; }
            }
        }
        // A SHORT READ IS A FAILURE, NOT A COUNT.
        //
        // This used to `return received as i32` unconditionally. When the
        // device never answered, the poll loop above ran out and `received`
        // was 0 — so the function returned **0**, which every caller that
        // tests `n < 0` reads as success over a buffer it never wrote. A dead
        // sensor became a reading of zero: `ina219` publishing 0 V,
        // `i2c_read_cap` handing ring 3 `Ok(0)`, `i2c_driver` `Ok(0)`. A
        // partial read was worse, because it looked like a positive result.
        //
        // Callers that already compared against the expected length
        // (`baro`: `< 26`, `< 6`; `ads1115`: `== 2`; `imu`: `< 14`) were
        // right, and this makes the ones that did not right as well. Nothing
        // asks for a zero-length read — `buf.is_empty()` is refused at the
        // top — so no legitimate call loses a result.
        if received != buf.len() { return -1; }
        received as i32
    }

    pub fn i2c_detect(bus: u8, addr: u8) -> bool {
        // Send a 0-byte write and check for ACK (quick-write probe)
        let base = match bus_base(bus) { Some(b) => b, None => return false };
        // Probing writes IC_TAR too, so it races the sensor tasks exactly as
        // the transfer paths do. `i2c_scan` calls this in a loop and must NOT
        // hold the lock itself: `SpinLock` is not recursive, so a scan holding
        // it would deadlock hard on the first probe.
        let slot = match i2c_bus_lock_slot(bus) { Some(s) => s, None => return false };
        let _bus_guard = match I2C_BUS_LOCKS.get(slot) { Some(m) => m.lock(), None => return false };
        wr(base, IC_TAR, addr as u32);
        wr(base, IC_ENABLE, 1);
        wr(base, IC_DATA_CMD, CMD_STOP); // zero-length write → address-only
        wait_tfne(base)
    }

    /// Deliberately takes no lock: each `i2c_detect` below is individually
    /// atomic, which is the property that matters, and a scan interleaved with
    /// a sensor read between probes reports the same result. Wrapping the loop
    /// would re-enter the bus's `SpinLock`, which is not recursive — an
    /// immediate hard deadlock on the first probe, with preemption already off.
    pub fn i2c_scan(bus: u8) {
        azos_drv_sys::kconsoleln!("[I2C] Scanning bus {} (JH7110 DW-I2C):", bus);
        azos_drv_sys::kconsoleln!("[I2C]      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
        for row in 0..8u8 {
            azos_drv_sys::kconsole!("[I2C] {:02x}: ", row * 16);
            for col in 0..16u8 {
                let a = row * 16 + col;
                if a < 8 || a > 0x77 { azos_drv_sys::kconsole!("   "); }
                else if i2c_detect(bus, a) { azos_drv_sys::kconsole!("{:02x} ", a); }
                else                       { azos_drv_sys::kconsole!("-- "); }
            }
            azos_drv_sys::kconsoleln!();
        }
    }

    pub fn i2c_info() {
        azos_drv_sys::kconsoleln!("[I2C] JH7110 DesignWare APB I2C");
        azos_drv_sys::kconsoleln!("[I2C]   I2C0 @ {:#010x}", I2C0_BASE);
        azos_drv_sys::kconsoleln!("[I2C]   I2C1 @ {:#010x}", I2C1_BASE);
    }
}

#[cfg(feature = "vf2")]
pub use dw_i2c::*;
