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
/// `PiMutex` was the first choice, but its acquire path yields
/// (`crates/core/sync/src/pi_mutex.rs:234`), and the lock is taken inside a
/// controller step that may run with preemption already off (a caller under
/// a `SpinLock`, early boot). Until wave 15 the typed syscall path called
/// the transfer inside `cap_store::with_table` (the table's `SpinLock`); it
/// now resolves the capability there and transfers after releasing it
/// (`i2c_cap::I2cAccess`).
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
/// `PreemptGuard` (`:162`), so preemption is off while it is held. Since
/// wave 15 (S1) it is held only for ONE service step of `crate::i2c_txn`
/// (`dw_i2c::step`): the register accesses that move the FIFOs, bounded by
/// the FIFO depth, never a wait on the wire. Before, it was held for the
/// whole transfer polling `IC_STATUS` (~1.35 ms for the IMU's 14 bytes at
/// 100 kHz, the full poll bound on a wedged device). Synchronous callers
/// sleep between steps; the typed syscall path resolves the capability
/// under the table lock and transfers after releasing it.
///
/// # Why this cannot deadlock
///
/// * Same hart: the holder runs with preemption off and no interrupt
///   handler reaches this code (callers are `imu_task`, `sensor_ahrs_task`,
///   the shell and the syscall handlers — no trap handler, and no `*_panic`
///   helper, unlike `gpio`/`pwm`/`esc`), so nothing else on this hart can
///   re-enter and contend. `lock_irqsave` would therefore buy nothing.
/// * Cross hart: a waiter spins only for the length of the holder's
///   step, which is bounded by the FIFO depth, and the holder cannot be
///   descheduled. So the holder always reaches release.
/// * Recursion is the one way to hang this, and it is avoided by
///   construction: `i2c_scan` deliberately does **not** take the lock,
///   because it calls `i2c_detect`, which does.
pub static I2C_BUS_LOCKS: [azos_sync::SpinLock<()>; I2C_BUS_COUNT] =
    [const { azos_sync::SpinLock::new(()) }; I2C_BUS_COUNT];

// ── Queued transactions (wave 15, IO-QUEUES-AUDIT S1) ─────────────────────────
//
// A caller that may not wait for the wire (the real-time `imu` task) queues a
// transaction with `i2c_submit_read` and collects it later with `i2c_take`;
// `crate::i2c_txn` is the queue and the DesignWare state machine. On the
// VisionFive 2 the `i2c-svc` task (or the controller's interrupt, once its
// line is wired) runs `i2c_service`, one bounded step at a time; the QEMU
// simulation transfers at submit. The synchronous entry points below stay
// for callers that hold a lock across the transfer (the capability-table
// syscall path), and wait for a queued transaction on their bus to finish
// before they touch `IC_TAR`.

/// Kconfig `I2C_TXN_QUEUE_DEPTH`: transactions queued per bus, and
/// completions kept per bus.
pub const I2C_TXN_QUEUE_DEPTH: usize = azos_limits::I2C_TXN_QUEUE_DEPTH as usize;

/// Kconfig `I2C_DW_RX_FIFO_DEPTH`: the DesignWare controller's RX FIFO
/// depth; reads in flight never exceed it.
pub const I2C_DW_RX_FIFO_DEPTH: usize = azos_limits::I2C_DW_RX_FIFO_DEPTH as usize;

/// One transaction queue and state machine per bus (`i2c_bus_lock_slot`).
pub static I2C_QUEUES: [azos_sync::SpinLock<crate::i2c_txn::I2cBus<I2C_TXN_QUEUE_DEPTH>>; I2C_BUS_COUNT] =
    [const { azos_sync::SpinLock::new(crate::i2c_txn::I2cBus::new(I2C_DW_RX_FIFO_DEPTH)) }; I2C_BUS_COUNT];

/// The finished transaction `ticket` on `bus`, if it has finished: its
/// bytes, whether every byte moved, and the clock value of the step that
/// finished it. Never waits.
pub fn i2c_take(bus: u8, ticket: u32) -> Option<crate::i2c_txn::Completion> {
    let slot = i2c_bus_lock_slot(bus)?;
    I2C_QUEUES.get(slot)?.lock().take(ticket)
}

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

    /// Queue a read of `len` bytes from register `reg` of `addr` (see the
    /// queued-transaction section above). The simulation has no wire: the
    /// transfer runs here and the completion is stamped `now`. `None` when
    /// the queue refuses (full, or a length above `TXN_RD_MAX`).
    pub fn i2c_submit_read(bus: u8, addr: u8, reg: u8, len: usize, now: u64) -> Option<u32> {
        if len == 0 || len > crate::i2c_txn::TXN_RD_MAX {
            return None;
        }
        let slot = i2c_bus_lock_slot(bus)?;
        let q = I2C_QUEUES.get(slot)?;
        let ticket = q.lock().alloc_ticket();
        let mut buf = [0u8; crate::i2c_txn::TXN_RD_MAX];
        let ok = i2c_read(bus, addr, reg, &mut buf[..len]) == len as i32;
        q.lock().complete_now(ticket, ok, &buf[..len], now);
        Some(ticket)
    }

    /// Nothing to step: the simulation completes at submit.
    pub fn i2c_service(_bus: u8, _now: u64) -> bool {
        false
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
    use super::{i2c_bus_lock_slot, I2C_BUS_COUNT, I2C_BUS_LOCKS, I2C_QUEUES};
    use core::sync::atomic::{AtomicUsize, Ordering};


    // Register offsets
    const IC_CON:        usize = 0x00;
    const IC_SS_SCL_HCNT: usize = 0x14;
    const IC_SS_SCL_LCNT: usize = 0x18;
    const IC_ENABLE:     usize = 0x6C;
    // 0x40 in the DW_apb_i2c databook; this read 0x80 (IC_TX_ABRT_SOURCE,
    // which clears nothing) before wave 15. Board validation pending.
    const IC_CLR_INTR:   usize = 0x40;

    // IC_CON bits
    const CON_MASTER:    u32 = 1 << 0;
    const CON_SPEED_STD: u32 = 1 << 1;
    const CON_10BIT_OFF: u32 = 0;       // 7-bit addressing
    const CON_RESTART:   u32 = 1 << 5;
    const CON_SLAVE_DIS: u32 = 1 << 6;

    // The transfer registers and bits (IC_TAR, IC_DATA_CMD, IC_STATUS, the
    // interrupt registers) are `crate::i2c_txn`'s: every transfer, queued
    // or synchronous, runs through its state machine.

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

    /// A synchronous transfer (wave 15, S1): the transaction goes on the
    /// bus queue like a queued one, on the caller's own buffers, and the
    /// caller waits for its completion SLEEPING between service steps
    /// (`set_sleep_hook`). Preemption is off only inside each step (the bus
    /// lock: a few register accesses, bounded by the FIFO depth), never
    /// across wire time. A context that may not sleep (before the
    /// scheduler, under a spinlock, in an interrupt) steps without sleeping
    /// in between: still no lock held across the wire. A timeout
    /// (`I2C_XFER_TIMEOUT_US`) ends the transaction as failed.
    fn transfer(bus: u8, addr: u8, wr: &[u8], rd: &mut [u8]) -> Option<crate::i2c_txn::Completion> {
        let base = bus_base(bus)?;
        let slot = i2c_bus_lock_slot(bus)?;
        let q = I2C_QUEUES.get(slot)?;
        let ticket = loop {
            // SAFETY: `wr` and `rd` outlive the wait below, which returns
            // only with this ticket's completion (a timeout finishes it).
            let r = unsafe { q.lock().submit_ext(addr, wr.as_ptr(), wr.len(), rd.as_mut_ptr(), rd.len()) };
            match r {
                Ok(t) => break t,
                Err(crate::i2c_txn::SubmitError::Full) => {
                    // The queue drains by the steps; this caller runs them too.
                    let _ = step(base, slot);
                    if !sleep_between_steps() { core::hint::spin_loop(); }
                }
                Err(_) => return None,
            }
        };
        Some(crate::i2c_txn::wait_completion(
            || {
                let _ = step(base, slot);
                q.lock().take(ticket)
            },
            sleep_between_steps,
        ))
    }

    pub fn i2c_write(bus: u8, addr: u8, data: &[u8]) -> i32 {
        if data.is_empty() { return -1; }
        match transfer(bus, addr, data, &mut []) {
            Some(c) if c.ok => 0,
            _ => -1,
        }
    }

    pub fn i2c_read(bus: u8, addr: u8, reg: u8, buf: &mut [u8]) -> i32 {
        if buf.is_empty() { return -1; }
        // A SHORT READ IS A FAILURE, NOT A COUNT: a NACK or a timeout
        // returns -1, never 0 or a partial count (callers that test `n < 0`
        // must not read a buffer the device never wrote).
        let n = buf.len();
        match transfer(bus, addr, &[reg], buf) {
            Some(c) if c.ok => n as i32,
            _ => -1,
        }
    }

    pub fn i2c_detect(bus: u8, addr: u8) -> bool {
        // A one-byte write of 0x00 with STOP (as before): ACKed or aborted.
        matches!(transfer(bus, addr, &[0], &mut []), Some(c) if c.ok)
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

    /// The controller's registers for `crate::i2c_txn`.
    struct Mmio(usize);

    impl crate::i2c_txn::DwRegs for Mmio {
        #[inline]
        fn rd(&self, off: usize) -> u32 { rd(self.0, off) }
        #[inline]
        fn wr(&self, off: usize, val: u32) { wr(self.0, off, val) }
    }

    /// Kconfig `I2C_XFER_TIMEOUT_US` in timebase ticks.
    fn xfer_timeout() -> u64 {
        azos_limits::I2C_XFER_TIMEOUT_US as u64 * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000
    }

    /// Wakes the `i2c-svc` task (registered by the kernel); 0: none.
    static SERVICE_KICK: AtomicUsize = AtomicUsize::new(0);

    /// Register what a submit calls to get its transaction serviced.
    pub fn set_service_kick(f: fn()) {
        SERVICE_KICK.store(f as usize, Ordering::Release);
    }

    fn kick() {
        let f = SERVICE_KICK.load(Ordering::Acquire);
        if f != 0 {
            // SAFETY: only `set_service_kick` stores here, and it stores a `fn()`.
            let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(f) };
            f();
        }
    }

    /// Queue a read of `len` bytes from register `reg` of `addr` on `bus`
    /// (the queued-transaction section at the top of this file). Never
    /// waits; the service step puts it on the wire. `None` when the queue
    /// refuses (full, counted, or a bad length). `_now` keeps the signature
    /// of the simulation's, which completes at submit.
    pub fn i2c_submit_read(bus: u8, addr: u8, reg: u8, len: usize, _now: u64) -> Option<u32> {
        bus_base(bus)?;
        let slot = i2c_bus_lock_slot(bus)?;
        let ticket = I2C_QUEUES.get(slot)?.lock().submit(addr, &[reg], len).ok()?;
        kick();
        Some(ticket)
    }

    /// One bounded step of `bus`'s controller (`crate::i2c_txn`): from the
    /// `i2c-svc` task, or the controller's interrupt once its line is
    /// wired. Returns whether the bus still has work (queued or on the wire).
    pub fn i2c_service(bus: u8, _now: u64) -> bool {
        let Some(base) = bus_base(bus) else { return false };
        let Some(slot) = i2c_bus_lock_slot(bus) else { return false };
        step(base, slot)
    }

    /// One step under the bus lock (`I2C_BUS_LOCKS`, also taken by
    /// `i2c_init`) and the queue's: the only preemption-off window of a
    /// transfer. Returns whether the bus still has work.
    fn step(base: usize, slot: usize) -> bool {
        let (Some(m), Some(q)) = (I2C_BUS_LOCKS.get(slot), I2C_QUEUES.get(slot)) else { return false };
        let _bus_guard = m.lock();
        let mut qg = q.lock();
        let _ = qg.service(&Mmio(base), azos_drv_sys::timebase::now(), xfer_timeout());
        !qg.is_idle()
    }

    /// The kernel's "sleep `us` if this context may sleep" (registered at
    /// boot); returns whether it slept. 0: nothing registered (early boot).
    static SLEEP_HOOK: AtomicUsize = AtomicUsize::new(0);

    /// Register the sleep a synchronous transfer waits with.
    pub fn set_sleep_hook(f: fn(u64) -> bool) {
        SLEEP_HOOK.store(f as usize, Ordering::Release);
    }

    fn sleep_between_steps() -> bool {
        let f = SLEEP_HOOK.load(Ordering::Acquire);
        if f == 0 {
            return false;
        }
        // SAFETY: only `set_sleep_hook` stores here, and it stores a `fn(u64) -> bool`.
        let f: fn(u64) -> bool = unsafe { core::mem::transmute::<usize, fn(u64) -> bool>(f) };
        f(azos_limits::I2C_SERVICE_POLL_US as u64)
    }

    pub fn i2c_info() {
        azos_drv_sys::kconsoleln!("[I2C] JH7110 DesignWare APB I2C");
        azos_drv_sys::kconsoleln!("[I2C]   I2C0 @ {:#010x}", I2C0_BASE);
        azos_drv_sys::kconsoleln!("[I2C]   I2C1 @ {:#010x}", I2C1_BASE);
    }
}

#[cfg(feature = "vf2")]
pub use dw_i2c::*;
