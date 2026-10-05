// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// U05-4 (2026-09-26): same class as `gpio.rs`/`pwm.rs`/`i2c.rs` — a `k1`
// build fell through to the QEMU sim below with no real K1 SPI driver
// behind it. `rc.rs`'s compile-time refusal, applied here per U05-4/§5 Q2
// [rec]. Placed before the module doc for the same `unused_doc_comments`
// reason as `gpio.rs`.
#[cfg(feature = "k1")]
compile_error!(
    "crates/drivers/bus/src/spi.rs: no real K1 SPI driver exists yet — a `k1` \
     build must not silently drive the QEMU simulation while advertising \
     real MMIO. See U05-4."
);

/// SPI master driver — full-duplex serial peripheral interface.
///
/// QEMU: in-memory simulation with 2 devices (SPI flash + LIDAR placeholder).
/// VF2:  Cadence SPI controller — MMIO skeleton (register model UNVERIFIED,
/// see the `vf2` module doc below — U05-1).
pub const SPI_MAX_DEVICES: usize = 8;

#[derive(Clone, Copy)]
pub struct SpiDevice {
    pub bus:  u8,
    pub cs:   u8,
    pub regs: [u8; 256],
}

impl SpiDevice {
    pub const fn new() -> Self {
        SpiDevice { bus: 0, cs: 0, regs: [0u8; 256] }
    }
}

// ── QEMU: in-memory simulation ────────────────────────────────────────────────

#[cfg(not(feature = "vf2"))]
mod sim {
    use super::*;
    use azos_sync::SpinLock;

    struct SpiState {
        devices: [SpiDevice; SPI_MAX_DEVICES],
        count:   usize,
        init:    bool,
    }

    impl SpiState {
        const fn new() -> Self {
            SpiState { devices: [SpiDevice::new(); SPI_MAX_DEVICES], count: 0, init: false }
        }

        fn find(&self, bus: u8, cs: u8) -> Option<usize> {
            for i in 0..self.count {
                if self.devices[i].bus == bus && self.devices[i].cs == cs {
                    return Some(i);
                }
            }
            None
        }
    }

    static SPI: SpinLock<SpiState> = SpinLock::new(SpiState::new());

    pub fn spi_init() {
        let mut state = SPI.lock();
        if state.init { return; }

        // Simulated SPI flash (W25Q32) at bus=0 cs=0
        // JEDEC ID: 0xEF (Winbond), 0x40 (SPI flash), 0x16 (32Mbit)
        if state.count < SPI_MAX_DEVICES {
            let i = state.count;
            state.devices[i].bus  = 0;
            state.devices[i].cs   = 0;
            state.devices[i].regs[0] = 0xEF; // Manufacturer ID
            state.devices[i].regs[1] = 0x40; // Memory type
            state.devices[i].regs[2] = 0x16; // Capacity (32Mbit)
            state.devices[i].regs[3] = 0xFF; // Status register default
            state.count += 1;
        }

        // Simulated SPI LIDAR placeholder at bus=0 cs=1
        if state.count < SPI_MAX_DEVICES {
            let i = state.count;
            state.devices[i].bus  = 0;
            state.devices[i].cs   = 1;
            state.devices[i].regs[0] = 0xA0; // LIDAR device ID
            state.devices[i].regs[1] = 0x01; // firmware version
            state.count += 1;
        }

        state.init = true;
        azos_drv_sys::kprintln!("[SPI] Initialized (simulated, {} devices)", state.count);
    }

    /// Full-duplex SPI transfer: write `tx` and simultaneously read into `rx`.
    ///
    /// Simulation: writes tx bytes to device register file starting at offset 0,
    /// then copies from register file into rx.
    pub fn spi_transfer(bus: u8, cs: u8, tx: &[u8], rx: &mut [u8]) -> i32 {
        let mut state = SPI.lock();
        match state.find(bus, cs) {
            Some(i) => {
                // Write tx bytes into device registers
                for (j, &b) in tx.iter().enumerate() {
                    if j < 256 { state.devices[i].regs[j] = b; }
                }
                // Read device registers into rx
                for (j, b) in rx.iter_mut().enumerate() {
                    *b = state.devices[i].regs[j & 0xFF];
                }
                0
            }
            None => -1,
        }
    }

    /// Write-only SPI transaction.
    pub fn spi_write(bus: u8, cs: u8, data: &[u8]) -> i32 {
        let mut state = SPI.lock();
        match state.find(bus, cs) {
            Some(i) => {
                for (j, &b) in data.iter().enumerate() {
                    if j < 256 { state.devices[i].regs[j] = b; }
                }
                0
            }
            None => -1,
        }
    }

    /// Read from a device register via SPI.
    ///
    /// Sends register address, then reads `buf.len()` bytes starting from that register.
    pub fn spi_read(bus: u8, cs: u8, reg: u8, buf: &mut [u8]) -> i32 {
        let state = SPI.lock();
        match state.find(bus, cs) {
            Some(i) => {
                for (j, b) in buf.iter_mut().enumerate() {
                    *b = state.devices[i].regs[(reg as usize + j) & 0xFF];
                }
                buf.len() as i32
            }
            None => -1,
        }
    }

    /// Detect whether a device is present at bus/cs.
    pub fn spi_detect(bus: u8, cs: u8) -> bool {
        SPI.lock().find(bus, cs).is_some()
    }

    pub fn spi_info() {
        let state = SPI.lock();
        azos_drv_sys::kconsoleln!("[SPI] {} device(s) registered (simulated)", state.count);
        for i in 0..state.count {
            let d = &state.devices[i];
            let jedec = (d.regs[0] as u32) << 16
                      | (d.regs[1] as u32) << 8
                      | d.regs[2] as u32;
            azos_drv_sys::kconsoleln!("[SPI]   bus={} cs={} JEDEC={:#08x}", d.bus, d.cs, jedec);
        }
    }
}

#[cfg(not(feature = "vf2"))]
pub use sim::*;

// ── VisionFive 2 / JH7110: register model UNVERIFIED (U05-1, 2026-09-26) ───
//
// **Both the address and the IP identity below were wrong.** `0x1004_0000`
// is `i2c1@10040000` in mainline `jh7110.dtsi` (`compatible =
// "snps,designware-i2c"`) — `i2c_init` (`i2c.rs`) programs this SAME
// address as bus 1 today, so this module's real hardware target has, until
// now, also been a live I2C controller's `IC_CON`/`IC_SS_SCL_HCNT`. The
// real `spi0` is `spi0@10060000`, `compatible = "arm,pl022", "arm,primecell"`
// — an ARM PL022 (SSP), a completely different register model
// (`SSPCR0`/`SSPCR1`/`SSPDR`/`SSPSR`/`SSPCPSR`) from the Cadence/Zynq one
// implemented below. Base corrected to `platform::hw::SPI0_BASE`
// (`0x1006_0000`); the PL022 register map is a separate, not-yet-ported
// fix (the Cadence register offsets below are left as documented, known-
// wrong dead code rather than rewritten this pass) — `main.rs`'s
// unconditional `spi_init()` call needs gating on a board that actually
// maps this address before this module is safe to call at all (see the
// `main.rs` diff in this front's report).
//
// Register map below is the OLD (Cadence/Zynq) model — NOT what is at
// `SPI0_BASE` now. Kept for reference only:
//   0x00  CDNS_SPI_CR   — Config: manual CS, CPOL, CPHA, master mode, baud
//   0x04  CDNS_SPI_SR   — Status: TX full, TX empty, RX not empty, busy
//   0x14  CDNS_SPI_ER   — Enable register (bit 0 = SPI enable)
//   0x1C  CDNS_SPI_TXD  — TX data (8-bit write)
//   0x20  CDNS_SPI_RXD  — RX data (8-bit read)

#[cfg(feature = "vf2")]
mod cdns_spi {
    /// Corrected 2026-09-26 (U05-1): was a literal `0x1004_0000` (`i2c1`,
    /// see the module doc above). Now the real `spi0` address — but this
    /// module's register layout below is still the wrong IP's.
    const SPI0_BASE: usize = azos_drv_base::platform::hw::SPI0_BASE;

    // Register offsets
    const CDNS_SPI_CR:  usize = 0x00;
    const CDNS_SPI_SR:  usize = 0x04;
    const CDNS_SPI_ER:  usize = 0x14;
    const CDNS_SPI_TXD: usize = 0x1C;
    const CDNS_SPI_RXD: usize = 0x20;

    // CR bits
    const CR_MASTER:    u32 = 1 << 0;
    const CR_CPOL:      u32 = 1 << 1;
    const CR_CPHA:      u32 = 1 << 2;
    const CR_CS_BITS:   u32 = 0xF << 10; // CS[3:0] in bits 13:10 (active low)
    const CR_MANUAL_CS: u32 = 1 << 14;

    // SR bits
    const SR_TX_FULL:      u32 = 1 << 3;
    const SR_TX_NOT_FULL:  u32 = 1 << 2;
    const SR_RX_NOT_EMPTY: u32 = 1 << 4;

    /// Timeout for TX/RX spin loops (~10 ms at typical clock).
    const SPI_TIMEOUT: u32 = 100_000;

    #[inline(always)]
    fn rd(base: usize, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((base + off) as *const u32) }
    }

    #[inline(always)]
    fn wr(base: usize, off: usize, val: u32) {
        unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) }
    }

    /// Assert CS line for the given slave (active low in CR bits 13:10).
    fn cs_assert(cs: u8) {
        let mut cr = rd(SPI0_BASE, CDNS_SPI_CR);
        // Clear all CS bits then clear the target bit (active low)
        cr |= CR_CS_BITS;
        cr &= !(1u32 << (10 + (cs & 3)));
        wr(SPI0_BASE, CDNS_SPI_CR, cr);
    }

    /// Deassert all CS lines (set all CS bits high = inactive).
    fn cs_deassert() {
        let cr = rd(SPI0_BASE, CDNS_SPI_CR) | CR_CS_BITS;
        wr(SPI0_BASE, CDNS_SPI_CR, cr);
    }

    /// Wait for a status bit with timeout. Returns false on timeout.
    #[inline]
    fn wait_sr(mask: u32, expect_set: bool) -> bool {
        for _ in 0..SPI_TIMEOUT {
            let sr = rd(SPI0_BASE, CDNS_SPI_SR);
            if expect_set { if sr & mask != 0 { return true; } }
            else          { if sr & mask == 0 { return true; } }
            core::hint::spin_loop();
        }
        false
    }

    pub fn spi_init() {
        // Enable SPI master, CPOL=0, CPHA=0, manual CS, all CS deasserted
        wr(SPI0_BASE, CDNS_SPI_CR, CR_MASTER | CR_MANUAL_CS | CR_CS_BITS);
        wr(SPI0_BASE, CDNS_SPI_ER, 1); // enable
        azos_drv_sys::kprintln!("[SPI] JH7110 Cadence SPI @ {:#010x}", SPI0_BASE);
    }

    pub fn spi_transfer(bus: u8, cs: u8, tx: &[u8], rx: &mut [u8]) -> i32 {
        if bus != 0 { return -1; }
        cs_assert(cs);
        let len = tx.len().min(rx.len());
        for i in 0..len {
            if !wait_sr(SR_TX_NOT_FULL, true) { cs_deassert(); return -1; }
            wr(SPI0_BASE, CDNS_SPI_TXD, tx[i] as u32);
            if !wait_sr(SR_RX_NOT_EMPTY, true) { cs_deassert(); return -1; }
            rx[i] = (rd(SPI0_BASE, CDNS_SPI_RXD) & 0xFF) as u8;
        }
        cs_deassert();
        0
    }

    pub fn spi_write(bus: u8, cs: u8, data: &[u8]) -> i32 {
        if bus != 0 { return -1; }
        cs_assert(cs);
        for &b in data {
            if !wait_sr(SR_TX_NOT_FULL, true) { cs_deassert(); return -1; }
            wr(SPI0_BASE, CDNS_SPI_TXD, b as u32);
            // Drain RX FIFO
            while rd(SPI0_BASE, CDNS_SPI_SR) & SR_RX_NOT_EMPTY != 0 {
                let _ = rd(SPI0_BASE, CDNS_SPI_RXD);
            }
        }
        cs_deassert();
        0
    }

    pub fn spi_read(bus: u8, cs: u8, reg: u8, buf: &mut [u8]) -> i32 {
        if bus != 0 { return -1; }
        cs_assert(cs);
        // Send register address
        if !wait_sr(SR_TX_NOT_FULL, true) { cs_deassert(); return -1; }
        wr(SPI0_BASE, CDNS_SPI_TXD, reg as u32);
        if !wait_sr(SR_RX_NOT_EMPTY, true) { cs_deassert(); return -1; }
        let _ = rd(SPI0_BASE, CDNS_SPI_RXD); // discard dummy byte
        // Read data
        for b in buf.iter_mut() {
            if !wait_sr(SR_TX_NOT_FULL, true) { cs_deassert(); return -1; }
            wr(SPI0_BASE, CDNS_SPI_TXD, 0x00); // clock out dummy
            if !wait_sr(SR_RX_NOT_EMPTY, true) { cs_deassert(); return -1; }
            *b = (rd(SPI0_BASE, CDNS_SPI_RXD) & 0xFF) as u8;
        }
        cs_deassert();
        buf.len() as i32
    }

    pub fn spi_detect(bus: u8, _cs: u8) -> bool {
        // On real hardware: try a JEDEC ID read and check for valid response
        bus == 0
    }

    pub fn spi_info() {
        let sr = rd(SPI0_BASE, CDNS_SPI_SR);
        let cr = rd(SPI0_BASE, CDNS_SPI_CR);
        azos_drv_sys::kconsoleln!("[SPI] JH7110 Cadence SPI @ {:#010x}", SPI0_BASE);
        azos_drv_sys::kconsoleln!("[SPI]   CR={:#010x}  SR={:#010x}", cr, sr);
    }
}

#[cfg(feature = "vf2")]
pub use cdns_spi::*;
