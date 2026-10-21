// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// SPI master driver — full-duplex serial peripheral interface.
///
/// QEMU: in-memory simulation with 2 devices (SPI flash + LIDAR placeholder).
/// VF2:  Cadence SPI controller — MMIO skeleton (register model UNVERIFIED,
/// see the `vf2` module doc below — U05-1).
/// K1:   no controller driver: the K1's SPI (`spacemit,k1-spi`) is none of
/// the above and no reference source for it is vendored, so the `k1_spi`
/// module below answers "no controller" to every call — it neither drives
/// the simulation nor pokes MMIO.
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

#[cfg(not(any(feature = "vf2", feature = "k1")))]
mod sim {
    use super::*;
    use azos_sync::SpinLock;

    /// The simulated controller's clock ceiling, Hz: below the interface's
    /// [`azos_devif::spi::SPEED_MAX_HZ`], as a real controller's is (it divides
    /// its peripheral clock).
    pub const SIM_SPEED_CEILING_HZ: u32 = 25_000_000;

    /// What the controller was last programmed with: the bus is shared, so
    /// the last chip select to configure it decides how the next transfer
    /// clocks.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Programmed {
        pub bus:  u8,
        pub cs:   u8,
        pub mode: u8,
        pub hz:   u32,
        pub held: bool,
    }

    struct SpiState {
        devices:    [SpiDevice; SPI_MAX_DEVICES],
        count:      usize,
        init:       bool,
        programmed: Option<Programmed>,
    }

    impl SpiState {
        const fn new() -> Self {
            SpiState { devices: [SpiDevice::new(); SPI_MAX_DEVICES], count: 0, init: false, programmed: None }
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

    /// Program the controller for the port's mode, clock and chip-select
    /// hold. The simulation has no wire to retime: it remembers the setup (what
    /// `spi_info` and `spi_programmed` report) and refuses a clock above
    /// [`SIM_SPEED_CEILING_HZ`], leaving the setup it had.
    pub fn spi_apply(bus: u8, cs: u8, mode: u8, hz: u32, held: bool) -> bool {
        if hz > SIM_SPEED_CEILING_HZ {
            return false;
        }
        SPI.lock().programmed = Some(Programmed { bus, cs, mode, hz, held });
        true
    }

    /// The setup the controller holds now; `None` before anything was
    /// programmed.
    pub fn spi_programmed() -> Option<Programmed> {
        SPI.lock().programmed
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
        if let Some(p) = state.programmed {
            azos_drv_sys::kconsoleln!(
                "[SPI]   programmed for bus={} cs={}: mode {} {} Hz{}",
                p.bus, p.cs, p.mode, p.hz, if p.held { " (cs held)" } else { "" });
        }
    }
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub use sim::*;

// ── SpacemiT K1: no controller driver ────────────────────────────────────────
//
// Until U05-4 a `k1` build refused to compile here (`compile_error!`) because
// it fell through to the simulation above while the platform advertised real
// MMIO. That fall-through is what is gone: on the K1 every entry point
// answers failure, the way an I2C bus the tree has no node for does
// (`i2c.rs`), so the `Spi` interface (`SpiPort`, below) reports
// `NO_RESOURCE`/`FAULT` and the TPM bring-up finds no device. A K1 SPI master
// (the SSP block, `spacemit,k1-spi`) replaces this module when a board user
// needs one; nothing on the K1 image does today.

#[cfg(feature = "k1")]
mod k1_spi {
    pub fn spi_transfer(_bus: u8, _cs: u8, _tx: &[u8], _rx: &mut [u8]) -> i32 { -1 }

    pub fn spi_write(_bus: u8, _cs: u8, _data: &[u8]) -> i32 { -1 }

    pub fn spi_read(_bus: u8, _cs: u8, _reg: u8, _buf: &mut [u8]) -> i32 { -1 }

    pub fn spi_detect(_bus: u8, _cs: u8) -> bool { false }

    pub fn spi_apply(_bus: u8, _cs: u8, _mode: u8, _hz: u32, _held: bool) -> bool { false }
}

#[cfg(feature = "k1")]
pub use k1_spi::*;

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

    /// The register model above is not the PL022 at `SPI0_BASE` (see the
    /// module note), so no mode, clock or chip-select hold is programmed:
    /// only the setup the controller comes up in is accepted, and the
    /// interface answers `UNSUPPORTED` for the rest.
    pub fn spi_apply(_bus: u8, _cs: u8, mode: u8, hz: u32, held: bool) -> bool {
        mode == 0 && hz == azos_devif::spi::SPEED_DEFAULT_HZ && !held
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

// ── The `Spi` interface (azos_devif::spi) ─────────────────────────────────────
//
// One value per chip select. The host (kernel or ring 3) checks the op class
// the capability carries (`WRITE` for every op that clocks bytes, `EXEC` to
// configure) before it calls in, and
// resolves the badge with `SpiPort::from_badge`; this layer checks what the
// device and the controller can do. The functions above are the only way to
// the wire.

use azos_devif::spi::{self, MAX_BYTES, MODES, SPEED_MAX_HZ, SPEED_MIN_HZ};
use azos_devif::{outcome, Out};
use azos_devif::i2c::Bytes;

/// What a chip select was last set up with.
#[derive(Clone, Copy)]
struct Setup {
    used: bool,
    bus:  u8,
    cs:   u8,
    mode: u8,
    hz:   u32,
    held: bool,
}

impl Setup {
    const fn empty() -> Self {
        Setup { used: false, bus: 0, cs: 0, mode: 0, hz: spi::SPEED_DEFAULT_HZ, held: false }
    }
}

static SETUPS: azos_sync::SpinLock<[Setup; SPI_MAX_DEVICES]> =
    azos_sync::SpinLock::new([Setup::empty(); SPI_MAX_DEVICES]);

/// The `Spi` interface over one chip select of one bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpiPort {
    pub bus: u8,
    pub cs:  u8,
}

impl SpiPort {
    /// The port an endpoint badge names (`bus << 8 | cs`).
    pub const fn from_badge(badge: u32) -> Self {
        let (bus, cs) = spi::unbadge(badge);
        SpiPort { bus, cs }
    }

    /// `NO_RESOURCE` unless a device answers the chip select.
    fn present(&self) -> Result<(), u32> {
        if spi_detect(self.bus, self.cs) { Ok(()) } else { Err(outcome::NO_RESOURCE) }
    }

    /// This chip select's setup: what it was last given, or the defaults.
    fn setup_in(&self, table: &[Setup; SPI_MAX_DEVICES]) -> Setup {
        table
            .iter()
            .find(|s| s.used && s.bus == self.bus && s.cs == self.cs)
            .copied()
            .unwrap_or(Setup { used: true, bus: self.bus, cs: self.cs, ..Setup::empty() })
    }

    /// Run one bus operation for this chip select. The controller is shared by
    /// every chip select of the bus, so the setup of this one (mode, clock,
    /// hold) is programmed first, and the table lock is held until the
    /// operation ends so no other chip select retimes the bus under it.
    /// `FAULT` when the controller refuses a setup it accepted before.
    fn on_bus<T>(&self, op: impl FnOnce() -> Result<T, u32>) -> Result<T, u32> {
        self.present()?;
        let table = SETUPS.lock();
        let s = self.setup_in(&table);
        if !spi_apply(self.bus, self.cs, s.mode, s.hz, s.held) {
            return Err(outcome::FAULT);
        }
        op()
    }

    /// Change this port's setup with `edit` and program the controller with
    /// the result; the setup is kept only when the controller took it, and a
    /// refused one leaves nothing behind.
    fn reconfigure(&self, edit: impl FnOnce(&mut Setup)) -> Out<()> {
        if let Err(c) = self.present() {
            return Out::err(c);
        }
        let mut table = SETUPS.lock();
        let at = match table.iter().position(|s| s.used && s.bus == self.bus && s.cs == self.cs) {
            Some(i) => i,
            None => match table.iter().position(|s| !s.used) {
                Some(i) => i,
                None => return Out::err(outcome::BUSY),
            },
        };
        let mut next = self.setup_in(&table);
        edit(&mut next);
        if !spi_apply(self.bus, self.cs, next.mode, next.hz, next.held) {
            return Out::err(outcome::UNSUPPORTED);
        }
        table[at] = next;
        Out::ok(())
    }
}

/// Up to [`MAX_BYTES`] bytes of a request, or the refusal.
fn request_bytes(data: &Bytes, buf: &mut [u8; MAX_BYTES]) -> Result<usize, u32> {
    let n = data.n as usize;
    if n == 0 || n > MAX_BYTES {
        return Err(outcome::BAD_ARGUMENT);
    }
    data.copy_to(buf);
    Ok(n)
}

impl azos_devif::Spi for SpiPort {
    fn transfer(&mut self, data: Bytes) -> Out<Bytes> {
        let mut tx = [0u8; MAX_BYTES];
        let n = match request_bytes(&data, &mut tx) {
            Ok(n) => n,
            Err(c) => return Out::err(c),
        };
        let r = self.on_bus(|| {
            let mut rx = [0u8; MAX_BYTES];
            if spi_transfer(self.bus, self.cs, &tx[..n], &mut rx[..n]) == 0 {
                Ok(Bytes::from_slice(&rx[..n]))
            } else {
                Err(outcome::FAULT)
            }
        });
        match r {
            Ok(b) => Out::ok(b),
            Err(c) => Out::err(c),
        }
    }

    fn write(&mut self, data: Bytes) -> Out<()> {
        let mut tx = [0u8; MAX_BYTES];
        let n = match request_bytes(&data, &mut tx) {
            Ok(n) => n,
            Err(c) => return Out::err(c),
        };
        let r = self.on_bus(|| if spi_write(self.bus, self.cs, &tx[..n]) == 0 { Ok(()) } else { Err(outcome::FAULT) });
        match r {
            Ok(()) => Out::ok(()),
            Err(c) => Out::err(c),
        }
    }

    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        let len = len as usize;
        if reg > 0xFF || len == 0 || len > MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let r = self.on_bus(|| {
            let mut buf = [0u8; MAX_BYTES];
            let n = spi_read(self.bus, self.cs, reg as u8, &mut buf[..len]);
            if n < 0 {
                return Err(outcome::FAULT);
            }
            Ok(Bytes::from_slice(&buf[..(n as usize).min(len)]))
        });
        match r {
            Ok(b) => Out::ok(b),
            Err(c) => Out::err(c),
        }
    }

    fn set_mode(&mut self, mode: u32) -> Out<()> {
        if mode >= MODES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        self.reconfigure(|s| s.mode = mode as u8)
    }

    fn set_speed(&mut self, hz: u32) -> Out<()> {
        if !(SPEED_MIN_HZ..=SPEED_MAX_HZ).contains(&hz) {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        self.reconfigure(|s| s.hz = hz)
    }

    fn hold_cs(&mut self, hold: bool) -> Out<()> {
        self.reconfigure(|s| s.held = hold)
    }
}
