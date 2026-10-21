// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// UART bridge driver — secondary UART for ESP32-C3 WiFi bridge.
///
/// VF2: JH7110 UART1 (DesignWare APB UART, `snps,dw-apb-uart`) at
/// 0x10010000, 115200 baud. Same IP as UART0 — see `uart.rs`'s module doc
/// comment: real hardware needs `reg-shift = 2` / 32-bit-wide MMIO accesses,
/// confirmed for this exact node (`serial@10010000`) against StarFive's
/// `u-boot` tree, `arch/riscv/dts/jh7110.dtsi` (fetched 2026-09-18).
/// QEMU/K1: stubs (no bridge hardware).
///
/// Architecture:
///   VF2 ──UART1 (TX/RX/GND)──→ ESP32-C3 ──WiFi/TCP──→ macOS (brain server)
///
/// The VF2 sends/receives brain protocol packets (MAGIC "BR" framed) over
/// UART1.  The ESP32 firmware is a transparent byte relay between its UART
/// and a TCP socket to the brain server.

// ── QEMU / K1: no bridge hardware ───────────────────────────────────────────

#[cfg(not(feature = "vf2"))]
pub fn bridge_init() -> i32 { -1 }

#[cfg(not(feature = "vf2"))]
pub fn bridge_is_ready() -> bool { false }

#[cfg(not(feature = "vf2"))]
pub fn bridge_send(_data: &[u8]) -> i32 { -1 }

#[cfg(not(feature = "vf2"))]
pub fn bridge_recv(_buf: &mut [u8]) -> i32 { 0 }

/// Same shape as the real one so a caller does not need a `cfg`. Zeroes are
/// honest here: with no bridge there is no link to lose bytes on.
#[cfg(not(feature = "vf2"))]
pub fn bridge_losses() -> (u32, u32) { (0, 0) }

#[cfg(not(feature = "vf2"))]
pub fn bridge_info() {
    azos_drv_sys::kprintln!("[BRIDGE] Not available (no VF2 UART1)");
}

// ── VF2: NS16550A UART1 for ESP32 bridge ─────────────────────────────────────

#[cfg(feature = "vf2")]
mod uart1 {
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

    const BASE: usize = azos_drv_base::platform::hw::UART1_BASE;

    // NS16550A register offsets
    const THR: usize = 0;
    const RBR: usize = 0;
    const IER: usize = 1;
    const FCR: usize = 2;
    const LCR: usize = 3;
    const MCR: usize = 4;
    const LSR: usize = 5;

    const LSR_DATA_READY: u8 = 1 << 0;
    /// Overrun Error: the receiver was handed a byte before the previous one
    /// was read, and the previous one is GONE. The driver never looked at this
    /// bit until 2026-09-11, so hardware-level byte loss was not merely
    /// unhandled — it was undetectable.
    const LSR_OVERRUN:    u8 = 1 << 1;
    const LSR_THR_EMPTY:  u8 = 1 << 5;
    const LCR_8BITS:      u8 = 0x03;
    const LCR_DLAB:       u8 = 1 << 7;
    const LCR_SPAR:       u8 = 1 << 5;
    const FCR_FIFO:       u8 = 0x07; // enable + clear RX + clear TX

    // DW-APB-UART busy-detect status register — same IP as UART0, same
    // quirk. See uart.rs's `set_lcr` for the full citation (Linux
    // `8250_dwlib.h`'s `DW_UART_USR`/`DW_UART_USR_BUSY`).
    const USR: usize = 0x1f;
    const USR_BUSY: u8 = 1 << 0;

    // JH7110 UART1 clock: same as UART0 → divisor 13 for 115200 baud.
    const DIVISOR: u8 = 13;

    static INIT_DONE: AtomicBool = AtomicBool::new(false);

    // RX ring buffer (polled, not IRQ-driven — bridge runs in its own task)
    const RX_CAP: usize = 512;
    static mut RX_BUF: [u8; RX_CAP] = [0u8; RX_CAP];
    static RX_HEAD: AtomicUsize = AtomicUsize::new(0);
    static RX_TAIL: AtomicUsize = AtomicUsize::new(0);

    /// Bytes dropped because the software ring was full.
    ///
    /// The drop itself is not new; the COUNT is. A silent discard on a link
    /// that carries actuator commands means a frame can go missing with no
    /// trace anywhere, and the first symptom is a robot that ignored an
    /// instruction. Cheap to count, impossible to reconstruct afterwards.
    static RX_DROPPED: AtomicU32 = AtomicU32::new(0);
    /// Times the hardware reported an overrun — bytes lost inside the UART,
    /// before the driver ever saw them.
    static RX_OVERRUN: AtomicU32 = AtomicU32::new(0);

    // JH7110 DW-APB-UART: reg-shift=2, reg-io-width=4 — see module doc
    // comment. 4-byte register stride, 32-bit accesses; low byte carries
    // the 16550-compatible register value.
    #[inline(always)]
    fn rd(reg: usize) -> u8 {
        unsafe { core::ptr::read_volatile((BASE + (reg << 2)) as *const u32) as u8 }
    }

    #[inline(always)]
    fn wr(reg: usize, val: u8) {
        unsafe { core::ptr::write_volatile((BASE + (reg << 2)) as *mut u32, val as u32) }
    }

    // Busy-detect-safe LCR write — see the USR/USR_BUSY doc comment above.
    // A real DW-APB-UART core silently drops an LCR write made while it's
    // mid-transaction; this retries it the same way Linux's
    // `dw8250_check_lcr`/`dw8250_idle_enter` does.
    fn set_lcr(value: u8) {
        wr(LCR, value);
        if (rd(LCR) & !LCR_SPAR) == (value & !LCR_SPAR) {
            return;
        }
        let mut retries: u8 = 4;
        loop {
            wr(FCR, FCR_FIFO);
            if rd(USR) & USR_BUSY == 0 {
                break;
            }
            retries -= 1;
            if retries == 0 {
                break;
            }
            for _ in 0..256 {
                core::hint::spin_loop();
            }
        }
        wr(LCR, value);
    }

    /// Initialize UART1 at 115200 baud, 8N1, FIFO enabled.
    pub fn bridge_init() -> i32 {
        wr(IER, 0x00);           // disable interrupts
        set_lcr(LCR_DLAB);      // enable DLAB for divisor access
        wr(RBR, DIVISOR);       // divisor low
        wr(IER, 0x00);          // divisor high = 0
        set_lcr(LCR_8BITS);     // 8N1, DLAB off
        wr(FCR, FCR_FIFO);      // enable + clear FIFOs
        wr(MCR, 0x03);          // DTR + RTS

        // Verify: read LSR to confirm UART is responsive
        let lsr = rd(LSR);
        if lsr == 0xFF {
            // No UART at this address (floating bus)
            azos_drv_sys::kprintln!("[BRIDGE] UART1 @ {:#010x} not responding", BASE);
            return -1;
        }

        INIT_DONE.store(true, Ordering::Release);
        azos_drv_sys::kprintln!("[BRIDGE] UART1 @ {:#010x} ready (115200 8N1)", BASE);
        0
    }

    pub fn bridge_is_ready() -> bool {
        INIT_DONE.load(Ordering::Acquire)
    }

    /// Drain hardware FIFO into software ring buffer (non-blocking).
    ///
    /// Both loss paths are COUNTED here, and neither was before: the hardware
    /// overrun (bytes gone inside the UART) and the ring-full discard (bytes
    /// gone in software). See [`bridge_losses`].
    fn poll_rx() {
        loop {
            // One LSR read per byte, and the overrun bit is checked from it:
            // reading LSR is what CLEARS OE on a 16550, so a second read to
            // ask about it separately would race with the clear and lose the
            // report.
            let lsr = rd(LSR);
            if lsr & LSR_OVERRUN != 0 {
                RX_OVERRUN.fetch_add(1, Ordering::Relaxed);
            }
            if lsr & LSR_DATA_READY == 0 { break; }

            let c = rd(RBR);
            let head = RX_HEAD.load(Ordering::Relaxed);
            let next = (head + 1) % RX_CAP;
            if next != RX_TAIL.load(Ordering::Acquire) {
                unsafe { RX_BUF[head] = c; }
                RX_HEAD.store(next, Ordering::Release);
            } else {
                RX_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// `(ring_dropped, hardware_overruns)` since boot.
    ///
    /// Exposed rather than merely logged: a link that loses bytes intermittently
    /// looks exactly like a peer that sends malformed frames, and telling those
    /// two apart after the fact is impossible without a number.
    pub fn bridge_losses() -> (u32, u32) {
        (
            RX_DROPPED.load(Ordering::Relaxed),
            RX_OVERRUN.load(Ordering::Relaxed),
        )
    }

    /// Send raw bytes over UART1, draining RX while it waits.
    ///
    /// **The drain is the fix.** This used to spin on `THR_EMPTY` and nothing
    /// else, so for the whole duration of a send the receiver was unattended:
    /// the hardware FIFO is 16 bytes, and at 115200 baud a 70-byte
    /// `SensorPacket` takes ~6 ms — about 69 byte-times in which an inbound
    /// frame could overrun with the driver looking the other way. The link is
    /// full duplex; the driver was not.
    ///
    /// Still blocking, and that is now affordable: the camera path that made
    /// one send 1.67 seconds long is gone (see `behavior_task`), so the
    /// longest thing this carries is a sensor packet.
    pub fn bridge_send(data: &[u8]) -> i32 {
        if !INIT_DONE.load(Ordering::Acquire) { return -1; }
        for &b in data {
            while rd(LSR) & LSR_THR_EMPTY == 0 {
                // Serve the receiver while the transmitter is busy. `poll_rx`
                // only moves bytes into the ring, so it cannot re-enter this
                // function or block.
                poll_rx();
                core::hint::spin_loop();
            }
            wr(THR, b);
        }
        data.len() as i32
    }

    /// Receive bytes from UART1 into `buf` (non-blocking).
    /// Returns number of bytes read (0 if none available).
    pub fn bridge_recv(buf: &mut [u8]) -> i32 {
        if !INIT_DONE.load(Ordering::Acquire) { return 0; }

        // Drain hardware FIFO first
        poll_rx();

        let mut count = 0usize;
        while count < buf.len() {
            let tail = RX_TAIL.load(Ordering::Relaxed);
            if tail == RX_HEAD.load(Ordering::Acquire) {
                break; // ring empty
            }
            buf[count] = unsafe { RX_BUF[tail] };
            RX_TAIL.store((tail + 1) % RX_CAP, Ordering::Release);
            count += 1;
        }
        count as i32
    }

    pub fn bridge_info() {
        if !INIT_DONE.load(Ordering::Acquire) {
            azos_drv_sys::kprintln!("[BRIDGE] UART1 not initialized");
            return;
        }
        let lsr = rd(LSR);
        azos_drv_sys::kprintln!("[BRIDGE] UART1 @ {:#010x} (115200 8N1)", BASE);
        // Printed even when zero: "no losses" is the useful reading, and a
        // line that only appears on failure cannot be checked for absence.
        let (dropped, overruns) = bridge_losses();
        azos_drv_sys::kwarn!("[BRIDGE]   lost: {} ring-full, {} hw overrun", dropped, overruns);
        azos_drv_sys::kprintln!("[BRIDGE]   LSR={:#04x} (data_ready={}, thr_empty={})",
            lsr,
            if lsr & LSR_DATA_READY != 0 { "yes" } else { "no" },
            if lsr & LSR_THR_EMPTY  != 0 { "yes" } else { "no" });
        let head = RX_HEAD.load(Ordering::Relaxed);
        let tail = RX_TAIL.load(Ordering::Relaxed);
        let used = (head + RX_CAP - tail) % RX_CAP;
        azos_drv_sys::kprintln!("[BRIDGE]   RX buffer: {}/{} bytes", used, RX_CAP);
    }
}

#[cfg(feature = "vf2")]
pub use uart1::*;

// ── The `Uart` interface (azos_devif::uart) ───────────────────────────────────
//
// The bridge is one port, UART1, with a line the board fixed (115200 8N1).
// The host (the kernel, or a ring-3 driver endpoint) checks the op class the
// capability carries before it calls in, resolves the queue handles the client
// moved ([`BridgePort::queues`]) to their driver ends and calls
// [`BridgePort::pump`] from its service loop. Bytes never cross a call.

use azos_devif::uart::{self as iface, Chunk, ChunkSink, ChunkSource, RxQueue, TxQueue};
use azos_devif::{outcome, Cap, Out};

/// The port number the bridge answers to (`endpoint = "uart.1"`).
pub const BRIDGE_PORT: u32 = 1;

/// Chunks one [`BridgePort::pump`] moves in each direction, so a flood on one
/// queue cannot keep the service loop from the other.
const PUMP_CHUNKS: usize = 8;

/// The `Uart` interface over the bridge's UART1.
/// `Clone`: the host runs a pass on a copy, with its lock released.
#[derive(Clone)]
pub struct BridgePort {
    port: u32,
    rings: Option<(Cap<RxQueue>, Cap<TxQueue>)>,
    /// Receive chunks the queue had no room for.
    rx_full: u32,
    /// Transmit chunks the line did not take whole.
    tx_lost: u32,
    /// `bridge_losses()` summed as of the last chunk pushed, to flag the next
    /// chunk when more were lost since.
    losses_seen: u32,
    /// A chunk was dropped on a full queue: flag the next one.
    gap: bool,
}

impl BridgePort {
    pub const fn new(port: u32) -> Self {
        BridgePort { port, rings: None, rx_full: 0, tx_lost: 0, losses_seen: 0, gap: false }
    }

    /// The queues attached, for the host to resolve.
    pub fn queues(&self) -> Option<(Cap<RxQueue>, Cap<TxQueue>)> {
        self.rings
    }

    fn losses() -> u32 {
        let (dropped, overruns) = bridge_losses();
        dropped.wrapping_add(overruns)
    }

    /// Move what the line received to `rx` and what the client queued on
    /// `tx` to the line; the number of chunks moved. Does nothing while no
    /// rings are attached.
    pub fn pump(&mut self, rx: &mut impl ChunkSink, tx: &mut impl ChunkSource) -> usize {
        if self.rings.is_none() {
            return 0;
        }
        let mut moved = 0;
        for _ in 0..PUMP_CHUNKS {
            let mut buf = [0u8; iface::CHUNK_DATA];
            let n = bridge_recv(&mut buf);
            if n <= 0 {
                break;
            }
            let lost = Self::losses();
            let mut flags = 0;
            if self.gap || lost != self.losses_seen {
                flags |= iface::CHUNK_OVERRUN;
            }
            if rx.push(&Chunk::new(&buf[..n as usize], flags)) {
                self.gap = false;
                self.losses_seen = lost;
            } else {
                self.rx_full = self.rx_full.wrapping_add(1);
                self.gap = true;
            }
            moved += 1;
        }
        for _ in 0..PUMP_CHUNKS {
            let Some(chunk) = tx.pop() else { break };
            if bridge_send(chunk.bytes()) != chunk.len as i32 {
                self.tx_lost = self.tx_lost.wrapping_add(1);
            }
            moved += 1;
        }
        moved
    }
}

impl azos_devif::Uart for BridgePort {
    fn configure(&mut self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()> {
        if !(iface::BAUD_MIN..=iface::BAUD_MAX).contains(&baud)
            || !(5..=8).contains(&data_bits)
            || parity > iface::PARITY_EVEN
            || !(1..=2).contains(&stop_bits)
        {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if self.port != BRIDGE_PORT {
            return Out::err(outcome::NO_RESOURCE);
        }
        if !bridge_is_ready() {
            return Out::err(outcome::NOT_READY);
        }
        // The divisor and the line control register are set once, in
        // `bridge_init`: the line is the board's, not the client's.
        if (baud, data_bits, parity, stop_bits) == (115_200, 8, iface::PARITY_NONE, 1) {
            Out::ok(())
        } else {
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn attach(&mut self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()> {
        if self.port != BRIDGE_PORT {
            return Out::err(outcome::NO_RESOURCE);
        }
        if !bridge_is_ready() {
            return Out::err(outcome::NOT_READY);
        }
        if self.rings.is_some() {
            return Out::err(outcome::BUSY);
        }
        self.losses_seen = Self::losses();
        self.gap = false;
        self.rings = Some((rx, tx));
        Out::ok(())
    }

    fn detach(&mut self) -> Out<()> {
        self.rings = None;
        Out::ok(())
    }

    fn status(&self) -> Out<iface::Status> {
        if self.port != BRIDGE_PORT {
            return Out::err(outcome::NO_RESOURCE);
        }
        Out::ok(iface::Status { rx_lost: self.rx_full.wrapping_add(Self::losses()), tx_lost: self.tx_lost })
    }
}
