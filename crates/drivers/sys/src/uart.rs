// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// UART driver.
///
/// NS16550A-register-model for QEMU virt / SpacemiT K1. On real VisionFive 2
/// (JH7110) hardware the UART0/UART1 IP is a Synopsys DesignWare APB UART
/// (`snps,dw-apb-uart`), which is 16550-register-compatible but NOT
/// byte-addressed on real silicon: JH7110's own device tree gives it
/// `reg-io-width = <4>` and `reg-shift = <2>` (32-bit accesses, registers on
/// a 4-byte stride), unlike QEMU's generic 16550 model, which is
/// byte-addressed (`reg-shift = 0`). Confirmed against StarFive's own
/// `u-boot` tree, `arch/riscv/dts/jh7110.dtsi`, `uart0`/`uart1` nodes
/// (<https://github.com/starfive-tech/u-boot/blob/JH7110_VisionFive2_devel/arch/riscv/dts/jh7110.dtsi>),
/// fetched 2026-09-18. `#[cfg(feature = "vf2")]` below switches to the
/// shifted, 32-bit-wide access pattern; QEMU and K1 keep the original
/// byte-stride path (K1's own UART register-stride behavior has not been
/// independently re-verified in this pass — out of scope until board
/// bring-up).
///
/// Phase 5: Added SMP-safe spinlock via AtomicBool.
/// Before `enable_smp_lock()` is called, no spinning occurs (safe for early boot).
///
/// Ported from kernel/drivers/uart.c
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
// In scope for `azos_arch::ARCH`'s methods. This guard is the console
// path — the one that produced the shredded-marker failure on BOTH ISAs —
// so the interrupt masking around it goes through the cross-ISA contract
// rather than being written twice, once per ISA, with a chance to diverge.
use azos_arch::Interrupts;
use azos_sync::PiMutex;

// arch-only: the MMIO back ends' base; x86_64's COM1 is port I/O.
#[cfg(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none")))]
use azos_drv_base::platform::hw::UART_BASE;

// ---- IRQ ring buffer (shared across all platforms) ----

/// Ring buffer capacity for IRQ-driven UART RX.
const RX_BUF_CAP: usize = 256;

/// Static ring buffer for interrupt-driven character reception.
static mut RX_BUF: [u8; RX_BUF_CAP] = [0u8; RX_BUF_CAP];
static RX_HEAD: AtomicUsize = AtomicUsize::new(0);
static RX_TAIL: AtomicUsize = AtomicUsize::new(0);
/// Set to true after `uart_enable_irq()` — changes `can_read()`/`getc()` behavior.
static IRQ_MODE: AtomicBool = AtomicBool::new(false);

// ---- SMP lock (shared across all platforms) ----

/// Global UART spinlock — only active after `enable_smp_lock()` is called.
static UART_LOCK: AtomicBool = AtomicBool::new(false);
/// Set to true when secondary CPUs are active to enable the spinlock.
static SMP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// RAII guard that releases the UART lock on drop.
///
/// K-A16: IRQ-safe by construction (mirrors `CpuLockGuard` in
/// `crates/core/sched/src/scheduler.rs`): disables `sstatus.SIE` for the duration
/// the lock is held and restores the previous interrupt state on drop.
/// `acquire()` used to be a plain spin — a tick firing on the same hart
/// while a task held it (e.g. mid-`kprintln!`) could enter the timer ISR,
/// which itself prints (WCET probes, panic/fault paths), and spin forever
/// on a lock only the preempted holder could release — a same-hart
/// deadlock. Also applied to `try_acquire()`'s successful case: it never
/// spins so it was never *itself* deadlock-prone, but without this a tick
/// firing while a trap/panic handler is mid-print through its guard could
/// still nest into another UART caller — keeping both entry points on the
/// same IRQ-safe discipline is what makes it safe to add a new caller later
/// without re-opening this hazard.
pub struct UartGuard {
    prev_sstatus: azos_arch::InterruptState,
    /// `console-splice-smoke` only: when the lock was taken (see
    /// [`lock_probe`]).
    #[cfg(feature = "console-splice-smoke")]
    t0: u64,
}

impl Drop for UartGuard {
    fn drop(&mut self) {
        #[cfg(feature = "console-splice-smoke")]
        lock_probe::end_hold(self.t0);
        if SMP_ACTIVE.load(Ordering::Relaxed) {
            UART_LOCK.store(false, Ordering::Release);
        }
        azos_arch::ARCH.restore(self.prev_sstatus);
    }
}

/// Acquire exclusive access to the UART.
pub fn acquire() -> UartGuard {
    let prev_sstatus = azos_arch::ARCH.disable_all();
    if SMP_ACTIVE.load(Ordering::Relaxed) {
        while UART_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }
    #[cfg(feature = "console-splice-smoke")]
    lock_probe::begin_hold();
    UartGuard {
        prev_sstatus,
        #[cfg(feature = "console-splice-smoke")]
        t0: crate::timebase::now(),
    }
}

/// Try to acquire the UART lock without blocking.
/// Returns `None` if the lock is already held (e.g. called from ISR context).
pub fn try_acquire() -> Option<UartGuard> {
    let prev_sstatus = azos_arch::ARCH.disable_all();
    if SMP_ACTIVE.load(Ordering::Relaxed) {
        if UART_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Restore interrupts before reporting failure — no guard will be
            // returned to do it for us.
            azos_arch::ARCH.restore(prev_sstatus);
            return None;
        }
    }
    #[cfg(feature = "console-splice-smoke")]
    lock_probe::begin_hold();
    Some(UartGuard {
        prev_sstatus,
        #[cfg(feature = "console-splice-smoke")]
        t0: crate::timebase::now(),
    })
}

/// Enable the SMP UART lock.
pub fn enable_smp_lock() {
    SMP_ACTIVE.store(true, Ordering::SeqCst);
}

// ============================================================
// `Console` — which device the console IS, as a runtime choice
// ============================================================
//
// `ns16550a` (RISC-V: QEMU/VF2/K1) and `pl011` (aarch64 QEMU `virt`) below
// share one call shape, picked at compile time by the single
// `use ns16550a as hw` / `use pl011 as hw` at "Public API" further down.
// `Console` gives the *output* half of that shape a name and each module a
// matching zero-sized `impl`, and [`console_register`] lets boot pick which
// one the ring-3 write path talks to — the same move `EthNetDevice`/
// `VirtioNetDevice` make in `crates/drivers/net/src/net_device.rs` for the NIC
// side. It does NOT touch the 18 board-level `cfg`s inside `ns16550a`
// itself (`vf2`/`k1` register stride, divisor, DLAB skip, the DW8250 LCR
// erratum workaround): those are one ISA's *register model* varying by
// board, not one *console concept* varying by ISA, and collapsing them
// would mean splitting `ns16550a` into a byte-stride and a 4-byte-stride
// impl — a real second change, out of scope here.
//
// # Why only `write_bytes`
//
// This trait used to declare eight methods (`init`/`can_write`/
// `can_read_hw`/`putc_raw`/`write_bytes`/`getc_raw`/`enable_irq`/
// `irq_handler`) and have no caller at all. `lto = false` in this
// workspace, and behind `dyn` an UNCALLED trait method is not free: it
// keeps its implementation alive through the vtable, and every declared
// method costs a shim plus a vtable slot in a build that can never call it.
// The seven methods with no caller are gone from the trait; the free
// functions they wrapped are untouched and still reached through `hw::`,
// which is still a compile-time-resolved direct call. Add a method back
// here the day something calls it, not before.
//
// # What does NOT go through this
//
// The panic path (`puts` → [`write_str_translated`], used by
// `kernel/src/panic.rs`) and `kprint!`/`kprintln!` stay on the direct,
// statically-dispatched path — see [`write_str_translated`] for why that is
// deliberate and not an oversight. Console *input* (`can_read`/`getc`) is
// also untouched: nothing routes it, so nothing declares it.
//
// The trait is the console class trait, `azos_drv_api::console::Console`.
use azos_drv_api::console::Console;

// ============================================================
// NS16550A UART (QEMU / VF2 / K1)
// ============================================================

#[cfg(target_arch = "riscv64")]
mod ns16550a {
    use super::*;

    // UART reference clock and baud-rate divisor.
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    const UART_DIVISOR: u8 = 3;   // QEMU only
    #[cfg(feature = "vf2")]
    const UART_DIVISOR: u8 = 13;  // VF2 JH7110: ~115200 baud

    // Register offsets
    const REG_THR: usize = 0;
    const REG_RBR: usize = 0;
    const REG_IER: usize = 1;
    const REG_FCR: usize = 2;
    const REG_LCR: usize = 3;
    const REG_MCR: usize = 4;
    const REG_LSR: usize = 5;

    const LSR_DATA_READY: u8 = 1 << 0;
    const LSR_THR_EMPTY: u8 = 1 << 5;
    /// Transmitter empty: FIFO and shift register both drained.
    const LSR_TEMT: u8 = 1 << 6;

    const LCR_8BITS: u8 = 0x03;
    #[cfg(not(feature = "k1"))]
    const LCR_DLAB: u8 = 1 << 7;

    const FCR_ENABLE_FIFO: u8 = 0x01;
    const FCR_CLEAR_RX: u8 = 0x02;
    const FCR_CLEAR_TX: u8 = 0x04;

    const IER_RX_AVAIL: u8 = 1 << 0;
    /// ETBEI: interrupt while the transmit holding register (with FIFOs on:
    /// the TX FIFO) is empty.
    const IER_THR_EMPTY: u8 = 1 << 1;

    // ---- Register access: byte-stride/8-bit (QEMU generic 16550) ----
    //
    // QEMU's `hw/char/serial.c` 16550 model is byte-addressed: register N
    // lives at `UART_BASE + N`, accessed with 8-bit loads/stores.
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    #[inline(always)]
    fn read_reg(reg: usize) -> u8 {
        unsafe { core::ptr::read_volatile((UART_BASE + reg) as *const u8) }
    }

    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    #[inline(always)]
    fn write_reg(reg: usize, val: u8) {
        unsafe { core::ptr::write_volatile((UART_BASE + reg) as *mut u8, val) }
    }

    // ---- Register access: 4-byte-stride/32-bit (JH7110 DW-APB-UART, K1) ----
    //
    // Real VisionFive 2 silicon: register N lives at `UART_BASE + N*4`
    // (`reg-shift = 2`) and must be accessed with 32-bit loads/stores
    // (`reg-io-width = 4`) — see the module doc comment for the source.
    // The low byte carries the same 16550-compatible register semantics;
    // the upper 24 bits are unused by this IP in 8-bit-UART mode.
    //
    // K1: its DTS node (`serial@d4017000`, `spacemit,k1-uart`,
    // `intel,xscale-uart`) declares the same `reg-shift = <2>` and
    // `reg-io-width = <4>`, so it takes this stride too. Byte-stride access
    // read the wrong register (LSR polled forever). NOT verified on K1
    // silicon: integrated behind the K1 build's `compile_error!` (owner
    // decision 2026-09-28) so it does not rot before a board exists. The
    // DW busy-detect workaround below stays VF2-only: an xscale UART is not
    // a DesignWare part.
    #[cfg(any(feature = "vf2", feature = "k1"))]
    #[inline(always)]
    fn read_reg(reg: usize) -> u8 {
        unsafe { core::ptr::read_volatile((UART_BASE + (reg << 2)) as *const u32) as u8 }
    }

    #[cfg(any(feature = "vf2", feature = "k1"))]
    #[inline(always)]
    fn write_reg(reg: usize, val: u8) {
        unsafe { core::ptr::write_volatile((UART_BASE + (reg << 2)) as *mut u32, val as u32) }
    }

    // ---- LCR write, busy-detect-safe on real DW-APB-UART silicon ----
    //
    // On a real DesignWare APB UART core (unlike QEMU's generic 16550
    // model), a write to LCR while the core is mid-transaction (e.g. a
    // frame still shifting out from U-Boot's own console use of this same
    // UART, moments before jumping to this kernel) is silently DISCARDED —
    // no fault, no indication, the register just keeps its old value. This
    // is a documented DW8250 erratum-class quirk, not specific to JH7110.
    // Faithful port of Linux's `dw8250_check_lcr` / `dw8250_idle_enter`
    // (`drivers/tty/serial/8250/8250_dw.c`, `8250_dwlib.h`): write LCR,
    // read it back (masking the stick-parity bit, irrelevant here), and if
    // it didn't take, clear the FIFOs and poll the DW-specific "UART
    // Status Register" busy bit before retrying the write once.
    // `DW_UART_USR` = register index `0x1f` (byte offset `0x7C` at this
    // IP's `reg-shift = 2`), `DW_UART_USR_BUSY = BIT(0)` — both confirmed
    // against Linux mainline `drivers/tty/serial/8250/8250_dwlib.h`
    // (fetched 2026-09-18):
    // <https://raw.githubusercontent.com/torvalds/linux/master/drivers/tty/serial/8250/8250_dwlib.h>
    #[cfg(feature = "vf2")]
    const REG_USR: usize = 0x1f;
    #[cfg(feature = "vf2")]
    const USR_BUSY: u8 = 1 << 0;
    #[cfg(feature = "vf2")]
    const LCR_SPAR: u8 = 1 << 5;

    #[cfg(feature = "vf2")]
    fn set_lcr(value: u8) {
        write_reg(REG_LCR, value);
        if (read_reg(REG_LCR) & !LCR_SPAR) == (value & !LCR_SPAR) {
            return; // write took immediately — the common case
        }
        // Write was dropped: the core was busy. Mirror dw8250_idle_enter's
        // clear-FIFO-then-poll-USR loop (4 retries, "always enough in
        // tests" per the Linux comment this is ported from) before
        // retrying the LCR write once.
        let mut retries: u8 = 4;
        loop {
            write_reg(REG_FCR, FCR_ENABLE_FIFO | FCR_CLEAR_RX | FCR_CLEAR_TX);
            if read_reg(REG_USR) & USR_BUSY == 0 {
                break;
            }
            retries -= 1;
            if retries == 0 {
                break; // give up quietly, same as Linux's write_err path
            }
            for _ in 0..256 {
                core::hint::spin_loop();
            }
        }
        write_reg(REG_LCR, value);
    }

    #[cfg(not(feature = "vf2"))]
    #[inline(always)]
    fn set_lcr(value: u8) {
        write_reg(REG_LCR, value);
    }

    pub fn init() {
        write_reg(REG_IER, 0x00);

        #[cfg(not(feature = "k1"))]
        {
            set_lcr(LCR_DLAB);
            write_reg(REG_RBR, UART_DIVISOR);
            write_reg(REG_IER, 0x00);
        }

        set_lcr(LCR_8BITS);
        write_reg(REG_FCR, FCR_ENABLE_FIFO | FCR_CLEAR_RX | FCR_CLEAR_TX);
        write_reg(REG_MCR, 0x03);
    }

    #[inline]
    pub fn can_write() -> bool {
        read_reg(REG_LSR) & LSR_THR_EMPTY != 0
    }

    #[inline]
    pub fn can_read_hw() -> bool {
        read_reg(REG_LSR) & LSR_DATA_READY != 0
    }

    pub fn putc_raw(c: u8) {
        while !can_write() {}
        write_reg(REG_THR, c);
    }

    /// Size of the 16550A transmit FIFO, enabled in [`init`] via
    /// `FCR_ENABLE_FIFO`.
    const TX_FIFO_DEPTH: usize = 16;

    /// Write a whole slice, polling the line-status register once per FIFO
    /// load instead of once per byte.
    ///
    /// `LSR_THR_EMPTY` with the FIFO on means "the transmit FIFO can accept
    /// data", not "one byte fits" — so after a single successful poll it is
    /// safe to push up to [`TX_FIFO_DEPTH`] bytes. Doing it a byte at a time
    /// costs one MMIO read per byte for no reason, and MMIO is exactly what
    /// is expensive here: under QEMU TCG every access traps to the device
    /// model, and on real hardware the poll spins until the shift register
    /// drains at the line rate.
    ///
    /// Measured from ring 3 before this existed (`userspace/bench/latbench`):
    /// `write(fd, 64 bytes)` cost 241 us against a 2.3 us syscall floor —
    /// about 3.7 us per byte, all of it MMIO polling. At 115200 baud on real
    /// hardware the same line is ~5.6 ms, against reflex's 25 ms control
    /// period.
    ///
    /// This does not make console output asynchronous — a full FIFO still
    /// blocks the caller. Fixing that properly means a TX ring drained by the
    /// THR-empty interrupt, which trades away the guarantee that a panic
    /// message reaches the wire before the board resets.
    pub fn write_bytes(bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() {
            while !can_write() {}
            let n = (bytes.len() - i).min(TX_FIFO_DEPTH);
            for &b in &bytes[i..i + n] {
                write_reg(REG_THR, b);
            }
            i += n;
        }
    }

    pub fn getc_raw() -> u8 {
        while !can_read_hw() {}
        read_reg(REG_RBR)
    }

    pub fn enable_irq() {
        IRQ_MODE.store(true, Ordering::Release);
        let ier = read_reg(REG_IER);
        write_reg(REG_IER, ier | IER_RX_AVAIL);
    }

    /// RX half of the interrupt. Returns whether it moved a byte. Only once
    /// [`enable_irq`] has switched readers to the ring: the same line now
    /// also carries the TX interrupt, and a polled console's bytes must stay
    /// in the FIFO for `getc_raw`.
    pub fn irq_handler() -> bool {
        if !IRQ_MODE.load(Ordering::Relaxed) {
            return false;
        }
        let mut any = false;
        while read_reg(REG_LSR) & LSR_DATA_READY != 0 {
            let c = read_reg(REG_RBR);
            any = true;
            if super::rx_intercept(c) {
                continue;
            }
            let head = RX_HEAD.load(Ordering::Relaxed);
            let next = (head + 1) % RX_BUF_CAP;
            if next != RX_TAIL.load(Ordering::Acquire) {
                unsafe { RX_BUF[head] = c; }
                RX_HEAD.store(next, Ordering::Release);
            }
        }
        any
    }

    /// One FIFO load from `src`, never waiting: THRE with the FIFOs on means
    /// the whole TX FIFO is empty, so up to [`TX_FIFO_DEPTH`] bytes fit;
    /// otherwise nothing is written. Returns how many bytes went.
    pub fn tx_fill(src: &[u8]) -> usize {
        if read_reg(REG_LSR) & LSR_THR_EMPTY == 0 {
            return 0;
        }
        let n = src.len().min(TX_FIFO_DEPTH);
        for &b in &src[..n] {
            write_reg(REG_THR, b);
        }
        n
    }

    /// Unmask/mask the TX-empty interrupt (ETBEI). With THRE already set,
    /// unmasking raises it at once (16550 behaviour, and QEMU's model).
    pub fn tx_irq_set(on: bool) {
        let ier = read_reg(REG_IER);
        write_reg(REG_IER, if on { ier | IER_THR_EMPTY } else { ier & !IER_THR_EMPTY });
    }

    /// Wait until the last byte has left the shift register (a reset right
    /// after would cut it on a real board).
    pub fn tx_wait_idle() {
        while read_reg(REG_LSR) & LSR_TEMT == 0 {}
    }

    /// Zero-sized [`super::Console`] adapter over the free functions above —
    /// same pattern as `EthNetDevice`/`VirtioNetDevice` in `net_device.rs`.
    pub struct Ns16550aConsole;

    impl super::Console for Ns16550aConsole {
        #[inline] fn write_bytes(&self, bytes: &[u8]) { super::tx_write_wait(bytes, false) }
    }
}

// ============================================================
// PL011 UART (aarch64 — QEMU `virt` machine)
// ============================================================
//
// The 16550 register model above has no aarch64 equivalent: QEMU's `virt`
// machine (and every real Arm SoC this tree might target later) wires a PL011
// at the platform UART base instead — a different register layout, not just
// a different address. Same public shape as `ns16550a` (`init`/`can_write`/
// `can_read_hw`/`putc_raw`/`write_bytes`/`getc_raw`/`enable_irq`/
// `irq_handler`) so the dispatch below (`use pl011 as hw` /
// `use ns16550a as hw`) stays a single, zero-cost `hw::` call site instead of
// a second copy of every function in "Public API".
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod pl011 {
    use super::*;

    // Register offsets (PrimeCell PL011 TRM, ARM DDI 0183).
    const REG_DR:    usize = 0x000; // Data register (RX/TX)
    const REG_FR:    usize = 0x018; // Flag register
    const REG_LCR_H: usize = 0x02C; // Line control
    const REG_CR:    usize = 0x030; // Control
    const REG_IMSC:  usize = 0x038; // Interrupt mask set/clear
    const REG_MIS:   usize = 0x040; // Masked interrupt status
    const REG_ICR:   usize = 0x044; // Interrupt clear

    // Flag register bits.
    const FR_RXFE: u32 = 1 << 4; // Receive FIFO empty
    const FR_TXFF: u32 = 1 << 5; // Transmit FIFO full — "one more byte fits"
                                  // is `!TXFF`, NOT the same test as the
                                  // 16550's THR-empty bit above: THRE means
                                  // "FIFO accepts data", TXFF alone means
                                  // "FIFO is full". `can_write` below is
                                  // deliberately `!TXFF`, and the FIFO-batch
                                  // write path uses TXFE (below), not TXFF,
                                  // for exactly that reason.
    const FR_TXFE: u32 = 1 << 7; // Transmit FIFO completely empty
    const FR_BUSY: u32 = 1 << 3; // Transmitting (FIFO or shift register)

    // Line control bits.
    const LCRH_FEN:     u32 = 1 << 4;      // Enable FIFOs
    const LCRH_WLEN_8:  u32 = 0b11 << 5;   // 8 data bits

    // Control register bits.
    const CR_UARTEN: u32 = 1 << 0;
    const CR_TXE:    u32 = 1 << 8;
    const CR_RXE:    u32 = 1 << 9;

    // Interrupt bits (same positions in IMSC/RIS/MIS/ICR).
    const INT_RX:  u32 = 1 << 4; // RXIM — receive FIFO
    const INT_RT:  u32 = 1 << 6; // RTIM — receive timeout (partial FIFO)
    const INT_TX:  u32 = 1 << 5; // TXIM — transmit FIFO at/below its level

    #[inline(always)]
    fn read_reg(reg: usize) -> u32 {
        unsafe { core::ptr::read_volatile((UART_BASE + reg) as *const u32) }
    }

    #[inline(always)]
    fn write_reg(reg: usize, val: u32) {
        unsafe { core::ptr::write_volatile((UART_BASE + reg) as *mut u32, val) }
    }

    /// Baud-rate divisor (`IBRD`/`FBRD`) is deliberately left unprogrammed:
    /// QEMU's PL011 model isn't timing-accurate and works at its power-on
    /// default regardless, and this tree has no confirmed input-clock
    /// frequency for a real PL011 instance to compute a divisor from —
    /// inventing one would be exactly the kind of unverified register value
    /// this project refuses to guess (see `platform::hw`'s `WDT_CLK_HZ`
    /// caveat for the same discipline applied to a different register).
    pub fn init() {
        write_reg(REG_CR, 0); // Disable while configuring.
        write_reg(REG_IMSC, 0); // All interrupts masked.
        write_reg(REG_ICR, 0x7FF); // Clear anything latched.
        write_reg(REG_LCR_H, LCRH_WLEN_8 | LCRH_FEN); // 8N1, FIFOs on.
        write_reg(REG_CR, CR_UARTEN | CR_TXE | CR_RXE);
    }

    #[inline]
    pub fn can_write() -> bool {
        read_reg(REG_FR) & FR_TXFF == 0
    }

    #[inline]
    pub fn can_read_hw() -> bool {
        read_reg(REG_FR) & FR_RXFE == 0
    }

    pub fn putc_raw(c: u8) {
        while !can_write() {}
        write_reg(REG_DR, c as u32);
    }

    /// Same FIFO depth (16 bytes) and same "poll once, push a batch"
    /// strategy as `ns16550a::write_bytes` — but gated on `FR_TXFE`
    /// (FIFO *completely* empty), not `FR_TXFF` (FIFO *not full*): "not
    /// full" only promises room for one more byte, and treating it as
    /// license to push sixteen would drop the tail of every line longer
    /// than however many slots were actually free.
    const TX_FIFO_DEPTH: usize = 16;

    pub fn write_bytes(bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() {
            while read_reg(REG_FR) & FR_TXFE == 0 {}
            let n = (bytes.len() - i).min(TX_FIFO_DEPTH);
            for &b in &bytes[i..i + n] {
                write_reg(REG_DR, b as u32);
            }
            i += n;
        }
    }

    pub fn getc_raw() -> u8 {
        while !can_read_hw() {}
        read_reg(REG_DR) as u8
    }

    pub fn enable_irq() {
        IRQ_MODE.store(true, Ordering::Release);
        let imsc = read_reg(REG_IMSC);
        write_reg(REG_IMSC, imsc | INT_RX | INT_RT);
    }

    /// RX half of the interrupt. Returns whether RX had work: RX/RX-timeout
    /// status pending, or a byte moved (a TX interrupt that finds bytes in
    /// the RX FIFO drains them, and the parked reader must still be woken).
    /// Only once [`enable_irq`] switched readers to the ring: under
    /// `pl011-rx-irq-canary` the line carries TX interrupts only and the
    /// polled console's bytes must stay in the FIFO.
    pub fn irq_handler() -> bool {
        if !IRQ_MODE.load(Ordering::Relaxed) {
            return false;
        }
        let mut any = read_reg(REG_MIS) & (INT_RX | INT_RT) != 0;
        while read_reg(REG_FR) & FR_RXFE == 0 {
            let c = read_reg(REG_DR) as u8;
            any = true;
            if super::rx_intercept(c) {
                continue;
            }
            let head = RX_HEAD.load(Ordering::Relaxed);
            let next = (head + 1) % RX_BUF_CAP;
            if next != RX_TAIL.load(Ordering::Acquire) {
                unsafe { RX_BUF[head] = c; }
                RX_HEAD.store(next, Ordering::Release);
            }
        }
        // Clear whatever RX-side status is latched (RXIM + the receive
        // timeout that fires for a partial, below-trigger-level FIFO) —
        // matches what was actually drained above.
        write_reg(REG_ICR, INT_RX | INT_RT);
        any
    }

    /// Up to [`TX_FIFO_DEPTH`] bytes from `src`, one `!TXFF` test per byte
    /// ("one more fits"), never waiting. Returns how many bytes went.
    pub fn tx_fill(src: &[u8]) -> usize {
        let mut n = 0;
        while n < src.len() && n < TX_FIFO_DEPTH && read_reg(REG_FR) & FR_TXFF == 0 {
            write_reg(REG_DR, src[n] as u32);
            n += 1;
        }
        n
    }

    /// Unmask/mask the TX interrupt. The caller primes the FIFO first
    /// ([`super::TxRing::kick`]): a PL011 raises TXRIS when its FIFO level
    /// passes the trigger level, so an interrupt is only owed once data
    /// went in. TXIC is never written: QEMU's model sets TX after every
    /// `DR` write and the next refill depends on it.
    pub fn tx_irq_set(on: bool) {
        let imsc = read_reg(REG_IMSC);
        write_reg(REG_IMSC, if on { imsc | INT_TX } else { imsc & !INT_TX });
    }

    /// Wait until the last byte has left the shift register.
    pub fn tx_wait_idle() {
        while read_reg(REG_FR) & FR_BUSY != 0 {}
    }

    /// Zero-sized [`super::Console`] adapter over the free functions above —
    /// same pattern as `Ns16550aConsole`.
    pub struct Pl011Console;

    impl super::Console for Pl011Console {
        #[inline] fn write_bytes(&self, bytes: &[u8]) { super::tx_write_wait(bytes, false) }
    }
}

// ============================================================
// x86_64 skeleton (and any further ISA): the PC's COM1 is a 16550 too, but
// behind PORT I/O (0x3F8, `in`/`out`), not MMIO, with its IRQ on IOAPIC
// GSI 4. Every body is a `todo!()` naming that; nothing here runs.
// ============================================================

#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
mod com16550_pio {
    //! COM1: polled for the boot banner and the panic path, RX by interrupt
    //! once `enable_irq` runs (the IOAPIC route is the boot hook's).
    const COM1: u16 = 0x3F8;
    const REG_THR: u16 = 0;
    const REG_IER: u16 = 1;
    const REG_FCR: u16 = 2;
    const REG_LCR: u16 = 3;
    const REG_MCR: u16 = 4;
    const REG_LSR: u16 = 5;
    const LSR_DR: u8 = 0x01;
    const LSR_THRE: u8 = 0x20;
    const LSR_TEMT: u8 = 0x40;
    const IER_RX_AVAIL: u8 = 0x01;

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn outb(reg: u16, v: u8) {
        // SAFETY: COM1's own I/O ports.
        unsafe { core::arch::asm!("out dx, al", in("dx") COM1 + reg, in("al") v, options(nomem, nostack, preserves_flags)) };
    }
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn inb(reg: u16) -> u8 {
        let v: u8;
        // SAFETY: COM1's own I/O ports.
        unsafe { core::arch::asm!("in al, dx", in("dx") COM1 + reg, out("al") v, options(nomem, nostack, preserves_flags)) };
        v
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn outb(_reg: u16, _v: u8) { todo!("port: COM1 port I/O") }
    #[cfg(not(target_arch = "x86_64"))]
    fn inb(_reg: u16) -> u8 { todo!("port: COM1 port I/O") }

    /// 115200 8N1, FIFOs on, interrupts off (polled).
    pub fn init() {
        outb(REG_IER, 0x00);
        outb(REG_LCR, 0x80);
        outb(REG_THR, 0x01);
        outb(REG_IER, 0x00);
        outb(REG_LCR, 0x03);
        outb(REG_FCR, 0xC7);
        outb(REG_MCR, 0x0B);
    }
    pub fn can_write() -> bool { inb(REG_LSR) & LSR_THRE != 0 }
    pub fn can_read_hw() -> bool { inb(REG_LSR) & LSR_DR != 0 }
    pub fn putc_raw(c: u8) {
        while !can_write() {
            core::hint::spin_loop();
        }
        outb(REG_THR, c);
    }
    pub fn write_bytes(bytes: &[u8]) {
        for &b in bytes {
            putc_raw(b);
        }
    }
    pub fn getc_raw() -> u8 { inb(REG_THR) }
    /// RX interrupts on (IER bit 0); MCR OUT2 (set by `init`) gates the
    /// line to the PIC/IOAPIC on a PC. The IOAPIC route is the boot hook's.
    pub fn enable_irq() {
        super::IRQ_MODE.store(true, super::Ordering::Release);
        outb(REG_IER, inb(REG_IER) | IER_RX_AVAIL);
    }
    /// Drain the RX FIFO into the shared ring (the 16550 MMIO back end's
    /// loop, over port I/O). True if a byte arrived.
    pub fn irq_handler() -> bool {
        if !super::IRQ_MODE.load(super::Ordering::Relaxed) {
            return false;
        }
        let mut any = false;
        while inb(REG_LSR) & LSR_DR != 0 {
            let c = inb(REG_THR);
            any = true;
            if super::rx_intercept(c) {
                continue;
            }
            let head = super::RX_HEAD.load(super::Ordering::Relaxed);
            let next = (head + 1) % super::RX_BUF_CAP;
            if next != super::RX_TAIL.load(super::Ordering::Acquire) {
                // SAFETY: single producer (this handler, interrupts off);
                // the slot is not visible to the consumer until RX_HEAD moves.
                unsafe { super::RX_BUF[head] = c; }
                super::RX_HEAD.store(next, super::Ordering::Release);
            }
        }
        any
    }
    /// Writes into free FIFO room only (THRE: the 16-byte FIFO is empty).
    pub fn tx_fill(src: &[u8]) -> usize {
        if !can_write() {
            return 0;
        }
        let n = src.len().min(16);
        for &b in &src[..n] {
            outb(REG_THR, b);
        }
        n
    }
    /// Polled: there is no TX interrupt to arm yet.
    pub fn tx_irq_set(_on: bool) {}
    pub fn tx_wait_idle() {
        while inb(REG_LSR) & LSR_TEMT == 0 {
            core::hint::spin_loop();
        }
    }

    /// The x86 console: same driver shape as the MMIO 16550.
    pub struct Com16550Console;
    impl super::Console for Com16550Console {
        #[inline] fn write_bytes(&self, bytes: &[u8]) { super::tx_write_wait(bytes, false) }
    }
}

// The single dispatch point "Public API" below calls through: RISC-V's
// 16550 path is untouched, aarch64 gets PL011, and both compile to a direct
// call with no vtable/indirection (`hw::` resolves to one module per
// target, so this costs nothing beyond what naming `ns16550a::` directly
// already cost).
#[cfg(target_arch = "riscv64")]
use ns16550a as hw;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use pl011 as hw;
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
use com16550_pio as hw;

/// The [`Console`] this build's platform UART is.
///
/// A `static`, not a `const`: `kernel_main` passes `&CONSOLE` to
/// [`console_register`], which wants a `&'static dyn Console`, and a
/// `static` gives that without leaning on rvalue static promotion of a
/// const's temporary. It is a zero-sized type, so the `static` itself
/// occupies no bytes.
///
/// Naming it directly (`write_translated(&CONSOLE, ..)` in
/// [`write_str_translated`]) is a *static* dispatch — the generic
/// monomorphizes to this concrete type and inlines straight to `hw::
/// write_bytes`. Only [`console_write`] pays a vtable.
#[cfg(target_arch = "riscv64")]
pub static CONSOLE: ns16550a::Ns16550aConsole = ns16550a::Ns16550aConsole;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub static CONSOLE: pl011::Pl011Console = pl011::Pl011Console;
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub static CONSOLE: com16550_pio::Com16550Console = com16550_pio::Com16550Console;

/// Gate-only: a [`Console`] that prefixes every write with `CANARY>`.
///
/// **Why this exists at all.** The console abstraction is otherwise
/// untestable. `console_write` falls back to the direct path when nothing is
/// registered, which is a correctness property — an early-boot ring-3 write
/// still reaches the wire — but it means a build with the registration
/// REMOVED produces byte-identical output. "It still works" would prove
/// nothing, so the gate needs a console whose effect is visible.
///
/// With this registered, two things must hold at once and the row checks
/// both: a ring-3 `write(1, ...)` comes out prefixed, and the kernel's own
/// `kprintln!` does NOT — that second half is what proves the panic path is
/// still on the direct route, which is the property that matters when a
/// panic handler has to print.
///
/// Never enabled in a shipping build; `kernel/Cargo.toml` gates it behind
/// `console-route-canary`, which also pulls `qemu`.
///
/// U07-1: [`console_write_ring3`] has not always called `write_bytes` once
/// per line (until wave 9 it was once per 16-byte FIFO load), so prefixing
/// every CALL would splice `CANARY>` into the middle of a line whenever a
/// writer splits one. [`CANARY_AT_LINE_START`] makes the prefix a per-LINE
/// property: it is set after every `write_bytes` call to whether that call's
/// last byte was `\r` (true only for the `"\n\r"` piece [`write_translated`]
/// emits at a real newline), so a line split across several calls gets
/// exactly one prefix.
#[cfg(feature = "console-route-canary")]
pub struct CanaryConsole;

/// See [`CanaryConsole`]'s doc. Starts `true` so the very first byte this
/// console ever writes is prefixed with no write having happened yet.
///
/// **Process-wide, not per-task.** A task that writes a line with no
/// trailing `\n` leaves this `false`; the NEXT write through this console —
/// from any task — starts unprefixed until a real newline sets it back to
/// `true`. Harmless for what this console exists to prove (gate-only, one
/// probe program, `tools/ci_check.sh`'s `console-route-canary` row), but not
/// a general per-line guarantee across multiple ring-3 writers.
#[cfg(feature = "console-route-canary")]
static CANARY_AT_LINE_START: AtomicBool = AtomicBool::new(true);

#[cfg(feature = "console-route-canary")]
impl Console for CanaryConsole {
    fn write_bytes(&self, bytes: &[u8]) {
        if CANARY_AT_LINE_START.load(Ordering::Relaxed) {
            tx_write_wait(b"CANARY>", false);
        }
        tx_write_wait(bytes, false);
        CANARY_AT_LINE_START.store(bytes.ends_with(b"\r"), Ordering::Relaxed);
    }
}

/// The canary console instance — see [`CanaryConsole`].
#[cfg(feature = "console-route-canary")]
pub static CANARY_CONSOLE: CanaryConsole = CanaryConsole;

// ---- Which device is the console: registered at boot ----
//
// Mechanism copied from `crates/core/sync/src/waitqueue.rs`'s
// `wq_set_callbacks` — a boot-time registration read through an atomic —
// rather than `crates/core/arch-api`'s `ARCH` singleton, because `ARCH` is a
// compile-time constant the ISA picks and this has to be a *choice*: the
// point of the trait is that the console can be something other than the
// platform UART without the ring-3 write path knowing. It differs from
// `wq_set_callbacks` in storing a trait object instead of three `fn`
// pointers, because there is one implementation with one method, and a
// `&dyn Console` keeps the "this is a device" shape that a bare
// `fn(&[u8])` would throw away.
//
// A `dyn` reference is a fat pointer and there is no `AtomicFatPtr`, so the
// reference lives in a `static mut` and an `AtomicBool` carries the
// happens-before edge: `console_register` publishes with a `Release` store
// after the write, every reader `Acquire`-loads before the read. The write
// is a place write and the read a place copy — no `&`/`&mut` to the
// `static mut` is ever formed, which is what `static_mut_refs` forbids.
static mut CONSOLE_IMPL: Option<&'static dyn Console> = None;

/// Set once `CONSOLE_IMPL` is published. Before that, every console write
/// falls back to the direct path, which is what makes early boot (and the
/// panic path, which never consults this at all) work with no registration.
static CONSOLE_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Register which device is the console.
///
/// # Contract
///
/// Called once, from `kernel_main` on the boot hart, before
/// [`enable_smp_lock`] brings a second hart into the console path. Calling
/// it later is not unsound — the `Release`/`Acquire` pair below orders it —
/// but a write racing another hart's read would let one line go to the old
/// device and the next to the new one.
pub fn console_register(console: &'static dyn Console) {
    unsafe { CONSOLE_IMPL = Some(console) };
    CONSOLE_REGISTERED.store(true, Ordering::Release);
}

/// The registered console, or `None` if boot has not registered one yet.
#[inline]
fn registered_console() -> Option<&'static dyn Console> {
    if !CONSOLE_REGISTERED.load(Ordering::Acquire) {
        return None;
    }
    // Copies the value out of the place. Never `&CONSOLE_IMPL`.
    unsafe { CONSOLE_IMPL }
}

// ============================================================
// Public API (dispatches to platform module)
// ============================================================

/// UART0 interrupt number.
///
/// RISC-V / PLIC: QEMU `virt` machine external interrupt 10
/// (`hw/riscv/virt.c`'s `VIRT_UART0_IRQ`). Real JH7110 UART0: interrupt 32
/// — confirmed against StarFive's `u-boot` tree,
/// `arch/riscv/dts/jh7110.dtsi`, `uart0@10000000`'s `interrupts` property
/// (fetched 2026-09-18, same source as the register-stride fix above).
/// K1's real UART0 IRQ number has not been independently verified in this
/// pass — kept on the QEMU-shaped default (out of scope until board
/// bring-up).
#[cfg(all(target_arch = "riscv64", not(feature = "vf2")))]
pub const UART_IRQ: u32 = 10;
#[cfg(all(target_arch = "riscv64", feature = "vf2"))]
pub const UART_IRQ: u32 = 32;
/// aarch64 / GICv3: QEMU `virt` wires the PL011 to SPI 1 — INTID =
/// (32 = first SPI) + 1 = 33, the standard, widely-documented `virt`
/// mapping. Not yet independently re-derived from a fetched `virt.c` the
/// way the RISC-V numbers above were.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub const UART_IRQ: u32 = 33;
/// x86_64 skeleton: COM1 is legacy IRQ 4, an IOAPIC GSI (placeholder until
/// the port routes it).
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub const UART_IRQ: u32 = 4;

/// Set by the first [`init`]; see its doc for why later calls must not reach
/// the hardware.
static HW_INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Initialize the UART hardware. Only the first call programs the device;
/// every later call returns without touching it.
///
/// A second `hw::init()` is not harmless. Both back ends start by masking
/// every UART interrupt (16550: `IER = 0`; PL011: `IMSC = 0`), and neither
/// clears `IRQ_MODE`. Once [`enable_irq`] has run, that leaves [`can_read`]
/// polling a ring buffer the ISR can no longer fill: received bytes sit in
/// the hardware FIFO and the console stops answering.
///
/// That is what silenced the riscv64 shell: the driver-registry smoke in
/// `kernel_main` calls `UartDriver::init`, whose own `initialized` flag
/// starts `false`, so it ran `hw::init()` a second time, after the boot hook
/// had enabled the RX interrupt (observed: two calls, `IER = 0x1` on entry
/// to the second, `IER = 0x0` afterwards, `LSR.DR = 1` with the ring empty).
///
/// Consequence for `UartDriver::shutdown` followed by `init`: the device is
/// not reprogrammed. The console is live from the first line the kernel
/// prints until reset, and nothing here powers it down.
pub fn init() {
    if HW_INIT_DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    hw::init();
}

/// Returns true if the transmitter is ready.
#[inline]
pub fn can_write() -> bool {
    hw::can_write()
}

/// Returns true if there is data ready to read.
#[inline]
pub fn can_read() -> bool {
    if IRQ_MODE.load(Ordering::Relaxed) {
        RX_TAIL.load(Ordering::Relaxed) != RX_HEAD.load(Ordering::Acquire)
    } else {
        hw::can_read_hw()
    }
}

/// Write a single byte to the UART (blocking).
pub fn putc(c: u8) {
    hw::putc_raw(c);
    if c == b'\n' {
        putc(b'\r');
    }
}

/// Read a single byte from the UART (blocking).
pub fn getc() -> u8 {
    if IRQ_MODE.load(Ordering::Relaxed) {
        loop {
            if let Some(c) = try_getc() { return c; }
            core::hint::spin_loop();
        }
    } else {
        hw::getc_raw()
    }
}

/// Write a string to the UART **without taking the console lock**.
///
/// # This is the panic path's writer, and only that
///
/// `kernel/src/panic.rs` uses it deliberately: a panicking hart cannot afford
/// to spin on a lock another hart is holding, because the lock holder may be
/// the thing that just died. Its doc says so at `panic.rs:10`.
///
/// **Everything else wants [`puts_locked`].** An unlocked write splices into
/// whatever another hart is printing, and `crates/core/syscall`'s console arm
/// already records why that is not merely ugly: "the CI scenarios grep this
/// output, and a spliced line makes a passing run look like a failing one."
///
/// It happened: gate 114's `seccomp: replaced image is refused` went red with
/// the refusal having worked, because the shell's `robot> ` prompt — written
/// through here — landed between `REFUSED` and `: /fat/UHELLO.ELF`, and the
/// row's fixed-string marker spans exactly that point.
///
/// # Not through `Console`, deliberately
///
/// It writes through [`write_str_translated`], which names [`CONSOLE`]
/// statically: no lock, no vtable, no registration. A panicking hart must
/// reach the wire by the most direct route that exists — see
/// [`write_str_translated`]'s own doc.
pub fn puts(s: &str) {
    write_str_translated(s.as_bytes());
}

/// Write a string to the UART as one kernel line (see [`kernel_print`]).
///
/// The [`puts`] every non-panic caller should use: one writer at a time, so a
/// line cannot be spliced by another hart mid-marker, and it defers while
/// ring 3 owns the console like every other kernel writer.
pub fn puts_locked(s: &str) {
    write_locked(s.as_bytes());
}

/// [`puts_locked`] for bytes: the kernel shell's listings and echo.
/// Straight to the wire when nobody owns the console and nothing is
/// deferred, so a key echo is still immediate then.
pub fn write_locked(bytes: &[u8]) {
    kernel_emit(&mut |sink: &mut dyn FnMut(&[u8])| sink(bytes));
}

/// [`write_locked`] for one byte (the shell's single-character echo).
pub fn putc_locked(c: u8) {
    write_locked(&[c]);
}

/// Print formatted kernel output: what `kprint!`/`kprintln!` expand to
/// (`newline` adds the `\n` inside the same line). See [`kernel_emit`].
pub fn kernel_print(args: fmt::Arguments<'_>, newline: bool) {
    // Format BEFORE the console lock (wave 13, RT7). The lock hold masks
    // interrupts, and formatting inside it was the longest masked window on
    // a hart: 9.7 us per WCET/report line under -icount (lat-trace, site
    // `uart.rs` try_acquire..drop), longer than the timer-ISR entry, and
    // what made a 1 ms RT waker's worst wake later than Linux's. Formatted
    // here, the hold is a copy of at most `PREFORMAT_BYTES`. A longer line
    // falls back to formatting inside the hold, as before (rare, and
    // still one line, unsplit). `console-format-in-lock` (gate canary)
    // keeps the old path for every line.
    if !cfg!(feature = "console-format-in-lock") {
        let mut line = PreFormatted { buf: [0u8; PREFORMAT_BYTES], len: 0, overflow: false };
        let _ = fmt::Write::write_fmt(&mut line, args);
        if newline {
            let _ = fmt::Write::write_str(&mut line, "\n");
        }
        if !line.overflow {
            let bytes = &line.buf[..line.len];
            kernel_emit(&mut |sink: &mut dyn FnMut(&[u8])| sink(bytes));
            return;
        }
        PREFORMAT_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    }
    kernel_emit(&mut |sink: &mut dyn FnMut(&[u8])| {
        let _ = fmt::Write::write_fmt(&mut Sink(&mut *sink), args);
        if newline {
            sink(b"\n");
        }
    });
}

/// Longest kernel line [`kernel_print`] formats outside the console lock.
pub const PREFORMAT_BYTES: usize = 256;

/// Lines longer than [`PREFORMAT_BYTES`], formatted inside the lock instead.
pub static PREFORMAT_OVERFLOWS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// One kernel line formatted into a stack buffer (see [`kernel_print`]).
struct PreFormatted {
    buf: [u8; PREFORMAT_BYTES],
    len: usize,
    overflow: bool,
}

impl fmt::Write for PreFormatted {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let b = s.as_bytes();
        if self.len + b.len() > PREFORMAT_BYTES {
            self.overflow = true;
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }
}

/// A `core::fmt::Write` over one line's sink.
struct Sink<'a>(&'a mut dyn FnMut(&[u8]));

impl fmt::Write for Sink<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        (self.0)(s.as_bytes());
        Ok(())
    }
}

/// One kernel line, `emit` producing its bytes: the protocol is
/// [`crate::console_defer::kernel_print`]. A caller with interrupts on
/// (task context: syscalls run with them on, interrupt handlers with them
/// off) and no spinlock held (preemption depth 0) that finds a residual
/// drains it as the console's owner, interrupts ON, holding
/// [`CONSOLE_LINE_LOCK`] like a ring-3 owner — tried, never waited for.
/// Every other caller helps with at most one chunk and defers.
/// Under bypass (a halt, a panic, a reboot) the line goes straight to the
/// wire under the UART lock, ignoring ownership.
fn kernel_emit(emit: &mut dyn FnMut(&mut dyn FnMut(&[u8]))) {
    // Sampled BEFORE any lock: `acquire` masks interrupts, and the line
    // lock's own state lock raises the preemption depth.
    let may_own = crate::console_defer::may_own(
        azos_arch::ARCH.interrupts_enabled(),
        azos_sync::preempt::depth(),
    );
    if BYPASS.load(Ordering::Relaxed) {
        let _guard = acquire();
        // SAFETY: `_guard` holds the UART lock.
        unsafe { tx_state() }.flush_sync();
        emit(&mut |b: &[u8]| write_str_translated(b));
        return;
    }
    crate::console_defer::kernel_print(
        &KernelDeferLock::<false>,
        may_own,
        || CONSOLE_LINE_LOCK.try_lock(),
        &mut KernelWire,
        emit,
    );
}

/// Write bytes to `console`, expanding `\n` to `\r\n`, using the FIFO-aware
/// batched path. Splits the input at newlines so the CRLF translation that
/// [`putc`] does per byte is preserved without paying a line-status poll per
/// byte.
///
/// Generic over `?Sized` so the two callers share one copy of this logic
/// and still get the dispatch each of them needs: [`write_str_translated`]
/// instantiates it at the concrete [`CONSOLE`] type (static, inlined,
/// identical code to the `hw::write_bytes` calls this used to make
/// directly), [`console_write`] instantiates it at `dyn Console` (one
/// indirect call per chunk). Writing the splitter twice — once direct, once
/// through the trait — is exactly how the two would drift apart.
#[inline]
fn write_translated<C: Console + ?Sized>(console: &C, bytes: &[u8]) {
    let mut start = 0;
    for i in 0..bytes.len() {
        if bytes[i] == b'\n' {
            console.write_bytes(&bytes[start..i]);
            console.write_bytes(b"\n\r");
            start = i + 1;
        }
    }
    if start < bytes.len() {
        console.write_bytes(&bytes[start..]);
    }
}

/// Write bytes to the platform UART, expanding `\n` to `\r\n`.
///
/// # This is the direct path, and the panic path depends on it
///
/// It names [`CONSOLE`] statically and **never consults
/// [`console_register`]**: no atomic load, no vtable, no registration to
/// have happened. `kernel/src/panic.rs` reaches here through [`puts`], and
/// a panic handler that printed through a registered implementation would
/// print nothing in the two cases that matter most — a panic before
/// registration runs, and a panic *inside* whatever was registered. The
/// same reasoning keeps `kprint!`/`kprintln!` here: they are the kernel's
/// own diagnostics, including the ones a fault handler emits.
///
/// Ring-3 writes go through [`console_write`] instead.
pub fn write_str_translated(bytes: &[u8]) {
    #[cfg(feature = "console-splice-smoke")]
    lock_probe::wire(bytes.len());
    write_translated(&DirectHw, bytes);
}

/// The platform UART with no TX ring in between: [`CONSOLE`]'s impl now
/// queues ring 3's bytes into the TX ring (wave 11), and the direct path
/// must not — it is the panic/halt/reset writer and the pre-interrupt one.
struct DirectHw;

impl Console for DirectHw {
    #[inline]
    fn write_bytes(&self, bytes: &[u8]) {
        hw::write_bytes(bytes)
    }
}

/// Write bytes to whichever device boot registered as the console,
/// expanding `\n` to `\r\n`.
///
/// The [`Console`]-dispatched write with no ownership protocol. Nothing in
/// the kernel calls it today: `sys_write` to fd 1/2 goes through
/// [`console_write_ring3`]. It takes no line lock and does not own the
/// console, so a kernel line may land inside its bytes; and since wave 11
/// the platform [`Console`] impls queue into the TX ring and take the UART
/// lock themselves, so it must NOT be called with that lock held.
///
/// Falls back to the direct [`write_str_translated`] path when nothing has
/// been registered, so a ring-3 write during early boot still reaches the
/// wire. That fallback is also why an unapplied registration produces
/// byte-identical output: it is a correctness property, not a test.
pub fn console_write(bytes: &[u8]) {
    match registered_console() {
        Some(console) => write_translated(console, bytes),
        None => write_str_translated(bytes),
    }
}

/// Write a ring-3 `write(1|2, ..)` to the console: the whole write is one
/// piece on the wire against every kernel print but the lock-free ones.
///
/// # Ownership, not a held lock (wave 9)
///
/// The caller becomes the console's OWNER (see [`crate::console_defer`] for
/// the protocol and why): it takes the UART spinlock only to flip ownership
/// and to copy deferred kernel bytes out, never across wire time, and writes
/// its own bytes with interrupts ON. A `kprint!`/`kprintln!` from any hart
/// or any interrupt handler that runs meanwhile finds the console owned and
/// appends its line to [`DEFER`] instead of touching the UART; this function
/// puts those lines on the wire after each ring-3 line and gives the console
/// back only when none are left (bounded by `DRAIN_BUDGET`; a residual is
/// drained by the next kernel print, ahead of its own line, with interrupts
/// on in task context — see [`kernel_emit`]).
///
/// Before this, the ring-3 bytes went out in 16-byte pieces under one
/// `acquire()` each, and gate 192b's `ipc: census counters zero` read
/// `[IPCTEST] ALL PA[SCHED-DBG]   ASKS-SCHED ...`: a timer-ISR `kprintln!`
/// in the gap after byte 16. An ISR print, so no task-context lock could
/// have excluded it — only ownership that interrupt handlers defer to does.
///
/// Interrupts are masked on this hart only for the lock holds: the flip, and
/// each drain step's copy of at most `DRAIN_CHUNK` bytes — shorter than the
/// old 16-byte FIFO load. Since wave 11 the bytes themselves go into the TX
/// ring ([`tx_write_wait`]) and this returns once they are queued, not once
/// they are on the wire. `console-splice-smoke`'s `[SPLICE] DONE` line
/// reports the longest and the total per call.
///
/// # Ownership cannot leak
///
/// It ends only when this function returns, or at a halt
/// ([`console_bypass_for_halt`]). As of 2026-09-28 no path ends a task inside
/// a syscall from another hart: `SYS_KILL` only sets pending bits nothing
/// delivers (`crates/core/ipc/src/signal.rs`), and every kill is the task's own
/// user-mode trap. `sys_write` copies from ring 3 before calling this, so a
/// bad user pointer returns before ownership is taken. **Invariant for later
/// work:** anything that can end a task inside a syscall (signal delivery, a
/// supervisor kill) must release console ownership and `CONSOLE_LINE_LOCK`
/// on that exit path — a leaked ownership silences every kernel print.
///
/// # What can still splice
///
/// * A line a program builds from several `write` calls (`libsys`'s
///   `print` + `print` + `println`): between two syscalls the console is not
///   owned.
/// * The lock-free writer: [`puts`] (the panic path, by design). `sys_putchar`
///   and `vfs`'s `/dev/stdout` come through here, and `uart_driver`'s write
///   op and the kernel shell through [`write_locked`]/[`putc_locked`]
///   (wave 11; [`putc`] has no caller left in the kernel).
pub fn console_write_ring3(bytes: &[u8]) {
    let _line = CONSOLE_LINE_LOCK.lock();
    #[cfg(feature = "console-splice-smoke")]
    let t_call = ring3_probe::start();
    let console: &dyn Console = match registered_console() {
        Some(console) => console,
        None => &CONSOLE,
    };
    crate::console_defer::owner_write(
        &KernelDeferLock::<true>,
        bytes,
        // `owner_write` cuts after the only `\n` a piece can hold, so no
        // second scan: the body, then the `"\n\r"` `CanaryConsole` keys its
        // per-line prefix on (the shape `write_translated` produces).
        &mut |line: &[u8]| match line.split_last() {
            Some((&b'\n', body)) => {
                if !body.is_empty() {
                    console.write_bytes(body);
                }
                console.write_bytes(b"\n\r");
            }
            _ => console.write_bytes(line),
        },
        &mut |deferred: &[u8]| tx_write_wait(deferred, true),
    );
    #[cfg(feature = "console-splice-smoke")]
    ring3_probe::end_call(t_call);
}

/// Kernel lines deferred while ring 3 owns the console.
///
/// Sized against measurements (2026-09-28), not by feel: the `ipc-census`
/// dump's `console defer hwm=` line peaked at 3072 B over fifteen `ipc:
/// census counters zero` boots (bursts of ISR census lines landing while a
/// ring-3 line is out); the aarch64 `-smp 2` splice smoke, a stress run,
/// overflowed 4 KiB once (4 lines dropped, owner preempted for 155 ms) and
/// peaked at 4257 B in three runs at 8 KiB. A drop fails every gate row
/// (`[CONSOLE] dropped` is in `QEMU_FAIL_RE`), so 8 KiB: 2.7x the census
/// peak, 1.9x the stress peak. The time an owner spends draining is bounded
/// separately (`console_defer::DRAIN_BUDGET`), not by this.
/// Kconfig `CONSOLE_DEFER_BYTES` (default 8192).
pub const DEFER_BYTES: usize = azos_limits::CONSOLE_DEFER_BYTES;

struct DeferCell(core::cell::UnsafeCell<crate::console_defer::ConsoleDefer<DEFER_BYTES>>);
// SAFETY: every access is under the UART spinlock (see `defer_state`).
unsafe impl Sync for DeferCell {}

static DEFER: DeferCell = DeferCell(core::cell::UnsafeCell::new(
    crate::console_defer::ConsoleDefer::new(),
));

/// [`crate::console_defer::ConsoleDefer::stranded`], published after every
/// change of the deferred state (always under the UART lock) so the idle
/// loop can test it with one relaxed load and no lock
/// ([`console_idle_drain`]). A stale read costs one idle pass of delay, or
/// one drain attempt that finds nothing.
static STRANDED: AtomicBool = AtomicBool::new(false);

#[inline]
fn publish(st: &crate::console_defer::ConsoleDefer<DEFER_BYTES>) {
    STRANDED.store(st.stranded(), Ordering::Relaxed);
}

/// Whether a console residual is stranded (one relaxed load): an idle hart
/// must then not sleep to its ceiling (`timebase::set_next_tick_tickless`).
#[inline]
pub fn console_stranded() -> bool {
    STRANDED.load(Ordering::Relaxed)
}

/// Idle loop, every pass (task context, no lock held): drain a residual that
/// a budget-limited release left with no later writer to carry it — on a
/// quiet system it would otherwise wait for the next print. One relaxed load
/// when nothing is stranded.
#[inline]
pub fn console_idle_drain() {
    let stranded = STRANDED.load(Ordering::Relaxed);
    if !stranded {
        return;
    }
    if BYPASS.load(Ordering::Relaxed) {
        return;
    }
    #[cfg(feature = "console-splice-smoke")]
    lock_probe::IDLE_DRAINS.fetch_add(1, Ordering::Relaxed);
    crate::console_defer::idle_drain(
        &KernelDeferLock::<false>,
        stranded,
        || CONSOLE_LINE_LOCK.try_lock(),
        &mut KernelWire,
    );
}

/// Set for good by a halt or a panic: from then on kernel output ignores
/// ownership and goes straight to the wire, so the last lines before a
/// halt are never parked behind an owner that will not run again.
static BYPASS: AtomicBool = AtomicBool::new(false);

/// # Safety
/// The caller holds the UART lock (an [`acquire`] or [`try_acquire`] guard)
/// and does not keep the reference past it.
#[inline]
unsafe fn defer_state() -> &'static mut crate::console_defer::ConsoleDefer<DEFER_BYTES> {
    unsafe { &mut *DEFER.0.get() }
}

// ============================================================
// TX ring: the UART fed by its TX interrupt (wave 11)
// ============================================================
//
// Before this, every byte reached the UART from the writer itself, spinning
// on the FIFO between loads. For a kernel line that spin ran inside the UART
// spinlock hold, interrupts masked: up to one line, or one 128-byte
// [`crate::console_defer::DRAIN_CHUNK`], of wire time (≈ 11 ms per 128 B at
// 115200 baud on the real boards). Now writers copy into this ring under the
// lock and the UART's own TX-empty interrupt moves it to the FIFO. No writer
// waits for the wire with interrupts masked:
//
// * Under the lock ([`KernelWire::put`]: kernel lines, a helper's chunk,
//   `wcet`'s ISR report): take what fits, never wait. What does not fit is
//   deferred by `console_defer` exactly as a line written while ring 3 owns
//   the console, and drained by the same machinery (a later writer, the idle
//   loop, or [`tx_irq`] itself, which pulls the next chunk of a stranded
//   residual when it refills).
// * An owner (ring 3, or a kernel writer draining a residual), lock released
//   ([`tx_write_wait`]): copies a piece per hold and waits for room only with
//   the lock released, in the caller's interrupt state. While it waits it
//   puts one FIFO load out itself if the FIFO has room, so a stalled or lost
//   interrupt delays output and never strands a task.
// * The interrupt ([`tx_irq`]): writes only what the FIFO takes at that
//   moment, never waiting — on a real UART one FIFO's worth per interrupt.
//   Under QEMU the UART transmits instantly and THRE/TX comes back at once,
//   so "while it takes more" would empty the whole ring inside one masked
//   handler; [`TX_IRQ_BUDGET`] bounds that. The price under QEMU is a run of
//   back-to-back interrupts on the boot hart until the ring is empty.
// * Synchronous, by design: the panic path ([`puts`], [`console_enter_bypass`]),
//   halts ([`console_bypass_for_halt`]) and resets ([`console_flush_for_reboot`]).
//   Each first empties the ring to the FIFO (it is older output), then
//   writes straight to the wire.
//
// Until [`enable_tx_irq`] (the boot hook that wires the UART interrupt), and
// for good once [`BYPASS`] is set, every path is the synchronous one it was
// before. The ring is guarded by the UART spinlock, like [`DEFER`].

/// TX ring size. A ring-3 writer that outruns the wire waits for room (with
/// interrupts on); a kernel line that does not fit is deferred, not dropped,
/// so this bounds latency of queued output, not correctness: ≈ 0.36 s of
/// wire at 115200 baud. Kconfig `CONSOLE_TX_RING_BYTES` (default 4096).
pub const TX_RING_BYTES: usize = azos_limits::CONSOLE_TX_RING_BYTES;

/// Bytes an owner copies into the ring per UART lock hold.
const TX_OWNER_PIECE: usize = 256;

/// Most bytes a writer's hold moves to the FIFO (priming it, or putting
/// one load out itself while it waits for ring room): one 16-byte FIFO.
const TX_KICK_BUDGET: usize = 16;

/// Most bytes one TX interrupt moves to the FIFO. On a real UART the FIFO
/// fills first (16 bytes), so this never binds; under QEMU, which transmits
/// instantly, it is the bound. One FIFO per interrupt there cost ten times
/// the throughput the console had before (aarch64 smoke, 2026-10-02: the
/// ring stayed full and the ring-3 writer stalled), so 256: the interrupt's
/// FIFO writes take the place of the old writer's, which ran under the
/// same lock with interrupts masked too, never with a wait in between.
/// Kconfig `CONSOLE_TX_IRQ_BUDGET` (default 256).
const TX_IRQ_BUDGET: usize = azos_limits::CONSOLE_TX_IRQ_BUDGET;

pub(crate) struct TxRing {
    buf: [u8; TX_RING_BYTES],
    head: usize,
    len: usize,
    /// The TX interrupt is unmasked at the device. Invariant outside a hold:
    /// `len > 0` implies `active` while [`tx_async`] holds.
    active: bool,
    hwm: usize,
    irqs: u64,
}

struct TxCell(core::cell::UnsafeCell<TxRing>);
// SAFETY: every access is under the UART spinlock (see `tx_state`).
unsafe impl Sync for TxCell {}

static TX: TxCell = TxCell(core::cell::UnsafeCell::new(TxRing {
    buf: [0; TX_RING_BYTES],
    head: 0,
    len: 0,
    active: false,
    hwm: 0,
    irqs: 0,
}));

/// Set once by [`enable_tx_irq`]: the UART interrupt is wired to a hart and
/// its handler calls [`irq_handler`].
static TX_ASYNC: AtomicBool = AtomicBool::new(false);

/// # Safety
/// The caller holds the UART lock and does not keep the reference past it,
/// nor alongside another one from this function.
#[inline]
unsafe fn tx_state() -> &'static mut TxRing {
    unsafe { &mut *TX.0.get() }
}

#[inline]
fn tx_async() -> bool {
    TX_ASYNC.load(Ordering::Relaxed) && !BYPASS.load(Ordering::Relaxed)
}

/// Length on the wire of `bytes` once `\n` becomes `\n\r`.
fn translated_len(bytes: &[u8]) -> usize {
    bytes.len() + bytes.iter().filter(|&&b| b == b'\n').count()
}

impl TxRing {
    #[inline]
    fn free(&self) -> usize {
        TX_RING_BYTES - self.len
    }

    #[inline]
    /// Append `b` (which fits: the caller checked `free`), wrapping once.
    fn copy_in(&mut self, b: &[u8]) {
        let t = (self.head + self.len) % TX_RING_BYTES;
        let first = (TX_RING_BYTES - t).min(b.len());
        self.buf[t..t + first].copy_from_slice(&b[..first]);
        self.buf[..b.len() - first].copy_from_slice(&b[first..]);
        self.len += b.len();
    }

    fn push(&mut self, b: u8) {
        let t = (self.head + self.len) % TX_RING_BYTES;
        self.buf[t] = b;
        self.len += 1;
    }

    fn consume(&mut self, n: usize) {
        self.head = (self.head + n) % TX_RING_BYTES;
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
        }
    }

    /// Copy the longest prefix of `bytes` that fits (a `\n` only together
    /// with its `\r`). Returns how many input bytes went in.
    ///
    /// Runs without a `\n` go in as at most two block copies (wave 13, RT7):
    /// this runs under the UART lock with interrupts masked, and the old
    /// byte-at-a-time push made a 230-byte report line a 3.5 us masked
    /// window under -icount.
    fn put(&mut self, bytes: &[u8], translate: bool) -> usize {
        let mut i = 0;
        while i < bytes.len() {
            let run_end = if translate {
                bytes[i..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |p| i + p)
            } else {
                bytes.len()
            };
            if run_end > i {
                let n = (run_end - i).min(self.free());
                if n == 0 {
                    break;
                }
                self.copy_in(&bytes[i..i + n]);
                i += n;
                if i < run_end {
                    break; // the ring is full
                }
                continue;
            }
            // `bytes[i]` is a `\n`: it goes in only together with its `\r`.
            if self.free() < 2 {
                break;
            }
            self.push(b'\n');
            self.push(b'\r');
            i += 1;
        }
        if self.len > self.hwm {
            self.hwm = self.len;
        }
        i
    }

    /// Move what the FIFO takes right now, at most `budget` bytes, never
    /// waiting: `hw::tx_fill` writes only into free FIFO slots and stops at
    /// the first full one. On a real UART that is one FIFO's worth at most,
    /// whatever the budget (the line drains it at the baud rate). QEMU
    /// transmits instantly, so there the budget is what bounds it.
    fn fill(&mut self, budget: usize) -> usize {
        let mut moved = 0;
        while self.len > 0 && moved < budget {
            let end = (self.head + self.len).min(TX_RING_BYTES).min(self.head + (budget - moved));
            let n = hw::tx_fill(&self.buf[self.head..end]);
            if n == 0 {
                break;
            }
            self.consume(n);
            moved += n;
        }
        #[cfg(feature = "console-splice-smoke")]
        lock_probe::fill(moved);
        moved
    }

    /// Start transmission if it is idle: prime the FIFO (a PL011 interrupt
    /// is only owed once data went in), then unmask the TX interrupt — even
    /// if the FIFO took everything. That costs one interrupt that finds the
    /// ring empty and masks it again, and it is what keeps this to ONE FIFO
    /// load per hold: under QEMU the FIFO is empty again at once, and a
    /// kernel line arrives in several pieces, each of which would otherwise
    /// prime it again — the whole line on the wire inside one hold.
    fn kick(&mut self) {
        if self.active || self.len == 0 {
            return;
        }
        self.fill(TX_KICK_BUDGET);
        hw::tx_irq_set(true);
        self.active = true;
    }

    /// Everything queued straight to the wire, spinning on the FIFO: the
    /// halt, panic and reset paths only, lock held.
    fn flush_sync(&mut self) {
        while self.len > 0 {
            let end = (self.head + self.len).min(TX_RING_BYTES);
            let n = end - self.head;
            hw::write_bytes(&self.buf[self.head..end]);
            #[cfg(feature = "console-splice-smoke")]
            lock_probe::wire(n);
            self.consume(n);
        }
        if self.active {
            hw::tx_irq_set(false);
            self.active = false;
        }
    }
}

/// The kernel's [`crate::console_defer::Wire`]: under the UART lock, a
/// prefix into the TX ring (or, before [`enable_tx_irq`] and in bypass,
/// the synchronous write it always was); with the lock released, all of it,
/// waiting for room ([`tx_write_wait`]).
struct KernelWire;

impl crate::console_defer::Wire for KernelWire {
    fn put(&mut self, b: &[u8]) -> usize {
        // SAFETY: `Wire::put` is called with the UART lock held.
        let tx = unsafe { tx_state() };
        if !tx_async() {
            tx.flush_sync();
            write_str_translated(b);
            return b.len();
        }
        let n = tx.put(b, true);
        tx.kick();
        n
    }

    fn put_all(&mut self, b: &[u8]) {
        tx_write_wait(b, true);
    }

    fn fits(&self, b: &[u8]) -> bool {
        // SAFETY: `Wire::fits` is called with the UART lock held.
        !tx_async() || unsafe { tx_state() }.free() >= translated_len(b)
    }

    fn room(&self) -> usize {
        if !tx_async() {
            return usize::MAX;
        }
        // SAFETY: `Wire::room` is called with the UART lock held.
        unsafe { tx_state() }.free()
    }
}

/// The UART lock as an owner takes it: spin with the caller's interrupt
/// state between attempts — ON in task context — so the masked window is
/// only the hold.
fn acquire_spinning_unmasked() -> UartGuard {
    loop {
        if let Some(g) = try_acquire() {
            return g;
        }
        while UART_LOCK.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    }
}

/// An owner's write (ring 3's line, or deferred kernel bytes it drains),
/// called with no lock held: copy into the TX ring one
/// [`TX_OWNER_PIECE`] per hold, waiting for room with the lock released.
/// `translate`: expand `\n` to `\n\r` (kernel bytes; ring 3's pieces arrive
/// already translated by [`console_write_ring3`]).
pub(crate) fn tx_write_wait(bytes: &[u8], translate: bool) {
    let mut rest = bytes;
    while !rest.is_empty() {
        if !tx_async() {
            // Not wired yet, or a halt/panic/reset began meanwhile.
            if translate {
                write_str_translated(rest);
            } else {
                hw::write_bytes(rest);
            }
            return;
        }
        let piece = &rest[..rest.len().min(TX_OWNER_PIECE)];
        let n = {
            let _guard = acquire_spinning_unmasked();
            // SAFETY: `_guard` holds the UART lock for this block.
            let tx = unsafe { tx_state() };
            if tx_async() {
                let n = tx.put(piece, translate);
                if n == 0 {
                    // Full: one FIFO load ourselves if there is room.
                    tx.fill(TX_KICK_BUDGET);
                }
                tx.kick();
                n
            } else {
                0
            }
        };
        rest = &rest[n..];
        if n == 0 {
            for _ in 0..64 {
                core::hint::spin_loop();
            }
        }
    }
}

/// TX half of the UART interrupt: what the FIFO takes now (at most
/// [`TX_IRQ_BUDGET`]), then — ring low and a
/// residual stranded behind no owner — one [`crate::console_defer::DRAIN_CHUNK`]
/// of it into the ring; mask the interrupt once the ring is empty. Never
/// spins on the UART. In bypass it only masks: the halting hart owns the
/// wire now, and its lock may never be released.
fn tx_irq() {
    if !TX_ASYNC.load(Ordering::Relaxed) {
        return;
    }
    let _guard = loop {
        if let Some(g) = try_acquire() {
            break g;
        }
        if BYPASS.load(Ordering::Relaxed) {
            hw::tx_irq_set(false);
            return;
        }
        core::hint::spin_loop();
    };
    let low = {
        // SAFETY: `_guard` holds the UART lock; this reference ends here.
        let tx = unsafe { tx_state() };
        if BYPASS.load(Ordering::Relaxed) {
            hw::tx_irq_set(false);
            tx.active = false;
            return;
        }
        if !tx.active {
            return;
        }
        tx.irqs += 1;
        tx.fill(TX_IRQ_BUDGET);
        tx.len < TX_RING_BYTES / 2
    };
    if low {
        // SAFETY: `_guard` holds the UART lock.
        let st = unsafe { defer_state() };
        if st.stranded() {
            st.help(&mut KernelWire);
            publish(st);
        }
    }
    // SAFETY: `_guard` holds the UART lock; the reference above has ended.
    let tx = unsafe { tx_state() };
    if tx.len == 0 && tx.active {
        hw::tx_irq_set(false);
        tx.active = false;
    }
}

/// Boot hook, once the UART interrupt is routed to a hart and its handler
/// calls [`irq_handler`]: console output goes through the TX ring from now
/// on. `console-tx-sync` (gate canary) leaves it synchronous.
pub fn enable_tx_irq() {
    #[cfg(not(feature = "console-tx-sync"))]
    TX_ASYNC.store(true, Ordering::Release);
}

/// `(tx_async, ring_high_water_bytes, tx_interrupts)`, read under the UART
/// lock.
pub fn console_tx_stats() -> (bool, usize, u64) {
    let _guard = acquire();
    // SAFETY: `_guard` holds the UART lock for this scope.
    let tx = unsafe { tx_state() };
    (TX_ASYNC.load(Ordering::Relaxed), tx.hwm, tx.irqs)
}

/// Kernel output. **The caller holds the UART lock** for the whole line:
/// `wcet`'s `try_acquire` report is the only caller (through [`Uart`]). It
/// defers behind a residual rather than drain it; every other kernel writer
/// goes through [`kernel_emit`].
fn kernel_write_locked(bytes: &[u8]) {
    if BYPASS.load(Ordering::Relaxed) {
        // SAFETY: caller holds the UART lock (this function's contract).
        unsafe { tx_state() }.flush_sync();
        write_str_translated(bytes);
        return;
    }
    // SAFETY: caller holds the UART lock (this function's contract).
    let st = unsafe { defer_state() };
    st.kernel_write(bytes, &mut KernelWire);
    publish(st);
}

/// The UART spinlock as an owner (ring 3 or a draining kernel writer) and
/// [`kernel_emit`] take it: spin with the caller's interrupt state between
/// attempts — ON in task context — so the masked window is only the hold.
/// `RING3`: the ring-3 owner's holds, the ones [`ring3_probe`] times.
struct KernelDeferLock<const RING3: bool>;

impl<const RING3: bool> crate::console_defer::DeferLock<DEFER_BYTES> for KernelDeferLock<RING3> {
    fn with<R>(&self, f: impl FnOnce(&mut crate::console_defer::ConsoleDefer<DEFER_BYTES>) -> R) -> R {
        let guard = acquire_spinning_unmasked();
        #[cfg(feature = "console-splice-smoke")]
        let t_hold = ring3_probe::start();
        // SAFETY: `guard` holds the UART lock until the end of this block.
        let st = unsafe { defer_state() };
        let r = f(&mut *st);
        publish(st);
        #[cfg(feature = "console-splice-smoke")]
        if RING3 {
            ring3_probe::end_hold(t_hold);
        }
        drop(guard);
        r
    }
}

/// A halt path's first call (`[FATAL]` sites, `unhandled_trap`, the panic
/// handler): kernel output bypasses ownership from now on, and whatever was
/// deferred goes to the wire now if the UART lock is free. Returns whether
/// it was (the panic handler's existing lock peek).
pub fn console_bypass_for_halt() -> bool {
    BYPASS.store(true, Ordering::SeqCst);
    flush_deferred_if_free()
}

/// A deliberate reset or power-off (`sys_reboot`/`sys_shutdown`, the
/// shell's `reboot`/`shutdown`, the secure-boot recovery steer): kernel
/// output bypasses ownership from now on, and everything deferred goes to
/// the wire now. Unlike [`console_bypass_for_halt`] it WAITS for the UART
/// lock: nothing here is dying, a holder releases within one hold, and a
/// line printed just before the reset must not be left behind an owner
/// that will not drain it before the reset. The masked window of this last flush (up to
/// one buffer) no longer matters.
///
/// The TX ring goes first (it is older than anything deferred), and the
/// call returns only once the UART's transmitter is idle: a reset with
/// bytes still in the FIFO cuts them on a real board.
pub fn console_flush_for_reboot() {
    BYPASS.store(true, Ordering::SeqCst);
    let _guard = acquire();
    // SAFETY: `_guard` holds the UART lock for this scope.
    unsafe { tx_state() }.flush_sync();
    // SAFETY: `_guard` holds the UART lock for this scope.
    let st = unsafe { defer_state() };
    if st.has_residual() {
        st.flush_residual(&mut |b: &[u8]| write_str_translated(b));
        publish(st);
    }
    hw::tx_wait_idle();
}

/// Mark the bypass — lock-free, for the top of the panic handler — and put
/// the TX ring on the wire synchronously if the UART lock is free, so the
/// panic text that follows (lock-free, [`puts`]) comes after the output
/// that was already queued. If the lock is busy (its holder may be the
/// hart that died) the ring is left behind; the panic text still goes out.
pub fn console_enter_bypass() {
    BYPASS.store(true, Ordering::SeqCst);
    if let Some(_guard) = try_acquire() {
        // SAFETY: `_guard` holds the UART lock for this scope.
        unsafe { tx_state() }.flush_sync();
    }
}

/// Put deferred kernel output on the wire if the UART lock is free, with a
/// note first so a reader knows it is older than what precedes it. Returns
/// whether the lock was free.
pub fn flush_deferred_if_free() -> bool {
    let Some(_guard) = try_acquire() else { return false };
    // SAFETY: `_guard` holds the UART lock for this scope.
    unsafe { tx_state() }.flush_sync();
    // SAFETY: `_guard` holds the UART lock for this scope.
    let st = unsafe { defer_state() };
    if st.has_residual() {
        write_str_translated(b"[CONSOLE] deferred kernel output follows\n");
        st.flush_residual(&mut |b: &[u8]| write_str_translated(b));
        publish(st);
    }
    true
}

/// `(high_water_bytes, total_dropped_lines, total_deferred_bytes)`, read
/// under the UART lock. Callable from any context that may `kprintln!`.
pub fn console_defer_stats() -> (usize, u32, u64) {
    let _guard = acquire();
    // SAFETY: `_guard` holds the UART lock for this scope.
    let st = unsafe { defer_state() };
    (st.high_water(), st.total_dropped_lines(), st.total_deferred())
}

/// Gate-only measurement for the `console-splice-smoke` reproducer: how long
/// [`console_write_ring3`] holds the UART lock (interrupts masked) per hold,
/// and how long one call takes end to end. Units are [`crate::timebase::now`]
/// ticks (10 MHz on QEMU `virt` riscv64; the generic counter's frequency on
/// aarch64). Compiled out of every other build.
#[cfg(feature = "console-splice-smoke")]
pub mod ring3_probe {
    use core::sync::atomic::{AtomicU64, Ordering};

    static MAX_HOLD: AtomicU64 = AtomicU64::new(0);
    static HOLDS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_HOLD: AtomicU64 = AtomicU64::new(0);
    static MAX_CALL: AtomicU64 = AtomicU64::new(0);
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_CALL: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub(super) fn start() -> u64 {
        crate::timebase::now()
    }

    #[inline]
    pub(super) fn end_hold(t0: u64) {
        let d = crate::timebase::now().wrapping_sub(t0);
        MAX_HOLD.fetch_max(d, Ordering::Relaxed);
        HOLDS.fetch_add(1, Ordering::Relaxed);
        TOTAL_HOLD.fetch_add(d, Ordering::Relaxed);
    }

    #[inline]
    pub(super) fn end_call(t0: u64) {
        let d = crate::timebase::now().wrapping_sub(t0);
        MAX_CALL.fetch_max(d, Ordering::Relaxed);
        CALLS.fetch_add(1, Ordering::Relaxed);
        TOTAL_CALL.fetch_add(d, Ordering::Relaxed);
    }

    /// `(max_hold, holds, total_hold, max_call, calls, total_call)`.
    pub fn read() -> (u64, u64, u64, u64, u64, u64) {
        (
            MAX_HOLD.load(Ordering::Relaxed),
            HOLDS.load(Ordering::Relaxed),
            TOTAL_HOLD.load(Ordering::Relaxed),
            MAX_CALL.load(Ordering::Relaxed),
            CALLS.load(Ordering::Relaxed),
            TOTAL_CALL.load(Ordering::Relaxed),
        )
    }

    /// Zero every counter, so a reading covers only the smoke's own writes.
    pub fn reset() {
        for c in [&MAX_HOLD, &HOLDS, &TOTAL_HOLD, &MAX_CALL, &CALLS, &TOTAL_CALL] {
            c.store(0, Ordering::Relaxed);
        }
    }
}

/// Gate-only measurement for the `console-splice-smoke` reproducer: every
/// UART lock hold of any writer (kernel lines, the ring-3 owner's steps,
/// flushes), acquire to release. The lock masks interrupts on its hart for
/// exactly that span, so the maximum is the longest interrupts-masked window
/// the console produced. Same ticks as [`ring3_probe`]. Compiled out of
/// every other build.
#[cfg(feature = "console-splice-smoke")]
pub mod lock_probe {
    use core::sync::atomic::{AtomicU64, Ordering};

    use core::sync::atomic::AtomicUsize;
    use azos_arch::Cpu;

    static MAX_HOLD: AtomicU64 = AtomicU64::new(0);
    static HOLDS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_HOLD: AtomicU64 = AtomicU64::new(0);
    /// Bytes put on the wire inside one hold, and the largest such count:
    /// the masked window in bytes, free of the host-scheduling noise that
    /// dominates the tick maxima under QEMU.
    static HOLD_BYTES: AtomicU64 = AtomicU64::new(0);
    static MAX_HOLD_BYTES: AtomicU64 = AtomicU64::new(0);
    /// Bytes the TX ring moved into the FIFO inside one hold (wave 11), and
    /// the largest such count. Unlike [`wire`], a fill never waits: it writes
    /// only what the FIFO takes at that moment, so on a real UART one hold
    /// moves at most one FIFO's worth; under QEMU (instant transmit) an
    /// interrupt's refill may move up to `TX_IRQ_BUDGET`.
    static HOLD_FILL: AtomicU64 = AtomicU64::new(0);
    static MAX_HOLD_FILL: AtomicU64 = AtomicU64::new(0);
    /// Idle passes that found a stranded residual and drained it.
    pub(super) static IDLE_DRAINS: AtomicU64 = AtomicU64::new(0);
    /// `hart_id + 1` of the lock holder, 0 = none. Interrupts are masked on
    /// the holder, so a write from that hart is a write inside the hold.
    static HOLDER: AtomicUsize = AtomicUsize::new(0);

    #[inline]
    pub(super) fn begin_hold() {
        HOLD_BYTES.store(0, Ordering::Relaxed);
        HOLD_FILL.store(0, Ordering::Relaxed);
        HOLDER.store(azos_arch::ARCH.hart_id() + 1, Ordering::Relaxed);
    }

    /// A wire write of `n` bytes: counted if this hart holds the lock.
    #[inline]
    pub(super) fn wire(n: usize) {
        if HOLDER.load(Ordering::Relaxed) == azos_arch::ARCH.hart_id() + 1 {
            HOLD_BYTES.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    /// A non-blocking FIFO fill of `n` bytes from the TX ring.
    #[inline]
    pub(super) fn fill(n: usize) {
        if HOLDER.load(Ordering::Relaxed) == azos_arch::ARCH.hart_id() + 1 {
            HOLD_FILL.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    /// Largest number of bytes one hold moved from the TX ring to the FIFO.
    pub fn max_fill() -> u64 {
        MAX_HOLD_FILL.load(Ordering::Relaxed)
    }

    #[inline]
    pub(super) fn end_hold(t0: u64) {
        let d = crate::timebase::now().wrapping_sub(t0);
        MAX_HOLD.fetch_max(d, Ordering::Relaxed);
        HOLDS.fetch_add(1, Ordering::Relaxed);
        TOTAL_HOLD.fetch_add(d, Ordering::Relaxed);
        HOLDER.store(0, Ordering::Relaxed);
        MAX_HOLD_BYTES.fetch_max(HOLD_BYTES.load(Ordering::Relaxed), Ordering::Relaxed);
        MAX_HOLD_FILL.fetch_max(HOLD_FILL.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// `(max_hold, holds, total_hold, max_hold_bytes, idle_drains)`.
    pub fn read() -> (u64, u64, u64, u64, u64) {
        (
            MAX_HOLD.load(Ordering::Relaxed),
            HOLDS.load(Ordering::Relaxed),
            TOTAL_HOLD.load(Ordering::Relaxed),
            MAX_HOLD_BYTES.load(Ordering::Relaxed),
            IDLE_DRAINS.load(Ordering::Relaxed),
        )
    }

    /// Zero every counter, so a reading covers only the smoke's window.
    pub fn reset() {
        for c in [&MAX_HOLD, &HOLDS, &TOTAL_HOLD, &MAX_HOLD_BYTES, &MAX_HOLD_FILL, &IDLE_DRAINS] {
            c.store(0, Ordering::Relaxed);
        }
    }
}

/// Orders console owners among themselves (preemptible, priority
/// inheritance): held across [`console_write_ring3`], and by a kernel writer
/// while it drains a residual as the owner ([`kernel_emit`], `try_lock`
/// only), so ownership is never contended.
static CONSOLE_LINE_LOCK: PiMutex<()> = PiMutex::new(());

/// A zero-size writer that implements `core::fmt::Write` for KERNEL output.
///
/// **Use it only with the UART lock held** (`acquire`/`try_acquire`), as
/// `wcet`'s interrupt-context report does: while ring 3 owns the console, or
/// a residual waits, its bytes are deferred into state that lock guards (see
/// [`console_write_ring3`]). It never drains a residual; `kprint!`/
/// `kprintln!` go through [`kernel_print`], which does. The lock-free writer
/// is [`puts`].
pub struct Uart;

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        kernel_write_locked(s.as_bytes());
        Ok(())
    }
}

// ---- Kernel log levels ----
//
// Linux numbering (`KERN_ERR` 3 .. `KERN_DEBUG` 7). A build keeps the lines
// at or below `CONFIG_LOG_LEVEL` (config/Kconfig.development); a line above
// it sits behind a constant-false `if`, so its format string, its formatting
// code and its call are not in the image and its arguments are not
// evaluated. The arguments still type-check, so a variable read only by a
// compiled-out line raises no unused warning at any level.
//
// Which macro a line takes:
// - `kerr!`: something failed or was refused and the system is worse for
//   it (a fault that kills a task, a boot self-check that failed, a driver
//   given up on, a halting refusal).
// - `kwarn!`: a security refusal or a safety event the system handled
//   (a capability or seccomp denial, a verification failure, an e-stop,
//   a watchdog stop), or a degraded mode.
// - `kinfo!` / `kprintln!` / `kprint!`: progress and status.
// - `kdebug!`: diagnostics for a developer.
// - `kconsole!` / `kconsoleln!`: not a log line. Output a person asked for
//   (the shell's commands) and the panic report: always printed.

/// Kernel log levels (Linux numbering).
pub mod level {
    /// `KERN_ERR`.
    pub const ERR: usize = 3;
    /// `KERN_WARNING`.
    pub const WARN: usize = 4;
    /// `KERN_INFO`: what a plain `kprintln!` logs at.
    pub const INFO: usize = 6;
    /// `KERN_DEBUG`.
    pub const DEBUG: usize = 7;
}

/// This build's log level (`CONFIG_LOG_LEVEL`; `azos_limits`' build script
/// refuses any value but 3, 4, 6 or 7).
pub const LOG_LEVEL: usize = azos_limits::LOG_LEVEL;

/// One kernel log line at `$lvl`, or nothing when the build's level is
/// below it. Use the named macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __klog {
    ($lvl:expr, $nl:expr, $($arg:tt)*) => {{
        if const { $crate::uart::LOG_LEVEL >= $lvl } {
            $crate::uart::kernel_print(format_args!($($arg)*), $nl);
        }
    }};
}

/// Print formatted output to UART (SMP-safe), no newline, at info level:
/// one kernel line, see [`uart::kernel_print`](crate::uart::kernel_print).
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { $crate::__klog!($crate::uart::level::INFO, false, $($arg)*) };
}

/// Print formatted output to UART with newline (SMP-safe), at info level.
#[macro_export]
macro_rules! kprintln {
    () => { $crate::__klog!($crate::uart::level::INFO, false, "\n") };
    ($($arg:tt)*) => { $crate::__klog!($crate::uart::level::INFO, true, $($arg)*) };
}

/// A kernel log line at err level (see the level guide above `level`).
#[macro_export]
macro_rules! kerr {
    () => { $crate::__klog!($crate::uart::level::ERR, false, "\n") };
    ($($arg:tt)*) => { $crate::__klog!($crate::uart::level::ERR, true, $($arg)*) };
}

/// A kernel log line at warn level.
#[macro_export]
macro_rules! kwarn {
    () => { $crate::__klog!($crate::uart::level::WARN, false, "\n") };
    ($($arg:tt)*) => { $crate::__klog!($crate::uart::level::WARN, true, $($arg)*) };
}

/// A kernel log line at info level (same as `kprintln!`).
#[macro_export]
macro_rules! kinfo {
    () => { $crate::__klog!($crate::uart::level::INFO, false, "\n") };
    ($($arg:tt)*) => { $crate::__klog!($crate::uart::level::INFO, true, $($arg)*) };
}

/// A kernel log line at debug level.
#[macro_export]
macro_rules! kdebug {
    () => { $crate::__klog!($crate::uart::level::DEBUG, false, "\n") };
    ($($arg:tt)*) => { $crate::__klog!($crate::uart::level::DEBUG, true, $($arg)*) };
}

/// Console output that is not a log line, no newline: printed at every
/// level (the shell's command output, the panic report).
#[macro_export]
macro_rules! kconsole {
    ($($arg:tt)*) => {{
        $crate::uart::kernel_print(format_args!($($arg)*), false);
    }};
}

/// [`kconsole!`] with a newline.
#[macro_export]
macro_rules! kconsoleln {
    () => { $crate::kconsole!("\n") };
    ($($arg:tt)*) => {{
        $crate::uart::kernel_print(format_args!($($arg)*), true);
    }};
}

// ---- IRQ-driven RX ----

/// Enable UART RX interrupt.
pub fn enable_irq() {
    hw::enable_irq();
}

/// UART IRQ handler — called from the PLIC/APLIC external interrupt path
/// (riscv64) and the PL011 SPI arm (aarch64). One line carries both
/// directions: RX into the ring, then one bounded TX refill ([`tx_irq`]).
/// Returns whether the RX side had work (aarch64 counts and wakes on it, so
/// a TX interrupt is not reported as received input).
pub fn irq_handler() -> bool {
    let rx = hw::irq_handler();
    tx_irq();
    rx
}

// ---- RX wake: a reader parked until the RX interrupt fires ----
//
// The ring above says whether input is there; nothing in this crate can wake
// a task (it sits below `azos_sched`). So the reader publishes its TID
// here before it parks, and the kernel's IRQ arm, which can reach the
// scheduler, takes it and wakes that task by TID. Taking (swap to 0) makes
// one arm worth at most one wake.
//
// Both ISAs since wave 11 (RFC-0055 S1): aarch64's PL011 arm and riscv64's
// PLIC arm (`kernel/src/trap/interrupt.rs`) take the waiter once the boot
// code has wired the RX interrupt. Only the console's input owner
// ([`CONSOLE_RX`]) arms it, so one slot is enough.

/// TID of the task parked on console input, 0 = none.
static RX_WAITER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Set once the boot code has wired the RX interrupt AND the IRQ arm that
/// takes [`RX_WAITER`]. Until then a reader must keep polling: parking on a
/// wake nobody delivers would make the console deaf.
static RX_WAKE_WIRED: AtomicBool = AtomicBool::new(false);

/// The RX interrupt wakes a parked reader (see [`rx_waiter_arm`]).
#[inline]
pub fn rx_wake_wired() -> bool {
    RX_WAKE_WIRED.load(Ordering::Acquire)
}

/// Boot code: the RX interrupt is live and its IRQ arm calls
/// [`rx_waiter_take`].
pub fn set_rx_wake_wired() {
    RX_WAKE_WIRED.store(true, Ordering::Release);
}

/// A reader about to park: the next RX interrupt wakes `tid`. The reader
/// must re-test [`can_read`] AFTER this, or a byte that landed between its
/// last test and this store is never announced.
#[inline]
pub fn rx_waiter_arm(tid: u32) {
    RX_WAITER.store(tid, Ordering::SeqCst);
    // Store(WAITER) -> load(RX_HEAD) in the reader's re-test, against
    // store(RX_HEAD) -> load(WAITER) in the IRQ arm (Dekker): each side
    // needs a full fence between its store and its load, or both can miss
    // the other's store and the byte sits in the ring with nobody woken.
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// The reader is running again (woken, timed out, or found input on its
/// re-test): no wake is owed any more.
#[inline]
pub fn rx_waiter_disarm() {
    RX_WAITER.store(0, Ordering::SeqCst);
}

/// IRQ arm: the TID to wake, at most once per arm; 0 if nobody is parked.
#[inline]
pub fn rx_waiter_take() -> u32 {
    // The other half of [`rx_waiter_arm`]'s fence: the ring's RX_HEAD store
    // (in `irq_handler`) must be visible before WAITER is read.
    core::sync::atomic::fence(Ordering::SeqCst);
    RX_WAITER.swap(0, Ordering::SeqCst)
}

// ---- Console input owner (RFC-0055) ----

/// The one reader of console input: the user shell (its TID) or the recovery
/// console ([`console_rx::RX_OWNER_KERNEL`]). See `console_rx.rs`.
pub static CONSOLE_RX: crate::console_rx::RxOwner = crate::console_rx::RxOwner::new();

/// Wave 13: `^C` received while console input is lent ([`CONSOLE_RX`]) to a
/// Linux job: not queued, counted here; the kernel's IRQ arm turns it into
/// `SIGINT` for that job ([`take_intr`]).
static INTR_PENDING: AtomicU32 = AtomicU32::new(0);
/// Every such `^C` since boot: what a reader compares to drop the line it
/// was editing.
static INTR_SEQ: AtomicU32 = AtomicU32::new(0);

/// RX interrupt: is byte `c` the interrupt character of a lent console?
/// Then it is consumed here. Atomics only.
#[inline]
fn rx_intercept(c: u8) -> bool {
    if c == 0x03 && CONSOLE_RX.lendee() != 0 && !cfg!(feature = "console-isig-canary") {
        INTR_SEQ.fetch_add(1, Ordering::AcqRel);
        INTR_PENDING.fetch_add(1, Ordering::AcqRel);
        return true;
    }
    false
}

/// IRQ arm: was a lent console interrupted since the last call?
pub fn take_intr() -> bool {
    INTR_PENDING.swap(0, Ordering::AcqRel) != 0
}

/// How many lent-console interrupts there have been.
pub fn intr_seq() -> u32 {
    INTR_SEQ.load(Ordering::Acquire)
}

/// Copy up to `out.len()` bytes from the RX ring (non-blocking). Returns how
/// many. The caller must own console input ([`CONSOLE_RX`]).
/// Reads the ring in IRQ mode and the device FIFO otherwise, as [`getc`].
pub fn rx_read(out: &mut [u8]) -> usize {
    let mut n = 0;
    while n < out.len() && can_read() {
        out[n] = getc();
        n += 1;
    }
    n
}

/// Returns the number of characters available in the RX ring buffer.
pub fn rx_available() -> usize {
    let head = RX_HEAD.load(Ordering::Acquire);
    let tail = RX_TAIL.load(Ordering::Relaxed);
    (head + RX_BUF_CAP - tail) % RX_BUF_CAP
}

/// Read one character from the RX ring buffer (non-blocking).
pub fn try_getc() -> Option<u8> {
    let tail = RX_TAIL.load(Ordering::Relaxed);
    if tail == RX_HEAD.load(Ordering::Acquire) {
        return None;
    }
    let c = unsafe { RX_BUF[tail] };
    RX_TAIL.store((tail + 1) % RX_BUF_CAP, Ordering::Release);
    Some(c)
}
