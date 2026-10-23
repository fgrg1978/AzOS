// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device half the PCI NICs share: [`crate::e1000e`] and [`crate::igc`]
//! program different registers and write different descriptors, but the
//! memory the controller sees, the receive and transmit paths over it, the
//! interrupt hook, the MSI wiring and the bring-up order are one thing.
//!
//! # Shape
//!
//! * [`Wire`] is what differs and needs no bring-up: the queue register
//!   map, the interrupt registers, the descriptor encoders and the link
//!   decoder. [`Chip`] (behind the drivers' features) is what differs during
//!   bring-up: identify the part, reset it, describe and enable the queues.
//! * [`Mem`] is the rings and buffers, alone in `.bss` (a [`Nic`] is
//!   initialised data: it holds the DMA domain's fat pointer).
//! * [`Nic`] is the driver state and every path over it. A driver is one
//!   `static` of each plus thin free functions the NIC table calls.
//!
//! The ring paths and [`Nic::go_live`] touch no PCI type, so
//! `tests/host/drivers-tests` runs both drivers' [`Wire`]s through them over
//! a register file in host memory. The PCI bring-up ([`Nic::init_pci`]) is
//! behind the `e1000e` / `igc` features, as the drivers' device halves are.
//!
//! # A wedged transmit ring (`net-timeout`)
//!
//! Frames announced to the controller that it takes none of for Kconfig
//! `NET_TX_TIMEOUT_MS` (time the guest ran, [`TxWatch`]) are a wedged NIC:
//! the send that sees it asks the timeout policy (`azos_drv_api::recovery`).
//! Once per boot (`DEVICE_TIMEOUT_RESETS`) the controller is reset and
//! brought up again over the same rings and buffers ([`Nic::restart`], the
//! bring-up's steps), the frames in the ring dropped; after that the NIC is
//! stopped and latched dead until reboot. Both are `net-timeout` decision
//! records.

use crate::e1000e::{
    icr_wakes_rx, rx_accept, rx_post, tx_done, tx_doorbell_due, Desc, Link, RxCursor, RxStatus, TxCursor, BUF_SIZE,
    DESC_BYTES, ICR_LSC, IMS_RUN, REG_STATUS, RING_MULTIPLE, STATUS_LU, TX_FRAME_MAX,
};
use azos_dma::Direction;
use azos_drv_api::net::NetError;
use azos_drv_api::recovery::{Class, Recovery, StallClock, TxWatch, Verdict, STALL_GAP_US, TX_LOOK_US};
use azos_drv_virtio::virtio::Dma;
use azos_sync::SpinLock;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The registers of one queue (offsets from BAR 0).
#[derive(Clone, Copy, Debug)]
pub struct RingRegs {
    /// Ring base, low and high dwords.
    pub bal: usize,
    pub bah: usize,
    /// Ring length in bytes.
    pub len: usize,
    pub head: usize,
    pub tail: usize,
    /// Queue control (`RXDCTL` / `TXDCTL`).
    pub ctl: usize,
}

/// What differs between the controllers and is needed once they run.
pub trait Wire: Sized + 'static {
    /// The driver's name in the console.
    const NAME: &'static str;
    const RX: RingRegs;
    const TX: RingRegs;
    /// Interrupt cause (read clears it), mask set and mask clear.
    const ICR: usize;
    const IMS: usize;
    const IMC: usize;
    /// Decode the write-back of a receive descriptor from its second word.
    fn rx_status(hi: u64) -> RxStatus;
    /// A transmit descriptor for one whole frame in one buffer.
    fn tx_frame(buf_bus: u64, len: usize) -> Desc;
    /// What `STATUS` says about the link.
    fn link(status: u32) -> Link;
}

// ---------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------

/// BAR 0 of the controller, typed by the driver whose map it is read with.
pub struct Regs<W> {
    bar: usize,
    _wire: PhantomData<fn() -> W>,
}

impl<W> Clone for Regs<W> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W> Copy for Regs<W> {}

impl<W: Wire> Regs<W> {
    #[inline(always)]
    pub fn rd(&self, off: usize) -> u32 {
        // SAFETY: `bar` is BAR 0 mapped by `map_bars` (a `Regs` is made only
        // from a stored BAR); `off` is a register of the driver's map.
        unsafe { core::ptr::read_volatile((self.bar + off) as *const u32) }
    }

    #[inline(always)]
    pub fn wr(&self, off: usize, val: u32) {
        // SAFETY: as `rd`.
        unsafe { core::ptr::write_volatile((self.bar + off) as *mut u32, val) }
    }

    fn link_is_up(&self) -> bool {
        self.rd(REG_STATUS) & STATUS_LU != 0
    }
}

fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

/// Spin for `us` microseconds.
pub fn wait_us(us: u64) {
    let end = now().saturating_add(us.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000);
    while now() < end {
        core::hint::spin_loop();
    }
}

/// Spin up to `us` microseconds for `cond`; whether it held.
pub fn wait_for(us: u64, mut cond: impl FnMut() -> bool) -> bool {
    let end = now().saturating_add(us.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000);
    loop {
        if cond() {
            return true;
        }
        if now() >= end {
            return false;
        }
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------
// Memory the controller sees
// ---------------------------------------------------------------------

/// A descriptor ring, alone in its pages: a translating domain maps whole
/// pages, and what the device writes must not share one with the driver's
/// state.
#[repr(C, align(4096))]
struct Ring<const N: usize>(UnsafeCell<[Desc; N]>);

/// The buffers of one ring, one per descriptor, `BUF_SIZE` apart.
#[repr(C, align(4096))]
struct Bufs<const N: usize>(UnsafeCell<[[u8; BUF_SIZE]; N]>);

/// The rings and buffers of one NIC, all zero: they live in `.bss`.
pub struct Mem<const RX_N: usize, const TX_N: usize> {
    rx_ring: Ring<RX_N>,
    tx_ring: Ring<TX_N>,
    rx_bufs: Bufs<RX_N>,
    tx_bufs: Bufs<TX_N>,
}

// SAFETY: a ring is touched only under the lock of its side (`Nic::rx`,
// `Nic::tx`) or by the device, which owns the descriptors the cursors say it
// owns. Buffer `i` belongs to descriptor `i`: written by the device while the
// receive descriptor is posted, read by the one caller that consumed it
// (under the receive lock) until it is posted again; the transmit buffer is
// written by `send` (under the transmit lock) only while its descriptor is
// not in flight.
unsafe impl<const RX_N: usize, const TX_N: usize> Sync for Mem<RX_N, TX_N> {}

impl<const RX_N: usize, const TX_N: usize> Mem<RX_N, TX_N> {
    pub const fn new() -> Self {
        Mem {
            rx_ring: Ring(UnsafeCell::new([Desc { lo: 0, hi: 0 }; RX_N])),
            tx_ring: Ring(UnsafeCell::new([Desc { lo: 0, hi: 0 }; TX_N])),
            rx_bufs: Bufs(UnsafeCell::new([[0u8; BUF_SIZE]; RX_N])),
            tx_bufs: Bufs(UnsafeCell::new([[0u8; BUF_SIZE]; TX_N])),
        }
    }

    // The pointers below are in bounds for `i` below the ring length, which
    // every caller keeps (`wrapping_add` makes forming one safe; using it is
    // the callers' unsafe).

    #[inline(always)]
    pub fn rx_desc(&self, i: usize) -> *mut Desc {
        (self.rx_ring.0.get() as *mut Desc).wrapping_add(i)
    }

    #[inline(always)]
    pub fn tx_desc(&self, i: usize) -> *mut Desc {
        (self.tx_ring.0.get() as *mut Desc).wrapping_add(i)
    }

    #[inline(always)]
    pub fn rx_buf(&self, i: usize) -> *mut u8 {
        (self.rx_bufs.0.get() as *mut [u8; BUF_SIZE]).wrapping_add(i) as *mut u8
    }

    #[inline(always)]
    pub fn tx_buf(&self, i: usize) -> *mut u8 {
        (self.tx_bufs.0.get() as *mut [u8; BUF_SIZE]).wrapping_add(i) as *mut u8
    }
}

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

struct RxState {
    dma: Dma,
    /// Bus address of receive buffer 0 (buffers are `BUF_SIZE` apart).
    buf_bus: u64,
    cur: RxCursor,
}

struct TxState {
    dma: Dma,
    buf_bus: u64,
    cur: TxCursor,
    /// Open TX batches ([`Nic::tx_batch_begin`]); 0 = every send rings at
    /// once.
    depth: u16,
    /// Frames published since the last doorbell.
    pending: u16,
    /// How long the announced frames have sat with no progress.
    watch: TxWatch,
}

// SAFETY: the `Dma` holds a `&'static dyn DmaDomain`, immutable once the
// driver is up; the rest is plain data.
unsafe impl Send for RxState {}
unsafe impl Send for TxState {}

/// One PCI NIC: its state and the paths over `mem`. Everything is atomics or
/// behind the lock of its side, so a `static` of it is `Sync`.
pub struct Nic<W: Wire, const RX_N: usize, const TX_N: usize> {
    mem: &'static Mem<RX_N, TX_N>,
    rx: SpinLock<RxState>,
    tx: SpinLock<TxState>,
    /// CPU address of BAR 0; 0 until [`Nic::set_bar`]. Read by the
    /// interrupt path without a lock.
    bar: AtomicUsize,
    ready: AtomicBool,
    /// The station address, bytes 0-5 little-endian in the low 48 bits.
    mac: AtomicU64,
    /// `STATUS.LU` as last read: at bring-up, by the link-change interrupt,
    /// and (polled mode) by the receive path when it finds the ring empty.
    link_up: AtomicBool,
    /// MSI is armed: [`Nic::msi_irq`] matches `msi_token`.
    msi_armed: AtomicBool,
    /// What the kernel's interrupt path passes to [`Nic::msi_irq`] for the
    /// vector (`MsiRoute::isr_token`): an IMSIC identity, an LPI slot, a
    /// vector.
    msi_token: AtomicU32,
    /// Receive interrupts taken (`ICR` carried a receive cause).
    rx_irqs: AtomicU32,
    /// The transmit ring holds announced frames (`TxState::watch` runs):
    /// [`Nic::tx_watch`] takes the lock only then.
    tx_watched: AtomicBool,
    /// Live, being reset after a wedged transmit ring, or latched dead.
    recovery: Recovery,
    /// The transmit ring's budget in time the guest ran (Kconfig
    /// `NET_TX_TIMEOUT_MS`), and the clock that measures it.
    tx_budget_ms: u64,
    stall: StallClock,
    /// Reset the controller and bring it up again over the same memory
    /// (`init_pci` installs [`Nic::restart`]); `true` when it came back.
    restart: SpinLock<Option<fn(&Self) -> bool>>,
    /// What `init_pci` gave the controller, for [`Nic::restart`].
    #[cfg(any(feature = "e1000e", feature = "igc"))]
    saved: SpinLock<Option<bring_up::Saved>>,
    _wire: PhantomData<fn() -> W>,
}

impl<W: Wire, const RX_N: usize, const TX_N: usize> Nic<W, RX_N, TX_N> {
    /// Kconfig `NET_TX_BATCH_MAX`: inside a batch, frames published before
    /// the doorbell is rung anyway.
    const TX_BATCH_MAX: u16 = azos_limits::NET_TX_BATCH_MAX as u16;
    /// Consumed receive descriptors held back before `RDT` is written: an
    /// eighth of the ring, so the controller never runs short while a
    /// batch is being read, and one write covers many frames.
    const RX_RDT_BATCH: u16 = if RX_N / 8 > 0 { (RX_N / 8) as u16 } else { 1 };

    const CHECK: () = {
        assert!(RX_N % RING_MULTIPLE == 0 && TX_N % RING_MULTIPLE == 0);
        assert!(RX_N >= 8 && TX_N >= 8 && RX_N <= 4096 && TX_N <= 4096);
        assert!(TX_FRAME_MAX <= BUF_SIZE);
    };

    pub const fn new(mem: &'static Mem<RX_N, TX_N>) -> Self {
        Self::with_tx_budget(mem, azos_limits::NET_TX_TIMEOUT_MS as u64)
    }

    /// [`Nic::new`] with a transmit budget of `tx_budget_ms` instead of
    /// Kconfig's (the host tests, whose time is short).
    pub const fn with_tx_budget(mem: &'static Mem<RX_N, TX_N>, tx_budget_ms: u64) -> Self {
        let () = Self::CHECK;
        Nic {
            mem,
            rx: SpinLock::new(RxState { dma: Dma::fallback(), buf_bus: 0, cur: RxCursor::new() }),
            tx: SpinLock::new(TxState {
                dma: Dma::fallback(),
                buf_bus: 0,
                cur: TxCursor::new(),
                depth: 0,
                pending: 0,
                watch: TxWatch::new(),
            }),
            bar: AtomicUsize::new(0),
            ready: AtomicBool::new(false),
            mac: AtomicU64::new(0),
            link_up: AtomicBool::new(false),
            msi_armed: AtomicBool::new(false),
            msi_token: AtomicU32::new(0),
            rx_irqs: AtomicU32::new(0),
            tx_watched: AtomicBool::new(false),
            recovery: Recovery::new(Class::Net, W::NAME, azos_limits::DEVICE_TIMEOUT_RESETS as u8),
            tx_budget_ms,
            stall: StallClock::new(),
            restart: SpinLock::new(None),
            #[cfg(any(feature = "e1000e", feature = "igc"))]
            saved: SpinLock::new(None),
            _wire: PhantomData,
        }
    }

    /// How the controller is reset and brought up again after a wedged
    /// transmit ring (`init_pci` installs the bring-up's; a host test its
    /// model's).
    pub fn set_restart(&self, f: fn(&Self) -> bool) {
        *self.restart.lock() = Some(f);
    }

    /// Resets the timeout policy has done since boot.
    pub fn resets(&self) -> u8 {
        self.recovery.resets()
    }

    /// Latched dead until reboot.
    pub fn is_dead(&self) -> bool {
        self.recovery.dead()
    }

    /// Where BAR 0 is mapped; the registers are reachable from here on.
    pub fn set_bar(&self, bar: usize) {
        self.bar.store(bar, Ordering::Release);
    }

    #[inline(always)]
    pub fn regs(&self) -> Regs<W> {
        Regs { bar: self.bar.load(Ordering::Relaxed), _wire: PhantomData }
    }

    /// Descriptors: receive ones carry their buffer, transmit ones are idle;
    /// then both rings are made visible to the device. Bring-up, with the
    /// device stopped.
    pub fn prime(&self, dma: &Dma, rx_buf_bus: u64) {
        for i in 0..RX_N {
            // SAFETY: bring-up is single-threaded and the device is stopped.
            unsafe { self.mem.rx_desc(i).write_volatile(rx_post(rx_buf_bus + (i * BUF_SIZE) as u64)) };
        }
        for i in 0..TX_N {
            // SAFETY: as above.
            unsafe { self.mem.tx_desc(i).write_volatile(Desc { lo: 0, hi: 0 }) };
        }
        // SAFETY: both rings are mapped kernel memory.
        unsafe {
            dma.sync_for_device(self.mem.rx_ring.0.get() as *const u8, RX_N * DESC_BYTES, Direction::Bidirectional);
            dma.sync_for_device(self.mem.tx_ring.0.get() as *const u8, TX_N * DESC_BYTES, Direction::Bidirectional);
        }
    }

    /// The last bring-up step, once the controller runs: install the state
    /// the paths below read, give the controller every receive descriptor
    /// but one (the first tail write), wait up to `link_wait_us` for the
    /// link once, arm the interrupt when `msi_token` is `Some`, and publish
    /// the station address and readiness.
    pub fn go_live(&self, dma: Dma, rx_buf_bus: u64, tx_buf_bus: u64, mac: [u8; 6], link_wait_us: u64, msi_token: Option<u32>) {
        let r = self.regs();
        let rx_cur = RxCursor::new();
        {
            let mut rx = self.rx.lock();
            *rx = RxState { dma, buf_bus: rx_buf_bus, cur: rx_cur };
        }
        {
            let mut tx = self.tx.lock();
            *tx = TxState { dma, buf_bus: tx_buf_bus, cur: TxCursor::new(), depth: 0, pending: 0, watch: TxWatch::new() };
            self.tx_watched.store(false, Ordering::Relaxed);
        }
        azos_dma::order::io_wmb();
        r.wr(W::RX.tail, rx_cur.rdt(RX_N) as u32);

        // Link: wait for it once, here.
        let up = wait_for(link_wait_us, || r.link_is_up()) || r.link_is_up();
        self.link_up.store(up, Ordering::Release);

        // Interrupts last: everything they touch is in place.
        if let Some(token) = msi_token {
            self.msi_token.store(token, Ordering::Relaxed);
            self.rx_irqs.store(0, Ordering::Relaxed);
            self.msi_armed.store(true, Ordering::Release);
            r.wr(W::IMS, IMS_RUN);
        }

        let packed = mac.iter().enumerate().fold(0u64, |a, (i, b)| a | (*b as u64) << (8 * i));
        self.mac.store(packed, Ordering::Release);
        self.ready.store(true, Ordering::Release);
    }

    // ---- Interrupt path ----

    /// Interrupt-path hook: `token` is the number the interrupt controller
    /// reported. Returns `true` when it is this NIC's vector: `ICR` is read
    /// (which clears it), a link change refreshes the cached link, a receive
    /// cause is counted. The caller then wakes whatever drains the ring.
    /// Lock-free and bounded: callable from an ISR.
    #[inline]
    pub fn msi_irq(&self, token: u32) -> bool {
        if !self.msi_armed.load(Ordering::Acquire) || self.msi_token.load(Ordering::Relaxed) != token {
            return false;
        }
        let r = self.regs();
        let icr = r.rd(W::ICR);
        if icr & ICR_LSC != 0 {
            self.link_up.store(r.link_is_up(), Ordering::Release);
        }
        if icr_wakes_rx(icr) {
            self.rx_irqs.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// `true` once the NIC's MSI is programmed: the receive ring is read
    /// after an interrupt, so whatever calls `net_poll` is woken by one.
    pub fn irq_driven(&self) -> bool {
        self.msi_armed.load(Ordering::Acquire)
    }

    /// Receive interrupts taken so far.
    pub fn rx_irq_count(&self) -> u32 {
        self.rx_irqs.load(Ordering::Relaxed)
    }

    /// The station address; all-zero before bring-up.
    pub fn mac(&self) -> [u8; 6] {
        let m = self.mac.load(Ordering::Acquire);
        core::array::from_fn(|i| (m >> (8 * i)) as u8)
    }

    /// Whether bring-up completed.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    // ---- Receive ----

    /// Write `RDT` for every consumed descriptor re-posted so far.
    fn flush_tail(&self, rx: &mut RxState) {
        if rx.cur.unposted == 0 {
            return;
        }
        azos_dma::order::io_wmb();
        self.regs().wr(W::RX.tail, rx.cur.rdt(RX_N) as u32);
        rx.cur.flushed();
    }

    /// Copy at most one received frame into `buf`; `Ok(0)` when none is
    /// queued. A frame the stack must not see (errored, split, runt, too big
    /// for `buf`) is dropped here, its descriptor re-posted, and the next one
    /// looked at.
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        if !self.ready.load(Ordering::Acquire) {
            return Err(NetError::NotReady);
        }
        let mem = self.mem;
        let mut rx = self.rx.lock();
        if !self.ready.load(Ordering::Acquire) {
            // Being reset: the ring is the restart's until it is live again.
            return Err(NetError::NotReady);
        }
        loop {
            let i = rx.cur.clean as usize;
            // SAFETY: descriptor `i` is in the mapped ring; the controller
            // owns it until it writes DD, and reads of it are volatile.
            let st = unsafe {
                rx.dma.sync_for_cpu(mem.rx_desc(i) as *const u8, DESC_BYTES, Direction::Bidirectional);
                W::rx_status(core::ptr::read_volatile(&(*mem.rx_desc(i)).hi))
            };
            if !st.done {
                self.flush_tail(&mut rx);
                if !self.msi_armed.load(Ordering::Relaxed) {
                    // Polled mode has no link-change interrupt.
                    self.link_up.store(self.regs().link_is_up(), Ordering::Relaxed);
                }
                return Ok(0);
            }
            // The write-back is visible: the frame it describes is too.
            azos_dma::order::dma_rmb();
            let len = st.len as usize;
            let accept = rx_accept(&st, rx.cur.discarding, buf.len().min(BUF_SIZE));
            if accept {
                // SAFETY: buffer `i` holds `len <= BUF_SIZE` bytes the
                // controller wrote; `buf` has room for them.
                unsafe {
                    rx.dma.sync_for_cpu(mem.rx_buf(i) as *const u8, len, Direction::FromDevice);
                    core::ptr::copy_nonoverlapping(mem.rx_buf(i) as *const u8, buf.as_mut_ptr(), len);
                }
            }
            rx.cur.discarding = !st.eop;
            let taken = rx.cur.take(RX_N) as usize;
            let bus = rx.buf_bus + (taken * BUF_SIZE) as u64;
            // SAFETY: the descriptor and its buffer are ours again; the new
            // `RDT` is written only after this store (see `flush_tail`). The
            // write-back may have overwritten the buffer address: the
            // descriptor is posted whole.
            unsafe {
                rx.dma.sync_for_device(mem.rx_buf(taken) as *const u8, BUF_SIZE, Direction::FromDevice);
                mem.rx_desc(taken).write_volatile(rx_post(bus));
                rx.dma.sync_for_device(mem.rx_desc(taken) as *const u8, DESC_BYTES, Direction::Bidirectional);
            }
            if rx.cur.flush_due(Self::RX_RDT_BATCH) {
                self.flush_tail(&mut rx);
            }
            if accept {
                return Ok(len);
            }
        }
    }

    // ---- Transmit ----

    /// The stall clock looks at the controller now: the tick, and its credit.
    fn look(&self) -> (u64, u64) {
        let t = now();
        self.stall.observe(t, STALL_GAP_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000);
        (t, self.stall.credit())
    }

    fn reclaim(&self, tx: &mut TxState) {
        let dma = tx.dma;
        let mem = self.mem;
        let freed = tx.cur.reclaim(TX_N, |i| {
            // SAFETY: descriptor `i` is in the mapped ring; the controller
            // writes DD and then leaves it alone.
            unsafe {
                dma.sync_for_cpu(mem.tx_desc(i as usize) as *const u8, DESC_BYTES, Direction::Bidirectional);
                tx_done(core::ptr::read_volatile(&(*mem.tx_desc(i as usize)).hi))
            }
        });
        // Frames announced and not yet taken back (the ones of an open batch
        // are not the controller's to take).
        let held = (tx.cur.tail as usize + TX_N - tx.cur.clean as usize) % TX_N;
        let (t, credit) = self.look();
        tx.watch.reclaimed(t, credit, freed, held.saturating_sub(tx.pending as usize));
        self.tx_watched.store(tx.watch.running(), Ordering::Relaxed);
    }

    /// [`reclaim`](Self::reclaim), then look at the ring's budget:
    /// `Some((held, waited))` when its announced frames sat past it, for the
    /// caller to drop the lock and call [`tx_timed_out`](Self::tx_timed_out).
    fn reclaim_and_watch(&self, tx: &mut TxState) -> Option<(u64, u64)> {
        self.reclaim(tx);
        let (t, _) = self.look();
        let budget = self.tx_budget_ms.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1000;
        if !tx.watch.expired(&self.stall, t, budget) {
            return None;
        }
        let held = (tx.cur.tail as usize + TX_N - tx.cur.clean as usize) % TX_N;
        Some((held as u64, tx.watch.waited(t)))
    }

    /// `NetDevice::tx_watch`: look at the transmit ring between sends, so its
    /// budget runs out for a sender that sends seldom too (`TxWatch`).
    pub fn tx_watch(&self) -> Option<u64> {
        if !self.tx_watched.load(Ordering::Relaxed) || !self.ready.load(Ordering::Acquire) {
            return None;
        }
        let mut tx = self.tx.lock();
        if !self.ready.load(Ordering::Acquire) {
            return None;
        }
        if let Some((held, waited)) = self.reclaim_and_watch(&mut tx) {
            drop(tx);
            self.tx_timed_out(held, waited);
            return None;
        }
        tx.watch.running().then(|| now() + TX_LOOK_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000)
    }

    /// Tell the controller about every frame published so far.
    fn ring_doorbell(&self, tx: &mut TxState) {
        if tx.pending == 0 {
            return;
        }
        azos_dma::order::io_wmb();
        self.regs().wr(W::TX.tail, tx.cur.tail as u32);
        tx.pending = 0;
        let (t, credit) = self.look();
        tx.watch.published(t, credit);
        self.tx_watched.store(true, Ordering::Relaxed);
    }

    /// Frames sat in the transmit ring past the budget with the controller
    /// taking none (`held` of them, for `waited` ticks): the timeout policy
    /// resets the controller once, then latches it dead. Called by `send`
    /// or [`Nic::tx_watch`] with no lock held.
    #[cold]
    fn tx_timed_out(&self, held: u64, waited: u64) {
        let ms = waited.saturating_mul(1000) / azos_drv_sys::timebase::TIMER_FREQ.max(1);
        match self.recovery.timed_out(held, ms) {
            Verdict::Reset => {
                azos_drv_sys::kerr!("[NET] {}: {} frames sat {} ms in the transmit ring: resetting the controller", W::NAME, held, ms);
                let f = *self.restart.lock();
                let ok = f.is_some_and(|f| f(self));
                if !ok {
                    self.stop();
                    azos_drv_sys::kerr!("[NET] {}: the reset did not bring the controller back: the NIC is down until reboot", W::NAME);
                }
                self.recovery.reset_done(ok, held, ms);
            }
            Verdict::Latch => {
                self.stop();
                azos_drv_sys::kerr!("[NET] {}: transmit ring wedged again with its resets spent: the NIC is down until reboot", W::NAME);
            }
            Verdict::Handled => {}
        }
    }

    /// Stop the controller for good: no send or receive from here on, its
    /// interrupts masked and both engines off (the buffers stay the
    /// driver's, never reused).
    fn stop(&self) {
        self.ready.store(false, Ordering::Release);
        self.msi_armed.store(false, Ordering::Release);
        let r = self.regs();
        r.wr(W::IMC, !0);
        r.wr(crate::e1000e::REG_RCTL, 0);
        r.wr(crate::e1000e::REG_TCTL, 0);
    }

    /// Wait out every send and receive already inside its lock, once
    /// `ready` is clear: the next one sees it and leaves the rings alone.
    fn quiesce_paths(&self) {
        self.ready.store(false, Ordering::Release);
        drop(self.tx.lock());
        drop(self.rx.lock());
    }

    /// Queue `frame` for transmission: copied into the staging buffer of the
    /// next descriptor, which is published, and announced at once or at the
    /// end of the batch.
    #[inline]
    pub fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
        if !self.ready.load(Ordering::Acquire) {
            return Err(NetError::NotReady);
        }
        if frame.is_empty() || frame.len() > TX_FRAME_MAX {
            return Err(NetError::BadLength);
        }
        if !self.link_up.load(Ordering::Acquire) {
            // The MAC would hold the frame until the link comes: refuse it
            // instead of filling the ring. Polled mode learns of the link
            // here; with the interrupt it is the link-change cause.
            if self.msi_armed.load(Ordering::Relaxed) || !self.regs().link_is_up() {
                return Err(NetError::NotReady);
            }
            self.link_up.store(true, Ordering::Release);
        }
        let mem = self.mem;
        let mut tx = self.tx.lock();
        if !self.ready.load(Ordering::Acquire) {
            // Being reset: the ring is the restart's until it is live again.
            return Err(NetError::NotReady);
        }
        if let Some((held, waited)) = self.reclaim_and_watch(&mut tx) {
            drop(tx);
            self.tx_timed_out(held, waited);
            return Err(NetError::NotReady);
        }
        let Some(i) = tx.cur.push(TX_N) else {
            // Full: make sure what is queued is on its way, and say so.
            self.ring_doorbell(&mut tx);
            return Err(NetError::QueueFull);
        };
        let i = i as usize;
        let bus = tx.buf_bus + (i * BUF_SIZE) as u64;
        // SAFETY: slot `i` is ours (not in flight); the buffer holds
        // `frame.len() <= BUF_SIZE` bytes after the copy.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), mem.tx_buf(i), frame.len());
            tx.dma.sync_for_device(mem.tx_buf(i) as *const u8, frame.len(), Direction::ToDevice);
            mem.tx_desc(i).write_volatile(W::tx_frame(bus, frame.len()));
            tx.dma.sync_for_device(mem.tx_desc(i) as *const u8, DESC_BYTES, Direction::Bidirectional);
        }
        tx.pending = tx.pending.saturating_add(1);
        if tx_doorbell_due(tx.depth, tx.pending, Self::TX_BATCH_MAX) {
            self.ring_doorbell(&mut tx);
        }
        Ok(frame.len())
    }

    /// Open a TX batch: sends until [`Nic::tx_batch_end`] share one doorbell.
    pub fn tx_batch_begin(&self) {
        if self.ready.load(Ordering::Acquire) {
            let mut tx = self.tx.lock();
            tx.depth = tx.depth.saturating_add(1);
        }
    }

    /// Close the batch and announce what it queued.
    pub fn tx_batch_end(&self) {
        if self.ready.load(Ordering::Acquire) {
            let mut tx = self.tx.lock();
            tx.depth = tx.depth.saturating_sub(1);
            if tx.depth == 0 {
                self.ring_doorbell(&mut tx);
            }
        }
    }
}

// ---------------------------------------------------------------------
// PCI bring-up
// ---------------------------------------------------------------------

#[cfg(any(feature = "e1000e", feature = "igc"))]
pub use bring_up::*;

#[cfg(any(feature = "e1000e", feature = "igc"))]
mod bring_up {
    use super::*;
    use crate::e1000e::{
        mac_from_ra, ra_from_mac, ring_bytes, CTRL_CLEAR, CTRL_SLU, EECD_AUTO_RD, MTA_DWORDS, REG_CTRL, REG_EECD,
        REG_MTA, REG_RAH0, REG_RAL0, REG_RCTL, REG_TCTL, TCTL_PSP, XDCTL_QUEUE_ENABLE,
    };
    use azos_drv_sys::{kprintln, kwarn};
    use azos_drv_virtio::virtio::pci::msix_selftest::{map_bars, MsiRoute, SelftestError};
    use azos_pci::{BarWindow, ConfigSpace, FunctionInfo};

    /// Why [`Nic::init_pci`] did not bring the controller up.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum NicError {
        AlreadyUp,
        /// The function's device id is not one the driver knows (igc).
        UnknownDevice,
        Bars(SelftestError),
        /// BAR 0 is not a memory BAR.
        NoRegisters,
        /// A buffer mapping or the DMA domain was refused.
        Dma,
        /// The reset bit did not clear (e1000e).
        ResetTimeout,
        /// `RAL0/RAH0` hold no usable station address (reset did not
        /// finish, or the NVM is blank).
        NoMac,
    }

    /// What differs between the controllers during bring-up.
    pub trait Chip: Wire {
        /// What [`Chip::identify`] learns from the PCI function.
        type Model: Copy;
        /// How long [`Nic::go_live`] waits for the link.
        const LINK_WAIT_US: u64;
        /// Which part this function is; refused when the driver does not
        /// drive it. Before any register is touched.
        fn identify(info: &FunctionInfo) -> Result<Self::Model, NicError>;
        /// Reset the controller and set its link up: everything before the
        /// station address is read (see the [`Regs`] steps they share).
        fn reset(r: &Regs<Self>, info: &FunctionInfo, model: Self::Model) -> Result<(), NicError>;
        /// Describe both rings to the controller, enable the queues and
        /// start the engines (`TCTL`, `RCTL` last). The interrupts are
        /// still masked.
        fn start_queues(r: &Regs<Self>, rx_ring_bus: u64, tx_ring_bus: u64, rx_n: usize, tx_n: usize);
        /// The part-specific words of the bring-up line (`desc=ext`,
        /// `model=Igb`).
        fn detail(model: Self::Model, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result;
    }

    /// What [`Nic::init_pci`] gave the controller: [`Nic::restart`] brings
    /// it up again with the same function, rings, buffers and interrupt.
    #[derive(Clone, Copy)]
    pub struct Saved {
        info: FunctionInfo,
        dma: Dma,
        rx_ring_bus: u64,
        tx_ring_bus: u64,
        rx_buf_bus: u64,
        tx_buf_bus: u64,
        token: Option<u32>,
    }

    // SAFETY: as `RxState`: the `Dma` holds a `&'static dyn DmaDomain`,
    // immutable once the driver is up; the rest is plain data.
    unsafe impl Send for Saved {}

    struct Detail<C: Chip>(C::Model);

    impl<C: Chip> core::fmt::Display for Detail<C> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            C::detail(self.0, f)
        }
    }

    /// The reset and queue steps both controllers take the same way.
    impl<W: Wire> Regs<W> {
        /// Mask the interrupts, stop both engines and let in-flight DMA
        /// finish.
        pub fn quiesce(&self) {
            self.wr(W::IMC, !0);
            self.wr(REG_RCTL, 0);
            self.wr(REG_TCTL, TCTL_PSP);
            let _ = self.rd(REG_STATUS); // flush the posted writes
            wait_us(10_000);
        }

        /// Set the reset `bit` of `CTRL` and wait for it to clear itself;
        /// whether it did.
        pub fn reset_via(&self, bit: u32) -> bool {
            self.wr(REG_CTRL, self.rd(REG_CTRL) | bit);
            wait_us(20_000);
            wait_for(100_000, || self.rd(REG_CTRL) & bit == 0)
        }

        /// After the reset: the NVM load (station address, configuration)
        /// runs and is reported in `EECD` by controllers that have the bit
        /// (PCH parts do not, so a timeout is not an error); then what the
        /// reset raised is cleared.
        pub fn after_reset(&self) {
            let _ = wait_for(20_000, || self.rd(REG_EECD) & EECD_AUTO_RD != 0);
            self.wr(W::IMC, !0);
            let _ = self.rd(W::ICR); // clears what the reset raised
        }

        /// Link: set link up, leave speed and duplex to the auto-negotiation.
        pub fn link_setup(&self) {
            self.wr(REG_CTRL, (self.rd(REG_CTRL) | CTRL_SLU) & !CTRL_CLEAR);
        }

        /// The station address as the NVM load left it; the unicast filter
        /// is entry 0, the multicast table is cleared (`MPE` accepts
        /// multicast).
        pub fn program_mac(&self) -> Result<[u8; 6], NicError> {
            let mac = mac_from_ra(self.rd(REG_RAL0), self.rd(REG_RAH0)).ok_or(NicError::NoMac)?;
            let (ral, rah) = ra_from_mac(mac);
            self.wr(REG_RAL0, ral);
            self.wr(REG_RAH0, rah);
            for i in 0..MTA_DWORDS {
                self.wr(REG_MTA + 4 * i, 0);
            }
            Ok(mac)
        }

        /// Tell the controller where a ring of `n` descriptors is.
        pub fn describe_ring(&self, q: &RingRegs, bus: u64, n: usize) {
            self.wr(q.bal, bus as u32);
            self.wr(q.bah, (bus >> 32) as u32);
            self.wr(q.len, ring_bytes(n));
        }

        /// Head and tail to 0; the receive tail is written again when the
        /// controller is given its descriptors ([`Nic::go_live`]).
        pub fn zero_ring(&self, q: &RingRegs) {
            self.wr(q.head, 0);
            self.wr(q.tail, 0);
        }

        /// Wait for both queues to report enabled. A part that does not is
        /// not refused on that (Linux does not wait for it everywhere): the
        /// first frames say whether the queue runs.
        pub fn await_queues(&self) {
            let enabled = |q: &RingRegs| self.rd(q.ctl) & XDCTL_QUEUE_ENABLE != 0;
            if !wait_for(10_000, || enabled(&W::TX) && enabled(&W::RX)) {
                kwarn!("[NET] {}: a queue did not report enabled (TXDCTL {:#x} RXDCTL {:#x}); continuing",
                    W::NAME, self.rd(W::TX.ctl), self.rd(W::RX.ctl));
            }
        }
    }

    impl<C: Chip, const RX_N: usize, const TX_N: usize> Nic<C, RX_N, TX_N> {
        /// Bring up the function `info` as a NIC of the table.
        ///
        /// Its BAR 0 is assigned from `window` and mapped, the buffers and
        /// rings are mapped through the function's DMA domain, the
        /// controller is reset, its link set up and its rings started.
        /// Interrupt mode is chosen when `info` has an MSI capability and
        /// `route.prepare` provides a target for it; otherwise the receive
        /// path is polled.
        pub fn init_pci<Cfg, R>(
            &self,
            cfg: &mut Cfg,
            info: &FunctionInfo,
            window: &mut BarWindow,
            route: &mut R,
        ) -> Result<(), NicError>
        where
            Cfg: ConfigSpace,
            R: MsiRoute,
        {
            if self.ready.load(Ordering::Acquire) {
                return Err(NicError::AlreadyUp);
            }
            let model = C::identify(info)?;
            let bar_base = map_bars(cfg, info, window).map_err(NicError::Bars)?;
            let bar = bar_base[0];
            if bar == 0 {
                return Err(NicError::NoRegisters);
            }
            self.set_bar(bar);
            let r = self.bring_up(cfg, info, route, model);
            if r.is_err() {
                // Stop the DMA and the interrupts before the error is reported.
                let r = self.regs();
                r.wr(C::IMC, !0);
                r.wr(REG_RCTL, 0);
                r.wr(REG_TCTL, 0);
                self.msi_armed.store(false, Ordering::Release);
            }
            r
        }

        fn bring_up<Cfg: ConfigSpace, R: MsiRoute>(
            &self,
            cfg: &mut Cfg,
            info: &FunctionInfo,
            route: &mut R,
            model: C::Model,
        ) -> Result<(), NicError> {
            let mem = self.mem;
            let r = self.regs();
            // The buffers and rings, through the function's DMA domain.
            let dma = Dma::pci(info.bdf.requester_id());
            let map = |ptr: *const u8, len: usize, dir| dma.map(ptr, len, dir).map_err(|_| NicError::Dma);
            let rx_buf_bus = map(mem.rx_bufs.0.get() as *const u8, RX_N * BUF_SIZE, Direction::FromDevice)?;
            let tx_buf_bus = map(mem.tx_bufs.0.get() as *const u8, TX_N * BUF_SIZE, Direction::ToDevice)?;
            let rx_ring_bus = map(mem.rx_ring.0.get() as *const u8, RX_N * DESC_BYTES, Direction::Bidirectional)?;
            let tx_ring_bus = map(mem.tx_ring.0.get() as *const u8, TX_N * DESC_BYTES, Direction::Bidirectional)?;

            C::reset(&r, info, model)?;
            let mac = r.program_mac()?;
            self.prime(&dma, rx_buf_bus);

            // MSI: programmed before the interrupts are unmasked.
            let mut token = None;
            if let Some(msi) = info.msi {
                if route.prepare(1) {
                    let (addr, data) = route.target(0);
                    // The message is a DMA write to the doorbell: a
                    // translating domain must let it through.
                    dma.allow_msi(addr).map_err(|_| NicError::Dma)?;
                    if azos_pci::program_msi(cfg, info.bdf, &msi, addr, data)
                        && azos_pci::msi_is_enabled(cfg, info.bdf, &msi)
                    {
                        token = Some(route.isr_token(0));
                    }
                }
            }

            // Every buffer is mapped: from here a translating domain refuses
            // the controller anything else.
            dma.enable().map_err(|_| NicError::Dma)?;

            C::start_queues(&r, rx_ring_bus, tx_ring_bus, RX_N, TX_N);
            *self.saved.lock() = Some(Saved { info: *info, dma, rx_ring_bus, tx_ring_bus, rx_buf_bus, tx_buf_bus, token });
            self.set_restart(Self::restart);
            self.go_live(dma, rx_buf_bus, tx_buf_bus, mac, C::LINK_WAIT_US, token);

            let link = C::link(r.rd(REG_STATUS));
            if let Some(token) = token {
                kprintln!("[NET] {} {} mode=irq token={} {} rx={} tx={}",
                    C::NAME, info.bdf, token, Detail::<C>(model), RX_N, TX_N);
            } else {
                kprintln!("[NET] {} {} mode=poll (no MSI route on this machine) {} rx={} tx={}",
                    C::NAME, info.bdf, Detail::<C>(model), RX_N, TX_N);
            }
            if link.up {
                kprintln!("[NET] {} link up {} Mb/s", C::NAME, link.mbps);
            } else {
                kwarn!("[NET] {} link down after {} ms: frames are refused until it comes", C::NAME, C::LINK_WAIT_US / 1000);
            }
            kprintln!(
                "[NET] {}: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                C::NAME, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            Ok(())
        }

        /// After a wedged transmit ring (the timeout policy handed out the
        /// reset): stop every path, reset the controller and bring it up
        /// again as `bring_up` did, over the same rings and buffers (no
        /// mapping, no MSI programming: the function's config space is
        /// untouched by `CTRL.RST`). The frames in the ring are dropped.
        /// `false`: the controller did not come back, or it is not the same
        /// one (another station address).
        fn restart(&self) -> bool {
            let Some(sv) = *self.saved.lock() else { return false };
            let Ok(model) = C::identify(&sv.info) else { return false };
            self.quiesce_paths();
            let r = self.regs();
            if C::reset(&r, &sv.info, model).is_err() {
                return false;
            }
            match r.program_mac() {
                Ok(mac) if mac == self.mac() => {}
                _ => {
                    kwarn!("[NET] {} {}: no station address, or another one, after the reset", C::NAME, sv.info.bdf);
                    return false;
                }
            }
            self.prime(&sv.dma, sv.rx_buf_bus);
            C::start_queues(&r, sv.rx_ring_bus, sv.tx_ring_bus, RX_N, TX_N);
            self.go_live(sv.dma, sv.rx_buf_bus, sv.tx_buf_bus, self.mac(), C::LINK_WAIT_US, sv.token);
            kprintln!("[NET] {} {}: controller reset and brought up again", C::NAME, sv.info.bdf);
            true
        }
    }
}
