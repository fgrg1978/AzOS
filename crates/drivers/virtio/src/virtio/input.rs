// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO input (device id 18): keyboards, mice and tablets, by interrupt.
//!
//! Event queue 0 holds device-writable 8-byte buffers (`struct
//! virtio_input_event`: `type u16`, `code u16`, `value u32`, little endian).
//! The driver posts every buffer once and re-posts each as it is reaped, so
//! the device always has somewhere to put the next event. The status queue
//! (LEDs) is not set up: leaving a queue unready is legal.
//!
//! Completion is by interrupt, as the block device: the kernel wires each
//! transport's line ([`set_irq_line`]), the arm for that line calls [`irq`],
//! which acknowledges the device and reaps the used ring in interrupt context.
//! The handler is the whole consumer — there is no task to wake for it — so
//! each event is decided on the spot ([`azos_drv_input::keymap::route`]):
//!
//! * a keyboard's key press becomes a console byte in the UART's RX ring
//!   ([`azos_drv_sys::uart::rx_push`]): the same ring, the same single owner
//!   of console input, so the shell reads a virtio keyboard with no
//!   UART input at all;
//! * everything else (mouse buttons, axes and wheel, tablet positions, the
//!   modifier keys, keys with no byte) is published into the shared event
//!   ring ([`azos_drv_input::events`], packed with
//!   [`azos_drv_input::keymap::pack`]), and counted in [`stats`]. **The
//!   ring-3 terminal server drains that ring** (`userspace/services/termd`);
//!   a full ring drops the newest event (counted in `ring_drops`). The PS/2
//!   driver (`azos_drv_input::ps2`) publishes into the same ring, in the same
//!   word format.
//!
//! Queue memory and event buffers are in `static` storage behind one lock that
//! is taken only before a line is enabled and inside the handler (interrupts
//! off): never held across an enabled interrupt.

// The vf2 and k1 boards carry no virtio-input device: `init_at` below refuses
// every window, and the bring-up it would call is not reachable.
#![cfg_attr(any(feature = "vf2", feature = "k1"), allow(unused_imports, dead_code))]

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use azos_sync::SpinLock;
use azos_drv_input::events;

pub use super::input_cfg::{Info, Kind};
use super::input_cfg::{read_info, CFG_MAX};
use azos_drv_input::keymap::{pack, route, Keymap, Route, BTN_MOUSE, EV_ABS, EV_KEY, EV_REL};
use azos_dma::Direction;
use super::{
    Dma, init as virtio_init, mmio_read, mmio_write, probe, virtq_alloc_desc,
    virtq_init, virtq_notify_mmio, virtq_poll_with_len, virtq_publish, VirtioDev, Virtq,
    VIRTIO_DEV_INPUT, VIRTIO_MMIO_BASE, VIRTIO_MMIO_CONFIG, VIRTIO_MMIO_COUNT,
    VIRTIO_MMIO_INTERRUPT_ACK, VIRTIO_MMIO_INTERRUPT_STATUS, VIRTIO_MMIO_STATUS,
    VIRTIO_MMIO_STRIDE, VIRTIO_QUEUE_SIZE, VIRTIO_STATUS_DRIVER_OK,
};
use azos_drv_sys::kprintln;

/// Devices kept (a keyboard and a mouse are the usual pair).
pub const MAX_DEVS: usize = 4;
/// One buffer per event-queue slot.
const EVQ: usize = VIRTIO_QUEUE_SIZE;
/// Bytes of one `virtio_input_event`.
const EV_BYTES: u32 = 8;
/// One event buffer alone in its cache lines: behind a non-coherent device the
/// CPU flushes a buffer's lines as it re-posts it, and a neighbour the device
/// is writing must not share one.
#[repr(C, align(128))]
struct EvBuf([u32; 2]);

struct Dev {
    vdev: VirtioDev,
    vq: Virtq,
    /// The device's DMA domain and the bus address of `bufs[0]` (the buffers
    /// are `size_of::<EvBuf>()` apart).
    dma: Dma,
    bufs_bus: u64,
    /// The device's DMA target: slot `i` is descriptor `i`'s buffer.
    bufs: [EvBuf; EVQ],
    km: Keymap,
    info: Info,
    slot: usize,
    ready: bool,
}

impl Dev {
    const fn zeroed() -> Self {
        Dev {
            vdev: VirtioDev::zeroed(),
            vq: Virtq::zeroed(),
            dma: Dma::fallback(),
            bufs_bus: 0,
            bufs: [const { EvBuf([0; 2]) }; EVQ],
            km: Keymap::new(),
            info: Info { name: [0; 32], name_len: 0, kind: Kind::Other },
            slot: usize::MAX,
            ready: false,
        }
    }
}

struct State {
    devs: [Dev; MAX_DEVS],
    n: usize,
}

// SAFETY: the raw pointers inside are used only under `INPUT`'s lock.
unsafe impl Send for State {}

static INPUT: SpinLock<State> = SpinLock::new(State { devs: [const { Dev::zeroed() }; MAX_DEVS], n: 0 });

/// The wired line of device `i` (`u32::MAX`: not wired), read lock-free by
/// every interrupt arm before it takes the lock.
static LINES: [AtomicU32; MAX_DEVS] = [const { AtomicU32::new(u32::MAX) }; MAX_DEVS];

// ---- Counters (read by `stats`) ----
static EVENTS: AtomicU32 = AtomicU32::new(0);
static KEY_BYTES: AtomicU32 = AtomicU32::new(0);
static BYTE_DROPS: AtomicU32 = AtomicU32::new(0);
static MOUSE_REL: AtomicU32 = AtomicU32::new(0);
static MOUSE_ABS: AtomicU32 = AtomicU32::new(0);
static MOUSE_BTN: AtomicU32 = AtomicU32::new(0);
static PUBLISHED: AtomicU32 = AtomicU32::new(0);
static RING_DROPS: AtomicU32 = AtomicU32::new(0);
static SHORT: AtomicU32 = AtomicU32::new(0);
static IRQS: AtomicU32 = AtomicU32::new(0);
static NDEVS: AtomicUsize = AtomicUsize::new(0);

/// What the driver has seen since boot.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub irqs: u32,
    pub events: u32,
    /// Console bytes queued from key presses.
    pub key_bytes: u32,
    /// Key bytes the RX ring refused (full, or a `^C` taken by a lent console).
    pub byte_drops: u32,
    /// Mouse/tablet: relative-axis events, absolute-axis events, button events.
    pub rel: u32,
    pub abs: u32,
    pub buttons: u32,
    /// Events put in the shared event ring, and those it had no room for.
    pub published: u32,
    pub ring_drops: u32,
    /// Used entries shorter than an event.
    pub short: u32,
}

pub fn stats() -> Stats {
    Stats {
        irqs: IRQS.load(Ordering::Relaxed),
        events: EVENTS.load(Ordering::Relaxed),
        key_bytes: KEY_BYTES.load(Ordering::Relaxed),
        byte_drops: BYTE_DROPS.load(Ordering::Relaxed),
        rel: MOUSE_REL.load(Ordering::Relaxed),
        abs: MOUSE_ABS.load(Ordering::Relaxed),
        buttons: MOUSE_BTN.load(Ordering::Relaxed),
        published: PUBLISHED.load(Ordering::Relaxed),
        ring_drops: RING_DROPS.load(Ordering::Relaxed),
        short: SHORT.load(Ordering::Relaxed),
    }
}

/// Devices brought up.
pub fn device_count() -> usize {
    NDEVS.load(Ordering::Acquire)
}

// ---- Config space: byte access ----
//
// `select`/`subsel`/`size` are single bytes and the answer is a byte string:
// a 32-bit access would write or read the neighbours too.

#[inline(always)]
unsafe fn cfg_read8(dev: &VirtioDev, off: usize) -> u8 {
    core::ptr::read_volatile((dev.base as *const u8).add(VIRTIO_MMIO_CONFIG as usize + off))
}

#[inline(always)]
unsafe fn cfg_write8(dev: &VirtioDev, off: usize, v: u8) {
    core::ptr::write_volatile((dev.base as *mut u8).add(VIRTIO_MMIO_CONFIG as usize + off), v)
}

/// One config query against a real device: the answer's bytes and count.
unsafe fn cfg_query(dev: &VirtioDev, select: u8, subsel: u8, out: &mut [u8; CFG_MAX]) -> usize {
    cfg_write8(dev, 0, select);
    cfg_write8(dev, 1, subsel);
    core::sync::atomic::fence(Ordering::SeqCst);
    let size = (cfg_read8(dev, 2) as usize).min(CFG_MAX);
    for (i, b) in out.iter_mut().enumerate().take(size) {
        *b = cfg_read8(dev, 8 + i);
    }
    size
}

// ---- Bring-up ----

/// Bring up the virtio-input device whose virtio-mmio transport is at `base`
/// and post its buffers. Called by the hardware bus when it binds
/// `virtio-input` to a device (`kernel/src/boot/hwbus.rs`), in task context,
/// before any line is enabled; the buffers are posted but the lines are the
/// kernel's to wire ([`set_irq_line`]). `Err` for a window that is not an
/// input device, a full device table, or a device that fails its bring-up.
#[cfg(any(feature = "vf2", feature = "k1"))]
pub fn init_at(_base: usize) -> Result<(), ()> { Err(()) }

#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub fn init_at(base: usize) -> Result<(), ()> {
    let mut st = INPUT.lock();
    if st.n >= MAX_DEVS {
        return Err(());
    }
    let slot = match base.checked_sub(VIRTIO_MMIO_BASE) {
        Some(off) if off % VIRTIO_MMIO_STRIDE == 0 && off / VIRTIO_MMIO_STRIDE < VIRTIO_MMIO_COUNT => {
            off / VIRTIO_MMIO_STRIDE
        }
        _ => return Err(()),
    };
    let mut vdev = VirtioDev::zeroed();
    if unsafe { probe(base, &mut vdev) }.is_err() || vdev.device_id != VIRTIO_DEV_INPUT {
        return Err(());
    }
    let i = st.n;
    let d = &mut st.devs[i];
    if unsafe { virtio_init(&mut vdev) }.is_err() {
        kprintln!("[VIRTIO-INPUT] slot {}: FEATURES_OK refused", slot);
        return Err(());
    }
    d.info = read_info(&mut |sel, sub, out| unsafe { cfg_query(&vdev, sel, sub, out) });
    // The device's DMA domain, and its event buffers mapped through it
    // (the device writes them).
    d.dma = Dma::mmio(base);
    let dma = d.dma;
    match dma.map(d.bufs.as_ptr() as *const u8, EVQ * core::mem::size_of::<EvBuf>(), Direction::FromDevice) {
        Ok(bus) => d.bufs_bus = bus,
        Err(()) => {
            kprintln!("[VIRTIO-INPUT] slot {}: event buffers not mappable", slot);
            return Err(());
        }
    }
    if unsafe { virtq_init(&mut vdev, 0, &mut d.vq, &dma) }.is_err() || dma.enable().is_err() {
        kprintln!("[VIRTIO-INPUT] slot {}: event queue 0 could not be set up", slot);
        return Err(());
    }
    // Every buffer, once: descriptor `idx` owns `bufs[idx]`.
    for _ in 0..(d.vq.num as usize).min(EVQ) {
        let Some(idx) = (unsafe { virtq_alloc_desc(&mut d.vq) }) else { break };
        unsafe {
            let desc = d.vq.desc.add(idx);
            dma.sync_for_device((&raw const d.bufs[idx]) as *const u8, EV_BYTES as usize, Direction::FromDevice);
            (*desc).addr = d.bufs_bus + (idx * core::mem::size_of::<EvBuf>()) as u64;
            (*desc).len = EV_BYTES;
            (*desc).flags = super::VIRTQ_DESC_F_WRITE;
            (*desc).next = 0;
            virtq_publish(&mut d.vq, idx);
        }
    }
    unsafe {
        let s = mmio_read(vdev.base, VIRTIO_MMIO_STATUS);
        mmio_write(vdev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK);
        virtq_notify_mmio(&vdev, 0);
    }
    d.vdev = vdev;
    d.slot = slot;
    d.km = Keymap::new();
    d.ready = true;
    kprintln!("[VIRTIO-INPUT] slot {}: \"{}\" ({}, virtio-mmio v{})",
        slot, d.info.name(), d.info.kind.name(), vdev.version);
    st.n += 1;
    NDEVS.store(st.n, Ordering::Release);
    Ok(())
}

/// Device `i`: `(slot, MMIO base, kind)`, for the kernel to map to a line.
pub fn device(i: usize) -> Option<(usize, usize, Kind)> {
    let st = INPUT.lock();
    if i >= st.n || !st.devs[i].ready {
        return None;
    }
    let d = &st.devs[i];
    Some((d.slot, d.vdev.base as usize, d.info.kind))
}

/// Take device `i`'s events by interrupt on `line`. Call BEFORE the interrupt
/// controller enables `line` (the arm must already recognise it: [`irq`]);
/// the interrupt the device raised while it was being set up is acknowledged
/// here so a level line is not asserted the moment it is enabled.
pub fn set_irq_line(i: usize, line: u32) -> bool {
    let st = INPUT.lock();
    if i >= st.n || !st.devs[i].ready {
        return false;
    }
    let base = st.devs[i].vdev.base;
    unsafe {
        let status = mmio_read(base, VIRTIO_MMIO_INTERRUPT_STATUS);
        mmio_write(base, VIRTIO_MMIO_INTERRUPT_ACK, status);
    }
    LINES[i].store(line, Ordering::Release);
    true
}

/// Undo [`set_irq_line`] for device `i`: the interrupt controller refused to
/// enable the line, so it is no longer one of the wired lines.
pub fn irq_line_off(i: usize) {
    if let Some(l) = LINES.get(i) {
        l.store(u32::MAX, Ordering::Release);
    }
}

/// Is `line` one of the wired lines?
pub fn owns_line(line: u32) -> bool {
    line != u32::MAX && LINES.iter().any(|l| l.load(Ordering::Acquire) == line)
}

/// The interrupt arm for `line` (interrupt context, interrupts off): `None`
/// when the line is not a virtio-input device's. Otherwise acknowledge the
/// device, reap its used ring, route each event, re-post each buffer and ring
/// the doorbell once. `Some(true)`: console bytes were queued, or the terminal
/// server slept on the event ring and was nudged, so the caller wakes the
/// console's parked reader (`uart::rx_waiter_take`).
pub fn irq(line: u32) -> Option<bool> {
    if line == u32::MAX {
        return None;
    }
    let i = LINES.iter().position(|l| l.load(Ordering::Acquire) == line)?;
    let mut st = INPUT.lock();
    let d = &mut st.devs[i];
    if !d.ready {
        return Some(false);
    }
    IRQS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `vdev.base` is the initialised device's mapped MMIO window.
    unsafe {
        let status = mmio_read(d.vdev.base, VIRTIO_MMIO_INTERRUPT_STATUS);
        mmio_write(d.vdev.base, VIRTIO_MMIO_INTERRUPT_ACK, status);
    }
    let mut wake = false;
    let mut recycled = false;
    // SAFETY: the queue was initialised by `init_all` and is touched only here.
    while let Some((idx, len)) = unsafe { virtq_poll_with_len(&mut d.vq) } {
        if len >= EV_BYTES as usize {
            // SAFETY: `idx < num <= EVQ` (checked by the poll); the device wrote it.
            let (w0, w1) = unsafe {
                d.dma.sync_for_cpu((&raw const d.bufs[idx]) as *const u8, EV_BYTES as usize, Direction::FromDevice);
                (u32::from_le(core::ptr::read_volatile(&raw const d.bufs[idx].0[0])),
                 u32::from_le(core::ptr::read_volatile(&raw const d.bufs[idx].0[1])))
            };
            let (ty, code, value) = (w0 as u16, (w0 >> 16) as u16, w1);
            EVENTS.fetch_add(1, Ordering::Relaxed);
            let r = if d.info.kind == Kind::Keyboard {
                route(&mut d.km, ty, code, value)
            } else if ty == 0 {
                Route::Consumed
            } else {
                Route::Publish
            };
            match r {
                Route::Byte(b) => {
                    events::observe(pack(ty, code, value));
                    if !cfg!(feature = "input-rx-canary") && azos_drv_sys::uart::rx_push(b) {
                        KEY_BYTES.fetch_add(1, Ordering::Relaxed);
                        wake = true;
                    } else {
                        BYTE_DROPS.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Route::Consumed => {
                    // A swallowed key event (the release of a key that made a
                    // byte) still belongs to the input server's stream.
                    if ty == EV_KEY {
                        events::observe(pack(ty, code, value));
                    }
                }
                Route::Publish => {
                    match ty {
                        EV_REL => { MOUSE_REL.fetch_add(1, Ordering::Relaxed); }
                        EV_ABS => { MOUSE_ABS.fetch_add(1, Ordering::Relaxed); }
                        // A modifier or a key with no byte is published too; only a
                        // mouse button counts as one.
                        EV_KEY if code >= BTN_MOUSE => { MOUSE_BTN.fetch_add(1, Ordering::Relaxed); }
                        _ => {}
                    }
                    let r = events::publish(pack(ty, code, value));
                    if r.kept() {
                        PUBLISHED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        RING_DROPS.fetch_add(1, Ordering::Relaxed);
                    }
                    // The terminal server slept on the ring: nudge its console
                    // wait and have the caller wake it.
                    if r.wake() {
                        azos_drv_sys::uart::rx_nudge();
                        wake = true;
                    }
                }
            }
        } else {
            SHORT.fetch_add(1, Ordering::Relaxed);
        }
        // Re-post the same descriptor: its buffer is free again.
        unsafe {
            d.dma.sync_for_device((&raw const d.bufs[idx]) as *const u8, EV_BYTES as usize, Direction::FromDevice);
            virtq_publish(&mut d.vq, idx);
        }
        recycled = true;
    }
    if recycled {
        unsafe { virtq_notify_mmio(&d.vdev, 0) };
    }
    Some(wake)
}
