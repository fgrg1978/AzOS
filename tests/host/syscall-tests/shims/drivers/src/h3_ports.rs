// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-ins for the four interface adapters the kernel hosts in
//! `crates/core/syscall/src/devices.rs`: `SpiPort` and `CanPort`
//! (`crates/drivers/bus`), `BridgePort` (the UART bridge) and `AdcPort`
//! (`crates/drivers/sensor`'s ADS1115).
//!
//! The adapters are tested against their drivers in `tests/host/drivers-tests`;
//! what `syscall-tests` asks is what the SERVER in front of them does: which
//! op class it demands, in what order, and what reaches the adapter. So every
//! op here only RECORDS that it was reached (`calls`: op, resource, argument)
//! and answers the outcome a test armed (`answer`, 0 = served), with a value
//! the test can recognise on the wire. Nothing else is simulated, and the
//! ports that keep state across calls (the bridge's rings, the ADC's batch)
//! keep exactly the state the real ones keep and use the real `Batch`.

use azos_devif::adc::{self, Batch, Record, RecordSink, SampleQueue};
use azos_devif::can::{self, Frame};
use azos_devif::i2c::Bytes;
use azos_devif::uart::{self, Chunk, ChunkSink, ChunkSource, RxQueue, TxQueue};
use azos_devif::{outcome, Cap, Out};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::Mutex;

static CALLS: Mutex<Vec<(&'static str, u32, u32)>> = Mutex::new(Vec::new());
static ANSWER: AtomicU32 = AtomicU32::new(outcome::OK);

/// Every adapter op reached since the last [`reset`], in order:
/// `(op, resource, first argument)`.
pub fn calls() -> Vec<(&'static str, u32, u32)> {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Forget the calls and arm the outcome the adapters answer from now on.
pub fn reset(answer: u32) {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ANSWER.store(answer, SeqCst);
}

thread_local! {
    static PASS_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` in the middle of every adapter pass of THIS thread: where the real
/// adapters busy-wait on the transmitter or sleep in the I2C queue. A test
/// uses it to do what other tasks do meanwhile (attach, stop, exit); with a
/// spin lock held across the pass that would never return.
pub fn on_pass(f: Option<Box<dyn FnMut()>>) {
    PASS_HOOK.with(|h| *h.borrow_mut() = f);
}

fn mid_pass() {
    // Taken out while it runs, so the hook may itself reach a pass.
    if let Some(mut f) = PASS_HOOK.with(|h| h.borrow_mut().take()) {
        f();
        PASS_HOOK.with(|h| {
            let mut slot = h.borrow_mut();
            if slot.is_none() {
                *slot = Some(f);
            }
        });
    }
}

fn note(op: &'static str, resource: u32, arg: u32) -> u32 {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, resource, arg));
    ANSWER.load(SeqCst)
}

/// Answer `value` with the armed outcome (the value only when it is 0).
fn out<T: Default>(code: u32, value: T) -> Out<T> {
    if code == outcome::OK { Out::ok(value) } else { Out::err(code) }
}

// ── Spi ───────────────────────────────────────────────────────────────────

/// The `Spi` adapter of one chip select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpiPort {
    pub bus: u8,
    pub cs: u8,
}

impl SpiPort {
    pub const fn from_badge(badge: u32) -> Self {
        let (bus, cs) = azos_devif::spi::unbadge(badge);
        SpiPort { bus, cs }
    }

    fn badge(&self) -> u32 {
        azos_devif::spi::badge(self.bus, self.cs)
    }
}

impl azos_devif::Spi for SpiPort {
    fn transfer(&mut self, data: Bytes) -> Out<Bytes> {
        out(note("spi.transfer", self.badge(), data.n as u32), data)
    }
    fn write(&mut self, data: Bytes) -> Out<()> {
        out(note("spi.write", self.badge(), data.n as u32), ())
    }
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        out(note("spi.read", self.badge(), reg), Bytes::from_slice(&[0xA5; 3][..(len as usize).min(3)]))
    }
    fn set_mode(&mut self, mode: u32) -> Out<()> {
        out(note("spi.mode", self.badge(), mode), ())
    }
    fn set_speed(&mut self, hz: u32) -> Out<()> {
        out(note("spi.speed", self.badge(), hz), ())
    }
    fn hold_cs(&mut self, hold: bool) -> Out<()> {
        out(note("spi.hold", self.badge(), hold as u32), ())
    }
}

// ── Can ───────────────────────────────────────────────────────────────────

/// The `Can` adapter of the one controller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CanPort;

/// The frame `recv` answers.
pub fn can_rx_frame() -> Frame {
    Frame::new(0x123, 0, &[1, 2, 3])
}

impl azos_devif::Can for CanPort {
    fn send(&mut self, frame: Frame) -> Out<()> {
        out(note("can.send", 0, frame.id), ())
    }
    fn recv(&mut self) -> Out<Frame> {
        out(note("can.recv", 0, 0), can_rx_frame())
    }
    fn add_filter(&mut self, id: u32, _mask: u32) -> Out<()> {
        out(note("can.filter", 0, id), ())
    }
    fn clear_filters(&mut self) -> Out<()> {
        out(note("can.clear", 0, 0), ())
    }
    fn set_bitrate(&mut self, bps: u32) -> Out<()> {
        out(note("can.bitrate", 0, bps), ())
    }
    fn state(&self) -> Out<u32> {
        out(note("can.state", 0, 0), can::STATE_ACTIVE)
    }
    fn recover(&mut self) -> Out<()> {
        out(note("can.recover", 0, 0), ())
    }
}

// ── Uart (the bridge) ─────────────────────────────────────────────────────

/// The port number the bridge answers to.
pub const BRIDGE_PORT: u32 = 1;

/// The `Uart` adapter of the bridge: it keeps the rings it was attached to,
/// as the real one does, and moves one chunk each way per [`pump`](Self::pump).
#[derive(Clone)]
pub struct BridgePort {
    port: u32,
    rings: Option<(Cap<RxQueue>, Cap<TxQueue>)>,
}

impl BridgePort {
    pub const fn new(port: u32) -> Self {
        BridgePort { port, rings: None }
    }

    pub fn queues(&self) -> Option<(Cap<RxQueue>, Cap<TxQueue>)> {
        self.rings
    }

    /// One received chunk (the bytes `[0xB0, port]`) to `rx`, and what `tx`
    /// holds to the line (noted); the chunks moved. Nothing while detached.
    pub fn pump(&mut self, rx: &mut impl ChunkSink, tx: &mut impl ChunkSource) -> usize {
        if self.rings.is_none() {
            return 0;
        }
        mid_pass();
        let mut moved = 0;
        if rx.push(&Chunk::new(&[0xB0, self.port as u8], 0)) {
            moved += 1;
        }
        while let Some(c) = tx.pop() {
            note("bridge.tx", self.port, c.len);
            moved += 1;
        }
        moved
    }
}

impl azos_devif::Uart for BridgePort {
    fn configure(&mut self, baud: u32, _data_bits: u32, _parity: u32, _stop_bits: u32) -> Out<()> {
        if self.port != BRIDGE_PORT {
            return Out::err(outcome::NO_RESOURCE);
        }
        out(note("uart.configure", self.port, baud), ())
    }
    fn attach(&mut self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()> {
        if self.port != BRIDGE_PORT {
            return Out::err(outcome::NO_RESOURCE);
        }
        let code = note("uart.attach", self.port, rx.raw());
        if code != outcome::OK {
            return Out::err(code);
        }
        if self.rings.is_some() {
            return Out::err(outcome::BUSY);
        }
        self.rings = Some((rx, tx));
        Out::ok(())
    }
    fn detach(&mut self) -> Out<()> {
        self.rings = None;
        out(note("uart.detach", self.port, 0), ())
    }
    fn status(&self) -> Out<uart::Status> {
        if self.port != BRIDGE_PORT {
            return Out::err(outcome::NO_RESOURCE);
        }
        out(note("uart.status", self.port, 0), uart::Status::default())
    }
}

// ── Adc ───────────────────────────────────────────────────────────────────

/// The `Adc` adapter of one channel, with the real [`Batch`]. A sample is the
/// reading `raw = 100 + channel`, `mv = 7`.
#[derive(Clone)]
pub struct AdcPort {
    channel: u8,
    batch: Batch,
    queue: Option<Cap<SampleQueue>>,
}

impl AdcPort {
    pub const fn new(channel: u32) -> Self {
        AdcPort { channel: if channel > 255 { 255 } else { channel as u8 }, batch: Batch::idle(), queue: None }
    }

    pub fn queue(&self) -> Option<Cap<SampleQueue>> {
        self.queue
    }

    pub fn next_due_ns(&self) -> Option<u64> {
        self.batch.next_due_ns()
    }

    pub fn pump(&mut self, now_ns: u64, sink: &mut impl RecordSink) -> bool {
        if !self.batch.due(now_ns) {
            return false;
        }
        mid_pass();
        let record: Record = self.batch.record(now_ns, self.channel, 100 + self.channel as i16, 7);
        let delivered = sink.push(&record);
        self.batch.done(now_ns, delivered);
        if !self.batch.is_active() {
            self.queue = None;
        }
        true
    }
}

impl azos_devif::Adc for AdcPort {
    fn read(&mut self) -> Out<adc::Reading> {
        out(note("adc.read", self.channel as u32, 0), adc::Reading { raw: 100 + self.channel as i32, mv: 7 })
    }
    fn set_rate(&mut self, hz: u32) -> Out<u32> {
        out(note("adc.set_rate", self.channel as u32, hz), hz)
    }
    fn rate(&self) -> Out<u32> {
        out(note("adc.rate", self.channel as u32, 0), 128)
    }
    fn start_batch(&mut self, queue: Cap<SampleQueue>, count: u32) -> Out<()> {
        let code = note("adc.start_batch", self.channel as u32, queue.raw());
        if code != outcome::OK {
            return Out::err(code);
        }
        if self.batch.is_active() {
            return Out::err(outcome::BUSY);
        }
        self.batch.start(128, count);
        self.queue = Some(queue);
        Out::ok(())
    }
    fn stop_batch(&mut self) -> Out<u32> {
        self.queue = None;
        out(note("adc.stop_batch", self.channel as u32, 0), self.batch.stop())
    }
}
