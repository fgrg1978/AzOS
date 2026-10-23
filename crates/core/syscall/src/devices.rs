// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Gpio`, `I2c`, `Pwm`, `Spi`, `Can`, `Uart` and `Adc` interfaces the
//! kernel hosts: one pin, one device on a bus, one PWM channel, one SPI chip
//! select, one CAN controller, one serial port, one ADC channel, each the
//! badge of the endpoint capability a topology row grants (`endpoint =
//! "gpio.20"`, `"i2c.0.0x68"`, `"pwm.4"`, `"spi.0.1"`, `"can.0"`, `"uart.1"`,
//! `"adc.2"`).
//!
//! Each op makes the same three checks, in this order, before it touches a
//! driver: the op class the capability carries (`READ` observes, `WRITE`
//! acts; containment refuses the acting class), the resource the badge names
//! (a pin or a channel the board has), and, for the acting ops, that the
//! resource is not one a motor drives. The motor's H-bridge is reachable only
//! through the `Motor` interface, whose path runs the e-stop latch and the
//! actuation envelope: a duty or a direction pin written below it would
//! bypass both. The drivers run with NO capability-table lock held (the
//! caller's rights were read before the op; a driver transfer under the table's
//! preemption-disabling lock would nest the driver's own).
//!
//! # Queues (`Uart::attach`, `Adc::start_batch`)
//!
//! Bytes and samples never cross a call: the client makes a queue, hands the
//! kernel its end, and the pump ([`pump`]) moves data between the queue and
//! the adapter (`BridgePort::pump`, a plugged line's `pump`, `AdcPort::pump`). A queue is a **region
//! ring**: a `Cap<Shm>` to a zero-filled read-write region whose pages are
//! physically contiguous (`MemSpec::contig`), laid out as
//! `azos_rings::region::SpscSlots` (a zero region is an empty ring), with the
//! record (2 words, 16 bytes) or the chunk (5 words, 40 bytes) as the slot and
//! as many slots as the region holds in a power of two (`slots_for`): the
//! capacity is the region's size, so client and kernel cannot disagree.
//!
//! The kernel end is **resolved in place**, not moved: the handle in the
//! request is read in the caller's table (it must be a `Shm` carrying `WRITE`
//! for a queue the kernel fills, `READ` for one it drains), the client keeps
//! its handle, and only the packed `(index, generation)` reference is kept.
//! Every push or pop asks the region table again
//! (`azos_ipc::memobj::memobj_with_span_ref`, which holds its lock across the
//! one ring step), so a region freed, resized or broken out of copy-on-write
//! after the attach is a failed push, which ends the attachment, and never a
//! write into a frame that belongs to someone else.
//!
//! The region is the client's, shared with the reader it chose: every index
//! and flag in it is untrusted. The ring step masks each index into the ring,
//! so a hostile value misplaces the client's own data and nothing outside the
//! span; a transmit slot is decoded with the length checked (`Chunk::decode`).
//! The attachment belongs to the task that made it: its exit ends it
//! ([`release_all`], from the kernel's task-exit hook), and so does the region
//! being freed (the next pass finds the reference stale). Any holder of
//! `WRITE` on the port may detach; a full ring drops the newest item and the next record or chunk that fits says
//! so (`RECORD_LOST`, `CHUNK_OVERRUN`).
//!
//! The pump runs in a kernel task of its own (`dev-pump`), created by the
//! first attach and parked while nothing is attached ([`kick_pump`]); no lock
//! is held while an adapter works (see [`pump`]).
//!
//! # The `Uart` port table
//!
//! `Uart` ports are slots of one table ([`PORTS`]). Slot `uart.1` is the
//! companion-radio bridge (`BridgePort`, a board's own UART). The slots after
//! it are for **hot-plugged lines**: a driver that finds a serial device at run
//! time (the USB CDC-ACM function, `kernel/src/boot/usb/serial.rs`) offers it
//! with [`plug_line`], which answers the port number it got (`uart.2`, one
//! line at a time because the class driver serves one), and withdraws it with
//! [`unplug_line`] when the device goes. A line is a [`SerialLine`], behind a
//! sleeping lock of its own, so **the table's spin lock is never held while a
//! line works**: every op copies the slot's adapter out, runs on the copy and
//! publishes only if the slot is still the one it started from (`gen`, bumped
//! by every attach, end, plug and unplug). A slot with nothing plugged in
//! answers like a port the board does not have (`NO_RESOURCE`), which is also
//! what a ring-3 client that holds `uart.2` sees while the device is absent or
//! after it was unplugged; its queues are dropped with the line, and it
//! attaches again when the next device comes up.
//!
//! A port is attached by **one client at a time**: a ring-3 task through
//! `Uart::attach` (queues it made), or the kernel itself through
//! [`attach_client`] (a [`PortClient`], no queues: the USB serial console).
//! The kernel's attachment is not the business of a task that holds `WRITE` on
//! the port: its `detach` answers `REFUSED`, and its attach is `BUSY`.
//!
//! The kernel-hosted call path moves no capability, and refuses a request that
//! carries entries for any interface but these two (`takes_caps`); the register
//! form carries none, so `attach` and `start_batch` are message-form only.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_devif::adc::{self, Record, RecordSink, SampleQueue};
use azos_devif::can::Frame;
use azos_devif::i2c::{self, Bytes};
use azos_devif::uart::{self, Chunk, ChunkSink, ChunkSource, RxQueue, TxQueue};
use azos_devif::{outcome, Cap, Out};
use azos_drv_bus::uart_bridge::{BridgePort, BRIDGE_PORT};
use azos_drv_sensor::ads1115::AdcPort;
use azos_rings::region::{RingStep, SpscSlots, RING_SLOTS};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::handlers::{gpio_pin_is_motor_bound, pwm_channel_is_motor_bound, pwm_control_reaches_a_motor};
use crate::khost::Caller;

/// The `Gpio` interface served for one caller.
pub struct GpioServer(pub Caller);

impl GpioServer {
    /// The pin, if the board has it.
    fn pin(&self) -> Result<u32, u32> {
        let pin = self.0.badge;
        if (pin as usize) < azos_drv_gpio::gpio::GPIO_MAX_PINS {
            Ok(pin)
        } else {
            Err(outcome::BAD_ARGUMENT)
        }
    }
}

impl azos_devif::Gpio for GpioServer {
    fn read(&self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        let pin = match self.pin() {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        let v = azos_drv_gpio::gpio::gpio_read(pin);
        if v < 0 {
            Out::err(outcome::FAULT)
        } else {
            Out::ok(v as u32)
        }
    }

    fn write(&mut self, level: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let pin = match self.pin() {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        if gpio_pin_is_motor_bound(pin) {
            return Out::err(outcome::REFUSED);
        }
        if azos_drv_gpio::gpio::gpio_write(pin, level & 1) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }

    fn set_dir(&mut self, dir: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let pin = match self.pin() {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        if gpio_pin_is_motor_bound(pin) {
            return Out::err(outcome::REFUSED);
        }
        let dir = match dir {
            azos_devif::gpio::DIR_INPUT => azos_drv_gpio::gpio::GpioDir::Input,
            azos_devif::gpio::DIR_OUTPUT => azos_drv_gpio::gpio::GpioDir::Output,
            _ => return Out::err(outcome::BAD_ARGUMENT),
        };
        if azos_drv_gpio::gpio::gpio_set_direction(pin, dir) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }
}

/// The `I2c` interface served for one caller.
pub struct I2cServer(pub Caller);

impl azos_devif::I2c for I2cServer {
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        if let Err(o) = self.0.gate::<Bytes>(CapPerms::READ) {
            return o;
        }
        let len = len as usize;
        if reg > 0xFF || len == 0 || len > i2c::MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let (bus, addr) = i2c::unbadge(self.0.badge);
        let mut buf = [0u8; i2c::MAX_BYTES];
        let n = azos_drv_bus::i2c::i2c_read(bus, addr, reg as u8, &mut buf[..len]);
        if n < 0 {
            return Out::err(outcome::FAULT);
        }
        Out::ok(Bytes::from_slice(&buf[..(n as usize).min(len)]))
    }

    fn write(&mut self, data: Bytes) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let n = data.n as usize;
        if n == 0 || n > i2c::MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let (bus, addr) = i2c::unbadge(self.0.badge);
        let mut buf = [0u8; i2c::MAX_BYTES];
        data.copy_to(&mut buf);
        if azos_drv_bus::i2c::i2c_write(bus, addr, &buf[..n]) == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }

    fn detect(&mut self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        let (bus, addr) = i2c::unbadge(self.0.badge);
        Out::ok(u32::from(azos_drv_bus::i2c::i2c_detect(bus, addr)))
    }
}

/// What a PWM op reaches, declared by the op: the same declaration the typed
/// calls made, for the same reason (only the op knows).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Writes the control register, which on a part with a shared one reaches
    /// every channel of the instance: enable, disable, set period.
    Control,
    /// Writes this channel's own compare register: duty only.
    DutyOnly,
}

/// The `Pwm` interface served for one caller.
pub struct PwmServer(pub Caller);

impl PwmServer {
    fn run(&self, reach: Reach, op: impl FnOnce(u32) -> i32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let domain = azos_drv_actuator::pwm_domain::PWM_DOMAIN;
        let ch = self.0.badge;
        if ch >= domain.channels {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        // Control ops are refused by REACH, duty by the named channel: a duty
        // write reaches only what it names, a control write reaches every
        // channel of a shared-control part.
        let blocked = match reach {
            Reach::Control => pwm_control_reaches_a_motor(domain, ch),
            Reach::DutyOnly => pwm_channel_is_motor_bound(ch),
        };
        if blocked {
            return Out::err(outcome::REFUSED);
        }
        // The buzzer's channel has one holder at a time (the kernel host or
        // the ring-3 one); a write from the other is refused, not queued.
        let rc = if ch == azos_drv_actuator::buzzer_channel::CHANNEL {
            match azos_drv_actuator::buzzer_channel::ring3_channel_write(|| op(ch)) {
                Some(rc) => rc,
                None => return Out::err(outcome::REFUSED),
            }
        } else {
            op(ch)
        };
        if rc == 0 {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }
}

impl azos_devif::Pwm for PwmServer {
    fn enable(&mut self) -> Out<()> {
        self.run(Reach::Control, azos_drv_actuator::pwm::pwm_enable)
    }
    fn disable(&mut self) -> Out<()> {
        self.run(Reach::Control, azos_drv_actuator::pwm::pwm_disable)
    }
    fn set_period(&mut self, ns: u32) -> Out<()> {
        self.run(Reach::Control, |ch| azos_drv_actuator::pwm::pwm_set_period(ch, ns))
    }
    fn set_duty(&mut self, ns: u32) -> Out<()> {
        self.run(Reach::DutyOnly, |ch| azos_drv_actuator::pwm::pwm_set_duty(ch, ns))
    }
    fn set_duty_pct(&mut self, pct: u32) -> Out<()> {
        self.run(Reach::DutyOnly, |ch| azos_drv_actuator::pwm::pwm_set_duty_pct(ch, pct))
    }
}

/// The `Spi` interface served for one caller: one chip select of one bus (the
/// badge, `bus << 8 | cs`). Every op that puts bytes on the wire needs `WRITE`
/// (the first byte is a command the device acts on, a read included), the
/// port's configuration needs `EXEC`; the interface declares no `READ` op. The
/// port (`SpiPort`) checks the bounds, finds the device and programs the
/// controller with this chip select's setup; this layer is the capability
/// gate in front of it.
pub struct SpiServer(pub Caller);

impl SpiServer {
    fn port(&self) -> azos_drv_bus::spi::SpiPort {
        azos_drv_bus::spi::SpiPort::from_badge(self.0.badge)
    }
}

impl azos_devif::Spi for SpiServer {
    fn transfer(&mut self, data: Bytes) -> Out<Bytes> {
        if let Err(o) = self.0.gate::<Bytes>(CapPerms::WRITE) {
            return o;
        }
        self.port().transfer(data)
    }

    fn write(&mut self, data: Bytes) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        self.port().write(data)
    }

    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        if let Err(o) = self.0.gate::<Bytes>(CapPerms::WRITE) {
            return o;
        }
        self.port().read(reg, len)
    }

    fn set_mode(&mut self, mode: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        self.port().set_mode(mode)
    }

    fn set_speed(&mut self, hz: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        self.port().set_speed(hz)
    }

    fn hold_cs(&mut self, hold: bool) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        self.port().hold_cs(hold)
    }
}

/// The `Can` interface served for one caller: the controller the badge names
/// (`can.0`; the board has one, so any other badge is `NO_RESOURCE`). `READ`
/// receives and observes the state, `WRITE` transmits (and is refused while
/// the system is contained: a frame on the bus is acting), `EXEC` retunes the
/// bus (filters, bitrate, leaving bus-off). The port (`CanPort`) checks the
/// frame and maps the controller's answer.
pub struct CanServer(pub Caller);

impl CanServer {
    /// The controller, if the board has it.
    fn port(&self) -> Result<azos_drv_bus::can::CanPort, u32> {
        if self.0.badge == 0 {
            Ok(azos_drv_bus::can::CanPort)
        } else {
            Err(outcome::NO_RESOURCE)
        }
    }
}

impl azos_devif::Can for CanServer {
    fn send(&mut self, frame: Frame) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        match self.port() {
            Ok(mut p) => p.send(frame),
            Err(c) => Out::err(c),
        }
    }

    fn recv(&mut self) -> Out<Frame> {
        if let Err(o) = self.0.gate::<Frame>(CapPerms::READ) {
            return o;
        }
        match self.port() {
            Ok(mut p) => p.recv(),
            Err(c) => Out::err(c),
        }
    }

    fn add_filter(&mut self, id: u32, mask: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        match self.port() {
            Ok(mut p) => p.add_filter(id, mask),
            Err(c) => Out::err(c),
        }
    }

    fn clear_filters(&mut self) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        match self.port() {
            Ok(mut p) => p.clear_filters(),
            Err(c) => Out::err(c),
        }
    }

    fn set_bitrate(&mut self, bps: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        match self.port() {
            Ok(mut p) => p.set_bitrate(bps),
            Err(c) => Out::err(c),
        }
    }

    fn state(&self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        match self.port() {
            Ok(p) => p.state(),
            Err(c) => Out::err(c),
        }
    }

    fn recover(&mut self) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        match self.port() {
            Ok(mut p) => p.recover(),
            Err(c) => Out::err(c),
        }
    }
}

// ── Queues the client made ────────────────────────────────────────────────

/// Most slots a queue's ring can have (the region protocol's index width).
const SLOTS_MAX: usize = 1 << 31;

/// Slots of a ring of `W`-word slots in a region of `bytes`: the most a power
/// of two fits, `None` below two.
fn slots_for<const W: usize>(bytes: usize) -> Option<u32> {
    let room = bytes.checked_sub(RING_SLOTS)? / (W * 8);
    if room < 2 {
        return None;
    }
    let n = 1usize << (usize::BITS - 1 - room.leading_zeros());
    Some(n.min(SLOTS_MAX) as u32)
}

/// Why a handle a client hands the kernel as a ring is not one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RegionRefusal {
    /// Not a region the caller holds (or it is gone).
    NotARegion,
    /// The capability lacks the right asked for (recorded under the region's
    /// kind).
    Denied,
}

/// The region the handle `raw` in `tid`'s table names, and its size in bytes,
/// when the capability carries `need` (`WRITE` for a ring the kernel fills,
/// `READ` for one it drains): the check every queue a client makes goes
/// through, here and for the NIC queues (`crate::nicq`). The kernel keeps the
/// packed reference only, never an address.
pub(crate) fn ring_region(tid: u32, raw: u32, need: CapPerms) -> Result<(u32, usize), RegionRefusal> {
    let named = azos_ipc::cap_store::read_table(tid, |t| t.peek_raw(CapHandle(raw))).flatten();
    let Some((ty, rights, region)) = named else { return Err(RegionRefusal::NotARegion) };
    if ty != azos_abi::cap::ty::SHM {
        return Err(RegionRefusal::NotARegion);
    }
    if !rights.contains(need) {
        crate::handlers::note_typed_denial_for(tid, ty, azos_ipc::cap::CapError::MissingPerms);
        return Err(RegionRefusal::Denied);
    }
    let desc = azos_ipc::memobj::memobj_describe_ref(region).map_err(|_| RegionRefusal::NotARegion)?;
    Ok((region, desc.page_count * azos_arch::PAGE_SIZE))
}

/// The kernel's end of one queue: the region and the slot count the region's
/// size implies. Holds no address (module doc, "Queues").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QueueEnd {
    pub(crate) region: u32,
    pub(crate) slots: u32,
}

impl QueueEnd {
    /// The end the handle `raw` in the caller's table names, for a ring of
    /// `W`-word slots: `need` is the right the capability must carry (`WRITE`
    /// for a queue the kernel fills, `READ` for one it drains).
    /// `BAD_ARGUMENT` for a handle that is not a region or a region too small
    /// for a ring, `DENIED` (recorded under the region's kind) for a missing
    /// right, `UNSUPPORTED` for a region the kernel cannot touch as one piece
    /// (read-only, shared with a clone, hidden from the kernel, or not
    /// physically contiguous).
    pub(crate) fn resolve<const W: usize>(who: &Caller, raw: u32, need: CapPerms) -> Result<QueueEnd, u32> {
        let (region, bytes) = ring_region(who.tid, raw, need).map_err(|e| match e {
            RegionRefusal::NotARegion => outcome::BAD_ARGUMENT,
            RegionRefusal::Denied => outcome::DENIED,
        })?;
        let Some(slots) = slots_for::<W>(bytes) else {
            return Err(outcome::BAD_ARGUMENT);
        };
        let end = QueueEnd { region, slots };
        match azos_ipc::memobj::memobj_with_span_ref(region, end.ring_bytes::<W>(), |_| ()) {
            Ok(Some(())) => Ok(end),
            Ok(None) => Err(outcome::UNSUPPORTED),
            Err(_) => Err(outcome::BAD_ARGUMENT),
        }
    }

    fn ring_bytes<const W: usize>(&self) -> usize {
        SpscSlots::<W>::bytes(self.slots)
    }

    /// Append `item`: `Ok(false)` when the ring is full (the item is lost,
    /// the caller counts it), `Err` when the region can no longer be touched.
    pub(crate) fn push<const W: usize>(&self, item: &[u64; W]) -> Result<bool, ()> {
        let step = azos_ipc::memobj::memobj_with_span_ref(self.region, self.ring_bytes::<W>(), |base| {
            match (SpscSlots::<W> { base, cap: self.slots }).try_push(item) {
                RingStep::Done => (true, None),
                RingStep::DoneWake { addr } => (true, Some(addr - base)),
                RingStep::Blocked => (false, None),
            }
        });
        match step {
            Ok(Some((pushed, wake))) => {
                if let Some(off) = wake {
                    // The reader announced it may be asleep: wake it after the
                    // region table is released.
                    crate::vdso_notify::notify_wake_kernel(self.region, off as u32, 1);
                }
                Ok(pushed)
            }
            _ => Err(()),
        }
    }

    /// Take the oldest item: `Ok(None)` when the ring is empty.
    pub(crate) fn pop<const W: usize>(&self) -> Result<Option<[u64; W]>, ()> {
        let step = azos_ipc::memobj::memobj_with_span_ref(self.region, self.ring_bytes::<W>(), |base| {
            let mut out = [0u64; W];
            match (SpscSlots::<W> { base, cap: self.slots }).try_pop(&mut out) {
                RingStep::Done => (Some(out), None),
                RingStep::DoneWake { addr } => (Some(out), Some(addr - base)),
                RingStep::Blocked => (None, None),
            }
        });
        match step {
            Ok(Some((item, wake))) => {
                if let Some(off) = wake {
                    crate::vdso_notify::notify_wake_kernel(self.region, off as u32, 1);
                }
                Ok(item)
            }
            _ => Err(()),
        }
    }
}

/// Slot words of a record and of a chunk (the little-endian words of the bytes
/// `Record::encode` and `Chunk::encode` give).
const RECORD_WORDS: usize = adc::RECORD_BYTES / 8;
const CHUNK_WORDS: usize = uart::CHUNK_BYTES / 8;

fn words_of<const N: usize>(bytes: &[u8]) -> [u64; N] {
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8])))
}

fn bytes_of<const N: usize, const B: usize>(words: &[u64; N]) -> [u8; B] {
    let mut b = [0u8; B];
    for (i, w) in words.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    b
}

/// The sample queue as the adapter's sink; `gone` once the region could not be
/// touched (the attachment is then over).
struct RecordRing {
    end: QueueEnd,
    gone: bool,
}

impl RecordSink for RecordRing {
    fn push(&mut self, record: &Record) -> bool {
        match self.end.push::<RECORD_WORDS>(&words_of(&record.encode())) {
            Ok(fit) => fit,
            Err(()) => {
                self.gone = true;
                false
            }
        }
    }
}

/// One end of an attachment: a ring the client made, or a client of the
/// kernel's own.
#[derive(Clone, Copy)]
enum Dest {
    Ring(QueueEnd),
    Client(&'static dyn PortClient),
}

/// The received-chunk end as the line's sink.
struct ChunkRx {
    dest: Dest,
    gone: bool,
}

impl ChunkSink for ChunkRx {
    fn push(&mut self, chunk: &Chunk) -> bool {
        let end = match self.dest {
            Dest::Ring(end) => end,
            Dest::Client(c) => return c.rx(chunk),
        };
        match end.push::<CHUNK_WORDS>(&words_of(&chunk.encode())) {
            Ok(fit) => fit,
            Err(()) => {
                self.gone = true;
                false
            }
        }
    }
}

/// The transmit end as the line's source. A slot the client wrote wrong
/// (a length past the chunk) is consumed and skipped, not clamped; the skips
/// are bounded so a client cannot keep one pass from ending.
struct ChunkTx {
    dest: Dest,
    gone: bool,
}

impl ChunkSource for ChunkTx {
    fn pop(&mut self) -> Option<Chunk> {
        let end = match self.dest {
            Dest::Ring(end) => end,
            Dest::Client(c) => return c.tx(),
        };
        for _ in 0..PUMP_SKIPS {
            match end.pop::<CHUNK_WORDS>() {
                Ok(Some(w)) => {
                    if let Some(c) = Chunk::decode(&bytes_of::<CHUNK_WORDS, { uart::CHUNK_BYTES }>(&w)) {
                        return Some(c);
                    }
                }
                Ok(None) => return None,
                Err(()) => {
                    self.gone = true;
                    return None;
                }
            }
        }
        None
    }
}

/// Wrong slots one pass skips before it gives the line back.
const PUMP_SKIPS: usize = 8;

// ── The pump ──────────────────────────────────────────────────────────────

/// A serial line the kernel finds at run time and offers as a `Uart` port (the
/// USB CDC-ACM function): the four `Uart` ops, the pump's pass, and the
/// kernel's own attachment. Every method takes `&self`: the line has a lock of
/// its own, a sleeping one, which is why the port table never calls it with
/// the table's spin lock held.
pub trait SerialLine: Send + Sync {
    fn configure(&self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()>;
    /// Attach the queues a ring-3 client made. `BUSY` if anyone holds the line.
    fn attach(&self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()>;
    /// Attach a client of the kernel's (no queues): the same, for [`PortClient`].
    fn attach_kernel(&self) -> Out<()>;
    fn detach(&self) -> Out<()>;
    fn status(&self) -> Out<uart::Status>;
    /// One pass: what the line received to `rx`, what `tx` holds to the line;
    /// the chunks moved. It must not wait for the device or for a lock another
    /// task may hold across a wait (a line busy with its own bring-up moves
    /// nothing).
    fn pump(&self, rx: &mut dyn ChunkSink, tx: &mut dyn ChunkSource) -> usize;
}

/// A client of a port that lives in the kernel and has no queues to attach: the
/// USB serial console. The pump calls it from the `dev-pump` task, in task
/// context, with no lock of the table held.
pub trait PortClient: Send + Sync {
    /// A chunk the line received; `false` when it was lost.
    fn rx(&self, chunk: &Chunk) -> bool;
    /// The next chunk for the line, if there is one.
    fn tx(&self) -> Option<Chunk>;
    /// Chunks (or bytes) the client has lost on its way to the line since it
    /// attached, for [`azos_devif::Uart::status`].
    fn lost(&self) -> u32;
}

/// What a port is driven by: the board's own adapter (the bridge; and, on a
/// port with nothing behind it, an adapter that answers `NO_RESOURCE` to
/// everything), or a plugged [`SerialLine`].
#[derive(Clone)]
enum Line {
    Fixed(BridgePort),
    Plugged(&'static dyn SerialLine),
}

impl Line {
    fn pump(&mut self, rx: &mut ChunkRx, tx: &mut ChunkTx) -> usize {
        match self {
            Line::Fixed(p) => p.pump(rx, tx),
            Line::Plugged(l) => l.pump(rx, tx),
        }
    }
}

impl azos_devif::Uart for Line {
    fn configure(&mut self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()> {
        match self {
            Line::Fixed(p) => azos_devif::Uart::configure(p, baud, data_bits, parity, stop_bits),
            Line::Plugged(l) => l.configure(baud, data_bits, parity, stop_bits),
        }
    }

    fn attach(&mut self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()> {
        match self {
            Line::Fixed(p) => azos_devif::Uart::attach(p, rx, tx),
            Line::Plugged(l) => l.attach(rx, tx),
        }
    }

    fn detach(&mut self) -> Out<()> {
        match self {
            Line::Fixed(p) => azos_devif::Uart::detach(p),
            Line::Plugged(l) => l.detach(),
        }
    }

    fn status(&self) -> Out<uart::Status> {
        match self {
            Line::Fixed(p) => azos_devif::Uart::status(p),
            Line::Plugged(l) => l.status(),
        }
    }
}

/// One port of the table and the ends attached to it.
struct UartHost {
    line: Line,
    ends: Option<(Dest, Dest)>,
    /// The task that attached them ([`KERNEL_OWNER`] for the kernel; see
    /// [`release_all`]).
    owner: u32,
    /// Bumped by every change of the attachment or of the line (attach, end,
    /// plug, unplug). A pass of the pump works on a copy of `line` with no lock
    /// held and publishes it only if this is still the number it started from.
    gen: u32,
}

/// [`UartHost::owner`] of an attachment the kernel made itself. Not a task id.
const KERNEL_OWNER: u32 = u32::MAX;

/// The first port number of the hot-plugged lines (the bridge is the one
/// before it) and how many there are: the USB class driver serves one serial
/// function at a time.
pub const LINE_PORT_BASE: u32 = BRIDGE_PORT + 1;
pub const LINE_PORTS: usize = 1;

/// Bridge plus the plug slots.
const PORT_SLOTS: usize = 1 + LINE_PORTS;

/// The table slot of port `port`, if the table has it. Slot 0 is the bridge.
const fn slot_of(port: u32) -> Option<usize> {
    if port == BRIDGE_PORT {
        Some(0)
    } else if port >= LINE_PORT_BASE && ((port - LINE_PORT_BASE) as usize) < LINE_PORTS {
        Some(1 + (port - LINE_PORT_BASE) as usize)
    } else {
        None
    }
}

const fn slot_port(slot: usize) -> u32 {
    if slot == 0 { BRIDGE_PORT } else { LINE_PORT_BASE + (slot - 1) as u32 }
}

const fn port_table() -> [UartHost; PORT_SLOTS] {
    let mut t = [const { UartHost { line: Line::Fixed(BridgePort::new(0)), ends: None, owner: 0, gen: 0 } }; PORT_SLOTS];
    let mut i = 0;
    while i < PORT_SLOTS {
        t[i].line = Line::Fixed(BridgePort::new(slot_port(i)));
        i += 1;
    }
    t
}

/// The `Uart` ports: the bridge, then the hot-plugged lines. One static,
/// because the ports keep their rings.
static PORTS: SpinLock<[UartHost; PORT_SLOTS]> = SpinLock::new(port_table());

/// Offer a serial line the kernel found as a `Uart` port. The port number it
/// got (`uart.N`, for a topology row or for [`attach_client`]), or `None` when
/// every plug slot is taken.
pub fn plug_line(line: &'static dyn SerialLine) -> Option<u32> {
    let mut t = PORTS.lock();
    let i = (1..PORT_SLOTS).find(|&i| matches!(t[i].line, Line::Fixed(_)))?;
    t[i] = UartHost { line: Line::Plugged(line), ends: None, owner: 0, gen: t[i].gen.wrapping_add(1) };
    Some(slot_port(i))
}

/// Withdraw the line plugged at `port` (its device is gone): the attachment is
/// dropped with it, and a pass in flight on it publishes nothing. The line is
/// not told to detach: it is the one that found out.
pub fn unplug_line(port: u32) {
    let Some(i) = slot_of(port).filter(|&i| i != 0) else { return };
    let mut t = PORTS.lock();
    t[i] = UartHost { line: Line::Fixed(BridgePort::new(port)), ends: None, owner: 0, gen: t[i].gen.wrapping_add(1) };
}

/// One channel's port and the queue its batch fills.
struct AdcHost {
    port: AdcPort,
    queue: Option<QueueEnd>,
    /// The task that started the batch (see [`release_all`]).
    owner: u32,
    /// As [`UartHost::gen`]: bumped by every start and stop of the batch.
    gen: u32,
}

macro_rules! adc_hosts {
    ($($n:literal)*) => { [$(AdcHost { port: AdcPort::new($n), queue: None, owner: 0, gen: 0 }),*] };
}

static ADC: SpinLock<[AdcHost; adc::CHANNELS as usize]> = SpinLock::new(adc_hosts!(0 1 2 3 4 5 6 7));

/// The pump task's TID, `0` until it has started to run.
static PUMP_TID: AtomicU32 = AtomicU32::new(0);

/// The pump task's creation is claimed (by the first attach that found none).
static PUMP_SPAWNED: AtomicBool = AtomicBool::new(false);

/// An attach has published its state: make sure the pump task exists and
/// looks at it. The task is created by the first attach (a machine where
/// nothing ever attaches, or that has no bridge or converter to attach to,
/// never pays its stack or its task slot) and parks when nothing is attached,
/// so it is created once. `false` when the task cannot be created: the
/// caller undoes its attachment.
///
/// A creation in flight needs no wake: the task stores its TID before its
/// first pass, and that pass takes the same locks the attach released, so it
/// sees the attachment. After that the wake is stamped even if the task has
/// not parked yet (`wq_wake_by_tid`), or ends a timed sleep that would run
/// past the new source's first pass.
pub(crate) fn kick_pump() -> bool {
    let tid = PUMP_TID.load(Ordering::Acquire);
    if tid != 0 {
        azos_sched::wq_wake_by_tid(tid);
        azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
        return true;
    }
    if PUMP_SPAWNED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return true;
    }
    match azos_sched::try_task_create_affinity("dev-pump", pump_task, 0, azos_sched::DEFAULT_PRIORITY, -1) {
        Some(idx) => {
            if let Some(tid) = azos_sched::tid_for_idx(idx) {
                PUMP_TID.store(tid, Ordering::Release);
            }
            true
        }
        None => {
            PUMP_SPAWNED.store(false, Ordering::Release);
            false
        }
    }
}

/// Wake the pump task if it exists, from any context (an interrupt handler):
/// [`kick_pump`] without the creation. `false` when there is no pump task yet.
pub fn wake_pump() -> bool {
    let tid = PUMP_TID.load(Ordering::Acquire);
    if tid == 0 {
        return false;
    }
    azos_sched::wq_wake_by_tid(tid);
    azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    true
}

/// Host tests only: the task a test saw created is gone, so the next attach
/// creates one again (it never runs on the host).
#[cfg(test)]
pub(crate) fn forget_pump_task() {
    PUMP_TID.store(0, Ordering::Release);
    PUMP_SPAWNED.store(false, Ordering::Release);
}

/// The pump task: one [`pump`] pass, then sleep until the pass it answers is
/// due (`DEVIF_PUMP_POLL_US` after the last one for a source that must be
/// looked at, the sample's own time for a converter that is not ready yet),
/// or park on the wait queue with no deadline when nothing is attached
/// ([`kick_pump`] wakes it).
fn pump_task(_: usize) {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    PUMP_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    let poll_ns = azos_limits::DEVIF_PUMP_POLL_US as u64 * 1_000;
    loop {
        let now_ns = azos_abi::time::ticks_to_ns(now(), TIMER_FREQ);
        match pump(now_ns, poll_ns) {
            Some(due_ns) => {
                let wait = azos_abi::time::ns_to_ticks_ceil(due_ns.saturating_sub(now_ns), TIMER_FREQ);
                azos_sched::task_block(azos_sched::WaitReason::Timer(now() + wait.max(1)));
            }
            None => azos_sched::wq_block_current(),
        }
    }
}

/// A task exited: end what it attached. The queues belong to the task that
/// made the attachment (it held `WRITE` on the port, or `READ` on the channel,
/// to do it); without this a region another task still holds would keep the
/// line open, and that task could transmit on it by writing the ring without
/// ever holding the endpoint. Called from the kernel's task-exit hook, first
/// among the exit work.
pub fn release_all(tid: u32) {
    #[cfg(feature = "virtio-snd")]
    crate::sound_host::release_all(tid);
    for i in 0..PORT_SLOTS {
        let line = {
            let mut t = PORTS.lock();
            if t[i].ends.is_some() && t[i].owner == tid { end_ends(&mut t[i]) } else { Ended::Nothing }
        };
        line.finish();
    }
    let mut hosts = ADC.lock();
    for host in hosts.iter_mut() {
        if host.queue.is_some() && host.owner == tid {
            let _ = end_batch(host);
        }
    }
}

/// What ending an attachment left to do once the table's lock is released.
enum Ended {
    /// The adapter was told (the table's own); this is its answer.
    Told(Out<()>),
    /// A plugged line holds the attachment: tell it, outside the lock.
    Call(&'static dyn SerialLine),
    /// There was no attachment.
    Nothing,
}

impl Ended {
    fn finish(self) -> Out<()> {
        match self {
            Ended::Told(o) => o,
            Ended::Call(l) => l.detach(),
            Ended::Nothing => Out::ok(()),
        }
    }
}

/// End the port's attachment (the lock is held): the ends are forgotten and
/// `gen` bumped (if there were any), so a pass in flight puts nothing back.
fn end_ends(h: &mut UartHost) -> Ended {
    let had = h.ends.take().is_some();
    if had {
        h.gen = h.gen.wrapping_add(1);
    }
    match &mut h.line {
        Line::Fixed(p) => Ended::Told(azos_devif::Uart::detach(p)),
        Line::Plugged(l) if had => Ended::Call(*l),
        Line::Plugged(_) => Ended::Nothing,
    }
}

/// End the attachment of slot `i`. The table's lock is not held on entry.
fn end_attachment(i: usize) {
    let ended = end_ends(&mut PORTS.lock()[i]);
    let _ = ended.finish();
}

/// End the channel's batch (the lock is held); the samples the queue took.
fn end_batch(host: &mut AdcHost) -> Out<u32> {
    host.queue = None;
    host.gen = host.gen.wrapping_add(1);
    azos_devif::Adc::stop_batch(&mut host.port)
}

/// When the pump should look at the channel again, if its batch runs.
fn adc_next(host: &AdcHost, now_ns: u64, poll_ns: u64) -> Option<u64> {
    host.queue?;
    Some(match host.port.next_due_ns() {
        Some(due) if due > now_ns => due,
        _ => now_ns.saturating_add(poll_ns),
    })
}

/// One service pass at `now_ns` (nanoseconds on the vDSO clock): move what each
/// attached `Uart` port received to its receive end and what its client queued
/// to the line, and take the ADC batches' samples that are due. `poll_ns` is how
/// soon to look again at a source with no interrupt (a serial line, a converter
/// that has not answered yet). Answers when the next pass is due, `None` when
/// nothing is attached (the pump task then parks until [`kick_pump`] wakes
/// it).
///
/// **No lock is held while an adapter works.** `BridgePort::pump` busy-waits
/// on the transmitter, a plugged line takes a sleeping lock and `AdcPort::pump`
/// reads the converter through the I2C queue, which sleeps; a spin lock held
/// across any of them would stall every hart that attaches, detaches or exits
/// meanwhile. So a pass copies the
/// adapter under the lock, runs it on the copy with the lock released, and
/// publishes the copy under the lock, but only if the attachment is still the
/// one it started from (`gen`): a detach, a stop or a task exit that came in
/// meanwhile stands, and the copy (with its counters and, for a converter,
/// the one sample it took, which may land in the queue after the stop) is
/// dropped.
///
/// The price is two lock operations per attached channel per pass instead of
/// one for all; an idle channel costs one.
///
/// An attachment whose queue can no longer be touched (its region was freed)
/// is ended here: the port is detached, the batch stopped.
pub fn pump(now_ns: u64, poll_ns: u64) -> Option<u64> {
    let mut next: Option<u64> = None;
    let mut soonest = |t: u64| next = Some(next.map_or(t, |n| n.min(t)));
    for i in 0..PORT_SLOTS {
        let taken = {
            let t = PORTS.lock();
            t[i].ends.map(|(rx, tx)| (t[i].line.clone(), rx, tx, t[i].gen))
        };
        let Some((mut line, rx, tx, gen)) = taken else { continue };
        let mut sink = ChunkRx { dest: rx, gone: false };
        let mut source = ChunkTx { dest: tx, gone: false };
        line.pump(&mut sink, &mut source);
        let (attached, ended) = {
            let mut t = PORTS.lock();
            let host = &mut t[i];
            let mut ended = Ended::Nothing;
            if host.gen == gen {
                host.line = line;
                if sink.gone || source.gone {
                    ended = end_ends(host);
                }
            }
            (host.ends.is_some(), ended)
        };
        let _ = ended.finish();
        if attached {
            soonest(now_ns.saturating_add(poll_ns));
        }
    }
    for ch in 0..adc::CHANNELS as usize {
        let taken = {
            let hosts = ADC.lock();
            hosts[ch].queue.map(|end| (hosts[ch].port.clone(), end, hosts[ch].gen))
        };
        let Some((mut port, end, gen)) = taken else { continue };
        let mut sink = RecordRing { end, gone: false };
        port.pump(now_ns, &mut sink);
        let mut hosts = ADC.lock();
        let host = &mut hosts[ch];
        if host.gen == gen {
            host.port = port;
            if sink.gone {
                let _ = end_batch(host);
            } else if host.port.queue().is_none() {
                // The batch ran its count.
                host.queue = None;
                host.gen = host.gen.wrapping_add(1);
            }
        }
        if let Some(t) = adc_next(host, now_ns, poll_ns) {
            soonest(t);
        }
    }
    #[cfg(feature = "virtio-snd")]
    if let Some(t) = crate::sound_host::pump(now_ns, poll_ns) {
        soonest(t);
    }
    next
}

// ── Uart ──────────────────────────────────────────────────────────────────

/// The `Uart` interface served for one caller: the port the badge names
/// (`uart.1`, the companion-radio bridge; `uart.2`, the USB serial line while
/// one is plugged in; any other port is nothing the board has). `READ`
/// observes the counters, `WRITE` attaches and detaches the queues (which lets
/// bytes leave the machine, so containment refuses it), `EXEC` configures the
/// line. The adapter (`BridgePort`, or a plugged [`SerialLine`]) validates the
/// line and keeps the rings; a port it does not drive is `NO_RESOURCE`.
pub struct UartServer(pub Caller);

impl UartServer {
    /// A copy of the adapter of the port the badge names, to run an op on with
    /// no lock held (a plugged line takes a sleeping lock of its own). A port
    /// outside the table is a fresh adapter that has nothing behind it and
    /// answers `NO_RESOURCE`.
    fn line(&self) -> Line {
        match slot_of(self.0.badge) {
            Some(i) => PORTS.lock()[i].line.clone(),
            None => Line::Fixed(BridgePort::new(self.0.badge)),
        }
    }
}

/// Attach `ends` to slot `i` as `owner`, `on_line` being the adapter's own
/// attach. It runs on a copy of the adapter with no lock held, and the copy is
/// published only if nothing changed the slot meanwhile (`gen`): an unplug, a
/// task exit or another attach that got in first wins, and this attach answers
/// as if it came after (`BUSY`, or `NO_RESOURCE` when the line is gone). A
/// copy that lost to an unplug and a replug of the very same line is detached
/// again, so the new session does not start held.
fn attach_slot(i: usize, ends: (Dest, Dest), owner: u32, on_line: impl FnOnce(&mut Line) -> Out<()>) -> Out<()> {
    let (mut line, gen) = {
        let t = PORTS.lock();
        if t[i].ends.is_some() {
            return Out::err(outcome::BUSY);
        }
        (t[i].line.clone(), t[i].gen)
    };
    let r = on_line(&mut line);
    if r.code != outcome::OK {
        return r;
    }
    let stale = {
        let mut t = PORTS.lock();
        let host = &mut t[i];
        if host.gen != gen {
            // The line told us yes, but the slot is not what it was. The
            // attach is not published, and the line is told to let go unless
            // the slot no longer owes it anything: an unplug took the old
            // line (it forgot the attach with itself), but a line that was
            // unplugged and plugged back is the same object and still holds
            // our attach. Were it left held, every later attach would answer
            // `BUSY` until something detached it. A slot that records an
            // attachment of its own keeps it: that is the line's, not ours.
            let again = match (&line, &host.line) {
                (Line::Plugged(a), Line::Plugged(b)) if host.ends.is_none() => core::ptr::addr_eq(*a, *b),
                _ => false,
            };
            let code = if host.ends.is_some() { outcome::BUSY } else { outcome::NO_RESOURCE };
            Some((again, code))
        } else {
            host.line = line.clone();
            host.ends = Some(ends);
            host.owner = owner;
            host.gen = gen.wrapping_add(1);
            None
        }
    };
    if let Some((again, code)) = stale {
        if again {
            // Outside the lock: a plugged line takes a sleeping lock of its own.
            let _ = azos_devif::Uart::detach(&mut line);
        }
        return Out::err(code);
    }
    if !kick_pump() {
        // No task to move the data: the attachment would never run.
        end_attachment(i);
        return Out::err(outcome::NO_RESOURCE);
    }
    r
}

/// Attach a client of the kernel's own to the port `port` (a plugged line): the
/// USB serial console. `BUSY` if anyone holds the port, `NO_RESOURCE` if no
/// line is plugged in there. The pump moves the data from then on, polling the
/// line; [`PortClient::rx`] and [`PortClient::tx`] are called from its task.
pub fn attach_client(port: u32, client: &'static dyn PortClient) -> Out<()> {
    let Some(i) = slot_of(port) else { return Out::err(outcome::NO_RESOURCE) };
    attach_slot(i, (Dest::Client(client), Dest::Client(client)), KERNEL_OWNER, |line| match line {
        Line::Plugged(l) => l.attach_kernel(),
        Line::Fixed(_) => Out::err(outcome::NO_RESOURCE),
    })
}

impl azos_devif::Uart for UartServer {
    fn configure(&mut self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        azos_devif::Uart::configure(&mut self.line(), baud, data_bits, parity, stop_bits)
    }

    fn attach(&mut self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let Some(i) = slot_of(self.0.badge) else {
            return azos_devif::Uart::attach(&mut BridgePort::new(self.0.badge), rx, tx);
        };
        // The queues are resolved before the port's lock is taken (the cap
        // table and the region table are read; the port lock stays a leaf).
        let rx_end = match QueueEnd::resolve::<CHUNK_WORDS>(&self.0, rx.raw(), CapPerms::WRITE) {
            Ok(e) => e,
            Err(c) => return Out::err(c),
        };
        let tx_end = match QueueEnd::resolve::<CHUNK_WORDS>(&self.0, tx.raw(), CapPerms::READ) {
            Ok(e) => e,
            Err(c) => return Out::err(c),
        };
        if rx_end.region == tx_end.region {
            // One ring cannot be both directions: the kernel would read back
            // the bytes it just received.
            return Out::err(outcome::BAD_ARGUMENT);
        }
        attach_slot(i, (Dest::Ring(rx_end), Dest::Ring(tx_end)), self.0.tid, |line| {
            azos_devif::Uart::attach(line, rx, tx)
        })
    }

    fn detach(&mut self) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        let Some(i) = slot_of(self.0.badge) else {
            return azos_devif::Uart::detach(&mut BridgePort::new(self.0.badge));
        };
        let ended = {
            let mut t = PORTS.lock();
            if t[i].owner == KERNEL_OWNER && t[i].ends.is_some() {
                // The kernel's own attachment (the console) is not the business
                // of a task that holds the port.
                return Out::err(outcome::REFUSED);
            }
            end_ends(&mut t[i])
        };
        ended.finish()
    }

    fn status(&self) -> Out<uart::Status> {
        if let Err(o) = self.0.gate::<uart::Status>(CapPerms::READ) {
            return o;
        }
        let lost = match slot_of(self.0.badge) {
            Some(i) => match PORTS.lock()[i].ends {
                Some((_, Dest::Client(c))) => Some(c),
                _ => None,
            },
            None => None,
        };
        let mut r = azos_devif::Uart::status(&self.line());
        if let (Some(c), true) = (lost, r.code == outcome::OK) {
            r.value.tx_lost = r.value.tx_lost.wrapping_add(c.lost());
        }
        r
    }
}

// ── Adc ───────────────────────────────────────────────────────────────────

/// The `Adc` interface served for one caller: the converter channel the badge
/// names (`adc.2`). Every op observes (`READ`) except `set_rate`, which retunes
/// the converter all channels share (`EXEC`). The one-shot ops run on a fresh
/// adapter of the channel: they keep no state and take no lock. `start_batch` and `stop_batch` use the
/// channel's own adapter, which keeps the batch.
pub struct AdcServer(pub Caller);

impl AdcServer {
    /// The channel, if the interface can name it.
    fn channel(&self) -> Result<usize, u32> {
        if self.0.badge < adc::CHANNELS {
            Ok(self.0.badge as usize)
        } else {
            Err(outcome::NO_RESOURCE)
        }
    }
}

impl azos_devif::Adc for AdcServer {
    fn read(&mut self) -> Out<adc::Reading> {
        if let Err(o) = self.0.gate::<adc::Reading>(CapPerms::READ) {
            return o;
        }
        azos_devif::Adc::read(&mut AdcPort::new(self.0.badge))
    }

    fn set_rate(&mut self, hz: u32) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::EXEC) {
            return o;
        }
        azos_devif::Adc::set_rate(&mut AdcPort::new(self.0.badge), hz)
    }

    fn rate(&self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        azos_devif::Adc::rate(&AdcPort::new(self.0.badge))
    }

    fn start_batch(&mut self, queue: Cap<SampleQueue>, count: u32) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::READ) {
            return o;
        }
        let ch = match self.channel() {
            Ok(c) => c,
            Err(c) => return Out::err(c),
        };
        let end = match QueueEnd::resolve::<RECORD_WORDS>(&self.0, queue.raw(), CapPerms::WRITE) {
            Ok(e) => e,
            Err(c) => return Out::err(c),
        };
        let r = {
            let mut hosts = ADC.lock();
            let host = &mut hosts[ch];
            let r = azos_devif::Adc::start_batch(&mut host.port, queue, count);
            if r.code == outcome::OK {
                host.queue = Some(end);
                host.owner = self.0.tid;
                host.gen = host.gen.wrapping_add(1);
            }
            r
        };
        if r.code == outcome::OK && !kick_pump() {
            let _ = end_batch(&mut ADC.lock()[ch]);
            return Out::err(outcome::NO_RESOURCE);
        }
        r
    }

    fn stop_batch(&mut self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        let ch = match self.channel() {
            Ok(c) => c,
            Err(c) => return Out::err(c),
        };
        end_batch(&mut ADC.lock()[ch])
    }
}
