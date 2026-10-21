// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Spi`, `Can`, `Adc` and `Uart` interfaces (S4 HAL H3): their op tables
//! (every op declares how a transport may retry it, the irreversible ones
//! declare their failure contract), their wire forms and the bounded types
//! they carry, each driven through the generated client and dispatcher over a
//! mock bus.

use azos_devif::adc::{self, Batch, Record, RecordSink, SampleQueue};
use azos_devif::can::{self, Frame};
use azos_devif::i2c::Bytes;
use azos_devif::spi;
use azos_devif::uart::{self, Chunk, RxQueue, TxQueue};
use azos_devif::{
    outcome, Adc, AdcCall, AdcClient, AdcIdl, Can, CanCall, CanClient, CanIdl, Out, Spi, SpiCall, SpiClient, SpiIdl, Uart,
    UartCall, UartClient, UartIdl, ADC_ID, CAN_ID, SPI_ID, UART_ID,
};
use azos_idl::{Cap, MsgDesc, OnFailure, OpInfo, Reader, Result as IdlResult, Transport, Wire, Writer, MSG_VERSION};
use std::cell::{Cell, RefCell};

/// A transport whose far end is a dispatcher over a mock: the message the
/// client built is kept so a test can read the wire.
struct Loop<'a> {
    serve: &'a dyn Fn(&MsgDesc, &mut MsgDesc),
    sent: Cell<u32>,
    last: RefCell<MsgDesc>,
}

impl<'a> Loop<'a> {
    fn new(serve: &'a dyn Fn(&MsgDesc, &mut MsgDesc)) -> Self {
        Loop { serve, sent: Cell::new(0), last: RefCell::new(MsgDesc::default()) }
    }
}

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        self.sent.set(self.sent.get() + 1);
        let req = *msg;
        *self.last.borrow_mut() = req;
        (self.serve)(&req, msg);
        Ok(())
    }
}

fn name_of(t: &[OpInfo], n: &str) -> OpInfo {
    *t.iter().find(|o| o.name == n).unwrap_or_else(|| panic!("no op {n}"))
}

/// Every op of the four interfaces names how a transport may treat a lost
/// reply, fits the message, and the ops that act on the world (a byte clocked
/// into a chip, a frame on the bus, a line opened to the outside) are
/// `once_only` and say what happens when their service fails.
///
/// **Canary.** Drop `#[once_only]` from `Spi::transfer` or `Spi::read`, or the `#[on_failure]`
/// from `Can::send`: red (the second does not compile, the lint refuses it;
/// the first fails the `once_only` line).
#[test]
fn the_op_tables_declare_delivery_and_the_irreversible_ones_their_failure() {
    let tables: [(&str, &[OpInfo], u32); 4] = [
        ("spi", &SpiIdl::OPS, SPI_ID),
        ("can", &CanIdl::OPS, CAN_ID),
        ("adc", &AdcIdl::OPS, ADC_ID),
        ("uart", &UartIdl::OPS, UART_ID),
    ];
    for (iface, t, _) in tables {
        for (i, o) in t.iter().enumerate() {
            assert_eq!(o.op as usize, i + 1, "{iface}.{}", o.name);
            assert!(o.delivery().is_some(), "{iface}.{} declares no delivery class", o.name);
            assert!(o.req_words <= 8 && o.rep_words <= 8, "{iface}.{}", o.name);
        }
    }
    let acts = [
        name_of(&SpiIdl::OPS, "transfer"),
        name_of(&SpiIdl::OPS, "write"),
        // `read` sends a caller-chosen first byte, which the device may take
        // for a command: it is `transfer` with a one-byte request.
        name_of(&SpiIdl::OPS, "read"),
        name_of(&CanIdl::OPS, "send"),
        name_of(&UartIdl::OPS, "attach"),
    ];
    for o in acts {
        assert!(o.once_only() && !o.retry_safe(), "{} may be asked again", o.name);
        assert_eq!(o.on_failure, Some(OnFailure::Degrade), "{}", o.name);
        assert!(o.deadline_ns > 0 && o.budget_us > 0, "{} has no deadline", o.name);
    }
    // Reading consumes a frame: at most once, never retried blind.
    let recv = name_of(&CanIdl::OPS, "recv");
    assert!(recv.at_most_once() && !recv.retry_safe());
    // The capability entries: one queue to the converter, two to a port.
    assert_eq!(name_of(&AdcIdl::OPS, "start_batch").req_caps, 1);
    assert_eq!(name_of(&UartIdl::OPS, "attach").req_caps, 2);
    assert_eq!(SpiIdl::ID, SPI_ID);
    assert_eq!(CanIdl::ID, CAN_ID);
    assert_eq!(AdcIdl::ID, ADC_ID);
    assert_eq!(UartIdl::ID, UART_ID);
}

/// The four interface ids are distinct from each other and from the other
/// interfaces of the registry (the rows themselves are `h3_hosts.rs`'s).
#[test]
fn the_ids_do_not_collide_with_the_registry() {
    let mine = [SPI_ID, CAN_ID, ADC_ID, UART_ID];
    for (i, a) in mine.iter().enumerate() {
        assert!(!mine[i + 1..].contains(a));
        assert_eq!(azos_devif::IFACES.iter().filter(|f| f.id == *a).count(), 1);
    }
    assert_eq!(SPI_ID.to_be_bytes(), *b"SPI ");
    assert_eq!(CAN_ID.to_be_bytes(), *b"CAN ");
    assert_eq!(ADC_ID.to_be_bytes(), *b"ADC ");
    assert_eq!(UART_ID.to_be_bytes(), *b"UART");
}

// ── Spi ──────────────────────────────────────────────────────────────────

/// A mock bus with one device: a register file; a transfer writes the bytes
/// into it from register 0 and answers the file's bytes, as the simulated flash
/// of the bus driver does. The controller only runs mode 0 at its default
/// clock and releases the chip select after every transfer, like the JH7110
/// path.
struct MockSpi {
    regs: [u8; 256],
    present: bool,
    mode: u32,
    hz: u32,
    held: bool,
    flexible: bool,
    transfers: u32,
}

impl MockSpi {
    fn new() -> Self {
        let mut regs = [0u8; 256];
        regs[..3].copy_from_slice(&[0xEF, 0x40, 0x16]);
        MockSpi { regs, present: true, mode: 0, hz: spi::SPEED_DEFAULT_HZ, held: false, flexible: true, transfers: 0 }
    }
}

impl Spi for MockSpi {
    fn transfer(&mut self, data: Bytes) -> Out<Bytes> {
        let n = data.n as usize;
        if n == 0 || n > spi::MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if !self.present {
            return Out::err(outcome::NO_RESOURCE);
        }
        let mut tx = [0u8; spi::MAX_BYTES];
        data.copy_to(&mut tx);
        self.transfers += 1;
        self.regs[..n].copy_from_slice(&tx[..n]);
        Out::ok(Bytes::from_slice(&self.regs[..n]))
    }
    fn write(&mut self, data: Bytes) -> Out<()> {
        let r = self.transfer(data);
        Out::new(r.code, ())
    }
    fn read(&mut self, reg: u32, len: u32) -> Out<Bytes> {
        if reg > 0xFF || len == 0 || len as usize > spi::MAX_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let reg = reg as usize;
        let bytes: Vec<u8> = (0..len as usize).map(|j| self.regs[(reg + j) & 0xFF]).collect();
        Out::ok(Bytes::from_slice(&bytes))
    }
    fn set_mode(&mut self, mode: u32) -> Out<()> {
        if mode >= spi::MODES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if !self.flexible && mode != 0 {
            return Out::err(outcome::UNSUPPORTED);
        }
        self.mode = mode;
        Out::ok(())
    }
    fn set_speed(&mut self, hz: u32) -> Out<()> {
        if !(spi::SPEED_MIN_HZ..=spi::SPEED_MAX_HZ).contains(&hz) {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if !self.flexible && hz != spi::SPEED_DEFAULT_HZ {
            return Out::err(outcome::UNSUPPORTED);
        }
        self.hz = hz;
        Out::ok(())
    }
    fn hold_cs(&mut self, hold: bool) -> Out<()> {
        if !self.flexible && hold {
            return Out::err(outcome::UNSUPPORTED);
        }
        self.held = hold;
        Out::ok(())
    }
}

/// A transfer answers the bytes clocked in, as many as were sent; the badge
/// is bus and chip select; every bound refuses at the interface.
///
/// **Canary.** Make `transfer` answer `len + 1` bytes, or accept 33 bytes: red.
#[test]
fn spi_transfer_is_full_duplex_and_bounded() {
    assert_eq!(spi::unbadge(spi::badge(1, 3)), (1, 3));
    assert_eq!(spi::badge(0, 1), 1);
    let mock = RefCell::new(MockSpi::new());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = SpiIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop::new(&serve);
    let mut c = SpiClient::new(&lp);

    let r = c.transfer(Bytes::from_slice(&[0x9F, 0, 0])).unwrap();
    let mut got = [0u8; 3];
    assert!(r.is_ok());
    assert_eq!(r.value.copy_to(&mut got), 3);
    assert_eq!(got, [0x9F, 0, 0], "the mock device echoes what it was sent");
    assert_eq!(c.read(0, 4).unwrap().value, Bytes::from_slice(&[0x9F, 0, 0, 0]));

    // A transfer is the header and five words; its reply is the status, the
    // outcome and five words.
    let first = c.transfer(Bytes::from_slice(&[1; 32])).unwrap();
    assert!(first.is_ok() && first.value.n == 32);
    assert_eq!(lp.last.borrow().n_words, 1 + Bytes::WORDS as u8);

    for bad in [0usize, 33] {
        let b = Bytes { n: bad as u32, w: [0; 4] };
        assert_eq!(c.transfer(b).unwrap().code, outcome::BAD_ARGUMENT, "len {bad}");
        assert_eq!(c.write(b).unwrap().code, outcome::BAD_ARGUMENT, "len {bad}");
    }
    assert_eq!(c.read(256, 1).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.read(0, 0).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.read(0, 33).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(mock.borrow().transfers, 2, "a refused transfer never reached the bus");

    mock.borrow_mut().present = false;
    assert_eq!(c.transfer(Bytes::from_slice(&[1])).unwrap().code, outcome::NO_RESOURCE);
}

/// Mode, speed and the chip-select hold are bounded at the interface and a
/// controller that cannot run the setup says `UNSUPPORTED`, leaving the
/// setup as it was.
#[test]
fn spi_setup_is_bounded_and_a_refusal_leaves_it_alone() {
    let mock = RefCell::new(MockSpi::new());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = SpiIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop::new(&serve);
    let mut c = SpiClient::new(&lp);
    assert_eq!(c.set_mode(3).unwrap(), Out::ok(()));
    assert_eq!(c.set_mode(4).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.set_speed(spi::SPEED_MAX_HZ).unwrap(), Out::ok(()));
    assert_eq!(c.set_speed(spi::SPEED_MAX_HZ + 1).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.set_speed(spi::SPEED_MIN_HZ - 1).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.hold_cs(true).unwrap(), Out::ok(()));
    assert!(mock.borrow().held);
    assert_eq!((mock.borrow().mode, mock.borrow().hz), (3, spi::SPEED_MAX_HZ));

    {
        let mut m = mock.borrow_mut();
        m.flexible = false;
        m.mode = 0;
        m.hz = spi::SPEED_DEFAULT_HZ;
        m.held = false;
    }
    assert_eq!(c.set_mode(2).unwrap().code, outcome::UNSUPPORTED);
    assert_eq!(c.set_speed(4_000_000).unwrap().code, outcome::UNSUPPORTED);
    assert_eq!(c.hold_cs(true).unwrap().code, outcome::UNSUPPORTED);
    assert_eq!((mock.borrow().mode, mock.borrow().hz, mock.borrow().held), (0, spi::SPEED_DEFAULT_HZ, false));
    assert_eq!(c.set_mode(0).unwrap(), Out::ok(()), "the setup the controller has is accepted");
}

// ── Can ──────────────────────────────────────────────────────────────────

/// What a frame is: the ones a controller can transmit.
///
/// **Canary.** Let `is_valid` accept a 12-bit standard id, or data past the
/// length: red.
#[test]
fn a_can_frame_is_valid_only_when_the_controller_could_transmit_it() {
    assert!(Frame::new(0x7FF, 0, &[1, 2, 3]).is_valid());
    assert!(!Frame::new(0x800, 0, &[]).is_valid(), "12 bits is not a standard id");
    assert!(Frame::new(0x800, can::FLAG_EXTENDED, &[]).is_valid());
    assert!(Frame::new(can::EXT_ID_MAX, can::FLAG_EXTENDED, &[0xFF; 8]).is_valid());
    assert!(!Frame::new(can::EXT_ID_MAX + 1, can::FLAG_EXTENDED, &[]).is_valid());
    assert!(!Frame { id: 1, flags: 0, dlc: 9, data: 0 }.is_valid(), "dlc past eight");
    assert!(!Frame { id: 1, flags: 0, dlc: 2, data: 0x1_0000 }.is_valid(), "data past the length");
    assert!(!Frame { id: 1, flags: 4, dlc: 0, data: 0 }.is_valid(), "an unknown flag");
    assert!(Frame { id: 1, flags: can::FLAG_RTR, dlc: 4, data: 0 }.is_valid(), "a remote request has a length and no data");
    assert!(!Frame { id: 1, flags: can::FLAG_RTR, dlc: 4, data: 1 }.is_valid());
    // Nine bytes are cut to eight, never wrapped.
    let f = Frame::new(1, 0, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(f.dlc, 8);
    let mut out = [0u8; 8];
    assert_eq!(f.copy_to(&mut out), 8);
    assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn a_can_frame_crosses_as_four_words() {
    let f = Frame::new(0x123, can::FLAG_EXTENDED, &[0xAA, 0xBB, 0xCC]);
    let mut m = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut m);
        Out::ok(f).put(&mut w);
        w.finish();
    }
    assert_eq!((m.n_words, m.words[1], m.words[2], m.words[3], m.words[4]), (5, 0x123, 1, 3, 0xCC_BBAA));
    let mut r = Reader::new(&m);
    assert_eq!(<Out<Frame> as Wire>::get(&mut r), Out::ok(f));
    assert!(r.finish().is_ok());
}

/// A mock controller: a receive ring of four, two filter slots, a bus-off
/// latch. A sent frame loops back if it passes the filters.
struct MockCan {
    state: u32,
    rx: std::collections::VecDeque<Frame>,
    filters: Vec<(u32, u32)>,
    bitrate: u32,
    sent: u32,
}

impl MockCan {
    fn new() -> Self {
        MockCan { state: can::STATE_ACTIVE, rx: Default::default(), filters: vec![], bitrate: 500_000, sent: 0 }
    }
}

impl Can for MockCan {
    fn send(&mut self, frame: Frame) -> Out<()> {
        if !frame.is_valid() {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        match self.state {
            can::STATE_UNINIT => return Out::err(outcome::NOT_READY),
            can::STATE_BUS_OFF => return Out::err(outcome::FAULT),
            _ => {}
        }
        self.sent += 1;
        if (self.filters.is_empty() || self.filters.iter().any(|&(id, m)| frame.id & m == id & m)) && self.rx.len() < 4 {
            self.rx.push_back(frame);
        }
        Out::ok(())
    }
    fn recv(&mut self) -> Out<Frame> {
        match self.rx.pop_front() {
            Some(f) => Out::ok(f),
            None => Out::err(outcome::NOT_READY),
        }
    }
    fn add_filter(&mut self, id: u32, mask: u32) -> Out<()> {
        if self.filters.len() >= 2 {
            return Out::err(outcome::BUSY);
        }
        self.filters.push((id, mask));
        Out::ok(())
    }
    fn clear_filters(&mut self) -> Out<()> {
        self.filters.clear();
        Out::ok(())
    }
    fn set_bitrate(&mut self, bps: u32) -> Out<()> {
        if !(can::BITRATE_MIN..=can::BITRATE_MAX).contains(&bps) {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        self.bitrate = bps;
        Out::ok(())
    }
    fn state(&self) -> Out<u32> {
        Out::ok(self.state)
    }
    fn recover(&mut self) -> Out<()> {
        if self.state == can::STATE_UNINIT {
            return Out::err(outcome::NOT_READY);
        }
        self.state = can::STATE_ACTIVE;
        Out::ok(())
    }
}

/// Send, filter, receive and the bus-off cycle through the client: a frame the
/// controller cannot transmit never reaches it, bus-off refuses until
/// `recover`, and the frames come back in order.
///
/// **Canary.** Let `recover` leave `state` at bus-off, or `send` ignore the
/// state: red.
#[test]
fn can_send_filter_recv_and_the_bus_off_cycle() {
    let mock = RefCell::new(MockCan::new());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = CanIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop::new(&serve);
    let mut c = CanClient::new(&lp);

    assert_eq!(c.recv().unwrap().code, outcome::NOT_READY, "nothing received yet");
    assert_eq!(c.send(Frame::new(0x100, 0, &[1])).unwrap(), Out::ok(()));
    assert_eq!(c.send(Frame::new(0x200, 0, &[2, 3])).unwrap(), Out::ok(()));
    assert_eq!(c.recv().unwrap().value, Frame::new(0x100, 0, &[1]), "oldest first");
    assert_eq!(c.recv().unwrap().value.id, 0x200);
    assert_eq!(c.recv().unwrap().code, outcome::NOT_READY);

    assert_eq!(c.add_filter(0x100, 0x700).unwrap(), Out::ok(()));
    assert_eq!(c.add_filter(0x300, 0x7FF).unwrap(), Out::ok(()));
    assert_eq!(c.add_filter(0x400, 0x7FF).unwrap().code, outcome::BUSY, "no filter left");
    for id in [0x1FF, 0x200, 0x300, 0x301] {
        c.send(Frame::new(id, 0, &[])).unwrap();
    }
    let mut ids = vec![];
    while let Out { code: outcome::OK, value } = c.recv().unwrap() {
        ids.push(value.id);
    }
    assert_eq!(ids, [0x1FF, 0x300], "only the ids that pass a filter");
    assert_eq!(c.clear_filters().unwrap(), Out::ok(()));
    c.send(Frame::new(0x555, 0, &[])).unwrap();
    assert_eq!(c.recv().unwrap().value.id, 0x555, "no filter: everything passes");

    assert_eq!(c.set_bitrate(1_000_000).unwrap(), Out::ok(()));
    assert_eq!(c.set_bitrate(1_000_001).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.set_bitrate(9_999).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(mock.borrow().bitrate, 1_000_000);

    let sent = mock.borrow().sent;
    assert_eq!(c.send(Frame { id: 0x900, flags: 0, dlc: 0, data: 0 }).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(mock.borrow().sent, sent, "an invalid frame is refused before the controller");

    mock.borrow_mut().state = can::STATE_BUS_OFF;
    assert_eq!(c.state().unwrap().value, can::STATE_BUS_OFF);
    assert_eq!(c.send(Frame::new(1, 0, &[])).unwrap().code, outcome::FAULT);
    assert_eq!(c.recover().unwrap(), Out::ok(()));
    assert_eq!(c.recover().unwrap(), Out::ok(()), "recovering again is served");
    assert_eq!(c.state().unwrap().value, can::STATE_ACTIVE);
    assert_eq!(c.send(Frame::new(1, 0, &[])).unwrap(), Out::ok(()));

    mock.borrow_mut().state = can::STATE_UNINIT;
    assert_eq!(c.send(Frame::new(1, 0, &[])).unwrap().code, outcome::NOT_READY);
    assert_eq!(c.recover().unwrap().code, outcome::NOT_READY);
}

// ── Adc ──────────────────────────────────────────────────────────────────

/// A queue the test owns the consumer end of: room for `cap` records.
struct Ring {
    cap: usize,
    items: Vec<Record>,
}

impl RecordSink for Ring {
    fn push(&mut self, r: &Record) -> bool {
        if self.items.len() >= self.cap {
            return false;
        }
        self.items.push(*r);
        true
    }
}

#[test]
fn an_adc_record_is_sixteen_bytes_and_reads_back() {
    let r = Record { acq_ns: 0x0102_0304_0506_0708, mv: -1234, raw: -32768, channel: 3, flags: adc::RECORD_LOST };
    let b = r.encode();
    assert_eq!(b.len(), adc::RECORD_BYTES);
    assert_eq!(&b[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(Record::decode(&b), r);
    assert_eq!(Record::default().encode(), [0u8; 16]);
}

/// The batch's schedule: the first sample at the host's first look, then one
/// per period counted from the previous one's due time, a count that ends the
/// batch, a ring that was full flagged on the next record, and a late wake-up
/// that skips the periods it missed rather than bursting.
///
/// **Canary.** Count the period from `now` instead of the previous due time
/// (the batch drifts: the third line goes red), or burst on a late wake-up
/// (the fifth line goes red).
#[test]
fn an_adc_batch_keeps_its_period_counts_down_and_marks_what_it_lost() {
    let ms = 1_000_000u64;
    let mut b = Batch::idle();
    assert!(!b.is_active() && !b.due(0) && b.next_due_ns().is_none());

    b.start(100, 4); // 10 ms period
    assert_eq!(b.next_due_ns(), Some(0));
    assert!(b.due(5 * ms), "the first sample is due at the first look");
    let rec = b.record(5 * ms, 2, 100, 7);
    assert_eq!((rec.acq_ns, rec.channel, rec.raw, rec.mv, rec.flags), (5 * ms, 2, 100, 7, 0));
    b.done(5 * ms, true);
    assert_eq!(b.next_due_ns(), Some(15 * ms));
    assert!(!b.due(14 * ms) && b.due(15 * ms));
    // Taken 3 ms late: the next one is still due on the grid.
    b.done(18 * ms, true);
    assert_eq!(b.next_due_ns(), Some(25 * ms), "the period counts from the due time, not from when it ran");

    // A full ring: the sample is lost and the next record says so.
    b.done(25 * ms, false);
    assert_eq!(b.next_due_ns(), Some(35 * ms));
    assert_eq!(b.record(35 * ms, 2, 1, 1).flags, adc::RECORD_LOST);
    assert_eq!(b.record(35 * ms, 2, 1, 1).flags, 0, "the flag is reported once");

    // Four samples were asked for; the fourth ends the batch.
    b.done(35 * ms, true);
    assert!(!b.is_active());
    assert_eq!(b.stop(), 3, "three samples reached the ring, one did not");

    // Until stopped, and a wake-up 47 ms late skips four periods.
    b.start(100, 0);
    b.done(0, true);
    assert_eq!(b.next_due_ns(), Some(10 * ms));
    b.done(57 * ms, true);
    assert_eq!(b.next_due_ns(), Some(60 * ms), "skipped periods are not burst");
    assert_eq!(b.record(60 * ms, 0, 0, 0).flags, adc::RECORD_LOST, "the skipped periods are reported");
    assert!(b.is_active());
    assert_eq!(b.stop(), 2);
    assert!(!b.is_active() && b.next_due_ns().is_none());

    // A rate past the interface's is held at it, a zero rate at one.
    b.start(0, 1);
    b.done(0, true);
    b.start(u32::MAX, 0);
    b.done(0, true);
    assert_eq!(b.next_due_ns(), Some(1_000), "1 MHz is one microsecond");
}

/// A mock converter: four channels, the codes of a ramp, rates of the ADS1115's
/// table, one batch at a time into a ring the mock fills when pumped.
struct MockAdc {
    channel: u32,
    rate: u32,
    inited: bool,
    batch: Batch,
    queue: Option<Cap<SampleQueue>>,
    code: i32,
}

impl MockAdc {
    fn new(channel: u32) -> Self {
        MockAdc { channel, rate: 128, inited: true, batch: Batch::idle(), queue: None, code: 1000 }
    }
    fn check(&self) -> Result<(), u32> {
        if self.channel > 3 {
            Err(outcome::NO_RESOURCE)
        } else if !self.inited {
            Err(outcome::NOT_READY)
        } else {
            Ok(())
        }
    }
    fn pump(&mut self, now: u64, ring: &mut Ring) -> bool {
        if !self.batch.due(now) {
            return false;
        }
        self.code += 1;
        let rec = self.batch.record(now, self.channel as u8, self.code as i16, self.code / 8);
        let ok = ring.push(&rec);
        self.batch.done(now, ok);
        true
    }
}

impl Adc for MockAdc {
    fn read(&mut self) -> Out<adc::Reading> {
        if let Err(c) = self.check() {
            return Out::err(c);
        }
        Out::ok(adc::Reading { raw: self.code, mv: self.code / 8 })
    }
    fn set_rate(&mut self, hz: u32) -> Out<u32> {
        if !(1..=adc::RATE_MAX_HZ).contains(&hz) {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if let Err(c) = self.check() {
            return Out::err(c);
        }
        match [8, 16, 32, 64, 128, 250, 475, 860].into_iter().find(|&r| r >= hz) {
            Some(r) => {
                self.rate = r;
                Out::ok(r)
            }
            None => Out::err(outcome::UNSUPPORTED),
        }
    }
    fn rate(&self) -> Out<u32> {
        match self.check() {
            Ok(()) => Out::ok(self.rate),
            Err(c) => Out::err(c),
        }
    }
    fn start_batch(&mut self, queue: Cap<SampleQueue>, count: u32) -> Out<()> {
        if let Err(c) = self.check() {
            return Out::err(c);
        }
        if self.batch.is_active() {
            return Out::err(outcome::BUSY);
        }
        self.batch.start(self.rate, count);
        self.queue = Some(queue);
        Out::ok(())
    }
    fn stop_batch(&mut self) -> Out<u32> {
        self.queue = None;
        Out::ok(self.batch.stop())
    }
}

/// One-shot reads, the rate rounding up to the converter's table, and a batch
/// into a queue: the queue handle crosses as a capability entry, the samples
/// come back in order on the ring with no further call, and a batch that ends
/// lets go of the queue.
///
/// **Canary.** Round the rate down instead of up, or let `start_batch` start a
/// second batch: red.
#[test]
fn an_adc_reads_once_sets_its_rate_and_batches_into_a_queue() {
    let mock = RefCell::new(MockAdc::new(2));
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = AdcIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop::new(&serve);
    let mut c = AdcClient::new(&lp);

    assert_eq!(c.read().unwrap(), Out::ok(adc::Reading { raw: 1000, mv: 125 }));
    assert_eq!(c.rate().unwrap(), Out::ok(128));
    assert_eq!(c.set_rate(100).unwrap(), Out::ok(128), "the nearest rate at or above");
    assert_eq!(c.set_rate(129).unwrap(), Out::ok(250));
    assert_eq!(c.set_rate(860).unwrap(), Out::ok(860));
    assert_eq!(c.set_rate(861).unwrap().code, outcome::UNSUPPORTED, "the converter is slower than that");
    assert_eq!(c.set_rate(0).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.set_rate(adc::RATE_MAX_HZ + 1).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.set_rate(100).unwrap().value, 128);

    let q: Cap<SampleQueue> = Cap::from_raw(41);
    assert_eq!(c.start_batch(q, 3).unwrap(), Out::ok(()));
    let r = *lp.last.borrow();
    assert_eq!((r.n_words, r.n_caps, r.caps[0].handle), (2, 1, 41), "the queue is the one capability entry");
    assert_eq!(r.words[1], 3);
    assert_eq!(mock.borrow().queue, Some(q));
    assert_eq!(c.start_batch(Cap::from_raw(42), 1).unwrap().code, outcome::BUSY);
    assert_eq!(mock.borrow().queue, Some(q), "the refused queue did not replace the running one");

    // The device samples at its rate; no call carries a sample.
    let sent = lp.sent.get();
    let mut ring = Ring { cap: 8, items: vec![] };
    let period = 1_000_000_000 / 128u64;
    for k in 0..5u64 {
        mock.borrow_mut().pump(k * period, &mut ring);
    }
    assert_eq!(lp.sent.get(), sent, "samples travel on the queue, not in calls");
    assert_eq!(ring.items.iter().map(|r| r.raw).collect::<Vec<_>>(), [1001, 1002, 1003], "three asked for, three taken");
    assert!(ring.items.iter().all(|r| r.channel == 2 && r.flags == 0));
    assert_eq!(ring.items[1].acq_ns, period);
    assert_eq!(c.stop_batch().unwrap(), Out::ok(3));
    assert_eq!(mock.borrow().queue, None, "a stopped batch lets go of the queue");
    assert_eq!(c.start_batch(Cap::from_raw(43), 1).unwrap(), Out::ok(()), "a stopped batch can be restarted");

    // A full ring: the lost sample is reported on the next one that fits.
    let mut tight = Ring { cap: 1, items: vec![] };
    let mut m = mock.borrow_mut();
    m.batch.start(128, 0);
    m.pump(0, &mut tight);
    m.pump(period, &mut tight);
    tight.cap = 2;
    m.pump(2 * period, &mut tight);
    assert_eq!(tight.items.iter().map(|r| r.flags).collect::<Vec<_>>(), [0, adc::RECORD_LOST]);
    drop(m);

    // A channel the part does not have, and a converter not yet initialized.
    *mock.borrow_mut() = MockAdc::new(5);
    assert_eq!(c.read().unwrap().code, outcome::NO_RESOURCE);
    assert_eq!(c.start_batch(Cap::from_raw(1), 1).unwrap().code, outcome::NO_RESOURCE);
    *mock.borrow_mut() = MockAdc { inited: false, ..MockAdc::new(0) };
    assert_eq!(c.read().unwrap().code, outcome::NOT_READY);
    assert_eq!(c.rate().unwrap().code, outcome::NOT_READY);
}

// ── Uart ─────────────────────────────────────────────────────────────────

/// A chunk is 40 bytes on a queue and the bytes that were not written are
/// not read: a length past the data is refused, not clamped.
///
/// **Canary.** Clamp the length in `decode` instead of refusing it: the
/// `None` line goes red.
#[test]
fn a_uart_chunk_is_forty_bytes_and_a_wrong_length_is_refused() {
    let c = Chunk::new(b"hello", uart::CHUNK_OVERRUN);
    let b = c.encode();
    assert_eq!(b.len(), uart::CHUNK_BYTES);
    assert_eq!(&b[0..4], &5u32.to_le_bytes());
    assert_eq!(&b[4..8], &uart::CHUNK_OVERRUN.to_le_bytes());
    assert_eq!(&b[8..13], b"hello");
    let d = Chunk::decode(&b).unwrap();
    assert_eq!((d.bytes(), d.flags), (&b"hello"[..], uart::CHUNK_OVERRUN));
    let mut bad = b;
    bad[0..4].copy_from_slice(&33u32.to_le_bytes());
    assert!(Chunk::decode(&bad).is_none());
    // More bytes than a chunk holds are cut at the chunk.
    let long = Chunk::new(&[7u8; 100], 0);
    assert_eq!(long.len as usize, uart::CHUNK_DATA);
    assert_eq!(long.bytes().len(), uart::CHUNK_DATA);
}

/// A mock port: loops the transmit queue back to the receive queue the way a
/// wire with TX tied to RX does, over two in-memory rings.
struct MockUart {
    line: (u32, u32, u32, u32),
    rings: Option<(Cap<RxQueue>, Cap<TxQueue>)>,
    rx_lost: u32,
    tx_lost: u32,
    ready: bool,
}

impl MockUart {
    fn new() -> Self {
        MockUart { line: (115_200, 8, uart::PARITY_NONE, 1), rings: None, rx_lost: 0, tx_lost: 0, ready: true }
    }
    /// One service round: pop each transmit chunk and receive it back.
    fn pump(&mut self, tx: &mut Vec<Chunk>, rx: &mut Vec<Chunk>, rx_room: usize) {
        if self.rings.is_none() {
            return;
        }
        for c in tx.drain(..) {
            let mut c = c;
            if rx.len() >= rx_room {
                self.rx_lost += 1;
                continue;
            }
            if self.rx_lost > 0 {
                c.flags |= uart::CHUNK_OVERRUN;
            }
            rx.push(c);
        }
    }
}

impl Uart for MockUart {
    fn configure(&mut self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()> {
        if !(uart::BAUD_MIN..=uart::BAUD_MAX).contains(&baud)
            || !(5..=8).contains(&data_bits)
            || parity > uart::PARITY_EVEN
            || !(1..=2).contains(&stop_bits)
        {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        self.line = (baud, data_bits, parity, stop_bits);
        Out::ok(())
    }
    fn attach(&mut self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()> {
        if !self.ready {
            return Out::err(outcome::NOT_READY);
        }
        if self.rings.is_some() {
            return Out::err(outcome::BUSY);
        }
        self.rings = Some((rx, tx));
        Out::ok(())
    }
    fn detach(&mut self) -> Out<()> {
        self.rings = None;
        Out::ok(())
    }
    fn status(&self) -> Out<uart::Status> {
        Out::ok(uart::Status { rx_lost: self.rx_lost, tx_lost: self.tx_lost })
    }
}

/// Configure, attach two queues (two capability entries, receive first),
/// bytes on the rings with no call between, a full receive queue counted and
/// flagged, detach.
///
/// **Canary.** Swap the capability order in `attach`'s mock, or let a second
/// `attach` replace the rings: red.
#[test]
fn a_uart_attaches_two_queues_and_moves_bytes_without_calls() {
    let mock = RefCell::new(MockUart::new());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = UartIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop::new(&serve);
    let mut c = UartClient::new(&lp);

    assert_eq!(c.configure(9600, 7, uart::PARITY_EVEN, 2).unwrap(), Out::ok(()));
    assert_eq!(mock.borrow().line, (9600, 7, uart::PARITY_EVEN, 2));
    for bad in [(299, 8, 0, 1), (4_000_001, 8, 0, 1), (9600, 4, 0, 1), (9600, 9, 0, 1), (9600, 8, 3, 1), (9600, 8, 0, 0), (9600, 8, 0, 3)] {
        assert_eq!(c.configure(bad.0, bad.1, bad.2, bad.3).unwrap().code, outcome::BAD_ARGUMENT, "{bad:?}");
    }
    assert_eq!(mock.borrow().line, (9600, 7, uart::PARITY_EVEN, 2), "a refused line changed nothing");

    let (rxq, txq): (Cap<RxQueue>, Cap<TxQueue>) = (Cap::from_raw(10), Cap::from_raw(11));
    assert_eq!(c.attach(rxq, txq).unwrap(), Out::ok(()));
    let r = *lp.last.borrow();
    assert_eq!((r.n_words, r.n_caps, r.caps[0].handle, r.caps[1].handle), (1, 2, 10, 11));
    assert_eq!(mock.borrow().rings, Some((rxq, txq)));
    assert_eq!(c.attach(Cap::from_raw(12), Cap::from_raw(13)).unwrap().code, outcome::BUSY);
    assert_eq!(mock.borrow().rings, Some((rxq, txq)), "the refused rings did not replace the attached ones");

    let sent = lp.sent.get();
    let (mut tx, mut rx) = (vec![Chunk::new(b"AT\r\n", 0), Chunk::new(b"OK", 0)], vec![]);
    mock.borrow_mut().pump(&mut tx, &mut rx, 4);
    assert_eq!(lp.sent.get(), sent, "bytes travel on the queues, not in calls");
    assert_eq!(rx.iter().map(|c| c.bytes().to_vec()).collect::<Vec<_>>(), [b"AT\r\n".to_vec(), b"OK".to_vec()]);

    // The receive queue is full: the chunk is counted and the next is flagged.
    let mut tx = vec![Chunk::new(b"lost", 0), Chunk::new(b"seen", 0)];
    let mut rx = vec![Chunk::new(b"x", 0); 3];
    mock.borrow_mut().pump(&mut tx, &mut rx, 3);
    assert_eq!(c.status().unwrap().value, uart::Status { rx_lost: 2, tx_lost: 0 });
    rx.clear();
    let mut tx = vec![Chunk::new(b"fits", 0)];
    mock.borrow_mut().pump(&mut tx, &mut rx, 3);
    assert_eq!(rx[0].flags, uart::CHUNK_OVERRUN, "the reader sees the gap");

    assert_eq!(c.detach().unwrap(), Out::ok(()));
    assert_eq!(c.detach().unwrap(), Out::ok(()), "detaching twice is served");
    assert_eq!(mock.borrow().rings, None);
    mock.borrow_mut().ready = false;
    assert_eq!(c.attach(rxq, txq).unwrap().code, outcome::NOT_READY, "a port with no hardware behind it");
}
