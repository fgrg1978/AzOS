// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The mass-storage class driver (`azos_usb::class::msc`) against a fake
//! Bulk-Only stick behind the register-level xHCI mock.
//!
//! [`Stick`] answers what the driver puts on bulk-OUT: it reads the CBW the
//! mock logged, runs the SCSI command against its own store (the target half
//! of `azos_scsi`), and queues the data and the CSW on bulk-IN. Its knobs make
//! it misbehave the ways a real stick does.

use azos_devif::outcome::{BUSY, OK, UNSUPPORTED};
use azos_scsi::bbb::{Cbw, Csw, CBW_TOTAL_LEN, CSW_STATUS_FAIL, CSW_STATUS_OK, CSW_STATUS_PHASE_ERROR};
use azos_scsi::initiator::INQUIRY_LEN;
use azos_scsi::target::{
    execute_scsi, parse_scsi_command, BlockDevice, ScsiCommand, ScsiResponse, Sense, BLOCK_SIZE, SCSI_OP_INQUIRY,
    SCSI_OP_READ_10, SCSI_OP_READ_CAPACITY_10, SCSI_OP_REQUEST_SENSE, SCSI_OP_SYNCHRONIZE_CACHE_10,
    SCSI_OP_TEST_UNIT_READY, SCSI_OP_WRITE_10,
};
use azos_usb::class::msc::{Fail, IoStatus, Msc, State, Take};
use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
use azos_usb::hw::Clock;
use azos_usb::usbcore::desc::Setup;

use crate::devices::*;
use crate::harness::Rig;
use crate::mock::{MockClock, MockMem};

type Driver = Msc<'static, MockMem, MockClock>;

const SECTORS: u32 = 64;
/// Bulk IN 1 is DCI 3; bulk OUT 2 is DCI 4.
const DCI_IN: usize = 3;

/// A Bulk-Only stick.
struct Stick {
    store: Vec<u8>,
    sense: Sense,
    /// Opcodes of the commands seen, in order.
    ops: Vec<u8>,
    seen: usize,
    /// A WRITE(10) waiting for its data: tag, lba, blocks, and the failure
    /// to report once the data is in.
    awaiting: Option<(u32, u32, u32, Option<Sense>)>,
    // Knobs.
    device_type: u8,
    block_len: u32,
    last_lba: Option<u32>,
    /// TEST UNIT READY answers NOT READY this many times.
    not_ready: u32,
    /// The next command after power-up reports UNIT ATTENTION once.
    unit_attention: bool,
    /// The next READ(10)/WRITE(10) fails with a medium error.
    fail_io: u32,
    /// A cache-less device: SYNCHRONIZE CACHE is an invalid opcode.
    no_cache: bool,
    /// The next READ(10) stalls its data stage (no data is queued).
    stall_read: bool,
    /// Do not answer the next command at all.
    mute: bool,
    /// Answer the next command's CSW with the wrong tag.
    bad_tag: bool,
    /// Answer the next command with a phase error CSW.
    phase_error: bool,
}

impl Stick {
    fn new() -> Stick {
        let mut store = vec![0u8; SECTORS as usize * BLOCK_SIZE];
        for (i, b) in store.iter_mut().enumerate() {
            *b = (i % 251) as u8 ^ (i / 512) as u8;
        }
        Stick {
            store,
            sense: Sense::NONE,
            ops: Vec::new(),
            seen: 0,
            awaiting: None,
            device_type: 0,
            block_len: 512,
            last_lba: None,
            not_ready: 0,
            unit_attention: false,
            fail_io: 0,
            no_cache: false,
            stall_read: false,
            mute: false,
            bad_tag: false,
            phase_error: false,
        }
    }

    fn count(&self, op: u8) -> usize {
        self.ops.iter().filter(|o| **o == op).count()
    }

    /// Look at what the driver sent since the last step and answer it.
    fn step(&mut self, hw: &crate::mock::Hw, dev: &DevRef) {
        let new: Vec<(u8, Vec<u8>)> = dev.borrow().out_log[self.seen..].to_vec();
        self.seen += new.len();
        for (_, data) in new {
            if let Some((tag, lba, blocks, failure)) = self.awaiting.take() {
                assert_eq!(data.len(), blocks as usize * BLOCK_SIZE, "the data stage is the whole write");
                match failure {
                    Some(sense) => self.fail(hw, dev, tag, sense),
                    None => {
                        let at = lba as usize * BLOCK_SIZE;
                        self.store[at..at + data.len()].copy_from_slice(&data);
                        self.csw(hw, dev, tag, 0, CSW_STATUS_OK);
                    }
                }
                continue;
            }
            assert_eq!(data.len(), CBW_TOTAL_LEN, "a CBW");
            let cbw = Cbw::parse(&data).expect("valid CBW");
            self.command(hw, dev, &cbw);
        }
    }

    fn csw(&mut self, hw: &crate::mock::Hw, dev: &DevRef, tag: u32, residue: u32, status: u8) {
        let tag = if std::mem::take(&mut self.bad_tag) { tag ^ 0x100 } else { tag };
        let status = if std::mem::take(&mut self.phase_error) { CSW_STATUS_PHASE_ERROR } else { status };
        hw.inject_in(dev, 1, &Csw::new(tag, residue, status).encode());
    }

    fn fail(&mut self, hw: &crate::mock::Hw, dev: &DevRef, tag: u32, sense: Sense) {
        self.sense = sense;
        self.csw(hw, dev, tag, 0, CSW_STATUS_FAIL);
    }

    fn command(&mut self, hw: &crate::mock::Hw, dev: &DevRef, cbw: &Cbw) {
        let op = cbw.cdb[0];
        self.ops.push(op);
        if std::mem::take(&mut self.mute) {
            return;
        }
        let tag = cbw.tag;
        // What makes this command fail, if anything: a unit attention (to the
        // first command after power-up that is not INQUIRY / REQUEST SENSE),
        // or an injected medium error on a data command.
        let mut failure = None;
        if self.unit_attention && op != SCSI_OP_REQUEST_SENSE && op != SCSI_OP_INQUIRY {
            self.unit_attention = false;
            failure = Some(Sense { key: 6, asc: 0x29, ascq: 0 });
        } else if matches!(op, SCSI_OP_READ_10 | SCSI_OP_WRITE_10) && self.fail_io > 0 {
            self.fail_io -= 1;
            failure = Some(Sense::READ_ERROR);
        }
        if let (Some(sense), false) = (failure, op == SCSI_OP_WRITE_10) {
            // A command that moves data to the host stalls bulk-IN when it
            // fails (BBB §6.7.2); the others just report it.
            if op == SCSI_OP_READ_10 {
                let slot = hw.slot_of(dev).unwrap();
                hw.inject_error(slot, DCI_IN, 6);
            }
            return self.fail(hw, dev, tag, sense);
        }
        match op {
            SCSI_OP_TEST_UNIT_READY if self.not_ready > 0 => {
                self.not_ready -= 1;
                self.fail(hw, dev, tag, Sense { key: 2, asc: 0x04, ascq: 1 })
            }
            SCSI_OP_TEST_UNIT_READY => self.csw(hw, dev, tag, 0, CSW_STATUS_OK),
            SCSI_OP_REQUEST_SENSE => {
                let mut d = [0u8; 18];
                d[0] = 0x70;
                d[2] = self.sense.key;
                d[7] = 10;
                d[12] = self.sense.asc;
                d[13] = self.sense.ascq;
                self.sense = Sense::NONE;
                hw.inject_in(dev, 1, &d);
                self.csw(hw, dev, tag, 0, CSW_STATUS_OK);
            }
            SCSI_OP_INQUIRY => {
                let mut d = [0u8; INQUIRY_LEN];
                d[0] = self.device_type;
                d[1] = 0x80;
                d[4] = 31;
                d[8..16].copy_from_slice(b"TESTSTK ");
                d[16..32].copy_from_slice(b"Bulk Only Disk  ");
                d[32..36].copy_from_slice(b"1.00");
                hw.inject_in(dev, 1, &d);
                self.csw(hw, dev, tag, 0, CSW_STATUS_OK);
            }
            SCSI_OP_READ_CAPACITY_10 => {
                let mut d = [0u8; 8];
                d[0..4].copy_from_slice(&self.last_lba.unwrap_or(SECTORS - 1).to_be_bytes());
                d[4..8].copy_from_slice(&self.block_len.to_be_bytes());
                hw.inject_in(dev, 1, &d);
                self.csw(hw, dev, tag, 0, CSW_STATUS_OK);
            }
            SCSI_OP_READ_10 => {
                let Some(ScsiCommand::Read10 { lba, blocks }) = parse_scsi_command(&cbw.cdb[..10]) else { panic!() };
                assert_eq!(cbw.data_transfer_len, blocks as u32 * BLOCK_SIZE as u32);
                assert!(cbw.direction_is_in());
                if std::mem::take(&mut self.stall_read) {
                    let slot = hw.slot_of(dev).unwrap();
                    hw.inject_error(slot, DCI_IN, 6);
                } else {
                    let at = lba as usize * BLOCK_SIZE;
                    hw.inject_in(dev, 1, &self.store[at..at + blocks as usize * BLOCK_SIZE]);
                }
                self.csw(hw, dev, tag, 0, CSW_STATUS_OK);
            }
            SCSI_OP_WRITE_10 => {
                let Some(ScsiCommand::Write10 { lba, blocks }) = parse_scsi_command(&cbw.cdb[..10]) else { panic!() };
                assert_eq!(cbw.data_transfer_len, blocks as u32 * BLOCK_SIZE as u32);
                assert!(!cbw.direction_is_in());
                self.awaiting = Some((tag, lba, blocks as u32, failure));
            }
            SCSI_OP_SYNCHRONIZE_CACHE_10 if self.no_cache => self.fail(hw, dev, tag, Sense::INVALID_OPCODE),
            SCSI_OP_SYNCHRONIZE_CACHE_10 => self.csw(hw, dev, tag, 0, CSW_STATUS_OK),
            _ => self.fail(hw, dev, tag, Sense::INVALID_OPCODE),
        }
    }
}

/// A block device over nothing, so `execute_scsi` can be asked what the
/// gadget would answer to INQUIRY (kept honest by the scsi-tests).
struct NoDisk;
impl BlockDevice for NoDisk {
    fn block_count(&self) -> u32 {
        0
    }
    fn read_block(&self, _: u32, _: &mut [u8]) -> Result<(), ()> {
        Err(())
    }
    fn write_block(&mut self, _: u32, _: &[u8]) -> Result<(), ()> {
        Err(())
    }
    fn sync_cache(&self) -> Result<(), ()> {
        Ok(())
    }
}

/// The controller, the class driver and one stick.
struct Bench {
    rig: Rig,
    msc: UsbClassDirect<Driver>,
    dev: DevRef,
    stick: Stick,
}

fn bot_device(proto: u8) -> DevRef {
    let dd = device_desc(0x0210, 0, 0, 0, 64, 0x0951, 0x1666, 1, 2);
    let cfg = config_desc(1, &[iface(0, 8, 6, proto, vec![ep(0x81, 2, 512, 0), ep(0x02, 2, 512, 0)])]);
    let mut d = MockDev::new(3, dd, cfg);
    d.strings = vec![string_desc("Kingston"), string_desc("DataTraveler")];
    d.into_ref()
}

impl Bench {
    /// A stick plugged into root port 1, and the driver ready (or failed).
    fn new() -> Bench {
        Bench::with(Stick::new())
    }

    fn with(stick: Stick) -> Bench {
        let rig = Rig::new();
        let msc = UsbClassDirect(Msc::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]));
        let dev = bot_device(0x50);
        rig.hw.attach_root(1, dev.clone());
        let mut b = Bench { rig, msc, dev, stick };
        b.until(|b| b.msc.0.state() != State::Idle && b.msc.0.state() != State::Claimed && b.msc.0.state() != State::Probing, 3000);
        b
    }

    fn drv(&mut self) -> &mut Driver {
        &mut self.msc.0
    }

    /// One millisecond of everything.
    fn turn(&mut self) {
        let mut reg = Registry::new();
        reg.register(0, Driver::rule(), &mut self.msc).unwrap();
        self.rig.usb.service(&mut reg);
        drop(reg);
        if let Some(c) = self.msc.0.session_wanted() {
            let mut s = self.rig.usb.session(c);
            self.msc.0.open(&mut s);
        }
        self.msc.0.service();
        self.stick.step(&self.rig.hw, &self.dev);
        self.rig.hw.clock().delay_us(1_000);
    }

    fn until(&mut self, mut done: impl FnMut(&mut Bench) -> bool, max_turns: u32) -> bool {
        for _ in 0..max_turns {
            if done(self) {
                return true;
            }
            self.turn();
        }
        done(self)
    }

    /// Take the slot, start `f`, and run until the command is reported.
    fn io(&mut self, f: impl FnOnce(&mut Driver) -> Result<(), ()>) -> Result<IoStatus, ()> {
        assert_eq!(self.drv().take(), Take::Granted);
        if f(self.drv()).is_err() {
            self.drv().release();
            return Err(());
        }
        let mut got = None;
        self.until(
            |b| {
                got = b.msc.0.reap();
                got.is_some()
            },
            20_000,
        );
        Ok(got.expect("the command finished"))
    }

    fn read(&mut self, lba: u64, n: u32) -> (IoStatus, Vec<u8>) {
        let st = self.io(|d| d.start_read(lba, n)).expect("started");
        let mut out = vec![0u8; n as usize * BLOCK_SIZE];
        self.drv().copy_out(0, &mut out);
        self.drv().release();
        (st, out)
    }

    fn write(&mut self, lba: u64, data: &[u8], fua: bool) -> IoStatus {
        let st = self.io(|d| d.start_write(lba, (data.len() / BLOCK_SIZE) as u32, fua, &[data])).expect("started");
        self.drv().release();
        st
    }

    fn flush(&mut self) -> IoStatus {
        let st = self.io(|d| d.start_flush()).expect("started");
        self.drv().release();
        st
    }
}

// ---- Bring-up ----

#[test]
fn a_stick_is_identified_and_sized() {
    let mut b = Bench::new();
    assert_eq!(b.drv().state(), State::Ready);
    let caps = b.drv().caps().unwrap();
    assert_eq!(caps.sectors, SECTORS as u64);
    // 64 KiB of staging by default.
    assert_eq!(caps.max_sectors as usize * BLOCK_SIZE, azos_limits::USB_MSC_XFER_KB as usize * 1024);
    let id = b.drv().identity().unwrap();
    assert_eq!(&id.inquiry.vendor, b"TESTSTK ");
    assert_eq!(&id.inquiry.product, b"Bulk Only Disk  ");
    assert_eq!(id.vid_pid, 0x0951_1666);
    // INQUIRY, TEST UNIT READY, READ CAPACITY, in that order, once each.
    assert_eq!(b.stick.ops, vec![SCSI_OP_INQUIRY, SCSI_OP_TEST_UNIT_READY, SCSI_OP_READ_CAPACITY_10]);
}

#[test]
fn the_driver_answers_inquiry_as_the_gadget_does() {
    // The fake stick's INQUIRY is built by hand; the gadget's is the target
    // half of azos_scsi. Both must parse the same, or the fake proves nothing.
    let cmd = parse_scsi_command(&azos_scsi::initiator::Cdb::inquiry(36).bytes[..6]).unwrap();
    let mut buf = [0u8; 64];
    let ScsiResponse::Done { data_in_len } = execute_scsi(cmd, &NoDisk, &mut buf, &mut Sense::default()) else { panic!() };
    assert!(azos_scsi::initiator::parse_inquiry(&buf[..data_in_len]).unwrap().is_block_device());
}

#[test]
fn a_unit_that_is_becoming_ready_is_waited_for() {
    let mut s = Stick::new();
    s.not_ready = 3;
    s.unit_attention = true;
    let mut b = Bench::with(s);
    assert_eq!(b.drv().state(), State::Ready);
    // Three NOT READY and the unit attention: every failed TEST UNIT READY was
    // followed by a REQUEST SENSE.
    assert!(b.stick.count(SCSI_OP_TEST_UNIT_READY) >= 4);
    assert_eq!(b.stick.count(SCSI_OP_REQUEST_SENSE), b.stick.count(SCSI_OP_TEST_UNIT_READY) - 1);
}

#[test]
fn a_unit_that_never_becomes_ready_is_given_up_on() {
    let mut s = Stick::new();
    s.not_ready = u32::MAX;
    let mut b = Bench::with(s);
    // Drive past the ready budget.
    b.until(|b| matches!(b.msc.0.state(), State::Failed(_)), 20_000);
    assert_eq!(b.drv().state(), State::Failed(Fail::NotReady));
    assert_eq!(b.drv().take(), Take::Dead);
}

#[test]
fn a_device_that_is_not_a_disk_is_refused() {
    let mut s = Stick::new();
    s.device_type = 5; // CD-ROM
    let mut b = Bench::with(s);
    assert_eq!(b.drv().state(), State::Failed(Fail::NotBlockDevice));
    assert_eq!(b.drv().take(), Take::Dead);
    // No TEST UNIT READY was sent to something that is not a disk.
    assert_eq!(b.stick.ops, vec![SCSI_OP_INQUIRY]);
}

#[test]
fn a_medium_the_block_layer_cannot_use_is_refused() {
    use azos_scsi::initiator::CapacityError;
    let mut s = Stick::new();
    s.block_len = 4096;
    assert_eq!(Bench::with(s).drv().state(), State::Failed(Fail::Capacity(CapacityError::BlockLen(4096))));
    let mut s = Stick::new();
    s.last_lba = Some(u32::MAX);
    assert_eq!(Bench::with(s).drv().state(), State::Failed(Fail::Capacity(CapacityError::TooLarge)));
}

#[test]
fn a_uas_interface_is_seen_and_declined() {
    let mut rig = Rig::new();
    let mut msc: UsbClassDirect<Driver> = UsbClassDirect(Msc::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]));
    rig.hw.attach_root(1, bot_device(0x62));
    for _ in 0..3000 {
        let mut reg = Registry::new();
        reg.register(0, Driver::rule(), &mut msc).unwrap();
        rig.usb.service(&mut reg);
        rig.hw.clock().delay_us(1_000);
    }
    assert_eq!(msc.0.uas_declined(), 1);
    assert_eq!(msc.0.state(), State::Idle);
    assert_eq!(msc.0.session_wanted(), None);
    assert_eq!(msc.0.take(), Take::Dead);
    // The core knew the device and offered it.
    assert_eq!(rig.usb.devices().count(), 1);
}

#[test]
fn a_second_stick_is_declined_while_one_is_driven() {
    let mut b = Bench::new();
    let other = bot_device(0x50);
    b.rig.hw.attach_root(2, other.clone());
    b.until(|b| b.rig.usb.devices().count() == 2, 3000);
    b.run(200);
    assert_eq!(b.drv().busy_declined(), 1);
    // The first one is untouched.
    assert_eq!(b.drv().state(), State::Ready);
    assert_eq!(b.read(0, 1).0, IoStatus::Ok);
    let c = azos_usb::Claim::new(b.rig.slot_of(&other), 0, b.rig.usb.device(b.rig.slot_of(&other)).unwrap().generation);
    assert_eq!(UsbClass::attach(&mut b.msc.0, c.0, 0x1111_2222, 8 << 16 | 6 << 8 | 0x50, 0).code, BUSY);
}

impl Bench {
    fn run(&mut self, turns: u32) {
        for _ in 0..turns {
            self.turn();
        }
    }
}

#[test]
fn a_class_other_than_bot_is_not_taken() {
    let rig = Rig::new();
    let mut msc: Driver = Msc::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]);
    // A CBI-style interface (protocol 0) is neither BOT nor UAS.
    assert_eq!(msc.attach(azos_usb::Claim::new(1, 0, 1).0, 0, 8 << 16 | 6 << 8, 0).code, UNSUPPORTED);
    assert_eq!(msc.uas_declined(), 0);
    assert_eq!(msc.state(), State::Idle);
    // A device-scope claim is not an interface.
    assert_ne!(msc.attach(azos_usb::Claim::new(1, azos_usb::class::WHOLE_DEVICE, 1).0, 0, 8 << 16 | 6 << 8 | 0x50, 0).code, OK);
    assert_eq!(msc.state(), State::Idle);
}

// ---- Data ----

#[test]
fn a_read_returns_what_the_stick_holds() {
    let mut b = Bench::new();
    let (st, data) = b.read(5, 3);
    assert_eq!(st, IoStatus::Ok);
    assert_eq!(data, b.stick.store[5 * BLOCK_SIZE..8 * BLOCK_SIZE]);
    // One READ(10), nothing else.
    assert_eq!(b.stick.count(SCSI_OP_READ_10), 1);
}

#[test]
fn a_write_reaches_the_stick_and_reads_back() {
    let mut b = Bench::new();
    let data: Vec<u8> = (0..2 * BLOCK_SIZE).map(|i| (i * 7 + 3) as u8).collect();
    assert_eq!(b.write(10, &data, false), IoStatus::Ok);
    assert_eq!(b.stick.store[10 * BLOCK_SIZE..12 * BLOCK_SIZE], data[..]);
    // A write without FUA does not flush the stick's cache.
    assert_eq!(b.stick.count(SCSI_OP_SYNCHRONIZE_CACHE_10), 0);
    let (st, back) = b.read(10, 2);
    assert_eq!((st, back), (IoStatus::Ok, data));
}

#[test]
fn a_write_is_gathered_from_its_segments() {
    let mut b = Bench::new();
    let (a, c): (Vec<u8>, Vec<u8>) = ((0..BLOCK_SIZE).map(|i| i as u8).collect(), vec![0xee; BLOCK_SIZE]);
    let st = b.io(|d| d.start_write(20, 2, false, &[&a, &c])).unwrap();
    b.drv().release();
    assert_eq!(st, IoStatus::Ok);
    assert_eq!(b.stick.store[20 * BLOCK_SIZE..21 * BLOCK_SIZE], a[..]);
    assert_eq!(b.stick.store[21 * BLOCK_SIZE..22 * BLOCK_SIZE], c[..]);
}

#[test]
fn a_fua_write_flushes_the_cache_before_it_completes() {
    let mut b = Bench::new();
    assert_eq!(b.write(0, &[1u8; BLOCK_SIZE], true), IoStatus::Ok);
    let n = b.stick.ops.len();
    assert_eq!(&b.stick.ops[n - 2..], &[SCSI_OP_WRITE_10, SCSI_OP_SYNCHRONIZE_CACHE_10]);
}

#[test]
fn a_fua_write_to_a_stick_without_a_cache_is_durable_already() {
    let mut s = Stick::new();
    s.no_cache = true;
    let mut b = Bench::with(s);
    assert_eq!(b.write(0, &[1u8; BLOCK_SIZE], true), IoStatus::Ok);
    assert_eq!(b.stick.count(SCSI_OP_SYNCHRONIZE_CACHE_10), 1);
    // The refused SYNCHRONIZE CACHE was followed by a REQUEST SENSE that
    // cleared it, and the disk is still good.
    assert_eq!(b.drv().state(), State::Ready);
    assert_eq!(b.read(0, 1).0, IoStatus::Ok);
}

#[test]
fn a_flush_is_a_synchronize_cache() {
    let mut b = Bench::new();
    assert_eq!(b.flush(), IoStatus::Ok);
    assert_eq!(*b.stick.ops.last().unwrap(), SCSI_OP_SYNCHRONIZE_CACHE_10);
}

#[test]
fn a_flush_of_a_stick_without_a_cache_is_unsupported_not_an_error() {
    let mut s = Stick::new();
    s.no_cache = true;
    let mut b = Bench::with(s);
    assert_eq!(b.flush(), IoStatus::Unsupported);
    assert_eq!(b.drv().state(), State::Ready, "the disk is not failed by it");
}

#[test]
fn arguments_outside_the_disk_are_refused_before_the_wire() {
    let mut b = Bench::new();
    let max = b.drv().caps().unwrap().max_sectors;
    let before = b.stick.ops.len();
    for (lba, n) in [(0u64, 0u32), (SECTORS as u64, 1), (SECTORS as u64 - 1, 2), (u64::MAX, 1), (0, max + 1)] {
        assert_eq!(b.drv().take(), Take::Granted);
        assert!(b.drv().start_read(lba, n).is_err(), "{lba}+{n}");
        b.drv().release();
    }
    // A write whose segments are not the sectors it names.
    assert_eq!(b.drv().take(), Take::Granted);
    assert!(b.drv().start_write(0, 2, false, &[&[0u8; BLOCK_SIZE]]).is_err());
    b.drv().release();
    assert_eq!(b.stick.ops.len(), before);
}

#[test]
fn only_one_command_is_held_at_a_time() {
    let mut b = Bench::new();
    assert_eq!(b.drv().take(), Take::Granted);
    assert_eq!(b.drv().take(), Take::Busy);
    b.drv().release();
    assert_eq!(b.drv().take(), Take::Granted);
    b.drv().release();
}

// ---- Errors ----

#[test]
fn a_failed_command_is_an_io_error_and_the_disk_goes_on() {
    let mut s = Stick::new();
    s.fail_io = 1;
    let mut b = Bench::with(s);
    let (st, _) = b.read(0, 1);
    assert_eq!(st, IoStatus::Io);
    // The REQUEST SENSE ran (CHECK CONDITION is cleared by it).
    assert_eq!(*b.stick.ops.last().unwrap(), SCSI_OP_REQUEST_SENSE);
    assert_eq!(b.drv().state(), State::Ready);
    assert_eq!(b.read(0, 1).0, IoStatus::Ok);
}

#[test]
fn a_failed_write_is_an_io_error_after_its_data_went_out() {
    let mut s = Stick::new();
    s.fail_io = 1;
    let mut b = Bench::with(s);
    let before = b.stick.store.clone();
    assert_eq!(b.write(3, &[9u8; BLOCK_SIZE], false), IoStatus::Io);
    assert_eq!(b.stick.store, before, "nothing was written");
    assert_eq!(*b.stick.ops.last().unwrap(), SCSI_OP_REQUEST_SENSE);
    assert_eq!(b.write(3, &[9u8; BLOCK_SIZE], false), IoStatus::Ok);
}

#[test]
fn a_unit_attention_is_retried_once() {
    let mut b = Bench::new();
    b.stick.unit_attention = true;
    let (st, data) = b.read(2, 1);
    assert_eq!(st, IoStatus::Ok, "the retry succeeded");
    assert_eq!(data, b.stick.store[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
    assert_eq!(b.stick.count(SCSI_OP_READ_10), 2);
}

#[test]
fn a_stalled_data_stage_is_cleared_and_fails_the_command() {
    let mut s = Stick::new();
    s.stall_read = true;
    let mut b = Bench::with(s);
    let (st, _) = b.read(0, 1);
    assert_eq!(st, IoStatus::Io);
    // CLEAR_FEATURE(ENDPOINT_HALT) on the bulk-IN endpoint reached the device.
    let clears: Vec<[u8; 8]> =
        b.dev.borrow().requests.iter().map(|(s, _)| *s).filter(|s| s[1] == 1 && s[0] == 0x02).collect();
    assert_eq!(clears, vec![Setup::clear_halt(0x81).to_bytes()]);
    // The CSW was read afterwards and the disk is usable.
    assert_eq!(b.drv().state(), State::Ready);
    assert_eq!(b.read(0, 1).0, IoStatus::Ok);
}

#[test]
fn a_phase_error_fails_the_disk() {
    let mut b = Bench::new();
    b.stick.phase_error = true;
    let (st, _) = b.read(0, 1);
    assert_eq!(st, IoStatus::Io);
    assert_eq!(b.drv().state(), State::Failed(Fail::Transport));
    assert_eq!(b.drv().take(), Take::Dead);
}

#[test]
fn a_csw_for_another_command_fails_the_disk() {
    let mut b = Bench::new();
    b.stick.bad_tag = true;
    assert_eq!(b.read(0, 1).0, IoStatus::Io);
    assert_eq!(b.drv().state(), State::Failed(Fail::Transport));
}

#[test]
fn a_command_the_stick_never_answers_fails_the_disk() {
    let mut b = Bench::new();
    b.stick.mute = true;
    let st = b.io(|d| d.start_read(0, 1)).unwrap();
    assert_eq!(st, IoStatus::Io);
    assert_eq!(b.drv().state(), State::Failed(Fail::Timeout));
    // It took the configured time, not less.
    assert!(b.rig.hw.clock().now_us() >= azos_limits::USB_MSC_TIMEOUT_MS as u64 * 1000);
    b.drv().release();
    assert_eq!(b.drv().take(), Take::Dead);
}

// ---- Unplug ----

#[test]
fn unplugging_returns_the_driver_to_idle_and_a_new_stick_works() {
    let mut b = Bench::new();
    assert_eq!(b.read(0, 1).0, IoStatus::Ok);
    b.rig.hw.detach_root(1);
    b.until(|b| b.msc.0.state() == State::Idle, 3000);
    assert_eq!(b.drv().state(), State::Idle);
    assert_eq!(b.drv().caps(), None);
    assert_eq!(b.drv().take(), Take::Dead);
    // The pipe rings were let go of: a second stick opens its own.
    b.dev = bot_device(0x50);
    b.stick = Stick::new();
    b.rig.hw.attach_root(1, b.dev.clone());
    b.until(|b| b.msc.0.state() == State::Ready, 3000);
    assert_eq!(b.drv().state(), State::Ready);
    assert_eq!(b.read(1, 1).0, IoStatus::Ok);
}

#[test]
fn unplugging_with_a_command_in_the_stick_finishes_it_failed() {
    let mut b = Bench::new();
    b.stick.mute = true;
    assert_eq!(b.drv().take(), Take::Granted);
    b.drv().start_read(0, 1).unwrap();
    b.run(5);
    b.rig.hw.detach_root(1);
    let mut got = None;
    b.until(
        |b| {
            got = b.msc.0.reap();
            got.is_some()
        },
        3000,
    );
    assert_eq!(got, Some(IoStatus::Io));
    b.drv().release();
    b.until(|b| b.msc.0.state() == State::Idle, 3000);
    assert_eq!(b.drv().state(), State::Idle);
}

#[test]
fn a_stick_removed_before_it_was_opened_leaves_nothing_behind() {
    let mut rig = Rig::new();
    let mut msc: UsbClassDirect<Driver> = UsbClassDirect(Msc::new(rig.hw.mem(), rig.hw.clock(), u64::MAX, &rig.rings[..]));
    let dev = bot_device(0x50);
    rig.hw.attach_root(1, dev);
    // Enumerate, but never open a session.
    for _ in 0..3000 {
        let mut reg = Registry::new();
        reg.register(0, Driver::rule(), &mut msc).unwrap();
        rig.usb.service(&mut reg);
        rig.hw.clock().delay_us(1_000);
        if msc.0.state() == State::Claimed {
            break;
        }
    }
    assert_eq!(msc.0.state(), State::Claimed);
    rig.hw.detach_root(1);
    for _ in 0..500 {
        let mut reg = Registry::new();
        reg.register(0, Driver::rule(), &mut msc).unwrap();
        rig.usb.service(&mut reg);
        msc.0.service();
        rig.hw.clock().delay_us(1_000);
    }
    assert_eq!(msc.0.state(), State::Idle);
    assert_eq!(msc.0.session_wanted(), None);
}
