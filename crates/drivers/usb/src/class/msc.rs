// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The mass-storage class driver: a USB stick (or any SCSI-transparent
//! Bulk-Only disk) as a block device.
//!
//! It is a class driver like the lister ([`crate::listing`]): it serves
//! [`UsbClass`], claims one interface of class 8 / subclass 6 / protocol 0x50,
//! and moves data only through the pipes the core opened for that claim. The
//! SCSI commands and the wrappers around them are `azos_scsi` (the same crate
//! the gadget serves them from), so the two ends cannot drift apart.
//!
//! # Where it sits
//!
//! This file is the protocol and nothing else: it holds no lock, reaches no
//! hardware, and is shaped like the block layer's `HwQueue` (`take`, `start_*`,
//! `reap`, `copy_out`, `release`) without naming it, as `azos_nvme` is the wire
//! half of `block/src/nvme.rs`. The block-layer adapter wraps one [`Msc`] in a
//! lock and forwards `HwQueue` to it; the `usb` task calls
//! [`Msc::session_wanted`] / [`Msc::open`] after each turn of the core, and
//! [`Msc::service`] advances whatever is in flight.
//!
//! # One command at a time
//!
//! Bulk-Only Transport has no tags: a command is a CBW on bulk-OUT, an
//! optional data stage, and a CSW on bulk-IN, and the next command may not
//! start before the CSW (UAS exists to lift this). The depth is therefore 1,
//! stated by [`Msc::take`] answering `Busy` while a command is held. The
//! block layer's merging is what makes that cost little: a run of adjacent
//! requests is one READ(10) of up to [`Msc::caps`]`.max_sectors`.
//!
//! One transfer is outstanding per pipe at a time; each stage of a command is
//! submitted when the previous one completes, so a read takes three turns of
//! the core (CBW, data, CSW), a flush two.
//!
//! # Errors (BBB §6.6, §6.7)
//!
//! - A data stage that STALLs: the halt is cleared (CLEAR_FEATURE on the
//!   control pipe) and the CSW is read; the command then fails.
//! - A CSW that STALLs: cleared and read once more; a second stall fails.
//! - CSW status 1 (command failed): REQUEST SENSE, then the command fails; a
//!   UNIT ATTENTION is retried once (a reset or a medium change is reported to
//!   the first command after it, then cleared).
//! - Anything else, an invalid or unmatched CSW, a phase error (status 2), a
//!   transfer that fails otherwise, or a command that outlives
//!   `USB_MSC_TIMEOUT_MS`: **Reset Recovery** (§5.3.4). The bulk pipes are
//!   closed and opened again through a session ([`Msc::session_wanted`] asks
//!   for one, [`Msc::open`] does it): that recalls a transfer the device never
//!   finished (the controller drops the endpoint, so nothing more is written
//!   into the staging buffer) and starts the host's side of both endpoints
//!   over. Then, on the control pipe, Bulk-Only Mass Storage Reset, and
//!   CLEAR_FEATURE(ENDPOINT_HALT) on bulk-IN and on bulk-OUT; the command is
//!   then started again from its CBW. One recovery per command: a command
//!   that needs a second, or a recovery that fails (a control stage that does
//!   not complete, or completes with an error), **fails** the disk: every
//!   command it holds finishes `Io`, [`Msc::take`] answers `Dead`, and the
//!   staging memory stays allocated (a control transfer it could not recall
//!   may still be in the controller) until the device is unplugged. While the
//!   unit is being identified there is no recovery: a stick that cannot
//!   answer INQUIRY or READ CAPACITY is failed at once.
//!
//! # Flush, FUA
//!
//! `FUA` is native in the block layer's contract, but a stick's cache is
//! flushed with SYNCHRONIZE CACHE(10), not with a bit on WRITE(10) that many
//! bridges ignore: a write with FUA is a WRITE(10) followed by a
//! SYNCHRONIZE CACHE(10) under the same command. A device that answers INVALID
//! COMMAND OPERATION CODE to it has no cache to flush: that is success after a
//! FUA write and [`IoStatus::Unsupported`] for a flush of its own.
//!
//! # Memory
//!
//! The data stage uses one staging buffer of `USB_MSC_XFER_KB` (plus a page
//! for the wrappers), allocated through [`Memory`] when the device is opened
//! and given back at unplug. A write is copied into it by [`Msc::start_write`],
//! a read out of it by [`Msc::copy_out`]; the cache maintenance of a
//! non-coherent master is this driver's ([`Memory::to_device`] before a
//! stage the device reads, [`Memory::from_device`] after one it wrote).
//!
//! # Limits
//!
//! One disk at a time (a second stick is declined `BUSY`), LUN 0 only,
//! 512-byte blocks, READ CAPACITY(10) (media up to 2 TiB), no UAS (an
//! interface of protocol 0x62 is declined and counted in
//! [`Msc::uas_declined`]).

use azos_devif::outcome::{BAD_ARGUMENT, BUSY, OK, UNSUPPORTED};
use azos_devif::Out;
use azos_scsi::bbb::{
    Csw, CSW_STATUS_FAIL, CSW_STATUS_OK, CSW_TOTAL_LEN, CBW_TOTAL_LEN, INTERFACE_CLASS, INTERFACE_PROTOCOL_BBB,
    INTERFACE_PROTOCOL_UAS, INTERFACE_SUBCLASS_SCSI, REQ_BULK_ONLY_RESET,
};
use azos_scsi::initiator::{
    parse_inquiry, parse_read_capacity_10, parse_sense, CapacityError, Cdb, Inquiry, INQUIRY_LEN,
    READ_CAPACITY_10_LEN, SENSE_LEN,
};
use azos_scsi::target::{Sense, BLOCK_SIZE};

use crate::class::{Claim, Match, Scope, UsbClass, UsbDevice};
use crate::hw::{Clock, DmaBuf, Memory, PAGE};
use crate::usbcore::desc::{Setup, RT_RECIP_INTERFACE, RT_TYPE_CLASS};
use crate::usbcore::pipe::{Completion, Dir, PipeEnd, PipeRings, Status, Transfer};
use azos_rings::Push;

/// Bytes of the data staging buffer (Kconfig `USB_MSC_XFER_KB`).
const STAGE_BYTES: usize = azos_limits::USB_MSC_XFER_KB as usize * 1024;
/// How long one command may take, and how long a unit may take to become
/// ready, in microseconds (Kconfig `USB_MSC_TIMEOUT_MS`).
const TIMEOUT_US: u64 = azos_limits::USB_MSC_TIMEOUT_MS as u64 * 1000;
/// Gap between two TEST UNIT READY while a unit is becoming ready.
const READY_RETRY_US: u64 = 100_000;

const _: () = assert!(STAGE_BYTES % PAGE == 0 && STAGE_BYTES >= PAGE, "USB_MSC_XFER_KB is a multiple of 4");

// The buffer: wrappers and small replies in the first page, data after it.
const CBW_OFF: usize = 0;
const CSW_OFF: usize = 64;
const SMALL_OFF: usize = 128;
const SMALL_LEN: usize = 64;
const DATA_OFF: usize = PAGE;
const _: () = assert!(CBW_TOTAL_LEN <= CSW_OFF - CBW_OFF && CSW_TOTAL_LEN <= SMALL_OFF - CSW_OFF);
const _: () = assert!(INQUIRY_LEN <= SMALL_LEN && SENSE_LEN <= SMALL_LEN && READ_CAPACITY_10_LEN <= SMALL_LEN);

/// What the block layer is told about a finished command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoStatus {
    Ok,
    /// The device has no such command (a flush with no cache to flush).
    Unsupported,
    /// The command failed, or the disk did.
    Io,
}

/// The answer of [`Msc::take`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Take {
    /// The command slot is the caller's: `start_*` it or `release` it.
    Granted,
    /// A command is held (or the disk is still coming up).
    Busy,
    /// No disk, or the disk failed: nothing will ever be started.
    Dead,
}

/// What the disk is, once it is ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub sectors: u64,
    /// Sectors one command carries at most.
    pub max_sectors: u32,
}

/// Why a disk is failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// The device is not a block device (INQUIRY said a CD-ROM, a tape ...).
    NotBlockDevice,
    /// The interface has no bulk IN and bulk OUT endpoint.
    NoEndpoints,
    /// The core refused a pipe.
    Pipe,
    /// No DMA memory for the staging buffer.
    NoMemory,
    /// The unit did not become ready in time, or said so for good.
    NotReady,
    /// READ CAPACITY gave a medium this driver does not drive.
    Capacity(CapacityError),
    /// A stage failed in a way only Reset Recovery repairs: a transfer
    /// error, an invalid or unmatched CSW, a phase error.
    Transport,
    /// A command did not finish in `USB_MSC_TIMEOUT_MS`.
    Timeout,
    /// The device was unplugged.
    Gone,
}

/// Where the driver is in the life of one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No device.
    Idle,
    /// A device was claimed; the `usb` task opens its pipes next.
    Claimed,
    /// Pipes open, identifying the unit.
    Probing,
    Ready,
    Failed(Fail),
}

/// The unit's identity, from INQUIRY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub inquiry: Inquiry,
    pub vid_pid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Cbw,
    Data,
    Csw,
    /// CLEAR_FEATURE(ENDPOINT_HALT) on the data endpoint, then the CSW.
    ClearData,
    /// CLEAR_FEATURE(ENDPOINT_HALT) on bulk-IN, then the CSW again.
    ClearCsw,
    /// Reset Recovery on the control pipe: Bulk-Only Mass Storage Reset,
    /// then CLEAR_FEATURE(ENDPOINT_HALT) on bulk-IN, then on bulk-OUT.
    Reset,
    ResetIn,
    ResetOut,
}

impl Phase {
    const fn code(self) -> u32 {
        match self {
            Phase::Cbw => 1,
            Phase::Data => 2,
            Phase::Csw => 3,
            Phase::ClearData => 4,
            Phase::ClearCsw => 5,
            Phase::Reset => 6,
            Phase::ResetIn => 7,
            Phase::ResetOut => 8,
        }
    }
}

/// What a running command is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Inquiry,
    Ready,
    SenseAfterReady,
    Capacity,
    SenseAfterCapacity,
    /// The command the block layer started.
    Io,
    /// REQUEST SENSE after a failed [`Step::Io`].
    SenseAfterIo,
    /// The SYNCHRONIZE CACHE(10) of a FUA write.
    SyncAfterWrite,
    /// Reset Recovery's control requests ([`Phase::Reset`] ...).
    Recover,
}

/// The data stage of a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Data {
    None,
    In { off: usize, len: u32 },
    Out { off: usize, len: u32 },
}

impl Data {
    fn len(self) -> u32 {
        match self {
            Data::None => 0,
            Data::In { len, .. } | Data::Out { len, .. } => len,
        }
    }
}

/// One command on the wire.
#[derive(Clone, Copy)]
struct Run {
    step: Step,
    cdb: Cdb,
    data: Data,
    /// `dCBWTag` of the command (and of its CSW).
    tag: u32,
    phase: Phase,
    deadline_us: u64,
    /// Bytes the data stage moved.
    actual: u32,
    /// The data stage stalled.
    stalled: bool,
    /// The CSW was already re-read once after a stall.
    csw_retried: bool,
}

/// What the block layer asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoKind {
    Read,
    Write { fua: bool },
    Flush,
}

#[derive(Clone, Copy, Debug)]
struct Io {
    kind: IoKind,
    lba: u32,
    sectors: u16,
    /// A UNIT ATTENTION was already retried.
    retried: bool,
    /// The SYNCHRONIZE CACHE(10) of a FUA write is the command on the wire.
    syncing: bool,
    /// The command went through a Reset Recovery already.
    recovered: bool,
}

/// The one command slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Free,
    /// Granted by [`Msc::take`], not started.
    Taken,
    /// Started; in the device.
    Running,
    Finished(IoStatus),
    /// [`Msc::reap`] reported it; the caller copies the data out and releases.
    Reported,
}

/// The pipes of a claim.
struct Pipes<'q> {
    ctl: PipeEnd<'q>,
    bin: PipeEnd<'q>,
    bout: PipeEnd<'q>,
    ep_in: u8,
    ep_out: u8,
}

pub struct Msc<'q, M: Memory, C: Clock> {
    mem: M,
    clock: C,
    mask: u64,
    rings: &'q [PipeRings],
    state: State,
    claim: Option<Claim>,
    vid_pid: u32,
    /// The core told us the device is gone; clean up on the next turn.
    gone: bool,
    pipes: Option<Pipes<'q>>,
    buf: Option<DmaBuf>,
    run: Option<Run>,
    io: Option<Io>,
    slot: Slot,
    caps: Option<Caps>,
    ident: Option<Identity>,
    next_tag: u32,
    /// Absolute time the unit must be ready by, and the next TEST UNIT READY.
    ready_by_us: u64,
    next_try_us: u64,
    uas_declined: u32,
    busy_declined: u32,
    /// A transfer went into a pipe since [`Msc::take_submitted`] last asked.
    submitted: bool,
    /// Reset Recovery waits for a session to reopen the bulk pipes in, and
    /// why it started (what the disk fails with if the recovery does).
    reopen: Option<Fail>,
    /// Reset Recoveries that brought the disk back.
    recoveries: u32,
}

impl<'q, M: Memory, C: Clock> Msc<'q, M, C> {
    /// A driver with no device. `mask` is the controller's DMA mask (the
    /// staging buffer is allocated under it), `rings` the pipe rings the core
    /// indexes by pipe number.
    pub fn new(mem: M, clock: C, mask: u64, rings: &'q [PipeRings]) -> Self {
        Msc {
            mem,
            clock,
            mask,
            rings,
            state: State::Idle,
            claim: None,
            vid_pid: 0,
            gone: false,
            pipes: None,
            buf: None,
            run: None,
            io: None,
            slot: Slot::Free,
            caps: None,
            ident: None,
            next_tag: 0,
            ready_by_us: 0,
            next_try_us: 0,
            uas_declined: 0,
            busy_declined: 0,
            submitted: false,
            reopen: None,
            recoveries: 0,
        }
    }

    /// The rule to register it under: interfaces of class 8, subclass 6. The
    /// protocol is not part of the rule so that a UAS interface (0x62) is
    /// seen, counted and declined by [`UsbClass::attach`], not silently
    /// skipped.
    pub const fn rule() -> Match {
        Match {
            scope: Scope::Interface,
            vid_pid: None,
            class: Some(INTERFACE_CLASS),
            subclass: Some(INTERFACE_SUBCLASS_SCSI),
            protocol: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The identity of the unit, once INQUIRY answered.
    pub fn identity(&self) -> Option<Identity> {
        self.ident
    }

    /// Interfaces of protocol 0x62 (UAS) declined so far.
    pub fn uas_declined(&self) -> u32 {
        self.uas_declined
    }

    /// Sticks declined because a disk is already driven.
    pub fn busy_declined(&self) -> u32 {
        self.busy_declined
    }

    /// Reset Recoveries that brought the disk back.
    pub fn recoveries(&self) -> u32 {
        self.recoveries
    }

    /// Whether a transfer was put into a pipe since the last call. The core
    /// moves it to the controller on its next turn: whoever runs the core
    /// (the `usb` task, asleep for its poll period) is woken when this is
    /// true, so a command is not held up by the period.
    pub fn take_submitted(&mut self) -> bool {
        core::mem::take(&mut self.submitted)
    }

    // ---- Binding ----

    /// The claim to open a session for: set by [`UsbClass::attach`] (the
    /// pipes are to be opened) and by a Reset Recovery (the bulk pipes are to
    /// be opened again), cleared by [`Msc::open`]. The `usb` task asks after
    /// each turn of the core.
    pub fn session_wanted(&self) -> Option<Claim> {
        let wanted = self.state == State::Claimed || (self.state == State::Ready && self.reopen.is_some());
        if wanted && !self.gone { self.claim } else { None }
    }

    /// Through `dev` (the session of [`Msc::session_wanted`]): open the pipes
    /// of the claimed interface and start identifying the unit, or reopen the
    /// bulk pipes of a Reset Recovery and send its control requests.
    pub fn open(&mut self, dev: &mut dyn UsbDevice) {
        match self.state {
            State::Claimed => match self.open_pipes(dev) {
                Ok(()) => self.begin_probe(),
                Err(f) => self.fail(f),
            },
            State::Ready => {
                let Some(why) = self.reopen.take() else { return };
                match self.reopen_bulk(dev) {
                    Ok(()) => self.begin_reset(),
                    Err(_) => self.fail(why),
                }
            }
            _ => {}
        }
    }

    /// Close the bulk pipes and open them again: a transfer still in the
    /// controller is dropped with its endpoint, and both endpoints start over
    /// on the host's side (the device's are cleared by the recovery's
    /// CLEAR_FEATUREs). Each pipe is closed before its ends are let go of,
    /// and its completions drained after: a completion the close itself posts
    /// would otherwise keep the ring from ever being handed out again.
    fn reopen_bulk(&mut self, dev: &mut dyn UsbDevice) -> Result<(), Fail> {
        let Some(Pipes { ctl, mut bin, mut bout, ep_in, ep_out }) = self.pipes.take() else { return Err(Fail::Pipe) };
        for e in [&mut bin, &mut bout] {
            let _ = dev.pipe_close(e.id as u32);
            while e.cq.pop().is_some() {}
        }
        drop((bin, bout));
        match (open_one(dev, self.rings, ep_in), open_one(dev, self.rings, ep_out)) {
            (Ok(bin), Ok(bout)) => {
                self.pipes = Some(Pipes { ctl, bin, bout, ep_in, ep_out });
                Ok(())
            }
            (a, b) => {
                // Nothing is queued on what did open: give it back. The
                // control pipe goes too; the core closes it at unplug.
                for e in [a.ok(), b.ok(), Some(ctl)].into_iter().flatten() {
                    let id = e.id;
                    drop(e);
                    let _ = dev.pipe_close(id as u32);
                }
                Err(Fail::Pipe)
            }
        }
    }

    fn open_pipes(&mut self, dev: &mut dyn UsbDevice) -> Result<(), Fail> {
        let n = dev.info(4);
        if n.code != OK {
            return Err(Fail::Pipe);
        }
        let (mut ep_in, mut ep_out) = (None, None);
        for i in 0..n.value as u32 {
            let e = dev.endpoint(i);
            if e.code != OK {
                continue;
            }
            let (addr, attrs) = ((e.value & 0xff) as u8, ((e.value >> 8) & 0xff) as u8);
            if attrs & 3 != 2 {
                continue; // not bulk
            }
            let slot = if addr & 0x80 != 0 { &mut ep_in } else { &mut ep_out };
            slot.get_or_insert(addr);
        }
        let (Some(ep_in), Some(ep_out)) = (ep_in, ep_out) else { return Err(Fail::NoEndpoints) };
        let buf = self.mem.alloc_region(PAGE + STAGE_BYTES, PAGE, self.mask).ok_or(Fail::NoMemory)?;
        let mut ends: [Option<PipeEnd<'q>>; 3] = [None, None, None];
        let mut result = Ok(());
        for (end, ep) in ends.iter_mut().zip([0, ep_in, ep_out]) {
            match open_one(dev, self.rings, ep) {
                Ok(e) => *end = Some(e),
                Err(f) => {
                    result = Err(f);
                    break;
                }
            }
        }
        match (result, ends) {
            (Ok(()), [Some(ctl), Some(bin), Some(bout)]) => {
                self.buf = Some(buf);
                self.pipes = Some(Pipes { ctl, bin, bout, ep_in, ep_out });
                Ok(())
            }
            (r, ends) => {
                // Nothing was queued: give back what was taken.
                for e in ends.into_iter().flatten() {
                    let id = e.id;
                    drop(e);
                    let _ = dev.pipe_close(id as u32);
                }
                self.mem.free_region(buf);
                Err(r.err().unwrap_or(Fail::Pipe))
            }
        }
    }

    // ---- Block-layer surface ----

    /// The disk's size, once it is ready.
    pub fn caps(&self) -> Option<Caps> {
        self.caps
    }

    /// Take the command slot.
    pub fn take(&mut self) -> Take {
        match self.state {
            State::Ready => {
                if self.slot == Slot::Free {
                    self.slot = Slot::Taken;
                    Take::Granted
                } else {
                    Take::Busy
                }
            }
            State::Claimed | State::Probing => Take::Busy,
            State::Idle | State::Failed(_) => Take::Dead,
        }
    }

    /// Start a read of `sectors` sectors at `lba` on the slot [`Msc::take`]
    /// granted. `Err` when the arguments do not fit this disk or it died; the
    /// slot is then the caller's to [`Msc::release`].
    pub fn start_read(&mut self, lba: u64, sectors: u32) -> Result<(), ()> {
        self.start(IoKind::Read, lba, sectors)
    }

    /// Start a write; the sectors are the concatenation of `segs`. `fua`: the
    /// data is on the medium when the command completes.
    pub fn start_write(&mut self, lba: u64, sectors: u32, fua: bool, segs: &[&[u8]]) -> Result<(), ()> {
        let want = sectors as usize * BLOCK_SIZE;
        if segs.iter().map(|s| s.len()).sum::<usize>() != want {
            return Err(());
        }
        self.check_start(lba, sectors)?;
        let buf = self.buf.as_ref().ok_or(())?;
        let mut off = DATA_OFF;
        for s in segs {
            buf.write_bytes(off, s);
            off += s.len();
        }
        self.start(IoKind::Write { fua }, lba, sectors)
    }

    /// Start a flush of the whole medium.
    pub fn start_flush(&mut self) -> Result<(), ()> {
        self.start(IoKind::Flush, 0, 0)
    }

    fn check_start(&self, lba: u64, sectors: u32) -> Result<Caps, ()> {
        let caps = self.caps.filter(|_| self.state == State::Ready).ok_or(())?;
        if self.slot != Slot::Taken || sectors == 0 || sectors > caps.max_sectors {
            return Err(());
        }
        if lba.checked_add(sectors as u64).is_none_or(|e| e > caps.sectors) {
            return Err(());
        }
        Ok(caps)
    }

    fn start(&mut self, kind: IoKind, lba: u64, sectors: u32) -> Result<(), ()> {
        if kind != IoKind::Flush {
            self.check_start(lba, sectors)?;
        } else if self.slot != Slot::Taken || self.state != State::Ready {
            return Err(());
        }
        self.io = Some(Io { kind, lba: lba as u32, sectors: sectors as u16, retried: false, syncing: false, recovered: false });
        self.slot = Slot::Running;
        self.begin_io();
        Ok(())
    }

    /// The finished command, if there is one. Advances the machine first, so
    /// a caller that polls here needs no other call.
    pub fn reap(&mut self) -> Option<IoStatus> {
        self.service();
        match self.slot {
            Slot::Finished(s) => {
                self.slot = Slot::Reported;
                Some(s)
            }
            _ => None,
        }
    }

    /// Copy `dst.len()` bytes of a finished read, from byte `off` of its data.
    pub fn copy_out(&self, off: usize, dst: &mut [u8]) {
        let Some(buf) = self.buf.as_ref() else { return };
        if off.checked_add(dst.len()).is_some_and(|e| e <= STAGE_BYTES) {
            buf.read_bytes(DATA_OFF + off, dst);
        }
    }

    /// The slot is free again.
    pub fn release(&mut self) {
        self.slot = Slot::Free;
        self.io = None;
    }

    // ---- The machine ----

    /// Advance: take the completions the core posted, start the next stage,
    /// fail what outlived its deadline, clean up after an unplug.
    pub fn service(&mut self) {
        if self.gone {
            self.cleanup();
            return;
        }
        loop {
            let Some(c) = self.pop() else { break };
            self.complete(c);
        }
        let now = self.clock.now_us();
        match self.state {
            State::Probing => {
                if self.run.is_none() && now >= self.next_try_us {
                    // Between two TEST UNIT READY.
                    self.begin(Step::Ready, Cdb::test_unit_ready(), Data::None);
                } else if let Some(r) = self.run {
                    if now > r.deadline_us {
                        self.fail(Fail::Timeout);
                    }
                }
            }
            State::Ready => {
                if let Some(r) = self.run {
                    if now > r.deadline_us {
                        self.transport_error(Fail::Timeout);
                    }
                }
            }
            _ => {}
        }
    }

    fn pop(&mut self) -> Option<(Phase, Completion)> {
        let run = self.run?;
        let p = self.pipes.as_mut()?;
        let pipe = match run.phase {
            Phase::Cbw => &mut p.bout,
            Phase::Data => match run.data {
                Data::Out { .. } => &mut p.bout,
                _ => &mut p.bin,
            },
            Phase::Csw => &mut p.bin,
            Phase::ClearData | Phase::ClearCsw | Phase::Reset | Phase::ResetIn | Phase::ResetOut => &mut p.ctl,
        };
        pipe.cq.pop().map(|c| (run.phase, c))
    }

    fn complete(&mut self, (phase, c): (Phase, Completion)) {
        let Some(mut run) = self.run else { return };
        if c.tag != Self::wire_tag(&run, phase) {
            return self.transport_error(Fail::Transport);
        }
        let Some(buf) = self.buf.as_ref() else { return };
        match phase {
            Phase::Cbw => {
                if c.status != Status::Ok || c.actual as usize != CBW_TOTAL_LEN {
                    return self.transport_error(Fail::Transport);
                }
                run.phase = if run.data == Data::None { Phase::Csw } else { Phase::Data };
            }
            Phase::Data => {
                run.actual = c.actual;
                match c.status {
                    Status::Ok => {
                        if let Data::In { off, len } = run.data {
                            self.mem.from_device(buf.cpu().wrapping_add(off), (c.actual.min(len)) as usize);
                        }
                        run.phase = Phase::Csw;
                    }
                    Status::Stall => {
                        run.stalled = true;
                        run.phase = Phase::ClearData;
                    }
                    _ => return self.transport_error(Fail::Transport),
                }
            }
            Phase::ClearData => {
                if c.status != Status::Ok {
                    return self.transport_error(Fail::Transport);
                }
                run.phase = Phase::Csw;
            }
            Phase::Csw => match c.status {
                Status::Ok if c.actual as usize == CSW_TOTAL_LEN => {
                    self.mem.from_device(buf.cpu().wrapping_add(CSW_OFF), CSW_TOTAL_LEN);
                    let mut raw = [0u8; CSW_TOTAL_LEN];
                    buf.read_bytes(CSW_OFF, &mut raw);
                    return match Csw::parse(&raw) {
                        Some(csw) if csw.tag == run.tag => self.csw(run, csw),
                        _ => self.transport_error(Fail::Transport),
                    };
                }
                Status::Stall if !run.csw_retried => {
                    run.csw_retried = true;
                    run.phase = Phase::ClearCsw;
                }
                _ => return self.transport_error(Fail::Transport),
            },
            Phase::ClearCsw => {
                if c.status != Status::Ok {
                    return self.transport_error(Fail::Transport);
                }
                run.phase = Phase::Csw;
            }
            Phase::Reset | Phase::ResetIn | Phase::ResetOut => {
                if c.status != Status::Ok {
                    return self.transport_error(Fail::Transport);
                }
                run.phase = match phase {
                    Phase::Reset => Phase::ResetIn,
                    Phase::ResetIn => Phase::ResetOut,
                    _ => return self.recovered(),
                };
            }
        }
        self.run = Some(run);
        self.submit_phase();
    }

    /// A valid CSW for `run`.
    fn csw(&mut self, run: Run, csw: Csw) {
        self.run = None;
        match csw.status {
            CSW_STATUS_OK => {
                // A data stage that moved less than asked (or stalled) is a
                // command that did not do what was asked.
                let short = run.stalled || csw.data_residue != 0 || run.actual != run.data.len();
                self.after(run, if short { Outcome::Short } else { Outcome::Good });
            }
            CSW_STATUS_FAIL => self.after(run, Outcome::CheckCondition),
            _ => self.transport_error(Fail::Transport),
        }
    }

    fn after(&mut self, run: Run, out: Outcome) {
        let now = self.clock.now_us();
        match (run.step, out) {
            (Step::Inquiry, Outcome::Good) => {
                let mut d = [0u8; SMALL_LEN];
                self.small(&mut d);
                match parse_inquiry(&d[..INQUIRY_LEN]) {
                    Some(i) if i.is_block_device() => {
                        self.ident = Some(Identity { inquiry: i, vid_pid: self.vid_pid });
                        self.ready_by_us = now + TIMEOUT_US;
                        self.next_try_us = now;
                    }
                    Some(_) => self.fail(Fail::NotBlockDevice),
                    None => self.fail(Fail::Transport),
                }
                // The next TEST UNIT READY is started by `service`.
            }
            (Step::Inquiry, _) => self.fail(Fail::Transport),
            (Step::Ready, Outcome::Good) => self.begin(Step::Capacity, Cdb::read_capacity_10(), Data::In { off: SMALL_OFF, len: READ_CAPACITY_10_LEN as u32 }),
            (Step::Ready, _) => self.begin(Step::SenseAfterReady, Cdb::request_sense(SENSE_LEN as u8), Data::In { off: SMALL_OFF, len: SENSE_LEN as u32 }),
            (Step::SenseAfterReady, _) => {
                let s = self.sense(out);
                if now > self.ready_by_us || !s.is_some_and(|s| s.is_not_ready() || s.is_unit_attention()) {
                    return self.fail(Fail::NotReady);
                }
                // Try again in a little while.
                self.next_try_us = now + READY_RETRY_US;
            }
            (Step::Capacity, Outcome::Good) => {
                let mut d = [0u8; SMALL_LEN];
                self.small(&mut d);
                match parse_read_capacity_10(&d[..READ_CAPACITY_10_LEN]) {
                    Ok(c) => {
                        let max = ((STAGE_BYTES / BLOCK_SIZE) as u32).min(u16::MAX as u32);
                        self.caps = Some(Caps { sectors: c.sectors, max_sectors: max });
                        self.state = State::Ready;
                    }
                    Err(e) => self.fail(Fail::Capacity(e)),
                }
            }
            (Step::Capacity, _) => self.begin(Step::SenseAfterCapacity, Cdb::request_sense(SENSE_LEN as u8), Data::In { off: SMALL_OFF, len: SENSE_LEN as u32 }),
            (Step::SenseAfterCapacity, _) => {
                // A unit attention before the first READ CAPACITY is normal
                // (the TEST UNIT READY consumed it on most devices); try once
                // more through the ready loop.
                if now > self.ready_by_us || !self.sense(out).is_some_and(|s| s.is_unit_attention() || s.is_not_ready()) {
                    return self.fail(Fail::NotReady);
                }
                self.next_try_us = now + READY_RETRY_US;
            }
            (Step::Io, Outcome::Good) => self.io_next(),
            (Step::Io, Outcome::Short) => self.finish_io(IoStatus::Io),
            (Step::Io, Outcome::CheckCondition) => {
                self.begin(Step::SenseAfterIo, Cdb::request_sense(SENSE_LEN as u8), Data::In { off: SMALL_OFF, len: SENSE_LEN as u32 })
            }
            (Step::SenseAfterIo, _) => {
                let sense = self.sense(out).unwrap_or(Sense::NONE);
                let Some(io) = self.io else { return };
                if sense.is_unit_attention() && !io.retried {
                    self.io = Some(Io { retried: true, ..io });
                    return self.begin_io();
                }
                self.finish_io(match (sense.is_invalid_opcode(), io.kind, io.syncing) {
                    // No cache to flush: a flush of its own is unsupported, a
                    // FUA write was durable when its WRITE(10) completed.
                    (true, IoKind::Flush, _) => IoStatus::Unsupported,
                    (true, IoKind::Write { .. }, true) => IoStatus::Ok,
                    _ => IoStatus::Io,
                });
            }
            (Step::SyncAfterWrite, Outcome::Good) => self.finish_io(IoStatus::Ok),
            // A device with no cache answers INVALID OPCODE: its writes were
            // durable when they completed.
            (Step::SyncAfterWrite, _) => self.begin(Step::SenseAfterIo, Cdb::request_sense(SENSE_LEN as u8), Data::In { off: SMALL_OFF, len: SENSE_LEN as u32 }),
            // Its control requests complete in `complete`, not with a CSW.
            (Step::Recover, _) => {}
        }
    }

    /// The block layer's command finished a stage that went well.
    fn io_next(&mut self) {
        let Some(io) = self.io else { return };
        if let IoKind::Write { fua: true } = io.kind {
            // Not yet durable: flush the cache under the same command.
            self.io = Some(Io { syncing: true, ..io });
            return self.begin(Step::SyncAfterWrite, Cdb::synchronize_cache_10(), Data::None);
        }
        self.finish_io(IoStatus::Ok);
    }

    fn finish_io(&mut self, s: IoStatus) {
        if self.slot == Slot::Running {
            self.slot = Slot::Finished(s);
        }
    }

    fn begin_io(&mut self) {
        let Some(io) = self.io else { return };
        let bytes = io.sectors as u32 * BLOCK_SIZE as u32;
        match io.kind {
            IoKind::Read => self.begin(Step::Io, Cdb::read_10(io.lba, io.sectors), Data::In { off: DATA_OFF, len: bytes }),
            IoKind::Write { .. } => self.begin(Step::Io, Cdb::write_10(io.lba, io.sectors), Data::Out { off: DATA_OFF, len: bytes }),
            IoKind::Flush => self.begin(Step::Io, Cdb::synchronize_cache_10(), Data::None),
        }
    }

    fn begin_probe(&mut self) {
        self.state = State::Probing;
        self.begin(Step::Inquiry, Cdb::inquiry(INQUIRY_LEN as u8), Data::In { off: SMALL_OFF, len: INQUIRY_LEN as u32 });
    }

    /// Put a command on the wire: its CBW first.
    fn begin(&mut self, step: Step, cdb: Cdb, data: Data) {
        self.next_tag = self.next_tag.wrapping_add(1);
        self.run = Some(Run {
            step,
            cdb,
            data,
            tag: self.next_tag,
            phase: Phase::Cbw,
            deadline_us: self.clock.now_us() + TIMEOUT_US,
            actual: 0,
            stalled: false,
            csw_retried: false,
        });
        self.submit_phase();
    }

    /// The transport failed `f`-wise under a command of the block layer:
    /// Reset Recovery, once per command; otherwise (while identifying the
    /// unit, during a recovery, or for the second time) the disk fails.
    fn transport_error(&mut self, f: Fail) {
        // `run` is `None` when a CSW was the trouble (`csw` took it).
        let recoverable = self.state == State::Ready
            && self.run.is_none_or(|r| r.step != Step::Recover)
            && self.io.is_some_and(|io| !io.recovered);
        if !recoverable {
            return self.fail(f);
        }
        self.run = None;
        if let Some(io) = self.io {
            self.io = Some(Io { recovered: true, retried: false, syncing: false, ..io });
        }
        // The bulk pipes are reopened in the next session (`open`).
        self.reopen = Some(f);
    }

    /// The bulk pipes are new: the recovery's control requests.
    fn begin_reset(&mut self) {
        self.next_tag = self.next_tag.wrapping_add(1);
        self.run = Some(Run {
            step: Step::Recover,
            cdb: Cdb::test_unit_ready(),
            data: Data::None,
            tag: self.next_tag,
            phase: Phase::Reset,
            deadline_us: self.clock.now_us() + TIMEOUT_US,
            actual: 0,
            stalled: false,
            csw_retried: false,
        });
        self.submit_phase();
    }

    /// The device answered the whole recovery: start the command again.
    fn recovered(&mut self) {
        self.run = None;
        self.recoveries += 1;
        self.begin_io();
    }

    fn wire_tag(run: &Run, phase: Phase) -> u32 {
        run.tag << 4 | phase.code()
    }

    /// Submit the transfer of the current phase.
    fn submit_phase(&mut self) {
        let (Some(run), Some(buf)) = (self.run, self.buf.as_ref()) else { return };
        let Some(p) = self.pipes.as_mut() else { return };
        let tag = Self::wire_tag(&run, run.phase);
        let (pipe, t) = match run.phase {
            Phase::Cbw => {
                let cbw = run.cdb.cbw(run.tag, run.data.len(), matches!(run.data, Data::In { .. })).encode();
                buf.write_bytes(CBW_OFF, &cbw);
                self.mem.to_device(buf.cpu().wrapping_add(CBW_OFF), CBW_TOTAL_LEN);
                (&mut p.bout, xfer(tag, Dir::Out, buf.bus_at(CBW_OFF), CBW_TOTAL_LEN as u32))
            }
            Phase::Data => match run.data {
                Data::In { off, len } => (&mut p.bin, xfer(tag, Dir::In, buf.bus_at(off), len)),
                Data::Out { off, len } => {
                    self.mem.to_device(buf.cpu().wrapping_add(off), len as usize);
                    (&mut p.bout, xfer(tag, Dir::Out, buf.bus_at(off), len))
                }
                Data::None => return,
            },
            Phase::Csw => (&mut p.bin, xfer(tag, Dir::In, buf.bus_at(CSW_OFF), CSW_TOTAL_LEN as u32)),
            Phase::ClearData | Phase::ClearCsw | Phase::ResetIn | Phase::ResetOut => {
                let ep = match (run.phase, run.data) {
                    (Phase::ClearData, Data::Out { .. }) | (Phase::ResetOut, _) => p.ep_out,
                    _ => p.ep_in,
                };
                let mut t = xfer(tag, Dir::Out, 0, 0);
                t.setup = Setup::clear_halt(ep).to_bytes();
                (&mut p.ctl, t)
            }
            Phase::Reset => {
                let iface = self.claim.map_or(0, |c| c.iface());
                let mut t = xfer(tag, Dir::Out, 0, 0);
                t.setup = Setup {
                    request_type: RT_TYPE_CLASS | RT_RECIP_INTERFACE,
                    request: REQ_BULK_ONLY_RESET,
                    value: 0,
                    index: iface as u16,
                    length: 0,
                }
                .to_bytes();
                (&mut p.ctl, t)
            }
        };
        self.submitted = true;
        if !matches!(pipe.sq.push(t), Push::Pushed) {
            // One transfer per pipe is outstanding, so the ring cannot be
            // full: a ring that says so is broken.
            self.fail(Fail::Transport);
        }
    }

    /// The sense a REQUEST SENSE that finished with `out` returned.
    fn sense(&self, out: Outcome) -> Option<Sense> {
        if out != Outcome::Good {
            return None;
        }
        let mut d = [0u8; SMALL_LEN];
        self.small(&mut d);
        parse_sense(&d[..SENSE_LEN])
    }

    /// The first `SMALL_LEN` bytes of the small area, as the device left them.
    fn small(&self, out: &mut [u8; SMALL_LEN]) {
        if let Some(buf) = self.buf.as_ref() {
            self.mem.from_device(buf.cpu().wrapping_add(SMALL_OFF), SMALL_LEN);
            buf.read_bytes(SMALL_OFF, out);
        }
    }

    fn fail(&mut self, f: Fail) {
        self.run = None;
        self.reopen = None;
        self.state = State::Failed(f);
        if matches!(self.slot, Slot::Running) {
            self.slot = Slot::Finished(IoStatus::Io);
        }
    }

    /// The device is gone and the core has released the pipes: drain what is
    /// left, let go of the ring ends and the memory, forget the unit.
    fn cleanup(&mut self) {
        if let Some(mut p) = self.pipes.take() {
            for e in [&mut p.ctl, &mut p.bin, &mut p.bout] {
                while e.cq.pop().is_some() {}
            }
        }
        if let Some(b) = self.buf.take() {
            self.mem.free_region(b);
        }
        // A command in the device when it left is reported failed.
        if self.slot == Slot::Running {
            self.slot = Slot::Finished(IoStatus::Io);
        }
        self.run = None;
        self.reopen = None;
        self.caps = None;
        self.ident = None;
        self.claim = None;
        self.gone = false;
        self.state = State::Idle;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Good,
    /// CSW good, data stage short or stalled.
    Short,
    CheckCondition,
}

/// Open the pipe of endpoint `ep` (0: control) and take the driver's ends of
/// its rings.
fn open_one<'q>(dev: &mut dyn UsbDevice, rings: &'q [PipeRings], ep: u8) -> Result<PipeEnd<'q>, Fail> {
    let p = dev.pipe_open(ep as u32);
    if p.code != OK {
        return Err(Fail::Pipe);
    }
    let id = p.value as u8;
    match rings.get(id as usize).and_then(|r| PipeEnd::take(r, id)) {
        Some(e) => Ok(e),
        None => {
            let _ = dev.pipe_close(id as u32);
            Err(Fail::Pipe)
        }
    }
}

fn xfer(tag: u32, dir: Dir, buf: u64, len: u32) -> Transfer {
    Transfer { tag, dir, setup: [0; 8], buf, len }
}

impl<M: Memory, C: Clock> UsbClass for Msc<'_, M, C> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, _speed_port: u32) -> Out<u32> {
        let protocol = triple as u8;
        if protocol == INTERFACE_PROTOCOL_UAS {
            self.uas_declined += 1;
            return Out::new(UNSUPPORTED, 0);
        }
        if protocol != INTERFACE_PROTOCOL_BBB {
            return Out::new(UNSUPPORTED, 0);
        }
        if self.state != State::Idle || self.gone {
            self.busy_declined += 1;
            return Out::new(BUSY, 0);
        }
        let c = Claim(claim);
        if c.is_device_scope() {
            return Out::new(BAD_ARGUMENT, 0);
        }
        self.claim = Some(c);
        self.vid_pid = vid_pid;
        self.state = State::Claimed;
        Out::new(OK, 0)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        if self.claim == Some(Claim(claim)) {
            // The core killed the pipes: what was queued completes as
            // disconnected, and the ring ends are let go of by `service`.
            self.gone = true;
            self.run = None;
            self.state = State::Failed(Fail::Gone);
        }
        Out::new(OK, 0)
    }
}
