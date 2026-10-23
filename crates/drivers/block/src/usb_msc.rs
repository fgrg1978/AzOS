// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A USB mass-storage disk as a hardware queue of the block request layer
//! (Kconfig `USB_STORAGE`).
//!
//! The protocol is `azos_usb::class::msc` (Bulk-Only Transport and SCSI over
//! the pipes of the USB core, pure and host-tested against an xHCI mock); this
//! file is what the kernel adds, as `nvme.rs` is for `azos_nvme`: one lock
//! around the protocol, the [`HwQueue`] it implements, and the wait.
//!
//! # Who runs it
//!
//! The protocol sits behind a sleeping mutex, not a spinlock: opening a stick's
//! pipes goes through the core's controller commands, which sleep (the clock's
//! `delay_us`). Every other use of it is short and never waits for the device.
//!
//! Two parties turn the crank, and both only ever push to or pop from the
//! pipes' rings:
//!
//! - the `usb` task runs the core's `service` (which moves the rings'
//!   submissions to the controller and posts its completions), then
//!   [`UsbDisk::drive`]: it opens the pipes of a stick the core just handed
//!   over, advances the protocol, and wakes the task asleep in
//!   [`HwQueue::wait`];
//! - a task doing block I/O: [`HwQueue::start`] puts the command's CBW into
//!   the bulk-OUT ring, [`HwQueue::reap`] takes the completions and puts the
//!   next stage in. Each time something went into a ring the `usb` task is
//!   woken ([`set_hooks`]'s `kick`), so a stage costs the controller's time,
//!   not `USB_POLL_MS`.
//!
//! The disk is **not** the boot block device: [`UsbDisk`] owns a request layer
//! of its own ([`UsbDisk::read`] ...), and `blkdev` is untouched. A device
//! that is bound with `queue::bind` is the one `blkdev` drives; a stick that
//! comes and goes must not take that place.
//!
//! One command is in the disk at a time (Bulk-Only Transport has no tags), so
//! [`HwQueue::claim`] answers `Busy` while one is held; the request layer
//! merges adjacent requests into one command of up to `USB_MSC_XFER_KB`.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use azos_drv_api::block::DeviceWait;
use azos_drv_sys::kprintln;
use azos_sync::kmutex::Mutex;
use azos_usb::class::msc::{Fail, IoStatus, Msc, State, Take};
use azos_usb::class::UsbClass;
use azos_usb::hw::{Clock, Memory, Regs};
use azos_usb::usbcore::Usb;
use azos_devif::Out;

use crate::queue::{Claim, Failure, HwCaps, HwCmd, HwDone, HwOp, HwQueue, HwStatus, ReqQueue, HW_TAGS_MAX};

azos_common::ro_hook! {
    /// The kernel's hook: block the caller until woken or `deadline`
    /// (timebase ticks), `false` when it cannot block.
    static BLOCK_FN: fn(u64) -> bool;
}
azos_common::ro_hook! {
    /// The kernel's hook: wake task `tid`.
    static WAKE_FN: fn(u32);
}
azos_common::ro_hook! {
    /// The kernel's hook: wake the `usb` task now (a transfer was queued).
    static KICK_FN: fn();
}

/// Let waiters sleep instead of spin and let a queued transfer wake the `usb`
/// task: call once the scheduler exists.
pub fn set_hooks(block_until: fn(u64) -> bool, wake: fn(u32), kick: fn()) {
    BLOCK_FN.set(block_until);
    WAKE_FN.set(wake);
    KICK_FN.set(kick);
}

fn ns_to_ticks(ns: u64) -> u64 {
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    (ns / 1_000_000_000).saturating_mul(f).saturating_add((ns % 1_000_000_000) * f / 1_000_000_000)
}

/// What [`UsbDisk::drive`] saw happen to the disk, for the caller to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    None,
    /// The disk became ready (and a line was printed).
    Ready,
    /// The disk that was there (ready, failed, or still coming up) went away:
    /// what was mounted from it is to be retired.
    Gone,
}

/// One USB mass-storage disk.
pub struct UsbDisk<'q, M: Memory, C: Clock> {
    msc: Mutex<Msc<'q, M, C>>,
    rq: ReqQueue,
    /// The task asleep in [`HwQueue::wait`].
    waiter: DeviceWait,
    /// The `usb` task turned the crank since the reaper last looked
    /// ([`HwQueue::reap`] clears it): what the sleeper re-checks once it is
    /// listed, so a turn that came before the listing is not slept through.
    progress: AtomicBool,
    /// The state last reported, as a code.
    shown: AtomicU8,
}

impl<'q, M: Memory + Send, C: Clock + Send> UsbDisk<'q, M, C> {
    pub fn new(msc: Msc<'q, M, C>) -> Self {
        UsbDisk { msc: Mutex::new(msc), rq: ReqQueue::new(), waiter: DeviceWait::new(), progress: AtomicBool::new(false), shown: AtomicU8::new(0) }
    }

    /// [`UsbDisk::new`] in place. The request queue is `HARTS` x `DEPTH`
    /// entries (tens of KB on a many-hart machine); `new` followed by
    /// `Box::new` has two or three copies of it in the caller's frame, `init`
    /// on a `Box::new_uninit` none: the queue is copied from a constant
    /// straight into the box.
    pub fn init<'a>(slot: &'a mut core::mem::MaybeUninit<Self>, msc: Msc<'q, M, C>) -> &'a mut Self {
        let p = slot.as_mut_ptr();
        // SAFETY: `p` is valid and aligned for a `Self`, and each field is
        // written once before `&mut *p` exists.
        unsafe {
            core::ptr::addr_of_mut!((*p).msc).write(Mutex::new(msc));
            core::ptr::addr_of_mut!((*p).rq).write(const { ReqQueue::new() });
            core::ptr::addr_of_mut!((*p).waiter).write(DeviceWait::new());
            core::ptr::addr_of_mut!((*p).progress).write(AtomicBool::new(false));
            core::ptr::addr_of_mut!((*p).shown).write(AtomicU8::new(0));
            &mut *p
        }
    }

    /// The rule to register the class driver under.
    pub const fn rule() -> azos_usb::class::Match {
        Msc::<'q, M, C>::rule()
    }

    /// The class driver to register with the USB core: it takes this disk's
    /// lock for each call (the registry holds it for a whole service call).
    pub fn class(&self) -> DiskClass<'_, 'q, M, C> {
        DiskClass(self)
    }

    /// Turn the crank from the `usb` task, after the core's turn: open a
    /// stick the core handed over, advance the protocol, report a change,
    /// wake the task waiting for the disk.
    pub fn drive<R: Regs, M2: Memory, C2: Clock>(&self, usb: &mut Usb<'_, R, M2, C2>) -> Event {
        let (state, id, sectors) = {
            let mut m = self.msc.lock();
            if let Some(claim) = m.session_wanted() {
                let mut session = usb.session(claim);
                m.open(&mut session);
            }
            m.service();
            (m.state(), m.identity(), m.caps().map_or(0, |c| c.sectors))
        };
        let code = state_code(state);
        let was = self.shown.swap(code, Ordering::AcqRel);
        let event = if was != code {
            match (state, id) {
                (State::Ready, Some(id)) => {
                    kprintln!(
                        "[USB] mass storage {:04x}:{:04x} {} {}: {} sectors",
                        id.vid_pid >> 16,
                        id.vid_pid & 0xffff,
                        text(&id.inquiry.vendor),
                        text(&id.inquiry.product),
                        sectors
                    );
                    Event::Ready
                }
                // The unplug's turn often cleans up at once (`Idle`, not
                // `Failed(Gone)` first): any state but idle before it was a disk.
                (State::Failed(Fail::Gone), _) | (State::Idle, _) => {
                    if was != state_code(State::Idle) { Event::Gone } else { Event::None }
                }
                (State::Failed(f), _) => {
                    kprintln!("[USB] mass storage not used: {:?}", f);
                    Event::None
                }
                _ => Event::None,
            }
        } else {
            Event::None
        };
        self.wake();
        event
    }

    /// Wake the task asleep in [`HwQueue::wait`], if any.
    fn wake(&self) {
        // The event first, then the look at who is listed (`DeviceWait`).
        self.progress.store(true, Ordering::SeqCst);
        let tid = self.waiter.sleeper();
        if tid != 0 {
            if let Some(w) = WAKE_FN.get() {
                w(tid);
            }
        }
    }

    /// Whether a disk is ready to be read.
    pub fn ready(&self) -> bool {
        self.msc.lock().state() == State::Ready
    }

    /// Read `count` sectors from `sector` into `buf` for `owner`.
    pub fn read(&self, owner: u32, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), Failure> {
        self.rq.transfer(self, owner, false, sector, count, 0, buf.as_mut_ptr(), buf.len())
    }

    /// Write `count` sectors from `buf` at `sector` for `owner`, `flags`
    /// (`FLAG_FUA`, `FLAG_PREFLUSH`) on each request.
    pub fn write(&self, owner: u32, sector: u64, count: u32, flags: u32, buf: &[u8]) -> Result<(), Failure> {
        // The queue only reads a write's buffer.
        self.rq.transfer(self, owner, true, sector, count, flags, buf.as_ptr() as *mut u8, buf.len())
    }

    /// Make every write that completed so far durable.
    pub fn flush(&self, owner: u32) -> Result<(), Failure> {
        self.rq.flush(self, owner)
    }
}

fn state_code(s: State) -> u8 {
    match s {
        State::Idle => 0,
        State::Claimed => 1,
        State::Probing => 2,
        State::Ready => 3,
        State::Failed(Fail::Gone) => 4,
        State::Failed(_) => 5,
    }
}

/// An INQUIRY string without its padding (ASCII; anything else is a `?`).
fn text(b: &[u8]) -> &str {
    core::str::from_utf8(b).map(str::trim).unwrap_or("?")
}

/// [`UsbDisk`] as a class driver.
pub struct DiskClass<'a, 'q, M: Memory, C: Clock>(&'a UsbDisk<'q, M, C>);

impl<M: Memory + Send, C: Clock + Send> UsbClass for DiskClass<'_, '_, M, C> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> Out<u32> {
        let r = self.0.msc.lock().attach(claim, vid_pid, triple, speed_port);
        r
    }
    fn detach(&mut self, claim: u32) -> Out<u32> {
        let r = self.0.msc.lock().detach(claim);
        // A task waiting for a command must see the disk go.
        self.0.wake();
        r
    }
}

impl<M: Memory + Send, C: Clock + Send> HwQueue for UsbDisk<'_, M, C> {
    fn caps(&self) -> HwCaps {
        match self.msc.lock().caps() {
            Some(c) => HwCaps { sectors: c.sectors, max_sectors: c.max_sectors, max_discard_sectors: 0, fua: false },
            // Nothing is queued while there is no disk: the request layer
            // refuses every request against zero sectors.
            None => HwCaps { sectors: 0, max_sectors: 1, max_discard_sectors: 0, fua: false },
        }
    }

    fn cpu(&self) -> usize {
        azos_arch::Cpu::hart_id(&azos_arch::ARCH)
    }

    fn claim(&self) -> Claim {
        match self.msc.lock().take() {
            Take::Granted => Claim::Tag(0),
            Take::Busy => Claim::Busy,
            Take::Dead => Claim::Dead,
        }
    }

    fn start(&self, _tag: u8, cmd: &HwCmd<'_>) -> Result<(), ()> {
        let mut m = self.msc.lock();
        let r = match cmd.op {
            HwOp::Read => m.start_read(cmd.lba, cmd.sectors),
            HwOp::Write => m.start_write(cmd.lba, cmd.sectors, cmd.fua, cmd.segs),
            HwOp::Flush => m.start_flush(),
            HwOp::Discard => Err(()),
        };
        let kick = m.take_submitted();
        drop(m);
        if kick {
            self.kick();
        }
        r
    }

    fn reap(&self, out: &mut [HwDone; HW_TAGS_MAX]) -> usize {
        // Before the look: a turn of the crank after this store is one the
        // look may not have seen, and `wait` must not sleep through it.
        self.progress.store(false, Ordering::SeqCst);
        let mut m = self.msc.lock();
        let done = m.reap();
        let kick = m.take_submitted();
        drop(m);
        if kick {
            self.kick();
        }
        match done {
            Some(s) => {
                out[0] = HwDone {
                    tag: 0,
                    status: match s {
                        IoStatus::Ok => HwStatus::Ok,
                        IoStatus::Unsupported => HwStatus::Unsupported,
                        IoStatus::Io => HwStatus::Io,
                    },
                };
                1
            }
            None => 0,
        }
    }

    fn copy_out(&self, _tag: u8, off: usize, dst: &mut [u8]) {
        self.msc.lock().copy_out(off, dst);
    }

    fn release(&self, _tag: u8) {
        self.msc.lock().release();
    }

    fn wait(&self, until_ns: u64) -> bool {
        let tid = azos_sync::waitqueue::caller_tid();
        let Some(block) = BLOCK_FN.get().filter(|_| tid != 0 && tid != u32::MAX) else {
            return false;
        };
        // Re-check after listing: the `usb` task's wake before the listing
        // reached nobody (this was the whole slice lost per stage).
        self.waiter.park(tid, || self.progress.load(Ordering::SeqCst), || block(ns_to_ticks(until_ns)))
    }
}

impl<M: Memory + Send, C: Clock + Send> UsbDisk<'_, M, C> {
    fn kick(&self) {
        if let Some(k) = KICK_FN.get() {
            k();
        }
    }
}
