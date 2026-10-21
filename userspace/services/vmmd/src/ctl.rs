// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The control plane of the monitor: the `VmCtl` interface
//! (`azos_devif::vmctl`) that launches and ends a guest, as a state machine
//! over a [`Host`], plus the two pieces that carry it between threads and to
//! the guest's console.
//!
//! # Who does what
//!
//! The monitor's loop owns everything a machine is made of (the VM, its RAM,
//! the trap rings, the device models), and one thread cannot both sleep on the
//! trap port and block in the endpoint's accept. So a second thread, the
//! *service thread*, accepts the calls and hands each to the loop through the
//! [`Mailbox`]; the loop runs it between two passes ([`Control`] over its
//! [`Host`]) and hands the answer back. The state machine is therefore single
//! threaded, and the same code runs at start-up (`autostart`) as when a tool
//! calls.
//!
//! # What is decided here
//!
//! * the **ceiling**: a guest is built from a signed row; it can be given
//!   fewer CPUs or less memory than the row declares, never more, and the
//!   refusal says which number it exceeded;
//! * the **image name**: a plain relative path ([`image_ok`]), which the host
//!   then opens beneath the one directory the monitor's row grants;
//! * the **life**: free, created (kernel loaded), running, pausing (a hold is
//!   asked and some vCPU still enters the guest), paused; what each call needs
//!   and what it leaves behind when it fails (a failed create gives the
//!   machine back, so the row is free again). A pause is asked of the kernel
//!   per vCPU and taken by each vCPU's thread within a tick, which the loop
//!   cannot wait for (a vCPU may wait for a device model's answer, and this
//!   program is the model): the table stays *pausing* until [`Control::settle`]
//!   sees every vCPU hold the guest;
//! * the **receipt** of every refusal: cause, the number that explains it and
//!   a serial of the refusals so far, logged as well.
//!
//! The host does the work (system calls, the kernel's VM); the tests
//! (`tests/host/vmmd-tests/src/ctl_tests.rs`) run this code against a model.

use crate::life::PrepareError;
use crate::loader::LoadError;
use azos_devif::outcome;
use azos_devif::vm::{RUN_PAUSED, RUN_RUNNING};
use azos_devif::vmctl::{
    cause, ConsoleLease, ImageName, Info, Receipt, VmCtl, ENDED_FAULTED, ENDED_NEVER, ENDED_STOPPED,
    IMAGE_MAX, STATE_CREATED, STATE_FREE, STATE_PAUSED, STATE_PAUSING, STATE_RUNNING,
};
use azos_devif::{Lent, MsgDesc, Out};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};

/// Rows this monitor serves: its row grants `vm.0` (`VMMD_VM`), so one.
pub const ROWS: u32 = 1;

/// The kernel `autostart` loads when the volume has it: beneath the guest
/// directory, where the disk image lives.
pub const DEFAULT_IMAGE: &[u8] = b"KERNEL.ELF";

/// What the signed row declares of a guest (`Vm::config`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub cpus: u32,
    pub mem_mib: u32,
}

/// Why a step of the host failed: the [`cause`] and its number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fail {
    pub cause: u32,
    pub arg: u64,
}

impl Fail {
    pub const fn new(cause: u32, arg: u64) -> Fail {
        Fail { cause, arg }
    }
}

/// The monitor's loop, as far as the control plane needs it. Every method is
/// one act on the real machine; none of them decides anything.
pub trait Host {
    /// Open the kernel `image`, a name [`image_ok`] accepted, beneath the
    /// monitor's guest directory (`IMAGE_OPEN` when it cannot).
    fn open(&mut self, image: &[u8]) -> Result<(), Fail>;
    /// Build the machine for the row with `cpus` CPUs and `mem_mib` MiB
    /// visible to the guest: the VM, its RAM, the trap page, the device
    /// windows. Gives back what it made when it fails.
    fn build(&mut self, cpus: u32, mem_mib: u32) -> Result<(), Fail>;
    /// Read the opened image into RAM and put the machine's description next
    /// to it (`IMAGE_REFUSED` when the kernel is refused).
    fn load(&mut self) -> Result<(), Fail>;
    /// Start the boot CPU (`START_REFUSED` with the outcome).
    fn boot(&mut self) -> Result<(), Fail>;
    /// Ask every vCPU that runs to hold the guest (`Vcpu::pause`). `Err`: the
    /// kernel refused one (`PAUSE_REFUSED`); the ones asked before it are
    /// released again.
    fn pause(&mut self) -> Result<(), Fail>;
    /// Let every vCPU that holds the guest, or was asked to, run on
    /// (`Vcpu::resume`).
    fn resume(&mut self) -> Result<(), Fail>;
    /// Does every vCPU that runs hold the guest? Also asks the ones the guest
    /// started since the pause was asked.
    fn paused(&mut self) -> bool;
    /// Stop what runs and give the machine back; `false` when a CPU did not
    /// end in time or the VM refused.
    fn halt(&mut self) -> bool;
    /// Attach a fresh console ring to the guest's console (replacing an
    /// earlier one) and answer the handle to lend, ring access included.
    fn console(&mut self) -> Result<u32, Fail>;
    /// A line for the operator.
    fn log(&mut self, line: &[u8]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Free,
    Created,
    Running,
    /// A hold is asked; some vCPU has not taken it.
    Pausing,
    /// Every vCPU holds the guest.
    Paused,
}

/// One vCPU endpoint (`Vcpu`), as far as holding the guest goes.
pub trait Holder {
    /// `Vcpu::state`: `None` when the call did not reach the interface.
    fn state(&mut self) -> Option<u64>;
    /// `Vcpu::pause`: `Err` carries the outcome.
    fn pause(&mut self) -> Result<(), u32>;
    /// `Vcpu::resume`: `Err` carries the outcome.
    fn resume(&mut self) -> Result<(), u32>;
}

/// Does `state` (`Vcpu::state`) say the vCPU's thread runs?
fn runs(state: Option<u64>) -> bool {
    matches!(state, Some(s) if s & 0xFF == RUN_RUNNING)
}

/// Ask every vCPU of `0..count` that runs to hold the guest. When the kernel
/// refuses one, the ones asked before it are released again and the refusal
/// is the outcome (a half-held guest is not a paused one). A vCPU that
/// already holds it, or was asked to, is left as it is.
pub fn pause_all<C: Holder>(cpus: &mut [Option<C>], count: usize) -> Result<(), Fail> {
    for k in 0..count.min(cpus.len()) {
        let Some(c) = cpus[k].as_mut() else { continue };
        let st = c.state();
        if !runs(st) || st.is_some_and(|s| s & RUN_PAUSED != 0) {
            continue;
        }
        match c.pause() {
            // Asked already: the thread has not taken it yet.
            Ok(()) | Err(outcome::BUSY) => {}
            Err(code) => {
                for earlier in cpus[..k].iter_mut().flatten() {
                    let _ = earlier.resume();
                }
                return Err(Fail::new(cause::PAUSE_REFUSED, code as u64));
            }
        }
    }
    Ok(())
}

/// Let every vCPU of `0..count` that runs go on; the ones that hold nothing
/// are left. The kernel refusing one does not keep the others held: all are
/// asked, and the first refusal is the outcome.
pub fn resume_all<C: Holder>(cpus: &mut [Option<C>], count: usize) -> Result<(), Fail> {
    let mut first = None;
    for c in cpus.iter_mut().take(count).flatten() {
        if !runs(c.state()) {
            continue;
        }
        match c.resume() {
            Ok(()) | Err(outcome::BUSY) => {}
            Err(code) => first = first.or(Some(code)),
        }
    }
    match first {
        None => Ok(()),
        Some(code) => Err(Fail::new(cause::PAUSE_REFUSED, code as u64)),
    }
}

/// Does every vCPU of `0..count` that runs hold the guest? The ones that do
/// not are asked again: a vCPU the guest started after the pause was asked
/// still enters it.
pub fn all_held<C: Holder>(cpus: &mut [Option<C>], count: usize) -> bool {
    let mut held = true;
    for c in cpus.iter_mut().take(count).flatten() {
        let st = c.state();
        if runs(st) && st.is_some_and(|s| s & RUN_PAUSED == 0) {
            held = false;
            let _ = c.pause();
        }
    }
    held
}

/// The table: the one VM the monitor serves, and the refusals it has made.
pub struct Control {
    row: Row,
    phase: Phase,
    /// What the guest sees, while it is built.
    cpus: u32,
    mem_mib: u32,
    ended: u32,
    serial: u32,
}

/// May `name` be opened beneath the guest directory? A plain relative path of
/// letters, digits and `. _ - /`, with no empty, `.` or `..` component. (The
/// kernel refuses `..` and an absolute name as well; this refuses them first,
/// with a receipt.)
pub fn image_ok(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > IMAGE_MAX {
        return false;
    }
    if !name.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'/')) {
        return false;
    }
    name.split(|&c| c == b'/').all(|part| !part.is_empty() && part != b"." && part != b"..")
}

/// The number [`cause::IMAGE_REFUSED`] carries for a refused preparation.
pub fn refusal_code(e: &PrepareError) -> u64 {
    match e {
        PrepareError::Kernel(l) => match l {
            LoadError::Read => 1,
            LoadError::Truncated => 2,
            LoadError::NotElf => 3,
            LoadError::Machine => 4,
            LoadError::Phdrs => 5,
            LoadError::Loads => 6,
            LoadError::BadSegment => 7,
            LoadError::OutOfRam => 8,
            LoadError::Overlap => 9,
            LoadError::BadEntry => 10,
            LoadError::NoPvhEntry => 11,
        },
        PrepareError::Tree(_) | PrepareError::Pvh(_) => 12,
        PrepareError::NoRoom => 13,
    }
}

/// The interface outcome a cause answers with.
pub fn outcome_of(c: u32) -> u32 {
    match c {
        cause::NONE => outcome::OK,
        cause::NO_SUCH_ROW | cause::NO_SUCH_VM => outcome::NO_RESOURCE,
        cause::OVER_CPUS | cause::OVER_MEM => outcome::REFUSED,
        cause::IMAGE_NAME => outcome::BAD_ARGUMENT,
        cause::NOT_FREE | cause::RUNNING | cause::ALREADY_PAUSED => outcome::BUSY,
        cause::NOT_CREATED | cause::NOT_RUNNING | cause::NOT_PAUSED => outcome::NOT_READY,
        _ => outcome::FAULT,
    }
}

impl Control {
    /// A table of the one VM, whose signed row declares `row`.
    pub const fn new(row: Row) -> Control {
        Control { row, phase: Phase::Free, cpus: row.cpus, mem_mib: row.mem_mib, ended: ENDED_NEVER, serial: 0 }
    }

    fn receipt(&self, id: u32) -> Receipt {
        Receipt { id, cause: cause::NONE, arg: 0, serial: self.serial }
    }

    /// Count a refusal, log it, answer its receipt.
    fn refuse<H: Host>(&mut self, h: &mut H, op: &[u8], id: u32, f: Fail) -> Receipt {
        self.serial = self.serial.wrapping_add(1);
        h.log(b"[vmmd] ");
        h.log(op);
        h.log(b" refused: ");
        h.log(cause::text(f.cause));
        h.log(b"\n");
        Receipt { id, cause: f.cause, arg: f.arg, serial: self.serial }
    }

    /// Build the machine of `row` and load `image` into it.
    pub fn create<H: Host>(&mut self, h: &mut H, row: u32, cpus: u32, mem_mib: u32, image: &[u8]) -> Result<Receipt, Receipt> {
        let op: &[u8] = b"create";
        if row >= ROWS {
            return Err(self.refuse(h, op, row, Fail::new(cause::NO_SUCH_ROW, ROWS as u64)));
        }
        let id = row;
        let (cpus, mem_mib) = (if cpus == 0 { self.row.cpus } else { cpus }, if mem_mib == 0 { self.row.mem_mib } else { mem_mib });
        #[cfg(not(feature = "canary-ctl-no-ceiling"))]
        if cpus > self.row.cpus {
            return Err(self.refuse(h, op, id, Fail::new(cause::OVER_CPUS, self.row.cpus as u64)));
        }
        #[cfg(not(feature = "canary-ctl-no-ceiling"))]
        if mem_mib > self.row.mem_mib {
            return Err(self.refuse(h, op, id, Fail::new(cause::OVER_MEM, self.row.mem_mib as u64)));
        }
        if self.phase != Phase::Free {
            return Err(self.refuse(h, op, id, Fail::new(cause::NOT_FREE, 0)));
        }
        #[cfg(not(feature = "canary-ctl-image-unchecked"))]
        if !image_ok(image) {
            return Err(self.refuse(h, op, id, Fail::new(cause::IMAGE_NAME, 0)));
        }
        if let Err(f) = h.open(image) {
            return Err(self.refuse(h, op, id, f));
        }
        if let Err(f) = h.build(cpus, mem_mib) {
            return Err(self.refuse(h, op, id, f));
        }
        if let Err(f) = h.load() {
            // The machine was built for this kernel only: give it back. When
            // that fails too, it is still held: the row is not free, and
            // `stop` is the way to retry the give-back.
            if !h.halt() {
                self.phase = Phase::Created;
                return Err(self.refuse(h, op, id, Fail::new(cause::STOP_FAILED, f.cause as u64)));
            }
            return Err(self.refuse(h, op, id, f));
        }
        self.phase = Phase::Created;
        (self.cpus, self.mem_mib) = (cpus, mem_mib);
        Ok(self.receipt(id))
    }

    /// Start VM `id`'s boot CPU.
    pub fn start<H: Host>(&mut self, h: &mut H, id: u32) -> Result<Receipt, Receipt> {
        let op: &[u8] = b"start";
        if id >= ROWS {
            return Err(self.refuse(h, op, id, Fail::new(cause::NO_SUCH_VM, 0)));
        }
        match self.phase {
            Phase::Free => return Err(self.refuse(h, op, id, Fail::new(cause::NOT_CREATED, 0))),
            Phase::Running | Phase::Pausing | Phase::Paused => {
                return Err(self.refuse(h, op, id, Fail::new(cause::RUNNING, 0)));
            }
            Phase::Created => {}
        }
        if let Err(f) = h.boot() {
            return Err(self.refuse(h, op, id, f));
        }
        self.phase = Phase::Running;
        Ok(self.receipt(id))
    }

    /// End VM `id`, created or running, and give its machine back.
    pub fn stop<H: Host>(&mut self, h: &mut H, id: u32) -> Result<Receipt, Receipt> {
        let op: &[u8] = b"stop";
        if id >= ROWS {
            return Err(self.refuse(h, op, id, Fail::new(cause::NO_SUCH_VM, 0)));
        }
        if self.phase == Phase::Free {
            return Err(self.refuse(h, op, id, Fail::new(cause::NOT_CREATED, 0)));
        }
        let freed = h.halt();
        // Whatever the machine's answer, the guest is over: a machine that
        // could not be given back is reported, and the row stays unusable
        // until the monitor is restarted (the supervisor does that).
        self.ended = ENDED_STOPPED;
        if !freed {
            return Err(self.refuse(h, op, id, Fail::new(cause::STOP_FAILED, 0)));
        }
        self.phase = Phase::Free;
        Ok(self.receipt(id))
    }

    /// Hold VM `id`'s running guest.
    pub fn pause<H: Host>(&mut self, h: &mut H, id: u32) -> Result<Receipt, Receipt> {
        let op: &[u8] = b"pause";
        if id >= ROWS {
            return Err(self.refuse(h, op, id, Fail::new(cause::NO_SUCH_VM, 0)));
        }
        match self.phase {
            Phase::Free => return Err(self.refuse(h, op, id, Fail::new(cause::NOT_CREATED, 0))),
            Phase::Created => return Err(self.refuse(h, op, id, Fail::new(cause::NOT_RUNNING, 0))),
            Phase::Pausing | Phase::Paused => {
                return Err(self.refuse(h, op, id, Fail::new(cause::ALREADY_PAUSED, 0)));
            }
            Phase::Running => {}
        }
        if let Err(f) = h.pause() {
            return Err(self.refuse(h, op, id, f));
        }
        self.phase = Phase::Pausing;
        self.settle(h);
        Ok(self.receipt(id))
    }

    /// Let VM `id`'s held guest run on, or cancel a hold not yet taken.
    pub fn resume<H: Host>(&mut self, h: &mut H, id: u32) -> Result<Receipt, Receipt> {
        let op: &[u8] = b"resume";
        if id >= ROWS {
            return Err(self.refuse(h, op, id, Fail::new(cause::NO_SUCH_VM, 0)));
        }
        match self.phase {
            Phase::Free => return Err(self.refuse(h, op, id, Fail::new(cause::NOT_CREATED, 0))),
            Phase::Created | Phase::Running => return Err(self.refuse(h, op, id, Fail::new(cause::NOT_PAUSED, 0))),
            Phase::Pausing | Phase::Paused => {}
        }
        if let Err(f) = h.resume() {
            return Err(self.refuse(h, op, id, f));
        }
        self.phase = Phase::Running;
        Ok(self.receipt(id))
    }

    /// The monitor's loop, between two passes: a pause asked becomes taken
    /// once every vCPU holds the guest.
    pub fn settle<H: Host>(&mut self, h: &mut H) {
        if self.phase == Phase::Pausing && h.paused() {
            self.phase = Phase::Paused;
        }
    }

    /// A ring for VM `id`'s console output, as a lease.
    pub fn console<H: Host>(&mut self, h: &mut H, id: u32, rights: u16) -> Result<ConsoleLease, Receipt> {
        let op: &[u8] = b"console";
        if id >= ROWS {
            return Err(self.refuse(h, op, id, Fail::new(cause::NO_SUCH_VM, 0)));
        }
        if self.phase == Phase::Free {
            return Err(self.refuse(h, op, id, Fail::new(cause::NOT_CREATED, 0)));
        }
        match h.console() {
            Ok(handle) => Ok(ConsoleLease { receipt: self.receipt(id), ring: Lent::dup(handle, rights) }),
            Err(f) => Err(self.refuse(h, op, id, f)),
        }
    }

    /// The monitor's loop saw the guest end (and has given the machine back):
    /// the row is free again. `fault`: the last CPU ended on an exit nothing
    /// serves.
    pub fn finished(&mut self, fault: bool) {
        self.phase = Phase::Free;
        self.ended = if fault { ENDED_FAULTED } else { ENDED_STOPPED };
    }

    /// The table's entry `index`.
    pub fn info(&self, index: u32) -> Option<Info> {
        (index < ROWS).then(|| {
            let (state, cpus, mem_mib) = match self.phase {
                Phase::Free => (STATE_FREE, self.row.cpus, self.row.mem_mib),
                Phase::Created => (STATE_CREATED, self.cpus, self.mem_mib),
                Phase::Running => (STATE_RUNNING, self.cpus, self.mem_mib),
                Phase::Pausing => (STATE_PAUSING, self.cpus, self.mem_mib),
                Phase::Paused => (STATE_PAUSED, self.cpus, self.mem_mib),
            };
            Info { id: index, state, cpus, mem_mib, ended: self.ended }
        })
    }

    /// Start what the volume carries: [`DEFAULT_IMAGE`] on row 0 with what the
    /// row declares, created and started through the calls a tool makes.
    /// `false` when the volume has no such kernel (the refusal is logged like
    /// any other: a monitor without a guest to boot is the usual case).
    pub fn autostart<H: Host>(&mut self, h: &mut H) -> bool {
        match self.create(h, 0, 0, 0, DEFAULT_IMAGE) {
            Ok(_) => {}
            Err(_) => return false,
        }
        self.start(h, 0).is_ok()
    }
}

fn answer<T>(r: Result<T, Receipt>, with: impl FnOnce(Receipt) -> T) -> Out<T> {
    match r {
        Ok(v) => Out::ok(v),
        Err(rc) => Out::new(outcome_of(rc.cause), with(rc)),
    }
}

/// The table and the machine for the length of one call: what `VmCtlIdl`
/// dispatches to.
pub struct Bound<'a, H: Host> {
    pub ctl: &'a mut Control,
    pub host: &'a mut H,
    /// `CapPerms` bits the console ring is lent with.
    pub ring_rights: u16,
}

impl<H: Host> VmCtl for Bound<'_, H> {
    fn list(&self, index: u32) -> Out<Info> {
        match self.ctl.info(index) {
            Some(i) => Out::ok(i),
            None => Out::err(outcome::NO_RESOURCE),
        }
    }

    fn create(&mut self, row: u32, cpus: u32, mem_mib: u32, image: ImageName) -> Out<Receipt> {
        let mut name = [0u8; IMAGE_MAX];
        let n = image.unpack(&mut name);
        answer(self.ctl.create(self.host, row, cpus, mem_mib, &name[..n]), |r| r)
    }

    fn start(&mut self, id: u32) -> Out<Receipt> {
        answer(self.ctl.start(self.host, id), |r| r)
    }

    fn stop(&mut self, id: u32) -> Out<Receipt> {
        answer(self.ctl.stop(self.host, id), |r| r)
    }

    fn console(&mut self, id: u32) -> Out<ConsoleLease> {
        answer(self.ctl.console(self.host, id, self.ring_rights), |receipt| ConsoleLease { receipt, ring: Lent::none() })
    }

    fn pause(&mut self, id: u32) -> Out<Receipt> {
        answer(self.ctl.pause(self.host, id), |r| r)
    }

    fn resume(&mut self, id: u32) -> Out<Receipt> {
        answer(self.ctl.resume(self.host, id), |r| r)
    }
}

// ---------------------------------------------------------------------------
// The memory a smaller guest sees
// ---------------------------------------------------------------------------

use crate::guest::{GuestMem, OutOfRam};

/// The first `bytes` of a guest's RAM and no more. The kernel attaches the
/// whole of the row's memory (`Vm::start` wants all of it), so a guest asked
/// for less sees a prefix: the kernel is loaded into it, the description
/// names its size, and the models refuse an address past it. The rest stays
/// attached, unused.
pub struct Limited<'a> {
    inner: &'a mut dyn GuestMem,
    bytes: u64,
}

impl<'a> Limited<'a> {
    pub fn new(inner: &'a mut dyn GuestMem, bytes: u64) -> Limited<'a> {
        let bytes = bytes.min(inner.range().1);
        Limited { inner, bytes }
    }
}

impl GuestMem for Limited<'_> {
    fn range(&self) -> (u64, u64) {
        (self.inner.range().0, self.bytes)
    }

    fn read(&self, gpa: u64, out: &mut [u8]) -> Result<(), OutOfRam> {
        if !self.contains(gpa, out.len() as u64) {
            return Err(OutOfRam);
        }
        self.inner.read(gpa, out)
    }

    fn write(&mut self, gpa: u64, data: &[u8]) -> Result<(), OutOfRam> {
        if !self.contains(gpa, data.len() as u64) {
            return Err(OutOfRam);
        }
        self.inner.write(gpa, data)
    }
}

// ---------------------------------------------------------------------------
// The mailbox
// ---------------------------------------------------------------------------

const IDLE: u32 = 0;
const POSTED: u32 = 1;
const DONE: u32 = 2;

/// How the two threads sleep and wake each other.
pub trait Wake {
    /// Make the monitor's loop run a pass now (it sleeps on the trap port).
    fn wake_monitor(&self);
    /// Sleep while `word` still holds `seen`.
    fn park(&self, word: &AtomicU32, seen: u32);
    /// Wake the sleepers on `word`.
    fn unpark(&self, word: &AtomicU32);
}

/// One request at a time between the service thread and the loop: the service
/// thread [`call`](Mailbox::call)s and sleeps, the loop [`take`](Mailbox::take)s
/// between passes, runs it and [`answer`](Mailbox::answer)s.
pub struct Mailbox {
    state: AtomicU32,
    req: UnsafeCell<MaybeUninit<MsgDesc>>,
    rep: UnsafeCell<MaybeUninit<MsgDesc>>,
}

// SAFETY: `req` is written by the service thread before it stores `POSTED`
// (Release) and read by the loop after it loads `POSTED` (Acquire); `rep` is
// written by the loop before it stores `DONE` (Release) and read by the
// service thread after it loads `DONE` (Acquire). Neither is touched in any
// other state, and only the service thread posts, one request at a time.
unsafe impl Sync for Mailbox {}

impl Mailbox {
    pub const fn new() -> Mailbox {
        Mailbox { state: AtomicU32::new(IDLE), req: UnsafeCell::new(MaybeUninit::uninit()), rep: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    /// Service thread: hand `req` to the loop and sleep until it answers.
    pub fn call(&self, w: &impl Wake, req: &MsgDesc) -> MsgDesc {
        // SAFETY: the state is IDLE: the loop does not touch `req`.
        unsafe { (*self.req.get()).write(*req) };
        self.state.store(POSTED, Ordering::Release);
        w.wake_monitor();
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s == DONE {
                break;
            }
            w.park(&self.state, s);
        }
        // SAFETY: DONE was loaded with Acquire: the loop is finished with `rep`.
        let rep = unsafe { (*self.rep.get()).assume_init() };
        self.state.store(IDLE, Ordering::Release);
        rep
    }

    /// The loop: the request posted, if one is.
    pub fn take(&self) -> Option<MsgDesc> {
        if self.state.load(Ordering::Acquire) != POSTED {
            return None;
        }
        // SAFETY: POSTED was loaded with Acquire: the service thread is done
        // with `req` and waits for DONE.
        Some(unsafe { (*self.req.get()).assume_init() })
    }

    /// The loop: answer the request [`take`](Mailbox::take) gave.
    pub fn answer(&self, w: &impl Wake, rep: &MsgDesc) {
        // SAFETY: the state is POSTED: the service thread only waits.
        unsafe { (*self.rep.get()).write(*rep) };
        self.state.store(DONE, Ordering::Release);
        w.unpark(&self.state);
    }
}

// ---------------------------------------------------------------------------
// The guest's console output
// ---------------------------------------------------------------------------

use crate::console::Term;
use azos_rings::region::SpscStream;

/// Where the guest's console bytes go: the monitor's own console, or a ring
/// a tool drains while it is attached. The bytes have passed the console
/// filter and volume limit already (`console::Guarded` wraps this).
pub struct Sink<T: Term> {
    pub inner: T,
    ring: Option<SpscStream>,
    /// Bytes the current ring had no room for (its holder does not drain).
    lost: u64,
}

/// A ring the sink stopped writing, and what it dropped while it did.
#[derive(Clone, Copy, Debug)]
pub struct Retired {
    pub ring: SpscStream,
    /// Bytes that did not fit while the sink wrote it.
    pub lost: u64,
}

impl<T: Term> Sink<T> {
    pub const fn new(inner: T) -> Sink<T> {
        Sink { inner, ring: None, lost: 0 }
    }

    /// Send the output to `ring` (a fresh ring). The ring the sink wrote
    /// before is no longer written: it comes back, to be closed and released.
    pub fn attach(&mut self, ring: SpscStream) -> Option<Retired> {
        let old = self.detach();
        self.ring = Some(ring);
        old
    }

    /// Stop writing the ring (the output goes to `inner` again). Detach
    /// before the ring's region is released: the sink holds no mapping of its
    /// own.
    pub fn detach(&mut self) -> Option<Retired> {
        let lost = core::mem::take(&mut self.lost);
        self.ring.take().map(|ring| Retired { ring, lost })
    }
}

impl<T: Term> Term for Sink<T> {
    fn write(&mut self, bytes: &[u8]) {
        match self.ring {
            Some(r) => {
                let (n, _) = r.write(bytes);
                self.lost += (bytes.len() - n) as u64;
            }
            None => self.inner.write(bytes),
        }
    }

    /// The guest has no input.
    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }

    fn tick(&mut self, now_ns: u64) {
        self.inner.tick(now_ns);
    }
}
