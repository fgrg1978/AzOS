// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `VmCtl` control plane: the state machine over a model of the monitor's
//! loop, the interface's wire form through the generated client and the
//! server's dispatch, the mailbox between the service thread and the loop,
//! and the console ring.

use crate::console::Term;
use crate::ctl::{
    all_held, image_ok, outcome_of, pause_all, refusal_code, resume_all, Bound, Control, Fail, Holder, Host, Limited,
    Mailbox, Row, Sink, Wake, DEFAULT_IMAGE, ROWS,
};
use crate::guest::GuestMem;
use crate::life::PrepareError;
use crate::loader::LoadError;
use azos_devif::vm::{RUN_PAUSED, RUN_RUNNING, RUN_STOPPED};
use azos_devif::vmctl::{
    cause, ConsoleLease, ImageName, ENDED_FAULTED, ENDED_NEVER, ENDED_STOPPED, IMAGE_MAX, STATE_CREATED, STATE_FREE,
    STATE_PAUSED, STATE_PAUSING, STATE_RUNNING,
};
use azos_devif::{outcome, IdlError, MsgDesc, Transport, VmCtlCall, VmCtlClient, VmCtlIdl};
use azos_rings::region::SpscStream;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

const ROW: Row = Row { cpus: 4, mem_mib: 256 };

/// A model of the monitor's loop: it records every act and fails the ones it
/// is told to.
#[derive(Default)]
struct Model {
    calls: Vec<String>,
    log: Vec<u8>,
    fail_open: Option<Fail>,
    fail_build: Option<Fail>,
    fail_load: Option<Fail>,
    fail_boot: Option<Fail>,
    fail_console: Option<Fail>,
    halt_ok_not: bool,
    handle: u32,
    fail_pause: Option<Fail>,
    fail_resume: Option<Fail>,
    /// `paused()` answers `true` from this many looks on.
    held_after: u32,
    looks: u32,
}

impl Host for Model {
    fn open(&mut self, image: &[u8]) -> Result<(), Fail> {
        self.calls.push(format!("open {}", String::from_utf8_lossy(image)));
        self.fail_open.map_or(Ok(()), Err)
    }

    fn build(&mut self, cpus: u32, mem_mib: u32) -> Result<(), Fail> {
        self.calls.push(format!("build {cpus} {mem_mib}"));
        self.fail_build.map_or(Ok(()), Err)
    }

    fn load(&mut self) -> Result<(), Fail> {
        self.calls.push("load".into());
        self.fail_load.map_or(Ok(()), Err)
    }

    fn boot(&mut self) -> Result<(), Fail> {
        self.calls.push("boot".into());
        self.fail_boot.map_or(Ok(()), Err)
    }

    fn pause(&mut self) -> Result<(), Fail> {
        self.calls.push("pause".into());
        self.looks = 0;
        self.fail_pause.map_or(Ok(()), Err)
    }

    fn resume(&mut self) -> Result<(), Fail> {
        self.calls.push("resume".into());
        self.fail_resume.map_or(Ok(()), Err)
    }

    fn paused(&mut self) -> bool {
        self.looks += 1;
        self.looks > self.held_after
    }

    fn halt(&mut self) -> bool {
        self.calls.push("halt".into());
        !self.halt_ok_not
    }

    fn console(&mut self) -> Result<u32, Fail> {
        self.calls.push("console".into());
        match self.fail_console {
            Some(f) => Err(f),
            None => Ok(self.handle),
        }
    }

    fn log(&mut self, line: &[u8]) {
        self.log.extend_from_slice(line);
    }
}

fn created(ctl: &mut Control, m: &mut Model) {
    ctl.create(m, 0, 0, 0, b"K.ELF").unwrap();
    m.calls.clear();
}

// ── create ───────────────────────────────────────────────────────────────

#[test]
fn a_create_opens_builds_and_loads_in_that_order_and_leaves_the_machine_created() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    let r = ctl.create(&mut m, 0, 2, 128, b"guests/a-1.elf").unwrap();
    assert_eq!((r.id, r.cause, r.serial), (0, cause::NONE, 0));
    assert_eq!(m.calls, ["open guests/a-1.elf", "build 2 128", "load"]);
    let i = ctl.info(0).unwrap();
    assert_eq!((i.state, i.cpus, i.mem_mib), (STATE_CREATED, 2, 128), "the guest sees what it was asked for");
    }

#[test]
fn zero_means_what_the_row_declares() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap();
    assert_eq!(m.calls[1], "build 4 256");
    // The same row, as a boundary: exactly the ceiling is served.
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    ctl.create(&mut m, 0, 4, 256, b"K.ELF").unwrap();
    assert_eq!(m.calls[1], "build 4 256");
}

#[test]
fn a_guest_cannot_be_given_more_than_its_row_declares() {
    for (cpus, mem, want, ceiling) in [(5, 0, cause::OVER_CPUS, 4), (0, 257, cause::OVER_MEM, 256), (1000, 1, cause::OVER_CPUS, 4)] {
        let (mut ctl, mut m) = (Control::new(ROW), Model::default());
        let r = ctl.create(&mut m, 0, cpus, mem, b"K.ELF").unwrap_err();
        assert_eq!((r.cause, r.arg), (want, ceiling), "the receipt names the ceiling");
        assert!(m.calls.is_empty(), "nothing was opened or built for a request over the row: {:?}", m.calls);
        assert_eq!(ctl.info(0).unwrap().state, STATE_FREE);
    }
}

#[test]
fn a_row_the_monitor_does_not_serve_is_refused_with_the_count() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    let r = ctl.create(&mut m, ROWS, 0, 0, b"K.ELF").unwrap_err();
    assert_eq!((r.cause, r.arg, r.id), (cause::NO_SUCH_ROW, ROWS as u64, ROWS));
    assert!(m.calls.is_empty());
}

#[test]
fn an_image_name_that_climbs_or_is_absolute_is_refused_before_the_host_sees_it() {
    for bad in [
        &b""[..],
        b"/fat/VM/KERNEL.ELF",
        b"../KERNEL.ELF",
        b"a/../../b",
        b"a//b",
        b"a/./b",
        b"a/",
        b"a b",
        b"a\0b",
        b"caf\xc3\xa9.elf",
        &[b'x'; IMAGE_MAX + 1],
    ] {
        let (mut ctl, mut m) = (Control::new(ROW), Model::default());
        let r = ctl.create(&mut m, 0, 0, 0, bad).unwrap_err();
        assert_eq!(r.cause, cause::IMAGE_NAME, "{bad:?}");
        assert!(m.calls.is_empty(), "{bad:?} reached the host: {:?}", m.calls);
    }
    for good in [&b"KERNEL.ELF"[..], b"vm-2/k_1.elf", &[b'x'; IMAGE_MAX]] {
        assert!(image_ok(good), "{good:?}");
    }
}

#[test]
fn a_machine_already_built_is_not_built_again() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    created(&mut ctl, &mut m);
    let r = ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err();
    assert_eq!(r.cause, cause::NOT_FREE);
    ctl.start(&mut m, 0).unwrap();
    assert_eq!(ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err().cause, cause::NOT_FREE);
    assert!(!m.calls.iter().any(|c| c.starts_with("open") || c.starts_with("build")));
}

#[test]
fn a_create_that_fails_leaves_the_row_free_and_gives_back_what_it_built() {
    // The image cannot be opened: nothing was built.
    let (mut ctl, mut m) = (Control::new(ROW), Model { fail_open: Some(Fail::new(cause::IMAGE_OPEN, 0)), ..Model::default() });
    assert_eq!(ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err().cause, cause::IMAGE_OPEN);
    assert_eq!(m.calls, ["open K.ELF"]);
    // The machine cannot be built: it cleans up after itself.
    let (mut ctl, mut m) = (Control::new(ROW), Model { fail_build: Some(Fail::new(cause::BUILD, 2)), ..Model::default() });
    let r = ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err();
    assert_eq!((r.cause, r.arg), (cause::BUILD, 2));
    assert_eq!(m.calls, ["open K.ELF", "build 4 256"]);
    // The kernel is refused after the machine was built for it: given back.
    let (mut ctl, mut m) = (Control::new(ROW), Model { fail_load: Some(Fail::new(cause::IMAGE_REFUSED, 3)), ..Model::default() });
    let r = ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err();
    assert_eq!((r.cause, r.arg), (cause::IMAGE_REFUSED, 3));
    assert_eq!(m.calls, ["open K.ELF", "build 4 256", "load", "halt"]);
    m.fail_load = None;
    m.calls.clear();
    assert_eq!(ctl.info(0).unwrap().state, STATE_FREE);
    assert!(ctl.create(&mut m, 0, 0, 0, b"K.ELF").is_ok(), "the row can be tried again");
}

#[test]
fn a_create_whose_give_back_fails_keeps_the_row_built_and_stop_can_retry() {
    let (mut ctl, mut m) = (
        Control::new(ROW),
        Model { fail_load: Some(Fail::new(cause::IMAGE_REFUSED, 3)), halt_ok_not: true, ..Model::default() },
    );
    let r = ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err();
    assert_eq!((r.cause, r.arg), (cause::STOP_FAILED, cause::IMAGE_REFUSED as u64), "the receipt says both");
    assert_ne!(ctl.info(0).unwrap().state, STATE_FREE, "the machine is still held: the row is not free");
    m.fail_load = None;
    assert_eq!(ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err().cause, cause::NOT_FREE);
    // The give-back works this time, through the call a tool has.
    m.halt_ok_not = false;
    ctl.stop(&mut m, 0).unwrap();
    assert_eq!(ctl.info(0).unwrap().state, STATE_FREE);
    assert!(ctl.create(&mut m, 0, 0, 0, b"K.ELF").is_ok());
}

// ── start, stop, finished ────────────────────────────────────────────────

#[test]
fn a_guest_starts_once_and_only_after_it_is_created() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    assert_eq!(ctl.start(&mut m, 0).unwrap_err().cause, cause::NOT_CREATED);
    assert_eq!(ctl.start(&mut m, 1).unwrap_err().cause, cause::NO_SUCH_VM);
    created(&mut ctl, &mut m);
    ctl.start(&mut m, 0).unwrap();
    assert_eq!(ctl.info(0).unwrap().state, STATE_RUNNING);
    assert_eq!(ctl.start(&mut m, 0).unwrap_err().cause, cause::RUNNING);
    assert_eq!(m.calls, ["boot"], "the second start never reached the host");
}

#[test]
fn a_boot_cpu_the_kernel_refuses_leaves_the_guest_created_and_says_why() {
    let (mut ctl, mut m) = (Control::new(ROW), Model { fail_boot: Some(Fail::new(cause::START_REFUSED, 5)), ..Model::default() });
    created(&mut ctl, &mut m);
    let r = ctl.start(&mut m, 0).unwrap_err();
    assert_eq!((r.cause, r.arg), (cause::START_REFUSED, 5));
    assert_eq!(ctl.info(0).unwrap().state, STATE_CREATED);
    m.fail_boot = None;
    assert!(ctl.start(&mut m, 0).is_ok(), "it can be started once the kernel allows");
}

#[test]
fn a_stop_gives_the_machine_back_whether_it_was_created_or_running() {
    for run in [false, true] {
        let (mut ctl, mut m) = (Control::new(ROW), Model::default());
        created(&mut ctl, &mut m);
        if run {
            ctl.start(&mut m, 0).unwrap();
        }
        m.calls.clear();
        ctl.stop(&mut m, 0).unwrap();
        assert_eq!(m.calls, ["halt"]);
        let i = ctl.info(0).unwrap();
        assert_eq!((i.state, i.ended, i.cpus, i.mem_mib), (STATE_FREE, ENDED_STOPPED, 4, 256), "the row's numbers are back");
        assert_eq!(ctl.stop(&mut m, 0).unwrap_err().cause, cause::NOT_CREATED, "a second stop has nothing to stop");
    }
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    assert_eq!(ctl.stop(&mut m, 7).unwrap_err().cause, cause::NO_SUCH_VM);
}

#[test]
fn a_machine_that_cannot_be_given_back_is_reported_and_not_called_free() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    created(&mut ctl, &mut m);
    m.halt_ok_not = true;
    assert_eq!(ctl.stop(&mut m, 0).unwrap_err().cause, cause::STOP_FAILED);
    assert_ne!(ctl.info(0).unwrap().state, STATE_FREE, "the row is not offered again over a machine still held");
}

#[test]
fn a_guest_that_ends_by_itself_frees_the_row_and_records_how() {
    for (fault, ended) in [(false, ENDED_STOPPED), (true, ENDED_FAULTED)] {
        let (mut ctl, mut m) = (Control::new(ROW), Model::default());
        assert_eq!(ctl.info(0).unwrap().ended, ENDED_NEVER);
        created(&mut ctl, &mut m);
        ctl.start(&mut m, 0).unwrap();
        ctl.finished(fault);
        let i = ctl.info(0).unwrap();
        assert_eq!((i.state, i.ended), (STATE_FREE, ended));
        assert!(ctl.create(&mut m, 0, 0, 0, b"K.ELF").is_ok(), "and the row can be created again");
    }
}

#[test]
fn the_table_has_one_entry_per_row_served() {
    let ctl = Control::new(ROW);
    let i = ctl.info(0).unwrap();
    assert_eq!((i.id, i.state, i.cpus, i.mem_mib), (0, STATE_FREE, 4, 256));
    assert!(ctl.info(ROWS).is_none());
}

// ── receipts ─────────────────────────────────────────────────────────────

#[test]
fn every_refusal_is_counted_logged_and_receipted() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    let a = ctl.create(&mut m, 0, 9, 0, b"K.ELF").unwrap_err();
    let b = ctl.start(&mut m, 0).unwrap_err();
    assert_eq!((a.serial, b.serial), (1, 2));
    let ok = ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap();
    assert_eq!((ok.cause, ok.serial), (cause::NONE, 2), "a served call carries the refusals so far");
    let log = String::from_utf8(m.log.clone()).unwrap();
    assert!(log.contains("create refused: more CPUs than the row declares"), "{log}");
    assert!(log.contains("start refused: the VM holds no kernel"), "{log}");
    assert_eq!(log.matches('\n').count(), 2);
}

#[test]
fn a_cause_answers_with_the_outcome_its_kind_deserves() {
    assert_eq!(outcome_of(cause::NONE), outcome::OK);
    assert_eq!(outcome_of(cause::OVER_CPUS), outcome::REFUSED);
    assert_eq!(outcome_of(cause::OVER_MEM), outcome::REFUSED);
    assert_eq!(outcome_of(cause::IMAGE_NAME), outcome::BAD_ARGUMENT);
    assert_eq!(outcome_of(cause::NOT_FREE), outcome::BUSY);
    assert_eq!(outcome_of(cause::RUNNING), outcome::BUSY);
    assert_eq!(outcome_of(cause::NOT_CREATED), outcome::NOT_READY);
    assert_eq!(outcome_of(cause::NO_SUCH_VM), outcome::NO_RESOURCE);
    assert_eq!(outcome_of(cause::NO_SUCH_ROW), outcome::NO_RESOURCE);
    assert_eq!(outcome_of(cause::IMAGE_REFUSED), outcome::FAULT);
    assert_eq!(outcome_of(cause::BUILD), outcome::FAULT);
}

#[test]
fn a_refused_kernel_names_the_loader_error_in_its_receipt() {
    use crate::dtb::DtbError;
    use crate::pvh::PvhError;
    assert_eq!(refusal_code(&PrepareError::Kernel(LoadError::Read)), 1);
    assert_eq!(refusal_code(&PrepareError::Kernel(LoadError::NotElf)), 3);
    assert_eq!(refusal_code(&PrepareError::Kernel(LoadError::Machine)), 4);
    assert_eq!(refusal_code(&PrepareError::Kernel(LoadError::NoPvhEntry)), 11);
    assert_eq!(refusal_code(&PrepareError::Tree(DtbError::Full)), 12);
    assert_eq!(refusal_code(&PrepareError::Pvh(PvhError::Full)), 12);
    assert_eq!(refusal_code(&PrepareError::NoRoom), 13);
    // Distinct numbers for every loader error: a receipt tells them apart.
    let all = [
        LoadError::Read,
        LoadError::Truncated,
        LoadError::NotElf,
        LoadError::Machine,
        LoadError::Phdrs,
        LoadError::Loads,
        LoadError::BadSegment,
        LoadError::OutOfRam,
        LoadError::Overlap,
        LoadError::BadEntry,
        LoadError::NoPvhEntry,
    ];
    let codes: std::collections::BTreeSet<_> = all.iter().map(|e| refusal_code(&PrepareError::Kernel(*e))).collect();
    assert_eq!(codes.len(), all.len());
}

// ── autostart ────────────────────────────────────────────────────────────

#[test]
fn the_monitor_starts_the_volumes_kernel_through_the_same_calls_a_tool_makes() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    assert!(ctl.autostart(&mut m));
    assert_eq!(m.calls, [format!("open {}", String::from_utf8_lossy(DEFAULT_IMAGE)), "build 4 256".into(), "load".into(), "boot".into()]);
    assert_eq!(ctl.info(0).unwrap().state, STATE_RUNNING);
    // A volume without the kernel: nothing started, nothing left built.
    let (mut ctl, mut m) = (Control::new(ROW), Model { fail_open: Some(Fail::new(cause::IMAGE_OPEN, 0)), ..Model::default() });
    assert!(!ctl.autostart(&mut m));
    assert_eq!(ctl.info(0).unwrap().state, STATE_FREE);
}

// ── the interface, end to end ────────────────────────────────────────────

/// The generated client against the generated dispatch, with the table and
/// the model behind it.
struct Loop<'a> {
    ctl: &'a RefCell<Control>,
    host: &'a RefCell<Model>,
}

impl Transport for Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
        let req = *msg;
        let mut rep = MsgDesc::default();
        let (mut ctl, mut host) = (self.ctl.borrow_mut(), self.host.borrow_mut());
        let mut svc = Bound { ctl: &mut ctl, host: &mut *host, ring_rights: 0x3 };
        let _ = VmCtlIdl::dispatch(&mut svc, &req, &mut rep);
        *msg = rep;
        Ok(())
    }
}

#[test]
fn the_calls_reach_the_table_and_the_answers_come_back_typed() {
    let (ctl, host) = (RefCell::new(Control::new(ROW)), RefCell::new(Model { handle: 77, ..Model::default() }));
    let mut c = VmCtlClient::new(Loop { ctl: &ctl, host: &host });

    let l = c.list(0).unwrap();
    assert!(l.is_ok());
    assert_eq!((l.value.state, l.value.cpus, l.value.mem_mib), (STATE_FREE, 4, 256));
    assert_eq!(c.list(1).unwrap().code, outcome::NO_RESOURCE);

    let image = ImageName::pack(b"KERNEL.ELF").unwrap();
    let r = c.create(0, 2, 64, image).unwrap();
    assert!(r.is_ok());
    assert_eq!(host.borrow().calls, ["open KERNEL.ELF", "build 2 64", "load"]);
    assert_eq!(c.list(0).unwrap().value.state, STATE_CREATED);

    // A refusal is an outcome with the receipt in the value.
    let over = c.create(0, 0, 0, image).unwrap();
    assert_eq!((over.code, over.value.cause), (outcome::BUSY, cause::NOT_FREE));
    let big = {
        c.stop(0).unwrap();
        c.create(0, 0, 4096, image).unwrap()
    };
    assert_eq!((big.code, big.value.cause, big.value.arg), (outcome::REFUSED, cause::OVER_MEM, 256));
    assert_eq!(big.value.serial, 2, "the serial counts refusals across calls");

    c.create(0, 0, 0, image).unwrap();
    assert!(c.start(0).unwrap().is_ok());
    assert_eq!(c.list(0).unwrap().value.state, STATE_RUNNING);

    // The console lends the ring the host made, with the rights the server was given.
    let lease: ConsoleLease = c.console(0).unwrap().value;
    assert_eq!(lease.receipt.cause, cause::NONE);
    assert!(lease.ring.get().is_some(), "a ring was lent");
    assert!(c.stop(0).unwrap().is_ok());
    let none = c.console(0).unwrap();
    assert_eq!((none.code, none.value.receipt.cause), (outcome::NOT_READY, cause::NOT_CREATED));
    assert!(none.value.ring.get().is_none(), "nothing is lent with a refusal");
}

#[test]
fn an_image_name_round_trips_and_an_unfit_one_is_not_packed() {
    let n = ImageName::pack(b"guests/linux.elf").unwrap();
    let mut out = [0u8; IMAGE_MAX];
    let len = n.unpack(&mut out);
    assert_eq!(&out[..len], b"guests/linux.elf");
    assert!(ImageName::pack(b"").is_none());
    assert!(ImageName::pack(&[b'a'; IMAGE_MAX + 1]).is_none());
    let full = ImageName::pack(&[b'a'; IMAGE_MAX]).unwrap();
    assert_eq!(full.unpack(&mut out), IMAGE_MAX);
}

// ── the mailbox ──────────────────────────────────────────────────────────

struct Spin {
    monitor_woken: AtomicBool,
}

impl Wake for Spin {
    fn wake_monitor(&self) {
        self.monitor_woken.store(true, Ordering::SeqCst);
    }

    fn park(&self, word: &AtomicU32, seen: u32) {
        while word.load(Ordering::Acquire) == seen {
            std::thread::yield_now();
        }
    }

    fn unpark(&self, _word: &AtomicU32) {}
}

#[test]
fn the_service_thread_posts_the_loop_runs_it_and_the_answer_comes_back() {
    static BOX: Mailbox = Mailbox::new();
    let w = Arc::new(Spin { monitor_woken: AtomicBool::new(false) });
    assert!(BOX.take().is_none(), "nothing is pending at first");
    let svc = {
        let w = w.clone();
        std::thread::spawn(move || {
            let mut sum = 0u64;
            for i in 0..200u64 {
                let mut req = MsgDesc::default();
                req.words[0] = i;
                req.badge = 9;
                let rep = BOX.call(&*w, &req);
                assert_eq!(rep.words[0], i * 2 + 1);
                sum += rep.words[0];
            }
            sum
        })
    };
    let mut served = 0;
    while served < 200 {
        if let Some(req) = BOX.take() {
            assert_eq!(req.badge, 9);
            let mut rep = MsgDesc::default();
            rep.words[0] = req.words[0] * 2 + 1;
            BOX.answer(&*w, &rep);
            served += 1;
        } else {
            std::thread::yield_now();
        }
    }
    assert_eq!(svc.join().unwrap(), (0..200u64).map(|i| i * 2 + 1).sum::<u64>());
    assert!(w.monitor_woken.load(Ordering::SeqCst), "each post wakes the loop that sleeps on the trap port");
    assert!(BOX.take().is_none(), "and the box is empty again");
}

// ── the console ring ─────────────────────────────────────────────────────

#[derive(Default)]
struct Console {
    out: Vec<u8>,
}

impl Term for Console {
    fn write(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
}

#[repr(align(64))]
struct Region([u8; 8192]);

fn ring(region: &mut Box<Region>) -> SpscStream {
    let r = SpscStream { base: region.0.as_mut_ptr() as usize, cap: azos_devif::vmctl::CONSOLE_RING_CAP };
    assert!(SpscStream::bytes(r.cap) <= azos_devif::vmctl::CONSOLE_RING_PAGES as usize * 4096);
    r.init();
    r
}

#[test]
fn the_guests_output_goes_to_the_ring_once_one_is_attached_and_to_the_console_before() {
    let (mut a, mut b) = (Box::new(Region([0; 8192])), Box::new(Region([0; 8192])));
    let mut sink = Sink::new(Console::default());
    sink.write(b"before ");
    let first = ring(&mut a);
    sink.attach(first);
    sink.write(b"[vm0] hello\n");
    let mut got = [0u8; 64];
    let (n, _) = first.read(&mut got);
    assert_eq!(&got[..n], b"[vm0] hello\n");
    assert_eq!(sink.inner.out, b"before ", "nothing reached the console while a ring held the output");
    // A second tool takes over: the first ring is no longer written.
    let second = ring(&mut b);
    let old = sink.attach(second).expect("the first ring comes back");
    assert_eq!((old.ring.base, old.lost), (first.base, 0));
    sink.write(b"more");
    assert_eq!((first.len(), second.len()), (0, 4));
    assert_eq!(sink.read(&mut got), 0, "the guest has no input");
    // Detached, the output is the operator's again, and no ring is written.
    let last = sink.detach().expect("the second ring comes back");
    assert_eq!(last.ring.base, second.base);
    assert!(sink.detach().is_none());
    sink.write(b"after");
    assert_eq!((second.len(), sink.inner.out.ends_with(b"after")), (4, true));
}

#[test]
fn a_closed_ring_tells_its_holder_after_the_last_byte_it_will_get() {
    use azos_devif::vmctl::ConsoleRing;
    let mut region = Box::new(Region([0; 8192]));
    let r = ring(&mut region);
    let mut sink = Sink::new(Console::default());
    sink.attach(r);
    sink.write(b"last words");
    assert!(!ConsoleRing::closed(r.base), "a quiet guest is not a closed ring");
    ConsoleRing::close(sink.detach().unwrap().ring.base);
    assert!(ConsoleRing::closed(r.base));
    let mut got = [0u8; 32];
    let (n, _) = r.read(&mut got);
    assert_eq!(&got[..n], b"last words", "what came before the close is still there to drain");
}

#[test]
fn a_holder_that_does_not_drain_loses_bytes_the_sink_counts_and_never_blocks() {
    let mut region = Box::new(Region([0; 8192]));
    let r = ring(&mut region);
    let mut sink = Sink::new(Console::default());
    sink.attach(r);
    let chunk = [b'x'; 1000];
    for _ in 0..6 {
        sink.write(&chunk);
    }
    assert_eq!(r.len(), azos_devif::vmctl::CONSOLE_RING_CAP, "the ring holds what fits");
    let retired = sink.detach().unwrap();
    assert_eq!(retired.lost, 6000 - azos_devif::vmctl::CONSOLE_RING_CAP as u64, "the ring comes back with its count");
    sink.attach(r);
    let mut buf = vec![0u8; 8192];
    let (n, _) = r.read(&mut buf);
    assert_eq!(n, azos_devif::vmctl::CONSOLE_RING_CAP as usize);
    sink.write(b"again");
    assert_eq!(r.len(), 5, "and the ring takes bytes again once drained");
}

// ── a smaller guest ──────────────────────────────────────────────────────

struct Flat {
    base: u64,
    bytes: Vec<u8>,
}

impl GuestMem for Flat {
    fn range(&self) -> (u64, u64) {
        (self.base, self.bytes.len() as u64)
    }

    fn read(&self, gpa: u64, out: &mut [u8]) -> Result<(), crate::guest::OutOfRam> {
        let at = (gpa - self.base) as usize;
        out.copy_from_slice(&self.bytes[at..at + out.len()]);
        Ok(())
    }

    fn write(&mut self, gpa: u64, data: &[u8]) -> Result<(), crate::guest::OutOfRam> {
        let at = (gpa - self.base) as usize;
        self.bytes[at..at + data.len()].copy_from_slice(data);
        Ok(())
    }
}

#[test]
fn a_guest_asked_for_less_memory_sees_a_prefix_and_nothing_past_it() {
    let mut full = Flat { base: 0x8000_0000, bytes: vec![0; 1 << 20] };
    let mut view = Limited::new(&mut full, 0x1_0000);
    assert_eq!(view.range(), (0x8000_0000, 0x1_0000));
    assert!(view.write(0x8000_0000 + 0xFFF8, &[1; 8]).is_ok());
    assert!(view.write(0x8000_0000 + 0xFFF9, &[1; 8]).is_err(), "a write across the end of the view is refused");
    assert!(view.write(0x8000_0000 + 0x2_0000, &[1]).is_err());
    let mut b = [0u8; 1];
    assert!(view.read(0x8000_0000 + 0x1_0000, &mut b).is_err());
    assert!(!view.contains(0x8000_0000, 0x1_0001));
    // Asking for more than there is gives all there is.
    let mut small = Flat { base: 0, bytes: vec![0; 4096] };
    assert_eq!(Limited::new(&mut small, 1 << 30).range().1, 4096);
    assert_eq!(full.bytes[0xFFF8..0x1_0000], [1; 8], "what was written inside went through");
    assert!(full.bytes[0x1_0000..].iter().all(|&b| b == 0), "nothing was written past the view");
}

// ── pause and resume ─────────────────────────────────────────────────────

fn running(ctl: &mut Control, m: &mut Model) {
    created(ctl, m);
    ctl.start(m, 0).unwrap();
    m.calls.clear();
}

#[test]
fn a_pause_holds_the_running_guest_and_the_table_says_when_every_vcpu_took_it() {
    let (mut ctl, mut m) = (Control::new(ROW), Model { held_after: 2, ..Model::default() });
    running(&mut ctl, &mut m);
    let r = ctl.pause(&mut m, 0).unwrap();
    assert_eq!((r.id, r.cause), (0, cause::NONE));
    assert_eq!(m.calls, ["pause"]);
    assert_eq!(ctl.info(0).unwrap().state, STATE_PAUSING, "asked, not yet taken by every vCPU");
    ctl.settle(&mut m);
    assert_eq!(ctl.info(0).unwrap().state, STATE_PAUSING, "one more look");
    ctl.settle(&mut m);
    assert_eq!(ctl.info(0).unwrap().state, STATE_PAUSED);
    let looks = m.looks;
    ctl.settle(&mut m);
    assert_eq!(m.looks, looks, "a settled table does not look again");
}

#[test]
fn a_pause_every_vcpu_has_already_taken_is_paused_at_once() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    running(&mut ctl, &mut m);
    ctl.pause(&mut m, 0).unwrap();
    assert_eq!(ctl.info(0).unwrap().state, STATE_PAUSED);
}

#[test]
fn a_resume_lets_a_held_guest_run_on_and_cancels_a_hold_not_yet_taken() {
    for taken in [true, false] {
        let (mut ctl, mut m) = (Control::new(ROW), Model { held_after: if taken { 0 } else { 99 }, ..Model::default() });
        running(&mut ctl, &mut m);
        ctl.pause(&mut m, 0).unwrap();
        assert_eq!(ctl.info(0).unwrap().state, if taken { STATE_PAUSED } else { STATE_PAUSING });
        let r = ctl.resume(&mut m, 0).unwrap();
        assert_eq!(r.cause, cause::NONE);
        assert_eq!(m.calls, ["pause", "resume"]);
        assert_eq!(ctl.info(0).unwrap().state, STATE_RUNNING);
        ctl.settle(&mut m);
        assert_eq!(ctl.info(0).unwrap().state, STATE_RUNNING, "a cancelled hold does not settle");
        // And it can be held again.
        assert!(ctl.pause(&mut m, 0).is_ok());
    }
}

#[test]
fn a_pause_that_cannot_be_served_is_refused_with_a_receipt_that_names_why() {
    // Nothing built.
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    let r = ctl.pause(&mut m, 0).unwrap_err();
    assert_eq!((r.cause, r.serial), (cause::NOT_CREATED, 1));
    // Built, nothing running: nothing to hold.
    created(&mut ctl, &mut m);
    let r = ctl.pause(&mut m, 0).unwrap_err();
    assert_eq!((r.cause, r.serial), (cause::NOT_RUNNING, 2));
    // Held twice.
    ctl.start(&mut m, 0).unwrap();
    m.calls.clear();
    ctl.pause(&mut m, 0).unwrap();
    let r = ctl.pause(&mut m, 0).unwrap_err();
    assert_eq!((r.cause, r.serial), (cause::ALREADY_PAUSED, 3));
    assert_eq!(m.calls, ["pause"], "the kernel was asked once");
    assert_eq!(ctl.info(0).unwrap().state, STATE_PAUSED, "a refusal changes nothing");
    // A VM the monitor does not serve.
    let r = ctl.pause(&mut m, ROWS).unwrap_err();
    assert_eq!(r.cause, cause::NO_SUCH_VM);
    // The kernel refusing a vCPU leaves the guest running.
    let (mut ctl, mut m) = (Control::new(ROW), Model { fail_pause: Some(Fail::new(cause::PAUSE_REFUSED, 7)), ..Model::default() });
    running(&mut ctl, &mut m);
    let r = ctl.pause(&mut m, 0).unwrap_err();
    assert_eq!((r.cause, r.arg), (cause::PAUSE_REFUSED, 7));
    assert_eq!(ctl.info(0).unwrap().state, STATE_RUNNING);
}

#[test]
fn a_resume_that_cannot_be_served_is_refused_with_a_receipt_that_names_why() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    assert_eq!(ctl.resume(&mut m, 0).unwrap_err().cause, cause::NOT_CREATED);
    created(&mut ctl, &mut m);
    assert_eq!(ctl.resume(&mut m, 0).unwrap_err().cause, cause::NOT_PAUSED);
    ctl.start(&mut m, 0).unwrap();
    assert_eq!(ctl.resume(&mut m, 0).unwrap_err().cause, cause::NOT_PAUSED, "a running guest is not held");
    assert_eq!(ctl.resume(&mut m, ROWS).unwrap_err().cause, cause::NO_SUCH_VM);
    assert!(!m.calls.contains(&"resume".to_string()), "the kernel was never asked");
    // The kernel refusing leaves it held.
    let (mut ctl, mut m) = (Control::new(ROW), Model { fail_resume: Some(Fail::new(cause::PAUSE_REFUSED, 3)), ..Model::default() });
    running(&mut ctl, &mut m);
    ctl.pause(&mut m, 0).unwrap();
    let r = ctl.resume(&mut m, 0).unwrap_err();
    assert_eq!((r.cause, r.arg), (cause::PAUSE_REFUSED, 3));
    assert_eq!(ctl.info(0).unwrap().state, STATE_PAUSED);
}

#[test]
fn a_held_guest_is_still_running_for_a_start_and_a_stop_ends_it() {
    let (mut ctl, mut m) = (Control::new(ROW), Model::default());
    running(&mut ctl, &mut m);
    ctl.pause(&mut m, 0).unwrap();
    assert_eq!(ctl.start(&mut m, 0).unwrap_err().cause, cause::RUNNING);
    assert_eq!(ctl.create(&mut m, 0, 0, 0, b"K.ELF").unwrap_err().cause, cause::NOT_FREE);
    ctl.stop(&mut m, 0).unwrap();
    assert_eq!(ctl.info(0).unwrap().state, STATE_FREE);
    assert_eq!(ctl.info(0).unwrap().ended, ENDED_STOPPED);
    // The console of a held guest is lent like any other.
    let (mut ctl, mut m) = (Control::new(ROW), Model { handle: 5, ..Model::default() });
    running(&mut ctl, &mut m);
    ctl.pause(&mut m, 0).unwrap();
    assert!(ctl.console(&mut m, 0, 3).is_ok());
}

#[test]
fn the_refusal_causes_of_a_pause_answer_the_outcomes_a_caller_can_tell_apart() {
    assert_eq!(outcome_of(cause::ALREADY_PAUSED), outcome::BUSY);
    assert_eq!(outcome_of(cause::NOT_RUNNING), outcome::NOT_READY);
    assert_eq!(outcome_of(cause::NOT_PAUSED), outcome::NOT_READY);
    assert_eq!(outcome_of(cause::PAUSE_REFUSED), outcome::FAULT);
    for c in [cause::NOT_RUNNING, cause::ALREADY_PAUSED, cause::NOT_PAUSED, cause::PAUSE_REFUSED] {
        assert_ne!(cause::text(c), cause::text(u32::MAX), "cause {c} has a text of its own");
    }
}

#[test]
fn the_pause_and_the_resume_reach_the_table_through_the_interface() {
    let (ctl, host) = (RefCell::new(Control::new(ROW)), RefCell::new(Model::default()));
    let mut c = VmCtlClient::new(Loop { ctl: &ctl, host: &host });
    let image = ImageName::pack(b"KERNEL.ELF").unwrap();
    let none = c.pause(0).unwrap();
    assert_eq!((none.code, none.value.cause), (outcome::NOT_READY, cause::NOT_CREATED));
    c.create(0, 0, 0, image).unwrap();
    assert!(c.start(0).unwrap().is_ok());
    assert!(c.pause(0).unwrap().is_ok());
    assert_eq!(c.list(0).unwrap().value.state, STATE_PAUSED);
    let again = c.pause(0).unwrap();
    assert_eq!((again.code, again.value.cause), (outcome::BUSY, cause::ALREADY_PAUSED));
    assert_eq!(again.value.serial, 2, "the serial counts every refusal");
    assert!(c.resume(0).unwrap().is_ok());
    assert_eq!(c.list(0).unwrap().value.state, STATE_RUNNING);
    let not = c.resume(0).unwrap();
    assert_eq!((not.code, not.value.cause), (outcome::NOT_READY, cause::NOT_PAUSED));
}

// ── the vCPUs behind it ──────────────────────────────────────────────────

/// A vCPU endpoint of the kernel's: its state word, and what `pause` and
/// `resume` answer.
#[derive(Default)]
struct Cpu {
    state: Option<u64>,
    /// `pause` answers this (`None`: success, the thread takes the hold after
    /// `takes` looks).
    refuse_pause: Option<u32>,
    refuse_resume: Option<u32>,
    asked: u32,
    released: u32,
}

impl Cpu {
    fn on() -> Option<Cpu> {
        Some(Cpu { state: Some(RUN_RUNNING), ..Cpu::default() })
    }
}

impl Holder for Cpu {
    fn state(&mut self) -> Option<u64> {
        self.state
    }

    fn pause(&mut self) -> Result<(), u32> {
        self.asked += 1;
        match self.refuse_pause {
            Some(code) => Err(code),
            // The kernel refuses a second ask, as `Vcpu::pause` does.
            None if self.state.is_some_and(|s| s & RUN_PAUSED != 0) => Err(outcome::BUSY),
            None => {
                // The thread takes the hold at its next look: model it as taken.
                self.state = Some(RUN_RUNNING | RUN_PAUSED);
                Ok(())
            }
        }
    }

    fn resume(&mut self) -> Result<(), u32> {
        self.released += 1;
        match self.refuse_resume {
            Some(code) => Err(code),
            None if self.state.is_some_and(|s| s & RUN_PAUSED == 0) => Err(outcome::BUSY),
            None => {
                self.state = Some(RUN_RUNNING);
                Ok(())
            }
        }
    }
}

#[test]
fn every_vcpu_that_runs_is_asked_and_the_ones_that_do_not_are_left_alone() {
    let mut cpus = [Cpu::on(), Some(Cpu { state: Some(RUN_STOPPED), ..Cpu::default() }), None, Cpu::on()];
    pause_all(&mut cpus, 4).unwrap();
    let asked: Vec<u32> = cpus.iter().map(|c| c.as_ref().map_or(0, |c| c.asked)).collect();
    assert_eq!(asked, [1, 0, 0, 1], "a stopped vCPU and a missing endpoint are not asked");
    assert!(all_held(&mut cpus, 4));
    // Asking again asks nobody: the ones that hold it are skipped.
    pause_all(&mut cpus, 4).unwrap();
    assert_eq!(cpus[0].as_ref().unwrap().asked, 1);
    // Only the first `count` are the guest's.
    let mut cpus = [Cpu::on(), Cpu::on()];
    pause_all(&mut cpus, 1).unwrap();
    assert_eq!(cpus[1].as_ref().unwrap().asked, 0);
}

#[test]
fn a_vcpu_the_kernel_refuses_releases_the_ones_asked_before_it() {
    let mut cpus = [Cpu::on(), Cpu::on(), Some(Cpu { refuse_pause: Some(outcome::REFUSED), ..Cpu { state: Some(RUN_RUNNING), ..Cpu::default() } })];
    let f = pause_all(&mut cpus, 3).unwrap_err();
    assert_eq!((f.cause, f.arg), (cause::PAUSE_REFUSED, outcome::REFUSED as u64));
    assert_eq!(cpus[0].as_ref().unwrap().released, 1);
    assert_eq!(cpus[1].as_ref().unwrap().released, 1);
    assert!(cpus[0].as_ref().unwrap().state.is_some_and(|s| s & RUN_PAUSED == 0), "none is left half held");
}

#[test]
fn a_vcpu_that_was_already_asked_is_not_a_refusal() {
    // Busy: the kernel says a pause is asked and not yet taken.
    let mut cpus = [Some(Cpu { refuse_pause: Some(outcome::BUSY), ..Cpu { state: Some(RUN_RUNNING), ..Cpu::default() } })];
    assert!(pause_all(&mut cpus, 1).is_ok());
}

#[test]
fn the_table_is_not_paused_while_a_vcpu_still_enters_and_the_late_one_is_asked() {
    let mut cpus = [Cpu::on(), Some(Cpu { state: Some(RUN_STOPPED), ..Cpu::default() })];
    pause_all(&mut cpus, 2).unwrap();
    assert!(all_held(&mut cpus, 2));
    // The guest starts its second vCPU after the pause was asked.
    cpus[1].as_mut().unwrap().state = Some(RUN_RUNNING);
    assert!(!all_held(&mut cpus, 2), "a vCPU that runs does not hold the guest");
    assert_eq!(cpus[1].as_ref().unwrap().asked, 1, "and is asked");
    assert!(all_held(&mut cpus, 2), "the next look finds it held");
    // A vCPU that cannot be reached counts as not running: it blocks nothing.
    cpus[1].as_mut().unwrap().state = None;
    assert!(all_held(&mut cpus, 2));
}

#[test]
fn a_resume_goes_on_past_a_refusal_and_reports_the_first() {
    let mut cpus = [
        Some(Cpu { state: Some(RUN_RUNNING | RUN_PAUSED), refuse_resume: Some(outcome::REFUSED), ..Cpu::default() }),
        Some(Cpu { state: Some(RUN_RUNNING | RUN_PAUSED), ..Cpu::default() }),
        Some(Cpu { state: Some(RUN_RUNNING), ..Cpu::default() }),
    ];
    let f = resume_all(&mut cpus, 3).unwrap_err();
    assert_eq!((f.cause, f.arg), (cause::PAUSE_REFUSED, outcome::REFUSED as u64));
    assert_eq!(cpus[1].as_ref().unwrap().state, Some(RUN_RUNNING), "the others were released all the same");
    // The vCPU that was not held answers BUSY: not a failure.
    let mut cpus = [Cpu::on()];
    assert!(resume_all(&mut cpus, 1).is_ok());
}

/// `make azos-guest` puts the guest kernel on the host volume under the name the
/// monitor starts at boot (`/fat/VM/` + [`DEFAULT_IMAGE`]), as an ELF: a text
/// check of mk/images.mk, the one place that packs the volume.
#[test]
fn the_guest_volume_carries_the_image_the_monitor_starts() {
    let mk = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../mk/images.mk")).unwrap();
    let name = String::from_utf8_lossy(DEFAULT_IMAGE);
    assert!(mk.contains(&format!("::VM/{name}\n")), "the volume has no VM/{name}");
    assert!(!mk.contains("::VM/GUEST.BIN"), "a flat image the monitor never loads");
}
