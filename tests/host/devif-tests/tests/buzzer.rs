// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Buzzer` interface: its wire form, its op table and the two stubs
//! agreeing, which is what lets one caller serve both placements.

use azos_devif::buzzer::{ENDPOINT, ENDPOINT_NAME};
use azos_devif::{outcome, Buzzer, BuzzerCall, BuzzerClient, BuzzerDirect, BuzzerIdl, BuzzerPlaced, Out, BUZZER_ID};
use azos_idl::{header, IdlError, MsgDesc, Result as IdlResult, Transport};
use std::cell::{Cell, RefCell};

/// A buzzer that remembers what it was asked.
#[derive(Default)]
struct Log(Vec<(&'static str, u32, u32)>);

impl Buzzer for Log {
    fn tone(&mut self, freq_hz: u32, ms: u32) -> Out<()> { self.0.push(("tone", freq_hz, ms)); Out::ok(()) }
    fn on(&mut self, freq_hz: u32) -> Out<()> { self.0.push(("on", freq_hz, 0)); Out::ok(()) }
    fn off(&mut self) -> Out<()> { self.0.push(("off", 0, 0)); Out::ok(()) }
    fn beep(&mut self) -> Out<()> { self.0.push(("beep", 0, 0)); Out::ok(()) }
    fn alert(&mut self) -> Out<()> { self.0.push(("alert", 0, 0)); Out::err(outcome::FAULT) }
    fn startup(&mut self) -> Out<()> { self.0.push(("startup", 0, 0)); Out::ok(()) }
}

/// The ring-3 host as the test sees it: the generated dispatcher over a `Log`.
struct Loop<'a> {
    server: &'a RefCell<Log>,
    sent: Cell<u32>,
    last: RefCell<MsgDesc>,
}
impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        self.sent.set(self.sent.get() + 1);
        let req = *msg;
        *self.last.borrow_mut() = req;
        let _ = BuzzerIdl::dispatch(&mut *self.server.borrow_mut(), &req, msg);
        Ok(())
    }
}

/// Every op is idempotent (a caller whose call a move between hosts lost may
/// ask again), the table is the trait in order, and a request fits the four
/// register words.
///
/// **Canary.** Drop `#[idempotent]` from `startup`: the flag assertion is red.
#[test]
fn the_op_table_is_the_trait_and_every_op_may_be_asked_again() {
    let names: Vec<&str> = BuzzerIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["tone", "on", "off", "beep", "alert", "startup"]);
    for (i, o) in BuzzerIdl::OPS.iter().enumerate() {
        assert_eq!(o.op as usize, i + 1);
        assert!(o.idempotent() && o.retry_safe(), "{} may not be retried", o.name);
        assert!(o.req_words <= 4 && o.rep_words <= 4 && o.req_caps == 0 && o.rep_caps == 0, "{}", o.name);
    }
    assert_eq!(BuzzerIdl::ID, BUZZER_ID);
}

/// The request is the header and the arguments; the reply is the status and
/// the outcome code.
#[test]
fn the_wire_form_is_header_then_arguments() {
    let log = RefCell::new(Log::default());
    let lp = Loop { server: &log, sent: Cell::new(0), last: RefCell::new(MsgDesc::default()) };
    let mut c = BuzzerClient::new(&lp);
    assert_eq!(c.tone(440, 50), Ok(Out::ok(())));
    let r = *lp.last.borrow();
    assert_eq!((r.n_words, r.n_caps), (3, 0));
    assert_eq!(r.words[0], header(BUZZER_ID, 1, BuzzerIdl::OP_TONE));
    assert_eq!((r.words[1], r.words[2]), (440, 50));
    assert_eq!(c.alert(), Ok(Out::err(outcome::FAULT)), "the outcome travels in the reply");
    assert_eq!(log.borrow().0, [("tone", 440, 50), ("alert", 0, 0)]);
}

/// One `BuzzerPlaced` is either host: the same calls reach the same
/// implementation whether it is in this address space or behind a message.
#[test]
fn the_placed_stub_reaches_the_same_driver_in_either_host() {
    fn all<C: BuzzerCall>(c: &mut C) -> Result<(), IdlError> {
        c.tone(1000, 50)?;
        c.on(440)?;
        c.off()?;
        c.beep()?;
        c.startup()?;
        Ok(())
    }
    let want = [("tone", 1000, 50), ("on", 440, 0), ("off", 0, 0), ("beep", 0, 0), ("startup", 0, 0)];

    let mut direct: BuzzerPlaced<Log, &Loop> = BuzzerPlaced::Direct(BuzzerDirect(Log::default()));
    all(&mut direct).unwrap();
    match &direct {
        BuzzerPlaced::Direct(d) => assert_eq!(d.0 .0, want),
        _ => unreachable!(),
    }

    let log = RefCell::new(Log::default());
    let lp = Loop { server: &log, sent: Cell::new(0), last: RefCell::new(MsgDesc::default()) };
    let mut ep: BuzzerPlaced<Log, &Loop> = BuzzerPlaced::Endpoint(BuzzerClient::new(&lp));
    all(&mut ep).unwrap();
    assert_eq!(log.borrow().0, want);
    assert_eq!(lp.sent.get(), 5, "one message per call");
}

/// The kernel finds the endpoint by the name a topology grant `endpoint.<name>`
/// gives it in the pool (`cap_seed::declare_topology_endpoint` strips the
/// prefix): the two spellings are one name.
///
/// **Canary.** Change `ENDPOINT_NAME`: red. A kernel that asked the pool for the
/// full dotted spelling would create a second endpoint nobody serves.
#[test]
fn the_pool_name_is_the_topology_name_without_its_prefix() {
    assert_eq!(ENDPOINT.strip_prefix("endpoint."), Some(ENDPOINT_NAME));
    assert!(ENDPOINT_NAME.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'));
    assert!(ENDPOINT_NAME.len() <= 24, "ENDPOINT_NAME_MAX");
}
