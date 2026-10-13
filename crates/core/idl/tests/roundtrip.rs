// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Round trips through a loopback transport, the op table, and the attribute
//! flags, on the real expansion.

use azos_idl::*;
use std::cell::{Cell, RefCell};

pub struct Console;
pub struct Motor;

#[azos_interface(id = 0x4D54_0001, level = 2)]
pub trait Calc {
    fn add(&mut self, a: u32, b: u32) -> u32;
    #[idempotent]
    fn neg(&self, v: i32) -> i32;
    #[at_most_once]
    fn mix(&mut self, flag: bool, small: i8, wide: i64, ratio: f32, exact: f64) -> u64;
    #[once_only]
    fn actuate(&mut self, motor: Cap<Motor>, duty: [u8; 3]) -> [u16; 2];
    fn nothing(&mut self);
    fn swap_caps(&mut self, a: Cap<Console>, b: Cap<Console>) -> Cap<Console>;
}

#[derive(Default)]
struct CalcImpl {
    calls: u32,
    seen_motor: Option<u32>,
}

impl Calc for CalcImpl {
    fn add(&mut self, a: u32, b: u32) -> u32 {
        self.calls += 1;
        a.wrapping_add(b)
    }
    fn neg(&self, v: i32) -> i32 { v.wrapping_neg() }
    fn mix(&mut self, flag: bool, small: i8, wide: i64, ratio: f32, exact: f64) -> u64 {
        self.calls += 1;
        (flag as u64).wrapping_add(small as i64 as u64).wrapping_add(wide as u64).wrapping_add(ratio.to_bits() as u64).wrapping_add(exact.to_bits())
    }
    fn actuate(&mut self, motor: Cap<Motor>, duty: [u8; 3]) -> [u16; 2] {
        self.seen_motor = Some(motor.raw());
        [duty[0] as u16 * 2, duty[1] as u16 + duty[2] as u16]
    }
    fn nothing(&mut self) { self.calls += 1; }
    fn swap_caps(&mut self, a: Cap<Console>, _b: Cap<Console>) -> Cap<Console> { a }
}

/// A loopback: the "kernel" is the dispatcher, the message the real MsgDesc.
struct Loopback {
    server: RefCell<CalcImpl>,
    last_req: RefCell<MsgDesc>,
    calls: Cell<u32>,
}
impl Loopback {
    fn new() -> Self {
        Loopback { server: RefCell::new(CalcImpl::default()), last_req: RefCell::new(MsgDesc::default()), calls: Cell::new(0) }
    }
}
impl Transport for &Loopback {
    fn call(&self, msg: &mut MsgDesc) -> Result {
        self.calls.set(self.calls.get() + 1);
        let req = *msg;
        *self.last_req.borrow_mut() = req;
        let _ = CalcIdl::dispatch(&mut *self.server.borrow_mut(), &req, msg);
        Ok(())
    }
}

#[test]
fn round_trip_every_shape() {
    let lb = Loopback::new();
    let mut c = CalcClient::new(&lb);
    assert_eq!(c.add(40, 2), Ok(42));
    assert_eq!(c.add(u32::MAX, 1), Ok(0));
    assert_eq!(c.neg(-7), Ok(7));
    assert_eq!(c.neg(i32::MIN), Ok(i32::MIN));
    assert_eq!(
        c.mix(true, -3, -5_000_000_000, 1.5, -2.25),
        Ok(1u64.wrapping_add((-3i64) as u64).wrapping_add((-5_000_000_000i64) as u64).wrapping_add(1.5f32.to_bits() as u64).wrapping_add((-2.25f64).to_bits()))
    );
    assert_eq!(c.actuate(Cap::from_raw(77), [10, 20, 30]), Ok([20, 50]));
    assert_eq!(lb.server.borrow().seen_motor, Some(77));
    assert_eq!(c.nothing(), Ok(()));
    assert_eq!(c.swap_caps(Cap::from_raw(5), Cap::from_raw(6)), Ok(Cap::from_raw(5)));
    assert_eq!(lb.calls.get(), 8);
}

#[test]
fn direct_stub_agrees_with_the_client_stub() {
    let lb = Loopback::new();
    let mut via_msg = CalcClient::new(&lb);
    let mut direct = CalcDirect(CalcImpl::default());
    for (a, b) in [(0u32, 0u32), (1, 2), (u32::MAX, u32::MAX), (7, 0xFFFF_0000)] {
        assert_eq!(via_msg.add(a, b), direct.add(a, b));
    }
    for v in [0i32, -1, 5, i32::MIN, i32::MAX] {
        assert_eq!(via_msg.neg(v), direct.neg(v));
    }
    assert_eq!(via_msg.nothing(), direct.nothing());
    // Generic code does not know the placement.
    fn use_it<C: CalcCall>(c: &mut C) -> Result<u32> { c.add(20, 22) }
    assert_eq!(use_it(&mut via_msg), Ok(42));
    assert_eq!(use_it(&mut direct), Ok(42));
}

/// One value is either stub: the same generic code runs on a `Placed` that
/// holds the direct stub and on one that holds the endpoint stub, and they
/// agree; switching the variant between calls switches the host, not the
/// call. **Canary.** Make a generated `Endpoint` arm answer without calling
/// the transport: the message count reads short, red.
#[test]
fn a_placed_value_is_either_stub_and_the_caller_cannot_tell() {
    let lb = Loopback::new();
    type P<'a> = CalcPlaced<CalcImpl, &'a Loopback>;
    let mut p: P = CalcPlaced::Direct(CalcDirect(CalcImpl::default()));
    fn use_it<C: CalcCall>(c: &mut C) -> Result<(u32, i32)> { Ok((c.add(20, 22)?, c.neg(-5)?)) }
    assert_eq!(use_it(&mut p), Ok((42, 5)));
    assert_eq!(lb.calls.get(), 0, "the direct arm sends no message");
    p = CalcPlaced::Endpoint(CalcClient::new(&lb));
    assert_eq!(use_it(&mut p), Ok((42, 5)));
    assert_eq!(lb.calls.get(), 2, "the endpoint arm sends one message per call");
    assert_eq!(lb.server.borrow().calls, 1, "the server saw the add");
}

#[test]
fn the_request_has_the_documented_wire_form() {
    let lb = Loopback::new();
    let mut c = CalcClient::new(&lb).with_deadline(123_456);
    c.add(40, 2).unwrap();
    let r = *lb.last_req.borrow();
    assert_eq!(r.version, MSG_VERSION);
    assert_eq!((r.n_words, r.n_caps), (3, 0));
    assert_eq!(r.words[0], (0x4D54_0001u64 << 32) | (2 << 16) | 1);
    assert_eq!((r.words[1], r.words[2]), (40, 2));
    assert_eq!(r.deadline, 123_456);
    c.actuate(Cap::from_raw(9), [1, 2, 3]).unwrap();
    let r = *lb.last_req.borrow();
    assert_eq!((r.n_words, r.n_caps), (4, 1));
    assert_eq!(header_op(r.words[0]), 4);
    assert_eq!((r.caps[0].handle, r.caps[0].mode), (9, CAP_MODE_MOVE));
    assert_eq!(&r.words[1..4], &[1, 2, 3]);
}

#[test]
fn op_table() {
    let t = &CalcIdl::OPS;
    assert_eq!(t.len(), 6);
    let names: Vec<_> = t.iter().map(|o| o.name).collect();
    assert_eq!(names, ["add", "neg", "mix", "actuate", "nothing", "swap_caps"]);
    for (i, o) in t.iter().enumerate() {
        assert_eq!(o.op as usize, i + 1, "op numbers follow method order from 1");
    }
    assert_eq!(CalcIdl::OP_ADD, 1);
    assert_eq!(CalcIdl::OP_SWAP_CAPS, 6);
    assert_eq!((CalcIdl::ID, CalcIdl::LEVEL), (0x4D54_0001, 2));
    // sizes: header + args / status + return
    assert_eq!((t[0].req_words, t[0].req_caps, t[0].rep_words, t[0].rep_caps), (3, 0, 2, 0));
    assert_eq!((t[2].req_words, t[2].rep_words), (6, 2));
    assert_eq!((t[3].req_words, t[3].req_caps, t[3].rep_words), (4, 1, 3));
    assert_eq!((t[4].req_words, t[4].rep_words), (1, 1));
    assert_eq!((t[5].req_words, t[5].req_caps, t[5].rep_words, t[5].rep_caps), (1, 2, 1, 1));
}

#[test]
fn attribute_flags_are_in_the_op_table() {
    let t = &CalcIdl::OPS;
    assert_eq!(t[0].flags, 0);
    assert!(t[1].idempotent() && !t[1].at_most_once() && !t[1].once_only());
    assert!(t[2].at_most_once() && !t[2].idempotent() && !t[2].once_only());
    assert!(t[3].once_only() && !t[3].idempotent() && !t[3].at_most_once());
    assert_eq!(t[1].flags, OP_IDEMPOTENT);
    assert_eq!(t[2].flags, OP_AT_MOST_ONCE);
    assert_eq!(t[3].flags, OP_ONCE_ONLY);
    assert!(t[1].retry_safe() && !t[2].retry_safe() && !t[3].retry_safe() && !t[0].retry_safe());
}

#[test]
fn delivery_is_the_attribute_and_an_unmarked_op_has_none() {
    let t = &CalcIdl::OPS;
    assert_eq!(t[0].delivery(), None);
    assert_eq!(t[1].delivery(), Some(Delivery::Idempotent));
    assert_eq!(t[2].delivery(), Some(Delivery::AtMostOnce));
    assert_eq!(t[3].delivery(), Some(Delivery::OnceOnly));
}

#[test]
fn the_remote_failures_are_statuses_and_distinct() {
    let all = [IdlError::NoConnection, IdlError::PeerDied, IdlError::DeadlineExpired, IdlError::Refused];
    for (i, e) in all.iter().enumerate() {
        assert_ne!(e.status(), STATUS_OK);
        assert!(e.status() < 16, "small and non-negative: the fast path shares reply word 0 with its error code");
        assert_eq!(IdlError::from_status(e.status()), Some(*e));
        for f in &all[i + 1..] {
            assert_ne!(e.status(), f.status());
        }
    }
    // A client sees them from a reply, whatever the op.
    struct Fixed(u64);
    impl Transport for Fixed {
        fn call(&self, m: &mut MsgDesc) -> Result { m.words[0] = self.0; m.n_words = 1; Ok(()) }
    }
    assert_eq!(CalcClient::new(Fixed(IdlError::NoConnection.status())).add(1, 2), Err(IdlError::NoConnection));
    assert_eq!(CalcClient::new(Fixed(IdlError::PeerDied.status())).add(1, 2), Err(IdlError::PeerDied));
}

fn dispatch_raw(req: &MsgDesc) -> (MsgDesc, Result) {
    let mut s = CalcImpl::default();
    let mut rep = MsgDesc::default();
    let r = CalcIdl::dispatch(&mut s, req, &mut rep);
    (rep, r)
}

fn req(op: u16, words: &[u64]) -> MsgDesc {
    let mut m = MsgDesc::default();
    m.version = MSG_VERSION;
    m.words[0] = header(0x4D54_0001, 2, op);
    m.words[1..1 + words.len()].copy_from_slice(words);
    m.n_words = (1 + words.len()) as u8;
    m
}

#[test]
fn the_server_refuses_what_it_cannot_serve() {
    // good
    let (rep, r) = dispatch_raw(&req(1, &[1, 2]));
    assert_eq!((r, rep.words[0], rep.words[1], rep.n_words), (Ok(()), 0, 3, 2));
    // unknown op, and op 0 (a zeroed message is never valid)
    assert_eq!(dispatch_raw(&req(99, &[])).1, Err(IdlError::BadOp));
    assert_eq!(dispatch_raw(&req(0, &[])).1, Err(IdlError::BadOp));
    assert_eq!(dispatch_raw(&MsgDesc::default()).1, Err(IdlError::Malformed));
    // wrong interface
    let mut m = req(1, &[1, 2]);
    m.words[0] = header(0x1234, 2, 1);
    assert_eq!(dispatch_raw(&m).1, Err(IdlError::BadInterface));
    // a client built against a newer level
    let mut m = req(1, &[1, 2]);
    m.words[0] = header(0x4D54_0001, 3, 1);
    assert_eq!(dispatch_raw(&m).1, Err(IdlError::LevelTooNew));
    // an older client is served
    m.words[0] = header(0x4D54_0001, 1, 1);
    assert_eq!(dispatch_raw(&m).1, Ok(()));
    // too few words / unexpected capability / value that does not fit
    assert_eq!(dispatch_raw(&req(1, &[1])).1, Err(IdlError::Malformed));
    let mut m = req(1, &[1, 2]);
    m.n_caps = 1;
    assert_eq!(dispatch_raw(&m).1, Err(IdlError::Malformed));
    assert_eq!(dispatch_raw(&req(1, &[1 << 32, 2])).1, Err(IdlError::Malformed), "u32 argument wider than 32 bits");
    assert_eq!(dispatch_raw(&req(3, &[2, 0, 0, 0, 0])).1, Err(IdlError::Malformed), "bool that is 2");
    // an error reply is status-only and always a valid reply
    let (rep, _) = dispatch_raw(&req(99, &[]));
    assert_eq!((rep.n_words, rep.words[0]), (1, IdlError::BadOp.status()));
    // extra words are tolerated (a register transport pads)
    let (_, r) = dispatch_raw(&req(1, &[1, 2, 0, 0]));
    assert_eq!(r, Ok(()));
}

#[test]
fn the_client_maps_replies_and_transport_failures() {
    struct Failing;
    impl Transport for Failing {
        fn call(&self, _m: &mut MsgDesc) -> Result { Err(IdlError::Transport(-7)) }
    }
    assert_eq!(CalcClient::new(Failing).add(1, 2), Err(IdlError::Transport(-7)));

    struct Fixed(fn(&mut MsgDesc));
    impl Transport for Fixed {
        fn call(&self, m: &mut MsgDesc) -> Result { (self.0)(m); Ok(()) }
    }
    // status refused
    let mut c = CalcClient::new(Fixed(|m| { m.words[0] = IdlError::LevelTooNew.status(); m.n_words = 1; }));
    assert_eq!(c.add(1, 2), Err(IdlError::LevelTooNew));
    // short reply
    let mut c = CalcClient::new(Fixed(|m| { m.words[0] = 0; m.n_words = 1; }));
    assert_eq!(c.add(1, 2), Err(IdlError::Malformed));
    // empty reply
    let mut c = CalcClient::new(Fixed(|m| { m.n_words = 0; }));
    assert_eq!(c.add(1, 2), Err(IdlError::Malformed));
    // a return that does not fit: u32 reply of 1<<40
    let mut c = CalcClient::new(Fixed(|m| { m.words[0] = 0; m.words[1] = 1 << 40; m.n_words = 2; }));
    assert_eq!(c.add(1, 2), Err(IdlError::Malformed));
    // an unexpected capability in a reply with none declared
    let mut c = CalcClient::new(Fixed(|m| { m.words[0] = 0; m.words[1] = 3; m.n_words = 2; m.n_caps = 1; }));
    assert_eq!(c.add(1, 2), Err(IdlError::Malformed));
}

// A `words = 4` interface over a transport that carries exactly four
// registers and no capabilities: the shape of the fast path.
#[azos_interface(id = 0x45_43_48, level = 1, words = 4)]
pub trait Reg4 {
    fn echo(&mut self, a: u64, b: u64, c: u64) -> u64;
}
struct Reg4Impl;
impl Reg4 for Reg4Impl {
    fn echo(&mut self, a: u64, b: u64, c: u64) -> u64 { a ^ b ^ c }
}
struct RegisterWire;
impl Transport for RegisterWire {
    fn call(&self, msg: &mut MsgDesc) -> Result {
        // request: 4 registers out of the message
        let regs: [u64; 4] = [msg.words[0], msg.words[1], msg.words[2], msg.words[3]];
        let mut req = MsgDesc::default();
        req.words[..4].copy_from_slice(&regs);
        req.n_words = 4;
        let mut rep = MsgDesc::default();
        let _ = Reg4Idl::dispatch(&mut Reg4Impl, &req, &mut rep);
        // reply: 4 registers back, padded; the count is the register count
        let out: [u64; 4] = [rep.words[0], rep.words[1], rep.words[2], rep.words[3]];
        *msg = MsgDesc::default();
        msg.words[..4].copy_from_slice(&out);
        msg.n_words = 4;
        Ok(())
    }
}

#[test]
fn a_four_word_interface_fits_a_register_transport() {
    let mut c = Reg4Client::new(RegisterWire);
    assert_eq!(c.echo(1, 2, 4), Ok(7));
    assert_eq!(c.echo(u64::MAX, 0, 1), Ok(u64::MAX - 1));
    assert_eq!(Reg4Idl::OPS[0].req_words, 4);
}

#[test]
fn cap_is_a_typed_copy_handle() {
    let a: Cap<Motor> = Cap::from_raw(3);
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.raw(), 3);
    assert_eq!(core::mem::size_of::<Cap<Motor>>(), 4);
}

// ── Lent<T>: a capability lent in a reply, or none ──────────────────────

#[azos_interface(id = 0x4D54_0002, level = 1)]
pub trait Lender {
    /// `which` 0 lends the server's handle 9 with rights 0x2; 2 lends it until
    /// t = 5 s; any other lends nothing.
    fn borrow(&mut self, which: u32) -> Lent<Motor>;
}

struct LenderImpl;
impl Lender for LenderImpl {
    fn borrow(&mut self, which: u32) -> Lent<Motor> {
        match which {
            0 => Lent::dup(9, 0x2),
            2 => Lent::dup_until(9, 0x2, 5_000_000_000),
            _ => Lent::none(),
        }
    }
}

struct LenderLoop;
impl Transport for LenderLoop {
    fn call(&self, msg: &mut MsgDesc) -> Result {
        let mut rep = MsgDesc::default();
        LenderIdl::dispatch(&mut LenderImpl, msg, &mut rep)?;
        *msg = rep;
        Ok(())
    }
}

#[test]
fn a_lent_capability_is_a_dup_entry_with_rights_and_none_is_no_entry() {
    let mut rep = MsgDesc::default();
    let mut req = MsgDesc::default();
    req.version = MSG_VERSION;
    {
        let mut w = Writer::new(&mut req);
        w.word(header(LenderIdl::ID, LenderIdl::LEVEL, LenderIdl::OP_BORROW));
        w.word(0);
        w.finish();
    }
    LenderIdl::dispatch(&mut LenderImpl, &req, &mut rep).unwrap();
    assert_eq!(rep.n_caps, 1);
    assert_eq!(rep.caps[0].handle, 9);
    // Canary: a MOVE entry (mode 0) here would take the server's own capability.
    assert_eq!(rep.caps[0].mode, CAP_MODE_DUP);
    // Canary: rights 0 would mean "the sender's own", no attenuation at all.
    assert_eq!(rep.caps[0].rights, 0x2);

    let mut c = LenderClient::new(LenderLoop);
    let got = c.borrow(0).unwrap();
    assert!(got.get().is_some());
    assert_eq!(got.get().unwrap().raw(), 9);

    // None: no entry on the wire, and the client reads it as none.
    req.words[1] = 1;
    LenderIdl::dispatch(&mut LenderImpl, &req, &mut rep).unwrap();
    assert_eq!(rep.n_caps, 0);
    assert_eq!(c.borrow(1).unwrap().get(), None);
}

#[test]
fn a_lent_capability_carries_its_deadline_and_none_carries_none() {
    let mut req = MsgDesc::default();
    req.version = MSG_VERSION;
    let mut rep = MsgDesc::default();
    for (which, want) in [(0u64, 0u64), (2, 5_000_000_000)] {
        {
            let mut w = Writer::new(&mut req);
            w.word(header(LenderIdl::ID, LenderIdl::LEVEL, LenderIdl::OP_BORROW));
            w.word(which);
            w.finish();
        }
        LenderIdl::dispatch(&mut LenderImpl, &req, &mut rep).unwrap();
        // Canary: a macro that dropped the deadline would write 0 here for
        // `which` 2, and the receiver's copy would live as long as the server's.
        assert_eq!(rep.caps[0].expiry_ns, want, "which {which}");
    }
    assert_eq!(Lent::<Motor>::dup_until(9, 0x2, 7).expiry_ns(), 7);
    // Rights 0 still lends nothing, deadline or not.
    assert_eq!(Lent::<Motor>::dup_until(9, 0, 7), Lent::none());
}

#[test]
fn a_reply_with_more_capabilities_than_the_op_returns_is_refused() {
    struct Leaky;
    impl Transport for Leaky {
        fn call(&self, m: &mut MsgDesc) -> Result {
            let mut rep = MsgDesc::default();
            LenderIdl::dispatch(&mut LenderImpl, m, &mut rep)?;
            rep.caps[1] = rep.caps[0];
            rep.n_caps = 2;
            *m = rep;
            Ok(())
        }
    }
    let mut c = LenderClient::new(Leaky);
    assert_eq!(c.borrow(0), Err(IdlError::Malformed));
}

#[test]
fn lending_with_no_rights_lends_nothing() {
    // Rights 0 would cross as "the sender's own": the type refuses to say it.
    assert_eq!(Lent::<Motor>::dup(9, 0).get(), None);
    assert_eq!(Lent::<Motor>::dup(9, 0), Lent::none());
}
