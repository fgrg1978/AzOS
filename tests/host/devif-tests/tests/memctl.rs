// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `MemCtl` interface: its registry row, its op table (one capability
//! entry per op: the memory object) and the generated client and dispatcher
//! over a mock that remembers which object each op named.

use azos_devif::memctl::VolatileMem;
use azos_devif::{
    by_key, by_name, key, outcome, parse_target, Cap, MemCtl, MemCtlCall, MemCtlClient, MemCtlIdl, Out, MEMCTL_ID,
};
use azos_idl::{MsgDesc, Result as IdlResult, Transport};
use std::cell::RefCell;

struct Loop<'a> {
    serve: &'a dyn Fn(&MsgDesc, &mut MsgDesc),
}

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let req = *msg;
        (self.serve)(&req, msg);
        Ok(())
    }
}

/// The owner's objects: handle 7 is volatile and was purged, handle 8 is
/// volatile and whole; every other handle is no volatile object.
#[derive(Default)]
struct Mock {
    seen: Vec<(&'static str, u32)>,
}

impl Mock {
    fn answer(&mut self, op: &'static str, mem: Cap<VolatileMem>) -> Out<bool> {
        self.seen.push((op, mem.raw()));
        match mem.raw() {
            7 => Out::ok(true),
            8 => Out::ok(false),
            _ => Out::err(outcome::BAD_ARGUMENT),
        }
    }
}

impl MemCtl for Mock {
    fn set_volatile(&mut self, mem: Cap<VolatileMem>) -> Out<bool> {
        self.answer("set_volatile", mem)
    }
    fn set_nonvolatile(&mut self, mem: Cap<VolatileMem>) -> Out<bool> {
        self.answer("set_nonvolatile", mem)
    }
}

/// The row: key 24, after `display`, the id "MCTL", no resource spelling.
///
/// **Canary.** Move the key, or give the row a resource: red.
#[test]
fn the_memctl_row_is_registered_after_net_and_names_no_resource() {
    assert_eq!(key::MEMCTL, 24);
    assert_eq!(MEMCTL_ID.to_be_bytes(), *b"MCTL");
    let i = by_name("memctl").expect("no row memctl");
    assert_eq!((i.key, i.id), (key::MEMCTL, MEMCTL_ID));
    assert_eq!(by_key(key::MEMCTL).map(|x| x.name), Some("memctl"));
    assert_eq!(parse_target("memctl").map(|(i, b)| (i.name, b)), Some(("memctl", 0)));
    assert!(parse_target("memctl.1").is_none(), "a MemCtl endpoint has no resource");
    assert_eq!(azos_devif::IFACES.iter().filter(|f| f.id == MEMCTL_ID).count(), 1);
}

/// Each op names exactly one memory object (the table is what the host-side
/// `takes_caps` relies on), and both can be asked again: setting a state twice
/// is setting it once.
///
/// **Canary.** An op with no capability parameter: `req_caps` red.
#[test]
fn each_op_carries_one_capability_entry() {
    assert_eq!(MemCtlIdl::ID, MEMCTL_ID);
    assert_eq!(MemCtlIdl::OPS.len(), 2);
    for (i, o) in MemCtlIdl::OPS.iter().enumerate() {
        assert_eq!(o.op as usize, i + 1, "{}", o.name);
        assert_eq!(o.req_caps, 1, "{}", o.name);
        assert_eq!(o.flags, azos_idl::OP_IDEMPOTENT, "{}", o.name);
        assert!(o.req_words <= 8 && o.rep_words <= 8, "{}", o.name);
    }
}

/// Through the generated client and dispatcher: the object each op named
/// arrives as the handle the client sent, the answer says whether it was
/// purged, and a refusal keeps its code.
///
/// **Canary.** Swap the two ops in the trait: the `seen` list reads the wrong
/// names.
#[test]
fn the_client_and_the_dispatcher_carry_both_ops() {
    let mock = RefCell::new(Mock::default());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = MemCtlIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop { serve: &serve };
    let mut c = MemCtlClient::new(&lp);

    assert_eq!(c.set_volatile(Cap::from_raw(8)).unwrap(), Out::ok(false));
    assert_eq!(c.set_nonvolatile(Cap::from_raw(7)).unwrap(), Out::ok(true));
    assert_eq!(c.set_volatile(Cap::from_raw(3)).unwrap(), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(
        mock.borrow().seen,
        vec![("set_volatile", 8), ("set_nonvolatile", 7), ("set_volatile", 3)],
    );
}
