// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `PowerMon` interface over the INA219 chip source: its wire form, and the
//! two hosts agreeing, which is what lets one caller serve both placements.

use azos_devif::powermon::{ENDPOINT, ENDPOINT_NAME, RECORD_BYTES};
use azos_devif::{outcome, Out, PowerMon, PowerMonCall, PowerMonClient, PowerMonDirect, PowerMonIdl, PowerMonPlaced, PowerStats, Sample, POWERMON_ID};
use azos_idl::{header, MsgDesc, Result as IdlResult, Transport};
use azos_ina219::{Bus, Ina219, Monitor};
use std::cell::{Cell, RefCell};

/// An INA219 that reads 7400 mV and 1500 mA.
struct Fake;
impl Bus for Fake {
    fn write(&mut self, _data: &[u8]) -> bool {
        true
    }
    fn read(&mut self, reg: u8, buf: &mut [u8]) -> bool {
        let raw: u16 = match reg {
            0x02 => 7400 / 4 << 3,
            0x04 => 15000,
            _ => 0,
        };
        buf.copy_from_slice(&raw.to_be_bytes());
        true
    }
}

fn sampled() -> Ina219 {
    let mut chip = Ina219::new();
    assert!(chip.init(&mut Fake));
    chip.poll(&mut Fake, 1_000);
    chip.poll(&mut Fake, 101_000);
    chip
}

/// The kernel host: the chip logic called directly.
struct KernelHost(Ina219);
impl PowerMon for KernelHost {
    fn read(&mut self) -> Out<Sample> {
        Monitor { chip: &self.0, acq_ns: 42 }.read()
    }
    fn stats(&mut self) -> Out<PowerStats> {
        Monitor { chip: &self.0, acq_ns: 42 }.stats()
    }
}

/// The ring-3 host as `ina_drv` builds it: the same chip logic behind the
/// generated dispatcher.
struct Ring3Host(Ina219);
impl PowerMon for Ring3Host {
    fn read(&mut self) -> Out<Sample> {
        Monitor { chip: &self.0, acq_ns: 42 }.read()
    }
    fn stats(&mut self) -> Out<PowerStats> {
        Monitor { chip: &self.0, acq_ns: 42 }.stats()
    }
}

struct Loop<'a> {
    server: &'a RefCell<Ring3Host>,
    sent: Cell<u32>,
    last: RefCell<MsgDesc>,
}
impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        self.sent.set(self.sent.get() + 1);
        let req = *msg;
        *self.last.borrow_mut() = req;
        let _ = PowerMonIdl::dispatch(&mut *self.server.borrow_mut(), &req, msg);
        Ok(())
    }
}

fn record(s: &Sample) -> [u8; RECORD_BYTES] {
    let mut b = [0u8; RECORD_BYTES];
    assert_eq!(s.copy_to(&mut b), RECORD_BYTES);
    b
}

/// The table is the trait in order, both ops may be asked again, and a reply
/// fits the message.
///
/// **Canary.** Drop `#[idempotent]` from `stats`: red.
#[test]
fn the_op_table_is_the_trait_and_every_op_may_be_asked_again() {
    let names: Vec<&str> = PowerMonIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["read", "stats"]);
    for o in PowerMonIdl::OPS {
        assert!(o.idempotent() && o.retry_safe(), "{} may not be retried", o.name);
    }
    assert_eq!(PowerMonIdl::ID, POWERMON_ID);
}

/// One `PowerMonPlaced` is either host: the same calls give the same record
/// whether the chip logic is in this address space or behind a message.
///
/// **Canary.** Make `Ring3Host::read` add one to the record's first byte: red
/// (the ring-3 answer is no longer the kernel's).
#[test]
fn the_placed_stub_reads_the_same_sample_in_either_host() {
    let mut direct: PowerMonPlaced<KernelHost, &Loop> = PowerMonPlaced::Direct(PowerMonDirect(KernelHost(sampled())));
    let kernel = direct.read().unwrap();

    let host = RefCell::new(Ring3Host(sampled()));
    let lp = Loop { server: &host, sent: Cell::new(0), last: RefCell::new(MsgDesc::default()) };
    let mut ep: PowerMonPlaced<KernelHost, &Loop> = PowerMonPlaced::Endpoint(PowerMonClient::new(&lp));
    let ring3 = ep.read().unwrap();

    assert!(kernel.is_ok() && ring3.is_ok());
    assert_eq!(record(&ring3.value), record(&kernel.value), "the same record from either host");
    assert_eq!(ring3.value.acq_ns, kernel.value.acq_ns);
    let rec = record(&kernel.value);
    assert_eq!(u16::from_le_bytes([rec[0], rec[1]]), 7400, "mV");
    assert_eq!(u16::from_le_bytes([rec[2], rec[3]]), 1500, "mA");

    assert_eq!(ep.stats().unwrap(), direct.stats().unwrap(), "the same counters from either host");
    assert_eq!(lp.sent.get(), 2, "one message per call");
}

/// The request is the header alone; the reply carries the record and the
/// stamp, and the counters of a monitor that has not been configured say so.
#[test]
fn the_wire_form_is_the_header_and_an_unconfigured_chip_is_not_ready() {
    let host = RefCell::new(Ring3Host(Ina219::new()));
    let lp = Loop { server: &host, sent: Cell::new(0), last: RefCell::new(MsgDesc::default()) };
    let mut c = PowerMonClient::new(&lp);
    assert_eq!(c.read().unwrap().code, outcome::NOT_READY, "no data, never a fabricated battery");
    let r = *lp.last.borrow();
    assert_eq!((r.n_words, r.n_caps), (1, 0));
    assert_eq!(r.words[0], header(POWERMON_ID, 1, PowerMonIdl::OP_READ));
    let st = c.stats().unwrap().value;
    assert!(!st.configured && st.samples == 0);
}

/// The kernel finds the endpoint by the name a topology grant gives it in the
/// pool.
///
/// **Canary.** Change `ENDPOINT_NAME`: red.
#[test]
fn the_pool_name_is_the_topology_name_without_its_prefix() {
    assert_eq!(ENDPOINT.strip_prefix("endpoint."), Some(ENDPOINT_NAME));
    assert!(ENDPOINT_NAME.len() <= 24, "ENDPOINT_NAME_MAX");
}
