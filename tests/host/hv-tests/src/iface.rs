// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Vm` and `Vcpu` interfaces: their ids, their registry rows and their
//! wire form, through the generated client and dispatcher.

use azos_devif::{
    by_key, by_name, key, outcome, parse_target, Cap, Out, Vcpu, VcpuCall, VcpuClient, VcpuIdl, Vm, VmCall, VmClient, VmIdl,
    VCPU_ID, VM_ID,
};
use azos_devif::vm::{
    vcpu_badge, vm_badge, EventPort, GuestRam, NicRing, TrapPage, RUN_FAULTED, RUN_RUNNING, RUN_STOPPED, SPACE_MMIO,
    TRAP_PAGE_BYTES,
};
use azos_idl::{MsgDesc, Result as IdlResult, Transport};

/// A transport whose far end is a dispatcher over a mock.
struct Loop<'a>(&'a dyn Fn(&MsgDesc, &mut MsgDesc));

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let req = *msg;
        (self.0)(&req, msg);
        Ok(())
    }
}

#[derive(Default)]
struct MockVm {
    windows: Vec<(u32, u64, u64, u32)>,
    created: u32,
    ram: Vec<(u32, u64)>,
    traps: Vec<(u32, u32, u64)>,
    nic: Vec<u32>,
}

impl Vm for MockVm {
    fn state(&self) -> Out<u32> {
        Out::ok(1)
    }
    fn config(&self) -> Out<[u64; 5]> {
        Out::ok([2, 512, 3, 1 | 2 << 4 | 3 << 8, 0x8000_0000])
    }
    fn create(&mut self) -> Out<()> {
        self.created += 1;
        Out::ok(())
    }
    fn destroy(&mut self) -> Out<()> {
        Out::err(outcome::BUSY)
    }
    fn window(&mut self, space: u32, base: u64, len: u64, device: u32) -> Out<()> {
        self.windows.push((space, base, len, device));
        Out::ok(())
    }
    fn ram(&mut self, mem: Cap<GuestRam>, gpa: u64) -> Out<()> {
        self.ram.push((mem.raw(), gpa));
        Out::ok(())
    }
    fn traps(&mut self, page: Cap<TrapPage>, events: Cap<EventPort>, key: u64) -> Out<()> {
        self.traps.push((page.raw(), events.raw(), key));
        Out::ok(())
    }
    fn net(&mut self, ring: Cap<NicRing>) -> Out<()> {
        self.nic.push(ring.raw());
        Out::err(outcome::REFUSED)
    }
}

#[derive(Default)]
struct MockVcpu {
    irq: u32,
    msi: Vec<u32>,
    started: Vec<(u64, u64)>,
    kicks: u32,
    paused: i32,
}

impl Vcpu for MockVcpu {
    fn pending(&self) -> Out<u64> {
        Out::ok(1 << 33)
    }
    fn inject(&mut self, irq: u32) -> Out<()> {
        self.irq = irq;
        Out::ok(())
    }
    fn inject_msi(&mut self, id: u32) -> Out<()> {
        self.msi.push(id);
        if id <= 48 { Out::ok(()) } else { Out::err(outcome::BAD_ARGUMENT) }
    }
    fn set_affinity(&mut self, mask: u64) -> Out<u64> {
        Out::ok(mask & 0b1010)
    }
    fn start(&mut self, pc: u64, arg: u64) -> Out<()> {
        self.started.push((pc, arg));
        Out::ok(())
    }
    fn stop(&mut self) -> Out<()> {
        Out::err(outcome::BUSY)
    }
    fn kick(&mut self) -> Out<()> {
        self.kicks += 1;
        Out::ok(())
    }
    fn state(&self) -> Out<u64> {
        Out::ok(RUN_FAULTED | 3 << 8)
    }
    fn pause(&mut self) -> Out<()> {
        self.paused += 1;
        if self.paused > 1 { Out::err(outcome::BUSY) } else { Out::ok(()) }
    }
    fn resume(&mut self) -> Out<()> {
        self.paused -= 1;
        Out::ok(())
    }
}

#[test]
fn the_ids_are_the_reserved_ones_and_the_registry_has_both() {
    assert_eq!((VM_ID, VCPU_ID), (0x564D_0001, 0x564D_0002));
    let vm = by_name("vm").unwrap();
    let vcpu = by_name("vcpu").unwrap();
    assert_eq!((vm.id, vm.key, vcpu.id, vcpu.key), (VM_ID, key::VM, VCPU_ID, key::VCPU));
    assert_eq!(by_key(key::VM).map(|i| i.name), Some("vm"));
    assert_eq!(by_key(key::VCPU).map(|i| i.name), Some("vcpu"));
}

#[test]
fn a_topology_target_names_a_vm_or_a_vcpu_by_position() {
    let badge = |t: &str| parse_target(t).map(|(i, b)| (i.key, b));
    assert_eq!(badge("vm.0"), Some((key::VM, 1)));
    assert_eq!(badge("vm.15"), Some((key::VM, 16)));
    assert_eq!(vm_badge(3), 4);
    assert_eq!(badge("vcpu.0.0"), Some((key::VCPU, 1 << 8)));
    assert_eq!(badge("vcpu.2.255"), Some((key::VCPU, 3 << 8 | 255)));
    assert_eq!(vcpu_badge(2, 255), 3 << 8 | 255);
    for bad in ["vm", "vm.16", "vm.x", "vm.0.0", "vcpu", "vcpu.0", "vcpu.16.0", "vcpu.0.256", "vcpu.0.0.0", "vm2"] {
        assert!(badge(bad).is_none(), "{bad}");
    }
    // VM 0's badge is never the unbadged endpoint's 0.
    assert_ne!(badge("vm.0").unwrap().1, 0);
}

#[test]
fn the_vm_ops_are_numbered_from_one_in_the_order_written() {
    let names: Vec<&str> = VmIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["state", "config", "create", "destroy", "window", "ram", "traps", "net"]);
    let names: Vec<&str> = VcpuIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["pending", "inject", "set_affinity", "start", "stop", "kick", "state", "pause", "resume", "inject_msi"]);
    // The observers may be asked again; the acting ops may not.
    assert!(VmIdl::OPS[0].idempotent() && VmIdl::OPS[1].idempotent());
    for acting in 2..VmIdl::OPS.len() {
        assert!(!VmIdl::OPS[acting].idempotent(), "{}", VmIdl::OPS[acting].name);
    }
    assert!(VcpuIdl::OPS[0].idempotent() && VcpuIdl::OPS[6].idempotent());
    for acting in (1..6).chain(7..VcpuIdl::OPS.len()) {
        assert!(!VcpuIdl::OPS[acting].idempotent(), "{}", VcpuIdl::OPS[acting].name);
    }
}

#[test]
fn a_vm_call_crosses_the_wire_and_comes_back() {
    let mock = std::cell::RefCell::new(MockVm::default());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = VmIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let l = Loop(&serve);
    let mut c = VmClient::new(&l);
    assert_eq!(VmCall::state(&mut c), Ok(Out::ok(1)));
    assert_eq!(VmCall::config(&mut c), Ok(Out::ok([2, 512, 3, 1 | 2 << 4 | 3 << 8, 0x8000_0000])));
    assert_eq!(VmCall::create(&mut c), Ok(Out::ok(())));
    assert_eq!(VmCall::destroy(&mut c), Ok(Out::err(outcome::BUSY)));
    assert_eq!(VmCall::window(&mut c, SPACE_MMIO, 0x1000_1000, 0x1000, 2), Ok(Out::ok(())));
    assert_eq!(mock.borrow().windows, vec![(SPACE_MMIO, 0x1000_1000, 0x1000, 2)]);
    assert_eq!(mock.borrow().created, 1);
}

#[test]
fn a_memory_object_and_a_port_cross_as_capability_entries() {
    let mock = std::cell::RefCell::new(MockVm::default());
    let seen = std::cell::RefCell::new(Vec::new());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        seen.borrow_mut().push((req.n_words, req.n_caps));
        let _ = VmIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let l = Loop(&serve);
    let mut c = VmClient::new(&l);
    assert_eq!(VmCall::ram(&mut c, Cap::from_raw(7), 0x8010_0000), Ok(Out::ok(())));
    assert_eq!(VmCall::traps(&mut c, Cap::from_raw(8), Cap::from_raw(9), 0xE0E0), Ok(Out::ok(())));
    // The NIC is refused by the server's rule, and the refusal comes back as the outcome.
    assert_eq!(VmCall::net(&mut c, Cap::from_raw(10)), Ok(Out::err(outcome::REFUSED)));
    assert_eq!(mock.borrow().ram, vec![(7, 0x8010_0000)]);
    assert_eq!(mock.borrow().traps, vec![(8, 9, 0xE0E0)]);
    assert_eq!(mock.borrow().nic, vec![10]);
    // The handles are entries, not words: header + gpa, header + key, header.
    assert_eq!(*seen.borrow(), vec![(2, 1), (2, 2), (1, 1)]);
    // The trap page the interface names is the one the wire form has.
    assert_eq!(TRAP_PAGE_BYTES, azos_hv::trapwire::PAGE_BYTES);
}

#[test]
fn a_vcpu_call_crosses_the_wire_and_comes_back() {
    let mock = std::cell::RefCell::new(MockVcpu::default());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = VcpuIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let l = Loop(&serve);
    let mut c = VcpuClient::new(&l);
    assert_eq!(VcpuCall::pending(&mut c), Ok(Out::ok(1 << 33)));
    assert_eq!(VcpuCall::inject(&mut c, 33), Ok(Out::ok(())));
    assert_eq!(mock.borrow().irq, 33);
    // A message-signalled identity is an op of its own, not a line number.
    assert_eq!(VcpuCall::inject_msi(&mut c, 5), Ok(Out::ok(())));
    assert_eq!(VcpuCall::inject_msi(&mut c, 49), Ok(Out::err(outcome::BAD_ARGUMENT)));
    assert_eq!(mock.borrow().msi, vec![5, 49]);
    assert_eq!(mock.borrow().irq, 33, "and it did not touch the line op");
    assert_eq!(VcpuCall::set_affinity(&mut c, 0b1111), Ok(Out::ok(0b1010)));
    assert_eq!(VcpuCall::start(&mut c, 0x8000_0000, 0x8700_0000), Ok(Out::ok(())));
    assert_eq!(mock.borrow().started, vec![(0x8000_0000, 0x8700_0000)]);
    assert_eq!(VcpuCall::stop(&mut c), Ok(Out::err(outcome::BUSY)));
    assert_eq!(VcpuCall::kick(&mut c), Ok(Out::ok(())));
    assert_eq!(mock.borrow().kicks, 1);
    assert_eq!(VcpuCall::state(&mut c), Ok(Out::ok(RUN_FAULTED | 3 << 8)));
    assert_eq!((RUN_STOPPED, RUN_RUNNING, RUN_FAULTED), (0, 1, 2));
    // Pause and resume are ops of their own, each with its own answer.
    assert_eq!(VcpuCall::pause(&mut c), Ok(Out::ok(())));
    assert_eq!(VcpuCall::pause(&mut c), Ok(Out::err(outcome::BUSY)), "a second pause is refused");
    assert_eq!(VcpuCall::resume(&mut c), Ok(Out::ok(())));
    assert_eq!(mock.borrow().paused, 1);
    assert_eq!(azos_devif::vm::RUN_PAUSED, 1 << 8, "a flag above the state byte, below a fault's code");
}

#[test]
fn a_request_for_the_other_interface_is_refused_by_id() {
    // A Vcpu request handed to the Vm dispatcher.
    let mock = std::cell::RefCell::new(MockVm::default());
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = VmIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let l = Loop(&serve);
    let mut c = VcpuClient::new(&l);
    assert!(VcpuCall::pending(&mut c).is_err());
}
