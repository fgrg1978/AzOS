// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot admission of the topology's guest rows, from rows the topology
//! parser produced.

use azos_arch_api::{HvKind, HvStatus};
use azos_hv::admit::{admit, Admitted, HostFacts, Refusal, VirtRole};
use azos_hv::vm::{InjectError, VmState, VmTable, MAX_VCPUS, MAX_VMS};
use azos_topology::{parse_caps, parse_sched, GuestSpec, Topology};

fn topology(body: &str) -> Box<Topology<'static>> {
    let sched: &'static str = "[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";
    let caps: &'static str = Box::leak(format!("format = 7\n{body}").into_boxed_str());
    let mut t = Box::new(Topology::empty());
    parse_sched(sched.as_bytes(), &mut t).unwrap();
    parse_caps(caps.as_bytes(), &mut t).unwrap_or_else(|e| panic!("{e:?}\n{body}"));
    t
}

fn row(name: &str, cpus: u32, mem: u32, env: &str, devices: &str) -> String {
    format!("[guest.{name}]\ncpus = {cpus}\nmem_mib = {mem}\nenvelope = \"{env}\"\ndevices = [{devices}]\n")
}

fn facts() -> HostFacts {
    HostFacts {
        role: VirtRole::Hosted,
        hv: HvStatus::Usable(HvKind::RiscvH),
        online: 0b1111,
        rt: 0,
        free_mib: 4096,
        max_guest_mib: 4096,
    }
}

#[test]
fn rows_that_fit_are_admitted_and_become_vms() {
    let t = topology(&row("linux", 2, 512, "contained", "\"virtio-blk\", \"virtio-net\", \"virtio-console\""));
    let plan = admit(t.guests(), &facts()).unwrap();
    assert_eq!((plan.guests, plan.vcpus, plan.mem_mib), (1, 2, 512));
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    assert_eq!(vms.len(), 1);
    let vm = vms.vm(0).unwrap();
    assert_eq!((vm.state, vm.cpus, vm.mem_mib, vm.vmid), (VmState::Admitted, 2, 512, 1));
    assert_eq!(vm.devices_len(), 3);
    assert_eq!(vms.vcpus_used(), 2);
    assert!(vms.vcpu(0, 1).is_some() && vms.vcpu(0, 2).is_none());
    // Hosted: a vCPU may run on any hart.
    assert_eq!(vms.vcpu(0, 0).unwrap().affinity, 0b1111);
}

#[test]
fn no_rows_is_an_empty_plan_whatever_the_machine() {
    let t = topology("");
    let mut f = facts();
    f.role = VirtRole::None;
    f.hv = HvStatus::Absent("no");
    let plan = admit(t.guests(), &f).unwrap();
    assert_eq!((plan.guests, plan.vcpus), (0, 0));
}

#[test]
fn a_none_kernel_and_a_cpu_without_the_extension_refuse_the_rows_as_a_set() {
    let t = topology(&row("g", 1, 8, "full", ""));
    let mut f = facts();
    f.role = VirtRole::None;
    assert_eq!(admit(t.guests(), &f), Err(Refusal::RoleNone));
    let mut f = facts();
    f.hv = HvStatus::Absent("boot entered at EL1: no EL2 to keep");
    assert_eq!(admit(t.guests(), &f), Err(Refusal::NoHypervisor("boot entered at EL1: no EL2 to keep")));
}

#[test]
fn memory_is_summed_over_the_rows_and_checked_against_what_is_free() {
    let t = topology(&format!("{}{}", row("a", 1, 100, "full", ""), row("b", 1, 60, "full", "")));
    let mut f = facts();
    f.free_mib = 160;
    assert_eq!(admit(t.guests(), &f).unwrap().mem_mib, 160);
    f.free_mib = 159;
    assert_eq!(admit(t.guests(), &f), Err(Refusal::Memory { need_mib: 160, free_mib: 159 }));
}

#[test]
fn a_backend_nobody_serves_refuses_the_row_and_names_it() {
    let t = topology(&format!(
        "{}{}",
        row("a", 1, 8, "full", "\"virtio-blk\""),
        row("b", 1, 8, "full", "\"virtio-net\", \"virtio-floppy\"")
    ));
    assert_eq!(admit(t.guests(), &facts()), Err(Refusal::UnknownDevice { guest: 1, device: 1 }));
}

#[test]
fn the_vcpu_pool_is_a_limit_of_the_image_not_of_the_row() {
    let over = MAX_VCPUS as u32 + 1;
    let rows = [GuestSpec { cpus: over.min(255) as u8, mem_mib: 1, ..GuestSpec::empty() }];
    assert_eq!(admit(&rows, &facts()), Err(Refusal::TooManyVcpus { need: over, room: MAX_VCPUS }));
}

#[test]
fn guest_ram_is_bounded_by_what_the_memory_object_table_can_describe() {
    // Plenty of free memory, but the table of objects (64 pages each) can
    // name only 6 MiB of it: refused for the ceiling, not for being free.
    let t = topology(&format!("{}{}", row("a", 1, 4, "full", ""), row("b", 1, 3, "full", "")));
    let mut f = facts();
    f.max_guest_mib = 6;
    assert_eq!(admit(t.guests(), &f), Err(Refusal::RamCeiling { need_mib: 7, max_mib: 6 }));
    f.max_guest_mib = 7;
    assert_eq!(admit(t.guests(), &f).unwrap().mem_mib, 7);
    // Free memory is checked first: a host short of memory says so.
    f.free_mib = 5;
    f.max_guest_mib = 4;
    assert_eq!(admit(t.guests(), &f), Err(Refusal::Memory { need_mib: 7, free_mib: 5 }));
}

#[test]
fn more_rows_than_the_table_are_refused() {
    let rows = vec![GuestSpec { cpus: 1, mem_mib: 1, ..GuestSpec::empty() }; MAX_VMS + 1];
    assert_eq!(admit(&rows, &facts()), Err(Refusal::TooManyVms { rows: MAX_VMS + 1, room: MAX_VMS }));
}

#[test]
fn harts_with_a_deadline_reservation_are_not_the_guests() {
    let t = topology(&row("g", 1, 8, "full", ""));
    let mut f = facts();
    f.rt = 0b0101;
    let plan = admit(t.guests(), &f).unwrap();
    assert_eq!(plan.affinity[0], 0b1010, "harts 0 and 2 hold reservations");
    // Every online hart reserved: nowhere to put a vCPU.
    f.rt = 0b1111;
    assert_eq!(admit(t.guests(), &f), Err(Refusal::NoHart));
    // A hart that is reserved but offline changes nothing.
    f.online = 0b0011;
    f.rt = 0b1100;
    assert_eq!(admit(t.guests(), &f).unwrap().affinity[0], 0b0011);
}

#[test]
fn a_static_partition_gives_each_vcpu_a_hart_of_its_own() {
    let t = topology(&row("g", 2, 8, "full", ""));
    let mut f = facts();
    f.role = VirtRole::Static;
    f.online = 0b11110;
    f.rt = 0b00100;
    let plan: Admitted = admit(t.guests(), &f).unwrap();
    // Usable: 1, 3, 4. The guest's two vCPUs take the lowest two.
    assert!(plan.pinned);
    assert_eq!(plan.affinity[0], 0b01010);
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    assert_eq!(vms.vcpu(0, 0).unwrap().affinity, 0b00010);
    assert_eq!(vms.vcpu(0, 1).unwrap().affinity, 0b01000);
    // Three vCPUs on two usable harts: refused, not shared.
    let t = topology(&row("g", 3, 8, "full", ""));
    f.online = 0b0011;
    f.rt = 0;
    assert_eq!(admit(t.guests(), &f), Err(Refusal::NotEnoughHarts { need: 3, have: 2 }));
}

#[test]
fn installing_twice_is_refused() {
    let t = topology(&row("g", 1, 8, "full", ""));
    let plan = admit(t.guests(), &facts()).unwrap();
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::ArmEl2).unwrap();
    assert!(vms.install(t.guests(), &plan, HvKind::ArmEl2).is_err());
    // The default RAM base follows the platform's machine model.
    assert_eq!(vms.vm(0).unwrap().ram_base, 0x4000_0000);
}

fn one_vm() -> VmTable {
    let t = topology(&row("g", 2, 8, "full", "\"virtio-blk\""));
    let plan = admit(t.guests(), &facts()).unwrap();
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    vms
}

#[test]
fn the_life_of_a_vm_follows_its_transitions_and_no_others() {
    let mut vms = one_vm();
    let s2 = azos_arch_api::Stage2Root { root: 0x1000, aux: 0 };
    assert!(vms.destroyed(0).is_err(), "nothing to give back");
    let vm = vms.vm_mut(0).unwrap();
    vm.created(s2).unwrap();
    assert!(vm.created(s2).is_err());
    vm.add_window(azos_hv::vm::Space::Pio, 0x3F8, 8, 0).unwrap();
    vms.destroyed(0).unwrap();
    let vm = vms.vm_mut(0).unwrap();
    assert_eq!((vm.state, vm.stage2), (VmState::Admitted, None));
    // The windows went with the mapping they were declared against.
    vm.add_window(azos_hv::vm::Space::Pio, 0x3F8, 8, 0).unwrap();
    vm.created(s2).unwrap();
}

#[test]
fn an_interrupt_is_raised_only_in_a_created_vm() {
    let mut vms = one_vm();
    assert_eq!(vms.inject(0, 0, 3), Err(InjectError::NotCreated), "an admitted VM has no tables");
    assert_eq!(vms.vcpu(0, 0).unwrap().pending(), 0);
    vms.vm_mut(0).unwrap().created(azos_arch_api::Stage2Root { root: 0x1000, aux: 0 }).unwrap();
    assert_eq!(vms.inject(0, 1, 5), Ok(()));
    assert_eq!(vms.inject(0, 1, 64), Err(InjectError::BadIrq));
    assert_eq!(vms.inject(0, 2, 1), Err(InjectError::NoSuchVcpu));
    assert_eq!(vms.inject(1, 0, 1), Err(InjectError::NoSuchVcpu));
    assert_eq!((vms.vcpu(0, 0).unwrap().pending(), vms.vcpu(0, 1).unwrap().pending()), (0, 1 << 5));
}

#[test]
fn destroying_a_vm_resets_its_vcpus_and_only_its_own() {
    let t = topology(&format!("{}{}", row("a", 1, 8, "full", ""), row("b", 1, 8, "full", "")));
    let plan = admit(t.guests(), &facts()).unwrap();
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    let s2 = azos_arch_api::Stage2Root { root: 0x1000, aux: 0 };
    for i in 0..2 {
        vms.vm_mut(i).unwrap().created(s2).unwrap();
        vms.inject(i, 0, 9).unwrap();
        vms.vcpu_mut(i, 0).unwrap().affinity = 0b1;
    }
    let home = facts().online;
    vms.destroyed(0).unwrap();
    let (a, b) = (vms.vcpu(0, 0).unwrap(), vms.vcpu(1, 0).unwrap());
    assert_eq!((a.pending(), a.affinity), (0, home), "a recreated VM inherits nothing");
    assert_eq!((b.pending(), b.affinity), (1 << 9, 0b1), "another VM's vCPUs are left alone");
    // Recreated, the VM starts clean, and only now can it be injected into.
    assert_eq!(vms.inject(0, 0, 1), Err(InjectError::NotCreated));
    vms.vm_mut(0).unwrap().created(s2).unwrap();
    assert_eq!(vms.vcpu(0, 0).unwrap().pending(), 0);
}
