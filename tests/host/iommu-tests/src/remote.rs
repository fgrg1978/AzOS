// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Smmuv3Remote`: the kernel's half of an SMMU a monitor owns. A model of the
//! monitor records what it was asked; the descriptors are the kernel's own, so
//! they are read back from the memory the unit would fetch them from.
//!
//! WHY. Every stream the kernel sets up goes through the monitor, and the
//! entry the monitor writes names the descriptor the kernel wrote: a descriptor
//! written after the entry went live, a stream left in a mode the kernel did not
//! ask for, or an ASID that stays held, each is a DMA path nobody saw.

use crate::common::TestMem;
use azos_iommu::smmuv3::{classify, encode_cd, Remote, RemoteStream, Smmuv3Remote, CD_BYTES};
use azos_iommu::{rd64, DomainMode, FaultKind, IommuUnit};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Log {
    calls: Vec<String>,
    /// Dword 0 of the descriptor at the address of a nested attach, read when the attach arrived.
    cd_seen: Vec<u64>,
    refuse: bool,
    events: Vec<[u64; 2]>,
    mem: Option<&'static TestMem>,
}

#[derive(Clone, Default)]
struct Model(Arc<Mutex<Log>>);

impl Remote for Model {
    fn init(&self, base: u64, size: u64, max_sid: u32) -> Option<u64> {
        self.0.lock().unwrap().calls.push(format!("init {base:#x} {size:#x} {max_sid}"));
        Some(5)
    }
    fn attach(&self, sid: u32, stream: RemoteStream) -> bool {
        let mut l = self.0.lock().unwrap();
        l.calls.push(format!("attach {sid} {stream:?}"));
        if let (RemoteStream::Nested(cd), Some(mem)) = (stream, l.mem) {
            let w = rd64(mem, cd, 0);
            l.cd_seen.push(w);
        }
        !l.refuse
    }
    fn flush(&self, sid: u32) -> bool {
        self.0.lock().unwrap().calls.push(format!("flush {sid}"));
        true
    }
    fn event(&self) -> Option<[u64; 2]> {
        self.0.lock().unwrap().events.pop()
    }
}

fn unit() -> (Smmuv3Remote<Model>, Model, &'static TestMem) {
    let mem = TestMem::leak();
    let m = Model::default();
    m.0.lock().unwrap().mem = Some(mem);
    let u = Smmuv3Remote::new(m.clone(), mem, 0x0905_0000, 0x2_0000, 7).unwrap();
    (u, m, mem)
}

#[test]
fn a_translating_stream_is_nested_on_a_descriptor_written_before_the_monitor_hears_of_it() {
    let (mut u, m, mem) = unit();
    u.attach(3, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    let l = m.0.lock().unwrap();
    assert_eq!(l.calls[0], "init 0x9050000 0x20000 7");
    let cd_pa = mem.page(0); // the descriptors' page, the unit's only allocation
    assert_eq!(l.calls[1], format!("attach 3 Nested({cd_pa})"));
    // ASID 1, the first: its descriptor, as the stage-1-only driver writes it.
    assert_eq!(l.cd_seen, vec![encode_cd(0x8020_0000, 4, 5, 1)[0]]);
    assert!(mem.cleaned_all(cd_pa, CD_BYTES), "visible to a unit that does not snoop");
}

#[test]
fn each_translating_stream_has_a_descriptor_and_an_asid_of_its_own() {
    let (mut u, m, mem) = unit();
    u.attach(1, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    u.attach(2, DomainMode::Translate { root_pa: 0x8030_0000 }).unwrap();
    let l = m.0.lock().unwrap();
    let base = mem.page(0);
    assert_eq!(l.calls[1], format!("attach 1 Nested({base})"));
    assert_eq!(l.calls[2], format!("attach 2 Nested({})", base + CD_BYTES));
    assert_eq!(l.cd_seen[1] >> 48, 2, "ASID 2 in the second descriptor");
}

#[test]
fn bypass_is_stage_two_only_and_block_is_block_and_neither_is_a_bypass() {
    let (mut u, m, _) = unit();
    u.attach(1, DomainMode::Bypass).unwrap();
    u.attach(2, DomainMode::Block).unwrap();
    let l = m.0.lock().unwrap();
    assert_eq!(l.calls[1], "attach 1 S2Only");
    assert_eq!(l.calls[2], "attach 2 Block");
}

#[test]
fn a_stream_that_stops_translating_gives_its_asid_back() {
    let (mut u, _, _) = unit();
    for dev in 0..16 {
        u.attach(dev, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    }
    assert!(u.attach(16, DomainMode::Translate { root_pa: 0x8020_0000 }).is_err(), "all 16 held");
    u.attach(5, DomainMode::Block).unwrap();
    u.attach(16, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
}

#[test]
fn a_refusal_of_the_monitor_is_the_streams_error() {
    let (mut u, m, _) = unit();
    m.0.lock().unwrap().refuse = true;
    assert!(u.attach(1, DomainMode::Bypass).is_err());
    assert!(u.attach(1, DomainMode::Translate { root_pa: 0x8020_0000 }).is_err());
}

#[test]
fn only_a_translating_stream_is_flushed() {
    let (mut u, m, _) = unit();
    u.flush(1).unwrap();
    u.attach(1, DomainMode::Translate { root_pa: 0x8020_0000 }).unwrap();
    u.flush(1).unwrap();
    let l = m.0.lock().unwrap();
    assert_eq!(l.calls.iter().filter(|c| c.starts_with("flush")).count(), 1);
}

#[test]
fn the_monitors_fault_records_become_dma_faults() {
    let (mut u, m, _) = unit();
    // F_TRANSLATION (0x10) of stream 0x18 at 0x8010_0000, and F_PERMISSION (0x13).
    m.0.lock().unwrap().events = vec![[0x13 | 0x20u64 << 32, 0x8020_0000], [0x10 | 0x18u64 << 32, 0x8010_0000]];
    let mut seen = Vec::new();
    assert_eq!(u.poll_faults(&mut |f| seen.push(f)), 2);
    assert_eq!((seen[0].device_id, seen[0].fault_addr, seen[0].kind), (0x18, 0x8010_0000, FaultKind::UnmappedIova));
    assert_eq!((seen[1].device_id, seen[1].fault_addr), (0x20, 0x8020_0000));
    assert_eq!(seen[0], classify(&azos_iommu::smmuv3::EventRecord { event_type: 0x10, stream_id: 0x18, input_addr: 0x8010_0000 }));
    assert_eq!(u.poll_faults(&mut |_| panic!("no more")), 0);
}

#[test]
fn a_unit_the_monitor_refuses_is_no_unit() {
    struct No;
    impl Remote for No {
        fn init(&self, _: u64, _: u64, _: u32) -> Option<u64> { None }
        fn attach(&self, _: u32, _: RemoteStream) -> bool { true }
        fn flush(&self, _: u32) -> bool { true }
        fn event(&self) -> Option<[u64; 2]> { None }
    }
    assert!(Smmuv3Remote::new(No, TestMem::leak(), 0x0905_0000, 0x2_0000, 7).is_err());
}
