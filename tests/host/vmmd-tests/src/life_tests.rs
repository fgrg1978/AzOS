// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The life of a guest's vCPUs (`life`): the boot CPU started, the started
//! ones watched, stopped and waited for, against a model of the kernel's vCPU
//! threads.

use crate::life::{boot, halt, watch, Boot, Cpu, Entry, Watch, RUN_FAULTED, RUN_RUNNING, VCPUS};

const ENTRY: Entry = Entry { pc: 0x8020_0000, arg: 0x8000_0000 };

/// One vCPU thread as the kernel keeps it: it ends `lag` looks after a stop.
#[derive(Default)]
struct Thread {
    state: u64,
    started: Vec<(u64, u64)>,
    stops: u32,
    /// `Err(code)`: the start is refused.
    refuse: Option<u32>,
    lag: u32,
    stopping: Option<u32>,
    unreachable: bool,
}

impl Thread {
    fn running() -> Self {
        Thread { state: RUN_RUNNING, ..Thread::default() }
    }
}

impl Cpu for Thread {
    fn launch(&mut self, pc: u64, arg: u64) -> Result<(), u32> {
        if let Some(code) = self.refuse {
            return Err(code);
        }
        self.started.push((pc, arg));
        self.state = RUN_RUNNING;
        Ok(())
    }

    fn request_stop(&mut self) {
        self.stops += 1;
        if self.state & 0xFF == RUN_RUNNING && self.stopping.is_none() {
            self.stopping = Some(self.lag);
        }
    }

    fn run_state(&mut self) -> Option<u64> {
        if self.unreachable {
            return None;
        }
        if let Some(left) = self.stopping {
            if left == 0 {
                self.state = 0;
                self.stopping = None;
            } else {
                self.stopping = Some(left - 1);
            }
        }
        Some(self.state)
    }
}

fn guest(n: usize) -> Vec<Option<Thread>> {
    (0..VCPUS).map(|k| (k < n).then(Thread::default)).collect()
}

#[test]
fn only_the_boot_cpu_starts_and_it_gets_the_entry_and_the_boot_information() {
    let mut cpus = guest(4);
    assert_eq!(boot(&mut cpus, 4, ENTRY), Boot::Started);
    assert_eq!(cpus[0].as_ref().unwrap().started, vec![(ENTRY.pc, ENTRY.arg)]);
    for k in 1..4 {
        assert!(cpus[k].as_ref().unwrap().started.is_empty(), "vCPU {k} waits for the guest to ask");
    }
}

#[test]
fn a_vcpu_without_an_endpoint_starts_none() {
    // The row granted vcpu.0.0 and vcpu.0.2 but not vcpu.0.1.
    let mut cpus = guest(3);
    cpus[1] = None;
    assert_eq!(boot(&mut cpus, 3, ENTRY), Boot::NoEndpoint(1));
    assert!(cpus.iter().flatten().all(|c| c.started.is_empty()), "no CPU of a guest that cannot have them all");
}

#[test]
fn more_vcpus_than_the_monitor_serves_starts_none() {
    let mut cpus = guest(VCPUS);
    assert_eq!(boot(&mut cpus, VCPUS + 1, ENTRY), Boot::TooMany);
    assert!(cpus.iter().flatten().all(|c| c.started.is_empty()));
}

#[test]
fn a_refused_boot_cpu_is_reported_with_the_outcome() {
    let mut cpus = guest(3);
    cpus[0].as_mut().unwrap().refuse = Some(7);
    assert_eq!(boot(&mut cpus, 3, ENTRY), Boot::Refused(7));
    assert!(cpus.iter().flatten().all(|c| c.started.is_empty()));
}

#[test]
fn a_guest_whose_vcpus_all_run_is_not_over() {
    let mut cpus: Vec<_> = (0..VCPUS).map(|k| (k < 2).then(Thread::running)).collect();
    assert_eq!(watch(&mut cpus, 2, 0b11), Watch::Running);
}

#[test]
fn a_vcpu_that_left_ends_the_guest_and_a_fault_is_reported() {
    let mut cpus: Vec<_> = (0..VCPUS).map(|k| (k < 3).then(Thread::running)).collect();
    cpus[1].as_mut().unwrap().state = 0;
    assert_eq!(watch(&mut cpus, 3, 0b111), Watch::Over { fault: None });
    cpus[2].as_mut().unwrap().state = RUN_FAULTED | 5 << 8;
    assert_eq!(watch(&mut cpus, 3, 0b111), Watch::Over { fault: Some(RUN_FAULTED | 5 << 8) });
}

#[test]
fn a_vcpu_the_guest_has_not_asked_for_is_not_a_vcpu_that_left() {
    // vCPU 0 runs, vCPU 1 was never started: the guest is not over.
    let mut cpus: Vec<_> = (0..VCPUS).map(|k| (k < 2).then(|| if k == 0 { Thread::running() } else { Thread::default() })).collect();
    assert_eq!(watch(&mut cpus, 2, 0b01), Watch::Running);
    // Once it has been started, its leaving ends the guest.
    assert_eq!(watch(&mut cpus, 2, 0b11), Watch::Over { fault: None });
}

#[test]
fn a_vcpu_that_cannot_be_asked_counts_as_gone() {
    let mut cpus: Vec<_> = (0..VCPUS).map(|k| (k < 2).then(Thread::running)).collect();
    cpus[0].as_mut().unwrap().unreachable = true;
    assert_eq!(watch(&mut cpus, 2, 0b01), Watch::Over { fault: None });
}

#[test]
fn halt_stops_what_runs_and_waits_for_the_threads() {
    let mut cpus: Vec<_> = (0..VCPUS).map(|k| (k < 3).then(Thread::running)).collect();
    cpus[0].as_mut().unwrap().state = RUN_FAULTED | 1 << 8;
    for c in cpus.iter_mut().flatten() {
        c.lag = 2;
    }
    let mut pauses = 0;
    assert!(halt(&mut cpus, 3, 10, &mut || pauses += 1));
    assert_eq!(cpus[0].as_ref().unwrap().stops, 0, "the faulted one is already over");
    for k in 1..3 {
        assert!(cpus[k].as_ref().unwrap().stops >= 1, "vCPU {k}");
        assert_eq!(cpus[k].as_ref().unwrap().state & 0xFF, 0);
    }
    assert!(pauses >= 1 && pauses <= 3, "it waited for the lag, not for the budget: {pauses}");
}

#[test]
fn halt_gives_up_on_a_thread_that_does_not_end() {
    let mut cpus: Vec<_> = (0..VCPUS).map(|k| (k < 1).then(Thread::running)).collect();
    cpus[0].as_mut().unwrap().lag = 1000;
    let mut pauses = 0;
    assert!(!halt(&mut cpus, 1, 5, &mut || pauses += 1));
    assert_eq!(pauses, 5);
}

#[test]
fn halt_of_a_guest_that_is_not_running_does_not_wait() {
    let mut cpus = guest(2);
    let mut pauses = 0;
    assert!(halt(&mut cpus, 2, 5, &mut || pauses += 1));
    assert_eq!(pauses, 0);
}

#[test]
fn the_monitor_and_the_interface_agree_on_the_state_words_and_the_grants() {
    assert_eq!((RUN_RUNNING, RUN_FAULTED), (azos_devif::vm::RUN_RUNNING, azos_devif::vm::RUN_FAULTED));
    assert_eq!(VCPUS, azos_topology::builder::VMMD_VCPUS_MAX);
    assert!(VCPUS as u32 <= azos_devif::vm::VCPUS);
}
