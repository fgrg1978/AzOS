// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! CPU hotplug policy (`crates/core/sched/src/hart_set.rs`, Kconfig
//! `CPU_HOTPLUG`): which CPU may leave and join, who takes its work, and a
//! model of the offline sequence driven by those decisions.
//!
//! Canary (three buckets). Discriminates: `rt_cpu_is_refused`,
//! `isolated_cpu_is_refused` and `pinned_task_refuses_the_change` fail if the
//! refusal is dropped or reordered behind the prefix test; the model's
//! `no_task_lands_on_the_offline_cpu` fails if the takeover could name the
//! CPU going down. Does not discriminate: the reason names (documentation).

#[allow(dead_code)] // the boot-time half of the file (`stranded`) is the wake tests'
#[path = "../../../../crates/core/sched/src/hart_set.rs"]
mod hart_set;

use hart_set::*;

const N: usize = 4;

fn machine(alive: u64) -> Machine {
    Machine { alive, num_cpus: N, boot: 0, caller: 0, rt: 0, isolated: 0, stopped: !alive & 0b1111, firmware: true, busy: false }
}

#[test]
fn the_top_of_the_prefix_goes_offline() {
    assert_eq!(check_offline(&machine(0b1111), 3, 0), Ok(()));
}

#[test]
fn a_cpu_below_the_top_is_refused_so_the_prefix_stays_whole() {
    // Taking CPU 1 of 0..4 off would leave 2 and 3 above a hole: the scheduler
    // walks `0..online_prefix`, which would become 1 and strand them.
    assert_eq!(check_offline(&machine(0b1111), 1, 0), Err(HotplugReason::NotAtPrefixEdge));
    assert_eq!(check_offline(&machine(0b1111), 2, 0), Err(HotplugReason::NotAtPrefixEdge));
}

#[test]
fn a_stranded_cpu_past_a_hole_may_go_offline() {
    // CPU 2 failed to start at boot; 3 came up and sits past the hole. It
    // holds no work (the prefix is 0..2), so it can leave from any place.
    let m = machine(0b1011);
    assert_eq!(online_prefix(m.alive, N), 2);
    assert_eq!(check_offline(&m, 3, 0), Ok(()));
}

#[test]
fn the_boot_cpu_and_the_last_cpu_stay() {
    let mut m = machine(0b0011);
    m.boot = 1;
    m.caller = 0;
    assert_eq!(check_offline(&m, 1, 0), Err(HotplugReason::BootCpu));
    let one = machine(0b0001);
    // The only CPU is also the boot CPU and the caller: the first test that
    // applies answers, but the CPU is kept either way.
    assert!(check_offline(&one, 0, 0).is_err());
    let mut last = machine(0b0010);
    last.boot = 3;
    last.caller = 3;
    assert_eq!(check_offline(&last, 1, 0), Err(HotplugReason::LastCpu));
}

#[test]
fn the_callers_cpu_stays() {
    let mut m = machine(0b1111);
    m.caller = 3;
    assert_eq!(check_offline(&m, 3, 0), Err(HotplugReason::CallerCpu));
}

#[test]
fn rt_cpu_is_refused() {
    let mut m = machine(0b1111);
    m.rt = 1 << 3;
    assert_eq!(check_offline(&m, 3, 0), Err(HotplugReason::RealTime));
    // The real-time state of another CPU is no obstacle.
    m.rt = 1 << 1;
    assert_eq!(check_offline(&m, 3, 0), Ok(()));
}

#[test]
fn isolated_cpu_is_refused_before_the_prefix_test() {
    let mut m = machine(0b1111);
    m.isolated = 1 << 1;
    // CPU 1 is both isolated and below the edge: the operator hears about the
    // isolation, which is the more useful answer.
    assert_eq!(check_offline(&m, 1, 0), Err(HotplugReason::Isolated));
}

#[test]
fn pinned_task_refuses_the_change() {
    let m = machine(0b1111);
    assert_eq!(check_offline(&m, 3, 1), Err(HotplugReason::Pinned));
    assert_eq!(check_offline(&m, 3, 0), Ok(()));
}

#[test]
fn no_firmware_no_change_either_way() {
    let mut m = machine(0b0111);
    m.firmware = false;
    assert_eq!(check_offline(&m, 2, 0), Err(HotplugReason::NoFirmware));
    assert_eq!(check_online(&m, 3), Err(HotplugReason::NoFirmware));
}

#[test]
fn busy_and_range() {
    let mut m = machine(0b1111);
    m.busy = true;
    assert_eq!(check_offline(&m, 3, 0), Err(HotplugReason::Busy));
    assert_eq!(check_online(&m, 3), Err(HotplugReason::Busy));
    m.busy = false;
    assert_eq!(check_offline(&m, N, 0), Err(HotplugReason::NotPossible));
    assert_eq!(check_online(&m, 200), Err(HotplugReason::NotPossible));
}

#[test]
fn online_takes_the_first_cpu_past_the_prefix() {
    let m = machine(0b0011);
    assert_eq!(check_online(&m, 2), Ok(()));
    assert_eq!(check_online(&m, 3), Err(HotplugReason::NotAtPrefixEdge), "would leave a hole at 2");
    // A CPU that never stopped here has no context to resume.
    let mut fresh = m;
    fresh.stopped = 0;
    assert_eq!(check_online(&fresh, 2), Err(HotplugReason::NeverStopped));
    assert_eq!(check_online(&m, 1), Err(HotplugReason::NoChange));
}

#[test]
fn online_after_offline_is_the_inverse() {
    let full = 0b1111u64;
    let off = alive_after(full, 3, false);
    assert_eq!(off, 0b0111);
    assert_eq!(online_prefix(off, N), 3);
    assert_eq!(check_online(&machine(off), 3), Ok(()));
    assert_eq!(alive_after(off, 3, true), full);
}

#[test]
fn takeover_is_the_lowest_other_live_cpu() {
    assert_eq!(takeover_cpu(0b1111, N, 3), Some(0));
    assert_eq!(takeover_cpu(0b1111, N, 0), Some(1));
    assert_eq!(takeover_cpu(0b0100, N, 2), None, "nobody else");
    assert_eq!(takeover_cpu(0b1110, N, 1), Some(2));
}

#[test]
fn the_drain_keeps_idle_and_stops_at_a_pin() {
    assert_eq!(disposition(false, false), Disposition::Move);
    assert_eq!(disposition(true, true), Disposition::KeepIdle, "the idle task is pinned by construction");
    assert_eq!(disposition(false, true), Disposition::Pinned);
}

#[test]
fn the_record_carries_the_op_as_a_number() {
    assert_eq!(HotplugOp::Offline as u64, 0);
    assert_eq!(HotplugOp::Online as u64, 1);
}

#[test]
fn reason_codes_are_stable_and_distinct() {
    use HotplugReason::*;
    let all = [NotPossible, NoChange, BootCpu, LastCpu, CallerCpu, RealTime, Isolated, Pinned,
        NotAtPrefixEdge, NoFirmware, Busy, Timeout, FirmwareRefused, NeverStopped];
    for (i, r) in all.iter().enumerate() {
        assert_eq!(r.code(), i as u32 + 1, "{:?}", r);
        assert!(!r.name().is_empty());
    }
}

/// The offline sequence as `smp.rs` runs it, on queues of task ids: the
/// prefix shrinks first, then the dying CPU's queue is drained to the
/// takeover CPU (the real code asks `find_best_cpu`, which only looks inside
/// the prefix; the takeover CPU is inside it by construction).
fn offline(queues: &mut Vec<Vec<(u32, bool, bool)>>, alive: &mut u64, cpu: usize) -> Result<usize, HotplugReason> {
    let pinned = queues[cpu].iter().filter(|&&(_, idle, pin)| !idle && pin).count() as u32;
    let m = machine(*alive);
    check_offline(&m, cpu, pinned)?;
    *alive = alive_after(*alive, cpu, false);
    let to = takeover_cpu(*alive, N, cpu).expect("another CPU is live");
    assert!(to < online_prefix(*alive, N), "the takeover CPU is inside the prefix");
    let mut moved = 0;
    let mut keep = Vec::new();
    let drained: Vec<_> = queues[cpu].drain(..).collect();
    for t in drained {
        match disposition(t.1, t.2) {
            Disposition::Move => {
                queues[to].push(t);
                moved += 1;
            }
            Disposition::KeepIdle => keep.push(t),
            Disposition::Pinned => unreachable!("refused above"),
        }
    }
    queues[cpu] = keep;
    Ok(moved)
}

#[test]
fn no_task_lands_on_the_offline_cpu() {
    // (tid, is_idle, pinned)
    let mut q: Vec<Vec<(u32, bool, bool)>> = vec![
        vec![(1, false, false), (100, true, true)],
        vec![(2, false, false), (101, true, true)],
        vec![(3, false, false), (102, true, true)],
        vec![(4, false, false), (5, false, false), (103, true, true)],
    ];
    let mut alive = 0b1111;
    assert_eq!(offline(&mut q, &mut alive, 3), Ok(2));
    assert_eq!(q[3], vec![(103, true, true)], "only the idle task is left on the dead CPU");
    assert_eq!(q[0].len(), 4, "the takeover CPU got both");
    let total: usize = q.iter().map(|v| v.len()).sum();
    assert_eq!(total, 9, "no task lost or duplicated");
}

#[test]
fn a_pinned_task_stops_the_sequence_before_anything_moves() {
    let mut q: Vec<Vec<(u32, bool, bool)>> = vec![
        vec![(100, true, true)], vec![(101, true, true)], vec![(102, true, true)],
        vec![(4, false, true), (5, false, false), (103, true, true)],
    ];
    let before = q.clone();
    let mut alive = 0b1111;
    assert_eq!(offline(&mut q, &mut alive, 3), Err(HotplugReason::Pinned));
    assert_eq!(q, before);
    assert_eq!(alive, 0b1111, "the CPU is still online");
}

#[test]
fn offline_then_online_then_offline_again() {
    let mut q: Vec<Vec<(u32, bool, bool)>> = vec![vec![(100, true, true)], vec![(101, true, true)],
        vec![(102, true, true)], vec![(103, true, true), (7, false, false)]];
    let mut alive = 0b1111;
    assert_eq!(offline(&mut q, &mut alive, 3), Ok(1));
    assert_eq!(offline(&mut q, &mut alive, 2), Ok(0));
    assert_eq!(online_prefix(alive, N), 2);
    assert_eq!(check_online(&machine(alive), 3), Err(HotplugReason::NotAtPrefixEdge));
    assert_eq!(check_online(&machine(alive), 2), Ok(()));
    alive = alive_after(alive, 2, true);
    assert_eq!(check_online(&machine(alive), 3), Ok(()));
}
