// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The RFC-0051 E0–E2 row (`energy-smoke`): `-smp 2 -icount
//! shift=0,sleep=off`, the built-in topology carrying the fake two-domain
//! model `azos_topology::builder::FAKE_ENERGY_MODEL`. Each check ends in
//! one verdict line only its own path prints (`[ENERGY] <check> PASS|FAIL`):
//!
//! * **model** — boot resolved the topology's model (not the DTB's, not none),
//!   with exactly the declared shape: domains `cpus = 0x1 / 0x2`, 3 + 4 OPPs,
//!   2 + 1 idle states, top capacity 1024; mode `performance`; and the seams
//!   are still today's (`Legacy`/`Fixed`/`WfiOnly`, invariant I4 holds with a
//!   model present in E0–E2). Canary `energy-model-canary` (boot does not read
//!   the topology's model): FAIL.
//! * **refuse** — the same text with one power figure wrong (the big domain's
//!   third OPP cheaper than its second), parsed by the SCHED.TOML parser and
//!   resolved like boot does: refused with `PowerNotIncreasing { domain: 1,
//!   opp: 2 }`, no model. Canary `energy-validate-canary` (validation accepts
//!   everything): FAIL.
//! * **util** — a task pinned to CPU 1 computes for [`BUSY_MS`]; then its
//!   utilisation must read at least [`BUSY_MIN`] of 1024, and CPU 1's too.
//!   It then sleeps [`IDLE_MS`]; its utilisation must read at most
//!   [`IDLE_MAX`]. Canaries `energy-util-canary` (dispatch records the task
//!   as not running: busy reads 0) and `energy-switchout-canary` (switch-out
//!   leaves it running: it still reads busy after sleeping): FAIL.
//!
//! The run ends with `[ENERGY] cost`: timebase ticks over N calls of the
//! switch hook and of the tick hook, as nanoseconds per call, which under
//! `-icount shift=0` are instructions per call.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};
use azos_energy::{EnergyMode, ModelFault, ModelSource, Seams};
use azos_sched::{task_block_outcome, BlockOutcome, WaitReason};

const CTL_PRIO: u32 = 14;
const BUSY_PRIO: u32 = 18;
const BUSY_MS: u64 = 300;
const IDLE_MS: u64 = 200;
/// A task that computes the whole window, minus what the other tasks on its
/// CPU take, on 1024.
const BUSY_MIN: u32 = 800;
/// Four empty windows (window tracker) read 0; 200 ms is six PELT half-lives.
const IDLE_MAX: u32 = 50;
const COST_CALLS: u32 = 10_000;

/// `FAKE_ENERGY_MODEL` without its idle states and with the big domain's
/// third OPP at 250 mW, below the second's 300 mW: power must rise with
/// frequency, so validation must refuse it at exactly that OPP.
const INVALID_MODEL: &[u8] = br#"
[energy]
mode = "performance"

[energy.domain.little]
cpus = 1
opps = [
  { freq_khz = 400000, capacity = 160, power_mw = 30 },
  { freq_khz = 800000, capacity = 320, power_mw = 90 },
  { freq_khz = 1200000, capacity = 480, power_mw = 190 },
]

[energy.domain.big]
cpus = 2
opps = [ { freq_khz = 500000, capacity = 256, power_mw = 120 }, { freq_khz = 1000000, capacity = 512, power_mw = 300 },
  { freq_khz = 1500000, capacity = 768, power_mw = 250 },
  { freq_khz = 2000000, capacity = 1024, power_mw = 1100 } ]
"#;

static BUSY_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);
static BUSY_DONE: AtomicBool = AtomicBool::new(false);
static BUSY_END: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn ms(ms: u64) -> u64 {
    TIMER_FREQ.saturating_mul(ms) / 1_000
}
fn ns(t: u64) -> u64 {
    ((t as u128) * 1_000_000_000u128 / TIMER_FREQ.max(1) as u128) as u64
}
fn isa() -> &'static str {
    if cfg!(target_arch = "riscv64") { "riscv64" } else { "aarch64" }
}
fn block_until(deadline: u64) {
    while now() < deadline {
        if task_block_outcome(WaitReason::Timer(deadline)) == BlockOutcome::Refused {
            while now() < deadline {
                core::hint::spin_loop();
            }
        }
    }
}
fn self_idx() -> usize {
    azos_sched::idx_for_tid(azos_sched::current_task_tid()).unwrap_or(usize::MAX)
}

/// Create the controller (CPU 0) and the busy task (CPU 1).
pub fn spawn() {
    azos_sched::task_create_affinity("energy-ctl", ctl_task, 0, CTL_PRIO, 0);
    kprintln!("[ENERGY] created energy-ctl on cpu 0");
}

fn busy_task(_: usize) {
    BUSY_IDX.store(self_idx(), Ordering::Release);
    let end = now() + ms(BUSY_MS);
    while now() < end {
        core::hint::spin_loop();
    }
    BUSY_END.store(now(), Ordering::Release);
    BUSY_DONE.store(true, Ordering::Release);
    loop {
        block_until(now() + ms(10_000));
    }
}

fn check_model() {
    let m = azos_sched::energy::model();
    let d = m.domains();
    let shape_ok = m.source == ModelSource::Topology
        && d.len() == 2
        && d[0].cpus == 0b01
        && d[1].cpus == 0b10
        && d[0].opps().len() == 3
        && d[1].opps().len() == 4
        && d[0].idle_states().len() == 2
        && d[1].idle_states().len() == if cfg!(feature = "energy-gov-smoke") { 2 } else { 1 }
        && d[1].max_capacity() == 1024
        && d[0].idle_states()[1].name() == b"retention";
    // `energy-gov-smoke`: the balanced model opts in to E3/E4 (and declares
    // WCET reference clocks); otherwise performance mode is today's seams.
    #[cfg(not(feature = "energy-gov-smoke"))]
    let (want_mode, want_seams, wref_ok) = (EnergyMode::Performance, Seams::TODAY, d.iter().all(|x| x.wcet_ref_khz == 0));
    #[cfg(feature = "energy-gov-smoke")]
    let (want_mode, want_seams, wref_ok) = (
        EnergyMode::Balanced,
        Seams {
            placement: azos_energy::Placement::Legacy,
            governor: azos_energy::Governor::DeadlineFloor,
            idle: azos_energy::IdleGovernor::Teo,
        },
        d.len() == 2 && d[0].wcet_ref_khz == 800_000 && d[1].wcet_ref_khz == 1_000_000,
    );
    let mode_ok = azos_sched::energy::mode() == want_mode;
    let seams_ok = azos_sched::energy::seams() == want_seams && wref_ok;
    let verdict = if shape_ok && mode_ok && seams_ok { "PASS" } else { "FAIL" };
    kprintln!(
        "[ENERGY] model {} {} source={} domains={} opps={} mode={} seams={:?} expected={}",
        verdict, isa(), m.source.as_str(), d.len(), m.opp_count(),
        azos_sched::energy::mode().as_str(), azos_sched::energy::seams(), seams_ok,
    );
}

fn check_refuse(num_cpus: usize) {
    let spec = match azos_topology::parser::parse_energy(INVALID_MODEL) {
        Ok(s) => s,
        Err(e) => {
            kprintln!("[ENERGY] refuse FAIL {} the invalid model did not even parse: {:?}", isa(), e);
            return;
        }
    };
    let (m, r) = azos_energy::resolve(&spec.model, None, num_cpus);
    let want = Some(ModelFault::PowerNotIncreasing { domain: 1, opp: 2 });
    if r.topology_fault == want && m.source == ModelSource::None && m.domains().is_empty() {
        kprintln!("[ENERGY] refuse PASS {} fault={:?} model=none", isa(), r.topology_fault);
    } else {
        kprintln!(
            "[ENERGY] refuse FAIL {} fault={:?} model={} domains={}",
            isa(), r.topology_fault, m.source.as_str(), m.domains().len(),
        );
    }
}

fn check_util() {
    let start = now();
    azos_sched::task_create_affinity("energy-busy", busy_task, 0, BUSY_PRIO, 1);
    let deadline = start + ms(BUSY_MS * 20);
    while !BUSY_DONE.load(Ordering::Acquire) && now() < deadline {
        block_until(now() + ms(5));
    }
    let idx = BUSY_IDX.load(Ordering::Acquire);
    if !BUSY_DONE.load(Ordering::Acquire) || idx == usize::MAX {
        kprintln!("[ENERGY] util FAIL {} the busy task did not finish", isa());
        return;
    }
    let busy = azos_sched::energy::task_util(idx);
    let cpu1 = azos_sched::energy::cpu_util(1);
    let end = BUSY_END.load(Ordering::Acquire);
    block_until(end + ms(IDLE_MS));
    let idle = azos_sched::energy::task_util(idx);
    let ok = busy >= BUSY_MIN && cpu1 >= BUSY_MIN && idle <= IDLE_MAX;
    kprintln!(
        "[ENERGY] util {} {} busy={} cpu1={} after_{}ms_idle={} (need >= {} / >= {} / <= {})",
        if ok { "PASS" } else { "FAIL" }, isa(), busy, cpu1, IDLE_MS, idle, BUSY_MIN, BUSY_MIN, IDLE_MAX,
    );
}

fn ctl_task(_: usize) {
    // Let boot settle (the robot tasks' own start-up bursts).
    block_until(now() + ms(500));
    let num_cpus = azos_sched::smp::NUM_ONLINE_CPUS.load(Ordering::Acquire);
    check_model();
    check_refuse(num_cpus);
    check_util();
    #[cfg(feature = "energy-gov-smoke")]
    gov::check();
    let me = self_idx();
    let sw = azos_sched::energy::probe_switch_cost(0, me, COST_CALLS);
    let tk = azos_sched::energy::probe_tick_cost(0, me, COST_CALLS);
    kprintln!(
        "[ENERGY] cost {} switch_hook={} ns/call tick_hook={} ns/call (x{}; instructions under -icount shift=0)",
        isa(), ns(sw) / COST_CALLS as u64, ns(tk) / COST_CALLS as u64, COST_CALLS,
    );
    kprintln!("[ENERGY] done {}", isa());
    loop {
        block_until(now() + ms(10_000));
    }
}

/// RFC-0051 E3/E4 (`energy-gov-smoke`, the balanced fake model): CPU 0 is
/// the little domain (OPPs 160/320/480, WCET floor OPP 1 at 800 MHz), CPU 1
/// the big one (256/512/768/1024, WCET floor OPP 1 at 1 GHz, idle states
/// `wfi` and `retention`: exit 120 us, residency 500 us). The checks run on
/// CPU 1, which the boot leaves quiet on both ISAs (on aarch64 the `behavior`
/// task keeps CPU 0 busy). QEMU models no clock and no idle power: these
/// checks see the decisions, never an effect.
///
/// * `gov`: quiet, the big domain sits on its WCET floor (I6), not lower; a
///   busy burst on CPU 1 drives it from the floor to its top (schedutil); a
///   reservation of density 0.6 on CPU 1 raises it to OPP 2
///   (0.6 × 1024 × 1.2 = 737 > 512, I1) while CPU 1 is otherwise idle; its
///   release brings it back to the floor. No sampled OPP of either domain is
///   ever below its floor.
/// * `idle`: quiet, CPU 1's idle governor picks `retention` at least once;
///   with the reservation (relative deadline 100 us < 120 us) it never does
///   and the RT slack limits some choices (I3); no choice ever exceeded the
///   slack.
#[cfg(feature = "energy-gov-smoke")]
mod gov {
    use super::*;
    use core::sync::atomic::AtomicU8;
    use azos_sched::energy::{domain_opp, gov_stats, idle_stats};

    const CPU: usize = 1;
    static RT_STATE: AtomicU8 = AtomicU8::new(0); // 0 pending, 1 reserved, 2 refused
    static RT_STOP: AtomicBool = AtomicBool::new(false);
    static BURST_DONE: AtomicBool = AtomicBool::new(false);
    static MIN_OPP: [AtomicU8; 2] = [AtomicU8::new(u8::MAX), AtomicU8::new(u8::MAX)];

    fn rt_task(_: usize) {
        let me = self_idx();
        let r = azos_sched::rt::Reservation {
            runtime_us: 60, period_us: 1_000, deadline_us: 100, hard: false, cpu_mask: 1 << CPU, band: false,
        };
        match azos_sched::rt::reserve(me, r) {
            Ok(_) => RT_STATE.store(1, Ordering::Release),
            Err(e) => {
                kprintln!("[ENERGY] gov: reservation refused: {}", e.name());
                RT_STATE.store(2, Ordering::Release);
            }
        }
        while !RT_STOP.load(Ordering::Acquire) {
            block_until(now() + ms(5));
        }
        azos_sched::task_exit();
    }

    fn burst_task(_: usize) {
        let end = now() + ms(100);
        while now() < end {
            core::hint::spin_loop();
        }
        BURST_DONE.store(true, Ordering::Release);
        azos_sched::task_exit();
    }

    /// Sleep `ms_` in 5 ms steps, sampling both domains' OPPs; returns the
    /// highest OPP of the big domain seen.
    fn watch(ms_: u64) -> u8 {
        let end = now() + ms(ms_);
        let mut hi = 0;
        while now() < end {
            block_until(now() + ms(5));
            for d in 0..2 {
                let o = domain_opp(d);
                if o != azos_sched::energy::OPP_BOOT {
                    MIN_OPP[d].fetch_min(o, Ordering::Relaxed);
                }
            }
            hi = hi.max(domain_opp(CPU));
        }
        hi
    }

    pub(super) fn check() {
        // Quiet: the util check's busy task has ended.
        watch(150);
        let quiet = domain_opp(CPU);
        let quiet_util = azos_sched::energy::cpu_util_at(CPU, now());
        let i0 = idle_stats(CPU);
        watch(200);
        let i1 = idle_stats(CPU);
        let quiet_ret = i1.picks[1] - i0.picks[1];

        let before = domain_opp(CPU);
        azos_sched::task_create_affinity("energy-burst", burst_task, 0, BUSY_PRIO, CPU as i8);
        let mut busy_max = 0;
        let give_up = now() + ms(2_000);
        while !BURST_DONE.load(Ordering::Acquire) && now() < give_up {
            busy_max = busy_max.max(watch(5));
        }
        watch(150);

        azos_sched::task_create_affinity("energy-rt", rt_task, 0, BUSY_PRIO, CPU as i8);
        let give_up = now() + ms(1_000);
        while RT_STATE.load(Ordering::Acquire) == 0 && now() < give_up {
            block_until(now() + ms(5));
        }
        let reserved = RT_STATE.load(Ordering::Acquire) == 1;
        watch(100);
        let with_rt = domain_opp(CPU);
        let r0 = idle_stats(CPU);
        watch(200);
        let r1 = idle_stats(CPU);
        let rt_ret = r1.picks[1] - r0.picks[1];
        let rt_slack = r1.by_slack - r0.by_slack;
        RT_STOP.store(true, Ordering::Release);
        watch(100);
        let released = domain_opp(CPU);
        let g = gov_stats();
        let mins = (MIN_OPP[0].load(Ordering::Relaxed), MIN_OPP[1].load(Ordering::Relaxed));

        let gov_ok = quiet == 1 && before == 1 && busy_max == 3 && reserved && with_rt == 2
            && released == 1 && mins.0 >= 1 && mins.1 >= 1 && g.why[1] > 0 && g.why[2] > 0;
        kprintln!(
            "[ENERGY] gov {} {} big_quiet={} (util {}) big_before_burst={} big_burst_max={} rt_reserved={} \
             big_with_rt={} big_after_release={} min_opp_little/big={}/{} evals={} changes={} \
             why(schedutil/deadline/wcet)={}/{}/{} (need 1, 1, 3, true, 2, 1, >=1/>=1; \
             decisions recorded only: no clock driver)",
            if gov_ok { "PASS" } else { "FAIL" }, isa(), quiet, quiet_util, before, busy_max, reserved,
            with_rt, released, mins.0, mins.1, g.evals, g.changes, g.why[0], g.why[1], g.why[2],
        );
        let idle_ok = quiet_ret > 0 && reserved && rt_ret == 0 && rt_slack > 0 && r1.i3_violations == 0;
        kprintln!(
            "[ENERGY] idle {} {} cpu1_retention_quiet={} cpu1_retention_with_rt={} rt_slack_limited={} \
             i3_violations={} history_limited={} intercepts={} picks_cpu1={:?} \
             (need >0, 0, >0, 0; every state entered as wfi)",
            if idle_ok { "PASS" } else { "FAIL" }, isa(), quiet_ret, rt_ret, rt_slack,
            r1.i3_violations, r1.by_history, r1.intercepts, r1.picks,
        );
    }
}
