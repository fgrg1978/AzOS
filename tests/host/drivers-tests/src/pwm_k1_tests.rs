// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `pwm_k1.rs` (the SpacemiT K1 PWM, the PXA PWM) run on the host over a
//! register-level model of one controller.
//!
//! The model is written from Linux v7.2.9 `drivers/pwm/pwm-pxa.c`, not from
//! the driver: its own copy of the offsets and fields, and the arithmetic the
//! file documents,
//!
//! ```text
//! period_ns = 10^9 * (PRESCALE + 1) * (PV + 1) / PWM_CLK_RATE
//! duty_ns   = 10^9 * (PRESCALE + 1) * DC       / PWM_CLK_RATE
//! ```
//!
//! with `PWMDCR_FD` (bit 10) meaning "full duty". The registers keep only the
//! bits they have (`PWMCR` 7, `PWMDCR` 11, `PWMPCR` 10), so a driver that
//! writes into reserved bits reads back less than it wrote. The model decodes
//! what the driver programmed with that arithmetic (`Out`), so a driver that
//! encodes wrongly is judged by what the output would do, not by its own
//! constants. It logs every access.
//!
//! `gated` models a controller whose function clock is off: writes go
//! nowhere and reads return 0. The APBC controller that gates it is not
//! modelled by AzOS (see `pwm_k1.rs`), and the readback the driver reports
//! must show it.
//!
//! What it does NOT know, and the board must confirm (listed in the front's
//! report): the function clock rate and the mux/gate state the firmware left;
//! whether a `PWMDCR` rewrite takes effect at the next period or at once; the
//! output level at duty 0 (the model, like Linux's "disable", assumes
//! inactive-low).

use super::pwm_k1::*;
use std::cell::RefCell;
use std::rc::Rc;

// The model's own copy of the reference.
const M_PWMCR: usize = 0x00;
const M_PWMDCR: usize = 0x04;
const M_PWMPCR: usize = 0x08;
const M_CR_MASK: u32 = 0x7f; // prescale [5:0] | SD bit 6
const M_DCR_MASK: u32 = 0x7ff; // dc [9:0] | FD bit 10
const M_PCR_MASK: u32 = 0x3ff;
const M_FD: u32 = 1 << 10;
const M_CLK: u64 = 12_800_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    Read(usize),
    Write(usize, u32),
}

#[derive(Default)]
struct Part {
    cr: u32,
    dcr: u32,
    pcr: u32,
    gated: bool,
    log: Vec<Access>,
}

/// What the registers make the output do.
#[derive(Debug)]
struct Out {
    period_ns: u64,
    duty_ns: u64,
}

#[derive(Clone)]
struct Model(Rc<RefCell<Part>>);

impl Model {
    fn new() -> Self {
        Model(Rc::new(RefCell::new(Part::default())))
    }
    fn gated() -> Self {
        let m = Self::new();
        m.0.borrow_mut().gated = true;
        m
    }
    fn log(&self) -> Vec<Access> {
        self.0.borrow().log.clone()
    }
    fn clear_log(&self) {
        self.0.borrow_mut().log.clear();
    }
    fn regs(&self) -> (u32, u32, u32) {
        let p = self.0.borrow();
        (p.cr, p.dcr, p.pcr)
    }
    fn out(&self) -> Out {
        let p = self.0.borrow();
        let step = (p.cr & 0x3f) as u64 + 1;
        let period_ns = 1_000_000_000 * step * (p.pcr as u64 + 1) / M_CLK;
        let duty_ns = if p.dcr & M_FD != 0 { period_ns } else { 1_000_000_000 * step * p.dcr as u64 / M_CLK };
        Out { period_ns, duty_ns }
    }
}

impl PxaPwmBus for Model {
    fn read32(&mut self, off: usize) -> u32 {
        let mut p = self.0.borrow_mut();
        p.log.push(Access::Read(off));
        if p.gated {
            return 0;
        }
        match off {
            M_PWMCR => p.cr,
            M_PWMDCR => p.dcr,
            M_PWMPCR => p.pcr,
            _ => panic!("read of offset {off:#x}: not a register of this block"),
        }
    }
    fn write32(&mut self, off: usize, v: u32) {
        let mut p = self.0.borrow_mut();
        p.log.push(Access::Write(off, v));
        if p.gated {
            return;
        }
        match off {
            M_PWMCR => p.cr = v & M_CR_MASK,
            M_PWMDCR => p.dcr = v & M_DCR_MASK,
            M_PWMPCR => p.pcr = v & M_PCR_MASK,
            _ => panic!("write to offset {off:#x}: not a register of this block"),
        }
    }
}

// ── the period arithmetic ───────────────────────────────────────────────────

/// The registers `pxa_pwm_config` computes for 1 ms at 12.8 MHz, worked by
/// hand: 12 800 cycles; prescale = 12 799 / 1024 = 12; pv = 12 800 / 13 - 1 =
/// 983; 50 %: dc = 984 * 500 000 / 1 000 000 = 492; PWMCR = 12 | SD.
#[test]
fn a_one_millisecond_half_duty_period_programs_the_registers_linux_would() {
    let t = timing_for(1_000_000).unwrap();
    assert_eq!(t, Timing { prescale: 12, pv: 983 });
    assert_eq!(duty_count(t, 500_000, 1_000_000), 492);

    let m = Model::new();
    PxaPwm::new(m.clone()).configure(t, 492);
    assert_eq!(m.regs(), (0x4c, 492, 983));
    assert_eq!(
        m.log(),
        vec![Access::Write(M_PWMCR, 0x4c), Access::Write(M_PWMDCR, 492), Access::Write(M_PWMPCR, 983)],
        "pxa_pwm_config's order: PWMCR, PWMDCR, PWMPCR"
    );
}

#[test]
fn the_programmed_period_is_the_one_asked_for_to_a_prescale_step() {
    // From the shortest the part can do to its longest, every 7.3 us.
    let mut ns = 100u32;
    while ns <= 5_120_000 {
        let t = timing_for(ns).unwrap_or_else(|| panic!("{ns} ns is inside the range"));
        let m = Model::new();
        PxaPwm::new(m.clone()).configure(t, 0);
        let got = m.out().period_ns;
        let step_ns = (t.prescale as u64 + 1) * 1_000_000_000 / M_CLK + 1;
        assert!(got <= ns as u64, "{ns} ns asked, the part would run {got} ns: longer than asked");
        assert!(ns as u64 - got <= step_ns, "{ns} ns asked, {got} ns programmed: more than a prescale step ({step_ns}) short");
        ns += 7_321;
    }
}

#[test]
fn the_period_range_is_the_clocks() {
    assert_eq!(timing_for(0), None, "a zero period");
    // 1 ns is less than one clock cycle: pxa_pwm_config rounds up to 1.
    assert_eq!(timing_for(1), Some(Timing { prescale: 0, pv: 0 }));
    // 64 * 1024 cycles at 12.8 MHz = 5.12 ms: the longest, prescale 63, pv 1023.
    assert_eq!(timing_for(5_120_000), Some(Timing { prescale: 63, pv: 1023 }));
    // One cycle more needs prescale 64: refused, as Linux's -EINVAL.
    assert_eq!(timing_for(5_121_000), None);
    // A 50 Hz servo/ESC period is far out.
    assert_eq!(timing_for(20_000_000), None);
    assert_eq!(timing_for(u32::MAX), None);
}

// ── the duty arithmetic ─────────────────────────────────────────────────────

#[test]
fn duty_counts_and_the_full_duty_flag() {
    let t = timing_for(1_000_000).unwrap(); // pv = 983: 984 counts per period
    assert_eq!(duty_count(t, 0, 1_000_000), 0);
    assert_eq!(duty_count(t, 250_000, 1_000_000), 246);
    assert_eq!(duty_count(t, 999_999, 1_000_000), 983, "just short of full is not full");
    assert_eq!(duty_count(t, 1_000_000, 1_000_000), 1 << 10, "PWMDCR_FD");
    assert_eq!(duty_count(t, 2_000_000, 1_000_000), 1 << 10, "more than the period is full");
}

#[test]
fn the_percentage_decodes_from_the_registers() {
    assert_eq!(duty_pct_of(0, 983), 0);
    assert_eq!(duty_pct_of(492, 983), 50);
    assert_eq!(duty_pct_of(1 << 10, 983), 100);
    assert_eq!(duty_pct_of((1 << 10) | 5, 983), 100, "FD wins over a stale count");
    // 1023 is the largest pv: 1024 counts, dc = 1023 is 99.9 %, rounds to 100.
    assert_eq!(duty_pct_of(1023, 1023), 100);
}

// ── where the controllers are ───────────────────────────────────────────────

#[test]
fn a_node_address_names_the_hardware_pwm_number() {
    // pwm0..pwm7 of k1.dtsi, literally.
    let nodes = [0xd401_a000usize, 0xd401_a400, 0xd401_a800, 0xd401_ac00, 0xd401_b000, 0xd401_b400, 0xd401_b800, 0xd401_bc00];
    for (n, base) in nodes.iter().enumerate() {
        assert_eq!(channel_of(*base), Some(n), "pwm{n}");
    }
    assert_eq!(channel_of(0xd402_0000), None, "pwm8 starts the second block: not driven");
    assert_eq!(channel_of(0xd401_c000), None, "past pwm7 is not a PWM (i2c7 is at d401d000)");
    assert_eq!(channel_of(0xd401_a010), None, "inside a window is not its start");
    assert_eq!(channel_of(0xd401_9000), None, "the GPIO block");
    assert_eq!(channel_of(0), None);
}

// ── the channel ─────────────────────────────────────────────────────────────

fn chan(period_ns: u32) -> (ChanState, PxaPwm<Model>, Model) {
    let m = Model::new();
    let c = ChanState::new();
    let mut p = PxaPwm::new(m.clone());
    assert_eq!(c.set_period(&mut p, period_ns), 0);
    m.clear_log();
    (c, p, m)
}

#[test]
fn enabling_a_channel_nobody_gave_a_duty_leaves_it_low() {
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(m.out().duty_ns, 0);
    assert_eq!(c.snapshot(), (true, 1_000_000, 0));
}

#[test]
fn a_duty_set_while_disabled_waits_for_the_enable() {
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.set_duty_pct(&mut p, 50), 0);
    assert_eq!(m.regs().1, 0, "disabled: PWMDCR stays 0, the output is inactive");
    assert_eq!(m.regs().2, 983, "but the period is programmed");
    assert_eq!(c.enable(&mut p), 0);
    let o = m.out();
    assert!(o.duty_ns.abs_diff(500_000) <= 1_100, "{o:?}");
    assert_eq!(m.regs().1, 492);
}

#[test]
fn disable_is_one_store_that_zeroes_the_duty_and_enable_restores_it() {
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.set_duty_pct(&mut p, 25), 0);
    assert_eq!(c.enable(&mut p), 0);
    let live = m.regs();
    assert_eq!(live.1, 246);

    m.clear_log();
    assert_eq!(c.disable(&mut p), 0);
    assert_eq!(m.log(), vec![Access::Write(M_PWMDCR, 0)], "ONE store");
    assert_eq!(m.out().duty_ns, 0);
    assert_eq!(c.snapshot(), (false, 1_000_000, 250_000), "the setting is kept");

    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(m.regs(), live, "the same registers as before the stop");
}

#[test]
fn an_out_of_range_period_is_refused_and_changes_nothing() {
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.set_duty_pct(&mut p, 40), 0);
    assert_eq!(c.enable(&mut p), 0);
    let before = (m.regs(), c.snapshot());
    m.clear_log();
    for bad in [0u32, 5_121_000, 20_000_000] {
        assert_eq!(c.set_period(&mut p, bad), -1, "{bad} ns");
    }
    assert_eq!(m.log(), vec![], "no register written");
    assert_eq!((m.regs(), c.snapshot()), before);
}

#[test]
fn shrinking_the_period_clamps_the_duty_and_keeps_it_in_nanoseconds() {
    let (c, mut p, m) = chan(4_000_000);
    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(c.set_duty(&mut p, 3_000_000), 0);
    assert_eq!(c.snapshot().2, 3_000_000);
    assert_eq!(c.set_period(&mut p, 2_000_000), 0);
    assert_eq!(c.snapshot().2, 2_000_000, "clamped to the new period");
    assert_eq!(m.regs().1, 1 << 10, "a full period is PWMDCR_FD");
    // A longer period keeps the clamped duty, it does not scale it back.
    assert_eq!(c.set_period(&mut p, 4_000_000), 0);
    assert_eq!(c.snapshot().2, 2_000_000);
    let o = m.out();
    assert!(o.duty_ns.abs_diff(2_000_000) <= 2_100 && o.period_ns.abs_diff(4_000_000) <= 2_100, "{o:?}");
}

#[test]
fn the_reported_duty_is_the_hardwares_number() {
    let (c, mut p, _m) = chan(1_000_000);
    assert_eq!(c.enable(&mut p), 0);
    for pct in 0..=100u32 {
        let got = c.set_duty_pct_reporting(&mut p, pct).unwrap();
        assert!(got.abs_diff(pct) <= 1, "asked {pct} %, the registers describe {got} %");
    }
    assert_eq!(c.set_duty_pct_reporting(&mut p, 100), Some(100));
    assert_eq!(c.set_duty_pct_reporting(&mut p, 250), Some(100), "clamped");
    assert_eq!(c.set_duty_pct_reporting(&mut p, 0), Some(0));
}

#[test]
fn a_disabled_channel_reports_zero_whatever_was_asked() {
    let (c, mut p, _m) = chan(1_000_000);
    assert_eq!(c.set_duty_pct_reporting(&mut p, 80), Some(0));
}

#[test]
fn a_controller_whose_clock_is_off_is_reported_not_believed() {
    // The APBC gate is the platform's and unmodelled: if the firmware left it
    // off, the registers hold nothing. The driver reads back; it must say 0.
    let m = Model::gated();
    let c = ChanState::new();
    let mut p = PxaPwm::new(m.clone());
    assert_eq!(c.enable(&mut p), 0, "the writes themselves cannot tell");
    assert_eq!(c.set_duty_pct_reporting(&mut p, 50), Some(0), "the readback can");
    assert_eq!(m.regs(), (0, 0, 0));
}

#[test]
fn the_panic_stop_is_one_store_and_never_starts_an_output() {
    let (c, mut p, m) = chan(1_000_000);
    // Disabled: a stop (or a mistaken "set 100") leaves the output low.
    m.clear_log();
    c.stop_to(&mut p, 100);
    assert_eq!(m.log(), vec![Access::Write(M_PWMDCR, 0)], "one store, and it is 0");

    // Enabled at 60 %: the stop to 0 is one store of 0.
    assert_eq!(c.set_duty_pct(&mut p, 60), 0);
    assert_eq!(c.enable(&mut p), 0);
    assert!(m.regs().1 > 0);
    m.clear_log();
    c.stop_to(&mut p, 0);
    assert_eq!(m.log(), vec![Access::Write(M_PWMDCR, 0)]);
    assert_eq!(m.out().duty_ns, 0);

    // The safe-state drive may also ask for a duty on an enabled channel.
    m.clear_log();
    c.stop_to(&mut p, 100);
    assert_eq!(m.log(), vec![Access::Write(M_PWMDCR, 1 << 10)]);
}

#[test]
fn only_the_stop_path_avoids_the_whole_configuration() {
    // A duty change on a live channel rewrites PWMCR, PWMDCR, PWMPCR (the
    // sequence pxa_pwm_config runs on every apply); the stop path is the one
    // single store.
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.enable(&mut p), 0);
    m.clear_log();
    assert_eq!(c.set_duty_pct(&mut p, 10), 0);
    let writes: Vec<usize> = m.log().iter().filter_map(|a| if let Access::Write(o, _) = a { Some(*o) } else { None }).collect();
    assert_eq!(writes, vec![M_PWMCR, M_PWMDCR, M_PWMPCR]);
}

// ── the stop is remembered (the cross-hart races of the lock-free store) ────

/// A bus that runs `hook` once, right after (or, with `before`, right
/// before) the write at `trigger` offset: the moment another hart's
/// `pwm_set_duty_pct_panic` lands in the middle of a locked writer's three
/// stores, or a `disable` lands just before the stop's store.
struct Hooked<'a> {
    inner: Model,
    trigger: usize,
    before: bool,
    hook: Option<Box<dyn FnOnce() + 'a>>,
}

impl PxaPwmBus for Hooked<'_> {
    fn read32(&mut self, off: usize) -> u32 {
        self.inner.read32(off)
    }
    fn write32(&mut self, off: usize, v: u32) {
        if off == self.trigger && self.before {
            if let Some(h) = self.hook.take() {
                h();
            }
        }
        self.inner.write32(off, v);
        if off == self.trigger {
            if let Some(h) = self.hook.take() {
                h();
            }
        }
    }
}

#[test]
fn a_stop_that_lands_inside_a_configuration_is_not_overwritten_by_its_stale_duty() {
    // Canary: without the pending stop the writer's PWMPCR store (the third)
    // is harmless but its PWMDCR store is not; the stop lands after PWMDCR was
    // written and BEFORE the writer's last store, then the writer finishes.
    // The final PWMDCR must be the stop's, and the output must be low.
    for hit in [M_PWMCR, M_PWMDCR, M_PWMPCR] {
        let m = Model::new();
        let c = ChanState::new();
        let mut p0 = PxaPwm::new(m.clone());
        assert_eq!(c.set_period(&mut p0, 1_000_000), 0);
        assert_eq!(c.enable(&mut p0), 0);
        assert_eq!(c.set_duty_pct(&mut p0, 60), 0);
        assert!(m.out().duty_ns > 0);

        let stopper_bus = m.clone();
        let cr = &c;
        let mut p = PxaPwm::new(Hooked {
            inner: m.clone(),
            trigger: hit,
            before: false,
            hook: Some(Box::new(move || cr.stop_to(&mut PxaPwm::new(stopper_bus), 0))),
        });
        // The writer computed 80 % from the cache before the stop.
        assert_eq!(c.set_duty_pct(&mut p, 80), 0);
        assert_eq!(m.regs().1, 0, "stop after the writer's store at {hit:#x} was lost");
        assert_eq!(m.out().duty_ns, 0);
    }
}

#[test]
fn a_stop_lands_before_a_writer_that_already_read_the_cache_and_still_wins() {
    // The writer read enabled/period/duty, then the stop ran completely, then
    // the writer stored (hook at the first store: PWMCR).
    let m = Model::new();
    let c = ChanState::new();
    let mut p0 = PxaPwm::new(m.clone());
    assert_eq!(c.set_period(&mut p0, 1_000_000), 0);
    assert_eq!(c.enable(&mut p0), 0);
    assert_eq!(c.set_duty_pct(&mut p0, 60), 0);
    let sb = m.clone();
    let cr = &c;
    let mut p = PxaPwm::new(Hooked { inner: m.clone(), trigger: M_PWMCR, before: false, hook: Some(Box::new(move || cr.stop_to(&mut PxaPwm::new(sb), 0))) });
    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(m.regs().1, 0);
}

#[test]
fn after_a_stop_enable_set_period_and_disable_enable_do_not_restart_the_old_duty() {
    // Canary: the cache held the pre-stop 60 %; without recording the stop,
    // each of these re-applied it and the output restarted.
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(c.set_duty_pct(&mut p, 60), 0);
    c.stop_to(&mut p, 0);
    assert_eq!(c.snapshot().2, 0, "the cache says what the part does");

    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(m.out().duty_ns, 0, "enable");
    assert_eq!(c.set_period(&mut p, 2_000_000), 0);
    assert_eq!(m.out().duty_ns, 0, "set_period");
    assert_eq!(c.disable(&mut p), 0);
    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(m.out().duty_ns, 0, "disable then enable");

    // A new duty command is a newer command: it supersedes the stop.
    assert_eq!(c.set_duty_pct(&mut p, 25), 0);
    assert!(m.out().duty_ns.abs_diff(500_000) <= 2_100, "{:?}", m.out());
    // And the stop does not linger after it was superseded.
    assert_eq!(c.set_period(&mut p, 1_000_000), 0);
    assert!(m.out().duty_ns.abs_diff(500_000) <= 2_100, "{:?}", m.out());
}

#[test]
fn a_stop_of_a_disabled_channel_is_zero_and_stays_zero_through_enable() {
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.set_duty_pct(&mut p, 70), 0);
    c.stop_to(&mut p, 100);
    assert_eq!(c.enable(&mut p), 0);
    assert_eq!(m.out().duty_ns, 0, "a stop never starts an output");
}

#[test]
fn a_stop_keeps_its_duty_across_a_period_change() {
    // The pending stop is a percentage, not a register value: a new period
    // changes the counters, and the re-asserted value follows them.
    let (c, mut p, m) = chan(1_000_000);
    assert_eq!(c.enable(&mut p), 0);
    c.stop_to(&mut p, 40);
    assert_eq!(c.set_period(&mut p, 2_000_000), 0);
    let o = m.out();
    assert!(o.duty_ns.abs_diff(800_000) <= 4_200 && o.period_ns.abs_diff(2_000_000) <= 4_200, "{o:?}");
}

#[test]
fn a_disable_racing_a_stop_leaves_the_channel_low() {
    // The stop read `enabled`, then a disable ran completely (its 0 store),
    // then the stop's store: the channel is disabled and must end low.
    let m = Model::new();
    let c = ChanState::new();
    let mut p0 = PxaPwm::new(m.clone());
    assert_eq!(c.set_period(&mut p0, 1_000_000), 0);
    assert_eq!(c.enable(&mut p0), 0);
    assert_eq!(c.set_duty_pct(&mut p0, 60), 0);
    // The disable lands between the stop's read of `enabled` and its store.
    let db = m.clone();
    let cr = &c;
    let mut p = PxaPwm::new(Hooked { inner: m.clone(), trigger: M_PWMDCR, before: true, hook: Some(Box::new(move || { cr.disable(&mut PxaPwm::new(db)); })) });
    c.stop_to(&mut p, 100);
    assert_eq!(m.out().duty_ns, 0);
}
