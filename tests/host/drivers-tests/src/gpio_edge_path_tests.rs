// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kill switch's edge-to-press path on the host: the controller model
//! (`gpio_jh7110_irq_tests`' block, `gpio_k1_tests`' part are separate; this
//! file keeps a minimal one of its own) raises its line on an edge, the
//! handler's step (`Jh7110Irq::take`) acknowledges and masks, the task's step
//! samples the level through `debounce::Switch` and unmasks. A press is the
//! stop (`gate::latch_and_stop` in the kernel) and the record.
//!
//! The canary is the poll it replaced: one sample per 500 ms period, no edge.
//! The same switch history must give the poll a press up to a period late,
//! and the edge path a press at the edge's own handling.

use super::debounce::{Step, Switch};
use super::gpio_jh7110_irq::{Jh7110Bus, Jh7110Irq};
use std::cell::RefCell;
use std::rc::Rc;

/// Microseconds, the test's clock.
type Us = u64;

const PIN: u32 = 30;
const WINDOW_US: Us = 5_000;
const POLL_US: Us = 500_000;

/// A one-word model of the JH7110 block: enough for one pin on both edges
/// (the full model is `gpio_jh7110_irq_tests`').
#[derive(Default)]
struct Block {
    regs: std::collections::HashMap<usize, u32>,
    level: bool,
    ris: u32,
}

impl Block {
    fn get(&self, off: usize) -> u32 {
        *self.regs.get(&off).unwrap_or(&0)
    }
    fn drive(&mut self, high: bool) {
        if self.level != high {
            self.level = high;
            let bit = 1 << PIN;
            if self.get(0x0e0) & bit != 0 && self.get(0x0f0) & bit != 0 {
                self.ris |= bit;
            }
        }
    }
    fn line(&self) -> bool {
        self.get(0x0dc) & 1 != 0 && self.ris & self.get(0x100) != 0
    }
}

#[derive(Clone)]
struct Bus(Rc<RefCell<Block>>);

impl Jh7110Bus for Bus {
    fn read32(&mut self, off: usize) -> u32 {
        let b = self.0.borrow();
        if off == 0x110 { b.ris & b.get(0x100) } else { b.get(off) }
    }
    fn write32(&mut self, off: usize, v: u32) {
        let mut b = self.0.borrow_mut();
        if off == 0x0e8 {
            let rising = !b.get(0x0e8) & v;
            b.ris &= !rising;
        }
        b.regs.insert(off, v);
    }
}

/// The edge path: the changes of the pad at one instant are applied, then
/// handled (the handler, then the woken task's sample); a release window also
/// gets its deadline sample. Returns the times of the presses.
fn edge_path(history: &[(Us, bool)]) -> Vec<Us> {
    let block = Rc::new(RefCell::new(Block { level: true, ..Default::default() }));
    let mut irq = Jh7110Irq::new(Bus(block.clone()));
    irq.init();
    irq.set_both_edges(PIN);
    irq.ack(PIN);
    irq.set_unmasked(PIN, true);
    // Active-low: the pad reads 0 when pressed.
    let mut sw = Switch::new(true, WINDOW_US);
    let mut presses = Vec::new();
    let sample = |sw: &mut Switch, t: Us, block: &Rc<RefCell<Block>>, presses: &mut Vec<Us>| {
        let level = block.borrow().level as i32;
        if sw.sample(t, level) == Step::Press {
            presses.push(t);
        }
    };
    // The arm's own sample.
    sample(&mut sw, 0, &block, &mut presses);
    let mut i = 0;
    while i < history.len() {
        let t = history[i].0;
        // A release window that ended before this edge is sampled at its end.
        if let Some(d) = sw.deadline() {
            if d <= t {
                sample(&mut sw, d, &block, &mut presses);
            }
        }
        while i < history.len() && history[i].0 == t {
            block.borrow_mut().drive(history[i].1);
            i += 1;
        }
        if block.borrow().line() {
            assert!(irq.take(PIN), "the line is up for the armed pin");
            assert!(!block.borrow().line(), "acknowledged and masked by the handler");
            sample(&mut sw, t, &block, &mut presses);
            irq.set_unmasked(PIN, true);
        }
    }
    presses
}

/// The poll it replaced: the pad read once per period.
fn old_poll(history: &[(Us, bool)], until: Us) -> Vec<Us> {
    let mut was_pressed = false;
    let mut presses = Vec::new();
    let mut t = 0;
    while t <= until {
        let high = history.iter().rev().find(|&&(ht, _)| ht <= t).map_or(true, |&(_, h)| h);
        let pressed = !high;
        if !pressed {
            was_pressed = false;
        }
        if pressed && !was_pressed {
            was_pressed = true;
            presses.push(t);
        }
        t += POLL_US;
    }
    presses
}

/// Pressed at 1.2 s with a bounce, held, released at 3 s with a bounce.
const ONE_PRESS: &[(Us, bool)] = &[
    (1_200_000, false),
    (1_200_150, true),
    (1_200_300, false),
    (3_000_000, true),
    (3_000_200, false),
    (3_000_400, true),
];

#[test]
fn the_edge_path_presses_at_the_edge() {
    let p = edge_path(ONE_PRESS);
    assert_eq!(p, vec![1_200_000], "one press, at the first edge's handling");
}

#[test]
fn canary_the_old_poll_presses_up_to_a_period_late() {
    let p = old_poll(ONE_PRESS, 4_000_000);
    assert_eq!(p.len(), 1);
    // Discriminates: 300 ms after the edge, against the edge path's 0, and
    // 1 ms is the target.
    assert!(p[0] - 1_200_000 > 1_000, "the poll's press is {} us after the edge", p[0] - 1_200_000);
}

#[test]
fn a_release_and_a_second_press_after_the_window_are_two_presses() {
    let mut h = ONE_PRESS.to_vec();
    h.push((5_000_000, false));
    assert_eq!(edge_path(&h), vec![1_200_000, 5_000_000]);
}

#[test]
fn a_glitch_over_before_the_sample_is_not_a_press() {
    // The pad dips and is back high before the handler's sample: the model
    // applies both edges, and the sample after the second one reads high.
    let block_history = [(2_000_000, false), (2_000_000, true)];
    assert_eq!(edge_path(&block_history), Vec::<Us>::new());
}

#[test]
fn a_switch_held_at_the_arm_is_a_press_with_no_edge() {
    let block = Rc::new(RefCell::new(Block { level: false, ..Default::default() }));
    let mut irq = Jh7110Irq::new(Bus(block.clone()));
    irq.init();
    irq.set_both_edges(PIN);
    irq.ack(PIN);
    irq.set_unmasked(PIN, true);
    assert!(!block.borrow().line(), "no edge to raise the line");
    let mut sw = Switch::new(true, WINDOW_US);
    assert_eq!(sw.sample(0, block.borrow().level as i32), Step::Press, "the arm's sample is the press");
}

#[test]
fn a_refused_read_is_no_sample_and_polarity_follows_the_tree() {
    let mut sw = Switch::new(true, WINDOW_US);
    assert_eq!(sw.sample(0, -1), Step::Quiet);
    assert_eq!(sw.sample(1, 1), Step::Quiet, "active-low: high is released");
    let mut hi = Switch::new(false, WINDOW_US);
    assert_eq!(hi.sample(0, 0), Step::Quiet, "active-high: low is released");
    assert_eq!(hi.sample(1, 1), Step::Press);
}
