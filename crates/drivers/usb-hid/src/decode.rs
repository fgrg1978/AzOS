// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Input reports to evdev events, and the autorepeat USB keyboards lack.
//!
//! [`Decoder::report`] walks a [`Layout`]'s controls for one report. Axes are
//! emitted as they are read (a relative axis when it moved, an absolute one
//! when it changed); keys and buttons are collected into the set of evdev codes
//! that are down in this report and compared with the set of the previous
//! report of the same ID, so a press, a release and a key that stays down are
//! told apart whether the keyboard sends a bitmap, an array of six keys or a
//! mix. Within one report the modifier keys are emitted first, then the
//! releases, then the presses: Shift and `a` arriving together are `A`, and
//! Shift going up with a key coming down is `a`.
//!
//! The events are the ones every other input producer emits: `(type, code,
//! value)`, `EV_KEY` with value 1 or 0, `EV_REL`, `EV_ABS` scaled to
//! `0..=ABS_MAX`. A USB keyboard repeats nothing in hardware: [`Repeat`] is
//! the typematic of the keys that make bytes.

use azos_input_wire::event::{ABS_MAX, BTN_MOUSE, EV_ABS, EV_KEY, EV_REL};

use crate::report::{Kind, Layout, MAX_CONTROLS, MAX_IDS};
use crate::usage::{button_code, is_array_error, is_modifier_code, key_code, MODIFIER_CODES, PAGE_KEYBOARD};

/// Evdev codes the key set holds (keys below 0x100 and 16 buttons from 0x110).
const CODES: usize = 0x120;
const WORDS: usize = CODES.div_ceil(64);

/// A set of evdev key and button codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CodeSet([u64; WORDS]);

impl CodeSet {
    const EMPTY: CodeSet = CodeSet([0; WORDS]);

    /// Add `code`; 0 is no key.
    fn set(&mut self, code: u16) {
        if code != 0 && (code as usize) < CODES {
            self.0[code as usize / 64] |= 1 << (code % 64);
        }
    }

    fn has(&self, code: u16) -> bool {
        (code as usize) < CODES && self.0[code as usize / 64] & 1 << (code % 64) != 0
    }

    /// Call `f` for every code in `self` and not in `other`, in code order.
    fn for_each_not_in(&self, other: &CodeSet, mut f: impl FnMut(u16)) {
        for w in 0..WORDS {
            let mut bits = self.0[w] & !other.0[w];
            while bits != 0 {
                let b = bits.trailing_zeros();
                bits &= bits - 1;
                f((w * 64) as u16 + b as u16);
            }
        }
    }
}

/// Read `size` bits at bit `off` of `p` (little-endian bit order, as HID
/// numbers them); `None` when they are not all there.
fn bits(p: &[u8], off: usize, size: usize) -> Option<u32> {
    if size == 0 || size > 32 || off + size > p.len() * 8 {
        return None;
    }
    let (first, last) = (off / 8, (off + size - 1) / 8);
    let mut v = 0u64;
    for (k, b) in p[first..=last].iter().enumerate() {
        v |= (*b as u64) << (8 * k);
    }
    Some(((v >> (off % 8)) & ((1u64 << size) - 1)) as u32)
}

fn sign_extend(v: u32, size: usize) -> i32 {
    let shift = 32 - size as u32;
    ((v << shift) as i32) >> shift
}

/// The state of the decoder of one interface.
#[derive(Clone, Copy, Debug)]
pub struct Decoder {
    /// The keys and buttons down after the last report of each ID.
    down: [CodeSet; MAX_IDS],
    /// The last position of each absolute control (`i32::MIN`: none yet).
    last: [i32; MAX_CONTROLS],
    /// Reports dropped: for an ID the layout does not have, too short to hold
    /// anything, or a key array that said nothing reliable (rollover).
    pub dropped: u32,
}

impl Decoder {
    pub const fn new() -> Decoder {
        Decoder { down: [CodeSet::EMPTY; MAX_IDS], last: [i32::MIN; MAX_CONTROLS], dropped: 0 }
    }

    /// One report from the device. `emit(type, code, value)` is called once per
    /// event.
    pub fn report(&mut self, l: &Layout, buf: &[u8], mut emit: impl FnMut(u16, u16, u32)) {
        let (idx, payload) = if l.has_ids {
            let Some((&id, rest)) = buf.split_first() else {
                self.dropped += 1;
                return;
            };
            let Some(i) = l.index_of(id) else {
                self.dropped += 1;
                return;
            };
            (i, if cfg!(feature = "canary-report-id") { buf } else { rest })
        } else {
            (0, buf)
        };
        if payload.is_empty() {
            self.dropped += 1;
            return;
        }
        let mut now = CodeSet::EMPTY;
        for (ci, c) in l.controls().iter().enumerate() {
            if c.id as usize != idx {
                continue;
            }
            match c.kind {
                Kind::Bits => {
                    for i in 0..c.count as usize {
                        let Some(v) = bits(payload, c.off as usize + i * c.size as usize, c.size as usize) else { break };
                        if v == 0 {
                            continue;
                        }
                        let usage = c.base.wrapping_add(i as u16);
                        let code = if c.page == PAGE_KEYBOARD { key_code(usage) } else { button_code(usage) };
                        now.set(code);
                    }
                }
                Kind::Array => {
                    for i in 0..c.count as usize {
                        let Some(v) = bits(payload, c.off as usize + i * c.size as usize, c.size as usize) else { break };
                        let v = v as i32;
                        if v < c.lmin || v > c.lmax {
                            continue;
                        }
                        let usage = (c.base as i32 + (v - c.lmin)) as u16;
                        if is_array_error(usage) {
                            // The keyboard cannot tell which keys are down: the
                            // report changes nothing.
                            #[cfg(not(feature = "canary-rollover"))]
                            {
                                self.dropped += 1;
                                return;
                            }
                        }
                        now.set(key_code(usage));
                    }
                }
                Kind::Rel => {
                    let Some(v) = bits(payload, c.off as usize, c.size as usize) else { continue };
                    #[cfg(not(feature = "canary-sign"))]
                    let v = if c.lmin < 0 { sign_extend(v, c.size as usize) } else { v as i32 };
                    #[cfg(feature = "canary-sign")]
                    let v = v as i32;
                    if v != 0 {
                        emit(EV_REL, c.code, v as u32);
                    }
                }
                Kind::Abs => {
                    let Some(v) = bits(payload, c.off as usize, c.size as usize) else { continue };
                    let v = if c.lmin < 0 { sign_extend(v, c.size as usize) } else { v as i32 };
                    let last = &mut self.last[ci];
                    if *last != v && c.lmax > c.lmin {
                        *last = v;
                        let span = c.lmax as i64 - c.lmin as i64;
                        let scaled = ((v as i64 - c.lmin as i64) * ABS_MAX as i64 / span).clamp(0, ABS_MAX as i64);
                        emit(EV_ABS, c.code, scaled as u32);
                    }
                }
            }
        }
        let prev = self.down[idx];
        self.down[idx] = now;
        diff(&prev, &now, &mut emit);
    }

    /// Every key and button still down is released (the device is gone, or its
    /// pipe failed). The consumers keep state built from the events.
    pub fn release_all(&mut self, mut emit: impl FnMut(u16, u16, u32)) {
        for d in self.down.iter_mut() {
            diff(d, &CodeSet::EMPTY, &mut emit);
            *d = CodeSet::EMPTY;
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new()
    }
}

/// Emit the changes from `prev` to `now`: modifiers, then releases, then presses.
fn diff(prev: &CodeSet, now: &CodeSet, emit: &mut impl FnMut(u16, u16, u32)) {
    let modifiers = |emit: &mut dyn FnMut(u16, u16, u32)| {
        for m in MODIFIER_CODES {
            if prev.has(m) != now.has(m) {
                emit(EV_KEY, m, now.has(m) as u32);
            }
        }
    };
    #[cfg(not(feature = "canary-modifier-order"))]
    modifiers(emit);
    prev.for_each_not_in(now, |c| {
        if !is_modifier_code(c) {
            emit(EV_KEY, c, 0);
        }
    });
    now.for_each_not_in(prev, |c| {
        if !is_modifier_code(c) {
            emit(EV_KEY, c, 1);
        }
    });
    #[cfg(feature = "canary-modifier-order")]
    modifiers(emit);
}

/// Typematic for a keyboard that sends a report on change only: the most recent
/// key to go down repeats after a delay, at a period, until it or another key
/// changes. Modifiers and buttons do not repeat.
#[derive(Clone, Copy, Debug)]
pub struct Repeat {
    code: u16,
    next_ms: u64,
}

impl Repeat {
    pub const fn new() -> Repeat {
        Repeat { code: 0, next_ms: 0 }
    }

    /// Whether `code` is a key that repeats.
    pub const fn repeats(code: u16) -> bool {
        code != 0 && code < BTN_MOUSE && !is_modifier_code(code)
    }

    /// Note an event the decoder emitted. `delay_ms` is the wait before the
    /// first repeat of a key that just went down.
    pub fn observe(&mut self, ty: u16, code: u16, value: u32, now_ms: u64, delay_ms: u64) {
        if ty != EV_KEY {
            return;
        }
        if value == 1 && Self::repeats(code) {
            self.code = code;
            self.next_ms = now_ms + delay_ms;
        } else if value == 0 && code == self.code {
            self.code = 0;
        }
    }

    /// The key to repeat now, if one is due; the next one is `period_ms` on
    /// (from now: a service that ran late repeats once, not in a burst).
    pub fn due(&mut self, now_ms: u64, period_ms: u64) -> Option<u16> {
        if self.code != 0 && now_ms >= self.next_ms {
            self.next_ms = now_ms + period_ms;
            return Some(self.code);
        }
        None
    }

    /// Forget the key (the device went away).
    pub fn clear(&mut self) {
        self.code = 0;
    }
}

impl Default for Repeat {
    fn default() -> Self {
        Repeat::new()
    }
}
