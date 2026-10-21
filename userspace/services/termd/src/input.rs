// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The terminal server's consumer of the input event ring.
//!
//! The kernel's input drivers (PS/2, virtio-input) publish every event the
//! console has no byte for into one ring, in one word format
//! (`azos_input_wire::event`). This is its consumer, as gpm is on a Linux
//! console: key events become escape sequences ([`crate::keys`]) and mouse
//! events become the pointer, selection, paste and scrollback
//! ([`crate::mouse`]) or xterm mouse reports, all of it on the terminal
//! input ([`Sink`]).
//!
//! [`Input::pump`] takes what is in the ring each time the server looks at its
//! input. When there is nothing and the server is about to sleep on the
//! console (the same wait serves the typed bytes and the ring),
//! [`Input::announce`] says so on the ring's consumer flag, which makes the
//! producer nudge that wait on its next event; [`Input::woke`] withdraws it.
//! No timer: an idle terminal is not woken. The screen region is optional:
//! without a framebuffer console there is no screen to point at, and keys
//! still work.
//!
//! **Resynchronizing.** Modifiers and buttons are rebuilt from the events, and
//! a full ring drops the newest one: a lost release would leave Shift, Ctrl or
//! a button stuck (Shift stuck turns mouse reporting off). The producer counts
//! its drops in the region ([`EventSource::drops`]); when the count moved and
//! the ring has been drained, everything held is let go (a button held is
//! released to the program that was told it went down). The count has no
//! position, so a key or button pressed after the drop but before the ring
//! emptied is let go too: a forgotten press comes back with the next one, a
//! stuck one would not.
//!
//! Pure given a ring and a screen: `tests/host/term-tests` pulls this file in
//! with `#[path]`.

use crate::keys::{self, Mods};
use crate::mouse::{Mouse, Sink};
use azos_input_wire::event::*;
use azos_input_wire::screen::{Overlay, Viewer};
use azos_rings::region::{RingSleep, SpscRing};
use core::sync::atomic::{AtomicU32, Ordering};

/// Most events one [`Input::pump`] takes, so a flood cannot starve the
/// terminal's other work.
pub const BATCH: usize = 128;

/// Where events come from: the consumer end of the ring.
pub trait EventSource {
    fn pop(&mut self) -> Option<u64>;
    /// The consumer is about to sleep: announce it so the producer wakes it.
    /// `false`: an event arrived meanwhile, do not sleep.
    fn announce(&mut self) -> bool;
    /// The consumer is awake again: withdraw the announcement.
    fn woke(&mut self);
    /// Events the producer dropped (full ring) since it began; wraps.
    fn drops(&self) -> u32;
}

impl EventSource for SpscRing {
    fn pop(&mut self) -> Option<u64> {
        match self.try_pop() {
            (azos_rings::region::RingStep::Blocked, _) => None,
            (_, w) => Some(w),
        }
    }

    fn announce(&mut self) -> bool {
        matches!(self.consumer_sleep(), RingSleep::Wait { .. })
    }

    fn woke(&mut self) {
        self.consumer_woke();
    }

    fn drops(&self) -> u32 {
        // SAFETY: the mapping is the event region, `main.rs` checked it
        // reaches the counter's line (`DROPS_OFFSET`); it stays mapped.
        unsafe { &*((self.base + DROPS_OFFSET) as *const AtomicU32) }.load(Ordering::Acquire)
    }
}

/// The consumer.
pub struct Input<R: EventSource> {
    ring: R,
    screen: Option<Viewer>,
    mods: Mods,
    mouse: Mouse,
    /// The last overlay written to the region.
    shown: Overlay,
    /// The producer's drop count the state was last made sure of.
    drops: u32,
}

impl<R: EventSource> Input<R> {
    /// Take over `ring`, dropping what piled up before there was a consumer
    /// (stale keys and motion nobody should act on now).
    pub fn new(mut ring: R, screen: Option<Viewer>) -> Self {
        while ring.pop().is_some() {}
        let drops = ring.drops();
        let mut s = Self { ring, screen, mods: Mods::new(), mouse: Mouse::new(), shown: Overlay::default(), drops };
        if let Some(scr) = &s.screen {
            s.mouse.sync(scr);
        }
        s
    }

    /// Is there a screen to point at?
    pub fn has_screen(&self) -> bool {
        self.screen.is_some()
    }

    /// Typed bytes arrived on the console: a key was pressed.
    pub fn console_key(&mut self) {
        self.mouse.key_pressed();
    }

    /// The program that was in the foreground is gone: forget the mouse mode
    /// it set and left on.
    pub fn job_ended(&mut self) {
        if let Some(scr) = &self.screen {
            scr.clear_mouse_mode();
        }
    }

    /// Take the events waiting, at most [`BATCH`]. Returns whether any were.
    pub fn pump(&mut self, now_ns: u64, sink: &mut impl Sink) -> bool {
        if let Some(scr) = &self.screen {
            self.mouse.sync(scr);
        }
        // Read before draining: a drop that lands while draining is seen the
        // next time.
        let drops = self.ring.drops();
        let mut any = false;
        let mut drained = false;
        for _ in 0..BATCH {
            let Some(w) = self.ring.pop() else {
                drained = true;
                break;
            };
            any = true;
            let (ty, code, value) = unpack(w);
            self.event(ty, code, value, now_ns, sink);
        }
        // Only after the ring is empty, so no event from before the drop is
        // still to come; what was pressed after it is forgotten as well.
        if drained && drops != self.drops {
            self.drops = drops;
            self.let_go(now_ns, sink);
        }
        any
    }

    /// About to sleep on the console: `false` if the ring has something, which
    /// the caller takes first.
    pub fn announce(&mut self) -> bool {
        self.ring.announce()
    }

    /// The console wait returned.
    pub fn woke(&mut self) {
        self.ring.woke();
    }

    /// Forget what is held: a release may have been dropped.
    fn let_go(&mut self, now_ns: u64, sink: &mut impl Sink) {
        self.mods = Mods::new();
        if let Some(scr) = &self.screen {
            self.mouse.release_all(now_ns, scr, &self.mods, sink);
        }
    }

    fn event(&mut self, ty: u16, code: u16, value: u32, now_ns: u64, sink: &mut impl Sink) {
        match ty {
            EV_KEY if code < BTN_MOUSE => {
                if self.mods.key(code, value) || value == 0 {
                    return;
                }
                self.mouse.key_pressed();
                // The secure-attention chord is the terminal server's alone:
                // it is not an escape sequence for the client, and a held key
                // repeating (value 2) is not a second press.
                if code == KEY_DELETE && self.mods.ctrl() && self.mods.alt() {
                    if value == 1 {
                        sink.attention();
                    }
                    return;
                }
                if let Some(seq) = keys::encode(code, &self.mods) {
                    sink.push(seq.bytes());
                }
            }
            EV_KEY => {
                if let Some(scr) = &self.screen {
                    self.mouse.button(code, value != 0, now_ns, scr, &self.mods, sink);
                }
            }
            EV_REL => {
                let Some(scr) = &self.screen else { return };
                match code {
                    // The value is a device's 32 bits, two's complement: any i32.
                    REL_X | REL_Y => self.mouse.rel(code, value as i32, scr, &self.mods, sink),
                    REL_WHEEL => self.mouse.wheel(value as i32, scr, &self.mods, sink),
                    _ => {}
                }
            }
            EV_ABS => {
                if let Some(scr) = &self.screen {
                    self.mouse.abs(code, value, scr, &self.mods, sink);
                }
            }
            _ => {}
        }
    }

    /// The overlay to hand the renderer, if it changed since the last time.
    /// `true`: it was written to the screen region and the renderer should be
    /// told to draw it.
    pub fn flush_overlay(&mut self) -> bool {
        let Some(scr) = &self.screen else { return false };
        if !self.mouse.take_dirty() {
            return false;
        }
        let o = self.mouse.overlay();
        if o == self.shown {
            return false;
        }
        scr.set_overlay(&o);
        self.shown = o;
        true
    }

    /// The modifiers held, for the tests.
    #[cfg(test)]
    pub fn mods(&self) -> Mods {
        self.mods
    }

    /// The mouse, for the tests.
    #[cfg(test)]
    pub fn mouse(&self) -> &Mouse {
        &self.mouse
    }
}
