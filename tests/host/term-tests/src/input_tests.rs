// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The terminal server as the consumer of the input event ring: keys to
//! escape sequences, the mouse to selection, paste, scrollback and reports.
//!
//! The ring is a real `SpscRing` over host memory, the screen a real
//! `Publisher`/`Viewer` pair over host memory, so the producer side here is
//! the one the kernel runs. **Canary**: `--features canary-drop-input` makes
//! the server stop draining the ring; the tests that go through
//! `Service::read_event` (the ones named `served_*`) must go red.

use crate::input::{Input, BATCH};
use crate::keys::{encode, Mods};
use crate::mouse::{Sink, CLIP_MAX, MICKEYS_X, MICKEYS_Y};
use crate::service::{Console, Service};
use azos_input_wire::event::*;
use azos_input_wire::screen::*;
use azos_rings::region::{RingSleep, RingStep, SpscRing, RING_CONS_WAIT};
use core::sync::atomic::{AtomicU32, Ordering};
use azos_term::{unpack_event, Kind, Terminal, WAIT_FOREVER};

const COLS: u32 = 16;
const ROWS: u32 = 6;
const SB: u32 = 4;
const L: Layout = Layout { cols_max: COLS, rows_max: ROWS, sb_cap: SB };

#[repr(align(64))]
struct RingMem([u8; REGION_BYTES]);

/// A ring, a screen and the producer's handles on both.
struct Rig {
    ring: SpscRing,
    _ring_mem: Box<RingMem>,
    _scr_mem: Vec<u32>,
    p: Publisher,
    /// The pointer's position in device counts, as the test moves it.
    x: i32,
    y: i32,
}

impl Rig {
    fn new() -> (Rig, Viewer) {
        let mut ring_mem = Box::new(RingMem([0; REGION_BYTES]));
        let ring = SpscRing { base: ring_mem.0.as_mut_ptr() as usize, cap: RING_CAP };
        ring.init();
        let mut scr_mem = vec![0u32; L.bytes().div_ceil(4)];
        let base = scr_mem.as_mut_ptr() as *mut u8;
        // SAFETY: the Vec lives as long as the rig and is never resized.
        let (p, v) = unsafe {
            let mut p = Publisher::format(base, L.bytes(), L).expect("formats");
            p.set_dims(COLS, ROWS);
            (p, Viewer::open(base, L.bytes()).expect("opens"))
        };
        (Rig { ring, _ring_mem: ring_mem, _scr_mem: scr_mem, p, x: 0, y: 0 }, v)
    }

    fn send(&self, ty: u16, code: u16, value: u32) {
        assert!(!matches!(self.ring.try_push(pack(ty, code, value)), RingStep::Blocked), "ring full");
    }

    fn key(&self, code: u16, value: u32) {
        self.send(EV_KEY, code, value);
    }

    /// The producer dropped an event (a full ring): what `events::publish`
    /// does to the region's counter.
    fn drop_one(&self) {
        let d = unsafe { &*((self.ring.base + DROPS_OFFSET) as *const AtomicU32) };
        d.store(d.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
    }

    /// Is the consumer announced as asleep?
    fn announced(&self) -> bool {
        unsafe { &*((self.ring.base + RING_CONS_WAIT) as *const AtomicU32) }.load(Ordering::Relaxed) != 0
    }

    /// Put the pointer on (`col`, `row`): one relative move.
    fn goto(&mut self, col: u32, row: u32) {
        let (tx, ty) = (col as i32 * MICKEYS_X + MICKEYS_X / 2, row as i32 * MICKEYS_Y + MICKEYS_Y / 2);
        if tx != self.x {
            self.send(EV_REL, REL_X, (tx - self.x) as u32);
        }
        if ty != self.y {
            self.send(EV_REL, REL_Y, (ty - self.y) as u32);
        }
        self.x = tx;
        self.y = ty;
    }

    fn text_rows(&mut self, rows: &[(&str, bool)]) {
        for (r, (t, wrapped)) in rows.iter().enumerate() {
            let mut cells = [b' '; COLS as usize];
            cells[..t.len()].copy_from_slice(t.as_bytes());
            self.p.put_row(r as u32, &cells, *wrapped);
        }
        self.p.bump_seq();
    }

    fn scroll_off(&mut self, line: &str) {
        let mut cells = [b' '; COLS as usize];
        cells[..line.len()].copy_from_slice(line.as_bytes());
        self.p.push_scrollback(&cells, false);
        self.p.bump_seq();
    }
}

/// What the server pushed to the terminal input.
#[derive(Default)]
struct Typed {
    pushed: Vec<u8>,
    reports: Vec<u8>,
}

impl Sink for Typed {
    fn push(&mut self, b: &[u8]) {
        self.pushed.extend_from_slice(b);
    }
    fn report(&mut self, b: &[u8]) {
        self.reports.extend_from_slice(b);
    }
}

fn input(rig: &Rig, v: Viewer) -> Input<SpscRing> {
    Input::new(rig.ring, Some(v))
}

// ── keys ────────────────────────────────────────────────────────────────────

#[test]
fn the_key_table_is_xterm() {
    let none = Mods::new();
    let with = |codes: &[u16]| {
        let mut m = Mods::new();
        for &c in codes {
            assert!(m.key(c, 1));
        }
        m
    };
    let seq = |code, m: &Mods| encode(code, m).map(|s| s.bytes().to_vec());
    for (code, want) in [
        (KEY_UP, "\x1b[A"), (KEY_DOWN, "\x1b[B"), (KEY_RIGHT, "\x1b[C"), (KEY_LEFT, "\x1b[D"),
        (KEY_HOME, "\x1b[H"), (KEY_END, "\x1b[F"),
        (KEY_INSERT, "\x1b[2~"), (KEY_DELETE, "\x1b[3~"), (KEY_PAGEUP, "\x1b[5~"), (KEY_PAGEDOWN, "\x1b[6~"),
        (KEY_F1, "\x1bOP"), (KEY_F1 + 1, "\x1bOQ"), (KEY_F1 + 2, "\x1bOR"), (KEY_F1 + 3, "\x1bOS"),
        (KEY_F1 + 4, "\x1b[15~"), (KEY_F1 + 5, "\x1b[17~"), (KEY_F1 + 6, "\x1b[18~"), (KEY_F1 + 7, "\x1b[19~"),
        (KEY_F1 + 8, "\x1b[20~"), (KEY_F10, "\x1b[21~"), (KEY_F11, "\x1b[23~"), (KEY_F12, "\x1b[24~"),
    ] {
        assert_eq!(seq(code, &none), Some(want.as_bytes().to_vec()), "key {code}");
    }
    // Modifiers: 1 + shift 1 + alt 2 + ctrl 4 + meta 8.
    assert_eq!(seq(KEY_UP, &with(&[KEY_LEFTSHIFT])), Some(b"\x1b[1;2A".to_vec()));
    assert_eq!(seq(KEY_UP, &with(&[KEY_RIGHTALT])), Some(b"\x1b[1;3A".to_vec()));
    assert_eq!(seq(KEY_RIGHT, &with(&[KEY_LEFTCTRL])), Some(b"\x1b[1;5C".to_vec()));
    assert_eq!(seq(KEY_RIGHT, &with(&[KEY_LEFTSHIFT, KEY_LEFTALT])), Some(b"\x1b[1;4C".to_vec()));
    assert_eq!(seq(KEY_HOME, &with(&[KEY_LEFTCTRL, KEY_LEFTSHIFT, KEY_LEFTALT, KEY_LEFTMETA])), Some(b"\x1b[1;16H".to_vec()));
    assert_eq!(seq(KEY_DELETE, &with(&[KEY_LEFTCTRL])), Some(b"\x1b[3;5~".to_vec()));
    assert_eq!(seq(KEY_F12, &with(&[KEY_RIGHTSHIFT])), Some(b"\x1b[24;2~".to_vec()));
    assert_eq!(seq(KEY_F1, &with(&[KEY_LEFTCTRL])), Some(b"\x1b[1;5P".to_vec()), "F1 with a modifier is CSI");
    // A key with no sequence.
    assert_eq!(seq(KEY_A, &none), None);
    assert_eq!(seq(KEY_ESC, &none), None);
}

#[test]
fn modifiers_are_followed_by_physical_key_and_released() {
    let mut m = Mods::new();
    m.key(KEY_LEFTSHIFT, 1);
    m.key(KEY_RIGHTSHIFT, 1);
    m.key(KEY_LEFTSHIFT, 0);
    assert!(m.shift(), "the other shift is still down");
    m.key(KEY_RIGHTSHIFT, 0);
    assert!(!m.shift());
    assert_eq!(m.param(), 1);
    assert!(!m.key(KEY_UP, 1), "an arrow is no modifier");
}

#[test]
fn ring_events_become_sequences_on_press_and_repeat_only() {
    let (rig, v) = Rig::new();
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.key(KEY_LEFTCTRL, 1);
    rig.key(KEY_UP, 1);
    rig.key(KEY_UP, 2);
    rig.key(KEY_UP, 0);
    rig.key(KEY_LEFTCTRL, 0);
    rig.key(KEY_DOWN, 1);
    rig.key(KEY_A, 1);
    assert!(inp.pump(0, &mut t));
    assert_eq!(t.pushed, b"\x1b[1;5A\x1b[1;5A\x1b[B", "ctrl-up twice (press, repeat), then down; the release and a plain key say nothing");
    assert!(!inp.pump(0, &mut t), "drained");
}

#[test]
fn events_that_piled_up_before_the_consumer_are_not_acted_on() {
    let (rig, v) = Rig::new();
    rig.key(KEY_UP, 1);
    rig.key(KEY_DELETE, 1);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    inp.pump(0, &mut t);
    assert!(t.pushed.is_empty(), "stale keys are dropped at attach");
}

#[test]
fn a_pump_takes_a_bounded_batch() {
    let (rig, v) = Rig::new();
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    for _ in 0..BATCH + 5 {
        rig.key(KEY_UP, 1);
    }
    inp.pump(0, &mut t);
    assert_eq!(t.pushed.len(), BATCH * 3);
    inp.pump(0, &mut t);
    assert_eq!(t.pushed.len(), (BATCH + 5) * 3);
}

#[test]
fn announcing_a_sleep_makes_the_next_push_ask_for_a_wake_and_an_event_in_the_way_refuses_it() {
    let (rig, v) = Rig::new();
    let mut inp = input(&rig, v);
    assert!(inp.announce(), "empty: sleep");
    assert!(rig.announced());
    assert!(matches!(rig.ring.try_push(pack(EV_REL, REL_X, 1)), RingStep::DoneWake { .. }), "the producer owes the wake");
    assert!(!rig.announced(), "once");
    assert!(matches!(rig.ring.try_push(pack(EV_REL, REL_X, 1)), RingStep::Done), "no wake owed while awake");
    // An event that came between the last look and the announcement.
    assert!(!inp.announce(), "not empty: do not sleep");
    assert!(!rig.announced(), "and no flag left");
    inp.woke();
    assert!(!rig.announced());
    assert!(matches!(rig.ring.consumer_sleep(), RingSleep::Retry));
}

// ── the producer's drops: nothing stays held ────────────────────────────────

#[test]
fn a_dropped_shift_release_does_not_leave_the_mouse_reports_off() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false)]);
    rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.key(KEY_LEFTSHIFT, 1);
    rig.goto(0, 0);
    inp.pump(0, &mut t);
    // The release was dropped: the ring was full.
    rig.drop_one();
    inp.pump(0, &mut t);
    rig.send(EV_KEY, BTN_LEFT, 1);
    inp.pump(0, &mut t);
    assert_eq!(t.reports, b"\x1b[<0;1;1M", "shift is no longer held: the program gets the click");
}

#[test]
fn nothing_is_let_go_until_the_events_before_the_drop_are_all_taken() {
    let (mut rig, v) = Rig::new();
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.key(KEY_LEFTSHIFT, 1);
    rig.goto(0, 0);
    inp.pump(0, &mut t);
    assert!(inp.mods().shift());
    // No drop: nothing is let go however many pumps.
    inp.pump(0, &mut t);
    assert!(inp.mods().shift(), "no drop, the shift stands");
    // A drop with more events behind than one pump takes.
    rig.drop_one();
    for _ in 0..BATCH + 5 {
        rig.send(EV_REL, REL_X, 0);
    }
    inp.pump(0, &mut t);
    assert!(inp.mods().shift(), "the ring still has events from before the drop: they may hold the release");
    inp.pump(0, &mut t);
    assert!(!inp.mods().shift(), "the ring is drained: let go");
    inp.pump(0, &mut t);
    rig.key(KEY_LEFTSHIFT, 1);
    inp.pump(0, &mut t);
    assert!(inp.mods().shift(), "and the same drop is not acted on twice");
}

#[test]
fn a_dropped_button_release_ends_the_drag_and_copies_the_selection() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(5, 0);
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.goto(9, 0);
    inp.pump(0, &mut t);
    assert!(inp.mouse().clip().is_empty(), "the button is down");
    rig.drop_one();
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().clip(), b"hello", "no button is held any more: the selection is final");
    // Moving no longer extends it.
    rig.goto(12, 0);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().sel, Some((5, 9)));
}

#[test]
fn a_dropped_button_release_reaches_the_program_that_saw_the_press() {
    let (mut rig, v) = Rig::new();
    rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(2, 1);
    rig.send(EV_KEY, BTN_RIGHT, 1);
    inp.pump(0, &mut t);
    assert_eq!(t.reports, b"\x1b[<2;3;2M");
    t.reports.clear();
    rig.drop_one();
    inp.pump(0, &mut t);
    assert_eq!(t.reports, b"\x1b[<2;3;2m", "released for it");
    t.reports.clear();
    rig.drop_one();
    inp.pump(0, &mut t);
    assert!(t.reports.is_empty(), "and only once");
}

#[test]
fn drops_before_the_consumer_attached_do_not_count() {
    let (mut rig, v) = Rig::new();
    rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
    rig.drop_one();
    rig.drop_one();
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.key(KEY_LEFTSHIFT, 1);
    inp.pump(0, &mut t);
    rig.goto(0, 0);
    rig.send(EV_KEY, BTN_LEFT, 1);
    inp.pump(0, &mut t);
    assert!(t.reports.is_empty(), "shift is held and nothing was let go");
}

// ── device data: any 32 bits ────────────────────────────────────────────────

#[test]
fn extreme_device_values_move_the_pointer_to_an_edge_and_panic_nothing() {
    let (mut rig, v) = Rig::new();
    for i in 0..6 {
        rig.scroll_off(&format!("line {i}"));
    }
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    for val in [i32::MAX, i32::MIN, i32::MAX, 1, i32::MIN + 1] {
        rig.send(EV_REL, REL_X, val as u32);
        rig.send(EV_REL, REL_Y, val as u32);
        inp.pump(0, &mut t);
    }
    rig.send(EV_REL, REL_X, i32::MAX as u32);
    rig.send(EV_REL, REL_Y, i32::MAX as u32);
    rig.send(EV_REL, REL_X, i32::MAX as u32);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().ptr, Some((COLS - 1, ROWS - 1)), "clamped to the last cell");
    rig.send(EV_REL, REL_X, i32::MIN as u32);
    rig.send(EV_REL, REL_X, i32::MIN as u32);
    rig.send(EV_REL, REL_Y, i32::MIN as u32);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().ptr, Some((0, 0)));
    rig.send(EV_ABS, ABS_X, u32::MAX);
    rig.send(EV_ABS, ABS_Y, u32::MAX);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().ptr, Some((COLS - 1, ROWS - 1)));
    // The wheel: every extreme, both ways, with the view at 0 and at the end.
    for w in [i32::MIN, i32::MAX, i32::MIN, 1, i32::MAX, -1, i32::MIN] {
        rig.send(EV_REL, REL_WHEEL, w as u32);
        inp.pump(0, &mut t);
    }
    assert_eq!(inp.mouse().overlay().view_off, 0, "the last turn was a huge one down");
    rig.send(EV_REL, REL_WHEEL, i32::MAX as u32);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, SB, "a huge one up stops at the scrollback's end");
    // And reporting: a huge wheel is bounded to a few reports.
    rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
    rig.send(EV_REL, REL_WHEEL, i32::MIN as u32);
    inp.pump(0, &mut t);
    assert_eq!(t.reports.len(), 4 * b"\x1b[<65;16;6M".len());
}

// ── selection ───────────────────────────────────────────────────────────────

/// Press at `from`, drag to `to`, release; the server's paste buffer.
fn drag(rig: &mut Rig, inp: &mut Input<SpscRing>, t: &mut Typed, from: (u32, u32), to: (u32, u32), now: u64) {
    rig.goto(from.0, from.1);
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.goto(to.0, to.1);
    rig.send(EV_KEY, BTN_LEFT, 0);
    inp.pump(now, t);
}

#[test]
fn a_drag_selects_cells_and_the_text_is_copied() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false), ("second line", false), ("third", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    drag(&mut rig, &mut inp, &mut t, (5, 0), (9, 0), 0);
    assert_eq!(inp.mouse().clip(), b"hello");
    assert!(inp.flush_overlay());
    let o = rig.p.overlay().expect("an even overlay");
    assert_eq!(o.sel, Some((5, 9)), "highlighted: view cells 5..=9 of row 0");
    assert_eq!(o.ptr, Some((9, 0)));
    // Dragging backwards selects the same way.
    drag(&mut rig, &mut inp, &mut t, (9, 0), (5, 0), 0);
    assert_eq!(inp.mouse().clip(), b"hello");
}

#[test]
fn a_selection_over_rows_keeps_the_line_breaks_and_drops_the_blanks() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false), ("second line", false), ("third", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    drag(&mut rig, &mut inp, &mut t, (5, 0), (2, 2), 0);
    assert_eq!(inp.mouse().clip(), b"hello\nsecond line\nthi", "the first row's blanks go, the last row stops where the drag did");
}

#[test]
fn a_selection_over_wrapped_lines_joins_what_the_terminal_wrapped() {
    let (mut rig, v) = Rig::new();
    // A command wrapped at 16 columns, then a new line.
    rig.text_rows(&[("ls -l /fat/tools", true), ("/bc", false), ("$ next", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    drag(&mut rig, &mut inp, &mut t, (0, 0), (2, 1), 0);
    assert_eq!(inp.mouse().clip(), b"ls -l /fat/tools/bc", "no newline between a wrapped row and the next");
    // The same text if the first row were NOT wrapped: a newline.
    rig.text_rows(&[("ls -l /fat/tools", false), ("/bc", false)]);
    drag(&mut rig, &mut inp, &mut t, (0, 0), (2, 1), 0);
    assert_eq!(inp.mouse().clip(), b"ls -l /fat/tools\n/bc");
}

#[test]
fn a_wrapped_row_keeps_its_trailing_blanks() {
    let (mut rig, v) = Rig::new();
    // "a" + 15 blanks is a full 16-cell row the writer wrapped: the blanks are text.
    rig.text_rows(&[("a", true), ("b", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    drag(&mut rig, &mut inp, &mut t, (0, 0), (0, 1), 0);
    assert_eq!(inp.mouse().clip(), b"a               b");
}

#[test]
fn a_click_without_a_drag_selects_nothing() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    drag(&mut rig, &mut inp, &mut t, (5, 0), (5, 0), 0);
    assert!(!inp.mouse().has_selection());
    assert!(inp.mouse().clip().is_empty());
}

#[test]
fn a_double_click_selects_a_word_and_a_slow_one_does_not() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("run /fat/x now", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    let click = |rig: &mut Rig, inp: &mut Input<SpscRing>, t: &mut Typed, at: u64| {
        rig.goto(6, 0);
        rig.send(EV_KEY, BTN_LEFT, 1);
        rig.send(EV_KEY, BTN_LEFT, 0);
        inp.pump(at, t);
    };
    click(&mut rig, &mut inp, &mut t, 1_000_000_000);
    assert!(!inp.mouse().has_selection());
    click(&mut rig, &mut inp, &mut t, 1_100_000_000);
    assert_eq!(inp.mouse().clip(), b"/fat/x", "a path is one word");
    // A third quick click takes the row.
    click(&mut rig, &mut inp, &mut t, 1_200_000_000);
    assert_eq!(inp.mouse().clip(), b"run /fat/x now");
    // 500 ms later it is a new single click: the selection is gone.
    click(&mut rig, &mut inp, &mut t, 1_800_000_000);
    assert!(!inp.mouse().has_selection());
}

#[test]
fn dragging_after_a_double_click_extends_by_words() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("one two three", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(1, 0);
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.send(EV_KEY, BTN_LEFT, 0);
    inp.pump(0, &mut t);
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.goto(9, 0);
    rig.send(EV_KEY, BTN_LEFT, 0);
    inp.pump(100_000_000, &mut t);
    assert_eq!(inp.mouse().clip(), b"one two three", "from the first word to the word under the pointer");
}

#[test]
fn the_right_button_extends_the_selection() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("0123456789", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    drag(&mut rig, &mut inp, &mut t, (2, 0), (4, 0), 0);
    assert_eq!(inp.mouse().clip(), b"234");
    rig.goto(7, 0);
    rig.send(EV_KEY, BTN_RIGHT, 1);
    rig.send(EV_KEY, BTN_RIGHT, 0);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().clip(), b"234567");
}

#[test]
fn new_output_drops_a_selection_that_the_cells_moved_from_under() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    drag(&mut rig, &mut inp, &mut t, (5, 0), (9, 0), 0);
    assert!(inp.mouse().has_selection());
    rig.p.bump_seq();
    inp.pump(0, &mut t);
    assert!(!inp.mouse().has_selection());
    assert_eq!(inp.mouse().clip(), b"hello", "what was copied stays pasteable");
}

// ── paste ───────────────────────────────────────────────────────────────────

#[test]
fn the_middle_button_pastes_the_selection_into_the_terminal_input() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(0, 0);
    rig.send(EV_KEY, BTN_MIDDLE, 1);
    rig.send(EV_KEY, BTN_MIDDLE, 0);
    inp.pump(0, &mut t);
    assert!(t.pushed.is_empty(), "nothing copied yet: nothing to paste");
    drag(&mut rig, &mut inp, &mut t, (5, 0), (9, 0), 0);
    rig.goto(0, 4);
    rig.send(EV_KEY, BTN_MIDDLE, 1);
    rig.send(EV_KEY, BTN_MIDDLE, 0);
    inp.pump(0, &mut t);
    assert_eq!(t.pushed, b"hello");
    assert!(t.reports.is_empty());
}

#[test]
fn a_paste_buffer_is_bounded() {
    assert_eq!(CLIP_MAX, 1024);
}

// ── scrollback ──────────────────────────────────────────────────────────────

#[test]
fn the_wheel_scrolls_the_scrollback_and_stops_at_its_ends() {
    let (mut rig, v) = Rig::new();
    for i in 0..6 {
        rig.scroll_off(&format!("line {i}"));
    }
    rig.text_rows(&[("live", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    let wheel = |rig: &Rig, n: i32| rig.send(EV_REL, REL_WHEEL, n as u32);
    rig.goto(0, 0);
    inp.pump(0, &mut t);
    wheel(&rig, 1);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, 3, "a notch is three rows");
    wheel(&rig, 1);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, SB, "bounded by the scrollback the kernel kept: {SB} lines");
    wheel(&rig, 5);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, SB, "and no further");
    assert!(inp.flush_overlay());
    assert_eq!(rig.p.overlay().expect("even").view_off, SB, "the renderer is told");
    wheel(&rig, -1);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, 1);
    wheel(&rig, -2);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, 0, "down to the live screen and not below");
}

#[test]
fn selecting_in_the_scrollback_copies_the_scrolled_lines() {
    let (mut rig, v) = Rig::new();
    for i in 0..4 {
        rig.scroll_off(&format!("old {i}"));
    }
    rig.text_rows(&[("live", false)]);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(0, 0);
    rig.send(EV_REL, REL_WHEEL, 1);
    inp.pump(0, &mut t);
    // View row 0 is now three lines back: "old 1", row 2 is the newest, "old 3".
    drag(&mut rig, &mut inp, &mut t, (0, 0), (4, 2), 0);
    assert_eq!(inp.mouse().clip(), b"old 1\nold 2\nold 3");
}

#[test]
fn a_key_brings_the_view_back_and_hides_the_pointer() {
    let (mut rig, v) = Rig::new();
    for i in 0..4 {
        rig.scroll_off(&format!("old {i}"));
    }
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(3, 3);
    rig.send(EV_REL, REL_WHEEL, 1);
    inp.pump(0, &mut t);
    assert!(inp.flush_overlay());
    let o = rig.p.overlay().expect("even");
    assert_eq!((o.ptr, o.view_off), (Some((3, 3)), 3));
    inp.console_key();
    assert!(inp.flush_overlay());
    let o = rig.p.overlay().expect("even");
    assert_eq!((o.ptr, o.view_off), (None, 0), "a typed byte hides the pointer and returns to the live screen");
    assert!(!inp.flush_overlay(), "nothing changed since");
    rig.send(EV_REL, REL_X, 1);
    inp.pump(0, &mut t);
    assert!(inp.flush_overlay());
    assert!(rig.p.overlay().expect("even").ptr.is_some(), "moving the mouse shows it again");
}

#[test]
fn output_returns_a_scrolled_view_to_the_live_screen() {
    let (mut rig, v) = Rig::new();
    for i in 0..4 {
        rig.scroll_off(&format!("old {i}"));
    }
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(0, 0);
    rig.send(EV_REL, REL_WHEEL, 1);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, 3);
    rig.scroll_off("new");
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().view_off, 0);
}

// ── the tablet ──────────────────────────────────────────────────────────────

#[test]
fn a_tablet_places_the_pointer_by_proportion() {
    let (rig, v) = Rig::new();
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.send(EV_ABS, ABS_X, ABS_MAX);
    rig.send(EV_ABS, ABS_Y, 0);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().ptr, Some((COLS - 1, 0)));
    rig.send(EV_ABS, ABS_X, ABS_MAX / 2);
    rig.send(EV_ABS, ABS_Y, ABS_MAX / 2);
    inp.pump(0, &mut t);
    assert_eq!(inp.mouse().overlay().ptr, Some((COLS / 2 - 1, ROWS / 2 - 1)), "half scale is just short of the middle cell");
}

// ── reporting ───────────────────────────────────────────────────────────────

#[test]
fn a_program_that_asked_for_sgr_reports_gets_them_and_nothing_is_selected() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false)]);
    rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(2, 1);
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.send(EV_KEY, BTN_LEFT, 0);
    rig.send(EV_KEY, BTN_RIGHT, 1);
    rig.send(EV_KEY, BTN_RIGHT, 0);
    rig.send(EV_REL, REL_WHEEL, 1);
    rig.send(EV_REL, REL_WHEEL, (-1i32) as u32);
    inp.pump(0, &mut t);
    assert_eq!(
        t.reports,
        b"\x1b[<0;3;2M\x1b[<0;3;2m\x1b[<2;3;2M\x1b[<2;3;2m\x1b[<64;3;2M\x1b[<65;3;2M",
        "left press and release, right press and release, wheel up and down; 1-based cells"
    );
    assert!(!inp.mouse().has_selection());
    // 1000 alone reports no motion.
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.goto(8, 1);
    inp.pump(0, &mut t);
    assert!(!t.reports.ends_with(b"\x1b[<32;9;2M"));
}

#[test]
fn drag_mode_reports_motion_with_a_button_down_and_any_motion_always() {
    let (mut rig, v) = Rig::new();
    rig.p.set_mouse_mode(MOUSE_DRAG | MOUSE_SGR);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(1, 1);
    inp.pump(0, &mut t);
    assert!(t.reports.is_empty(), "motion with no button, in drag mode");
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.goto(2, 1);
    rig.goto(2, 1);
    inp.pump(0, &mut t);
    assert_eq!(t.reports, b"\x1b[<0;2;2M\x1b[<32;3;2M", "the press, then one motion report: it moved one cell");
    rig.p.set_mouse_mode(MOUSE_MOTION | MOUSE_SGR);
    rig.send(EV_KEY, BTN_LEFT, 0);
    t.reports.clear();
    inp.pump(0, &mut t);
    rig.goto(5, 4);
    inp.pump(0, &mut t);
    assert!(t.reports.ends_with(b"\x1b[<35;6;5M"), "motion with nothing down is button 3 + 32: {:?}", String::from_utf8_lossy(&t.reports));
}

#[test]
fn x10_reports_when_sgr_was_not_asked() {
    let (mut rig, v) = Rig::new();
    rig.p.set_mouse_mode(MOUSE_PRESS);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.goto(2, 1);
    rig.send(EV_KEY, BTN_MIDDLE, 1);
    rig.send(EV_KEY, BTN_MIDDLE, 0);
    inp.pump(0, &mut t);
    assert_eq!(t.reports, [0x1b, b'[', b'M', 32 + 1, 32 + 3, 32 + 2, 0x1b, b'[', b'M', 32 + 3, 32 + 3, 32 + 2], "a release is button 3");
}

#[test]
fn modifiers_ride_the_report_and_shift_gives_the_selection_back() {
    let (mut rig, v) = Rig::new();
    rig.text_rows(&[("echo hello", false)]);
    rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
    let mut inp = input(&rig, v);
    let mut t = Typed::default();
    rig.key(KEY_LEFTCTRL, 1);
    rig.goto(0, 0);
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.send(EV_KEY, BTN_LEFT, 0);
    rig.key(KEY_LEFTCTRL, 0);
    inp.pump(0, &mut t);
    assert_eq!(t.reports, b"\x1b[<16;1;1M\x1b[<16;1;1m", "ctrl adds 16");
    t.reports.clear();
    rig.key(KEY_LEFTSHIFT, 1);
    drag(&mut rig, &mut inp, &mut t, (5, 0), (9, 0), 0);
    assert!(t.reports.is_empty(), "shift: no report");
    assert_eq!(inp.mouse().clip(), b"hello", "shift: the selection works as without a program");
}

#[test]
fn the_mouse_mode_is_forgotten_when_the_job_ends() {
    let (rig, v) = Rig::new();
    rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
    let mut inp = input(&rig, v);
    let before = rig.p.mode_clear_seq();
    inp.job_ended();
    assert_ne!(rig.p.mode_clear_seq(), before, "the renderer is asked to forget");
}

// ── no screen ───────────────────────────────────────────────────────────────

#[test]
fn without_a_screen_the_keys_still_work_and_the_mouse_is_ignored() {
    let (rig, _v) = Rig::new();
    let mut inp = Input::new(rig.ring, None);
    let mut t = Typed::default();
    rig.key(KEY_LEFT, 1);
    rig.send(EV_REL, REL_X, 5);
    rig.send(EV_KEY, BTN_LEFT, 1);
    rig.send(EV_REL, REL_WHEEL, 1);
    inp.pump(0, &mut t);
    assert_eq!(t.pushed, b"\x1b[D");
    assert!(t.reports.is_empty());
    assert!(!inp.flush_overlay());
}

// ── served: the consumer inside the terminal server ─────────────────────────

mod served {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Fake {
        typed: VecDeque<Vec<u8>>,
        shown: Vec<u8>,
        timeouts: Vec<Option<u64>>,
        clock: u64,
        refreshes: usize,
        /// The ring and the events the producer publishes while the server
        /// sleeps: each wait is cut short by one, as the kernel's nudge does.
        producer: Option<(SpscRing, VecDeque<u64>)>,
        /// Was the consumer announced during each wait?
        announced: Vec<bool>,
    }

    impl Console for Fake {
        fn read(&mut self, buf: &mut [u8], timeout_ns: Option<u64>) -> isize {
            self.timeouts.push(timeout_ns);
            assert!(self.timeouts.len() < 100, "the wait never ended");
            if let Some((ring, events)) = self.producer.as_mut() {
                let flag = unsafe { &*((ring.base + RING_CONS_WAIT) as *const AtomicU32) };
                self.announced.push(flag.load(Ordering::Relaxed) != 0);
                if let Some(w) = events.pop_front() {
                    // The producer's push finds the announcement: it nudges.
                    assert!(matches!(ring.try_push(w), RingStep::DoneWake { .. }));
                    return 0;
                }
            }
            self.clock += timeout_ns.unwrap_or(0);
            match self.typed.pop_front() {
                Some(c) => {
                    buf[..c.len()].copy_from_slice(&c);
                    c.len() as isize
                }
                None => 0,
            }
        }
        fn write(&mut self, b: &[u8]) {
            self.shown.extend_from_slice(b);
        }
        fn now_ns(&self) -> u64 {
            self.clock
        }
        fn refresh(&mut self) {
            self.refreshes += 1;
        }
    }

    fn raw_service(rig: &Rig, v: Option<Viewer>) -> Service<Fake> {
        let mut s = Service::new(Fake::default());
        s.set_mode(true);
        s.inp = Some(Input::new(rig.ring, v));
        s
    }

    fn bytes_of(s: &mut Service<Fake>, ms: u32) -> Vec<u8> {
        let e = unpack_event(&s.read_event(ms)).expect("an event");
        assert_eq!(e.kind, Kind::Bytes, "an event of bytes");
        e.inline().to_vec()
    }

    #[test]
    fn served_arrow_keys_reach_a_raw_client_as_escape_sequences() {
        let (rig, v) = Rig::new();
        let mut s = raw_service(&rig, Some(v));
        rig.key(KEY_UP, 1);
        rig.key(KEY_F1 + 4, 1);
        assert_eq!(bytes_of(&mut s, 50), b"\x1b[A\x1b[15~");
    }

    #[test]
    fn served_a_paste_arrives_as_typed_input() {
        let (mut rig, v) = Rig::new();
        rig.text_rows(&[("echo hello", false)]);
        let mut s = raw_service(&rig, Some(v));
        rig.goto(5, 0);
        rig.send(EV_KEY, BTN_LEFT, 1);
        rig.goto(9, 0);
        rig.send(EV_KEY, BTN_LEFT, 0);
        rig.send(EV_KEY, BTN_MIDDLE, 1);
        rig.send(EV_KEY, BTN_MIDDLE, 0);
        assert_eq!(bytes_of(&mut s, 50), b"hello");
        assert!(s.con.refreshes > 0, "the renderer was asked to draw the highlight");
        let o = rig.p.overlay().expect("even");
        assert_eq!(o.sel, Some((5, 9)));
    }

    #[test]
    fn served_a_mouse_report_reaches_a_raw_client_but_not_while_a_job_has_the_focus() {
        let (mut rig, v) = Rig::new();
        rig.p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
        let mut s = raw_service(&rig, Some(v));
        rig.goto(0, 0);
        rig.send(EV_KEY, BTN_LEFT, 1);
        assert_eq!(bytes_of(&mut s, 50), b"\x1b[<0;1;1M");
        s.set_foreground(9);
        rig.send(EV_KEY, BTN_LEFT, 0);
        let e = unpack_event(&s.read_event(50)).expect("an event");
        assert_eq!(e.kind, Kind::Timeout, "a job runs: nobody reads the report");
        s.set_foreground(0);
        assert_eq!(unpack_event(&s.read_event(50)).expect("an event").kind, Kind::Timeout, "and it was not kept for later");
        assert_eq!(rig.p.mode_clear_seq(), 1, "the focus coming back ended the job's mouse mode");
    }

    #[test]
    fn an_idle_prompt_sleeps_in_one_wait_to_the_callers_deadline_with_no_tick() {
        let (rig, v) = Rig::new();
        let mut s = raw_service(&rig, Some(v));
        s.con.producer = Some((rig.ring, VecDeque::new()));
        let e = unpack_event(&s.read_event(100)).expect("an event");
        assert_eq!(e.kind, Kind::Timeout);
        assert_eq!(s.con.timeouts, vec![Some(100_000_000)], "one wait, not a poll");
        assert_eq!(s.con.announced, vec![true], "the ring knew the server slept");
        assert!(!rig.announced(), "and knows it is awake again");
        // Waiting forever is one wait with no deadline until a byte arrives.
        s.con.timeouts.clear();
        s.con.typed.push_back(b"x".to_vec());
        let e = unpack_event(&s.read_event(WAIT_FOREVER)).expect("an event");
        assert_eq!(e.kind, Kind::Bytes);
        assert_eq!(s.con.timeouts, vec![None]);
    }

    #[test]
    fn served_an_event_published_while_asleep_wakes_the_wait_and_is_acted_on() {
        let (rig, v) = Rig::new();
        let mut s = raw_service(&rig, Some(v));
        s.con.producer = Some((rig.ring, VecDeque::from([pack(EV_KEY, KEY_UP, 1)])));
        // Forever: only the nudge ends the first wait.
        assert_eq!(bytes_of(&mut s, WAIT_FOREVER), b"\x1b[A");
        assert_eq!(s.con.timeouts, vec![None], "one sleep, ended by the nudge");
        assert_eq!(s.con.announced, vec![true]);
    }

    #[test]
    fn a_nudge_does_not_cut_the_callers_deadline_short() {
        let (rig, v) = Rig::new();
        let mut s = raw_service(&rig, Some(v));
        // Motion only: nothing for the client; the wait goes round with what
        // is left of the deadline.
        s.con.producer = Some((rig.ring, VecDeque::from([pack(EV_REL, REL_X, 3), pack(EV_REL, REL_X, 3)])));
        let e = unpack_event(&s.read_event(100)).expect("an event");
        assert_eq!(e.kind, Kind::Timeout);
        assert_eq!(s.con.timeouts, vec![Some(100_000_000); 3]);
        assert_eq!(s.con.clock, 100_000_000, "the clock ran only in the last wait");
    }

    #[test]
    fn without_a_ring_the_console_wait_is_what_it_was() {
        let mut s = Service::new(Fake::default());
        s.set_mode(true);
        s.con.typed.push_back(b"q".to_vec());
        assert_eq!(bytes_of(&mut s, WAIT_FOREVER), b"q");
        assert_eq!(s.con.timeouts, vec![None], "forever stays forever");
    }

    #[test]
    fn a_typed_byte_hides_the_pointer() {
        let (mut rig, v) = Rig::new();
        let mut s = raw_service(&rig, Some(v));
        rig.goto(3, 3);
        let _ = s.read_event(30);
        assert!(rig.p.overlay().expect("even").ptr.is_some());
        s.con.typed.push_back(b"x".to_vec());
        assert_eq!(bytes_of(&mut s, 50), b"x");
        assert!(rig.p.overlay().expect("even").ptr.is_none());
    }
}
