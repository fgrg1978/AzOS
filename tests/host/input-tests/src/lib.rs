// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/drivers/input/wire`: the event word and the screen
//! region the kernel and the terminal server share.

#[cfg(test)]
mod tests {
    use azos_input_wire::event::*;
    use azos_input_wire::screen::*;

    const L: Layout = Layout { cols_max: 8, rows_max: 4, sb_cap: 3 };

    fn mem() -> Vec<u32> {
        vec![0u32; L.bytes().div_ceil(4)]
    }

    fn pair(m: &mut Vec<u32>) -> (Publisher, Viewer) {
        let base = m.as_mut_ptr() as *mut u8;
        // SAFETY: the Vec outlives both handles in each test.
        unsafe {
            let mut p = Publisher::format(base, L.bytes(), L).expect("formats");
            p.set_dims(6, 4);
            (p, Viewer::open(base, L.bytes()).expect("opens"))
        }
    }

    #[test]
    fn a_word_round_trips() {
        for (t, c, v) in [(EV_KEY, KEY_UP, 1), (EV_REL, REL_WHEEL, (-3i32) as u32), (EV_ABS, ABS_X, ABS_MAX)] {
            assert_eq!(unpack(pack(t, c, v)), (t, c, v));
        }
    }

    #[test]
    fn the_viewer_reads_what_the_publisher_wrote() {
        let mut m = mem();
        let (mut p, v) = pair(&mut m);
        p.put_row(1, b"abcdef", true);
        let mut out = [0u8; 6];
        assert_eq!(v.row(1, &mut out), Some((6, true)));
        assert_eq!(&out, b"abcdef");
        assert_eq!(v.row(4, &mut out), None, "past the screen");
        assert_eq!(v.dims(), (6, 4));
    }

    #[test]
    fn scrollback_is_a_bounded_ring_newest_first() {
        let mut m = mem();
        let (mut p, v) = pair(&mut m);
        for l in [b"line-1", b"line-2", b"line-3", b"line-4"] {
            p.push_scrollback(l, false);
        }
        assert_eq!(v.sb_count(), 3, "bounded by sb_cap");
        let mut out = [0u8; 6];
        assert!(v.row(-1, &mut out).is_some());
        assert_eq!(&out, b"line-4");
        assert!(v.row(-3, &mut out).is_some());
        assert_eq!(&out, b"line-2", "line-1 fell off");
        assert_eq!(v.row(-4, &mut out), None);
        assert_eq!(p.sb_row(0, &mut out), Some(false));
        assert_eq!(&out, b"line-4");
    }

    #[test]
    fn the_overlay_travels_and_is_clamped() {
        let mut m = mem();
        let (p, v) = pair(&mut m);
        assert_eq!(p.overlay(), Some(Overlay::default()));
        v.set_overlay(&Overlay { ptr: Some((2, 1)), sel: Some((9, 4)), view_off: 7 });
        let o = p.overlay().expect("an even sequence");
        assert_eq!(o.ptr, Some((2, 1)));
        assert_eq!(o.sel, Some((4, 9)));
        assert_eq!(o.view_off, 0, "no scrollback to view");
        // A pointer outside the screen draws nothing; a selection past the
        // last cell is cut to it.
        v.set_overlay(&Overlay { ptr: Some((6, 0)), sel: Some((0, 1000)), view_off: 0 });
        let o = p.overlay().expect("even");
        assert_eq!(o.ptr, None);
        assert_eq!(o.sel, Some((0, 23)));
    }

    #[test]
    fn a_half_written_overlay_is_not_taken() {
        let mut m = mem();
        let (p, _v) = pair(&mut m);
        // The seqlock word is odd while the server writes.
        m[word::OVL_SEQ] = 1;
        assert_eq!(p.overlay(), None);
        m[word::OVL_SEQ] = 2;
        assert!(p.overlay().is_some());
    }

    #[test]
    fn memory_that_is_not_a_region_is_refused() {
        let mut m = mem();
        let base = m.as_mut_ptr() as *mut u8;
        // SAFETY: the Vec outlives the calls.
        unsafe {
            assert!(Viewer::open(base, L.bytes()).is_none(), "unformatted");
            assert!(Publisher::format(base, L.bytes() - 1, L).is_none(), "too small");
            Publisher::format(base, L.bytes(), L).expect("formats");
            assert!(Viewer::open(base, 64).is_none(), "shorter than its header");
            assert!(Viewer::open(base, L.bytes() - 8).is_none(), "shorter than its own geometry");
        }
    }

    #[test]
    fn the_mouse_mode_and_its_clear() {
        let mut m = mem();
        let (p, v) = pair(&mut m);
        p.set_mouse_mode(MOUSE_PRESS | MOUSE_SGR);
        assert_eq!(v.mouse_mode(), MOUSE_PRESS | MOUSE_SGR);
        let before = p.mode_clear_seq();
        v.clear_mouse_mode();
        assert_ne!(p.mode_clear_seq(), before);
    }
}

#[cfg(test)]
mod grid_tests;
