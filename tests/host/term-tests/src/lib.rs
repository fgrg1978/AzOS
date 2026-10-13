// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the Terminal object (the owner's native answer to a
//! pty): the interface and its codec (`userspace/lib/term`), and the pure
//! modules of the terminal server (`userspace/services/termd/src/{edit,disc,
//! service}.rs`, pulled in with `#[path]` so the code under test is the code
//! `TERMD.ELF` is built from).
//!
//! The service is driven through the generated client stub over a loopback
//! transport, so the wire form the shell sends is the one under test.

#[allow(dead_code)]
#[path = "../../../../userspace/services/termd/src/edit.rs"]
pub mod edit;
#[allow(dead_code)]
#[path = "../../../../userspace/services/termd/src/disc.rs"]
pub mod disc;
#[allow(dead_code)]
#[path = "../../../../userspace/services/termd/src/service.rs"]
pub mod service;

#[cfg(test)]
mod line_editor {
    use crate::edit::{Editor, Event, History, LINE_MAX};

    fn feed_all(e: &mut Editor, h: &History, bytes: &[u8]) -> (Vec<Event>, Vec<u8>) {
        let mut evs = Vec::new();
        let mut out = Vec::new();
        for &b in bytes {
            let ev = e.feed(b, h);
            out.extend_from_slice(e.take_output());
            if ev != Event::None {
                evs.push(ev);
            }
        }
        (evs, out)
    }

    fn fresh() -> Editor {
        let mut e = Editor::new();
        e.set_prompt(b"$ ");
        e.start();
        assert_eq!(e.take_output(), b"$ ");
        e
    }

    #[test]
    fn typed_bytes_echo_and_enter_completes_the_line() {
        let h = History::new();
        let mut e = fresh();
        let (evs, out) = feed_all(&mut e, &h, b"echo hi\r");
        assert_eq!(evs, vec![Event::Line]);
        assert_eq!(e.line(), b"echo hi");
        assert_eq!(out, b"echo hi\n");
    }

    #[test]
    fn backspace_and_del_erase_on_screen_and_in_the_line() {
        let h = History::new();
        let mut e = fresh();
        let (_, out) = feed_all(&mut e, &h, b"ab\x7fc\x08d");
        assert_eq!(e.line(), b"ad");
        // b, erase b, c, erase c, d.
        assert_eq!(out, b"ab\x08 \x08c\x08 \x08d");
    }

    #[test]
    fn backspace_on_an_empty_line_prints_nothing() {
        let h = History::new();
        let mut e = fresh();
        let (_, out) = feed_all(&mut e, &h, b"\x7f\x08");
        assert!(out.is_empty());
        assert_eq!(e.line(), b"");
    }

    #[test]
    fn ctrl_u_kills_and_ctrl_w_kills_a_word() {
        let h = History::new();
        let mut e = fresh();
        feed_all(&mut e, &h, b"ls -l /fat\x17");
        assert_eq!(e.line(), b"ls -l ");
        feed_all(&mut e, &h, b"\x15");
        assert_eq!(e.line(), b"");
    }

    #[test]
    fn left_arrow_then_insert_edits_the_middle() {
        let h = History::new();
        let mut e = fresh();
        feed_all(&mut e, &h, b"ac\x1b[Db");
        assert_eq!(e.line(), b"abc");
        assert_eq!(e.cursor(), 2);
        feed_all(&mut e, &h, b"\x01X\x05Y");
        assert_eq!(e.line(), b"XabcY");
    }

    #[test]
    fn delete_key_removes_under_the_cursor() {
        let h = History::new();
        let mut e = fresh();
        feed_all(&mut e, &h, b"abc\x01\x1b[3~");
        assert_eq!(e.line(), b"bc");
    }

    #[test]
    fn ctrl_c_and_ctrl_d_are_reported_not_acted_on() {
        let h = History::new();
        let mut e = fresh();
        let (evs, _) = feed_all(&mut e, &h, b"\x04");
        assert_eq!(evs, vec![Event::Eof]);
        let (evs, _) = feed_all(&mut e, &h, b"x\x03");
        assert_eq!(evs, vec![Event::Interrupt]);
        assert_eq!(e.line(), b"x", "^C leaves the decision to the caller");
        let (evs, _) = feed_all(&mut e, &h, b"\x04");
        assert!(evs.is_empty(), "^D on a non-empty line is delete-at-cursor, not EOF");
    }

    #[test]
    fn a_256_byte_overflow_is_dropped_not_wrapped() {
        let h = History::new();
        let mut e = fresh();
        let long = vec![b'a'; LINE_MAX + 20];
        feed_all(&mut e, &h, &long);
        assert_eq!(e.line().len(), LINE_MAX);
        let (evs, _) = feed_all(&mut e, &h, b"\r");
        assert_eq!(evs, vec![Event::Line]);
    }

    #[test]
    fn history_up_and_down_walk_and_restore_the_new_line() {
        let mut h = History::new();
        h.push(b"first");
        h.push(b"second");
        h.push(b"second"); // a repeat of the newest is not stored twice
        h.push(b"   "); // blanks are not stored
        assert_eq!(h.len(), 2);
        let mut e = fresh();
        feed_all(&mut e, &h, b"new");
        feed_all(&mut e, &h, b"\x1b[A");
        assert_eq!(e.line(), b"second");
        feed_all(&mut e, &h, b"\x1b[A");
        assert_eq!(e.line(), b"first");
        feed_all(&mut e, &h, b"\x1b[A");
        assert_eq!(e.line(), b"first", "past the oldest stays on it");
        feed_all(&mut e, &h, b"\x1b[B\x1b[B");
        assert_eq!(e.line(), b"new");
    }

    #[test]
    fn a_cursor_position_report_is_swallowed() {
        let h = History::new();
        let mut e = fresh();
        let (_, out) = feed_all(&mut e, &h, b"\x1b[24;80Rz");
        assert_eq!(e.line(), b"z");
        assert_eq!(out, b"z");
    }

    #[test]
    fn the_history_ring_wraps_keeping_the_newest() {
        let mut h = History::new();
        for i in 0..(crate::edit::HIST_N + 5) {
            h.push(format!("cmd{i}").as_bytes());
        }
        assert_eq!(h.len(), crate::edit::HIST_N);
        assert_eq!(h.get(0), Some(format!("cmd{}", crate::edit::HIST_N + 4).as_bytes()));
        assert_eq!(h.get(crate::edit::HIST_N), None);
    }
}

#[cfg(test)]
mod codec {
    use azos_term::*;

    #[test]
    fn bytes_pack_eight_to_a_word_little_endian() {
        let mut w = [0u64; 2];
        pack_bytes(b"abcdefghij", &mut w);
        assert_eq!(w[0], u64::from_le_bytes(*b"abcdefgh"));
        assert_eq!(w[1], u64::from_le_bytes([b'i', b'j', 0, 0, 0, 0, 0, 0]));
        let mut back = [0u8; 16];
        unpack_bytes(&w, &mut back);
        assert_eq!(&back[..10], b"abcdefghij");
        assert_eq!(&back[10..], &[0u8; 6]);
    }

    #[test]
    fn an_event_round_trips_every_field() {
        let mut e = Event::new(Kind::Interrupt);
        e.len = 0xBEEF;
        e.job = 0xDEAD_BEEF;
        for (i, b) in e.data.iter_mut().enumerate() {
            *b = i as u8 ^ 0xA5;
        }
        assert_eq!(unpack_event(&pack_event(&e)), Some(e));
    }

    #[test]
    fn an_unknown_kind_is_refused_not_guessed() {
        let mut w = pack_event(&Event::new(Kind::Eof));
        w[0] = (w[0] & !0xFF) | 0x7F;
        assert_eq!(unpack_event(&w), None);
    }

    #[test]
    fn a_chunk_carries_the_total_and_the_bytes_from_the_offset() {
        let line: Vec<u8> = (0..130u32).map(|i| i as u8).collect();
        let c = unpack_chunk(&pack_chunk(Some(&line), 96));
        assert!(c.valid);
        assert_eq!(c.total, 130);
        assert_eq!(&c.data[..34], &line[96..130]);
        assert_eq!(&c.data[34..], &[0u8; 14]);
        let none = unpack_chunk(&pack_chunk(None, 0));
        assert!(!none.valid);
        assert_eq!(none.total, 0);
        // An empty line exists: valid, length 0 (history keeps no blanks, but
        // the last line may be empty).
        assert!(unpack_chunk(&pack_chunk(Some(b""), 0)).valid);
    }

    #[test]
    fn the_size_packs_columns_high() {
        assert_eq!(pack_size(80, 24), 80 << 16 | 24);
        assert_eq!(unpack_size(pack_size(0xFFFF, 1)), (0xFFFF, 1));
    }

    #[test]
    fn the_interface_has_the_documented_shape() {
        let ops = TerminalIdl::OPS;
        let names: Vec<&str> = ops.iter().map(|o| o.name).collect();
        assert_eq!(
            names,
            ["size", "set_size", "set_mode", "set_echo", "set_foreground", "set_prompt", "begin_line", "redraw", "read_event",
             "line_chunk", "history", "hangup"]
        );
        let ev = ops.iter().find(|o| o.name == "read_event").unwrap();
        assert_eq!((ev.req_words, ev.rep_words), (2, 8), "header + timeout; status + 7 words");
        assert!(!ev.idempotent(), "reading consumes input");
        assert!(ops.iter().find(|o| o.name == "line_chunk").unwrap().idempotent());
        assert!(ops.iter().all(|o| o.req_caps == 0 && o.rep_caps == 0), "no capability crosses the terminal");
    }
}

#[cfg(test)]
mod discipline {
    use crate::disc::{Discipline, Event, HELD_MAX, RAW_MAX};

    /// Push `bytes` and collect every event they make, with the echo.
    fn run(d: &mut Discipline, bytes: &[u8]) -> (Vec<Event>, Vec<u8>) {
        d.push(bytes);
        let mut evs = Vec::new();
        let mut out = Vec::new();
        while let Some(e) = d.step() {
            evs.push(e);
            out.extend_from_slice(d.take_output());
            if let Event::Line = e {
                // keep going: a second line may follow
            }
        }
        out.extend_from_slice(d.take_output());
        (evs, out)
    }

    fn cooked() -> Discipline {
        let mut d = Discipline::new();
        d.set_prompt(b"$ ");
        d.begin_line();
        assert_eq!(d.take_output(), b"$ ");
        d
    }

    #[test]
    fn a_fresh_terminal_is_cooked_echoing_80_by_24_with_the_client_in_focus() {
        let d = Discipline::new();
        assert!(!d.is_raw() && d.echo());
        assert_eq!(d.size(), (80, 24));
        assert_eq!(d.foreground(), 0);
    }

    #[test]
    fn cooked_edits_echoes_and_delivers_a_line() {
        let mut d = cooked();
        let (evs, out) = run(&mut d, b"lx\x7fs\r");
        assert_eq!(evs, vec![Event::Line]);
        assert_eq!(d.line(), b"ls");
        assert_eq!(out, b"lx\x08 \x08s\n");
    }

    #[test]
    fn echo_off_hides_the_typing_but_not_the_prompt() {
        let mut d = Discipline::new();
        d.set_prompt(b"pw: ");
        d.set_echo(false);
        d.begin_line();
        assert_eq!(d.take_output(), b"pw: ", "the prompt is the client's text, not an echo");
        let (evs, out) = run(&mut d, b"secret\r");
        assert_eq!(evs, vec![Event::Line]);
        assert_eq!(d.line(), b"secret", "the line is still edited and delivered");
        assert!(out.is_empty(), "nothing typed is shown: {out:?}");
    }

    #[test]
    fn ctrl_c_is_a_typed_event_that_clears_the_line_and_shows_caret_c() {
        let mut d = cooked();
        let (evs, out) = run(&mut d, b"abc\x03");
        assert_eq!(evs, vec![Event::Interrupt(0)]);
        assert_eq!(out, b"abc^C\n");
        // The line is gone: Enter now delivers an empty line.
        let (evs, _) = run(&mut d, b"\r");
        assert_eq!(evs, vec![Event::Line]);
        assert_eq!(d.line(), b"");
    }

    #[test]
    fn ctrl_d_ends_input_only_on_an_empty_line() {
        let mut d = cooked();
        let (evs, _) = run(&mut d, b"a\x04");
        assert!(evs.is_empty(), "^D on a non-empty line deletes");
        let (evs, _) = run(&mut d, b"\x08\x04");
        assert_eq!(evs, vec![Event::Eof]);
    }

    #[test]
    fn raw_mode_delivers_bytes_unedited_and_unechoed_by_the_editor() {
        let mut d = Discipline::new();
        d.set_raw(true);
        d.set_echo(false);
        let (evs, out) = run(&mut d, b"a\x7f\x1b[Ab");
        assert_eq!(evs, vec![Event::Bytes(6)]);
        assert_eq!(&d.raw()[..6], b"a\x7f\x1b[Ab");
        assert!(out.is_empty());
    }

    #[test]
    fn raw_mode_chunks_at_the_event_size_and_passes_ctrl_d() {
        let mut d = Discipline::new();
        d.set_raw(true);
        d.set_echo(false);
        let mut bytes = vec![b'x'; RAW_MAX + 5];
        bytes.push(0x04);
        let (evs, _) = run(&mut d, &bytes);
        assert_eq!(evs, vec![Event::Bytes(RAW_MAX), Event::Bytes(6)]);
        assert_eq!(&d.raw()[..6], b"xxxxx\x04", "^D is data in raw mode");
    }

    #[test]
    fn raw_mode_still_reports_the_interrupt_key_and_splits_the_bytes_around_it() {
        let mut d = Discipline::new();
        d.set_raw(true);
        d.set_echo(false);
        let (evs, _) = run(&mut d, b"ab\x03cd");
        assert_eq!(evs, vec![Event::Bytes(2), Event::Interrupt(0), Event::Bytes(2)]);
    }

    #[test]
    fn a_job_in_focus_gets_interrupts_tagged_with_its_id_and_nothing_else() {
        let mut d = cooked();
        d.set_foreground(7);
        let (evs, out) = run(&mut d, b"ab\x03\x03");
        assert_eq!(evs, vec![Event::Interrupt(7), Event::Interrupt(7)]);
        assert_eq!(out, b"^C\n^C\n", "typed text is not shown while a job runs");
        assert_eq!(d.held(), 2, "ab is held as type-ahead");
    }

    #[test]
    fn an_interrupt_typed_before_the_focus_moved_belongs_to_the_job() {
        let mut d = cooked();
        // The shell is still spawning when ^C arrives; the type-ahead around
        // it is kept, the interrupt is the job's.
        d.push(b"ab\x03c");
        d.set_foreground(9);
        assert_eq!(d.held(), 3, "ab and c stay held, the interrupt does not");
        let (evs, _) = run(&mut d, b"");
        assert_eq!(evs, vec![Event::Interrupt(9)]);
        assert_eq!(d.held(), 3);
    }

    #[test]
    fn interrupts_not_delivered_when_the_job_ends_are_dropped() {
        let mut d = cooked();
        d.set_foreground(9);
        d.push(b"\x03\x03");
        d.set_foreground(0);
        let (evs, _) = run(&mut d, b"");
        assert!(evs.is_empty(), "the job is gone; its interrupts go with it: {evs:?}");
    }

    #[test]
    fn redraw_repaints_the_prompt_and_the_text_unless_echo_is_off() {
        let mut d = cooked();
        run(&mut d, b"ls");
        d.redraw();
        assert_eq!(d.take_output(), b"\r$ ls\x1b[K");
        d.set_echo(false);
        d.redraw();
        assert!(d.take_output().is_empty(), "typed text must not reappear on a redraw with echo off");
    }

    #[test]
    fn type_ahead_is_replayed_into_the_line_when_the_focus_returns() {
        let mut d = cooked();
        d.set_foreground(3);
        let (evs, _) = run(&mut d, b"ec");
        assert!(evs.is_empty());
        d.set_foreground(0);
        d.begin_line();
        assert_eq!(d.take_output(), b"$ ");
        let (evs, out) = run(&mut d, b"ho\r");
        assert_eq!(evs, vec![Event::Line]);
        assert_eq!(d.line(), b"echo");
        assert_eq!(out, b"echo\n", "the held bytes are echoed at the prompt, once");
    }

    #[test]
    fn type_ahead_is_bounded_and_drops_the_excess_not_the_oldest() {
        let mut d = Discipline::new();
        d.set_foreground(1);
        d.push(&vec![b'a'; HELD_MAX]);
        d.push(b"zzz");
        assert_eq!(d.held(), HELD_MAX);
        d.set_foreground(0);
        d.set_raw(true);
        let mut got = Vec::new();
        while let Some(Event::Bytes(n)) = d.step() {
            got.extend_from_slice(&d.raw()[..n]);
        }
        assert_eq!(got, vec![b'a'; HELD_MAX]);
    }

    #[test]
    fn lines_enter_the_history_newest_first() {
        let mut d = cooked();
        run(&mut d, b"one\rtwo\rtwo\r  \r");
        assert_eq!(d.history(0), Some(&b"two"[..]));
        assert_eq!(d.history(1), Some(&b"one"[..]));
        assert_eq!(d.history(2), None, "a repeat and a blank line are not kept");
        // Up arrow walks it, in the server, with no help from the client.
        d.begin_line();
        d.take_output();
        run(&mut d, b"\x1b[A");
        let (evs, _) = run(&mut d, b"\r");
        assert_eq!(evs, vec![Event::Line]);
        assert_eq!(d.line(), b"two");
    }

    #[test]
    fn two_lines_in_one_push_make_two_events() {
        let mut d = cooked();
        d.push(b"a\rb\r");
        assert_eq!(d.step(), Some(Event::Line));
        assert_eq!(d.line(), b"a");
        assert_eq!(d.step(), Some(Event::Line));
        assert_eq!(d.line(), b"b");
        assert_eq!(d.step(), None);
    }

    #[test]
    fn echo_off_also_hides_the_raw_bytes() {
        let mut d = Discipline::new();
        d.set_raw(true);
        let (_, out) = run(&mut d, b"hi");
        assert_eq!(out, b"hi", "raw with echo on shows the bytes");
        d.set_echo(false);
        let (_, out) = run(&mut d, b"hi");
        assert!(out.is_empty());
    }
}

#[cfg(test)]
mod served {
    use crate::service::{Console, Service};
    use azos_term::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// A console that types what the test scripted, one chunk per read, then
    /// times out; it records what the server wrote.
    #[derive(Default)]
    struct Fake {
        typed: VecDeque<Vec<u8>>,
        shown: Vec<u8>,
        timeouts: Vec<Option<u64>>,
    }

    impl Console for Fake {
        fn read(&mut self, buf: &mut [u8], timeout_ns: Option<u64>) -> isize {
            self.timeouts.push(timeout_ns);
            match self.typed.pop_front() {
                Some(c) => {
                    assert!(c.len() <= buf.len());
                    buf[..c.len()].copy_from_slice(&c);
                    c.len() as isize
                }
                None => 0,
            }
        }
        fn write(&mut self, b: &[u8]) {
            self.shown.extend_from_slice(b);
        }
    }

    /// The loopback: the request goes through the wire form to the server's
    /// dispatcher, as the kernel would carry it.
    struct Loop<'a>(&'a RefCell<Service<Fake>>);

    impl Transport for Loop<'_> {
        fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
            let req = *msg;
            let _ = TerminalIdl::dispatch(&mut *self.0.borrow_mut(), &req, msg);
            Ok(())
        }
    }

    fn server(chunks: &[&[u8]]) -> RefCell<Service<Fake>> {
        let mut f = Fake::default();
        f.typed = chunks.iter().map(|c| c.to_vec()).collect();
        RefCell::new(Service::new(f))
    }

    fn prompt(c: &mut TerminalClient<Loop<'_>>, p: &[u8]) {
        let mut w = [0u64; PROMPT_WORDS];
        pack_bytes(p, &mut w);
        c.set_prompt(p.len() as u32, w).unwrap();
    }

    fn event(c: &mut TerminalClient<Loop<'_>>, ms: u32) -> Event {
        unpack_event(&c.read_event(ms).unwrap()).unwrap()
    }

    #[test]
    fn a_client_reads_a_typed_line_through_the_wire() {
        let s = server(&[b"ec", b"ho hi\r"]);
        let mut c = TerminalClient::new(Loop(&s));
        prompt(&mut c, b"azos$ ");
        c.begin_line().unwrap();
        let e = event(&mut c, WAIT_FOREVER);
        assert_eq!(e.kind, Kind::Line);
        assert_eq!(e.len, 7);
        assert_eq!(e.inline(), b"echo hi");
        assert_eq!(s.borrow().con.shown, b"azos$ echo hi\n");
    }

    #[test]
    fn a_line_longer_than_a_chunk_is_fetched_whole() {
        let long: Vec<u8> = (0..200u32).map(|i| b'a' + (i % 26) as u8).collect();
        let mut typed = long.clone();
        typed.push(b'\r');
        let s = server(&[&typed[..60], &typed[60..120], &typed[120..180], &typed[180..]]);
        let mut c = TerminalClient::new(Loop(&s));
        c.begin_line().unwrap();
        let e = event(&mut c, WAIT_FOREVER);
        assert_eq!((e.kind, e.len), (Kind::Line, 200));
        let mut got = e.inline().to_vec();
        while got.len() < e.len as usize {
            let ch = unpack_chunk(&c.line_chunk(got.len() as u32).unwrap());
            assert!(ch.valid && ch.total == 200);
            let n = (200 - got.len()).min(CHUNK_BYTES);
            got.extend_from_slice(&ch.data[..n]);
        }
        assert_eq!(got, long);
    }

    #[test]
    fn nothing_typed_is_a_timeout_that_asked_the_console_for_that_long() {
        let s = server(&[]);
        let mut c = TerminalClient::new(Loop(&s));
        assert_eq!(event(&mut c, 5).kind, Kind::Timeout);
        assert_eq!(event(&mut c, 0).kind, Kind::Timeout);
        assert_eq!(event(&mut c, WAIT_FOREVER).kind, Kind::Timeout, "the fake times out even a forever wait");
        assert_eq!(s.borrow().con.timeouts, vec![Some(5_000_000), Some(0), None]);
    }

    #[test]
    fn ctrl_c_during_a_job_is_an_event_naming_the_job() {
        let s = server(&[b"x", b"\x03"]);
        let mut c = TerminalClient::new(Loop(&s));
        c.set_foreground(42).unwrap();
        let e = event(&mut c, 10);
        assert_eq!((e.kind, e.job), (Kind::Interrupt, 42));
        assert_eq!(s.borrow().con.shown, b"^C\n");
        c.set_foreground(0).unwrap();
        c.begin_line().unwrap();
        let e = event(&mut c, 0);
        assert_eq!(e.kind, Kind::Timeout, "x is type-ahead of an unfinished line, not an event");
    }

    #[test]
    fn mode_echo_and_size_are_typed_state() {
        let s = server(&[b"ab"]);
        let mut c = TerminalClient::new(Loop(&s));
        assert_eq!(unpack_size(c.size().unwrap()), (80, 24));
        c.set_size(132, 50).unwrap();
        assert_eq!(unpack_size(c.size().unwrap()), (132, 50));
        c.set_mode(true).unwrap();
        c.set_echo(false).unwrap();
        let e = event(&mut c, 0);
        assert_eq!((e.kind, e.inline()), (Kind::Bytes, &b"ab"[..]));
        assert!(s.borrow().con.shown.is_empty());
    }

    #[test]
    fn the_history_is_read_back_by_chunks_and_a_missing_one_is_not_valid() {
        let s = server(&[b"one\rtwo\r"]);
        let mut c = TerminalClient::new(Loop(&s));
        c.begin_line().unwrap();
        assert_eq!(event(&mut c, 0).kind, Kind::Line);
        assert_eq!(event(&mut c, 0).kind, Kind::Line);
        let h0 = unpack_chunk(&c.history(0, 0).unwrap());
        assert!(h0.valid);
        assert_eq!(&h0.data[..h0.total as usize], b"two");
        let h1 = unpack_chunk(&c.history(1, 0).unwrap());
        assert_eq!(&h1.data[..h1.total as usize], b"one");
        assert!(!unpack_chunk(&c.history(2, 0).unwrap()).valid);
    }

    #[test]
    fn hangup_is_seen_by_the_server_and_a_request_for_another_interface_is_refused() {
        let s = server(&[]);
        let mut c = TerminalClient::new(Loop(&s));
        assert_eq!(s.borrow().hung_up, None);
        c.hangup(3).unwrap();
        assert_eq!(s.borrow().hung_up, Some(3), "the status travels, signed");
        c.hangup(-1).unwrap();
        assert_eq!(s.borrow().hung_up, Some(-1));
        // A message that is not a Terminal request is refused by the dispatcher.
        let mut m = MsgDesc { version: azos_idl::MSG_VERSION, n_words: 1, ..MsgDesc::default() };
        m.words[0] = azos_idl::header(0x1234_5678, 1, 1);
        let mut rep = MsgDesc::default();
        assert_eq!(TerminalIdl::dispatch(&mut *s.borrow_mut(), &m, &mut rep), Err(IdlError::BadInterface));
    }
}
