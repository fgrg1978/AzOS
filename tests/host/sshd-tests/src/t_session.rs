// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The session behind the channel, over a scripted `Runner`: commands,
//! the prompt, the line discipline, `^C` and `^D`.

use crate::session::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Default)]
struct World {
    spawned: Vec<Vec<Vec<u8>>>,
    stdin: Vec<u8>,
    stdin_closed: bool,
    output: VecDeque<u8>,
    /// Exit status once the command is over.
    exit: Option<i32>,
    /// The command ends only when asked to stop (`spin`), at the first (soft)
    /// request unless `ignores_soft`.
    runs_until_stopped: bool,
    ignores_soft: bool,
    /// `cat`: echoes its stdin, ends when it is closed.
    cat: bool,
    stops: Vec<bool>,
    running: bool,
    /// An endless writer, for back-pressure.
    flood: bool,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<World>>);

impl Runner for Fake {
    fn spawn(&mut self, argv: &[Vec<u8>]) -> Result<(), &'static str> {
        let mut w = self.0.borrow_mut();
        w.spawned.push(argv.to_vec());
        let name = argv[0].clone();
        w.stdin.clear();
        w.stdin_closed = false;
        w.stops.clear();
        w.exit = None;
        w.cat = false;
        w.runs_until_stopped = false;
        w.ignores_soft = false;
        w.flood = false;
        w.output.clear();
        match &name[..] {
            b"echo" => {
                let line = argv[1..].iter().map(|a| a.as_slice()).collect::<Vec<_>>().join(&b' ');
                w.output.extend(line);
                w.output.push_back(b'\n');
                w.exit = Some(0);
            }
            b"false" => w.exit = Some(1),
            b"cat" => w.cat = true,
            b"spin" => w.runs_until_stopped = true,
            b"stubborn" => {
                w.runs_until_stopped = true;
                w.ignores_soft = true;
            }
            b"flood" => w.flood = true,
            b"missing" => return Err("command not found"),
            _ => w.exit = Some(0),
        }
        w.running = true;
        Ok(())
    }

    fn write_stdin(&mut self, data: &[u8]) -> usize {
        let mut w = self.0.borrow_mut();
        w.stdin.extend_from_slice(data);
        if w.cat {
            w.output.extend(data.iter().copied());
        }
        data.len()
    }

    fn close_stdin(&mut self) {
        let mut w = self.0.borrow_mut();
        w.stdin_closed = true;
        if w.cat {
            w.exit = Some(0);
        }
    }

    fn read_output(&mut self, buf: &mut [u8]) -> Read {
        let mut w = self.0.borrow_mut();
        if w.flood {
            buf.fill(b'f');
            return Read::Data(buf.len());
        }
        if w.output.is_empty() {
            return if w.exit.is_some() { Read::Eof } else { Read::Empty };
        }
        let n = buf.len().min(w.output.len());
        for b in buf.iter_mut().take(n) {
            *b = w.output.pop_front().unwrap();
        }
        Read::Data(n)
    }

    fn exit_status(&mut self) -> Option<i32> {
        let w = self.0.borrow();
        if w.running { w.exit } else { None }
    }

    fn stop(&mut self, force: bool) {
        let mut w = self.0.borrow_mut();
        w.stops.push(force);
        if w.runs_until_stopped && (force || !w.ignores_soft) {
            w.exit = Some(130);
        }
    }
}

fn session() -> (Session<Fake>, Fake) {
    let f = Fake::default();
    (Session::new(f.clone()), f)
}

/// Run the session until it stops moving; everything it wants to send.
fn settle(s: &mut Session<Fake>, now: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..20 {
        let moved = s.pump(now);
        out.extend_from_slice(s.output());
        let n = s.output().len();
        s.consumed(n);
        if !moved && n == 0 {
            break;
        }
    }
    out
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ── exec ────────────────────────────────────────────────────────────────────

#[test]
fn exec_runs_one_command_and_reports_its_status() {
    let (mut s, f) = session();
    s.on_exec(b"echo hello  world", 0);
    let out = settle(&mut s, 0);
    assert_eq!(text(&out), "hello world\n");
    assert_eq!(s.finished(), Some(0));
    assert_eq!(f.0.borrow().spawned, vec![vec![b"echo".to_vec(), b"hello".to_vec(), b"world".to_vec()]]);
    let (mut s, _) = session();
    s.on_exec(b"false", 0);
    settle(&mut s, 0);
    assert_eq!(s.finished(), Some(1));
}

#[test]
fn exec_quotes() {
    let (mut s, f) = session();
    s.on_exec(br#"echo 'a  b' "c \"d\" \\e" f'g'h"#, 0);
    settle(&mut s, 0);
    let args = f.0.borrow().spawned[0].clone();
    assert_eq!(args, vec![b"echo".to_vec(), b"a  b".to_vec(), b"c \"d\" \\e".to_vec(), b"fgh".to_vec()]);
}

#[test]
fn exec_what_is_not_found_says_so_with_status_127() {
    let (mut s, _) = session();
    s.on_exec(b"missing arg", 0);
    let out = settle(&mut s, 0);
    assert_eq!(text(&out), "command not found\n");
    assert_eq!(s.finished(), Some(127));
}

#[test]
fn exec_refuses_what_the_shell_owns_instead_of_running_it_as_something_else() {
    for line in ["echo a | cat", "echo a > f", "echo $HOME", "cat < f", "echo a; echo b", "echo a &", "ls *", "echo `id`", "echo (a)", "echo a\\ b"] {
        let (mut s, f) = session();
        s.on_exec(line.as_bytes(), 0);
        let out = settle(&mut s, 0);
        assert!(text(&out).contains("belong to the shell"), "{line}: {}", text(&out));
        assert_eq!(s.finished(), Some(2), "{line}");
        assert!(f.0.borrow().spawned.is_empty(), "{line} was run");
    }
    // Inside quotes the same characters are text.
    let (mut s, f) = session();
    s.on_exec(b"echo 'a | b > c $d'", 0);
    settle(&mut s, 0);
    assert_eq!(f.0.borrow().spawned[0][1], b"a | b > c $d");
}

#[test]
fn exec_limits() {
    let (mut s, _) = session();
    s.on_exec(b"echo 'unterminated", 0);
    assert_eq!(text(&settle(&mut s, 0)), "unterminated quote\n");
    let (mut s, _) = session();
    let many = (0..20).map(|i| format!("a{i}")).collect::<Vec<_>>().join(" ");
    s.on_exec(many.as_bytes(), 0);
    assert_eq!(text(&settle(&mut s, 0)), "too many arguments\n");
}

#[test]
fn exec_stdin_is_the_channel_and_eof_ends_it() {
    let (mut s, f) = session();
    s.on_exec(b"cat", 0);
    settle(&mut s, 0);
    s.on_data(b"one\ntwo\n", 0);
    let out = settle(&mut s, 0);
    assert_eq!(text(&out), "one\ntwo\n");
    assert_eq!(s.finished(), None, "cat reads until its input is closed");
    s.on_eof(0);
    settle(&mut s, 0);
    assert!(f.0.borrow().stdin_closed);
    assert_eq!(s.finished(), Some(0));
}

#[test]
fn exec_with_a_pty_translates_newlines_and_echoes_what_is_typed() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_exec(b"cat", 0);
    settle(&mut s, 0);
    s.on_data(b"hi\r", 0);
    let out = settle(&mut s, 0);
    // Echo of the typed line, then the command's copy of it, both with \r\n.
    assert_eq!(text(&out), "hi\r\nhi\r\n");
    assert_eq!(f.0.borrow().stdin, b"hi\n");
    // ^D on an empty line is end of input.
    s.on_data(&[4], 0);
    settle(&mut s, 0);
    assert!(f.0.borrow().stdin_closed);
    assert_eq!(s.finished(), Some(0));
}

#[test]
fn exec_output_is_untouched_without_a_pty() {
    let (mut s, _) = session();
    s.on_exec(b"echo a", 0);
    assert_eq!(settle(&mut s, 0), b"a\n");
}

// ── The prompt ──────────────────────────────────────────────────────────────

#[test]
fn the_prompt_runs_a_line_and_comes_back() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_shell();
    let out = text(&settle(&mut s, 0));
    assert!(out.contains("AzOS console over ssh"), "{out}");
    assert!(out.ends_with("azos-ssh$ "), "{out:?}");
    s.on_data(b"echo hi\r", 0);
    let out = text(&settle(&mut s, 0));
    // The echo of the line, the command's output, a new prompt.
    assert_eq!(out, "echo hi\r\nhi\r\nazos-ssh$ ");
    assert_eq!(f.0.borrow().spawned.len(), 1);
    assert_eq!(s.finished(), None);
}

#[test]
fn the_prompt_edits_the_line_like_the_console_does() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_shell();
    settle(&mut s, 0);
    // A typo, backspace, the rest; then the history key and enter.
    s.on_data(b"echo ax\x7fb\r", 0);
    settle(&mut s, 0);
    assert_eq!(f.0.borrow().spawned[0][1], b"ab");
    s.on_data(b"\x1b[A\r", 0);
    settle(&mut s, 0);
    assert_eq!(f.0.borrow().spawned.len(), 2, "up-arrow recalls the line");
    assert_eq!(f.0.borrow().spawned[1][1], b"ab");
}

#[test]
fn bytes_in_pieces_make_the_same_line() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_shell();
    settle(&mut s, 0);
    for b in b"echo split\r" {
        s.on_data(&[*b], 0);
        settle(&mut s, 0);
    }
    assert_eq!(f.0.borrow().spawned[0][1], b"split");
}

#[test]
fn without_a_pty_there_is_no_prompt_and_no_echo() {
    let (mut s, f) = session();
    s.on_shell();
    let banner = text(&settle(&mut s, 0));
    assert!(!banner.contains("azos-ssh$"), "{banner}");
    s.on_data(b"echo piped\n", 0);
    assert_eq!(text(&settle(&mut s, 0)), "piped\n");
    assert_eq!(f.0.borrow().spawned.len(), 1);
}

#[test]
fn exit_and_logout_end_the_session_with_a_status() {
    let (mut s, _) = session();
    s.on_shell();
    s.on_data(b"exit 3\n", 0);
    settle(&mut s, 0);
    assert_eq!(s.finished(), Some(3));
    let (mut s, _) = session();
    s.on_shell();
    s.on_data(b"logout\n", 0);
    settle(&mut s, 0);
    assert_eq!(s.finished(), Some(0));
}

#[test]
fn control_d_at_the_prompt_logs_out_and_control_c_starts_a_new_line() {
    let (mut s, _) = session();
    s.on_pty(80, 24);
    s.on_shell();
    settle(&mut s, 0);
    s.on_data(b"ec\x03", 0);
    let out = text(&settle(&mut s, 0));
    assert!(out.contains("^C"), "{out:?}");
    assert!(out.ends_with("azos-ssh$ "), "{out:?}");
    assert_eq!(s.finished(), None);
    s.on_data(&[4], 0);
    let out = text(&settle(&mut s, 0));
    assert!(out.contains("logout"), "{out:?}");
    assert_eq!(s.finished(), Some(0));
}

#[test]
fn the_client_closing_its_side_at_the_prompt_ends_the_session() {
    let (mut s, _) = session();
    s.on_shell();
    settle(&mut s, 0);
    s.on_eof(0);
    assert_eq!(s.finished(), Some(0));
}

#[test]
fn help_and_refusals_at_the_prompt_do_not_end_it() {
    let (mut s, f) = session();
    s.on_shell();
    settle(&mut s, 0);
    s.on_data(b"help\nmissing\necho a | b\n\n", 0);
    let out = text(&settle(&mut s, 0));
    assert!(out.contains("TOOLBOX.ELF"), "{out}");
    assert!(out.contains("command not found"), "{out}");
    assert!(out.contains("belong to the shell"), "{out}");
    assert_eq!(s.finished(), None);
    assert_eq!(f.0.borrow().spawned.len(), 1, "only `missing` reached the runner");
}

// ── A command that runs ─────────────────────────────────────────────────────

#[test]
fn control_c_stops_the_running_command_and_the_second_forces_it() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_shell();
    settle(&mut s, 0);
    s.on_data(b"stubborn\r", 0);
    settle(&mut s, 0);
    assert!(f.0.borrow().running);
    s.on_data(&[3], 10);
    settle(&mut s, 10);
    assert_eq!(f.0.borrow().stops, vec![false], "the first ^C asks");
    s.on_data(&[3], 20);
    let out = text(&settle(&mut s, 20));
    assert_eq!(f.0.borrow().stops, vec![false, true], "the second forces");
    assert!(out.ends_with("azos-ssh$ "), "back at the prompt: {out:?}");
}

#[test]
fn a_stop_that_is_not_obeyed_is_forced_after_the_grace() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_shell();
    settle(&mut s, 0);
    s.on_data(b"stubborn\r", 0);
    settle(&mut s, 0);
    s.on_data(&[3], 1000);
    settle(&mut s, 1000);
    settle(&mut s, 1000 + GRACE_MS - 1);
    assert_eq!(f.0.borrow().stops, vec![false]);
    settle(&mut s, 1000 + GRACE_MS);
    assert_eq!(f.0.borrow().stops, vec![false, true]);
}

#[test]
fn typed_lines_reach_the_running_command_and_do_not_run_as_commands() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_shell();
    settle(&mut s, 0);
    s.on_data(b"cat\r", 0);
    settle(&mut s, 0);
    s.on_data(b"echo not-a-command\r", 0);
    let out = text(&settle(&mut s, 0));
    assert!(out.contains("echo not-a-command\r\n"), "{out:?}");
    assert_eq!(f.0.borrow().stdin, b"echo not-a-command\n");
    assert_eq!(f.0.borrow().spawned.len(), 1);
    s.on_data(&[4], 0);
    let out = text(&settle(&mut s, 0));
    assert!(out.ends_with("azos-ssh$ "), "cat ended, the prompt is back: {out:?}");
    // The next prompt starts clean: the ^D was the command's, not a logout.
    assert_eq!(s.finished(), None);
}

#[test]
fn output_is_not_read_faster_than_the_channel_takes_it() {
    let (mut s, _) = session();
    s.on_exec(b"flood", 0);
    for _ in 0..200 {
        s.pump(0);
    }
    assert!(s.output().len() <= OUT_HIGH + 1024, "{} bytes held", s.output().len());
    // Taking it lets the command write on.
    let n = s.output().len();
    s.consumed(n);
    s.pump(0);
    assert!(!s.output().is_empty());
}

#[test]
fn a_client_that_goes_away_stops_the_command() {
    let (mut s, f) = session();
    s.on_exec(b"spin", 0);
    settle(&mut s, 0);
    s.on_close();
    assert_eq!(f.0.borrow().stops, vec![true]);
}

#[test]
fn what_a_command_wrote_before_it_exited_is_not_lost() {
    let (mut s, _) = session();
    s.on_exec(b"echo last words", 0);
    // One pump sees both the data and the exit.
    s.pump(0);
    let out = settle(&mut s, 0);
    assert_eq!(text(&out), "last words\n");
    assert_eq!(s.finished(), Some(0));
}

#[test]
fn finished_waits_for_the_output_to_be_taken() {
    let (mut s, _) = session();
    s.on_exec(b"echo a", 0);
    s.pump(0);
    s.pump(0);
    assert!(!s.output().is_empty());
    assert_eq!(s.finished(), None, "the status is told after the last byte");
    let n = s.output().len();
    s.consumed(n);
    assert_eq!(s.finished(), Some(0));
}

#[test]
fn a_script_piped_into_the_prompt_runs_in_order_and_then_the_session_ends() {
    let (mut s, f) = session();
    s.on_shell();
    // All of it at once, then the end of input, as `ssh host < script` sends
    // it. A command reads what arrives after it starts, so `cat` sees the end
    // of its input at once and the line after it runs next.
    s.on_data(b"echo one\ncat\necho three\n", 0);
    s.on_eof(0);
    let out = settle(&mut s, 0);
    assert_eq!(s.finished(), Some(0));
    let spawned = f.0.borrow().spawned.clone();
    assert_eq!(
        spawned.iter().map(|a| a[0].clone()).collect::<Vec<_>>(),
        vec![b"echo".to_vec(), b"cat".to_vec(), b"echo".to_vec()]
    );
    let t = text(&out);
    assert!(t.contains("one\n") && t.contains("three\n"), "{t:?}");
}

#[test]
fn lines_typed_ahead_run_when_the_command_ends() {
    let (mut s, f) = session();
    s.on_pty(80, 24);
    s.on_shell();
    settle(&mut s, 0);
    s.on_data(b"echo a\recho b\r", 0);
    settle(&mut s, 0);
    let spawned = f.0.borrow().spawned.clone();
    assert_eq!(spawned.len(), 2, "{spawned:?}");
    assert_eq!(spawned[1][1], b"b");
    assert_eq!(s.finished(), None);
}
