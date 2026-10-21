// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The terminal server's login gate: the secure-attention key, the prompt that
//! owns the input, and what it hands the login service.
//!
//! The console is scripted, the login service a stand-in that says what the
//! test needs and writes down what it was asked. **The property under test**:
//! what is typed after the key reaches the prompt and nothing else (not the
//! line discipline, so not the shell), and the passphrase is never shown and
//! never leaves the server but as a credential.

use crate::input::Input;
use crate::secure::{Echo, Prompt, Stage, Step};
use crate::service::{Console, Gate, Mode, Service};
use azos_input_wire::event::*;
use azos_login::{credential, pack_credential, pack_name, state, status, CREDENTIAL_WORDS, NAME_WORDS};
use azos_rings::region::{RingStep, SpscRing};
use azos_term::{unpack_event, Kind, Terminal, WAIT_FOREVER};
use std::collections::VecDeque;

const SAK: u8 = 0x1d;

// ── The prompt alone ────────────────────────────────────────────────────────

mod prompt {
    use super::*;

    /// Feed `bytes`; the steps seen (except `More`) and what was echoed.
    fn feed(p: &mut Prompt, bytes: &[u8]) -> (Vec<Step>, Vec<u8>) {
        let (mut steps, mut shown) = (vec![], vec![]);
        let mut e = Echo::new();
        for &b in bytes {
            let s = p.feed(b, &mut e);
            shown.extend_from_slice(e.take());
            if s != Step::More {
                steps.push(s);
            }
        }
        (steps, shown)
    }

    /// The name is echoed, the passphrase is not, in order.
    ///
    /// **Canary.** Echo the passphrase's bytes: `shown` has them.
    #[test]
    fn the_name_is_echoed_and_the_passphrase_is_not() {
        let mut p = Prompt::new();
        let (steps, shown) = feed(&mut p, b"alice\rhunter2\r");
        assert_eq!(steps, [Step::Passphrase, Step::Submit]);
        assert_eq!(shown, b"alice\r\n\r\n", "the name and the two Enters, nothing of the passphrase");
        assert_eq!((p.user(), p.passphrase()), (&b"alice"[..], &b"hunter2"[..]));
    }

    #[test]
    fn editing_keys_work_on_both_fields_and_cr_lf_is_one_enter() {
        let mut p = Prompt::new();
        let (steps, shown) = feed(&mut p, b"alicf\x7fe\r\nhunteX\x08r2\x15secret\r\n");
        assert_eq!(steps, [Step::Passphrase, Step::Submit], "the LF after a CR is the same Enter");
        assert_eq!(p.user(), b"alice");
        assert_eq!(p.passphrase(), b"secret", "^U clears the passphrase");
        assert!(shown.starts_with(b"alicf\x08 \x08e"));
    }

    #[test]
    fn a_name_is_the_rows_alphabet_and_the_fields_are_bounded() {
        let mut p = Prompt::new();
        feed(&mut p, b"a b/c.d\x01\x07\x1b[A_e-f9");
        assert_eq!(p.user(), b"abcd_e-f9", "blanks, slashes, dots, controls and an arrow key are not in a name");
        let mut p = Prompt::new();
        feed(&mut p, b"0123456789abcdefXYZ");
        assert_eq!(p.user().len(), azos_login::NAME_MAX, "past the kernel's name field nothing is taken");
        let mut p = Prompt::new();
        feed(&mut p, b"u\r");
        feed(&mut p, &vec![b'p'; azos_login::PASSPHRASE_MAX + 40]);
        assert_eq!(p.passphrase().len(), azos_login::PASSPHRASE_MAX);
    }

    #[test]
    fn an_empty_name_is_not_submitted_and_escape_sequences_are_skipped() {
        let mut p = Prompt::new();
        let (steps, _) = feed(&mut p, b"\r\n\r");
        assert!(steps.is_empty(), "Enter on an empty name asks again");
        assert_eq!(p.stage(), Stage::User);
        let (steps, _) = feed(&mut p, b"a\x1b[1;5Cb\x1bOP\rpw\r");
        assert_eq!(steps, [Step::Passphrase, Step::Submit]);
        assert_eq!((p.user(), p.passphrase()), (&b"ab"[..], &b"pw"[..]));
    }

    #[test]
    fn control_c_gives_up_and_control_d_does_on_an_empty_field_only() {
        let mut p = Prompt::new();
        assert_eq!(feed(&mut p, b"al\x04").0, [], "^D in the middle of a name is nothing");
        assert_eq!(feed(&mut p, b"\x03").0, [Step::Cancel]);
        let mut p = Prompt::new();
        assert_eq!(feed(&mut p, b"\x04").0, [Step::Cancel], "^D on an empty name");
        let mut p = Prompt::new();
        assert_eq!(feed(&mut p, b"a\r\x04").0, [Step::Passphrase, Step::Cancel], "and on an empty passphrase");
    }

    /// A reset forgets what was typed in both fields.
    ///
    /// **Canary.** Reset the lengths and leave the bytes: the buffers read
    /// back non-zero after `reset`.
    #[test]
    fn a_reset_wipes_the_passphrase_from_memory() {
        let mut p = Prompt::new();
        feed(&mut p, b"alice\rhunter2");
        p.reset();
        assert_eq!((p.user(), p.passphrase(), p.stage()), (&b""[..], &b""[..], Stage::User));
        // The bytes are gone, not just the lengths: type one character and look past it.
        feed(&mut p, b"a\r");
        let raw = unsafe { core::slice::from_raw_parts((&p as *const Prompt) as *const u8, core::mem::size_of::<Prompt>()) };
        assert!(!raw.windows(7).any(|w| w == b"hunter2"), "the old passphrase is still in the struct");
    }
}

// ── The service behind a gate ───────────────────────────────────────────────

/// One thing that happens while the server waits on the console.
enum Beat {
    /// Bytes typed, one read.
    Typed(Vec<u8>),
    /// An event the input driver publishes into the ring: the wait is cut short
    /// by it, as the kernel's nudge does.
    Key(u64),
}

/// A console that does what the test scripted, one beat per read, and fails
/// when the script is out (the real one would wait forever).
#[derive(Default)]
struct Con {
    script: VecDeque<Beat>,
    shown: Vec<u8>,
    ring: Option<SpscRing>,
}

impl Console for Con {
    fn read(&mut self, buf: &mut [u8], _: Option<u64>) -> isize {
        match self.script.pop_front() {
            Some(Beat::Typed(c)) => {
                buf[..c.len()].copy_from_slice(&c);
                c.len() as isize
            }
            Some(Beat::Key(w)) => {
                let _ = self.ring.as_ref().expect("a ring").try_push(w);
                0
            }
            None => -1,
        }
    }
    fn write(&mut self, b: &[u8]) {
        self.shown.extend_from_slice(b);
    }
    fn now_ns(&self) -> u64 {
        0
    }
    fn refresh(&mut self) {}
}

/// A login service that answers from a script and writes down the questions.
#[derive(Default)]
struct Stand {
    state: u32,
    replies: VecDeque<u32>,
    logins: Vec<([u64; NAME_WORDS], [u64; CREDENTIAL_WORDS])>,
    ended: usize,
    /// The next this many `end` calls report a shell that did not stop.
    stuck: usize,
}

impl Gate for Stand {
    fn state(&mut self) -> u32 {
        self.state
    }
    fn login(&mut self, user: [u64; NAME_WORDS], credential: [u64; CREDENTIAL_WORDS]) -> u32 {
        self.logins.push((user, credential));
        self.replies.pop_front().unwrap_or(status::REFUSED)
    }
    fn end(&mut self) -> bool {
        self.ended += 1;
        if self.stuck > 0 {
            self.stuck -= 1;
            return false;
        }
        true
    }
}

fn typed(chunks: &[&[u8]]) -> Con {
    Con { script: chunks.iter().map(|c| Beat::Typed(c.to_vec())).collect(), ..Con::default() }
}

fn gated(con: Con, st: u32, replies: &[u32]) -> Service<Con, Stand> {
    let mut s = Service::with_gate(con, Stand { state: st, replies: replies.iter().copied().collect(), ..Stand::default() });
    s.sak_serial = SAK;
    s.gate_up();
    s
}

fn asked(name: &[u8], pass: &[u8]) -> ([u64; NAME_WORDS], [u64; CREDENTIAL_WORDS]) {
    (pack_name(name).unwrap(), pack_credential(&credential(name, pass)))
}

fn shown(s: &Service<Con, Stand>) -> String {
    String::from_utf8_lossy(&s.con.shown).into_owned()
}

/// The gate settles from what the login service says.
#[test]
fn the_mode_follows_the_login_services_state() {
    assert_eq!(gated(Con::default(), state::OPEN, &[]).mode, Mode::Open);
    assert_eq!(gated(Con::default(), state::LOCKED, &[]).mode, Mode::Locked);
    assert_eq!(gated(Con::default(), state::SESSION, &[]).mode, Mode::Session);
    assert!(!gated(Con::default(), state::OPEN, &[]).guarded());
}

/// The topology decides what a login service that does not answer means. The
/// terminal server holds the call right on it only on a gated console
/// (`azos_topology::builder::login_call_withheld`): without the right there is
/// no gate and no question (`NoGate`), so the console the component manager
/// started the shell on is never locked and never ends; with it, a service that
/// cannot be reached reads as `LOCKED` (`termd`'s `LoginGate`), the secure wait
/// finds nothing to read and the server ends (the manager restarts it).
///
/// **Canary.** Let `NoGate` answer `LOCKED`: the first assertion is red; let the
/// gated console open when the service is silent: the second is.
#[test]
fn a_console_with_no_login_right_is_never_locked_and_a_silent_service_locks_a_gated_one() {
    let mut open = Service::new(Con::default());
    open.gate_up();
    open.locked_loop();
    assert!(!open.guarded() && !open.locked(), "no right to ask, no gate");
    assert!(open.con.shown.is_empty(), "nothing drawn over the shell's console");

    let mut shut = gated(Con::default(), state::LOCKED, &[]);
    shut.locked_loop();
    assert!(shut.locked(), "gated and unanswered: the console stays shut and the server ends");
}

/// Locked: nothing typed is served; the key opens the prompt; a good login
/// ends the lock.
///
/// **Canary.** Feed the line discipline from the locked wait: the junk typed
/// before the key is the first line the new session reads.
#[test]
fn a_locked_console_drops_what_is_typed_until_the_key_and_logs_a_user_in() {
    let mut s = gated(typed(&[b"junk\r", &[b'x', SAK, b'a', b'l', b'i', b'c', b'e', b'\r'], b"pw\r"]), state::LOCKED, &[status::STARTED]);
    s.locked_loop();
    assert_eq!(s.mode, Mode::Session);
    assert_eq!(s.gate.logins, vec![asked(b"alice", b"pw")], "what came after the key, and only that, is the login");
    let out = shown(&s);
    assert!(out.contains("press Ctrl+Alt+Del (or ^]"), "{out}");
    assert!(out.contains("login: alice\r\npassphrase: \r\n"), "{out}");
    assert!(!out.contains("pw") && !out.contains("junk"), "neither the passphrase nor the junk is ever shown: {out}");
    assert_eq!(s.d.line(), b"", "the discipline saw none of it");
}

/// A refused login asks again from the top; the person can give up and the
/// console goes back to waiting for the key.
///
/// **Canary.** Treat any reply as success: the first attempt starts a session.
#[test]
fn a_refusal_asks_again_and_giving_up_locks_the_console() {
    let mut s = gated(typed(&[&[SAK], b"alice\rbad\r", b"bob\rgood\r"]), state::LOCKED, &[status::REFUSED, status::STARTED]);
    s.locked_loop();
    assert_eq!(s.gate.logins, vec![asked(b"alice", b"bad"), asked(b"bob", b"good")]);
    assert!(shown(&s).contains("Login incorrect"));
    assert_eq!(s.mode, Mode::Session);

    let mut s = gated(typed(&[&[SAK], b"alice\x03"]), state::LOCKED, &[]);
    // The person gives up; the console waits for the key again, and the script is out.
    s.locked_loop();
    assert!(s.gate.logins.is_empty());
    assert_eq!(s.mode, Mode::Locked);
    assert_eq!(shown(&s).matches("press Ctrl+Alt+Del").count(), 2, "the banner again, then the console is unreadable");
}

#[test]
fn every_status_has_its_message_and_only_started_logs_in() {
    for (rc, text) in [(status::NOT_NOW, "not available now"), (status::NOT_READY, "cannot verify"), (status::NO_SESSION, "did not start")] {
        let mut s = gated(typed(&[&[SAK], b"alice\rpw\r"]), state::LOCKED, &[rc]);
        s.locked_loop();
        assert!(shown(&s).contains(text), "{rc}: {}", shown(&s));
        assert_eq!(s.mode, Mode::Locked);
    }
}

/// The serial key while a session reads: the session ends before the prompt,
/// what was typed before the key never reaches the discipline, what follows is
/// the login.
///
/// **Canary.** Push the chunk into the discipline before looking for the key:
/// `d.held()` is non-zero afterwards.
#[test]
fn the_serial_key_ends_the_session_and_takes_the_input() {
    let mut s = gated(typed(&[&[b'l', b's', SAK, b'b', b'o', b'b', b'\r', b'p', b'w', b'\r']]), state::SESSION, &[status::STARTED]);
    assert_eq!(s.mode, Mode::Session);
    let e = unpack_event(&s.read_event(WAIT_FOREVER)).unwrap();
    assert_eq!(e.kind, Kind::Timeout, "the reader is told nothing: it is gone");
    assert_eq!(s.gate.ended, 1, "the session ended first");
    assert_eq!(s.gate.logins, vec![asked(b"bob", b"pw")]);
    assert_eq!(s.mode, Mode::Session);
    assert_eq!(s.d.held(), 0);
    assert_eq!(s.d.line(), b"", "the new terminal is a fresh one");
}

/// A shell that survives the forced stop keeps the session: the secure prompt
/// is not drawn (the shell could draw over it or read it), nothing typed after
/// the key reaches the login service, and the next key asks the service to end
/// the session again.
///
/// **Canary.** Ignore the result of `Gate::end` in `take_over`: the first
/// read draws the prompt and the stuck session's user is logged out of the
/// screen while the shell runs on.
#[test]
fn a_shell_that_does_not_stop_keeps_the_session_and_gets_no_prompt() {
    let mut s = gated(typed(&[&[SAK, b'b', b'o', b'b', b'\r', b'p', b'w', b'\r'], &[SAK, b'b', b'o', b'b', b'\r', b'p', b'w', b'\r']]), state::SESSION, &[status::STARTED]);
    s.gate.stuck = 1;
    let e = unpack_event(&s.read_event(WAIT_FOREVER)).unwrap();
    assert_eq!(e.kind, Kind::Timeout);
    assert_eq!(s.gate.ended, 1);
    assert_eq!(s.mode, Mode::Session, "the session is still the last user's");
    assert!(!shown(&s).contains("login:"), "no prompt was drawn");
    assert!(shown(&s).contains("did not stop"), "the person is told");
    assert!(s.gate.logins.is_empty(), "nothing typed was taken for a login");
    // The next key tries again and, the shell gone, the prompt takes the input.
    let e = unpack_event(&s.read_event(WAIT_FOREVER)).unwrap();
    assert_eq!(e.kind, Kind::Timeout);
    assert_eq!(s.gate.ended, 2);
    assert_eq!(s.gate.logins, vec![asked(b"bob", b"pw")]);
}

/// The client hanging up with its shell stuck leaves the console unserved: the
/// key asks again, the prompt appears only once the session is gone.
///
/// **Canary.** Set the mode to `Locked` without looking at the result: the
/// first key draws the prompt with the session recorded and `ended` is 1.
#[test]
fn a_hung_up_session_that_does_not_stop_waits_for_the_key_before_the_prompt() {
    let mut s = gated(typed(&[b"typing that is dropped", &[SAK]]), state::SESSION, &[]);
    s.gate.stuck = 1;
    assert!(s.session_ended());
    assert_eq!(s.gate.ended, 2, "asked again at the key");
    assert_eq!(s.mode, Mode::Locked);
    assert!(!shown(&s).contains("login:"), "the prompt is the caller's, after the end");
    // A console that cannot be read while the shell is stuck: the caller ends.
    let mut s = gated(typed(&[]), state::SESSION, &[]);
    s.gate.stuck = 5;
    assert!(!s.session_ended());
    assert_eq!(s.mode, Mode::Session);
}

/// Without a gate the byte is a byte like any other and nothing is swallowed.
///
/// **Canary.** Look for the key in `Open` mode: the byte never reaches the line.
#[test]
fn without_a_gate_the_serial_byte_is_ordinary_input() {
    let mut s = Service::new(typed(&[&[b'a', SAK, b'b']]));
    s.sak_serial = SAK;
    s.set_mode(true);
    let e = unpack_event(&s.read_event(WAIT_FOREVER)).unwrap();
    assert_eq!(e.kind, Kind::Bytes);
    assert_eq!(e.inline(), &[b'a', SAK, b'b'], "the byte reaches a raw client like any other");
}

// ── The keyboard chord ──────────────────────────────────────────────────────

#[repr(align(64))]
struct RingMem([u8; REGION_BYTES]);

struct Keys {
    ring: SpscRing,
    _mem: Box<RingMem>,
}

impl Keys {
    fn new() -> Keys {
        let mut mem = Box::new(RingMem([0; REGION_BYTES]));
        let ring = SpscRing { base: mem.0.as_mut_ptr() as usize, cap: RING_CAP };
        ring.init();
        Keys { ring, _mem: mem }
    }

    fn word(code: u16, value: u32) -> u64 {
        pack(EV_KEY, code, value)
    }

    fn send(&self, code: u16, value: u32) {
        assert!(!matches!(self.ring.try_push(Self::word(code, value)), RingStep::Blocked));
    }

    fn chord(&self) {
        for (c, v) in [(KEY_LEFTCTRL, 1), (KEY_LEFTALT, 1), (KEY_DELETE, 1), (KEY_DELETE, 0), (KEY_LEFTALT, 0), (KEY_LEFTCTRL, 0)] {
            self.send(c, v);
        }
    }
}

/// Ctrl+Alt+Del in the input ring ends the session and takes the input; the
/// client never sees an escape sequence for it.
///
/// **Canary.** Encode the chord as the Delete sequence and let it through: the
/// line discipline holds `ESC [ 3 ; 7 ~` and the gate is not asked to end.
#[test]
fn the_keyboard_chord_ends_the_session_and_takes_the_input() {
    let k = Keys::new();
    let mut s = gated(typed(&[b"carol\rpw\r"]), state::SESSION, &[status::STARTED]);
    s.inp = Some(Input::new(k.ring, None));
    k.chord();
    let e = unpack_event(&s.read_event(WAIT_FOREVER)).unwrap();
    assert_eq!(e.kind, Kind::Timeout);
    assert_eq!(s.gate.ended, 1);
    assert_eq!(s.gate.logins, vec![asked(b"carol", b"pw")]);
    assert_eq!(s.d.held(), 0);
}

/// Only the whole chord is the key: Delete alone, with Ctrl alone or with Alt
/// alone is an ordinary key, and a repeating chord is one press.
///
/// **Canary.** Drop the Alt test: Ctrl+Del takes the console.
#[test]
fn only_the_whole_chord_is_the_key() {
    let k = Keys::new();
    let mut s = gated(typed(&[b"x\r"]), state::SESSION, &[]);
    s.set_mode(true);
    s.inp = Some(Input::new(k.ring, None));
    k.send(KEY_DELETE, 1);
    k.send(KEY_DELETE, 0);
    k.send(KEY_LEFTCTRL, 1);
    k.send(KEY_DELETE, 1);
    k.send(KEY_DELETE, 0);
    k.send(KEY_LEFTCTRL, 0);
    k.send(KEY_LEFTALT, 1);
    k.send(KEY_DELETE, 1);
    k.send(KEY_DELETE, 0);
    k.send(KEY_LEFTALT, 0);
    let e = unpack_event(&s.read_event(0)).unwrap();
    assert_eq!(e.kind, Kind::Bytes, "the Delete sequences reach a raw client");
    assert_eq!(s.gate.ended, 0);
    assert_eq!(s.mode, Mode::Session);
}

/// While the prompt owns the input, keys with no byte are nothing to it and
/// the chord starts it over.
#[test]
fn the_chord_restarts_the_prompt_and_other_keys_are_ignored() {
    let k = Keys::new();
    let mut con = Con { ring: Some(k.ring), ..Con::default() };
    // "al", an arrow key, the chord (one event per wait), then the whole login.
    con.script.push_back(Beat::Typed(b"al".to_vec()));
    con.script.push_back(Beat::Key(Keys::word(KEY_UP, 1)));
    for (c, v) in [(KEY_LEFTCTRL, 1), (KEY_LEFTALT, 1), (KEY_DELETE, 1)] {
        con.script.push_back(Beat::Key(Keys::word(c, v)));
    }
    con.script.push_back(Beat::Typed(b"bob\rpw\r".to_vec()));
    let mut s = gated(con, state::LOCKED, &[status::STARTED]);
    s.inp = Some(Input::new(k.ring, None));
    s.secure_prompt();
    assert_eq!(s.gate.logins, vec![asked(b"bob", b"pw")], "the \"al\" typed before the chord is forgotten, the arrow key typed nothing");
    assert_eq!(shown(&s).matches("login: ").count(), 2, "the prompt was drawn again");
}
