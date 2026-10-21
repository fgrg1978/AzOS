// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the console login: the Login object and the credential
//! (`userspace/lib/login`), the login service's logic
//! (`userspace/services/logind/src/daemon.rs`, pulled in with `#[path]` so the
//! code under test is the code `LOGIND.ELF` is built from) and the enrolment
//! derivation. The service is driven through the generated client stub over a
//! loopback, so the wire form the terminal server sends is the one under test.

#[allow(dead_code)]
#[path = "../../../../userspace/services/logind/src/daemon.rs"]
pub mod daemon;
pub mod enroll;

#[cfg(test)]
mod credential {
    use azos_login::*;

    /// RFC 7914 section 11 (PBKDF2-HMAC-SHA256), the vectors every
    /// implementation is held to: the stretching is the textbook one, not a
    /// look-alike.
    ///
    /// **Canary.** Start the loop at 2 rounds: the second vector is red.
    #[test]
    fn pbkdf2_matches_the_published_vectors() {
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(pbkdf2_sha256(b"password", b"salt", 1)), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        assert_eq!(hex(pbkdf2_sha256(b"password", b"salt", 2)), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
        assert_eq!(hex(pbkdf2_sha256(b"password", b"salt", 4096)), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    }

    /// The credential is the user's and the passphrase's: neither the same
    /// passphrase for another user nor a near miss gives it.
    ///
    /// **Canary.** Leave the user out of the salt: "another user" finds the
    /// same credential.
    #[test]
    fn the_credential_follows_user_and_passphrase() {
        let base = credential(b"alice", b"correct horse");
        assert_eq!(base, credential(b"alice", b"correct horse"));
        assert_ne!(base, credential(b"bob", b"correct horse"), "another user");
        assert_ne!(base, credential(b"alice", b"correct horsf"), "another passphrase");
        assert_ne!(base, credential(b"alice", b"correct horse "), "a trailing blank counts");
        assert_ne!(base, [0u8; 32]);
    }

    #[test]
    fn names_and_credentials_round_trip_through_the_words() {
        let w = pack_name(b"alice").unwrap();
        let mut b = [0u8; NAME_MAX];
        let n = unpack_name(&w, &mut b);
        assert_eq!(&b[..n], b"alice");
        assert_eq!(pack_name(b"sixteen-bytes-ok").map(|w| { let mut b = [0u8; NAME_MAX]; let n = unpack_name(&w, &mut b); b[..n].to_vec() }),
                   Some(b"sixteen-bytes-ok".to_vec()));
        assert!(pack_name(b"seventeen-bytes-x").is_none(), "wider than the kernel's name field");
        assert!(pack_name(b"a\0b").is_none(), "a NUL ends a name");
        let c = credential(b"alice", b"pw");
        assert_eq!(unpack_credential(&pack_credential(&c)), c);
    }
}

#[cfg(test)]
mod enrolment {
    use crate::enroll::*;

    const SEED: [u8; 32] = [0x42; 32];

    fn name(s: &[u8]) -> [u8; 16] {
        let mut n = [0u8; 16];
        n[..s.len()].copy_from_slice(s);
        n
    }

    /// One known answer, pinned: the enrolment tool is the kernel's own
    /// functions (there is no second implementation of the derivation to keep
    /// in step), so this fails when the derivation changes and the volumes
    /// already enrolled would stop admitting their users.
    ///
    /// **Canary.** Change a label of `login_public`: this is red.
    #[test]
    fn the_derivation_keeps_its_known_answer() {
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let v = verifier(&SEED, 1, &name(b"alice"), b"alice", b"correct horse").unwrap();
        assert_eq!(hex(v), "66fe1e6f1e9dc367e25fe8d19bd4b3e8622b13ff61491d99dc183faa8cd7a9d2");
    }

    /// What the tool prints is what the kernel's `login` op computes from the
    /// credential the terminal server makes: the root is the keys module's
    /// restated, the credential is the login library's.
    ///
    /// **Canary.** Use a different label for the root: the pinned root below
    /// is red.
    #[test]
    fn the_verifier_is_the_kernels_derivation_of_the_terminal_servers_credential() {
        let root = boot_root(&SEED).unwrap();
        let mut want = [0u8; 32];
        assert!(azos_crypto::hkdf::hkdf(b"azos keystore root v1", &SEED, b"boot", &mut want));
        assert_eq!(root, want);
        let cred = azos_login::credential(b"alice", b"pw");
        let v = verifier(&SEED, 1, &name(b"alice"), b"alice", b"pw").unwrap();
        assert_eq!(Some(v), azos_crypto::keystore::login_public(&root, 1, &name(b"alice"), &cred));
        assert_ne!(Some(v), verifier(&SEED, 2, &name(b"alice"), b"alice", b"pw"), "another place in the table");
        assert_ne!(Some(v), verifier(&[0x43; 32], 1, &name(b"alice"), b"alice", b"pw"), "another board");
        assert_eq!(verifier(&[0; 32], 1, &name(b"alice"), b"alice", b"pw"), None, "a board without a seed derives nothing");
    }
}

#[cfg(test)]
mod service {
    use crate::daemon::{outcome, Daemon, Kernel};
    use azos_idl::{MsgDesc, Transport};
    use azos_login::*;
    use std::cell::RefCell;

    /// A kernel that says what the test scripts and writes down what it was asked.
    struct Stand {
        enrolled: bool,
        verdict: Result<u32, u32>,
        spawn: Result<u32, isize>,
        verified: Vec<([u64; NAME_WORDS], [u64; CREDENTIAL_WORDS])>,
        started: Vec<Vec<u8>>,
        stopped: Vec<u32>,
        gone: bool,
        /// The shell survives the forced stop.
        stuck: bool,
        said: Vec<String>,
    }

    impl Stand {
        fn new(enrolled: bool) -> Self {
            Stand {
                enrolled,
                verdict: Ok(1),
                spawn: Ok(77),
                verified: vec![],
                started: vec![],
                stopped: vec![],
                gone: false,
                stuck: false,
                said: vec![],
            }
        }
    }

    impl Kernel for Stand {
        fn enrolled(&mut self) -> bool {
            self.enrolled
        }
        fn verify(&mut self, user: [u64; NAME_WORDS], credential: [u64; CREDENTIAL_WORDS]) -> Result<u32, u32> {
            self.verified.push((user, credential));
            self.verdict
        }
        fn start_session(&mut self, name: &[u8]) -> Result<u32, isize> {
            self.started.push(name.to_vec());
            self.spawn
        }
        fn stop_session(&mut self, tid: u32) -> bool {
            self.stopped.push(tid);
            !self.stuck
        }
        fn session_gone(&mut self, _tid: u32) -> bool {
            self.gone
        }
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
    }

    struct Loop<'a>(&'a RefCell<Daemon<Stand>>);

    impl Transport for Loop<'_> {
        fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
            let req = *msg;
            let _ = LoginIdl::dispatch(&mut *self.0.borrow_mut(), &req, msg);
            Ok(())
        }
    }

    fn cred() -> [u64; CREDENTIAL_WORDS] {
        pack_credential(&credential(b"alice", b"pw"))
    }

    fn alice() -> [u64; NAME_WORDS] {
        pack_name(b"alice").unwrap()
    }

    /// Nobody enrolled: the state is open, the kernel was asked once with no
    /// name (so it is a record), a login is not a login, and nothing starts.
    ///
    /// **Canary.** Skip the `enrolled` check in `login`: the second assertion
    /// starts a session.
    #[test]
    fn with_nobody_enrolled_the_console_is_open_and_recorded() {
        let d = RefCell::new(Daemon::new(Stand::new(false)));
        assert_eq!(d.borrow().k.verified, vec![([0; NAME_WORDS], [0; CREDENTIAL_WORDS])], "one call with no name, the record");
        let mut c = LoginClient::new(Loop(&d));
        assert_eq!(c.state().unwrap(), state::OPEN);
        assert_eq!(c.login(alice(), cred()).unwrap(), status::NOT_NOW);
        assert!(d.borrow().k.started.is_empty());
        assert_eq!(d.borrow().k.verified.len(), 1, "a login against no gate is not even asked");
    }

    /// The credential goes to the kernel as it came, the admitted user's shell
    /// starts with the user's name, and the state follows.
    ///
    /// **Canary.** Start the shell before asking the kernel: the refused case
    /// below starts one.
    #[test]
    fn an_admitted_credential_starts_the_users_shell() {
        let d = RefCell::new(Daemon::new(Stand::new(true)));
        let mut c = LoginClient::new(Loop(&d));
        assert_eq!(c.state().unwrap(), state::LOCKED);
        assert_eq!(c.login(alice(), cred()).unwrap(), status::STARTED);
        assert_eq!(d.borrow().k.verified, vec![(alice(), cred())]);
        assert_eq!(d.borrow().k.started, vec![b"alice".to_vec()]);
        assert_eq!(c.state().unwrap(), state::SESSION);
        // One session at a time: the second login is not asked of the kernel.
        assert_eq!(c.login(alice(), cred()).unwrap(), status::NOT_NOW);
        assert_eq!(d.borrow().k.verified.len(), 1);
    }

    #[test]
    fn a_refused_credential_starts_nothing_and_says_the_same_for_every_reason() {
        for code in [0u32, 1, 2, 5, 7] {
            let mut s = Stand::new(true);
            s.verdict = Err(code);
            let d = RefCell::new(Daemon::new(s));
            let mut c = LoginClient::new(Loop(&d));
            assert_eq!(c.login(alice(), cred()).unwrap(), status::REFUSED, "outcome {code}");
            assert!(d.borrow().k.started.is_empty());
            assert_eq!(c.state().unwrap(), state::LOCKED);
        }
        let mut s = Stand::new(true);
        s.verdict = Err(outcome::NOT_READY);
        let d = RefCell::new(Daemon::new(s));
        assert_eq!(LoginClient::new(Loop(&d)).login(alice(), cred()).unwrap(), status::NOT_READY);
    }

    /// A shell that did not start leaves no session; the credential is spent.
    #[test]
    fn a_shell_that_does_not_start_is_no_session() {
        let mut s = Stand::new(true);
        s.spawn = Err(-13);
        let d = RefCell::new(Daemon::new(s));
        let mut c = LoginClient::new(Loop(&d));
        assert_eq!(c.login(alice(), cred()).unwrap(), status::NO_SESSION);
        assert_eq!(c.state().unwrap(), state::LOCKED);
        assert!(d.borrow().k.said.iter().any(|l| l.contains("did not start")));
    }

    /// `end` stops the shell once and is idempotent; a shell that exited on
    /// its own is forgotten at the next login, which then goes ahead.
    ///
    /// **Canary.** Keep the TID after `end`: the second `end` stops it again.
    #[test]
    fn end_stops_the_session_once_and_a_dead_shell_is_forgotten() {
        let d = RefCell::new(Daemon::new(Stand::new(true)));
        let mut c = LoginClient::new(Loop(&d));
        assert_eq!(c.login(alice(), cred()).unwrap(), status::STARTED);
        assert_eq!(c.end().unwrap(), ended::OK);
        assert_eq!(c.end().unwrap(), ended::OK);
        assert_eq!(d.borrow().k.stopped, vec![77], "once");
        assert_eq!(c.state().unwrap(), state::LOCKED);
        assert_eq!(c.login(alice(), cred()).unwrap(), status::STARTED);
        d.borrow_mut().k.gone = true;
        assert_eq!(c.login(alice(), cred()).unwrap(), status::STARTED, "the first shell exited by itself");
        assert_eq!(d.borrow().k.started.len(), 3);
    }

    /// A shell that survives the forced stop is still the session: `end` says
    /// so, the state stays `SESSION`, no other login is taken (the kernel is
    /// not even asked), and a later `end` tries again; once the shell is gone
    /// the next login goes ahead.
    ///
    /// **Canary.** Take the session before stopping it (`session.take()`):
    /// the state is `LOCKED` and the second user's login starts a shell beside
    /// the survivor.
    #[test]
    fn a_shell_that_does_not_stop_stays_the_session_and_blocks_every_login() {
        let mut s = Stand::new(true);
        s.stuck = true;
        let d = RefCell::new(Daemon::new(s));
        let mut c = LoginClient::new(Loop(&d));
        assert_eq!(c.login(alice(), cred()).unwrap(), status::STARTED);
        assert_eq!(c.end().unwrap(), ended::RUNNING);
        assert_eq!(c.state().unwrap(), state::SESSION, "still recorded");
        let bob = pack_name(b"bob").unwrap();
        assert_eq!(c.login(bob, cred()).unwrap(), status::NOT_NOW);
        assert_eq!(d.borrow().k.verified.len(), 1, "no credential was checked for the second user");
        assert_eq!(d.borrow().k.started.len(), 1, "no second shell");
        assert_eq!(c.end().unwrap(), ended::RUNNING);
        assert_eq!(d.borrow().k.stopped, vec![77, 77], "asked to stop again");
        d.borrow_mut().k.stuck = false;
        assert_eq!(c.end().unwrap(), ended::OK);
        assert_eq!(c.state().unwrap(), state::LOCKED);
        assert_eq!(c.login(bob, cred()).unwrap(), status::STARTED);
    }
}
