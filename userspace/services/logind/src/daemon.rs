// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The login service's logic, apart from the system calls it makes.
//!
//! [`Daemon`] is the `Login` object's server. Everything it needs of the
//! system is the [`Kernel`] trait, so the host suite (`tests/host/logind-tests`)
//! pulls this file in with `#[path]` and drives it through the generated
//! client stub over a loopback, with a stand-in kernel that can say yes, no,
//! "locked" and "cannot start".
//!
//! One session at a time. The service keeps its TID and nothing else about it:
//! no name, no credential, no root (the kernel's Domain has those).

use azos_login::{ended, state, status, unpack_name, Login, NAME_MAX, NAME_WORDS, CREDENTIAL_WORDS};

/// The `keys` interface's outcomes the service tells apart.
pub mod outcome {
    /// The kernel cannot verify: it holds no root.
    pub const NOT_READY: u32 = 3;
}

/// What the service asks of the system.
pub trait Kernel {
    /// Is anybody enrolled (a `[login.NAME]` row in the signed topology)? A
    /// system that cannot say answers `true`: a login that is wrongly asked
    /// for is a console that waits, a login that is wrongly waived is a console
    /// open to anyone.
    fn enrolled(&mut self) -> bool;
    /// The kernel's `login` op of `keys`: `Ok(owner_root)` when the credential
    /// verifies (and the one-shot grant is armed), else the interface's
    /// outcome code.
    fn verify(&mut self, user: [u64; NAME_WORDS], credential: [u64; CREDENTIAL_WORDS]) -> Result<u32, u32>;
    /// Start the shell for the user `name` as a session (`SPAWN_F_USER`,
    /// spending the grant): the shell's TID, else a negative errno.
    fn start_session(&mut self, name: &[u8]) -> Result<u32, isize>;
    /// Stop the shell `tid` and everything beneath it, and reap it. `true`
    /// when it is gone; `false` when it survived the forced stop.
    fn stop_session(&mut self, tid: u32) -> bool;
    /// Has the shell `tid` exited? Reaps it when it has.
    fn session_gone(&mut self, tid: u32) -> bool;
    /// One line for the console.
    fn say(&mut self, line: &str);
}

/// The Login object.
pub struct Daemon<K: Kernel> {
    pub k: K,
    enrolled: bool,
    session: Option<u32>,
}

impl<K: Kernel> Daemon<K> {
    /// Ask the system whether anybody is enrolled and settle the mode. With
    /// nobody enrolled the console session is the system's: the kernel is
    /// asked once, with no name, so that it is a `login` decision record
    /// (`Admit`, root 0), and the service has nothing to do after that.
    pub fn new(mut k: K) -> Self {
        let enrolled = k.enrolled();
        if enrolled {
            k.say("[logind] users are enrolled: the console waits for a secure-attention login\n");
        } else {
            k.say("[logind] nobody is enrolled: the console session is the system's\n");
            let _ = k.verify([0; NAME_WORDS], [0; CREDENTIAL_WORDS]);
        }
        Self { k, enrolled, session: None }
    }

    /// Forget a session whose shell has exited on its own.
    fn reap(&mut self) {
        if let Some(tid) = self.session {
            if self.k.session_gone(tid) {
                self.session = None;
            }
        }
    }
}

impl<K: Kernel> Login for Daemon<K> {
    fn state(&self) -> u32 {
        match (self.enrolled, self.session) {
            (false, _) => state::OPEN,
            (true, None) => state::LOCKED,
            (true, Some(_)) => state::SESSION,
        }
    }

    fn login(&mut self, user: [u64; NAME_WORDS], credential: [u64; CREDENTIAL_WORDS]) -> u32 {
        self.reap();
        if !self.enrolled || self.session.is_some() {
            return status::NOT_NOW;
        }
        let verdict = self.k.verify(user, credential);
        let mut name = [0u8; NAME_MAX];
        let len = unpack_name(&user, &mut name);
        match verdict {
            Ok(_) => match self.k.start_session(&name[..len]) {
                Ok(tid) => {
                    self.session = Some(tid);
                    status::STARTED
                }
                Err(_) => {
                    self.k.say("[logind] the credential was admitted but the shell did not start\n");
                    status::NO_SESSION
                }
            },
            Err(outcome::NOT_READY) => status::NOT_READY,
            Err(_) => status::REFUSED,
        }
    }

    fn end(&mut self) -> u32 {
        self.reap();
        let Some(tid) = self.session else { return ended::OK };
        // The session stays recorded until the shell is known to be gone: a
        // shell that survived is still the previous user's, and no other user
        // may be logged in (or the secure prompt drawn) beside it.
        if self.k.stop_session(tid) {
            self.session = None;
            ended::OK
        } else {
            ended::RUNNING
        }
    }
}
