// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The secure-attention prompt: a user name and a passphrase, typed to the
//! terminal server and to no one else.
//!
//! The terminal server owns console input, so what is typed after the
//! secure-attention key goes here and nowhere else: not the line discipline,
//! not the shell, not a program the user was running (the session is ended
//! before the prompt is drawn). The user name is echoed; the passphrase is
//! not. The passphrase is wiped as soon as it has been made a credential.
//!
//! Pure: [`Prompt::feed`] takes one byte and says what to echo and what comes
//! next. `tests/host/term-tests` pulls this file in with `#[path]`.

use azos_login::{NAME_MAX, PASSPHRASE_MAX};

/// Bytes of echo one input byte can make.
pub const ECHO_MAX: usize = 64;

/// What [`Prompt::feed`] wants shown.
pub struct Echo {
    buf: [u8; ECHO_MAX],
    len: usize,
}

impl Echo {
    pub const fn new() -> Self {
        Echo { buf: [0; ECHO_MAX], len: 0 }
    }

    fn put(&mut self, b: &[u8]) {
        let n = b.len().min(ECHO_MAX - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
    }

    /// The bytes to show, and forget them.
    pub fn take(&mut self) -> &[u8] {
        let n = core::mem::take(&mut self.len);
        &self.buf[..n]
    }
}

/// What the prompt is asking for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    User,
    Passphrase,
}

/// What one byte did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing to act on yet.
    More,
    /// The user name is complete: ask for the passphrase.
    Passphrase,
    /// The passphrase is complete: [`Prompt::user`] and [`Prompt::passphrase`].
    Submit,
    /// The person gave up (^C, or ^D on an empty field).
    Cancel,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Esc {
    None,
    /// After ESC.
    Seen,
    /// In a CSI sequence, until its final byte.
    Csi,
    /// After `ESC O`: one more byte.
    Ss3,
}

/// The prompt.
pub struct Prompt {
    stage: Stage,
    user: [u8; NAME_MAX],
    ulen: usize,
    pass: [u8; PASSPHRASE_MAX],
    plen: usize,
    esc: Esc,
    /// The last byte was a CR: a LF right after it is the same Enter.
    after_cr: bool,
}

/// May `b` be in a user name: the alphabet of a `[login.NAME]` row.
pub const fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Overwrite `b` so that the compiler cannot take the stores for dead.
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, aligned byte of the slice.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// [`wipe`] for words (the credential on its way to the login service).
pub fn wipe_words(w: &mut [u64]) {
    for x in w.iter_mut() {
        // SAFETY: `x` is a valid, aligned word of the slice.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl Prompt {
    pub const fn new() -> Self {
        Prompt {
            stage: Stage::User,
            user: [0; NAME_MAX],
            ulen: 0,
            pass: [0; PASSPHRASE_MAX],
            plen: 0,
            esc: Esc::None,
            after_cr: false,
        }
    }

    /// What the prompt is asking for, for the host tests.
    #[cfg(test)]
    pub fn stage(&self) -> Stage {
        self.stage
    }

    pub fn user(&self) -> &[u8] {
        &self.user[..self.ulen]
    }

    pub fn passphrase(&self) -> &[u8] {
        &self.pass[..self.plen]
    }

    /// Forget everything typed and start again at the user name.
    pub fn reset(&mut self) {
        wipe(&mut self.user);
        wipe(&mut self.pass);
        *self = Prompt::new();
    }

    /// Take one byte typed at the prompt.
    pub fn feed(&mut self, b: u8, echo: &mut Echo) -> Step {
        // Escape sequences (arrow keys, function keys) are not text.
        match self.esc {
            Esc::Seen => {
                self.esc = match b {
                    b'[' => Esc::Csi,
                    b'O' => Esc::Ss3,
                    _ => Esc::None,
                };
                return Step::More;
            }
            Esc::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    self.esc = Esc::None;
                }
                return Step::More;
            }
            Esc::Ss3 => {
                self.esc = Esc::None;
                return Step::More;
            }
            Esc::None => {}
        }
        let cr_before = core::mem::replace(&mut self.after_cr, b == b'\r');
        match b {
            0x1b => {
                self.esc = Esc::Seen;
                Step::More
            }
            0x03 => Step::Cancel,
            0x04 => {
                if self.field_len() == 0 {
                    Step::Cancel
                } else {
                    Step::More
                }
            }
            b'\n' if cr_before => Step::More,
            b'\r' | b'\n' => match self.stage {
                Stage::User if self.ulen == 0 => Step::More,
                Stage::User => {
                    self.stage = Stage::Passphrase;
                    echo.put(b"\r\n");
                    Step::Passphrase
                }
                Stage::Passphrase => {
                    echo.put(b"\r\n");
                    Step::Submit
                }
            },
            0x7f | 0x08 => {
                match self.stage {
                    Stage::User if self.ulen > 0 => {
                        self.ulen -= 1;
                        self.user[self.ulen] = 0;
                        echo.put(b"\x08 \x08");
                    }
                    Stage::Passphrase if self.plen > 0 => {
                        self.plen -= 1;
                        self.pass[self.plen] = 0;
                    }
                    _ => {}
                }
                Step::More
            }
            0x15 => {
                match self.stage {
                    Stage::User => {
                        while self.ulen > 0 {
                            self.ulen -= 1;
                            self.user[self.ulen] = 0;
                            if echo.len + 3 <= ECHO_MAX {
                                echo.put(b"\x08 \x08");
                            }
                        }
                    }
                    Stage::Passphrase => {
                        wipe(&mut self.pass);
                        self.plen = 0;
                    }
                }
                Step::More
            }
            _ => {
                match self.stage {
                    Stage::User if name_byte(b) && self.ulen < NAME_MAX => {
                        self.user[self.ulen] = b;
                        self.ulen += 1;
                        echo.put(&[b]);
                    }
                    Stage::Passphrase if b >= 0x20 && b != 0x7f && self.plen < PASSPHRASE_MAX => {
                        self.pass[self.plen] = b;
                        self.plen += 1;
                    }
                    _ => {}
                }
                Step::More
            }
        }
    }

    fn field_len(&self) -> usize {
        match self.stage {
            Stage::User => self.ulen,
            Stage::Passphrase => self.plen,
        }
    }
}
