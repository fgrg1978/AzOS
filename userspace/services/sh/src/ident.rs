// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Whose shell this is: the prompt.
//!
//! A shell the console login started is a user's session: its Domain is owned
//! by the user and the login service gave it the user's name in `USER`. The
//! system's shell (nobody enrolled) has no `USER`.
//!
//! Pure: `tests/host/sh-tests` pulls this file in with `#[path]`.

/// The user name as it may be shown: `[A-Za-z0-9_-]`, at most 16 bytes. The
/// environment is the spawner's, so a byte outside that is not echoed to the
/// terminal.
fn clean(user: &[u8]) -> &[u8] {
    let n = user.iter().take(16).take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-').count();
    &user[..n]
}

/// The prompt: `<user>@` before `base` for a user's session, `base` alone for
/// the system's. Written to `out`, the bytes used.
pub fn prompt(user: Option<&[u8]>, base: &[u8], out: &mut [u8; 32]) -> usize {
    let mut n = 0;
    let mut put = |s: &[u8]| {
        out[n..n + s.len()].copy_from_slice(s);
        n += s.len();
    };
    if let Some(u) = user.map(clean).filter(|u| !u.is_empty()) {
        put(u);
        put(b"@");
    }
    put(base);
    n
}
