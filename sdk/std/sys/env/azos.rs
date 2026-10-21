// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The environment: a copy of the startup block's, edited in place. There is
//! no environment in the kernel to share with, so `set_var` is this
//! process's own.

pub use super::common::Env;
use crate::ffi::{OsStr, OsString};
use crate::io;
use crate::sync::Mutex;

static ENV: Mutex<Option<Vec<(OsString, OsString)>>> = Mutex::new(None);

fn os(b: &[u8]) -> OsString {
    // SAFETY: the encoding of an OsString here is bytes.
    unsafe { OsString::from_encoded_bytes_unchecked(b.to_vec()) }
}

fn with<R>(f: impl FnOnce(&mut Vec<(OsString, OsString)>) -> R) -> R {
    let mut g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let v = g.get_or_insert_with(|| {
        let mut v = Vec::new();
        let mut i = 0;
        while let Some(s) = azos_stdrt::start::env_at(i) {
            // KEY=VALUE; the first '=' splits (a key may be empty only in a
            // malformed block, which is skipped).
            if let Some(eq) = s.iter().skip(1).position(|&c| c == b'=') {
                v.push((os(&s[..eq + 1]), os(&s[eq + 2..])));
            }
            i += 1;
        }
        v
    });
    f(v)
}

pub fn env() -> Env {
    Env::new(with(|v| v.clone()))
}

pub fn getenv(key: &OsStr) -> Option<OsString> {
    with(|v| v.iter().find(|(k, _)| k == key).map(|(_, val)| val.clone()))
}

pub unsafe fn setenv(key: &OsStr, val: &OsStr) -> io::Result<()> {
    with(|v| match v.iter_mut().find(|(k, _)| k == key) {
        Some(e) => e.1 = val.to_os_string(),
        None => v.push((key.to_os_string(), val.to_os_string())),
    });
    Ok(())
}

pub unsafe fn unsetenv(key: &OsStr) -> io::Result<()> {
    with(|v| v.retain(|(k, _)| k != key));
    Ok(())
}
