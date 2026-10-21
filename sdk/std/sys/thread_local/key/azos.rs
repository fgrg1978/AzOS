// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Thread-local keys: azos_stdrt's registry (the image has no `PT_TLS`).

use azos_stdrt::thread as t;

pub type Key = usize;

#[inline]
pub fn create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> Key {
    match t::key_create(dtor) {
        Some(k) => k,
        None => rtabort!("out of TLS keys"),
    }
}

#[inline]
pub unsafe fn set(key: Key, value: *mut u8) {
    if !t::key_set(key, value) {
        rtabort!("out of memory for thread-local storage");
    }
}

#[inline]
pub unsafe fn get(key: Key) -> *mut u8 {
    t::key_get(key)
}

#[inline]
pub unsafe fn destroy(key: Key) {
    t::key_destroy(key)
}
