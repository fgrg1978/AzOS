// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The listing cursor (`crates/fs/src/dir_cursor.rs`): the `index`-th entry of
//! a directory is reached from where the last call stopped.
//!
//! **Canary.** `dir-cursor-canary`: a listing never resumes.

use super::dir_cursor_impl::DirCursor;

#[test]
fn a_listing_resumes_where_the_last_call_stopped() {
    let a = DirCursor::key(b"/", b"/data/big");
    let b = DirCursor::key(b"/", b"/data/other");
    assert_ne!(a, b);
    assert_ne!(DirCursor::key(b"/x", b"y"), DirCursor::key(b"/", b"x/y"), "the root is part of the key");
    let mut c = DirCursor::new();
    assert_eq!(c.resume(a, 0), (0, 0));
    // Entry 4 was read: the cookie 90 follows it.
    c.note(a, 5, 90);
    assert_eq!(c.resume(a, 5), (5, 90), "the next entry continues");
    assert_eq!(c.resume(a, 9), (5, 90), "a later one walks on from there");
    assert_eq!(c.resume(a, 4), (0, 0), "an earlier one starts over");
    assert_eq!(c.resume(b, 9), (0, 0), "another directory starts over");
    c.clear();
    assert_eq!(c.resume(a, 9), (0, 0));
}
