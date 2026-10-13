// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The refusals of `expand`, one exact message each, each with an accepting
//! twin that differs only in the offending item (so a refusal is the rule's,
//! not an accident of the fixture).

use super::expand;
use proc_macro2::TokenStream;
use std::str::FromStr;

const ATTR: &str = "id = 7, level = 1";

fn ts(s: &str) -> TokenStream {
    TokenStream::from_str(s).unwrap()
}

/// The expansion's error text, or panic if it expanded.
fn refused(attr: &str, item: &str) -> String {
    match expand(ts(attr), ts(item)) {
        Ok(_) => panic!("expected a refusal, but it expanded: {item}"),
        Err(e) => e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join(" | "),
    }
}

fn accepted(attr: &str, item: &str) -> String {
    match expand(ts(attr), ts(item)) {
        Ok(t) => t.to_string(),
        Err(e) => panic!("expected it to expand, got: {e}"),
    }
}

fn rejects(item: &str, needle: &str) {
    let e = refused(ATTR, item);
    assert!(e.contains(needle), "wanted `{needle}` in `{e}`");
}

fn accepts(item: &str) -> String {
    accepted(ATTR, item)
}

// ── anti-Unix lint ──────────────────────────────────────────────────────

#[test]
fn raw_integer_fd_parameter_is_refused() {
    rejects("trait T { fn read(&mut self, fd: i32) -> u32; }", "raw integer fd");
    rejects("trait T { fn read(&mut self, src_fd: u64) -> u32; }", "raw integer fd");
    rejects("trait T { fn read(&mut self, fd_in: u8) -> u32; }", "raw integer fd");
    rejects("trait T { fn read(&mut self, fds: [i32; 2]) -> u32; }", "raw integer fd");
    // twin: a typed handle named fd, and an integer that is not an fd
    accepts("trait T { fn read(&mut self, fd: Cap<File>) -> u32; }");
    accepts("trait T { fn read(&mut self, offset: i32) -> u32; }");
    accepts("trait T { fn read(&mut self, fdx: i32) -> u32; }");
}

#[test]
fn fd_types_and_fd_returning_methods_are_refused() {
    rejects("trait T { fn read(&mut self, h: RawFd) -> u32; }", "raw fd");
    rejects("trait T { fn open_fd(&mut self) -> i32; }", "returns a raw integer fd");
    accepts("trait T { fn open_file(&mut self) -> Cap<File>; }");
}

#[test]
fn errno_is_refused() {
    rejects("trait T { fn errno(&mut self) -> i32; }", "errno accessor");
    rejects("trait T { fn last_errno(&mut self) -> i32; }", "errno accessor");
    rejects("trait T { fn f(&mut self, errno: i32); }", "is an errno");
    rejects("trait T { fn f(&mut self) -> Errno; }", "`Errno`");
    rejects("trait T { fn f(&mut self) -> Result<u32, i32>; }", "`Result`");
    accepts("trait T { fn status(&mut self) -> i32; }");
}

#[test]
fn text_and_path_as_authority_is_refused() {
    rejects("trait T { fn open(&mut self, name: &str) -> u32; }", "`&str`");
    rejects("trait T { fn open(&mut self, name: String) -> u32; }", "`String`");
    rejects("trait T { fn open(&mut self, p: PathBuf) -> u32; }", "`PathBuf`");
    rejects("trait T { fn open(&mut self, p: &Path) -> u32; }", "reference");
    rejects("trait T { fn open(&mut self, p: Box<str>) -> u32; }", "`str`");
    rejects("trait T { fn open(&mut self, p: Option<String>) -> u32; }", "`String`");
    rejects("trait T { fn open(&mut self, p: *const u8) -> u32; }", "raw pointer");
    rejects("trait T { fn open(&mut self, path: u64) -> u32; }", "path used as authority");
    rejects("trait T { fn open(&mut self, dir_path: [u8; 16]) -> u32; }", "path used as authority");
    rejects("trait T { fn name(&mut self) -> &str; }", "return type contains");
    // twin: a warrant; and a numeric path that is geometry, not a name
    accepts("trait T { fn open(&mut self, dir: Cap<Dir>) -> u32; }");
    accepts("trait T { fn follow(&mut self, path: [f32; 4]) -> u32; }");
}

#[test]
fn ioctl_is_refused() {
    rejects("trait T { fn ioctl(&mut self, cmd: u32) -> u32; }", "an ioctl");
    rejects("trait T { fn fcntl(&mut self, cmd: u32) -> u32; }", "an ioctl");
    accepts("trait T { fn control(&mut self, cmd: u32) -> u32; }");
}

#[test]
fn every_refusal_is_reported_not_only_the_first() {
    let e = refused(ATTR, "trait T { fn f(&mut self, fd: i32, name: &str) -> u32; }");
    assert!(e.contains("raw integer fd") && e.contains("`&str`"), "{e}");
}

// ── attributes ──────────────────────────────────────────────────────────

fn flags_of(src: &str) -> Vec<u8> {
    // The op-table rows carry `flags : N`.
    let mut v = Vec::new();
    let mut it = src.split("flags :");
    it.next();
    for part in it {
        let n: String = part.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
        v.push(n.parse().unwrap());
    }
    v
}

#[test]
fn flags_are_carried_in_the_op_table_in_method_order() {
    let src = accepts(
        "trait T { fn a(&mut self); #[idempotent] fn b(&mut self); #[at_most_once] fn c(&mut self); #[once_only] fn d(&mut self); }",
    );
    assert_eq!(flags_of(&src), vec![0, 1, 2, 4]);
}

#[test]
fn flag_attributes_are_stripped_from_the_emitted_trait() {
    let src = accepts("trait T { #[idempotent] fn a(&mut self); }");
    assert!(!src.contains("# [idempotent]"), "{src}");
}

#[test]
fn flags_are_mutually_exclusive() {
    rejects("trait T { #[idempotent] #[once_only] fn a(&mut self); }", "mutually exclusive");
    rejects("trait T { #[at_most_once] #[idempotent] fn a(&mut self); }", "mutually exclusive");
    rejects("trait T { #[idempotent(3)] fn a(&mut self); }", "takes no arguments");
}

// ── op numbers ──────────────────────────────────────────────────────────

#[test]
fn op_numbers_follow_method_order_from_one() {
    let src = accepts("trait T { fn first(&mut self); fn second(&mut self); fn third(&mut self); }");
    assert!(src.contains("OP_FIRST : u16 = 1u16"), "{src}");
    assert!(src.contains("OP_SECOND : u16 = 2u16"), "{src}");
    assert!(src.contains("OP_THIRD : u16 = 3u16"), "{src}");
}

#[test]
fn the_size_check_is_emitted_for_request_and_reply() {
    let src = accepts("trait T { fn f(&mut self, a: u64) -> u64; }");
    assert!(src.contains("assert ! (TIdl :: REQ_WORDS_F <= TIdl :: WORDS"), "{src}");
    assert!(src.contains("assert ! (TIdl :: REP_WORDS_F <= TIdl :: WORDS"), "{src}");
    assert!(src.contains("TIdl :: REQ_CAPS_F <= :: azos_idl :: CAPS_MAX"), "{src}");
}

// ── interface arguments and shape ───────────────────────────────────────

#[test]
fn attribute_arguments_are_checked() {
    let item = "trait T { fn f(&mut self); }";
    assert!(refused("level = 1", item).contains("missing `id"));
    assert!(refused("id = 1", item).contains("missing `level"));
    assert!(refused("id = 0, level = 1", item).contains("`id` 0 is reserved"));
    assert!(refused("id = 1, level = 0", item).contains("`level` 0 is reserved"));
    assert!(refused("id = 1, level = 1, bogus = 2", item).contains("unknown argument `bogus`"));
    assert!(refused("id = 1, id = 2, level = 1", item).contains("given twice"));
    assert!(refused("id = 1, level = 1, words = 9", item).contains("outside 1..=8"));
    assert!(refused("id = 1, level = 1, words = 0", item).contains("outside 1..=8"));
    assert!(refused("id = x, level = 1", item).contains("integer literal"));
    accepted("id = 1, level = 1, words = 8", item);
    accepted("id = 0x4543_4801, level = 3", item);
}

#[test]
fn the_trait_shape_is_checked() {
    rejects("trait T { fn f(self); }", "`&self` or `&mut self`");
    rejects("trait T { fn f(); }", "`&self` or `&mut self`");
    rejects("trait T { fn f(&mut self) { } }", "no body");
    rejects("trait T { fn f<X>(&mut self, x: X); }", "no generics");
    rejects("trait T { async fn f(&mut self); }", "plain `fn`");
    rejects("trait T { type X; fn f(&mut self); }", "methods only");
    rejects("trait T<X> { fn f(&mut self); }", "no generics");
    rejects("trait T: Send { fn f(&mut self); }", "no supertraits");
    rejects("trait T { }", "at least one method");
    rejects("trait T { fn f(&mut self, (a, b): (u32, u32)); }", "plain name");
    assert!(expand(ts(ATTR), ts("struct S;")).is_err());
}
