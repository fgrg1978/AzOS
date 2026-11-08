// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_coreutils::argp::{parse_i64, parse_u64, ArgError, Argp, Item, NUM};
use azos_coreutils::glob::glob_match;
use azos_coreutils::path::{base_name, dir_name, PathBuf};
use azos_coreutils::regex::{Regex, RegexError};

fn items<'a>(args: &'a [&'a [u8]], spec: &'static [u8]) -> Vec<Result<Item<'a>, ArgError>> {
    let mut p = Argp::new(args, spec);
    let mut v = Vec::new();
    while let Some(i) = p.next() {
        v.push(i);
    }
    v
}

#[test]
fn argp_bundles_flags() {
    let a: [&[u8]; 2] = [b"-rf", b"x"];
    assert_eq!(items(&a, b"rf"), vec![Ok(Item::Flag(b'r')), Ok(Item::Flag(b'f')), Ok(Item::Operand(b"x"))]);
}

#[test]
fn argp_values_attached_and_separate() {
    let a: [&[u8]; 3] = [b"-n5", b"-d", b","];
    assert_eq!(items(&a, b"n:d:"), vec![Ok(Item::Val(b'n', b"5")), Ok(Item::Val(b'd', b","))]);
}

#[test]
fn argp_flag_then_value_in_one_bundle() {
    let a: [&[u8]; 2] = [b"-in", b"7"];
    assert_eq!(items(&a, b"in:"), vec![Ok(Item::Flag(b'i')), Ok(Item::Val(b'n', b"7"))]);
}

#[test]
fn argp_double_dash_ends_flags() {
    let a: [&[u8]; 3] = [b"-r", b"--", b"-x"];
    assert_eq!(items(&a, b"r"), vec![Ok(Item::Flag(b'r')), Ok(Item::Operand(b"-x"))]);
}

#[test]
fn argp_operands_in_any_position_and_dash_is_an_operand() {
    let a: [&[u8]; 3] = [b"a", b"-r", b"-"];
    assert_eq!(items(&a, b"r"), vec![Ok(Item::Operand(b"a")), Ok(Item::Flag(b'r')), Ok(Item::Operand(b"-"))]);
}

#[test]
fn argp_unknown_and_missing_value() {
    let a: [&[u8]; 1] = [b"-z"];
    assert_eq!(items(&a, b"r"), vec![Err(ArgError::Unknown(b'z'))]);
    let b: [&[u8]; 1] = [b"-n"];
    assert_eq!(items(&b, b"n:"), vec![Err(ArgError::MissingValue(b'n'))]);
}

#[test]
fn argp_count_form_and_negative_numbers() {
    let a: [&[u8]; 1] = [b"-5"];
    assert_eq!(items(&a, &[b'n', b':', NUM]), vec![Ok(Item::Val(NUM, b"5"))]);
    assert_eq!(items(&a, b"n:"), vec![Ok(Item::Operand(b"-5"))]);
}

#[test]
fn numbers_parse_strictly() {
    assert_eq!(parse_u64(b"42"), Some(42));
    assert_eq!(parse_u64(b""), None);
    assert_eq!(parse_u64(b"4x"), None);
    assert_eq!(parse_u64(b"99999999999999999999"), None);
    assert_eq!(parse_i64(b"-7"), Some(-7));
    assert_eq!(parse_i64(b"+7"), Some(7));
    assert_eq!(parse_i64(b"-"), None);
}

fn resolved(cwd: &str, p: &str) -> String {
    String::from_utf8(PathBuf::resolve(cwd.as_bytes(), p.as_bytes()).unwrap().as_bytes().to_vec()).unwrap()
}

#[test]
fn path_resolves_against_the_working_directory() {
    assert_eq!(resolved("/fat", "a/b"), "/fat/a/b");
    assert_eq!(resolved("/fat", "/tmp//x/./y/"), "/tmp/x/y");
    assert_eq!(resolved("/", "."), "/");
    assert_eq!(resolved("/fat", ""), "/fat");
}

#[test]
fn path_dotdot_pops_a_part() {
    assert_eq!(resolved("/fat/d", "../x"), "/fat/x");
    assert_eq!(resolved("/fat", "a/../../.."), "/");
}

#[test]
fn path_too_long_is_refused() {
    let long = "a/".repeat(80);
    assert!(PathBuf::resolve(b"/", long.as_bytes()).is_err());
}

#[test]
fn path_is_within() {
    let a = PathBuf::resolve(b"/", b"/fat/a").unwrap();
    let b = PathBuf::resolve(b"/", b"/fat/a/b").unwrap();
    let c = PathBuf::resolve(b"/", b"/fat/ab").unwrap();
    assert!(b.is_within(&a) && a.is_within(&a) && !c.is_within(&a) && !a.is_within(&b));
    assert!(a.is_within(&PathBuf::root()));
}

#[test]
fn base_and_dir_names() {
    assert_eq!(base_name(b"/a/b.txt"), b"b.txt");
    assert_eq!(base_name(b"a/b/"), b"b");
    assert_eq!(base_name(b"/"), b"/");
    assert_eq!(dir_name(b"/a/b.txt"), b"/a");
    assert_eq!(dir_name(b"b.txt"), b".");
    assert_eq!(dir_name(b"/b"), b"/");
    assert_eq!(dir_name(b"a/b/"), b"a");
}

#[test]
fn glob_patterns() {
    assert!(glob_match(b"*.txt", b"a.txt", false));
    assert!(!glob_match(b"*.txt", b"a.txt.bak", false));
    assert!(glob_match(b"a?c", b"abc", false));
    assert!(glob_match(b"[a-c]x", b"bx", false));
    assert!(!glob_match(b"[!a-c]x", b"bx", false));
    assert!(glob_match(b"*a*b*", b"xxaxxbxx", false));
    assert!(glob_match(b"*", b"", false));
    assert!(!glob_match(b"a", b"A", false));
    assert!(glob_match(b"*.txt", b"A.TXT", true));
    assert!(glob_match(b"[a-z]*", b"Q1", true));
}

fn re(p: &str, fold: bool) -> Regex {
    Regex::compile(p.as_bytes(), fold).unwrap()
}

#[test]
fn regex_literals_dot_and_anchors() {
    assert!(re("abc", false).is_match(b"xxabcxx"));
    assert!(!re("abc", false).is_match(b"xxabxcxx"));
    assert!(re("a.c", false).is_match(b"abc"));
    assert!(re("^abc", false).is_match(b"abcd"));
    assert!(!re("^abc", false).is_match(b"xabc"));
    assert!(re("abc$", false).is_match(b"xabc"));
    assert!(!re("abc$", false).is_match(b"abcx"));
    assert!(re("^$", false).is_match(b""));
    assert!(!re("^$", false).is_match(b"x"));
    assert!(re("", false).is_match(b"anything"));
}

#[test]
fn regex_repeats() {
    assert!(re("ab*c", false).is_match(b"ac"));
    assert!(re("ab*c", false).is_match(b"abbbc"));
    assert!(!re("ab+c", false).is_match(b"ac"));
    assert!(re("ab+c", false).is_match(b"abc"));
    assert!(re("ab?c", false).is_match(b"ac") && re("ab?c", false).is_match(b"abc"));
    assert!(!re("ab?c", false).is_match(b"abbc"));
    assert!(re("^a.*z$", false).is_match(b"a-middle-z"));
    assert!(!re("^a.*z$", false).is_match(b"a-middle-y"));
    assert!(re("x*", false).is_match(b"yyy"));
}

#[test]
fn regex_classes_and_shorthands() {
    assert!(re("[0-9]+", false).is_match(b"ab12"));
    assert!(!re("^[0-9]+$", false).is_match(b"ab12"));
    assert!(re("^[^0-9]*$", false).is_match(b"abc"));
    assert!(!re("^[^0-9]*$", false).is_match(b"ab1"));
    assert!(re("[]x]", false).is_match(b"]"));
    assert!(re(r"\d\d", false).is_match(b"a42"));
    assert!(re(r"^\w+\s\w+$", false).is_match(b"foo bar"));
    assert!(re(r"a\.b", false).is_match(b"a.b") && !re(r"a\.b", false).is_match(b"axb"));
    assert!(re(r"a\*", false).is_match(b"a*"));
}

#[test]
fn regex_case_folding() {
    assert!(re("hello", true).is_match(b"HeLLo"));
    assert!(re("[a-c]x", true).is_match(b"BX"));
    assert!(!re("hello", false).is_match(b"HELLO"));
}

#[test]
fn regex_refuses_what_it_does_not_have() {
    for (p, e) in [
        ("(a)", RegexError::Unsupported(b'(')),
        ("a|b", RegexError::Unsupported(b'|')),
        ("a{2}", RegexError::Unsupported(b'{')),
        (r"(a)\1", RegexError::Unsupported(b'(')),
        ("*a", RegexError::NothingToRepeat),
        ("a**", RegexError::NothingToRepeat),
        ("[ab", RegexError::BadClass),
        ("a\\", RegexError::TrailingBackslash),
    ] {
        assert_eq!(Regex::compile(p.as_bytes(), false).err(), Some(e), "{p}");
    }
    assert!(Regex::compile("a".repeat(61).as_bytes(), false).is_err());
}
