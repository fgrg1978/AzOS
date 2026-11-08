// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::{run, run_with, Mem};

fn with_stdin(s: &str) -> Mem {
    let mut m = Mem::new();
    m.set_stdin(s);
    m
}

fn numbered(n: usize) -> String {
    (1..=n).map(|i| format!("line{i}\n")).collect()
}

#[test]
fn head_stops_after_n_lines() {
    let mut m = with_stdin(&numbered(30));
    assert_eq!(run(&mut m, "head", &[]), 0);
    assert_eq!(m.out(), numbered(10));
    let mut m = with_stdin(&numbered(30));
    assert_eq!(run(&mut m, "head", &["-n", "3"]), 0);
    assert_eq!(m.out(), "line1\nline2\nline3\n");
}

#[test]
fn head_forms_files_and_short_input() {
    let mut m = with_stdin("");
    m.file("/a", &numbered(5)).file("/b", "x\ny");
    assert_eq!(run(&mut m, "head", &["-2", "/a"]), 0);
    assert_eq!(m.out(), "line1\nline2\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "head", &["-n1", "/a", "/b"]), 0);
    assert_eq!(m.out(), "==> /a <==\nline1\n\n==> /b <==\nx\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "head", &["-n", "0", "/a"]), 0);
    assert_eq!(m.out(), "");
    assert_eq!(run(&mut m, "head", &["-n", "x"]), 2);
    assert_eq!(run(&mut m, "head", &["/nope"]), 1);
}

#[test]
fn head_counts_lines_across_small_reads() {
    let mut m = with_stdin(&numbered(30));
    m.stdin_chunk = 3;
    assert_eq!(run(&mut m, "head", &["-n", "4"]), 0);
    assert_eq!(m.out(), "line1\nline2\nline3\nline4\n");
}

#[test]
fn tail_prints_the_last_n_lines() {
    let mut m = with_stdin(&numbered(30));
    assert_eq!(run(&mut m, "tail", &[]), 0);
    assert_eq!(m.out(), (21..=30).map(|i| format!("line{i}\n")).collect::<String>());
    let mut m = with_stdin(&numbered(5));
    assert_eq!(run(&mut m, "tail", &["-n", "2"]), 0);
    assert_eq!(m.out(), "line4\nline5\n");
}

#[test]
fn tail_edge_cases() {
    let mut m = with_stdin("a\nb\nc");
    assert_eq!(run(&mut m, "tail", &["-n", "2"]), 0);
    assert_eq!(m.out(), "b\nc");
    let mut m = with_stdin(&numbered(3));
    assert_eq!(run(&mut m, "tail", &["-n", "9"]), 0);
    assert_eq!(m.out(), numbered(3));
    let mut m = with_stdin(&numbered(3));
    assert_eq!(run(&mut m, "tail", &["-n", "0"]), 0);
    assert_eq!(m.out(), "");
}

#[test]
fn tail_keeps_the_end_of_an_input_larger_than_its_window() {
    let mut m = with_stdin(&numbered(2000));
    m.stdin_chunk = 100;
    assert_eq!(run_with(&mut m, "tail", &["-n", "3"], 256), 0);
    assert_eq!(m.out(), "line1998\nline1999\nline2000\n");
}

#[test]
fn tail_follow_is_refused_with_a_reason() {
    let mut m = with_stdin("x\n");
    assert_eq!(run(&mut m, "tail", &["-f", "x"]), 2);
    assert!(m.err().contains("no change notification"), "{}", m.err());
}

fn grep_in(text: &str, args: &[&str]) -> (i32, String) {
    let mut m = with_stdin(text);
    let st = run(&mut m, "grep", args);
    (st, m.out())
}

#[test]
fn grep_selects_matching_lines_and_sets_the_status() {
    assert_eq!(grep_in("apple\nbanana\ncherry\n", &["an"]), (0, "banana\n".to_string()));
    assert_eq!(grep_in("apple\n", &["zzz"]), (1, String::new()));
    assert_eq!(grep_in("a\n", &[]).0, 2);
}

#[test]
fn grep_v_selects_the_other_lines() {
    assert_eq!(grep_in("a\nb\na\nc\n", &["-v", "a"]), (0, "b\nc\n".to_string()));
}

#[test]
fn grep_flags() {
    let t = "Foo\nbar\nfoo bar\n";
    assert_eq!(grep_in(t, &["-i", "foo"]), (0, "Foo\nfoo bar\n".to_string()));
    assert_eq!(grep_in(t, &["-n", "bar"]), (0, "2:bar\n3:foo bar\n".to_string()));
    assert_eq!(grep_in(t, &["-c", "bar"]), (0, "2\n".to_string()));
    assert_eq!(grep_in(t, &["-q", "bar"]), (0, String::new()));
    assert_eq!(grep_in(t, &["-e", "^f"]), (0, "foo bar\n".to_string()));
    assert_eq!(grep_in(t, &["-F", "o b"]), (0, "foo bar\n".to_string()));
    assert_eq!(grep_in("a.c\nabc\n", &["-F", "a.c"]), (0, "a.c\n".to_string()));
    assert_eq!(grep_in("a.c\nabc\n", &["a.c"]), (0, "a.c\nabc\n".to_string()));
}

#[test]
fn grep_uses_the_regex_subset() {
    let t = "id=42\nid=x\nname\n";
    assert_eq!(grep_in(t, &["^id=[0-9]+$"]), (0, "id=42\n".to_string()));
    assert_eq!(grep_in(t, &[r"id=\d"]), (0, "id=42\n".to_string()));
    let mut m = with_stdin("x\n");
    assert_eq!(run(&mut m, "grep", &["a|b"]), 2);
    assert!(m.err().contains("use rg"), "{}", m.err());
}

#[test]
fn grep_files_names_and_recursion() {
    let mut m = Mem::new();
    m.cwd = b"/w".to_vec();
    m.file("/w/a.txt", "one\ntwo\n").file("/w/d/b.txt", "two\nthree\n").file("/w/d/s/c.txt", "four\n");
    assert_eq!(run(&mut m, "grep", &["two", "a.txt"]), 0);
    assert_eq!(m.out(), "two\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "grep", &["-n", "two", "a.txt", "d/b.txt"]), 0);
    assert_eq!(m.out(), "a.txt:2:two\nd/b.txt:1:two\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "grep", &["-r", "o", "d"]), 0);
    assert_eq!(m.out(), "d/b.txt:two\nd/s/c.txt:four\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "grep", &["-rl", "two"]), 0);
    assert_eq!(m.out(), "./a.txt\n./d/b.txt\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "grep", &["-rc", "o", "."]), 0);
    assert_eq!(m.out(), "./a.txt:2\n./d/b.txt:1\n./d/s/c.txt:1\n");
    m.stdout.clear();
    assert_eq!(run(&mut m, "grep", &["-h", "two", "a.txt", "d/b.txt"]), 0);
    assert_eq!(m.out(), "two\ntwo\n");
    assert_eq!(run(&mut m, "grep", &["x", "missing"]), 2);
}

#[test]
fn grep_reads_lines_across_small_reads_and_cuts_a_line_longer_than_its_buffer() {
    let mut m = with_stdin("needle in a haystack\nsecond\n");
    m.stdin_chunk = 2;
    assert_eq!(run(&mut m, "grep", &["needle"]), 0);
    assert_eq!(m.out(), "needle in a haystack\n");
    let mut m = with_stdin(&format!("{}\n", "x".repeat(100)));
    assert_eq!(run_with(&mut m, "grep", &["-c", "x"], 64), 0);
    assert_eq!(m.out(), "2\n", "a long line is examined in pieces of the buffer");
}

#[test]
fn sort_orders_lines_bytewise() {
    let mut m = with_stdin("pear\napple\nfig\napple\n");
    assert_eq!(run(&mut m, "sort", &[]), 0);
    assert_eq!(m.out(), "apple\napple\nfig\npear\n");
    let mut m = with_stdin("b\na\nc");
    assert_eq!(run(&mut m, "sort", &["-r"]), 0);
    assert_eq!(m.out(), "c\nb\na\n");
    let mut m = with_stdin("b\na\nb\na\nc\n");
    assert_eq!(run(&mut m, "sort", &["-u"]), 0);
    assert_eq!(m.out(), "a\nb\nc\n");
    let mut m = with_stdin("");
    assert_eq!(run(&mut m, "sort", &[]), 0);
    assert_eq!(m.out(), "");
}

#[test]
fn sort_n_orders_numbers_not_text() {
    let mut m = with_stdin("10\n9\n-3\n100\n2x\n");
    assert_eq!(run(&mut m, "sort", &["-n"]), 0);
    assert_eq!(m.out(), "-3\n2x\n9\n10\n100\n");
    let mut m = with_stdin("10\n9\n100\n");
    assert_eq!(run(&mut m, "sort", &["-rn"]), 0);
    assert_eq!(m.out(), "100\n10\n9\n");
}

#[test]
fn sort_merges_files_and_input_and_scales() {
    let mut m = with_stdin("m\n");
    m.file("/a", "z\nb\n").file("/b", "y\na");
    assert_eq!(run(&mut m, "sort", &["/a", "/b", "-"]), 0);
    assert_eq!(m.out(), "a\nb\nm\ny\nz\n");
    let mut text = String::new();
    for i in 0..1000 {
        text.push_str(&format!("{}\n", (i * 7919) % 1000));
    }
    let mut m = with_stdin(&text);
    m.stdin_chunk = 61;
    assert_eq!(run(&mut m, "sort", &["-n"]), 0);
    assert_eq!(m.out(), (0..1000).map(|i| format!("{i}\n")).collect::<String>());
}

#[test]
fn sort_says_when_the_input_does_not_fit() {
    let mut m = with_stdin(&numbered(100));
    assert_eq!(run_with(&mut m, "sort", &[], 300), 2);
    assert!(m.err().contains("larger than the sort buffer"), "{}", m.err());
    assert_eq!(m.out(), "", "nothing half-sorted is printed");
}

#[test]
fn uniq_collapses_adjacent_lines() {
    let mut m = with_stdin("a\na\nb\na\na\na\n");
    assert_eq!(run(&mut m, "uniq", &[]), 0);
    assert_eq!(m.out(), "a\nb\na\n");
    let mut m = with_stdin("a\na\nb\nc\nc\n");
    assert_eq!(run(&mut m, "uniq", &["-d"]), 0);
    assert_eq!(m.out(), "a\nc\n");
    let mut m = with_stdin("a\na\nb\nc\nc\n");
    assert_eq!(run(&mut m, "uniq", &["-u"]), 0);
    assert_eq!(m.out(), "b\n");
    let mut m = with_stdin("");
    assert_eq!(run(&mut m, "uniq", &[]), 0);
    assert_eq!(m.out(), "");
}

#[test]
fn uniq_c_counts_the_run() {
    let mut m = with_stdin("a\na\na\nb\n");
    m.stdin_chunk = 3;
    assert_eq!(run(&mut m, "uniq", &["-c"]), 0);
    assert_eq!(m.out(), "      3 a\n      1 b\n");
}

#[test]
fn tr_translates_deletes_and_squeezes() {
    let mut m = with_stdin("hello world\n");
    assert_eq!(run(&mut m, "tr", &["lo", "01"]), 0);
    assert_eq!(m.out(), "he001 w1r0d\n");
    let mut m = with_stdin("hello world\n");
    assert_eq!(run(&mut m, "tr", &["-d", "l"]), 0);
    assert_eq!(m.out(), "heo word\n");
    let mut m = with_stdin("a   b    c\n");
    assert_eq!(run(&mut m, "tr", &["-s", " "]), 0);
    assert_eq!(m.out(), "a b c\n");
    let mut m = with_stdin("aabbcc\n");
    assert_eq!(run(&mut m, "tr", &["-s", "ab", "xy"]), 0);
    assert_eq!(m.out(), "xycc\n");
}

#[test]
fn tr_range_includes_the_last_letter() {
    let mut m = with_stdin("quiz xyz\n");
    assert_eq!(run(&mut m, "tr", &["a-z", "A-Z"]), 0);
    assert_eq!(m.out(), "QUIZ XYZ\n");
}

#[test]
fn tr_classes_escapes_and_short_second_set() {
    let mut m = with_stdin("Hello 42\n");
    assert_eq!(run(&mut m, "tr", &["[:upper:][:digit:]", "u#"]), 0);
    assert_eq!(m.out(), "#ello ##\n", "the last byte of a short second set repeats");
    let mut m = with_stdin("a b\n");
    assert_eq!(run(&mut m, "tr", &[" ", r"\n"]), 0);
    assert_eq!(m.out(), "a\nb\n");
    let mut m = with_stdin("a\n");
    assert_eq!(run(&mut m, "tr", &[]), 2);
    assert_eq!(run(&mut m, "tr", &["z-a", "x"]), 2);
}

#[test]
fn tr_works_across_small_reads() {
    let mut m = with_stdin("aaaabbbb\n");
    m.stdin_chunk = 3;
    assert_eq!(run(&mut m, "tr", &["-s", "a"]), 0);
    assert_eq!(m.out(), "abbbb\n");
}

#[test]
fn cut_ranges_include_the_end() {
    let mut m = with_stdin("abcdef\n");
    assert_eq!(run(&mut m, "cut", &["-c", "2-4"]), 0);
    assert_eq!(m.out(), "bcd\n");
    let mut m = with_stdin("abcdef\n");
    assert_eq!(run(&mut m, "cut", &["-c", "1,3,5-"]), 0);
    assert_eq!(m.out(), "acef\n");
    let mut m = with_stdin("abcdef\n");
    assert_eq!(run(&mut m, "cut", &["-c", "-2"]), 0);
    assert_eq!(m.out(), "ab\n");
}

#[test]
fn cut_fields() {
    let mut m = with_stdin("a:b:c\nplain\nx:y\n");
    assert_eq!(run(&mut m, "cut", &["-d", ":", "-f", "2"]), 0);
    assert_eq!(m.out(), "b\nplain\ny\n");
    let mut m = with_stdin("a:b:c\nplain\nx:y\n");
    assert_eq!(run(&mut m, "cut", &["-d:", "-f1,3", "-s"]), 0);
    assert_eq!(m.out(), "a:c\nx\n");
    let mut m = with_stdin("a\tb\n");
    assert_eq!(run(&mut m, "cut", &["-f", "2"]), 0);
    assert_eq!(m.out(), "b\n");
    assert_eq!(run(&mut m, "cut", &[]), 2);
    assert_eq!(run(&mut m, "cut", &["-f", "0"]), 2);
    assert_eq!(run(&mut m, "cut", &["-f", "1", "-c", "1"]), 2);
}

#[test]
fn tee_copies_input_to_output_and_files() {
    let mut m = with_stdin("hello\nworld\n");
    m.stdin_chunk = 4;
    assert_eq!(run(&mut m, "tee", &["/o1", "/o2"]), 0);
    assert_eq!(m.out(), "hello\nworld\n");
    assert_eq!(m.read("/o1").unwrap(), "hello\nworld\n");
    assert_eq!(m.read("/o2").unwrap(), "hello\nworld\n");
}

#[test]
fn tee_a_appends_and_reports_an_unwritable_file() {
    let mut m = with_stdin("new\n");
    m.file("/o", "old\n").dir("/ro");
    m.read_only = Some(b"/ro".to_vec());
    assert_eq!(run(&mut m, "tee", &["-a", "/o", "/ro/x"]), 1);
    assert_eq!(m.read("/o").unwrap(), "old\nnew\n");
    assert_eq!(m.out(), "new\n", "the output still gets the input");
    assert!(m.err().contains("/ro/x: denied"), "{}", m.err());
}
