// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::{run, Mem};
use azos_coreutils::date::civil;
use azos_coreutils::refuse::{REFUSALS, REFUSED};

fn ok(name: &str, args: &[&str]) -> String {
    let mut m = Mem::new();
    m.cwd = b"/fat/work".to_vec();
    m.env = vec![b"A=1".to_vec(), b"B=two words".to_vec()];
    m.wall = Some(1_700_000_000_123_456_789);
    assert_eq!(run(&mut m, name, args), 0, "{name} {args:?}: {}", m.err());
    m.out()
}

#[test]
fn date_formats_the_wall_clock() {
    assert_eq!(ok("date", &[]), "2023-11-14 22:13:20 UTC\n");
    assert_eq!(ok("date", &["-u", "+%Y/%m/%d %H-%M-%S"]), "2023/11/14 22-13-20\n");
    assert_eq!(ok("date", &["+%s %a %b %j %F %T %Z %% %q"]), "1700000000 Tue Nov 318 2023-11-14 22:13:20 UTC % %q\n");
    assert_eq!(ok("date", &["+100%"]), "100%\n");
}

#[test]
fn date_civil_conversion_is_exact_over_leap_days() {
    let c = civil(951_782_400); // 2000-02-29
    assert_eq!((c.year, c.month, c.day, c.yday, c.wday), (2000, 2, 29, 60, 2));
    let c = civil(1_709_164_799); // 2024-02-28 23:59:59
    assert_eq!((c.year, c.month, c.day, c.hour, c.min, c.sec), (2024, 2, 28, 23, 59, 59));
    let c = civil(1_709_164_800); // 2024-02-29
    assert_eq!((c.month, c.day, c.yday), (2, 29, 60));
    let c = civil(1_709_251_200); // 2024-03-01
    assert_eq!((c.month, c.day, c.yday), (3, 1, 61));
    let c = civil(0);
    assert_eq!((c.year, c.month, c.day, c.wday), (1970, 1, 1, 4));
    let c = civil(4_102_444_799); // 2099-12-31 23:59:59
    assert_eq!((c.year, c.month, c.day, c.yday), (2099, 12, 31, 365));
}

#[test]
fn date_says_when_the_clock_is_not_set_and_will_not_set_it() {
    let mut m = Mem::new();
    assert_eq!(run(&mut m, "date", &[]), 1);
    assert!(m.err().contains("not set yet"), "{}", m.err());
    m.wall = Some(5_000_000_000);
    m.stderr.clear();
    assert_eq!(run(&mut m, "date", &["110812002026"]), 2);
    assert!(m.err().contains("time sources"), "{}", m.err());
}

#[test]
fn env_and_pwd_print_what_the_spawner_gave() {
    assert_eq!(ok("env", &[]), "A=1\nB=two words\n");
    assert_eq!(ok("pwd", &[]), "/fat/work\n");
    let mut m = Mem::new();
    assert_eq!(run(&mut m, "env", &["A=1", "cmd"]), 2);
    assert_eq!(run(&mut m, "pwd", &["-P"]), 2);
}

#[test]
fn basename_and_dirname() {
    assert_eq!(ok("basename", &["/a/b/c.txt"]), "c.txt\n");
    assert_eq!(ok("basename", &["/a/b/c.txt", ".txt"]), "c\n");
    assert_eq!(ok("basename", &["c.txt", "c.txt"]), "c.txt\n");
    assert_eq!(ok("basename", &["/a/b/"]), "b\n");
    assert_eq!(ok("dirname", &["/a/b/c.txt", "c.txt", "/x", "/"]), "/a/b\n.\n/\n/\n");
    let mut m = Mem::new();
    assert_eq!(run(&mut m, "basename", &[]), 2);
    assert_eq!(run(&mut m, "dirname", &[]), 2);
}

#[test]
fn seq_counts_up_down_and_by_steps() {
    assert_eq!(ok("seq", &["3"]), "1\n2\n3\n");
    assert_eq!(ok("seq", &["2", "4"]), "2\n3\n4\n");
    assert_eq!(ok("seq", &["10", "-5", "-5"]), "10\n5\n0\n-5\n");
    assert_eq!(ok("seq", &["-2", "1"]), "-2\n-1\n0\n1\n");
    assert_eq!(ok("seq", &["-s", ",", "3"]), "1,2,3\n");
    assert_eq!(ok("seq", &["0"]), "");
    assert_eq!(ok("seq", &["1", "2", "1"]), "1\n");
    let mut m = Mem::new();
    assert_eq!(run(&mut m, "seq", &["1", "0", "5"]), 2);
    assert_eq!(run(&mut m, "seq", &["x"]), 2);
    assert_eq!(run(&mut m, "seq", &[]), 2);
}

#[test]
fn seq_stops_when_the_reader_goes_away() {
    struct Closing(Mem, usize);
    // A closed output after N writes ends the loop with a clean status.
    use azos_coreutils::host::*;
    impl Host for Closing {
        type File = usize;
        fn cwd(&self) -> &[u8] { self.0.cwd() }
        fn env(&self, i: usize) -> Option<&[u8]> { self.0.env(i) }
        fn wall_ns(&self) -> Option<u64> { None }
        fn stdin(&mut self, b: &mut [u8]) -> Result<usize, Error> { self.0.stdin(b) }
        fn out(&mut self, b: &[u8]) -> Result<(), Error> {
            if self.1 == 0 { return Err(Error::Closed); }
            self.1 -= 1;
            Host::out(&mut self.0, b)
        }
        fn err(&mut self, b: &[u8]) { Host::err(&mut self.0, b) }
        fn stat(&mut self, p: &[u8]) -> Result<Stat, Error> { self.0.stat(p) }
        fn readdir(&mut self, p: &[u8], i: u32, n: &mut [u8; NAME_MAX]) -> Result<Option<Entry>, Error> { self.0.readdir(p, i, n) }
        fn open(&mut self, p: &[u8], m: Open) -> Result<usize, Error> { self.0.open(p, m) }
        fn read(&mut self, f: usize, b: &mut [u8]) -> Result<usize, Error> { Host::read(&mut self.0, f, b) }
        fn write(&mut self, f: usize, b: &[u8]) -> Result<usize, Error> { self.0.write(f, b) }
        fn close(&mut self, f: usize) { self.0.close(f) }
        fn mkdir(&mut self, p: &[u8]) -> Result<(), Error> { self.0.mkdir(p) }
        fn unlink(&mut self, p: &[u8]) -> Result<(), Error> { self.0.unlink(p) }
        fn rmdir(&mut self, p: &[u8]) -> Result<(), Error> { self.0.rmdir(p) }
        fn rename(&mut self, a: &[u8], b: &[u8]) -> Result<(), Error> { self.0.rename(a, b) }
        fn fs_info(&mut self, p: &[u8]) -> Result<FsInfo, Error> { self.0.fs_info(p) }
    }
    let mut h = Closing(Mem::new(), 5);
    let mut scratch = vec![0u8; 64];
    let st = azos_coreutils::run(&mut h, b"seq", &[b"1000000000"], &mut scratch).unwrap();
    assert_eq!(st, 0);
    assert_eq!(h.0.stderr, b"");
}

#[test]
fn printf_formats() {
    assert_eq!(ok("printf", &["hello\\n"]), "hello\n");
    assert_eq!(ok("printf", &["%s-%s\\n", "a", "b"]), "a-b\n");
    assert_eq!(ok("printf", &["%d %i %u\\n", "-5", "7", "9"]), "-5 7 9\n");
    assert_eq!(ok("printf", &["%x %X %o\\n", "255", "255", "8"]), "ff FF 10\n");
    assert_eq!(ok("printf", &["[%5s][%-5s][%05d][%c]\\n", "ab", "cd", "42", "xyz"]), "[   ab][cd   ][00042][x]\n");
    assert_eq!(ok("printf", &["100%%\\t|\\\\|\\n"]), "100%\t|\\|\n");
    assert_eq!(ok("printf", &["%s\\n", "a", "b", "c"]), "a\nb\nc\n");
    assert_eq!(ok("printf", &["%s %s\\n", "a"]), "a \n");
    assert_eq!(ok("printf", &["no conversions\\n", "ignored"]), "no conversions\n");
}

#[test]
fn printf_rejects_a_bad_number_and_a_bad_conversion() {
    let mut m = Mem::new();
    assert_eq!(run(&mut m, "printf", &["%d\\n", "12x"]), 1);
    assert_eq!(m.out(), "0\n");
    assert!(m.err().contains("not a number"), "{}", m.err());
    let mut m = Mem::new();
    assert_eq!(run(&mut m, "printf", &["%q"]), 2);
    assert_eq!(run(&mut m, "printf", &[]), 2);
}

#[test]
fn the_unix_commands_with_no_native_meaning_are_refused_by_name() {
    for (name, why) in REFUSALS {
        let name = std::str::from_utf8(name).unwrap();
        let mut m = Mem::new();
        assert_eq!(run(&mut m, name, &["x"]), REFUSED, "{name}");
        let err = m.err();
        assert!(err.starts_with(&format!("{name}: ")) && err.contains(std::str::from_utf8(why).unwrap()), "{err}");
        assert_eq!(m.out(), "");
    }
    for want in ["chmod", "chown", "chgrp", "ln", "kill", "mkfifo", "umask"] {
        assert!(REFUSALS.iter().any(|(n, _)| *n == want.as_bytes()), "{want}");
    }
}

#[test]
fn the_name_list_and_the_dispatch_agree() {
    for name in azos_coreutils::NAMES {
        let mut m = Mem::new();
        let mut s = vec![0u8; 64];
        assert!(azos_coreutils::run(&mut m, name, &[], &mut s).is_some(), "{}", String::from_utf8_lossy(name));
        assert!(azos_coreutils::is_tool(name));
    }
    let mut m = Mem::new();
    let mut s = vec![0u8; 64];
    assert!(azos_coreutils::run(&mut m, b"nosuch", &[], &mut s).is_none());
    assert!(!azos_coreutils::is_tool(b"ls"), "ls stays in the toolbox's own table");
    let mut sorted: Vec<_> = azos_coreutils::NAMES.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), azos_coreutils::NAMES.len(), "no duplicates");
}
