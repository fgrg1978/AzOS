// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the user shell's pure modules (RFC-0055):
//! `userspace/services/sh/src/{edit,parse,path}.rs`, pulled in with `#[path]`
//! so the code under test is the code `SH.ELF` is built from. The request
//! block the shell builds is checked here against `azos_abi::ushell`'s own
//! shape check, which is what the kernel runs on it.

#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/edit.rs"]
pub mod edit;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/parse.rs"]
pub mod parse;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/path.rs"]
pub mod path;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/req.rs"]
pub mod req;

#[cfg(test)]
mod line_editor {
    use crate::edit::{Editor, Event, History, LINE_MAX};

    fn feed_all(e: &mut Editor, h: &History, bytes: &[u8]) -> (Vec<Event>, Vec<u8>) {
        let mut evs = Vec::new();
        let mut out = Vec::new();
        for &b in bytes {
            let ev = e.feed(b, h);
            out.extend_from_slice(e.take_output());
            if ev != Event::None {
                evs.push(ev);
            }
        }
        (evs, out)
    }

    fn fresh() -> Editor {
        let mut e = Editor::new();
        e.set_prompt(b"$ ");
        e.start();
        assert_eq!(e.take_output(), b"$ ");
        e
    }

    #[test]
    fn typed_bytes_echo_and_enter_completes_the_line() {
        let h = History::new();
        let mut e = fresh();
        let (evs, out) = feed_all(&mut e, &h, b"echo hi\r");
        assert_eq!(evs, vec![Event::Line]);
        assert_eq!(e.line(), b"echo hi");
        assert_eq!(out, b"echo hi\n");
    }

    #[test]
    fn backspace_and_del_erase_on_screen_and_in_the_line() {
        let h = History::new();
        let mut e = fresh();
        let (_, out) = feed_all(&mut e, &h, b"ab\x7fc\x08d");
        assert_eq!(e.line(), b"ad");
        // b, erase b, c, erase c, d.
        assert_eq!(out, b"ab\x08 \x08c\x08 \x08d");
    }

    #[test]
    fn backspace_on_an_empty_line_prints_nothing() {
        let h = History::new();
        let mut e = fresh();
        let (_, out) = feed_all(&mut e, &h, b"\x7f\x08");
        assert!(out.is_empty());
        assert_eq!(e.line(), b"");
    }

    #[test]
    fn ctrl_u_kills_and_ctrl_w_kills_a_word() {
        let h = History::new();
        let mut e = fresh();
        feed_all(&mut e, &h, b"ls -l /fat\x17");
        assert_eq!(e.line(), b"ls -l ");
        feed_all(&mut e, &h, b"\x15");
        assert_eq!(e.line(), b"");
    }

    #[test]
    fn left_arrow_then_insert_edits_the_middle() {
        let h = History::new();
        let mut e = fresh();
        feed_all(&mut e, &h, b"ac\x1b[Db");
        assert_eq!(e.line(), b"abc");
        assert_eq!(e.cursor(), 2);
        feed_all(&mut e, &h, b"\x01X\x05Y");
        assert_eq!(e.line(), b"XabcY");
    }

    #[test]
    fn delete_key_removes_under_the_cursor() {
        let h = History::new();
        let mut e = fresh();
        feed_all(&mut e, &h, b"abc\x01\x1b[3~");
        assert_eq!(e.line(), b"bc");
    }

    #[test]
    fn ctrl_c_and_ctrl_d_are_reported_not_acted_on() {
        let h = History::new();
        let mut e = fresh();
        let (evs, _) = feed_all(&mut e, &h, b"\x04");
        assert_eq!(evs, vec![Event::Eof]);
        let (evs, _) = feed_all(&mut e, &h, b"x\x03");
        assert_eq!(evs, vec![Event::Interrupt]);
        assert_eq!(e.line(), b"x", "^C leaves the decision to the caller");
        let (evs, _) = feed_all(&mut e, &h, b"\x04");
        assert!(evs.is_empty(), "^D on a non-empty line is delete-at-cursor, not EOF");
    }

    #[test]
    fn a_256_byte_overflow_is_dropped_not_wrapped() {
        let h = History::new();
        let mut e = fresh();
        let long = vec![b'a'; LINE_MAX + 20];
        feed_all(&mut e, &h, &long);
        assert_eq!(e.line().len(), LINE_MAX);
        let (evs, _) = feed_all(&mut e, &h, b"\r");
        assert_eq!(evs, vec![Event::Line]);
    }

    #[test]
    fn history_up_and_down_walk_and_restore_the_new_line() {
        let mut h = History::new();
        h.push(b"first");
        h.push(b"second");
        h.push(b"second"); // a repeat of the newest is not stored twice
        h.push(b"   "); // blanks are not stored
        assert_eq!(h.len(), 2);
        let mut e = fresh();
        feed_all(&mut e, &h, b"new");
        feed_all(&mut e, &h, b"\x1b[A");
        assert_eq!(e.line(), b"second");
        feed_all(&mut e, &h, b"\x1b[A");
        assert_eq!(e.line(), b"first");
        feed_all(&mut e, &h, b"\x1b[A");
        assert_eq!(e.line(), b"first", "past the oldest stays on it");
        feed_all(&mut e, &h, b"\x1b[B\x1b[B");
        assert_eq!(e.line(), b"new");
    }

    #[test]
    fn a_cursor_position_report_is_swallowed() {
        let h = History::new();
        let mut e = fresh();
        let (_, out) = feed_all(&mut e, &h, b"\x1b[24;80Rz");
        assert_eq!(e.line(), b"z");
        assert_eq!(out, b"z");
    }

    #[test]
    fn the_history_ring_wraps_keeping_the_newest() {
        let mut h = History::new();
        for i in 0..(crate::edit::HIST_N + 5) {
            h.push(format!("cmd{i}").as_bytes());
        }
        assert_eq!(h.len(), crate::edit::HIST_N);
        assert_eq!(h.get(0), Some(format!("cmd{}", crate::edit::HIST_N + 4).as_bytes()));
        assert_eq!(h.get(crate::edit::HIST_N), None);
    }
}

#[cfg(test)]
mod parser {
    use crate::parse::{parse, ParseError, Pipeline, Redir, Vars};

    struct Env(Vec<(&'static [u8], &'static [u8])>);
    impl Vars for Env {
        fn get(&self, name: &[u8]) -> Option<&[u8]> {
            self.0.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
        }
    }

    fn env() -> Env {
        Env(vec![(b"FOO", b"bar"), (b"?", b"130"), (b"SP", b"a b")])
    }

    fn words(p: &Pipeline, c: usize) -> Vec<String> {
        (0..p.cmds[c].argc).map(|i| String::from_utf8(p.arg(c, i).to_vec()).unwrap()).collect()
    }

    fn ok(line: &str) -> Pipeline {
        let mut p = Pipeline::new();
        parse(line.as_bytes(), &env(), &mut p).unwrap_or_else(|e| panic!("{line}: {e:?}"));
        p
    }

    fn err(line: &str) -> ParseError {
        let mut p = Pipeline::new();
        parse(line.as_bytes(), &env(), &mut p).expect_err(line)
    }

    #[test]
    fn words_split_on_blanks() {
        let p = ok("  echo   hi\tthere ");
        assert_eq!(p.n, 1);
        assert_eq!(words(&p, 0), ["echo", "hi", "there"]);
        assert!(!p.background);
    }

    #[test]
    fn empty_and_comment_lines_are_no_command() {
        assert_eq!(ok("").n, 0);
        assert_eq!(ok("   # nothing").n, 0);
        assert_eq!(words(&ok("echo a # b"), 0), ["echo", "a"]);
        assert_eq!(words(&ok("echo a#b"), 0), ["echo", "a#b"]);
    }

    #[test]
    fn quoting_and_escapes() {
        assert_eq!(words(&ok(r#"echo 'a $FOO b' "c $FOO d" e\ f"#), 0),
                   ["echo", "a $FOO b", "c bar d", "e f"]);
        assert_eq!(words(&ok(r#"echo "x\"y" "\$FOO" """#), 0), ["echo", "x\"y", "$FOO", ""]);
        assert_eq!(words(&ok("echo a'b'\"c\"d"), 0), ["echo", "abcd"]);
    }

    #[test]
    fn variables_expand_and_unset_is_empty() {
        assert_eq!(words(&ok("echo $FOO ${FOO}x $? $NOPE. $"), 0), ["echo", "bar", "barx", "130", ".", "$"]);
        // No field splitting: a value with a blank stays one word.
        assert_eq!(words(&ok("echo $SP"), 0), ["echo", "a b"]);
    }

    #[test]
    fn unterminated_quotes_are_refused() {
        assert_eq!(err("echo 'abc"), ParseError::Unterminated);
        assert_eq!(err("echo \"abc"), ParseError::Unterminated);
    }

    #[test]
    fn pipelines_split_into_stages() {
        let p = ok("ls /fat | cat | wc");
        assert_eq!(p.n, 3);
        assert_eq!(words(&p, 0), ["ls", "/fat"]);
        assert_eq!(words(&p, 2), ["wc"]);
        assert_eq!(err("ls |"), ParseError::EmptyCommand);
        assert_eq!(err("| ls"), ParseError::EmptyCommand);
        assert_eq!(err("a | | b"), ParseError::EmptyCommand);
        assert_eq!(err("a|b|c|d|e"), ParseError::TooManyStages);
    }

    #[test]
    fn redirections_parse_with_and_without_blanks() {
        let p = ok("cat <in >out 2>>err");
        let c = p.cmds[0];
        assert_eq!(p.word(c.stdin.unwrap()), b"in");
        match c.stdout {
            Redir::File { path, append } => {
                assert_eq!(p.word(path), b"out");
                assert!(!append);
            }
            r => panic!("{r:?}"),
        }
        match c.stderr {
            Redir::File { path, append } => {
                assert_eq!(p.word(path), b"err");
                assert!(append);
            }
            r => panic!("{r:?}"),
        }
        assert_eq!(words(&p, 0), ["cat"]);
    }

    #[test]
    fn stderr_to_stdout_aliases() {
        let p = ok("args > f 2>&1");
        assert_eq!(p.cmds[0].stderr, Redir::ToStdout);
        assert!(matches!(p.cmds[0].stdout, Redir::File { append: false, .. }));
        // A lone `2` is a word.
        assert_eq!(words(&ok("echo 2 x2>y"), 0), ["echo", "2", "x2"]);
    }

    #[test]
    fn redirection_errors() {
        assert_eq!(err("cat <"), ParseError::MissingTarget);
        assert_eq!(err("cat > | wc"), ParseError::MissingTarget);
        assert_eq!(err("cat >a >b"), ParseError::Conflict);
        assert_eq!(err("cat a | wc <b"), ParseError::Conflict);
        assert_eq!(err("cat a >f | wc"), ParseError::Conflict);
        // Wave 12 (tests/fuzz/sh-fuzz): a target that expands to nothing is
        // refused, as bash's "ambiguous redirect" — an unset variable, an
        // empty quoted word, for each of `<`, `>`, `>>` and `2>`.
        // **Canary.** Accept `Tok::Word(w)` whatever its length: these are
        // parsed with an empty path.
        for line in ["cat < $NOPE", "echo x > $NOPE", "echo x >> \"\"", "cat 2> ''"] {
            assert_eq!(err(line), ParseError::MissingTarget, "{line}");
        }
        assert_eq!(words(&ok("cat < $FOO"), 0), ["cat"], "a set variable still names the file");
    }

    #[test]
    fn background_only_at_the_end() {
        let p = ok("spin &");
        assert!(p.background);
        assert_eq!(words(&p, 0), ["spin"]);
        assert_eq!(err("a & b"), ParseError::MisplacedAmp);
        assert_eq!(err("&"), ParseError::EmptyCommand);
    }

    #[test]
    fn unsupported_syntax_is_refused_not_guessed() {
        for l in ["a; b", "a && b", "a || b", "echo $(ls)", "echo `ls`", "echo ${FOO"] {
            assert_eq!(err(l), ParseError::Unsupported, "{l}");
        }
    }

    #[test]
    fn too_many_arguments() {
        let line = format!("echo {}", vec!["x"; 15].join(" "));
        assert_eq!(ok(&line).cmds[0].argc, 16);
        let line = format!("echo {}", vec!["x"; 16].join(" "));
        assert_eq!(err(&line), ParseError::TooManyArgs);
    }

    #[test]
    fn the_arena_bound_holds() {
        let big = "y".repeat(300);
        let line = format!("echo {big} {big} {big} {big}");
        assert_eq!(err(&line), ParseError::TooLong);
    }
}

#[cfg(test)]
mod paths {
    use crate::path::{elf_name, is_applet, join, resolve, PathError, PATH_MAX};

    fn j(cwd: &str, p: &str) -> String {
        let mut o = [0u8; PATH_MAX];
        let n = join(cwd.as_bytes(), p.as_bytes(), &mut o).unwrap();
        String::from_utf8(o[..n].to_vec()).unwrap()
    }

    #[test]
    fn join_normalises() {
        assert_eq!(j("/", "fat"), "/fat");
        assert_eq!(j("/fat", "A.TXT"), "/fat/A.TXT");
        assert_eq!(j("/fat", "/tmp//x/"), "/tmp/x");
        assert_eq!(j("/fat/sub", ".."), "/fat");
        assert_eq!(j("/fat", "../../.."), "/");
        assert_eq!(j("/fat", "./a/./b/../c"), "/fat/a/c");
        assert_eq!(j("/", ""), "/");
    }

    #[test]
    fn eight_three_names() {
        let mut o = [0u8; 12];
        let n = elf_name(b"toolbox", &mut o).unwrap();
        assert_eq!(&o[..n], b"TOOLBOX.ELF");
        let n = elf_name(b"Hello.elf", &mut o).unwrap();
        assert_eq!(&o[..n], b"HELLO.ELF");
        assert_eq!(elf_name(b"abcdefghi", &mut o), Err(PathError::NameTooLong));
        assert_eq!(elf_name(b"abcdefgh", &mut o).map(|n| n), Ok(12));
        assert_eq!(elf_name(b"a.b", &mut o), Err(PathError::BadName));
        assert_eq!(elf_name(b".elf", &mut o), Err(PathError::BadName));
    }

    #[test]
    fn resolve_walks_path_in_order_and_is_case_insensitive() {
        let files = ["/fat/HELLO.ELF", "/opt/HELLO.ELF", "/opt/TOOL.ELF"];
        let mut exists = |p: &[u8]| files.iter().any(|f| f.as_bytes() == p);
        let mut o = [0u8; PATH_MAX];
        let n = resolve(b"hello", b"/", b"/fat:/opt", &mut exists, &mut o).unwrap();
        assert_eq!(&o[..n], b"/fat/HELLO.ELF");
        let n = resolve(b"Tool", b"/", b"/fat:/opt", &mut exists, &mut o).unwrap();
        assert_eq!(&o[..n], b"/opt/TOOL.ELF");
        assert_eq!(resolve(b"nope", b"/", b"/fat:/opt", &mut exists, &mut o), Err(PathError::NotFound));
        assert_eq!(resolve(b"ninechars", b"/", b"/fat", &mut exists, &mut o), Err(PathError::NameTooLong));
    }

    #[test]
    fn a_name_with_a_slash_is_a_path() {
        let mut exists = |p: &[u8]| p == b"/fat/HELLO.ELF";
        let mut o = [0u8; PATH_MAX];
        let n = resolve(b"./HELLO.ELF", b"/fat", b"", &mut exists, &mut o).unwrap();
        assert_eq!(&o[..n], b"/fat/HELLO.ELF");
        assert_eq!(resolve(b"/fat/hello.elf", b"/", b"", &mut exists, &mut o), Err(PathError::NotFound),
                   "a path is used as typed, not case-folded");
    }

    #[test]
    fn applets_are_the_toolbox_table() {
        for a in ["ls", "cat", "echo", "wc", "args", "spin", "yes", "sleep", "true", "false"] {
            assert!(is_applet(a.as_bytes()), "{a}");
        }
        assert!(!is_applet(b"cd"));
    }
}

#[cfg(test)]
mod request_block {
    use crate::req::{Fd, ReqBuilder};
    use azos_abi::ushell::{SpawnReq, MOVE_CONSOLE, SPAWN_F_DIE_WITH_PARENT};

    #[test]
    fn the_builder_produces_a_block_the_kernel_shape_check_accepts() {
        let mut b = ReqBuilder::new();
        assert!(b.arg(b"args"));
        assert!(b.arg(b"one"));
        assert!(b.env(b"FOO=bar"));
        b.cwd(b"/fat");
        b.fd(1, Fd::Console);
        b.fd(2, Fd::Handle(0x1234));
        b.fd(0, Fd::Handle(0x55));
        let r: SpawnReq = b.finish(SPAWN_F_DIE_WITH_PARENT);
        assert_eq!(r.check_shape(), Ok(()));
        assert_eq!(r.argc, 2);
        assert_eq!(r.envc, 1);
        assert_eq!(r.nmoves, 3);
        assert!(r.moves[..3].iter().any(|m| m.child_fd == 1 && m.handle == MOVE_CONSOLE));
        assert_eq!(&b.argv_blob()[..], b"args\0one\0");
    }

    #[test]
    fn the_builder_bounds_argc_and_bytes() {
        let mut b = ReqBuilder::new();
        for _ in 0..16 {
            assert!(b.arg(b"x"));
        }
        assert!(!b.arg(b"x"), "a 17th argument is refused by the builder");
        let mut b = ReqBuilder::new();
        let big = [b'a'; 600];
        assert!(b.arg(&big));
        assert!(!b.arg(&big), "argv bytes stay under 1024");
        let r = b.finish(0);
        assert_eq!(r.check_shape(), Ok(()));
    }

    #[test]
    fn a_closed_fd_is_not_a_move() {
        let mut b = ReqBuilder::new();
        b.arg(b"x");
        b.fd(0, Fd::Closed);
        b.fd(1, Fd::Console);
        let r = b.finish(0);
        assert_eq!(r.nmoves, 1);
    }
}
