// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the user shell's pure modules:
//! `userspace/services/sh/src/{parse,path,req}.rs` and the task listing of
//! `userspace/services/toolbox/src/ps_view.rs`, pulled in with `#[path]`
//! so the code under test is the code `SH.ELF` and `TOOLBOX.ELF` are built from. The request
//! block the shell builds is checked here against `azos_abi::ushell`'s own
//! shape check, which is what the kernel runs on it.

#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/parse.rs"]
pub mod parse;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/ident.rs"]
pub mod ident;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/path.rs"]
pub mod path;
#[allow(dead_code)]
#[path = "../../../../userspace/services/sh/src/req.rs"]
pub mod req;
#[allow(dead_code)]
#[path = "../../../../userspace/services/toolbox/src/ps_view.rs"]
pub mod ps_view;

#[cfg(test)]
mod identity {
    use crate::ident::prompt;

    fn p(user: Option<&[u8]>) -> String {
        let mut b = [0u8; 32];
        let n = prompt(user, b"azos$ ", &mut b);
        String::from_utf8(b[..n].to_vec()).unwrap()
    }

    /// A user's session says whose it is, the system's does not; the prompt
    /// still fits the terminal's.
    ///
    /// **Canary.** Ignore `USER`: the first assertion reads `azos$ `.
    #[test]
    fn the_prompt_names_the_user_of_a_session() {
        assert_eq!(p(Some(b"alice")), "alice@azos$ ");
        assert_eq!(p(None), "azos$ ");
        assert_eq!(p(Some(b"")), "azos$ ", "an empty USER is none");
        assert!(p(Some(b"sixteen-bytes-ok")).len() <= 32);
    }

    /// The environment is the spawner's: what is not a name is not echoed to the terminal.
    ///
    /// **Canary.** Copy `USER` as it is: the escape sequence reaches the prompt.
    #[test]
    fn a_user_name_with_control_bytes_is_cut_where_it_stops_being_a_name() {
        assert_eq!(p(Some(b"al[2Jice")), "al@azos$ ");
        assert_eq!(p(Some(b"[31mred")), "azos$ ");
        assert_eq!(p(Some(b"waytoolongusername-of-all")), "waytoolonguserna@azos$ ");
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
        for a in ["ls", "cat", "echo", "wc", "args", "spin", "yes", "sleep", "true", "false", "ps", "inspect", "host", "ntp"] {
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

/// `ps` reads the task list from the introspection tree, not from `/proc`.
#[cfg(test)]
mod ps {
    use crate::ps_view::{Leaf, Table, HEADER, ROWS_MAX};

    /// The leaves the kernel's admin tree holds for one task, in its order.
    fn task(t: &mut Table, tid: u32, parent: u64, pri: u64, state: &str, name: &str) {
        let p = |f: &str| format!("sched/tasks/{tid}/{f}");
        t.feed(&p("name"), Leaf::Str(name));
        t.feed(&p("state"), Leaf::Str(state));
        t.feed(&p("priority"), Leaf::U64(pri));
        t.feed(&p("parent"), Leaf::U64(parent));
    }

    fn text(t: &Table) -> String {
        let mut s = String::new();
        t.render(&mut s).unwrap();
        s
    }

    #[test]
    fn the_listing_keeps_the_format_the_procfs_file_had() {
        let mut t = Table::new();
        task(&mut t, 1, 0, 8, "S", "kernel");
        task(&mut t, 12, 1, 24, "R", "SH.ELF");
        assert_eq!(text(&t), format!("{HEADER}    1     0   8 S kernel\n   12     1  24 R SH.ELF\n"));
        assert_eq!(HEADER, "  TID  PPID PRI S NAME\n");
    }

    #[test]
    fn only_leaves_under_sched_tasks_are_tasks() {
        let mut t = Table::new();
        t.feed("sched/tasks_seen", Leaf::U64(3));
        t.feed("sched/tasks", Leaf::U64(3));
        t.feed("sched/tasks/7", Leaf::U64(3));
        t.feed("sched/tasks/x/name", Leaf::Str("no"));
        t.feed("sched/tasks//name", Leaf::Str("no"));
        t.feed("memory/pages_free", Leaf::U64(9));
        t.feed("sched/tasks/7/extra", Leaf::U64(1));
        assert_eq!(t.len(), 1, "only the task 7 row, made by its unknown leaf");
        t.feed("sched/tasks/7/priority", Leaf::Str("wrong kind"));
        t.feed("sched/tasks/7/state", Leaf::U64(1));
        assert_eq!(text(&t), format!("{HEADER}    7     0   0 ? \n"));
    }

    #[test]
    fn a_rebuilt_region_walked_again_starts_from_nothing() {
        let mut t = Table::new();
        task(&mut t, 1, 0, 8, "S", "kernel");
        t.clear();
        task(&mut t, 2, 1, 9, "R", "again");
        assert_eq!(text(&t), format!("{HEADER}    2     1   9 R again\n"));
    }

    #[test]
    fn tasks_past_the_table_are_counted_once_each() {
        let mut t = Table::new();
        for tid in 1..=(ROWS_MAX as u32 + 3) {
            task(&mut t, tid, 0, 1, "R", "t");
        }
        assert_eq!(t.len(), ROWS_MAX);
        assert!(text(&t).ends_with("... 3 more\n"));
    }

    #[test]
    fn a_name_longer_than_the_kernel_publishes_is_cut() {
        let mut t = Table::new();
        task(&mut t, 5, 0, 1, "R", "0123456789abcdefXYZ");
        assert!(text(&t).ends_with(" R 0123456789abcdef\n"));
    }
}
