// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! libFuzzer target: one line through the user shell's parser
//! (`userspace/services/sh/src/parse.rs`, RFC-0055), the bytes a person or a
//! pasted script types at `SH.ELF`'s prompt.
//!
//! Input layout: `vars NUL line`. `vars` is `NAME=value` pairs separated by
//! `\n` (the shell's environment for `$NAME` / `${NAME}` / `$?`); with no NUL
//! the whole input is the line and no variable is set.
//!
//! Asserted on every input, beyond "no panic": a parse is deterministic; an
//! accepted pipeline has at most MAX_STAGES commands of 1..=MAX_ARGS words
//! each (none only for a blank or comment line, never in the background),
//! and every span it hands out (argv, `<`, `>`/`2>` targets) lies inside its
//! arena with a non-empty target; a refusal has a message. (The shell runs
//! nothing from a refused line, so what a refusal leaves in the pipeline is
//! not asserted.)
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../../../userspace/services/sh/src/parse.rs"]
#[allow(dead_code)]
mod parse;

use parse::{parse, Pipeline, Redir, Vars, ARENA, MAX_ARGS, MAX_STAGES};

struct Env<'a>(&'a [u8]);

impl Vars for Env<'_> {
    fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.0.split(|&b| b == b'\n').find_map(|kv| {
            let eq = kv.iter().position(|&b| b == b'=')?;
            (&kv[..eq] == name).then(|| &kv[eq + 1..])
        })
    }
}

fn span_ok(p: &Pipeline, s: parse::Span) -> bool {
    (s.at as usize + s.len as usize) <= ARENA && p.word(s).len() == s.len as usize
}

fn redir_ok(p: &Pipeline, r: Redir) -> bool {
    match r {
        Redir::None | Redir::ToStdout => true,
        Redir::File { path, .. } => path.len > 0 && span_ok(p, path),
    }
}

fuzz_target!(|data: &[u8]| {
    let (vars, line) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (&[][..], data),
    };
    let env = Env(vars);
    let mut a = Box::new(Pipeline::new());
    let mut b = Box::new(Pipeline::new());
    let ra = parse(line, &env, &mut a);
    let rb = parse(line, &env, &mut b);
    assert_eq!(ra, rb, "the same line parsed two ways");
    match ra {
        Ok(()) => {
            assert!(a.n <= MAX_STAGES, "{} commands", a.n);
            assert!(a.n > 0 || !a.background, "a background job of no command");
            assert_eq!(a.n, b.n);
            for (i, c) in a.cmds[..a.n].iter().enumerate() {
                assert!(c.argc >= 1 && c.argc <= MAX_ARGS, "command {i}: argc {}", c.argc);
                for (j, &w) in c.argv[..c.argc].iter().enumerate() {
                    assert!(span_ok(&a, w), "command {i} word {j} outside the arena");
                    assert_eq!(a.arg(i, j), b.arg(i, j), "nondeterministic word");
                }
                if let Some(s) = c.stdin {
                    assert!(s.len > 0 && span_ok(&a, s), "command {i}: stdin target");
                }
                assert!(redir_ok(&a, c.stdout) && redir_ok(&a, c.stderr), "command {i}: redirect");
            }
        }
        Err(e) => assert!(!e.message().is_empty()),
    }
});
