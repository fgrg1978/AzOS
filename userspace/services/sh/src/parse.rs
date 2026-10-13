// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Command-line parsing for the user shell (RFC-0055): words, quoting,
//! `$VAR` expansion, pipelines and redirections.
//!
//! Pure: no syscalls, no heap. A line becomes a [`Pipeline`] whose words live
//! in its own arena. `tests/host/sh-tests` pulls this file in with `#[path]`.
//!
//! Grammar, one pipeline per line:
//!
//! ```text
//! line     := pipeline [ '&' ] [ '#' comment ]
//! pipeline := command { '|' command }
//! command  := { word | redirect }
//! redirect := '<' word | '>' word | '>>' word | '2>' word | '2>>' word | '2>&1'
//! word     := { plain | '\' char | "'" ... "'" | '"' ... '"' }
//! ```
//!
//! Inside double quotes `\"`, `\\` and `\$` are escapes and `$NAME`,
//! `${NAME}` and `$?` expand; inside single quotes nothing does. An unset
//! variable expands to nothing. `;`, `&&`, `||` and `$(..)` are refused, not
//! guessed at.

/// Most commands in one pipeline.
pub const MAX_STAGES: usize = 4;
/// Most words of one command, its name included.
pub const MAX_ARGS: usize = 16;
/// Bytes of expanded words one line may produce.
pub const ARENA: usize = 1024;
/// Longest variable name.
pub const VAR_NAME_MAX: usize = 32;

/// A word in a [`Pipeline`]'s arena.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    /// Offset in the arena.
    pub at: u16,
    /// Length.
    pub len: u16,
}

/// Where an output stream goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Redir {
    /// Inherited: the console, or the next pipe.
    #[default]
    None,
    /// A file, truncated (`>`) or appended to (`>>`).
    File {
        /// The path as typed.
        path: Span,
        /// `>>`.
        append: bool,
    },
    /// `2>&1`: wherever standard output goes.
    ToStdout,
}

/// One command of a pipeline.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cmd {
    /// Its words; `argv[0]` is the command name.
    pub argv: [Span; MAX_ARGS],
    /// Words used.
    pub argc: usize,
    /// `< path`.
    pub stdin: Option<Span>,
    /// `>`/`>>`.
    pub stdout: Redir,
    /// `2>`/`2>>`/`2>&1`.
    pub stderr: Redir,
}

/// A parsed line.
pub struct Pipeline {
    /// The commands, `n` of them.
    pub cmds: [Cmd; MAX_STAGES],
    /// Commands used. 0 for an empty or comment-only line.
    pub n: usize,
    /// Ended with `&`.
    pub background: bool,
    arena: [u8; ARENA],
    used: usize,
}

impl Pipeline {
    /// An empty pipeline.
    pub const fn new() -> Self {
        const C: Cmd = Cmd {
            argv: [Span { at: 0, len: 0 }; MAX_ARGS],
            argc: 0,
            stdin: None,
            stdout: Redir::None,
            stderr: Redir::None,
        };
        Self { cmds: [C; MAX_STAGES], n: 0, background: false, arena: [0; ARENA], used: 0 }
    }

    /// The bytes of `s`.
    pub fn word(&self, s: Span) -> &[u8] {
        &self.arena[s.at as usize..(s.at + s.len) as usize]
    }

    /// Word `i` of command `c`.
    pub fn arg(&self, c: usize, i: usize) -> &[u8] {
        self.word(self.cmds[c].argv[i])
    }

    fn reset(&mut self) {
        self.n = 0;
        self.background = false;
        self.used = 0;
        for c in self.cmds.iter_mut() {
            *c = Cmd::default();
        }
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Variables a line may expand.
pub trait Vars {
    /// The value of `name` (`?` is the last status), or `None` if unset.
    fn get(&self, name: &[u8]) -> Option<&[u8]>;
}

/// Why a line did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A quote with no closing quote.
    Unterminated,
    /// `|` with nothing before or after it.
    EmptyCommand,
    /// More than [`MAX_ARGS`] words.
    TooManyArgs,
    /// More than [`MAX_STAGES`] commands.
    TooManyStages,
    /// A redirection with no file after it.
    MissingTarget,
    /// The words do not fit the arena.
    TooLong,
    /// `&` before the end of the line.
    MisplacedAmp,
    /// A redirection given twice for one stream, or `<` on a stage that reads
    /// a pipe.
    Conflict,
    /// `;`, `&&`, `||`, `$(`, a backquote or `${` without `}`.
    Unsupported,
}

impl ParseError {
    /// A message for the user.
    pub fn message(self) -> &'static [u8] {
        match self {
            ParseError::Unterminated => b"unterminated quote",
            ParseError::EmptyCommand => b"empty command in pipeline",
            ParseError::TooManyArgs => b"too many arguments (16 at most)",
            ParseError::TooManyStages => b"too many commands in pipeline (4 at most)",
            ParseError::MissingTarget => b"redirection without a file",
            ParseError::TooLong => b"line too long after expansion",
            ParseError::MisplacedAmp => b"'&' only at the end of a line",
            ParseError::Conflict => b"conflicting redirections",
            ParseError::Unsupported => b"unsupported syntax (; && || $( ` are not implemented)",
        }
    }
}

/// What the next token is.
enum Tok {
    Word(Span),
    Pipe,
    Amp,
    In,
    Out { append: bool },
    Err { append: bool },
    ErrToOut,
    End,
}

struct Lexer<'a, V: Vars> {
    s: &'a [u8],
    i: usize,
    vars: &'a V,
}

fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_special(b: u8) -> bool {
    matches!(b, b'|' | b'&' | b'<' | b'>' | b';' | b'`')
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

impl<V: Vars> Lexer<'_, V> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn push(&self, p: &mut Pipeline, b: &[u8]) -> Result<(), ParseError> {
        if p.used + b.len() > ARENA {
            return Err(ParseError::TooLong);
        }
        p.arena[p.used..p.used + b.len()].copy_from_slice(b);
        p.used += b.len();
        Ok(())
    }

    /// `$` was just consumed: expand what follows into the arena.
    fn expand(&mut self, p: &mut Pipeline) -> Result<(), ParseError> {
        let mut name = [0u8; VAR_NAME_MAX];
        let mut n = 0;
        match self.peek() {
            Some(b'?') => {
                self.i += 1;
                name[0] = b'?';
                n = 1;
            }
            Some(b'{') => {
                self.i += 1;
                loop {
                    match self.peek() {
                        Some(b'}') => {
                            self.i += 1;
                            break;
                        }
                        Some(b) if is_name_byte(b) || b == b'?' => {
                            if n == VAR_NAME_MAX {
                                return Err(ParseError::TooLong);
                            }
                            name[n] = b;
                            n += 1;
                            self.i += 1;
                        }
                        _ => return Err(ParseError::Unsupported),
                    }
                }
            }
            Some(b'(') => return Err(ParseError::Unsupported),
            Some(b) if is_name_byte(b) => {
                while let Some(b) = self.peek() {
                    if !is_name_byte(b) {
                        break;
                    }
                    if n == VAR_NAME_MAX {
                        return Err(ParseError::TooLong);
                    }
                    name[n] = b;
                    n += 1;
                    self.i += 1;
                }
            }
            // A lone `$` is literal.
            _ => return self.push(p, b"$"),
        }
        if let Some(v) = self.vars.get(&name[..n]) {
            self.push(p, v)?;
        }
        Ok(())
    }

    /// Read one word starting at the cursor (which is on a non-space,
    /// non-special byte).
    fn word(&mut self, p: &mut Pipeline) -> Result<Span, ParseError> {
        let start = p.used;
        while let Some(b) = self.peek() {
            if is_space(b) || is_special(b) {
                break;
            }
            self.i += 1;
            match b {
                b'\\' => match self.peek() {
                    Some(c) => {
                        self.i += 1;
                        self.push(p, &[c])?;
                    }
                    None => {}
                },
                b'\'' => loop {
                    match self.peek() {
                        Some(b'\'') => {
                            self.i += 1;
                            break;
                        }
                        Some(c) => {
                            self.i += 1;
                            self.push(p, &[c])?;
                        }
                        None => return Err(ParseError::Unterminated),
                    }
                },
                b'"' => loop {
                    match self.peek() {
                        Some(b'"') => {
                            self.i += 1;
                            break;
                        }
                        Some(b'\\') => {
                            self.i += 1;
                            match self.peek() {
                                Some(c @ (b'"' | b'\\' | b'$')) => {
                                    self.i += 1;
                                    self.push(p, &[c])?;
                                }
                                _ => self.push(p, b"\\")?,
                            }
                        }
                        Some(b'$') => {
                            self.i += 1;
                            self.expand(p)?;
                        }
                        Some(b'`') => return Err(ParseError::Unsupported),
                        Some(c) => {
                            self.i += 1;
                            self.push(p, &[c])?;
                        }
                        None => return Err(ParseError::Unterminated),
                    }
                },
                b'$' => self.expand(p)?,
                c => self.push(p, &[c])?,
            }
        }
        Ok(Span { at: start as u16, len: (p.used - start) as u16 })
    }

    fn next(&mut self, p: &mut Pipeline) -> Result<Tok, ParseError> {
        while self.peek().is_some_and(is_space) {
            self.i += 1;
        }
        let Some(b) = self.peek() else { return Ok(Tok::End) };
        let next = self.s.get(self.i + 1).copied();
        match b {
            b'#' => {
                self.i = self.s.len();
                Ok(Tok::End)
            }
            b'|' if next == Some(b'|') => Err(ParseError::Unsupported),
            b'|' => {
                self.i += 1;
                Ok(Tok::Pipe)
            }
            b'&' if next == Some(b'&') => Err(ParseError::Unsupported),
            b'&' => {
                self.i += 1;
                Ok(Tok::Amp)
            }
            b';' | b'`' => Err(ParseError::Unsupported),
            b'<' => {
                self.i += 1;
                Ok(Tok::In)
            }
            b'>' => {
                self.i += 1;
                let append = self.peek() == Some(b'>');
                if append {
                    self.i += 1;
                }
                Ok(Tok::Out { append })
            }
            b'2' if next == Some(b'>') => {
                self.i += 2;
                if self.s[self.i..].starts_with(b"&1") {
                    self.i += 2;
                    return Ok(Tok::ErrToOut);
                }
                let append = self.peek() == Some(b'>');
                if append {
                    self.i += 1;
                }
                Ok(Tok::Err { append })
            }
            _ => Ok(Tok::Word(self.word(p)?)),
        }
    }
}

/// Parse `line` into `out`, expanding variables from `vars`.
pub fn parse<V: Vars>(line: &[u8], vars: &V, out: &mut Pipeline) -> Result<(), ParseError> {
    out.reset();
    let mut lx = Lexer { s: line, i: 0, vars };
    let mut cur = Cmd::default();
    let mut started = false; // the current command has a word or a redirect
    loop {
        let tok = lx.next(out)?;
        match tok {
            Tok::Word(w) => {
                if cur.argc == MAX_ARGS {
                    return Err(ParseError::TooManyArgs);
                }
                cur.argv[cur.argc] = w;
                cur.argc += 1;
                started = true;
            }
            Tok::In | Tok::Out { .. } | Tok::Err { .. } => {
                // A target that expands to nothing (`< $UNSET`, `> ""`) is
                // refused, as bash's "ambiguous redirect": an empty path names
                // no file, and the open it led to failed later and less
                // clearly (found by tests/fuzz/sh-fuzz, wave 12).
                let target = match lx.next(out)? {
                    Tok::Word(w) if w.len > 0 => w,
                    _ => return Err(ParseError::MissingTarget),
                };
                match tok {
                    Tok::In => {
                        if cur.stdin.is_some() {
                            return Err(ParseError::Conflict);
                        }
                        cur.stdin = Some(target);
                    }
                    Tok::Out { append } => {
                        if cur.stdout != Redir::None {
                            return Err(ParseError::Conflict);
                        }
                        cur.stdout = Redir::File { path: target, append };
                    }
                    Tok::Err { append } => {
                        if cur.stderr != Redir::None {
                            return Err(ParseError::Conflict);
                        }
                        cur.stderr = Redir::File { path: target, append };
                    }
                    _ => {}
                }
                started = true;
            }
            Tok::ErrToOut => {
                if cur.stderr != Redir::None {
                    return Err(ParseError::Conflict);
                }
                cur.stderr = Redir::ToStdout;
                started = true;
            }
            Tok::Pipe => {
                if cur.argc == 0 {
                    return Err(ParseError::EmptyCommand);
                }
                if out.n == MAX_STAGES {
                    return Err(ParseError::TooManyStages);
                }
                out.cmds[out.n] = cur;
                out.n += 1;
                cur = Cmd::default();
                started = false;
                // A pipe must be followed by a command.
                let save = lx.i;
                let save_used = out.used;
                match lx.next(out)? {
                    Tok::End | Tok::Pipe | Tok::Amp => return Err(ParseError::EmptyCommand),
                    _ => {
                        lx.i = save;
                        out.used = save_used;
                    }
                }
            }
            Tok::Amp => {
                if cur.argc == 0 && out.n == 0 {
                    return Err(ParseError::EmptyCommand);
                }
                match lx.next(out)? {
                    Tok::End => {}
                    _ => return Err(ParseError::MisplacedAmp),
                }
                out.background = true;
                break;
            }
            Tok::End => break,
        }
    }
    if started || cur.argc > 0 {
        if cur.argc == 0 {
            return Err(ParseError::EmptyCommand);
        }
        if out.n == MAX_STAGES {
            return Err(ParseError::TooManyStages);
        }
        out.cmds[out.n] = cur;
        out.n += 1;
    }
    // A stage after the first reads the pipe: `<` there conflicts.
    for c in &out.cmds[1..out.n.max(1)] {
        if c.stdin.is_some() {
            return Err(ParseError::Conflict);
        }
    }
    // Every stage but the last writes the pipe: `>` there conflicts.
    if out.n > 1 {
        for c in &out.cmds[..out.n - 1] {
            if c.stdout != Redir::None {
                return Err(ParseError::Conflict);
            }
        }
    }
    Ok(())
}
