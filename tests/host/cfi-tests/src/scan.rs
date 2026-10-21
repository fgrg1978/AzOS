// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The landing-pad scanner: for every global symbol an assembly source
//! defines in executable code, the first instruction after its label must be
//! the ISA's landing pad, unless the symbol is on the exemption list with its
//! reason.
//!
//! The sources are the `.S` files of `kernel/src/entry/<isa>/asm` and the
//! `global_asm!` text of the arch crates (a Rust file is read line by line,
//! with the quotes and the trailing comma of a `".globl x",` line stripped,
//! so one scanner serves both). Section and mode are tracked: a symbol in
//! `.data`/`.bss`/`.rodata`/`.note`, or in 16/32-bit code, has no pad to carry.

use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Isa {
    Aarch64,
    X86_64,
}

impl Isa {
    /// Is `ins` (an instruction line, comments stripped) this ISA's landing pad?
    fn is_pad(self, ins: &str) -> bool {
        let ins = ins.trim();
        match self {
            // BTI is HINT #32|#34|#36|#38 (`bti`, `bti c`, `bti j`, `bti jc`); a pad
            // for a `bl`/`br` target is c, j or jc.
            Isa::Aarch64 => {
                let ins = ins.split_whitespace().collect::<Vec<_>>().join(" ");
                ins.starts_with("bti") || ["hint #34", "hint #36", "hint #38"].iter().any(|h| ins.starts_with(h))
            }
            Isa::X86_64 => ins.starts_with("endbr64"),
        }
    }
}

/// One global symbol without a pad that is not exempt.
#[derive(Debug, PartialEq, Eq)]
pub struct Missing {
    pub symbol: String,
    pub line: usize,
    pub found: String,
}

/// A line of assembly, with the Rust string syntax around it stripped.
fn asm_line(raw: &str) -> String {
    let mut s = raw.trim();
    // `"  .globl foo",` / `"foo:",` / `concat!(...)` forms of global_asm!.
    if let Some(r) = s.strip_prefix('"') {
        s = r.trim_end_matches(',').trim_end().trim_end_matches('"');
    }
    let s = s.trim_end_matches("\\n").trim_end_matches("\\n\\");
    // Comments: `//`, `#` (only at line start in GNU as for ARM/x86), `;`.
    let s = match s.find("//") {
        Some(i) => &s[..i],
        None => s,
    };
    let s = s.trim();
    if s.starts_with('#') || s.starts_with(';') {
        return String::new();
    }
    s.to_string()
}

/// Section state of a source: `true` when the current section is executable.
struct Sections {
    cur: bool,
    stack: Vec<bool>,
}

impl Sections {
    fn exec_of(line: &str) -> Option<bool> {
        let l = line.trim();
        let name_exec = |name: &str, flags: Option<&str>| match flags {
            Some(f) => f.contains('x'),
            None => name.starts_with(".text"),
        };
        for dir in [".section", ".pushsection"] {
            if let Some(rest) = l.strip_prefix(dir) {
                if !rest.starts_with(' ') && !rest.starts_with('\t') {
                    continue;
                }
                let mut it = rest.trim().splitn(3, ',');
                let name = it.next().unwrap_or("").trim();
                let flags = it.next().map(|f| f.trim().trim_matches('"'));
                return Some(name_exec(name, flags));
            }
        }
        match l.split_whitespace().next() {
            Some(".text") => Some(true),
            Some(".data") | Some(".bss") | Some(".rodata") => Some(false),
            _ => None,
        }
    }
}

/// Scan one source. `exempt` is the exemption list of this file: symbols that
/// legitimately carry no pad.
pub fn scan(text: &str, isa: Isa, exempt: &BTreeSet<&str>) -> Vec<Missing> {
    check(text, isa, exempt).1
}

/// [`scan`], and the global symbols it actually looked at (so a row can
/// prove the scan is not vacuous: that it reached the entries it should).
pub fn check(text: &str, isa: Isa, exempt: &BTreeSet<&str>) -> (Vec<String>, Vec<Missing>) {
    let mut checked = Vec::new();
    let lines: Vec<(usize, String)> = text.lines().enumerate().map(|(n, l)| (n + 1, asm_line(l))).collect();
    // Pass 1: the global names (a `.globl a, b, c` list too).
    let mut globals = BTreeSet::new();
    for (_, l) in &lines {
        for dir in [".globl", ".global"] {
            if let Some(rest) = l.strip_prefix(dir) {
                if rest.starts_with(' ') || rest.starts_with('\t') {
                    for n in rest.split(',') {
                        let n = n.trim().trim_matches('"');
                        if !n.is_empty() {
                            globals.insert(n.to_string());
                        }
                    }
                }
            }
        }
    }
    // Pass 2: walk the file, tracking section and code mode, and check each
    // global's label.
    let mut sec = Sections { cur: true, stack: Vec::new() };
    let mut mode64 = true;
    let mut out = Vec::new();
    for (i, (lineno, l)) in lines.iter().enumerate() {
        if l.starts_with(".code16") || l.starts_with(".code32") {
            mode64 = false;
        } else if l.starts_with(".code64") {
            mode64 = true;
        }
        if l.starts_with(".pushsection") {
            sec.stack.push(sec.cur);
        }
        if l.starts_with(".popsection") {
            sec.cur = sec.stack.pop().unwrap_or(true);
        }
        if let Some(e) = Sections::exec_of(l) {
            sec.cur = e;
        }
        let Some(name) = l.strip_suffix(':') else { continue };
        let name = name.trim();
        if !globals.contains(name) || !sec.cur || !mode64 || exempt.contains(name) {
            continue;
        }
        checked.push(name.to_string());
        // The first instruction after the label.
        let mut found = String::from("<end of file>");
        for (_, nl) in lines.iter().skip(i + 1) {
            let nl = nl.as_str();
            // Blank, a directive (`.balign`, `.type`), or another label of the same entry.
            if nl.is_empty() || nl.starts_with('.') || nl.ends_with(':') {
                continue;
            }
            found = nl.to_string();
            break;
        }
        if !isa.is_pad(&found) {
            out.push(Missing { symbol: name.to_string(), line: *lineno, found });
        }
    }
    (checked, out)
}

/// `text` with the pad that follows the first line of `label` blanked out
/// (the canary rows: the scan must then name that symbol).
pub fn without_pad_after(text: &str, label: &str, isa: Isa) -> String {
    let mut seen = false;
    let mut done = false;
    text.lines()
        .map(|l| {
            if !seen && l.trim() == label {
                seen = true;
            } else if seen && !done && isa.is_pad(&asm_line(l)) {
                done = true;
                return String::new();
            }
            l.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
