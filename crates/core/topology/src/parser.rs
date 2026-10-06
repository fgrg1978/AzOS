// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hand-rolled TOML subset parser — RFC-0005.
//!
//! This parser accepts only the subset that AZOS topology files use:
//!
//! - Section headers: `[class.NAME]`, `[task.NAME]`, `[sched]`.
//! - Comments: `# anything until end of line`.
//! - Scalars: bare integer, `"quoted string"`, `true` / `false`.
//! - Range: `[int, int]` (used only for `priority_range`).
//! - Array-of-inline-tables (multi-line):
//!
//!   ```toml
//!   caps = [
//!       { kind = "channel-pub", target = "/x", perm = "w" },
//!       { kind = "channel-sub", target = "/y", perm = "r" },
//!   ]
//!   ```
//!
//! Anything beyond this subset is rejected (`ParseError::Unsupported`).
//! That's deliberate: cert-grade input parsing means **less is more**.
//!
//! ## Implementation
//!
//! Single-pass, line-oriented, with a tiny state machine to handle
//! multi-line arrays. No allocation. No panics. All output strings
//! borrow from the input byte slice.
//!
//! ## Memory cost
//!
//! Stack-resident scratch: one `[CapSpec; MAX_CAPS_PER_TASK]` (~8 KB).
//! That buffer accumulates the caps for the *current* task and is
//! committed to the topology pool when the task's section ends.

use azos_abi::cap::{CapKind, CapPerms};

use crate::types::{
    CapSpec, ClassSpec, MaybeStr, PolicyKind, Preemption, RestartPolicy, SchedConfig, TaskAbi,
    Topology,
};
use crate::AdmissionError;

/// Errors returned by the parser.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// Section header missing closing `]`.
    UnterminatedSection,
    /// Section header refers to an unknown top-level kind.
    UnknownSection,
    /// Key-value pair has no `=`.
    MissingEquals,
    /// Value cannot be parsed.
    BadValue,
    /// Value's type does not match the field's expected type.
    TypeMismatch,
    /// Field name is not in the section's schema.
    UnknownField,
    /// String literal not closed.
    UnterminatedString,
    /// Inline table not closed.
    UnterminatedInlineTable,
    /// Array of inline tables not closed.
    UnterminatedArray,
    /// Inline table is missing a required field.
    MissingField,
    /// Inline table field count exceeds [`MAX_INLINE_FIELDS`].
    TooManyInlineFields,
    /// More caps for one task than [`MAX_CAPS_PER_TASK_BUF`].
    TooManyCapsPerTask,
    /// The literal string used for an enum-typed field is unknown.
    UnknownEnumValue,
    /// Identifier or string longer than the configured maximum.
    NameTooLong,
    /// Encountered something the subset does not accept (floats,
    /// multi-section keys, multi-line strings, …).
    Unsupported,
    /// Admission error surfaced from the topology builder.
    Admission(AdmissionError),
    /// Two tasks declare WRITE on the same motor — see [`motor_write_conflict`].
    MotorWriteConflict,
    /// `format = N` names a CAPS.TOML format this parser does not know
    /// (only 1 and 2 exist), or appears twice.
    UnsupportedFormat,
    /// A key that exists only from a later format (`restart`, `lease_seal`:
    /// format 2; `abi`: format 3) in a file that did not declare it: the writer and this reader would not
    /// agree on what the file says.
    FieldNeedsFormat,
    /// RFC-0051: more energy domains, OPPs per domain or idle states per
    /// domain than `azos_energy`'s fixed pools hold.
    TooManyEnergyEntries,
}

/// The CAPS.TOML formats this parser reads. A file with no `format = N`
/// line before its first section is format 1 (every topology written before
/// wave 11). Format 2 adds the task keys `restart` and `lease_seal`; format 3
/// (wave 12, RFC-0047) adds the task key `abi`; format 4 (wave 15) adds the
/// top-level binding keys `device`, `counter` and `sched_sha256` ([`Binding`]).
pub const CAPS_FORMAT_MAX: u8 = 4;

/// The top-level keys of a format-4 CAPS.TOML that bind the signed file to one
/// device, to a counter the device never lets go backwards, and to the exact
/// SCHED.TOML it was signed with (wave 15, TOPOSIGN). They sit inside the
/// signed bytes, so CAPS.SIG covers them; the sidecar format is unchanged.
///
/// ```toml
/// format = 4
/// device = "1b5a0a5b3f7d6a54263091faf0027124"   # 16 bytes, hex
/// counter = 2                                     # >= 1
/// sched_sha256 = "<64 hex>"                       # SHA-256 of SCHED.TOML
/// ```
///
/// Each key at most once, before the first section; a malformed value is a
/// parse error, never a missing key. Whether a missing key is acceptable is
/// the loader's policy (`crate::signed`), not the parser's.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Binding {
    /// `format = N` (1 when the line is absent).
    pub format: u8,
    /// `device = "<32 hex>"`.
    pub device: Option<[u8; crate::device_record::DEVICE_ID_LEN]>,
    /// `counter = N`, never 0.
    pub counter: Option<u64>,
    /// `sched_sha256 = "<64 hex>"`.
    pub sched_sha256: Option<[u8; 32]>,
}

/// Read only the top-level lines of a CAPS.TOML (those before its first
/// section): `format` and the [`Binding`] keys. Run on verified bytes, before
/// SCHED.TOML is parsed: the loader needs `sched_sha256` to authenticate it.
pub fn parse_binding(input: &[u8]) -> Result<Binding, ParseError> {
    let mut b = Binding { format: 1, ..Binding::default() };
    let mut format_declared = false;
    let mut rest: &[u8] = input;
    while !rest.is_empty() {
        let (line, next) = take_line(rest);
        rest = next;
        let mut effective = line;
        if let Some(idx) = find_comment_start(effective) {
            effective = &effective[..idx];
        }
        let effective = trim_trailing_ws(skip_inline_ws(effective));
        if effective.is_empty() {
            continue;
        }
        if parse_section_line(effective)?.is_some() {
            break;
        }
        top_level_line(effective, &mut b, &mut format_declared)?;
    }
    Ok(b)
}

/// One line before the first section of a CAPS.TOML: `format = N` (once, a
/// format this parser knows) or a [`Binding`] key (once, format 4 or later).
/// Any other key is ignored, as every key outside a section was before
/// format 2.
fn top_level_line(line: &[u8], b: &mut Binding, format_declared: &mut bool) -> Result<(), ParseError> {
    if let Some(n) = parse_format_line(line)? {
        if *format_declared || n == 0 || n > CAPS_FORMAT_MAX as u64 {
            return Err(ParseError::UnsupportedFormat);
        }
        b.format = n as u8;
        *format_declared = true;
        return Ok(());
    }
    let Ok((key, after)) = take_ident(line) else { return Ok(()) };
    if key != b"device" && key != b"counter" && key != b"sched_sha256" {
        return Ok(());
    }
    if b.format < 4 {
        return Err(ParseError::FieldNeedsFormat);
    }
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let after = skip_inline_ws(&after[1..]);
    match key {
        b"device" => {
            let (v, tail) = parse_quoted_string(after, 2 * crate::device_record::DEVICE_ID_LEN)?;
            if b.device.is_some() || !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            b.device = Some(parse_hex::<{ crate::device_record::DEVICE_ID_LEN }>(v)?);
        }
        b"counter" => {
            let (n, tail) = parse_unsigned_int(after)?;
            if b.counter.is_some() || n == 0 || !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            b.counter = Some(n);
        }
        _ => {
            let (v, tail) = parse_quoted_string(after, 64)?;
            if b.sched_sha256.is_some() || !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            b.sched_sha256 = Some(parse_hex::<32>(v)?);
        }
    }
    Ok(())
}

/// Two tasks that both declare WRITE on one motor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MotorWriteConflict {
    /// The motor id both declarations resolve to.
    pub motor_id: u32,
    /// Index into [`Topology::tasks`] of the first task declaring WRITE.
    pub first_task: usize,
    /// Index of the second.
    pub second_task: usize,
}

/// The first pair of tasks declaring WRITE on the same motor, if any.
///
/// **One writer per motor** (audit unit 2). A motor is commanded by one task;
/// a second holder of WRITE is a second source of commands the first cannot
/// see, and nothing downstream arbitrates between them. The capability model
/// grants at boot and never delegates, so the topology is the one place the
/// rule can be stated whole.
///
/// The motor id is read the way `azos_ipc::cap_seed::seed_one_cap` reads
/// it — `"motor."` then Rust's `u32` parse — so `motor.00` and `motor.+0` are
/// the same motor as `motor.0`, as they are once minted. Comparing target
/// strings would let one motor through under two spellings. A target that does
/// not parse mints nothing and conflicts with nothing. One task declaring the
/// same motor twice is one writer.
pub fn motor_write_conflict(topology: &Topology<'_>) -> Option<MotorWriteConflict> {
    let tasks = topology.tasks();
    for (a, first) in tasks.iter().enumerate() {
        for cap in topology.caps_of(first) {
            let Some(id) = motor_write_id(cap) else { continue };
            for (b, second) in tasks.iter().enumerate().skip(a + 1) {
                if topology.caps_of(second).iter().any(|c| motor_write_id(c) == Some(id)) {
                    return Some(MotorWriteConflict { motor_id: id, first_task: a, second_task: b });
                }
            }
        }
    }
    None
}

/// The motor a WRITE-bearing `Motor` grant names; `None` for anything else.
fn motor_write_id(cap: &CapSpec<'_>) -> Option<u32> {
    if cap.kind != CapKind::Motor || !cap.perms.contains(CapPerms::WRITE) {
        return None;
    }
    let digits = cap.target.as_str().strip_prefix("motor.")?;
    digits.parse::<u32>().ok()
}

impl From<AdmissionError> for ParseError {
    fn from(e: AdmissionError) -> Self {
        ParseError::Admission(e)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Tiny lexer helpers (operate on byte slices)
// ──────────────────────────────────────────────────────────────────────────

#[inline]
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

#[inline]
fn is_eol(b: u8) -> bool {
    matches!(b, b'\n' | b'\r')
}

#[inline]
fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

#[inline]
fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Skip leading spaces and tabs (not newlines).
fn skip_inline_ws(input: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < input.len() && is_ws(input[i]) {
        i += 1;
    }
    &input[i..]
}

/// Skip leading whitespace (incl. newlines, comments).
fn skip_ws_and_comments(mut input: &[u8]) -> &[u8] {
    loop {
        // Inline whitespace + newlines.
        let mut i = 0;
        while i < input.len() && (is_ws(input[i]) || is_eol(input[i])) {
            i += 1;
        }
        input = &input[i..];
        if input.is_empty() || input[0] != b'#' {
            return input;
        }
        // Comment — skip to next newline.
        let mut j = 0;
        while j < input.len() && !is_eol(input[j]) {
            j += 1;
        }
        input = &input[j..];
    }
}

/// Read one logical line (until first `\n`), returning (line, rest).
/// The newline is consumed in `rest`. Strips trailing `\r`.
fn take_line(input: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < input.len() && input[i] != b'\n' {
        i += 1;
    }
    let mut line = &input[..i];
    if let Some((&last, rest)) = line.split_last() {
        if last == b'\r' {
            line = rest;
        }
    }
    let next = if i < input.len() { &input[i + 1..] } else { &input[i..] };
    (line, next)
}

/// Parse a quoted string. Returns `(content, after)`. No escape
/// processing for the supported subset (RFC-0005 fields are simple
/// ASCII). Rejects strings longer than `max_len`.
fn parse_quoted_string<'a>(input: &'a [u8], max_len: usize) -> Result<(&'a [u8], &'a [u8]), ParseError> {
    if input.is_empty() || input[0] != b'"' {
        return Err(ParseError::BadValue);
    }
    let body = &input[1..];
    let mut i = 0;
    while i < body.len() && body[i] != b'"' {
        if body[i] == b'\\' || is_eol(body[i]) {
            return Err(ParseError::Unsupported);
        }
        i += 1;
    }
    if i >= body.len() {
        return Err(ParseError::UnterminatedString);
    }
    if i > max_len {
        return Err(ParseError::NameTooLong);
    }
    Ok((&body[..i], &body[i + 1..]))
}

/// Parse a non-negative decimal integer. Returns `(value, after)`.
/// Negative numbers not supported (not needed in our subset).
fn parse_unsigned_int(input: &[u8]) -> Result<(u64, &[u8]), ParseError> {
    let mut i = 0;
    let mut acc: u64 = 0;
    let mut any = false;
    while i < input.len() && input[i].is_ascii_digit() {
        any = true;
        let d = (input[i] - b'0') as u64;
        acc = acc.checked_mul(10).and_then(|v| v.checked_add(d)).ok_or(ParseError::BadValue)?;
        i += 1;
    }
    if !any {
        return Err(ParseError::BadValue);
    }
    Ok((acc, &input[i..]))
}

/// Parse `true` / `false`. Returns `(value, after)`.
fn parse_bool(input: &[u8]) -> Result<(bool, &[u8]), ParseError> {
    if input.starts_with(b"true") {
        Ok((true, &input[4..]))
    } else if input.starts_with(b"false") {
        Ok((false, &input[5..]))
    } else {
        Err(ParseError::BadValue)
    }
}

/// Parse `[lo, hi]` integer range (used for `priority_range`).
fn parse_range(input: &[u8]) -> Result<(u8, u8, &[u8]), ParseError> {
    let r = skip_inline_ws(input);
    if !r.starts_with(b"[") {
        return Err(ParseError::BadValue);
    }
    let r = skip_inline_ws(&r[1..]);
    let (lo, r) = parse_unsigned_int(r)?;
    let r = skip_inline_ws(r);
    if !r.starts_with(b",") {
        return Err(ParseError::BadValue);
    }
    let r = skip_inline_ws(&r[1..]);
    let (hi, r) = parse_unsigned_int(r)?;
    let r = skip_inline_ws(r);
    if !r.starts_with(b"]") {
        return Err(ParseError::BadValue);
    }
    if lo > 255 || hi > 255 {
        return Err(ParseError::BadValue);
    }
    Ok((lo as u8, hi as u8, &r[1..]))
}

/// Take an identifier from the head of input.
fn take_ident(input: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    if input.is_empty() || !is_ident_start(input[0]) {
        return Err(ParseError::BadValue);
    }
    let mut i = 1;
    while i < input.len() && is_ident_continue(input[i]) {
        i += 1;
    }
    Ok((&input[..i], &input[i..]))
}

// ──────────────────────────────────────────────────────────────────────────
// Section detection
// ──────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Section<'a> {
    Class(&'a [u8]),
    Task(&'a [u8]),
    Sched,
    /// `[operator]` — W2-B5: the e-stop release-authority public key.
    /// Declared in `CAPS.TOML` (it is a capability-adjacent authority, not
    /// a scheduler parameter), so `parse_sched` skips it the same way it
    /// already skips `Task`.
    Operator,
    /// `[pipeline.NAME]` — RFC-0049 P7: a data path and the DMA pool it
    /// needs (`dma_kb`). CAPS.TOML owns it; `parse_sched` skips it.
    Pipeline(&'a [u8]),
    /// `[energy]` — RFC-0051: the energy mode. SCHED.TOML owns it
    /// ([`parse_energy`]); CAPS.TOML skips it.
    Energy,
    /// `[energy.domain.NAME]` — RFC-0051: one performance domain of the
    /// energy model. SCHED.TOML owns it; CAPS.TOML skips it.
    EnergyDomain,
}

/// If `line` is a section header `[...]`, return the parsed Section.
fn parse_section_line(line: &[u8]) -> Result<Option<Section<'_>>, ParseError> {
    let trimmed = skip_inline_ws(line);
    if trimmed.is_empty() || trimmed[0] != b'[' {
        return Ok(None);
    }
    // Find closing ']' on the same line.
    let body = &trimmed[1..];
    let mut close = 0;
    while close < body.len() && body[close] != b']' {
        close += 1;
    }
    if close >= body.len() {
        return Err(ParseError::UnterminatedSection);
    }
    let inner = &body[..close];
    // Whatever follows ']' must be only ws / comment.
    let trailing = skip_inline_ws(&body[close + 1..]);
    if !trailing.is_empty() && trailing[0] != b'#' {
        return Err(ParseError::Unsupported);
    }

    // Parse `class.NAME` / `task.NAME` / `sched`.
    let inner = skip_inline_ws(inner);
    if let Some(name) = strip_prefix(inner, b"class.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::Class(name)))
    } else if let Some(name) = strip_prefix(inner, b"task.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::Task(name)))
    } else if let Some(name) = strip_prefix(inner, b"pipeline.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::Pipeline(name)))
    } else if let Some(name) = strip_prefix(inner, b"energy.domain.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::EnergyDomain))
    } else if trim_trailing_ws(inner) == b"energy" {
        Ok(Some(Section::Energy))
    } else if trim_trailing_ws(inner) == b"sched" {
        Ok(Some(Section::Sched))
    } else if trim_trailing_ws(inner) == b"operator" {
        Ok(Some(Section::Operator))
    } else {
        Err(ParseError::UnknownSection)
    }
}

fn strip_prefix<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= prefix.len() && &s[..prefix.len()] == prefix {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn trim_trailing_ws(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && is_ws(s[end - 1]) {
        end -= 1;
    }
    &s[..end]
}

// ──────────────────────────────────────────────────────────────────────────
// Inline-table parsing (for caps array)
// ──────────────────────────────────────────────────────────────────────────

/// One inline-table field as a (key, value) pair, used during parsing.
///
/// Some variants are unused today but exist for forward compatibility
/// with future inline-table fields (numeric thresholds, bool gates).
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum InlineValue<'a> {
    Str(&'a [u8]),
    Int(u64),
    Bool(bool),
    Range(u8, u8),
}

/// Maximum fields per inline table — over-provisioned for forward-compat
/// (Kconfig `TOPOLOGY_INLINE_FIELDS_MAX`).
const MAX_INLINE_FIELDS: usize = azos_limits::TOPOLOGY_INLINE_FIELDS_MAX;

/// Parse one `{ k = v, k = v, ... }` block. Returns the consumed bytes.
fn parse_inline_table<'a>(
    input: &'a [u8],
) -> Result<([(MaybeStr<'a>, InlineValue<'a>); MAX_INLINE_FIELDS], usize, &'a [u8]), ParseError>
{
    let r = skip_inline_ws(input);
    if r.is_empty() || r[0] != b'{' {
        return Err(ParseError::BadValue);
    }
    let mut r = &r[1..];
    let mut fields: [(MaybeStr<'a>, InlineValue<'a>); MAX_INLINE_FIELDS] =
        [(MaybeStr::from_bytes(&[]), InlineValue::Bool(false)); MAX_INLINE_FIELDS];
    let mut len = 0usize;
    loop {
        r = skip_inline_ws(r);
        if r.is_empty() {
            return Err(ParseError::UnterminatedInlineTable);
        }
        if r[0] == b'}' {
            return Ok((fields, len, &r[1..]));
        }
        if len >= MAX_INLINE_FIELDS {
            return Err(ParseError::TooManyInlineFields);
        }
        let (key_bytes, after) = take_ident(r)?;
        if key_bytes.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        let after = skip_inline_ws(after);
        if !after.starts_with(b"=") {
            return Err(ParseError::MissingEquals);
        }
        let after = skip_inline_ws(&after[1..]);
        // Value: string | int | bool
        let (value, after) = if after.starts_with(b"\"") {
            let (s, rest) = parse_quoted_string(after, crate::types::MAX_TARGET_LEN)?;
            (InlineValue::Str(s), rest)
        } else if after.starts_with(b"true") || after.starts_with(b"false") {
            let (b, rest) = parse_bool(after)?;
            (InlineValue::Bool(b), rest)
        } else {
            let (n, rest) = parse_unsigned_int(after)?;
            (InlineValue::Int(n), rest)
        };
        fields[len] = (MaybeStr::from_bytes(key_bytes), value);
        len += 1;
        let after = skip_inline_ws(after);
        if after.starts_with(b",") {
            r = &after[1..];
            continue;
        }
        if after.starts_with(b"}") {
            return Ok((fields, len, &after[1..]));
        }
        return Err(ParseError::UnterminatedInlineTable);
    }
}

/// Convert a parsed inline table into a `CapSpec`.
fn cap_spec_from_inline<'a>(
    fields: &[(MaybeStr<'a>, InlineValue<'a>)],
) -> Result<CapSpec<'a>, ParseError> {
    let mut kind: Option<CapKind> = None;
    let mut perms: Option<CapPerms> = None;
    let mut target: Option<MaybeStr<'a>> = None;
    // O3.4 (owner decision 2026-09-26): whether this grant carries `DUP`
    // (transferable via `move_cap`). Defaults to `false` below — a row
    // transfers authority only when it says so, never by omission.
    let mut transfer: Option<bool> = None;
    for (k, v) in fields {
        match k.as_str() {
            "kind" => {
                let s = match v {
                    InlineValue::Str(s) => *s,
                    _ => return Err(ParseError::TypeMismatch),
                };
                kind = Some(parse_cap_kind(s)?);
            }
            "perm" | "perms" => {
                let s = match v {
                    InlineValue::Str(s) => *s,
                    _ => return Err(ParseError::TypeMismatch),
                };
                perms = Some(parse_cap_perms(s)?);
            }
            "target" | "resource" => {
                let s = match v {
                    InlineValue::Str(s) => *s,
                    _ => return Err(ParseError::TypeMismatch),
                };
                target = Some(MaybeStr::from_bytes(s));
            }
            "transfer" => {
                let b = match v {
                    InlineValue::Bool(b) => *b,
                    _ => return Err(ParseError::TypeMismatch),
                };
                transfer = Some(b);
            }
            _ => return Err(ParseError::UnknownField),
        }
    }
    let kind = kind.ok_or(ParseError::MissingField)?;
    let perms = perms.unwrap_or(CapPerms::READ);
    let target = target.unwrap_or(MaybeStr::from_bytes(&[]));
    let transfer = transfer.unwrap_or(false);
    Ok(CapSpec { kind, perms, target, transfer })
}

fn parse_cap_kind(s: &[u8]) -> Result<CapKind, ParseError> {
    let s = core::str::from_utf8(s).map_err(|_| ParseError::Unsupported)?;
    let k = match s {
        "channel" | "channel-pub" | "channel-sub" => CapKind::Channel,
        "shm" => CapKind::Shm,
        "port" => CapKind::Port,
        "irq" => CapKind::Irq,
        "mmio" | "mmio-region" => CapKind::MmioRegion,
        "io-ring" => CapKind::IoRing,
        "sensor" | "encoder" => CapKind::Sensor,
        "gpio" => CapKind::Gpio,
        "i2c" => CapKind::I2c,
        "pwm" => CapKind::Pwm,
        // U10-6 / M40 (2026-09-26): gated the same way `builder.rs`'s
        // `CapSpec { kind: CapKind::Motor, .. }` rows already are (`grep -n
        // 'cfg(feature = "profile-actuation")' crates/core/topology/src/builder.rs`)
        // — the DATA was never the gap; the PARSER accepted the word
        // regardless. Without this, a signed CAPS.TOML on a non-actuating
        // build could ask for a drivetrain grant the profile says this
        // deployment must not hold, and — until `crates/core/ipc/src/cap_seed.rs`'s
        // matching gate lands (delivered as a diff; `azos_ipc` is not
        // this crate) — silently get nothing (`SeedOutcome::NoMinter`) rather
        // than a parse-time refusal. Refusing here means the OPERATOR sees
        // "this topology asks for something this build cannot honour" at
        // parse time, not "the drivetrain task got no capabilities" at boot
        // with no indication why.
        #[cfg(feature = "profile-actuation")]
        "motor" => CapKind::Motor,
        "file" => CapKind::File,
        "socket" => CapKind::Socket,
        // Wave 12: minted for the one target `"tasks"` with `READ`, the full
        // `/proc` task view (`crates/core/ipc/src/cap_seed.rs`).
        "task" => CapKind::Task,
        "ai-session" | "service-call" => CapKind::AiSession,
        // Wave 3 (2026-09-26): `Power` gained a minter
        // (`crates/core/ipc/src/cap_seed.rs`) and a real consumer already gated
        // on it (`sys_shutdown`/`sys_reboot`), so the comment below no
        // longer applies to it — see that arm's own note.
        "power" => CapKind::Power,
        // Added 2026-09-06 with the typed driver-registry path. Target
        // convention: `"drv.<DRV_KIND_* as decimal>"` — see
        // `crates/core/ipc/src/cap_seed.rs`.
        "driver-registry" => CapKind::DriverRegistry,
        // RFC-0040 gap 2. Named here AND minted in `cap_seed::seed_one_cap` in
        // the same commit: a kind this parser accepts but the seeder drops on
        // its `_ => None` arm lets a topology ask for a capability and receive
        // nothing, with no error — which is what `"task"` above did until
        // wave 12 gave it a minter (the one target `"tasks"`).
        "endpoint" => CapKind::Endpoint,
        // U06-9 (2026-09-26): named AND minted in the same commit
        // (`crates/core/ipc/src/cap_seed.rs`'s `CapKind::LinkKey` arm), same
        // discipline as `"endpoint"` above — a name with no minter is how
        // `"task"` silently granted nothing until wave 12.
        "linkkey" => CapKind::LinkKey,
        // Wave 9 (P9): named AND minted in the same commit
        // (`crates/core/ipc/src/cap_seed.rs`'s `CapKind::Entropy` arm).
        "entropy" => CapKind::Entropy,
        // RFC-0048 P3 (wave 8): named AND minted in the same commit, target
        // `"disk.part.<n>"` — ONE partition of the table the kernel parsed at
        // boot (`crates/core/ipc/src/disk_cap.rs`). The whole-disk resource has no
        // target spelling and no minter, so this word cannot express a raw
        // grant of the medium; the disk syscalls refuse and record any
        // sector outside the named partition.
        "disk" => CapKind::Disk,
        // RFC-0055 (wave 11): named AND minted in the same commit
        // (`crates/core/ipc/src/cap_seed.rs`'s `CapKind::Launch` arm,
        // `crates/core/ipc/src/launch_cap.rs`). Target: an image name,
        // `"TOOLBOX.ELF"`; perm `exec`. There is deliberately no `"pipe"`
        // word: a pipe end is minted by `SYS_PIPE_TYPED` at run time and never
        // granted by a row.
        "launch" => CapKind::Launch,
        // Wave 15 (TRACE): named AND minted in the same commit
        // (`crates/core/ipc/src/cap_seed.rs`'s `CapKind::Trace` arm). Target:
        // the bare word `"trace"`; perms read/write.
        "trace" => CapKind::Trace,
        // `CapKind::{Adc, Buzzer, NetConfig}` exist as of the same day
        // and are still DELIBERATELY absent from this table (`Power` was
        // here too until wave 3, 2026-09-26 — see the `"power"` arm above —
        // and `Disk` until wave 8, above).
        // A name here is what lets `CAPS.TOML` ask for a grant, and each of
        // these three is reachable from ring 3 today only through the
        // untyped `cap_check` path, which no production code grants. Adding
        // the name before the minter and the typed syscall would make a
        // signed topology able to express a raw-disk grant that no handler
        // is ready to honour — a door opened, not a hole closed.
        _ => return Err(ParseError::UnknownEnumValue),
    };
    Ok(k)
}

/// The word [`parse_cap_kind`] reads as `kind`, or `None` for a kind no word
/// names (a signed CAPS.TOML cannot grant it). The inverse of that table, kept
/// next to it: `tests/host/topology-tests` checks every word maps back to the
/// kind it came from, so the emitter (`crate::emit`) and the parser cannot
/// drift apart. `"motor"` only where the parser accepts it.
pub fn cap_kind_word(kind: CapKind) -> Option<&'static str> {
    Some(match kind {
        CapKind::Channel => "channel",
        CapKind::Shm => "shm",
        CapKind::Port => "port",
        CapKind::Irq => "irq",
        CapKind::MmioRegion => "mmio",
        CapKind::IoRing => "io-ring",
        CapKind::Sensor => "sensor",
        CapKind::Gpio => "gpio",
        CapKind::I2c => "i2c",
        CapKind::Pwm => "pwm",
        #[cfg(feature = "profile-actuation")]
        CapKind::Motor => "motor",
        CapKind::File => "file",
        CapKind::Socket => "socket",
        CapKind::Task => "task",
        CapKind::AiSession => "ai-session",
        CapKind::Power => "power",
        CapKind::DriverRegistry => "driver-registry",
        CapKind::Endpoint => "endpoint",
        CapKind::LinkKey => "linkkey",
        CapKind::Entropy => "entropy",
        CapKind::Disk => "disk",
        CapKind::Launch => "launch",
        CapKind::Trace => "trace",
        _ => return None,
    })
}

// Compile-time pin (M40): `CapKind::Motor` the ENUM VARIANT stays
// unconditional — ABI discriminants are not retired or hidden behind a
// feature any more than a syscall number is (established project
// discipline). Only this parser's acceptance of the WORD "motor" is gated,
// above. If a future edit tried to fix M40 by `#[cfg]`-gating the variant
// itself instead of the match arm, every non-`profile-actuation` build
// would fail HERE, at compile time, rather than at whatever ABI mismatch
// that would eventually cause.
#[cfg(not(feature = "profile-actuation"))]
const _: CapKind = CapKind::Motor;

fn parse_cap_perms(s: &[u8]) -> Result<CapPerms, ParseError> {
    let mut p = CapPerms::NONE;
    for &b in s {
        p = match b {
            b'r' | b'R' => p.union(CapPerms::READ),
            b'w' | b'W' => p.union(CapPerms::WRITE),
            b'x' | b'X' => p.union(CapPerms::EXEC),
            b'd' | b'D' => p.union(CapPerms::DUP),
            _ => return Err(ParseError::UnknownEnumValue),
        };
    }
    Ok(p)
}

// ──────────────────────────────────────────────────────────────────────────
// Public entry points
// ──────────────────────────────────────────────────────────────────────────

/// Maximum caps in the per-task scratch buffer. The topology pool is bounded
/// separately, to `MAX_CAPS_TOTAL`.
///
/// **Imported, not restated (2026-09-18).** This was `= 256` with a comment
/// saying it "matches `azos_ipc::cap::MAX_CAPS_PER_TASK`" — a comment
/// holding an invariant that nothing checked, and which was already false for
/// the embedded (32) and fleet (512) profiles, since both this and `ipc`'s
/// copy ignored the `config/Kconfig.limits` value they claimed to track. A scratch
/// buffer smaller than the cap table it mirrors rejects valid topologies;
/// larger, it wastes stack. `types.rs` in this same crate was already
/// importing `MAX_TASKS`/`MAX_CAPS_TOTAL` from `azos_limits` — this now
/// joins them.
const MAX_CAPS_PER_TASK_BUF: usize = azos_limits::MAX_CAPS_PER_TASK;

/// Parse `CAPS.TOML` content into the topology.
///
/// The topology may already contain classes parsed from `SCHED.TOML`;
/// this call appends task entries.
pub fn parse_caps<'a>(
    input: &'a [u8],
    topology: &mut Topology<'a>,
) -> Result<(), ParseError> {
    let mut current_section: Option<Section<'_>> = None;
    let mut current_task_caps: [CapSpec<'a>; MAX_CAPS_PER_TASK_BUF] =
        [CapSpec::empty(); MAX_CAPS_PER_TASK_BUF];
    let mut current_task_caps_len: usize = 0;
    let mut current_task_class: MaybeStr<'a> = MaybeStr::from_bytes(b"best_effort");
    let mut current_task_priority: u8 = 0;
    let mut current_task_mem_pages: u32 = 0;
    let mut current_task_mem_locked = false;
    let mut current_task_sqpoll_idle_ms: u32 = 0;
    let mut current_task_instances: u16 = 0;
    let mut current_task_start = false;
    let mut current_task_lease_seal = false;
    let mut current_task_mem_huge_mib: u16 = 0;
    let mut current_task_restart = RestartPolicy::OnFailure;
    let mut current_task_abi = TaskAbi::Native;
    // Format 1 until a `format = N` line before the first section says
    // otherwise. The binding keys are checked here as well (a malformed or
    // repeated one fails the parse) and read by the loader with
    // `parse_binding`.
    let mut binding = Binding { format: 1, ..Binding::default() };
    let mut format_declared = false;
    // An open `[pipeline.NAME]`: its name and `dma_kb` so far.
    let mut current_pipeline: Option<(MaybeStr<'a>, u32)> = None;
    let mut current_task_profile = crate::deadline::SchedProfile::NONE;
    let mut current_task_name: Option<MaybeStr<'a>> = None;

    let mut rest: &'a [u8] = input;
    while !rest.is_empty() {
        let (line, next) = take_line(rest);
        rest = next;

        // Strip comment + trailing whitespace.
        let mut effective = line;
        if let Some(idx) = find_comment_start(effective) {
            effective = &effective[..idx];
        }
        let effective = trim_trailing_ws(skip_inline_ws(effective));
        if effective.is_empty() {
            continue;
        }

        // Section?
        if let Some(section) = parse_section_line(effective)? {
            // Commit previous task before switching.
            if let Some(name) = current_task_name.take() {
                topology
                    .push_task_profiled(
                        name,
                        current_task_class,
                        current_task_priority,
                        &current_task_caps[..current_task_caps_len],
                        current_task_profile,
                    )
                    .map_err(ParseError::Admission)?;
                topology.set_last_task_mem_pages(current_task_mem_pages);
                topology.set_last_task_mem_locked(current_task_mem_locked);
                topology.set_last_task_sqpoll_idle_ms(current_task_sqpoll_idle_ms);
                if current_task_instances != 0 {
                    topology.set_last_task_instances(current_task_instances);
                }
                topology.set_last_task_start(current_task_start);
                topology.set_last_task_lease_seal(current_task_lease_seal);
                topology.set_last_task_restart(current_task_restart);
                topology.set_last_task_abi(current_task_abi).map_err(ParseError::Admission)?;
                current_task_abi = TaskAbi::Native;
                if current_task_mem_huge_mib != 0
                    && !topology.set_last_task_mem_huge_mib(current_task_mem_huge_mib)
                {
                    return Err(ParseError::BadValue);
                }
                current_task_mem_huge_mib = 0;
                current_task_restart = RestartPolicy::OnFailure;
                current_task_mem_pages = 0;
                current_task_mem_locked = false;
                current_task_sqpoll_idle_ms = 0;
                current_task_instances = 0;
                current_task_start = false;
                current_task_lease_seal = false;
                current_task_caps_len = 0;
                current_task_class = MaybeStr::from_bytes(b"best_effort");
                current_task_priority = 0;
                current_task_profile = crate::deadline::SchedProfile::NONE;
            }
            if let Some((name, kb)) = current_pipeline.take() {
                topology.push_pipeline(name, kb.div_ceil(4)).map_err(ParseError::Admission)?;
            }
            match section {
                Section::Pipeline(name) => {
                    current_task_name = None;
                    current_pipeline = Some((MaybeStr::from_bytes(name), 0));
                }
                Section::Task(name) => {
                    current_task_name = Some(MaybeStr::from_bytes(name));
                }
                Section::Class(_) | Section::Sched | Section::Energy | Section::EnergyDomain => {
                    // CAPS.TOML doesn't own these sections — silently
                    // skip; SCHED.TOML parser will pick them up.
                    current_task_name = None;
                }
                Section::Operator => {
                    // CAPS.TOML DOES own this one — it is a capability-
                    // adjacent authority, signed under the same `.SIG` as
                    // every `[task.*]` grant. No task is open, so there is
                    // nothing to commit.
                    current_task_name = None;
                }
            }
            current_section = Some(section);
            continue;
        }

        // Otherwise it's a kv line within a section.
        match current_section {
            Some(Section::Task(_)) => {
                handle_task_kv(
                    &mut rest,
                    effective,
                    &mut current_task_caps,
                    &mut current_task_caps_len,
                    &mut current_task_class,
                    &mut current_task_priority,
                    &mut current_task_profile,
                    &mut current_task_mem_pages,
                    &mut current_task_mem_locked,
                    &mut current_task_sqpoll_idle_ms,
                    &mut current_task_instances,
                    &mut current_task_start,
                    &mut current_task_mem_huge_mib,
                    &mut current_task_lease_seal,
                    &mut current_task_restart,
                    &mut current_task_abi,
                    binding.format,
                )?;
            }
            Some(Section::Operator) => {
                handle_operator_kv(effective, topology)?;
            }
            Some(Section::Pipeline(_)) => {
                if let Some((_, kb)) = current_pipeline.as_mut() {
                    handle_pipeline_kv(effective, kb)?;
                }
            }
            // Wave 11: `format = N` before the first section. Once, and only
            // a format this parser knows.
            None => {
                top_level_line(effective, &mut binding, &mut format_declared)?;
            }
            // KV outside a recognised section is ignored.
            _ => {}
        }
    }

    // Commit the last task.
    if let Some(name) = current_task_name {
        topology
            .push_task_profiled(
                name,
                current_task_class,
                current_task_priority,
                &current_task_caps[..current_task_caps_len],
                current_task_profile,
            )
            .map_err(ParseError::Admission)?;
        topology.set_last_task_mem_pages(current_task_mem_pages);
        topology.set_last_task_mem_locked(current_task_mem_locked);
        topology.set_last_task_sqpoll_idle_ms(current_task_sqpoll_idle_ms);
        if current_task_instances != 0 {
            topology.set_last_task_instances(current_task_instances);
        }
        topology.set_last_task_start(current_task_start);
        topology.set_last_task_lease_seal(current_task_lease_seal);
        topology.set_last_task_restart(current_task_restart);
        topology.set_last_task_abi(current_task_abi).map_err(ParseError::Admission)?;
        if current_task_mem_huge_mib != 0
            && !topology.set_last_task_mem_huge_mib(current_task_mem_huge_mib)
        {
            return Err(ParseError::BadValue);
        }
    }
    if let Some((name, kb)) = current_pipeline {
        topology.push_pipeline(name, kb.div_ceil(4)).map_err(ParseError::Admission)?;
    }

    // Over the whole topology, not only the tasks this file added.
    if motor_write_conflict(topology).is_some() {
        return Err(ParseError::MotorWriteConflict);
    }

    Ok(())
}

/// `Some(N)` for a `format = N` line, `None` for any other key (ignored, as
/// every key outside a section was before format 2). A `format` line whose
/// value is not an unsigned integer with nothing after it is refused.
fn parse_format_line(line: &[u8]) -> Result<Option<u64>, ParseError> {
    let Ok((key, after)) = take_ident(line) else { return Ok(None) };
    if key != b"format" {
        return Ok(None);
    }
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let (n, tail) = parse_unsigned_int(skip_inline_ws(&after[1..]))?;
    if !skip_inline_ws(tail).is_empty() {
        return Err(ParseError::BadValue);
    }
    Ok(Some(n))
}

/// Find the index of the first un-quoted `#` (start of a comment).
/// Returns `None` if there is no comment on the line.
fn find_comment_start(line: &[u8]) -> Option<usize> {
    let mut in_str = false;
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        if b == b'"' {
            in_str = !in_str;
        } else if b == b'#' && !in_str {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Handle one kv line inside a `[task.NAME]` section.
fn handle_task_kv<'a>(
    rest_in: &mut &'a [u8],
    line: &'a [u8],
    caps: &mut [CapSpec<'a>; MAX_CAPS_PER_TASK_BUF],
    caps_len: &mut usize,
    class_name: &mut MaybeStr<'a>,
    priority: &mut u8,
    profile: &mut crate::deadline::SchedProfile,
    mem_pages: &mut u32,
    mem_locked: &mut bool,
    sqpoll_idle_ms: &mut u32,
    instances: &mut u16,
    start: &mut bool,
    mem_huge_mib: &mut u16,
    lease_seal: &mut bool,
    restart: &mut RestartPolicy,
    abi: &mut TaskAbi,
    format: u8,
) -> Result<(), ParseError> {
    let (key, after) = take_ident(line)?;
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let after = skip_inline_ws(&after[1..]);
    let key_str = core::str::from_utf8(key).map_err(|_| ParseError::Unsupported)?;
    match key_str {
        "caps" => {
            // Either a one-liner `[]` (empty caps) or multi-line array.
            let r = skip_inline_ws(after);
            if !r.starts_with(b"[") {
                return Err(ParseError::BadValue);
            }
            let body_after_bracket = &r[1..];
            // If the rest of the line (after `[`) closes immediately,
            // the array is empty.
            let line_tail = trim_trailing_ws(skip_inline_ws(body_after_bracket));
            if line_tail.starts_with(b"]") {
                return Ok(());
            }
            // Otherwise, accumulate inline tables across subsequent lines
            // until `]`.
            let mut r = body_after_bracket;
            // First, try to parse any inline tables already on this line.
            r = consume_inline_tables_on_line(r, caps, caps_len)?;
            // r now points at the trailing portion of the first line
            // after the inline tables we read; if it's still in array,
            // continue reading subsequent lines.
            // Walk forward until we hit ']'.
            loop {
                let r2 = skip_inline_ws(r);
                if r2.starts_with(b"]") {
                    return Ok(());
                }
                if r2.is_empty() || is_eol(r2[0]) {
                    // EOF guard. `take_line` on an exhausted input returns
                    // `(&[], &[])` — an empty line and an unmoved cursor. A
                    // `caps = [` whose `]` never arrives therefore drove this
                    // loop forever: `r` was set to `b""` below, `continue`
                    // brought us straight back here, `rest_in` never shrank,
                    // and no state changed between iterations. Nothing breaks
                    // that cycle — this is boot-time parsing, so there is no
                    // preemption, no timeout and no watchdog kick to save us;
                    // the board simply never finishes booting. A malformed
                    // topology file must be *rejected*, and a reject that the
                    // operator can see beats a silent hang. Check before
                    // calling `take_line` so the cursor is known to advance.
                    if rest_in.is_empty() {
                        return Err(ParseError::UnterminatedArray);
                    }
                    // Move to next line.
                    let (next_line, next) = take_line(*rest_in);
                    *rest_in = next;
                    let mut nl = next_line;
                    if let Some(idx) = find_comment_start(nl) {
                        nl = &nl[..idx];
                    }
                    let nl = skip_inline_ws(nl);
                    let nl = trim_trailing_ws(nl);
                    if nl.is_empty() {
                        r = b"";
                        continue;
                    }
                    if nl.starts_with(b"]") {
                        return Ok(());
                    }
                    r = consume_inline_tables_on_line(nl, caps, caps_len)?;
                    continue;
                }
                // Otherwise the line had stray characters.
                return Err(ParseError::UnterminatedArray);
            }
        }
        "class" => {
            let (s, _) = parse_quoted_string(after, crate::types::MAX_TASK_NAME_LEN)?;
            *class_name = MaybeStr::from_bytes(s);
            Ok(())
        }
        "priority" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n > 255 {
                return Err(ParseError::BadValue);
            }
            *priority = n as u8;
            Ok(())
        }
        // Owner decision 102 — this task's budget of 4 KiB frames. Omitted or
        // `0` means no limit. Rejected rather than truncated when it does not
        // fit a `u32`, for the same reason the real-time fields are: a budget
        // that wrapped is a different budget, and this one decides whether a
        // task can allocate at all.
        "mem_pages" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n > u32::MAX as u64 {
                return Err(ParseError::BadValue);
            }
            *mem_pages = n as u32;
            Ok(())
        }
        // RFC-0049 P1/P2: `"locked"` makes `mem_pages` a reservation and
        // takes fork and demand paging away from the task; `"ceiling"` is the
        // default, said explicitly. Anything else is refused rather than read
        // as the default: a typo in the word that decides whether a control
        // task may fault must not boot as "may fault".
        "mem" => {
            let (v, _) = parse_quoted_string(after, crate::types::MAX_TASK_NAME_LEN)?;
            *mem_locked = match v {
                b"locked" => true,
                b"ceiling" => false,
                _ => return Err(ParseError::UnknownEnumValue),
            };
            Ok(())
        }
        // Kconfig LOCKED_HUGE_LEAVES (riscv64): MiB of this locked row mapped
        // with 2 MiB leaves. Even, at most `MAX_HUGE_MIB`: refused rather
        // than rounded, because the size is what admission reserves and what
        // the task is told it has. Whether the row is locked, and whether the
        // kernel was built with the option, is decided at admission / boot.
        "mem_huge_mib" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n == 0 || n % 2 != 0 || n > crate::types::MAX_HUGE_MIB as u64 {
                return Err(ParseError::BadValue);
            }
            *mem_huge_mib = n as u16;
            Ok(())
        }
        // RFC-0049 M1, wave 9: live instances of this row. 1..=MAX_TASKS;
        // 0 or more than the task pool can hold is refused, not clamped: an
        // instance count admission cannot honour is not a smaller one.
        "instances" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n == 0 || n > crate::types::MAX_TASKS as u64 {
                return Err(ParseError::BadValue);
            }
            *instances = n as u16;
            Ok(())
        }
        // May this task start an io_ring SQ poller, and how long does it poll
        // an empty queue before parking. Omitted or `0`: it may not. Rejected
        // rather than truncated past `u32`, as `mem_pages` is.
        "sqpoll_idle_ms" => {
            let (n, _) = parse_unsigned_int(after)?;
            *sqpoll_idle_ms = u32::try_from(n).map_err(|_| ParseError::BadValue)?;
            Ok(())
        }
        // Wave 9: the kernel starts this image at boot. `true` or `false`
        // only, as `transfer`; a row that says nothing is not started.
        // Nothing may follow the word: `start = trueish` is refused, not read
        // as `true`.
        "start" => {
            let (b, tail) = parse_bool(after)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            *start = b;
            Ok(())
        }
        // Wave 11 (LEASE3): every lease this task grants must be sealed
        // (`LEASE_GRANT_SEAL`). `true` or `false` only, as `start`. A
        // format-2 key, as `restart`: in a format-1 file it is refused, not
        // read, because that file's writer did not mean it.
        "lease_seal" => {
            if format < 2 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (b, tail) = parse_bool(after)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            *lease_seal = b;
            Ok(())
        }
        // Wave 11 (format 2): what the supervisor does when a supervised task
        // of this row ends: "always", "on-failure" (the default) or "no".
        // In a format-1 file the key is refused, not read: that file's
        // writer did not mean it. Nothing may follow the value.
        "restart" => {
            if format < 2 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (v, tail) = parse_quoted_string(after, crate::types::MAX_TASK_NAME_LEN)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            *restart = RestartPolicy::from_bytes(v).ok_or(ParseError::UnknownEnumValue)?;
            Ok(())
        }
        // Wave 12 (format 3, RFC-0047): the syscall table the image is run
        // against, "native" (the default) or "linux". Refused in a file of
        // an earlier format, as `restart` is in format 1.
        "abi" => {
            if format < 3 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (v, tail) = parse_quoted_string(after, crate::types::MAX_TASK_NAME_LEN)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            *abi = TaskAbi::from_bytes(v).ok_or(ParseError::UnknownEnumValue)?;
            Ok(())
        }
        // Real-time profile, checked for feasibility by `Topology::deadline_admission`.
        // Decimal `u32`s; a value that does not fit is rejected, never truncated,
        // because a period that wrapped is a different schedule.
        "period_us" | "runtime_us" | "deadline_us" | "cpu_mask" => {
            let (n, _) = parse_unsigned_int(after)?;
            let n = u32::try_from(n).map_err(|_| ParseError::BadValue)?;
            match key_str {
                "period_us" => profile.period_us = n,
                "runtime_us" => profile.runtime_us = n,
                "deadline_us" => profile.deadline_us = n,
                _ => profile.cpu_mask = n,
            }
            Ok(())
        }
        _ => Err(ParseError::UnknownField),
    }
}

/// One kv line inside a `[pipeline.NAME]` section. The only key is `dma_kb`,
/// the contiguous DMA memory the pipeline needs, in KiB (a `u32`; larger is
/// refused, never truncated).
fn handle_pipeline_kv(line: &[u8], dma_kb: &mut u32) -> Result<(), ParseError> {
    let (key, after) = take_ident(line)?;
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let after = skip_inline_ws(&after[1..]);
    match key {
        b"dma_kb" => {
            let (n, _) = parse_unsigned_int(after)?;
            *dma_kb = u32::try_from(n).map_err(|_| ParseError::BadValue)?;
            Ok(())
        }
        _ => Err(ParseError::UnknownField),
    }
}

/// Consume zero or more `{ ... },` blocks on a single line. Returns
/// the rest of the line after the last closing `}` (which may be
/// followed by `,` or `]` or whitespace + EOL).
fn consume_inline_tables_on_line<'a>(
    mut input: &'a [u8],
    caps: &mut [CapSpec<'a>; MAX_CAPS_PER_TASK_BUF],
    caps_len: &mut usize,
) -> Result<&'a [u8], ParseError> {
    loop {
        let r = skip_inline_ws(input);
        if r.is_empty() || r[0] != b'{' {
            return Ok(r);
        }
        let (fields, n_fields, after) = parse_inline_table(r)?;
        let cap = cap_spec_from_inline(&fields[..n_fields])?;
        if *caps_len >= MAX_CAPS_PER_TASK_BUF {
            return Err(ParseError::TooManyCapsPerTask);
        }
        caps[*caps_len] = cap;
        *caps_len += 1;
        let after = skip_inline_ws(after);
        if after.starts_with(b",") {
            input = &after[1..];
            continue;
        }
        return Ok(after);
    }
}

/// Parse `SCHED.TOML` content into the topology.
pub fn parse_sched<'a>(
    input: &'a [u8],
    topology: &mut Topology<'a>,
) -> Result<(), ParseError> {
    let mut current_section: Option<Section<'_>> = None;
    let mut current_class_name: Option<MaybeStr<'a>> = None;
    let mut staged = ClassSpec::empty();
    let mut sched_cfg = SchedConfig::DEFAULT;

    let mut rest: &'a [u8] = input;
    while !rest.is_empty() {
        let (line, next) = take_line(rest);
        rest = next;
        let mut effective = line;
        if let Some(idx) = find_comment_start(effective) {
            effective = &effective[..idx];
        }
        let effective = trim_trailing_ws(skip_inline_ws(effective));
        if effective.is_empty() {
            continue;
        }
        if let Some(section) = parse_section_line(effective)? {
            // Commit previous class if applicable.
            if let Some(name) = current_class_name.take() {
                staged.name = name;
                topology
                    .push_class(staged)
                    .map_err(ParseError::Admission)?;
                staged = ClassSpec::empty();
            }
            match section {
                Section::Class(name) => {
                    current_class_name = Some(MaybeStr::from_bytes(name));
                }
                Section::Sched
                | Section::Task(_)
                | Section::Operator
                | Section::Pipeline(_)
                | Section::Energy
                | Section::EnergyDomain => {
                    // `[operator]` belongs to CAPS.TOML (see `parse_caps`);
                    // SCHED.TOML ignores it exactly as it already ignores
                    // `[task.*]`. The energy sections are SCHED.TOML's, read
                    // by `parse_energy` in a pass of their own below.
                    current_class_name = None;
                }
            }
            current_section = Some(section);
            continue;
        }
        match current_section {
            Some(Section::Class(_)) => {
                handle_class_kv(effective, &mut staged)?;
            }
            Some(Section::Sched) => {
                handle_sched_kv(effective, &mut sched_cfg)?;
            }
            _ => {}
        }
    }
    if let Some(name) = current_class_name {
        staged.name = name;
        topology
            .push_class(staged)
            .map_err(ParseError::Admission)?;
    }
    topology.set_sched_config(sched_cfg);
    // RFC-0051 E2. Without the `energy` feature the sections were skipped
    // above and nothing reads them: the kernel runs with no model (I4).
    #[cfg(feature = "energy")]
    topology.set_energy(parse_energy(input)?);
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// Energy model (RFC-0051 E2)
// ──────────────────────────────────────────────────────────────────────────

/// Read the energy sections of a `SCHED.TOML`; every other section is
/// skipped. `parse_sched` calls it on the same text; the built-in topology's
/// fake model (`energy-fake-model`) goes through it too.
///
/// ```toml
/// [energy]
/// mode = "performance"            # | "balanced" | "endurance"; default performance
///
/// [energy.domain.little]          # NAME is for the reader; order is what counts
/// cpus = 1                        # bit n = CPU n, like a profile's cpu_mask
/// wcet_ref_khz = 600000           # optional (I6): clock the safety WCETs hold at
/// opps = [                        # slowest first
///   { freq_khz = 600000, capacity = 300, power_mw = 60 },
///   { freq_khz = 1200000, capacity = 600, power_mw = 200 },
/// ]
/// idle = [                        # shallowest first; power_mw optional
///   { name = "wfi", exit_latency_us = 1, target_residency_us = 1, power_mw = 20 },
/// ]
/// ```
///
/// Only the syntax and each value's range are checked here; whether the
/// model is consistent (and fits the machine) is
/// `azos_energy::EnergyModel::validate`'s question, asked at boot.
/// Domains are kept in declaration order.
#[cfg(feature = "energy")]
pub fn parse_energy(input: &[u8]) -> Result<azos_energy::EnergySpec, ParseError> {
    use azos_energy::{EnergyMode, EnergyModel, EnergySpec, ModelSource, PerfDomain};
    let mut spec = EnergySpec::DEFAULT;
    let mut model = EnergyModel::NONE;
    let mut section: Option<Section<'_>> = None;
    let mut rest: &[u8] = input;
    while !rest.is_empty() {
        let (line, next) = take_line(rest);
        rest = next;
        let mut effective = line;
        if let Some(idx) = find_comment_start(effective) {
            effective = &effective[..idx];
        }
        let effective = trim_trailing_ws(skip_inline_ws(effective));
        if effective.is_empty() {
            continue;
        }
        if let Some(sec) = parse_section_line(effective)? {
            if sec == Section::EnergyDomain {
                model.source = ModelSource::Topology;
                model.push_domain(PerfDomain::new(0)).map_err(|_| ParseError::TooManyEnergyEntries)?;
            }
            section = Some(sec);
            continue;
        }
        match section {
            Some(Section::Energy) => {
                let (key, value) = split_kv(effective)?;
                match key {
                    b"mode" => {
                        let (s, _) = parse_quoted_string(value, 16)?;
                        spec.mode = EnergyMode::from_str(s).ok_or(ParseError::UnknownEnumValue)?;
                    }
                    _ => return Err(ParseError::UnknownField),
                }
            }
            Some(Section::EnergyDomain) => {
                let (key, value) = split_kv(effective)?;
                let d = model.last_domain_mut().ok_or(ParseError::BadValue)?;
                match key {
                    b"cpus" => {
                        let (n, _) = parse_unsigned_int(value)?;
                        d.cpus = u32::try_from(n).map_err(|_| ParseError::BadValue)?;
                    }
                    b"wcet_ref_khz" => {
                        let (n, _) = parse_unsigned_int(value)?;
                        d.wcet_ref_khz = u32::try_from(n).map_err(|_| ParseError::BadValue)?;
                    }
                    b"opps" => parse_table_array(&mut rest, value, |f| {
                        let opp = azos_energy::Opp {
                            freq_khz: field_int(f, b"freq_khz", u32::MAX as u64)?.ok_or(ParseError::MissingField)? as u32,
                            capacity: field_int(f, b"capacity", u16::MAX as u64)?.ok_or(ParseError::MissingField)? as u16,
                            power_mw: field_int(f, b"power_mw", u32::MAX as u64)?.ok_or(ParseError::MissingField)? as u32,
                        };
                        only_fields(f, &[b"freq_khz", b"capacity", b"power_mw"])?;
                        d.push_opp(opp).map_err(|_| ParseError::TooManyEnergyEntries)
                    })?,
                    b"idle" => parse_table_array(&mut rest, value, |f| {
                        let name = f.iter().find(|(k, _)| k.as_bytes() == b"name").map(|(_, v)| *v);
                        let name = match name {
                            Some(InlineValue::Str(s)) if !s.is_empty() => s,
                            Some(_) => return Err(ParseError::TypeMismatch),
                            None => return Err(ParseError::MissingField),
                        };
                        let st = azos_energy::IdleState::new(
                            name,
                            field_int(f, b"exit_latency_us", u32::MAX as u64)?.ok_or(ParseError::MissingField)? as u32,
                            field_int(f, b"target_residency_us", u32::MAX as u64)?.ok_or(ParseError::MissingField)? as u32,
                            field_int(f, b"power_mw", u32::MAX as u64)?.unwrap_or(0) as u32,
                        );
                        only_fields(f, &[b"name", b"exit_latency_us", b"target_residency_us", b"power_mw"])?;
                        d.push_idle(st).map_err(|_| ParseError::TooManyEnergyEntries)
                    })?,
                    _ => return Err(ParseError::UnknownField),
                }
            }
            _ => {}
        }
    }
    spec.model = model;
    Ok(spec)
}

/// `key = value` → `(key, value)`, `value` starting at its first byte.
#[cfg(feature = "energy")]
fn split_kv(line: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let (key, after) = take_ident(line)?;
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    Ok((key, skip_inline_ws(&after[1..])))
}

/// The integer field `key` of an inline table, at most `max`; `None` if absent.
#[cfg(feature = "energy")]
fn field_int(fields: &[(MaybeStr<'_>, InlineValue<'_>)], key: &[u8], max: u64) -> Result<Option<u64>, ParseError> {
    match fields.iter().find(|(k, _)| k.as_bytes() == key) {
        None => Ok(None),
        Some((_, InlineValue::Int(n))) if *n <= max => Ok(Some(*n)),
        Some((_, InlineValue::Int(_))) => Err(ParseError::BadValue),
        Some(_) => Err(ParseError::TypeMismatch),
    }
}

/// Every field of an inline table is one of `known`, and none repeats.
#[cfg(feature = "energy")]
fn only_fields(fields: &[(MaybeStr<'_>, InlineValue<'_>)], known: &[&[u8]]) -> Result<(), ParseError> {
    for (i, (k, _)) in fields.iter().enumerate() {
        if !known.contains(&k.as_bytes()) {
            return Err(ParseError::UnknownField);
        }
        if fields[..i].iter().any(|(p, _)| p.as_bytes() == k.as_bytes()) {
            return Err(ParseError::BadValue);
        }
    }
    Ok(())
}

/// An array of inline tables, `[ {..}, {..} ]`, on one line or over several
/// (one or more tables per line, trailing comma allowed, comments and blank
/// lines skipped). `value` is the text after `=`; continuation lines are taken
/// from `rest`. `each` sees every table's fields. EOF before `]` is
/// `UnterminatedArray`, never a hang (see `handle_task_kv`'s `caps`).
#[cfg(feature = "energy")]
fn parse_table_array<'a, F>(rest: &mut &'a [u8], value: &'a [u8], mut each: F) -> Result<(), ParseError>
where
    F: FnMut(&[(MaybeStr<'a>, InlineValue<'a>)]) -> Result<(), ParseError>,
{
    let v = skip_inline_ws(value);
    if !v.starts_with(b"[") {
        return Err(ParseError::BadValue);
    }
    let mut cur: &'a [u8] = &v[1..];
    loop {
        let mut r = skip_inline_ws(cur);
        // Tables on the current line.
        while r.starts_with(b"{") {
            let (fields, n, after) = parse_inline_table(r)?;
            each(&fields[..n])?;
            r = skip_inline_ws(after);
            if r.starts_with(b",") {
                r = skip_inline_ws(&r[1..]);
            }
        }
        if r.starts_with(b"]") {
            let tail = skip_inline_ws(&r[1..]);
            if tail.is_empty() || tail[0] == b'#' || is_eol(tail[0]) {
                return Ok(());
            }
            return Err(ParseError::BadValue);
        }
        if !(r.is_empty() || r[0] == b'#' || is_eol(r[0])) {
            return Err(ParseError::UnterminatedArray);
        }
        if rest.is_empty() {
            return Err(ParseError::UnterminatedArray);
        }
        let (next_line, next) = take_line(rest);
        *rest = next;
        let mut nl = next_line;
        if let Some(idx) = find_comment_start(nl) {
            nl = &nl[..idx];
        }
        cur = trim_trailing_ws(nl);
    }
}

fn handle_class_kv<'a>(line: &'a [u8], staged: &mut ClassSpec<'a>) -> Result<(), ParseError> {
    let (key, after) = take_ident(line)?;
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let after = skip_inline_ws(&after[1..]);
    let key = core::str::from_utf8(key).map_err(|_| ParseError::Unsupported)?;
    match key {
        "cpu_budget_min_pct" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n > 100 {
                return Err(ParseError::BadValue);
            }
            staged.cpu_budget_min_pct = n as u8;
        }
        "cpu_budget_max_pct" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n > 100 {
                return Err(ParseError::BadValue);
            }
            staged.cpu_budget_max_pct = n as u8;
        }
        "policy" => {
            let (s, _) = parse_quoted_string(after, 16)?;
            let s = core::str::from_utf8(s).map_err(|_| ParseError::Unsupported)?;
            staged.policy = PolicyKind::from_str(s).ok_or(ParseError::UnknownEnumValue)?;
        }
        "priority_range" => {
            let (lo, hi, _) = parse_range(after)?;
            staged.priority_range = (lo, hi);
        }
        "preemption" => {
            let (s, _) = parse_quoted_string(after, 16)?;
            let s = core::str::from_utf8(s).map_err(|_| ParseError::Unsupported)?;
            staged.preemption = Preemption::from_str(s).ok_or(ParseError::UnknownEnumValue)?;
        }
        "time_slice_ms" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n > u16::MAX as u64 {
                return Err(ParseError::BadValue);
            }
            staged.time_slice_ms = n as u16;
        }
        "admission_control" => {
            let (b, _) = parse_bool(after)?;
            staged.admission_control = b;
        }
        _ => return Err(ParseError::UnknownField),
    }
    Ok(())
}

fn handle_sched_kv(line: &[u8], cfg: &mut SchedConfig) -> Result<(), ParseError> {
    let (key, after) = take_ident(line)?;
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let after = skip_inline_ws(&after[1..]);
    let key = core::str::from_utf8(key).map_err(|_| ParseError::Unsupported)?;
    match key {
        "partition_window_us" => {
            let (n, _) = parse_unsigned_int(after)?;
            if n > u32::MAX as u64 {
                return Err(ParseError::BadValue);
            }
            cfg.partition_window_us = n as u32;
        }
        _ => return Err(ParseError::UnknownField),
    }
    Ok(())
}

/// Handle one kv line inside `[operator]` — W2-B5.
///
/// Only field: `pubkey = "<64 lowercase or uppercase hex chars>"`, the raw
/// 32-byte Ed25519 public key of the operator who may release an armed
/// e-stop latch (see `azos_behavior::safety::ReleaseAuthority`). Any
/// other field, or a value that is not exactly 64 hex characters, is a
/// parse error rather than a silently-ignored line: this key gates a
/// safety authority, so a malformed declaration must fail closed at
/// *parse* time, not surface later as "every release refused" with no
/// indication why.
fn handle_operator_kv<'a>(
    line: &'a [u8],
    topology: &mut Topology<'a>,
) -> Result<(), ParseError> {
    let (key, after) = take_ident(line)?;
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let after = skip_inline_ws(&after[1..]);
    let key = core::str::from_utf8(key).map_err(|_| ParseError::Unsupported)?;
    match key {
        "pubkey" => {
            let (s, _) = parse_quoted_string(after, 64)?;
            let bytes = parse_hex32(s)?;
            topology.set_operator_pubkey(bytes);
        }
        _ => return Err(ParseError::UnknownField),
    }
    Ok(())
}

/// Decode exactly 64 hex characters into 32 raw bytes.
///
/// No allocation, no `u128` shortcuts (the value is a public key, not a
/// number) — two nibbles at a time, rejecting anything outside
/// `[0-9a-fA-F]` and any length other than exactly 64.
fn parse_hex32(s: &[u8]) -> Result<[u8; 32], ParseError> {
    parse_hex::<32>(s)
}

/// Decode exactly `2 * N` hex characters into `N` bytes.
fn parse_hex<const N: usize>(s: &[u8]) -> Result<[u8; N], ParseError> {
    if s.len() != 2 * N {
        return Err(ParseError::BadValue);
    }
    fn nibble(b: u8) -> Result<u8, ParseError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(ParseError::BadValue),
        }
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = nibble(s[i * 2])?;
        let lo = nibble(s[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

// Avoid unused-import warning when `current_section` is only set, never
// read in a code path the compiler cares about.
#[allow(dead_code)]
fn _unused_section_ref(_s: Section<'_>) {}

#[allow(dead_code)]
fn _unused_skip(_input: &[u8]) -> &[u8] {
    skip_ws_and_comments(_input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Topology;

    /// A `caps = [` array that runs off the end of the file must be
    /// *rejected*, not hung on. Before the EOF guard in `handle_task_kv`
    /// this input span the multi-line-array loop forever: `take_line` on
    /// an exhausted cursor keeps returning an empty line without
    /// advancing, so the loop had no way to terminate. If this test ever
    /// stops returning, the guard was removed — the failure mode is a
    /// hang at boot, so the test times out rather than failing loudly.
    #[test]
    fn unterminated_caps_array_is_rejected_not_hung() {
        let mut topo = Topology::empty();
        let caps = b"[task.a]\ncaps = [\n";
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::UnterminatedArray));
    }

    /// Same hazard with no trailing newline at all: `take_line` returns
    /// the final partial line and an empty remainder, so the very next
    /// iteration hits the guard.
    #[test]
    fn unterminated_caps_array_without_trailing_newline_is_rejected() {
        let mut topo = Topology::empty();
        // `gpio`, not `motor` (M40, 2026-09-26): `motor` now requires the
        // `profile-actuation` feature (see `parse_cap_kind`), and this test
        // is about the unterminated-array guard, not about `motor` — using
        // an always-accepted kind keeps it testing the same hazard under
        // either feature set.
        let caps = b"[task.a]\ncaps = [ { kind = \"gpio\", target = \"gpio.0\", perm = \"rw\" },";
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::UnterminatedArray));
    }

    /// The guard must not reject well-formed multi-line arrays: the
    /// closing `]` arrives on its own line, several blank/comment lines
    /// after the last inline table.
    #[test]
    fn multi_line_caps_array_still_parses() {
        let mut topo = Topology::empty();
        // `gpio`, not `motor` — same M40 reason as the test above.
        let caps = b"[task.a]\ncaps = [\n  { kind = \"gpio\", target = \"gpio.0\", perm = \"rw\" },\n\n  # trailing comment\n]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert_eq!(topo.tasks_len(), 1);
    }

    // ── M40 (U10-6, 2026-09-26): "motor" requires profile-actuation ────
    //
    // Mirrors `builder.rs`'s existing `autorun_task_declares_both_
    // drivetrain_motor_grants` test, which already runs this same file
    // twice under CI (`tools/ci_check.sh`'s "topology-tests" row with no
    // features, and its "topology(cap-canary)" row with
    // `cap-refusal-canary,profile-actuation`) — one test body, two
    // opposite assertions selected by the SAME cfg the parser itself uses.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn motor_cap_kind_parses_under_profile_actuation() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"motor\", target = \"motor.0\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert_eq!(topo.caps_of(&topo.tasks()[0])[0].kind, CapKind::Motor);
    }

    #[cfg(not(feature = "profile-actuation"))]
    #[test]
    fn motor_cap_kind_refused_without_profile_actuation() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"motor\", target = \"motor.0\", perm = \"rw\" } ]\n";
        // Not `NoMinter`-shaped silence — a parse-time refusal, so a
        // topology asking for something this build cannot honour is
        // rejected before it is ever admitted, not silently capless.
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::UnknownEnumValue));
    }

    // ── W2-B5 task 2 (U03-2): `Cap<Irq>` declaration is parser-ready ───
    //
    // `crates/core/ipc/src/cap_seed.rs` has no minter arm for `CapKind::Irq`
    // (A2's side of this gap — `seed_one_cap(.., CapKind::Irq, .., "irq.3")`
    // returns `None` today, by that crate's own test). This proves the
    // OTHER half is not the blocker: a topology can already DECLARE an IRQ
    // grant end-to-end through the real parser, with the "irq.<N>" target
    // convention `cap_seed.rs`'s own tests already assume, so the day a
    // minter arm is added there, nothing on the declaration side needs to
    // change.
    #[test]
    fn irq_cap_declaration_parses_end_to_end() {
        let mut topo = Topology::empty();
        let caps = b"[task.gpio_drv]\ncaps = [ { kind = \"irq\", target = \"irq.5\", perm = \"r\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert_eq!(topo.tasks_len(), 1);
        let task = &topo.tasks()[0];
        let cap_list = topo.caps_of(task);
        assert_eq!(cap_list.len(), 1);
        assert_eq!(cap_list[0].kind, CapKind::Irq);
        assert_eq!(cap_list[0].perms, CapPerms::READ);
        assert_eq!(cap_list[0].target, MaybeStr::from_bytes(b"irq.5"));
    }

    // ── O3.4 (owner decision 2026-09-26): `transfer` key ────────────────

    /// `transfer` defaults to `false` when absent — a row hands out
    /// authority to move the capability only when it says so explicitly.
    #[test]
    fn cap_transfer_defaults_to_false() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"channel\", target = \"7\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert!(!topo.caps_of(&topo.tasks()[0])[0].transfer);
    }

    /// `transfer = true` is read through and sets the field.
    #[test]
    fn cap_transfer_true_is_read_through() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"channel\", target = \"7\", perm = \"rw\", transfer = true } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert!(topo.caps_of(&topo.tasks()[0])[0].transfer);
    }

    /// A non-boolean `transfer` value is a type error, not a silent `false`.
    #[test]
    fn cap_transfer_non_bool_is_rejected() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"channel\", target = \"7\", perm = \"rw\", transfer = \"yes\" } ]\n";
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::TypeMismatch));
    }

    // ── W2-B5: `[operator]` section ────────────────────────────────────

    // The 64 hex chars spell out bytes 0x01..=0x20 (32 consecutive
    // values) in order, so the expected array is independently checkable
    // by eye against the string, not a copy-paste of it.
    const OP_TOML: &[u8] = concat!(
        "[operator]\npubkey = \"",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "\"\n"
    )
    .as_bytes();
    const OP_BYTES: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    #[test]
    fn operator_section_decodes_pubkey() {
        let mut topo = Topology::empty();
        assert!(parse_caps(OP_TOML, &mut topo).is_ok());
        assert_eq!(topo.operator_pubkey(), OP_BYTES);
        assert!(topo.has_operator_pubkey());
    }

    /// A default (no `[operator]` section) topology declares no key —
    /// the all-zero sentinel `operator_authority_init` already treats as
    /// "no release authority provisioned".
    #[test]
    fn absent_operator_section_leaves_key_zero() {
        let topo = Topology::empty();
        assert_eq!(topo.operator_pubkey(), [0u8; 32]);
        assert!(!topo.has_operator_pubkey());
    }

    /// 63 hex characters (one short) must be a parse error, not a
    /// silently zero-padded or truncated key — a malformed release
    /// authority must fail loudly at parse time, before boot ever
    /// reaches "every release refused" with no indication why.
    #[test]
    fn operator_pubkey_wrong_length_is_rejected() {
        let mut topo = Topology::empty();
        // 63 hex chars — one short of the required 64.
        let caps = b"[operator]\npubkey = \"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2\"\n";
        assert_eq!(caps.len(), b"[operator]\npubkey = \"".len() + 63 + b"\"\n".len());
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::BadValue));
    }

    /// Exactly 64 characters, but the first pair is not hex — must fail
    /// in the nibble decode, not the length check.
    #[test]
    fn operator_pubkey_non_hex_is_rejected() {
        let mut topo = Topology::empty();
        let caps = b"[operator]\npubkey = \"zz02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\"\n";
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::BadValue));
    }

    /// An unknown field inside `[operator]` is a parse error, matching
    /// every other section's schema-strictness.
    #[test]
    fn operator_section_unknown_field_is_rejected() {
        let mut topo = Topology::empty();
        let caps = b"[operator]\nbogus = \"x\"\n";
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::UnknownField));
    }

    /// `SCHED.TOML` does not own `[operator]` — it must be silently
    /// skipped there, exactly as `[task.*]` already is, not rejected as
    /// `UnknownSection`.
    #[test]
    fn sched_toml_ignores_operator_section() {
        let mut topo = Topology::empty();
        const TOML: &[u8] = concat!(
            "[operator]\npubkey = \"",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "\"\n[sched]\npartition_window_us = 5000\n"
        )
        .as_bytes();
        assert!(parse_sched(TOML, &mut topo).is_ok());
        // Not parsed — CAPS.TOML owns it, and this input never called
        // `parse_caps`.
        assert_eq!(topo.operator_pubkey(), [0u8; 32]);
        assert_eq!(topo.sched_config().partition_window_us, 5000);
    }
}
