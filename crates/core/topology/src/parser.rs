// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hand-rolled TOML subset parser.
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
//!       { kind = "queue", target = "7", perm = "w" },
//!       { kind = "endpoint", target = "gpio.3", perm = "r" },
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
    BuildId, CapSpec, ClassSpec, DegradeSpec, DeviceSpec, Envelope, FirewallSpec, FwAction, FwDir, FwProto, GuestSpec, IpAddr, IpPrefix, LeapEntry, RouteSpec, LOGIN_KEYS, SwapSpec, VolumeSpec, LivepatchSpec, MaybeStr, PatchIsa, PolicyKind, PolicyScope,
    PolicySpec, Preemption, PrincipalKind, RestartPolicy, SchedConfig, TaskAbi, Topology,
    ActivitySpec, ActivityTrigger, AudioDir, AudioSpec, BootChainSpec, DisplaySpec, EffectKind, EnvelopeSpec, FieldbusKind,
    FieldbusSpec, IslandSpec, KeyPurpose, KeySource, KeySpec, MissionSpec, ModelSpec, NicSpec, NumaSpec, RtcSpec,
    TsnSpec, UsbAuthorize, UsbSpec, UserSpec,
};
use crate::placement::{Host, PlaceSpec};
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
    /// (only 1 to [`CAPS_FORMAT_MAX`] exist), or appears twice.
    UnsupportedFormat,
    /// A key that exists only from a later format (`restart`:
    /// format 2; `abi`: format 3; `imports`, `timer_slack`: format 5; a `[device.NAME]`, `[signer.NAME]` or `[peer.NAME]` section, `export`, `place`, `stateless`, `call_budget_us`: format 6; `shadow`, `isolated`, `kmem_kib`, the device keys `safe_state`, `commit_ns`, `compensate`, the peer keys `noise_pk` and `measurement`: format 7) in a file that did not declare it: the writer and this reader would not
    /// agree on what the file says.
    FieldNeedsFormat,
    /// More energy domains, OPPs per domain or idle states per
    /// domain than `azos_energy`'s fixed pools hold.
    TooManyEnergyEntries,
}

/// The CAPS.TOML formats this parser reads. A file with no `format = N`
/// line before its first section is format 1 (every topology written before
/// wave 11). Format 2 adds the task key `restart`; format 3
/// adds the task key `abi`; format 4 (wave 15) adds the
/// top-level binding keys `device`, `counter` and `sched_sha256` ([`Binding`]);
/// format 6 adds the `[device.NAME]` sections (what the hardware bus does with
/// the devices they select); format 5 adds the task keys `imports`, the endpoint names the name server
/// may hand the row, and `timer_slack`, whether the row's task may have its
/// timers coalesced by its QoS tier; format 6 also adds the placement keys
/// `place`, `stateless` and `call_budget_us` ([`crate::placement::PlaceSpec`]),
/// the `[signer.NAME]` sections, the package signers the device admits, the
/// `[peer.NAME]` sections (classes of remote nodes) and the task key `export`,
/// the endpoints the RPC server's row may lend to a class. Format 7 (TOPO-ROWS-A
/// and B, wave 11) adds the task keys `shadow`, `isolated` and `kmem_kib`, the
/// device keys `safe_state`, `commit_ns` and `compensate`, the peer keys
/// `noise_pk` and `measurement` and the sections the `Section` enum lists.
/// Format 8 (TOPO-ROWS-C) adds the task keys `security_boundary` and
/// `partition_id`, the guest keys `passthrough`, `static`, `pcpus` and
/// `mem_base`, and the sections of [`Kind8`]. The new
/// SCHED.TOML keys (`isolcpus`, a class's `envelope` and `principal`) carry no
/// format: that file has none, and its hash is bound by the signed CAPS.TOM.
pub const CAPS_FORMAT_MAX: u8 = 8;

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

/// The first task holding `WRITE` on the `flight` endpoint without `WRITE` on
/// both wheels of the drivetrain, if any.
///
/// **Flight is pair-wide** (the console's `flight arm` rule, wave 12): arming
/// the flight controller and the ESCs is authority over every motor, so only
/// the row that may command the whole drivetrain may hold the endpoint's
/// `WRITE`. The endpoint is a kernel-hosted interface and no longer shares a
/// kind with the motors, so the topology is where the old pair check lives.
/// A `READ`-only grant arms nothing and is free.
pub fn flight_without_drivetrain(topology: &Topology<'_>) -> Option<usize> {
    for (t, task) in topology.tasks().iter().enumerate() {
        let caps = topology.caps_of(task);
        let flies = caps.iter().any(|c| {
            c.kind == CapKind::Endpoint && c.perms.contains(CapPerms::WRITE) && c.target.as_str() == "flight"
        });
        if flies && !(0..2).all(|id| caps.iter().any(|c| motor_write_id(c) == Some(id))) {
            return Some(t);
        }
    }
    None
}

/// The wheel a WRITE-bearing `motor.<wheel>` endpoint grant names; `None` for
/// anything else (other kinds, other interfaces, a `READ`-only grant).
fn motor_write_id(cap: &CapSpec<'_>) -> Option<u32> {
    if cap.kind != CapKind::Endpoint || !cap.perms.contains(CapPerms::WRITE) {
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
/// processing for the supported subset (topology fields are simple
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

/// A quoted string with nothing after it, at most `max_len` bytes.
fn quoted_only<'a>(value: &'a [u8], max_len: usize) -> Result<&'a [u8], ParseError> {
    let (v, tail) = parse_quoted_string(value, max_len)?;
    if !skip_inline_ws(tail).is_empty() {
        return Err(ParseError::BadValue);
    }
    Ok(v)
}

/// `true` or `false` with nothing after it.
fn bool_only(value: &[u8]) -> Result<bool, ParseError> {
    let (b, tail) = parse_bool(value)?;
    if !skip_inline_ws(tail).is_empty() {
        return Err(ParseError::BadValue);
    }
    Ok(b)
}

/// A decimal integer with nothing after it, at most `max`: a value that does
/// not fit is refused, never truncated (a budget that wrapped is a different
/// budget).
fn uint_only(value: &[u8], max: u64) -> Result<u64, ParseError> {
    let (n, tail) = parse_unsigned_int(value)?;
    if n > max || !skip_inline_ws(tail).is_empty() {
        return Err(ParseError::BadValue);
    }
    Ok(n)
}

/// A quoted hex string of exactly `2 * N` digits with nothing after it.
fn hex_only<const N: usize>(value: &[u8]) -> Result<[u8; N], ParseError> {
    parse_hex::<N>(quoted_only(value, 2 * N)?)
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
    /// `[pipeline.NAME]` — a data path and the DMA pool it
    /// needs (`dma_kb`). CAPS.TOML owns it; `parse_sched` skips it.
    Pipeline(&'a [u8]),
    /// `[device.NAME]` — format 6: what the hardware bus does with the
    /// devices `match` selects. CAPS.TOML owns it; `parse_sched` skips it.
    Device(&'a [u8]),
    /// `[signer.NAME]` — format 6: a package author the device admits and the
    /// ceiling of what the author's packages may ask for. CAPS.TOML owns it;
    /// `parse_sched` skips it.
    Signer(&'a [u8]),
    /// `[peer.NAME]` — format 6: a class of remote nodes (`nodes = [2, 3]`).
    /// CAPS.TOML owns it; `parse_sched` skips it.
    Peer(&'a [u8]),
    /// `[policy.NAME]` — format 7: a limit on a Domain and, with `scope =
    /// "subtree"`, its descendants. CAPS.TOML owns it; `parse_sched` skips it.
    Policy(&'a [u8]),
    /// `[livepatch.NAME]` — format 7: the admission of one signed kernel
    /// patch blob. CAPS.TOML owns it; `parse_sched` skips it.
    Livepatch(&'a [u8]),
    /// `[degrade.NAME]` — format 7: a battery threshold and the degrade level
    /// it enters. CAPS.TOML owns it; `parse_sched` skips it.
    Degrade(&'a [u8]),
    /// `[clock]` — format 7: the PTP domain and the TAI-UTC table. CAPS.TOML
    /// owns it; `parse_sched` skips it.
    Clock,
    /// `[swap.NAME]` — format 7: a swap area on a partition. CAPS.TOML owns
    /// it; `parse_sched` skips it.
    Swap(&'a [u8]),
    /// `[login.NAME]` — format 7: an SSH account and its public keys. CAPS.TOML
    /// owns it; `parse_sched` skips it.
    Login(&'a [u8]),
    /// `[volume.NAME]` — format 7: an azvol native volume and its mount point.
    /// CAPS.TOML owns it; `parse_sched` skips it.
    Volume(&'a [u8]),
    /// `[guest.NAME]` — format 7: a virtual machine. CAPS.TOML owns it;
    /// `parse_sched` skips it.
    Guest(&'a [u8]),
    /// `[route.NAME]` — format 7: a static route. CAPS.TOML owns it;
    /// `parse_sched` skips it.
    Route(&'a [u8]),
    /// `[firewall.NAME]` — format 7: a packet filter rule. CAPS.TOML owns it;
    /// `parse_sched` skips it.
    Firewall(&'a [u8]),
    /// A format-8 section ([`Kind8`]), named or (`mission`, `rtc`) not.
    /// CAPS.TOML owns it; `parse_sched` skips it.
    V8(Kind8, &'a [u8]),
    /// `[energy]` — the energy mode. SCHED.TOML owns it
    /// ([`parse_energy`]); CAPS.TOML skips it.
    Energy,
    /// `[energy.domain.NAME]` — one performance domain of the
    /// energy model. SCHED.TOML owns it; CAPS.TOML skips it.
    EnergyDomain,
}

/// The sections CAPS.TOML format 8 adds. `mission` and `rtc` are written alone;
/// the others as `[kind.NAME]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind8 {
    Tsn,
    Fieldbus,
    Audio,
    Display,
    User,
    Key,
    Mission,
    BootChain,
    Island,
    Activity,
    Numa,
    Envelope,
    Rtc,
    Nic,
    Model,
    Usb,
}

impl Kind8 {
    /// The `[kind.NAME]` sections: the word before the dot.
    const NAMED: [(&'static [u8], Kind8); 14] = [
        (b"tsn.", Kind8::Tsn),
        (b"fieldbus.", Kind8::Fieldbus),
        (b"audio.", Kind8::Audio),
        (b"display.", Kind8::Display),
        (b"user.", Kind8::User),
        (b"key.", Kind8::Key),
        (b"boot_chain.", Kind8::BootChain),
        (b"island.", Kind8::Island),
        (b"activity.", Kind8::Activity),
        (b"numa.", Kind8::Numa),
        (b"envelope.", Kind8::Envelope),
        (b"nic.", Kind8::Nic),
        (b"model.", Kind8::Model),
        (b"usb.", Kind8::Usb),
    ];
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
    } else if let Some(name) = strip_prefix(inner, b"device.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::Device(name)))
    } else if let Some(name) = strip_prefix(inner, b"signer.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::Signer(name)))
    } else if let Some(name) = strip_prefix(inner, b"peer.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::Peer(name)))
    } else if let Some(name) = strip_prefix(inner, b"policy.") {
        Ok(Some(Section::Policy(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"livepatch.") {
        Ok(Some(Section::Livepatch(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"degrade.") {
        Ok(Some(Section::Degrade(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"energy.domain.") {
        let name = trim_trailing_ws(name);
        if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }
        Ok(Some(Section::EnergyDomain))
    } else if let Some(name) = strip_prefix(inner, b"swap.") {
        Ok(Some(Section::Swap(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"login.") {
        Ok(Some(Section::Login(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"volume.") {
        Ok(Some(Section::Volume(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"guest.") {
        Ok(Some(Section::Guest(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"route.") {
        Ok(Some(Section::Route(row_name(name)?)))
    } else if let Some(name) = strip_prefix(inner, b"firewall.") {
        Ok(Some(Section::Firewall(row_name(name)?)))
    } else if let Some((kind, name)) = Kind8::NAMED.iter().find_map(|(w, k)| strip_prefix(inner, w).map(|n| (*k, n))) {
        Ok(Some(Section::V8(kind, row_name(name)?)))
    } else if trim_trailing_ws(inner) == b"mission" {
        Ok(Some(Section::V8(Kind8::Mission, &[])))
    } else if trim_trailing_ws(inner) == b"rtc" {
        Ok(Some(Section::V8(Kind8::Rtc, &[])))
    } else if trim_trailing_ws(inner) == b"clock" {
        Ok(Some(Section::Clock))
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

/// The NAME of a format-7 `[kind.NAME]` section: not empty, at most
/// `MAX_TASK_NAME_LEN` bytes. Its alphabet is the row's to check
/// (`Topology::push_*`).
fn row_name(name: &[u8]) -> Result<&[u8], ParseError> {
    let name = trim_trailing_ws(name);
    if name.is_empty() || name.len() > crate::types::MAX_TASK_NAME_LEN {
        return Err(ParseError::NameTooLong);
    }
    Ok(name)
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
#[derive(Clone, Copy, Debug)]
enum InlineValue<'a> {
    Str(&'a [u8]),
    Int(u64),
    Bool(bool),
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
    // O3.4 (owner decision 2026-09-26): whether this grant carries `DELEGATE`
    // (`DUP` and `TRANSFER`: transferable via `move_cap`). Defaults to `false` below — a row
    // transfers authority only when it says so, never by omission.
    let mut transfer: Option<bool> = None;
    // The ops of a kernel-hosted interface the grant is limited to (bit n = the
    // op numbered n); absent, every op.
    let mut ops: Option<u64> = None;
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
            "ops" => {
                // 0 would read as "no op" and mean "every op": refused.
                match v {
                    InlineValue::Int(n) if *n != 0 => ops = Some(*n),
                    InlineValue::Int(_) => return Err(ParseError::BadValue),
                    _ => return Err(ParseError::TypeMismatch),
                }
            }
            _ => return Err(ParseError::UnknownField),
        }
    }
    let kind = kind.ok_or(ParseError::MissingField)?;
    let perms = perms.unwrap_or(CapPerms::READ);
    let target = target.unwrap_or(MaybeStr::from_bytes(&[]));
    // U10-6 / M40 (2026-09-26): the drivetrain's endpoints (`motor.<wheel>`)
    // exist only in a build with the actuation profile. The seeder refuses
    // them too, but a refusal at parse time tells the OPERATOR that this
    // topology asks for something this build cannot honour, instead of the
    // drivetrain task getting no capabilities at boot with no indication why.
    #[cfg(not(feature = "profile-actuation"))]
    if kind == CapKind::Endpoint && target.as_str().strip_prefix("motor").is_some_and(|r| r.is_empty() || r.starts_with('.')) {
        return Err(ParseError::UnknownEnumValue);
    }
    let transfer = transfer.unwrap_or(false);
    // A mask of ops names the ops of an interface the kernel hosts. A task's
    // endpoint (`endpoint.<name>`) has no op table the kernel could hold a
    // call to, and any other kind's `OP_MASK` is a mask of op classes: neither
    // is spelled this way.
    let ops = ops.unwrap_or(0);
    if ops != 0 && (kind != CapKind::Endpoint || target.as_str().starts_with("endpoint.")) {
        return Err(ParseError::BadValue);
    }
    Ok(CapSpec { kind, perms, target, transfer, ops })
}

pub(crate) fn parse_cap_kind(s: &[u8]) -> Result<CapKind, ParseError> {
    let s = core::str::from_utf8(s).map_err(|_| ParseError::Unsupported)?;
    // One word per generic kind. The class within a kind is spelled by the
    // target, which `crates/core/ipc/src/cap_seed.rs` reads: a `device` row
    // names `irq.<N>`, `mmio.<index>` or `drv.<DRV_KIND_* as decimal>`; a
    // `node` row an absolute directory tree (`/fat`) or an image name
    // (`TOOLBOX.ELF`, perm `exec`); a `memobj` row `stream.<name>`; a `domain`
    // row `tasks`; a `log` row `trace`; an
    // `endpoint` row `endpoint.<name>` (a task-hosted endpoint) or
    // `<iface>[.<resource>]` (an interface the kernel hosts, `azos_devif`).
    // A kind this parser accepts but the seeder drops lets a topology ask for a
    // capability and receive nothing, with no error: every word below has a
    // minter, and a socket or a pipe end (minted by the call that creates it,
    // never granted by a row) has no word.
    let k = match s {
        "endpoint" => CapKind::Endpoint,
        "memobj" => CapKind::MemObj,
        "port" => CapKind::Port,
        "domain" => CapKind::Domain,
        "node" => CapKind::Node,
        "device" => CapKind::Device,
        "log" => CapKind::Log,
        _ => return Err(ParseError::UnknownEnumValue),
    };
    Ok(k)
}

/// The word [`parse_cap_kind`] reads as `kind`, or `None` for a kind no word
/// names (a signed CAPS.TOML cannot grant it). The inverse of that table, kept
/// next to it: `tests/host/topology-tests` checks every word maps back to the
/// kind it came from, so the emitter (`crate::emit`) and the parser cannot
/// drift apart.
pub fn cap_kind_word(kind: CapKind) -> Option<&'static str> {
    Some(match kind {
        CapKind::Endpoint => "endpoint",
        CapKind::MemObj => "memobj",
        CapKind::Port => "port",
        CapKind::Domain => "domain",
        CapKind::Node => "node",
        CapKind::Device => "device",
        CapKind::Log => "log",
        _ => return None,
    })
}

fn parse_cap_perms(s: &[u8]) -> Result<CapPerms, ParseError> {
    let mut p = CapPerms::NONE;
    for &b in s {
        p = match b {
            b'r' | b'R' => p.union(CapPerms::READ),
            b'w' | b'W' => p.union(CapPerms::WRITE),
            b'x' | b'X' => p.union(CapPerms::EXEC),
            b'd' | b'D' => p.union(CapPerms::DUP),
            b't' | b'T' => p.union(CapPerms::TRANSFER),
            b'm' | b'M' => p.union(CapPerms::MAP),
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
/// copy ignored the `config/limits/Kconfig.limits` value they claimed to track. A scratch
/// buffer smaller than the cap table it mirrors rejects valid topologies;
/// larger, it wastes stack. `types.rs` in this same crate was already
/// importing `MAX_TASKS`/`MAX_CAPS_TOTAL` from `azos_limits` — this now
/// joins them.
const MAX_CAPS_PER_TASK_BUF: usize = azos_limits::MAX_CAPS_PER_TASK;

/// The format-7 keys of the `[task.NAME]` row being read; applied to the row
/// when it is committed.
#[derive(Clone, Copy, Default)]
struct TaskExt {
    shadow: bool,
    isolated: bool,
    kmem_kib: u32,
    principal: Option<PrincipalKind>,
    security_boundary: bool,
    partition_id: u16,
}

impl TaskExt {
    fn commit(self, topology: &mut Topology<'_>) -> Result<(), ParseError> {
        topology.set_last_task_shadow(self.shadow);
        topology.set_last_task_isolated(self.isolated);
        topology.set_last_task_kmem_kib(self.kmem_kib);
        topology.set_last_task_principal(self.principal);
        // A partition id on a row that is no security boundary is refused
        // here, not when the key is read: the keys come in any order.
        if !topology.set_last_task_boundary(self.security_boundary, self.partition_id) {
            return Err(ParseError::Admission(AdmissionError::BadRow(crate::RowKind::Task)));
        }
        Ok(())
    }
}

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
    let mut current_task_mem_huge_mib: u16 = 0;
    let mut current_task_restart = RestartPolicy::OnFailure;
    let mut current_task_abi = TaskAbi::Native;
    let mut current_task_timer_slack = false;
    let mut current_task_lx_class = MaybeStr::from_bytes(&[]);
    let mut current_task_place = PlaceSpec::DEFAULT;
    let mut current_task_ext = TaskExt::default();
    let mut current_task_imports: [MaybeStr<'a>; crate::types::MAX_IMPORTS] =
        [MaybeStr::from_bytes(&[]); crate::types::MAX_IMPORTS];
    let mut current_task_imports_len: usize = 0;
    let mut current_task_exports: [crate::types::ExportSpec<'a>; crate::types::EXPORTS_TOTAL] =
        [crate::types::ExportSpec::empty(); crate::types::EXPORTS_TOTAL];
    let mut current_task_exports_len: usize = 0;
    // An open `[peer.NAME]`.
    let mut current_peer: Option<PeerStage<'a>> = None;
    // Format 1 until a `format = N` line before the first section says
    // otherwise. The binding keys are checked here as well (a malformed or
    // repeated one fails the parse) and read by the loader with
    // `parse_binding`.
    let mut binding = Binding { format: 1, ..Binding::default() };
    let mut format_declared = false;
    // An open `[pipeline.NAME]`: its name and `dma_kb` so far.
    let mut current_pipeline: Option<(MaybeStr<'a>, u32)> = None;
    // An open `[device.NAME]`: the row so far, and whether `match` was given.
    let mut current_device: Option<(DeviceSpec<'a>, bool)> = None;
    // An open `[signer.NAME]`.
    let mut current_signer: Option<SignerStage<'a>> = None;
    // An open section of the kinds format 7 added.
    let mut current_row: Option<RowStage<'a>> = None;
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
                topology.set_last_task_restart(current_task_restart);
                topology.set_last_task_abi(current_task_abi).map_err(ParseError::Admission)?;
                topology.set_last_task_timer_slack(current_task_timer_slack);
                if !current_task_lx_class.is_empty() {
                    topology.set_last_task_lx_class(current_task_lx_class).map_err(ParseError::Admission)?;
                }
                current_task_lx_class = MaybeStr::from_bytes(&[]);
                topology.set_last_task_place(current_task_place);
                topology
                    .set_last_task_imports(&current_task_imports[..current_task_imports_len])
                    .map_err(ParseError::Admission)?;
                topology
                    .set_last_task_exports(&current_task_exports[..current_task_exports_len])
                    .map_err(ParseError::Admission)?;
                current_task_ext.commit(topology)?;
                current_task_ext = TaskExt::default();
                current_task_imports_len = 0;
                current_task_exports_len = 0;
                current_task_abi = TaskAbi::Native;
                current_task_timer_slack = false;
                current_task_place = PlaceSpec::DEFAULT;
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
                current_task_caps_len = 0;
                current_task_class = MaybeStr::from_bytes(b"best_effort");
                current_task_priority = 0;
                current_task_profile = crate::deadline::SchedProfile::NONE;
            }
            if let Some((name, kb)) = current_pipeline.take() {
                topology.push_pipeline(name, kb.div_ceil(4)).map_err(ParseError::Admission)?;
            }
            if let Some((spec, has_match)) = current_device.take() {
                commit_device(topology, spec, has_match)?;
            }
            if let Some(st) = current_signer.take() {
                st.commit(topology)?;
            }
            if let Some(st) = current_peer.take() {
                st.commit(topology)?;
            }
            if let Some(r) = current_row.take() {
                r.commit(topology)?;
            }
            match section {
                Section::Policy(_)
                | Section::Livepatch(_)
                | Section::Degrade(_)
                | Section::Clock
                | Section::Swap(_)
                | Section::Login(_)
                | Section::Volume(_)
                | Section::Guest(_)
                | Section::Route(_)
                | Section::Firewall(_) => {
                    if binding.format < 7 {
                        return Err(ParseError::FieldNeedsFormat);
                    }
                    current_task_name = None;
                    current_row = RowStage::open(section);
                }
                Section::V8(..) => {
                    if binding.format < 8 {
                        return Err(ParseError::FieldNeedsFormat);
                    }
                    current_task_name = None;
                    current_row = RowStage::open(section);
                }
                Section::Peer(name) => {
                    if binding.format < 6 {
                        return Err(ParseError::FieldNeedsFormat);
                    }
                    current_task_name = None;
                    current_peer = Some(PeerStage::new(MaybeStr::from_bytes(name)));
                }
                Section::Pipeline(name) => {
                    current_task_name = None;
                    current_pipeline = Some((MaybeStr::from_bytes(name), 0));
                }
                Section::Device(name) => {
                    // A format-6 section: in an earlier file the writer did
                    // not mean it.
                    if binding.format < 6 {
                        return Err(ParseError::FieldNeedsFormat);
                    }
                    current_task_name = None;
                    current_device = Some((
                        DeviceSpec { name: MaybeStr::from_bytes(name), ..DeviceSpec::empty() },
                        false,
                    ));
                }
                Section::Task(name) => {
                    current_task_name = Some(MaybeStr::from_bytes(name));
                }
                Section::Signer(name) => {
                    if binding.format < 6 {
                        return Err(ParseError::FieldNeedsFormat);
                    }
                    current_task_name = None;
                    current_signer = Some(SignerStage::new(MaybeStr::from_bytes(name)));
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
                    &mut current_task_restart,
                    &mut current_task_abi,
                    &mut current_task_timer_slack,
                    &mut current_task_lx_class,
                    &mut current_task_place,
                    &mut current_task_imports,
                    &mut current_task_imports_len,
                    &mut current_task_exports,
                    &mut current_task_exports_len,
                    &mut current_task_ext,
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
            Some(Section::Device(_)) => {
                if let Some((spec, has_match)) = current_device.as_mut() {
                    handle_device_kv(effective, spec, has_match, binding.format)?;
                }
            }
            Some(Section::Signer(_)) => {
                if let Some(st) = current_signer.as_mut() {
                    st.kv(effective)?;
                }
            }
            Some(Section::Peer(_)) => {
                if let Some(st) = current_peer.as_mut() {
                    st.kv(effective, binding.format)?;
                }
            }
            Some(
                Section::Policy(_)
                | Section::Livepatch(_)
                | Section::Degrade(_)
                | Section::Clock
                | Section::Swap(_)
                | Section::Login(_)
                | Section::Volume(_)
                | Section::Guest(_)
                | Section::Route(_)
                | Section::Firewall(_)
                | Section::V8(..),
            ) => {
                if let Some(r) = current_row.as_mut() {
                    r.kv(effective, binding.format)?;
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
        topology.set_last_task_restart(current_task_restart);
        topology.set_last_task_abi(current_task_abi).map_err(ParseError::Admission)?;
        topology.set_last_task_timer_slack(current_task_timer_slack);
        if !current_task_lx_class.is_empty() {
            topology.set_last_task_lx_class(current_task_lx_class).map_err(ParseError::Admission)?;
        }
        topology.set_last_task_place(current_task_place);
        topology
            .set_last_task_imports(&current_task_imports[..current_task_imports_len])
            .map_err(ParseError::Admission)?;
        topology
            .set_last_task_exports(&current_task_exports[..current_task_exports_len])
            .map_err(ParseError::Admission)?;
        current_task_ext.commit(topology)?;
        if current_task_mem_huge_mib != 0
            && !topology.set_last_task_mem_huge_mib(current_task_mem_huge_mib)
        {
            return Err(ParseError::BadValue);
        }
    }
    if let Some((name, kb)) = current_pipeline {
        topology.push_pipeline(name, kb.div_ceil(4)).map_err(ParseError::Admission)?;
    }
    if let Some((spec, has_match)) = current_device {
        commit_device(topology, spec, has_match)?;
    }
    if let Some(st) = current_signer {
        st.commit(topology)?;
    }
    if let Some(st) = current_peer {
        st.commit(topology)?;
    }
    if let Some(r) = current_row {
        r.commit(topology)?;
    }

    // Over the whole topology, not only the tasks this file added.
    if motor_write_conflict(topology).is_some() {
        return Err(ParseError::MotorWriteConflict);
    }
    if flight_without_drivetrain(topology).is_some() {
        return Err(ParseError::Admission(AdmissionError::FlightWithoutDrivetrain));
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
    restart: &mut RestartPolicy,
    abi: &mut TaskAbi,
    timer_slack: &mut bool,
    lx_class: &mut MaybeStr<'a>,
    place: &mut PlaceSpec,
    imports: &mut [MaybeStr<'a>; crate::types::MAX_IMPORTS],
    imports_len: &mut usize,
    exports: &mut [crate::types::ExportSpec<'a>; crate::types::EXPORTS_TOTAL],
    exports_len: &mut usize,
    ext: &mut TaskExt,
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
        // `"locked"` makes `mem_pages` a reservation and
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
        // Wave 9: live instances of this row. 1..=MAX_TASKS;
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
        // Wave 12 (format 3): the syscall table the image is run
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
        // Format 5: this row's task may have its timers coalesced by its QoS
        // tier (`QOS_TIMER_TOLERANCE_ROWS_ONLY`). `true` or `false` only, as
        // `start`; refused in an earlier format like every key a later
        // format added.
        "timer_slack" => {
            if format < 5 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (b, tail) = parse_bool(after)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            *timer_slack = b;
            Ok(())
        }
        // Format 6: this row serves a Linux driver class; the kernel starts it
        // only when an id of that class matched a device the hardware bus
        // admitted. A quoted word, nothing after it, refused in an earlier
        // format like every key a later format added.
        "lx_class" => {
            if format < 6 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (v, tail) = parse_quoted_string(after, crate::types::DEVICE_DRIVER_MAX)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            if v.is_empty() {
                return Err(ParseError::BadValue);
            }
            *lx_class = MaybeStr::from_bytes(v);
            Ok(())
        }
        // Format 6: the placement of a driver row (`crate::placement`). Refused
        // in an earlier format like every key a later format added.
        // `stateless`: `true` or `false` only.
        "stateless" => {
            if format < 6 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (b, tail) = parse_bool(after)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            place.stateless = b;
            Ok(())
        }
        // `place`: the host the driver starts in, "kernel" or "ring3".
        "place" => {
            if format < 6 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (v, tail) = parse_quoted_string(after, crate::types::MAX_TASK_NAME_LEN)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            place.host = Host::from_bytes(v).ok_or(ParseError::UnknownEnumValue)?;
            Ok(())
        }
        // `call_budget_us`: a decimal `u32`; one that does not fit is rejected,
        // never truncated (a budget that wrapped admits a different move).
        "call_budget_us" => {
            if format < 6 {
                return Err(ParseError::FieldNeedsFormat);
            }
            let (n, tail) = parse_unsigned_int(after)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            place.call_budget_us = u32::try_from(n).map_err(|_| ParseError::BadValue)?;
            Ok(())
        }
        // Format 5: the endpoint names the name server may hand this row,
        // `imports = ["term", "log"]` on one line. A name is never authority:
        // the list says what the row may ASK for, and the name server answers
        // it with a derived capability or a recorded refusal. Refused in an
        // earlier format, like every key a later format added. Each name's
        // shape is checked when the row is committed
        // (`Topology::set_last_task_imports`); whether the server holds it,
        // at admission.
        "imports" => {
            if format < 5 {
                return Err(ParseError::FieldNeedsFormat);
            }
            *imports_len = 0;
            *imports_len = parse_string_array(
                after,
                crate::types::MAX_TASK_NAME_LEN,
                imports,
                ParseError::Admission(AdmissionError::TooManyImports),
            )?;
            Ok(())
        }
        // Format 6: the endpoints this row may lend to remote nodes,
        // `export = ["decisions@fleet"]` on one line: the endpoint it holds
        // the lend right on (`WRITE` + `transfer`) and the peer class
        // (`[peer.fleet]`) whose nodes may ask for it. Refused in an earlier
        // format. Each entry's shape is checked when the row is committed
        // (`Topology::set_last_task_exports`); that the row holds the endpoint
        // and the class exists, at admission.
        "export" => {
            if format < 6 {
                return Err(ParseError::FieldNeedsFormat);
            }
            if !after.starts_with(b"[") {
                return Err(ParseError::BadValue);
            }
            let mut r = &after[1..];
            *exports_len = 0;
            loop {
                r = skip_inline_ws(r);
                if r.starts_with(b"]") {
                    return if skip_inline_ws(&r[1..]).is_empty() { Ok(()) } else { Err(ParseError::BadValue) };
                }
                let (v, tail) = parse_quoted_string(r, 2 * crate::types::MAX_TASK_NAME_LEN + 2)?;
                let at = v.iter().position(|&c| c == b'@').ok_or(ParseError::BadValue)?;
                if *exports_len >= exports.len() {
                    return Err(ParseError::Admission(AdmissionError::TooManyExports));
                }
                exports[*exports_len] = crate::types::ExportSpec {
                    endpoint: MaybeStr::from_bytes(&v[..at]),
                    peer: MaybeStr::from_bytes(&v[at + 1..]),
                };
                *exports_len += 1;
                r = skip_inline_ws(tail);
                if r.starts_with(b",") {
                    r = &r[1..];
                } else if !r.starts_with(b"]") {
                    return Err(ParseError::BadValue);
                }
            }
        }
        // Format 7: observe-only admission (`TaskSpec::shadow`), a CPU of its
        // own (`TaskSpec::isolated`, checked at admission against `isolcpus`
        // and the profile) and a kernel-memory ceiling in KiB
        // (`TaskSpec::kmem_kib`, a `u32`, refused rather than truncated), and
        // the principal the row acts as over its class's (`TaskSpec::principal`).
        "shadow" | "isolated" | "kmem_kib" | "principal" => {
            if format < 7 {
                return Err(ParseError::FieldNeedsFormat);
            }
            match key_str {
                "shadow" => ext.shadow = bool_only(after)?,
                "isolated" => ext.isolated = bool_only(after)?,
                "principal" => {
                    if ext.principal.is_some() {
                        return Err(ParseError::BadValue);
                    }
                    ext.principal = Some(PrincipalKind::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?);
                }
                _ => ext.kmem_kib = uint_only(after, u32::MAX as u64)? as u32,
            }
            Ok(())
        }
        // Format 8: the row's Domain is a security boundary
        // (`TaskSpec::security_boundary`), in a hardware partition
        // (`TaskSpec::partition_id`, 1 to 65535; refused rather than
        // truncated, and only with the boundary).
        "security_boundary" | "partition_id" => {
            if format < 8 {
                return Err(ParseError::FieldNeedsFormat);
            }
            match key_str {
                "security_boundary" => ext.security_boundary = bool_only(after)?,
                _ => {
                    ext.partition_id = uint_only(after, u16::MAX as u64)? as u16;
                    if ext.partition_id == 0 {
                        return Err(ParseError::BadValue);
                    }
                }
            }
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

/// `["a", "b"]` on one line, each string at most `max_len` bytes, into `out`;
/// how many. `full` is the error when `out` cannot hold another.
fn parse_string_array<'a>(
    value: &'a [u8],
    max_len: usize,
    out: &mut [MaybeStr<'a>],
    full: ParseError,
) -> Result<usize, ParseError> {
    if !value.starts_with(b"[") {
        return Err(ParseError::BadValue);
    }
    let mut r = &value[1..];
    let mut n = 0;
    loop {
        r = skip_inline_ws(r);
        if r.starts_with(b"]") {
            return if skip_inline_ws(&r[1..]).is_empty() { Ok(n) } else { Err(ParseError::BadValue) };
        }
        let (v, tail) = parse_quoted_string(r, max_len)?;
        if n >= out.len() {
            return Err(full);
        }
        out[n] = MaybeStr::from_bytes(v);
        n += 1;
        r = skip_inline_ws(tail);
        if r.starts_with(b",") {
            r = &r[1..];
        } else if !r.starts_with(b"]") {
            return Err(ParseError::BadValue);
        }
    }
}


/// A `[peer.NAME]` section while it is being read: committed to the topology
/// when the next section (or the end of the file) closes it.
struct PeerStage<'a> {
    name: MaybeStr<'a>,
    nodes: [u32; crate::types::PEER_NODES],
    nodes_len: usize,
    pks: [[u8; 32]; crate::types::PEER_NODES],
    pks_len: usize,
    pks_declared: bool,
    measurement: Option<[u8; 32]>,
}

impl<'a> PeerStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self {
            name,
            nodes: [0; crate::types::PEER_NODES],
            nodes_len: 0,
            pks: [[0; 32]; crate::types::PEER_NODES],
            pks_len: 0,
            pks_declared: false,
            measurement: None,
        }
    }

    /// One kv line: `nodes = [2, 3]` (decimal `u32`s on one line; a value that
    /// does not fit is refused, never truncated), and from format 7
    /// `noise_pk = ["<64 hex>", ...]` (one key per node, in order) and
    /// `measurement = "<64 hex>"`, each at most once. Everything is checked
    /// when the section is committed ([`Topology::push_peer`]).
    fn kv(&mut self, line: &'a [u8], format: u8) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        match key {
            b"nodes" => {
                if !after.starts_with(b"[") {
                    return Err(ParseError::BadValue);
                }
                let mut r = &after[1..];
                self.nodes_len = 0;
                loop {
                    r = skip_inline_ws(r);
                    if r.starts_with(b"]") {
                        return if skip_inline_ws(&r[1..]).is_empty() { Ok(()) } else { Err(ParseError::BadValue) };
                    }
                    let (v, tail) = parse_unsigned_int(r)?;
                    let v = u32::try_from(v).map_err(|_| ParseError::BadValue)?;
                    if self.nodes_len >= self.nodes.len() {
                        return Err(ParseError::Admission(AdmissionError::BadPeer));
                    }
                    self.nodes[self.nodes_len] = v;
                    self.nodes_len += 1;
                    r = skip_inline_ws(tail);
                    if r.starts_with(b",") {
                        r = &r[1..];
                    } else if !r.starts_with(b"]") {
                        return Err(ParseError::BadValue);
                    }
                }
            }
            b"noise_pk" | b"measurement" => {
                if format < 7 {
                    return Err(ParseError::FieldNeedsFormat);
                }
                if key == b"measurement" {
                    if self.measurement.is_some() {
                        return Err(ParseError::BadValue);
                    }
                    self.measurement = Some(hex_only::<32>(after)?);
                    return Ok(());
                }
                if self.pks_declared {
                    return Err(ParseError::BadValue);
                }
                self.pks_declared = true;
                let mut names = [MaybeStr::from_bytes(&[]); crate::types::PEER_NODES];
                let n = parse_string_array(after, 64, &mut names, ParseError::Admission(AdmissionError::BadPeer))?;
                for (i, k) in names[..n].iter().enumerate() {
                    self.pks[i] = parse_hex::<32>(k.as_bytes())?;
                }
                self.pks_len = n;
                Ok(())
            }
            _ => Err(ParseError::UnknownField),
        }
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        topology
            .push_peer(self.name, &self.nodes[..self.nodes_len], &self.pks[..self.pks_len], self.measurement)
            .map_err(ParseError::Admission)
    }
}

/// A section of one of the kinds format 7 added while it is being read:
/// committed to the topology when the next section (or the end of the file)
/// closes it. Every kind has the same shape: a `kv` per line, a `commit` that
/// checks what only the whole section can be checked for.
enum RowStage<'a> {
    Policy(PolicyStage<'a>),
    Livepatch(LivepatchStage<'a>),
    Degrade(DegradeStage<'a>),
    Clock(ClockStage),
    Swap(SwapStage<'a>),
    Login(LoginStage<'a>),
    Volume(VolumeStage<'a>),
    Guest(GuestStage<'a>),
    Route(RouteStage<'a>),
    Firewall(FirewallStage<'a>),
    V8(Stage8<'a>),
}

impl<'a> RowStage<'a> {
    /// The stage a section header opens, for the kinds this enum holds.
    fn open(section: Section<'a>) -> Option<Self> {
        match section {
            Section::Policy(name) => Some(RowStage::Policy(PolicyStage::new(MaybeStr::from_bytes(name)))),
            Section::Livepatch(name) => Some(RowStage::Livepatch(LivepatchStage::new(MaybeStr::from_bytes(name)))),
            Section::Degrade(name) => Some(RowStage::Degrade(DegradeStage::new(MaybeStr::from_bytes(name)))),
            Section::Clock => Some(RowStage::Clock(ClockStage::new())),
            Section::Swap(name) => Some(RowStage::Swap(SwapStage::new(MaybeStr::from_bytes(name)))),
            Section::Login(name) => Some(RowStage::Login(LoginStage::new(MaybeStr::from_bytes(name)))),
            Section::Volume(name) => Some(RowStage::Volume(VolumeStage::new(MaybeStr::from_bytes(name)))),
            Section::Guest(name) => Some(RowStage::Guest(GuestStage::new(MaybeStr::from_bytes(name)))),
            Section::Route(name) => Some(RowStage::Route(RouteStage::new(MaybeStr::from_bytes(name)))),
            Section::Firewall(name) => Some(RowStage::Firewall(FirewallStage::new(MaybeStr::from_bytes(name)))),
            Section::V8(kind, name) => Some(RowStage::V8(Stage8::open(kind, MaybeStr::from_bytes(name)))),
            _ => None,
        }
    }

    fn kv(&mut self, line: &'a [u8], format: u8) -> Result<(), ParseError> {
        match self {
            RowStage::Policy(st) => st.kv(line),
            RowStage::Livepatch(st) => st.kv(line),
            RowStage::Degrade(st) => st.kv(line),
            RowStage::Clock(st) => st.kv(line),
            RowStage::Swap(st) => st.kv(line),
            RowStage::Login(st) => st.kv(line),
            RowStage::Volume(st) => st.kv(line),
            RowStage::Guest(st) => st.kv(line, format),
            RowStage::Route(st) => st.kv(line),
            RowStage::Firewall(st) => st.kv(line),
            RowStage::V8(st) => st.kv(line),
        }
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        match self {
            RowStage::Policy(st) => st.commit(topology),
            RowStage::Livepatch(st) => st.commit(topology),
            RowStage::Degrade(st) => st.commit(topology),
            RowStage::Clock(st) => st.commit(topology),
            RowStage::Swap(st) => st.commit(topology),
            RowStage::Login(st) => st.commit(topology),
            RowStage::Volume(st) => st.commit(topology),
            RowStage::Guest(st) => st.commit(topology),
            RowStage::Route(st) => st.commit(topology),
            RowStage::Firewall(st) => st.commit(topology),
            RowStage::V8(st) => st.commit(topology),
        }
    }
}

/// The stage of a format-8 section: one variant per [`Kind8`].
enum Stage8<'a> {
    Tsn(TsnStage<'a>),
    Fieldbus(FieldbusStage<'a>),
    Audio(AudioStage<'a>),
    Display(DisplayStage<'a>),
    User(UserStage<'a>),
    Key(KeyStage<'a>),
    Mission(MissionStage<'a>),
    BootChain(BootChainStage<'a>),
    Island(IslandStage<'a>),
    Activity(ActivityStage<'a>),
    Numa(NumaStage<'a>),
    Envelope(EnvelopeStage<'a>),
    Rtc(RtcStage<'a>),
    Nic(NicStage<'a>),
    Model(ModelStage<'a>),
    Usb(UsbStage<'a>),
}

impl<'a> Stage8<'a> {
    fn open(kind: Kind8, name: MaybeStr<'a>) -> Self {
        match kind {
            Kind8::Tsn => Stage8::Tsn(TsnStage::new(name)),
            Kind8::Fieldbus => Stage8::Fieldbus(FieldbusStage::new(name)),
            Kind8::Audio => Stage8::Audio(AudioStage::new(name)),
            Kind8::Display => Stage8::Display(DisplayStage::new(name)),
            Kind8::User => Stage8::User(UserStage::new(name)),
            Kind8::Key => Stage8::Key(KeyStage::new(name)),
            Kind8::Mission => Stage8::Mission(MissionStage::new()),
            Kind8::BootChain => Stage8::BootChain(BootChainStage::new(name)),
            Kind8::Island => Stage8::Island(IslandStage::new(name)),
            Kind8::Activity => Stage8::Activity(ActivityStage::new(name)),
            Kind8::Numa => Stage8::Numa(NumaStage::new(name)),
            Kind8::Envelope => Stage8::Envelope(EnvelopeStage::new(name)),
            Kind8::Rtc => Stage8::Rtc(RtcStage::new()),
            Kind8::Nic => Stage8::Nic(NicStage::new(name)),
            Kind8::Model => Stage8::Model(ModelStage::new(name)),
            Kind8::Usb => Stage8::Usb(UsbStage::new(name)),
        }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        match self {
            Stage8::Tsn(st) => st.kv(line),
            Stage8::Fieldbus(st) => st.kv(line),
            Stage8::Audio(st) => st.kv(line),
            Stage8::Display(st) => st.kv(line),
            Stage8::User(st) => st.kv(line),
            Stage8::Key(st) => st.kv(line),
            Stage8::Mission(st) => st.kv(line),
            Stage8::BootChain(st) => st.kv(line),
            Stage8::Island(st) => st.kv(line),
            Stage8::Activity(st) => st.kv(line),
            Stage8::Numa(st) => st.kv(line),
            Stage8::Envelope(st) => st.kv(line),
            Stage8::Rtc(st) => st.kv(line),
            Stage8::Nic(st) => st.kv(line),
            Stage8::Model(st) => st.kv(line),
            Stage8::Usb(st) => st.kv(line),
        }
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        match self {
            Stage8::Tsn(st) => st.commit(topology),
            Stage8::Fieldbus(st) => st.commit(topology),
            Stage8::Audio(st) => st.commit(topology),
            Stage8::Display(st) => st.commit(topology),
            Stage8::User(st) => st.commit(topology),
            Stage8::Key(st) => st.commit(topology),
            Stage8::Mission(st) => st.commit(topology),
            Stage8::BootChain(st) => st.commit(topology),
            Stage8::Island(st) => st.commit(topology),
            Stage8::Activity(st) => st.commit(topology),
            Stage8::Numa(st) => st.commit(topology),
            Stage8::Envelope(st) => st.commit(topology),
            Stage8::Rtc(st) => st.commit(topology),
            Stage8::Nic(st) => st.commit(topology),
            Stage8::Model(st) => st.commit(topology),
            Stage8::Usb(st) => st.commit(topology),
        }
    }
}

// ── CAPS.TOML format 8 rows (TOPO-ROWS-C) ──────────────────────────────────

/// Take `bit` of `seen`: a key may appear once.
fn claim(seen: &mut u16, bit: u16) -> Result<(), ParseError> {
    if *seen & bit != 0 {
        return Err(ParseError::BadValue);
    }
    *seen |= bit;
    Ok(())
}

/// A quoted row or device name (checked for its alphabet by `Topology::push_*`).
fn name_value<'a>(after: &'a [u8]) -> Result<MaybeStr<'a>, ParseError> {
    Ok(MaybeStr::from_bytes(quoted_only(after, crate::types::MAX_TASK_NAME_LEN)?))
}

/// `"aa:bb:cc:dd:ee:ff"`.
fn mac_value(after: &[u8]) -> Result<[u8; 6], ParseError> {
    let s = quoted_only(after, 17)?;
    if s.len() != 17 {
        return Err(ParseError::BadValue);
    }
    let mut mac = [0u8; 6];
    for (i, out) in mac.iter_mut().enumerate() {
        if i != 0 && s[i * 3 - 1] != b':' {
            return Err(ParseError::BadValue);
        }
        *out = parse_hex::<1>(&s[i * 3..i * 3 + 2])?[0];
    }
    Ok(mac)
}

/// Four hex digits, a USB vendor or product id.
fn usb_id_value(after: &[u8]) -> Result<u16, ParseError> {
    Ok(u16::from_be_bytes(hex_only::<2>(after)?))
}

/// A `[tsn.NAME]` section: `dev`, `window_us` and `link_budget`, all required.
struct TsnStage<'a> {
    spec: TsnSpec<'a>,
    seen: u16,
}

impl<'a> TsnStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: TsnSpec { name, ..TsnSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"dev" => 1,
            b"window_us" => 2,
            b"link_budget" => 4,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.dev = name_value(after)?,
            2 => self.spec.window_us = uint_only(after, u32::MAX as u64)? as u32,
            _ => self.spec.link_budget = uint_only(after, u32::MAX as u64)? as u32,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen != 7 {
            return Err(ParseError::MissingField);
        }
        topology.push_tsn(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[fieldbus.NAME]` section: `kind` and `dev` (required), `cycle_us`.
struct FieldbusStage<'a> {
    spec: FieldbusSpec<'a>,
    seen: u16,
}

impl<'a> FieldbusStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: FieldbusSpec { name, ..FieldbusSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"kind" => 1,
            b"dev" => 2,
            b"cycle_us" => 4,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.kind = FieldbusKind::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            2 => self.spec.dev = name_value(after)?,
            _ => self.spec.cycle_us = uint_only(after, u32::MAX as u64)? as u32,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 3 != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_fieldbus(self.spec).map_err(ParseError::Admission)
    }
}

/// An `[audio.NAME]` section: `dev`, `rate_hz` and `channels` (required),
/// `dir` (default `playback`).
struct AudioStage<'a> {
    spec: AudioSpec<'a>,
    seen: u16,
}

impl<'a> AudioStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: AudioSpec { name, ..AudioSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"dev" => 1,
            b"rate_hz" => 2,
            b"channels" => 4,
            b"dir" => 8,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.dev = name_value(after)?,
            2 => self.spec.rate_hz = uint_only(after, u32::MAX as u64)? as u32,
            4 => self.spec.channels = uint_only(after, u8::MAX as u64)? as u8,
            _ => self.spec.dir = AudioDir::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 7 != 7 {
            return Err(ParseError::MissingField);
        }
        topology.push_audio(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[display.NAME]` section: `dev`, `width` and `height` (required),
/// `rotation`, `primary`.
struct DisplayStage<'a> {
    spec: DisplaySpec<'a>,
    seen: u16,
}

impl<'a> DisplayStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: DisplaySpec { name, ..DisplaySpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"dev" => 1,
            b"width" => 2,
            b"height" => 4,
            b"rotation" => 8,
            b"primary" => 16,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.dev = name_value(after)?,
            2 => self.spec.width = uint_only(after, u16::MAX as u64)? as u16,
            4 => self.spec.height = uint_only(after, u16::MAX as u64)? as u16,
            8 => self.spec.rotation = uint_only(after, u16::MAX as u64)? as u16,
            _ => self.spec.primary = bool_only(after)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 7 != 7 {
            return Err(ParseError::MissingField);
        }
        topology.push_display(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[user.NAME]` section: `root` and `keystore`, both required.
struct UserStage<'a> {
    spec: UserSpec<'a>,
    seen: u16,
}

impl<'a> UserStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: UserSpec { name, ..UserSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"root" => 1,
            b"keystore" => 2,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        let path = MaybeStr::from_bytes(quoted_only(after, crate::types::MAX_TARGET_LEN)?);
        if bit == 1 {
            self.spec.root = path;
        } else {
            self.spec.keystore = path;
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_user(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[key.NAME]` section: `purpose` and `source` (required), `user`.
struct KeyStage<'a> {
    spec: KeySpec<'a>,
    seen: u16,
}

impl<'a> KeyStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: KeySpec { name, ..KeySpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"purpose" => 1,
            b"source" => 2,
            b"user" => 4,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.purpose = KeyPurpose::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            2 => self.spec.source = KeySource::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            _ => self.spec.user = Some(name_value(after)?),
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 3 != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_key(self.spec).map_err(ParseError::Admission)
    }
}

/// The `[mission]` section: `reserve_mj` (required), `task`.
struct MissionStage<'a> {
    spec: MissionSpec<'a>,
    seen: u16,
}

impl<'a> MissionStage<'a> {
    fn new() -> Self {
        Self { spec: MissionSpec { reserve_mj: 0, task: None }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"reserve_mj" => 1,
            b"task" => 2,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.reserve_mj = uint_only(after, u32::MAX as u64)? as u32,
            _ => self.spec.task = Some(name_value(after)?),
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 1 == 0 {
            return Err(ParseError::MissingField);
        }
        topology.set_mission(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[boot_chain.NAME]` section: `stage` and `digest`, both required.
struct BootChainStage<'a> {
    spec: BootChainSpec<'a>,
    seen: u16,
}

impl<'a> BootChainStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: BootChainSpec { name, ..BootChainSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"stage" => 1,
            b"digest" => 2,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.stage = uint_only(after, u8::MAX as u64)? as u8,
            _ => self.spec.digest = hex_only::<32>(after)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_boot_stage(self.spec).map_err(ParseError::Admission)
    }
}

/// An `[island.NAME]` section: `image`, `sha256` and `mailbox` (required),
/// `wake` (default none).
struct IslandStage<'a> {
    spec: IslandSpec<'a>,
    seen: u16,
}

impl<'a> IslandStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: IslandSpec { name, ..IslandSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"image" => 1,
            b"sha256" => 2,
            b"mailbox" => 4,
            b"wake" => 8,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.image = name_value(after)?,
            2 => self.spec.sha256 = hex_only::<32>(after)?,
            4 => self.spec.mailbox = name_value(after)?,
            _ => {
                let n = parse_string_array(
                    after,
                    crate::types::MAX_TASK_NAME_LEN,
                    &mut self.spec.wake,
                    ParseError::Admission(AdmissionError::BadRow(crate::RowKind::Island)),
                )?;
                self.spec.wake_len = n as u8;
            }
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 7 != 7 {
            return Err(ParseError::MissingField);
        }
        topology.push_island(self.spec).map_err(ParseError::Admission)
    }
}

/// An `[activity.NAME]` section: `task` and `trigger` (required),
/// `period_ms`.
struct ActivityStage<'a> {
    spec: ActivitySpec<'a>,
    seen: u16,
}

impl<'a> ActivityStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: ActivitySpec { name, ..ActivitySpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"task" => 1,
            b"trigger" => 2,
            b"period_ms" => 4,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.task = name_value(after)?,
            2 => {
                self.spec.trigger =
                    ActivityTrigger::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?
            }
            _ => self.spec.period_ms = uint_only(after, u32::MAX as u64)? as u32,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 3 != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_activity(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[numa.NAME]` section: `node` and `cpus`, both required.
struct NumaStage<'a> {
    spec: NumaSpec<'a>,
    seen: u16,
}

impl<'a> NumaStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: NumaSpec { name, ..NumaSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"node" => 1,
            b"cpus" => 2,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.node = uint_only(after, u8::MAX as u64)? as u8,
            _ => self.spec.cpus = uint_only(after, u64::MAX)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_numa(self.spec).map_err(ParseError::Admission)
    }
}

/// An `[envelope.NAME]` section: `kind`, `class` and `level`, all required.
struct EnvelopeStage<'a> {
    spec: EnvelopeSpec<'a>,
    seen: u16,
}

impl<'a> EnvelopeStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: EnvelopeSpec { name, ..EnvelopeSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"kind" => 1,
            b"class" => 2,
            b"level" => 4,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.kind = EffectKind::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            2 => self.spec.class = name_value(after)?,
            _ => self.spec.level = Envelope::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen != 7 {
            return Err(ParseError::MissingField);
        }
        topology.push_envelope(self.spec).map_err(ParseError::Admission)
    }
}

/// The `[rtc]` section: `dev` (required), `utc` (default `true`).
struct RtcStage<'a> {
    spec: RtcSpec<'a>,
    seen: u16,
}

impl<'a> RtcStage<'a> {
    fn new() -> Self {
        Self { spec: RtcSpec { dev: MaybeStr::from_bytes(&[]), utc: true }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"dev" => 1,
            b"utc" => 2,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.dev = name_value(after)?,
            _ => self.spec.utc = bool_only(after)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 1 == 0 {
            return Err(ParseError::MissingField);
        }
        topology.set_rtc(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[nic.NAME]` section: `dev` (required), `mtu`, `mac`.
struct NicStage<'a> {
    spec: NicSpec<'a>,
    seen: u16,
}

impl<'a> NicStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: NicSpec { name, ..NicSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"dev" => 1,
            b"mtu" => 2,
            b"mac" => 4,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.dev = name_value(after)?,
            2 => self.spec.mtu = uint_only(after, u16::MAX as u64)? as u16,
            _ => self.spec.mac = Some(mac_value(after)?),
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 1 == 0 {
            return Err(ParseError::MissingField);
        }
        topology.push_nic(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[model.NAME]` section: `bundle` (required), `variant`.
struct ModelStage<'a> {
    spec: ModelSpec<'a>,
    seen: u16,
}

impl<'a> ModelStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: ModelSpec { name, ..ModelSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"bundle" => 1,
            b"variant" => 2,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => self.spec.bundle = hex_only::<32>(after)?,
            _ => self.spec.variant = name_value(after)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 1 == 0 {
            return Err(ParseError::MissingField);
        }
        topology.push_model(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[usb.NAME]` section: `authorize` (required), `vid`, `pid`, `class`.
struct UsbStage<'a> {
    spec: UsbSpec<'a>,
    seen: u16,
}

impl<'a> UsbStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: UsbSpec { name, ..UsbSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"authorize" => 1,
            b"vid" => 2,
            b"pid" => 4,
            b"class" => 8,
            _ => return Err(ParseError::UnknownField),
        };
        claim(&mut self.seen, bit)?;
        match bit {
            1 => {
                self.spec.authorize =
                    UsbAuthorize::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?
            }
            2 => self.spec.vid = Some(usb_id_value(after)?),
            4 => self.spec.pid = Some(usb_id_value(after)?),
            _ => self.spec.class = Some(uint_only(after, u8::MAX as u64)? as u8),
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 1 == 0 {
            return Err(ParseError::MissingField);
        }
        topology.push_usb(self.spec).map_err(ParseError::Admission)
    }
}


/// A `[policy.NAME]` section: `domain = "<task row>"` (required),
/// `scope = "self" | "subtree"`, `create_endpoints = bool`,
/// `create_ports = bool`, `memobj_max_pages = N`, each at most once.
struct PolicyStage<'a> {
    spec: PolicySpec<'a>,
    seen: u8,
}

impl<'a> PolicyStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: PolicySpec { name, ..PolicySpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"domain" => 1,
            b"scope" => 2,
            b"create_endpoints" => 4,
            b"create_ports" => 8,
            b"memobj_max_pages" => 16,
            _ => return Err(ParseError::UnknownField),
        };
        if self.seen & bit != 0 {
            return Err(ParseError::BadValue);
        }
        self.seen |= bit;
        match bit {
            1 => self.spec.domain = MaybeStr::from_bytes(quoted_only(after, crate::types::MAX_TASK_NAME_LEN)?),
            2 => {
                self.spec.scope =
                    PolicyScope::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?
            }
            4 => self.spec.create_endpoints = bool_only(after)?,
            8 => self.spec.create_ports = bool_only(after)?,
            _ => self.spec.memobj_max_pages = uint_only(after, u32::MAX as u64)? as u32,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 1 == 0 {
            return Err(ParseError::MissingField);
        }
        topology.push_policy(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[livepatch.NAME]` section: `isa`, `build_id`, `sec_epoch` and `sha256`,
/// all required, each at most once.
struct LivepatchStage<'a> {
    spec: LivepatchSpec<'a>,
    seen: u8,
}

impl<'a> LivepatchStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: LivepatchSpec { name, ..LivepatchSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"isa" => 1,
            b"build_id" => 2,
            b"sec_epoch" => 4,
            b"sha256" => 8,
            _ => return Err(ParseError::UnknownField),
        };
        if self.seen & bit != 0 {
            return Err(ParseError::BadValue);
        }
        self.seen |= bit;
        match bit {
            1 => self.spec.isa = PatchIsa::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            2 => {
                let hex = quoted_only(after, 2 * 32)?;
                if hex.len() % 2 != 0 || hex.len() < 2 * BuildId::MIN_LEN {
                    return Err(ParseError::BadValue);
                }
                let mut buf = [0u8; 32];
                let n = hex.len() / 2;
                for (i, pair) in hex.chunks(2).enumerate() {
                    buf[i] = parse_hex::<1>(pair)?[0];
                }
                self.spec.build_id = BuildId::new(&buf[..n]).ok_or(ParseError::BadValue)?;
            }
            4 => self.spec.sec_epoch = uint_only(after, u32::MAX as u64)? as u32,
            _ => self.spec.sha256 = hex_only::<32>(after)?,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen != 15 {
            return Err(ParseError::MissingField);
        }
        topology.push_livepatch(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[degrade.NAME]` section: `level` and `battery_pct` (required),
/// `clear_pct` (default `battery_pct`), each at most once.
struct DegradeStage<'a> {
    spec: DegradeSpec<'a>,
    seen: u8,
}

impl<'a> DegradeStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: DegradeSpec { name, ..DegradeSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"level" => 1,
            b"battery_pct" => 2,
            b"clear_pct" => 4,
            _ => return Err(ParseError::UnknownField),
        };
        if self.seen & bit != 0 {
            return Err(ParseError::BadValue);
        }
        self.seen |= bit;
        match bit {
            1 => self.spec.level = Envelope::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            2 => self.spec.battery_pct = uint_only(after, 100)? as u8,
            _ => self.spec.clear_pct = uint_only(after, 100)? as u8,
        }
        Ok(())
    }

    fn commit(mut self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 3 != 3 {
            return Err(ParseError::MissingField);
        }
        if self.seen & 4 == 0 {
            self.spec.clear_pct = self.spec.battery_pct;
        }
        topology.push_degrade(self.spec).map_err(ParseError::Admission)
    }
}

/// The `[clock]` section: `ptp_domain = N` and
/// `leaps = ["<unix>:<offset>", ...]` (one line), each at most once.
struct ClockStage {
    ptp_domain: Option<u8>,
    leaps: [LeapEntry; crate::types::LEAP_ENTRIES],
    leaps_len: usize,
    leaps_seen: bool,
}

impl ClockStage {
    fn new() -> Self {
        Self {
            ptp_domain: None,
            leaps: [LeapEntry { utc_secs: 0, tai_offset: 0 }; crate::types::LEAP_ENTRIES],
            leaps_len: 0,
            leaps_seen: false,
        }
    }

    fn kv(&mut self, line: &[u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        match key {
            b"ptp_domain" => {
                if self.ptp_domain.is_some() {
                    return Err(ParseError::BadValue);
                }
                self.ptp_domain = Some(uint_only(after, crate::types::PTP_DOMAIN_MAX as u64)? as u8);
            }
            b"leaps" => {
                if self.leaps_seen {
                    return Err(ParseError::BadValue);
                }
                self.leaps_seen = true;
                let mut entries = [MaybeStr::from_bytes(&[]); crate::types::LEAP_ENTRIES];
                let n = parse_string_array(
                    after,
                    32,
                    &mut entries,
                    ParseError::Admission(AdmissionError::DuplicateRow(crate::RowKind::Clock)),
                )?;
                for (i, e) in entries[..n].iter().enumerate() {
                    let b = e.as_bytes();
                    let colon = b.iter().position(|&c| c == b':').ok_or(ParseError::BadValue)?;
                    let secs = uint_only(&b[..colon], u64::MAX)?;
                    let off = uint_only(&b[colon + 1..], u16::MAX as u64)?;
                    self.leaps[i] = LeapEntry { utc_secs: secs, tai_offset: off as u16 };
                }
                self.leaps_len = n;
            }
            _ => return Err(ParseError::UnknownField),
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'_>) -> Result<(), ParseError> {
        topology.set_clock(self.ptp_domain, &self.leaps[..self.leaps_len]).map_err(ParseError::Admission)
    }
}

/// A `[swap.NAME]` section: `partition = N`, required, once.
struct SwapStage<'a> {
    spec: SwapSpec<'a>,
    seen: bool,
}

impl<'a> SwapStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: SwapSpec { name, ..SwapSpec::empty() }, seen: false }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        if key != b"partition" {
            return Err(ParseError::UnknownField);
        }
        if self.seen {
            return Err(ParseError::BadValue);
        }
        self.seen = true;
        self.spec.partition = uint_only(after, u8::MAX as u64)? as u8;
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if !self.seen {
            return Err(ParseError::MissingField);
        }
        topology.push_swap(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[login.NAME]` section: `ssh_key = ["<64 hex>", ...]`, required, once.
struct LoginStage<'a> {
    keys: [[u8; 32]; LOGIN_KEYS],
    keys_len: usize,
    name: MaybeStr<'a>,
    seen: bool,
}

impl<'a> LoginStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { keys: [[0; 32]; LOGIN_KEYS], keys_len: 0, name, seen: false }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        if key != b"ssh_key" {
            return Err(ParseError::UnknownField);
        }
        if self.seen {
            return Err(ParseError::BadValue);
        }
        self.seen = true;
        let mut hex = [MaybeStr::from_bytes(&[]); LOGIN_KEYS];
        let n = parse_string_array(after, 64, &mut hex, ParseError::Admission(AdmissionError::BadRow(crate::RowKind::Login)))?;
        for (i, k) in hex[..n].iter().enumerate() {
            self.keys[i] = parse_hex::<32>(k.as_bytes())?;
        }
        self.keys_len = n;
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if !self.seen {
            return Err(ParseError::MissingField);
        }
        topology.push_login(self.name, &self.keys[..self.keys_len]).map_err(ParseError::Admission)
    }
}

/// A `[volume.NAME]` section: `partition` and `mount` (required),
/// `read_only`, `aead`, `verity_root`, each at most once.
struct VolumeStage<'a> {
    spec: VolumeSpec<'a>,
    seen: u8,
}

impl<'a> VolumeStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: VolumeSpec { name, ..VolumeSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"partition" => 1,
            b"mount" => 2,
            b"read_only" => 4,
            b"aead" => 8,
            b"verity_root" => 16,
            _ => return Err(ParseError::UnknownField),
        };
        if self.seen & bit != 0 {
            return Err(ParseError::BadValue);
        }
        self.seen |= bit;
        match bit {
            1 => self.spec.partition = uint_only(after, u8::MAX as u64)? as u8,
            2 => self.spec.mount = MaybeStr::from_bytes(quoted_only(after, crate::types::MAX_TARGET_LEN)?),
            4 => self.spec.read_only = bool_only(after)?,
            8 => self.spec.aead = bool_only(after)?,
            _ => self.spec.verity_root = Some(hex_only::<32>(after)?),
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 3 != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_volume(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[guest.NAME]` section: `cpus`, `mem_mib` and `envelope` (required),
/// `devices` (default none), each at most once; and, from format 8,
/// `passthrough`, `static`, `pcpus` and `mem_base`.
struct GuestStage<'a> {
    spec: GuestSpec<'a>,
    seen: u8,
}

impl<'a> GuestStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: GuestSpec { name, ..GuestSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8], format: u8) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"cpus" => 1,
            b"mem_mib" => 2,
            b"envelope" => 4,
            b"devices" => 8,
            b"passthrough" => 16,
            b"static" => 32,
            b"pcpus" => 64,
            b"mem_base" => 128,
            _ => return Err(ParseError::UnknownField),
        };
        if bit >= 16 && format < 8 {
            return Err(ParseError::FieldNeedsFormat);
        }
        if self.seen & bit != 0 {
            return Err(ParseError::BadValue);
        }
        self.seen |= bit;
        match bit {
            1 => self.spec.cpus = uint_only(after, u8::MAX as u64)? as u8,
            2 => self.spec.mem_mib = uint_only(after, u32::MAX as u64)? as u32,
            4 => self.spec.envelope = Envelope::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            16 => {
                let n = parse_string_array(
                    after,
                    crate::types::MAX_TASK_NAME_LEN,
                    &mut self.spec.passthrough,
                    ParseError::Admission(AdmissionError::BadRow(crate::RowKind::Guest)),
                )?;
                self.spec.passthrough_len = n as u8;
            }
            32 => self.spec.static_partition = bool_only(after)?,
            64 => self.spec.pcpus = uint_only(after, u64::MAX)?,
            128 => self.spec.mem_base = uint_only(after, u64::MAX)?,
            _ => {
                let n = parse_string_array(
                    after,
                    crate::types::MAX_TASK_NAME_LEN,
                    &mut self.spec.devices,
                    ParseError::Admission(AdmissionError::BadRow(crate::RowKind::Guest)),
                )?;
                self.spec.devices_len = n as u8;
            }
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 7 != 7 {
            return Err(ParseError::MissingField);
        }
        topology.push_guest(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[route.NAME]` section: `dest` and `dev` (required), `via`, `metric`,
/// each at most once.
struct RouteStage<'a> {
    spec: RouteSpec<'a>,
    seen: u8,
}

impl<'a> RouteStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: RouteSpec { name, ..RouteSpec::empty() }, seen: 0 }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"dest" => 1,
            b"dev" => 2,
            b"via" => 4,
            b"metric" => 8,
            _ => return Err(ParseError::UnknownField),
        };
        if self.seen & bit != 0 {
            return Err(ParseError::BadValue);
        }
        self.seen |= bit;
        match bit {
            1 => self.spec.dest = IpPrefix::parse(quoted_only(after, 64)?).ok_or(ParseError::BadValue)?,
            2 => self.spec.dev = MaybeStr::from_bytes(quoted_only(after, crate::types::MAX_TASK_NAME_LEN)?),
            4 => self.spec.via = Some(IpAddr::parse(quoted_only(after, 64)?).ok_or(ParseError::BadValue)?),
            _ => self.spec.metric = uint_only(after, u32::MAX as u64)? as u32,
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 3 != 3 {
            return Err(ParseError::MissingField);
        }
        topology.push_route(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[firewall.NAME]` section: `dir` and `action` (required), `proto`,
/// `port`, `port_end`, `addr`, each at most once.
struct FirewallStage<'a> {
    spec: FirewallSpec<'a>,
    seen: u8,
    port_end: Option<u16>,
}

impl<'a> FirewallStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self { spec: FirewallSpec { name, ..FirewallSpec::empty() }, seen: 0, port_end: None }
    }

    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = split_kv(line)?;
        let bit = match key {
            b"dir" => 1,
            b"action" => 2,
            b"proto" => 4,
            b"port" => 8,
            b"port_end" => 16,
            b"addr" => 32,
            _ => return Err(ParseError::UnknownField),
        };
        if self.seen & bit != 0 {
            return Err(ParseError::BadValue);
        }
        self.seen |= bit;
        match bit {
            1 => self.spec.dir = FwDir::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            2 => self.spec.action = FwAction::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            4 => self.spec.proto = FwProto::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?,
            8 => {
                // Port 0 is "any port", which is said by leaving `port` out.
                let p = uint_only(after, u16::MAX as u64)? as u16;
                if p == 0 {
                    return Err(ParseError::BadValue);
                }
                self.spec.port_lo = p;
            }
            16 => {
                let p = uint_only(after, u16::MAX as u64)? as u16;
                if p == 0 {
                    return Err(ParseError::BadValue);
                }
                self.port_end = Some(p);
            }
            _ => self.spec.addr = Some(IpPrefix::parse(quoted_only(after, 64)?).ok_or(ParseError::BadValue)?),
        }
        Ok(())
    }

    fn commit(mut self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        if self.seen & 3 != 3 {
            return Err(ParseError::MissingField);
        }
        // `port_end` completes a `port`; alone it has nothing to end.
        if self.port_end.is_some() && self.spec.port_lo == 0 {
            return Err(ParseError::MissingField);
        }
        self.spec.port_hi = self.port_end.unwrap_or(self.spec.port_lo);
        topology.push_firewall(self.spec).map_err(ParseError::Admission)
    }
}

/// A `[signer.NAME]` section while it is being read: committed to the
/// topology when the next section (or the end of the file) closes it.
struct SignerStage<'a> {
    name: MaybeStr<'a>,
    key_id: Option<[u8; 32]>,
    rt: bool,
    mem_pages_max: u32,
    warrants: [MaybeStr<'a>; crate::types::SIGNER_WARRANTS_TOTAL],
    warrants_len: usize,
}

impl<'a> SignerStage<'a> {
    fn new(name: MaybeStr<'a>) -> Self {
        Self {
            name,
            key_id: None,
            rt: false,
            mem_pages_max: 0,
            warrants: [MaybeStr::from_bytes(&[]); crate::types::SIGNER_WARRANTS_TOTAL],
            warrants_len: 0,
        }
    }

    /// One kv line: `key_id = "<64 hex>"`, `rt = bool`, `mem_pages_max = N`,
    /// `warrants = ["kind:prefix", ...]`, each at most once.
    fn kv(&mut self, line: &'a [u8]) -> Result<(), ParseError> {
        let (key, after) = take_ident(line)?;
        let after = skip_inline_ws(after);
        if !after.starts_with(b"=") {
            return Err(ParseError::MissingEquals);
        }
        let after = skip_inline_ws(&after[1..]);
        match key {
            b"key_id" => {
                let (v, tail) = parse_quoted_string(after, 64)?;
                if self.key_id.is_some() || !skip_inline_ws(tail).is_empty() {
                    return Err(ParseError::BadValue);
                }
                self.key_id = Some(parse_hex32(v)?);
            }
            b"rt" => {
                let (b, tail) = parse_bool(after)?;
                if !skip_inline_ws(tail).is_empty() {
                    return Err(ParseError::BadValue);
                }
                self.rt = b;
            }
            b"mem_pages_max" => {
                let (n, tail) = parse_unsigned_int(after)?;
                if !skip_inline_ws(tail).is_empty() {
                    return Err(ParseError::BadValue);
                }
                self.mem_pages_max = u32::try_from(n).map_err(|_| ParseError::BadValue)?;
            }
            b"warrants" => {
                if self.warrants_len != 0 {
                    return Err(ParseError::BadValue);
                }
                self.warrants_len = parse_string_array(
                    after,
                    crate::types::MAX_TARGET_LEN + 16,
                    &mut self.warrants,
                    ParseError::Admission(AdmissionError::TooManySigners),
                )?;
            }
            _ => return Err(ParseError::UnknownField),
        }
        Ok(())
    }

    fn commit(self, topology: &mut Topology<'a>) -> Result<(), ParseError> {
        let key_id = self.key_id.ok_or(ParseError::MissingField)?;
        topology
            .push_signer(self.name, key_id, self.rt, self.mem_pages_max, &self.warrants[..self.warrants_len])
            .map_err(ParseError::Admission)
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

/// Close a `[device.NAME]` section: a row without `match` selects nothing and
/// is refused, never read as "everything".
fn commit_device<'a>(
    topology: &mut Topology<'a>,
    spec: DeviceSpec<'a>,
    has_match: bool,
) -> Result<(), ParseError> {
    if !has_match {
        return Err(ParseError::MissingField);
    }
    topology.push_device(spec).map_err(ParseError::Admission)
}

/// One kv line inside a `[device.NAME]` section: `match = "<selector>"`
/// (required), `driver = "<native driver>"` and `admit = true | false`
/// (default true). Nothing may follow a value.
fn handle_device_kv<'a>(
    line: &'a [u8],
    spec: &mut DeviceSpec<'a>,
    has_match: &mut bool,
    format: u8,
) -> Result<(), ParseError> {
    let (key, after) = take_ident(line)?;
    let after = skip_inline_ws(after);
    if !after.starts_with(b"=") {
        return Err(ParseError::MissingEquals);
    }
    let after = skip_inline_ws(&after[1..]);
    let quoted = |after: &'a [u8]| -> Result<&'a [u8], ParseError> {
        let (v, tail) = parse_quoted_string(after, crate::types::DEVICE_SELECT_MAX)?;
        if !skip_inline_ws(tail).is_empty() {
            return Err(ParseError::BadValue);
        }
        Ok(v)
    };
    match key {
        b"match" => {
            if *has_match {
                return Err(ParseError::BadValue);
            }
            spec.select = MaybeStr::from_bytes(quoted(after)?);
            *has_match = true;
            Ok(())
        }
        b"driver" => {
            spec.driver = MaybeStr::from_bytes(quoted(after)?);
            Ok(())
        }
        b"admit" => {
            let (b, tail) = parse_bool(after)?;
            if !skip_inline_ws(tail).is_empty() {
                return Err(ParseError::BadValue);
            }
            spec.admit = b;
            Ok(())
        }
        // Format 7: the failure contract of the device (innovation B2). The
        // operation names are checked when the row is committed
        // (`Topology::push_device`); `commit_ns` is a `u64`.
        b"safe_state" | b"compensate" | b"commit_ns" => {
            if format < 7 {
                return Err(ParseError::FieldNeedsFormat);
            }
            if key == b"commit_ns" {
                spec.commit_ns = uint_only(after, u64::MAX)?;
                return Ok(());
            }
            // A key that is present names an operation: `""` is a typo, not
            // "none".
            let op = quoted_only(after, crate::types::MAX_TASK_NAME_LEN)?;
            if op.is_empty() {
                return Err(ParseError::BadValue);
            }
            if key == b"safe_state" {
                spec.safe_state = MaybeStr::from_bytes(op);
            } else {
                spec.compensate = MaybeStr::from_bytes(op);
            }
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
                | Section::Device(_)
                | Section::Signer(_)
                | Section::Peer(_)
                | Section::Policy(_)
                | Section::Livepatch(_)
                | Section::Degrade(_)
                | Section::Clock
                | Section::Swap(_)
                | Section::Login(_)
                | Section::Volume(_)
                | Section::Guest(_)
                | Section::Route(_)
                | Section::Firewall(_)
                | Section::V8(..)
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
    // E2. Without the `energy` feature the sections were skipped
    // above and nothing reads them: the kernel runs with no model (I4).
    #[cfg(feature = "energy")]
    topology.set_energy(parse_energy(input)?);
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// Energy model
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
        "envelope" => {
            staged.envelope = Envelope::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?;
        }
        "principal" => {
            staged.principal =
                PrincipalKind::from_bytes(quoted_only(after, 16)?).ok_or(ParseError::UnknownEnumValue)?;
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
        // The CPUs kept for isolated rows, a mask like `cpu_mask` (a `u32`,
        // refused rather than truncated). Checked against the rows and the
        // machine at admission.
        "isolcpus" => {
            cfg.isolcpus = uint_only(after, u32::MAX as u64)? as u32;
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
        // `endpoint`, not `motor` (M40, 2026-09-26): `motor` now requires the
        // `profile-actuation` feature (see `parse_cap_kind`), and this test
        // is about the unterminated-array guard, not about `motor` — using
        // an always-accepted kind keeps it testing the same hazard under
        // either feature set.
        let caps = b"[task.a]\ncaps = [ { kind = \"endpoint\", target = \"gpio.0\", perm = \"rw\" },";
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::UnterminatedArray));
    }

    /// The guard must not reject well-formed multi-line arrays: the
    /// closing `]` arrives on its own line, several blank/comment lines
    /// after the last inline table.
    #[test]
    fn multi_line_caps_array_still_parses() {
        let mut topo = Topology::empty();
        // `endpoint`, not `motor` — same M40 reason as the test above.
        let caps = b"[task.a]\ncaps = [\n  { kind = \"endpoint\", target = \"gpio.0\", perm = \"rw\" },\n\n  # trailing comment\n]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert_eq!(topo.tasks_len(), 1);
    }

    // ── M40 (U10-6, 2026-09-26): the `motor` endpoint requires profile-actuation ────
    //
    // Mirrors `builder.rs`'s existing `autorun_task_declares_both_
    // drivetrain_motor_grants` test, which already runs this same file
    // twice under CI (`tools/ci_check.sh`'s "topology-tests" row with no
    // features, and its "topology(cap-canary)" row with
    // `cap-refusal-canary,profile-actuation`) — one test body, two
    // opposite assertions selected by the SAME cfg the parser itself uses.
    #[cfg(feature = "profile-actuation")]
    #[test]
    fn the_motor_endpoint_parses_under_profile_actuation() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"endpoint\", target = \"motor.0\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert_eq!(topo.caps_of(&topo.tasks()[0])[0].kind, CapKind::Endpoint);
        assert_eq!(topo.caps_of(&topo.tasks()[0])[0].target.as_str(), "motor.0");
    }

    #[cfg(not(feature = "profile-actuation"))]
    #[test]
    fn the_motor_endpoint_is_refused_without_profile_actuation() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"endpoint\", target = \"motor.0\", perm = \"rw\" } ]\n";
        // Not `NoMinter`-shaped silence — a parse-time refusal, so a
        // topology asking for something this build cannot honour is
        // rejected before it is ever admitted, not silently capless.
        assert_eq!(parse_caps(caps, &mut topo), Err(ParseError::UnknownEnumValue));
    }

    // ── W2-B5 task 2 (U03-2): `Cap<Irq>` declaration is parser-ready ───
    //
    // `crates/core/ipc/src/cap_seed.rs` has no minter arm for `ty::IRQ`
    // (A2's side of this gap — `seed_one_cap(.., ty::IRQ, .., "irq.3")`
    // returns `None` today, by that crate's own test). This proves the
    // OTHER half is not the blocker: a topology can already DECLARE an IRQ
    // grant end-to-end through the real parser, with the "irq.<N>" target
    // convention `cap_seed.rs`'s own tests already assume, so the day a
    // minter arm is added there, nothing on the declaration side needs to
    // change.
    #[test]
    fn irq_cap_declaration_parses_end_to_end() {
        let mut topo = Topology::empty();
        let caps = b"[task.gpio_drv]\ncaps = [ { kind = \"device\", target = \"irq.5\", perm = \"r\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert_eq!(topo.tasks_len(), 1);
        let task = &topo.tasks()[0];
        let cap_list = topo.caps_of(task);
        assert_eq!(cap_list.len(), 1);
        assert_eq!(cap_list[0].kind, ty::IRQ);
        assert_eq!(cap_list[0].perms, CapPerms::READ);
        assert_eq!(cap_list[0].target, MaybeStr::from_bytes(b"irq.5"));
    }

    // ── O3.4 (owner decision 2026-09-26): `transfer` key ────────────────

    /// `transfer` defaults to `false` when absent — a row hands out
    /// authority to move the capability only when it says so explicitly.
    #[test]
    fn cap_transfer_defaults_to_false() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"queue\", target = \"7\", perm = \"rw\" } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert!(!topo.caps_of(&topo.tasks()[0])[0].transfer);
    }

    /// `transfer = true` is read through and sets the field.
    #[test]
    fn cap_transfer_true_is_read_through() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"queue\", target = \"7\", perm = \"rw\", transfer = true } ]\n";
        assert!(parse_caps(caps, &mut topo).is_ok());
        assert!(topo.caps_of(&topo.tasks()[0])[0].transfer);
    }

    /// A non-boolean `transfer` value is a type error, not a silent `false`.
    #[test]
    fn cap_transfer_non_bool_is_rejected() {
        let mut topo = Topology::empty();
        let caps = b"[task.autorun]\ncaps = [ { kind = \"queue\", target = \"7\", perm = \"rw\", transfer = \"yes\" } ]\n";
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
