// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A [`Topology`] written back out as the two signed formats: `SCHED.TOML`
//! (classes, `[sched]`) and `CAPS.TOML` (`format`, `[task.*]`, `[pipeline.*]`,
//! `[operator]`), the text [`crate::parser`] reads.
//!
//! The build uses it to ship the built-in topology as signed files
//! (`tests/host/topology-tests/src/bin/topo_emit.rs`, `make topology-files`):
//! what a kernel built from the same features and `.config` installs from
//! `builder.rs`, it installs from the volume. `topology-tests` proves the
//! round trip field by field (built-in -> text -> parsed -> equal).
//!
//! Everything the parser can express is written; what it cannot is refused
//! with an [`EmitError`], never dropped: a file that silently lacked a grant,
//! a profile or a key would be a different topology under the same signature.
//! Fields at their parser default are left out, so the text a reader audits
//! carries only what a row declares.
//!
//! `no_std`, through [`core::fmt::Write`]: no allocation, so the kernel could
//! call it too; today only the host emitter does.

use core::fmt::Write;

use crate::parser::Binding;
use crate::placement::Host;
use crate::types::{MaybeStr, RestartPolicy, TaskAbi, Topology};

/// The `format` the emitter writes: the newest the parser reads
/// ([`crate::parser::CAPS_FORMAT_MAX`]), so every key it may write is legal.
pub const EMIT_FORMAT: u8 = crate::parser::CAPS_FORMAT_MAX;

/// Why a topology could not be written as text the parser reads back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EmitError {
    /// The writer refused a write (a full fixed buffer, say).
    Write,
    /// A grant's kind has no word in the parser's table
    /// ([`crate::parser::cap_kind_word`]): a signed file cannot grant it.
    UnnamedCapKind(u8),
    /// A name or string holds a byte the parser cannot read back (a quote,
    /// a backslash, a line end; in a section name also `]`, `#` or a space).
    Unrepresentable,
    /// The topology declares an energy model; the emitter does not write the
    /// `[energy]` sections yet.
    EnergyModel,
}

impl From<core::fmt::Error> for EmitError {
    fn from(_: core::fmt::Error) -> Self {
        EmitError::Write
    }
}

fn quoted<'a>(s: &MaybeStr<'a>) -> Result<&'a str, EmitError> {
    let b = s.as_bytes();
    if b.iter().any(|&c| c == b'"' || c == b'\\' || c == b'\n' || c == b'\r') {
        return Err(EmitError::Unrepresentable);
    }
    core::str::from_utf8(b).map_err(|_| EmitError::Unrepresentable)
}

fn section_name<'a>(s: &MaybeStr<'a>) -> Result<&'a str, EmitError> {
    let b = s.as_bytes();
    if b.is_empty()
        || b.iter().any(|&c| c == b']' || c == b'#' || c == b'"' || c.is_ascii_whitespace() || c < 0x20)
    {
        return Err(EmitError::Unrepresentable);
    }
    core::str::from_utf8(b).map_err(|_| EmitError::Unrepresentable)
}

/// Write `SCHED.TOML`: `[sched]`, then one `[class.NAME]` per class in order.
pub fn emit_sched<W: Write>(topo: &Topology<'_>, out: &mut W) -> Result<(), EmitError> {
    #[cfg(feature = "energy")]
    if *topo.energy() != azos_energy::EnergySpec::DEFAULT {
        return Err(EmitError::EnergyModel);
    }
    writeln!(out, "# SCHED.TOML (RFC-0005), the scheduler classes of the topology.")?;
    writeln!(out, "[sched]")?;
    writeln!(out, "partition_window_us = {}", topo.sched_config().partition_window_us)?;
    for c in topo.classes() {
        writeln!(out)?;
        writeln!(out, "[class.{}]", section_name(&c.name)?)?;
        writeln!(out, "cpu_budget_min_pct = {}", c.cpu_budget_min_pct)?;
        writeln!(out, "cpu_budget_max_pct = {}", c.cpu_budget_max_pct)?;
        writeln!(out, "policy = \"{}\"", c.policy.as_str())?;
        writeln!(out, "priority_range = [{}, {}]", c.priority_range.0, c.priority_range.1)?;
        writeln!(out, "preemption = \"{}\"", c.preemption.as_str())?;
        writeln!(out, "time_slice_ms = {}", c.time_slice_ms)?;
        writeln!(out, "admission_control = {}", c.admission_control)?;
    }
    Ok(())
}

fn perm_letters(p: azos_abi::cap::CapPerms) -> ([u8; 4], usize) {
    use azos_abi::cap::CapPerms;
    let mut b = [0u8; 4];
    let mut n = 0;
    for (bit, ch) in [(CapPerms::READ, b'r'), (CapPerms::WRITE, b'w'), (CapPerms::EXEC, b'x'), (CapPerms::DUP, b'd')] {
        if p.contains(bit) {
            b[n] = ch;
            n += 1;
        }
    }
    (b, n)
}

/// Write `CAPS.TOML`: `format`, the [`Binding`] keys `binding` carries
/// (`device`, `counter`, `sched_sha256`; its `format` is ignored), one
/// `[task.NAME]` per row in order (its grants in order), then
/// `[pipeline.NAME]`, `[device.NAME]`, `[signer.NAME]`, `[peer.NAME]` and `[operator]` when declared.
pub fn emit_caps<W: Write>(topo: &Topology<'_>, binding: &Binding, out: &mut W) -> Result<(), EmitError> {
    writeln!(out, "# CAPS.TOML (RFC-0005), the capability rows of the topology.")?;
    writeln!(out, "format = {}", EMIT_FORMAT)?;
    if let Some(d) = binding.device {
        write!(out, "device = \"")?;
        for b in d {
            write!(out, "{:02x}", b)?;
        }
        writeln!(out, "\"")?;
    }
    if let Some(c) = binding.counter {
        writeln!(out, "counter = {}", c)?;
    }
    if let Some(h) = binding.sched_sha256 {
        write!(out, "sched_sha256 = \"")?;
        for b in h {
            write!(out, "{:02x}", b)?;
        }
        writeln!(out, "\"")?;
    }
    for t in topo.tasks() {
        writeln!(out)?;
        writeln!(out, "[task.{}]", section_name(&t.name)?)?;
        writeln!(out, "class = \"{}\"", quoted(&t.class_name)?)?;
        writeln!(out, "priority = {}", t.priority)?;
        let p = t.profile;
        if p.period_us != 0 { writeln!(out, "period_us = {}", p.period_us)?; }
        if p.runtime_us != 0 { writeln!(out, "runtime_us = {}", p.runtime_us)?; }
        if p.deadline_us != 0 { writeln!(out, "deadline_us = {}", p.deadline_us)?; }
        if p.cpu_mask != 0 { writeln!(out, "cpu_mask = {}", p.cpu_mask)?; }
        if t.mem_pages != 0 { writeln!(out, "mem_pages = {}", t.mem_pages)?; }
        if t.mem_locked { writeln!(out, "mem = \"locked\"")?; }
        if t.mem_huge_mib != 0 { writeln!(out, "mem_huge_mib = {}", t.mem_huge_mib)?; }
        if t.sqpoll_idle_ms != 0 { writeln!(out, "sqpoll_idle_ms = {}", t.sqpoll_idle_ms)?; }
        if t.instances != 0 { writeln!(out, "instances = {}", t.instances)?; }
        if t.start { writeln!(out, "start = true")?; }
        if t.lease_seal { writeln!(out, "lease_seal = true")?; }
        if t.restart != RestartPolicy::OnFailure { writeln!(out, "restart = \"{}\"", t.restart.as_str())?; }
        if t.abi != TaskAbi::Native { writeln!(out, "abi = \"{}\"", t.abi.as_str())?; }
        if t.timer_slack { writeln!(out, "timer_slack = true")?; }
        if !t.lx_class.is_empty() { writeln!(out, "lx_class = \"{}\"", quoted(&t.lx_class)?)?; }
        if t.place.host != Host::Ring3 { writeln!(out, "place = \"{}\"", t.place.host.as_str())?; }
        if t.place.stateless { writeln!(out, "stateless = true")?; }
        if t.place.call_budget_us != 0 { writeln!(out, "call_budget_us = {}", t.place.call_budget_us)?; }
        let imports = topo.imports_of(t);
        if !imports.is_empty() {
            write!(out, "imports = [")?;
            for (i, n) in imports.iter().enumerate() {
                write!(out, "{}\"{}\"", if i == 0 { "" } else { ", " }, quoted(n)?)?;
            }
            writeln!(out, "]")?;
        }
        let exports = topo.exports_of(t);
        if !exports.is_empty() {
            write!(out, "export = [")?;
            for (i, e) in exports.iter().enumerate() {
                write!(out, "{}\"{}@{}\"", if i == 0 { "" } else { ", " }, quoted(&e.endpoint)?, quoted(&e.peer)?)?;
            }
            writeln!(out, "]")?;
        }
        let caps = topo.caps_of(t);
        if caps.is_empty() {
            writeln!(out, "caps = []")?;
            continue;
        }
        writeln!(out, "caps = [")?;
        for c in caps {
            let word = crate::parser::cap_kind_word(c.kind)
                .ok_or(EmitError::UnnamedCapKind(c.kind as u8))?;
            let (letters, n) = perm_letters(c.perms);
            let perm = core::str::from_utf8(&letters[..n]).map_err(|_| EmitError::Unrepresentable)?;
            write!(out, "    {{ kind = \"{}\", target = \"{}\", perm = \"{}\"", word, quoted(&c.target)?, perm)?;
            if c.transfer {
                write!(out, ", transfer = true")?;
            }
            writeln!(out, " }},")?;
        }
        writeln!(out, "]")?;
    }
    for pl in topo.pipelines() {
        writeln!(out)?;
        writeln!(out, "[pipeline.{}]", section_name(&pl.name)?)?;
        writeln!(out, "dma_kb = {}", pl.dma_pages as u64 * 4)?;
    }
    for d in topo.devices() {
        writeln!(out)?;
        writeln!(out, "[device.{}]", section_name(&d.name)?)?;
        writeln!(out, "match = \"{}\"", quoted(&d.select)?)?;
        if !d.driver.is_empty() { writeln!(out, "driver = \"{}\"", quoted(&d.driver)?)?; }
        if !d.admit { writeln!(out, "admit = false")?; }
    }
    for sg in topo.signers() {
        writeln!(out)?;
        writeln!(out, "[signer.{}]", section_name(&sg.name)?)?;
        write!(out, "key_id = \"")?;
        for b in sg.key_id {
            write!(out, "{:02x}", b)?;
        }
        writeln!(out, "\"")?;
        if sg.rt { writeln!(out, "rt = true")?; }
        writeln!(out, "mem_pages_max = {}", sg.mem_pages_max)?;
        let warrants = topo.warrants_of(sg);
        if !warrants.is_empty() {
            write!(out, "warrants = [")?;
            for (i, w) in warrants.iter().enumerate() {
                write!(out, "{}\"{}\"", if i == 0 { "" } else { ", " }, quoted(w)?)?;
            }
            writeln!(out, "]")?;
        }
    }
    for pe in topo.peers() {
        writeln!(out)?;
        writeln!(out, "[peer.{}]", section_name(&pe.name)?)?;
        write!(out, "nodes = [")?;
        for (i, n) in pe.nodes().iter().enumerate() {
            write!(out, "{}{}", if i == 0 { "" } else { ", " }, n)?;
        }
        writeln!(out, "]")?;
    }
    if topo.has_operator_pubkey() {
        writeln!(out)?;
        writeln!(out, "[operator]")?;
        write!(out, "pubkey = \"")?;
        for b in topo.operator_pubkey() {
            write!(out, "{:02x}", b)?;
        }
        writeln!(out, "\"")?;
    }
    Ok(())
}

/// Where two topologies first differ, or `None` when every field the parser
/// can express is equal: classes, rows (with every row field and each grant,
/// in order), pipelines, device rows, signers, `[sched]` and the operator key. The round-trip check
/// of the emitter (`topo_emit` runs it on every file it writes, and
/// `topology-tests` on the built-in topology of each feature set).
pub fn first_difference(a: &Topology<'_>, b: &Topology<'_>) -> Option<&'static str> {
    if a.classes().len() != b.classes().len() {
        return Some("class count");
    }
    for (x, y) in a.classes().iter().zip(b.classes()) {
        if x.name != y.name { return Some("class name"); }
        if x.cpu_budget_min_pct != y.cpu_budget_min_pct || x.cpu_budget_max_pct != y.cpu_budget_max_pct {
            return Some("class budget");
        }
        if x.policy != y.policy { return Some("class policy"); }
        if x.priority_range != y.priority_range { return Some("class priority_range"); }
        if x.preemption != y.preemption { return Some("class preemption"); }
        if x.time_slice_ms != y.time_slice_ms { return Some("class time_slice_ms"); }
        if x.admission_control != y.admission_control { return Some("class admission_control"); }
    }
    if a.sched_config().partition_window_us != b.sched_config().partition_window_us {
        return Some("sched partition_window_us");
    }
    if a.tasks().len() != b.tasks().len() {
        return Some("task count");
    }
    for (x, y) in a.tasks().iter().zip(b.tasks()) {
        if x.name != y.name { return Some("task name"); }
        if x.class_name != y.class_name { return Some("task class"); }
        if x.priority != y.priority { return Some("task priority"); }
        if x.profile != y.profile { return Some("task real-time profile"); }
        if x.mem_pages != y.mem_pages { return Some("task mem_pages"); }
        if x.mem_locked != y.mem_locked { return Some("task mem"); }
        if x.mem_huge_mib != y.mem_huge_mib { return Some("task mem_huge_mib"); }
        if x.sqpoll_idle_ms != y.sqpoll_idle_ms { return Some("task sqpoll_idle_ms"); }
        if x.instances != y.instances { return Some("task instances"); }
        if x.start != y.start { return Some("task start"); }
        if x.lease_seal != y.lease_seal { return Some("task lease_seal"); }
        if x.restart != y.restart { return Some("task restart"); }
        if x.abi != y.abi { return Some("task abi"); }
        if x.timer_slack != y.timer_slack { return Some("task timer_slack"); }
        if x.lx_class != y.lx_class { return Some("task lx_class"); }
        if x.place != y.place { return Some("task placement"); }
        if topo_imports_differ(a, b, x, y) { return Some("task imports"); }
        if topo_exports_differ(a, b, x, y) { return Some("task exports"); }
        let (cx, cy) = (a.caps_of(x), b.caps_of(y));
        if cx.len() != cy.len() { return Some("task grant count"); }
        for (p, q) in cx.iter().zip(cy) {
            if p.kind != q.kind { return Some("grant kind"); }
            if p.perms != q.perms { return Some("grant perm"); }
            if p.target != q.target { return Some("grant target"); }
            if p.transfer != q.transfer { return Some("grant transfer"); }
        }
    }
    if a.pipelines().len() != b.pipelines().len() {
        return Some("pipeline count");
    }
    for (x, y) in a.pipelines().iter().zip(b.pipelines()) {
        if x.name != y.name || x.dma_pages != y.dma_pages { return Some("pipeline"); }
    }
    if a.devices().len() != b.devices().len() {
        return Some("device row count");
    }
    for (x, y) in a.devices().iter().zip(b.devices()) {
        if x.name != y.name || x.select != y.select || x.admit != y.admit || x.driver != y.driver {
            return Some("device row");
        }
    }
    if a.signers().len() != b.signers().len() {
        return Some("signer count");
    }
    for (x, y) in a.signers().iter().zip(b.signers()) {
        if x.name != y.name || x.key_id != y.key_id || x.rt != y.rt || x.mem_pages_max != y.mem_pages_max {
            return Some("signer");
        }
        let (p, q) = (a.warrants_of(x), b.warrants_of(y));
        if p.len() != q.len() || p.iter().zip(q).any(|(m, n)| m.as_bytes() != n.as_bytes()) {
            return Some("signer warrants");
        }
    }
    if a.peers().len() != b.peers().len() {
        return Some("peer count");
    }
    for (x, y) in a.peers().iter().zip(b.peers()) {
        if x.name != y.name || x.nodes() != y.nodes() { return Some("peer"); }
    }
    if a.operator_pubkey() != b.operator_pubkey() {
        return Some("operator pubkey");
    }
    None
}

fn topo_exports_differ(a: &Topology<'_>, b: &Topology<'_>, x: &crate::types::TaskSpec<'_>, y: &crate::types::TaskSpec<'_>) -> bool {
    let (p, q) = (a.exports_of(x), b.exports_of(y));
    p.len() != q.len()
        || p.iter().zip(q).any(|(m, n)| m.endpoint.as_bytes() != n.endpoint.as_bytes() || m.peer.as_bytes() != n.peer.as_bytes())
}

fn topo_imports_differ(a: &Topology<'_>, b: &Topology<'_>, x: &crate::types::TaskSpec<'_>, y: &crate::types::TaskSpec<'_>) -> bool {
    let (p, q) = (a.imports_of(x), b.imports_of(y));
    p.len() != q.len() || p.iter().zip(q).any(|(m, n)| m.as_bytes() != n.as_bytes())
}
