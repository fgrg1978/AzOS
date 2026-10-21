// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A [`Topology`] written back out as the two signed formats: `SCHED.TOML`
//! (classes, `[sched]`) and `CAPS.TOML` (`format`, `[task.*]`, `[pipeline.*]`,
//! `[device.*]`, `[signer.*]`, `[peer.*]`, the format-7 sections, `[operator]`),
//! the text [`crate::parser`] reads.
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
use crate::types::{Envelope, FwProto, MaybeStr, PolicyScope, PrincipalKind, RestartPolicy, TaskAbi, Topology};

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

fn write_hex<W: Write>(out: &mut W, bytes: &[u8]) -> Result<(), EmitError> {
    for b in bytes {
        write!(out, "{:02x}", b)?;
    }
    Ok(())
}

/// Write `SCHED.TOML`: `[sched]`, then one `[class.NAME]` per class in order.
pub fn emit_sched<W: Write>(topo: &Topology<'_>, out: &mut W) -> Result<(), EmitError> {
    #[cfg(feature = "energy")]
    if *topo.energy() != azos_energy::EnergySpec::DEFAULT {
        return Err(EmitError::EnergyModel);
    }
    writeln!(out, "# SCHED.TOML, the scheduler classes of the topology.")?;
    writeln!(out, "[sched]")?;
    writeln!(out, "partition_window_us = {}", topo.sched_config().partition_window_us)?;
    if topo.sched_config().isolcpus != 0 {
        writeln!(out, "isolcpus = {}", topo.sched_config().isolcpus)?;
    }
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
        if c.envelope != Envelope::Full { writeln!(out, "envelope = \"{}\"", c.envelope.as_str())?; }
        if c.principal != PrincipalKind::System { writeln!(out, "principal = \"{}\"", c.principal.as_str())?; }
    }
    Ok(())
}

fn perm_letters(p: azos_abi::cap::CapPerms) -> ([u8; 6], usize) {
    use azos_abi::cap::CapPerms;
    let mut b = [0u8; 6];
    let mut n = 0;
    for (bit, ch) in [
        (CapPerms::READ, b'r'),
        (CapPerms::WRITE, b'w'),
        (CapPerms::EXEC, b'x'),
        (CapPerms::DUP, b'd'),
        (CapPerms::TRANSFER, b't'),
        (CapPerms::MAP, b'm'),
    ] {
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
/// `[pipeline.NAME]`, `[device.NAME]`, `[signer.NAME]`, `[peer.NAME]`, `[policy.NAME]`, `[livepatch.NAME]`, `[degrade.NAME]`, `[swap.NAME]`, `[login.NAME]`, `[volume.NAME]`, `[guest.NAME]`, `[route.NAME]`, `[firewall.NAME]`, `[clock]`, the format-8 rows (`[tsn.NAME]`, `[fieldbus.NAME]`, `[audio.NAME]`, `[display.NAME]`, `[user.NAME]`, `[key.NAME]`, `[mission]`, `[boot_chain.NAME]`, `[island.NAME]`, `[activity.NAME]`, `[numa.NAME]`, `[envelope.NAME]`, `[rtc]`, `[nic.NAME]`, `[model.NAME]`, `[usb.NAME]`) and `[operator]` when declared.
pub fn emit_caps<W: Write>(topo: &Topology<'_>, binding: &Binding, out: &mut W) -> Result<(), EmitError> {
    writeln!(out, "# CAPS.TOML, the capability rows of the topology.")?;
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
        if t.restart != RestartPolicy::OnFailure { writeln!(out, "restart = \"{}\"", t.restart.as_str())?; }
        if t.abi != TaskAbi::Native { writeln!(out, "abi = \"{}\"", t.abi.as_str())?; }
        if t.timer_slack { writeln!(out, "timer_slack = true")?; }
        if !t.lx_class.is_empty() { writeln!(out, "lx_class = \"{}\"", quoted(&t.lx_class)?)?; }
        if t.place.host != Host::Ring3 { writeln!(out, "place = \"{}\"", t.place.host.as_str())?; }
        if t.place.stateless { writeln!(out, "stateless = true")?; }
        if t.place.call_budget_us != 0 { writeln!(out, "call_budget_us = {}", t.place.call_budget_us)?; }
        if t.shadow { writeln!(out, "shadow = true")?; }
        if t.isolated { writeln!(out, "isolated = true")?; }
        if t.kmem_kib != 0 { writeln!(out, "kmem_kib = {}", t.kmem_kib)?; }
        if let Some(p) = t.principal { writeln!(out, "principal = \"{}\"", p.as_str())?; }
        if t.security_boundary { writeln!(out, "security_boundary = true")?; }
        if t.partition_id != 0 { writeln!(out, "partition_id = {}", t.partition_id)?; }
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
                write!(out, "{}\"{}@{}", if i == 0 { "" } else { ", " }, quoted(&e.endpoint)?, quoted(&e.peer)?)?;
                write!(out, "\"")?;
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
            if c.ops != 0 {
                write!(out, ", ops = {}", c.ops)?;
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
        if !d.safe_state.is_empty() { writeln!(out, "safe_state = \"{}\"", quoted(&d.safe_state)?)?; }
        if d.commit_ns != 0 { writeln!(out, "commit_ns = {}", d.commit_ns)?; }
        if !d.compensate.is_empty() { writeln!(out, "compensate = \"{}\"", quoted(&d.compensate)?)?; }
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
        if !pe.noise_pks().is_empty() {
            write!(out, "noise_pk = [")?;
            for (i, k) in pe.noise_pks().iter().enumerate() {
                write!(out, "{}\"", if i == 0 { "" } else { ", " })?;
                write_hex(out, k)?;
                write!(out, "\"")?;
            }
            writeln!(out, "]")?;
        }
        if let Some(m) = pe.measurement {
            write!(out, "measurement = \"")?;
            write_hex(out, &m)?;
            writeln!(out, "\"")?;
        }
    }
    for po in topo.policies() {
        writeln!(out)?;
        writeln!(out, "[policy.{}]", section_name(&po.name)?)?;
        writeln!(out, "domain = \"{}\"", quoted(&po.domain)?)?;
        if po.scope != PolicyScope::This { writeln!(out, "scope = \"{}\"", po.scope.as_str())?; }
        if !po.create_endpoints { writeln!(out, "create_endpoints = false")?; }
        if !po.create_ports { writeln!(out, "create_ports = false")?; }
        if po.memobj_max_pages != 0 { writeln!(out, "memobj_max_pages = {}", po.memobj_max_pages)?; }
    }
    for l in topo.livepatches() {
        writeln!(out)?;
        writeln!(out, "[livepatch.{}]", section_name(&l.name)?)?;
        writeln!(out, "isa = \"{}\"", l.isa.as_str())?;
        write!(out, "build_id = \"")?;
        write_hex(out, l.build_id.as_bytes())?;
        writeln!(out, "\"")?;
        writeln!(out, "sec_epoch = {}", l.sec_epoch)?;
        write!(out, "sha256 = \"")?;
        write_hex(out, &l.sha256)?;
        writeln!(out, "\"")?;
    }
    for d in topo.degrades() {
        writeln!(out)?;
        writeln!(out, "[degrade.{}]", section_name(&d.name)?)?;
        writeln!(out, "level = \"{}\"", d.level.as_str())?;
        writeln!(out, "battery_pct = {}", d.battery_pct)?;
        if d.clear_pct != d.battery_pct { writeln!(out, "clear_pct = {}", d.clear_pct)?; }
    }
    for sw in topo.swaps() {
        writeln!(out)?;
        writeln!(out, "[swap.{}]", section_name(&sw.name)?)?;
        writeln!(out, "partition = {}", sw.partition)?;
    }
    for l in topo.logins() {
        writeln!(out)?;
        writeln!(out, "[login.{}]", section_name(&l.name)?)?;
        write!(out, "ssh_key = [")?;
        for (i, k) in l.keys().iter().enumerate() {
            write!(out, "{}\"", if i == 0 { "" } else { ", " })?;
            write_hex(out, k)?;
            write!(out, "\"")?;
        }
        writeln!(out, "]")?;
    }
    for v in topo.volumes() {
        writeln!(out)?;
        writeln!(out, "[volume.{}]", section_name(&v.name)?)?;
        writeln!(out, "partition = {}", v.partition)?;
        writeln!(out, "mount = \"{}\"", quoted(&v.mount)?)?;
        if v.read_only { writeln!(out, "read_only = true")?; }
        if v.aead { writeln!(out, "aead = true")?; }
        if let Some(r) = v.verity_root {
            write!(out, "verity_root = \"")?;
            write_hex(out, &r)?;
            writeln!(out, "\"")?;
        }
    }
    for g in topo.guests() {
        writeln!(out)?;
        writeln!(out, "[guest.{}]", section_name(&g.name)?)?;
        writeln!(out, "cpus = {}", g.cpus)?;
        writeln!(out, "mem_mib = {}", g.mem_mib)?;
        writeln!(out, "envelope = \"{}\"", g.envelope.as_str())?;
        if !g.devices().is_empty() {
            write!(out, "devices = [")?;
            for (i, d) in g.devices().iter().enumerate() {
                write!(out, "{}\"{}\"", if i == 0 { "" } else { ", " }, quoted(d)?)?;
            }
            writeln!(out, "]")?;
        }
        if !g.passthrough().is_empty() {
            write!(out, "passthrough = [")?;
            for (i, d) in g.passthrough().iter().enumerate() {
                write!(out, "{}\"{}\"", if i == 0 { "" } else { ", " }, quoted(d)?)?;
            }
            writeln!(out, "]")?;
        }
        if g.static_partition {
            writeln!(out, "static = true")?;
            writeln!(out, "pcpus = {}", g.pcpus)?;
            writeln!(out, "mem_base = {}", g.mem_base)?;
        }
    }
    for r in topo.routes() {
        writeln!(out)?;
        writeln!(out, "[route.{}]", section_name(&r.name)?)?;
        writeln!(out, "dest = \"{}\"", r.dest)?;
        if let Some(g) = r.via { writeln!(out, "via = \"{}\"", g)?; }
        writeln!(out, "dev = \"{}\"", quoted(&r.dev)?)?;
        if r.metric != 0 { writeln!(out, "metric = {}", r.metric)?; }
    }
    for f in topo.firewalls() {
        writeln!(out)?;
        writeln!(out, "[firewall.{}]", section_name(&f.name)?)?;
        writeln!(out, "dir = \"{}\"", f.dir.as_str())?;
        if f.proto != FwProto::Any { writeln!(out, "proto = \"{}\"", f.proto.as_str())?; }
        if f.port_lo != 0 {
            writeln!(out, "port = {}", f.port_lo)?;
            if f.port_hi != f.port_lo { writeln!(out, "port_end = {}", f.port_hi)?; }
        }
        if let Some(a) = f.addr { writeln!(out, "addr = \"{}\"", a)?; }
        writeln!(out, "action = \"{}\"", f.action.as_str())?;
    }
    let clock = topo.clock();
    if clock.is_declared() {
        writeln!(out)?;
        writeln!(out, "[clock]")?;
        if let Some(d) = clock.ptp_domain { writeln!(out, "ptp_domain = {}", d)?; }
        if !clock.leaps().is_empty() {
            write!(out, "leaps = [")?;
            for (i, l) in clock.leaps().iter().enumerate() {
                write!(out, "{}\"{}:{}\"", if i == 0 { "" } else { ", " }, l.utc_secs, l.tai_offset)?;
            }
            writeln!(out, "]")?;
        }
    }
    emit_format8(topo, out)?;
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
        if x.envelope != y.envelope { return Some("class envelope"); }
        if x.principal != y.principal { return Some("class principal"); }
    }
    if a.sched_config().partition_window_us != b.sched_config().partition_window_us {
        return Some("sched partition_window_us");
    }
    if a.sched_config().isolcpus != b.sched_config().isolcpus {
        return Some("sched isolcpus");
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
        if x.restart != y.restart { return Some("task restart"); }
        if x.abi != y.abi { return Some("task abi"); }
        if x.timer_slack != y.timer_slack { return Some("task timer_slack"); }
        if x.lx_class != y.lx_class { return Some("task lx_class"); }
        if x.place != y.place { return Some("task placement"); }
        if x.shadow != y.shadow { return Some("task shadow"); }
        if x.isolated != y.isolated { return Some("task isolated"); }
        if x.kmem_kib != y.kmem_kib { return Some("task kmem_kib"); }
        if x.principal != y.principal { return Some("task principal"); }
        if x.security_boundary != y.security_boundary { return Some("task security_boundary"); }
        if x.partition_id != y.partition_id { return Some("task partition_id"); }
        if topo_imports_differ(a, b, x, y) { return Some("task imports"); }
        if topo_exports_differ(a, b, x, y) { return Some("task exports"); }
        let (cx, cy) = (a.caps_of(x), b.caps_of(y));
        if cx.len() != cy.len() { return Some("task grant count"); }
        for (p, q) in cx.iter().zip(cy) {
            if p.kind != q.kind { return Some("grant kind"); }
            if p.perms != q.perms { return Some("grant perm"); }
            if p.target != q.target { return Some("grant target"); }
            if p.transfer != q.transfer { return Some("grant transfer"); }
            if p.ops != q.ops { return Some("grant ops"); }
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
        if x.safe_state != y.safe_state || x.commit_ns != y.commit_ns || x.compensate != y.compensate {
            return Some("device failure contract");
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
        if x.noise_pks() != y.noise_pks() { return Some("peer noise_pk"); }
        if x.measurement != y.measurement { return Some("peer measurement"); }
    }
    if a.policies().len() != b.policies().len() {
        return Some("policy count");
    }
    for (x, y) in a.policies().iter().zip(b.policies()) {
        if x.name != y.name
            || x.domain != y.domain
            || x.scope != y.scope
            || x.create_endpoints != y.create_endpoints
            || x.create_ports != y.create_ports
            || x.memobj_max_pages != y.memobj_max_pages
        {
            return Some("policy");
        }
    }
    if a.livepatches().len() != b.livepatches().len() {
        return Some("livepatch count");
    }
    for (x, y) in a.livepatches().iter().zip(b.livepatches()) {
        if x.name != y.name
            || x.isa != y.isa
            || x.build_id != y.build_id
            || x.sec_epoch != y.sec_epoch
            || x.sha256 != y.sha256
        {
            return Some("livepatch");
        }
    }
    if a.degrades().len() != b.degrades().len() {
        return Some("degrade count");
    }
    for (x, y) in a.degrades().iter().zip(b.degrades()) {
        if x.name != y.name || x.level != y.level || x.battery_pct != y.battery_pct || x.clear_pct != y.clear_pct {
            return Some("degrade");
        }
    }
    if a.routes().len() != b.routes().len() {
        return Some("route count");
    }
    for (x, y) in a.routes().iter().zip(b.routes()) {
        if x.name != y.name || x.dest != y.dest || x.via != y.via || x.dev != y.dev || x.metric != y.metric {
            return Some("route");
        }
    }
    if a.firewalls().len() != b.firewalls().len() {
        return Some("firewall count");
    }
    for (x, y) in a.firewalls().iter().zip(b.firewalls()) {
        if x.name != y.name
            || x.dir != y.dir
            || x.proto != y.proto
            || x.port_lo != y.port_lo
            || x.port_hi != y.port_hi
            || x.addr != y.addr
            || x.action != y.action
        {
            return Some("firewall");
        }
    }
    if a.guests().len() != b.guests().len() {
        return Some("guest count");
    }
    for (x, y) in a.guests().iter().zip(b.guests()) {
        if x.name != y.name
            || x.cpus != y.cpus
            || x.mem_mib != y.mem_mib
            || x.envelope != y.envelope
            || x.devices().len() != y.devices().len()
            || x.devices().iter().zip(y.devices()).any(|(m, n)| m.as_bytes() != n.as_bytes())
            || x.passthrough() != y.passthrough()
            || x.static_partition != y.static_partition
            || x.pcpus != y.pcpus
            || x.mem_base != y.mem_base
        {
            return Some("guest");
        }
    }
    if a.swaps().len() != b.swaps().len() {
        return Some("swap count");
    }
    for (x, y) in a.swaps().iter().zip(b.swaps()) {
        if x.name != y.name || x.partition != y.partition {
            return Some("swap");
        }
    }
    if a.logins().len() != b.logins().len() {
        return Some("login count");
    }
    for (x, y) in a.logins().iter().zip(b.logins()) {
        if x.name != y.name || x.keys() != y.keys() {
            return Some("login");
        }
    }
    if a.volumes().len() != b.volumes().len() {
        return Some("volume count");
    }
    for (x, y) in a.volumes().iter().zip(b.volumes()) {
        if x.name != y.name
            || x.partition != y.partition
            || x.mount != y.mount
            || x.read_only != y.read_only
            || x.aead != y.aead
            || x.verity_root != y.verity_root
        {
            return Some("volume");
        }
    }
    if a.clock().ptp_domain != b.clock().ptp_domain {
        return Some("clock ptp_domain");
    }
    if a.clock().leaps() != b.clock().leaps() {
        return Some("clock leaps");
    }
    if a.tsns() != b.tsns() { return Some("tsn"); }
    if a.fieldbuses() != b.fieldbuses() { return Some("fieldbus"); }
    if a.audios() != b.audios() { return Some("audio"); }
    if a.displays() != b.displays() { return Some("display"); }
    if a.users() != b.users() { return Some("user"); }
    if a.keys() != b.keys() { return Some("key"); }
    if a.mission() != b.mission() { return Some("mission"); }
    if a.boot_chain() != b.boot_chain() { return Some("boot_chain"); }
    if a.islands() != b.islands() { return Some("island"); }
    if a.activities() != b.activities() { return Some("activity"); }
    if a.numa_nodes() != b.numa_nodes() { return Some("numa"); }
    if a.envelopes() != b.envelopes() { return Some("envelope"); }
    if a.rtc() != b.rtc() { return Some("rtc"); }
    if a.nics() != b.nics() { return Some("nic"); }
    if a.models() != b.models() { return Some("model"); }
    if a.usb_rules() != b.usb_rules() { return Some("usb"); }
    if a.operator_pubkey() != b.operator_pubkey() {
        return Some("operator pubkey");
    }
    None
}

/// The format-8 rows, in the order the parser's table lists them. Each key
/// that has a default is written only when it differs from it.
fn emit_format8<W: Write>(topo: &Topology<'_>, out: &mut W) -> Result<(), EmitError> {
    for r in topo.tsns() {
        writeln!(out)?;
        writeln!(out, "[tsn.{}]", section_name(&r.name)?)?;
        writeln!(out, "dev = \"{}\"", quoted(&r.dev)?)?;
        writeln!(out, "window_us = {}", r.window_us)?;
        writeln!(out, "link_budget = {}", r.link_budget)?;
    }
    for r in topo.fieldbuses() {
        writeln!(out)?;
        writeln!(out, "[fieldbus.{}]", section_name(&r.name)?)?;
        writeln!(out, "kind = \"{}\"", r.kind.as_str())?;
        writeln!(out, "dev = \"{}\"", quoted(&r.dev)?)?;
        if r.cycle_us != 0 { writeln!(out, "cycle_us = {}", r.cycle_us)?; }
    }
    for r in topo.audios() {
        writeln!(out)?;
        writeln!(out, "[audio.{}]", section_name(&r.name)?)?;
        writeln!(out, "dev = \"{}\"", quoted(&r.dev)?)?;
        writeln!(out, "rate_hz = {}", r.rate_hz)?;
        writeln!(out, "channels = {}", r.channels)?;
        writeln!(out, "dir = \"{}\"", r.dir.as_str())?;
    }
    for r in topo.displays() {
        writeln!(out)?;
        writeln!(out, "[display.{}]", section_name(&r.name)?)?;
        writeln!(out, "dev = \"{}\"", quoted(&r.dev)?)?;
        writeln!(out, "width = {}", r.width)?;
        writeln!(out, "height = {}", r.height)?;
        if r.rotation != 0 { writeln!(out, "rotation = {}", r.rotation)?; }
        if r.primary { writeln!(out, "primary = true")?; }
    }
    for r in topo.users() {
        writeln!(out)?;
        writeln!(out, "[user.{}]", section_name(&r.name)?)?;
        writeln!(out, "root = \"{}\"", quoted(&r.root)?)?;
        writeln!(out, "keystore = \"{}\"", quoted(&r.keystore)?)?;
    }
    for r in topo.keys() {
        writeln!(out)?;
        writeln!(out, "[key.{}]", section_name(&r.name)?)?;
        writeln!(out, "purpose = \"{}\"", r.purpose.as_str())?;
        writeln!(out, "source = \"{}\"", r.source.as_str())?;
        if let Some(u) = &r.user { writeln!(out, "user = \"{}\"", quoted(u)?)?; }
    }
    if let Some(m) = topo.mission() {
        writeln!(out)?;
        writeln!(out, "[mission]")?;
        writeln!(out, "reserve_mj = {}", m.reserve_mj)?;
        if let Some(t) = &m.task { writeln!(out, "task = \"{}\"", quoted(t)?)?; }
    }
    for r in topo.boot_chain() {
        writeln!(out)?;
        writeln!(out, "[boot_chain.{}]", section_name(&r.name)?)?;
        writeln!(out, "stage = {}", r.stage)?;
        write!(out, "digest = \"")?;
        write_hex(out, &r.digest)?;
        writeln!(out, "\"")?;
    }
    for r in topo.islands() {
        writeln!(out)?;
        writeln!(out, "[island.{}]", section_name(&r.name)?)?;
        writeln!(out, "image = \"{}\"", quoted(&r.image)?)?;
        write!(out, "sha256 = \"")?;
        write_hex(out, &r.sha256)?;
        writeln!(out, "\"")?;
        writeln!(out, "mailbox = \"{}\"", quoted(&r.mailbox)?)?;
        if !r.wake().is_empty() {
            write!(out, "wake = [")?;
            for (i, w) in r.wake().iter().enumerate() {
                write!(out, "{}\"{}\"", if i == 0 { "" } else { ", " }, quoted(w)?)?;
            }
            writeln!(out, "]")?;
        }
    }
    for r in topo.activities() {
        writeln!(out)?;
        writeln!(out, "[activity.{}]", section_name(&r.name)?)?;
        writeln!(out, "task = \"{}\"", quoted(&r.task)?)?;
        writeln!(out, "trigger = \"{}\"", r.trigger.as_str())?;
        if r.period_ms != 0 { writeln!(out, "period_ms = {}", r.period_ms)?; }
    }
    for r in topo.numa_nodes() {
        writeln!(out)?;
        writeln!(out, "[numa.{}]", section_name(&r.name)?)?;
        writeln!(out, "node = {}", r.node)?;
        writeln!(out, "cpus = {}", r.cpus)?;
    }
    for r in topo.envelopes() {
        writeln!(out)?;
        writeln!(out, "[envelope.{}]", section_name(&r.name)?)?;
        writeln!(out, "kind = \"{}\"", r.kind.as_str())?;
        writeln!(out, "class = \"{}\"", quoted(&r.class)?)?;
        writeln!(out, "level = \"{}\"", r.level.as_str())?;
    }
    if let Some(r) = topo.rtc() {
        writeln!(out)?;
        writeln!(out, "[rtc]")?;
        writeln!(out, "dev = \"{}\"", quoted(&r.dev)?)?;
        if !r.utc { writeln!(out, "utc = false")?; }
    }
    for r in topo.nics() {
        writeln!(out)?;
        writeln!(out, "[nic.{}]", section_name(&r.name)?)?;
        writeln!(out, "dev = \"{}\"", quoted(&r.dev)?)?;
        if r.mtu != crate::types::NIC_MTU_DEFAULT { writeln!(out, "mtu = {}", r.mtu)?; }
        if let Some(m) = r.mac {
            writeln!(out, "mac = \"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\"", m[0], m[1], m[2], m[3], m[4], m[5])?;
        }
    }
    for r in topo.models() {
        writeln!(out)?;
        writeln!(out, "[model.{}]", section_name(&r.name)?)?;
        write!(out, "bundle = \"")?;
        write_hex(out, &r.bundle)?;
        writeln!(out, "\"")?;
        if !r.variant.is_empty() { writeln!(out, "variant = \"{}\"", quoted(&r.variant)?)?; }
    }
    for r in topo.usb_rules() {
        writeln!(out)?;
        writeln!(out, "[usb.{}]", section_name(&r.name)?)?;
        if let Some(v) = r.vid { writeln!(out, "vid = \"{:04x}\"", v)?; }
        if let Some(p) = r.pid { writeln!(out, "pid = \"{:04x}\"", p)?; }
        if let Some(c) = r.class { writeln!(out, "class = {}", c)?; }
        writeln!(out, "authorize = \"{}\"", r.authorize.as_str())?;
    }
    Ok(())
}

fn topo_exports_differ(a: &Topology<'_>, b: &Topology<'_>, x: &crate::types::TaskSpec<'_>, y: &crate::types::TaskSpec<'_>) -> bool {
    let (p, q) = (a.exports_of(x), b.exports_of(y));
    p.len() != q.len()
        || p.iter().zip(q).any(|(m, n)| {
            m.endpoint.as_bytes() != n.endpoint.as_bytes()
                || m.peer.as_bytes() != n.peer.as_bytes()
        })
}

fn topo_imports_differ(a: &Topology<'_>, b: &Topology<'_>, x: &crate::types::TaskSpec<'_>, y: &crate::types::TaskSpec<'_>) -> bool {
    let (p, q) = (a.imports_of(x), b.imports_of(y));
    p.len() != q.len() || p.iter().zip(q).any(|(m, n)| m.as_bytes() != n.as_bytes())
}
