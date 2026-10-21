// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! procfs/sysfs registration and the kernel-side file generators.

use crate::*;

/// Register the built-in `/proc` and `/sys` providers. Shared between both
/// `kernel_main`s (riscv64 had this in place; aarch64 never called
/// `azos_fs::procfs_init()` at all, so `/proc`/`/sys` did not exist on
/// that ISA regardless of what mounted underneath them).
///
/// Must run after the VFS is up (`install_ring3_seams`'s `azos_fs::init()`)
/// — `gen_fs` walks the mount table — but does not need FAT32 mounted: the
/// providers are callbacks invoked at read time, not values snapshotted at
/// registration, so ramfs/tmpfs-only boots still get a working `/proc`/`/sys`.
/// Both `kernel_main`s call this at the same relative position: right after
/// `install_ring3_seams()`.
pub(crate) fn install_procfs() {
    // F21: Procfs + sysfs — register built-in virtual-file providers.
    azos_fs::procfs_init();
    // /sys/scheduler: read-only, which dispatcher is active.
    azos_fs::procfs_register(
        azos_fs::ProcNs::Sys,
        b"scheduler",
        gen_sys_scheduler,
    );
    // A4.next — list registered drivers at /sys/drivers.
    azos_fs::procfs_register(
        azos_fs::ProcNs::Sys,
        b"drivers",
        gen_sys_drivers,
    );
    // Wave 12: the task list, for ring 3's `ps` (read through the `/proc`
    // mount, `kernel_main`).
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"tasks", gen_proc_tasks);
    // Wave 12 (owner round 48): `/proc/<tid>`, one task's line, under the
    // same filter as `/proc/tasks`.
    azos_fs::procfs_register_tid(gen_proc_tid);
    // The name server's view of the signed topology: the endpoints it holds
    // and the names each row may import.
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"names", gen_proc_names);
    // The hardware bus: every device it found and what became of it.
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"devices", super::hwbus::gen_proc_devices);
    // The RPC server's view of the signed topology: its peer classes and what
    // it may lend to each.
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"rpc", gen_proc_rpc);
    // The PTP daemon's view: the node's `[clock]` row (Kconfig PTPD).
    if azos_limits::PTPD {
        azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"clock", gen_proc_clock);
    }
    // The SSH server's and the login service's view: the signed topology's
    // `[login.NAME]` rows (Kconfig SSHD, CONSOLE_LOGIN).
    if azos_limits::SSHD || azos_limits::CONSOLE_LOGIN {
        azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"ssh", gen_proc_ssh);
    }
    // The MCP bridge's view: the endpoints its row can call (Kconfig MCP_BRIDGE).
    if azos_limits::MCP_BRIDGE {
        azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"mcp", gen_proc_mcp);
    }
    // The component manager's view of the rows it starts.
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"components", gen_proc_components);
    // Kconfig SOC_FRAMEWORKS: what the boot step registered.
    #[cfg(feature = "soc")]
    super::soc::install_procfs();
    #[cfg(feature = "thermal")]
    super::thermal::install_procfs();
    // Masked-window tracer read-out; absent (and not counted) by default.
    #[cfg(feature = "lat-trace")]
    lat_trace::install_procfs();
    // Kconfig CHAOS: each injection point's rate and counts.
    #[cfg(feature = "chaos")]
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"chaos", gen_proc_chaos);
    // Kconfig DECISION_RECORDS_DEV: the explained decisions, newest first.
    #[cfg(feature = "decisions")]
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"decisions", gen_proc_decisions);
    // The same records whole and binary, for the ring-3 `Decisions` server
    // (`userspace/services/decisd`): the ring or the durable journal.
    #[cfg(any(feature = "decisions", feature = "decisions-durable"))]
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"decisions.bin", gen_proc_decisions_bin);
    kprintln!("[FS] procfs/sysfs ready ({} entries)", azos_fs::procfs_count());
}

/// /sys/scheduler procfs entry: the dispatcher in force. The class dispatch
/// is the only one, so the answer is a constant.
fn gen_sys_scheduler(buf: &mut [u8]) -> usize {
    let s = b"active: classes\n";
    let n = s.len().min(buf.len());
    buf[..n].copy_from_slice(&s[..n]);
    n
}

/// A4.next — /sys/drivers procfs entry. Walks the
/// driver registry and emits one line per registered driver:
/// `<kind_hex> <name> <isolation> <perms>`. Empty if nothing
/// has registered yet.
///
/// Was `#[cfg(target_arch = "riscv64")]`-gated; removed by the aarch64
/// procfs parity task — the body only walks `azos_drv_base`'s
/// arch-neutral `runtime::registry::REGISTRY`, so the gate was never
/// load-bearing, only unreachable on the ISA that now also calls
/// `install_procfs()`.
fn gen_sys_drivers(buf: &mut [u8]) -> usize {
    use azos_drv_api::DriverIsolation;
    let reg = azos_drv_base::runtime::registry::REGISTRY.lock();
    let mut s = alloc::string::String::new();
    for kind in 0u32..0x100 {
        if let Some(d) = reg.find_by_kind(kind) {
            let m = d.manifest();
            let iso = match m.isolation {
                DriverIsolation::InKernel => "inkernel",
                DriverIsolation::UserProcess { .. } => "userproc",
                DriverIsolation::Hypervisor => "hypervisor",
            };
            s.push_str(&alloc::format!(
                "0x{:04x} {} {} 0x{:02x}\n",
                m.kind,
                m.name,
                iso,
                m.required_perms.bits(),
            ));
        }
    }
    let bytes = s.as_bytes();
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    n
}

/// The reader of a `/proc` task file and whether it holds the full view:
/// `Cap<Task>` `READ` on `"tasks"` (resource 0) in its own table (wave 12,
/// owner round 48). The generator runs in the reading task's own system call
/// (`stat`, `read`), so the current task is the reader; a reader with no
/// table holds nothing.
fn proc_task_viewer() -> (u32, bool) {
    let viewer = azos_sched::current_task_tid();
    let full = azos_ipc::cap_store::with_table(viewer, |t| {
        t.holds_kind_resource_with(
            azos_abi::cap::ty::TASK,
            0,
            azos_abi::cap::CapPerms::READ,
        )
    })
    .unwrap_or(false);
    (viewer, full)
}

struct ProcW<'a> { b: &'a mut [u8], n: usize }
impl core::fmt::Write for ProcW<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let s = s.as_bytes();
        if self.n + s.len() > self.b.len() { return Err(core::fmt::Error); }
        self.b[self.n..self.n + s.len()].copy_from_slice(s);
        self.n += s.len();
        Ok(())
    }
}

/// `/proc/chaos` (Kconfig CHAOS): one line per injection point.
#[cfg(feature = "chaos")]
fn gen_proc_chaos(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = ProcW { b: buf, n: 0 };
    let _ = write!(w, "seed {}\n", azos_chaos::seed());
    for p in azos_chaos::POINTS {
        let (rate, checked, fired) = azos_chaos::stats(p);
        if write!(w, "{} rate={} checked={} fired={}\n", p.name(), rate, checked, fired).is_err() {
            break;
        }
    }
    w.n
}

/// One `/proc/decisions` line: the rule, the verdict, the subject, the
/// numbers by name and the alternative the rule rejected.
#[cfg(feature = "decisions")]
pub(crate) fn decision_line(w: &mut impl core::fmt::Write, r: &azos_decision::Record) -> core::fmt::Result {
    // The provenance fields print when set; a ring record has none today, so
    // the line is the one it always was.
    azos_decision::ProvenanceRecord::from_record(r).write_line(w)
}

/// `/proc/decisions` (Kconfig DECISION_RECORDS_DEV): newest first, as many as
/// fit, after a header with the count written since boot.
#[cfg(feature = "decisions")]
fn gen_proc_decisions(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = ProcW { b: buf, n: 0 };
    let last = azos_decision::total();
    if write!(w, "# {} decisions since boot, ring {}, newest first\n", last, azos_decision::ENTRIES).is_err() {
        return w.n;
    }
    // Capability denials the durable rate limit did not write (the next
    // durable denial also carries the count since the last one: `dropped=`).
    if azos_decision::DURABLE
        && write!(w, "# deny_durable_dropped {}\n", azos_decision::deny_dropped_total()).is_err()
    {
        return w.n;
    }
    let first = last.saturating_sub(azos_decision::ENTRIES as u64 - 1).max(1);
    let mut seq = last;
    while seq >= first && seq != 0 {
        if let Some(r) = azos_decision::get(seq) {
            let mark = w.n;
            if decision_line(&mut w, &r).is_err() {
                w.n = mark;
                break;
            }
        }
        seq -= 1;
    }
    w.n
}

/// `/proc/names`: what the name server needs to answer a lookup, and nothing
/// for anyone else. **Empty unless the reader serves `endpoint.names`**
/// (holds `READ` on it): a name is never authority, and the list of what the
/// topology wires together is not for every task to read.
///
/// ```text
/// export <name> <endpoint pool index> <serving task, or - when unserved>
/// allow <badge> <name>
/// ```
///
/// `export` lines are the named endpoints the reader itself holds a
/// capability on (`NAMESD.ELF` holds one per name its row lends; the pool
/// index is what `SYS_CAP_INFO(Endpoint, index)` takes to give it the
/// handle). `allow` lines come from the signed rows' `imports`: the badge is
/// the row's identity as the kernel stamped it on that row's capability to
/// `endpoint.names` (`azos_syscall::spawn::names_badge`).
fn gen_proc_names(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    use azos_abi::cap::CapPerms;
    let viewer = azos_sched::current_task_tid();
    let held = |i: u32| {
        azos_ipc::cap_store::with_table(viewer, |t| {
            let h = t.lookup(azos_abi::cap::ty::ENDPOINT, i)?;
            t.peek_raw(h).map(|(_, perms, _)| perms)
        })
        .flatten()
    };
    let mut serves = false;
    for i in 0..azos_ipc::endpoint::MAX_ENDPOINTS as u32 {
        let Some(perms) = held(i) else { continue };
        if let Some((n, len, _)) = azos_ipc::endpoint::endpoint_name_owner(i as usize) {
            serves |= &n[..len] == azos_ipc::cap_seed::NAMES_ENDPOINT && perms.contains(CapPerms::READ);
        }
    }
    if !serves {
        return 0;
    }
    let mut w = ProcW { b: buf, n: 0 };
    for i in 0..azos_ipc::endpoint::MAX_ENDPOINTS as u32 {
        if held(i).is_none() {
            continue;
        }
        let Some((n, len, owner)) = azos_ipc::endpoint::endpoint_name_owner(i as usize) else { continue };
        if &n[..len] == azos_ipc::cap_seed::NAMES_ENDPOINT {
            continue;
        }
        let name = core::str::from_utf8(&n[..len]).unwrap_or("?");
        let row = azos_sched::task_row(owner);
        let server = row.as_ref().map(|r| {
            let l = r.name.iter().position(|&b| b == 0).unwrap_or(r.name.len());
            core::str::from_utf8(&r.name[..l]).unwrap_or("?")
        });
        if write!(w, "export {} {} {}\n", name, i, server.unwrap_or("-")).is_err() {
            return w.n;
        }
    }
    if let Some(topo) = azos_topology::get() {
        for (ti, task) in topo.tasks().iter().enumerate() {
            for name in topo.imports_of(task) {
                if write!(w, "allow {} {}\n", azos_syscall::spawn::names_badge(ti), name.as_str()).is_err() {
                    return w.n;
                }
            }
        }
    }
    w.n
}

/// `/proc/components`: the component manager's view of the signed topology.
/// **Empty unless the reader is the component manager's own row**
/// (`COMPMGR.ELF`): which images the system starts, and what each holds of
/// the endpoints that wire them together, is not for every task to read.
///
/// ```text
/// <image> <always|on-failure|no> <served endpoints,... or -> <needed endpoints,... or -> [dir]
/// ...
/// end
/// ```
///
/// `dir` is present only for a row a package brought: the directory its
/// program is in (`/pkg/APPS`) when it is not `/fat`.
///
/// The closing `end` line says the view is whole. A row that does not fit the
/// buffer is not written (never half of one), and then the `end` line is not
/// written either, so the reader knows rows are missing and does not take a
/// cut list for the system.
///
/// One line per row the manager starts (`for_each_launch_row`: the rows with
/// `start = true`, but not the manager's own row, which the kernel starts,
/// and not a row whose image the boot launcher found missing from the
/// volume), in the order to start them. A driver that moves between hosts
/// is a row like any other: its ring-3 host is the manager's.
/// *Served* are the endpoints the row holds the serving half of (`READ`).
/// *Needed* are those it holds the calling half of (`WRITE`, not lent on:
/// `transfer` marks the name server's lending right, which is not a call) and
/// the endpoints its `imports` list names, as `endpoint.<name>`, with the name
/// server's own (`azos_topology::builder::manager_view_endpoints`): a need is
/// a dependency, which the manager orders the start by
/// (`userspace/services/compmgr/src/tree.rs`).
fn gen_proc_components(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let Some(topo) = azos_topology::get() else { return 0 };
    let me = azos_sched::task_row(azos_sched::current_task_tid());
    let is_manager = me.is_some_and(|r| {
        let l = r.name.iter().position(|&b| b == 0).unwrap_or(r.name.len());
        &r.name[..l] == azos_topology::builder::TASK_COMPMGR_IMAGE
    });
    if !is_manager {
        return 0;
    }
    // Room for the closing line stays free while rows are written.
    let rows_cap = buf.len().saturating_sub(COMPONENTS_END.len());
    let mut w = ProcW { b: &mut buf[..rows_cap], n: 0 };
    let mut full = false;
    for_each_launch_row(topo, &mut |i, row| {
        if full || !azos_topology::builder::manager_starts(row) || !row_startable(i) {
            return;
        }
        let mark = w.n;
        let line = |w: &mut ProcW| -> core::fmt::Result {
            write!(w, "{} {} ", row.name.as_str(), view_restart(row))?;
            // Served and needed endpoints, in the form the manager matches
            // them in (`azos_topology::builder::manager_view_endpoints`).
            azos_topology::builder::manager_view_endpoints(topo, row, w)?;
            // A program a package brought is not on /fat: its directory.
            let mut dir = [0u8; 16];
            if let Some(d) = crate::boot::pkg_boot::image_dir(row.name.as_bytes(), &mut dir) {
                write!(w, " {}", core::str::from_utf8(d).unwrap_or(""))?;
            }
            write!(w, "\n")
        };
        if line(&mut w).is_err() {
            w.n = mark;
            full = true;
        }
    });
    let n = w.n;
    if full || buf.len() < n + COMPONENTS_END.len() {
        return n;
    }
    buf[n..n + COMPONENTS_END.len()].copy_from_slice(COMPONENTS_END);
    n + COMPONENTS_END.len()
}

/// The `restart` word of `row` in the view. **Gate canaries only:**
/// `restart-canary` (every row restarts on failure only, as before the key
/// existed) and `supall-canary` (no row is restarted) make the manager act on
/// a policy the signed topology does not state, so the `restart` and `supall`
/// rows must fail on the buzzer they restart, or do not.
fn view_restart(row: &azos_topology::TaskSpec<'_>) -> &'static str {
    if cfg!(feature = "supall-canary") {
        "no"
    } else if cfg!(feature = "restart-canary") {
        "on-failure"
    } else {
        row.restart.as_str()
    }
}

/// The closing line of a whole `/proc/components` (`VIEW_END` of
/// `userspace/services/compmgr/src/tree.rs`).
const COMPONENTS_END: &[u8] = b"end\n";

/// `/proc/rpc`: what the RPC server needs to know of the signed topology, and
/// nothing for anyone else. **Empty unless the reader serves a proxy
/// endpoint** (holds `READ` on an endpoint named `rpc-...`): which nodes
/// belong to which class, and which endpoints the row may lend to whom, is
/// not for every task to read.
///
/// ```text
/// peer <class> <node> <noise_pk: 64 hex digits>
/// export <name> <endpoint pool index> <class>
/// ```
///
/// One `peer` line per node of each `[peer.NAME]` that pins a `noise_pk` for
/// it, with that key: it is how the RPC server tells the node from anyone else
/// (the Noise IK handshake). A node with no pinned key has no line, and so no
/// session. One `export` line per
/// `export = ["NAME@CLASS"]` entry of the RPC server's row, with the pool
/// index of the endpoint `NAME` the reader holds a capability on (what
/// `SYS_CAP_INFO(Endpoint, index)` takes to give it the handle); an entry
/// whose endpoint the reader does not hold is not listed.
fn gen_proc_rpc(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    use azos_abi::cap::CapPerms;
    let viewer = azos_sched::current_task_tid();
    let held = |i: u32| {
        azos_ipc::cap_store::with_table(viewer, |t| {
            let h = t.lookup(azos_abi::cap::ty::ENDPOINT, i)?;
            t.peek_raw(h).map(|(_, perms, _)| perms)
        })
        .flatten()
    };
    let named = |i: u32| azos_ipc::endpoint::endpoint_name_owner(i as usize).map(|(n, l, _)| (n, l));
    let serves_proxy = (0..azos_ipc::endpoint::MAX_ENDPOINTS as u32).any(|i| {
        held(i).is_some_and(|p| p.contains(CapPerms::READ))
            && named(i).is_some_and(|(n, l)| n[..l].starts_with(azos_ipc::endpoint::PROXY_NAME_PREFIX))
    });
    let Some(topo) = azos_topology::get() else { return 0 };
    if !serves_proxy {
        return 0;
    }
    let mut w = ProcW { b: buf, n: 0 };
    for p in topo.peers() {
        for n in p.nodes() {
            let Some(pk) = p.noise_pk_of(*n) else { continue };
            if write!(w, "peer {} {} ", p.name.as_str(), n).is_err() {
                return w.n;
            }
            for b in pk {
                if write!(w, "{b:02x}").is_err() {
                    return w.n;
                }
            }
            if w.write_str("\n").is_err() {
                return w.n;
            }
        }
    }
    for task in topo.tasks() {
        for e in topo.exports_of(task) {
            let Some(i) = (0..azos_ipc::endpoint::MAX_ENDPOINTS as u32).find(|&i| {
                held(i).is_some() && named(i).is_some_and(|(n, l)| &n[..l] == e.endpoint.as_bytes())
            }) else {
                continue;
            };
            if write!(w, "export {} {} {}\n", e.endpoint.as_str(), i, e.peer.as_str()).is_err() {
                return w.n;
            }
        }
    }
    w.n
}

/// `/proc/clock` (Kconfig PTPD): the PTP domain the topology's `[clock]` row
/// declares, as one line `ptp_domain N`; empty when the row declares none (the
/// node takes no part in PTP). The PTP daemon (`userspace/services/ptpd`)
/// reads it to learn the `domainNumber` it serves.
fn gen_proc_clock(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let Some(domain) = azos_topology::get().and_then(|t| t.clock().ptp_domain) else { return 0 };
    let mut w = ProcW { b: buf, n: 0 };
    let _ = write!(w, "ptp_domain {}\n", domain);
    w.n
}

/// `/proc/ssh` (Kconfig SSHD or CONSOLE_LOGIN): the logins of the signed topology, one line
/// per public key,
///
/// ```text
/// <user name> <ssh-ed25519 public key: 64 hex digits>
/// ```
///
/// The SSH server (`userspace/services/sshd`) reads it at every connection: a
/// login is a signature by one of these keys, under the name of its line. The
/// login service (`userspace/services/logind`) reads whether it is empty: nobody
/// enrolled is a console with no login gate. The
/// keys are public, so the view is for any reader; what makes them the
/// accounts of the node is that the topology is signed. Empty when the
/// topology declares no `[login.NAME]` row, and then nobody can log in. A
/// line is written whole or not at all (`MAX_LOGINS * LOGIN_KEYS` lines fit
/// the file by a build-time assertion of the topology crate).
fn gen_proc_ssh(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let Some(topo) = azos_topology::get() else { return 0 };
    let mut w = ProcW { b: buf, n: 0 };
    for login in topo.logins() {
        for key in login.keys() {
            let mut line = [0u8; 24 + 1 + 64 + 1];
            let mut l = ProcW { b: &mut line, n: 0 };
            let _ = write!(l, "{} ", login.name.as_str());
            for b in key {
                let _ = write!(l, "{b:02x}");
            }
            let _ = l.write_str("\n");
            let n = l.n;
            if w.n + n > w.b.len() {
                return w.n;
            }
            w.b[w.n..w.n + n].copy_from_slice(&line[..n]);
            w.n += n;
        }
    }
    w.n
}

/// `/proc/mcp`: the endpoints the MCP bridge's row can call, and nothing for
/// anyone who holds none with the call right **and** the lend right (`WRITE` +
/// `DUP` + `TRANSFER`, the topology's `transfer = true`): the authority the bridge's row
/// grants is what opens the view, not the name of the image.
///
/// ```text
/// endpoint <name> <endpoint pool index>
/// ```
///
/// One line per endpoint the reader holds so. The bridge matches the name to
/// the interfaces it knows and derives, for each call, a one-use warrant from
/// the endpoint at that index.
fn gen_proc_mcp(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    use azos_abi::cap::CapPerms;
    let viewer = azos_sched::current_task_tid();
    let mut w = ProcW { b: buf, n: 0 };
    for i in 0..azos_ipc::endpoint::MAX_ENDPOINTS as u32 {
        let lends = azos_ipc::cap_store::with_table(viewer, |t| {
            let h = t.lookup(azos_abi::cap::ty::ENDPOINT, i)?;
            t.peek_raw(h).map(|(_, p, _)| p.contains(CapPerms::WRITE) && p.contains(CapPerms::DELEGATE))
        })
        .flatten()
        .unwrap_or(false);
        if !lends {
            continue;
        }
        let Some((n, len, _)) = azos_ipc::endpoint::endpoint_name_owner(i as usize) else { continue };
        let mark = w.n;
        if write!(w, "endpoint {} {}\n", core::str::from_utf8(&n[..len]).unwrap_or("?"), i).is_err() {
            w.n = mark;
            return w.n;
        }
    }
    w.n
}

/// `/proc/decisions.bin` (Kconfig DECISION_RECORDS_DEV or
/// DECISION_REFUSALS_DURABLE): the stored decisions as `PROVENANCE_SIZE`-byte
/// `ProvenanceRecord::to_bytes` records, oldest first, no header: the newest
/// that fit a procfs file (`PROCFS_MAX_FILE`), as `azos_decision::query`
/// lists them. A reader takes the file whole and decodes 104 bytes at a time.
#[cfg(any(feature = "decisions", feature = "decisions-durable"))]
fn gen_proc_decisions_bin(buf: &mut [u8]) -> usize {
    const SIZE: usize = azos_decision::PROVENANCE_SIZE;
    let mut ids = [0u64; azos_fs::procfs::PROCFS_MAX_FILE / SIZE];
    let fit = (buf.len() / SIZE).min(ids.len());
    let after = azos_decision::total().saturating_sub(fit as u64);
    let n = azos_decision::query(&azos_decision::Filter { after, ..azos_decision::Filter::ANY }, &mut ids[..fit]);
    let mut at = 0;
    for &id in &ids[..n] {
        if let Some(p) = azos_decision::lookup(id) {
            buf[at..at + SIZE].copy_from_slice(&p.to_bytes());
            at += SIZE;
        }
    }
    at
}

const PROC_TASKS_HEADER: &str = "  TID  PPID PRI S NAME\n";

fn proc_task_line(w: &mut ProcW, r: &azos_sched::TaskRow) -> core::fmt::Result {
    use core::fmt::Write;
    let name_len = r.name.iter().position(|&b| b == 0).unwrap_or(r.name.len());
    let name = core::str::from_utf8(&r.name[..name_len]).unwrap_or("?");
    write!(w, "{:5} {:5} {:3} {} {}\n", r.tid, r.parent, r.priority, r.state as char, name)
}

const PROC_TASK_ROW0: azos_sched::TaskRow =
    azos_sched::TaskRow { tid: 0, parent: 0, priority: 0, state: 0, name: [0; 16] };

/// `/proc/<tid>` (wave 12, owner round 48): the header and that one task's
/// line, as `/proc/tasks` prints it. Empty — no such file — for a TID that
/// is not live AND for one the reader may not see: a hidden task is not
/// even visible by path, as under Linux `hidepid=2`.
fn gen_proc_tid(tid: u32, buf: &mut [u8]) -> usize {
    let (viewer, full) = proc_task_viewer();
    if !azos_sched::task_visible_to(viewer, tid, full) {
        return 0;
    }
    let Some(r) = azos_sched::task_row(tid) else { return 0 };
    let mut w = ProcW { b: buf, n: 0 };
    use core::fmt::Write;
    if w.write_str(PROC_TASKS_HEADER).is_err() || proc_task_line(&mut w, &r).is_err() {
        return 0;
    }
    w.n
}

/// `/proc/tasks` (wave 12): one line per live task — TID, parent TID,
/// priority, state (`R` ready/running, `S` blocked, `Z` exited), name —
/// under a header. The file is bounded by the procfs buffer
/// (`azos_fs::procfs::PROCFS_MAX_FILE`): rows that do not fit are cut
/// and a last line `... N more` says how many.
///
/// **Filtered (owner round 48, Linux `hidepid=2`).** A reader sees only
/// itself and its descendants (`azos_sched::task_visible_to`) unless it
/// holds `Cap<Task>` `READ` on `"tasks"`; a task it may not see is neither
/// listed nor counted in `... N more`.
fn gen_proc_tasks(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    type W<'a> = ProcW<'a>;
    // The file holds about 60 lines; more rows than fit are only counted.
    const ROWS: usize = 96;
    let mut rows = [PROC_TASK_ROW0; ROWS];
    let all = azos_sched::task_rows(&mut rows);
    let (viewer, full) = proc_task_viewer();
    let mut n = 0;
    for i in 0..all {
        if azos_sched::task_visible_to(viewer, rows[i].tid, full) {
            rows[n] = rows[i];
            n += 1;
        }
    }
    const HEADER: &str = PROC_TASKS_HEADER;
    // Whole list when it fits (the VFS hands an exactly-sized buffer to the
    // second generation, after `stat` sized it); otherwise rows up to the
    // room left for the `... N more` line.
    let mut w = W { b: &mut buf[..], n: 0 };
    if w.write_str(HEADER).is_ok() && rows[..n].iter().all(|r| proc_task_line(&mut w, r).is_ok()) {
        return w.n;
    }
    let keep = 24.min(buf.len());
    let limit = buf.len() - keep;
    let mut w = W { b: &mut buf[..limit], n: 0 };
    let _ = w.write_str(HEADER);
    let mut shown = 0;
    for r in &rows[..n] {
        let at = w.n;
        if proc_task_line(&mut w, r).is_err() {
            w.n = at;
            break;
        }
        shown += 1;
    }
    let mut len = w.n;
    let mut tail = W { b: &mut buf[len..], n: 0 };
    let _ = write!(tail, "... {} more\n", n - shown);
    len += tail.n;
    len
}

// Kconfig KTEST: `install_procfs` ran on this ISA and every provider it
// registers answers. The eleven built-in paths (five from `procfs_init`, then
// /sys/scheduler, /sys/drivers, /proc/tasks, /proc/names, /proc/devices,
// /proc/rpc, /proc/components; `lat-trace` adds two, PTPD /proc/clock, SSHD
// /proc/ssh, MCP_BRIDGE /proc/mcp, `chaos` and `decisions` their own) are all
// listed, the count is exactly that, and the providers whose content is
// never empty return bytes through `procfs_read`. Canary
// `canary=procfs-skip` (`kernel_main` skips `install_procfs`): `not ok`.
#[cfg(feature = "ktest")]
mod ktests {
    const PATHS: [&str; 11] = [
        "/proc/uptime", "/proc/meminfo", "/proc/fs", "/sys/version", "/sys/platform",
        "/sys/scheduler", "/sys/drivers", "/proc/tasks", "/proc/names", "/proc/devices",
        "/proc/rpc",
    ];
    const NON_EMPTY: [&[u8]; 5] = [b"/proc/uptime", b"/proc/meminfo", b"/sys/version", b"/sys/platform", b"/sys/scheduler"];

    azos_ktest::ktest! {
        fn procfs_entries_registered() {
            let want = PATHS.len()
                + if cfg!(feature = "lat-trace") { 2 } else { 0 }
                + cfg!(feature = "chaos") as usize
                + cfg!(feature = "decisions") as usize
                + cfg!(any(feature = "decisions", feature = "decisions-durable")) as usize
                + 1 // /proc/components
                + azos_limits::SSHD as usize
                + azos_limits::PTPD as usize
                + azos_limits::MCP_BRIDGE as usize;
            if azos_fs::procfs_count() != want {
                return Err("procfs/sysfs does not hold exactly the built-in entries");
            }
            let mut seen = 0usize;
            azos_fs::procfs_ls(|p| {
                if let Some(i) = PATHS.iter().position(|q| *q == p) {
                    seen |= 1 << i;
                }
            });
            if seen != (1 << PATHS.len()) - 1 {
                return Err("a built-in procfs/sysfs path is not listed");
            }
            let mut buf = [0u8; 256];
            for p in NON_EMPTY {
                if azos_fs::procfs_read(p, &mut buf) == 0 {
                    return Err("a built-in provider returned nothing");
                }
            }
            Ok(())
        }
    }
}
