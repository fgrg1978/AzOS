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
    // A1.next — expose scheduler runtime registry at /sys/scheduler.
    // Read-only introspection of which dispatch backend is active.
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
    // Masked-window tracer read-out; absent (and not counted) by default.
    #[cfg(feature = "lat-trace")]
    lat_trace::install_procfs();
    // Kconfig CHAOS: each injection point's rate and counts.
    #[cfg(feature = "chaos")]
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"chaos", gen_proc_chaos);
    // Kconfig DECISION_RECORDS: the explained decisions, newest first.
    #[cfg(feature = "decisions")]
    azos_fs::procfs_register(azos_fs::ProcNs::Proc, b"decisions", gen_proc_decisions);
    kprintln!("[FS] procfs/sysfs ready ({} entries)", azos_fs::procfs_count());
}

/// /sys/scheduler procfs entry. Reports the active
/// scheduler dispatch backend (Legacy / Aps / reserved variants)
/// per the runtime registry from A1.
///
/// Was `#[cfg(target_arch = "riscv64")]`-gated; removed by the aarch64
/// procfs parity task — the body only walks `azos_sched`'s arch-neutral
/// runtime registry, so the gate was never load-bearing, only unreachable
/// on the ISA that now also calls `install_procfs()`.
fn gen_sys_scheduler(buf: &mut [u8]) -> usize {
    // The typed registry only exists when the APS backend is compiled in
    // (`sched-aps`). Without it the answer is a constant: Legacy is the only
    // backend linked, and `SchedulerHandle::Legacy` is wire byte 0. The file
    // stays registered either way so /sys/scheduler never disappears.
    #[cfg(feature = "sched-aps")]
    let (name, raw) = {
        use azos_sched::runtime::registry::{active, SchedulerHandle};
        let h = active();
        let name = match h {
            SchedulerHandle::Legacy => "legacy",
            SchedulerHandle::Aps => "aps",
            SchedulerHandle::Fifo => "fifo (reserved)",
            SchedulerHandle::EdfCbs => "edf-cbs (reserved)",
            SchedulerHandle::Rr => "rr (reserved)",
            SchedulerHandle::Cfs => "cfs (reserved)",
            SchedulerHandle::Sporadic => "sporadic (reserved)",
        };
        (name, h.as_raw())
    };
    #[cfg(not(feature = "sched-aps"))]
    let (name, raw): (&str, u8) = ("legacy", 0);
    let s = alloc::format!("active: {}\nraw: {}\n", name, raw);
    let bytes = s.as_bytes();
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    n
}

/// A4.next — /sys/drivers procfs entry. Walks the RFC-0002
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
            azos_abi::cap::CapKind::Task,
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
    let Some(info) = r.rule_info() else { return write!(w, "{} rule={}\n", r.seq, r.rule) };
    write!(w, "{} {} {} {}={}", r.seq, info.name, r.verdict_name(), info.subject, r.subject)?;
    for (k, v) in info.fields.iter().zip(r.n) {
        if *k != "-" {
            write!(w, " {}={}", k, v)?;
        }
    }
    write!(w, " rejected=\"{}\"\n", r.rejected())
}

/// `/proc/decisions` (Kconfig DECISION_RECORDS): newest first, as many as
/// fit, after a header with the count written since boot.
#[cfg(feature = "decisions")]
fn gen_proc_decisions(buf: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut w = ProcW { b: buf, n: 0 };
    let last = azos_decision::total();
    if write!(w, "# {} decisions since boot, ring {}, newest first\n", last, azos_decision::ENTRIES).is_err() {
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
// registers answers. The eight built-in paths (five from `procfs_init`, then
// /sys/scheduler, /sys/drivers, /proc/tasks; `lat-trace` adds two) are all
// listed, the count is exactly that, and the providers whose content is
// never empty return bytes through `procfs_read`. Canary
// `canary=procfs-skip` (`kernel_main` skips `install_procfs`): `not ok`.
#[cfg(feature = "ktest")]
mod ktests {
    const PATHS: [&str; 8] = [
        "/proc/uptime", "/proc/meminfo", "/proc/fs", "/sys/version", "/sys/platform",
        "/sys/scheduler", "/sys/drivers", "/proc/tasks",
    ];
    const NON_EMPTY: [&[u8]; 5] = [b"/proc/uptime", b"/proc/meminfo", b"/sys/version", b"/sys/platform", b"/sys/scheduler"];

    azos_ktest::ktest! {
        fn procfs_entries_registered() {
            let want = PATHS.len()
                + if cfg!(feature = "lat-trace") { 2 } else { 0 }
                + cfg!(feature = "chaos") as usize
                + cfg!(feature = "decisions") as usize;
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
