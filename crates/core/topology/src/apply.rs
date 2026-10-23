// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a topology row asks the scheduler for: the class and the priority a
//! task named by that row runs at.
//!
//! Every user-space task takes its scheduler class from the
//! topology. Until wave 7 nothing read `TaskSpec::priority` or `class_name`
//! outside admission; the loader and `SYS_SPAWN_EX` created every ring-3 task at
//! the scheduler's default. This is the pure half of applying it — the lookup
//! and the clamp — so a host test can pin it; the kernel side maps the class
//! name onto the classes its scheduler has and writes the task.
//!
//! # Priority semantics
//!
//! `priority` is ABSOLUTE (lower = more urgent), as the topology format's worked example
//! uses it (`shell`: `best_effort`, `priority = 20`, range `[16, 30]`). A value
//! outside its class's `priority_range` is clamped into it, never rejected:
//! the parser accepts any `u8` and a row that says `0` in `best_effort` means
//! "the most urgent best-effort task", which is the bottom of the range.

use crate::types::{MaybeStr, Topology};

/// The scheduler parameters a topology row resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowSched<'a> {
    /// No row is named `name`. The task keeps the priority it was created
    /// with.
    NoRow,
    /// The row names a class the topology does not declare. `admission_check`
    /// refuses such a topology, so an installed one never yields this; it is
    /// here so the function is total.
    UndeclaredClass,
    /// The row's class and its priority clamped into the class's range.
    Apply {
        /// The class name, as declared. Whether the running scheduler has a
        /// class of that name is the kernel's question, not this crate's.
        class_name: MaybeStr<'a>,
        /// The row's `priority`, as written.
        declared: u8,
        /// `declared` clamped into the class's inclusive `priority_range`.
        priority: u8,
    },
}

impl<'a> Topology<'a> {
    /// The class and priority the row named `name` asks for.
    pub fn row_sched(&self, name: &[u8]) -> RowSched<'a> {
        // By bytes: `find_task` wants a name of the topology's own lifetime.
        let Some(task) = self.tasks().iter().find(|t| t.name.as_bytes() == name) else {
            return RowSched::NoRow;
        };
        let Some(class) = self.find_class(&task.class_name) else {
            return RowSched::UndeclaredClass;
        };
        let (lo, hi) = class.priority_range;
        RowSched::Apply {
            class_name: task.class_name,
            declared: task.priority,
            priority: task.priority.clamp(lo, hi.max(lo)),
        }
    }
}

/// Bound a ring-3 task's priority to `[floor, ceil]` (lower number = more
/// urgent). Returns the bounded value and whether it was RAISED to `floor`.
///
/// `floor` is the scheduler's `RT_PRIORITY_THRESHOLD` (12): below it the tick
/// never preempts, so a ring-3 task there could starve `net-poll`/`sys-wdt`
/// (owner decision 2026-09-28). `ceil` is `IDLE_PRIORITY - 1` (31 is how the
/// scheduler recognises idle). Pure, so the host suite pins it.
pub const fn ring3_priority(priority: u32, floor: u32, ceil: u32) -> (u32, bool) {
    if priority < floor {
        (floor, true)
    } else if priority > ceil {
        (ceil, false)
    } else {
        (priority, false)
    }
}

/// One service relation of a topology: row `server` serves the endpoint
/// `endpoint` and row `client` calls it (indices into [`Topology::tasks`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceEdge<'a> {
    /// The row holding `READ` on `endpoint.<endpoint>`: it accepts the calls.
    pub server: usize,
    /// A row that calls it: a call right (`WRITE` or `EXEC`, the badged form
    /// the power service holds) without `READ` on the same endpoint, or an
    /// `imports` entry naming it.
    pub client: usize,
    /// The endpoint name, without the `endpoint.` prefix.
    pub endpoint: &'a [u8],
}

impl<'a> Topology<'a> {
    /// Every server/client pair the rows declare, in row order. An endpoint
    /// the kernel serves has no server row and yields nothing; the name
    /// server's lendable grants (`WRITE` + `transfer` on what it lends) are
    /// not calls, so it is not a client of what it lends.
    pub fn for_each_service_edge(&self, mut f: impl FnMut(ServiceEdge<'a>)) {
        use azos_abi::cap::{CapKind, CapPerms};
        let tasks = self.tasks();
        let names = self.names_server_row();
        for (si, s) in tasks.iter().enumerate() {
            for sc in self.caps_of(s) {
                let Some(ep) = crate::types::endpoint_target(sc) else { continue };
                if sc.kind != CapKind::Endpoint || !sc.perms.contains(CapPerms::READ) {
                    continue;
                }
                for (ci, c) in tasks.iter().enumerate() {
                    if ci == si {
                        continue;
                    }
                    let calls = self.caps_of(c).iter().any(|cc| {
                        cc.kind == CapKind::Endpoint
                            && (cc.perms.contains(CapPerms::WRITE) || cc.perms.contains(CapPerms::EXEC))
                            && !cc.perms.contains(CapPerms::READ)
                            && !(Some(ci) == names && cc.transfer)
                            && crate::types::endpoint_target(cc) == Some(ep)
                    });
                    let imports = self.imports_of(c).iter().any(|n| n.as_bytes() == ep);
                    if calls || imports {
                        f(ServiceEdge { server: si, client: ci, endpoint: ep });
                    }
                }
            }
        }
    }

    /// The first pair whose server does not outrank its client (a priority
    /// number equal to or larger than the client's, as
    /// [`row_sched`](Self::row_sched) applies it), or `None`.
    ///
    /// Every server strictly outranks every client it serves (owner decision
    /// 2026-10-23): a client never preempts the request it is waiting on, a
    /// request is never served below its caller, and a server never competes
    /// with its clients in their own bucket. A row whose class the topology
    /// does not declare is skipped: `admission_check` refuses it first.
    pub fn server_not_above_client(&self) -> Option<ServiceEdge<'a>> {
        let prio = |i: usize| match self.row_sched(self.tasks()[i].name.as_bytes()) {
            RowSched::Apply { priority, .. } => Some(priority),
            _ => None,
        };
        let mut found = None;
        self.for_each_service_edge(|e| {
            if found.is_none() {
                if let (Some(s), Some(c)) = (prio(e.server), prio(e.client)) {
                    if s >= c {
                        found = Some(e);
                    }
                }
            }
        });
        found
    }
}
