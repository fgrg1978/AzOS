// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The immediate priority ceiling of an endpoint, computed from the topology.
//!
//! The micro kernel has no wait graph: a server that is working for a client
//! runs at the endpoint's CEILING, the most urgent attribute among the server
//! itself and every task holding a `WRITE` capability to the endpoint. No
//! client can then be delayed by a task the server would have been preempted
//! by, and the ceiling is a number fixed when the topology is read, so
//! serving costs a compare, not a walk (the plan's `mcu` row: "ceiling").
//! Attributes are ordered by `PiAttr`, the same order the main kernel's wait
//! graph uses.
//!
//! A client in the deadline class has no fixed level to inherit. The ceiling
//! of an endpoint with one is the most urgent real-time level (0): the server
//! then runs ahead of every fixed-priority task and behind the deadline class
//! itself, so the client's bound is its own reservation plus the server's
//! critical section.

use crate::pi_attr::PiAttr;

use crate::sc::Class;

/// The attribute of a task: its class and level.
pub fn base_attr(class: Class, prio: u8) -> PiAttr {
    match class {
        Class::Stop => PiAttr::Stop,
        // The deadline is dynamic; the ceiling code never compares two
        // deadlines (see `client_ceiling`), so a placeholder orders it.
        Class::Dl => PiAttr::Dl { deadline_ns: 0 },
        Class::Rt => PiAttr::Rt { prio },
        Class::Fair => PiAttr::Fair,
        Class::Idle => PiAttr::Idle,
    }
}

/// What a client of attribute `a` contributes to the ceiling.
fn client_ceiling(a: PiAttr) -> PiAttr {
    match a {
        PiAttr::Dl { .. } | PiAttr::Stop => PiAttr::Rt { prio: 0 },
        other => other,
    }
}

/// The ceiling of an endpoint: the server's attribute raised by every
/// client's.
pub fn endpoint_ceiling(server: PiAttr, clients: impl IntoIterator<Item = PiAttr>) -> PiAttr {
    clients.into_iter().fold(client_ceiling(server), |c, a| c.max_urgent(client_ceiling(a)))
}

/// The level a task of attribute `base` runs at while it serves under
/// `ceiling` (`None` when it is not serving): the more urgent of the two.
/// A task in the deadline class keeps its reservation: it is ordered by
/// deadline, ahead of every level, whatever a ceiling says.
pub fn effective(base: PiAttr, ceiling: Option<PiAttr>) -> PiAttr {
    match (base, ceiling) {
        (PiAttr::Dl { .. }, _) | (_, None) => base,
        (b, Some(c)) => b.max_urgent(c),
    }
}
