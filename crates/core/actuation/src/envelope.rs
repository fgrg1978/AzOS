// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The wiring of the envelopes (Kconfig `EFFECT_WRITE_AHEAD`): the effect gate
//! (`effect_gate.rs`) holds a delete on a volume, a Domain's first packet to a
//! destination off the node, a configuration write, a step of applying an
//! update and a real-time reservation to the Domain's `[envelope.NAME]` row of
//! the signed topology. The filesystem, the socket layer, the configuration
//! store, the updater and the scheduler sit below this crate, so each asks
//! through a hook it owns (the last three through
//! `azos_common::envelope::asked`); this file installs the ends:
//!
//! * the **probe** the gate asks for a Domain's row: the task's scheduler
//!   class from the topology row it was seeded from (`natfork::row_of`, a
//!   thread through its process), the class's `delete` or `egress` ceiling;
//! * `azos_fs`'s delete gate, which passes the op and the volume of a change
//!   ([`delete_gate`]; the kernel hands it to `azos_fs::set_delete_gate`,
//!   since `fs` is scaffolding and a core crate may not depend on it);
//! * `azos_net`'s egress gate, which passes the socket owner and the
//!   destination;
//! * the **ask gate** of `azos_common::envelope`, which passes a configuration
//!   write, a step of an update (both the calling task's) or a reservation
//!   (the task it admits).
//!
//! A task seeded from no topology row (the kernel's own work: OTA, package
//! apply, log rotation), a boot with no topology, and a class with no row all
//! answer `full`: nothing is held. The refusal and its receipt are the
//! gate's.

use azos_common::envelope::{DeleteOp, DestClass};
use azos_topology::EffectKind;

use azos_common::envelope::Ask;

use crate::effect_gate::{
    self, Class, Effect, ENVELOPE_FULL, KIND_CONFIG_WRITE, KIND_NET_EGRESS, KIND_OTA_APPLY, KIND_RT_TIME,
    KIND_STORAGE_DELETE,
};

// The ceiling words are the topology's own: `Envelope::Full` to `Contained`.
const _: () = {
    assert!(azos_topology::Envelope::Full as u8 == ENVELOPE_FULL);
    assert!(azos_topology::Envelope::Contained as u8 == azos_common::envelope::LEVELS - 1);
};

/// The level of the row that holds effects of `kind` for the Domain `tid`
/// runs in; `full` when nothing does.
fn level(tid: u32, kind: u8) -> u8 {
    let Some(topo) = azos_topology::get() else { return ENVELOPE_FULL };
    let Some(row) = azos_syscall::natfork::row_of(azos_sched::group::proc_tid(tid)) else {
        return ENVELOPE_FULL;
    };
    let Some(task) = topo.tasks().get(row) else { return ENVELOPE_FULL };
    let effect = match kind {
        KIND_STORAGE_DELETE => EffectKind::Delete,
        KIND_NET_EGRESS => EffectKind::Egress,
        KIND_CONFIG_WRITE => EffectKind::Config,
        KIND_OTA_APPLY => EffectKind::Ota,
        KIND_RT_TIME => EffectKind::RtTime,
        _ => return ENVELOPE_FULL,
    };
    topo.effect_ceiling(task.class_name.as_bytes(), effect) as u8
}

/// `azos_fs`'s delete gate: the change runs in the caller's context. The
/// kernel installs it (`boot::seams`), after [`install`] has armed the probe.
pub fn delete_gate(op: DeleteOp, volume: u64) -> bool {
    let e = Effect {
        kind: KIND_STORAGE_DELETE,
        class: Class::Reversible,
        subject: op as u16,
        tid: azos_sched::current_task_tid(),
        a0: volume as u32,
        a1: 0,
    };
    effect_gate::record(&e).is_ok()
}

/// `azos_net`'s egress gate: the socket's owner is the Domain's task.
fn egress_gate(owner: u32, class: DestClass, dest: u32, port: u16) -> bool {
    let e = Effect {
        kind: KIND_NET_EGRESS,
        class: Class::Reversible,
        subject: port,
        tid: owner,
        a0: dest,
        a1: class as u32,
    };
    effect_gate::record(&e).is_ok()
}

/// The ask gate: a configuration write or an update step is the calling
/// task's own (the config and OTA calls run in the caller's context), a
/// reservation names the task it admits.
fn ask_gate(ask: Ask) -> bool {
    let e = match ask {
        Ask::Config { op, key } => Effect {
            kind: KIND_CONFIG_WRITE,
            class: Class::Reversible,
            subject: op as u16,
            tid: azos_sched::current_task_tid(),
            a0: key as u32,
            a1: (key >> 32) as u32,
        },
        Ask::Ota { op, slot } => Effect {
            kind: KIND_OTA_APPLY,
            class: Class::Reversible,
            subject: op as u16,
            tid: azos_sched::current_task_tid(),
            a0: slot as u32,
            a1: 0,
        },
        Ask::RtTime { tid, density_ppm } => {
            Effect { kind: KIND_RT_TIME, class: Class::Reversible, subject: 0, tid, a0: density_ppm, a1: 0 }
        }
    };
    effect_gate::record(&e).is_ok()
}

/// Install the probe and the egress and ask gates (boot, once, from
/// `gate::install`); the delete gate is the kernel's to install.
pub(crate) fn install() {
    effect_gate::set_envelope_probe(level);
    azos_net::socket::set_egress_gate(egress_gate);
    azos_common::envelope::set_ask_gate(ask_gate);
}
