// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interfaces the kernel hosts, served from endpoints (D6 part A).
//!
//! A task that holds a capability to a kernel-hosted endpoint
//! (`azos_ipc::endpoint::kernel_endpoint_cap`) calls it like any endpoint:
//! `SYS_IPC_CALL_V2` with a `MsgDesc` request, or the register form
//! `SYS_IPC_FAST_CALL_EP` (the request's four words in `a1..a4`, the reply's in
//! `a0..a3`). The kernel does not queue the call or switch to another task: it
//! decodes the request, runs the interface's implementation on the caller's
//! own stack and writes the reply (bounded, allocation-free: real-time safe).
//!
//! What the implementation is told of the caller ([`Caller`]):
//!
//! * the **badge** of the capability the call went through: the resource it
//!   stands for (a pin, a bus and an address, a wheel pair, a partition: each
//!   interface says), stamped from the signed topology and not the holder's to
//!   change;
//! * its **rights**, the op classes: `READ` observes, `WRITE` acts, `EXEC`
//!   controls. [`Caller::allows`] is the one check an op makes before it
//!   touches anything, and it applies the containment rule (a contained system
//!   refuses the acting class, observation stays live).
//!
//! The IDL's generated `<Name>Idl::dispatch` is the decoder, so a ring-3 driver
//! that serves the same trait from its own endpoint is called with the same
//! bytes.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::ipc_msg::{MsgDesc, MSG_VERSION};
use azos_idl::IdlError;

/// What a kernel-hosted op knows of its caller.
#[derive(Clone, Copy, Debug)]
pub struct Caller {
    /// The calling task.
    pub tid: u32,
    /// The badge of the endpoint capability the call went through (0 for an
    /// unbadged one: resource 0).
    pub badge: u32,
    /// The rights of that capability.
    pub rights: CapPerms,
}

impl Caller {
    /// May the caller use op class `class` (`READ`, `WRITE` or `EXEC`)?
    /// False when the capability lacks it, and for `WRITE` also while the
    /// system is contained (RFC-0036: observation stays live, acting does
    /// not).
    #[inline]
    pub fn allows(&self, class: CapPerms) -> bool {
        self.rights.contains(class) && !(class.contains(CapPerms::WRITE) && azos_ipc::cap::degraded_active())
    }

    /// Does the capability carry op class `class`, whatever containment says?
    /// For the ops whose refusal is made one level down: the motor layer's
    /// halt rule admits a stop while containment is armed, so the capability
    /// check in front of it must not refuse the stop first.
    #[inline]
    pub fn holds(&self, class: CapPerms) -> bool {
        self.rights.contains(class)
    }

    /// Does the caller's own table also hold `need` on the kernel-hosted
    /// endpoint `key` that carries `badge` (containment applies to `WRITE`)?
    /// The other wheel of a pair rule.
    pub fn also_holds(&self, key: u16, badge: u32, need: CapPerms) -> bool {
        azos_ipc::cap_store::read_table(self.tid, |t| {
            azos_ipc::endpoint::table_holds_host_badge_right(t, key, badge, need)
        })
        .unwrap_or(false)
    }

    /// Does the caller's own table hold `need` on ANY endpoint of interface
    /// `key`, whatever its badge, ignoring containment? The e-stop's gate.
    pub fn holds_any(&self, key: u16, need: CapPerms) -> bool {
        azos_ipc::cap_store::read_table(self.tid, |t| {
            t.lookup_where(azos_abi::cap::ty::ENDPOINT, |r, _, perms| {
                perms.contains(need) && azos_ipc::endpoint::host_key_of_ref(r) == Some(key)
            })
            .is_some()
        })
        .unwrap_or(false)
    }

    /// Record a refusal for a right the table lacks on ANOTHER endpoint (the
    /// second wheel of a pair rule): the capability used carried the class,
    /// the set the op needs did not.
    pub fn deny_missing(&self) {
        crate::handlers::note_typed_denial_for(
            self.tid,
            azos_abi::cap::ty::ENDPOINT,
            azos_ipc::cap::CapError::MissingPerms,
        );
    }

    /// The gate every op of a device interface makes first: the caller may use
    /// op class `class`, else the refusal is recorded and the op answers
    /// [`outcome::DENIED`](azos_devif::outcome::DENIED) with nothing done.
    pub fn gate<T: Default>(&self, class: CapPerms) -> Result<(), azos_devif::Out<T>> {
        if self.allows(class) {
            return Ok(());
        }
        self.deny(class);
        Err(azos_devif::Out::err(azos_devif::outcome::DENIED))
    }

    /// Record a refusal by op class: the flight recorder's capability-denial
    /// record (the same record a refused typed call wrote), charged to the
    /// caller.
    pub fn deny(&self, class: CapPerms) {
        let e = if self.rights.contains(class) {
            azos_ipc::cap::CapError::Contained
        } else {
            azos_ipc::cap::CapError::MissingPerms
        };
        crate::handlers::note_typed_denial_for(self.tid, azos_abi::cap::ty::ENDPOINT, e);
    }
}

impl Caller {
    /// [`deny`](Self::deny) for the ops the recovery console also offers: the
    /// console's refusal line, `[AUTHORITY] <cmd> REFUSED`, is printed only
    /// when the record was actually handed to the recorder (a bounded stream).
    pub fn deny_cmd(&self, class: CapPerms, cmd: &str) {
        let e = if self.rights.contains(class) {
            azos_ipc::cap::CapError::Contained
        } else {
            azos_ipc::cap::CapError::MissingPerms
        };
        if crate::handlers::note_typed_denial_recorded(self.tid, azos_abi::cap::ty::ENDPOINT, e) {
            azos_drv_sys::kwarn!(
                "[AUTHORITY] {} REFUSED: tid {} (ring 3) lacks the endpoint right {} (recorded)",
                cmd, self.tid, if class.contains(CapPerms::WRITE) { "WRITE" } else { "READ" });
        }
    }
}

/// The caller `tid` is, through the endpoint capability `ep_raw` it holds.
pub fn caller(tid: u32, ep_raw: u32) -> Option<Caller> {
    let h = CapHandle(ep_raw);
    azos_ipc::cap_store::read_table(tid, |t| {
        let (_, rights, _) = t.peek_raw(h)?;
        let badge = t.ext_of(h).map_or(0, |e| e.badge);
        Some(Caller { tid, badge, rights })
    })?
}

/// Serve `req` on the interface with host key `key`; the reply is in `rep`
/// (always: an unknown interface or a malformed request answers with the
/// IDL's error status, never with silence).
pub fn serve(key: u16, who: &Caller, req: &MsgDesc, rep: &mut MsgDesc) {
    use azos_devif::key as k;
    // The image's profile lists the interfaces it may call
    // (`ImageProfile::ifaces`): the syscall list says "may call an endpoint",
    // this says which. An unlisted one kills the task, as an unlisted call does
    // (audit mode records it instead).
    match azos_sched::scheduler::current_iface_verdict(key) {
        azos_sched::filter::FilterVerdict::Allow => {}
        azos_sched::filter::FilterVerdict::Audit => {
            crate::handlers::record_seccomp_audit(azos_abi::syscall_nr::SYS_IPC_CALL_V2 as u16)
        }
        _ => crate::handlers::seccomp_deny_iface_kill(key),
    }
    use azos_devif::{
        BehaviorIdl, ConfigIdl, EntropyIdl, FlightIdl, GpioIdl, I2cIdl, LinkKeyIdl, MotorIdl, OtaIdl, PowerIdl, PwmIdl, SensorIdl, BlockIdl,
    };
    let me = *who;
    let _ = match key {
        k::ENTROPY => EntropyIdl::dispatch(&mut crate::entropy::Server(me), req, rep),
        k::LINK_KEY => LinkKeyIdl::dispatch(&mut crate::link_key::Server(me), req, rep),
        k::POWER => PowerIdl::dispatch(&mut crate::power::Server(me), req, rep),
        k::FLIGHT => FlightIdl::dispatch(&mut crate::families::FlightServer(me), req, rep),
        k::BEHAVIOR => BehaviorIdl::dispatch(&mut crate::families::BehaviorServer(me), req, rep),
        k::CONFIG => ConfigIdl::dispatch(&mut crate::families::ConfigServer(me), req, rep),
        k::OTA => OtaIdl::dispatch(&mut crate::families::OtaServer(me), req, rep),
        k::GPIO => GpioIdl::dispatch(&mut crate::devices::GpioServer(me), req, rep),
        k::I2C => I2cIdl::dispatch(&mut crate::devices::I2cServer(me), req, rep),
        k::PWM => PwmIdl::dispatch(&mut crate::devices::PwmServer(me), req, rep),
        k::MOTOR => MotorIdl::dispatch(&mut crate::motor_host::MotorServer(me), req, rep),
        k::SENSOR => SensorIdl::dispatch(&mut crate::sensor_host::SensorServer(me), req, rep),
        k::BLOCK => BlockIdl::dispatch(&mut crate::block_host::BlockServer(me), req, rep),
        _ => {
            azos_idl::__private::error_reply(rep, IdlError::BadInterface);
            Err(IdlError::BadInterface)
        }
    };
}

/// [`serve`] for the register form: the request is four words (padded with
/// zeros, which the decoder tolerates), the reply four words.
pub fn serve_regs(key: u16, who: &Caller, words: [u64; 4]) -> [u64; 4] {
    let mut req = MsgDesc { version: MSG_VERSION, n_words: 4, ..MsgDesc::default() };
    req.words[..4].copy_from_slice(&words);
    let mut rep = MsgDesc::default();
    serve(key, who, &req, &mut rep);
    let mut out = [0u64; 4];
    for (o, w) in out.iter_mut().zip(rep.words.iter()).take(rep.n_words as usize) {
        *o = *w;
    }
    out
}
