// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The interfaces the kernel hosts, served from endpoints (D6 part A).
//!
//! A task that holds a capability to a kernel-hosted endpoint
//! (`azos_ipc::endpoint::kernel_endpoint_cap`) calls it like any endpoint:
//! `SYS_IPC_CALL` with a `MsgDesc` request, or the register form
//! `SYS_IPC_CALL` (the request's four words in `a1..a4`, the reply's in
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
    /// system is contained (observation stays live, acting does
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
    /// Run `f` on the kernel's address of the first `bytes` bytes of the
    /// memory object the caller's capability `raw` names: a buffer the caller
    /// shares for one call (`Cap<KeyBuf>`, `Cap<FrameBuf>`).
    ///
    /// `BAD_ARGUMENT` for a handle that is not a memory object or one smaller
    /// than `least` bytes, `DENIED` (recorded under the object's kind) for a
    /// missing `READ` or `WRITE`, `UNSUPPORTED` for an object the kernel cannot
    /// touch as one piece (read-only, shared with a clone, hidden from the
    /// kernel, or not physically contiguous). `f` runs with the region table's
    /// lock held.
    pub(crate) fn with_buffer(&self, raw: u32, least: usize, bytes: usize, f: impl FnOnce(usize)) -> Result<(), u32> {
        let region = self.shm_region(raw, least)?;
        match azos_ipc::memobj::memobj_with_span_ref(region, bytes, f) {
            Ok(Some(())) => Ok(()),
            Ok(None) => Err(azos_devif::outcome::UNSUPPORTED),
            Err(_) => Err(azos_devif::outcome::BAD_ARGUMENT),
        }
    }

    /// [`with_buffer`](Self::with_buffer) for a buffer of any frames: `f(offset,
    /// address, len)` runs for each page of the first `bytes` bytes (`Frame::next`).
    pub(crate) fn with_buffer_pages(&self, raw: u32, least: usize, bytes: usize, f: impl FnMut(usize, usize, usize)) -> Result<(), u32> {
        let region = self.shm_region(raw, least)?;
        match azos_ipc::memobj::memobj_with_pages_ref(region, bytes, f) {
            Ok(Some(())) => Ok(()),
            Ok(None) => Err(azos_devif::outcome::UNSUPPORTED),
            Err(_) => Err(azos_devif::outcome::BAD_ARGUMENT),
        }
    }

    /// The region of the memory object the caller's capability `raw` names, held
    /// with `READ` and `WRITE` and at least `least` bytes long.
    fn shm_region(&self, raw: u32, least: usize) -> Result<u32, u32> {
        let named = azos_ipc::cap_store::read_table(self.tid, |t| t.peek_raw(CapHandle(raw))).flatten();
        let Some((ty, rights, region)) = named else { return Err(azos_devif::outcome::BAD_ARGUMENT) };
        if ty != azos_abi::cap::ty::SHM {
            return Err(azos_devif::outcome::BAD_ARGUMENT);
        }
        if !rights.contains(CapPerms::READ.union(CapPerms::WRITE)) {
            crate::handlers::note_typed_denial_for(self.tid, ty, azos_ipc::cap::CapError::MissingPerms);
            return Err(azos_devif::outcome::DENIED);
        }
        let desc = azos_ipc::memobj::memobj_describe_ref(region).map_err(|_| azos_devif::outcome::BAD_ARGUMENT)?;
        if desc.page_count * azos_arch::PAGE_SIZE < least {
            return Err(azos_devif::outcome::BAD_ARGUMENT);
        }
        Ok(region)
    }

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

/// [`caller`], for the call whose request begins with the header word `header`
/// (`azos_idl::header`): `None` too when the capability's `OP_MASK` does not
/// list the op the header names, with the refusal recorded as any other
/// capability denial. The resolve passes a masked capability to an endpoint
/// the kernel hosts and leaves this to the call, which is the first to know
/// the op (`CapTable::get_hosted_uncontained`); an unmasked one costs the load
/// of its slot word. Every call to a hosted interface comes through here, so
/// no interface has to know about masks. Op 0 and ops past bit 63 are in no
/// mask: an interface that names the kernel's op numbers (`#[op = ..]`, the
/// file protocol's `NODE_*`, all above 63) cannot be attenuated by one, and a
/// masked capability to it is refused whole. A mask by the op's class is the
/// follow-up when such an interface is hosted.
pub fn admit(tid: u32, ep_raw: u32, header: u64) -> Option<Caller> {
    let h = CapHandle(ep_raw);
    let op = azos_idl::header_op(header);
    // One read of the table for the mask and the caller.
    let who = azos_ipc::cap_store::read_table(tid, |t| {
        let ops = t.hosted_op_mask(h);
        if ops != u64::MAX && (op == 0 || op >= 64 || ops >> op & 1 == 0) {
            return Some(None);
        }
        let (_, rights, _) = t.peek_raw(h)?;
        let badge = t.ext_of(h).map_or(0, |e| e.badge);
        Some(Some(Caller { tid, badge, rights }))
    })??;
    if who.is_none() {
        crate::handlers::note_typed_denial_for(
            tid,
            azos_abi::cap::ty::ENDPOINT,
            azos_ipc::cap::CapError::MissingPerms,
        );
    }
    who
}

/// One hosted interface: its host key, whether its requests may carry
/// capability entries (derived from the IDL: some op takes a `Cap` or a
/// `Lent`), whether an io_ring pass may serve a call through a capability of
/// a given badge, and the server dispatching a request for one caller.
struct Hosted {
    key: u16,
    takes_caps: bool,
    ring: fn(badge: u32) -> bool,
    dispatch: fn(&Caller, &MsgDesc, &mut MsgDesc),
}

/// No op of the interface may run in a pass.
fn not_on_the_ring(_: u32) -> bool {
    false
}

macro_rules! hosted {
    (ring = $ring:expr; $key:expr, $idl:ty, $server:expr) => {
        Hosted { ring: $ring, ..hosted!($key, $idl, $server) }
    };
    ($key:expr, $idl:ty, $server:expr) => {
        Hosted {
            key: $key,
            takes_caps: <$idl>::TAKES_CAPS,
            ring: not_on_the_ring,
            dispatch: |who, req, rep| {
                let _ = <$idl>::dispatch(&mut $server(*who), req, rep);
            },
        }
    };
}

/// The interfaces this build hosts, one row per host key. A `ring = f;` row
/// is served from an io_ring pass (`OP_CALL`) for a badge `f` admits: `f`
/// asks the device's backing driver whether its ops can sleep (a GPIO
/// controller's `may_sleep`, the I2C bus's `transfer_may_sleep`, the ADS1115's
/// queue) and admits only a device whose every op is a bounded register access
/// or a read of a value a task left, so it may run inline in a real-time
/// task's submit and in the SQ poller's pass. The bound is the op's own
/// (the motor layer's write, a console line at most a few times a minute), not
/// zero. Any other row is the call's alone: `Net::resolve` naps, `Power::sync`
/// and `Volume::check` do block I/O, `Power::suspend` and `reboot` take the
/// machine down, an ADC read waits in the converter's queue.
const HOSTED: &[Hosted] = {
    use azos_devif::key as k;
    use azos_devif::*;
    &[
        hosted!(k::ENTROPY, EntropyIdl, crate::entropy::Server),
        hosted!(k::LINK_KEY, LinkKeyIdl, crate::link_key::Server),
        hosted!(k::POWER, PowerIdl, crate::power::Server),
        hosted!(k::POWER_ASSERT, PowerAssertIdl, crate::power_assert::Server),
        hosted!(k::FLIGHT, FlightIdl, crate::families::FlightServer),
        hosted!(k::BEHAVIOR, BehaviorIdl, crate::families::BehaviorServer),
        hosted!(k::CONFIG, ConfigIdl, crate::families::ConfigServer),
        hosted!(k::OTA, OtaIdl, crate::families::OtaServer),
        hosted!(ring = crate::devices::gpio_ring_served; k::GPIO, GpioIdl, crate::devices::GpioServer),
        hosted!(ring = crate::devices::i2c_ring_served; k::I2C, I2cIdl, crate::devices::I2cServer),
        hosted!(ring = crate::devices::pwm_ring_served; k::PWM, PwmIdl, crate::devices::PwmServer),
        hosted!(ring = crate::motor_host::ring_served; k::MOTOR, MotorIdl, crate::motor_host::MotorServer),
        hosted!(ring = crate::sensor_host::ring_served; k::SENSOR, SensorIdl, crate::sensor_host::SensorServer),
        hosted!(k::BLOCK, BlockIdl, crate::block_host::BlockServer),
        hosted!(k::CLOCK, ClockIdl, crate::clock::Server),
        hosted!(k::SPI, SpiIdl, crate::devices::SpiServer),
        hosted!(k::CAN, CanIdl, crate::devices::CanServer),
        hosted!(k::UART, UartIdl, crate::devices::UartServer),
        #[cfg(feature = "board-io")]
        hosted!(k::ADC, AdcIdl, crate::adc_host::AdcServer),
        hosted!(k::NET, NetIdl, crate::net_host::Server),
        hosted!(k::DISPLAY, DisplayIdl, crate::display::Server),
        hosted!(k::MEMCTL, MemCtlIdl, crate::memctl::Server),
        hosted!(k::KEYS, KeysIdl, crate::keys::Server),
        #[cfg(feature = "use-robot")]
        hosted!(k::FRAME, FrameIdl, crate::frame_host::Server),
        hosted!(k::VOLUME, VolumeIdl, crate::volume_host::Server),
        #[cfg(feature = "virtio-snd")]
        hosted!(k::SOUND, SoundIdl, crate::sound_host::Server),
        #[cfg(feature = "hv")]
        hosted!(k::VM, VmIdl, crate::vm::VmServer),
        #[cfg(feature = "hv")]
        hosted!(k::VCPU, VcpuIdl, crate::vm::VcpuServer),
    ]
};

/// Host key to the row's position plus one (0: no row), built at compile time;
/// a key hosted twice or outside `azos_devif::IFACES` fails the build.
static SLOT: [u8; azos_devif::IFACES.len() + 1] = {
    let mut slot = [0u8; azos_devif::IFACES.len() + 1];
    let mut i = 0;
    while i < HOSTED.len() {
        let key = HOSTED[i].key as usize;
        assert!(key != 0 && key < slot.len(), "a hosted key is outside azos_devif::IFACES");
        assert!(slot[key] == 0, "a host key is hosted twice");
        slot[key] = i as u8 + 1;
        i += 1;
    }
    slot
};

fn row(key: u16) -> Option<&'static Hosted> {
    let i = *SLOT.get(key as usize)?;
    HOSTED.get((i as usize).checked_sub(1)?)
}

/// May a request to the interface with host key `key` carry capability
/// entries? Only the interfaces with an op that takes a queue, a memory
/// object or a port (`Uart::attach`, `Adc::start_batch`, `Vm::ram`,
/// `Display::surface`, `MemCtl::set_volatile`, `Keys::sign`, `Sound::open`):
/// the entries stay in the caller's table and the server resolves them there
/// (`devices.rs`, "Queues"; `vm.rs`, `resolve`; `memctl.rs`). Every other
/// interface, and a key this build does not host, refuses a request that
/// carries one.
pub fn takes_caps(key: u16) -> bool {
    row(key).is_some_and(|h| h.takes_caps)
}

/// May an io_ring pass serve a call on the interface with host key `key`
/// through a capability carrying `badge` (a `ring = f;` row of [`HOSTED`] whose
/// `f` admits the badge)? `false` for a key this build does not host.
pub fn ring_served(key: u16, badge: u32) -> bool {
    row(key).is_some_and(|h| (h.ring)(badge))
}

/// The host keys this build serves, each with its `takes_caps`.
pub fn hosted_keys() -> impl Iterator<Item = (u16, bool)> {
    HOSTED.iter().map(|h| (h.key, h.takes_caps))
}

/// Serve `req` on the interface with host key `key`; the reply is in `rep`
/// (always: an unknown interface or a malformed request answers with the
/// IDL's error status, never with silence).
pub fn serve(key: u16, who: &Caller, req: &MsgDesc, rep: &mut MsgDesc) {
    // The image's profile lists the interfaces it may call
    // (`ImageProfile::ifaces`): the syscall list says "may call an endpoint",
    // this says which. An unlisted one kills the task, as an unlisted call does
    // (audit mode records it instead).
    match azos_sched::scheduler::current_iface_verdict(key) {
        azos_sched::filter::FilterVerdict::Allow => {}
        azos_sched::filter::FilterVerdict::Audit => {
            crate::handlers::record_seccomp_audit(azos_abi::syscall_nr::SYS_IPC_CALL as u16)
        }
        _ => crate::handlers::seccomp_deny_iface_kill(key),
    }
    serve_admitted(key, who, req, rep);
}

/// [`serve`] for a caller whose profile was already asked about `key`: the
/// io_ring's `OP_CALL`, which asks the ring OWNER's profile and refuses the
/// entry rather than killing the task that runs the pass.
pub fn serve_admitted(key: u16, who: &Caller, req: &MsgDesc, rep: &mut MsgDesc) {
    match row(key) {
        Some(h) => (h.dispatch)(who, req, rep),
        None => azos_idl::__private::error_reply(rep, IdlError::BadInterface),
    }
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
