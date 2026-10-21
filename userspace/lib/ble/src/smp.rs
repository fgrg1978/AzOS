// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SMP: pairing with LE Secure Connections (Core Vol 3 Part H).
//!
//! What is implemented, and what is refused on purpose:
//!
//! * **LE Secure Connections only.** A peer that does not set the SC bit is
//!   refused (`AuthenticationRequirements`): legacy pairing's key exchange is
//!   breakable by a passive eavesdropper, so it is not a mode this host offers.
//! * **Just works and numeric comparison.** The local I/O capability is
//!   [`io_cap::NO_INPUT_NO_OUTPUT`] or [`io_cap::DISPLAY_YES_NO`]; a peer whose
//!   capabilities select passkey entry gets `PairingNotSupported`, as does OOB.
//!   [`Config::mitm`] makes just works a failure (`AuthenticationRequirements`).
//! * **The P-256 key agreement runs on the host** (RustCrypto `p256`): the
//!   controller is not asked for ECDH, so a controller without the commands
//!   works. The peer's public key is checked to be a point of the curve and not
//!   our own.
//! * **128-bit keys, no key distribution.** The LTK is derived (f5) and used to
//!   encrypt the link; the identity and signing keys are not negotiated
//!   (`Init/Resp key distribution` are zero), so what pairing leaves is [`Keys`].
//!   The upper layer stores it (the key store is a later front) and offers it
//!   back through [`Upper::ltk`](crate::Upper::ltk) when the peer reconnects.
//!
//! The state machine is per connection and a pure function of the PDUs, the
//! user's answer and the controller's encryption events: it returns the PDUs to
//! send and what to tell the upper layer ([`Actions`]); [`host`](crate::host)
//! moves them. All 128-bit values inside are in the specification's order;
//! the PDU codec reverses them to and from the air order.

use crate::crypto::{self, rev, U128};
use crate::{Error, PeerAddr, Platform};
use azos_crypto::ct::{ct_eq, secure_zero};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};

/// Seconds the whole procedure may take.
pub const TIMEOUT_MS: u64 = 30_000;
/// Longest SMP PDU (the public key).
pub const PDU_MAX: usize = 65;

/// PDU codes.
pub mod code {
    pub const PAIRING_REQUEST: u8 = 0x01;
    pub const PAIRING_RESPONSE: u8 = 0x02;
    pub const PAIRING_CONFIRM: u8 = 0x03;
    pub const PAIRING_RANDOM: u8 = 0x04;
    pub const PAIRING_FAILED: u8 = 0x05;
    pub const ENCRYPTION_INFORMATION: u8 = 0x06;
    pub const SECURITY_REQUEST: u8 = 0x0B;
    pub const PAIRING_PUBLIC_KEY: u8 = 0x0C;
    pub const DHKEY_CHECK: u8 = 0x0D;
    pub const KEYPRESS_NOTIFICATION: u8 = 0x0E;
}

/// Failure reasons.
pub mod reason {
    pub const PASSKEY_ENTRY_FAILED: u8 = 0x01;
    pub const OOB_NOT_AVAILABLE: u8 = 0x02;
    pub const AUTHENTICATION_REQUIREMENTS: u8 = 0x03;
    pub const CONFIRM_VALUE_FAILED: u8 = 0x04;
    pub const PAIRING_NOT_SUPPORTED: u8 = 0x05;
    pub const ENCRYPTION_KEY_SIZE: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const UNSPECIFIED: u8 = 0x08;
    pub const INVALID_PARAMETERS: u8 = 0x0A;
    pub const DHKEY_CHECK_FAILED: u8 = 0x0B;
    pub const NUMERIC_COMPARISON_FAILED: u8 = 0x0C;
    /// Not on the air: the 30 s procedure timeout.
    pub const TIMEOUT: u8 = 0xFF;
}

/// I/O capabilities.
pub mod io_cap {
    pub const DISPLAY_ONLY: u8 = 0;
    pub const DISPLAY_YES_NO: u8 = 1;
    pub const KEYBOARD_ONLY: u8 = 2;
    pub const NO_INPUT_NO_OUTPUT: u8 = 3;
    pub const KEYBOARD_DISPLAY: u8 = 4;
}

/// `AuthReq` bits.
pub mod auth {
    pub const BONDING: u8 = 0x01;
    pub const MITM: u8 = 0x04;
    pub const SC: u8 = 0x08;
}

/// The fields of a Pairing Request or Response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pairing {
    pub io_cap: u8,
    pub oob: u8,
    pub auth_req: u8,
    pub max_key_size: u8,
    pub init_key_dist: u8,
    pub resp_key_dist: u8,
}

/// A decoded SMP PDU. 128-bit values and public keys are as on the air (least
/// significant byte first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pdu {
    PairingRequest(Pairing),
    PairingResponse(Pairing),
    PairingConfirm([u8; 16]),
    PairingRandom([u8; 16]),
    PairingFailed(u8),
    SecurityRequest(u8),
    PairingPublicKey { x: [u8; 32], y: [u8; 32] },
    DhKeyCheck([u8; 16]),
}

impl Pdu {
    /// Decode a PDU. `Unknown` for a code that is not part of the procedures
    /// above (the key distribution PDUs included); the caller answers with
    /// `CommandNotSupported`.
    pub fn parse(b: &[u8]) -> Result<Pdu, Error> {
        let c = *b.first().ok_or(Error::Short)?;
        let p = &b[1..];
        let exact = |n: usize| match p.len() {
            l if l < n => Err(Error::Short),
            l if l > n => Err(Error::Invalid),
            _ => Ok(()),
        };
        let pairing = |p: &[u8]| Pairing {
            io_cap: p[0],
            oob: p[1],
            auth_req: p[2],
            max_key_size: p[3],
            init_key_dist: p[4],
            resp_key_dist: p[5],
        };
        Ok(match c {
            code::PAIRING_REQUEST => {
                exact(6)?;
                Pdu::PairingRequest(pairing(p))
            }
            code::PAIRING_RESPONSE => {
                exact(6)?;
                Pdu::PairingResponse(pairing(p))
            }
            code::PAIRING_CONFIRM => {
                exact(16)?;
                let mut v = [0u8; 16];
                v.copy_from_slice(p);
                Pdu::PairingConfirm(v)
            }
            code::PAIRING_RANDOM => {
                exact(16)?;
                let mut v = [0u8; 16];
                v.copy_from_slice(p);
                Pdu::PairingRandom(v)
            }
            code::PAIRING_FAILED => {
                exact(1)?;
                Pdu::PairingFailed(p[0])
            }
            code::SECURITY_REQUEST => {
                exact(1)?;
                Pdu::SecurityRequest(p[0])
            }
            code::PAIRING_PUBLIC_KEY => {
                exact(64)?;
                let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
                x.copy_from_slice(&p[..32]);
                y.copy_from_slice(&p[32..]);
                Pdu::PairingPublicKey { x, y }
            }
            code::DHKEY_CHECK => {
                exact(16)?;
                let mut v = [0u8; 16];
                v.copy_from_slice(p);
                Pdu::DhKeyCheck(v)
            }
            _ => return Err(Error::Unknown),
        })
    }

    /// Encode into an [`Sdu`].
    pub fn encode(&self) -> Sdu {
        let mut s = Sdu { len: 1, data: [0; PDU_MAX] };
        let put = |s: &mut Sdu, b: &[u8]| {
            s.data[s.len as usize..s.len as usize + b.len()].copy_from_slice(b);
            s.len += b.len() as u8;
        };
        match *self {
            Pdu::PairingRequest(p) | Pdu::PairingResponse(p) => {
                s.data[0] = if matches!(self, Pdu::PairingRequest(_)) { code::PAIRING_REQUEST } else { code::PAIRING_RESPONSE };
                put(&mut s, &[p.io_cap, p.oob, p.auth_req, p.max_key_size, p.init_key_dist, p.resp_key_dist]);
            }
            Pdu::PairingConfirm(v) => {
                s.data[0] = code::PAIRING_CONFIRM;
                put(&mut s, &v);
            }
            Pdu::PairingRandom(v) => {
                s.data[0] = code::PAIRING_RANDOM;
                put(&mut s, &v);
            }
            Pdu::PairingFailed(r) => {
                s.data[0] = code::PAIRING_FAILED;
                put(&mut s, &[r]);
            }
            Pdu::SecurityRequest(a) => {
                s.data[0] = code::SECURITY_REQUEST;
                put(&mut s, &[a]);
            }
            Pdu::PairingPublicKey { x, y } => {
                s.data[0] = code::PAIRING_PUBLIC_KEY;
                put(&mut s, &x);
                put(&mut s, &y);
            }
            Pdu::DhKeyCheck(v) => {
                s.data[0] = code::DHKEY_CHECK;
                put(&mut s, &v);
            }
        }
        s
    }
}

/// An encoded SMP PDU.
#[derive(Clone, Copy, Debug)]
pub struct Sdu {
    pub len: u8,
    pub data: [u8; PDU_MAX],
}

impl Sdu {
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

/// How the local side takes part in pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// [`io_cap::NO_INPUT_NO_OUTPUT`] or [`io_cap::DISPLAY_YES_NO`].
    pub io_cap: u8,
    /// Ask the peer to keep the key (the bonding bit).
    pub bonding: bool,
    /// Demand an authenticated key: just works is refused.
    pub mitm: bool,
    /// Answer a Pairing Request (the peripheral role); `false` refuses it.
    pub pairable: bool,
}

/// The two roles of the procedure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The central (the device that created the connection).
    Initiator,
    /// The peripheral.
    Responder,
}

/// Who and where: what the procedure is bound to, passed on every call.
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub role: Role,
    pub own: PeerAddr,
    pub peer: PeerAddr,
    pub cfg: Config,
}

/// What a finished pairing leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keys {
    pub peer: PeerAddr,
    /// The long term key (air order, as `LE Start Encryption` takes it).
    pub ltk: [u8; 16],
    /// The key was made with a man-in-the-middle-protected model (numeric
    /// comparison the user confirmed), not just works.
    pub authenticated: bool,
}

/// What a call asks of the host.
#[derive(Clone, Copy, Debug)]
pub struct Actions {
    pub send: [Option<Sdu>; 2],
    /// The six digits both users must see and compare; answer with `user_confirm`.
    pub numeric: Option<u32>,
    /// Start link encryption with this LTK (the initiator, after the checks).
    pub start_encryption: Option<[u8; 16]>,
    /// The procedure ended in failure with this [`reason`] (the PDU, if one is
    /// due, is already in `send`).
    pub failed: Option<u8>,
    /// The procedure ended well.
    pub keys: Option<Keys>,
}

impl Actions {
    const NONE: Actions = Actions { send: [None; 2], numeric: None, start_encryption: None, failed: None, keys: None };

    fn push(&mut self, p: Pdu) {
        let slot = if self.send[0].is_none() { 0 } else { 1 };
        self.send[slot] = Some(p.encode());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Model {
    JustWorks,
    Numeric,
    Passkey,
}

/// The association model for two capability sets (Core Vol 3 Part H Table 2.8,
/// the LE Secure Connections column).
fn model(init: u8, resp: u8, mitm: bool) -> Model {
    use io_cap::*;
    if !mitm {
        return Model::JustWorks;
    }
    let keyboard = |c: u8| c == KEYBOARD_ONLY || c == KEYBOARD_DISPLAY;
    let comparing = |c: u8| c == DISPLAY_YES_NO || c == KEYBOARD_DISPLAY;
    if init == NO_INPUT_NO_OUTPUT || resp == NO_INPUT_NO_OUTPUT {
        Model::JustWorks
    } else if comparing(init) && comparing(resp) {
        Model::Numeric
    } else if keyboard(init) || keyboard(resp) {
        Model::Passkey
    } else {
        Model::JustWorks
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Idle,
    // Initiator.
    WaitResponse,
    WaitPublicKey,
    WaitConfirm,
    WaitRandom,
    WaitUser,
    // Responder.
    WaitRandomR,
    WaitCheckR,
    // Both.
    WaitCheck,
    WaitEncryption,
}

/// The pairing state of one connection.
pub struct Smp {
    st: St,
    model: Model,
    deadline: u64,
    /// `AuthReq || OOB || IOcap` of the initiator and of the responder.
    iocap_a: [u8; 3],
    iocap_b: [u8; 3],
    secret: Option<SecretKey>,
    /// X coordinates of the initiator's and the responder's public keys.
    pk_a: [u8; 32],
    pk_b: [u8; 32],
    n_local: U128,
    n_peer: U128,
    confirm: U128,
    dhkey: [u8; 32],
    mac_key: U128,
    ltk: U128,
    user_ok: Option<bool>,
    check_peer: Option<U128>,
}

impl Default for Smp {
    fn default() -> Self {
        Self::new()
    }
}

impl Smp {
    pub const fn new() -> Smp {
        Smp {
            st: St::Idle,
            model: Model::JustWorks,
            deadline: 0,
            iocap_a: [0; 3],
            iocap_b: [0; 3],
            secret: None,
            pk_a: [0; 32],
            pk_b: [0; 32],
            n_local: [0; 16],
            n_peer: [0; 16],
            confirm: [0; 16],
            dhkey: [0; 32],
            mac_key: [0; 16],
            ltk: [0; 16],
            user_ok: None,
            check_peer: None,
        }
    }

    /// A procedure is running.
    pub fn active(&self) -> bool {
        self.st != St::Idle
    }

    /// The procedure ran past [`TIMEOUT_MS`]. The state is cleared.
    pub fn expired(&mut self, now_ms: u64) -> bool {
        if self.active() && now_ms >= self.deadline {
            self.wipe();
            true
        } else {
            false
        }
    }

    /// Forget everything, secrets zeroed (the link went away, or the end).
    pub fn wipe(&mut self) {
        secure_zero(&mut self.dhkey);
        secure_zero(&mut self.mac_key);
        secure_zero(&mut self.ltk);
        secure_zero(&mut self.n_local);
        secure_zero(&mut self.n_peer);
        self.secret = None;
        self.check_peer = None;
        self.user_ok = None;
        self.st = St::Idle;
    }

    fn fail(&mut self, why: u8, send: bool) -> Actions {
        self.wipe();
        let mut a = Actions::NONE;
        if send {
            a.push(Pdu::PairingFailed(why));
        }
        a.failed = Some(why);
        a
    }

    /// Begin as the initiator: the Pairing Request goes out.
    pub fn start(&mut self, ctx: &Ctx, now_ms: u64) -> Actions {
        let mut a = Actions::NONE;
        if self.active() || ctx.role != Role::Initiator {
            return a;
        }
        let req = local_pairing(ctx);
        self.iocap_a = [req.auth_req, 0, req.io_cap];
        self.deadline = now_ms + TIMEOUT_MS;
        self.st = St::WaitResponse;
        a.push(Pdu::PairingRequest(req));
        a
    }

    /// A PDU arrived on the SMP channel.
    pub fn on_pdu(&mut self, ctx: &Ctx, pdu: &Pdu, now_ms: u64, rng: &mut dyn Platform) -> Actions {
        // The peer gave up: nothing to send back.
        if let Pdu::PairingFailed(why) = *pdu {
            if self.active() {
                self.wipe();
                let mut a = Actions::NONE;
                a.failed = Some(why);
                return a;
            }
            return Actions::NONE;
        }
        match (ctx.role, self.st, *pdu) {
            // ── Responder ──────────────────────────────────────────────────
            (Role::Responder, St::Idle, Pdu::PairingRequest(req)) => self.on_request(ctx, &req, now_ms),
            (Role::Responder, St::WaitPublicKey, Pdu::PairingPublicKey { x, y }) => {
                self.on_public_key_responder(&x, &y, rng)
            }
            (Role::Responder, St::WaitRandomR, Pdu::PairingRandom(na)) => self.on_random_responder(ctx, &rev(&na)),
            (Role::Responder, St::WaitCheckR, Pdu::DhKeyCheck(ea)) => {
                self.check_peer = Some(rev(&ea));
                self.finish_responder(ctx)
            }
            // ── Initiator ──────────────────────────────────────────────────
            (Role::Initiator, St::WaitResponse, Pdu::PairingResponse(rsp)) => self.on_response(ctx, &rsp, rng),
            (Role::Initiator, St::WaitPublicKey, Pdu::PairingPublicKey { x, y }) => {
                self.on_public_key_initiator(&x, &y)
            }
            (Role::Initiator, St::WaitConfirm, Pdu::PairingConfirm(cb)) => {
                self.confirm = rev(&cb);
                rng.random(&mut self.n_local);
                let mut a = Actions::NONE;
                a.push(Pdu::PairingRandom(rev(&self.n_local)));
                self.st = St::WaitRandom;
                a
            }
            (Role::Initiator, St::WaitRandom, Pdu::PairingRandom(nb)) => self.on_random_initiator(ctx, &rev(&nb)),
            (Role::Initiator, St::WaitCheck, Pdu::DhKeyCheck(eb)) => self.on_check_initiator(ctx, &rev(&eb)),
            // Out of turn with nothing running (the tail of a procedure that
            // just ended): refused on the air, nobody's failure to report.
            (_, St::Idle, _) => {
                let mut a = Actions::NONE;
                a.push(Pdu::PairingFailed(reason::UNSPECIFIED));
                a
            }
            // Out of turn in the middle of one.
            _ => self.fail(reason::UNSPECIFIED, true),
        }
    }

    /// The user's verdict on the six digits.
    pub fn user_confirm(&mut self, ctx: &Ctx, ok: bool) -> Actions {
        if self.user_ok.is_some() || !matches!(self.st, St::WaitUser | St::WaitCheckR) {
            return Actions::NONE;
        }
        if !ok {
            return self.fail(reason::NUMERIC_COMPARISON_FAILED, true);
        }
        self.user_ok = Some(true);
        match ctx.role {
            Role::Initiator => self.send_check_initiator(ctx),
            Role::Responder => self.finish_responder(ctx),
        }
    }

    /// The controller asks for the key (the responder, after the initiator
    /// started encryption). Only the key this procedure just made is offered,
    /// for the zero `rand` and `ediv` Secure Connections uses.
    pub fn ltk_request(&mut self, rand: &[u8; 8], ediv: u16) -> Option<[u8; 16]> {
        if self.st == St::WaitEncryption && *rand == [0u8; 8] && ediv == 0 {
            Some(rev(&self.ltk))
        } else {
            None
        }
    }

    /// The controller reported the link encrypted (or not).
    pub fn encryption_changed(&mut self, ctx: &Ctx, ok: bool) -> Actions {
        if self.st != St::WaitEncryption {
            return Actions::NONE;
        }
        if !ok {
            return self.fail(reason::AUTHENTICATION_REQUIREMENTS, true);
        }
        let mut a = Actions::NONE;
        a.keys = Some(Keys { peer: ctx.peer, ltk: rev(&self.ltk), authenticated: self.model == Model::Numeric });
        self.wipe();
        a
    }

    // ── Steps ──────────────────────────────────────────────────────────────

    fn on_request(&mut self, ctx: &Ctx, req: &Pairing, now_ms: u64) -> Actions {
        if !ctx.cfg.pairable {
            return self.fail(reason::PAIRING_NOT_SUPPORTED, true);
        }
        if let Some(why) = check_peer_pairing(req) {
            return self.fail(why, true);
        }
        let rsp = local_pairing(ctx);
        self.iocap_a = [req.auth_req, req.oob, req.io_cap];
        self.iocap_b = [rsp.auth_req, rsp.oob, rsp.io_cap];
        let mitm = (req.auth_req | rsp.auth_req) & auth::MITM != 0;
        if let Some(why) = self.pick_model(ctx, req.io_cap, rsp.io_cap, mitm) {
            return self.fail(why, true);
        }
        self.deadline = now_ms + TIMEOUT_MS;
        self.st = St::WaitPublicKey;
        let mut a = Actions::NONE;
        a.push(Pdu::PairingResponse(rsp));
        a
    }

    fn pick_model(&mut self, ctx: &Ctx, io_a: u8, io_b: u8, mitm: bool) -> Option<u8> {
        self.model = model(io_a, io_b, mitm);
        match self.model {
            Model::Passkey => Some(reason::PAIRING_NOT_SUPPORTED),
            Model::JustWorks if ctx.cfg.mitm => Some(reason::AUTHENTICATION_REQUIREMENTS),
            _ => None,
        }
    }

    fn on_response(&mut self, ctx: &Ctx, rsp: &Pairing, rng: &mut dyn Platform) -> Actions {
        if let Some(why) = check_peer_pairing(rsp) {
            return self.fail(why, true);
        }
        self.iocap_b = [rsp.auth_req, rsp.oob, rsp.io_cap];
        let mitm = (self.iocap_a[0] | rsp.auth_req) & auth::MITM != 0;
        if let Some(why) = self.pick_model(ctx, self.iocap_a[2], rsp.io_cap, mitm) {
            return self.fail(why, true);
        }
        let Some((x, y)) = self.new_key(rng) else {
            return self.fail(reason::UNSPECIFIED, true);
        };
        self.pk_a = x;
        let mut a = Actions::NONE;
        a.push(Pdu::PairingPublicKey { x: rev(&x), y: rev(&y) });
        self.st = St::WaitPublicKey;
        a
    }

    fn on_public_key_initiator(&mut self, x: &[u8; 32], y: &[u8; 32]) -> Actions {
        let (px, py) = (rev(x), rev(y));
        match self.agree(&px, &py) {
            Some(()) => {
                self.pk_b = px;
                self.st = St::WaitConfirm;
                Actions::NONE
            }
            None => self.fail(reason::INVALID_PARAMETERS, true),
        }
    }

    fn on_public_key_responder(&mut self, x: &[u8; 32], y: &[u8; 32], rng: &mut dyn Platform) -> Actions {
        let (px, py) = (rev(x), rev(y));
        let Some((lx, ly)) = self.new_key(rng) else {
            return self.fail(reason::UNSPECIFIED, true);
        };
        if self.agree(&px, &py).is_none() {
            return self.fail(reason::INVALID_PARAMETERS, true);
        }
        self.pk_a = px;
        self.pk_b = lx;
        rng.random(&mut self.n_local);
        // Cb = f4(PKbx, PKax, Nb, 0)
        let cb = crypto::f4(&self.pk_b, &self.pk_a, &self.n_local, 0);
        let mut a = Actions::NONE;
        a.push(Pdu::PairingPublicKey { x: rev(&lx), y: rev(&ly) });
        a.push(Pdu::PairingConfirm(rev(&cb)));
        self.st = St::WaitRandomR;
        a
    }

    fn on_random_responder(&mut self, ctx: &Ctx, na: &U128) -> Actions {
        self.n_peer = *na;
        let mut a = Actions::NONE;
        a.push(Pdu::PairingRandom(rev(&self.n_local)));
        self.derive(ctx);
        self.present(&mut a, self.n_peer, self.n_local);
        self.st = St::WaitCheckR;
        a
    }

    fn on_random_initiator(&mut self, ctx: &Ctx, nb: &U128) -> Actions {
        // The responder committed to Nb before it saw Na: the commitment must open.
        let want = crypto::f4(&self.pk_b, &self.pk_a, nb, 0);
        let opens = ct_eq(&want, &self.confirm);
        #[cfg(feature = "canary-no-confirm-check")]
        let opens = true;
        if !opens {
            return self.fail(reason::CONFIRM_VALUE_FAILED, true);
        }
        self.n_peer = *nb;
        self.derive(ctx);
        let mut a = Actions::NONE;
        self.present(&mut a, self.n_local, self.n_peer);
        self.st = St::WaitUser;
        if self.user_ok == Some(true) {
            let b = self.send_check_initiator(ctx);
            a.send = b.send;
        }
        a
    }

    /// (MacKey, LTK) = f5(DHKey, Na, Nb, A, B).
    fn derive(&mut self, ctx: &Ctx) {
        let (na, nb) = self.nonces_ab(ctx);
        let (a1, a2) = addrs_ab(ctx);
        let (mac, ltk) = crypto::f5(&self.dhkey, &na, &nb, &a1, &a2);
        self.mac_key = mac;
        self.ltk = ltk;
    }

    /// `(Na, Nb)`: the initiator's and the responder's nonces.
    fn nonces_ab(&self, ctx: &Ctx) -> (U128, U128) {
        match ctx.role {
            Role::Initiator => (self.n_local, self.n_peer),
            Role::Responder => (self.n_peer, self.n_local),
        }
    }

    /// Numeric comparison asks the user; just works answers for them.
    fn present(&mut self, a: &mut Actions, na: U128, nb: U128) {
        if self.model == Model::Numeric {
            a.numeric = Some(crypto::g2(&self.pk_a, &self.pk_b, &na, &nb));
            self.user_ok = None;
        } else {
            self.user_ok = Some(true);
        }
    }

    fn send_check_initiator(&mut self, ctx: &Ctx) -> Actions {
        let (na, nb) = self.nonces_ab(ctx);
        let (a1, a2) = addrs_ab(ctx);
        let ea = crypto::f6(&self.mac_key, &na, &nb, &[0; 16], &self.iocap_a, &a1, &a2);
        let mut a = Actions::NONE;
        a.push(Pdu::DhKeyCheck(rev(&ea)));
        self.st = St::WaitCheck;
        a
    }

    fn on_check_initiator(&mut self, ctx: &Ctx, eb: &U128) -> Actions {
        let (na, nb) = self.nonces_ab(ctx);
        let (a1, a2) = addrs_ab(ctx);
        let want = crypto::f6(&self.mac_key, &nb, &na, &[0; 16], &self.iocap_b, &a2, &a1);
        let good = ct_eq(&want, eb);
        #[cfg(feature = "canary-no-dhkey-check")]
        let good = true;
        if !good {
            return self.fail(reason::DHKEY_CHECK_FAILED, true);
        }
        self.st = St::WaitEncryption;
        let mut a = Actions::NONE;
        a.start_encryption = Some(rev(&self.ltk));
        a
    }

    fn finish_responder(&mut self, ctx: &Ctx) -> Actions {
        let (Some(true), Some(ea)) = (self.user_ok, self.check_peer) else {
            return Actions::NONE;
        };
        let (na, nb) = self.nonces_ab(ctx);
        let (a1, a2) = addrs_ab(ctx);
        let want = crypto::f6(&self.mac_key, &na, &nb, &[0; 16], &self.iocap_a, &a1, &a2);
        let good = ct_eq(&want, &ea);
        #[cfg(feature = "canary-no-dhkey-check")]
        let good = true;
        if !good {
            return self.fail(reason::DHKEY_CHECK_FAILED, true);
        }
        let eb = crypto::f6(&self.mac_key, &nb, &na, &[0; 16], &self.iocap_b, &a2, &a1);
        let mut a = Actions::NONE;
        a.push(Pdu::DhKeyCheck(rev(&eb)));
        self.st = St::WaitEncryption;
        a
    }

    // ── P-256 ──────────────────────────────────────────────────────────────

    /// A fresh key pair; the X and Y of the public key, most significant first.
    fn new_key(&mut self, rng: &mut dyn Platform) -> Option<([u8; 32], [u8; 32])> {
        let mut raw = [0u8; 32];
        for _ in 0..8 {
            rng.random(&mut raw);
            if let Ok(sk) = SecretKey::from_slice(&raw) {
                secure_zero(&mut raw);
                let pt = sk.public_key().to_encoded_point(false);
                let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
                x.copy_from_slice(pt.x()?);
                y.copy_from_slice(pt.y()?);
                self.secret = Some(sk);
                return Some((x, y));
            }
        }
        secure_zero(&mut raw);
        None
    }

    /// DHKey from our secret and the peer's key (most significant first). `None`
    /// when the point is not on the curve, or is our own public key.
    fn agree(&mut self, x: &[u8; 32], y: &[u8; 32]) -> Option<()> {
        let sk = self.secret.take()?;
        let pt = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let peer = Option::<PublicKey>::from(PublicKey::from_encoded_point(&pt))?;
        // A peer that sends our own key back has a DH key anyone can compute.
        #[cfg(not(feature = "canary-allow-reflected-key"))]
        if peer == sk.public_key() {
            return None;
        }
        let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
        self.dhkey.copy_from_slice(shared.raw_secret_bytes());
        Some(())
    }
}

/// The pairing parameters the local side puts on the air.
fn local_pairing(ctx: &Ctx) -> Pairing {
    let mut auth_req = auth::SC;
    if ctx.cfg.bonding {
        auth_req |= auth::BONDING;
    }
    if ctx.cfg.mitm {
        auth_req |= auth::MITM;
    }
    Pairing { io_cap: ctx.cfg.io_cap, oob: 0, auth_req, max_key_size: 16, init_key_dist: 0, resp_key_dist: 0 }
}

/// What the local side requires of the peer's parameters.
fn check_peer_pairing(p: &Pairing) -> Option<u8> {
    if p.auth_req & auth::SC == 0 {
        return Some(reason::AUTHENTICATION_REQUIREMENTS);
    }
    if p.oob != 0 {
        return Some(reason::OOB_NOT_AVAILABLE);
    }
    if p.max_key_size < 16 {
        return Some(reason::ENCRYPTION_KEY_SIZE);
    }
    if p.io_cap > io_cap::KEYBOARD_DISPLAY {
        return Some(reason::INVALID_PARAMETERS);
    }
    None
}

/// `(A, B)` of the functions: type byte then the address, most significant
/// first, of the initiator and of the responder.
fn addrs_ab(ctx: &Ctx) -> ([u8; 7], [u8; 7]) {
    let seven = |a: &PeerAddr| {
        let mut o = [0u8; 7];
        o[0] = a.kind;
        o[1..].copy_from_slice(&rev(&a.addr));
        o
    };
    match ctx.role {
        Role::Initiator => (seven(&ctx.own), seven(&ctx.peer)),
        Role::Responder => (seven(&ctx.peer), seven(&ctx.own)),
    }
}
