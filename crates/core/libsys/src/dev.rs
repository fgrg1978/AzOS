// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Clients of the interfaces the kernel hosts and of driver endpoints
//! (`azos_devif`, D6 part A).
//!
//! A device or a kernel service is an endpoint: the capability a topology row
//! grants, found with [`lookup`], called through a transport ([`Ep`], the v2
//! call, or [`Regs`], the register form for an interface declared
//! `words = 4`) by the generated `<Name>Client`. Nothing here says whether
//! the kernel or a ring-3 driver serves it.

pub use azos_devif::*;

use crate::{cap_lookup_host, fast_ipc_call_ep_status, ipc_call_v2};

/// The v2 call (`SYS_IPC_CALL_V2`) on the endpoint capability `.0`: any
/// interface.
#[derive(Clone, Copy, Debug)]
pub struct Ep(pub u32);

impl Transport for Ep {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        match ipc_call_v2(self.0, msg) {
            0 => Ok(()),
            rc => Err(IdlError::Transport(rc)),
        }
    }
}

/// The register form (`SYS_IPC_FAST_CALL_EP`) on the endpoint capability
/// `.0`: four words each way, no capability. Only for an interface declared
/// `words = 4` (a request is the header and up to three arguments; a reply
/// the status and up to three words): the hot paths of the actuators and the
/// sensors.
#[derive(Clone, Copy, Debug)]
pub struct Regs(pub u32);

impl Transport for Regs {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        if msg.n_caps != 0 || msg.n_words > 4 {
            return Err(IdlError::Malformed);
        }
        let w = [msg.words[0], msg.words[1], msg.words[2], msg.words[3]];
        match fast_ipc_call_ep_status(self.0, w, 0) {
            Ok(r) => {
                let mut rep = MsgDesc { version: azos_idl::MSG_VERSION, n_words: 4, ..MsgDesc::default() };
                rep.words[..4].copy_from_slice(&r);
                *msg = rep;
                Ok(())
            }
            Err(rc) => Err(IdlError::Transport(rc)),
        }
    }
}

/// This task's endpoint capability to the kernel-hosted interface `key`
/// (`azos_devif::key`) that carries `badge`, or `None`: the task's topology
/// row does not grant it.
pub fn lookup(key: u16, badge: u32) -> Option<u32> {
    let h = cap_lookup_host(key, badge);
    (h > 0).then_some(h as u32)
}

/// Did the call reach the interface, and did the op succeed? The one
/// question most callers of an actuator interface ask of a reply.
pub fn succeeded<T>(r: azos_idl::Result<Out<T>>) -> bool {
    matches!(r, Ok(ref o) if o.is_ok())
}

/// The op's value, or why there is none: the interface's outcome (`DENIED`,
/// `BAD_ARGUMENT`, `REFUSED`, ...), or [`outcome::NO_SERVER`] when the call
/// did not reach the interface at all.
pub fn value<T>(r: azos_idl::Result<Out<T>>) -> Result<T, u32> {
    match r {
        Ok(o) if o.is_ok() => Ok(o.value),
        Ok(o) => Err(o.code),
        Err(_) => Err(outcome::NO_SERVER),
    }
}

/// Fill `buf` from the kernel entropy pool behind the entropy endpoint `ep`
/// (`READ`). `Err` is the outcome: `NOT_READY` when the pool is unseeded (no
/// entropy source fed it at boot, and nothing seeds it later in the same boot:
/// retrying does not help, and `buf` is untouched), `DENIED` for a capability
/// without `READ`, `NO_SERVER` when the call did not reach the kernel's
/// interface.
pub fn entropy_read(ep: u32, buf: &mut [u8]) -> Result<(), u32> {
    let mut c = EntropyClient::new(Ep(ep));
    let mut done = 0;
    while done < buf.len() {
        let want = (buf.len() - done).min(entropy::DRAW_WORDS * 8);
        let words = want.div_ceil(8);
        let mut out = match c.draw(words as u32) {
            Ok(o) => o,
            Err(_) => return Err(outcome::NO_SERVER),
        };
        if !out.is_ok() {
            return Err(out.code);
        }
        for (i, b) in buf[done..done + want].iter_mut().enumerate() {
            *b = out.value[i / 8].to_le_bytes()[i % 8];
        }
        // The words were key material on this stack: not left behind.
        // SAFETY: a valid, aligned `&mut [u64; N]`; volatile so it is not elided.
        unsafe { core::ptr::write_volatile(&mut out.value, [0; entropy::DRAW_WORDS]) };
        done += want;
    }
    Ok(())
}

/// The 32-byte brain-link PSK from the kernel-hosted `linkkey` endpoint `ep`
/// (`READ`). `Err` is the outcome: `NOT_READY` when the kernel holds no key
/// (absent, unprovisioned or all zero: `buf` is untouched), `DENIED` for a
/// capability without `READ`, `NO_SERVER` when the call did not reach the
/// kernel's interface.
pub fn link_key_read(ep: u32, buf: &mut [u8; linkkey::KEY_WORDS * 8]) -> Result<(), u32> {
    let mut c = LinkKeyClient::new(Ep(ep));
    let mut out = match c.read() {
        Ok(o) => o,
        Err(_) => return Err(outcome::NO_SERVER),
    };
    if !out.is_ok() {
        return Err(out.code);
    }
    for (i, b) in buf.iter_mut().enumerate() {
        *b = out.value[i / 8].to_le_bytes()[i % 8];
    }
    // The words were the key on this stack: not left behind.
    // SAFETY: a valid, aligned `&mut [u64; N]`; volatile so it is not elided.
    unsafe { core::ptr::write_volatile(&mut out.value, [0; linkkey::KEY_WORDS]) };
    Ok(())
}

/// Read the sensor behind the sensor endpoint `ep` (`READ`): the record is
/// copied into `buf` (as far as it fits) and the sample, with its acquisition
/// stamp on the clock [`crate::vdso_now_ns`] reads, is returned. `Err` is the
/// outcome: `NOT_READY` when the driver has nothing yet, `UNSUPPORTED` for the
/// LiDAR and the camera (their records travel on the stream rings), `DENIED`
/// for a capability without `READ`, `NO_SERVER` when the call did not reach the
/// kernel's interface.
pub fn sensor_read(ep: u32, buf: &mut [u8]) -> Result<Sample, u32> {
    let s = value(SensorClient::new(Ep(ep)).read())?;
    s.copy_to(buf);
    Ok(s)
}

/// Publish the sensor behind `ep` into this task's vDSO page
/// ([`crate::vdso_task_map`] first). `Ok(true)`: refreshed at every timer
/// interrupt; `Ok(false)`: bound, but the type has no interrupt-safe source and
/// its slot stays unpublished (read it with [`sensor_read`]).
pub fn sensor_bind_vdso(ep: u32) -> Result<bool, u32> {
    value(SensorClient::new(Ep(ep)).bind_vdso())
}
