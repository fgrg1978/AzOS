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

/// The brain's pinned static Noise public key from the kernel-hosted `linkkey`
/// endpoint `ep` (`READ`): `Ok(Some(key))` when the signed topology's
/// `[peer.brain]` row pins one (the link is `Noise_IK` toward it), `Ok(None)`
/// when nothing is pinned (`Noise_XX`). `Err` is the outcome of a call that
/// failed: `DENIED` for a capability without `READ`, `NO_SERVER` when the
/// call did not reach the kernel's interface. A caller must not read an `Err`
/// as "nothing pinned": that would let a failed call downgrade `IK` to `XX`.
pub fn brain_pk_read(ep: u32) -> Result<Option<[u8; linkkey::KEY_WORDS * 8]>, u32> {
    let mut c = LinkKeyClient::new(Ep(ep));
    let out = match c.brain_pk() {
        Ok(o) => o,
        Err(_) => return Err(outcome::NO_SERVER),
    };
    match out.code {
        outcome::OK => {
            let mut pk = [0u8; linkkey::KEY_WORDS * 8];
            for (i, b) in pk.iter_mut().enumerate() {
                *b = out.value[i / 8].to_le_bytes()[i % 8];
            }
            Ok(Some(pk))
        }
        outcome::NO_RESOURCE => Ok(None),
        code => Err(code),
    }
}

/// Read the sensor behind the sensor endpoint `ep` (`READ`): the record is
/// copied into `buf` (as far as it fits) and the sample, with its acquisition
/// stamp on the clock [`crate::vdso_now_ns`] reads, is returned. `Err` is the
/// outcome: `NOT_READY` when the driver has nothing yet, `UNSUPPORTED` for the
/// LiDAR and the camera (a scan travels on the io_ring's `READ_SENSOR` op), `DENIED`
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

/// Sign `msg` (1..=[`keys::SIGN_MSG_MAX`] bytes) with the key `key` of the
/// kernel-hosted `keys` endpoint `ep` (`READ`): the message goes to the kernel
/// in a memory object made for the call, the signature (Ed25519, 64 bytes)
/// comes back in the same one, and the object is given back before this
/// returns. `Err` is the outcome: `DENIED` for a key the caller may not use (its
/// policy, its owner, its image, its uses), `NO_RESOURCE` for a handle that is
/// not a key, `BAD_ARGUMENT` for a length outside the range or a key that does not
/// sign, `FAULT` when the object could not be made or mapped, `NO_SERVER` when
/// the call did not reach the interface.
pub fn keys_sign(ep: u32, key: u32, msg: &[u8]) -> Result<[u8; keys::SIG_BYTES], u32> {
    if msg.is_empty() || msg.len() > keys::SIGN_MSG_MAX {
        return Err(outcome::BAD_ARGUMENT);
    }
    let cap = crate::shm_create_typed(1, crate::SHM_RW);
    if cap <= 0 {
        return Err(outcome::FAULT);
    }
    let cap = cap as u32;
    let va = crate::shm_map_typed(cap);
    let out = if va <= 0 {
        Err(outcome::FAULT)
    } else {
        let base = va as usize as *mut u8;
        // SAFETY: `base` is the start of a one-page read-write mapping this task
        // made just now and owns until `shm_release_typed`; the message is at
        // most `SIGN_MSG_MAX` bytes and the signature `SIG_BYTES`, both within
        // the page.
        unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), base, msg.len()) };
        let mut c = KeysClient::new(Ep(ep));
        match c.sign(key, Cap::<keys::KeyBuf>::from_raw(cap), msg.len() as u32) {
            Ok(o) if o.is_ok() => {
                let mut sig = [0u8; keys::SIG_BYTES];
                // SAFETY: as above; the kernel wrote the signature over the message.
                unsafe { core::ptr::copy_nonoverlapping(base, sig.as_mut_ptr(), keys::SIG_BYTES) };
                Ok(sig)
            }
            Ok(o) => Err(o.code),
            Err(_) => Err(outcome::NO_SERVER),
        }
    };
    let _ = crate::shm_release_typed(cap);
    out
}
