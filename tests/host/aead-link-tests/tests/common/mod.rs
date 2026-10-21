// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Shared by the two test targets: the brain model and the helpers around it.
#![allow(dead_code)]

use azos_crypto::noise::{CipherState, HandshakeState, Pattern};
use azos_crypto::secure_channel::*;
use azos_crypto::x25519::x25519_pubkey;

pub const PSK: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
};
pub const E_ROBOT: [u8; 32] = [0x33; 32];
pub const E_BRAIN: [u8; 32] = [0x44; 32];
/// The operator's own brain key, pinned in the IK tests.
pub const BRAIN_IK_SK: [u8; 32] = [0x77; 32];

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub fn prologue(pb: u8) -> Vec<u8> {
    let mut p = PROLOGUE_LABEL.to_vec();
    p.push(pb);
    p
}

pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut f = (body.len() as u16).to_be_bytes().to_vec();
    f.extend_from_slice(body);
    f
}

/// What a completed handshake leaves: the robot's link, the brain's transport
/// ciphers and the bytes that crossed the wire.
pub struct Session {
    pub robot: Link,
    pub brain_send: CipherState,
    pub brain_recv: CipherState,
    /// robot -> brain, with the pattern byte in front of frame 1.
    pub msg1: Vec<u8>,
    pub msg2: Vec<u8>,
    pub msg3: Option<Vec<u8>>,
}

/// Run a whole handshake. The brain uses `brain_psk` to check the robot's
/// static (and, for XX, as its own identity); `ik_sk` is its pinned key.
pub fn handshake(robot_psk: &[u8; 32], pinned: Option<[u8; 32]>, brain_psk: &[u8; 32], ik_sk: &[u8; 32]) -> Result<Session, String> {
    let mut ini = Initiator::new(robot_psk, pinned.as_ref()).map_err(|e| format!("new: {e:?}"))?;
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    let n = ini.step(None, &E_ROBOT, &mut out).map_err(|e| format!("robot msg1: {e:?}"))?;
    let msg1 = out[..n].to_vec();
    let pb = msg1[0];
    assert_eq!(pb, ini.pattern_byte());
    // The brain: pick the pattern from the byte, answer.
    let (pattern, sk) = match pb {
        PATTERN_IK => (Pattern::Ik, *ik_sk),
        PATTERN_XX => (Pattern::Xx, brain_static_key(brain_psk)),
        other => return Err(format!("unknown pattern byte {other:#x}")),
    };
    let mut bhs = HandshakeState::responder(pattern, &sk, &prologue(pb)).map_err(|e| format!("brain new: {e:?}"))?;
    assert_eq!(u16::from_be_bytes([msg1[1], msg1[2]]) as usize, msg1.len() - 3);
    let mut nopayload = [];
    bhs.read_message(&msg1[3..], &mut nopayload).map_err(|e| format!("brain read 1: {e:?}"))?;
    let want_robot = x25519_pubkey(&kernel_static_key(brain_psk));
    if pattern == Pattern::Ik && bhs.remote_static() != Some(&want_robot) {
        return Err("brain: robot static is not the derived one".into());
    }
    let mut buf = [0u8; 256];
    let m = bhs.write_message(&E_BRAIN, &[], &mut buf).map_err(|e| format!("brain write 2: {e:?}"))?;
    let msg2 = frame(&buf[..m]);
    let n = ini.step(Some(&msg2), &E_ROBOT, &mut out).map_err(|e| format!("robot step 2: {e:?}"))?;
    let mut msg3 = None;
    if n > 0 {
        let f = out[..n].to_vec();
        bhs.read_message(&f[FRAME_HEAD..], &mut nopayload).map_err(|e| format!("brain read 3: {e:?}"))?;
        if bhs.remote_static() != Some(&want_robot) {
            return Err("brain: robot static is not the derived one".into());
        }
        msg3 = Some(f);
    }
    assert!(ini.is_done() && bhs.is_finished());
    assert_eq!(ini.handshake_hash(), bhs.handshake_hash());
    let robot = ini.finish().map_err(|e| format!("finish: {e:?}"))?;
    let mut bt = bhs.finish().map_err(|e| format!("brain finish: {e:?}"))?;
    let brain_send = core::mem::replace(&mut bt.send, CipherState::empty());
    let brain_recv = core::mem::replace(&mut bt.recv, CipherState::empty());
    Ok(Session { robot, brain_send, brain_recv, msg1, msg2, msg3 })
}

pub fn ik() -> Session {
    let pinned = x25519_pubkey(&BRAIN_IK_SK);
    handshake(&PSK, Some(pinned), &PSK, &BRAIN_IK_SK).unwrap()
}

pub fn xx() -> Session {
    handshake(&PSK, None, &PSK, &[0; 32]).unwrap()
}

/// A transport frame as the brain writes it.
pub fn brain_seal(cs: &mut CipherState, plain: &[u8]) -> Vec<u8> {
    let head = ((plain.len() + 16) as u16).to_be_bytes();
    let mut body = plain.to_vec();
    let tag = cs.encrypt(&head, &mut body).unwrap();
    let mut f = head.to_vec();
    f.extend_from_slice(&body);
    f.extend_from_slice(&tag);
    f
}

/// A transport frame as the robot wrote it, opened the way the brain does:
/// returns the plaintext (empty: a rekey signal, after which the brain rekeys).
pub fn brain_open(cs: &mut CipherState, f: &[u8]) -> Result<Vec<u8>, String> {
    let total = frame_len(f, max_body_for(MAX_MESSAGE_BYTES)).map_err(|e| format!("{e:?}"))?;
    assert_eq!(total, f.len());
    let (head, rest) = f.split_at(2);
    let (ct, tag) = rest.split_at(rest.len() - 16);
    let mut buf = ct.to_vec();
    let mut t = [0u8; 16];
    t.copy_from_slice(tag);
    cs.decrypt(head, &mut buf, &t).map_err(|e| format!("{e:?}"))?;
    if buf.is_empty() {
        cs.rekey();
    }
    Ok(buf)
}

/// Open one frame on the robot's side from a copy, returning (kind, data).
pub fn robot_open(l: &mut Link, f: &[u8]) -> Result<(RecordKind, Vec<u8>), RecordError> {
    let mut b = f.to_vec();
    let o = l.open_frame(&mut b, max_body_for(MAX_MESSAGE_BYTES))?;
    assert_eq!(o.consumed, f.len());
    let data = match o.kind {
        RecordKind::Data { len } => b[FRAME_HEAD..FRAME_HEAD + len].to_vec(),
        RecordKind::Rekey => vec![],
    };
    Ok((o.kind, data))
}

pub fn seal(l: &mut Link, msg: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; sealed_len_max(msg.len())];
    let n = l.seal_message(msg, &mut out).unwrap();
    out.truncate(n);
    out
}


impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Session")
    }
}
