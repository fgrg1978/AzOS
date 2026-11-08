// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Authority` interface the kernel hosts (`azos_devif::authority`): a
//! ring-3 engine's protocol frame, answered by the handler of the extension
//! that owns the protocol ([`set_handler`]). The base names no protocol.

use azos_abi::cap::CapPerms;
use azos_devif::authority::{put_bytes, FRAME_BYTES, PUT_BYTES, PUT_WORDS};
use azos_devif::{outcome, Out};

use crate::khost::Caller;

/// An extension's answer to frame `kind` with `payload` from task `tid`.
pub type FrameHandler = fn(kind: u8, payload: &[u8], tid: u32);

azos_common::ro_hook! {
    /// The installed handler; unset: no extension answers, `UNSUPPORTED`.
    static HANDLER: FrameHandler;
}

/// Install the handler (an extension, at boot, once).
pub fn set_handler(h: FrameHandler) {
    HANDLER.set(h);
}

/// Forget the handler: host-test hygiene (the hook is process-wide).
#[cfg(not(target_os = "none"))]
pub fn clear_handler_for_tests() {
    HANDLER.clear_for_tests();
}

/// Staging slots: the tasks that may have a frame half staged at once.
const SLOTS: usize = 4;

/// One task's staged frame; tid 0 is a free slot.
#[derive(Clone, Copy)]
struct Stage {
    tid: u32,
    bytes: [u8; FRAME_BYTES],
}

static STAGES: azos_sync::SpinLock<[Stage; SLOTS]> =
    azos_sync::SpinLock::new([Stage { tid: 0, bytes: [0; FRAME_BYTES] }; SLOTS]);

/// A task is exiting: its staged bytes go with it.
pub fn release(tid: u32) {
    for s in STAGES.lock().iter_mut().filter(|s| s.tid == tid) {
        s.tid = 0;
    }
}

/// The `Authority` interface served for one caller.
pub struct Server(pub Caller);

impl Server {
    /// `WRITE`, without the containment step: an e-stop, a degrade and the
    /// operator's release are exactly what a contained system must still take.
    fn writer(&self) -> Result<(), Out<()>> {
        if self.0.holds(CapPerms::WRITE) {
            Ok(())
        } else {
            self.0.deny(CapPerms::WRITE);
            Err(Out::err(outcome::DENIED))
        }
    }
}

impl azos_devif::Authority for Server {
    fn put(&mut self, offset: u32, words: [u64; PUT_WORDS]) -> Out<()> {
        if let Err(o) = self.writer() {
            return o;
        }
        let off = offset as usize;
        if off % PUT_BYTES != 0 || off >= FRAME_BYTES {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let mut stages = STAGES.lock();
        let slot = match stages.iter().position(|s| s.tid == self.0.tid) {
            Some(i) => i,
            None => match stages.iter().position(|s| s.tid == 0) {
                Some(i) => {
                    stages[i] = Stage { tid: self.0.tid, bytes: [0; FRAME_BYTES] };
                    i
                }
                None => return Out::err(outcome::NO_RESOURCE),
            },
        };
        let end = (off + PUT_BYTES).min(FRAME_BYTES);
        stages[slot].bytes[off..end].copy_from_slice(&put_bytes(&words)[..end - off]);
        Out::ok(())
    }

    fn frame(&mut self, kind: u32, len: u32) -> Out<()> {
        if let Err(o) = self.writer() {
            return o;
        }
        let (Ok(kind), true) = (u8::try_from(kind), len as usize <= FRAME_BYTES) else {
            return Out::err(outcome::BAD_ARGUMENT);
        };
        let Some(h) = HANDLER.get() else { return Out::err(outcome::UNSUPPORTED) };
        let mut bytes = [0u8; FRAME_BYTES];
        for s in STAGES.lock().iter_mut().filter(|s| s.tid == self.0.tid) {
            bytes = s.bytes;
            s.tid = 0;
        }
        h(kind, &bytes[..len as usize], self.0.tid);
        Out::ok(())
    }
}
