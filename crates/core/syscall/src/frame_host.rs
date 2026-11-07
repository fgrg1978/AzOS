// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Frame` interface the kernel hosts (`endpoint = "frame.0"`) and the
//! frame class's pool it serves (`azos_devif::frame` has the contract).
//!
//! The pool is `azos_cam_ring::FramePool` sized by Kconfig (`FRAME_POOL_SLOTS`
//! buffers of `FRAME_BYTES`, the sender and `FRAME_READERS` ring-3 readers,
//! the policy `FRAME_POOL_*`). It starts with no buffer: the boot lends it
//! kernel memory objects when a camera is set up, and until then nothing is
//! claimed and no reader attaches. A reader is a cursor: reader [`LINK`] is the
//! brain link's sender, readers `1..` are the ring-3 tasks that called `next`.
//! The producers (the capture task, a USB camera's class driver) write frames
//! in the nanoseconds of the vDSO clock.
//!
//! * **Whose cursor.** A table of the task ids that hold a reader slot; the
//!   first `next` of a task takes one, `close` and the task's exit
//!   ([`release_all`], from the kernel's task-exit hook) give it back and
//!   detach the cursor, so a task that died under `FRAME_POOL_BACKPRESSURE`
//!   holds capture back no longer.
//! * **The copy.** A reference on the frame's buffer is held for the copy and
//!   no longer: the frame goes into the caller's buffer (`Caller::with_buffer`,
//!   checked first, so a bad buffer takes no frame) from a shared slice. The
//!   pool's buffers are mapped nowhere but in the kernel.
//! * **Not on the ring.** An io_ring pass does not serve `Frame`: a call takes
//!   a capability entry and copies a frame under the region table's lock, which
//!   is not a bounded register access (`khost`'s `HOSTED` has no `ring =` for it).

use azos_abi::cap::CapPerms;
use azos_cam_ring::{FramePool, FrameFormat, Policy};
use azos_devif::frame::{self, Meta};
use azos_devif::{outcome, Cap, Out};
use azos_sync::SpinLock;

use crate::khost::Caller;

/// Buffers of the pool.
pub const SLOTS: usize = azos_limits::FRAME_POOL_SLOTS as usize;
/// Bytes of a buffer.
pub const BYTES: usize = azos_limits::FRAME_BYTES as usize;
/// Ring-3 readers at once.
pub const RING3_READERS: usize = azos_limits::FRAME_READERS as usize;
/// The reader the brain link's sender is.
pub const LINK: usize = 0;
/// Cursors of the pool: the sender and the ring-3 readers.
pub const READERS: usize = 1 + RING3_READERS;

pub const POLICY: Policy = if azos_limits::FRAME_POOL_BACKPRESSURE {
    Policy::Backpressure
} else {
    Policy::OverwriteOldest
};

pub type Pool = FramePool<SLOTS, BYTES, READERS>;

/// The pool. All zero until the boot lends it buffers, so `.bss`.
pub static POOL: Pool = Pool::new(POLICY);

azos_common::ro_hook! {
    /// Wake the producers of the pool: `(first)` is whether the reader that
    /// attached is the first one. Installed by the boot of a camera.
    static PRODUCER_WAKE: fn(bool);
}

/// Install the producers' wake. Called once at boot, before any reader.
pub fn set_producer_wake(wake: fn(bool)) {
    PRODUCER_WAKE.set(wake);
}

/// Attach reader `c` and wake the producers if it is the first. `false`: the
/// pool has no buffers.
pub fn attach(c: usize) -> bool {
    let first = !POOL.any_attached();
    let attached = POOL.attach(c);
    if attached {
        if let Some(wake) = PRODUCER_WAKE.get() {
            wake(first);
        }
    }
    attached
}

/// The task that holds each ring-3 reader slot (0: free); slot `i` is the
/// pool's cursor `1 + i`. A leaf lock, held to find or change a slot.
static HOLDERS: SpinLock<[u32; RING3_READERS]> = SpinLock::new([0; RING3_READERS]);

/// The cursor of `tid`, taking a free slot if it has none. `None`: all taken.
fn cursor_of(tid: u32) -> Option<usize> {
    let mut h = HOLDERS.lock();
    #[cfg(not(feature = "frame-slot-per-call-canary"))]
    if let Some(i) = h.iter().position(|t| *t == tid) {
        return Some(1 + i);
    }
    let i = h.iter().position(|t| *t == 0)?;
    h[i] = tid;
    Some(1 + i)
}

/// End `tid`'s reading, if it has any.
fn end_reading(tid: u32) {
    let mut h = HOLDERS.lock();
    if let Some(i) = h.iter().position(|t| *t == tid) {
        h[i] = 0;
        POOL.detach(1 + i);
    }
}

/// A task exited: it reads no more.
pub(crate) fn release_all(tid: u32) {
    #[cfg(not(feature = "frame-exit-keeps-canary"))]
    end_reading(tid);
    #[cfg(feature = "frame-exit-keeps-canary")]
    let _ = tid;
}

/// The `Frame` interface served for one caller.
pub struct Server(pub Caller);

impl azos_devif::Frame for Server {
    fn buffer_bytes(&self) -> Out<u32> {
        if let Err(o) = self.0.gate::<u32>(CapPerms::READ) {
            return o;
        }
        if self.0.badge >= frame::CAMERAS {
            return Out::err(outcome::NO_RESOURCE);
        }
        Out::ok(BYTES as u32)
    }

    /// In order: the right (`READ`); the camera; the buffer (a bad one takes
    /// no frame); a reader slot; the frame, copied under a reference that ends
    /// with the call.
    fn next(&mut self, buf: Cap<frame::FrameBuf>) -> Out<Meta> {
        if let Err(o) = self.0.gate::<Meta>(CapPerms::READ) {
            return o;
        }
        if self.0.badge >= frame::CAMERAS {
            return Out::err(outcome::NO_RESOURCE);
        }
        if !POOL.ready() {
            return Out::err(outcome::NOT_READY);
        }
        #[cfg(not(feature = "frame-check-late-canary"))]
        if let Err(code) = self.0.with_buffer(buf.raw(), BYTES, BYTES, |_| ()) {
            return Out::err(code);
        }
        let Some(c) = cursor_of(self.0.tid) else { return Out::err(outcome::BUSY) };
        if !attach(c) {
            return Out::err(outcome::NOT_READY);
        }
        let Some(f) = POOL.acquire_latest(c) else { return Out::err(outcome::NOT_READY) };
        let bytes = f.bytes();
        let copied = if bytes.is_empty() || cfg!(feature = "frame-copy-skip-canary") { Ok(()) } else { self.0.with_buffer(buf.raw(), BYTES, bytes.len(), |base| {
            // SAFETY: `base` addresses at least `bytes.len()` bytes of the
            // object, kernel-mapped, held by the region table's lock for this
            // closure; the object is read-write and is not a pool buffer.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, bytes.len()) }
        }) };
        if copied.is_err() {
            return Out::err(outcome::FAULT);
        }
        let info = f.info();
        Out::ok(Meta {
            len: bytes.len() as u32,
            skipped: f.skipped().min(u32::MAX as u64) as u32,
            seq: f.seq(),
            acq_ns: f.stamp(),
            format: match info.format {
                FrameFormat::Jpeg => frame::format::JPEG,
                FrameFormat::Yuyv => frame::format::YUYV,
            },
            size: u32::from(info.width) << 16 | u32::from(info.height),
        })
    }

    fn close(&mut self) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::READ) {
            return o;
        }
        if self.0.badge >= frame::CAMERAS {
            return Out::err(outcome::NO_RESOURCE);
        }
        end_reading(self.0.tid);
        Out::ok(())
    }
}
