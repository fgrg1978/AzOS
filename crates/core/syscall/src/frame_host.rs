// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Frame` interface the kernel hosts (`endpoint = "frame.0"`) and the
//! frame class's pool it serves (`azos_devif::frame` has the contract).
//!
//! The pool is `azos_cam_ring::FramePool` sized by Kconfig (`FRAME_POOL_SLOTS`
//! buffers of `FRAME_BYTES`, the sender and `FRAME_READERS` ring-3 readers,
//! the policy `FRAME_POOL_*`). It starts with no buffer: the boot lends it
//! kernel memory objects when the first reader attaches, and until then
//! nothing is claimed and no reader attaches. A reader is a cursor: reader [`LINK`] is the
//! brain link's sender, readers `1..` are the ring-3 tasks that called `next`.
//! The producers (the capture task, a USB camera's class driver) write frames
//! in the nanoseconds of the vDSO clock.
//!
//! * **The camera effect.** A camera frame is what the camera saw, so a task's
//!   first `next` needs the `cam` effect of its scheduler class, as a capture
//!   stream needs `mic` (`crate::effect`); default-deny: only a class an
//!   `[envelope.NAME]` row of kind `cam` names at a level other than `contained`
//!   has it, any other is refused (`REFUSED`) before it learns
//!   anything of the pool. The grant, each refusal and a reader's first frame
//!   are `cam-capture` decision records, and the console says when a reader
//!   opens and ends.
//! * **Whose cursor.** A table of the task ids that hold a reader slot; the
//!   first `next` of a task takes one, `close` and the task's exit
//!   ([`release_all`], from the kernel's task-exit hook) give it back and
//!   detach the cursor, so a task that died under `FRAME_POOL_BACKPRESSURE`
//!   holds capture back no longer.
//! * **The copy.** A reference on the frame's buffer is held for the copy and
//!   no longer: the frame goes into the caller's buffer (`Caller::with_buffer_pages`,
//!   checked first, so a bad buffer takes no frame) from a shared slice. The
//!   pool's buffers are mapped nowhere but in the kernel.
//! * **Not on the ring.** An io_ring pass does not serve `Frame`: a call takes
//!   a capability entry and copies a frame under the region table's lock, which
//!   is not a bounded register access (`khost`'s `HOSTED` has no `ring =` for it).

use azos_abi::cap::CapPerms;
use azos_cam_ring::{FrameFormat, FramePool, Policy};
use azos_decision::{Rule, Verdict};
use azos_topology::EffectKind;
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

const _: () = assert!(
    SLOTS >= RING3_READERS + 3,
    "FRAME_POOL_SLOTS must be at least FRAME_READERS + 3 (a buffer per reader, the sender's, the newest frame and the one being written): raise FRAME_POOL_SLOTS or lower FRAME_READERS"
);

pub type Pool = FramePool<SLOTS, BYTES, READERS>;

/// The pool. All zero until the boot lends it buffers, so `.bss`.
pub static POOL: Pool = Pool::new(POLICY);

azos_common::ro_hook! {
    /// Wake the producers of the pool: `(first)` is whether the reader that
    /// attached is the first one. Installed by the boot of a camera.
    static PRODUCER_WAKE: fn(bool);
}

azos_common::ro_hook! {
    /// Give the pool its buffers: called by the first attach that finds it
    /// without. Installed by the boot of a camera.
    static LEND: fn();
}

/// Install the lender of the pool's buffers. Called once at boot.
pub fn set_lend(lend: fn()) {
    LEND.set(lend);
}

/// Install the producers' wake. Called once at boot, before any reader.
pub fn set_producer_wake(wake: fn(bool)) {
    PRODUCER_WAKE.set(wake);
}

/// Attach reader `c` and wake the producers if it is the first. `false`: the
/// pool has no buffers.
pub fn attach(c: usize) -> bool {
    if !POOL.ready() {
        if let Some(lend) = LEND.get() {
            lend();
        }
    }
    let first = !POOL.any_attached();
    // The sender is the reader the pool is owed to; ring 3 never holds capture back.
    let attached = if c == LINK { POOL.attach_owed(c) } else { POOL.attach(c) };
    if attached {
        if let Some(wake) = PRODUCER_WAKE.get() {
            wake(first);
        }
    }
    attached
}

/// A ring-3 reader slot: the task that holds it (0: free) and whether it has
/// read its first frame. Slot `i` is the pool's cursor `1 + i`.
#[derive(Clone, Copy)]
struct Holder {
    tid: u32,
    read: bool,
}

/// The holders of the ring-3 reader slots. A leaf lock, held to find or change
/// a slot.
static HOLDERS: SpinLock<[Holder; RING3_READERS]> = SpinLock::new([Holder { tid: 0, read: false }; RING3_READERS]);

/// Does `tid` hold a reader slot?
fn is_reader(tid: u32) -> bool {
    HOLDERS.lock().iter().any(|h| h.tid == tid)
}

/// The cursor of `tid`, taking a free slot if it has none. `None`: all taken.
fn cursor_of(tid: u32) -> Option<usize> {
    let mut h = HOLDERS.lock();
    #[cfg(not(feature = "frame-slot-per-call-canary"))]
    if let Some(i) = h.iter().position(|x| x.tid == tid) {
        return Some(1 + i);
    }
    let i = h.iter().position(|x| x.tid == 0)?;
    h[i] = Holder { tid, read: false };
    Some(1 + i)
}

/// `tid`'s first frame was read: `true` once per slot.
fn first_read(tid: u32) -> bool {
    let mut h = HOLDERS.lock();
    match h.iter_mut().find(|x| x.tid == tid) {
        Some(x) if !x.read => {
            x.read = true;
            true
        }
        _ => false,
    }
}

/// End `tid`'s reading, if it has any.
fn end_reading(tid: u32) {
    let ended = {
        let mut h = HOLDERS.lock();
        h.iter().position(|x| x.tid == tid).map(|i| {
            h[i] = Holder { tid: 0, read: false };
            POOL.detach(1 + i);
        })
    };
    if ended.is_some() {
        azos_drv_sys::kwarn!("[CAMERA] frame reader of tid {} ended", tid);
    }
}

/// One `cam-capture` decision record.
fn record(verdict: Verdict, tid: u32, seq: u64, why: u32) {
    #[cfg(not(feature = "frame-unrecorded-canary"))]
    azos_decision::record(Rule::CamCapture, verdict, tid, [0, seq, why as u64]);
    #[cfg(feature = "frame-unrecorded-canary")]
    let _ = (verdict, tid, seq, why);
}

/// The pool could not be made: `have` of its buffers were (the boot refuses it).
pub fn refuse_pool(have: usize) {
    record(Verdict::Refuse, 0, have as u64, frame::reason::POOL);
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

    /// In order: the right (`READ`); the camera; for a task that is not yet a
    /// reader, its class's `cam` effect (a task without it learns nothing of
    /// the camera); the pool; the buffer (a bad one takes no frame); a reader
    /// slot; the frame, copied under a reference that ends with the call.
    /// A grant, a refusal and a task's first frame are `cam-capture` records.
    fn next(&mut self, buf: Cap<frame::FrameBuf>) -> Out<Meta> {
        if let Err(o) = self.0.gate::<Meta>(CapPerms::READ) {
            return o;
        }
        if self.0.badge >= frame::CAMERAS {
            return Out::err(outcome::NO_RESOURCE);
        }
        let tid = self.0.tid;
        let newcomer = !is_reader(tid);
        #[cfg(not(feature = "frame-effect-ignored-canary"))]
        if newcomer && !crate::effect::task_has(EffectKind::Cam, tid) {
            record(Verdict::Refuse, tid, 0, frame::reason::NO_EFFECT);
            return Out::err(outcome::REFUSED);
        }
        if !POOL.ready() {
            return Out::err(outcome::NOT_READY);
        }
        #[cfg(not(feature = "frame-check-late-canary"))]
        let held = match self.0.pin_buffer(buf.raw(), BYTES, BYTES) {
            Ok(h) => Some(h),
            Err(code) => return Out::err(code),
        };
        #[cfg(feature = "frame-check-late-canary")]
        let held = None;
        let Some(c) = cursor_of(tid) else {
            record(Verdict::Refuse, tid, 0, frame::reason::NO_SLOT);
            return Out::err(outcome::BUSY);
        };
        if newcomer {
            record(Verdict::Admit, tid, 0, frame::reason::GRANTED);
            azos_drv_sys::kwarn!("[CAMERA] frame reader opened by tid {}", tid);
        }
        if !attach(c) {
            return Out::err(outcome::NOT_READY);
        }
        let Some(f) = POOL.acquire_latest(c) else { return Out::err(outcome::NOT_READY) };
        let bytes = f.bytes();
        let held = match held {
            Some(h) => h,
            None => match self.0.pin_buffer(buf.raw(), BYTES, BYTES) {
                Ok(h) => h,
                Err(_) => return Out::err(outcome::FAULT),
            },
        };
        if !cfg!(feature = "frame-copy-skip-canary") {
            held.write(bytes);
        }
        drop(held);
        #[cfg(not(feature = "frame-first-read-always-canary"))]
        let first = first_read(tid);
        #[cfg(feature = "frame-first-read-always-canary")]
        let first = true;
        if first {
            record(Verdict::Admit, tid, f.seq(), frame::reason::FIRST_FRAME);
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
