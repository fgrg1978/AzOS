// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Frame` interface: the frames of a camera, for a task that looks at
//! them.
//!
//! The kernel hosts it on `frame.<n>` endpoints, one per camera (`frame.0`,
//! the perception camera: the CSI path's capture or a USB camera). A frame is
//! too big for a reply, so [`Frame::next`] **copies** the newest frame the
//! task has not taken into a memory object the task made, and answers what the
//! bytes are. A copy and not a mapping, because the frames stay in the kernel's
//! pool: the task can neither write a frame another reader will read nor keep
//! one after the pool reuses its buffer, and the kernel needs no way to take a
//! mapping back.
//!
//! The first `next` of a task makes it a **reader** of the camera: it takes
//! only frames committed after that, and the camera captures while somebody
//! reads. There are `FRAME_READERS` readers at once; the kernel's own sender
//! to the companion is one more and not counted. A reader ends with [`Frame::close`]
//! or with its task. Under `FRAME_POOL_BACKPRESSURE` a reader that stops
//! reading holds capture back for every reader until it closes or exits.
//!
//! The capability's `READ` is the right to read: a camera frame is what the
//! camera saw. A task's first `next` also needs the **`cam` effect** of its
//! scheduler class (`azos_topology::EffectKind::Cam`), as a capture stream needs
//! `mic` and default-deny: only a class an `[envelope.NAME]` row of kind `cam`
//! names at a level other than `contained` has it; any other is refused. The grant, each refusal and the first frame are `cam-capture`
//! decision records.
//!
//! # The buffer
//!
//! A `Cap<FrameBuf>` names a read-write memory object of at least
//! [`Frame::buffer_bytes`] bytes, an ordinary anonymous one (the kernel copies
//! into it page by page, so it needs no device visibility), held with `READ`
//! and `WRITE`. It stays in the caller's table and the call keeps nothing of it.
//!
//! # Outcomes
//!
//! `OK` with the [`Meta`]; `DENIED` without `READ`; `NO_RESOURCE` for an
//! instance the topology does not name; `REFUSED` when the task's class has no
//! `cam` effect; `NOT_READY` when the pool has no
//! buffers (no camera) or no frame newer than the reader's; `BUSY` when every
//! reader slot is taken; `BAD_ARGUMENT` for a handle that is not a memory
//! object or one too small; `UNSUPPORTED` for an object the kernel cannot
//! write (read-only, shared with a clone); `FAULT` when the copy failed.

use crate::outcome::Out;
use azos_idl::{azos_interface, Cap, Reader, Wire, Writer};

/// The interface id (ASCII "FRAM").
pub const FRAME_ID: u32 = 0x4652_414D;

/// Cameras the interface names: `frame.0`.
pub const CAMERAS: u32 = 1;

/// What a `Cap<FrameBuf>` names: a read-write memory object (any kind of
/// frames) of at least [`Frame::buffer_bytes`] bytes the caller shares with the
/// pool for one call.
pub struct FrameBuf;

/// The `reason` of a `cam-capture` decision record
/// (`azos_decision::Rule::CamCapture`).
pub mod reason {
    /// The task became a reader.
    pub const GRANTED: u32 = 0;
    /// Its class has no `cam` effect.
    pub const NO_EFFECT: u32 = 1;
    /// Every reader slot is taken.
    pub const NO_SLOT: u32 = 2;
    /// The task read its first frame.
    pub const FIRST_FRAME: u32 = 3;
    /// The pool could not be made.
    pub const POOL: u32 = 4;
}

/// What the bytes of a frame are ([`Meta::format`]).
pub mod format {
    /// A baseline JPEG; the size is in its header.
    pub const JPEG: u32 = 0;
    /// Packed YUV 4:2:2 (`Y0 U Y1 V` per two pixels), `2 * width * height`
    /// bytes.
    pub const YUYV: u32 = 1;
}

/// The frame [`Frame::next`] copied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    /// Bytes copied to the start of the buffer.
    pub len: u32,
    /// Frames committed since this reader's previous one that it never took.
    pub skipped: u32,
    /// The frame's sequence number (1, 2, ...), for every reader the same.
    pub seq: u64,
    /// When the frame was acquired, nanoseconds on the vDSO clock; 0 = unknown.
    pub acq_ns: u64,
    /// One of [`format`].
    pub format: u32,
    /// Pixels per row and rows, `width << 16 | height`; 0 when the bytes carry
    /// their own size (a JPEG).
    pub size: u32,
}

impl Wire for Meta {
    const WORDS: usize = 6;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.len.put(w);
        self.skipped.put(w);
        self.seq.put(w);
        self.acq_ns.put(w);
        self.format.put(w);
        self.size.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        Meta {
            len: u32::get(r),
            skipped: u32::get(r),
            seq: u64::get(r),
            acq_ns: u64::get(r),
            format: u32::get(r),
            size: u32::get(r),
        }
    }
}

#[azos_interface(id = 0x4652_414D, level = 1)]
pub trait Frame {
    /// The least size of the buffer [`Frame::next`] takes, in bytes: the
    /// biggest frame the camera's pool holds (Kconfig `FRAME_BYTES`). Needs
    /// `READ`.
    #[idempotent]
    fn buffer_bytes(&self) -> Out<u32>;
    /// Copy the newest frame this task has not taken into `buf`, and make the
    /// task a reader if it is not one. `NOT_READY` while there is none. A
    /// refused call (a bad buffer, no slot) takes no frame. Needs `READ`.
    fn next(&mut self, buf: Cap<FrameBuf>) -> Out<Meta>;
    /// End this task's reading: the camera stops waiting for it. Nothing to
    /// end is not an error. Needs `READ`.
    #[idempotent]
    fn close(&mut self) -> Out<()>;
}
