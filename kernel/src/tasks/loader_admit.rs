// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Admission of the autorun loader's staging buffer: how many frames an image
//! of a given size takes, and whether the budget of the row that bounds it allows them.
//!
//! The loader (`loader.rs`) reads the image's size first and stages the file
//! in a run of frames of exactly that size, given back before the new address
//! space is switched in. This is the
//! decision it makes before it takes a frame, pulled out so the host suite
//! (`tests/host/pkg-tests`, which pulls this file in with `#[path]`) runs the
//! code the kernel links. It names nothing of the kernel.

/// Why an image may not be staged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The file is empty (or is not a regular file, which reports no size).
    Empty,
    /// The image needs `frames`, more than the row's budget `limit`: an
    /// image its own row could not hold either (`exec_admit` refuses
    /// `ctx.frames > limit`), so it is refused before a frame is spent on it.
    OverBudget { frames: u32, limit: u32 },
    /// The image needs `frames`, more than the longest run the frame
    /// allocator forms (`max_run`, Kconfig `PMM_MAX_ORDER`).
    TooLarge { frames: u32, max_run: u32 },
    /// The image fits and no run of `frames` frames is free right now (the
    /// kernel found out by asking the allocator; [`admit`] never says it).
    NoFrames { frames: u32 },
}

/// The frames to stage `bytes` of image, or why not.
///
/// `frame_bytes` is the frame size, `limit` the row's budget in frames
/// (0 = none), `max_run` the longest physically contiguous run the frame
/// allocator forms.
pub fn admit(bytes: u64, frame_bytes: u64, limit: u32, max_run: u32) -> Result<u32, Refusal> {
    if bytes == 0 {
        return Err(Refusal::Empty);
    }
    let frames = bytes.div_ceil(frame_bytes);
    // A run past `u32` is past every limit as well: report the ceiling hit.
    let Ok(frames) = u32::try_from(frames) else {
        return Err(Refusal::TooLarge { frames: u32::MAX, max_run });
    };
    if frames > max_run {
        return Err(Refusal::TooLarge { frames, max_run });
    }
    if limit != 0 && frames > limit {
        return Err(Refusal::OverBudget { frames, limit });
    }
    Ok(frames)
}

impl Refusal {
    /// The frames the image needed: what the refusal's durable record carries.
    pub fn frames(self) -> u32 {
        match self {
            Refusal::Empty => 0,
            Refusal::OverBudget { frames, .. } | Refusal::TooLarge { frames, .. } | Refusal::NoFrames { frames } => frames,
        }
    }
}
