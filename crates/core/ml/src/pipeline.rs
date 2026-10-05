// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Zero-copy sensor → inference pipeline (F15).
//!
//! Manages double/triple buffering between DMA sensor capture and ML inference.
//! Minimizes latency by overlapping capture and inference on different buffers.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pipeline buffers (triple buffering).
pub const PIPELINE_MAX_BUFFERS: usize = 3;

/// Maximum buffer size in bytes (256 KiB — enough for 96×96×3 RGB + headroom).
pub const PIPELINE_BUFFER_SIZE: usize = 256 * 1024;

/// Pipeline stages.
const STAGE_IDLE: u8 = 0;
const STAGE_CAPTURING: u8 = 1;
const STAGE_READY: u8 = 2;
const STAGE_INFERRING: u8 = 3;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A pipeline buffer slot.
pub struct PipelineBuffer {
    /// Physical address of the buffer (DMA-accessible).
    pub phys_addr: usize,
    /// Current stage of this buffer.
    stage: AtomicU8,
    /// Actual data length in this buffer.
    pub data_len: AtomicU32,
}

impl PipelineBuffer {
    pub const fn empty() -> Self {
        Self {
            phys_addr: 0,
            stage: AtomicU8::new(STAGE_IDLE),
            data_len: AtomicU32::new(0),
        }
    }

    pub fn is_idle(&self) -> bool {
        self.stage.load(Ordering::Acquire) == STAGE_IDLE
    }

    pub fn is_ready(&self) -> bool {
        self.stage.load(Ordering::Acquire) == STAGE_READY
    }
}

/// The inference pipeline configuration.
pub struct InferencePipeline {
    /// Buffer pool.
    pub buffers: [PipelineBuffer; PIPELINE_MAX_BUFFERS],
    /// Number of active buffers (2 = double, 3 = triple).
    pub buffer_count: u8,
    /// Index of buffer currently being captured into.
    capture_idx: AtomicU8,
    /// Index of buffer currently being inferred on.
    infer_idx: AtomicU8,
    /// Total frames captured.
    pub frames_captured: AtomicU32,
    /// Total frames inferred.
    pub frames_inferred: AtomicU32,
    /// Whether the pipeline is active.
    pub active: bool,
}

impl InferencePipeline {
    pub const fn new() -> Self {
        Self {
            buffers: [
                PipelineBuffer::empty(),
                PipelineBuffer::empty(),
                PipelineBuffer::empty(),
            ],
            buffer_count: 2, // double buffering by default
            capture_idx: AtomicU8::new(0),
            infer_idx: AtomicU8::new(1),
            frames_captured: AtomicU32::new(0),
            frames_inferred: AtomicU32::new(0),
            active: false,
        }
    }

    /// Initialize the pipeline with allocated physical buffers.
    pub fn init(&mut self, buffer_addrs: &[usize], count: u8) {
        let n = (count as usize).min(PIPELINE_MAX_BUFFERS);
        for i in 0..n {
            self.buffers[i].phys_addr = buffer_addrs[i];
            self.buffers[i].stage.store(STAGE_IDLE, Ordering::Release);
        }
        self.buffer_count = n as u8;
        self.active = true;
    }

    /// Get the next buffer for DMA capture. Returns buffer index and phys_addr.
    /// Returns None if no idle buffer available.
    pub fn acquire_capture_buffer(&self) -> Option<(usize, usize)> {
        let n = self.buffer_count as usize;
        for i in 0..n {
            if self.buffers[i].is_idle() {
                self.buffers[i].stage.store(STAGE_CAPTURING, Ordering::Release);
                self.capture_idx.store(i as u8, Ordering::Relaxed);
                return Some((i, self.buffers[i].phys_addr));
            }
        }
        None // all buffers in use
    }

    /// Mark a capture buffer as ready for inference.
    pub fn capture_complete(&self, buf_idx: usize, data_len: usize) {
        if buf_idx >= PIPELINE_MAX_BUFFERS { return; }
        self.buffers[buf_idx].data_len.store(data_len as u32, Ordering::Release);
        self.buffers[buf_idx].stage.store(STAGE_READY, Ordering::Release);
        self.frames_captured.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the next buffer ready for inference. Returns buffer index and phys_addr.
    pub fn acquire_infer_buffer(&self) -> Option<(usize, usize, u32)> {
        let n = self.buffer_count as usize;
        for i in 0..n {
            if self.buffers[i].is_ready() {
                self.buffers[i].stage.store(STAGE_INFERRING, Ordering::Release);
                self.infer_idx.store(i as u8, Ordering::Relaxed);
                let len = self.buffers[i].data_len.load(Ordering::Acquire);
                return Some((i, self.buffers[i].phys_addr, len));
            }
        }
        None
    }

    /// Release a buffer back to idle after inference is complete.
    pub fn infer_complete(&self, buf_idx: usize) {
        if buf_idx >= PIPELINE_MAX_BUFFERS { return; }
        self.buffers[buf_idx].stage.store(STAGE_IDLE, Ordering::Release);
        self.frames_inferred.fetch_add(1, Ordering::Relaxed);
    }

    /// Get pipeline throughput stats: (captured, inferred, dropped).
    pub fn stats(&self) -> (u32, u32, u32) {
        let captured = self.frames_captured.load(Ordering::Relaxed);
        let inferred = self.frames_inferred.load(Ordering::Relaxed);
        let dropped = captured.saturating_sub(inferred);
        (captured, inferred, dropped)
    }
}
