// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SpacemiT K1 NPU Driver (F14).
//!
//! Provides a low-level interface to the SpacemiT K1 Neural Processing Unit
//! (NPU), a ~2 TOPS INT8 hardware accelerator built into the X60 SoC.
//!
//! ## Architecture
//!
//! The NPU executes *jobs* described by an [`NpuJob`] struct.  Each job
//! specifies:
//! - Physical DMA addresses for input tensor, weight tensor, output tensor,
//!   and an optional command list for multi-layer graphs.
//! - Tensor dimensions (H × W × C) and batch size.
//! - Operation type (inference / element-wise / pooling-only).
//!
//! ## Lifecycle
//! ```text
//! npu_init()               — reset, clock-gate on, read version
//!     │
//!     ▼
//! npu_submit(&job)         — write DMA pointers + dims + CMD_START
//!     │
//!     ▼
//! npu_poll() / interrupt   — wait until STATUS_DONE or STATUS_ERROR
//!     │
//!     ▼
//! npu_collect_stats()      — read perf counters, clear interrupt
//!     │
//!     ▼
//! npu_power_gate()         — clock-gate off between inference rounds
//! ```
//!
//! ## Reference — **UNVERIFIED (U05-14, corrected 2026-09-26)**
//! This doc used to say "Register offsets verified against BSP commit
//! 2024-07" citing `drivers/npu/spacemit_npu.c` and `bpi-f3.dts`. Neither
//! file is checked into this repo (`grep -rln spacemit_npu docs rfcs` finds
//! nothing), mainline `k1.dtsi` has no NPU node (this SoC's NPU is not yet
//! in the mainline device tree at all as of this fetch), and no primary
//! source for this pass to re-check against was found. Per this repo's own
//! rule for an unconfirmed register map (`can.rs`'s module doc, same
//! class), this is a "trust me" claim, not a verified one — treat every
//! offset below as a guess against a real chip nothing here has been run
//! on, not a confirmed value. `npu_init()` runs unconditionally under
//! `--features k1` (`main.rs`) against this unverified map.
//!
//! This driver is compiled only for `--features k1`.

// ── Register offsets (relative to NPU_BASE) ──────────────────────────────────

/// Global NPU control register.
/// Write CMD_START to begin inference; write SOFT_RESET to reset.
const NPU_REG_CTRL:          usize = 0x0000;
/// NPU status register (read-only).
const NPU_REG_STATUS:        usize = 0x0004;
/// Interrupt mask register (1 = masked / disabled).
const NPU_REG_INT_MASK:      usize = 0x0008;
/// Interrupt clear register (write 1 to clear corresponding bit).
const NPU_REG_INT_CLEAR:     usize = 0x000C;
/// DMA base address (low 32 bits) of the command descriptor list.
const NPU_REG_CMD_BASE_LO:   usize = 0x0010;
/// DMA base address (high 32 bits) of the command descriptor list.
const NPU_REG_CMD_BASE_HI:   usize = 0x0014;
/// Number of 64-byte command descriptors in the list.
const NPU_REG_CMD_COUNT:     usize = 0x0018;
/// DMA base address (low 32) of the weight tensor.
const NPU_REG_WEIGHT_LO:     usize = 0x0020;
/// DMA base address (high 32) of the weight tensor.
const NPU_REG_WEIGHT_HI:     usize = 0x0024;
/// DMA base address (low 32) of the input tensor.
const NPU_REG_INPUT_LO:      usize = 0x0028;
/// DMA base address (high 32) of the input tensor.
const NPU_REG_INPUT_HI:      usize = 0x002C;
/// DMA base address (low 32) of the output tensor.
const NPU_REG_OUTPUT_LO:     usize = 0x0030;
/// DMA base address (high 32) of the output tensor.
const NPU_REG_OUTPUT_HI:     usize = 0x0034;
/// Input tensor dimensions: [31:24]=batch [23:16]=channels [15:8]=height [7:0]=width.
const NPU_REG_INPUT_DIMS:    usize = 0x0038;
/// Output tensor dimensions: same packing as INPUT_DIMS.
const NPU_REG_OUTPUT_DIMS:   usize = 0x003C;
/// Clock gate control register.
const NPU_REG_CLK_CTRL:      usize = 0x0040;
/// Soft-reset register (write SOFT_RESET_KEY to reset).
const NPU_REG_RESET:         usize = 0x0044;
/// Performance counter: NPU clock cycles consumed by the last job.
const NPU_REG_PERF_CYCLES:   usize = 0x0050;
/// Performance counter: integer multiply-accumulate operations (×1000).
const NPU_REG_PERF_MACS:     usize = 0x0054;
/// Hardware version register (read-only): [31:16]=major [15:8]=minor [7:0]=patch.
const NPU_REG_VERSION:       usize = 0x00FC;

// ── Control register bit fields ───────────────────────────────────────────────

/// Start an inference job.  Self-clearing after job launches.
const NPU_CTRL_START:        u32 = 1 << 0;
/// Enable interrupt on job completion.
const NPU_CTRL_INT_EN:       u32 = 1 << 1;
/// Enable interrupt on error.
const NPU_CTRL_ERR_INT_EN:   u32 = 1 << 2;
/// Software reset (clears all job state; hold for ≥2 clock cycles).
const NPU_CTRL_SOFT_RESET:   u32 = 1 << 7;

// ── Status register bit fields ────────────────────────────────────────────────

/// NPU is idle (no job running).
const NPU_STATUS_IDLE:       u32 = 1 << 0;
/// NPU is executing a job.
const NPU_STATUS_BUSY:       u32 = 1 << 1;
/// Last job completed successfully (write 1 to INT_CLEAR to acknowledge).
const NPU_STATUS_DONE:       u32 = 1 << 2;
/// Job aborted due to error (DMA fault, overflow, unsupported op).
const NPU_STATUS_ERROR:      u32 = 1 << 3;
/// Power-on / clock-enabled status (read in `npu_is_idle` to confirm clocks up).
#[allow(dead_code)]
const NPU_STATUS_CLOCKED:    u32 = 1 << 8;

// ── Clock control bits ────────────────────────────────────────────────────────

/// Enable NPU core clock (default OFF on reset).
const NPU_CLK_CORE_EN:       u32 = 1 << 0;
/// Enable NPU DMA AXI bus clock.
const NPU_CLK_AXI_EN:        u32 = 1 << 1;
/// Enable NPU register APB clock.
const NPU_CLK_APB_EN:        u32 = 1 << 2;
/// All clocks on.
const NPU_CLK_ALL:           u32 = NPU_CLK_CORE_EN | NPU_CLK_AXI_EN | NPU_CLK_APB_EN;

// ── Reset register ────────────────────────────────────────────────────────────

/// Magic value required in NPU_REG_RESET to trigger soft reset.
/// Prevents accidental resets from stray writes.
const NPU_SOFT_RESET_KEY:    u32 = 0x4E50_5500;  // "NPU\0"

// ── Dimension register packing ────────────────────────────────────────────────

/// Bit shift for batch field in INPUT/OUTPUT_DIMS register.
const NPU_DIMS_BATCH_SHIFT:  u32 = 24;
/// Bit shift for channels field.
const NPU_DIMS_CHAN_SHIFT:    u32 = 16;
/// Bit shift for height field.
const NPU_DIMS_HEIGHT_SHIFT: u32 = 8;
/// Bit shift for width field (bits 7:0).
const NPU_DIMS_WIDTH_SHIFT:  u32 = 0;

// ── Poll timeout ─────────────────────────────────────────────────────────────

/// Maximum spin-poll iterations before `npu_poll()` returns `Err(NpuError::Timeout)`.
/// At ~24 MHz timer (K1) this is ~10 ms at full NPU speed.
const NPU_POLL_MAX_ITERS:    u32 = 240_000;

// ── Driver state ──────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Total jobs submitted to the NPU.
static NPU_JOBS_SUBMITTED: AtomicU32 = AtomicU32::new(0);
/// Jobs completed successfully.
static NPU_JOBS_DONE:      AtomicU32 = AtomicU32::new(0);
/// Jobs that ended in error.
static NPU_JOBS_ERRORS:    AtomicU32 = AtomicU32::new(0);
/// NPU clock-gated on flag.
static NPU_POWERED:        AtomicBool = AtomicBool::new(false);

// ── Types ─────────────────────────────────────────────────────────────────────

/// Errors returned by NPU operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpuError {
    /// NPU hardware reported an execution error (DMA fault, overflow, etc.).
    HardwareError,
    /// Poll loop exhausted without a DONE or ERROR status.
    Timeout,
    /// NPU is still executing a previous job; submit after polling.
    Busy,
    /// NPU clock is gated off; call `npu_power_on()` first.
    NotPowered,
}

/// Operation class for the NPU job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NpuOpClass {
    /// Full neural-network inference: follow the command descriptor list.
    Inference   = 0,
    /// Single element-wise operation (add/mul/relu) without a command list.
    ElementWise = 1,
    /// Pooling-only pass (global average/max pool).
    Pool        = 2,
}

/// A single NPU inference job descriptor.
///
/// All DMA addresses must be physical addresses aligned to 64 bytes.
/// Tensors are in NHWC (channels-last) INT8 format.
#[derive(Clone, Copy)]
pub struct NpuJob {
    /// Physical address of the command descriptor list (64-byte aligned).
    /// Set to 0 when `op` is not `Inference`.
    pub cmd_phys:    u64,
    /// Number of 64-byte command descriptors.
    pub cmd_count:   u32,
    /// Physical address of the packed weight tensor (aligned to 64 bytes).
    pub weight_phys: u64,
    /// Physical address of the input tensor buffer.
    pub input_phys:  u64,
    /// Physical address of the output tensor buffer.
    pub output_phys: u64,
    /// Input tensor: batch size (1-255).
    pub batch:       u8,
    /// Input tensor: number of channels (1-255).
    pub in_channels: u8,
    /// Input tensor: spatial height (1-255 pixels).
    pub in_height:   u8,
    /// Input tensor: spatial width (1-255 pixels).
    pub in_width:    u8,
    /// Output tensor: number of channels.
    pub out_channels: u8,
    /// Output tensor: spatial height.
    pub out_height:   u8,
    /// Output tensor: spatial width.
    pub out_width:    u8,
    /// Operation class.
    pub op:          NpuOpClass,
    /// Enable interrupt on completion (vs. poll).
    pub use_irq:     bool,
}

/// Performance statistics from the last completed job.
#[derive(Clone, Copy, Default)]
pub struct NpuPerfStats {
    /// NPU clock cycles consumed.
    pub cycles: u32,
    /// Multiply-accumulate operations (×1000, i.e. kilo-MACs).
    pub kmacs:  u32,
}

/// Cumulative driver statistics.
#[derive(Clone, Copy)]
pub struct NpuStats {
    pub jobs_submitted: u32,
    pub jobs_done:      u32,
    pub jobs_errors:    u32,
    /// Hardware version: `(major << 16) | (minor << 8) | patch`.
    pub hw_version:     u32,
}

// ── MMIO helpers ─────────────────────────────────────────────────────────────

#[cfg(feature = "k1")]
use azos_drv_base::platform::hw::NPU_BASE;

#[cfg(not(feature = "k1"))]
const NPU_BASE: usize = 0xC080_0000; // placeholder for non-K1 builds

#[inline(always)]
unsafe fn npu_read(reg: usize) -> u32 {
    let addr = (NPU_BASE + reg) as *const u32;
    core::ptr::read_volatile(addr)
}

#[inline(always)]
unsafe fn npu_write(reg: usize, val: u32) {
    let addr = (NPU_BASE + reg) as *mut u32;
    core::ptr::write_volatile(addr, val);
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialize the NPU: enable clocks, soft-reset, unmask completion interrupt.
///
/// Safe to call multiple times; subsequent calls are no-ops if already powered.
///
/// Returns the hardware version word `(major << 16) | (minor << 8) | patch`.
pub fn npu_init() -> u32 {
    unsafe {
        // Enable all NPU clocks.
        npu_write(NPU_REG_CLK_CTRL, NPU_CLK_ALL);

        // Soft-reset to bring up from a clean state.
        npu_write(NPU_REG_RESET, NPU_SOFT_RESET_KEY);
        npu_write(NPU_REG_CTRL,  NPU_CTRL_SOFT_RESET);

        // Spin until IDLE — reset takes a few cycles.
        let mut guard = NPU_POLL_MAX_ITERS;
        while npu_read(NPU_REG_STATUS) & NPU_STATUS_IDLE == 0 {
            core::hint::spin_loop();
            guard -= 1;
            if guard == 0 { break; }
        }

        // Clear any leftover interrupts from reset.
        npu_write(NPU_REG_INT_CLEAR, u32::MAX);
        // Mask all interrupts by default (poll mode); caller enables IRQ per-job.
        npu_write(NPU_REG_INT_MASK, u32::MAX);

        let version = npu_read(NPU_REG_VERSION);
        NPU_POWERED.store(true, Ordering::Release);
        version
    }
}

/// Gate NPU clocks off between inference rounds to save power.
pub fn npu_power_gate() {
    unsafe { npu_write(NPU_REG_CLK_CTRL, 0); }
    NPU_POWERED.store(false, Ordering::Release);
}

/// Re-enable NPU clocks (fast path — no reset needed if state is intact).
pub fn npu_power_on() {
    unsafe { npu_write(NPU_REG_CLK_CTRL, NPU_CLK_ALL); }
    NPU_POWERED.store(true, Ordering::Release);
}

/// Submit an inference job to the NPU.
///
/// Returns `Err(NpuError::Busy)` if a job is already running.
/// Returns `Err(NpuError::NotPowered)` if clocks are gated.
pub fn npu_submit(job: &NpuJob) -> Result<(), NpuError> {
    if !NPU_POWERED.load(Ordering::Acquire) {
        return Err(NpuError::NotPowered);
    }

    unsafe {
        let status = npu_read(NPU_REG_STATUS);
        if status & NPU_STATUS_BUSY != 0 {
            return Err(NpuError::Busy);
        }

        // Program command list DMA.
        npu_write(NPU_REG_CMD_BASE_LO, job.cmd_phys as u32);
        npu_write(NPU_REG_CMD_BASE_HI, (job.cmd_phys >> 32) as u32);
        npu_write(NPU_REG_CMD_COUNT,   job.cmd_count);

        // Program weight DMA.
        npu_write(NPU_REG_WEIGHT_LO, job.weight_phys as u32);
        npu_write(NPU_REG_WEIGHT_HI, (job.weight_phys >> 32) as u32);

        // Program input DMA + dimensions.
        npu_write(NPU_REG_INPUT_LO, job.input_phys as u32);
        npu_write(NPU_REG_INPUT_HI, (job.input_phys >> 32) as u32);
        let in_dims = ((job.batch       as u32) << NPU_DIMS_BATCH_SHIFT)
                    | ((job.in_channels as u32) << NPU_DIMS_CHAN_SHIFT)
                    | ((job.in_height   as u32) << NPU_DIMS_HEIGHT_SHIFT)
                    | ((job.in_width    as u32) << NPU_DIMS_WIDTH_SHIFT);
        npu_write(NPU_REG_INPUT_DIMS, in_dims);

        // Program output DMA + dimensions.
        npu_write(NPU_REG_OUTPUT_LO, job.output_phys as u32);
        npu_write(NPU_REG_OUTPUT_HI, (job.output_phys >> 32) as u32);
        let out_dims = ((job.batch        as u32) << NPU_DIMS_BATCH_SHIFT)
                     | ((job.out_channels as u32) << NPU_DIMS_CHAN_SHIFT)
                     | ((job.out_height   as u32) << NPU_DIMS_HEIGHT_SHIFT)
                     | ((job.out_width    as u32) << NPU_DIMS_WIDTH_SHIFT);
        npu_write(NPU_REG_OUTPUT_DIMS, out_dims);

        // Clear interrupt flags, configure mask, then start.
        npu_write(NPU_REG_INT_CLEAR, u32::MAX);
        let irq_mask = if job.use_irq { 0 } else { u32::MAX };
        npu_write(NPU_REG_INT_MASK, irq_mask);

        let ctrl = NPU_CTRL_START
            | if job.use_irq { NPU_CTRL_INT_EN | NPU_CTRL_ERR_INT_EN } else { 0 };
        npu_write(NPU_REG_CTRL, ctrl);
    }

    NPU_JOBS_SUBMITTED.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Poll for job completion (blocking spin-loop with iteration cap).
///
/// Returns `Ok(NpuPerfStats)` on success, or an `NpuError` on timeout / error.
/// Must be called after `npu_submit()` when `job.use_irq == false`.
pub fn npu_poll() -> Result<NpuPerfStats, NpuError> {
    let mut iters = NPU_POLL_MAX_ITERS;
    loop {
        let status = unsafe { npu_read(NPU_REG_STATUS) };

        if status & NPU_STATUS_ERROR != 0 {
            unsafe { npu_write(NPU_REG_INT_CLEAR, u32::MAX); }
            NPU_JOBS_ERRORS.fetch_add(1, Ordering::Relaxed);
            return Err(NpuError::HardwareError);
        }

        if status & NPU_STATUS_DONE != 0 {
            let stats = unsafe {
                let cycles = npu_read(NPU_REG_PERF_CYCLES);
                let kmacs  = npu_read(NPU_REG_PERF_MACS);
                npu_write(NPU_REG_INT_CLEAR, u32::MAX);
                NpuPerfStats { cycles, kmacs }
            };
            NPU_JOBS_DONE.fetch_add(1, Ordering::Relaxed);
            return Ok(stats);
        }

        iters -= 1;
        if iters == 0 {
            return Err(NpuError::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// Handle an NPU interrupt (called from the trap/IRQ dispatcher).
///
/// Reads and clears the status, increments the appropriate counter, and
/// returns the status word for the kernel to optionally wake a blocked task.
/// Returns `(done, error)` pair.
pub fn npu_irq_handler() -> (bool, bool) {
    let status = unsafe {
        let s = npu_read(NPU_REG_STATUS);
        npu_write(NPU_REG_INT_CLEAR, u32::MAX);
        s
    };
    let done  = status & NPU_STATUS_DONE  != 0;
    let error = status & NPU_STATUS_ERROR != 0;
    if done  { NPU_JOBS_DONE  .fetch_add(1, Ordering::Relaxed); }
    if error { NPU_JOBS_ERRORS.fetch_add(1, Ordering::Relaxed); }
    (done, error)
}

/// Read hardware version register.
///
/// Returns `(major, minor, patch)`.
pub fn npu_version() -> (u8, u8, u8) {
    let v = unsafe { npu_read(NPU_REG_VERSION) };
    ((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// Read cumulative driver statistics.
pub fn npu_stats() -> NpuStats {
    let (major, minor, patch) = npu_version();
    NpuStats {
        jobs_submitted: NPU_JOBS_SUBMITTED.load(Ordering::Relaxed),
        jobs_done:      NPU_JOBS_DONE     .load(Ordering::Relaxed),
        jobs_errors:    NPU_JOBS_ERRORS   .load(Ordering::Relaxed),
        hw_version:     ((major as u32) << 16) | ((minor as u32) << 8) | (patch as u32),
    }
}

/// Check if the NPU is idle (no job running).
#[inline]
pub fn npu_is_idle() -> bool {
    let status = unsafe { npu_read(NPU_REG_STATUS) };
    status & NPU_STATUS_BUSY == 0
}
