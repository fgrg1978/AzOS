// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// DMA controller skeleton — memory-to-memory copy acceleration.
///
/// QEMU: simulated via `core::ptr::copy_nonoverlapping` (always completes instantly).
/// K1: **no controller driven** (see the `k1` module below).
/// VF2: **wrong IP AND wrong job, corrected 2026-09-26 (U05-1).** This module
/// used to address `0x1600_8000` as a "SiFive PDMA"; that address is real
/// hardware, but mainline `jh7110.dtsi` names it `sdma:
/// dma-controller@16008000`, `compatible = "arm,pl080", "arm,primecell"` —
/// an ARM PL080, used on real silicon for the crypto engine's DMA. The
/// general-purpose DMA controller (what this module's `dma_memcpy` API is
/// for) is a SEPARATE device, `dma: dma-controller@16050000`, `compatible =
/// "starfive,jh7110-axi-dma"`: the hardware bus binds that node to this
/// driver (`dma_attach`, `kernel/src/boot/hwbus.rs`) and the window is the
/// node's `reg`. The PL080 is claimed by nothing. Register offsets below
/// are neither IP's (the `dma_memcpy` helpers have no caller, U05-7), so
/// they are left as documented, known-wrong code rather than rewritten
/// against either real register map; the testing week confirms or replaces
/// them on a VisionFive 2.
pub const DMA_MAX_CHANNELS: usize = 8;

#[derive(Clone, Copy)]
pub struct DmaChannel {
    pub id:     u8,
    pub src:    usize,
    pub dst:    usize,
    pub len:    usize,
    pub active: bool,
}

impl DmaChannel {
    pub const fn new(id: u8) -> Self {
        DmaChannel { id, src: 0, dst: 0, len: 0, active: false }
    }
}

// ── QEMU: simulated DMA (ptr::copy_nonoverlapping) ──────────────────────────

#[cfg(not(any(feature = "vf2", feature = "k1")))]
mod sim {
    use super::*;
    use azos_sync::SpinLock;

    struct DmaState {
        channels: [DmaChannel; DMA_MAX_CHANNELS],
        init: bool,
    }

    impl DmaState {
        const fn new() -> Self {
            DmaState {
                channels: [
                    DmaChannel::new(0), DmaChannel::new(1),
                    DmaChannel::new(2), DmaChannel::new(3),
                    DmaChannel::new(4), DmaChannel::new(5),
                    DmaChannel::new(6), DmaChannel::new(7),
                ],
                init: false,
            }
        }
    }

    static DMA: SpinLock<DmaState> = SpinLock::new(DmaState::new());

    pub fn dma_init() {
        let mut state = DMA.lock();
        if state.init { return; }
        for i in 0..DMA_MAX_CHANNELS {
            state.channels[i] = DmaChannel::new(i as u8);
        }
        state.init = true;
        azos_drv_sys::kprintln!("[DMA] Initialized (simulated, {} channels)", DMA_MAX_CHANNELS);
    }

    /// Request (reserve) a DMA channel.  Returns true if the channel was free.
    pub fn dma_request(ch: usize) -> bool {
        if ch >= DMA_MAX_CHANNELS { return false; }
        let mut state = DMA.lock();
        if state.channels[ch].active { return false; }
        state.channels[ch].active = true;
        true
    }

    /// Release a DMA channel.
    pub fn dma_release(ch: usize) {
        if ch >= DMA_MAX_CHANNELS { return; }
        let mut state = DMA.lock();
        state.channels[ch].active = false;
        state.channels[ch].src = 0;
        state.channels[ch].dst = 0;
        state.channels[ch].len = 0;
    }

    /// Start a DMA transfer.  In QEMU sim this completes synchronously via
    /// `core::ptr::copy_nonoverlapping`.
    ///
    /// # Safety
    /// Caller must ensure `src` and `dst` are valid, non-overlapping memory
    /// regions of at least `len` bytes.
    pub fn dma_transfer(ch: usize, src: usize, dst: usize, len: usize) -> i32 {
        if ch >= DMA_MAX_CHANNELS || len == 0 { return -1; }
        let mut state = DMA.lock();
        if !state.channels[ch].active { return -1; }
        state.channels[ch].src = src;
        state.channels[ch].dst = dst;
        state.channels[ch].len = len;

        // Simulated: instant memory copy
        unsafe {
            core::ptr::copy_nonoverlapping(
                src as *const u8,
                dst as *mut u8,
                len,
            );
        }
        0
    }

    /// Check if a DMA transfer is complete.  Always true in simulation.
    pub fn dma_is_complete(ch: usize) -> bool {
        if ch >= DMA_MAX_CHANNELS { return false; }
        let state = DMA.lock();
        state.channels[ch].active
    }

    pub fn dma_info() {
        let state = DMA.lock();
        azos_drv_sys::kconsoleln!("[DMA] Simulated DMA — {} channels", DMA_MAX_CHANNELS);
        for i in 0..DMA_MAX_CHANNELS {
            let ch = &state.channels[i];
            if ch.active {
                azos_drv_sys::kconsoleln!("[DMA]   ch{}: ACTIVE src={:#x} dst={:#x} len={}",
                    i, ch.src, ch.dst, ch.len);
            } else {
                azos_drv_sys::kconsoleln!("[DMA]   ch{}: free", i);
            }
        }
    }
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub use sim::*;

// ── VisionFive 2 / JH7110: PDMA controller ─────────────────────────────────
//
// JH7110 Platform DMA (PDMA) at 0x16008000.
// Based on SiFive PDMA specification.
//
// Per-channel register block (stride 0x100):
//   +0x00  CONTROL      — enable, claim, run/halt
//   +0x04  NEXT_CONFIG   — transfer config: wsize, rsize, repeat
//   +0x08  NEXT_BYTES    — transfer byte count
//   +0x0C  NEXT_DST      — destination address (64-bit)
//   +0x14  NEXT_SRC      — source address (64-bit)
//   +0x1C  EXEC_CONFIG   — running transfer config (read-only)
//   +0x20  EXEC_BYTES    — running byte count (read-only)

#[cfg(feature = "vf2")]
mod pdma {
    use super::*;
    use azos_sync::SpinLock;

    use azos_drv_base::window::{Taken, Window};

    /// The `starfive,jh7110-axi-dma` window, attached when the hardware bus
    /// binds the node (`dma_attach`). Unbound: no controller, every entry
    /// point answers failure and no register is touched.
    static WINDOW: Window = Window::new();

    const PDMA_CH_STRIDE: usize = 0x100;

    // Per-channel register offsets
    const PDMA_CONTROL:     usize = 0x00;
    const PDMA_NEXT_CONFIG: usize = 0x04;
    const PDMA_NEXT_BYTES:  usize = 0x08;
    const PDMA_NEXT_DST:    usize = 0x0C;
    const PDMA_NEXT_SRC:    usize = 0x14;

    // CONTROL bits
    const CTRL_CLAIM: u32 = 1 << 0;
    const CTRL_RUN:   u32 = 1 << 1;
    const CTRL_DONE:  u32 = 1 << 30;

    struct DmaState {
        channels: [DmaChannel; DMA_MAX_CHANNELS],
    }

    impl DmaState {
        const fn new() -> Self {
            DmaState {
                channels: [
                    DmaChannel::new(0), DmaChannel::new(1),
                    DmaChannel::new(2), DmaChannel::new(3),
                    DmaChannel::new(4), DmaChannel::new(5),
                    DmaChannel::new(6), DmaChannel::new(7),
                ],
            }
        }
    }

    static DMA: SpinLock<DmaState> = SpinLock::new(DmaState::new());

    /// An unbound read is 0 and an unbound write goes nowhere; the entry
    /// points check `bound()` first.
    #[inline(always)]
    fn rd(ch: usize, off: usize) -> u32 {
        match WINDOW.base() {
            // SAFETY: the base the bus bound and the kernel mapped.
            Some(b) => unsafe { core::ptr::read_volatile((b + ch * PDMA_CH_STRIDE + off) as *const u32) },
            None => 0,
        }
    }

    #[inline(always)]
    fn wr(ch: usize, off: usize, val: u32) {
        if let Some(b) = WINDOW.base() {
            // SAFETY: as `rd`.
            unsafe { core::ptr::write_volatile((b + ch * PDMA_CH_STRIDE + off) as *mut u32, val) }
        }
    }

    #[inline(always)]
    fn bound() -> bool {
        WINDOW.base().is_some()
    }

    /// Hand the driver the controller the hardware bus bound at `base`.
    /// Nothing is written: a channel is claimed by `dma_request`. `Err` when
    /// a controller is already attached.
    pub fn dma_attach(base: usize) -> Result<(), Taken> {
        WINDOW.attach(base)?;
        azos_drv_sys::kprintln!("[DMA] JH7110 DMA controller @ {:#010x} ({} channels)", base, DMA_MAX_CHANNELS);
        Ok(())
    }

    pub fn dma_request(ch: usize) -> bool {
        if ch >= DMA_MAX_CHANNELS || !bound() { return false; }
        let mut state = DMA.lock();
        if state.channels[ch].active { return false; }
        wr(ch, PDMA_CONTROL, CTRL_CLAIM);
        state.channels[ch].active = true;
        true
    }

    pub fn dma_release(ch: usize) {
        if ch >= DMA_MAX_CHANNELS || !bound() { return; }
        let mut state = DMA.lock();
        wr(ch, PDMA_CONTROL, 0);
        state.channels[ch].active = false;
    }

    /// Timeout for DMA completion polling (~100 ms at typical clock).
    const DMA_TIMEOUT: u32 = 1_000_000;

    pub fn dma_transfer(ch: usize, src: usize, dst: usize, len: usize) -> i32 {
        if ch >= DMA_MAX_CHANNELS || len == 0 || !bound() { return -1; }
        let mut state = DMA.lock();
        if !state.channels[ch].active { return -1; }
        state.channels[ch].src = src;
        state.channels[ch].dst = dst;
        state.channels[ch].len = len;
        // Program PDMA registers
        wr(ch, PDMA_NEXT_SRC, src as u32);
        wr(ch, PDMA_NEXT_DST, dst as u32);
        wr(ch, PDMA_NEXT_BYTES, len as u32);
        wr(ch, PDMA_NEXT_CONFIG, 0); // default config
        wr(ch, PDMA_CONTROL, CTRL_CLAIM | CTRL_RUN);
        // Drop the lock before polling — allows other code to run.
        drop(state);
        // Poll for completion with timeout.
        for _ in 0..DMA_TIMEOUT {
            if rd(ch, PDMA_CONTROL) & CTRL_DONE != 0 {
                return 0;
            }
            core::hint::spin_loop();
        }
        -1 // timeout
    }

    pub fn dma_is_complete(ch: usize) -> bool {
        if ch >= DMA_MAX_CHANNELS || !bound() { return false; }
        rd(ch, PDMA_CONTROL) & CTRL_DONE != 0
    }

    pub fn dma_info() {
        let state = DMA.lock();
        azos_drv_sys::kconsoleln!("[DMA] JH7110 DMA controller @ {:#010x}", WINDOW.base().unwrap_or(0));
        for i in 0..DMA_MAX_CHANNELS {
            let ch = &state.channels[i];
            let ctrl = rd(i, PDMA_CONTROL);
            if ch.active {
                azos_drv_sys::kconsoleln!("[DMA]   ch{}: ACTIVE ctrl={:#010x} src={:#x} dst={:#x} len={}",
                    i, ctrl, ch.src, ch.dst, ch.len);
            } else {
                azos_drv_sys::kconsoleln!("[DMA]   ch{}: free (ctrl={:#010x})", i, ctrl);
            }
        }
    }
}

#[cfg(feature = "vf2")]
pub use pdma::*;

// ── SpacemiT K1: the PDMA is not driven ─────────────────────────────────────
//
// The K1 has a general-purpose DMA controller, `pdma: dma-controller@d4000000`
// (`compatible = "spacemit,k1-pdma"`, 16 channels, one shared interrupt,
// `status = "disabled"` in `k1.dtsi`), the Marvell MMP PDMA with 64-bit
// addressing: Linux v7.2.9 `drivers/dma/mmp_pdma.c` (`spacemit_k1_pdma_ops`)
// and the binding `spacemit,k1-pdma.yaml`. This module does NOT drive it, and
// that is a decision, not a gap: nothing in the tree takes a DMA channel.
// `dma_memcpy` and its three siblings below have no caller on any board
// (the VF2 note at the top of this file says as much), and the peripherals whose requests
// the PDMA serves (UART 0/2..9, I2C, SPI3, I2S, QSPI, CAN; `k1-pdma.h`) are
// driven by the CPU here. A driver for it would be several hundred lines with
// no user: descriptors in DMA-visible memory, a bus address from a
// `DmaDomain`, `azos_dma::cache` bracketing, the request-to-channel map.
//
// So on a `k1` build every entry point answers "no controller" exactly as a
// VF2 tree without the node does, the helpers below fall back to the CPU
// copy they already fall back to when no channel is free, and no `hwbus.ids`
// row binds the node. The first consumer of a K1 DMA channel writes the
// driver from Linux `mmp_pdma.c` (`spacemit_k1_pdma_ops`); nothing of it is
// kept here.

#[cfg(feature = "k1")]
mod k1 {
    /// Nothing to bring up; says so once, where the board's other drivers
    /// say what they bound.
    pub fn dma_init() {
        azos_drv_sys::kprintln!("[DMA] SpacemiT K1 PDMA not driven: no consumer (copies run on the CPU)");
    }

    /// No channel exists: the caller's CPU fallback runs.
    pub fn dma_request(_ch: usize) -> bool {
        false
    }

    pub fn dma_release(_ch: usize) {}

    pub fn dma_transfer(_ch: usize, _src: usize, _dst: usize, _len: usize) -> i32 {
        -1
    }

    pub fn dma_is_complete(_ch: usize) -> bool {
        false
    }

    pub fn dma_info() {
        azos_drv_sys::kconsoleln!("[DMA] SpacemiT K1 PDMA not driven: no consumer");
    }
}

#[cfg(feature = "k1")]
pub use k1::*;

// ---------------------------------------------------------------------------
// High-level DMA helpers (F02 wiring)
// ---------------------------------------------------------------------------

/// Reserved DMA channel for network packet copy.
const DMA_CH_NET: usize = 0;

/// Reserved DMA channel for camera frame copy.
const DMA_CH_CAMERA: usize = 1;

/// Reserved DMA channel for LiDAR scan copy.
const DMA_CH_LIDAR: usize = 2;

/// One-shot DMA memory copy. Reserves a channel, transfers, releases.
///
/// Returns 0 on success, -1 on failure.
/// Falls back to CPU memcpy if DMA is unavailable.
///
/// # Safety
/// `src` and `dst` must be valid, non-overlapping memory of `len` bytes.
pub fn dma_memcpy(src: usize, dst: usize, len: usize) -> i32 {
    /// Minimum transfer size to justify DMA overhead (below this, CPU is faster).
    const DMA_MIN_TRANSFER_SIZE: usize = 256;

    if len < DMA_MIN_TRANSFER_SIZE || len == 0 {
        // Small transfer: CPU copy is faster than DMA setup overhead
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len); }
        return 0;
    }

    // Try to use DMA
    if dma_request(DMA_CH_NET) {
        let result = dma_transfer(DMA_CH_NET, src, dst, len);
        dma_release(DMA_CH_NET);
        result
    } else if dma_request(DMA_CH_CAMERA) {
        // Fallback to alternate channel
        let result = dma_transfer(DMA_CH_CAMERA, src, dst, len);
        dma_release(DMA_CH_CAMERA);
        result
    } else {
        // All channels busy — CPU fallback
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len); }
        0
    }
}

/// DMA copy for network packets (uses reserved NET channel).
///
/// # Safety
/// See `dma_memcpy`.
pub fn dma_net_copy(src: usize, dst: usize, len: usize) -> i32 {
    if !dma_request(DMA_CH_NET) {
        // Busy — fall back to CPU
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len); }
        return 0;
    }
    let result = dma_transfer(DMA_CH_NET, src, dst, len);
    dma_release(DMA_CH_NET);
    result
}

/// DMA copy for camera frames (uses reserved CAMERA channel).
///
/// # Safety
/// See `dma_memcpy`.
pub fn dma_camera_copy(src: usize, dst: usize, len: usize) -> i32 {
    if !dma_request(DMA_CH_CAMERA) {
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len); }
        return 0;
    }
    let result = dma_transfer(DMA_CH_CAMERA, src, dst, len);
    dma_release(DMA_CH_CAMERA);
    result
}

/// DMA copy for LiDAR scans (uses reserved LIDAR channel).
///
/// # Safety
/// See `dma_memcpy`.
pub fn dma_lidar_copy(src: usize, dst: usize, len: usize) -> i32 {
    if !dma_request(DMA_CH_LIDAR) {
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len); }
        return 0;
    }
    let result = dma_transfer(DMA_CH_LIDAR, src, dst, len);
    dma_release(DMA_CH_LIDAR);
    result
}
