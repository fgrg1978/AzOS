// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// RC (Remote Control) receiver driver — SBUS / PPM input.
///
/// Phase K1: provides RC receiver initialization and channel reading.
/// In QEMU (`RcMode::Simulated`), returns simulated neutral stick positions
/// — labeled as such, and only reachable in that mode.
///
/// **`RcMode::Sbus` / `RcMode::Ppm` are still not live.** [`sbus_decode`]
/// below turns a complete 25-byte SBUS frame into channel values, and it is
/// pure — it is handed bytes, it does not fetch them. What is still absent is
/// the *byte source*: nothing configures a UART for 100 kbaud 8E2 inverted,
/// nothing accumulates a frame from an RX interrupt, and nothing captures a
/// PPM pulse train. No caller of [`sbus_decode`] exists outside host tests,
/// so nothing ever calls [`rc_set_channels`] from real hardware.
///
/// Selecting either mode therefore does not enable RC input; [`rc_init`]
/// leaves the driver in failsafe/not-ready rather than handing a caller
/// fabricated "live" stick data it would trust as a real transmitter link.
/// [`rc_read`] returns `None` for these modes until the byte source exists
/// and drives the decoder from live frames.
///
/// Standard channel mapping:
/// - CH1: Roll     (1000-2000, center 1500)
/// - CH2: Pitch    (1000-2000, center 1500)
/// - CH3: Throttle (1000-2000, min 1000)
/// - CH4: Yaw      (1000-2000, center 1500)
/// - CH5: Mode switch
/// - CH6+: Auxiliary

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// RC input mode.
#[derive(Clone, Copy, PartialEq)]
pub enum RcMode {
    /// SBUS: 100000 baud, 8E2, inverted — most common in drones.
    Sbus,
    /// PPM: sum signal on single wire, timer capture.
    Ppm,
    /// Simulated: returns fixed values (QEMU).
    ///
    /// **Does not exist on a board target**, and that is the whole point.
    /// This variant marks the driver ready with failsafe CLEARED and hands
    /// out fixed neutral sticks, so `rc_age` never grows and the link-loss
    /// failsafe chain can never fire. On a laptop that is a useful stand-in;
    /// on a real machine it is a fabricated "link established" that no
    /// operator asked for, and the kernel selected it unconditionally at
    /// `rc_init` for every target until 2026-09-10.
    ///
    /// Gated with `cfg` rather than with a runtime check on purpose: a board
    /// build that tries to select it must FAIL TO COMPILE. A runtime guard
    /// would still ship the code and still depend on somebody reaching it.
    /// Same principle as requiring secure boot instead of assuming it.
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    Simulated,
}

// ---------------------------------------------------------------------------
// SBUS frame decode — pure, no MMIO, no globals, host-testable.
//
// Everything from here to the end of this section is arithmetic over 25 bytes
// somebody else supplied. It is deliberately separate from any byte source:
// the transport (UART at 100 kbaud, 8E2, signal-inverted) cannot be exercised
// without the board, but the bit unpacking can be gotten wrong on a laptop and
// a wrong unpacking is silent — it yields a perfectly plausible stick value.
// `tests/host/drivers-tests` pulls this module in with `#[path]` and tests the
// functions below directly, the same way `pwm_domain::pwm_control_allowed` and
// `drv_resource::motor_bridge_op_needs_pair` are tested.
// ---------------------------------------------------------------------------

/// Bytes in one SBUS frame.
pub const SBUS_FRAME_LEN: usize = 25;

/// Frame start byte.
pub const SBUS_START_BYTE: u8 = 0x0F;

/// Frame end byte.
///
/// Standard SBUS ends every frame with `0x00`. Futaba's SBUS2 reuses this
/// byte to tag a telemetry slot (`0x04` / `0x14` / `0x24` / `0x34`), so a
/// strict comparison rejects SBUS2 frames. That is the intended behaviour for
/// the FrSky receiver this tree targets, and it is an assumption about that
/// receiver — one that only the board can falsify.
pub const SBUS_END_BYTE: u8 = 0x00;

/// Flags byte (`frame[23]`), bit 0: digital channel 17.
pub const SBUS_FLAG_CH17: u8 = 1 << 0;
/// Flags byte (`frame[23]`), bit 1: digital channel 18.
pub const SBUS_FLAG_CH18: u8 = 1 << 1;
/// Flags byte (`frame[23]`), bit 2: this frame was lost in transit.
///
/// A single dropped frame. Receivers set this transiently on a healthy link;
/// it is *not* by itself loss of the transmitter.
pub const SBUS_FLAG_FRAME_LOST: u8 = 1 << 2;
/// Flags byte (`frame[23]`), bit 3: the receiver has entered failsafe.
///
/// The receiver asserts this after losing the transmitter for long enough to
/// give up. This is the bit an RC-link-loss failsafe turns on.
pub const SBUS_FLAG_FAILSAFE: u8 = 1 << 3;

/// Raw SBUS channel value at the low mechanical stop (-100%).
pub const SBUS_RAW_MIN: u16 = 172;
/// Raw SBUS channel value at centre.
pub const SBUS_RAW_CENTER: u16 = 992;
/// Raw SBUS channel value at the high mechanical stop (+100%).
pub const SBUS_RAW_MAX: u16 = 1811;

/// Low end of the pulse-width range [`rc_read`] hands out.
pub const RC_PULSE_MIN_US: u16 = 1000;
/// High end of the pulse-width range [`rc_read`] hands out.
pub const RC_PULSE_MAX_US: u16 = 2000;

/// One decoded SBUS frame.
///
/// `channels` are **raw** SBUS counts, 0..=2047, not microseconds — the
/// conversion is [`sbus_channel_to_us`], kept separate so a caller that wants
/// the untruncated receiver value (a failsafe check on a switch position, say)
/// can have it without the clamp.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SbusFrame {
    /// 16 proportional channels, 0..=2047.
    pub channels: [u16; 16],
    /// The receiver has lost the transmitter and entered failsafe.
    pub failsafe: bool,
    /// This particular frame was lost in transit.
    pub frame_lost: bool,
    /// Digital channel 17.
    pub ch17: bool,
    /// Digital channel 18.
    pub ch18: bool,
}

/// Decode one complete SBUS frame.
///
/// Returns `None` when the start or end byte is wrong — a frame that failed
/// framing is a frame whose channel bits are at unknown offsets, so there is
/// nothing to salvage from it and no partial result worth returning.
///
/// The 16 channels are 11 bits each, packed LSB-first into `frame[1..=22]`
/// with no byte alignment: channel `i` occupies stream bits `11*i ..= 11*i+10`
/// counting from bit 0 of `frame[1]`. Since `11*i % 8 <= 7`, one channel spans
/// at most three bytes, which is why the window below is three wide.
pub fn sbus_decode(frame: &[u8; SBUS_FRAME_LEN]) -> Option<SbusFrame> {
    if frame[0] != SBUS_START_BYTE {
        return None;
    }
    if frame[SBUS_FRAME_LEN - 1] != SBUS_END_BYTE {
        return None;
    }

    let mut channels = [0u16; 16];
    for (i, ch) in channels.iter_mut().enumerate() {
        let bit = i * 11;          // bit offset into the payload bitstream
        let byte = 1 + bit / 8;    // payload starts at frame[1]
        let shift = bit % 8;       // 0..=7

        // A third byte is needed only when the 11 bits do not fit in two:
        // shift + 11 > 16, i.e. shift >= 6. Channel 15 has shift 5 and byte
        // 21, so it reads frame[21] and frame[22] and stops short of the
        // flags byte.
        //
        // Two things this guard is NOT, both checked rather than assumed:
        // it is not a bounds check — the largest `byte + 2` over the sixteen
        // channels is 23, inside the 25-byte frame — and it is not what keeps
        // the flags out of a channel value. Whenever `shift < 6`, `hi`'s bits
        // land at word bit `16 - shift >= 11` and the `& 0x07FF` below
        // discards them, so dropping the guard entirely changes no decoded
        // value. Verified by mutation: relaxing it to `> 15` leaves every
        // test green. It stays because reading a byte whose bits are then
        // thrown away is worth avoiding, not because correctness rests on it.
        let lo = frame[byte] as u32;
        let mid = frame[byte + 1] as u32;
        let hi = if shift + 11 > 16 { frame[byte + 2] as u32 } else { 0 };

        let word = lo | (mid << 8) | (hi << 16);
        *ch = ((word >> shift) & 0x07FF) as u16;
    }

    let flags = frame[SBUS_FRAME_LEN - 2];
    Some(SbusFrame {
        channels,
        failsafe: flags & SBUS_FLAG_FAILSAFE != 0,
        frame_lost: flags & SBUS_FLAG_FRAME_LOST != 0,
        ch17: flags & SBUS_FLAG_CH17 != 0,
        ch18: flags & SBUS_FLAG_CH18 != 0,
    })
}

/// Convert one raw SBUS count (0..=2047) to the pulse width in microseconds
/// that [`rc_read`] and [`rc_set_channels`] speak.
///
/// The affine part is the mapping every common flight stack uses:
/// `us = raw * 5 / 8 + 880`, which puts 192 at exactly 1000 µs, 992 at exactly
/// 1500 µs and 1792 at exactly 2000 µs. The canonical stick stops sit slightly
/// outside that: 172 maps to 987 and 1811 to 2011.
///
/// The result is then clamped to [`RC_PULSE_MIN_US`]..=[`RC_PULSE_MAX_US`],
/// because that is the range `rc_read` documents and the range its callers
/// scale against. A transmitter configured for extended travel must not turn
/// into an out-of-range command downstream; the raw count is still available
/// in [`SbusFrame::channels`] for anything that needs the unclamped value.
pub fn sbus_channel_to_us(raw: u16) -> u16 {
    let raw = (raw & 0x07FF) as u32;
    let us = raw * 5 / 8 + 880;
    if us < RC_PULSE_MIN_US as u32 {
        RC_PULSE_MIN_US
    } else if us > RC_PULSE_MAX_US as u32 {
        RC_PULSE_MAX_US
    } else {
        us as u16
    }
}

/// Convert a decoded frame's 16 raw channels into the `[u16; 16]` pulse-width
/// array [`rc_set_channels`] takes and [`rc_read`] returns.
///
/// This is the whole adaptation between the SBUS wire format and the driver's
/// existing shape. It is a separate function, and not folded into
/// [`sbus_decode`], so the lossy step (the clamp in [`sbus_channel_to_us`]) is
/// never applied to data a caller asked to see raw.
pub fn sbus_frame_to_pulses(frame: &SbusFrame) -> [u16; 16] {
    let mut out = [0u16; 16];
    for (o, raw) in out.iter_mut().zip(frame.channels.iter()) {
        *o = sbus_channel_to_us(*raw);
    }
    out
}

static RC_READY: AtomicBool = AtomicBool::new(false);
static RC_MODE: AtomicU8 = AtomicU8::new(0); // 0=Sbus, 1=Ppm, 2=Simulated
static RC_FAILSAFE: AtomicBool = AtomicBool::new(true);

/// Simulated RC channels (neutral sticks, throttle low).
static mut RC_CHANNELS: [u16; 16] = [
    1500, 1500, 1000, 1500,  // Roll, Pitch, Throttle, Yaw
    1000, 1500, 1500, 1500,  // Mode(low), Aux1-3
    1500, 1500, 1500, 1500,  // Aux4-7
    1500, 1500, 1500, 1500,  // Aux8-11
];

/// Last update timestamp.
static mut RC_LAST_UPDATE: u64 = 0;

/// Initialize RC receiver.
///
/// `RcMode::Simulated` (QEMU / host testing) marks the driver ready with
/// failsafe cleared, and hands out the fixed neutral-stick array below —
/// that is its documented job.
///
/// `RcMode::Sbus` and `RcMode::Ppm` do *not* do the equivalent for real
/// hardware: there is no decoder in this file to back them (see the module
/// doc comment). Selecting either one leaves the driver **not ready** and
/// **in failsafe**, so [`rc_read`] keeps returning `None` — a caller that
/// checks it degrades (disarms / RTLs) instead of flying on a fabricated
/// "link established" state. This must change only once a real SBUS/PPM
/// decode routine exists and calls [`rc_set_channels`] from live frames.
pub fn rc_init(mode: RcMode) {
    let mode_val = match mode {
        RcMode::Sbus => 0,
        RcMode::Ppm => 1,
        #[cfg(not(any(feature = "vf2", feature = "k1")))]
        RcMode::Simulated => 2,
    };
    RC_MODE.store(mode_val, Ordering::Relaxed);

    match mode {
        #[cfg(not(any(feature = "vf2", feature = "k1")))]
        RcMode::Simulated => {
            RC_FAILSAFE.store(false, Ordering::Relaxed);
            RC_READY.store(true, Ordering::Release);
        }
        RcMode::Sbus | RcMode::Ppm => {
            // No decoder exists yet — fail closed rather than fabricate a
            // live link. See the module doc comment.
            azos_drv_sys::kwarn!(
                "[RC] WARNING: no {} decoder implemented — RC input held in failsafe (not ready)",
                if mode_val == 0 { "SBUS" } else { "PPM" }
            );
            RC_FAILSAFE.store(true, Ordering::Relaxed);
            RC_READY.store(false, Ordering::Release);
        }
    }

    unsafe { RC_LAST_UPDATE = azos_drv_sys::timebase::now(); }

    let mode_name = match mode {
        RcMode::Sbus => "SBUS",
        RcMode::Ppm => "PPM",
        #[cfg(not(any(feature = "vf2", feature = "k1")))]
        RcMode::Simulated => "Simulated",
    };
    azos_drv_sys::kprintln!("[RC] Initialized (mode: {})", mode_name);
}

/// Read current RC channel values.
///
/// Returns an array of 16 channel values (1000-2000 µs range) and a failsafe
/// flag. Returns `None` whenever the driver is not ready to hand out live
/// data — either because [`rc_init`] was never called, or because it was
/// called with `RcMode::Sbus`/`RcMode::Ppm`, for which no decoder exists
/// (see the module doc comment): those modes never become ready, so this
/// keeps returning `None` rather than synthesizing a value that looks like
/// a live transmitter link. Only `RcMode::Simulated` (QEMU / host testing)
/// ever makes this `Some`.
pub fn rc_read() -> Option<([u16; 16], bool)> {
    if !RC_READY.load(Ordering::Acquire) { return None; }

    let channels = unsafe { RC_CHANNELS };
    let failsafe = RC_FAILSAFE.load(Ordering::Acquire);
    Some((channels, failsafe))
}

/// Get timestamp of last RC update.
pub fn rc_last_update() -> u64 {
    unsafe { RC_LAST_UPDATE }
}

/// Feed simulated RC data (for testing).
///
/// Updates channel values and resets failsafe timer.
pub fn rc_set_channels(channels: &[u16; 16]) {
    unsafe {
        RC_CHANNELS = *channels;
        RC_LAST_UPDATE = azos_drv_sys::timebase::now();
    }
    RC_FAILSAFE.store(false, Ordering::Release);
}

/// Apply one decoded SBUS frame: channels, and the failsafe bit.
///
/// **The one place the failsafe decision is made, and it is a decision.** An
/// SBUS frame carries two status bits and they do not mean the same thing:
///
///   * `failsafe` (flags bit 3) is the RECEIVER's own verdict — it has lost
///     the link to the transmitter for long enough to give up and is now
///     outputting its configured failsafe positions.
///   * `frame_lost` (flags bit 2) is set when a SINGLE frame did not arrive.
///     At 100 Hz that happens with ordinary interference.
///
/// **Only bit 3 feeds `RC_FAILSAFE`** (owner decision, 2026-09-07). Feeding
/// `frame_lost` as well would turn one dropped frame into apparent link loss,
/// and what `RC_FAILSAFE` gates is whether the frame refreshes `CH_RC_INPUT` —
/// so whether `rc_age` grows and `FailsafeAction::RTL` fires. A spurious RTL
/// with propellers turning is not the safe side of that trade. ArduPilot and
/// PX4 both act on the receiver's verdict, not on frame loss.
///
/// `frame_lost` is therefore READ and DISCARDED here rather than never
/// decoded: `SbusFrame` carries it, so a future link-quality counter has it
/// without re-deciding this.
///
/// # Ordering
///
/// Channels first, failsafe second, and not the other way round.
/// [`rc_set_channels`] clears `RC_FAILSAFE` unconditionally — it is the "a
/// good frame arrived" path — so setting the flag before it would be undone.
pub fn rc_apply_sbus_frame(frame: &SbusFrame) {
    rc_set_channels(&sbus_frame_to_pulses(frame));
    // Deliberately NOT `frame.failsafe || frame.frame_lost`.
    rc_set_failsafe(frame.failsafe);
}

/// Set failsafe state (simulates signal loss).
pub fn rc_set_failsafe(fs: bool) {
    RC_FAILSAFE.store(fs, Ordering::Release);
}

/// Check if RC is initialized.
pub fn rc_is_ready() -> bool {
    RC_READY.load(Ordering::Acquire)
}

/// Print RC status info.
pub fn rc_info() {
    if !RC_READY.load(Ordering::Acquire) {
        azos_drv_sys::kconsoleln!("[RC] Not initialized");
        return;
    }
    let mode_val = RC_MODE.load(Ordering::Relaxed);
    let mode_name = match mode_val {
        0 => "SBUS",
        1 => "PPM",
        _ => "Simulated",
    };
    let failsafe = RC_FAILSAFE.load(Ordering::Acquire);
    azos_drv_sys::kconsoleln!("[RC] Mode: {}  Failsafe: {}", mode_name, failsafe);

    let channels = unsafe { RC_CHANNELS };
    azos_drv_sys::kconsoleln!("[RC] CH1(roll)={} CH2(pitch)={} CH3(thr)={} CH4(yaw)={}",
        channels[0], channels[1], channels[2], channels[3]);
    azos_drv_sys::kconsoleln!("[RC] CH5(mode)={} CH6(aux)={}",
        channels[4], channels[5]);
}
