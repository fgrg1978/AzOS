// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Conversions between nanoseconds and the machine's tick counter: the RISC-V
//! `time` CSR, the Arm generic timer's count, the x86_64 clock's ticks.
//!
//! The ABI speaks nanoseconds; the counter ticks at a per-board frequency.
//! The kernel and ring 3 convert with the same two
//! functions, so a deadline computed from a clock read means the same instant
//! on both sides.
//!
//! Both split the value at the second so no intermediate product needs 128
//! bits. They are exact for any frequency up to 10^8 Hz and saturate, rather
//! than wrap, above that.

use core::sync::atomic::{fence, AtomicU32, Ordering};

/// Nanoseconds in one second.
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// The first counter value at or after `ns` nanoseconds, on a counter that
/// ticks `freq_hz` times per second. Rounds up, so a deadline converted here
/// is never reached early.
pub const fn ns_to_ticks_ceil(ns: u64, freq_hz: u64) -> u64 {
    let whole = (ns / NS_PER_SEC).saturating_mul(freq_hz);
    let part = ((ns % NS_PER_SEC).saturating_mul(freq_hz)).saturating_add(NS_PER_SEC - 1) / NS_PER_SEC;
    whole.saturating_add(part)
}

/// Nanoseconds elapsed at counter value `ticks`, rounded down.
///
/// `freq_hz` must not be 0; a zero frequency (a vDSO page that does not
/// publish one) returns 0.
pub const fn ticks_to_ns(ticks: u64, freq_hz: u64) -> u64 {
    if freq_hz == 0 {
        return 0;
    }
    let whole = (ticks / freq_hz).saturating_mul(NS_PER_SEC);
    let part = (ticks % freq_hz).saturating_mul(NS_PER_SEC) / freq_hz;
    whole.saturating_add(part)
}

/// A clock a deadline or a timestamp is read on.
///
/// One `u32`: the kind in bits 24..32, the index in bits 0..24. [`ClockId::MONO`]
/// is raw `0`, so a zero-filled field (a default descriptor)
/// names the monotonic boot clock.
///
/// Served: [`ClockId::MONO`], [`ClockId::REAL`], [`ClockId::TAI`] and
/// [`ClockId::BOOT`] (the vDSO's clock, [`ClockOffsets`]: the monotonic
/// counter plus an offset, no syscall). `TSC_RAW`, `PTP`, `TSN_DOMAIN` and
/// `VCPU` are reserved numbers so a caller can name them and be refused
/// (`Unsupported`) instead of silently read on the wrong clock.
///
/// Owner decision 16-10: records and deadlines use TAI-based monotonic time,
/// TAI taken from PTP or NTP plus the leap-second row of the topology
/// (`[clock]`, [`tai_minus_utc`]). Until a time source has set it, `REAL` and
/// `TAI` read like `MONO` (time since boot, as Linux's `CLOCK_TAI` does before
/// its offset is set). The sources are the kernel's SNTP client
/// (`azos_net::ntp`) and, with Kconfig `PTPD`, the PTP daemon
/// (`userspace/services/ptpd`), which offers its measurements to the kernel's
/// `Clock` interface (source PTP). That daemon steers `REAL` and `TAI`; it is
/// not the reserved [`ClockId::KIND_PTP`], which would name a PTP *hardware*
/// clock (a NIC's PHC) as a clock to read, and no kernel serves one.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClockId(pub u32);

impl ClockId {
    /// Bits of the index.
    pub const INDEX_BITS: u32 = 24;
    /// Mask of the index.
    pub const INDEX_MASK: u32 = (1 << Self::INDEX_BITS) - 1;

    /// Kind: the monotonic boot clock (the vDSO's, `azos_libsys::vdso_now_ns`).
    pub const KIND_MONO: u8 = 0;
    /// Kind: wall-clock time (UTC, Unix epoch): the monotonic clock plus the
    /// real offset.
    pub const KIND_REAL: u8 = 1;
    /// Kind (reserved): the raw hardware counter, unscaled.
    pub const KIND_TSC_RAW: u8 = 2;
    /// Kind (reserved): PTP hardware clock number `index`.
    pub const KIND_PTP: u8 = 3;
    /// Kind (reserved): time-sensitive-networking domain `index`.
    pub const KIND_TSN_DOMAIN: u8 = 4;
    /// Kind (reserved): the virtual time of vCPU `index`.
    pub const KIND_VCPU: u8 = 5;
    /// Kind: International Atomic Time, the Unix epoch, no leap seconds:
    /// UTC plus the TAI-UTC offset. What decision records and deadlines use.
    pub const KIND_TAI: u8 = 6;
    /// Kind: the monotonic clock plus the time the machine spent suspended
    /// (Linux's `CLOCK_BOOTTIME`). It reads as `MONO` until a system suspend
    /// finds the counter stopped across the sleep (`azos_drv_power::pm::suspend`).
    pub const KIND_BOOT: u8 = 7;

    /// The monotonic boot clock.
    pub const MONO: ClockId = ClockId::new(Self::KIND_MONO, 0);
    /// Wall-clock time.
    pub const REAL: ClockId = ClockId::new(Self::KIND_REAL, 0);
    /// International Atomic Time.
    pub const TAI: ClockId = ClockId::new(Self::KIND_TAI, 0);
    /// Monotonic time including suspend.
    pub const BOOT: ClockId = ClockId::new(Self::KIND_BOOT, 0);
    /// The raw hardware counter (reserved).
    pub const TSC_RAW: ClockId = ClockId::new(Self::KIND_TSC_RAW, 0);

    /// `kind` and `index` (an index past 24 bits is truncated).
    pub const fn new(kind: u8, index: u32) -> ClockId {
        ClockId((kind as u32) << Self::INDEX_BITS | (index & Self::INDEX_MASK))
    }
    /// PTP hardware clock `n` (reserved).
    pub const fn ptp(n: u32) -> ClockId {
        ClockId::new(Self::KIND_PTP, n)
    }
    /// TSN domain `n` (reserved).
    pub const fn tsn_domain(n: u32) -> ClockId {
        ClockId::new(Self::KIND_TSN_DOMAIN, n)
    }
    /// Virtual time of vCPU `n` (reserved).
    pub const fn vcpu(n: u32) -> ClockId {
        ClockId::new(Self::KIND_VCPU, n)
    }
    /// The kind (high bits).
    pub const fn kind(self) -> u8 {
        (self.0 >> Self::INDEX_BITS) as u8
    }
    /// The index (low bits).
    pub const fn index(self) -> u32 {
        self.0 & Self::INDEX_MASK
    }
    /// The raw `u32`, as it travels in a message descriptor.
    pub const fn raw(self) -> u32 {
        self.0
    }
    /// Is this the monotonic boot clock?
    pub const fn is_mono(self) -> bool {
        self.0 == Self::MONO.0
    }

    /// The clock a POSIX or Linux `clockid_t` names ([`posix_clock`]); `None`
    /// for a number that is not served (the CPU-time clocks, an unknown id).
    /// The one table the Linux personality, the Linux runtime and the C
    /// library read, so they cannot disagree about what a number means.
    pub const fn from_posix(id: u64) -> Option<ClockId> {
        Some(match id {
            posix_clock::REALTIME | posix_clock::REALTIME_COARSE => ClockId::REAL,
            posix_clock::MONOTONIC | posix_clock::MONOTONIC_RAW | posix_clock::MONOTONIC_COARSE => ClockId::MONO,
            posix_clock::BOOTTIME => ClockId::BOOT,
            posix_clock::TAI => ClockId::TAI,
            _ => return None,
        })
    }
}

/// The `clockid_t` numbers (Linux's, which the C library shares) that name a
/// served clock.
pub mod posix_clock {
    /// `CLOCK_REALTIME`: wall-clock time.
    pub const REALTIME: u64 = 0;
    /// `CLOCK_MONOTONIC`.
    pub const MONOTONIC: u64 = 1;
    /// `CLOCK_MONOTONIC_RAW` (the same clock: the counter is not slewed).
    pub const MONOTONIC_RAW: u64 = 4;
    /// `CLOCK_REALTIME_COARSE` (read like `REALTIME`).
    pub const REALTIME_COARSE: u64 = 5;
    /// `CLOCK_MONOTONIC_COARSE` (read like `MONOTONIC`).
    pub const MONOTONIC_COARSE: u64 = 6;
    /// `CLOCK_BOOTTIME`: monotonic including suspend.
    pub const BOOTTIME: u64 = 7;
    /// `CLOCK_TAI`: International Atomic Time.
    pub const TAI: u64 = 11;
}

/// Why a clock read was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    /// The clock is a reserved number no kernel serves yet.
    Unsupported,
}

/// How far each served clock runs ahead of the monotonic one, in nanoseconds:
/// `REAL = MONO + real`, `TAI = MONO + tai`, `BOOT = MONO + boot` (saturating).
/// The vDSO publishes them ([`ClockWords`]); a time source (NTP or PTP) moves
/// `real` and `tai`, and the monotonic counter underneath never
/// steps. All zero until one does, when every clock reads as the monotonic
/// one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClockOffsets {
    /// Wall clock (UTC) minus monotonic.
    pub real: u64,
    /// TAI minus monotonic: `real` plus the TAI-UTC seconds then in force.
    pub tai: u64,
    /// Boot clock minus monotonic: the total time spent suspended that the
    /// monotonic counter did not count. 0 until a system suspend finds the
    /// counter stopped across the sleep (`mm::vdso::vdso_add_suspended`).
    pub boot: u64,
}

impl ClockOffsets {
    /// Nothing set: every clock reads as the monotonic one.
    pub const ZERO: ClockOffsets = ClockOffsets { real: 0, tai: 0, boot: 0 };

    /// The offsets after the wall clock read `unix_ns` (UTC nanoseconds since
    /// the Unix epoch) when the monotonic clock read `mono_ns`. `tai` is
    /// `real` plus the TAI-UTC seconds `leaps` gives for that second (0 for a
    /// table that does not reach back that far, or an empty one: TAI then
    /// equals UTC, as Linux's does with no offset set). `boot` is kept: a
    /// time sync does not change how long the machine slept.
    pub fn with_wall(self, mono_ns: u64, unix_ns: u64, leaps: impl IntoIterator<Item = (u64, u16)>) -> ClockOffsets {
        let real = unix_ns.saturating_sub(mono_ns);
        let leap = tai_minus_utc(leaps, unix_ns / NS_PER_SEC).unwrap_or(0) as u64;
        ClockOffsets { real, tai: real.saturating_add(leap * NS_PER_SEC), boot: self.boot }
    }
}

/// TAI minus UTC, in seconds, at Unix second `unix_secs`: the offset of the
/// last entry whose first second is not after it. `leaps` is the `[clock]`
/// row's table, oldest first, as `(utc_secs, tai_offset)`. `None` for an empty
/// table or a time before its first entry.
pub fn tai_minus_utc(leaps: impl IntoIterator<Item = (u64, u16)>, unix_secs: u64) -> Option<u16> {
    let mut at = None;
    for (from, off) in leaps {
        if from > unix_secs {
            break;
        }
        at = Some(off);
    }
    at
}

/// Now on clock `id`, in nanoseconds. `mono` reads the monotonic clock and
/// `offsets` the published [`ClockOffsets`]; each is called only if `id` needs
/// it, and a reserved id reads nothing and returns
/// [`ClockError::Unsupported`].
pub fn clock_now_with(
    id: ClockId,
    mono: impl FnOnce() -> u64,
    offsets: impl FnOnce() -> ClockOffsets,
) -> Result<u64, ClockError> {
    let pick: fn(&ClockOffsets) -> u64 = match id.0 {
        x if x == ClockId::MONO.0 => return Ok(mono()),
        x if x == ClockId::REAL.0 => |o| o.real,
        x if x == ClockId::TAI.0 => |o| o.tai,
        x if x == ClockId::BOOT.0 => |o| o.boot,
        _ => return Err(ClockError::Unsupported),
    };
    let off = pick(&offsets());
    Ok(mono().saturating_add(off))
}

/// The vDSO page's clock words (at `vdso::VDSO_CLOCK_WORDS_OFFSET`): the
/// [`ClockOffsets`] under their own seqlock.
///
/// A separate generation word from the page's `seq`: the timer ISR drops a
/// tick's update when `seq` is odd, and a time source writing here, rarely
/// and from task context, must not make it lose ticks. The kernel
/// writes with [`ClockWords::update`]; ring 3 and the kernel's own readers
/// read with [`ClockWords::read`] (only loads, so a read-only mapping is
/// fine). The same type on both sides, so the protocol has one
/// implementation.
#[repr(C, align(8))]
pub struct ClockWords {
    /// Seqlock generation: even = stable, odd = a write is in progress.
    gen: AtomicU32,
    _pad: u32,
    real: Word64,
    tai: Word64,
    boot: Word64,
}

/// One 64-bit offset of the seqlock-guarded block. Only ever read or written
/// between two reads of `gen` (readers) or inside the claimed odd generation
/// (the single writer), so it needs no atomicity of its own: the generation
/// check rejects a torn read.
#[cfg(target_has_atomic = "64")]
type Word64 = core::sync::atomic::AtomicU64;

/// The same word on a target without 64-bit atomics (AzOS-micro, riscv32):
/// two 32-bit halves. A reader that sees the halves of two different writes
/// also sees a changed generation and retries.
#[cfg(not(target_has_atomic = "64"))]
struct Word64 {
    lo: AtomicU32,
    hi: AtomicU32,
}

#[cfg(not(target_has_atomic = "64"))]
impl Word64 {
    const fn new(v: u64) -> Word64 {
        Word64 { lo: AtomicU32::new(v as u32), hi: AtomicU32::new((v >> 32) as u32) }
    }
    fn load(&self, o: Ordering) -> u64 {
        self.lo.load(o) as u64 | (self.hi.load(o) as u64) << 32
    }
    fn store(&self, v: u64, o: Ordering) {
        self.lo.store(v as u32, o);
        self.hi.store((v >> 32) as u32, o);
    }
}

impl ClockWords {
    /// All offsets zero, generation 0.
    pub const fn new() -> ClockWords {
        ClockWords { gen: AtomicU32::new(0), _pad: 0, real: Word64::new(0), tai: Word64::new(0), boot: Word64::new(0) }
    }

    /// A consistent copy of the offsets: retried while a write is open or
    /// completed in between. Spins while a write is open; the writer runs
    /// with interrupts off and for a handful of instructions.
    pub fn read(&self) -> ClockOffsets {
        loop {
            let g1 = self.gen.load(Ordering::Acquire);
            if g1 & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let o = ClockOffsets {
                real: self.real.load(Ordering::Relaxed),
                tai: self.tai.load(Ordering::Relaxed),
                boot: self.boot.load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            if self.gen.load(Ordering::Relaxed) == g1 {
                return o;
            }
            core::hint::spin_loop();
        }
    }

    /// Replace the offsets with `f` of the current ones, atomically for
    /// readers. Writers exclude each other by claiming the generation word
    /// (an even-to-odd compare-exchange), so a second writer waits for the
    /// first; unlike the per-tick page update, a time sync is never dropped.
    ///
    /// The caller must have interrupts masked: an interrupt that preempted
    /// the writer inside the window would leave every reader on this hart
    /// spinning on an odd generation.
    pub fn update(&self, f: impl FnOnce(ClockOffsets) -> ClockOffsets) {
        let mut g = self.gen.load(Ordering::Relaxed);
        loop {
            if g & 1 == 0 {
                match self.gen.compare_exchange_weak(g, g.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(now) => g = now,
                }
            } else {
                core::hint::spin_loop();
                g = self.gen.load(Ordering::Relaxed);
            }
        }
        // The odd generation must be seen before any new value.
        fence(Ordering::Release);
        let cur = ClockOffsets {
            real: self.real.load(Ordering::Relaxed),
            tai: self.tai.load(Ordering::Relaxed),
            boot: self.boot.load(Ordering::Relaxed),
        };
        let new = f(cur);
        self.real.store(new.real, Ordering::Relaxed);
        self.tai.store(new.tai, Ordering::Relaxed);
        self.boot.store(new.boot, Ordering::Relaxed);
        self.gen.store(g.wrapping_add(2), Ordering::Release);
    }
}

impl Default for ClockWords {
    fn default() -> Self {
        Self::new()
    }
}
