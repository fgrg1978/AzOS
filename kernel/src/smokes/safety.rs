// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Safety smokes: reflex, envelope, geofence, brain-lies, capability denial
//! (with its exec-refusal read-back and seccomp audit task), and the shared
//! on-disk safety-record lookups.

use crate::*;

/// cap-deny-smoke: prove an exec refusal is RECORDED, not only printed.
///
/// Called by `autorun_task` on its refusal path, after the durable write, with
/// the first four bytes of the refused digest: only a record carrying them
/// counts. It reads the log back a few times with a flush between reads instead
/// of once, to absorb a slow block device. Every scenario boots a freshly made
/// image, so a record found is this boot's.
#[cfg(feature = "cap-deny-smoke")]
pub(crate) fn exec_refusal_readback(digest_head: u32) {
    const ATTEMPTS: u32 = 20;
    const INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 2;
    let code = azos_behavior::logger::SAFETY_EXEC_REFUSED;
    let (mut found, mut records) = (false, 0u32);
    for _ in 0..ATTEMPTS {
        let _ = azos_behavior::logger::logger_flush();
        let (f, n) = find_safety_record_detail_on_disk(code, 0, Some(digest_head));
        records = n;
        if f {
            found = true;
            break;
        }
        let dl = azos_drv_sys::timebase::now() + INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }
    if found {
        kprintln!("[AUTORUN] exec refusal RECORDED: the autorun refusal of sha256 {:08x}... \
                   is in the persistent log, {} records", digest_head, records);
    } else {
        kprintln!("[AUTORUN] exec refusal NOT RECORDED: {} records on disk, none is the \
                   autorun refusal of sha256 {:08x}...", records, digest_head);
    }
}

/// cap-deny-smoke: prove a syscall an audit-mode image profile let through is
/// RECORDED on disk.
///
/// Spawned by `autorun_task` only when the image it is about to exec runs in
/// audit mode, with the one syscall number that image issues outside its row
/// (`tests/host/seccomp-tests`, `AUDITED_PROBES`): 116, the retired
/// `SYS_CAP_GRANT`, for `CAPTEST.ELF` on the `userspace: denial RECORDED` boot.
/// Only a `SAFETY_SECCOMP_AUDIT` record, action 0, whose detail is that number
/// counts. Polls like `cap_deny_smoke_task`: 60 s of CLINT time, one disk read
/// every half second.
#[cfg(feature = "cap-deny-smoke")]
pub(crate) fn seccomp_audit_smoke_task(expected_nr: usize) {
    const ATTEMPTS: u32 = 120;
    const INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 2;
    let code = azos_behavior::logger::SAFETY_SECCOMP_AUDIT;
    let nr = expected_nr as u32;
    let (mut found, mut records, mut attempts) = (false, 0u32, 0u32);
    while attempts < ATTEMPTS && !found {
        attempts += 1;
        let dl = azos_drv_sys::timebase::now() + INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
        let _ = azos_behavior::logger::logger_flush();
        let (f, n) = find_safety_record_detail_on_disk(code, 0, Some(nr));
        found = f;
        records = n;
    }
    if found {
        kprintln!("[SECCOMPAUDIT] RECORDED: syscall {} let through by an audit-mode image \
                   profile is in the persistent log after {} attempt(s), {} records",
                  nr, attempts, records);
    } else {
        kprintln!("[SECCOMPAUDIT] NOT RECORDED: {} records on disk, none is the seccomp \
                   audit record of syscall {}", records, nr);
    }
}

// ISA-neutral, same reasoning as `gpio_user_driver_smoke_task` above:
// `rangefinder::us_set_distance`/`us_read_mm` simulate the sensor in
// software (QEMU has no real rangefinder either way) and carry no
// `target_arch` branch.
#[cfg(feature = "reflex-smoke")]
pub(crate) fn reflex_smoke_task(_arg: usize) {
    use azos_drv_sensor::rangefinder;
    use azos_syscall::sleep::sleep_ms;

    // Each step is a sleep on the counter. It was a count of `task_yield()`s
    // (2,000,000 on riscv64, 40,000,000 on aarch64, where the riscv64 count
    // placed and cleared the obstacle inside one of reflex's 25 ms polls): a
    // yield count is real time only relative to how fast QEMU-TCG runs this
    // ISA on this host at that moment. reflex itself sleeps 25 ms between
    // polls (`REFLEX_PERIOD_MS`), so 1 s per step is 40 polls.
    /// Time for the autorun task to load REFLEX.ELF from FAT32 and reach its
    /// main loop.
    const LOAD_MS: u64 = 20_000;
    /// Obstacle held, then road held clear.
    const STEP_MS: u64 = 1_000;

    sleep_ms(LOAD_MS);

    kprintln!("[REFLEXSMOKE] placing obstacle at 100mm (critical < 150mm)");
    rangefinder::us_set_distance(0, 100);

    sleep_ms(STEP_MS);

    kprintln!("[REFLEXSMOKE] clearing road to 1500mm (clear > 600mm)");
    rangefinder::us_set_distance(0, 1500);

    sleep_ms(STEP_MS);

    kprintln!("[REFLEXSMOKE] DONE");
}

/// envelope-smoke: prove RFC-0033's motor envelope actually refuses a command
/// the brain had no right to issue, at the real MotorCmd -> PWM chokepoint.
///
/// Sequence, all observed on the console:
///   1. publish (100,-100) on `CH_MOTOR_CMD` — above the wheeled cap of 80
///      (`SAFETY_WHEELED_MAX_SPEED_PCT`) — expect
///      `[ENVELOPE] refused: asked (100,-100) applied (80,-80)`
///   2. publish (50,-50), inside the envelope — expect
///      `[ENVELOPE] within bounds again`
///
/// **Why it publishes in a loop rather than once.** RT-MOTOR's watchdog trips
/// at 500 ms of silence and switches to SAFE STOP, which skips the envelope
/// branch entirely. A single publish would therefore prove nothing: the
/// command has to keep arriving for the chokepoint to keep running.
///
/// The second phase matters as much as the first. A monitor that clamps
/// everything forever is not a safety envelope, it is a broken robot — so the
/// scenario also asserts the command is released once it is legal again.
///
/// **Expect the console to alternate.** `CH_MOTOR_CMD` has several publishers
/// — the local control loop at the `motor_cmd_publish(sl, sr)` site, and the
/// safety paths that publish `(0,0)` — and the channel keeps only the last
/// write. So an over-cap command from this task is repeatedly interleaved with
/// in-envelope commands from elsewhere, and the edge trigger fires on each
/// genuine transition. That is the arbitration behaving as built, not a fault
/// in the envelope.
/// Scan the flight recorder on disk for one safety record.
///
/// Returns `(found, records_seen)`. Matches on BOTH the violation code and the
/// action byte, because several codes are only meaningful with it — the
/// unknown-packet record carries the packet type there, so a match on the code
/// alone would pass on a record about a different frame.
///
/// **Extracted 2026-09-08.** This scan was written inline twice inside
/// `envelope_smoke_task` (once for the envelope refusal, once for the e-stop)
/// and a third smoke probe was about to copy it again. It is not incidental
/// code: it decodes the on-disk format, so three copies are three places for
/// the reader to drift from `LogRecord::decode`.
///
/// Opens `LOG00000.BIN` specifically. Every smoke scenario boots a freshly
/// made image, so serial 0 is the only file that exists; a probe that ran long
/// enough to rotate would need `make_log_path`, and none does.
#[cfg(any(feature = "envelope-smoke", feature = "brain-lies-smoke", feature = "cap-deny-smoke",
          feature = "disk-part-row", feature = "ml-kill-smoke", feature = "fence-refuse-smoke"))]
pub(crate) fn find_safety_record_on_disk(code: u8, action: u8) -> (bool, u32) {
    find_safety_record_detail_on_disk(code, action, None)
}

/// [`find_safety_record_on_disk`], and with `detail` set only a record whose
/// detail word equals it counts: for a probe that knows which event it waits
/// for, not only which kind (the seccomp audit record of syscall 116, the exec
/// refusal of one digest).
#[cfg(any(feature = "envelope-smoke", feature = "brain-lies-smoke", feature = "cap-deny-smoke",
          feature = "disk-part-row", feature = "ml-kill-smoke", feature = "rc-failsafe-smoke",
          feature = "fence-refuse-smoke"))]
pub(crate) fn find_safety_record_detail_on_disk(code: u8, action: u8, detail: Option<u32>) -> (bool, u32) {
    let mut found = false;
    let mut records = 0u32;
    let Ok(vol) = azos_fs::fat32_mount_volume() else {
        kprintln!("[LOGSCAN] no FAT32 volume");
        return (false, 0);
    };
    let Ok(file) = azos_fs::fat32_open(vol, b"/LOG/LOG00000.BIN",
                                           azos_fs::open_flags::READ) else {
        kprintln!("[LOGSCAN] no log file on disk");
        return (false, 0);
    };
    // Header, then fixed-size records, one at a time: the point is to find a
    // record, not to put the whole log on the kernel stack.
    let mut hdr = [0u8; azos_behavior::logger::LOG_FILE_HEADER_BYTES];
    let _ = azos_fs::fat32_read(file, &mut hdr);
    loop {
        let mut raw = [0u8; azos_behavior::logger::LOG_RECORD_SIZE];
        match azos_fs::fat32_read(file, &mut raw) {
            Ok(n) if n == azos_behavior::logger::LOG_RECORD_SIZE => {
                let rec = azos_behavior::logger::LogRecord::decode(&raw);
                records += 1;
                if rec.kind == azos_behavior::logger::LOG_EVT_SAFETY_VIOLATION
                    && rec.payload[0] == code
                    && rec.payload[1] == action
                    && detail.map_or(true, |d| {
                        // `log_safety_violation` stores detail little-endian at 4..8.
                        u32::from_le_bytes([rec.payload[4], rec.payload[5],
                                            rec.payload[6], rec.payload[7]]) == d
                    })
                {
                    found = true;
                }
            }
            _ => break,
        }
    }
    let _ = azos_fs::fat32_close(file);
    (found, records)
}

#[cfg(feature = "envelope-smoke")]
pub(crate) fn envelope_smoke_task(_arg: usize) {
    use azos_syscall::sleep::{ms_to_ticks, sleep_ms};
    /// How long RT-MOTOR gets to reach its loop, and how long each phase
    /// publishes, in ms of counter time. Both were 200,000 yields: a count,
    /// whose duration followed host load.
    const SETTLE_MS: u64 = 2_000;
    const PHASE_MS: u64 = 1_500;

    /// Publish `(l, r)` every millisecond for `PHASE_MS`. The sleep, not a
    /// yield, is what gives RT-MOTOR (and every lower-priority task on this
    /// hart) its turns.
    fn publish_for_phase(l: i32, r: i32) {
        let end = azos_drv_sys::timebase::now().saturating_add(ms_to_ticks(PHASE_MS));
        while azos_drv_sys::timebase::now() < end {
            azos_robot::motor_cmd_publish(l, r);
            sleep_ms(1);
        }
    }

    // Let RT-MOTOR reach its loop first.
    sleep_ms(SETTLE_MS);

    kprintln!("[ENVSMOKE] asking for (100,-100); wheeled cap is 80");
    publish_for_phase(100, -100);

    kprintln!("[ENVSMOKE] asking for (50,-50), inside the envelope");
    publish_for_phase(50, -50);

    // ── The record half of the thesis sentence ───────────────────────────
    //
    // Asserting on the console line proves the kernel REFUSED. It says nothing
    // about whether it RECORDED, and the thesis requires both — "no motor moves
    // outside a safety envelope ... and without a record". So read the record
    // back off the disk it was supposed to reach, rather than trusting that the
    // call was made.
    //
    // A flush first, because safety events are rare and the ring only spills
    // itself when it is half full; `sys-wdt` also flushes every ~500 ms, but
    // waiting on another task's cadence would make this scenario time-dependent
    // for no reason.
    let _ = azos_behavior::logger::logger_flush();

    let (found, records) = find_safety_record_on_disk(
        azos_behavior::logger::SAFETY_ENVELOPE_REFUSED, 0);

    if found {
        kprintln!("[ENVSMOKE] RECORDED: envelope refusal is in the persistent log \
                   ({} records)", records);
    } else {
        kprintln!("[ENVSMOKE] NOT RECORDED: {} records on disk, none is an \
                   envelope refusal", records);
    }

    // ── Durability, which the periodic flush cannot demonstrate ─────────
    //
    // Everything above proves the record REACHES the disk. It does not prove
    // it reaches the disk in time, and for an e-stop that is the whole
    // question: the event is the one most likely to be followed within
    // milliseconds by a reset, a power cut, or a human pulling the plug. A
    // record that is still in RAM when that happens is a record of nothing.
    //
    // So: write an e-stop record through the durable path and read it straight
    // back, with NO `logger_flush` and NO watchdog cycle in between. If the
    // durability is really in `log_safety_violation_durable` this finds it; if
    // it silently regresses to the deferred variant, this is the only thing in
    // the tree that would notice.
    //
    // Honest about what this does NOT cover. Four e-stop sources, three of
    // them now driven end to end, each asserted on the LATCH rather than on a
    // console line — a handler that stops the wheels without latching still
    // prints "envelope latched", measured:
    //
    //   ring 3 via SYS_ROBOT_ESTOP  — `userspace: ring-3 e-stop`
    //   brain over TCP  (PKT_ESTOP) — `safety: brain e-stop (tcp)`
    //   the physical GPIO switch    — `safety: kill switch (gpio)`
    //   brain over UART (PKT_ESTOP) — NOT COVERABLE HERE, see below
    //
    // The UART one is not a gap waiting to be filled: the bridge is
    // `cfg(feature = "vf2")`, `bridge_is_ready()` is a literal `false` in every
    // QEMU build, and it reads UART1 at 0x10010000, which `-machine virt` does
    // not have and cannot be given. Its DECISION is covered on the host
    // instead (`tests/host/behavior-tests`, module `remote_actuation`), shared with
    // the TCP path so the two cannot drift again; its TRANSPORT waits for the
    // board.
    let _ = azos_behavior::logger::log_safety_violation_durable(
        azos_behavior::logger::SAFETY_ESTOP, 7, 0xE570_0000);

    let (estop_on_disk, _) = find_safety_record_on_disk(
        azos_behavior::logger::SAFETY_ESTOP, 7);

    if estop_on_disk {
        kprintln!("[ENVSMOKE] ESTOP DURABLE: the record was on disk before any \
                   watchdog cycle");
    } else {
        kprintln!("[ENVSMOKE] ESTOP NOT DURABLE: the record was still in RAM — a \
                   reset here would erase it");
    }

    kprintln!("[ENVSMOKE] DONE");
}

/// geofence-smoke: prove the on-board geofence (E03) acts on the kernel's own
/// GPS fix, both ways, through the snapshot the behavior loop takes.
///
/// Sequence, all observed on the console:
///   1. wait for `sensor-ahrs` to carry the simulated fix onto `SENSOR_BUS`
///   2. arm a 100 m fence centred on it — expect `[GEOFENCE] inside: Inside`
///   3. feed the GPS driver a checksummed GGA sentence ~1 km north, quality 1
///      with 4 satellites (the weakest fix the fence trusts), through
///      `gps_feed_byte`, and wait for it to reach the bus — expect
///      `[GEOFENCE] outside: GeofenceViolation`, read from `safety_check`,
///      the function L0 calls
///   4. disarm the fence, so the rest of the boot is not held at zero
///
/// Any other reading prints `[GEOFENCE] FAILED:` with what was read, so a
/// higher-priority L0 verdict masking the fence is told apart from a fix that
/// never reached it.
/// A GGA fix ~1 km north of the simulated one (Munich): 48°08.6460' N
/// (48.1441°), 0.009° north at the same longitude, quality 1 with 4
/// satellites (the weakest fix the fence trusts). `*59` is the XOR of every
/// byte between `$` and `*`. Shared by `geofence-smoke` and wave 15's
/// `fence-refuse-smoke` (`smokes/rc_fence.rs`).
#[cfg(any(feature = "geofence-smoke", feature = "fence-refuse-smoke",
          all(feature = "ktest", feature = "geofence")))]
pub(crate) const OUTSIDE_GGA: &[u8] =
    b"$GPGGA,120000.00,4808.6460,N,01134.9200,E,1,04,1.10,519.0,M,47.0,M,,*59\r\n";
/// [`OUTSIDE_GGA`]'s latitude in the geofence's unit.
#[cfg(any(feature = "geofence-smoke", all(feature = "ktest", feature = "geofence")))]
pub(crate) const OUTSIDE_LAT_UDEG: i32 = 48_144_100;

#[cfg(any(feature = "geofence-smoke", all(feature = "ktest", feature = "geofence")))]
/// The geofence scenario's outcome, for the ktest verdict
/// ([`safety_geofence_breach_latches_estop`]): `[GEOFENCE] FAILED` lines
/// printed, and whether the breach held the e-stop.
static GEOFENCE_FAILS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(any(feature = "geofence-smoke", all(feature = "ktest", feature = "geofence")))]
static GEOFENCE_HELD: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(any(feature = "geofence-smoke", all(feature = "ktest", feature = "geofence")))]
pub(crate) fn geofence_smoke_task(_arg: usize) {
    use azos_behavior::safety::{
        geofence_disable, geofence_set, geofence_status, safety_check,
        GeofenceStatus, SafetyViolation,
    };
    use azos_behavior::sensor_bus::{deg7_to_udeg, SENSOR_BUS};
    use azos_behavior::types::SensorState;

    /// One `sensor-ahrs` GPS publish period.
    const POLL_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 10;
    /// 10 s of polls before giving up.
    const MAX_POLLS: u32 = 100;
    const RADIUS_M: u32 = 100;

    fn poll() -> SensorState {
        let dl = azos_drv_sys::timebase::now() + POLL_TICKS;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
        let mut s = SensorState::new();
        SENSOR_BUS.snapshot(&mut s);
        s
    }

    // 1. The simulated fix, through the bus.
    let mut s = poll();
    let mut polls: u32 = 1;
    while s.gps_fix == 0 && polls < MAX_POLLS { s = poll(); polls += 1; }
    if s.gps_fix == 0 {
        GEOFENCE_FAILS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        kprintln!("[GEOFENCE] FAILED: no GPS fix reached the sensor bus in {} polls", polls);
        return;
    }

    // 2. A fence around the driver's own fix, in the bus's unit.
    let centre = azos_gps::CH_GPS.read().val;
    geofence_set(deg7_to_udeg(centre.lat_deg7), deg7_to_udeg(centre.lon_deg7), RADIUS_M);
    let s = poll();
    let status = geofence_status(&s);
    if status != GeofenceStatus::Inside {
        GEOFENCE_FAILS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        kprintln!("[GEOFENCE] FAILED: at the fence centre read {:?} \
                   (lat_udeg={} lon_udeg={} fix={} sats={})",
                  status, s.gps_lat_udeg, s.gps_lon_udeg, s.gps_fix, s.gps_satellites);
        geofence_disable();
        return;
    }
    kprintln!("[GEOFENCE] inside: {:?}", status);

    // 3. A fix outside it, through the driver's byte feed.
    // Read BEFORE the breach exists. The behaviour task watches this same
    // fence on its own loop and may latch the e-stop between the injection
    // and the read below; `safety_check` then answers RemoteEstop, because
    // L0 outranks the geofence layer -- correct behaviour, and for five gates
    // this probe simply won the race and never saw it. This stamp is what
    // makes "the loop latched THIS breach" different from "something else
    // had already stopped the machine".
    let estop_before = azos_behavior::safety::estop_is_active();

    let mut accepted = false;
    for &b in OUTSIDE_GGA { accepted |= azos_gps::gps_feed_byte(b); }
    if !accepted {
        GEOFENCE_FAILS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        kprintln!("[GEOFENCE] FAILED: the GPS driver rejected the injected GGA sentence");
        geofence_disable();
        return;
    }
    let mut s = poll();
    let mut polls: u32 = 1;
    while s.gps_lat_udeg != OUTSIDE_LAT_UDEG && polls < MAX_POLLS { s = poll(); polls += 1; }
    let status = geofence_status(&s);
    let verdict = safety_check(&s);
    // Either outcome proves the GPS path reached the fence: L0 says
    // GeofenceViolation, or the behaviour loop got there first and L0 now
    // reports the latch it set. The second only counts when the e-stop was
    // CLEAR before the injection and the reading says Outside now -- an
    // e-stop from any other source still fails this probe.
    let loop_latched = !estop_before
        && status == GeofenceStatus::Outside
        && azos_behavior::safety::estop_is_active();
    if verdict.violation == SafetyViolation::GeofenceViolation || loop_latched {
        kprintln!("[GEOFENCE] outside: {:?} (behaviour loop latched first: {})",
                  verdict.violation, loop_latched);
        // The latch, on the same path the behaviour task uses: a breach must
        // hold the machine after the reading stops saying Outside, not only
        // while it says it. When the loop already latched it, this call
        // returns None by design -- the latch is its own guard -- so the
        // overshoot is measured directly instead.
        let latched = azos_behavior::safety::geofence_breach_latch(&s).or_else(|| {
            // Re-read the latch HERE, instead of trusting the `loop_latched`
            // computed above.
            //
            // Gate 77 (2026-09-19) failed on exactly that: the production
            // behaviour loop latched in the window between that computation and
            // this call, so `geofence_breach_latch` correctly returned `None`
            // (the latch is its own guard) while `loop_latched` was a stale
            // `false` — and the probe reported "the breach latched nothing"
            // about a breach the log shows was handled ("motors stopped,
            // envelope latched, 899 m beyond the fence"). The machine was held;
            // only the probe was wrong. Whoever wins the race, what matters is
            // the same: the e-stop was clear before the injection, the reading
            // says Outside, and it is active now.
            let held_now = !estop_before
                && status == GeofenceStatus::Outside
                && azos_behavior::safety::estop_is_active();
            if held_now {
                Some(azos_behavior::safety::geofence_overshoot_m(
                        s.gps_lat_udeg, s.gps_lon_udeg).unwrap_or(0))
            } else {
                None
            }
        });
        match latched {
            Some(overshoot_m) => {
                let held = azos_behavior::safety::estop_is_active();
                GEOFENCE_HELD.store(held, core::sync::atomic::Ordering::SeqCst);
                kprintln!("[GEOFENCE] latched: {} ({} m beyond the fence)", held, overshoot_m);
                if !held {
                    GEOFENCE_FAILS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                    kprintln!("[GEOFENCE] FAILED: the breach did not hold the e-stop");
                }
                // A second pass must not re-record: the latch is the guard.
                if azos_behavior::safety::geofence_breach_latch(&s).is_some() {
                    GEOFENCE_FAILS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                    kprintln!("[GEOFENCE] FAILED: a held latch was recorded twice");
                }
                // Owner decision, 2026-09-25: this probe no longer releases the
                // latch it set, even though it is the one that set it. Only a
                // verified operator authority may clear the latch now (see
                // `safety::ReleaseAuthority`'s module note) — the old comment
                // here ("released only because THIS probe latched it") was
                // exactly the self-release shape the decision closes, just with
                // a kernel-internal caller instead of the brain. `estop_deactivate`
                // is gone (private, `estop_deactivate_unchecked`); the probe has
                // no proof to construct one, and does not get a bypass. The gate
                // row only reads the `[GEOFENCE] latched: true` line above, which
                // is unaffected — nothing after this point in the boot depends on
                // the latch being clear.
            }
            None => { GEOFENCE_FAILS.fetch_add(1, core::sync::atomic::Ordering::SeqCst); kprintln!("[GEOFENCE] FAILED: the breach latched nothing") }
        }
    } else {
        GEOFENCE_FAILS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        kprintln!("[GEOFENCE] FAILED: injected fix read as {:?}, L0 saw {:?} \
                   (lat_udeg={} lon_udeg={} fix={} sats={})",
                  status, verdict.violation, s.gps_lat_udeg, s.gps_lon_udeg,
                  s.gps_fix, s.gps_satellites);
    }

    // 4. Disarm.
    geofence_disable();
    kprintln!("[GEOFENCE] DONE");
}

// L0 sees the GPS: a fence armed around the simulated fix reads Inside; a
// checksummed GGA sentence ~1 km outside it, fed through the driver's byte
// feed, is a GeofenceViolation (or the behaviour loop latched it first), the
// breach latches the e-stop exactly once and the e-stop holds (the row
// `safety: geofence sees GPS`, `[GEOFENCE] latched: true`; the latch, not
// the verdict, since a breach stops the motors). It leaves the e-stop latched for the rest of the boot:
// the tests after it in name order (`sensors_*`, `sync_*`, `tlb_*`) do not
// read it.
#[cfg(feature = "ktest")]
azos_ktest::ktest_late! {
    #[cfg(feature = "geofence")]
    fn safety_geofence_breach_latches_estop() {
        crate::ktest::probe("geofence-smoke", geofence_smoke_task, 0, azos_sched::DEFAULT_PRIORITY, -1)?;
        if GEOFENCE_FAILS.load(core::sync::atomic::Ordering::SeqCst) != 0 {
            Err("the scenario printed [GEOFENCE] FAILED")
        } else if !GEOFENCE_HELD.load(core::sync::atomic::Ordering::SeqCst) {
            Err("the breach did not latch and hold the e-stop")
        } else {
            Ok(())
        }
    }
}

/// Read `SAFETY_UNKNOWN_PKT` back off the flight recorder.
///
/// **What was missing.** `fake_brain.py` sends a fourth frame carrying a
/// packet type this build does not act on, and the dispatch's `else` arm
/// records `SAFETY_UNKNOWN_PKT` instead of dropping it in silence. The gate
/// exercised that arm — the frame is sent on every run — but asserted nothing
/// about the RECORD, because `log_safety_violation` writes the flight recorder
/// and not the console. `ci_check.sh` said so in a comment and named the fix:
/// a kernel-side smoke feature, the way `envelope-smoke` does it.
///
/// **Polls rather than sleeps.** The record depends on a peer over TCP: the
/// robot must dial out, the frames arrive 0.5 s apart, and the fourth is the
/// one that matters. A fixed wait would either be too short on a loaded host
/// or waste the scenario's budget on every green run. So this flushes and
/// scans on a cadence until it finds the record or runs out of attempts, and
/// says which.
///
/// The action byte is matched too, not just the violation code: the record
/// carries the packet type there (`0x7F`, `PKT_UNKNOWN_PROBE` in
/// `tools/fake_brain.py`), so a match on the code alone would pass on a
/// record about some other frame.
#[cfg(feature = "brain-lies-smoke")]
pub(crate) fn brain_lies_smoke_task(_arg: usize) {
    /// `PKT_UNKNOWN_PROBE` in `tools/fake_brain.py`. Deliberately not a type
    /// the kernel handles — if a future build starts acting on 0x7F this
    /// scenario must fail rather than quietly test nothing, and it will,
    /// because the record would stop being written.
    const UNKNOWN_PKT_TYPE: u8 = 0x7F;
    /// One flush-and-scan every half second for 60 s of wall time, measured on
    /// the CLINT rather than in yields: how long a yield takes depends on what
    /// else shares the hart. The scenario stops waiting at the verdict line.
    const ATTEMPTS: u32 = 120;
    const INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 2;

    for attempt in 0..ATTEMPTS {
        let dl = azos_drv_sys::timebase::now() + INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));

        // Safety events are rare and the ring only spills when half full, so
        // without this the record can sit in RAM for the whole scenario.
        let _ = azos_behavior::logger::logger_flush();

        let (found, records) = find_safety_record_on_disk(
            azos_behavior::logger::SAFETY_UNKNOWN_PKT, UNKNOWN_PKT_TYPE);
        if found {
            kprintln!("[BRAINSMOKE] RECORDED: unknown packet type {:#04x} is in \
                       the persistent log after {} attempt(s), {} records",
                      UNKNOWN_PKT_TYPE, attempt + 1, records);
            return;
        }
    }

    let (_, records) = find_safety_record_on_disk(
        azos_behavior::logger::SAFETY_UNKNOWN_PKT, UNKNOWN_PKT_TYPE);
    kprintln!("[BRAINSMOKE] NOT RECORDED: {} records on disk, none is an \
               unknown-packet event for type {:#04x}", records, UNKNOWN_PKT_TYPE);
}

/// cap-deny-smoke: prove a capability refusal is RECORDED, not only refused.
///
/// `captest` hands `gpio_read_typed` the null handle on purpose, and its
/// scenario asserts the errno. The errno proves the kernel refused; the
/// thesis also requires a record, and nothing ever read that record back —
/// `SAFETY_CAP_DENIED_TYPED` was wired and host-tested and never observed on
/// a disk. This polls the flight recorder for exactly that record: code
/// `SAFETY_CAP_DENIED_TYPED`, action `CapKind::Gpio.denial_code()`; and for the
/// untyped one: code `SAFETY_CAP_DENIED`, action `CapKind::Adc.denial_code()`.
///
/// Polls rather than waiting on a marker: the kernel cannot see ring 3's
/// console verdict, and the refusal lands whenever the autorun reaches it.
#[cfg(feature = "cap-deny-smoke")]
pub(crate) fn cap_deny_smoke_task(_arg: usize) {
    /// One disk read every half second for 60 s of wall time, measured on the
    /// CLINT rather than in yields: how long a yield takes depends on what else
    /// shares the hart, and a slow ELF load must not run the probe out of time.
    /// The scenario waits 120 s for the verdict.
    const ATTEMPTS: u32 = 120;
    const INTERVAL: u64 = azos_drv_sys::timebase::TIMER_FREQ / 2;
    // Both records come from the same `captest` run. The untyped one is
    // `adc_read(0) [ungranted]`, refused by `cap_check`, which writes
    // `SAFETY_CAP_DENIED` under the ADC kind: `CapKind::Adc` has no minter and
    // no topology name, so no ring-3 table can hold it and the probe cannot
    // turn into a grant when a topology changes. (It was `gpio_read(0)` until
    // the untyped check moved onto the capability table, where autorun holds
    // `gpio.0` under `cap-refusal-canary`.) The typed one is
    // `gpio_read_typed(0) [forged cap]`, which writes `SAFETY_CAP_DENIED_TYPED`
    // under the GPIO kind. The untyped verdict prints first because the
    // scenario stops waiting at the typed one.
    let adc = azos_abi::cap::CapKind::Adc.denial_code();
    let gpio = azos_abi::cap::CapKind::Gpio.denial_code();
    let untyped = azos_behavior::logger::SAFETY_CAP_DENIED;
    let typed = azos_behavior::logger::SAFETY_CAP_DENIED_TYPED;

    let mut attempts = 0u32;
    let (mut got_untyped, mut got_typed, mut records) = (false, false, 0u32);
    while attempts < ATTEMPTS && !(got_untyped && got_typed) {
        attempts += 1;
        let dl = azos_drv_sys::timebase::now() + INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));

        // Safety events are rare and the ring only spills when half full.
        let _ = azos_behavior::logger::logger_flush();

        let (u, n) = find_safety_record_on_disk(untyped, adc);
        let (t, _) = find_safety_record_on_disk(typed, gpio);
        got_untyped |= u;
        got_typed |= t;
        records = n;
    }

    if got_untyped {
        kprintln!("[CAPDENYSMOKE] UNTYPED RECORDED: an untyped ADC capability refusal \
                   is in the persistent log, {} records", records);
    } else {
        kprintln!("[CAPDENYSMOKE] UNTYPED NOT RECORDED: {} records on disk, none is an \
                   untyped ADC capability refusal", records);
    }
    if got_typed {
        kprintln!("[CAPDENYSMOKE] RECORDED: a typed GPIO capability refusal is in \
                   the persistent log after {} attempt(s), {} records", attempts, records);
    } else {
        kprintln!("[CAPDENYSMOKE] NOT RECORDED: {} records on disk, none is a typed \
                   GPIO capability refusal", records);
    }
}
