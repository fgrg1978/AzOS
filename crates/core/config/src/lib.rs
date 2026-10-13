// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
//! Persistent key-value configuration store — Phase 18 + G2.
//!
//! Parses and serialises simple `KEY=VALUE` settings.
//!
//! ## Runtime atomics
//!
//! `cfg_apply()` transfers parsed values into `AtomicBool` / `AtomicU32`
//! globals that can be read safely from concurrent tasks without locking.
//!
//! # File format
//!
//! ```text
//! # AzOS Configuration
//! ml_enabled=1
//! sched_hz=100
//! watchdog_ms=500
//! motor_max_speed=100
//! ```
//!
//! Lines starting with `#` and blank lines are ignored.
//! Keys and values are byte strings; leading/trailing spaces are stripped.
//!
//! # Limits
//!
//! The numbers live on the constants; repeating them here is how this block
//! came to claim a `MAX_VAL` of 16 for two years after it became 48.
//!
//! - Up to [`MAX_ENTRIES`] entries — anything past that is dropped and
//!   counted ([`cfg_dropped_count`]).
//! - Keys  ≤ [`MAX_KEY`] bytes.
//! - Values ≤ [`MAX_VAL`] bytes — longer ones are cut and counted
//!   ([`cfg_truncated_count`]).
//!
//! A key that appears on two lines is an error: [`cfg_load`] refuses the whole
//! file with [`CfgError::DuplicateKey`] and leaves the running configuration
//! untouched.
//!
//! # Thread safety
//!
//! `cfg_load` is called once during single-threaded boot (before tasks start).
//! `cfg_get` / `cfg_set` are only used from the shell task (single writer).
//! Consumers that need safe concurrent access should copy values into an
//! `AtomicBool` / `AtomicU32` after `cfg_load` (see `ML_ENABLED` etc.).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// W2-B5: authority-checked load — the caller verifies `CONFIG.SIG`
// (crypto stays out of this crate, see `signed.rs`'s module doc) and
// passes the verdict to `signed::cfg_load_verified`.
mod signed;
pub use signed::{
    cfg_load_verified, config_after_rejected, config_authority_decision, AuthorityLoss, ConfigDecision,
    ConfigSigCheck, ConfigTrust, DeviceFloor, ESTOP_GPIO_PIN_FAIL_CLOSED,
};

// ── Runtime atomics (Phase 18 + G2) ──────────────────────────────────────────

/// Runtime flag — true if the ML deliberative pipeline is enabled.
pub static ML_ENABLED: AtomicBool = AtomicBool::new(true);

/// Runtime: behavior VLA server IP packed as `(a<<24)|(b<<16)|(c<<8)|d`.
pub static BEHAVIOR_SERVER_IP: AtomicU32 = AtomicU32::new(0);

/// Runtime: behavior VLA server port (default 0 = disabled).
pub static BEHAVIOR_SERVER_PORT: AtomicU32 = AtomicU32::new(0);

/// Runtime: the brain's camera connection port (C1). Default 0: no camera
/// connection, and camera frames stay on the control connection.
pub static BEHAVIOR_CAMERA_PORT: AtomicU32 = AtomicU32::new(0);

/// Runtime: behavior layer 1 (avoid-obstacle) enabled.
pub static BEHAVIOR_L1_ENABLED: AtomicBool = AtomicBool::new(true);

/// Runtime: behavior layer 2 (remote-vla) enabled.
pub static BEHAVIOR_L2_ENABLED: AtomicBool = AtomicBool::new(true);

/// Runtime: behavior layer 3 (explore) enabled.
pub static BEHAVIOR_L3_ENABLED: AtomicBool = AtomicBool::new(true);

/// Runtime: RFC-0019 forward-secret link enabled.  When set, behavior_task
/// runs a Noise_XXpsk0 handshake immediately after TCP `Established` and
/// wraps every subsequent frame in the X25519+AES-CTR+HMAC AEAD layer
/// from `domains/robot/behavior::encrypt_link`.  Both sides MUST agree on this
/// flag — kernel and brain.  See RFC-0019 § "Opt-in flags".
///
/// CONFIG.INI key: `link_encrypt=0` to disable.  **Default ON since
/// 2026-08-23 (user decision, closing the HMAC-only+reboot wedge):**
/// with a LINK.KEY provisioned the link always runs AEAD — which also makes
/// the brain's per-connection Receiver reset apply, so a kernel reboot no
/// longer wedges the link as replay. Without a key the brain connection is
/// closed rather than downgraded (fail-closed, same K-C5 posture; smoke
/// scenarios without a brain listener are unaffected).
///
/// This is the RUNTIME default and CONFIG.INI can still turn it off — the
/// FAT volume is USB-exposed, so this knob is deliberately not a security
/// boundary. The non-overridable version is the `link-encrypt-enforced`
/// build feature, whose gate ORs over this flag and ignores the INI.
pub static CFG_LINK_ENCRYPT: AtomicBool = AtomicBool::new(true);

/// Runtime: RFC-0021 multi-stream link framing enabled.  When set, every
/// brain↔kernel frame is prefixed with a 1-byte stream-id + 2-byte length
/// (`crates/net/multi-stream`), the OUTERMOST wire layer — control traffic rides
/// `STREAM_CONTROL`, camera/lidar get their own stream-ids.  Composes outside
/// the RFC-0019 AEAD layer.  Both sides MUST agree.
///
/// CONFIG.INI key: `multi_stream=1`.  Default off.
pub static CFG_MULTI_STREAM: AtomicBool = AtomicBool::new(false);

/// Runtime: run the synthetic microbench suite ONCE during early boot, then
/// halt.  The early-boot window (after subsystem init, before the scheduler
/// + secondary harts start and before the timer ISR is enabled) is a
/// quiescent single-active-hart context — no cross-hart `rdcycle` contention
/// and no timer preemption — giving the cleanest possible measurement under
/// QEMU TCG (the SMP behavior-task path is too noisy; `-smp 1` full boot
/// hangs at flight init).  For determinism this is best paired with QEMU
/// `-icount`.  Used to capture `bench_synth` baselines; NOT for normal boots.
///
/// CONFIG.INI key: `bench_boot=1`.  Default off.
pub static CFG_BENCH_BOOT: AtomicBool = AtomicBool::new(false);

/// Runtime: PID proportional gain (×1000 fixed-point: 1000 = 1.0).
pub static CFG_PID_KP: AtomicU32 = AtomicU32::new(1);

/// Runtime: PID integral gain.
pub static CFG_PID_KI: AtomicU32 = AtomicU32::new(0);

/// Runtime: PID derivative gain.
pub static CFG_PID_KD: AtomicU32 = AtomicU32::new(0);

/// Runtime: encoder ticks per metre.
pub static CFG_TICKS_PER_M: AtomicU32 = AtomicU32::new(1000);

/// Runtime: wheel base in millimetres.
pub static CFG_WHEEL_BASE_MM: AtomicU32 = AtomicU32::new(200);

/// Runtime: network IP packed as `(a<<24)|(b<<16)|(c<<8)|d`.
pub static CFG_NET_IP: AtomicU32 = AtomicU32::new(0x0A00_020F); // 10.0.2.15

/// Runtime: network gateway packed.
pub static CFG_NET_GATEWAY: AtomicU32 = AtomicU32::new(0x0A00_0202); // 10.0.2.2

/// Runtime: network mask packed.
pub static CFG_NET_MASK: AtomicU32 = AtomicU32::new(0xFFFF_FF00); // 255.255.255.0

/// Runtime: DHCP enabled (1 = auto-discover IP at boot, 0 = use static config).
pub static CFG_NET_DHCP: AtomicU32 = AtomicU32::new(0);

/// Runtime: IMU calibration offset — accel X (signed, milli-g units).
pub static CFG_IMU_OFFSET_AX: AtomicU32 = AtomicU32::new(0);

/// Runtime: IMU calibration offset — accel Y.
pub static CFG_IMU_OFFSET_AY: AtomicU32 = AtomicU32::new(0);

/// Runtime: IMU calibration offset — accel Z.
pub static CFG_IMU_OFFSET_AZ: AtomicU32 = AtomicU32::new(0);

/// Runtime: hardware watchdog timeout in milliseconds.
pub static CFG_WATCHDOG_MS: AtomicU32 = AtomicU32::new(500);

/// Runtime: motor max speed (0-100).
pub static CFG_MOTOR_MAX_SPEED: AtomicU32 = AtomicU32::new(100);

/// Runtime: auto-reboot delay after panic (ms). 0 = disabled (infinite WFI).
pub static CFG_PANIC_REBOOT_DELAY_MS: AtomicU32 = AtomicU32::new(0);

/// Runtime: GPIO pin for hardware kill-switch (255 = disabled).
pub static CFG_ESTOP_GPIO_PIN: AtomicU32 = AtomicU32::new(255);

/// Runtime: if non-zero, kernel spawns an OTA listener on this port at boot
/// (without needing a shell command).  0 = disabled.
pub static CFG_OTA_AUTO_RECV_PORT: AtomicU32 = AtomicU32::new(0);

// ── Q4.2: sched_hz clamp (owner decision, 2026-09-25) ────────────────────────
//
// Two sources fed the scheduler tick: Kconfig `SCHED_HZ` (`config/Kconfig.timing`,
// the compile-time default for this board/profile) and CONFIG.INI's
// `sched_hz` key on the removable FAT volume, which used to override it
// outright (`kernel/src/main.rs`, `if cfg_hz >= 10 { sched_hz_set(...) }` —
// no upper bound at all). Removable media must not be able to RAISE the
// tick above what was compiled in for this board. Decision: CONFIG.INI may
// only LOWER `SCHED_HZ`, within `[SCHED_HZ_FLOOR, SCHED_HZ]`.
//
// `SCHED_HZ_FLOOR` is a single constant (`config/Kconfig.timing`) rather than a
// paired MIN/MAX: the ceiling is already `SCHED_HZ` itself (board/profile
// dependent — 100/250/500 across defconfigs), so a separate MAX would just
// be a second number required to stay in lockstep with the first. Only the
// floor needs to exist independently.

/// Outcome of resolving a CONFIG.INI `sched_hz` request against the
/// Kconfig compile-time default and floor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SchedHzResolution {
    /// The value actually applied to the scheduler.
    pub effective: u32,
    /// The raw value `cfg_get_u32(b"sched_hz", compile_default)` returned
    /// (a non-numeric or absent key already resolves to `compile_default`
    /// there, before this function ever sees it).
    pub requested: u32,
    /// True if `effective != requested` — the boot log line uses this to
    /// decide whether to say anything beyond the plain `sched_hz=N`.
    pub clamped: bool,
}

/// Resolve a requested scheduler tick rate against the Kconfig compile-time
/// ceiling (`compile_default`, i.e. `azos_limits::SCHED_HZ`) and floor
/// (`floor`, i.e. `azos_limits::SCHED_HZ_FLOOR`).
///
/// Three buckets, matching the Q4.2 decision:
/// - `requested > compile_default`: CONFIG.INI is trying to RAISE the tick.
///   Refused — clamped down to `compile_default`.
/// - `requested < floor`: not a deliberate slow-tick request (0, or a typo
///   like `sched_hz=3`) — treated as garbage and rejected back to
///   `compile_default`, the same way the caller already had to fall back
///   for a non-numeric value.
/// - otherwise: within `[floor, compile_default]` — accepted unchanged,
///   which is the whole point of letting CONFIG.INI lower the tick.
///
/// Pure function — no atomics, no lock — so the kernel boot path and the
/// host-side tests in `tests/host/config-tests` exercise identical logic.
pub fn resolve_sched_hz(requested: u32, compile_default: u32, floor: u32) -> SchedHzResolution {
    let effective = if requested > compile_default || requested < floor {
        compile_default
    } else {
        requested
    };
    SchedHzResolution {
        effective,
        requested,
        clamped: effective != requested,
    }
}

/// Unpack an IP from packed u32 to `[u8; 4]`.
pub fn unpack_ip(packed: u32) -> [u8; 4] {
    [
        (packed >> 24) as u8,
        (packed >> 16) as u8,
        (packed >>  8) as u8,
        packed as u8,
    ]
}

/// Unpack server IP from packed u32 to `[u8; 4]`.
pub fn behavior_server_ip_bytes() -> [u8; 4] {
    unpack_ip(BEHAVIOR_SERVER_IP.load(Ordering::Relaxed))
}

/// Apply loaded configuration to runtime atomic values.
///
/// Call once after `cfg_load`, still in single-threaded boot.
/// Subsequent calls (e.g. after `config load` in the shell) are safe because
/// `AtomicBool::store` with `Release` ordering is visible to any `Acquire` load.
pub fn cfg_apply() {
    ML_ENABLED.store(cfg_get_u32(b"ml_enabled", 1) != 0, Ordering::Release);
    BEHAVIOR_SERVER_PORT.store(cfg_get_u32(b"behavior_server_port", 0), Ordering::Release);
    BEHAVIOR_CAMERA_PORT.store(cfg_get_u32(b"behavior_camera_port", 0), Ordering::Release);

    // Parse behavior_server_ip as dotted-decimal → packed u32.
    if let Some(ip_val) = cfg_get(b"behavior_server_ip") {
        if let Some(packed) = parse_ip_packed(ip_val) {
            BEHAVIOR_SERVER_IP.store(packed, Ordering::Release);
        }
    }

    // Phase G2: behavior layers
    BEHAVIOR_L1_ENABLED.store(cfg_get_u32(b"behavior_l1_enabled", 1) != 0, Ordering::Release);
    BEHAVIOR_L2_ENABLED.store(cfg_get_u32(b"behavior_l2_enabled", 1) != 0, Ordering::Release);
    BEHAVIOR_L3_ENABLED.store(cfg_get_u32(b"behavior_l3_enabled", 1) != 0, Ordering::Release);
    // RFC-0019 opt-in.  Off by default; both sides must set this together.
    // Default 1 (see CFG_LINK_ENCRYPT): an INI without the key keeps AEAD
    // on; only an explicit `link_encrypt=0` turns it off.
    CFG_LINK_ENCRYPT.store(cfg_get_u32(b"link_encrypt", 1) != 0, Ordering::Release);
    // RFC-0021 opt-in.  Off by default; both sides must set this together.
    CFG_MULTI_STREAM.store(cfg_get_u32(b"multi_stream", 0) != 0, Ordering::Release);
    // Early-boot synthetic bench capture.  Off by default.
    CFG_BENCH_BOOT.store(cfg_get_u32(b"bench_boot", 0) != 0, Ordering::Release);

    // PID tuning
    CFG_PID_KP.store(cfg_get_u32(b"pid_kp", 1), Ordering::Release);
    CFG_PID_KI.store(cfg_get_u32(b"pid_ki", 0), Ordering::Release);
    CFG_PID_KD.store(cfg_get_u32(b"pid_kd", 0), Ordering::Release);

    // Robot physical
    CFG_TICKS_PER_M.store(cfg_get_u32(b"ticks_per_m", 1000), Ordering::Release);
    CFG_WHEEL_BASE_MM.store(cfg_get_u32(b"wheel_base_mm", 200), Ordering::Release);

    // Network
    if let Some(v) = cfg_get(b"net_ip") {
        if let Some(p) = parse_ip_packed(v) { CFG_NET_IP.store(p, Ordering::Release); }
    }
    if let Some(v) = cfg_get(b"net_gateway") {
        if let Some(p) = parse_ip_packed(v) { CFG_NET_GATEWAY.store(p, Ordering::Release); }
    }
    if let Some(v) = cfg_get(b"net_mask") {
        if let Some(p) = parse_ip_packed(v) { CFG_NET_MASK.store(p, Ordering::Release); }
    }
    CFG_NET_DHCP.store(cfg_get_u32(b"dhcp", 0), Ordering::Release);

    // IMU calibration (signed offsets stored as u32 bit-patterns)
    CFG_IMU_OFFSET_AX.store(cfg_get_i32(b"imu_offset_ax", 0) as u32, Ordering::Release);
    CFG_IMU_OFFSET_AY.store(cfg_get_i32(b"imu_offset_ay", 0) as u32, Ordering::Release);
    CFG_IMU_OFFSET_AZ.store(cfg_get_i32(b"imu_offset_az", 0) as u32, Ordering::Release);

    // Watchdog + motor
    CFG_WATCHDOG_MS.store(cfg_get_u32(b"watchdog_ms", 500), Ordering::Release);
    CFG_MOTOR_MAX_SPEED.store(cfg_get_u32(b"motor_max_speed", 100), Ordering::Release);

    // Panic + safety
    CFG_PANIC_REBOOT_DELAY_MS.store(cfg_get_u32(b"panic_reboot_ms", 0), Ordering::Release);
    CFG_ESTOP_GPIO_PIN.store(cfg_get_u32(b"estop_gpio_pin", 255), Ordering::Release);

    // OTA auto-recv (0 = disabled)
    CFG_OTA_AUTO_RECV_PORT.store(cfg_get_u32(b"ota_auto_recv_port", 0), Ordering::Release);
}

/// Parse "a.b.c.d" into packed u32 `(a<<24)|(b<<16)|(c<<8)|d`.
fn parse_ip_packed(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut octet  = 0u32;
    let mut idx    = 0usize;
    let mut any    = false;

    for &b in s {
        if b >= b'0' && b <= b'9' {
            octet = octet.saturating_mul(10).saturating_add((b - b'0') as u32);
            if octet > 255 { return None; }
            any = true;
        } else if b == b'.' {
            if !any || idx >= 3 || octet > 255 { return None; }
            octets[idx] = octet as u8;
            idx += 1;
            octet = 0;
            any = false;
        } else {
            break;
        }
    }
    if any && idx == 3 && octet <= 255 {
        octets[3] = octet as u8;
        Some((octets[0] as u32) << 24
           | (octets[1] as u32) << 16
           | (octets[2] as u32) << 8
           |  octets[3] as u32)
    } else {
        None
    }
}

/// Maximum number of configuration entries stored.
pub const MAX_ENTRIES: usize = 32;
/// Maximum key length in bytes.
pub const MAX_KEY: usize = 24;
/// Maximum value length in bytes.
///
/// Was 16 until 2026-08-20, which is exactly the length of
/// `/fat/GPIODRV.ELF` and `/fat/SYSTEST.ELF` — the two autorun paths in use.
/// They fit by one byte of luck; `/fat/BRAINCLI.ELF` (17) did not, and the
/// parser silently cut it to `/fat/BRAINCLI.EL`, so the failure surfaced far
/// from its cause as "[AUTORUN] File not found". 48 leaves real headroom for
/// paths, and truncation is now counted rather than silent — see
/// [`cfg_truncated_count`].
pub const MAX_VAL: usize = 48;

#[derive(Copy, Clone)]
struct Entry {
    key:     [u8; MAX_KEY],
    val:     [u8; MAX_VAL],
    key_len: u8,
    val_len: u8,
    used:    bool,
}

impl Entry {
    const fn new() -> Self {
        Entry {
            key:     [0; MAX_KEY],
            val:     [0; MAX_VAL],
            key_len: 0,
            val_len: 0,
            used:    false,
        }
    }
}

static mut ENTRIES: [Entry; MAX_ENTRIES] = [Entry::new(); MAX_ENTRIES];
static mut COUNT:   usize                = 0;

// ── Parser ────────────────────────────────────────────────────────────────────

/// Why [`cfg_load`] refused a file.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CfgError {
    /// The same key appears on two lines. Whichever one wins, the other is a
    /// setting the operator wrote and the machine does not run, so the file is
    /// refused as a whole and nothing is stored. `key` holds the first
    /// `len` bytes of the repeated key (at most [`MAX_KEY`]).
    DuplicateKey { key: [u8; MAX_KEY], len: u8 },
}

impl CfgError {
    /// The repeated key, as it would have been stored.
    pub fn key(&self) -> &[u8] {
        match self {
            CfgError::DuplicateKey { key, len } => &key[..*len as usize],
        }
    }
}

/// Walk the `KEY=VALUE` lines of `data`, in order, calling `f(key, value,
/// raw_value_len)` for each line that has a non-empty key. `key` is cut to
/// [`MAX_KEY`] and `value` to [`MAX_VAL`] exactly as they are stored;
/// `raw_value_len` is the length before the cut. Blank lines, `#` comments and
/// lines without `=` are skipped. One scanner serves the duplicate check and
/// the load, so the two cannot disagree about what a line is.
fn scan_lines<'a, F: FnMut(&'a [u8], &'a [u8], usize)>(data: &'a [u8], mut f: F) {
    let mut i = 0;
    while i < data.len() {
        // Skip blank lines and leading whitespace.
        while i < data.len()
            && (data[i] == b'\r' || data[i] == b'\n'
                || data[i] == b' '  || data[i] == b'\t')
        {
            i += 1;
        }
        if i >= data.len() { break; }

        // Skip comment lines.
        if data[i] == b'#' {
            while i < data.len() && data[i] != b'\n' { i += 1; }
            continue;
        }

        // Scan key up to '=' or end-of-line.
        let key_start = i;
        while i < data.len() && data[i] != b'=' && data[i] != b'\n' { i += 1; }
        if i >= data.len() || data[i] != b'=' { continue; }
        let key_end = rtrim(data, key_start, i);
        i += 1; // skip '='

        // Scan value up to end-of-line.
        let val_start = i;
        while i < data.len() && data[i] != b'\n' && data[i] != b'\r' { i += 1; }
        let val_end = rtrim(data, val_start, i);

        let klen = (key_end - key_start).min(MAX_KEY);
        let vlen = (val_end - val_start).min(MAX_VAL);
        if klen == 0 { continue; }
        f(&data[key_start..key_start + klen],
          &data[val_start..val_start + vlen],
          val_end - val_start);
    }
}

/// The key of the `n`-th `KEY=VALUE` line of `data`, if there is one.
fn nth_key(data: &[u8], n: usize) -> Option<&[u8]> {
    let mut idx = 0usize;
    let mut found = None;
    scan_lines(data, |k, _, _| {
        if idx == n { found = Some(k); }
        idx += 1;
    });
    found
}

/// First key that appears on two lines of `data`, if any. Quadratic in the
/// number of lines, which is bounded by the size of the file CONFIG.INI is
/// read into (1 KiB), and it runs once per load.
fn find_duplicate_key(data: &[u8]) -> Option<&[u8]> {
    let mut n = 0usize;
    while let Some(k) = nth_key(data, n) {
        let mut m = 0usize;
        while m < n {
            if nth_key(data, m) == Some(k) { return Some(k); }
            m += 1;
        }
        n += 1;
    }
    None
}

/// Load configuration from an INI-format byte slice.
///
/// On success it overwrites all previous entries. A key that appears on two
/// lines is an ERROR ([`CfgError::DuplicateKey`]): the file is refused as a
/// whole, and the previous configuration is left exactly as it was, so a
/// caller can neither read a half-loaded store nor mistake one line for the
/// other. (Until wave 11 the first line silently won and the second was
/// ignored.)
///
/// Lines starting with `#` and blank lines are silently ignored.
pub fn cfg_load(data: &[u8]) -> Result<(), CfgError> {
    if let Some(k) = find_duplicate_key(data) {
        let mut key = [0u8; MAX_KEY];
        key[..k.len()].copy_from_slice(k);
        return Err(CfgError::DuplicateKey { key, len: k.len() as u8 });
    }
    // Safety: called once during single-threaded boot.
    unsafe {
        ENTRIES = [Entry::new(); MAX_ENTRIES];
        COUNT   = 0;
    }
    // A load replaces the whole configuration, so both tallies belong to this
    // load and not to whatever was parsed before it.
    TRUNCATED_VALUES.store(0, Ordering::Relaxed);
    DROPPED_ENTRIES.store(0, Ordering::Relaxed);
    scan_lines(data, |key, val, raw_vlen| {
        // A value cut to fit is a configuration the operator did not write.
        // Silently honouring the prefix is worse than either honouring the
        // whole thing or refusing it: the symptom appears somewhere else
        // entirely. Count it so boot can say so out loud.
        if raw_vlen > MAX_VAL {
            TRUNCATED_VALUES.fetch_add(1, Ordering::Relaxed);
        }
        // Safety: single-threaded boot, COUNT < MAX_ENTRIES checked.
        unsafe {
            if COUNT < MAX_ENTRIES {
                let e = &mut ENTRIES[COUNT];
                e.key[..key.len()].copy_from_slice(key);
                e.key_len = key.len() as u8;
                e.val[..val.len()].copy_from_slice(val);
                e.val_len = val.len() as u8;
                e.used    = true;
                COUNT    += 1;
            } else {
                // Past `MAX_ENTRIES` the parser used to drop the line and say
                // nothing, so a 32-line preamble could push a real key out of
                // the running configuration with no symptom at the point of
                // failure — `autorun` missing reads as "no autorun
                // configured", not as "your file did not fit". Counted for
                // the same reason truncation is: boot says so out loud.
                DROPPED_ENTRIES.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    Ok(())
}

// ── Accessors ─────────────────────────────────────────────────────────────────

/// Return the value bytes for `key`, or `None` if the key is not found.
/// Number of `CONFIG.INI` values that were longer than [`MAX_VAL`] and got
/// cut. Non-zero means the running configuration is not the one on disk.
static TRUNCATED_VALUES: AtomicU32 = AtomicU32::new(0);

/// How many values the parser had to truncate. Boot prints a warning when
/// this is non-zero; see `kernel/src/main.rs`.
pub fn cfg_truncated_count() -> u32 {
    TRUNCATED_VALUES.load(Ordering::Relaxed)
}

/// Number of `KEY=VALUE` lines past [`MAX_ENTRIES`] that were dropped. The
/// same meaning as [`cfg_truncated_count`] one level up: non-zero means the
/// running configuration is missing lines that are on disk.
static DROPPED_ENTRIES: AtomicU32 = AtomicU32::new(0);

/// How many entries did not fit. Boot prints a warning when this is non-zero;
/// see `kernel/src/main.rs`.
pub fn cfg_dropped_count() -> u32 {
    DROPPED_ENTRIES.load(Ordering::Relaxed)
}

pub fn cfg_get(key: &[u8]) -> Option<&'static [u8]> {
    unsafe {
        for i in 0..COUNT {
            let e = &ENTRIES[i];
            if e.used && &e.key[..e.key_len as usize] == key {
                return Some(&e.val[..e.val_len as usize]);
            }
        }
    }
    None
}

/// Return value parsed as `u32`, or `default` if the key is absent / not numeric.
pub fn cfg_get_u32(key: &[u8], default: u32) -> u32 {
    match cfg_get(key) {
        None    => default,
        Some(v) => parse_u32(v).unwrap_or(default),
    }
}

/// Return value parsed as `i32`, or `default` if the key is absent / not numeric.
/// Handles leading `-` for negative values.
pub fn cfg_get_i32(key: &[u8], default: i32) -> i32 {
    match cfg_get(key) {
        None    => default,
        Some(v) => parse_i32(v).unwrap_or(default),
    }
}

/// Set (or insert) a key-value pair in memory.
///
/// Returns `false` if the key or value exceeds the maximum length, or the
/// table is already full and the key is new.
pub fn cfg_set(key: &[u8], val: &[u8]) -> bool {
    if key.len() > MAX_KEY || val.len() > MAX_VAL { return false; }
    let klen = key.len();
    let vlen = val.len();
    unsafe {
        // Update existing entry if key already present.
        for i in 0..COUNT {
            let e = &mut ENTRIES[i];
            if e.used && &e.key[..e.key_len as usize] == key {
                e.val = [0; MAX_VAL];
                e.val[..vlen].copy_from_slice(&val[..vlen]);
                e.val_len = vlen as u8;
                return true;
            }
        }
        // Insert new entry.
        if COUNT < MAX_ENTRIES {
            let e = &mut ENTRIES[COUNT];
            e.key[..klen].copy_from_slice(&key[..klen]);
            e.key_len = klen as u8;
            e.val[..vlen].copy_from_slice(&val[..vlen]);
            e.val_len = vlen as u8;
            e.used    = true;
            COUNT    += 1;
            return true;
        }
    }
    false
}

/// Returns the current number of loaded entries.
pub fn cfg_count() -> usize {
    unsafe { COUNT }
}

/// Retrieve entry at index `i` (0 = first). Returns `(key, value)` slices.
/// Returns `None` if `i >= cfg_count()`.
pub fn cfg_iter(i: usize) -> Option<(&'static [u8], &'static [u8])> {
    unsafe {
        if i >= COUNT { return None; }
        let e = &ENTRIES[i];
        if !e.used { return None; }
        Some((&e.key[..e.key_len as usize], &e.val[..e.val_len as usize]))
    }
}

/// Serialise all entries into `buf` as `KEY=VALUE\n` text.
/// Returns the number of bytes written.
pub fn cfg_serialize(buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    unsafe {
        for i in 0..COUNT {
            let e = &ENTRIES[i];
            if !e.used { continue; }
            let kl = e.key_len as usize;
            let vl = e.val_len as usize;
            if pos + kl + 1 + vl + 1 > buf.len() { break; }
            buf[pos..pos + kl].copy_from_slice(&e.key[..kl]); pos += kl;
            buf[pos] = b'=';                                    pos += 1;
            buf[pos..pos + vl].copy_from_slice(&e.val[..vl]); pos += vl;
            buf[pos] = b'\n';                                   pos += 1;
        }
    }
    pos
}

// ── Phase G2: Factory defaults ───────────────────────────────────────────────

/// Populate the config store with factory-default values (22 keys).
///
/// Call when CONFIG.INI is missing (first boot) or on `config defaults`.
/// Overwrites all previous entries.
pub fn cfg_defaults() {
    // Safety: called during single-threaded boot or from shell (single writer).
    unsafe {
        ENTRIES = [Entry::new(); MAX_ENTRIES];
        COUNT   = 0;
    }
    // General
    cfg_set(b"ml_enabled", b"1");
    cfg_set(b"sched_hz", b"100");
    cfg_set(b"watchdog_ms", b"500");
    cfg_set(b"motor_max_speed", b"100");
    // Behavior engine
    cfg_set(b"behavior_server_ip", b"0.0.0.0");
    cfg_set(b"behavior_server_port", b"0");
    cfg_set(b"behavior_camera_port", b"0");
    cfg_set(b"behavior_l1_enabled", b"1");
    cfg_set(b"behavior_l2_enabled", b"1");
    cfg_set(b"behavior_l3_enabled", b"1");
    // PID tuning
    cfg_set(b"pid_kp", b"1");
    cfg_set(b"pid_ki", b"0");
    cfg_set(b"pid_kd", b"0");
    // Robot physical
    cfg_set(b"ticks_per_m", b"1000");
    cfg_set(b"wheel_base_mm", b"200");
    // Network
    cfg_set(b"net_ip", b"10.0.2.15");
    cfg_set(b"net_gateway", b"10.0.2.2");
    cfg_set(b"net_mask", b"255.255.255.0");
    // IMU calibration
    cfg_set(b"imu_offset_ax", b"0");
    cfg_set(b"imu_offset_ay", b"0");
    cfg_set(b"imu_offset_az", b"0");
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn rtrim(data: &[u8], start: usize, end: usize) -> usize {
    let mut e = end;
    while e > start && (data[e - 1] == b' ' || data[e - 1] == b'\t') { e -= 1; }
    e
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    let mut v   = 0u32;
    let mut any = false;
    for &b in s {
        if b < b'0' || b > b'9' { break; }
        v   = v.saturating_mul(10).saturating_add((b - b'0') as u32);
        any = true;
    }
    if any { Some(v) } else { None }
}

fn parse_i32(s: &[u8]) -> Option<i32> {
    if s.is_empty() { return None; }
    let (neg, start) = if s[0] == b'-' { (true, 1) } else { (false, 0) };
    let mut v   = 0i32;
    let mut any = false;
    for &b in &s[start..] {
        if b < b'0' || b > b'9' { break; }
        v   = v.saturating_mul(10).saturating_add((b - b'0') as i32);
        any = true;
    }
    if !any { return None; }
    if neg { Some(-v) } else { Some(v) }
}
