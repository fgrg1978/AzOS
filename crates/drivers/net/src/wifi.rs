// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// WiFi driver (Phase O1+O2) — API surface only.
///
/// No supported platform (QEMU / VF2 / K1) has a WiFi peripheral, so every
/// entry point here is a no-op stub and the link to the ground station runs
/// over wired Ethernet instead.  The module is kept so callers (syscalls,
/// telemetry) can compile against a stable WiFi API.
///
/// # Architecture
///
/// ```text
/// Board                            Server
/// ┌────────────┐    Ethernet     ┌─────────────┐
/// │ Flight ctrl│ ──────────────> │ Ground Stn  │
/// │ AHRS       │ <────────────── │ Perception  │
/// │ Safety     │                 │ SLAM        │
/// └────────────┘                 └─────────────┘
/// ```

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

// ── WiFi state ───────────────────────────────────────────────────────────────

/// WiFi connection status.
#[derive(Clone, Copy, PartialEq)]
pub enum WifiState {
    /// Not initialized.
    Off,
    /// Scanning / connecting.
    Connecting,
    /// Connected to AP, IP assigned.
    Connected,
    /// Connection lost.
    Disconnected,
}

static WIFI_STATE: AtomicU8 = AtomicU8::new(0); // 0=Off, 1=Connecting, 2=Connected, 3=Disconnected
static WIFI_READY: AtomicBool = AtomicBool::new(false);
#[allow(dead_code)]
static WIFI_TX_PACKETS: AtomicU32 = AtomicU32::new(0);
#[allow(dead_code)]
static WIFI_RX_PACKETS: AtomicU32 = AtomicU32::new(0);

// SSID stored as fixed bytes (max 32).
#[allow(dead_code)]
static mut WIFI_SSID: [u8; 32] = [0u8; 32];
#[allow(dead_code)]
static mut WIFI_SSID_LEN: u8 = 0;

fn state_to_u8(s: WifiState) -> u8 {
    match s {
        WifiState::Off => 0,
        WifiState::Connecting => 1,
        WifiState::Connected => 2,
        WifiState::Disconnected => 3,
    }
}

fn u8_to_state(v: u8) -> WifiState {
    match v {
        1 => WifiState::Connecting,
        2 => WifiState::Connected,
        3 => WifiState::Disconnected,
        _ => WifiState::Off,
    }
}

// ── Init ─────────────────────────────────────────────────────────────────────

/// Initialize WiFi subsystem.
///
/// No-op: no WiFi hardware on the supported platforms (uses Ethernet instead).
pub fn wifi_init() {
    // No WiFi peripheral — use Ethernet.
}

/// Connect to a WiFi access point.
///
/// `ssid`: network name (max 32 bytes).
/// `pass`: password (max 64 bytes).
///
/// No-op: no WiFi hardware on the supported platforms.
pub fn wifi_connect(ssid: &[u8], _pass: &[u8]) {
    let _ = ssid;
}

/// Disconnect from WiFi.
pub fn wifi_disconnect() {
    WIFI_STATE.store(state_to_u8(WifiState::Disconnected), Ordering::Release);
    WIFI_READY.store(false, Ordering::Release);
}

/// Get current WiFi state.
pub fn wifi_state() -> WifiState {
    u8_to_state(WIFI_STATE.load(Ordering::Acquire))
}

/// Check if WiFi is connected and ready.
pub fn wifi_is_ready() -> bool {
    WIFI_READY.load(Ordering::Acquire)
}

// ── Send / Receive (UDP) ─────────────────────────────────────────────────────

/// Send a UDP packet over WiFi.
///
/// No-op: no WiFi hardware on the supported platforms (always returns 0).
pub fn wifi_send_udp(ip: &[u8; 4], port: u16, data: &[u8]) -> usize {
    if !WIFI_READY.load(Ordering::Acquire) { return 0; }

    let _ = (ip, port, data);
    0
}

/// Receive a UDP packet over WiFi.
///
/// Returns number of bytes received, or 0 if nothing available.
pub fn wifi_recv_udp(buf: &mut [u8]) -> usize {
    if !WIFI_READY.load(Ordering::Acquire) { return 0; }

    let _ = buf;
    0
}

// ── Info ─────────────────────────────────────────────────────────────────────

/// Print WiFi status.
pub fn wifi_info() {
    let state = wifi_state();
    let state_name = match state {
        WifiState::Off => "OFF",
        WifiState::Connecting => "CONNECTING",
        WifiState::Connected => "CONNECTED",
        WifiState::Disconnected => "DISCONNECTED",
    };
    azos_drv_sys::kconsoleln!("[WIFI] State: {}", state_name);
    azos_drv_sys::kconsoleln!("[WIFI] Not available (use Ethernet)");
}
