// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E02 — LoRa transport stub.
//!
//! This is a **protocol-level placeholder** that implements the
//! [`crate::multilink::Transport`] trait on top of the existing UART
//! bridge.  On real hardware it will be swapped for a SX1262 (or
//! similar) SPI driver; for now we send/receive raw bytes over
//! `uart_bridge`, which is exactly how the ESP32-C3 WiFi bridge works
//! too.
//!
//! The framing is intentionally identical to the TCP path so the brain
//! does not care whether a packet arrived via WiFi or LoRa.

use super::multilink::{
    Transport, TransportError,
    LINK_QUALITY_DOWN, LINK_QUALITY_UNKNOWN,
};

/// Minimum link-quality reported when the LoRa link is "up".
/// Pure UART has no signal information — we report `UNKNOWN` (mid-scale).
const LORA_STUB_QUALITY: u8 = LINK_QUALITY_UNKNOWN;

/// LoRa transport — UART-bridge based stub.
///
/// Real implementation (future) will own an SX1262 / SX1276 driver;
/// the public trait surface stays the same.
pub struct LoRaTransport {
    /// Statically allocated name for diagnostics.
    name: &'static str,
}

impl LoRaTransport {
    /// Construct a LoRa transport that uses the kernel's `uart_bridge`.
    pub const fn new() -> Self {
        Self { name: "lora" }
    }

    /// Rename the transport (for multi-radio setups).
    pub const fn with_name(name: &'static str) -> Self {
        Self { name }
    }
}

impl Default for LoRaTransport {
    fn default() -> Self { Self::new() }
}

impl Transport for LoRaTransport {
    fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        if !azos_drv_bus::uart_bridge::bridge_is_ready() {
            return Err(TransportError::NotReady);
        }
        let sent = azos_drv_bus::uart_bridge::bridge_send(data);
        if sent < 0 {
            Err(TransportError::Io)
        } else {
            Ok(sent as usize)
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        if !azos_drv_bus::uart_bridge::bridge_is_ready() {
            return Err(TransportError::NotReady);
        }
        let n = azos_drv_bus::uart_bridge::bridge_recv(buf);
        if n > 0 {
            Ok(n as usize)
        } else {
            Err(TransportError::WouldBlock)
        }
    }

    fn is_up(&self) -> bool {
        azos_drv_bus::uart_bridge::bridge_is_ready()
    }

    fn link_quality(&self) -> u8 {
        if self.is_up() { LORA_STUB_QUALITY } else { LINK_QUALITY_DOWN }
    }

    fn name(&self) -> &'static str { self.name }
}
