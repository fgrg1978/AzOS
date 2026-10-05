// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E02 — RF transport stub.
//!
//! Placeholder for a future 900 MHz point-to-point RF modem (e.g.
//! RFM69, RFM95, or a custom FSK transceiver).  Interface-compatible
//! with [`crate::multilink::Transport`] so the [`MultiLinkTransport`]
//! multiplexer can treat it as the "emergency" fallback link.
//!
//! Until we have real RF hardware this stub always reports the link as
//! down; adding it to the multiplexer is therefore a no-op except it
//! lets user code ship a consistent topology.

use super::multilink::{
    Transport, TransportError, LINK_QUALITY_DOWN, LINK_QUALITY_UNKNOWN,
};

/// Maximum RF payload per frame — 900 MHz modems are typically
/// limited to ~64 bytes per packet.  Kept here so the mux can fragment
/// if needed in the future.
pub const RF_MAX_PAYLOAD: usize = 64;

/// Quality value reported when the stub is "armed" (future real
/// implementation will return RSSI-derived 0..=255).
const RF_STUB_QUALITY: u8 = LINK_QUALITY_UNKNOWN;

/// RF transport — always down until hardware support lands.
pub struct RfTransport {
    name:   &'static str,
    /// `true` once real hardware is wired up; stub keeps it `false`.
    armed:  bool,
}

impl RfTransport {
    /// Construct the RF stub (armed=false until hardware is ready).
    pub const fn new() -> Self {
        Self { name: "rf", armed: false }
    }

    /// Force-arm the transport (for mocking / integration tests).
    pub fn set_armed(&mut self, armed: bool) {
        self.armed = armed;
    }
}

impl Default for RfTransport {
    fn default() -> Self { Self::new() }
}

impl Transport for RfTransport {
    fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        if !self.armed {
            return Err(TransportError::NotReady);
        }
        if data.len() > RF_MAX_PAYLOAD {
            return Err(TransportError::BufTooSmall);
        }
        // Future: hand `data` to SPI driver.  For now just drop it.
        Ok(data.len())
    }

    fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, TransportError> {
        if !self.armed {
            return Err(TransportError::NotReady);
        }
        Err(TransportError::WouldBlock)
    }

    fn is_up(&self) -> bool { self.armed }

    fn link_quality(&self) -> u8 {
        if self.armed { RF_STUB_QUALITY } else { LINK_QUALITY_DOWN }
    }

    fn name(&self) -> &'static str { self.name }
}
