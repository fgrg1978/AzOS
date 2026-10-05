// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The USB device-controller class: what a device-mode controller implements
//! to host the DFU class.

/// Operations a USB device-mode controller must support to host
/// the DFU class. Everything else (bulk endpoints, isochronous,
/// suspend/resume) is out of scope for recovery.
pub trait UsbDeviceController {
    /// Initialise the controller hardware: clock, PHY, mode
    /// select (force-device), interrupt mask, EP0 FIFO sizing.
    /// Called once at recovery-mode boot.
    fn init(&mut self) -> Result<(), UsbDeviceError>;

    /// Wait for bus reset + address-assigned, then advertise the
    /// descriptor blob built by
    /// [`azos_dfu::DescriptorBuilder`]. Returns once the host
    /// has issued `SET_CONFIGURATION(1)` and we're ready to take
    /// DFU class requests.
    fn enumerate(&mut self, descriptor_blob: &[u8]) -> Result<(), UsbDeviceError>;

    /// Poll the EP0 OUT FIFO.  Returns `Ok(Some(setup))` when a
    /// complete 8-byte setup packet has arrived, `Ok(None)` when
    /// no packet is ready, `Err` on bus error.
    fn poll_setup(&mut self) -> Result<Option<[u8; 8]>, UsbDeviceError>;

    /// Read up to `out.len()` bytes from EP0 OUT data stage.
    /// Returns the number actually transferred.
    fn read_out_data(&mut self, out: &mut [u8]) -> Result<usize, UsbDeviceError>;

    /// Write `data` to EP0 IN data stage as the response to the
    /// pending control transfer.
    fn write_in_data(&mut self, data: &[u8]) -> Result<(), UsbDeviceError>;

    /// STALL the current control transfer.  Used when the DFU
    /// state machine rejects a request (returns an `Err`).
    fn stall_ep0(&mut self) -> Result<(), UsbDeviceError>;

    /// Pulse the bus disconnect line so the host treats us as a
    /// fresh device on the next attach.  Used after manifestation
    /// to re-enumerate as the now-flashed runtime image.
    fn bus_reset_device_side(&mut self) -> Result<(), UsbDeviceError>;
}

/// Errors that the controller surface can return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbDeviceError {
    NotImplemented,
    Timeout,
    BusError,
    InvalidState,
}
