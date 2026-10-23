// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Intel igc Ethernet (Kconfig `DRV_IGC`, cargo feature `igc`): the I225 and
//! I226 2.5 GbE controllers (I225-LM/V/IT/K, I226-LM/V/IT/K, I220-V, I221-V)
//! that sit on current Intel and Ryzen desktop and mini-PC boards, and
//! QEMU's `-device igb` (an 82576) for the gate.
//!
//! The ids the bus binds it to are in `crates/drivers/net/hwbus.ids`; it is
//! one more backend of the NIC table of [`crate::net_device`].
//!
//! # Shape
//!
//! The same halves as [`crate::e1000e`] -- a wire format, a thin device
//! (reset, queue set-up), and the device half both share
//! ([`crate::pci_nic`]) -- and most of the first one *is* e1000e's. The I225
//! dropped the legacy 82543 descriptors and every register block that only
//! they used; what is left is the igb family's programming model, which is
//! e1000e's with four differences:
//!
//! * **Queue registers** live in the per-queue blocks (`RDBAL`... at
//!   `0xc000`, `TDBAL`... at `0xe000`, 0x40 apart), not at `0x2800`/`0x3800`;
//!   the interrupt registers moved to `0x1500` (`ICR`, `IMS`, `IMC`).
//! * **Advanced descriptors**, always. A receive descriptor is posted as
//!   (packet buffer, header buffer = 0) and written back as (RSS/checksum
//!   words, status and errors, length, VLAN): the same upper word as e1000e's
//!   *extended* write-back, so [`rx_status`] is that decoder and every RX
//!   cursor and verdict of e1000e is reused. `SRRCTL` selects the format and
//!   the buffer size (`DESCTYPE` = one buffer, `BSIZEPKT` in KiB). A
//!   transmit descriptor is `(addr, cmd_type_len | olinfo_status << 32)`:
//!   `DEXT` and `DTYP` = 3 in the command, the frame length again in
//!   `PAYLEN` (bits 31:14 of `olinfo_status`); the write-back puts `DD` in
//!   the status dword, bit 32 of the second word, where [`crate::e1000e`]'s
//!   `tx_done` already looks.
//! * **Link**: `STATUS` has a 2.5 Gb/s speed bit (22) on top of the 10/100/
//!   1000 encoding ([`link_from_status`]).
//! * **Reset** is `CTRL.RST` (bit 26), the same bit as e1000e's, on the I225
//!   (`igc_reset_hw_base`) and on the 82576 (`igb_reset_hw_82575`), after
//!   the PCIe master requests are disabled. `CTRL.DEV_RST` (bit 29) is the
//!   82580's global device reset, `igb` only, and not an I225 bit.
//!
//! The device half is the e1000e one (one receive ring, one transmit ring in
//! `.bss`, one 2 KiB staging buffer per descriptor, everything mapped through
//! the function's DMA domain, the frame copied in/out so the device never
//! sees a caller's memory, one MSI where the machine routes it, polled
//! otherwise) with those differences applied. It is a second copy of that
//! half, not a shared one: the rings are statics, and the two controllers
//! are different drivers that may be in one image.
//!
//! # Not done (needs the hardware)
//!
//! Everything here is checked against the Linux v7.2.9 `igc` and `igb`
//! register headers (see the host tests, which cite them by name); no I225
//! was available, and QEMU's `igb` is an 82576 whose model differs from the
//! I225 (no 2.5 Gb/s, the legacy interrupt registers at 0xc0 in `igb`). Not done: the PHY power-up
//! (`igc_power_up_link`) that a PHY left powered down by a previous OS
//! needs, the packet-buffer size programming (`PBA`) and flow control (the
//! reset defaults stand), the I225 revision A errata workarounds, EEE, the
//! second to fourth queues, RSS, checksum and TSO offloads, MSI-X. A part
//! with a blank NVM has no station address and is refused ([`NicError::NoMac`](crate::pci_nic::NicError::NoMac)).

#[cfg(not(target_endian = "little"))]
compile_error!("igc descriptors are little-endian words read as native u64s");

use crate::e1000e::{Desc, Link};

// ---------------------------------------------------------------------
// Registers (offsets from BAR 0) and bits
// ---------------------------------------------------------------------

pub const REG_CTRL_EXT: usize = 0x0018;
pub const REG_ICR: usize = 0x1500;
pub const REG_IMS: usize = 0x1508;
pub const REG_IMC: usize = 0x150c;

/// Queue 0 of the receive block (`RDBAL(n)` = 0xc000 + 0x40 n).
pub const REG_RDBAL: usize = 0xc000;
pub const REG_RDBAH: usize = 0xc004;
pub const REG_RDLEN: usize = 0xc008;
pub const REG_SRRCTL: usize = 0xc00c;
pub const REG_RDH: usize = 0xc010;
pub const REG_RDT: usize = 0xc018;
pub const REG_RXDCTL: usize = 0xc028;
/// Queue 0 of the transmit block (`TDBAL(n)` = 0xe000 + 0x40 n).
pub const REG_TDBAL: usize = 0xe000;
pub const REG_TDBAH: usize = 0xe004;
pub const REG_TDLEN: usize = 0xe008;
pub const REG_TDH: usize = 0xe010;
pub const REG_TDT: usize = 0xe018;
pub const REG_TXDCTL: usize = 0xe028;

/// `CTRL.GIO_MASTER_DISABLE` (`IGC_CTRL_GIO_MASTER_DISABLE`): stop the
/// controller issuing PCIe requests; the first step of a reset.
pub const CTRL_GIO_MASTER_DISABLE: u32 = 1 << 2;
/// `STATUS.GIO_MASTER_ENABLE`: set while PCIe master requests are pending.
pub const STATUS_GIO_MASTER_ENABLE: u32 = 1 << 19;
/// `CTRL_EXT.DRV_LOAD`: tells the manageability firmware a driver owns the
/// controller.
pub const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;

pub const STATUS_LU: u32 = 1 << 1;
pub const STATUS_SPEED_100: u32 = 0x40;
pub const STATUS_SPEED_1000: u32 = 0x80;
pub const STATUS_SPEED_2500: u32 = 1 << 22;

/// `SRRCTL.DESCTYPE` = 1 (bits 27:25): advanced descriptors, one buffer
/// (no header split).
pub const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;
/// `SRRCTL.BSIZEPKT` (bits 6:0) is in 1 KiB units.
pub const SRRCTL_BSIZEPKT_SHIFT: u32 = 10;

/// `SRRCTL` for a receive buffer of `buf` bytes: advanced one-buffer
/// descriptors, the size in KiB (a multiple of 1 KiB, at most 127).
pub const fn srrctl(buf: usize) -> u32 {
    SRRCTL_DESCTYPE_ADV_ONEBUF | ((buf >> SRRCTL_BSIZEPKT_SHIFT) as u32 & 0x7f)
}

/// Queue thresholds, as the Linux driver programs them minus write-back
/// batching (`WTHRESH` stays 0, so a descriptor is written back as soon as
/// it is done: a polled driver should not wait for three more frames).
/// Receive: `PTHRESH` 8, `HTHRESH` 8. Transmit: `PTHRESH` 8, `HTHRESH` 1.
pub const RXDCTL_RUN: u32 = 8 | (8 << 8) | crate::e1000e::XDCTL_QUEUE_ENABLE;
pub const TXDCTL_RUN: u32 = 8 | (1 << 8) | crate::e1000e::XDCTL_QUEUE_ENABLE;

// ---------------------------------------------------------------------
// Controllers
// ---------------------------------------------------------------------

/// The two controller families this driver speaks to. The driver programs
/// them identically (the same reset bit, the same queue and interrupt
/// registers); the family is named on the bring-up line (`model=Igb`), which
/// is how a log says whether a function is the I225 hardware or QEMU's
/// 82576.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    /// I220/I221/I225/I226.
    I225,
    /// The 82576 QEMU's `igb` models.
    Igb,
}

/// PCI device ids (vendor 8086) of the I220/I221/I225/I226 parts, from the
/// Linux `igc` PCI table (`igc_hw.h` `IGC_DEV_ID_*`, `igc_main.c`
/// `igc_pci_tbl`). The blank-NVM ids (`IGC_DEV_ID_I226_BLANK_NVM` 0x125f,
/// `IGC_DEV_ID_I225_BLANK_NVM` 0x15fd: no station address) are left out.
pub const I225_DEVICE_IDS: [u16; 14] = [
    0x15f2, // I225-LM
    0x15f3, // I225-V
    0x15f8, // I225-I
    0x15f7, // I220-V
    0x3100, // I225-K
    0x3101, // I225-K2
    0x3102, // I226-K
    0x5502, // I225-LMVP
    0x5503, // I226-LMVP
    0x0d9f, // I225-IT
    0x125b, // I226-LM
    0x125c, // I226-V
    0x125d, // I226-IT
    0x125e, // I221-V
];
/// QEMU's `-device igb`: an 82576 (`E1000_DEV_ID_82576` in `igb/e1000_hw.h`).
pub const IGB_QEMU_DEVICE_ID: u16 = 0x10c9;

/// Which family a PCI device id (vendor 8086) belongs to; `None` for an id
/// this driver does not drive.
pub const fn model_for(device: u16) -> Option<Model> {
    if device == IGB_QEMU_DEVICE_ID {
        return Some(Model::Igb);
    }
    let mut i = 0;
    while i < I225_DEVICE_IDS.len() {
        if I225_DEVICE_IDS[i] == device {
            return Some(Model::I225);
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------
// Rings
// ---------------------------------------------------------------------

/// A receive descriptor handed to the controller: the packet buffer's bus
/// address and a zero header buffer address (whose bit 0 is `DD` in the
/// write-back, so a posted descriptor never reads as done). The write-back
/// overwrites both words; a consumed descriptor must be posted again whole.
pub const fn rx_post(buf_bus: u64) -> Desc {
    crate::e1000e::rx_post(buf_bus)
}

/// Decode the write-back of an advanced receive descriptor from its second
/// word: status and errors in 31:0 (status in the low byte, errors in the
/// top byte), length in 47:32, VLAN tag in 63:48. That is e1000e's extended
/// format; the error bits that matter sit in the same places
/// (`CE`, `SE`, `SEQ`, `CXE`, `RXE`).
pub const fn rx_status(hi: u64) -> crate::e1000e::RxStatus {
    crate::e1000e::rx_status(hi, true)
}

/// Advanced transmit descriptor command bits (the `cmd_type_len` dword).
pub const ADVTXD_DTYP_DATA: u32 = 3 << 20;
pub const ADVTXD_DCMD_EOP: u32 = 1 << 24;
pub const ADVTXD_DCMD_IFCS: u32 = 1 << 25;
pub const ADVTXD_DCMD_RS: u32 = 1 << 27;
pub const ADVTXD_DCMD_DEXT: u32 = 1 << 29;
/// `olinfo_status.PAYLEN` starts at bit 14.
pub const ADVTXD_PAYLEN_SHIFT: u32 = 14;

/// An advanced data descriptor for one whole frame in one buffer: end of
/// packet, the FCS appended by the controller, a status write-back when done.
///
/// First word: the buffer's bus address. Second word: `cmd_type_len` (length
/// in 15:0, `DTYP` in 23:20, the command bits above) in the low dword,
/// `olinfo_status` (the frame length again in `PAYLEN`) in the high one.
pub const fn tx_frame(buf_bus: u64, len: usize) -> Desc {
    let cmd_type_len = (len as u32 & 0xffff)
        | ADVTXD_DTYP_DATA
        | ADVTXD_DCMD_EOP
        | ADVTXD_DCMD_IFCS
        | ADVTXD_DCMD_RS
        | ADVTXD_DCMD_DEXT;
    let olinfo_status = (len as u32) << ADVTXD_PAYLEN_SHIFT;
    Desc { lo: buf_bus, hi: cmd_type_len as u64 | (olinfo_status as u64) << 32 }
}

/// Has the controller written the transmit descriptor back? `DD` is bit 0 of
/// the status dword that overlays `olinfo_status`: the place e1000e's
/// descriptors keep it too. A descriptor the driver filled has bit 32 clear
/// whatever the length (`PAYLEN` starts at bit 14 of that dword).
pub const fn tx_done(hi: u64) -> bool {
    crate::e1000e::tx_done(hi)
}

// ---------------------------------------------------------------------
// Link
// ---------------------------------------------------------------------

/// What `STATUS` says about the link: 10, 100, 1000 or 2500 Mb/s.
pub const fn link_from_status(status: u32) -> Link {
    if status & STATUS_LU == 0 {
        return Link { up: false, mbps: 0 };
    }
    let mbps = if status & STATUS_SPEED_1000 != 0 {
        if status & STATUS_SPEED_2500 != 0 { 2500 } else { 1000 }
    } else if status & STATUS_SPEED_100 != 0 {
        100
    } else {
        10
    };
    Link { up: true, mbps }
}

// ---------------------------------------------------------------------
// The wire map, as the shared device half runs it
// ---------------------------------------------------------------------

/// igc's register map, descriptors and link decoding for [`crate::pci_nic`],
/// the device half this driver shares with e1000e.
pub struct IgcWire;

impl crate::pci_nic::Wire for IgcWire {
    const NAME: &'static str = "igc";
    const RX: crate::pci_nic::RingRegs = crate::pci_nic::RingRegs {
        bal: REG_RDBAL,
        bah: REG_RDBAH,
        len: REG_RDLEN,
        head: REG_RDH,
        tail: REG_RDT,
        ctl: REG_RXDCTL,
    };
    const TX: crate::pci_nic::RingRegs = crate::pci_nic::RingRegs {
        bal: REG_TDBAL,
        bah: REG_TDBAH,
        len: REG_TDLEN,
        head: REG_TDH,
        tail: REG_TDT,
        ctl: REG_TXDCTL,
    };
    const ICR: usize = REG_ICR;
    const IMS: usize = REG_IMS;
    const IMC: usize = REG_IMC;

    #[inline(always)]
    fn rx_status(hi: u64) -> crate::e1000e::RxStatus {
        rx_status(hi)
    }

    #[inline(always)]
    fn tx_frame(buf_bus: u64, len: usize) -> Desc {
        tx_frame(buf_bus, len)
    }

    #[inline(always)]
    fn link(status: u32) -> Link {
        link_from_status(status)
    }
}

// ---------------------------------------------------------------------
// The device
// ---------------------------------------------------------------------

#[cfg(feature = "igc")]
pub use device::*;

#[cfg(feature = "igc")]
mod device {
    use super::*;
    use crate::e1000e::{RCTL_RUN, REG_CTRL, REG_RCTL, REG_RXCSUM, REG_STATUS, REG_TCTL, TCTL_RUN};
    use crate::pci_nic::{wait_for, Chip, Mem, Nic, NicError, Regs, Wire};
    use azos_drv_api::net::{NetDevice, NetError};
    use azos_drv_sys::kwarn;
    use azos_drv_virtio::virtio::pci::msix_selftest::MsiRoute;
    use azos_pci::{BarWindow, ConfigSpace, FunctionInfo};

    /// Kconfig `IGC_RX_DESCS` / `IGC_TX_DESCS`.
    const RX_N: usize = azos_limits::IGC_RX_DESCS as usize;
    const TX_N: usize = azos_limits::IGC_TX_DESCS as usize;

    const _: () = assert!(crate::e1000e::BUF_SIZE % (1 << SRRCTL_BSIZEPKT_SHIFT) == 0);

    /// How long the reset waits for the PCIe master requests to drain. Linux
    /// polls `MASTER_DISABLE_TIMEOUT` (800) times 2-3 ms; the requests of a
    /// controller that did not start a transfer drain at once.
    const MASTER_DISABLE_WAIT_US: u64 = 100_000;

    static MEM: Mem<RX_N, TX_N> = Mem::new();
    static NIC: Nic<IgcWire, RX_N, TX_N> = Nic::new(&MEM);

    impl Chip for IgcWire {
        type Model = Model;
        /// Kconfig `IGC_LINK_WAIT_MS`.
        const LINK_WAIT_US: u64 = azos_limits::IGC_LINK_WAIT_MS as u64 * 1000;

        fn identify(info: &FunctionInfo) -> Result<Model, NicError> {
            model_for(info.device).ok_or(NicError::UnknownDevice)
        }

        /// As `igc_reset_hw_base` / `igb_reset_hw_82575`: disable the PCIe
        /// master requests, mask interrupts, stop both engines, let in-flight
        /// DMA finish, then `CTRL.RST`; it clears itself. A master that stays
        /// busy or a bit that does not clear is reported and not fatal (Linux
        /// goes on too): a controller still in reset reads all ones and is
        /// refused for want of a station address.
        fn reset(r: &Regs<Self>, info: &FunctionInfo, _model: Model) -> Result<(), NicError> {
            r.wr(REG_CTRL, r.rd(REG_CTRL) | CTRL_GIO_MASTER_DISABLE);
            if !wait_for(MASTER_DISABLE_WAIT_US, || r.rd(REG_STATUS) & STATUS_GIO_MASTER_ENABLE == 0) {
                kwarn!("[NET] igc {}: PCIe master requests still pending; resetting anyway", info.bdf);
            }
            r.quiesce();
            if !r.reset_via(crate::e1000e::CTRL_RST) {
                kwarn!("[NET] igc {}: CTRL.RST did not clear; continuing", info.bdf);
            }
            r.after_reset();
            r.link_setup();
            // A driver owns the controller: the manageability firmware
            // stands off.
            r.wr(REG_CTRL_EXT, r.rd(REG_CTRL_EXT) | CTRL_EXT_DRV_LOAD);
            Ok(())
        }

        fn start_queues(r: &Regs<Self>, rx_ring_bus: u64, tx_ring_bus: u64, rx_n: usize, tx_n: usize) {
            // Transmit ring, then receive ring, then the engines. The queue
            // is enabled after its ring is described; its tail is written
            // last.
            r.describe_ring(&Self::TX, tx_ring_bus, tx_n);
            r.zero_ring(&Self::TX);
            r.wr(REG_TXDCTL, TXDCTL_RUN);
            r.describe_ring(&Self::RX, rx_ring_bus, rx_n);
            r.wr(REG_SRRCTL, srrctl(crate::e1000e::BUF_SIZE));
            r.zero_ring(&Self::RX);
            r.wr(REG_RXDCTL, RXDCTL_RUN);
            r.await_queues();
            // No checksum offload.
            r.wr(REG_RXCSUM, 0);
            r.wr(REG_TCTL, TCTL_RUN);
            r.wr(REG_RCTL, RCTL_RUN);
        }

        fn detail(model: Model, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "model={:?}", model)
        }
    }

    /// Bring up the igc function `info` as a NIC of the table (see
    /// [`Nic::init_pci`]).
    pub fn init_pci<C, R>(
        cfg: &mut C,
        info: &FunctionInfo,
        window: &mut BarWindow,
        route: &mut R,
    ) -> Result<(), NicError>
    where
        C: ConfigSpace,
        R: MsiRoute,
    {
        NIC.init_pci(cfg, info, window, route)
    }

    /// Interrupt-path hook: `true` when `token` is this NIC's vector (see
    /// [`Nic::msi_irq`]).
    #[inline]
    pub fn msi_irq(token: u32) -> bool {
        NIC.msi_irq(token)
    }

    /// `true` once the NIC's MSI is programmed.
    pub fn irq_driven() -> bool {
        NIC.irq_driven()
    }

    /// Receive interrupts taken so far.
    pub fn rx_irq_count() -> u32 {
        NIC.rx_irq_count()
    }

    /// `NetDevice` over the shared NIC, as `E1000eNetDevice` is.
    pub struct IgcNetDevice;

    impl NetDevice for IgcNetDevice {
        #[inline]
        fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
            NIC.send(frame)
        }
        #[inline]
        fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
            NIC.recv(buf)
        }
        fn mac(&self) -> [u8; 6] {
            NIC.mac()
        }
        fn is_ready(&self) -> bool {
            NIC.is_ready()
        }
        #[inline]
        fn tx_batch_begin(&self) {
            NIC.tx_batch_begin()
        }
        #[inline]
        fn tx_batch_end(&self) {
            NIC.tx_batch_end()
        }
        #[inline]
        fn tx_watch(&self) -> Option<u64> {
            NIC.tx_watch()
        }
    }
}

// ---------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e1000e::{RxCursor, RxStatus, TxCursor, RXD_STAT_DD, RXD_STAT_EOP, TCTL_RUN};

    /// **Discriminates.** The advanced write-back is read where the manual
    /// puts it: status and errors in the low dword, the length in 47:32 and
    /// the VLAN tag above it, whatever the RSS/checksum words in the first
    /// qword say. A decoder that read the legacy layout (length in 15:0)
    /// would report the status byte's neighbours as the length.
    #[test]
    fn advanced_rx_writeback_decodes_status_length_and_errors() {
        let hi = (RXD_STAT_DD | RXD_STAT_EOP) as u64 | 0x0456 << 32 | 0x8100 << 48;
        assert_eq!(rx_status(hi), RxStatus { done: true, eop: true, len: 0x0456, bad: false });
        // A posted descriptor (header address 0) is not done.
        assert!(!rx_status(rx_post(0x1000).hi).done);
        // CRC error (bit 24), RX error (bit 31): frame errors; the TCP/IP
        // checksum errors (29, 30) alone are not (no offload is enabled).
        assert!(rx_status(hi | 1 << 24).bad);
        assert!(rx_status(hi | 1 << 31).bad);
        assert!(!rx_status(hi | 1 << 29 | 1 << 30).bad);
    }

    /// **Discriminates.** The advanced transmit descriptor bit for bit:
    /// `DEXT` (bit 29), `RS` (27), `IFCS` (25), `EOP` (24), `DTYP` = 3 at
    /// 23:20, the length at 15:0, and the length again at bit 14 of the
    /// second dword (`PAYLEN`). Dropping `PAYLEN` or `DEXT` changes the
    /// word. The e1000e extended form (DTYP = 1, no PAYLEN) is a different
    /// word for the same frame.
    #[test]
    fn tx_frame_is_the_advanced_data_descriptor() {
        let d = tx_frame(0x1000, 60);
        assert_eq!(d.lo, 0x1000);
        assert_eq!(d.hi, 0x000f_0000_2b30_003c);
        assert_eq!(tx_frame(0, 1514).hi, (1514u64 << 14) << 32 | 0x2b30_0000 | 1514);
        assert_ne!(d.hi, crate::e1000e::tx_frame(0x1000, 60, true).hi);
    }

    /// **Discriminates.** `DD` is the status dword's bit 0 (bit 32 of the
    /// second word) and a descriptor the driver filled is never done, for
    /// any frame length: `PAYLEN` begins at bit 14 of the same dword and
    /// must not reach bit 0. The write-back replaces the command dword with
    /// a sequence number, which is not a status.
    #[test]
    fn tx_done_is_the_status_dword_dd() {
        for len in [1usize, 60, 64, 1000, 1514] {
            assert!(!tx_done(tx_frame(0x1000, len).hi), "len {len}");
        }
        assert!(tx_done(tx_frame(0x1000, 60).hi | 1 << 32));
        assert!(tx_done(0x0000_0001_0000_0000));
        assert!(!tx_done(0x0000_0000_ffff_ffff), "the low dword is not a status");
    }

    /// **Discriminates.** `SRRCTL` for the 2 KiB buffers: advanced one-buffer
    /// descriptors (`DESCTYPE` 1 at 27:25) and `BSIZEPKT` 2 (KiB). A size
    /// given in bytes would overflow the 7-bit field; the field is masked.
    #[test]
    fn srrctl_selects_advanced_descriptors_and_the_buffer_size() {
        assert_eq!(srrctl(2048), 0x0200_0002);
        assert_eq!(srrctl(4096), 0x0200_0004);
        assert_eq!(srrctl(1 << 20) & 0x7f, 0, "the size field does not spill into DESCTYPE");
        assert_eq!(srrctl(1 << 20) >> 25, 1);
    }

    /// **Discriminates.** Link from `STATUS`: down is down whatever the speed
    /// bits say; up reports 10, 100, 1000 and 2500 (bit 22 qualifies the
    /// gigabit encoding only), and the 0xc0 encoding some parts report for
    /// gigabit is 1000, not 100.
    #[test]
    fn link_from_status_decodes_speed_including_2500() {
        assert_eq!(link_from_status(STATUS_SPEED_100 | STATUS_SPEED_2500), Link { up: false, mbps: 0 });
        assert_eq!(link_from_status(STATUS_LU), Link { up: true, mbps: 10 });
        assert_eq!(link_from_status(STATUS_LU | STATUS_SPEED_100), Link { up: true, mbps: 100 });
        assert_eq!(link_from_status(STATUS_LU | STATUS_SPEED_1000), Link { up: true, mbps: 1000 });
        assert_eq!(link_from_status(STATUS_LU | 0xc0), Link { up: true, mbps: 1000 });
        assert_eq!(link_from_status(STATUS_LU | STATUS_SPEED_1000 | STATUS_SPEED_2500), Link { up: true, mbps: 2500 });
        assert_eq!(link_from_status(STATUS_LU | STATUS_SPEED_2500), Link { up: true, mbps: 10 }, "2.5G needs the gigabit bit");
    }

    /// **Discriminates.** The family of each id: the I225/I226 table and
    /// QEMU's 82576; an id from the e1000e table (82574L), the blank-NVM ids
    /// (`IGC_DEV_ID_I226_BLANK_NVM`, `IGC_DEV_ID_I225_BLANK_NVM`: no station
    /// address, so the NIC would only be refused) and zero are not this
    /// driver's.
    #[test]
    fn model_follows_the_device_id() {
        assert_eq!(model_for(0x15f3), Some(Model::I225));
        assert_eq!(model_for(0x125c), Some(Model::I225));
        assert_eq!(model_for(IGB_QEMU_DEVICE_ID), Some(Model::Igb));
        assert_eq!(model_for(0x10d3), None, "an 82574L is the e1000e driver's");
        assert_eq!(model_for(0x125f), None, "I226 blank NVM");
        assert_eq!(model_for(0x15fd), None, "I225 blank NVM");
        assert_eq!(model_for(0), None);
    }

    /// **Discriminates.** The PCI ids against the Linux v7.2.9 `igc_hw.h`
    /// `IGC_DEV_ID_*` list, each by its Linux name (the same 14 as
    /// `igc_pci_tbl` minus the two blank-NVM ids), and QEMU's `igb` against
    /// `E1000_DEV_ID_82576` of `igb/e1000_hw.h`. A transposed digit in either
    /// table fails its line; a name added in Linux and not here is a new
    /// line to add.
    #[test]
    fn device_ids_are_igc_hw_h() {
        let igc_hw_h: [(&str, u16); 14] = [
            ("IGC_DEV_ID_I225_LM", 0x15F2),
            ("IGC_DEV_ID_I225_V", 0x15F3),
            ("IGC_DEV_ID_I225_I", 0x15F8),
            ("IGC_DEV_ID_I220_V", 0x15F7),
            ("IGC_DEV_ID_I225_K", 0x3100),
            ("IGC_DEV_ID_I225_K2", 0x3101),
            ("IGC_DEV_ID_I226_K", 0x3102),
            ("IGC_DEV_ID_I225_LMVP", 0x5502),
            ("IGC_DEV_ID_I226_LMVP", 0x5503),
            ("IGC_DEV_ID_I225_IT", 0x0D9F),
            ("IGC_DEV_ID_I226_LM", 0x125B),
            ("IGC_DEV_ID_I226_V", 0x125C),
            ("IGC_DEV_ID_I226_IT", 0x125D),
            ("IGC_DEV_ID_I221_V", 0x125E),
        ];
        for (name, id) in igc_hw_h {
            assert!(I225_DEVICE_IDS.contains(&id), "{name} {id:#x}");
            assert_eq!(model_for(id), Some(Model::I225), "{name}");
        }
        assert_eq!(I225_DEVICE_IDS.len(), igc_hw_h.len());
        assert_eq!(IGB_QEMU_DEVICE_ID, 0x10C9, "E1000_DEV_ID_82576");
    }

    /// **Discriminates.** The id table the bus binds and the one the driver
    /// classifies are the same set: every `igc` line of `hwbus.ids` is an id
    /// `model_for` knows, and every id `model_for` knows has a line. A new id
    /// in one place and not the other fails here.
    #[test]
    fn hwbus_ids_and_model_for_agree() {
        let ids = include_str!("../hwbus.ids");
        let mut bound = [0u16; 64];
        let mut n = 0;
        for line in ids.lines().filter(|l| l.split_whitespace().next() == Some("igc")) {
            let sel = line.split_whitespace().nth(1).expect("an igc line has a selector");
            let dev = sel.strip_prefix("pci:8086:").expect("igc binds Intel functions by id");
            let dev = u16::from_str_radix(dev, 16).expect("a hex device id");
            assert!(model_for(dev).is_some(), "{sel} is bound but model_for refuses it");
            assert!(line.contains("if=DRV_IGC"), "{line}");
            bound[n] = dev;
            n += 1;
        }
        let bound = &bound[..n];
        for id in I225_DEVICE_IDS.iter().chain([&IGB_QEMU_DEVICE_ID]) {
            assert!(bound.contains(id), "{id:#x} is classified but not bound");
        }
        assert_eq!(n, I225_DEVICE_IDS.len() + 1);
    }

    /// **Discriminates.** The transmit control word. Linux sets `EN`, `PSP`,
    /// `RTLC` and the collision threshold (`igc_setup_tctl`: `IGC_TCTL_EN`
    /// 0x2, `IGC_TCTL_PSP` 0x8, `IGC_TCTL_RTLC` 0x01000000, `IGC_TCTL_CT`
    /// 0xff0 = `IGC_COLLISION_THRESHOLD` 15 << 4) and, at link-up,
    /// `IGC_COLLISION_DISTANCE` 63 << `IGC_COLD_SHIFT` 12 in the *same*
    /// register, under `IGC_TCTL_COLD` 0x003ff000 (`igc_config_collision_dist`);
    /// `igb` has the same field (`E1000_TCTL_COLD`, `E1000_COLD_SHIFT`). The
    /// driver programs that final word once. Register 0x404 (`TCTL_EXT`)
    /// is in neither igc's register header nor igb's (which only dumps it
    /// for ethtool), so nothing here writes it: the previous driver put the
    /// distance there and left `TCTL.COLD` at its reset value.
    #[test]
    fn tctl_is_linuxs_final_word_with_cold_in_tctl() {
        let tctl = 0x2 | 0x8 | 0x0100_0000 | (15 << 4) | (63 << 12);
        assert_eq!(TCTL_RUN, tctl);
        assert_eq!(TCTL_RUN & 0x0000_0ff0, 15 << 4, "IGC_TCTL_CT");
        assert_eq!(TCTL_RUN & 0x003f_f000, 63 << 12, "IGC_TCTL_COLD");
        assert_eq!(TCTL_RUN & !(0x2 | 0x8 | 0x0100_0000 | 0x0ff0 | 0x003f_f000), 0, "no other bit");
    }

    /// **Discriminates.** The reset. `igc_reset_hw_base` and
    /// `igb_reset_hw_82575` both set `CTRL.RST` (`IGC_CTRL_RST` /
    /// `E1000_CTRL_RST`, 0x04000000) after `*_disable_pcie_master`
    /// (`IGC_CTRL_GIO_MASTER_DISABLE` 0x4, wait for
    /// `IGC_STATUS_GIO_MASTER_ENABLE` 0x00080000 to clear). Bit 29
    /// (`E1000_CTRL_DEV_RST`, `igb/e1000_82575.h`) is the 82580's global
    /// device reset, used only by `igb_reset_hw_82580` (`e1000_82575.c`) and
    /// absent from `igc_defines.h`: the previous driver reset the I225 with
    /// it.
    #[test]
    fn reset_is_ctrl_rst_after_master_disable() {
        assert_eq!(crate::e1000e::CTRL_RST, 0x0400_0000);
        assert_eq!(CTRL_GIO_MASTER_DISABLE, 0x0000_0004);
        assert_eq!(STATUS_GIO_MASTER_ENABLE, 0x0008_0000);
        let dev_rst = 0x2000_0000u32; // E1000_CTRL_DEV_RST: igb 82580 only
        assert_ne!(crate::e1000e::CTRL_RST, dev_rst);
        // None of the CTRL bits the driver sets or clears is bit 29.
        let ctrl_bits = crate::e1000e::CTRL_CLEAR | crate::e1000e::CTRL_SLU | CTRL_GIO_MASTER_DISABLE;
        assert_eq!(ctrl_bits & dev_rst, 0);
    }

    /// **Discriminates.** The registers and bits the driver takes from
    /// e1000e's file but programs on igc, against the literals of
    /// `igc_regs.h` and `igc_defines.h` (the Linux names are in the
    /// comments): a shared constant that drifted from the I225's header
    /// fails here, not on a board.
    #[test]
    fn shared_registers_and_bits_are_igc_regs_h_and_igc_defines_h() {
        use crate::e1000e as e;
        // igc_regs.h
        assert_eq!(e::REG_CTRL, 0x00000, "IGC_CTRL");
        assert_eq!(e::REG_STATUS, 0x00008, "IGC_STATUS");
        assert_eq!(e::REG_EECD, 0x00010, "IGC_EECD");
        assert_eq!(REG_CTRL_EXT, 0x00018, "IGC_CTRL_EXT");
        assert_eq!(e::REG_RCTL, 0x00100, "IGC_RCTL");
        assert_eq!(e::REG_TCTL, 0x00400, "IGC_TCTL");
        assert_eq!(e::REG_RXCSUM, 0x05000, "IGC_RXCSUM");
        assert_eq!(e::REG_MTA, 0x05200, "IGC_MTA");
        assert_eq!(e::REG_RAL0, 0x05400, "IGC_RAL(0)");
        assert_eq!(e::REG_RAH0, 0x05404, "IGC_RAH(0)");
        assert_eq!((REG_ICR, REG_IMS, REG_IMC), (0x01500, 0x01508, 0x0150C), "IGC_ICR, IGC_IMS, IGC_IMC");
        // igc_defines.h
        assert_eq!(CTRL_EXT_DRV_LOAD, 0x1000_0000, "IGC_CTRL_EXT_DRV_LOAD");
        assert_eq!(e::CTRL_SLU, 0x0000_0040, "IGC_CTRL_SLU");
        assert_eq!(e::CTRL_FRCSPD, 0x0000_0800, "IGC_CTRL_FRCSPD");
        assert_eq!(e::CTRL_FRCDPX, 0x0000_1000, "IGC_CTRL_FRCDPX");
        assert_eq!(e::CTRL_VME, 0x4000_0000, "IGC_CTRL_VME");
        assert_eq!(e::CTRL_PHY_RST, 0x8000_0000, "IGC_CTRL_PHY_RST");
        assert_eq!(STATUS_LU, 0x0000_0002, "IGC_STATUS_LU");
        assert_eq!(STATUS_SPEED_100, 0x0000_0040, "IGC_STATUS_SPEED_100");
        assert_eq!(STATUS_SPEED_1000, 0x0000_0080, "IGC_STATUS_SPEED_1000");
        assert_eq!(STATUS_SPEED_2500, 0x0040_0000, "IGC_STATUS_SPEED_2500");
        assert_eq!(e::EECD_AUTO_RD, 0x0000_0200, "IGC_EECD_AUTO_RD");
        assert_eq!(e::RAH_AV, 0x8000_0000, "IGC_RAH_AV");
        assert_eq!(e::RCTL_EN, 0x0000_0002, "IGC_RCTL_EN");
        assert_eq!(e::RCTL_MPE, 0x0000_0010, "IGC_RCTL_MPE");
        assert_eq!(e::RCTL_BAM, 0x0000_8000, "IGC_RCTL_BAM");
        assert_eq!(e::RCTL_SECRC, 0x0400_0000, "IGC_RCTL_SECRC");
        assert_eq!(e::RCTL_RUN, 0x0400_8012, "EN | BAM | MPE | SECRC, 2 KiB buffers (BSIZE 0)");
        assert_eq!(e::TCTL_EN, 0x0000_0002, "IGC_TCTL_EN");
        assert_eq!(e::TCTL_PSP, 0x0000_0008, "IGC_TCTL_PSP");
        assert_eq!(e::TCTL_RTLC, 0x0100_0000, "IGC_TCTL_RTLC");
        assert_eq!(e::ICR_LSC, 0x0000_0004, "IGC_ICR_LSC");
        assert_eq!(e::ICR_RXDMT0, 0x0000_0010, "IGC_ICR_RXDMT0");
        assert_eq!(e::ICR_RXO, 0x0000_0040, "IGC_ICR_RXO");
        assert_eq!(e::ICR_RXT0, 0x0000_0080, "IGC_ICR_RXT0");
        // igc.h IGC_RXDCTL_QUEUE_ENABLE, IGC_TXDCTL_QUEUE_ENABLE (igb: E1000_*XDCTL_QUEUE_ENABLE)
        assert_eq!(e::XDCTL_QUEUE_ENABLE, 0x0200_0000);
    }

    /// **Discriminates.** The queue-0 registers against `igc_regs.h`
    /// (`IGC_RDBAL(n)` = 0x0C000 + 0x40 n, `IGC_TDBAL(n)` = 0x0E000 + 0x40 n,
    /// `IGC_SRRCTL(n)` = 0x0C00C + 0x40 n, the others at the offsets of the
    /// block) and the queue stride against `igb/e1000_regs.h`:
    /// `E1000_RDBAL(_n)` for `_n >= 4` is 0x0C000 + 0x40 n, so queue 4 is
    /// at 0xC100 -- the same linear block, queue 0 at its base. (`igb` keeps
    /// queues 0-3 at the legacy 0x2800/0x3800 as well; see the open issue
    /// about QEMU's model.)
    #[test]
    fn queue_blocks_follow_igc_regs_h_and_igbs_stride() {
        let rdbal = |n: usize| 0x0C000 + n * 0x40;
        let tdbal = |n: usize| 0x0E000 + n * 0x40;
        assert_eq!(REG_RDBAL, rdbal(0));
        assert_eq!(REG_RDBAH, rdbal(0) + 4);
        assert_eq!(REG_RDLEN, rdbal(0) + 8);
        assert_eq!(REG_SRRCTL, 0x0C00C);
        assert_eq!(REG_RDH, 0x0C010);
        assert_eq!(REG_RDT, 0x0C018);
        assert_eq!(REG_RXDCTL, 0x0C028);
        assert_eq!(REG_TDBAL, tdbal(0));
        assert_eq!(REG_TDBAH, 0x0E004);
        assert_eq!(REG_TDLEN, 0x0E008);
        assert_eq!(REG_TDH, 0x0E010);
        assert_eq!(REG_TDT, 0x0E018);
        assert_eq!(REG_TXDCTL, 0x0E028);
        // igb E1000_RDBAL(4) / E1000_TDBAL(4)
        assert_eq!((rdbal(4), tdbal(4)), (0x0C100, 0x0E100));
    }

    /// **Discriminates.** The queue thresholds against `igc.h` and
    /// `igc_main.c`: receive `IGC_RXDCTL_PTHRESH` 8 and `IGC_RXDCTL_HTHRESH`
    /// 8 << 8, transmit `IGC_TXDCTL_PTHRESH(8)` and `IGC_TXDCTL_HTHRESH(1)`
    /// (bits 12:8), each with `QUEUE_ENABLE` (bit 25). Linux also sets a
    /// write-back threshold (`IGC_RXDCTL_WTHRESH` 4 << 16, `IGC_TXDCTL_WTHRESH(16)`);
    /// this driver leaves it 0 on purpose (a polled driver should not wait
    /// for three more frames), so a descriptor is written back the moment
    /// it is done.
    #[test]
    fn queue_thresholds_are_linuxs_without_writeback_batching() {
        assert_eq!(RXDCTL_RUN, 8 | (8 << 8) | 0x0200_0000);
        assert_eq!(TXDCTL_RUN, 8 | (1 << 8) | 0x0200_0000);
        for r in [RXDCTL_RUN, TXDCTL_RUN] {
            assert_eq!(r & (0x1f << 16), 0, "WTHRESH 0");
        }
    }

    /// **Discriminates.** The advanced descriptor against the Linux literals:
    /// `IGC_ADVTXD_DTYP_DATA` 0x00300000, `DCMD_EOP` 0x01000000, `DCMD_IFCS`
    /// 0x02000000, `DCMD_RS` 0x08000000, `DCMD_DEXT` 0x20000000, `PAYLEN_SHIFT`
    /// 14 (`igc_base.h`; the same values in `igb/e1000_82575.h`), `IGC_TXD_STAT_DD`
    /// 0x1; `IGC_SRRCTL_DESCTYPE_ADV_ONEBUF` (1 at 27:25 = 0x02000000, `igb`:
    /// `E1000_SRRCTL_DESCTYPE_ADV_ONEBUF`) and `IGC_SRRCTL_BSIZEPKT` (bits 6:0,
    /// `size / 1024`).
    #[test]
    fn advanced_descriptor_bits_are_igc_base_h() {
        assert_eq!(ADVTXD_DTYP_DATA, 0x0030_0000);
        assert_eq!(ADVTXD_DCMD_EOP, 0x0100_0000);
        assert_eq!(ADVTXD_DCMD_IFCS, 0x0200_0000);
        assert_eq!(ADVTXD_DCMD_RS, 0x0800_0000);
        assert_eq!(ADVTXD_DCMD_DEXT, 0x2000_0000);
        assert_eq!(ADVTXD_PAYLEN_SHIFT, 14);
        assert_eq!(SRRCTL_DESCTYPE_ADV_ONEBUF, 0x0200_0000);
        assert_eq!(SRRCTL_BSIZEPKT_SHIFT, 10);
        assert_eq!(srrctl(2048) & 0x7f, 2048 / 1024);
        assert_eq!(srrctl(2048) & !0x7f, 0x0200_0000, "no BSIZEHDR, no other field");
    }

    /// **Discriminates.** The receive error bits the driver drops a frame
    /// for are `igb`'s `E1000_RXDEXT_ERR_FRAME_ERR_MASK` (`CE` 0x01000000,
    /// `SE` 0x02000000, `SEQ` 0x04000000, `CXE` 0x10000000, `RXE` 0x80000000),
    /// exact for the 82576. `igc_defines.h` defines only `RXE` (0x80000000)
    /// of them (`IGC_RXDEXT_STATERR_RXE`) next to the checksum errors
    /// `L4E` 0x20000000 and `IPE` 0x40000000, which are not frame errors
    /// here; for the I225 the other four are a superset that relies on
    /// them reading 0 (open issue).
    #[test]
    fn rx_error_bits_are_igbs_frame_error_mask() {
        let igb_mask = 0x0100_0000u32 | 0x0200_0000 | 0x0400_0000 | 0x1000_0000 | 0x8000_0000;
        assert_eq!(u32::from(crate::e1000e::RXD_ERR_FRAME) << 24, igb_mask);
        let ok = (RXD_STAT_DD | RXD_STAT_EOP) as u64 | 60 << 32;
        for bit in [24, 25, 26, 28, 31] {
            assert!(rx_status(ok | 1 << bit).bad, "bit {bit}");
        }
        for bit in [29, 30] {
            assert!(!rx_status(ok | 1 << bit).bad, "checksum error bit {bit}");
        }
    }

    /// The software model of the controller used below: it owns the ring
    /// from `RDH` to `RDT` and writes a frame's advanced write-back over the
    /// descriptor, *including the first word*, which on the real thing holds
    /// the RSS hash and packet type where the buffer address was.
    struct FakeAdvRx {
        ring: [Desc; 8],
        head: usize,
    }

    impl FakeAdvRx {
        fn deliver(&mut self, tail: usize, len: u16, eop: bool) -> bool {
            if self.head == tail {
                return false;
            }
            let status = RXD_STAT_DD | if eop { RXD_STAT_EOP } else { 0 };
            self.ring[self.head] = Desc { lo: 0xdead_beef_0000_0001, hi: status as u64 | (len as u64) << 32 };
            self.head = (self.head + 1) % 8;
            true
        }
    }

    /// The whole receive handshake with the advanced write-back: a burst
    /// arrives, is read in order, every consumed descriptor is posted again
    /// *whole* (the write-back destroyed the buffer address), and the ring
    /// takes the next burst. **Discriminates** a driver that clears only
    /// `DD` and leaves the hash in the address word: the model then hands
    /// the next frame to address 0xdeadbeef00000001.
    #[test]
    fn rx_ring_reposts_the_whole_descriptor_after_the_writeback_clobbers_it() {
        let n = 8;
        let mut dev = FakeAdvRx { ring: [rx_post(0); 8], head: 0 };
        for (i, d) in dev.ring.iter_mut().enumerate() {
            *d = rx_post(0x1000 * (i as u64 + 1));
        }
        let mut cur = RxCursor::new();
        let tail = cur.rdt(n) as usize;
        let accepted: usize = (0..8).map(|i| dev.deliver(tail, 60 + i, true) as usize).sum();
        assert_eq!(accepted, 7);
        let mut lens = [0u16; 7];
        for len in lens.iter_mut() {
            let st = rx_status(dev.ring[cur.clean as usize].hi);
            assert!(st.done && crate::e1000e::rx_accept(&st, cur.discarding, 1514));
            *len = st.len;
            let i = cur.take(n) as usize;
            assert_eq!(dev.ring[i].lo, 0xdead_beef_0000_0001, "the model clobbered the address word");
            dev.ring[i] = rx_post(0x1000 * (i as u64 + 1));
        }
        assert_eq!(lens, [60, 61, 62, 63, 64, 65, 66]);
        assert!(dev.ring.iter().enumerate().all(|(i, d)| d.lo == 0x1000 * (i as u64 + 1) && !rx_status(d.hi).done));
        // The tail goes back to the controller; the next frame is accepted.
        let tail = cur.rdt(n) as usize;
        assert_eq!(tail, 6);
        assert!(dev.deliver(tail, 100, true));
        assert_eq!(rx_status(dev.ring[cur.clean as usize].hi).len, 100);
    }

    /// The transmit handshake with the advanced descriptor: frames are
    /// published at `tail`, the controller's write-back marks them done in
    /// order, and `reclaim` frees exactly those. **Discriminates** a `tx_done`
    /// that looked at the command dword (the model puts a sequence number
    /// there): the first frame would read as done before it was sent.
    #[test]
    fn tx_ring_completes_in_order_by_the_status_dword() {
        let n = 8;
        let mut ring = [Desc { lo: 0, hi: 0 }; 8];
        let mut cur = TxCursor::new();
        for k in 0..5u16 {
            let i = cur.push(n).expect("room") as usize;
            ring[i] = tx_frame(0x1000 * (i as u64 + 1), 60 + k as usize);
        }
        assert_eq!(cur.reclaim(n, |i| tx_done(ring[i as usize].hi)), 0, "nothing sent yet");
        // The controller sends the first three: write-back = (seq, DD).
        for (seq, d) in ring.iter_mut().take(3).enumerate() {
            d.hi = seq as u64 | 1 << 32;
        }
        assert_eq!(cur.reclaim(n, |i| tx_done(ring[i as usize].hi)), 3);
        assert_eq!(cur.clean, 3);
    }
}
