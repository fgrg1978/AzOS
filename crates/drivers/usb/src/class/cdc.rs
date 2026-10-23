// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The communications class drivers: a USB serial line (CDC-ACM) and a USB
//! network interface (CDC-ECM, CDC-NCM).
//!
//! Both are class drivers like the mass-storage one ([`super::msc`]): they
//! serve [`UsbClass`], claim interfaces, and move data only through the pipes
//! the core opened for those claims. This file is the protocol and nothing
//! else: no lock, no hardware. The kernel half wraps one function in a lock
//! (`crates/drivers/net/src/usb_net.rs` for the NIC, which registers with the
//! device table as `net_device::register_usb`) and turns the crank from the
//! `usb` task: [`CdcNet::session_wanted`] / [`CdcNet::open`] after each turn
//! of the core, then [`CdcNet::service`] ([`CdcAcm::pump`] for a serial line).
//!
//! # Two interfaces, two claims
//!
//! A CDC function is a communications interface (class 2: the class requests
//! and, for ACM, the line) and a data interface (class 0x0a: the bulk
//! endpoints). The core hands each interface to one driver, and a claim names
//! one interface, so a function holds **two claims**, the communications one
//! first (it precedes its data interface in every descriptor set seen; a data
//! interface listed first is declined). Both are offered to the same driver
//! object: register it twice, under [`CdcNet::comm_rule`] and
//! [`CdcNet::data_rule`] (or the ACM pair), through two handles to one
//! lock. The data interface is accepted only when the same driver already
//! holds the communications interface of the same device, so a composite
//! device with an ACM and an ECM function reaches each driver the right
//! interface. The union functional descriptor is read at setup and a data
//! interface it does not name fails the function ([`Fail::Mismatch`]).
//!
//! # Alternate settings
//!
//! ECM and NCM put their bulk endpoints in alternate setting 1 of the data
//! interface and none in setting 0 (so an idle function holds no bandwidth).
//! The core keeps the endpoints of the first setting that has some
//! ([`UsbDevice::info`] key 6 names it); setup selects it with SET_INTERFACE
//! before a pipe carries anything.
//!
//! # Setup (all through the control pipes, one request at a time)
//!
//! The configuration descriptor is read again (the core's tables do not keep
//! class-specific descriptors) for the union, the Ethernet networking
//! descriptor (MAC string, segment size), the NCM descriptor and the ACM
//! capabilities; then, for ECM and NCM, the MAC address string; for NCM,
//! GET_NTB_PARAMETERS and, when the device's blocks may exceed ours,
//! SET_NTB_INPUT_SIZE; then SET_INTERFACE; then SET_ETHERNET_PACKET_FILTER
//! (directed, broadcast, all multicast; a device that refuses it is used
//! anyway, as hosts do). Every step has `CTL_TIMEOUT_US` (5 s, USB 2.0
//! §9.2.6.4) to finish.
//!
//! # Network data path
//!
//! `USB_CDC_BUFS` receive buffers are posted to bulk-IN at all times; a
//! completed one is *held* until the stack has taken its frames, then posted
//! again, so the device is flow-controlled by the stack and nothing is copied
//! but the frame itself. ECM: one frame per transfer. NCM: one NTB-16
//! ([`ntb`]) per transfer, parsed lazily, datagram by datagram; a block that
//! lies about itself ends at the first bad field and counts in
//! [`NetStats::ntb_malformed`]. Transmit: one buffer per ECM frame; NCM packs
//! frames into the open block while a batch is open ([`CdcNet::tx_begin`] /
//! [`CdcNet::tx_end`], the shape of `NetDevice::tx_batch_*`), or sends each
//! frame alone. The block honours the device's alignment, divisor, remainder,
//! size and datagram limits.
//!
//! **No zero-length packets.** The core queues no zero-length transfer, so a
//! transmission whose length is a multiple of the endpoint's packet size
//! would never end at the device. ECM and NCM append one zero byte then: an
//! Ethernet frame may carry padding, and an NTB states its own length.
//!
//! # Serial data path (ACM)
//!
//! The `Uart` interface of `azos_devif`: [`CdcAcm`] implements it, and the
//! host resolves the queues the client attached ([`CdcAcm::queues`]) and calls
//! [`CdcAcm::pump`], which moves bytes between the pipes and
//! [`Chunk`]s. `configure` queues SET_LINE_CODING and answers at once;
//! `attach` raises DTR and RTS (a device that holds its data until the port
//! is opened sends it then), `detach` drops them. While no client holds the
//! port the receive pipe is not posted, so the device keeps its data. Once it
//! is, bytes are lost, and counted, rather than stalling the bus: the receive
//! pipe is drained into chunks as they arrive and a full queue loses its
//! chunk (the next one that fits is flagged `CHUNK_OVERRUN`).
//!
//! # Errors
//!
//! A STALL on a bulk pipe is cleared (CLEAR_FEATURE on the data claim's
//! control pipe) and the buffer posted again; any other bad completion is
//! counted and the buffer posted again, and [`MAX_BAD_RUN`] in a row fail the
//! function (it stays failed until unplugged, as the mass-storage driver
//! does). A setup step that fails or times out fails the function.
//!
//! # Limits
//!
//! One network function and one serial function at a time (a second of each
//! is declined `BUSY`); NTB-16 only (the format every NCM device must
//! support), CRC mode off; no link-status notifications (the function is up
//! while it is present) and no network statistics, multicast filter lists or
//! power filters; Ethernet frames up to the device's segment size, 1518 bytes
//! at most; a serial write whose length is a multiple of the packet size may
//! sit in the device until the next write (no zero-length packets, above).
//! There is no `Terminal` interface in the tree: a serial line is a `Uart`.
//!
//! # Kernel binding
//!
//! Both functions are bound in the kernel (Kconfig `USB_CDC`,
//! `kernel/src/boot/usb.rs`). The network function becomes a NIC. The serial
//! function becomes a **port of the `Uart` table**
//! (`crates/core/syscall/src/devices.rs`): when it is ready the kernel offers
//! it as `uart.2` ([`CdcAcm`] behind a sleeping lock, `kernel/src/boot/usb/serial.rs`),
//! and withdraws it when the device is unplugged, so a task that holds a
//! `uart.2` endpoint attaches its queues like on the bridge's port and the
//! host pumps them through [`CdcAcm::pump`]. With Kconfig `USB_CDC_CONSOLE` the
//! kernel holds the line itself ([`CdcAcm::attach_kernel`], a holder with no
//! queues): what the console writes is sent to the device and what the device
//! sends is the console's input, so a PC or a board with no UART has a console
//! over USB. QEMU has no CDC-ACM device (`-device usb-serial` is an FTDI
//! adapter, which this driver does not claim): the protocol is exercised by
//! `tests/host/usb-cdc-tests` over the xHCI mock, and the rest on a board or a
//! PC with a CDC-ACM gadget (`g_serial`, a Pico or ESP32-S3 USB-CDC).

use azos_devif::outcome::{BAD_ARGUMENT, BUSY, NOT_READY, OK, UNSUPPORTED};
use azos_devif::uart::{self as uart, Chunk, ChunkSink, ChunkSource, RxQueue, TxQueue};
use azos_devif::{Cap, Out};
use azos_rings::Push;

use crate::class::{Claim, Match, UsbClass, UsbDevice};
use crate::hw::{Clock, DmaBuf, Memory, PAGE};
use crate::usbcore::desc::{
    Setup, DT_CONFIG, DT_STRING, REQ_SET_INTERFACE, RT_DIR_IN, RT_RECIP_INTERFACE, RT_TYPE_CLASS, RT_TYPE_STANDARD,
};
use crate::usbcore::pipe::{Completion, Dir, PipeEnd, PipeRings, Status, Transfer};

use ntb::{Bytes, Rx16, Tx16, TxParams};

// ---- Protocol constants (USB CDC 1.2, PSTN 1.2, ECM 1.2, NCM 1.0) ----

/// Class of a communications interface.
pub const CLASS_COMM: u8 = 2;
/// Class of a CDC data interface.
pub const CLASS_DATA: u8 = 0x0a;
/// Communications subclass: abstract control model (a serial line).
pub const SUBCLASS_ACM: u8 = 2;
/// Communications subclass: Ethernet control model.
pub const SUBCLASS_ECM: u8 = 6;
/// Communications subclass: network control model.
pub const SUBCLASS_NCM: u8 = 0x0d;

/// Descriptor type of a class-specific interface descriptor.
const CS_INTERFACE: u8 = 0x24;
const FUNC_ACM: u8 = 0x02;
const FUNC_UNION: u8 = 0x06;
const FUNC_ETHERNET: u8 = 0x0f;
const FUNC_NCM: u8 = 0x1a;

const REQ_SET_LINE_CODING: u8 = 0x20;
const REQ_SET_CONTROL_LINE_STATE: u8 = 0x22;
const REQ_SET_PACKET_FILTER: u8 = 0x43;
const REQ_GET_NTB_PARAMETERS: u8 = 0x80;
const REQ_SET_NTB_INPUT_SIZE: u8 = 0x86;

// SET_ETHERNET_PACKET_FILTER bits (CDC ECM 1.2 table 62): 0 promiscuous, 1 all
// multicast, 2 directed, 3 broadcast, 4 multicast list.
const FILTER_ALL_MULTICAST: u16 = 1 << 1;
const FILTER_DIRECTED: u16 = 1 << 2;
const FILTER_BROADCAST: u16 = 1 << 3;
/// What the host listens to: its own address, broadcast, every multicast
/// (the stack does the group filtering, as it does on any Ethernet).
const PACKET_FILTER: u16 = FILTER_DIRECTED | FILTER_BROADCAST | FILTER_ALL_MULTICAST;

/// ACM bmCapabilities bit 1: the device takes SET_LINE_CODING,
/// SET_CONTROL_LINE_STATE and GET_LINE_CODING.
const ACM_CAP_LINE: u8 = 1 << 1;
/// NCM bmNetworkCapabilities bit 0: SET_ETHERNET_PACKET_FILTER is supported.
const NCM_CAP_FILTER: u8 = 1 << 0;

/// DTR | RTS of SET_CONTROL_LINE_STATE.
const LINE_ACTIVE: u16 = 0b11;

/// How long one control request of setup may take: the USB 2.0 limit for a
/// request with a data stage (§9.2.6.4).
pub(crate) const CTL_TIMEOUT_US: u64 = 5_000_000;
/// Language the MAC address string is asked in: US English, which every
/// device that has strings has (index 0 lists others; none is needed).
const LANG_EN_US: u16 = 0x0409;

/// Consecutive bad bulk completions that fail a function.
pub const MAX_BAD_RUN: u32 = 32;

// ---- Sizes (Kconfig USB_CDC_BUFS, USB_CDC_NTB_KB) ----

/// Buffers per direction.
pub(crate) const BUFS: usize = azos_limits::USB_CDC_BUFS as usize;
/// NTB buffer of an NCM function.
const NTB_BYTES: usize = azos_limits::USB_CDC_NTB_KB as usize * 1024;
/// Buffer of an ECM function: one frame, VLAN tag included, a multiple of
/// every bulk packet size (64, 512, 1024).
const ECM_BYTES: usize = 2048;
/// Buffer of an ACM function: a multiple of every bulk packet size.
const ACM_BYTES: usize = 1024;
/// Largest Ethernet frame handed up or accepted: header, 1500 of payload, a
/// VLAN tag.
pub const FRAME_MAX: usize = 1518;
/// Smallest: an Ethernet header.
pub const FRAME_MIN: usize = 14;

const _: () = assert!(BUFS >= 2 && BUFS <= crate::PIPE_DEPTH, "USB_CDC_BUFS is at most USB_PIPE_DEPTH");
const _: () = assert!(BUFS <= 8, "the buffer masks are eight bits");
const _: () = assert!(NTB_BYTES % PAGE == 0 && NTB_BYTES >= PAGE && NTB_BYTES <= 60 * 1024);
const _: () = assert!(ECM_BYTES > FRAME_MAX && ACM_BYTES % 64 == 0);

// The control area, the first page of a function's region: the configuration
// descriptor, a string descriptor, the small payloads.
const CFG_OFF: usize = 0;
const CFG_MAX: usize = 1024;
const STR_OFF: usize = 1024;
const STR_MAX: usize = 64;
const SMALL_OFF: usize = 1088;
const SMALL_MAX: usize = 64;
/// The bulk buffers start on the page after.
const POOL_OFF: usize = PAGE;
const _: () = assert!(SMALL_OFF + SMALL_MAX <= PAGE);

// Transfer tags.
const TAG_STEP: u32 = 0x200;
const TAG_OUT: u32 = 0x100;
const TAG_CLEAR_IN: u32 = 0x301;
const TAG_CLEAR_OUT: u32 = 0x302;
const TAG_LINE: u32 = 0x303;

// ---- Shared states ----

/// Why a function is failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// The data interface has no bulk IN and bulk OUT endpoint.
    NoEndpoints,
    /// The core refused a pipe.
    Pipe,
    /// No DMA memory for the buffers.
    NoMemory,
    /// The configuration or a string descriptor is not what a CDC function
    /// of this kind has.
    Descriptor,
    /// The union descriptor names another data interface than the claimed one.
    Mismatch,
    /// The device's NTB parameters cannot be driven (no NTB-16, a block limit
    /// too small for one frame).
    Params,
    /// A setup request failed (the argument is the step's code).
    Control(u8),
    /// A setup request outlived `CTL_TIMEOUT_US`.
    Timeout,
    /// [`MAX_BAD_RUN`] bulk transfers in a row failed.
    Transport,
    /// The device was unplugged.
    Gone,
}

/// Where a function is in the life of one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No device.
    Idle,
    /// A device was claimed; the `usb` task opens its pipes next.
    Claimed,
    /// Pipes open, setup requests running.
    Setup,
    Ready,
    Failed(Fail),
}

// ---- The network transfer block (NCM 1.0, NTB-16) ----

/// NTB-16: parse a received block, build a block to send. Pure functions over
/// bytes, so the host tests feed it blocks the way a hostile device would.
pub mod ntb {
    /// NTH16 signature, "NCMH".
    pub const NTH16_SIG: u32 = 0x484d_434e;
    /// NDP16 signature without CRC, "NCM0".
    pub const NDP16_SIG: u32 = 0x304d_434e;
    /// Bytes of an NTH16.
    pub const NTH16_LEN: usize = 12;
    /// Bytes of an NDP16 before its entries.
    pub const NDP16_HEAD: usize = 8;
    /// Bytes of an NDP16 entry.
    pub const ENTRY_LEN: usize = 4;
    /// Bytes of GET_NTB_PARAMETERS' answer.
    pub const PARAMS_LEN: usize = 28;
    /// Most NDPs chained in one block.
    const MAX_HOPS: u8 = 4;
    /// Datagrams one block built here carries at most.
    pub const TX_MAX_DATAGRAMS: usize = 32;
    /// Alignment values larger than this are taken for a lie.
    const MAX_ALIGN: usize = 64;

    /// A source of bytes: a slice in a test, a DMA buffer in the driver.
    pub trait Bytes {
        fn size(&self) -> usize;
        /// Copy `out.len()` bytes from `off` (the caller has checked the range).
        fn read(&self, off: usize, out: &mut [u8]);
    }

    impl Bytes for [u8] {
        fn size(&self) -> usize {
            self.len()
        }
        fn read(&self, off: usize, out: &mut [u8]) {
            out.copy_from_slice(&self[off..off + out.len()]);
        }
    }

    fn rd<const N: usize, B: Bytes + ?Sized>(b: &B, off: usize) -> Option<[u8; N]> {
        if off.checked_add(N)? > b.size() {
            return None;
        }
        let mut a = [0u8; N];
        b.read(off, &mut a);
        Some(a)
    }

    fn le16(b: &[u8]) -> usize {
        u16::from_le_bytes([b[0], b[1]]) as usize
    }

    /// Why a block is refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum NtbError {
        /// Shorter than its own headers.
        Short,
        /// Not an NTH16.
        Signature,
        /// wHeaderLength is not 12.
        HeaderLength,
        /// wBlockLength is larger than what arrived.
        BlockLength,
        /// wNdpIndex points outside the block.
        NdpIndex,
        /// Not an NDP16 without CRC.
        NdpSignature,
        /// wLength of an NDP is under 16 or runs past the block.
        NdpLength,
        /// A datagram lies outside the block.
        Datagram,
        /// The NDP chain is longer than [`MAX_HOPS`] or goes backwards.
        Chain,
    }

    /// The reading of one received block: its datagrams, one at a time.
    #[derive(Clone, Copy, Debug)]
    pub struct Rx16 {
        /// The end of the block (wBlockLength, or what arrived when it is 0).
        limit: usize,
        /// The NDP being read (0: none left), where its entries end, the
        /// entry to read next, and the NDP that follows.
        ndp: usize,
        ndp_end: usize,
        entry: usize,
        next_ndp: usize,
        hops: u8,
        /// wSequence of the NTH.
        pub sequence: u16,
    }

    impl Rx16 {
        /// Start reading the block in `b`, of which `actual` bytes arrived.
        pub fn open<B: Bytes + ?Sized>(b: &B, actual: usize) -> Result<Rx16, NtbError> {
            let n = b.size().min(actual);
            let h: [u8; NTH16_LEN] = rd(b, 0).filter(|_| n >= NTH16_LEN).ok_or(NtbError::Short)?;
            if u32::from_le_bytes([h[0], h[1], h[2], h[3]]) != NTH16_SIG {
                return Err(NtbError::Signature);
            }
            if le16(&h[4..]) != NTH16_LEN {
                return Err(NtbError::HeaderLength);
            }
            let block = le16(&h[8..]);
            if block > n {
                return Err(NtbError::BlockLength);
            }
            let mut r = Rx16 {
                limit: if block == 0 { n } else { block },
                ndp: 0,
                ndp_end: 0,
                entry: 0,
                next_ndp: 0,
                hops: 0,
                sequence: le16(&h[6..]) as u16,
            };
            r.load(b, le16(&h[10..]))?;
            Ok(r)
        }

        fn load<B: Bytes + ?Sized>(&mut self, b: &B, off: usize) -> Result<(), NtbError> {
            if off < NTH16_LEN || off + NDP16_HEAD + 2 * ENTRY_LEN > self.limit {
                return Err(NtbError::NdpIndex);
            }
            let h: [u8; NDP16_HEAD] = rd(b, off).ok_or(NtbError::NdpIndex)?;
            if u32::from_le_bytes([h[0], h[1], h[2], h[3]]) != NDP16_SIG {
                return Err(NtbError::NdpSignature);
            }
            let len = le16(&h[4..]);
            if len < NDP16_HEAD + 2 * ENTRY_LEN || off + len > self.limit {
                return Err(NtbError::NdpLength);
            }
            self.ndp = off;
            self.ndp_end = off + len;
            self.entry = off + NDP16_HEAD;
            self.next_ndp = le16(&h[6..]);
            Ok(())
        }

        /// The next datagram of the block as (offset, length) from the start
        /// of the block; `None` after the last. An error ends the block: what
        /// was yielded before it stands, nothing more is read.
        #[allow(clippy::type_complexity)]
        pub fn next<B: Bytes + ?Sized>(&mut self, b: &B) -> Result<Option<(usize, usize)>, NtbError> {
            loop {
                if self.ndp == 0 {
                    return Ok(None);
                }
                if self.entry + ENTRY_LEN <= self.ndp_end {
                    let e: [u8; ENTRY_LEN] = rd(b, self.entry).ok_or(NtbError::Short)?;
                    self.entry += ENTRY_LEN;
                    let (idx, len) = (le16(&e), le16(&e[2..]));
                    if idx != 0 && len != 0 {
                        #[cfg(not(feature = "canary-ntb-bounds"))]
                        if idx < NTH16_LEN || idx + len > self.limit {
                            self.ndp = 0;
                            return Err(NtbError::Datagram);
                        }
                        return Ok(Some((idx, len)));
                    }
                }
                // A null entry, or a table that ends without one.
                if self.next_ndp == 0 {
                    self.ndp = 0;
                    return Ok(None);
                }
                self.hops += 1;
                let (cur, next) = (self.ndp, self.next_ndp);
                if self.hops > MAX_HOPS || next <= cur {
                    self.ndp = 0;
                    return Err(NtbError::Chain);
                }
                if let Err(e) = self.load(b, next) {
                    self.ndp = 0;
                    return Err(e);
                }
            }
        }
    }

    /// What GET_NTB_PARAMETERS answers (NCM 1.0 table 6-3).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Params {
        /// bmNtbFormatsSupported: bit 0 NTB-16, bit 1 NTB-32.
        pub formats: u16,
        /// Largest block the device sends.
        pub in_max: u32,
        /// Largest block the device takes (0: not stated).
        pub out_max: u32,
        pub out_divisor: u16,
        pub out_remainder: u16,
        pub out_align: u16,
        /// Most datagrams in a block sent to the device (0: no limit).
        pub out_datagrams: u16,
    }

    impl Params {
        /// Parse the answer; `None` when it is shorter than the table.
        pub fn parse(b: &[u8]) -> Option<Params> {
            if b.len() < PARAMS_LEN || le16(b) < PARAMS_LEN {
                return None;
            }
            let le32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
            Some(Params {
                formats: le16(&b[2..]) as u16,
                in_max: le32(4),
                out_max: le32(16),
                out_divisor: le16(&b[20..]) as u16,
                out_remainder: le16(&b[22..]) as u16,
                out_align: le16(&b[24..]) as u16,
                out_datagrams: le16(&b[26..]) as u16,
            })
        }

        /// The limits of the blocks built for this device, no larger than
        /// `cap` bytes (the caller keeps a byte of its buffer for the pad). A value a device states wrongly (an alignment that is
        /// not a power of two, under 4 or a lie) is replaced by 4, as the
        /// reference host does.
        pub fn tx(&self, cap: usize) -> TxParams {
            let ok = |v: usize, min: usize| v >= min && v <= MAX_ALIGN && v.is_power_of_two();
            let align = if ok(self.out_align as usize, 4) { self.out_align as usize } else { 4 };
            let divisor = if ok(self.out_divisor as usize, 1) { self.out_divisor as usize } else { 4 };
            let remainder = if (self.out_remainder as usize) < divisor { self.out_remainder as usize } else { 0 };
            // The device's limit counts the byte that ends a block on a packet boundary.
            let dev = if self.out_max == 0 { usize::MAX } else { (self.out_max as usize).saturating_sub(1) };
            TxParams {
                max_size: cap.min(dev).min(u16::MAX as usize),
                ndp_align: align,
                divisor,
                remainder,
                max_datagrams: self.out_datagrams as usize,
            }
        }
    }

    /// The limits of the blocks sent to a device.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TxParams {
        /// Bytes of the whole block, at most.
        pub max_size: usize,
        /// Alignment of the NDP (a power of two, 4 or more).
        pub ndp_align: usize,
        /// A datagram starts at an offset that is `remainder` modulo this.
        pub divisor: usize,
        pub remainder: usize,
        /// Datagrams in the block, at most (0: no limit but ours).
        pub max_datagrams: usize,
    }

    /// The building of one block to send: an NTH, the datagrams, the NDP last.
    /// The caller writes through a closure, so the same code fills a DMA
    /// buffer and a `Vec`.
    #[derive(Clone, Copy, Debug)]
    pub struct Tx16 {
        p: TxParams,
        /// The end of what is written.
        pos: usize,
        entries: [(u16, u16); TX_MAX_DATAGRAMS],
        count: usize,
        seq: u16,
    }

    fn align_up(v: usize, a: usize) -> usize {
        v.div_ceil(a) * a
    }

    impl Tx16 {
        pub const fn new(p: TxParams) -> Tx16 {
            Tx16 { p: Self::norm(p), pos: NTH16_LEN, entries: [(0, 0); TX_MAX_DATAGRAMS], count: 0, seq: 0 }
        }

        /// A divisor or an alignment of 0 is 1 (no constraint); a remainder
        /// past the divisor is 0.
        const fn norm(mut p: TxParams) -> TxParams {
            if p.divisor == 0 {
                p.divisor = 1;
            }
            if p.ndp_align == 0 {
                p.ndp_align = 1;
            }
            if p.remainder >= p.divisor {
                p.remainder = 0;
            }
            if p.max_size > u16::MAX as usize {
                p.max_size = u16::MAX as usize;
            }
            p
        }

        /// Forget the block under construction.
        pub fn reset(&mut self) {
            self.pos = NTH16_LEN;
            self.count = 0;
        }

        pub fn is_empty(&self) -> bool {
            self.count == 0
        }

        pub fn count(&self) -> usize {
            self.count
        }

        /// Where a datagram written at `pos` starts, and the length of the
        /// block if it were the last.
        fn place(&self, len: usize) -> (usize, usize) {
            #[cfg_attr(feature = "canary-ntb-align", allow(unused_variables))]
            let d = self.p.divisor;
            #[cfg(not(feature = "canary-ntb-align"))]
            let off = self.pos + (d + self.p.remainder - self.pos % d) % d;
            #[cfg(feature = "canary-ntb-align")]
            let off = self.pos;
            let ndp = align_up(off + len, self.p.ndp_align);
            (off, ndp + NDP16_HEAD + ENTRY_LEN * (self.count + 2))
        }

        /// Would a datagram of `len` bytes still fit?
        pub fn can_add(&self, len: usize) -> bool {
            if len == 0 || len > u16::MAX as usize || self.count >= TX_MAX_DATAGRAMS {
                return false;
            }
            if self.p.max_datagrams != 0 && self.count >= self.p.max_datagrams {
                return false;
            }
            self.place(len).1 <= self.p.max_size
        }

        /// Append a datagram: `put(offset, bytes)` writes into the block.
        /// `false` (nothing written) when it does not fit.
        pub fn add(&mut self, frame: &[u8], put: &mut dyn FnMut(usize, &[u8])) -> bool {
            if !self.can_add(frame.len()) {
                return false;
            }
            let (off, _) = self.place(frame.len());
            if off > self.pos {
                put(self.pos, &[0u8; MAX_ALIGN][..off - self.pos]);
            }
            put(off, frame);
            self.entries[self.count] = (off as u16, frame.len() as u16);
            self.count += 1;
            self.pos = off + frame.len();
            true
        }

        /// Close the block: the NDP after the datagrams, the NTH at the start.
        /// Returns the block's length; the builder is empty again.
        pub fn finish(&mut self, put: &mut dyn FnMut(usize, &[u8])) -> usize {
            let ndp = align_up(self.pos, self.p.ndp_align);
            if ndp > self.pos {
                put(self.pos, &[0u8; MAX_ALIGN][..ndp - self.pos]);
            }
            let ndp_len = NDP16_HEAD + ENTRY_LEN * (self.count + 1);
            let total = ndp + ndp_len;
            let mut head = [0u8; NDP16_HEAD];
            head[0..4].copy_from_slice(&NDP16_SIG.to_le_bytes());
            head[4..6].copy_from_slice(&(ndp_len as u16).to_le_bytes());
            put(ndp, &head);
            for (i, (o, l)) in self.entries[..self.count].iter().enumerate() {
                let mut e = [0u8; ENTRY_LEN];
                e[0..2].copy_from_slice(&o.to_le_bytes());
                e[2..4].copy_from_slice(&l.to_le_bytes());
                put(ndp + NDP16_HEAD + i * ENTRY_LEN, &e);
            }
            put(ndp + NDP16_HEAD + self.count * ENTRY_LEN, &[0u8; ENTRY_LEN]);
            let mut nth = [0u8; NTH16_LEN];
            nth[0..4].copy_from_slice(&NTH16_SIG.to_le_bytes());
            nth[4..6].copy_from_slice(&(NTH16_LEN as u16).to_le_bytes());
            nth[6..8].copy_from_slice(&self.seq.to_le_bytes());
            nth[8..10].copy_from_slice(&(total as u16).to_le_bytes());
            nth[10..12].copy_from_slice(&(ndp as u16).to_le_bytes());
            put(0, &nth);
            self.seq = self.seq.wrapping_add(1);
            self.reset();
            total
        }
    }
}

// ---- The class-specific descriptors ----

/// What the functional descriptors of a communications interface say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommInfo {
    /// The data interface the union descriptor names (the interface after
    /// the communications one when there is no union).
    pub data_iface: u8,
    pub has_union: bool,
    /// iMACAddress of the Ethernet networking descriptor (0: none).
    pub mac_string: u8,
    /// wMaxSegmentSize (0: none stated).
    pub max_segment: u16,
    /// bmNetworkCapabilities of the NCM descriptor.
    pub ncm_caps: u8,
    pub has_ncm: bool,
    /// bmCapabilities of the ACM descriptor.
    pub acm_caps: u8,
    pub has_acm: bool,
}

/// Read the class-specific descriptors that follow interface `comm_iface`
/// (setting 0) in the configuration descriptor `cfg`. A damaged descriptor
/// ends the walk; what was read before it stands.
pub fn parse_comm<B: Bytes + ?Sized>(cfg: &B, comm_iface: u8) -> CommInfo {
    let mut info = CommInfo { data_iface: comm_iface.wrapping_add(1), ..CommInfo::default() };
    let size = cfg.size();
    if size < 9 {
        return info;
    }
    let mut h = [0u8; 4];
    cfg.read(0, &mut h);
    let total = (u16::from_le_bytes([h[2], h[3]]) as usize).min(size);
    let mut off = h[0] as usize;
    let mut here = false;
    while off + 2 <= total {
        let mut d = [0u8; 16];
        let len = {
            let mut l = [0u8; 2];
            cfg.read(off, &mut l);
            l[0] as usize
        };
        if len < 2 || off + len > total {
            break;
        }
        let n = len.min(d.len());
        cfg.read(off, &mut d[..n]);
        match d[1] {
            4 if len >= 9 => here = d[2] == comm_iface && d[3] == 0,
            CS_INTERFACE if here && len >= 3 => match d[2] {
                FUNC_UNION if len >= 5 => {
                    // bControlInterface, then the subordinates.
                    if d[3] == comm_iface {
                        info.data_iface = d[4];
                        info.has_union = true;
                    }
                }
                FUNC_ETHERNET if len >= 13 => {
                    info.mac_string = d[3];
                    info.max_segment = u16::from_le_bytes([d[8], d[9]]);
                }
                FUNC_NCM if len >= 6 => {
                    info.ncm_caps = d[5];
                    info.has_ncm = true;
                }
                FUNC_ACM if len >= 4 => {
                    info.acm_caps = d[3];
                    info.has_acm = true;
                }
                _ => {}
            },
            _ => {}
        }
        off += len;
    }
    info
}

/// The MAC address in an iMACAddress string descriptor: twelve hexadecimal
/// digits in UTF-16, upper or lower case.
pub fn mac_from_string(d: &[u8]) -> Option<[u8; 6]> {
    if d.len() < 2 + 24 || d[1] != DT_STRING || (d[0] as usize) < 2 + 24 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        let hex = |k: usize| -> Option<u8> {
            let (lo, hi) = (d[2 + 2 * k], d[3 + 2 * k]);
            if hi != 0 {
                return None;
            }
            (lo as char).to_digit(16).map(|v| v as u8)
        };
        *m = hex(2 * i)? << 4 | hex(2 * i + 1)?;
    }
    Some(mac)
}

/// Does the union descriptor name the data interface that was claimed?
fn pairs(info: &CommInfo, data: Claim) -> bool {
    cfg!(feature = "canary-mismatch") || info.data_iface == data.iface()
}

/// A window on a DMA buffer, for the parsers.
struct View<'a> {
    buf: &'a DmaBuf,
    off: usize,
    len: usize,
}

impl Bytes for View<'_> {
    fn size(&self) -> usize {
        self.len
    }
    fn read(&self, off: usize, out: &mut [u8]) {
        self.buf.read_bytes(self.off + off, out);
    }
}

// ---- What both functions share: the claims, the pipes ----

/// The two claims of a function and the pipes opened on them.
struct Bind<'q> {
    comm: Option<Claim>,
    data: Option<Claim>,
    vid_pid: u32,
    /// Control pipes of the communications claim and the data claim.
    ctl_c: Option<PipeEnd<'q>>,
    ctl_d: Option<PipeEnd<'q>>,
    bin: Option<PipeEnd<'q>>,
    bout: Option<PipeEnd<'q>>,
    ep_in: u8,
    ep_out: u8,
    mps_out: u16,
    /// The alternate setting that has the bulk endpoints.
    alt: u8,
}

impl<'q> Bind<'q> {
    const fn new() -> Bind<'q> {
        Bind {
            comm: None,
            data: None,
            vid_pid: 0,
            ctl_c: None,
            ctl_d: None,
            bin: None,
            bout: None,
            ep_in: 0,
            ep_out: 0,
            mps_out: 0,
            alt: 0,
        }
    }

    fn owns(&self, c: Claim) -> bool {
        self.comm == Some(c) || self.data == Some(c)
    }

    /// Take an interface if it is this function's to take: a communications
    /// interface of a subclass `comm_ok` accepts, or the data interface that
    /// follows one already held on the same device.
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, comm_ok: fn(u8) -> bool) -> u32 {
        let c = Claim(claim);
        if c.is_device_scope() {
            return BAD_ARGUMENT;
        }
        let (class, sub) = ((triple >> 16) as u8, (triple >> 8) as u8);
        match class {
            CLASS_COMM if comm_ok(sub) => {
                if self.comm.is_some() {
                    return BUSY;
                }
                self.comm = Some(c);
                self.vid_pid = vid_pid;
                OK
            }
            CLASS_DATA if sub == 0 => match self.comm {
                Some(m) if m.slot() == c.slot() && m.generation() == c.generation() && self.data.is_none() => {
                    self.data = Some(c);
                    OK
                }
                _ => UNSUPPORTED,
            },
            _ => UNSUPPORTED,
        }
    }

    /// The claim to open a session for next.
    fn wanted(&self) -> Option<Claim> {
        let (c, d) = (self.comm?, self.data?);
        if self.ctl_c.is_none() {
            Some(c)
        } else if self.bout.is_none() {
            Some(d)
        } else {
            None
        }
    }

    fn all_open(&self) -> bool {
        self.ctl_c.is_some() && self.ctl_d.is_some() && self.bin.is_some() && self.bout.is_some()
    }

    /// Open what the session `dev` is for: the control pipe of the
    /// communications claim, or the control and bulk pipes of the data claim.
    fn open(&mut self, rings: &'q [PipeRings], dev: &mut dyn UsbDevice) -> Result<(), Fail> {
        if self.ctl_c.is_none() {
            self.ctl_c = Some(open_one(dev, rings, 0)?);
            return Ok(());
        }
        let alt = dev.info(6);
        self.alt = if alt.code == OK { alt.value as u8 } else { 0 };
        let n = dev.info(4);
        if n.code != OK {
            return Err(Fail::Pipe);
        }
        let (mut ep_in, mut ep_out) = (None, None);
        for i in 0..n.value as u32 {
            let e = dev.endpoint(i);
            if e.code != OK || (e.value >> 8) & 3 != 2 {
                continue; // not bulk
            }
            let (addr, mps) = ((e.value & 0xff) as u8, (e.value >> 16) as u16);
            if addr & 0x80 != 0 {
                ep_in.get_or_insert(addr);
            } else if ep_out.is_none() {
                ep_out = Some((addr, mps));
            }
        }
        let (Some(ep_in), Some((ep_out, mps_out))) = (ep_in, ep_out) else { return Err(Fail::NoEndpoints) };
        if mps_out == 0 {
            return Err(Fail::NoEndpoints);
        }
        let mut ends: [Option<PipeEnd<'q>>; 3] = [None, None, None];
        let mut result = Ok(());
        for (end, ep) in ends.iter_mut().zip([0, ep_in, ep_out]) {
            match open_one(dev, rings, ep) {
                Ok(e) => *end = Some(e),
                Err(f) => {
                    result = Err(f);
                    break;
                }
            }
        }
        match (result, ends) {
            (Ok(()), [Some(ctl), Some(bin), Some(bout)]) => {
                self.ctl_d = Some(ctl);
                self.bin = Some(bin);
                self.bout = Some(bout);
                self.ep_in = ep_in;
                self.ep_out = ep_out;
                self.mps_out = mps_out;
                Ok(())
            }
            (r, ends) => {
                // Nothing was queued: give back what this session took.
                for e in ends.into_iter().flatten() {
                    let id = e.id;
                    drop(e);
                    let _ = dev.pipe_close(id as u32);
                }
                Err(r.err().unwrap_or(Fail::Pipe))
            }
        }
    }

    /// Submit a control request on the communications (`data`: the data
    /// claim's) control pipe.
    fn ctl(&mut self, data: bool, tag: u32, s: Setup, buf: u64) -> bool {
        let p = if data { self.ctl_d.as_mut() } else { self.ctl_c.as_mut() };
        let Some(p) = p else { return false };
        let t = Transfer {
            tag,
            dir: if s.is_in() { Dir::In } else { Dir::Out },
            setup: s.to_bytes(),
            buf,
            len: s.length as u32,
        };
        matches!(p.sq.push(t), Push::Pushed)
    }

    fn submit(pipe: &mut Option<PipeEnd<'q>>, tag: u32, dir: Dir, buf: u64, len: u32) -> bool {
        let Some(p) = pipe.as_mut() else { return false };
        matches!(p.sq.push(Transfer { tag, dir, setup: [0; 8], buf, len }), Push::Pushed)
    }

    fn submit_in(&mut self, tag: u32, buf: u64, len: u32) -> bool {
        Self::submit(&mut self.bin, tag, Dir::In, buf, len)
    }

    fn submit_out(&mut self, tag: u32, buf: u64, len: u32) -> bool {
        Self::submit(&mut self.bout, tag, Dir::Out, buf, len)
    }

    fn pop_in(&mut self) -> Option<Completion> {
        self.bin.as_mut()?.cq.pop()
    }

    fn pop_out(&mut self) -> Option<Completion> {
        self.bout.as_mut()?.cq.pop()
    }

    /// A control completion of either pipe.
    fn pop_ctl(&mut self) -> Option<Completion> {
        if let Some(c) = self.ctl_c.as_mut().and_then(|p| p.cq.pop()) {
            return Some(c);
        }
        self.ctl_d.as_mut()?.cq.pop()
    }

    /// Let go of every pipe end (draining what the core completed as
    /// disconnected) and of the claims.
    fn release(&mut self) {
        for p in [&mut self.ctl_c, &mut self.ctl_d, &mut self.bin, &mut self.bout] {
            if let Some(mut e) = p.take() {
                while e.cq.pop().is_some() {}
            }
        }
        *self = Bind::new();
    }
}

/// Open the pipe of endpoint `ep` (0: control) and take the driver's ends of
/// its rings.
pub(crate) fn open_one<'q>(dev: &mut dyn UsbDevice, rings: &'q [PipeRings], ep: u8) -> Result<PipeEnd<'q>, Fail> {
    let p = dev.pipe_open(ep as u32);
    if p.code != OK {
        return Err(Fail::Pipe);
    }
    let id = p.value as u8;
    match rings.get(id as usize).and_then(|r| PipeEnd::take(r, id)) {
        Some(e) => Ok(e),
        None => {
            let _ = dev.pipe_close(id as u32);
            Err(Fail::Pipe)
        }
    }
}

fn class_in(request: u8, value: u16, index: u16, length: u16) -> Setup {
    Setup { request_type: RT_DIR_IN | RT_TYPE_CLASS | RT_RECIP_INTERFACE, request, value, index, length }
}

fn class_out(request: u8, value: u16, index: u16, length: u16) -> Setup {
    Setup { request_type: RT_TYPE_CLASS | RT_RECIP_INTERFACE, request, value, index, length }
}

/// SET_INTERFACE to the data claim's interface.
fn set_interface(iface: u8, alt: u8) -> Setup {
    Setup {
        request_type: RT_TYPE_STANDARD | RT_RECIP_INTERFACE,
        request: REQ_SET_INTERFACE,
        value: alt as u16,
        index: iface as u16,
        length: 0,
    }
}

fn get_config(len: u16) -> Setup {
    Setup::get_descriptor(DT_CONFIG, 0, 0, len)
}

fn get_string(index: u8, len: u16) -> Setup {
    Setup::get_descriptor(DT_STRING, index, LANG_EN_US, len)
}

/// The halts of the bulk pipes still to clear, and the request clearing one.
#[derive(Clone, Copy, Default)]
struct Halts {
    clear_in: bool,
    clear_out: bool,
    /// The tag of the CLEAR_FEATURE on the wire (0: none).
    busy: u32,
}

impl Halts {
    /// Collect a finished clear and start the next one. `true` when a
    /// request was queued.
    fn poll(&mut self, b: &mut Bind<'_>, done: Option<Completion>) -> bool {
        if done.is_some_and(|c| c.tag == self.busy) {
            self.busy = 0;
        }
        if self.busy != 0 || cfg!(feature = "canary-no-clear-halt") {
            return false;
        }
        let (tag, ep) = if self.clear_in {
            (TAG_CLEAR_IN, b.ep_in)
        } else if self.clear_out {
            (TAG_CLEAR_OUT, b.ep_out)
        } else {
            return false;
        };
        if !b.ctl(true, tag, Setup::clear_halt(ep), 0) {
            return false; // try again next turn
        }
        if tag == TAG_CLEAR_IN {
            self.clear_in = false;
        } else {
            self.clear_out = false;
        }
        self.busy = tag;
        true
    }

    /// Bulk IN is halted or being cleared: do not post to it.
    fn in_blocked(&self) -> bool {
        self.clear_in || self.busy == TAG_CLEAR_IN
    }
}

// ============================================================================
// Network: CDC-ECM and CDC-NCM
// ============================================================================

/// Which Ethernet function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ecm,
    Ncm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Config,
    MacString,
    NtbParams,
    NtbInput,
    SetAlt,
    Filter,
}

impl Step {
    const fn code(self) -> u8 {
        match self {
            Step::Config => 1,
            Step::MacString => 2,
            Step::NtbParams => 3,
            Step::NtbInput => 4,
            Step::SetAlt => 5,
            Step::Filter => 6,
        }
    }
}

/// What a network function counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    /// Frames handed up, and frames accepted for sending.
    pub rx_frames: u32,
    pub tx_frames: u32,
    /// Transfers received and sent (an NCM block carries several frames).
    pub rx_transfers: u32,
    pub tx_transfers: u32,
    /// Blocks refused, or cut short at a bad field.
    pub ntb_malformed: u32,
    /// Received frames larger than the caller's buffer, or under an Ethernet
    /// header.
    pub rx_dropped: u32,
    /// Bad bulk completions (counted, the buffer posted again).
    pub rx_errors: u32,
    pub tx_errors: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RxSlot {
    Free,
    Posted,
    /// Completed; its frames are not all taken.
    Held,
}

#[derive(Clone, Copy)]
enum Cursor {
    None,
    /// ECM: the one frame of `len` bytes, if not taken.
    Ecm { len: u32, taken: bool },
    Ncm(Rx16),
}

#[derive(Clone, Copy)]
struct RxBuf {
    slot: RxSlot,
    cursor: Cursor,
}

/// A CDC-ECM or CDC-NCM function as a NIC.
pub struct CdcNet<'q, M: Memory, C: Clock> {
    mem: M,
    clock: C,
    mask: u64,
    rings: &'q [PipeRings],
    state: State,
    kind: Option<Kind>,
    bind: Bind<'q>,
    /// The core told us the device is gone; clean up on the next turn.
    gone: bool,
    region: Option<DmaBuf>,
    step: Step,
    step_deadline_us: u64,
    // What setup learned.
    info: CommInfo,
    mac: [u8; 6],
    ntb_params: ntb::Params,
    /// Bytes of one bulk buffer, and the largest frame accepted.
    stride: usize,
    seg_max: usize,
    // Receive.
    rx: [RxBuf; BUFS],
    fifo: [u8; BUFS],
    fifo_head: usize,
    fifo_len: usize,
    // Transmit.
    tx_busy: [bool; BUFS],
    tx16: Tx16,
    /// The buffer the block under construction is in.
    tx_open: Option<usize>,
    batching: bool,
    halts: Halts,
    bad_run: u32,
    submitted: bool,
    stats: NetStats,
}

impl<'q, M: Memory, C: Clock> CdcNet<'q, M, C> {
    /// A function with no device. `mask` is the controller's DMA mask,
    /// `rings` the pipe rings the core indexes by pipe number.
    pub fn new(mem: M, clock: C, mask: u64, rings: &'q [PipeRings]) -> Self {
        CdcNet {
            mem,
            clock,
            mask,
            rings,
            state: State::Idle,
            kind: None,
            bind: Bind::new(),
            gone: false,
            region: None,
            step: Step::Config,
            step_deadline_us: 0,
            info: CommInfo::default(),
            mac: [0; 6],
            ntb_params: ntb::Params::default(),
            stride: 0,
            seg_max: 0,
            rx: [RxBuf { slot: RxSlot::Free, cursor: Cursor::None }; BUFS],
            fifo: [0; BUFS],
            fifo_head: 0,
            fifo_len: 0,
            tx_busy: [false; BUFS],
            tx16: Tx16::new(TxParams { max_size: 0, ndp_align: 4, divisor: 4, remainder: 0, max_datagrams: 0 }),
            tx_open: None,
            batching: false,
            halts: Halts::default(),
            bad_run: 0,
            submitted: false,
            stats: NetStats::default(),
        }
    }

    /// The rule of the communications interface (ECM and NCM are told apart
    /// by [`UsbClass::attach`]; an ACM interface is declined there).
    pub const fn comm_rule() -> Match {
        Match::interface_class(CLASS_COMM)
    }

    /// The rule of the data interface.
    pub const fn data_rule() -> Match {
        Match::interface_class(CLASS_DATA)
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn kind(&self) -> Option<Kind> {
        self.kind
    }

    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    /// The MAC address the device states; all-zero before setup learned it.
    pub fn mac(&self) -> [u8; 6] {
        if self.state == State::Ready { self.mac } else { [0; 6] }
    }

    pub fn vid_pid(&self) -> u32 {
        self.bind.vid_pid
    }

    pub fn stats(&self) -> NetStats {
        self.stats
    }

    /// Whether a transfer went into a pipe since the last call: the core
    /// moves it to the controller on its next turn, so whoever runs the core
    /// is woken when this is true.
    pub fn take_submitted(&mut self) -> bool {
        core::mem::take(&mut self.submitted)
    }

    /// Whether received buffers wait for the stack to take their frames (as of
    /// the last [`CdcNet::service`] or [`CdcNet::recv`]): the signal for whoever
    /// runs the stack's receive pass.
    pub fn rx_pending(&self) -> bool {
        self.fifo_len > 0
    }

    // ---- Binding ----

    /// The claim to open a session for next (the communications claim, then
    /// the data claim); `None` when there is nothing to open.
    pub fn session_wanted(&self) -> Option<Claim> {
        if self.state == State::Claimed { self.bind.wanted() } else { None }
    }

    /// Open the pipes of the claim [`CdcNet::session_wanted`] named through
    /// `dev`; after the second session the function starts its setup.
    pub fn open(&mut self, dev: &mut dyn UsbDevice) {
        if self.state != State::Claimed {
            return;
        }
        if let Err(f) = self.bind.open(self.rings, dev) {
            return self.fail(f);
        }
        if self.bind.all_open() {
            self.start();
        }
    }

    fn start(&mut self) {
        let Some(kind) = self.kind else { return self.fail(Fail::Descriptor) };
        self.stride = match kind {
            Kind::Ecm => ECM_BYTES,
            Kind::Ncm => NTB_BYTES,
        };
        let pool = (2 * BUFS * self.stride).next_multiple_of(PAGE);
        match self.mem.alloc_region(POOL_OFF + pool, PAGE, self.mask) {
            Some(r) => self.region = Some(r),
            None => return self.fail(Fail::NoMemory),
        }
        self.state = State::Setup;
        self.go(Step::Config);
    }

    fn fail(&mut self, f: Fail) {
        self.state = State::Failed(f);
    }

    // ---- Setup ----

    /// Run `step`: queue its request.
    fn go(&mut self, step: Step) {
        let Some(region) = self.region else { return };
        self.step = step;
        self.step_deadline_us = self.clock.now_us() + CTL_TIMEOUT_US;
        let tag = TAG_STEP | step.code() as u32;
        let (comm, data) = match (self.bind.comm, self.bind.data) {
            (Some(c), Some(d)) => (c.iface(), d.iface()),
            _ => return self.fail(Fail::Gone),
        };
        let ok = match step {
            Step::Config => self.bind.ctl(false, tag, get_config(CFG_MAX as u16), region.bus_at(CFG_OFF)),
            Step::MacString => self.bind.ctl(false, tag, get_string(self.info.mac_string, STR_MAX as u16), region.bus_at(STR_OFF)),
            Step::NtbParams => {
                self.bind.ctl(false, tag, class_in(REQ_GET_NTB_PARAMETERS, 0, comm as u16, ntb::PARAMS_LEN as u16), region.bus_at(SMALL_OFF))
            }
            Step::NtbInput => {
                // dwNtbInMaxSize: what the device may send, no more than a buffer of ours.
                region.write_bytes(SMALL_OFF, &(self.stride as u32).to_le_bytes());
                self.mem.to_device(region.cpu().wrapping_add(SMALL_OFF), 4);
                self.bind.ctl(false, tag, class_out(REQ_SET_NTB_INPUT_SIZE, 0, comm as u16, 4), region.bus_at(SMALL_OFF))
            }
            Step::SetAlt => self.bind.ctl(true, tag, set_interface(data, self.bind.alt), 0),
            Step::Filter => self.bind.ctl(false, tag, class_out(REQ_SET_PACKET_FILTER, PACKET_FILTER, comm as u16, 0), 0),
        };
        if ok {
            self.submitted = true;
        } else {
            self.fail(Fail::Control(step.code()));
        }
    }

    /// The step after `step`, given what is known.
    fn next_step(&self, step: Step) -> Option<Step> {
        let ncm = self.kind == Some(Kind::Ncm);
        let alt = |s: &Self| if s.bind.alt != 0 { Some(Step::SetAlt) } else { s.filter_step() };
        match step {
            Step::Config => Some(Step::MacString),
            Step::MacString if ncm => Some(Step::NtbParams),
            Step::MacString => alt(self),
            Step::NtbParams
                if !cfg!(feature = "canary-ntb-input-size")
                    && (self.ntb_params.in_max == 0 || self.ntb_params.in_max as usize > self.stride) =>
            {
                Some(Step::NtbInput)
            }
            Step::NtbParams | Step::NtbInput => alt(self),
            Step::SetAlt => self.filter_step(),
            Step::Filter => None,
        }
    }

    fn filter_step(&self) -> Option<Step> {
        let has = match self.kind {
            Some(Kind::Ecm) => true,
            _ => self.info.ncm_caps & NCM_CAP_FILTER != 0,
        };
        if has { Some(Step::Filter) } else { None }
    }

    fn on_step(&mut self, c: Completion) {
        let step = self.step;
        if c.tag != TAG_STEP | step.code() as u32 {
            return;
        }
        if c.status != Status::Ok {
            // A device that refuses the packet filter is used anyway.
            if step != Step::Filter {
                return self.fail(Fail::Control(step.code()));
            }
        } else if let Err(f) = self.learn(step, c.actual as usize) {
            return self.fail(f);
        }
        match self.next_step(step) {
            Some(next) => self.go(next),
            None => self.finish_setup(),
        }
    }

    /// Take in what `step` read.
    fn learn(&mut self, step: Step, actual: usize) -> Result<(), Fail> {
        let Some(region) = self.region else { return Err(Fail::Gone) };
        match step {
            Step::Config => {
                let n = actual.min(CFG_MAX);
                self.mem.from_device(region.cpu().wrapping_add(CFG_OFF), n);
                let cfg = View { buf: &region, off: CFG_OFF, len: n };
                let comm = self.bind.comm.ok_or(Fail::Gone)?;
                let data = self.bind.data.ok_or(Fail::Gone)?;
                let info = parse_comm(&cfg, comm.iface());
                if !pairs(&info, data) {
                    return Err(Fail::Mismatch);
                }
                if info.mac_string == 0 || (self.kind == Some(Kind::Ncm) && !info.has_ncm) {
                    return Err(Fail::Descriptor);
                }
                self.info = info;
                self.seg_max = match info.max_segment as usize {
                    0 => 1514,
                    m if (FRAME_MIN..=FRAME_MAX).contains(&m) => m,
                    m if m > FRAME_MAX => FRAME_MAX,
                    _ => return Err(Fail::Params),
                };
            }
            Step::MacString => {
                let n = actual.min(STR_MAX);
                self.mem.from_device(region.cpu().wrapping_add(STR_OFF), n);
                let mut d = [0u8; STR_MAX];
                region.read_bytes(STR_OFF, &mut d[..n]);
                self.mac = mac_from_string(&d[..n]).ok_or(Fail::Descriptor)?;
            }
            Step::NtbParams => {
                self.mem.from_device(region.cpu().wrapping_add(SMALL_OFF), ntb::PARAMS_LEN);
                let mut d = [0u8; ntb::PARAMS_LEN];
                region.read_bytes(SMALL_OFF, &mut d);
                let p = ntb::Params::parse(&d[..actual.min(ntb::PARAMS_LEN)]).ok_or(Fail::Descriptor)?;
                if p.formats & 1 == 0 {
                    return Err(Fail::Params);
                }
                // One byte is kept for the pad that ends a block on a packet boundary.
                let tx = p.tx(self.stride.saturating_sub(1));
                let mut probe = Tx16::new(tx);
                if !probe.can_add(self.seg_max) {
                    return Err(Fail::Params);
                }
                probe.reset();
                self.tx16 = probe;
                self.ntb_params = p;
            }
            Step::NtbInput | Step::SetAlt | Step::Filter => {}
        }
        Ok(())
    }

    fn finish_setup(&mut self) {
        self.state = State::Ready;
        self.fill_rx();
    }

    // ---- The turn of the machine ----

    /// Advance: take what the core completed, start the next step, post
    /// receive buffers, clear halts, fail what outlived its deadline, clean
    /// up after an unplug.
    pub fn service(&mut self) {
        if self.gone {
            return self.cleanup();
        }
        match self.state {
            State::Setup => {
                while let Some(c) = self.bind.pop_ctl() {
                    self.on_step(c);
                    if self.state != State::Setup {
                        break;
                    }
                }
                if self.state == State::Setup && self.clock.now_us() > self.step_deadline_us {
                    self.fail(Fail::Timeout);
                }
            }
            State::Ready => {
                self.reap_rx();
                self.reap_tx();
                loop {
                    let done = self.bind.pop_ctl();
                    let more = done.is_some();
                    if self.halts.poll(&mut self.bind, done) {
                        self.submitted = true;
                    }
                    if !more {
                        break;
                    }
                }
                self.fill_rx();
            }
            _ => {}
        }
    }

    fn cleanup(&mut self) {
        self.bind.release();
        if let Some(r) = self.region.take() {
            self.mem.free_region(r);
        }
        self.state = State::Idle;
        self.kind = None;
        self.gone = false;
        self.fifo_head = 0;
        self.fifo_len = 0;
        self.rx = [RxBuf { slot: RxSlot::Free, cursor: Cursor::None }; BUFS];
        self.tx_busy = [false; BUFS];
        self.tx_open = None;
        self.batching = false;
        self.halts = Halts::default();
        self.bad_run = 0;
        self.mac = [0; 6];
        self.tx16.reset();
        // The counters are the function's life, not the device's.
    }

    // ---- Receive ----

    fn rx_off(&self, i: usize) -> usize {
        POOL_OFF + i * self.stride
    }

    fn tx_off(&self, i: usize) -> usize {
        POOL_OFF + (BUFS + i) * self.stride
    }

    /// Post every free receive buffer.
    fn fill_rx(&mut self) {
        if self.state != State::Ready || self.halts.in_blocked() {
            return;
        }
        let Some(region) = self.region else { return };
        for i in 0..BUFS {
            if self.rx[i].slot != RxSlot::Free {
                continue;
            }
            if !self.bind.submit_in(i as u32, region.bus_at(self.rx_off(i)), self.stride as u32) {
                break;
            }
            self.rx[i].slot = RxSlot::Posted;
            self.submitted = true;
        }
    }

    fn reap_rx(&mut self) {
        while let Some(c) = self.bind.pop_in() {
            let i = (c.tag & 0xff) as usize;
            if i >= BUFS || self.rx[i].slot != RxSlot::Posted {
                continue;
            }
            self.rx[i].slot = RxSlot::Free;
            match c.status {
                Status::Ok => {
                    self.bad_run = 0;
                    if c.actual > 0 {
                        self.hold(i, c.actual as usize);
                    }
                }
                Status::Disconnected => {}
                Status::Stall => self.halts.clear_in = true,
                _ => self.bad(false),
            }
        }
    }

    /// A buffer arrived: keep it until its frames are taken.
    fn hold(&mut self, i: usize, actual: usize) {
        let Some(region) = self.region else { return };
        let actual = actual.min(self.stride);
        self.mem.from_device(region.cpu().wrapping_add(self.rx_off(i)), actual);
        self.stats.rx_transfers += 1;
        let cursor = match self.kind {
            Some(Kind::Ncm) => {
                let view = View { buf: &region, off: self.rx_off(i), len: actual };
                match Rx16::open(&view, actual) {
                    Ok(r) => Cursor::Ncm(r),
                    Err(_) => {
                        self.stats.ntb_malformed += 1;
                        return;
                    }
                }
            }
            _ => Cursor::Ecm { len: actual as u32, taken: false },
        };
        self.rx[i] = RxBuf { slot: RxSlot::Held, cursor };
        self.fifo[(self.fifo_head + self.fifo_len) % BUFS] = i as u8;
        self.fifo_len += 1;
    }

    fn bad(&mut self, tx: bool) {
        if tx {
            self.stats.tx_errors += 1;
        } else {
            self.stats.rx_errors += 1;
        }
        self.bad_run += 1;
        if self.bad_run >= MAX_BAD_RUN {
            self.fail(Fail::Transport);
        }
    }

    /// The next frame of the buffer at the head of the queue: (offset in the
    /// region, length), `None` when it has no more.
    fn next_frame(&mut self, i: usize) -> Option<(usize, usize)> {
        let region = self.region?;
        let base = self.rx_off(i);
        match self.rx[i].cursor {
            Cursor::Ecm { len, taken } => {
                if taken {
                    return None;
                }
                self.rx[i].cursor = Cursor::Ecm { len, taken: true };
                Some((base, len as usize))
            }
            Cursor::Ncm(mut r) => {
                // The view is as long as the buffer: `open` bounded the block.
                let view = View { buf: &region, off: base, len: self.stride };
                let next = r.next(&view);
                self.rx[i].cursor = Cursor::Ncm(r);
                match next {
                    Ok(Some((off, len))) => Some((base + off, len)),
                    Ok(None) => None,
                    Err(_) => {
                        self.stats.ntb_malformed += 1;
                        None
                    }
                }
            }
            Cursor::None => None,
        }
    }

    /// Copy the next received frame into `out`; the frame's length, 0 when
    /// there is none. A frame larger than `out`, or smaller than an Ethernet
    /// header, is dropped and counted.
    pub fn recv(&mut self, out: &mut [u8]) -> usize {
        if self.state != State::Ready {
            return 0;
        }
        self.reap_rx();
        let Some(region) = self.region else { return 0 };
        while self.fifo_len > 0 {
            let i = self.fifo[self.fifo_head] as usize;
            match self.next_frame(i) {
                Some((off, len)) => {
                    if len < FRAME_MIN || len > out.len() {
                        self.stats.rx_dropped += 1;
                        continue;
                    }
                    region.read_bytes(off, &mut out[..len]);
                    self.stats.rx_frames += 1;
                    return len;
                }
                None => {
                    // Taken it all: the buffer goes back to the device.
                    self.rx[i] = RxBuf { slot: RxSlot::Free, cursor: Cursor::None };
                    self.fifo_head = (self.fifo_head + 1) % BUFS;
                    self.fifo_len -= 1;
                    self.fill_rx();
                }
            }
        }
        0
    }

    // ---- Transmit ----

    fn reap_tx(&mut self) {
        while let Some(c) = self.bind.pop_out() {
            let i = (c.tag & 0xff) as usize;
            if c.tag & TAG_OUT == 0 || i >= BUFS || !self.tx_busy[i] {
                continue;
            }
            self.tx_busy[i] = false;
            match c.status {
                Status::Ok => self.bad_run = 0,
                Status::Disconnected => {}
                Status::Stall => {
                    self.halts.clear_out = true;
                    self.stats.tx_errors += 1;
                }
                _ => self.bad(true),
            }
        }
    }

    fn free_tx(&self) -> Option<usize> {
        (0..BUFS).find(|&i| !self.tx_busy[i] && self.tx_open != Some(i))
    }

    /// Send the frame (a whole Ethernet frame, header included). `Err` says
    /// why nothing was queued.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), SendError> {
        if self.state != State::Ready {
            return Err(SendError::NotReady);
        }
        if frame.len() < FRAME_MIN || frame.len() > self.seg_max {
            return Err(SendError::BadLength);
        }
        self.reap_tx();
        match self.kind {
            Some(Kind::Ncm) => self.send_ncm(frame)?,
            _ => self.send_ecm(frame)?,
        }
        self.stats.tx_frames += 1;
        Ok(())
    }

    fn send_ecm(&mut self, frame: &[u8]) -> Result<(), SendError> {
        let (Some(region), Some(i)) = (self.region, self.free_tx()) else { return Err(SendError::QueueFull) };
        let off = self.tx_off(i);
        region.write_bytes(off, frame);
        #[cfg_attr(feature = "canary-zlp-pad", allow(unused_mut))]
        let mut n = frame.len();
        // A frame that ends on a packet boundary needs a short packet after
        // it, and the core queues no zero-length transfer: one byte of padding.
        #[cfg(not(feature = "canary-zlp-pad"))]
        if n % self.bind.mps_out as usize == 0 {
            region.write_bytes(off + n, &[0]);
            n += 1;
        }
        self.mem.to_device(region.cpu().wrapping_add(off), n);
        self.submit_tx(i, n)
    }

    fn submit_tx(&mut self, i: usize, n: usize) -> Result<(), SendError> {
        let Some(region) = self.region else { return Err(SendError::NotReady) };
        if !self.bind.submit_out(TAG_OUT | i as u32, region.bus_at(self.tx_off(i)), n as u32) {
            return Err(SendError::QueueFull);
        }
        self.tx_busy[i] = true;
        self.stats.tx_transfers += 1;
        self.submitted = true;
        Ok(())
    }

    fn send_ncm(&mut self, frame: &[u8]) -> Result<(), SendError> {
        let Some(region) = self.region else { return Err(SendError::NotReady) };
        if self.tx_open.is_some() && !self.tx16.can_add(frame.len()) {
            self.flush()?;
        }
        let i = match self.tx_open {
            Some(i) => i,
            None => {
                let i = self.free_tx().ok_or(SendError::QueueFull)?;
                self.tx_open = Some(i);
                self.tx16.reset();
                i
            }
        };
        let base = self.tx_off(i);
        let added = self.tx16.add(frame, &mut |off, b| region.write_bytes(base + off, b));
        if !added {
            // An empty block that cannot take a frame: the parameters were
            // checked at setup, so this does not happen; refuse, do not spin.
            self.tx_open = None;
            return Err(SendError::BadLength);
        }
        if !self.batching {
            self.flush()?;
        }
        Ok(())
    }

    /// Close the block under construction and queue it.
    pub fn flush(&mut self) -> Result<(), SendError> {
        let (Some(region), Some(i)) = (self.region, self.tx_open) else { return Ok(()) };
        let base = self.tx_off(i);
        #[cfg_attr(feature = "canary-zlp-pad", allow(unused_mut))]
        let mut n = self.tx16.finish(&mut |off, b| region.write_bytes(base + off, b));
        self.tx_open = None;
        // The block states its own length: the pad that ends it on a packet boundary
        // is outside it (the builder kept a byte for it).
        #[cfg(not(feature = "canary-zlp-pad"))]
        if n % self.bind.mps_out as usize == 0 {
            region.write_bytes(base + n, &[0]);
            n += 1;
        }
        self.mem.to_device(region.cpu().wrapping_add(base), n);
        self.submit_tx(i, n)
    }

    /// Open a batch: frames sent until [`CdcNet::tx_end`] share blocks.
    pub fn tx_begin(&mut self) {
        self.batching = true;
    }

    /// Close the batch and queue what it built.
    pub fn tx_end(&mut self) {
        self.batching = false;
        let _ = self.flush();
    }
}

impl<M: Memory, C: Clock> super::net::NetFunction for CdcNet<'_, M, C> {
    const RULES: &'static [Match] = &[Self::comm_rule(), Self::data_rule()];

    fn session_wanted(&self) -> Option<Claim> {
        CdcNet::session_wanted(self)
    }
    fn open(&mut self, dev: &mut dyn UsbDevice) {
        CdcNet::open(self, dev)
    }
    fn service(&mut self) {
        CdcNet::service(self)
    }
    fn is_ready(&self) -> bool {
        CdcNet::is_ready(self)
    }
    fn rx_pending(&self) -> bool {
        CdcNet::rx_pending(self)
    }
    fn take_submitted(&mut self) -> bool {
        CdcNet::take_submitted(self)
    }
    fn mac(&self) -> [u8; 6] {
        CdcNet::mac(self)
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), SendError> {
        CdcNet::send(self, frame)
    }
    fn recv(&mut self, out: &mut [u8]) -> usize {
        CdcNet::recv(self, out)
    }
    fn tx_begin(&mut self) {
        CdcNet::tx_begin(self)
    }
    fn tx_end(&mut self) {
        CdcNet::tx_end(self)
    }
}

/// Why [`CdcNet::send`] queued nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    NotReady,
    /// Under an Ethernet header, or over the device's segment size.
    BadLength,
    /// No transmit buffer is free right now.
    QueueFull,
}

impl<M: Memory, C: Clock> UsbClass for CdcNet<'_, M, C> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, _speed_port: u32) -> Out<u32> {
        if self.gone || !matches!(self.state, State::Idle | State::Claimed) {
            return Out::new(BUSY, 0);
        }
        let sub = (triple >> 8) as u8;
        let kind = match ((triple >> 16) as u8, sub) {
            (CLASS_COMM, SUBCLASS_ECM) => Some(Kind::Ecm),
            (CLASS_COMM, SUBCLASS_NCM) => Some(Kind::Ncm),
            _ => None,
        };
        let code = self.bind.attach(claim, vid_pid, triple, |s| s == SUBCLASS_ECM || s == SUBCLASS_NCM);
        if code == OK {
            if kind.is_some() {
                self.kind = kind;
            }
            self.state = State::Claimed;
        }
        Out::new(code, 0)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        if self.bind.owns(Claim(claim)) {
            // The core killed the pipes: what was queued completes as
            // disconnected, and the ring ends are let go of by `service`.
            self.gone = true;
            self.state = State::Failed(Fail::Gone);
        }
        Out::new(OK, 0)
    }
}

// ============================================================================
// Serial: CDC-ACM as a Uart
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcmStep {
    Config,
    SetAlt,
}

impl AcmStep {
    const fn code(self) -> u8 {
        match self {
            AcmStep::Config => 1,
            AcmStep::SetAlt => 5,
        }
    }
}

/// What a serial function counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcmStats {
    /// Chunks the receive queue had no room for.
    pub rx_lost: u32,
    /// Bytes received while no client held the port.
    pub rx_discarded: u32,
    /// Transmit chunks the pipe did not take whole.
    pub tx_lost: u32,
    pub rx_errors: u32,
    pub tx_errors: u32,
}

/// The line as SET_LINE_CODING states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LineCoding {
    baud: u32,
    stop: u8,
    parity: u8,
    data: u8,
}

/// Who holds a serial function: a client with queues, or the kernel itself (the
/// serial console, which has none: its host moves the chunks).
#[derive(Clone, Copy)]
enum Holder {
    Client(Cap<RxQueue>, Cap<TxQueue>),
    Kernel,
}

/// A CDC-ACM function as a serial port.
pub struct CdcAcm<'q, M: Memory, C: Clock> {
    mem: M,
    clock: C,
    mask: u64,
    rings: &'q [PipeRings],
    state: State,
    bind: Bind<'q>,
    gone: bool,
    region: Option<DmaBuf>,
    step: AcmStep,
    step_deadline_us: u64,
    caps: u8,
    // The Uart side.
    attached: Option<Holder>,
    /// The line the client asked for, and the DTR/RTS state it wants.
    want_line: Option<LineCoding>,
    want_dtr: Option<bool>,
    /// A line request is on the wire.
    line_busy: bool,
    // Buffers.
    rx_posted: [bool; BUFS],
    tx_busy: [bool; BUFS],
    halts: Halts,
    bad_run: u32,
    gap: bool,
    submitted: bool,
    stats: AcmStats,
}

impl<'q, M: Memory, C: Clock> CdcAcm<'q, M, C> {
    pub fn new(mem: M, clock: C, mask: u64, rings: &'q [PipeRings]) -> Self {
        CdcAcm {
            mem,
            clock,
            mask,
            rings,
            state: State::Idle,
            bind: Bind::new(),
            gone: false,
            region: None,
            step: AcmStep::Config,
            step_deadline_us: 0,
            caps: 0,
            attached: None,
            want_line: None,
            want_dtr: None,
            line_busy: false,
            rx_posted: [false; BUFS],
            tx_busy: [false; BUFS],
            halts: Halts::default(),
            bad_run: 0,
            gap: false,
            submitted: false,
            stats: AcmStats::default(),
        }
    }

    pub const fn comm_rule() -> Match {
        Match::interface_class(CLASS_COMM)
    }

    pub const fn data_rule() -> Match {
        Match::interface_class(CLASS_DATA)
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    pub fn vid_pid(&self) -> u32 {
        self.bind.vid_pid
    }

    pub fn stats(&self) -> AcmStats {
        self.stats
    }

    /// The queues the client attached, for the host to resolve to their
    /// driver ends. `None` while nobody holds the port, and while the kernel
    /// does ([`CdcAcm::attach_kernel`]).
    pub fn queues(&self) -> Option<(Cap<RxQueue>, Cap<TxQueue>)> {
        match self.attached {
            Some(Holder::Client(rx, tx)) => Some((rx, tx)),
            _ => None,
        }
    }

    /// The same as `Uart::attach` for a holder that has no queues: the kernel's
    /// serial console. [`CdcAcm::pump`] then moves chunks to and from whatever
    /// sink and source its host hands it.
    pub fn attach_kernel(&mut self) -> Out<()> {
        self.take(Holder::Kernel)
    }

    fn take(&mut self, who: Holder) -> Out<()> {
        if self.state != State::Ready {
            return Out::err(NOT_READY);
        }
        if self.attached.is_some() {
            return Out::err(BUSY);
        }
        self.attached = Some(who);
        self.gap = false;
        if self.caps & ACM_CAP_LINE != 0 {
            self.want_dtr = Some(true);
        }
        Out::ok(())
    }

    pub fn take_submitted(&mut self) -> bool {
        core::mem::take(&mut self.submitted)
    }

    pub fn session_wanted(&self) -> Option<Claim> {
        if self.state == State::Claimed { self.bind.wanted() } else { None }
    }

    pub fn open(&mut self, dev: &mut dyn UsbDevice) {
        if self.state != State::Claimed {
            return;
        }
        if let Err(f) = self.bind.open(self.rings, dev) {
            return self.fail(f);
        }
        if self.bind.all_open() {
            match self.mem.alloc_region(POOL_OFF + (2 * BUFS * ACM_BYTES).next_multiple_of(PAGE), PAGE, self.mask) {
                Some(r) => self.region = Some(r),
                None => return self.fail(Fail::NoMemory),
            }
            self.state = State::Setup;
            self.go(AcmStep::Config);
        }
    }

    fn fail(&mut self, f: Fail) {
        self.state = State::Failed(f);
    }

    fn go(&mut self, step: AcmStep) {
        let Some(region) = self.region else { return };
        self.step = step;
        self.step_deadline_us = self.clock.now_us() + CTL_TIMEOUT_US;
        let tag = TAG_STEP | step.code() as u32;
        let ok = match (step, self.bind.data) {
            (AcmStep::Config, _) => self.bind.ctl(false, tag, get_config(CFG_MAX as u16), region.bus_at(CFG_OFF)),
            (AcmStep::SetAlt, Some(d)) => self.bind.ctl(true, tag, set_interface(d.iface(), self.bind.alt), 0),
            _ => false,
        };
        if ok {
            self.submitted = true;
        } else {
            self.fail(Fail::Control(step.code()));
        }
    }

    fn on_step(&mut self, c: Completion) {
        let step = self.step;
        if c.tag != TAG_STEP | step.code() as u32 {
            return;
        }
        if c.status != Status::Ok {
            return self.fail(Fail::Control(step.code()));
        }
        if step == AcmStep::Config {
            let (Some(region), Some(comm), Some(data)) = (self.region, self.bind.comm, self.bind.data) else {
                return self.fail(Fail::Gone);
            };
            let n = (c.actual as usize).min(CFG_MAX);
            self.mem.from_device(region.cpu().wrapping_add(CFG_OFF), n);
            let info = parse_comm(&View { buf: &region, off: CFG_OFF, len: n }, comm.iface());
            if !pairs(&info, data) {
                return self.fail(Fail::Mismatch);
            }
            self.caps = if info.has_acm { info.acm_caps } else { 0 };
            if self.bind.alt != 0 {
                return self.go(AcmStep::SetAlt);
            }
        }
        self.state = State::Ready;
    }

    /// Advance the setup, the line requests, the halts and the deadlines;
    /// clean up after an unplug.
    pub fn service(&mut self) {
        if self.gone {
            return self.cleanup();
        }
        match self.state {
            State::Setup => {
                while let Some(c) = self.bind.pop_ctl() {
                    self.on_step(c);
                    if self.state != State::Setup {
                        break;
                    }
                }
                if self.state == State::Setup && self.clock.now_us() > self.step_deadline_us {
                    self.fail(Fail::Timeout);
                }
            }
            State::Ready => {
                loop {
                    let done = self.bind.pop_ctl();
                    let more = done.is_some();
                    if let Some(c) = done {
                        if c.tag == TAG_LINE {
                            self.line_busy = false;
                        }
                    }
                    if self.halts.poll(&mut self.bind, done) {
                        self.submitted = true;
                    }
                    if !more {
                        break;
                    }
                }
                self.line_requests();
            }
            _ => {}
        }
    }

    /// Queue the next line request the client's calls left.
    fn line_requests(&mut self) {
        if self.line_busy {
            return;
        }
        let Some(region) = self.region else { return };
        let comm = match self.bind.comm {
            Some(c) => c.iface() as u16,
            None => return,
        };
        let ok = if let Some(l) = self.want_line.take() {
            let mut p = [0u8; 7];
            p[0..4].copy_from_slice(&l.baud.to_le_bytes());
            p[4] = l.stop;
            p[5] = l.parity;
            p[6] = l.data;
            region.write_bytes(SMALL_OFF, &p);
            self.mem.to_device(region.cpu().wrapping_add(SMALL_OFF), 7);
            self.bind.ctl(false, TAG_LINE, class_out(REQ_SET_LINE_CODING, 0, comm, 7), region.bus_at(SMALL_OFF))
        } else if let Some(on) = self.want_dtr.take() {
            let v = if on { LINE_ACTIVE } else { 0 };
            self.bind.ctl(false, TAG_LINE, class_out(REQ_SET_CONTROL_LINE_STATE, v, comm, 0), 0)
        } else {
            return;
        };
        if ok {
            self.line_busy = true;
            self.submitted = true;
        }
    }

    fn cleanup(&mut self) {
        self.bind.release();
        if let Some(r) = self.region.take() {
            self.mem.free_region(r);
        }
        self.state = State::Idle;
        self.gone = false;
        self.attached = None;
        self.want_line = None;
        self.want_dtr = None;
        self.line_busy = false;
        self.rx_posted = [false; BUFS];
        self.tx_busy = [false; BUFS];
        self.halts = Halts::default();
        self.bad_run = 0;
        self.caps = 0;
    }

    fn rx_off(i: usize) -> usize {
        POOL_OFF + i * ACM_BYTES
    }

    fn tx_off(i: usize) -> usize {
        POOL_OFF + (BUFS + i) * ACM_BYTES
    }

    fn bad(&mut self, tx: bool) {
        if tx {
            self.stats.tx_errors += 1;
        } else {
            self.stats.rx_errors += 1;
        }
        self.bad_run += 1;
        if self.bad_run >= MAX_BAD_RUN {
            self.fail(Fail::Transport);
        }
    }

    /// Move bytes between the pipes and the client's queues; the number of
    /// chunks moved. Does nothing while no queues are attached (the device is
    /// not asked for data then).
    pub fn pump(&mut self, rx: &mut impl ChunkSink, tx: &mut impl ChunkSource) -> usize {
        self.service();
        if self.state != State::Ready || self.attached.is_none() {
            return 0;
        }
        let Some(region) = self.region else { return 0 };
        let mut moved = 0;
        // Receive: every completed buffer becomes chunks.
        while let Some(c) = self.bind.pop_in() {
            let i = (c.tag & 0xff) as usize;
            if i >= BUFS || !self.rx_posted[i] {
                continue;
            }
            self.rx_posted[i] = false;
            match c.status {
                Status::Ok => {
                    self.bad_run = 0;
                    let n = (c.actual as usize).min(ACM_BYTES);
                    self.mem.from_device(region.cpu().wrapping_add(Self::rx_off(i)), n);
                    let mut off = 0;
                    while off < n {
                        let take = (n - off).min(uart::CHUNK_DATA);
                        let mut d = [0u8; uart::CHUNK_DATA];
                        region.read_bytes(Self::rx_off(i) + off, &mut d[..take]);
                        let flags = if self.gap { uart::CHUNK_OVERRUN } else { 0 };
                        if rx.push(&Chunk::new(&d[..take], flags)) {
                            self.gap = false;
                        } else {
                            self.stats.rx_lost += 1;
                            self.gap = true;
                        }
                        off += take;
                        moved += 1;
                    }
                }
                Status::Disconnected => {}
                Status::Stall => self.halts.clear_in = true,
                _ => self.bad(false),
            }
        }
        if !self.halts.in_blocked() {
            for i in 0..BUFS {
                if self.rx_posted[i] {
                    continue;
                }
                if !self.bind.submit_in(i as u32, region.bus_at(Self::rx_off(i)), ACM_BYTES as u32) {
                    break;
                }
                self.rx_posted[i] = true;
                self.submitted = true;
            }
        }
        // Transmit: queued chunks are packed into a buffer each.
        while let Some(c) = self.bind.pop_out() {
            let i = (c.tag & 0xff) as usize;
            if c.tag & TAG_OUT == 0 || i >= BUFS || !self.tx_busy[i] {
                continue;
            }
            self.tx_busy[i] = false;
            match c.status {
                Status::Ok => self.bad_run = 0,
                Status::Disconnected => {}
                Status::Stall => {
                    self.halts.clear_out = true;
                    self.stats.tx_lost += 1;
                }
                _ => {
                    self.stats.tx_lost += 1;
                    self.bad(true)
                }
            }
        }
        while let Some(i) = (0..BUFS).find(|&i| !self.tx_busy[i]) {
            let mut n = 0;
            while n + uart::CHUNK_DATA <= ACM_BYTES {
                let Some(chunk) = tx.pop() else { break };
                region.write_bytes(Self::tx_off(i) + n, chunk.bytes());
                n += chunk.bytes().len();
                moved += 1;
            }
            if n == 0 {
                break;
            }
            self.mem.to_device(region.cpu().wrapping_add(Self::tx_off(i)), n);
            if self.bind.submit_out(TAG_OUT | i as u32, region.bus_at(Self::tx_off(i)), n as u32) {
                self.tx_busy[i] = true;
                self.submitted = true;
            } else {
                self.stats.tx_lost += 1;
            }
        }
        moved
    }
}

impl<M: Memory, C: Clock> UsbClass for CdcAcm<'_, M, C> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, _speed_port: u32) -> Out<u32> {
        if self.gone || !matches!(self.state, State::Idle | State::Claimed) {
            return Out::new(BUSY, 0);
        }
        let code = self.bind.attach(claim, vid_pid, triple, |s| s == SUBCLASS_ACM);
        if code == OK {
            self.state = State::Claimed;
        }
        Out::new(code, 0)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        if self.bind.owns(Claim(claim)) {
            self.gone = true;
            self.state = State::Failed(Fail::Gone);
        }
        Out::new(OK, 0)
    }
}

impl<M: Memory, C: Clock> azos_devif::Uart for CdcAcm<'_, M, C> {
    fn configure(&mut self, baud: u32, data_bits: u32, parity: u32, stop_bits: u32) -> Out<()> {
        if !(uart::BAUD_MIN..=uart::BAUD_MAX).contains(&baud)
            || !(5..=8).contains(&data_bits)
            || parity > uart::PARITY_EVEN
            || !(1..=2).contains(&stop_bits)
        {
            return Out::err(BAD_ARGUMENT);
        }
        if self.state != State::Ready {
            return Out::err(NOT_READY);
        }
        if self.caps & ACM_CAP_LINE == 0 {
            return Out::err(UNSUPPORTED);
        }
        // bCharFormat: 0 one stop bit, 2 two; bParityType: 0 none, 1 odd, 2 even.
        self.want_line = Some(LineCoding {
            baud,
            stop: if stop_bits == 2 { 2 } else { 0 },
            parity: parity as u8,
            data: data_bits as u8,
        });
        Out::ok(())
    }

    fn attach(&mut self, rx: Cap<RxQueue>, tx: Cap<TxQueue>) -> Out<()> {
        self.take(Holder::Client(rx, tx))
    }

    fn detach(&mut self) -> Out<()> {
        self.attached = None;
        if self.state == State::Ready && self.caps & ACM_CAP_LINE != 0 {
            self.want_dtr = Some(false);
        }
        Out::ok(())
    }

    fn status(&self) -> Out<uart::Status> {
        Out::ok(uart::Status { rx_lost: self.stats.rx_lost, tx_lost: self.stats.tx_lost })
    }
}
