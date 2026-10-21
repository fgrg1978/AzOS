// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Transfer request blocks (xHCI 1.2, section 6.4): the 16-byte entry of
//! every ring, its types, the builders of the ones the driver issues and the
//! decoders of the events it receives.

pub const TRB_BYTES: usize = 16;

pub mod ty {
    pub const NORMAL: u8 = 1;
    pub const SETUP: u8 = 2;
    pub const DATA: u8 = 3;
    pub const STATUS: u8 = 4;
    pub const ISOCH: u8 = 5;
    pub const LINK: u8 = 6;
    pub const EVENT_DATA: u8 = 7;
    pub const NOOP: u8 = 8;
    pub const ENABLE_SLOT: u8 = 9;
    pub const DISABLE_SLOT: u8 = 10;
    pub const ADDRESS_DEVICE: u8 = 11;
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    pub const EVALUATE_CONTEXT: u8 = 13;
    pub const RESET_ENDPOINT: u8 = 14;
    pub const STOP_ENDPOINT: u8 = 15;
    pub const SET_TR_DEQUEUE: u8 = 16;
    pub const RESET_DEVICE: u8 = 17;
    pub const NOOP_CMD: u8 = 23;
    pub const TRANSFER_EVENT: u8 = 32;
    pub const COMMAND_COMPLETION: u8 = 33;
    pub const PORT_STATUS_CHANGE: u8 = 34;
    pub const HOST_CONTROLLER_EVENT: u8 = 37;
}

/// Completion codes (section 6.4.5, table 6-90).
pub mod cc {
    pub const SUCCESS: u8 = 1;
    pub const DATA_BUFFER_ERROR: u8 = 2;
    pub const BABBLE: u8 = 3;
    pub const USB_TRANSACTION_ERROR: u8 = 4;
    pub const TRB_ERROR: u8 = 5;
    pub const STALL: u8 = 6;
    pub const RESOURCE_ERROR: u8 = 7;
    pub const BANDWIDTH_ERROR: u8 = 8;
    pub const NO_SLOTS: u8 = 9;
    pub const SLOT_NOT_ENABLED: u8 = 11;
    pub const ENDPOINT_NOT_ENABLED: u8 = 12;
    pub const SHORT_PACKET: u8 = 13;
    pub const PARAMETER_ERROR: u8 = 17;
    pub const CONTEXT_STATE_ERROR: u8 = 19;
    /// An isochronous interval went by with no descriptor to serve it.
    pub const MISSED_SERVICE: u8 = 23;
    pub const COMMAND_RING_STOPPED: u8 = 24;
    pub const COMMAND_ABORTED: u8 = 25;
    pub const STOPPED: u8 = 26;
    pub const STOPPED_LENGTH_INVALID: u8 = 27;
}

// Control word bits.
pub const C_CYCLE: u32 = 1 << 0;
/// Link: toggle cycle. Normal/Data: evaluate next TRB.
pub const C_TC: u32 = 1 << 1;
/// Normal/Data: interrupt on short packet.
pub const C_ISP: u32 = 1 << 2;
pub const C_CH: u32 = 1 << 4;
pub const C_IOC: u32 = 1 << 5;
/// Setup: immediate data (the 8 setup bytes are the parameter).
pub const C_IDT: u32 = 1 << 6;
/// Address Device: block set address request. Configure Endpoint: deconfigure.
pub const C_BSR_DC: u32 = 1 << 9;
/// Data/Status: direction IN.
pub const C_DIR_IN: u32 = 1 << 16;
/// Isoch (first TRB of the TD): start isochronous ASAP, the TD is scheduled
/// for the next service interval the endpoint has instead of a frame the
/// driver names. The burst count (TBC) is bits 8:7 and the packets of the
/// last burst (TLBPC) bits 19:16 of the same word (xHCI 1.2 section 6.4.1.3).
pub const C_SIA: u32 = 1 << 31;
/// Setup: transfer type, bits 17:16.
pub const C_TRT_NONE: u32 = 0 << 16;
pub const C_TRT_OUT: u32 = 2 << 16;
pub const C_TRT_IN: u32 = 3 << 16;

/// One TRB: the 64-bit parameter, the status word and the control word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Trb {
    pub param: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    pub const fn new(ty: u8, param: u64, status: u32, flags: u32) -> Trb {
        Trb { param, status, control: flags | (ty as u32) << 10 }
    }

    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3f) as u8
    }
    pub fn cycle(&self) -> bool {
        self.control & C_CYCLE != 0
    }
    /// The completion code of an event.
    pub fn code(&self) -> u8 {
        (self.status >> 24) as u8
    }
    /// The slot id of an event or a command TRB.
    pub fn slot(&self) -> u8 {
        (self.control >> 24) as u8
    }
    /// The endpoint id (device context index) of a transfer event or an
    /// endpoint command.
    pub fn endpoint(&self) -> u8 {
        ((self.control >> 16) & 0x1f) as u8
    }
    /// Bytes not transferred, of a transfer event (24 bits).
    pub fn residue(&self) -> u32 {
        self.status & 0x00ff_ffff
    }
    /// Port id of a port status change event.
    pub fn port_id(&self) -> u8 {
        (self.param >> 24) as u8
    }

    // ---- Builders ----

    pub fn link(target: u64, toggle: bool) -> Trb {
        Trb::new(ty::LINK, target, 0, if toggle { C_TC } else { 0 })
    }

    pub fn noop_cmd() -> Trb {
        Trb::new(ty::NOOP_CMD, 0, 0, 0)
    }
    pub fn enable_slot() -> Trb {
        // Slot type 0 selects the default (USB) protocol.
        Trb::new(ty::ENABLE_SLOT, 0, 0, 0)
    }
    pub fn disable_slot(slot: u8) -> Trb {
        Trb::new(ty::DISABLE_SLOT, 0, 0, (slot as u32) << 24)
    }
    pub fn address_device(slot: u8, input_ctx: u64, bsr: bool) -> Trb {
        Trb::new(ty::ADDRESS_DEVICE, input_ctx, 0, (slot as u32) << 24 | if bsr { C_BSR_DC } else { 0 })
    }
    pub fn configure_endpoint(slot: u8, input_ctx: u64, deconfigure: bool) -> Trb {
        Trb::new(ty::CONFIGURE_ENDPOINT, input_ctx, 0, (slot as u32) << 24 | if deconfigure { C_BSR_DC } else { 0 })
    }
    pub fn evaluate_context(slot: u8, input_ctx: u64) -> Trb {
        Trb::new(ty::EVALUATE_CONTEXT, input_ctx, 0, (slot as u32) << 24)
    }
    pub fn reset_endpoint(slot: u8, dci: u8) -> Trb {
        Trb::new(ty::RESET_ENDPOINT, 0, 0, (slot as u32) << 24 | (dci as u32) << 16)
    }
    pub fn stop_endpoint(slot: u8, dci: u8) -> Trb {
        Trb::new(ty::STOP_ENDPOINT, 0, 0, (slot as u32) << 24 | (dci as u32) << 16)
    }
    /// Set TR Dequeue Pointer: `deq` is the bus address of the TRB, `dcs` the
    /// cycle state the controller must expect there.
    pub fn set_tr_dequeue(slot: u8, dci: u8, deq: u64, dcs: bool) -> Trb {
        Trb::new(ty::SET_TR_DEQUEUE, (deq & !0xf) | dcs as u64, 0, (slot as u32) << 24 | (dci as u32) << 16)
    }

    /// Setup stage of a control transfer; the 8 setup bytes ride in the
    /// parameter (IDT), `data_len` selects the transfer type.
    pub fn setup(setup: [u8; 8], data_len: u16, dir_in: bool) -> Trb {
        let trt = if data_len == 0 {
            C_TRT_NONE
        } else if dir_in {
            C_TRT_IN
        } else {
            C_TRT_OUT
        };
        Trb::new(ty::SETUP, u64::from_le_bytes(setup), 8, C_IDT | trt)
    }
    /// A data stage or one TRB of a normal transfer. `td_size` is the number
    /// of packets still to come after this TRB's (capped at 31).
    pub fn data(ty_: u8, buf: u64, len: u32, td_size: u32, flags: u32) -> Trb {
        Trb::new(ty_, buf, (len & 0x1_ffff) | (td_size.min(31) << 17), flags)
    }
    /// Status stage; `dir_in` is the direction of the STATUS packet, the
    /// opposite of the data stage (IN when there is no data stage).
    pub fn status_stage(dir_in: bool) -> Trb {
        Trb::new(ty::STATUS, 0, 0, C_IOC | if dir_in { C_DIR_IN } else { 0 })
    }
}
