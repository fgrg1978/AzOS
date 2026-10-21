// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! xHCI register layout (xHCI 1.2 specification, section 5): offsets and bit
//! fields of the capability, operational, runtime and port registers, and the
//! decoding of the capability parameters.

// ---- Capability registers (offsets from the start of the window) ----

pub const CAPLENGTH: usize = 0x00; // 8 bits; HCIVERSION is bits 31:16 of the same word
pub const HCSPARAMS1: usize = 0x04;
pub const HCSPARAMS2: usize = 0x08;
pub const HCCPARAMS1: usize = 0x10;
pub const DBOFF: usize = 0x14;
pub const RTSOFF: usize = 0x18;

// ---- Operational registers (offsets from the operational base) ----

pub const USBCMD: usize = 0x00;
pub const USBSTS: usize = 0x04;
pub const PAGESIZE: usize = 0x08;
pub const CRCR: usize = 0x18;
pub const DCBAAP: usize = 0x30;
pub const CONFIG: usize = 0x38;
/// Port register set `n` (1-based) starts here from the operational base.
pub const PORT_BASE: usize = 0x400;
pub const PORT_STRIDE: usize = 0x10;
pub const PORTSC: usize = 0x00;

pub const CMD_RS: u32 = 1 << 0;
pub const CMD_HCRST: u32 = 1 << 1;
pub const CMD_INTE: u32 = 1 << 2;
pub const CMD_HSEE: u32 = 1 << 3;

pub const STS_HCH: u32 = 1 << 0;
pub const STS_HSE: u32 = 1 << 2;
pub const STS_EINT: u32 = 1 << 3;
pub const STS_PCD: u32 = 1 << 4;
pub const STS_CNR: u32 = 1 << 11;
pub const STS_HCE: u32 = 1 << 12;

pub const CRCR_RCS: u64 = 1 << 0;
pub const CRCR_CS: u64 = 1 << 1;
pub const CRCR_CA: u64 = 1 << 2;
pub const CRCR_CRR: u64 = 1 << 3;

// ---- Runtime registers (offsets from the runtime base) ----

/// Interrupter `n`'s register set.
pub const fn ir(n: usize) -> usize {
    0x20 + 0x20 * n
}
pub const IMAN: usize = 0x00;
pub const IMOD: usize = 0x04;
pub const ERSTSZ: usize = 0x08;
pub const ERSTBA: usize = 0x10;
pub const ERDP: usize = 0x18;

pub const IMAN_IP: u32 = 1 << 0;
pub const IMAN_IE: u32 = 1 << 1;
/// ERDP bit 3: Event Handler Busy, write 1 to clear.
pub const ERDP_EHB: u64 = 1 << 3;

// ---- PORTSC ----

pub const PORTSC_CCS: u32 = 1 << 0;
pub const PORTSC_PED: u32 = 1 << 1;
pub const PORTSC_OCA: u32 = 1 << 3;
pub const PORTSC_PR: u32 = 1 << 4;
pub const PORTSC_PLS_SHIFT: u32 = 5;
pub const PORTSC_PLS_MASK: u32 = 0xf << PORTSC_PLS_SHIFT;
pub const PORTSC_PP: u32 = 1 << 9;
pub const PORTSC_SPEED_SHIFT: u32 = 10;
pub const PORTSC_SPEED_MASK: u32 = 0xf << PORTSC_SPEED_SHIFT;
pub const PORTSC_PIC_MASK: u32 = 3 << 14;
pub const PORTSC_LWS: u32 = 1 << 16;
pub const PORTSC_CSC: u32 = 1 << 17;
pub const PORTSC_PEC: u32 = 1 << 18;
pub const PORTSC_WRC: u32 = 1 << 19;
pub const PORTSC_OCC: u32 = 1 << 20;
pub const PORTSC_PRC: u32 = 1 << 21;
pub const PORTSC_PLC: u32 = 1 << 22;
pub const PORTSC_CEC: u32 = 1 << 23;
pub const PORTSC_WAKE: u32 = 7 << 25;
pub const PORTSC_DR: u32 = 1 << 30;
pub const PORTSC_WPR: u32 = 1 << 31;
/// The bits a write acknowledges by writing 1 (RW1C): the change bits, and
/// PED, where a 1 *disables* the port.
pub const PORTSC_W1C: u32 =
    PORTSC_PED | PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;
/// Every change bit.
pub const PORTSC_CHANGES: u32 = PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;
/// What a read-modify-write of PORTSC may carry back: the read-only and
/// read/write-sticky bits, never a RW1C bit (writing it back would disable the
/// port or acknowledge a change nobody has seen). Link state is RWS but is
/// only taken by the controller with LWS set, so it is carried like the rest.
pub const PORTSC_NEUTRAL: u32 = PORTSC_CCS | PORTSC_OCA | PORTSC_PLS_MASK | PORTSC_PP | PORTSC_SPEED_MASK
    | PORTSC_PIC_MASK | PORTSC_WAKE | PORTSC_DR;

/// Port link state: U0 and the Rx.Detect used for a USB 3 port with nothing
/// behind it.
pub const PLS_U0: u32 = 0;
pub const PLS_RXDETECT: u32 = 5;
pub const PLS_POLLING: u32 = 7;

// ---- Extended capabilities ----

/// Extended capability id: USB Legacy Support (the BIOS/OS ownership handoff).
pub const XCAP_LEGACY: u32 = 1;
/// USBLEGSUP: BIOS owned semaphore, OS owned semaphore.
pub const LEGSUP_BIOS_OWNED: u32 = 1 << 16;
pub const LEGSUP_OS_OWNED: u32 = 1 << 24;
/// USBLEGCTLSTS (the dword after USBLEGSUP): the SMI enables the OS turns
/// off (USB SMI, host system error SMI, OS ownership change, PCI command,
/// BAR change) and the RW1C status bits it clears.
pub const LEGCTL_SMI_ENABLES: u32 = 1 << 0 | 1 << 4 | 1 << 13 | 1 << 14 | 1 << 15;
pub const LEGCTL_SMI_STATUS: u32 = 7 << 29;

// ---- Decoded capability parameters ----

/// The capability registers, read once at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// Length of the capability registers: where the operational ones start.
    pub caplength: usize,
    pub hciversion: u16,
    pub max_slots: u32,
    pub max_intrs: u32,
    pub max_ports: u32,
    /// Scratchpad buffers the controller wants.
    pub scratchpads: u32,
    /// 64-bit addressing capability (HCCPARAMS1.AC64).
    pub ac64: bool,
    /// 64-byte contexts (HCCPARAMS1.CSZ); 32 bytes otherwise.
    pub csz64: bool,
    /// Port power control (HCCPARAMS1.PPC).
    pub ppc: bool,
    pub dboff: usize,
    pub rtsoff: usize,
    /// Byte offset of the first extended capability (HCCPARAMS1.xECP, in
    /// dwords); 0: none.
    pub xecp: usize,
}

impl Caps {
    pub fn decode(cap0: u32, hcs1: u32, hcs2: u32, hcc1: u32, dboff: u32, rtsoff: u32) -> Caps {
        // Max Scratchpad Buffers is split: bits 25:21 are the high five,
        // bits 31:27 the low five.
        let hi = (hcs2 >> 21) & 0x1f;
        let lo = (hcs2 >> 27) & 0x1f;
        #[cfg(feature = "canary-scratchpad")]
        let scratchpads = lo;
        #[cfg(not(feature = "canary-scratchpad"))]
        let scratchpads = (hi << 5) | lo;
        #[cfg(feature = "canary-ac64")]
        let ac64 = true;
        #[cfg(not(feature = "canary-ac64"))]
        let ac64 = hcc1 & 1 != 0;
        #[cfg(feature = "canary-csz")]
        let csz64 = false;
        #[cfg(not(feature = "canary-csz"))]
        let csz64 = hcc1 & (1 << 2) != 0;
        Caps {
            caplength: (cap0 & 0xff) as usize,
            hciversion: (cap0 >> 16) as u16,
            max_slots: hcs1 & 0xff,
            max_intrs: (hcs1 >> 8) & 0x7ff,
            max_ports: hcs1 >> 24,
            scratchpads,
            ac64,
            csz64,
            ppc: hcc1 & (1 << 3) != 0,
            dboff: (dboff & !3) as usize,
            rtsoff: (rtsoff & !0x1f) as usize,
            xecp: (hcc1 >> 16) as usize * 4,
        }
    }

    /// Bytes of one context entry.
    pub fn ctx_size(&self) -> usize {
        if self.csz64 { 64 } else { 32 }
    }

    /// Operational registers' base, runtime registers' base, doorbell base.
    pub fn op_base(&self) -> usize {
        self.caplength
    }
}

/// Port speed ID (PORTSC bits 13:10 and slot context speed) for the default
/// protocol speed IDs; a controller with its own PSI table is mapped by
/// [`Speed::from_psiv`] to the nearest of these (xHCI 1.2, table 7-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Speed {
    Low,
    Full,
    High,
    Super,
    SuperPlus,
}

impl Speed {
    pub fn from_psiv(v: u32) -> Option<Speed> {
        Some(match v {
            1 => Speed::Full,
            2 => Speed::Low,
            3 => Speed::High,
            4 => Speed::Super,
            5 => Speed::SuperPlus,
            _ => return None,
        })
    }
    /// The slot context's speed field.
    pub fn psiv(self) -> u32 {
        match self {
            Speed::Full => 1,
            Speed::Low => 2,
            Speed::High => 3,
            Speed::Super => 4,
            Speed::SuperPlus => 5,
        }
    }
    /// Default endpoint-0 max packet size before the device descriptor says.
    pub fn default_ep0_mps(self) -> u16 {
        match self {
            Speed::Low | Speed::Full => 8,
            Speed::High => 64,
            Speed::Super | Speed::SuperPlus => 512,
        }
    }
    pub fn is_super(self) -> bool {
        self >= Speed::Super
    }
    pub fn name(self) -> &'static str {
        match self {
            Speed::Low => "1.5M",
            Speed::Full => "12M",
            Speed::High => "480M",
            Speed::Super => "5G",
            Speed::SuperPlus => "10G",
        }
    }
}
