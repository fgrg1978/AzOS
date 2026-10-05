// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// USB host controller skeleton — xHCI for VF2/K1.
///
/// QEMU: no USB host controller on virt machine; all ops return -1.
/// VF2: **address and IP both wrong, corrected 2026-09-26 (U05-1).**
/// `0x1040_0000` has no node in mainline `jh7110.dtsi` at all. The real
/// USB controller is `usb0@10100000`, `compatible = "starfive,jh7110-usb"`,
/// wrapping an inner `usb@0 { compatible = "cdns,usb3"; }` (Cadence USB3)
/// with THREE register windows at `+0/+0x10000/+0x20000` named
/// `"otg"`/`"xhci"`/`"dev"` — not a single flat xHCI Capability-register
/// block at a standalone base. `main.rs`'s unconditional `usb_init()` call
/// needs gating on a board that actually maps this address (see the
/// `main.rs` diff in this front's report) before this module is safe to
/// call at all — see `platform::hw::USB0_BASE`. Register offsets below are
/// left as documented, known-wrong dead code; a real Cadence USB3 driver is
/// a separate, larger port not attempted this pass.


/// Detected USB device descriptor.
#[derive(Clone, Copy)]
pub struct UsbDevice {
    pub addr:    u8,
    pub vid:     u16,
    pub pid:     u16,
    pub class:   u8,
    pub present: bool,
}

impl UsbDevice {
    pub const fn new() -> Self {
        UsbDevice { addr: 0, vid: 0, pid: 0, class: 0, present: false }
    }
}

// ── QEMU: no USB host ────────────────────────────────────────────────────────

#[cfg(not(feature = "vf2"))]
mod stub {
    pub fn usb_init() {
        azos_drv_sys::kprintln!("[USB] Not available (QEMU virt — no xHCI)");
    }

    /// Scan for USB devices.  Returns the number found (always 0 on QEMU).
    pub fn usb_scan() -> usize {
        0
    }

    pub fn usb_info() {
        azos_drv_sys::kconsoleln!("[USB] Not available (QEMU virt)");
        azos_drv_sys::kconsoleln!("[USB]   No xHCI controller present");
    }
}

#[cfg(not(feature = "vf2"))]
pub use stub::*;

// ── VisionFive 2 / JH7110: xHCI controller ─────────────────────────────────
//
// JH7110 USB 3.0 host: DWC3/xHCI at 0x10400000.
//
// xHCI Capability registers (read-only, from CAPLENGTH):
//   +0x00  CAPLENGTH  — offset to operational registers (u8)
//   +0x04  HCSPARAMS1 — structural params: MaxSlots, MaxIntrs, MaxPorts
//   +0x08  HCSPARAMS2 — structural params 2
//   +0x0C  HCSPARAMS3 — structural params 3
//   +0x10  HCCPARAMS1 — capability params
//
// Operational registers (at base + CAPLENGTH):
//   +0x00  USBCMD  — command: run/stop, HCRST, INTE, HSEE
//   +0x04  USBSTS  — status: HCH (halted), HSE, EINT, PCD, CNR
//   +0x30  DCBAAP  — Device Context Base Address Array Pointer (64-bit)
//   +0x38  CRCR    — Command Ring Control Register (64-bit)

#[cfg(feature = "vf2")]
mod xhci {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use azos_sync::SpinLock;

    // Corrected 2026-09-26 (U05-1): was a literal `0x1040_0000` (no node in
    // mainline at that address at all). Now the real `usb0` base — but see
    // the module doc above: this is the "otg" window's address, and this
    // module's flat-xHCI register model does not match the real device's
    // three-window (otg/xhci/dev) layout.
    const XHCI_BASE: usize = azos_drv_base::platform::hw::USB0_BASE;

    // Capability register offsets
    const CAPLENGTH:  usize = 0x00;
    const HCSPARAMS1: usize = 0x04;

    // Operational register offsets (relative to base + caplength)
    const USBCMD:  usize = 0x00;
    const USBSTS:  usize = 0x04;
    const DCBAAP:  usize = 0x30;
    const CRCR:    usize = 0x38;

    // USBCMD bits
    const CMD_RUN:   u32 = 1 << 0;
    const CMD_HCRST: u32 = 1 << 1;

    // USBSTS bits
    const STS_HCH: u32 = 1 << 0; // HC Halted
    const STS_CNR: u32 = 1 << 11; // Controller Not Ready

    // Port status/control register offset from operational base
    const PORTSC: usize = 0x400;
    // Port status bits
    const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
    const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled

    /// Maximum devices we track in the static table.
    const USB_MAX_DEVICES: usize = 8;

    /// Operational register base = XHCI_BASE + CAPLENGTH.
    /// Set once during usb_init(), read by usb_scan()/usb_info().
    static OP_BASE: AtomicUsize = AtomicUsize::new(0);

    /// Detected device table — port number + connected flag.
    static DEVICES: SpinLock<[super::UsbDevice; USB_MAX_DEVICES]> = SpinLock::new([super::UsbDevice::new(); USB_MAX_DEVICES]);
    static DEVICE_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Cached MaxPorts from HCSPARAMS1 (set during init).
    static MAX_PORTS: AtomicUsize = AtomicUsize::new(0);
    /// Cached MaxSlots from HCSPARAMS1 (set during init).
    static MAX_SLOTS: AtomicUsize = AtomicUsize::new(0);

    #[inline(always)]
    fn rd(off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((XHCI_BASE + off) as *const u32) }
    }

    #[inline(always)]
    fn wr(off: usize, val: u32) {
        unsafe { core::ptr::write_volatile((XHCI_BASE + off) as *mut u32, val) }
    }

    /// Read a 32-bit register at an absolute address.
    #[inline(always)]
    fn rd_abs(addr: usize) -> u32 {
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// Write a 32-bit register at an absolute address.
    #[inline(always)]
    fn wr_abs(addr: usize, val: u32) {
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }

    pub fn usb_init() {
        // 1. Read CAPLENGTH to compute operational register base
        let caplen = (rd(CAPLENGTH) & 0xFF) as usize;
        let op_base = XHCI_BASE + caplen;
        OP_BASE.store(op_base, Ordering::Release);

        // 2. Read HCSPARAMS1 for MaxSlots and MaxPorts
        let hcs1 = rd(HCSPARAMS1);
        let max_slots = (hcs1 & 0xFF) as usize;
        let max_ports = ((hcs1 >> 24) & 0xFF) as usize;
        MAX_SLOTS.store(max_slots, Ordering::Release);
        MAX_PORTS.store(max_ports, Ordering::Release);

        azos_drv_sys::kprintln!("[USB] JH7110 xHCI @ {:#010x}", XHCI_BASE);
        azos_drv_sys::kprintln!("[USB]   CAPLENGTH={} OpBase={:#010x}", caplen, op_base);
        azos_drv_sys::kprintln!("[USB]   MaxSlots={} MaxPorts={}", max_slots, max_ports);

        // 3. Stop the controller: clear CMD_RUN in USBCMD
        let cmd = rd_abs(op_base + USBCMD);
        wr_abs(op_base + USBCMD, cmd & !CMD_RUN);

        // 4. Wait for STS_HCH (halted) in USBSTS
        let mut halted = false;
        for _ in 0..100_000u32 {
            let sts = rd_abs(op_base + USBSTS);
            if sts & STS_HCH != 0 {
                halted = true;
                break;
            }
        }
        if !halted {
            azos_drv_sys::kerr!("[USB]   WARNING: controller did not halt (timeout)");
            return;
        }

        // 5. Reset the controller: set CMD_HCRST
        wr_abs(op_base + USBCMD, CMD_HCRST);

        let mut reset_done = false;
        for _ in 0..100_000u32 {
            let cmd_val = rd_abs(op_base + USBCMD);
            if cmd_val & CMD_HCRST == 0 {
                reset_done = true;
                break;
            }
        }
        if !reset_done {
            azos_drv_sys::kerr!("[USB]   WARNING: controller reset did not complete (timeout)");
            return;
        }

        // Wait for CNR (Controller Not Ready) to clear
        let mut ready = false;
        for _ in 0..100_000u32 {
            let sts = rd_abs(op_base + USBSTS);
            if sts & STS_CNR == 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            azos_drv_sys::kerr!("[USB]   WARNING: controller not ready after reset (timeout)");
            return;
        }

        azos_drv_sys::kprintln!("[USB]   Controller halted, reset, and ready");

        // Suppress unused warnings for items used in future phases
        let _ = (DCBAAP, CRCR, wr as fn(usize, u32));
    }

    /// Scan all xHCI root hub ports for connected devices.
    /// Returns the number of ports with a device connected.
    pub fn usb_scan() -> usize {
        let op_base = OP_BASE.load(Ordering::Acquire);
        if op_base == 0 {
            azos_drv_sys::kprintln!("[USB] scan: controller not initialized");
            return 0;
        }

        let max_ports = MAX_PORTS.load(Ordering::Acquire);
        let mut count: usize = 0;
        let mut devs = DEVICES.lock();

        // Reset device table
        DEVICE_COUNT.store(0, Ordering::Release);
        for i in 0..USB_MAX_DEVICES {
            devs[i] = super::UsbDevice::new();
        }

        // xHCI port registers: op_base + 0x400 + (port_index * 0x10)
        // Port indices are 0-based internally, xHCI ports are 1-based.
        for port in 0..max_ports {
            let portsc_addr = op_base + PORTSC + port * 0x10;
            let portsc = rd_abs(portsc_addr);
            let connected = portsc & PORTSC_CCS != 0;

            if connected && count < USB_MAX_DEVICES {
                devs[count].addr = (port + 1) as u8; // 1-based port number
                devs[count].present = true;
                count += 1;
            }
        }

        drop(devs);
        DEVICE_COUNT.store(count, Ordering::Release);
        count
    }

    /// Print xHCI capability info and per-port status.
    pub fn usb_info() {
        let op_base = OP_BASE.load(Ordering::Acquire);
        let max_slots = MAX_SLOTS.load(Ordering::Acquire);
        let max_ports = MAX_PORTS.load(Ordering::Acquire);

        azos_drv_sys::kconsoleln!("[USB] JH7110 xHCI @ {:#010x}", XHCI_BASE);

        if op_base == 0 {
            azos_drv_sys::kconsoleln!("[USB]   Controller not initialized (call usb_init first)");
            return;
        }

        azos_drv_sys::kconsoleln!("[USB]   OpBase={:#010x} MaxSlots={} MaxPorts={}", op_base, max_slots, max_ports);

        // Per-port status
        for port in 0..max_ports {
            let portsc_addr = op_base + PORTSC + port * 0x10;
            let portsc = rd_abs(portsc_addr);
            let ccs = portsc & PORTSC_CCS != 0;
            let ped = portsc & PORTSC_PED != 0;

            let conn_str = if ccs { "connected" } else { "disconnected" };
            let en_str   = if ped { "enabled" } else { "disabled" };
            azos_drv_sys::kconsoleln!("[USB]   Port {}: {} / {} (PORTSC={:#010x})",
                             port + 1, conn_str, en_str, portsc);
        }

        let dev_count = DEVICE_COUNT.load(Ordering::Acquire);
        azos_drv_sys::kconsoleln!("[USB]   Devices detected: {}", dev_count);
    }
}

#[cfg(feature = "vf2")]
pub use xhci::*;
