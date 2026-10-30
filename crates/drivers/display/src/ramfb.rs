// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! QEMU `ramfb` — a generic, QEMU-emulated framebuffer device, configured
//! via QEMU's `fw_cfg` mechanism. NOT related to real VF2 hardware in any
//! way — this exists only to answer "can this kernel drive *some*
//! framebuffer, in a way we can actually see and test in QEMU" as a check
//! separate from `dc8200.rs`/`hdmi.rs`, which QEMU cannot simulate at all.
//!
//! Requires `-device ramfb` on the QEMU command line (not on by default
//! for the `virt` machine) and a window/display backend able to show it
//! (e.g. `-display cocoa`/`-display gtk` — NOT `-nographic`, which this
//! whole session's QEMU testing has used exclusively until now).
//!
//! Protocol confirmed as hardware/device fact against QEMU mainline
//! source (`hw/display/ramfb.c`, `hw/riscv/virt.c`,
//! `include/hw/nvram/fw_cfg.h`, `include/standard-headers/linux/
//! qemu_fw_cfg.h`) — same licensing footing as `dc8200.rs`/`hdmi.rs`'s
//! use of Linux driver source: facts about the interface, not copied
//! code (QEMU is itself GPL; this project is Apache-2.0 OR GPL-2.0-only).

use azos_drv_base::platform::hw::FW_CFG_BASE;

// ---- fw_cfg classic PIO registers (byte-wide access) ----
// Only used for READS (file directory enumeration) below — confirmed
// against QEMU mainline (`hw/nvram/fw_cfg.c`, `fw_cfg_write()`): guest
// writes to the classic DATA register have been a no-op since QEMU
// v2.4 ("write support removed"). Configuring a writable file (like
// `etc/ramfb`) requires the separate DMA register/protocol below —
// this was the actual root cause of an earlier silent failure (config
// "succeeded" from this driver's point of view, produced no visible
// effect: QEMU discarded every byte written to REG_DATA).
const REG_DATA: usize = 0x00;
const REG_SELECTOR: usize = 0x08;
// fw_cfg DMA address register — confirmed against QEMU mainline
// (`hw/riscv/virt.c`'s `fw_cfg_init_mem_dma(base, ...)` →
// `fw_cfg_init_mem_internal(base+8, base, 8, base+16, ...)`): ctrl at
// base+8, data at base+0, DMA register at base+16.
const REG_DMA: usize = 0x10;

/// The interface word: bit 0 the classic registers, bit 1 the DMA one
/// (`FW_CFG_VERSION_DMA`), little endian.
const FW_CFG_ID: u16 = 0x01;
const FW_CFG_VERSION_DMA: u32 = 0x02;
const FW_CFG_FILE_DIR: u16 = 0x19;

// fw_cfg DMA control bits (`include/standard-headers/linux/qemu_fw_cfg.h`).
const FW_CFG_DMA_CTL_ERROR: u32 = 0x01;
const FW_CFG_DMA_CTL_SELECT: u32 = 0x08;
const FW_CFG_DMA_CTL_WRITE: u32 = 0x10;

const FW_CFG_MAX_FILE_PATH: usize = 56;
/// One `fw_cfg_file` directory entry: size(4) + select(2) + reserved(2) +
/// name(56) = 64 bytes.
const FW_CFG_FILE_ENTRY_SIZE: usize = 4 + 2 + 2 + FW_CFG_MAX_FILE_PATH;

const RAMFB_FILE_NAME: &[u8] = b"etc/ramfb";

/// `DRM_FORMAT_XRGB8888` ('X','R','2','4' packed little-endian per the
/// standard DRM fourcc convention) — matches the XRGB8888-shaped bytes
/// `crate::imp::fill_solid_color`-equivalent fill below already writes.
const FOURCC_XRGB8888: u32 = (b'X' as u32)
    | ((b'R' as u32) << 8)
    | ((b'2' as u32) << 16)
    | ((b'4' as u32) << 24);

#[inline(always)]
fn read_u8(off: usize) -> u8 {
    unsafe { azos_arch_api::mmio::read8(FW_CFG_BASE + off) }
}

// No 8-bit write helper on purpose: the only register we write is the selector,
// and sub-16-bit access to it faults on this device model (see `select` below).

fn select(key: u16) {
    // Selector register must be accessed as a genuine 16-bit-wide write —
    // confirmed empirically: two sequential 8-bit writes here raised a
    // Store/AMO access fault (scause 0x7) booting in QEMU, meaning the
    // device model rejects sub-16-bit access at this specific offset
    // (unlike the DATA register, which is documented as supporting
    // byte-wise streaming access). Big-endian on the wire.
    unsafe {
        azos_arch_api::mmio::write16(FW_CFG_BASE + REG_SELECTOR, key.to_be());
    }
}

fn read_data(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = read_u8(REG_DATA);
    }
}

/// One `fw_cfg_dma_access` descriptor (`control`, `length`, `address`,
/// all big-endian on the wire — this struct lives in guest RAM and QEMU
/// DMA-reads it directly, so field order/endianness must match
/// `hw/nvram/fw_cfg.c`'s `FWCfgDmaAccess` exactly). 16 bytes, no padding
/// (u64 `address` is already 8-byte aligned after two u32 fields).
#[repr(C, align(16))]
struct DmaAccess {
    control: u32,
    length: u32,
    address: u64,
}

/// The `RAMFBCfg` payload (addr, fourcc, flags, width, height, stride).
const RAMFB_CFG_BYTES: usize = 28;

/// The descriptor and the payload the device reads, in `.bss`, not on the
/// stack: a kernel stack need not be memory with a physical address the
/// kernel can name (`azos_mm::addr::virt_to_phys` covers the image and the
/// RAM map). Written by `init` alone, once, on the boot CPU.
static mut DMA: DmaAccess = DmaAccess { control: 0, length: 0, address: 0 };
static mut CFG: [u8; RAMFB_CFG_BYTES] = [0; RAMFB_CFG_BYTES];

/// How long the device has to answer a DMA request. QEMU completes it
/// inside the doorbell store; the budget bounds a device that never does.
const DMA_BUDGET_US: u64 = 100_000;

/// Why a DMA write did not happen.
#[derive(Debug)]
enum DmaFail {
    /// The device set the error bit (the file refused the payload).
    Refused,
    /// The device never wrote the descriptor back: it could not read it (an
    /// address that is not guest physical memory) or does not run.
    NoAnswer,
}

/// Write `CFG` to fw_cfg file `sel` (the selector key from
/// `find_ramfb_selector()`) via the DMA protocol, the only functional write
/// path (see `REG_DATA`'s doc comment). QEMU reads the descriptor and the
/// payload from guest physical memory, so both are handed by their physical
/// addresses.
fn dma_write_file(sel: u16) -> Result<(), DmaFail> {
    let dma = &raw mut DMA;
    let payload_pa = azos_mm::addr::virt_to_phys((&raw const CFG) as usize) as u64;
    let dma_pa = azos_mm::addr::virt_to_phys(dma as usize) as u64;
    // SAFETY: `init` is the only user of `DMA`, once, on the boot CPU.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*dma).control),
            (((sel as u32) << 16) | FW_CFG_DMA_CTL_SELECT | FW_CFG_DMA_CTL_WRITE).to_be(),
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dma).length), (RAMFB_CFG_BYTES as u32).to_be());
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dma).address), payload_pa.to_be());
    }

    // The descriptor and the payload before the doorbell. A single 8-byte
    // write to REG_DMA starts `fw_cfg_dma_transfer()`.
    azos_dma::order::io_wmb();
    // SAFETY: the fw_cfg DMA register of the board's mapped window.
    unsafe { azos_arch_api::mmio::write64(FW_CFG_BASE + REG_DMA, dma_pa.to_be()) };

    // The device clears `control` when it is done and leaves only the error
    // bit if it failed (Linux `fw_cfg_wait_for_control`). A volatile read:
    // the device writes the field behind the compiler's back.
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    let end = azos_drv_sys::timebase::now().saturating_add(DMA_BUDGET_US.saturating_mul(f) / 1_000_000);
    loop {
        // SAFETY: as above.
        let control = u32::from_be(unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*dma).control)) });
        if control & !FW_CFG_DMA_CTL_ERROR == 0 {
            return if control & FW_CFG_DMA_CTL_ERROR == 0 { Ok(()) } else { Err(DmaFail::Refused) };
        }
        if azos_drv_sys::timebase::now() >= end {
            return Err(DmaFail::NoAnswer);
        }
        core::hint::spin_loop();
    }
}

/// Does this fw_cfg have the DMA interface (`FW_CFG_ID` bit 1)?
fn has_dma() -> bool {
    select(FW_CFG_ID);
    let mut id = [0u8; 4];
    read_data(&mut id);
    u32::from_le_bytes(id) & FW_CFG_VERSION_DMA != 0
}

/// Search the fw_cfg file directory for `etc/ramfb`, returning its
/// `select` key if found. Returns `None` if `-device ramfb` wasn't
/// passed on the QEMU command line (the directory simply won't list it).
fn find_ramfb_selector() -> Option<u16> {
    select(FW_CFG_FILE_DIR);
    let mut count_buf = [0u8; 4];
    read_data(&mut count_buf);
    let count = u32::from_be_bytes(count_buf);

    let mut entry = [0u8; FW_CFG_FILE_ENTRY_SIZE];
    for _ in 0..count {
        read_data(&mut entry);
        // Layout: size(4) select(2) reserved(2) name(56) — only `select`
        // (bytes 4..6, big-endian) and `name` (bytes 8..64) are needed.
        let sel = u16::from_be_bytes([entry[4], entry[5]]);
        let name = &entry[8..8 + FW_CFG_MAX_FILE_PATH];
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if &name[..name_len] == RAMFB_FILE_NAME {
            return Some(sel);
        }
    }
    None
}

/// Configure QEMU's `ramfb` device to display `fb_addr` (a *guest
/// physical* address, which the device reads directly) as an
/// XRGB8888 framebuffer of `width`x`height`, `stride` bytes/row.
///
/// Returns `false` (does nothing else) if `ramfb` wasn't found in the
/// fw_cfg directory — most likely `-device ramfb` is missing from the
/// QEMU command line this session's usual `-nographic` invocations don't
/// include; see the module doc comment.
pub fn init(fb_addr: usize, width: u32, height: u32, stride: u32) -> bool {
    let Some(sel) = find_ramfb_selector() else {
        azos_drv_sys::kprintln!(
            "[RAMFB] 'etc/ramfb' not found in fw_cfg directory — is \
             -device ramfb on the QEMU command line?"
        );
        return false;
    };

    if !has_dma() {
        azos_drv_sys::kerr!("[RAMFB] fw_cfg has no DMA interface: 'etc/ramfb' cannot be written");
        return false;
    }

    // 28-byte `RAMFBCfg` payload (addr, fourcc, flags, width, height,
    // stride — confirmed field order against QEMU mainline
    // `hw/display/ramfb.c`'s `struct RAMFBCfg`), all big-endian.
    let mut payload = [0u8; RAMFB_CFG_BYTES];
    payload[0..8].copy_from_slice(&(fb_addr as u64).to_be_bytes());
    payload[8..12].copy_from_slice(&FOURCC_XRGB8888.to_be_bytes());
    payload[12..16].copy_from_slice(&0u32.to_be_bytes()); // flags
    payload[16..20].copy_from_slice(&width.to_be_bytes());
    payload[20..24].copy_from_slice(&height.to_be_bytes());
    payload[24..28].copy_from_slice(&stride.to_be_bytes());
    // SAFETY: `init` is the only user of `CFG`, once, on the boot CPU.
    unsafe { core::ptr::write_volatile(&raw mut CFG, payload) };

    if let Err(why) = dma_write_file(sel) {
        azos_drv_sys::kerr!("[RAMFB] DMA write of 'etc/ramfb' failed: {:?}", why);
        return false;
    }

    azos_drv_sys::kprintln!(
        "[RAMFB] configured: {}x{} @ {:#x}, stride={}", width, height, fb_addr, stride
    );
    true
}
