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
    unsafe { core::ptr::read_volatile((FW_CFG_BASE + off) as *const u8) }
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
        core::ptr::write_volatile(
            (FW_CFG_BASE + REG_SELECTOR) as *mut u16,
            key.to_be(),
        );
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
#[repr(C)]
struct DmaAccess {
    control: u32,
    length: u32,
    address: u64,
}

/// Write `payload` to the currently-selected-by-DMA fw_cfg file via the
/// DMA protocol — the only functional write path (see `REG_DATA`'s doc
/// comment). `sel` is the file's selector key from
/// `find_ramfb_selector()`.
///
/// `dma` and `payload` must be plain guest-RAM buffers whose addresses
/// QEMU can read directly (same identity-mapping assumption as the
/// framebuffer itself — see `lib.rs`'s `qemu_imp` module doc comment).
fn dma_write_file(sel: u16, payload: &[u8], dma: &mut DmaAccess) -> bool {
    dma.control = (((sel as u32) << 16) | FW_CFG_DMA_CTL_SELECT | FW_CFG_DMA_CTL_WRITE).to_be();
    dma.length = (payload.len() as u32).to_be();
    dma.address = (payload.as_ptr() as u64).to_be();

    // A single 8-byte write to REG_DMA (offset 0 within the DMA
    // sub-region) synchronously triggers `fw_cfg_dma_transfer()` in
    // QEMU — the whole transfer (select + write + callback) completes
    // before this store instruction retires; no polling needed.
    unsafe {
        core::ptr::write_volatile(
            (FW_CFG_BASE + REG_DMA) as *mut u64,
            (core::ptr::addr_of!(*dma) as u64).to_be(),
        );
    }

    // QEMU writes the result back into `dma.control` (big-endian) —
    // ERROR bit clear means the write_cb (ramfb_fw_cfg_write) ran. Must
    // be a volatile read: the compiler has no reason to know the
    // device just overwrote this field out from under it.
    let result_be = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(dma.control))
    };
    u32::from_be(result_be) & FW_CFG_DMA_CTL_ERROR == 0
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
/// physical* address QEMU can read directly — this kernel's identity
/// mapping in QEMU makes the virtual and physical addresses the same, so
/// the framebuffer's own `.bss` address works directly) as an
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

    // 28-byte `RAMFBCfg` payload (addr, fourcc, flags, width, height,
    // stride — confirmed field order against QEMU mainline
    // `hw/display/ramfb.c`'s `struct RAMFBCfg`), all big-endian.
    let mut payload = [0u8; 28];
    payload[0..8].copy_from_slice(&(fb_addr as u64).to_be_bytes());
    payload[8..12].copy_from_slice(&FOURCC_XRGB8888.to_be_bytes());
    payload[12..16].copy_from_slice(&0u32.to_be_bytes()); // flags
    payload[16..20].copy_from_slice(&width.to_be_bytes());
    payload[20..24].copy_from_slice(&height.to_be_bytes());
    payload[24..28].copy_from_slice(&stride.to_be_bytes());

    let mut dma = DmaAccess { control: 0, length: 0, address: 0 };
    if !dma_write_file(sel, &payload, &mut dma) {
        azos_drv_sys::kerr!(
            "[RAMFB] DMA write rejected by device (bad fourcc/dimensions/size?)"
        );
        return false;
    }

    azos_drv_sys::kprintln!(
        "[RAMFB] configured: {}x{} @ {:#x}, stride={}", width, height, fb_addr, stride
    );
    true
}
