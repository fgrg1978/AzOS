// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 virtio-rng driver: the host of `crates/drivers/virtio-rng`, built
//! into the image when Kconfig `DRV_VIRTIO_RNG_PLACEMENT` is `ring3`, the
//! kernel then leaving the device unbound.
//!
//! Started at boot by the component manager (its row's `start = true`) with
//! the capabilities of its row, `RNGDRV.ELF`: the device `virtio:4`'s
//! registers (`mmio.virtio:4`, READ|WRITE) and line (`irq.virtio:4`), the
//! `entropy` endpoint with `WRITE`, and the public introspection region, in
//! which it finds the device's bus handle and line. It
//!
//! 1. maps the registers (`DOMAIN_MMIO_MAP`);
//! 2. makes one physically contiguous memory object for the request queue
//!    and the buffer the device writes, maps it, and binds it to the device
//!    (`DEVICE_DMA_MAP`): the device is given that object's bus address and
//!    reaches nothing else (behind an IOMMU, nothing else at all);
//! 3. binds the device's line to a port (`PORT_SRC_IRQ`);
//! 4. reads 64 bytes at its start and every `DRV_VIRTIO_RNG_FEED_S` seconds:
//!    a request, the interrupt, the device's interrupt acknowledged, the line
//!    acknowledged (`DEVICE_IRQ_ACK`), the bytes fed to the pool.
//!
//! A device whose interrupt does not come within a second ends the driver
//! (exit 1): its row's supervisor restarts it, and the kernel, at the exit,
//! resets the device before the object's pages leave its domain.

#![no_std]
#![no_main]

use azos_abi::cap::CapPerms;
use azos_drvkit::Window;
use azos_inspect_lib::{str_in, u64_in, Inspector, Source};
use azos_libsys as sys;
use azos_virtio_rng::{Layout, Rng, BUF_BYTES, QUEUE_ENTRIES};

/// The key the line's events carry.
const IRQ_KEY: u64 = 0x524e_4744;
/// How long a read may take before the device is given up on.
const ANSWER_NS: u64 = 1_000_000_000;
/// The device, by what the bus says it is.
const IDENTITY: &[u8] = b"virtio:4";

fn fail(why: &[u8]) -> ! {
    let mut line = [0u8; 120];
    let head = b"[rngdrv] FAIL: ";
    let n = head.len() + why.len().min(line.len() - head.len());
    line[..head.len()].copy_from_slice(head);
    line[head.len()..n].copy_from_slice(&why[..n - head.len()]);
    sys::println(&line[..n]);
    sys::exit(1);
}

/// The bus handle and the line of the first `virtio:4` device in the
/// introspection tree's `devices/`.
fn find_device() -> Option<(u32, u32)> {
    let m = sys::inspect_map(azos_abi::cap::SHM_INSPECT_PUBLIC).ok()?;
    // SAFETY: the mapping lives as long as the task, read-only, and the kernel
    // writes it only with aligned 64-bit stores.
    let mut tree = unsafe { Inspector::from_mapped(m, None) }.ok()?;
    tree.with(Source::Public, |r| {
        let mut found = None;
        let Some(dir) = r.lookup("devices")? else { return Ok(None) };
        r.children(dir, &mut |info, _| {
            if found.is_some() {
                return;
            }
            let Ok(Some(id)) = str_in(r, info.id, "identity") else { return };
            if id.as_bytes() != IDENTITY {
                return;
            }
            let (Ok(handle), Ok(Some(line))) = (info.name.as_str().parse::<u32>(), u64_in(r, info.id, "irq")) else { return };
            found = Some((handle, line as u32));
        })?;
        Ok(found)
    })
    .ok()
    .flatten()
}

/// A handle this task holds of type `ty` naming `resource`.
fn held(ty: azos_abi::cap::CapType, resource: u32) -> Option<u32> {
    let h = sys::cap_lookup(ty.raw(), resource);
    (h >= 0).then_some(h as u32)
}

/// One read: the request, then its interrupt (an event on the port: one
/// taken before the wait is queued, not lost), then the bytes. `None`: no
/// interrupt in time. The used ring is read only after an interrupt, so a
/// line that does not deliver is a failure here, not a read that polls on.
fn read(rng: &mut Rng<Window, Window>, port: u32, line: u32, out: &mut [u8; BUF_BYTES]) -> Option<usize> {
    rng.request(BUF_BYTES).ok()?;
    let deadline = sys::vdso_now_ns().saturating_add(ANSWER_NS);
    loop {
        let mut ev = [0u8; sys::PORT_EVENT_BYTES];
        if sys::port_wait_until_typed(port, &mut ev, deadline) <= 0 {
            return None;
        }
        if ev[8] != sys::PORT_EVENT_IRQ || u64::from_le_bytes(ev[..8].try_into().unwrap_or([0; 8])) != IRQ_KEY {
            continue;
        }
        // The device's cause first, so its line is low when the kernel's
        // mask on it is lifted.
        rng.ack_interrupt();
        sys::irq_ack(line);
        if let Some(n) = rng.complete() {
            rng.copy_out(&mut out[..n]);
            return Some(n);
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let Some((handle, irq)) = find_device() else { fail(b"no virtio:4 device in devices/") };
    let (Some(dev), Some(line)) = (held(azos_abi::cap::ty::MMIO, handle), held(azos_abi::cap::ty::IRQ, irq)) else {
        fail(b"the row grants the device or its line not")
    };
    let Some(entropy) = sys::dev::lookup(sys::dev::key::ENTROPY, 0) else { fail(b"no entropy endpoint") };
    let regs = sys::mmio_map(handle as u64, CapPerms::RW.bits() as u64);
    if regs <= 0 {
        fail(b"the registers did not map");
    }
    let page = sys::PAGE_SIZE as u64;
    let bytes = Layout::of(QUEUE_ENTRIES, page).bytes;
    let pages = bytes.div_ceil(page);
    let obj = sys::shm_create_typed(
        pages,
        sys::SHM_RW | azos_abi::syscall_nr::SHM_KIND_CONTIG << azos_abi::syscall_nr::SHM_CREATE_KIND_SHIFT,
    );
    if obj <= 0 {
        fail(b"no contiguous memory for the queue");
    }
    let mem = sys::shm_map_typed(obj as u32);
    if mem <= 0 {
        fail(b"the queue memory did not map");
    }
    let Ok((bus, len)) = sys::dma_map(dev, obj as u32, sys::DMA_BIDIRECTIONAL) else {
        fail(b"the device may not reach the queue memory (DEVICE_DMA_MAP)")
    };
    // SAFETY: `regs` is the device's register window this task mapped, `mem`
    // the object's mapping of `len` bytes; the driver stays inside both.
    let (regs, mem) = unsafe { (Window::new(regs as usize), Window::new(mem as usize)) };
    let mut rng = match Rng::bring_up(regs, mem, bus, len, page) {
        Ok(r) => r,
        Err(_) => fail(b"the device did not come up"),
    };
    let port = sys::port_create_typed();
    if port <= 0 || sys::irq_bind(line, port as u32, IRQ_KEY, sys::DEVICE_IRQ_CPU_ANY) < 0 {
        fail(b"the line did not bind to a port");
    }
    let port = port as u32;
    sys::println(b"[rngdrv] virtio-rng up: queue in a DMA object, line on a port");
    let period_ns = azos_limits::DRV_VIRTIO_RNG_FEED_S as u64 * 1_000_000_000;
    let mut buf = [0u8; BUF_BYTES];
    let mut feeds = 0u32;
    loop {
        if cfg!(feature = "exit-mid-request") && feeds == 1 {
            let _ = rng.request(BUF_BYTES);
            sys::println(b"[rngdrv] exiting with a request in the device");
            sys::exit(3);
        }
        let Some(n) = read(&mut rng, port, line, &mut buf) else {
            rng.stop();
            fail(b"no answer from the device")
        };
        let fed = sys::dev::entropy_feed(entropy, &buf[..n]);
        // The bytes were entropy in this frame: not left behind.
        // SAFETY: a valid, aligned `&mut [u8; N]`; volatile so it is not elided.
        unsafe { core::ptr::write_volatile(&mut buf, [0; BUF_BYTES]) };
        if fed.is_err() {
            fail(b"the entropy endpoint refused the feed");
        }
        feeds = feeds.saturating_add(1);
        match feeds {
            1 => sys::println(b"[rngdrv] fed the pool from the device (DMA through the object, interrupt by port)"),
            // The third: the line was acknowledged and delivered again twice.
            3 => sys::println(b"[rngdrv] fed the pool 3 times"),
            _ => {}
        }
        let _ = sys::sleep_until_ns(sys::vdso_now_ns().saturating_add(period_ns));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(2);
}
