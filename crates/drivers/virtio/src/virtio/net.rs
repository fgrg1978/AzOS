// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// VirtIO Network driver — port of virtio_net_init / virtio_net_send / recv.
///
/// Two transports behind one set of free functions (`send`, `poll_recv`,
/// `get_mac`, `is_ready`, and `VirtioNetDevice` over them):
///
///  * virtio-MMIO ([`init`]): probes the QEMU `virt` MMIO window for a net
///    device (device_id = 1). Polled: nothing enables its interrupt line.
///  * virtio-pci modern ([`init_pci`], `pci` feature): a `1af4:1041`
///    function found by the kernel's bus-0 enumeration. With an MSI route
///    (riscv64 AIA/IMSIC, aarch64 GICv3 ITS) it runs in IRQ mode: MSI-X
///    vector 0 = config change, 1 = RX queue, 2 = TX queue, and
///    [`poll_recv`] does not read the RX ring until [`msi_irq`] has seen
///    an RX vector. Without a route (plain riscv64 `virt`, PLIC) it runs
///    polled, exactly like MMIO — no INTx wiring.
///
/// Both set up RX queue (0) and TX queue (1). `init_pci` runs first when a
/// PCI NIC is present; `init` then returns `Ok` without probing MMIO.

use core::sync::atomic::{fence, AtomicBool, AtomicU32, Ordering};

use super::{
    VirtioDev, Virtq,
    VIRTIO_DEV_NET, VIRTIO_QUEUE_SIZE,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    probe, init as virtio_init, virtq_init,
    virtq_alloc_desc, virtq_free_desc, virtq_submit, virtq_poll,
    virtq_publish, virtq_has_used, virtq_set_avail_flags, VIRTQ_AVAIL_F_NO_INTERRUPT,
    mmio_read, mmio_write, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_DRIVER_OK,
};
use azos_sync::SpinLock;

// ---- VirtIO Net header (prepended to every packet) ----
//
// struct virtio_net_hdr { flags u8, gso_type u8, hdr_len u16, gso_size u16,
// csum_start u16, csum_offset u16 [, num_buffers u16] }.
//
// The header length is NOT a constant of this driver; it is a property of
// what was negotiated with the device (virtio 1.2 §5.1.6.1):
//   * legacy transport (MMIO version 1, no VIRTIO_F_VERSION_1): 10 bytes —
//     `num_buffers` is only present when VIRTIO_NET_F_MRG_RXBUF is
//     negotiated, and this driver never asks for it;
//   * modern transport (MMIO version 2): `virtio_init_device` MUST accept
//     VIRTIO_F_VERSION_1 to get FEATURES_OK at all, and once VERSION_1 is
//     negotiated `num_buffers` is ALWAYS present — 12 bytes — whether or
//     not MRG_RXBUF is.
// The old comment here said "10 bytes, confirmed empirically by inspecting
// raw RX bytes"; that was confirmed on the legacy transport only (every
// riscv64 gate row boots without `-global virtio-mmio.force-legacy=false`).
// The aarch64 rows boot the modern transport, and with a 10-byte header
// there every TX frame went out with its first two Ethernet bytes eaten as
// `num_buffers` and every RX frame was parsed two bytes early: DHCP
// DISCOVER "sent", never answered (gate 182e, 2026-09-26; the same image
// got a lease the moment the flag was dropped).
const NET_HDR_LEGACY: usize = 10;
const NET_HDR_MODERN: usize = 12;

/// Header length on the wire for this device, decided by the transport
/// `virtio_init_device` negotiated with (see the block comment above).
#[inline]
fn net_hdr_size(dev: &VirtioDev) -> usize {
    if dev.version == 1 { NET_HDR_LEGACY } else { NET_HDR_MODERN }
}

// ---- RX buffers ----

const RX_BUF_SIZE: usize = 1526; // 1514 ETH + 12 VirtIO net hdr (with padding)
const NUM_RX_BUFS: usize = VIRTIO_QUEUE_SIZE / 2;

// ---- TX buffers ----

/// Max Ethernet frame we will transmit (no jumbo frames).
const TX_BUF_SIZE: usize = 1514;
/// One slot per descriptor index so a frame's buffer is identified by the very
/// descriptor that references it — no separate allocator, and the buffer is
/// live for exactly as long as the device owns the descriptor.
const NUM_TX_BUFS: usize = VIRTIO_QUEUE_SIZE;

struct NetState {
    dev:     VirtioDev,
    rxq:     Virtq,
    txq:     Virtq,
    mac:     [u8; 6],
    ready:   bool,
    rx_bufs: [[u8; RX_BUF_SIZE]; NUM_RX_BUFS],
    /// Driver-owned TX staging. The device is never handed a caller address:
    /// `send` returns as soon as the frame is queued, so a caller buffer could
    /// be reused or popped off the stack while the device is still reading it.
    tx_bufs: [[u8; TX_BUF_SIZE]; NUM_TX_BUFS],
    /// Frames dropped because the TX ring was still full after reclaiming.
    tx_dropped: u32,
    /// virtio-pci only: CPU address of the notify register of queue 0 (RX)
    /// and 1 (TX), written with the queue index as a 16-bit store. 0 on
    /// the MMIO transport, which notifies through `dev.base` instead —
    /// the value doubles as the transport discriminator.
    notify: [usize; 2],
    /// IRQ mode (virtio-pci with an MSI route): RX is read only after an
    /// RX MSI, and TX completions interrupt only while `tx_cb_on`.
    irq: bool,
    /// IRQ mode: TX completion interrupts currently requested (the ring
    /// filled up; the next reclaim switches them off again).
    tx_cb_on: bool,
}

impl NetState {
    const fn zeroed() -> Self {
        NetState {
            dev:     VirtioDev::zeroed(),
            rxq:     Virtq::zeroed(),
            txq:     Virtq::zeroed(),
            mac:     [0u8; 6],
            ready:   false,
            rx_bufs: [[0u8; RX_BUF_SIZE]; NUM_RX_BUFS],
            tx_bufs: [[0u8; TX_BUF_SIZE]; NUM_TX_BUFS],
            tx_dropped: 0,
            notify:  [0; 2],
            irq:     false,
            tx_cb_on: false,
        }
    }
}

unsafe impl Send for NetState {}

static NET: SpinLock<NetState> = SpinLock::new(NetState::zeroed());

// ---- MSI-X (virtio-pci IRQ mode) ----
//
// Outside `NET`: `msi_irq` runs in interrupt context and must not take a
// lock a task on the same hart may hold.

/// MSI-X vector of the device-configuration-change interrupt.
pub const VEC_CONFIG: u16 = 0;
/// MSI-X vector of RX queue 0.
pub const VEC_RX: u16 = 1;
/// MSI-X vector of TX queue 1.
pub const VEC_TX: u16 = 2;
/// Vectors this driver programs (`VEC_CONFIG..=VEC_TX`).
pub const NUM_VECTORS: usize = 3;

/// Set once `init_pci` has programmed the vectors and stored their tokens.
static MSI_ARMED: AtomicBool = AtomicBool::new(false);
/// What the kernel's interrupt path passes to [`msi_irq`] for each vector
/// (`MsiRoute::isr_token`): an IMSIC identity, or an LPI slot.
static MSI_TOKEN: [AtomicU32; NUM_VECTORS] = [const { AtomicU32::new(0) }; NUM_VECTORS];
/// Per-vector count of interrupts [`msi_irq`] accepted.
static MSI_COUNT: [AtomicU32; NUM_VECTORS] = [const { AtomicU32::new(0) }; NUM_VECTORS];
/// RX gate. Starts (and on the MMIO/polled paths stays) `true`. In IRQ
/// mode `poll_recv` clears it when it finds the RX ring empty, and only an
/// RX MSI sets it again: no RX-ring read happens without an interrupt.
static RX_PENDING: AtomicBool = AtomicBool::new(true);
/// `NetState::irq`, readable without the lock.
static IRQ_MODE: AtomicBool = AtomicBool::new(false);

/// TX completion interrupts. `false`: requested only while the ring is
/// full (reclaim is lazy, in `send`), the same trade Linux virtio-net makes
/// without napi_tx. `true`: one MSI per completed frame. A constant so the
/// egress lane can be measured both ways from one source (measured: see
/// `init_pci`'s `tx-irq=` boot line and the RFC-0046 stage-1 numbers).
#[cfg(all(feature = "pci", target_os = "none"))]
const TX_IRQ_ALWAYS: bool = false;

/// Interrupt-path hook: `token` is the number the interrupt controller
/// reported (riscv64: the IMSIC identity `irqchip::claim` returned;
/// aarch64: `intid - LPI_INTID_BASE`). Returns `true` when it is one of
/// this NIC's vectors — counted, and for the RX vector the RX gate opened.
/// The caller then wakes whatever drains the ring. Lock-free, bounded:
/// callable from an ISR.
#[inline]
pub fn msi_irq(token: u32) -> bool {
    if !MSI_ARMED.load(Ordering::Acquire) {
        return false;
    }
    for v in 0..NUM_VECTORS {
        if MSI_TOKEN[v].load(Ordering::Relaxed) == token {
            MSI_COUNT[v].fetch_add(1, Ordering::Relaxed);
            if v == VEC_RX as usize {
                RX_PENDING.store(true, Ordering::Release);
            }
            return true;
        }
    }
    false
}

/// Interrupts [`msi_irq`] accepted, per vector (`[config, rx, tx]`).
pub fn msi_counts() -> [u32; NUM_VECTORS] {
    [
        MSI_COUNT[0].load(Ordering::Relaxed),
        MSI_COUNT[1].load(Ordering::Relaxed),
        MSI_COUNT[2].load(Ordering::Relaxed),
    ]
}

/// `true` when the NIC is virtio-pci in IRQ mode: the RX ring is read only
/// after an RX MSI, so whatever calls `net_poll` must be woken by one.
pub fn irq_driven() -> bool {
    IRQ_MODE.load(Ordering::Relaxed)
}

/// "mmio", "pci-irq" or "pci-poll" once a NIC is up; "none" before.
pub fn transport() -> &'static str {
    let net = NET.lock();
    if !net.ready {
        "none"
    } else if net.notify[0] == 0 {
        "mmio"
    } else if net.irq {
        "pci-irq"
    } else {
        "pci-poll"
    }
}

// VirtIO-MMIO transport window — sourced from `super` (`virtio::mod`'s
// ISA-selected `VIRTIO_MMIO_*`) rather than a local literal; was
// `0x1000_1000..0x10008000` (8 slots) here only, now the same definition
// `blk.rs`/`rng.rs` use.
use super::VIRTIO_MMIO_BASE;
use super::VIRTIO_MMIO_STRIDE;
use super::VIRTIO_MMIO_COUNT as VIRTIO_MMIO_SLOTS;

/// Initialize the VirtIO network device.  Returns Ok(()) if found.
pub fn init() -> Result<(), ()> {
    let mut net = NET.lock();
    // A virtio-pci NIC brought up by `init_pci` owns the interface.
    if net.ready {
        return Ok(());
    }

    // Probe all VirtIO MMIO slots for a net device
    for i in 0..VIRTIO_MMIO_SLOTS {
        let base = VIRTIO_BASE + i * VIRTIO_MMIO_STRIDE;
        let mut dev = VirtioDev::zeroed();
        if unsafe { probe(base, &mut dev) }.is_err() { continue; }
        if dev.device_id != VIRTIO_DEV_NET { continue; }

        // Initialize the device
        unsafe { virtio_init(&mut dev) }?;

        // Set up RX queue (0) and TX queue (1)
        unsafe { virtq_init(&mut dev, 0, &mut net.rxq) }?;
        unsafe { virtq_init(&mut dev, 1, &mut net.txq) }?;

        // Read MAC address from config space (bytes 0-5).
        //
        // `mmio_read` is a 32-bit access, so it must only be issued at 4-byte
        // aligned offsets. The previous version looped `CONFIG + 0..6` and took
        // the low byte of each result: offsets 1/2/3 are unaligned, the device
        // rounds them down to offset 0, and the low byte of that word is always
        // MAC[0]. It therefore produced [m0,m0,m0,m0,m4,m4] — for QEMU's
        // default 52:54:00:12:34:56 that is 52:52:52:52:34:34, a MAC the guest
        // never actually owns. SLIRP tolerated the bogus address, so it went
        // unnoticed until two guests had to ARP for each other.
        //
        // Read the two aligned words instead and unpack. VirtIO MMIO config
        // space is little-endian and RISC-V is LE, so byte n of the config
        // space is byte n of the word, LSB first.
        let w0 = unsafe { mmio_read(dev.base, super::VIRTIO_MMIO_CONFIG) };
        let w1 = unsafe { mmio_read(dev.base, super::VIRTIO_MMIO_CONFIG + 4) };
        net.mac[0] =  w0        as u8;
        net.mac[1] = (w0 >>  8) as u8;
        net.mac[2] = (w0 >> 16) as u8;
        net.mac[3] = (w0 >> 24) as u8;
        net.mac[4] =  w1        as u8;
        net.mac[5] = (w1 >>  8) as u8;

        // DRIVER_OK
        let s = unsafe { mmio_read(dev.base, VIRTIO_MMIO_STATUS) };
        unsafe { mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK) };

        // Collect RX buffer pointers before mutably borrowing rxq
        let mut rx_ptrs = [0u64; NUM_RX_BUFS];
        for b in 0..NUM_RX_BUFS {
            rx_ptrs[b] = super::dma_addr_of(net.rx_bufs[b].as_ptr());
        }

        // Populate RX queue with buffers
        for b in 0..NUM_RX_BUFS {
            if let Some(desc_idx) = unsafe { virtq_alloc_desc(&mut net.rxq) } {
                unsafe {
                    (*net.rxq.desc.add(desc_idx)).addr  = rx_ptrs[b];
                    (*net.rxq.desc.add(desc_idx)).len   = RX_BUF_SIZE as u32;
                    (*net.rxq.desc.add(desc_idx)).flags = VIRTQ_DESC_F_WRITE;
                    (*net.rxq.desc.add(desc_idx)).next  = 0;
                    virtq_submit(&dev, 0, desc_idx, &mut net.rxq);
                }
            }
        }

        net.dev   = dev;
        net.ready = true;

        azos_drv_sys::kprintln!(
            "[NET] VirtIO net: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            net.mac[0], net.mac[1], net.mac[2],
            net.mac[3], net.mac[4], net.mac[5]
        );
        return Ok(());
    }

    Err(())
}

/// Get the MAC address of the network interface.
pub fn get_mac() -> [u8; 6] {
    NET.lock().mac
}

/// Returns true if the VirtIO net device was successfully initialized.
pub fn is_ready() -> bool {
    NET.lock().ready
}

/// Free a completed TX chain (hdr -> data) starting at `head`.
///
/// `.next` must be read before each free: `virtq_free_desc` overwrites it to
/// thread the descriptor back onto the free list.
unsafe fn tx_reclaim_chain(net: &mut NetState, head: usize) {
    let qsize = net.txq.num as usize;
    let mut idx = head;
    // Bounded and range-checked. `virtq_free_desc` scrubs the descriptor on
    // free (`flags`/`addr`/`len` zeroed, `.next` rethreaded onto the free
    // list), so a walk that reaches an already-freed descriptor sees no
    // NEXT flag and terminates there instead of following the free list to
    // the 0xFFFF terminator. The flags/next reads below still happen before
    // the free, and the loop stays bounded by qsize as defence in depth
    // against a duplicate completion from the device.
    for _ in 0..qsize {
        if idx >= qsize { return; }
        let d = net.txq.desc.add(idx);
        let has_next = (*d).flags & VIRTQ_DESC_F_NEXT != 0;
        let next = (*d).next as usize;
        virtq_free_desc(&mut net.txq, idx);
        if !has_next { return; }
        idx = next;
    }
}

/// Queue a raw Ethernet frame for transmission. `data` must include the
/// Ethernet header; the VirtIO net header is prepended automatically.
///
/// Asynchronous: returns once the frame is queued, without waiting for the
/// device to consume it. It previously spun on `virtq_poll` until each frame
/// completed, with `NET.lock()` held. Two problems, both fixed here:
///
///  * **Deadlock.** The spin was unbounded and the lock blocked every other
///    network path, RX draining included. Two of these kernels on one link
///    wedge each other permanently: both fill the peer's pipe, both block in
///    TX, and neither can drain the RX that would release the other.
///
///  * **Throughput.** Stalling on every frame caps TX at one frame per
///    completion round-trip. Gigabit is ~81k frames/s at 1500 bytes; a
///    synchronous handshake per frame cannot reach that at any clock rate.
///
/// Returning early means the device reads the buffer after we return, so the
/// frame is staged into driver-owned `tx_bufs` instead of pointing at caller
/// memory — otherwise a stack buffer could be reused mid-DMA. Completed chains
/// are reclaimed lazily at the head of the next call, so a descriptor the
/// device still owns is never recycled underneath it.
pub fn send(data: &[u8]) -> Result<(), ()> {
    if data.is_empty() || data.len() > TX_BUF_SIZE { return Err(()); }

    let mut net = NET.lock();
    if !net.ready { return Err(()); }

    // The only place descriptors come back — which is what makes the early
    // return safe.
    while let Some(done) = unsafe { virtq_poll(&mut net.txq) } {
        unsafe { tx_reclaim_chain(&mut net, done) };
    }
    if net.tx_cb_on && net.txq.free_count >= 2 {
        // Room again: back to no TX completion interrupts.
        net.tx_cb_on = false;
        unsafe { virtq_set_avail_flags(&mut net.txq, VIRTQ_AVAIL_F_NO_INTERRUPT) };
    }

    // Two descriptors per frame: VirtIO header, then payload.
    let hdr_idx = match unsafe { virtq_alloc_desc(&mut net.txq) } {
        Some(i) => i,
        None    => { tx_ring_full(&mut net); return Err(()); }
    };
    let data_idx = match unsafe { virtq_alloc_desc(&mut net.txq) } {
        Some(i) => i,
        None    => {
            unsafe { virtq_free_desc(&mut net.txq, hdr_idx) };
            tx_ring_full(&mut net);
            return Err(());
        }
    };

    // The header is constant (all zero: no checksum offload, no GSO, and
    // `num_buffers` is ignored by the device on TX) and read-only, so one
    // shared static is fine even with several frames in flight; only the
    // payload is per-descriptor. Sized for the modern header; the legacy
    // transport is told the shorter length below.
    static TX_HDR: [u8; NET_HDR_MODERN] = [0u8; NET_HDR_MODERN];
    let hdr_len = net_hdr_size(&net.dev);

    let len = data.len();
    net.tx_bufs[data_idx][..len].copy_from_slice(data);
    let buf_ptr = super::dma_addr_of(net.tx_bufs[data_idx].as_ptr());
    let dev = net.dev;

    unsafe {
        (*net.txq.desc.add(hdr_idx)).addr  = super::dma_addr_of(TX_HDR.as_ptr());
        (*net.txq.desc.add(hdr_idx)).len   = hdr_len as u32;
        (*net.txq.desc.add(hdr_idx)).flags = VIRTQ_DESC_F_NEXT;
        (*net.txq.desc.add(hdr_idx)).next  = data_idx as u16;

        (*net.txq.desc.add(data_idx)).addr  = buf_ptr;
        (*net.txq.desc.add(data_idx)).len   = len as u32;
        (*net.txq.desc.add(data_idx)).flags = 0;
        (*net.txq.desc.add(data_idx)).next  = 0;

        let notify = net.notify[1];
        if notify == 0 {
            virtq_submit(&dev, 1, hdr_idx, &mut net.txq);
        } else if virtq_publish(&mut net.txq, hdr_idx) {
            // virtio-pci notify: the queue index, 16 bits (virtio 1.x §4.1.5.2).
            core::ptr::write_volatile(notify as *mut u16, 1);
        }
    }

    Ok(())
}

/// The TX ring had no room for a frame: count the drop and, in IRQ mode,
/// ask the device to interrupt on the next completion (the ring-full case
/// is the one where a completion is worth an interrupt).
#[cold]
fn tx_ring_full(net: &mut NetState) {
    net.tx_dropped = net.tx_dropped.saturating_add(1);
    if net.irq && !net.tx_cb_on {
        net.tx_cb_on = true;
        unsafe { virtq_set_avail_flags(&mut net.txq, 0) };
    }
}

/// Frames dropped because the TX ring was full. Diagnostic only.
pub fn tx_dropped() -> u32 { NET.lock().tx_dropped }


/// Poll for a received Ethernet frame.  Copies data into `buf`, returns byte count.
/// Returns 0 if no packet is available.
pub fn poll_recv(buf: &mut [u8]) -> usize {
    // IRQ mode: no RX MSI since the ring was last found empty -> nothing
    // to read, and the ring is not touched. Always open on MMIO/polled.
    if !RX_PENDING.load(Ordering::Acquire) { return 0; }

    let mut net = NET.lock();
    if !net.ready { return 0; }

    // Use _with_len so we know the actual frame length — without it we'd
    // hand the network stack the entire RX_BUF_SIZE and ethertype/headers
    // would be parsed out of stale buffer contents (silently broken: ARP
    // never matches, TCP SYN never seen, accept() never returns).
    let (desc_idx, dev_len) = loop {
        match unsafe { crate::virtio::virtq_poll_with_len(&mut net.rxq) } {
            Some(x) => break x,
            None => {
                if !net.irq { return 0; }
                // Close the gate, then look once more: a frame whose MSI
                // landed before the store below is seen here; one whose
                // MSI lands after it re-opens the gate itself.
                RX_PENDING.store(false, Ordering::SeqCst);
                fence(Ordering::SeqCst);
                if !unsafe { virtq_has_used(&net.rxq) } { return 0; }
                RX_PENDING.store(true, Ordering::Relaxed);
            }
        }
    };

    // The descriptor points to one of our rx_bufs
    // A descriptor's `addr` is what the DEVICE was given: a PHYSICAL address.
    // Reading the received bytes through it needs the kernel's own view —
    // identity on riscv64, the upper half on aarch64. This read was the last
    // of the physical-as-virtual assumptions the upper-half migration
    // uncovered: the device delivered the packet (used.idx moved) and the
    // driver then parsed whatever the raw number pointed at.
    let rx_buf_ptr =
        azos_mm::addr::phys_to_virt(unsafe { (*net.rxq.desc.add(desc_idx)).addr } as usize);
    // Find which rx_buf slot this is
    let slot_opt = (0..NUM_RX_BUFS).find(|&s| {
        net.rx_bufs[s].as_ptr() as usize == rx_buf_ptr
    });
    if let Some(slot) = slot_opt {
        // dev_len includes the VirtIO net header; subtract it to get the
        // Ethernet frame length.
        //
        // Clamp against our own buffer: `dev_len` is written by the DEVICE into
        // the used ring and is not trustworthy. `virtq_poll_with_len` documents
        // that the caller must cap it, and this caller did not — a device
        // reporting more than RX_BUF_SIZE produced an out-of-range slice, which
        // panics, and `panic = "abort"` makes that a board reset triggered by
        // an inbound frame.
        let hdr_len   = net_hdr_size(&net.dev);
        let avail     = RX_BUF_SIZE.saturating_sub(hdr_len);
        let frame_len = dev_len.saturating_sub(hdr_len).min(avail);
        let packet = &net.rx_bufs[slot][hdr_len..hdr_len + frame_len];
        let n = packet.len().min(buf.len());
        buf[..n].copy_from_slice(&packet[..n]);

        // Re-queue the buffer (copy dev before mutable rxq borrow).
        // Rewrite addr/len as well as flags: it costs two stores and restores
        // the descriptor↔buffer invariant even if something scribbled on the
        // descriptor table (virtq_free_desc scrubs addr/len to 0 these days,
        // so a descriptor that ever passed through the free list would
        // otherwise be re-queued pointing at address 0).
        let addr = super::dma_addr_of(net.rx_bufs[slot].as_ptr());
        unsafe {
            let d = net.rxq.desc.add(desc_idx);
            (*d).addr  = addr;
            (*d).len   = RX_BUF_SIZE as u32;
            (*d).flags = VIRTQ_DESC_F_WRITE;
            (*d).next  = 0;
            rx_requeue(&mut net, desc_idx);
        }

        return n;
    }

    // Descriptor's addr doesn't match any rx_buf (device corruption, or a
    // scrubbed descriptor that leaked through the free list). Freeing it here
    // — the previous behaviour — permanently shrank the RX ring: with only
    // NUM_RX_BUFS buffers, a handful of these and the node goes deaf. RX
    // descriptors are paired 1:1 with rx_bufs[desc_idx] at init (allocated in
    // order from a fresh free list), so when the index is in range we can
    // restore that pairing and put the buffer back in service. Only an
    // out-of-range index — which virtq_poll_with_len already rejects — would
    // fall through to a free.
    if desc_idx < NUM_RX_BUFS {
        let addr = super::dma_addr_of(net.rx_bufs[desc_idx].as_ptr());
        unsafe {
            let d = net.rxq.desc.add(desc_idx);
            (*d).addr  = addr;
            (*d).len   = RX_BUF_SIZE as u32;
            (*d).flags = VIRTQ_DESC_F_WRITE;
            (*d).next  = 0;
            rx_requeue(&mut net, desc_idx);
        }
    } else {
        unsafe { virtq_free_desc(&mut net.rxq, desc_idx) };
    }
    0
}

/// Hand RX descriptor `desc_idx` (already filled in) back to the device,
/// through whichever transport this NIC uses.
#[inline(always)]
unsafe fn rx_requeue(net: &mut NetState, desc_idx: usize) {
    let notify = net.notify[0];
    if notify == 0 {
        let dev = net.dev;
        virtq_submit(&dev, 0, desc_idx, &mut net.rxq);
    } else if virtq_publish(&mut net.rxq, desc_idx) {
        core::ptr::write_volatile(notify as *mut u16, 0);
    }
}

/// Print network device info.
pub fn info() {
    let net = NET.lock();
    if !net.ready {
        azos_drv_sys::kprintln!("[NET] VirtIO net: not initialized");
        return;
    }
    azos_drv_sys::kprintln!(
        "[NET] VirtIO net ready — MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        net.mac[0], net.mac[1], net.mac[2],
        net.mac[3], net.mac[4], net.mac[5]
    );
}

// Alias for clarity
const VIRTIO_BASE: usize = VIRTIO_MMIO_BASE;

// ── NetDevice ────────────────────────────────────────────────────────────
//
// Thin, zero-sized adapter over `send`/`poll_recv`/`get_mac`/`is_ready`
// above — same pattern as `eth::EthNetDevice`. `send`'s `Result<(), ()>`
// only ever meant one of two things at its single call site (`crates/net/net`):
// "not ready" or "ring full"; split those here rather than changing `send`
// itself, since that keeps the fast path (an `Ok(())` return) exactly as
// cheap as before — the extra `is_ready()` read only runs on the error path.
use azos_drv_api::net::{NetDevice, NetError};

pub struct VirtioNetDevice;

impl NetDevice for VirtioNetDevice {
    #[inline]
    fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
        if frame.is_empty() || frame.len() > TX_BUF_SIZE {
            return Err(NetError::BadLength);
        }
        let len = frame.len();
        match send(frame) {
            Ok(()) => Ok(len),
            // `send()` itself only returns `Err(())` for "not ready" or "ring
            // full" (the length case was just ruled out above) — `is_ready()`
            // tells the two apart without touching `send`'s own logic.
            Err(()) => {
                if is_ready() {
                    Err(NetError::QueueFull)
                } else {
                    Err(NetError::NotReady)
                }
            }
        }
    }

    #[inline]
    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        Ok(poll_recv(buf))
    }

    #[inline]
    fn mac(&self) -> [u8; 6] {
        get_mac()
    }

    #[inline]
    fn is_ready(&self) -> bool {
        is_ready()
    }
}

// ── virtio-pci bring-up ──────────────────────────────────────────────────

/// Why [`init_pci`] did not bring the NIC up.
#[cfg(all(feature = "pci", target_os = "none"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciNetError {
    /// A NIC (either transport) is already up.
    AlreadyUp,
    /// Not a `1af4:1041` (virtio-net, modern) function.
    NotVirtioNet,
    /// BAR assignment or mapping failed.
    Bars(super::pci::msix_selftest::SelftestError),
    /// COMMON/NOTIFY/ISR capability missing or not in one mapped BAR.
    NoVirtioCaps,
    /// Feature negotiation failed.
    Negotiate(super::pci::NegotiateError),
    /// A queue the device offers is smaller than two entries, or has none.
    QueueTooSmall,
    /// The device read back `VIRTIO_PCI_NO_VECTOR` for a queue vector.
    VectorRefused,
    /// No page for a ring.
    NoMemory,
}

/// `VIRTIO_NET_F_MAC` (bit 5): the device config carries the MAC.
#[cfg(all(feature = "pci", target_os = "none"))]
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

/// Bring up the virtio-net-pci function `info` as the kernel's NIC.
///
/// Its memory BARs are assigned from `window` and mapped. IRQ mode is
/// chosen when `info` has MSI-X with at least [`NUM_VECTORS`] entries AND
/// `route.prepare` provides a target for them — the decision never reads
/// back the MSI-X Enable bit, so a device whose enable did not stick is a
/// NIC that receives nothing (which is what the gate canary relies on),
/// not a NIC that silently falls back to polling. Otherwise polled mode:
/// no vector programmed, `poll_recv` reads the ring on every call.
///
/// Only the hart `route` targets takes the NIC's interrupts (the boot
/// hart's IMSIC file / the ITS's one collection).
#[cfg(all(feature = "pci", target_os = "none"))]
pub fn init_pci<C, R>(
    cfg: &mut C,
    info: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
    route: &mut R,
) -> Result<(), PciNetError>
where
    C: azos_pci::ConfigSpace,
    R: super::pci::msix_selftest::MsiRoute,
{
    use super::pci::msix_selftest::{map_bars, KernelBar};
    use super::pci::{
        common_cfg_bar, find_virtio_caps, Mmio, VirtioPciDevice, VIRTIO_PCI_NO_VECTOR,
    };
    use azos_pci::BarMem;

    let mut net = NET.lock();
    if net.ready {
        return Err(PciNetError::AlreadyUp);
    }
    if info.vendor != 0x1af4 || info.device != 0x1041 {
        return Err(PciNetError::NotVirtioNet);
    }

    let bar_base = map_bars(cfg, info, window).map_err(PciNetError::Bars)?;

    // IRQ mode iff MSI-X is there with room for our vectors and the route
    // can target them. `prepare` also enables the identities/LPIs.
    let msix = info.msix.filter(|m| m.table_size as usize >= NUM_VECTORS);
    let irq = msix.is_some() && route.prepare(NUM_VECTORS as u16);
    let mut msix_on = false;
    if let (true, Some(m)) = (irq, msix) {
        let table_base = bar_base.get(m.table_bar as usize).copied().unwrap_or(0);
        if table_base == 0 {
            return Err(PciNetError::Bars(super::pci::msix_selftest::SelftestError::BarAssign));
        }
        let mut table = KernelBar::new(table_base);
        for vec in 0..NUM_VECTORS as u16 {
            let (addr, data) = route.target(vec);
            azos_pci::program_msix_entry(&mut table, m.table_offset, vec, addr, data, false);
        }
        // Read one entry back so a table the device ignores shows up here
        // rather than as silence later.
        let _ = BarMem::read32(&table, m.table_offset as usize);
        azos_pci::msix_set_enable(cfg, info.bdf, &m, true);
        msix_on = azos_pci::msix_is_enabled(cfg, info.bdf, &m);
    }

    let (caps, n) = find_virtio_caps(cfg, info.bdf);
    let common_bar = common_cfg_bar(&caps, n).ok_or(PciNetError::NoVirtioCaps)?;
    let dev_base = bar_base.get(common_bar as usize).copied().unwrap_or(0);
    if dev_base == 0 {
        return Err(PciNetError::NoVirtioCaps);
    }
    let mut dev = VirtioPciDevice::new(KernelBar::new(dev_base), &caps, n, common_bar)
        .ok_or(PciNetError::NoVirtioCaps)?;
    dev.begin(VIRTIO_NET_F_MAC, 0).map_err(PciNetError::Negotiate)?;
    dev.set_msix_config_vector(if irq { VEC_CONFIG } else { VIRTIO_PCI_NO_VECTOR });

    // Rings: one zeroed page each, sized VIRTIO_QUEUE_SIZE, then shrunk to
    // whatever the device agreed to.
    let q = VIRTIO_QUEUE_SIZE as u16;
    for (qi, vec) in [(0u16, VEC_RX), (1u16, VEC_TX)] {
        let vq = if qi == 0 { &mut net.rxq } else { &mut net.txq };
        let (d, a, u) = unsafe { super::virtq_alloc_rings(vq, q) }
            .map_err(|_| PciNetError::NoMemory)?;
        let v = if irq { vec } else { VIRTIO_PCI_NO_VECTOR };
        let agreed = dev.setup_queue(qi, q, d, a, u, v);
        if agreed < 2 {
            dev.reset();
            return Err(PciNetError::QueueTooSmall);
        }
        if agreed < q {
            unsafe { super::virtq_resize(vq, agreed) };
        }
        if irq && dev.queue_msix_vector(qi) != vec {
            dev.reset();
            return Err(PciNetError::VectorRefused);
        }
    }
    let notify_rx = dev_base + {
        let off = dev.queue_notify_off_of(0);
        dev.queue_notify_offset(off)
    };
    let notify_tx = dev_base + {
        let off = dev.queue_notify_off_of(1);
        dev.queue_notify_offset(off)
    };
    if irq && !TX_IRQ_ALWAYS {
        unsafe { virtq_set_avail_flags(&mut net.txq, VIRTQ_AVAIL_F_NO_INTERRUPT) };
    }

    // MAC: six bytes at the start of the device config (virtio-net
    // `struct virtio_net_config`), read as single bytes.
    let cfg_bar = KernelBar::new(dev_base);
    for i in 0..6 {
        net.mac[i] = cfg_bar.read8(dev.device_cfg + i);
    }

    // IRQ mode: the ring is empty right now, so the gate starts closed and
    // the first RX read waits for the first RX MSI.
    if irq {
        RX_PENDING.store(false, Ordering::SeqCst);
    }
    dev.set_driver_ok();

    // Post every RX buffer, one notify for the lot.
    let mut rx_ptrs = [0u64; NUM_RX_BUFS];
    for b in 0..NUM_RX_BUFS {
        rx_ptrs[b] = super::dma_addr_of(net.rx_bufs[b].as_ptr());
    }
    for b in 0..NUM_RX_BUFS {
        if let Some(desc_idx) = unsafe { virtq_alloc_desc(&mut net.rxq) } {
            unsafe {
                (*net.rxq.desc.add(desc_idx)).addr  = rx_ptrs[b];
                (*net.rxq.desc.add(desc_idx)).len   = RX_BUF_SIZE as u32;
                (*net.rxq.desc.add(desc_idx)).flags = VIRTQ_DESC_F_WRITE;
                (*net.rxq.desc.add(desc_idx)).next  = 0;
                let _ = virtq_publish(&mut net.rxq, desc_idx);
            }
        }
    }
    unsafe { core::ptr::write_volatile(notify_rx as *mut u16, 0) };

    // Modern transport: the 12-byte net header (`net_hdr_size`).
    net.dev = VirtioDev { base: core::ptr::null_mut(), device_id: VIRTIO_DEV_NET, version: 2 };
    net.notify = [notify_rx, notify_tx];
    net.irq = irq;
    net.ready = true;
    if irq {
        for v in 0..NUM_VECTORS {
            MSI_TOKEN[v].store(route.isr_token(v as u16), Ordering::Relaxed);
        }
        MSI_ARMED.store(true, Ordering::Release);
        IRQ_MODE.store(true, Ordering::Relaxed);
    }

    let mac = net.mac;
    drop(net);
    if irq {
        azos_drv_sys::kprintln!(
            "[NET] virtio-net-pci {} mode=irq msix={} vectors={} tokens={},{},{} tx-irq={}",
            info.bdf, if msix_on { "y" } else { "n" }, NUM_VECTORS,
            MSI_TOKEN[0].load(Ordering::Relaxed), MSI_TOKEN[1].load(Ordering::Relaxed),
            MSI_TOKEN[2].load(Ordering::Relaxed),
            if TX_IRQ_ALWAYS { "always" } else { "ring-full" });
    } else {
        azos_drv_sys::kprintln!("[NET] virtio-net-pci {} mode=poll (no MSI route on this machine)",
            info.bdf);
    }
    azos_drv_sys::kprintln!(
        "[NET] VirtIO net: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    Ok(())
}

/// One line with the per-vector MSI counts, `tag` saying when it was taken.
/// Prints nothing unless the NIC is in IRQ mode.
pub fn print_msi_counts(tag: &str) {
    if !irq_driven() {
        return;
    }
    let c = msi_counts();
    azos_drv_sys::kprintln!("[NET] msix counts ({}): config={} rx={} tx={}", tag, c[0], c[1], c[2]);
}
