// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO GPU (device id 16), 2D only: the development display on every ISA.
//!
//! The device shows a host-side image. The driver owns a framebuffer in guest
//! RAM, tells the device about it once (`RESOURCE_CREATE_2D`,
//! `RESOURCE_ATTACH_BACKING`, `SET_SCANOUT`), and after that every change the
//! CPU draws is committed with a `TRANSFER_TO_HOST_2D` of the changed rectangle
//! followed by a `RESOURCE_FLUSH` of it. The mode comes from the display
//! (`GET_EDID`'s preferred timing when the device offers `VIRTIO_GPU_F_EDID`,
//! else the size `GET_DISPLAY_INFO` reports); the refresh rate comes from the
//! EDID too, 60 Hz when it does not say.
//!
//! # Transports
//!
//! virtio-mmio ([`init_at`], bound by the hardware bus for `virtio:16`) and
//! virtio-pci ([`init_pci`], `1af4:1050`) differ only in how the device is
//! negotiated, its queue is registered and its doorbell is rung; everything
//! after the queue exists is shared ([`Gpu::start`]).
//!
//! # Flip
//!
//! [`flip`] is the hook `azos_fb` calls for every rectangle the console, the
//! panic screen or a compositor drew. It may run in any context, so it never
//! waits for a lock: the rectangle joins the pending damage
//! ([`gpu_proto::Damage`], one atomic word), and whoever holds the device lock
//! commits the damage (the caller, if the lock was free; else the holder, which
//! looks again after it unlocks).
//!
//! A commit is asynchronous: it is two requests (a transfer and a flush)
//! queued behind ONE doorbell, and `flip` returns without waiting for the
//! device (QEMU runs a control request later, on its main loop). Under the
//! lock a flip does only what costs no waiting: reap the answers the device
//! has written since the last one, copy two requests into a free pair of
//! slots, ring the doorbell. No interrupt is used (`avail.flags` asks the
//! device not to raise one); the next flip reaps. Four commits fit in the
//! queue. A flip that finds all four still in flight waits until the device
//! finishes one (spinning with the device lock held, interrupts on), so the
//! console cannot outrun the display by more than that, but only when its
//! caller allows it (`may_wait`: task context). The panic screen does not: its
//! rectangle stays in the pending damage and the next flip commits it. The
//! one caller that draws (`azos_fb`'s console, on its `draw` path) runs in
//! task context with no spinlock held; a flip that finds the lock held never
//! waits for it, it leaves its rectangle to the holder (a panic raised on the
//! hart that holds the lock therefore shows nothing: the holder cannot resume).
//! A device that answers nothing within [`WAIT_MS`] is given up on and nothing
//! is sent to it again (a dead display must not stop the kernel printing); its
//! pending damage is dropped, as is a rectangle whose request the device
//! refuses (it would be refused again). The start-up requests are the only
//! ones waited for each time.
//!

// The vf2 and k1 boards carry no virtio-gpu device: `init_at` below refuses
// every window.
#![cfg_attr(any(feature = "vf2", feature = "k1"), allow(unused_imports, dead_code))]

use core::sync::atomic::{fence, Ordering};

use azos_dma::Direction;
use azos_drv_sys::{kprintln, timebase};
use azos_sync::SpinLock;

use super::gpu_proto::{self as p, Damage, Rect};
use super::{
    init_with, mmio_read, mmio_write, probe, virtq_alloc_desc, virtq_free_desc, virtq_init,
    virtq_notify_mmio, virtq_poll_with_len, virtq_publish, virtq_set_avail_flags, Dma, VirtioDev,
    Virtq, VIRTIO_DEV_GPU, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_DRIVER_OK, VIRTQ_AVAIL_F_NO_INTERRUPT, VIRTQ_DESC_F_NEXT,
    VIRTQ_DESC_F_WRITE,
};

/// How long the device may take to finish a start-up request, or one of the
/// four commits in flight, before it is given up on. Generous on purpose: the
/// limit is read off the guest's clock, which a virtual-time (`-icount`) run
/// advances faster than the host serves the queue.
pub const WAIT_MS: u64 = 1000;

/// The only resource and scanout the driver creates.
const RESOURCE: u32 = 1;
const SCANOUT: u32 = 0;
/// The control queue.
const CONTROLQ: u32 = 0;

/// One request and its answer, alone in their cache lines: behind a
/// non-coherent device the CPU maintains the caches of each separately.
#[repr(C, align(128))]
struct Slot {
    req: [u8; 64],
    resp: [u8; 64],
}

impl Slot {
    const fn new() -> Self {
        Slot { req: [0; 64], resp: [0; 64] }
    }
}

/// The answer to the two start-up queries, the biggest the driver reads.
#[repr(C, align(128))]
struct Big([u8; p::RESP_LEN_EDID]);

/// The most EDID bytes kept (the protocol carries at most this many).
pub const EDID_MAX: usize = 1024;

const _: () = assert!(p::LEN_TRANSFER <= 64 && p::LEN_ATTACH_BACKING_1 <= 64 && p::LEN_SET_SCANOUT <= 64);
const _: () = assert!(p::RESP_LEN_DISPLAY_INFO <= p::RESP_LEN_EDID);

/// Commits in flight at once: a commit is two requests of two descriptors each.
const COMMITS_IN_FLIGHT: usize = super::VIRTIO_QUEUE_SIZE / 4;
/// Slot 0 carries the start-up requests (their answers land in [`Big`]); commit
/// `k` uses slot `1 + 2k` for its transfer and `2 + 2k` for its flush.
const SLOT_INIT: usize = 0;
const SLOTS: usize = 1 + 2 * COMMITS_IN_FLIGHT;
const _: () = assert!(SLOTS <= 16);

/// What [`Gpu::commit`] did with a rectangle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Commit {
    /// Queued behind a doorbell (or empty after clipping: nothing to show).
    Sent,
    /// Four commits are still in flight and the caller may not wait: the
    /// rectangle is still to commit.
    Full,
    /// A dead or absent display: nothing will ever be committed.
    Dropped,
}

/// How the doorbell is rung.
#[derive(Clone, Copy)]
enum Transport {
    Mmio(VirtioDev),
    /// virtio-pci: the address of queue 0's notify register.
    #[cfg(all(feature = "pci", target_os = "none"))]
    Pci { notify: usize },
}

impl Transport {
    fn kick(&self) {
        match *self {
            Transport::Mmio(d) => {
                // SAFETY: `d` is the initialised device's mapped window.
                unsafe { virtq_notify_mmio(&d, CONTROLQ) }
            }
            #[cfg(all(feature = "pci", target_os = "none"))]
            Transport::Pci { notify } => {
                // SAFETY: the notify register of a mapped BAR; queue 0.
                unsafe { core::ptr::write_volatile(notify as *mut u16, CONTROLQ as u16) }
            }
        }
    }
}

/// The framebuffer the driver allocated.
#[derive(Clone, Copy)]
struct Fb {
    phys: u64,
    va: usize,
    width: u32,
    height: u32,
    stride: u32,
    hz: u32,
}

struct Gpu {
    t: Option<Transport>,
    vq: Virtq,
    dma: Dma,
    slots: [Slot; SLOTS],
    slots_bus: u64,
    /// Bit `i`: slot `i` has a request the device has not answered yet.
    busy: u16,
    /// The slot whose request the chain headed by descriptor `d` carries.
    slot_of: [u8; super::VIRTQ_CAPACITY],
    big: Big,
    big_bus: u64,
    fb: Option<Fb>,
    /// The display's EDID as the device gave it (`GET_EDID`), `edid_len` bytes
    /// of it; zero when the device has none ([`edid`] hands it to the kernel).
    edid: [u8; EDID_MAX],
    edid_len: usize,
    /// The device stopped answering: nothing is sent to it again.
    dead: bool,
    /// A refused commit has been reported.
    warned: bool,
}

// SAFETY: the raw pointers inside (the queue, the doorbell) are used only
// under `GPU`'s lock.
unsafe impl Send for Gpu {}

impl Gpu {
    const fn new() -> Self {
        Gpu {
            t: None,
            vq: Virtq::zeroed(),
            dma: Dma::fallback(),
            slots: [const { Slot::new() }; SLOTS],
            slots_bus: 0,
            busy: 0,
            slot_of: [0; super::VIRTQ_CAPACITY],
            big: Big([0; p::RESP_LEN_EDID]),
            big_bus: 0,
            fb: None,
            edid: [0; EDID_MAX],
            edid_len: 0,
            dead: false,
            warned: false,
        }
    }
}

static GPU: SpinLock<Gpu> = SpinLock::new(Gpu::new());
static DAMAGE: Damage = Damage::new();

/// The display the driver brought up: what `azos_fb` registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framebuffer {
    /// Physical base of the pixels (guest RAM).
    pub phys: u64,
    /// Where the CPU reaches them: the kernel's direct map of that RAM, so the
    /// mapping keeps the attributes of the rest of RAM (a second, write-combining
    /// mapping of it would alias it with different attributes).
    pub va: usize,
    pub width: u32,
    pub height: u32,
    /// Bytes per row; 4 bytes per pixel, `0x00RRGGBB`.
    pub stride: u32,
    pub hz: u32,
}

/// The display, once a device is up.
pub fn framebuffer() -> Option<Framebuffer> {
    let g = GPU.lock();
    let fb = g.fb?;
    if g.dead {
        return None;
    }
    Some(Framebuffer { phys: fb.phys, va: fb.va, width: fb.width, height: fb.height, stride: fb.stride, hz: fb.hz })
}

/// The EDID of the display, once a device is up and gave one: the bytes and
/// their count. `kernel/src/boot/fb.rs` publishes it to the framebuffer's
/// connector (`azos_fb::scanout::publish_edid`).
pub fn edid() -> Option<([u8; EDID_MAX], usize)> {
    let g = GPU.lock();
    (g.edid_len != 0 && !g.dead).then_some((g.edid, g.edid_len))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuError {
    /// A device is already up (one display is driven).
    Busy,
    /// Not a virtio-gpu device, or the wrong kind of window.
    NotGpu,
    /// A legacy (version 1) virtio-mmio window: QEMU needs `-global
    /// virtio-mmio.force-legacy=false` for a virtio-gpu.
    Legacy,
    /// `FEATURES_OK` refused.
    Features,
    /// A DMA mapping was refused or the domain would not start.
    Dma,
    /// No memory for a ring or the framebuffer.
    NoMemory,
    /// The control queue could not be set up.
    Queue,
    /// A start-up request got no answer or an error: which one.
    Command(&'static str),
    #[cfg(all(feature = "pci", target_os = "none"))]
    Pci(&'static str),
}

// ---- Requests ----

impl Gpu {
    /// Queue one request/answer pair for slot `slot` on the control queue; the
    /// answer lands in `resp_bus..+resp_len`. The doorbell is NOT rung. `None`
    /// when the queue has no two free descriptors.
    fn queue(&mut self, slot: usize, req_bus: u64, req_len: usize, resp_bus: u64, resp_len: usize) -> Option<()> {
        // SAFETY: the queue was initialised by the bring-up; this is the only
        // user, under the lock.
        unsafe {
            let d0 = virtq_alloc_desc(&mut self.vq)?;
            let Some(d1) = virtq_alloc_desc(&mut self.vq) else {
                virtq_free_desc(&mut self.vq, d0);
                return None;
            };
            let a = self.vq.desc.add(d0);
            (*a).addr = req_bus;
            (*a).len = req_len as u32;
            (*a).flags = VIRTQ_DESC_F_NEXT;
            (*a).next = d1 as u16;
            let b = self.vq.desc.add(d1);
            (*b).addr = resp_bus;
            (*b).len = resp_len as u32;
            (*b).flags = VIRTQ_DESC_F_WRITE;
            (*b).next = 0;
            self.slot_of[d0] = slot as u8;
            virtq_publish(&mut self.vq, d0);
        }
        self.busy |= 1 << slot;
        Some(())
    }

    /// Take every answer the device has written: free the descriptors, release
    /// the slots, account the commits.
    fn reap(&mut self) {
        loop {
            // SAFETY: as in `queue`.
            let Some((head, _len)) = (unsafe { virtq_poll_with_len(&mut self.vq) }) else { return };
            // SAFETY: `head < num` (the poll checked); the second descriptor of
            // the pair is the head's `next`.
            unsafe {
                let tail = (*self.vq.desc.add(head)).next as usize;
                virtq_free_desc(&mut self.vq, head);
                virtq_free_desc(&mut self.vq, tail);
            }
            let slot = self.slot_of[head] as usize;
            self.busy &= !(1 << slot);
            // A start-up request is judged by the code that sent it; a refused
            // commit is said once (a console that failed to show a line must not
            // print a line per failure: that line would be flipped too).
            if slot != SLOT_INIT && !self.warned && !self.ok(slot) {
                self.warned = true;
                kprintln!("[VIRTIO-GPU] the display refused a request (later refusals are not reported)");
            }
        }
    }

    /// Reap until `done`; `false` when the device made no progress within
    /// [`WAIT_MS`]: it is then dead.
    fn wait_until(&mut self, done: impl Fn(&Gpu) -> bool) -> bool {
        let limit = timebase::TIMER_FREQ * WAIT_MS / 1000;
        let t0 = timebase::now();
        loop {
            self.reap();
            if done(self) {
                return true;
            }
            if timebase::now().wrapping_sub(t0) > limit {
                self.dead = true;
                kprintln!("[VIRTIO-GPU] no answer in {} ms: display stopped", WAIT_MS);
                return false;
            }
            core::hint::spin_loop();
        }
    }

    fn slot_bus(&self, i: usize) -> (u64, u64) {
        let base = self.slots_bus + (i * core::mem::size_of::<Slot>()) as u64;
        (base, base + core::mem::offset_of!(Slot, resp) as u64)
    }

    /// Put `req` in slot `i`, clear its answer and queue the pair.
    fn put(&mut self, i: usize, req: &[u8]) -> Option<()> {
        let (req_bus, resp_bus) = self.slot_bus(i);
        let s = &mut self.slots[i];
        s.req[..req.len()].copy_from_slice(req);
        s.resp[..p::RESP_LEN_NODATA].fill(0);
        // SAFETY: both ranges are inside the mapped slot.
        unsafe {
            self.dma.sync_for_device(s.req.as_ptr(), req.len(), Direction::ToDevice);
            self.dma.sync_for_device(s.resp.as_ptr(), p::RESP_LEN_NODATA, Direction::FromDevice);
        }
        self.queue(i, req_bus, req.len(), resp_bus, p::RESP_LEN_NODATA)
    }

    /// Was slot `i`'s answer `OK_NODATA`?
    fn ok(&self, i: usize) -> bool {
        let s = &self.slots[i];
        // SAFETY: inside the mapped slot; the device wrote it.
        unsafe { self.dma.sync_for_cpu(s.resp.as_ptr(), p::RESP_LEN_NODATA, Direction::FromDevice) };
        p::resp_type(&s.resp) == Some(p::RESP_OK_NODATA)
    }

    /// A start-up request whose answer is `resp_len` bytes in `big`, waited
    /// for; the answer's `type`, `None` when the device did not answer.
    fn query(&mut self, req: &[u8], resp_len: usize) -> Option<u32> {
        let (req_bus, _) = self.slot_bus(SLOT_INIT);
        let s = &mut self.slots[SLOT_INIT];
        s.req[..req.len()].copy_from_slice(req);
        self.big.0[..resp_len].fill(0);
        // SAFETY: both ranges are inside the mapped buffers.
        unsafe {
            self.dma.sync_for_device(s.req.as_ptr(), req.len(), Direction::ToDevice);
            self.dma.sync_for_device(self.big.0.as_ptr(), resp_len, Direction::FromDevice);
        }
        self.queue(SLOT_INIT, req_bus, req.len(), self.big_bus, resp_len)?;
        self.kick();
        if !self.wait_until(|g| g.busy & 1 << SLOT_INIT == 0) {
            return None;
        }
        // SAFETY: as above.
        unsafe { self.dma.sync_for_cpu(self.big.0.as_ptr(), resp_len, Direction::FromDevice) };
        p::resp_type(&self.big.0)
    }

    /// A start-up request with no data in its answer, waited for.
    fn command(&mut self, what: &'static str, req: &[u8]) -> Result<(), GpuError> {
        self.put(SLOT_INIT, req).ok_or(GpuError::Command(what))?;
        self.kick();
        if !self.wait_until(|g| g.busy & 1 << SLOT_INIT == 0) || !self.ok(SLOT_INIT) {
            return Err(GpuError::Command(what));
        }
        Ok(())
    }

    fn kick(&self) {
        if let Some(t) = &self.t {
            t.kick();
        }
    }

    /// The transfer slot of a commit that has both its slots and four
    /// descriptors free.
    fn free_commit(&self) -> Option<usize> {
        if self.vq.free_count < 4 {
            return None;
        }
        (0..COMMITS_IN_FLIGHT).map(|k| 1 + 2 * k).find(|&t| self.busy & 3 << t == 0)
    }

    /// Commit `r` of the framebuffer to the display: queue a transfer and a
    /// flush behind one doorbell and return; the answers are reaped by the next
    /// flip. When the last four commits are still in flight it waits for one if
    /// `may_wait`, else it commits nothing and says [`Commit::Full`].
    fn commit(&mut self, r: Rect, may_wait: bool) -> Commit {
        let Some(fb) = self.fb else { return Commit::Dropped };
        if self.dead {
            return Commit::Dropped;
        }
        let (x1, y1) = (r.x.saturating_add(r.w).min(fb.width), r.y.saturating_add(r.h).min(fb.height));
        if r.x >= x1 || r.y >= y1 {
            return Commit::Sent;
        }
        let r = Rect { x: r.x, y: r.y, w: x1 - r.x, h: y1 - r.y };
        let offset = r.y as u64 * fb.stride as u64 + r.x as u64 * p::BYTES_PER_PIXEL as u64;
        if may_wait {
            if !self.wait_until(|g| g.free_commit().is_some()) {
                return Commit::Dropped;
            }
        } else {
            self.reap();
        }
        let Some(t) = self.free_commit() else { return Commit::Full };
        // A non-coherent device reads RAM: write back the rows it will copy.
        if !self.dma.coherent() {
            for row in r.y..r.y + r.h {
                let at = fb.va + row as usize * fb.stride as usize + (r.x * p::BYTES_PER_PIXEL) as usize;
                // SAFETY: inside the framebuffer.
                unsafe {
                    self.dma.sync_for_device(at as *const u8, (r.w * p::BYTES_PER_PIXEL) as usize, Direction::ToDevice)
                };
            }
        }
        // Both fit: `free_commit` checked four descriptors and the two slots.
        let _ = self.put(t, &p::transfer_to_host_2d(RESOURCE, r, offset));
        let _ = self.put(t + 1, &p::resource_flush(RESOURCE, r));
        self.kick();
        Commit::Sent
    }

    /// Everything after the queue exists and the buffers are mapped: start the
    /// device, learn the mode, create the resource and show it.
    fn start(&mut self, edid: bool) -> Result<(), GpuError> {
        // Mapped before the domain starts enforcing: the slots and the
        // answer buffer. (The framebuffer is mapped after the mode is known;
        // a domain maps and unmaps at any time.)
        // SAFETY: the queue is set up; suppress the interrupt we do not take.
        unsafe { virtq_set_avail_flags(&mut self.vq, VIRTQ_AVAIL_F_NO_INTERRUPT) };

        let info = if self.query(&p::get_display_info(), p::RESP_LEN_DISPLAY_INFO).is_some() {
            p::parse_display_info(&self.big.0)
        } else {
            return Err(GpuError::Command("get_display_info"));
        };
        let from_edid = if edid && self.query(&p::get_edid(SCANOUT), p::RESP_LEN_EDID).is_some() {
            if let Some(blob) = p::edid_blob(&self.big.0) {
                self.edid[..blob.len()].copy_from_slice(blob);
                self.edid_len = blob.len();
            }
            p::parse_edid(&self.big.0)
        } else {
            None
        };
        let mode = p::choose_mode(from_edid, info);

        let stride = mode.width * p::BYTES_PER_PIXEL;
        let bytes = stride as usize * mode.height as usize;
        let page = azos_arch::PAGE_SIZE;
        let pages = (bytes + page - 1) / page;
        let phys = azos_mm::pmm::alloc_contiguous(pages).map_err(|_| GpuError::NoMemory)?.0;
        // A refusal from here on leaves the frames with the driver, as every
        // ring page of this crate is left on a failed bring-up (once, at boot).
        let bus = self.dma.map_phys(phys as u64, pages * page, Direction::ToDevice).map_err(|_| GpuError::Dma)?;
        let whole = Rect { x: 0, y: 0, w: mode.width, h: mode.height };
        // A device that refuses a step may already hold the backing.
        self.command("create_2d", &p::resource_create_2d(RESOURCE, p::FORMAT_B8G8R8X8, mode.width, mode.height))?;
        self.command("attach_backing", &p::resource_attach_backing_1(RESOURCE, bus, (pages * page) as u32))?;
        self.command("set_scanout", &p::set_scanout(SCANOUT, RESOURCE, whole))?;
        self.fb = Some(Fb {
            phys: phys as u64,
            va: super::dma_page_ptr(phys),
            width: mode.width,
            height: mode.height,
            stride,
            hz: mode.hz,
        });
        // The first frame: black, from the zeroed pages. The queue is empty.
        self.commit(whole, true);
        Ok(())
    }
}

/// Commit the damage pending, if the device is free; looks again after it lets
/// go, so a rectangle added while it was held is not left behind. `may_wait`:
/// the caller may spin for the device when the queue is full (see [`flip`]).
///
/// The two fences are the two halves of one handshake: a flipper adds its
/// rectangle, then looks at the lock; the holder releases the lock, then looks at
/// the rectangle. Without a full fence between each pair, both can look first
/// and miss the other (store -> load reordering), and the rectangle stays.
fn drain(may_wait: bool) {
    loop {
        fence(Ordering::SeqCst);
        let Some(mut g) = GPU.try_lock() else { return };
        let mut full = false;
        if let Some(r) = DAMAGE.take() {
            // A dead or absent display drops the damage.
            if g.commit(r, may_wait) == Commit::Full {
                // Still to show: back into the damage, merged with whatever
                // was added meanwhile, for the next flip.
                DAMAGE.add(r);
                full = true;
            }
        }
        drop(g);
        fence(Ordering::SeqCst);
        if full || !DAMAGE.pending() {
            return;
        }
    }
}

/// Show the rectangle `x, y, w, h` (pixels) of the framebuffer. The hook
/// `azos_fb::set_flip` registers; any context. `may_wait`: the caller is a
/// task that can afford to spin (at most [`WAIT_MS`]) for the device when four
/// commits are in flight; the panic screen passes `false`, and its rectangle
/// then stays pending until the next flip.
pub fn flip(x: u32, y: u32, w: u32, h: u32, may_wait: bool) {
    DAMAGE.add(Rect { x, y, w, h });
    drain(may_wait);
}

// ---- Bring-up ----

/// Map the driver's buffers through `dma` and fill in `g.slots_bus` and
/// `g.big_bus`.
fn map_buffers(g: &mut Gpu, dma: Dma) -> Result<(), GpuError> {
    g.dma = dma;
    g.slots_bus = dma
        .map(g.slots.as_ptr(), core::mem::size_of_val(&g.slots), Direction::Bidirectional)
        .map_err(|_| GpuError::Dma)?;
    g.big_bus = dma
        .map(&raw const g.big, core::mem::size_of::<Big>(), Direction::Bidirectional)
        .map_err(|_| GpuError::Dma)?;
    Ok(())
}

/// Bring up the virtio-gpu device whose virtio-mmio transport is at `base`.
/// Called by the hardware bus when it binds `virtio-gpu` to a device
/// (`kernel/src/boot/hwbus.rs`: the stage that settles every device no earlier
/// stage named, in task context), before the framebuffer is registered
/// (`kernel/src/boot/fb.rs` then asks [`framebuffer`]).
#[cfg(any(feature = "vf2", feature = "k1"))]
pub fn init_at(_base: usize) -> Result<(), ()> {
    Err(())
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub fn init_at(base: usize) -> Result<(), ()> {
    let mut g = GPU.lock();
    match init_mmio(&mut g, base) {
        Ok(()) => {
            let fb = g.fb.expect("start() set the framebuffer");
            kprintln!("[VIRTIO-GPU] virtio-mmio {:#x}: {}x{} at {} Hz, 2D scanout", base, fb.width, fb.height, fb.hz);
            Ok(())
        }
        Err(e) => {
            kprintln!("[VIRTIO-GPU] virtio-mmio {:#x} not used: {:?}", base, e);
            Err(())
        }
    }
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
fn init_mmio(g: &mut Gpu, base: usize) -> Result<(), GpuError> {
    if g.t.is_some() {
        return Err(GpuError::Busy);
    }
    let mut vdev = VirtioDev::zeroed();
    // SAFETY: `base` is a populated virtio-mmio window the bus enumerated.
    if unsafe { probe(base, &mut vdev) }.is_err() || vdev.device_id != VIRTIO_DEV_GPU {
        return Err(GpuError::NotGpu);
    }
    // virtio-gpu has no legacy interface, and QEMU's virtio-mmio is legacy
    // (version 1) unless started with `-global virtio-mmio.force-legacy=false`.
    if vdev.version == 1 {
        return Err(GpuError::Legacy);
    }
    // SAFETY: the status handshake of the window just probed.
    let accepted = unsafe { init_with(&mut vdev, p::F_EDID) }.map_err(|_| GpuError::Features)?;
    map_buffers(g, Dma::mmio(base))?;
    let dma = g.dma;
    // SAFETY: queue 0 of that device; `dma` maps its rings.
    if unsafe { virtq_init(&mut vdev, CONTROLQ, &mut g.vq, &dma) }.is_err() {
        return Err(GpuError::Queue);
    }
    dma.enable().map_err(|_| GpuError::Dma)?;
    g.t = Some(Transport::Mmio(vdev));
    // SAFETY: DRIVER_OK after the queue is registered, as the handshake ends.
    unsafe {
        let s = mmio_read(vdev.base, VIRTIO_MMIO_STATUS);
        mmio_write(vdev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK);
    }
    g.start(accepted & p::F_EDID != 0)
}

/// Bring up the virtio-gpu PCI function `info` (`1af4:1050`, modern
/// transport): its BARs are assigned from `window` and mapped, the control
/// queue is registered with no MSI-X vector (the queue is polled).
#[cfg(all(feature = "pci", target_os = "none"))]
pub fn init_pci<C: azos_pci::ConfigSpace>(
    cfg: &mut C,
    info: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
) -> Result<(), GpuError> {
    let mut g = GPU.lock();
    let r = init_pci_locked(&mut g, cfg, info, window);
    match r {
        Ok(()) => {
            let fb = g.fb.expect("start() set the framebuffer");
            kprintln!("[VIRTIO-GPU] virtio-pci {}: {}x{} at {} Hz, 2D scanout", info.bdf, fb.width, fb.height, fb.hz);
        }
        Err(e) => kprintln!("[VIRTIO-GPU] virtio-pci {} not used: {:?}", info.bdf, e),
    }
    r
}

#[cfg(all(feature = "pci", target_os = "none"))]
fn init_pci_locked<C: azos_pci::ConfigSpace>(
    g: &mut Gpu,
    cfg: &mut C,
    info: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
) -> Result<(), GpuError> {
    use super::pci::msix_selftest::{map_bars, KernelBar};
    use super::pci::{
        common_cfg_bar, find_virtio_caps, VirtioPciDevice, VIRTIO_F_ACCESS_PLATFORM_HI_BIT, VIRTIO_PCI_NO_VECTOR,
    };

    if g.t.is_some() {
        return Err(GpuError::Busy);
    }
    if info.vendor != 0x1af4 || info.device != p::PCI_DEVICE {
        return Err(GpuError::NotGpu);
    }
    let bar_base = map_bars(cfg, info, window).map_err(|_| GpuError::Pci("bars"))?;
    let dma = Dma::pci(info.bdf.requester_id());
    map_buffers(g, dma)?;

    let (caps, n) = find_virtio_caps(cfg, info.bdf);
    let bar = common_cfg_bar(&caps, n).ok_or(GpuError::Pci("no virtio capabilities"))?;
    let dev_base = bar_base.get(bar as usize).copied().filter(|&b| b != 0).ok_or(GpuError::Pci("bar unmapped"))?;
    let mut dev = VirtioPciDevice::new(KernelBar::new(dev_base), &caps, n, bar)
        .ok_or(GpuError::Pci("capabilities in different BARs"))?;
    dev.begin(p::F_EDID, VIRTIO_F_ACCESS_PLATFORM_HI_BIT).map_err(|_| GpuError::Features)?;
    let edid = dev.driver_features_low() & p::F_EDID != 0;

    let want = super::VIRTIO_QUEUE_SIZE as u16;
    // SAFETY: a fresh queue structure; the rings are mapped through `dma`.
    let (d, a, u) = unsafe { super::virtq_alloc_rings(&mut g.vq, want, &dma) }.map_err(|_| GpuError::NoMemory)?;
    let agreed = dev.setup_queue(CONTROLQ as u16, want, d, a, u, VIRTIO_PCI_NO_VECTOR);
    if agreed < 2 {
        dev.reset();
        return Err(GpuError::Queue);
    }
    if agreed < want {
        // SAFETY: the rings above, re-threaded for the smaller size.
        unsafe { super::virtq_resize(&mut g.vq, agreed) };
    }
    let off = dev.queue_notify_off_of(CONTROLQ as u16);
    let notify = dev_base + dev.queue_notify_offset(off);
    dma.enable().map_err(|_| GpuError::Dma)?;
    g.t = Some(Transport::Pci { notify });
    dev.set_driver_ok();
    g.start(edid)
}

// The queue logic against a device simulated in host memory (the suite that
// pulls this module in, `tests/host/drivers-tests`, builds it with `cfg(test)`).
// What needs the real device -- the doorbell, the bring-up, the display -- is
// covered by the QEMU rows.
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{VirtqAvail, VirtqDesc, VirtqUsed, VirtqUsedElem, VIRTQ_CAPACITY};

    /// A queue in leaked host memory, as the suite's `virtq` tests build one.
    fn queue(num: u16) -> Virtq {
        let desc = Box::leak(Box::new(core::array::from_fn::<VirtqDesc, VIRTQ_CAPACITY, _>(
            |_| VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 })));
        let avail = Box::leak(Box::new(VirtqAvail { flags: 0, idx: 0, ring: [0; VIRTQ_CAPACITY] }));
        let used = Box::leak(Box::new(VirtqUsed {
            flags: 0, idx: 0,
            ring: core::array::from_fn::<VirtqUsedElem, VIRTQ_CAPACITY, _>(|_| VirtqUsedElem { id: 0, len: 0 }) }));
        for i in 0..num as usize { desc[i].next = (i as u16) + 1; }
        let mut vq = Virtq::zeroed();
        vq.desc = desc.as_mut_ptr();
        vq.avail = avail;
        vq.used = used;
        vq.num = num;
        vq.free_head = 0;
        vq.free_count = num;
        vq
    }

    /// 64 x 32 pixels, a framebuffer the driver never reads (the device is simulated).
    fn gpu() -> Box<Gpu> {
        let mut g = Box::new(Gpu::new());
        g.vq = queue(16);
        let px = Box::leak(vec![0u8; 64 * 32 * 4].into_boxed_slice());
        g.fb = Some(Fb { phys: px.as_ptr() as u64, va: px.as_ptr() as usize, width: 64, height: 32, stride: 256, hz: 60 });
        // The host shim maps a virtual address to itself.
        g.slots_bus = g.slots.as_ptr() as u64;
        g.big_bus = (&raw const g.big) as u64;
        g
    }

    /// The device side of the queue: walks the avail ring, answers each chain.
    #[derive(Clone, Copy)]
    struct Dev {
        desc: *mut VirtqDesc,
        avail: *const VirtqAvail,
        used: *mut VirtqUsed,
        num: u16,
        seen: u16,
    }
    // SAFETY: the rings are leaked host memory the test hands to one thread at a time.
    unsafe impl Send for Dev {}

    impl Dev {
        fn of(vq: &Virtq) -> Dev {
            Dev { desc: vq.desc, avail: vq.avail, used: vq.used, num: vq.num, seen: 0 }
        }

        /// Answer every chain not seen yet with `answer(request type)`; the requests, in order.
        fn step(&mut self, answer: &dyn Fn(u32) -> u32) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            // SAFETY: the pointers are the leaked rings and the slots the driver queued.
            unsafe {
                let idx = core::ptr::read_volatile(core::ptr::addr_of!((*self.avail).idx));
                while self.seen != idx {
                    let head = core::ptr::addr_of!((*self.avail).ring[(self.seen % self.num) as usize]).read_unaligned() as usize;
                    let d0 = self.desc.add(head);
                    let (addr, len, flags, next) = (
                        core::ptr::addr_of!((*d0).addr).read_unaligned(),
                        core::ptr::addr_of!((*d0).len).read_unaligned(),
                        core::ptr::addr_of!((*d0).flags).read_unaligned(),
                        core::ptr::addr_of!((*d0).next).read_unaligned(),
                    );
                    assert_eq!(flags, VIRTQ_DESC_F_NEXT, "request: device-readable, chained");
                    let req = core::slice::from_raw_parts(addr as *const u8, len as usize).to_vec();
                    let d1 = self.desc.add(next as usize);
                    assert_eq!(core::ptr::addr_of!((*d1).flags).read_unaligned(), VIRTQ_DESC_F_WRITE, "answer: device-writable");
                    let resp = core::ptr::addr_of!((*d1).addr).read_unaligned() as *mut u8;
                    let ty = answer(u32::from_le_bytes(req[..4].try_into().unwrap()));
                    core::ptr::copy_nonoverlapping(ty.to_le_bytes().as_ptr(), resp, 4);
                    let u = core::ptr::addr_of_mut!((*self.used).idx);
                    let at = core::ptr::read_volatile(u);
                    core::ptr::addr_of_mut!((*self.used).ring[(at % self.num) as usize])
                        .write_unaligned(VirtqUsedElem { id: head as u32, len: 24 });
                    core::ptr::write_volatile(u, at.wrapping_add(1));
                    out.push(req);
                    self.seen = self.seen.wrapping_add(1);
                }
            }
            out
        }
    }

    const OK: fn(u32) -> u32 = |_| p::RESP_OK_NODATA;

    fn le32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn a_commit_is_a_transfer_then_a_flush_behind_one_publish() {
        // Canary: a swapped pair (flush before the copy), a wrong offset or a
        // rectangle not cut to the screen shows stale or garbage pixels.
        let mut g = gpu();
        let mut dev = Dev::of(&g.vq);
        g.commit(Rect { x: 4, y: 2, w: 8, h: 3 }, true);
        let reqs = dev.step(&OK);
        assert_eq!(reqs.len(), 2);
        assert_eq!(le32(&reqs[0], 0), p::CMD_TRANSFER_TO_HOST_2D);
        assert_eq!(le32(&reqs[1], 0), p::CMD_RESOURCE_FLUSH);
        let rect = |b: &[u8]| [le32(b, 24), le32(b, 28), le32(b, 32), le32(b, 36)];
        assert_eq!(rect(&reqs[0]), [4, 2, 8, 3]);
        assert_eq!(rect(&reqs[1]), [4, 2, 8, 3]);
        assert_eq!(u64::from_le_bytes(reqs[0][40..48].try_into().unwrap()), 2 * 256 + 4 * 4, "byte offset of the first pixel");
        assert_eq!((le32(&reqs[0], 48), le32(&reqs[1], 40)), (RESOURCE, RESOURCE));
        assert_eq!(g.busy, 0b110, "both slots of the first commit are out");
        assert_eq!(g.vq.free_count, 12);
        g.reap();
        assert_eq!((g.busy, g.vq.free_count), (0, 16), "answered: slots and descriptors are back");
    }

    #[test]
    fn a_rectangle_is_cut_to_the_framebuffer() {
        let mut g = gpu();
        let mut dev = Dev::of(&g.vq);
        g.commit(Rect { x: 60, y: 30, w: 100, h: 100 }, true);
        let reqs = dev.step(&OK);
        assert_eq!([le32(&reqs[0], 24), le32(&reqs[0], 28), le32(&reqs[0], 32), le32(&reqs[0], 36)], [60, 30, 4, 2]);
        g.commit(Rect { x: 64, y: 0, w: 5, h: 5 }, true);
        g.commit(Rect { x: 0, y: 32, w: 5, h: 5 }, true);
        g.commit(Rect { x: 1, y: 1, w: 0, h: 5 }, true);
        assert!(dev.step(&OK).is_empty(), "nothing on screen, nothing queued");
    }

    #[test]
    fn concurrent_commits_use_distinct_slots() {
        let mut g = gpu();
        let mut dev = Dev::of(&g.vq);
        for k in 0..COMMITS_IN_FLIGHT as u32 {
            g.commit(Rect { x: k, y: 0, w: 1, h: 1 }, true);
        }
        let reqs = dev.step(&OK);
        assert_eq!(reqs.len(), 2 * COMMITS_IN_FLIGHT);
        // Each commit's request is still intact in its own slot (none overwrote another).
        for (k, pair) in reqs.chunks(2).enumerate() {
            assert_eq!((le32(&pair[0], 24), le32(&pair[1], 24)), (k as u32, k as u32));
        }
        assert_eq!(g.busy, 0b1_1111_1110);
        assert_eq!(g.vq.free_count, 0, "the queue is full");
        assert!(g.free_commit().is_none());
    }

    #[test]
    fn a_fifth_commit_waits_for_the_device_and_reuses_a_slot() {
        let mut g = gpu();
        let dev = Dev::of(&g.vq);
        for k in 0..4u32 {
            g.commit(Rect { x: k, y: 0, w: 1, h: 1 }, true);
        }
        // The device catches up while the fifth commit waits.
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            let mut dev = dev;
            dev.step(&OK).len()
        });
        g.commit(Rect { x: 9, y: 0, w: 1, h: 1 }, true);
        assert_eq!(t.join().unwrap(), 8, "the first four commits were answered");
        assert!(!g.dead);
        // The first four are answered; the fifth went into the first pair's slots.
        g.reap();
        assert_eq!((g.busy, g.vq.free_count), (0b110, 12), "only the fifth is in flight");
        let mut dev2 = Dev::of(&g.vq);
        dev2.seen = 8;
        let reqs = dev2.step(&OK);
        assert_eq!(reqs.len(), 2);
        assert_eq!(le32(&reqs[0], 24), 9, "the fifth's rectangle");
        g.reap();
        assert_eq!((g.busy, g.vq.free_count), (0, 16), "and its answer frees it");
    }

    #[test]
    fn a_full_queue_is_not_waited_for_when_the_caller_cannot_wait() {
        let mut g = gpu();
        for k in 0..4u32 {
            assert_eq!(g.commit(Rect { x: k, y: 0, w: 1, h: 1 }, false), Commit::Sent);
        }
        let t0 = std::time::Instant::now();
        assert_eq!(g.commit(Rect { x: 9, y: 0, w: 1, h: 1 }, false), Commit::Full);
        assert!(t0.elapsed() < std::time::Duration::from_millis(100), "no spinning");
        assert!(!g.dead, "a busy device is not a dead one");
        assert_eq!(unsafe { (*g.vq.avail).idx }, 8, "the fifth was not queued");
        // Once the device answers, the same rectangle goes through.
        let mut dev = Dev::of(&g.vq);
        dev.step(&OK);
        assert_eq!(g.commit(Rect { x: 9, y: 0, w: 1, h: 1 }, false), Commit::Sent);
    }

    #[test]
    fn a_device_that_never_answers_is_given_up_on() {
        let mut g = gpu();
        for k in 0..4u32 {
            g.commit(Rect { x: k, y: 0, w: 1, h: 1 }, true);
        }
        let t0 = std::time::Instant::now();
        g.commit(Rect { x: 9, y: 0, w: 1, h: 1 }, true);
        assert!(g.dead, "nothing answered within WAIT_MS");
        assert!(t0.elapsed() >= std::time::Duration::from_millis(WAIT_MS * 9 / 10));
        assert_eq!(unsafe { (*g.vq.avail).idx }, 8, "the fifth was never queued");
        let t0 = std::time::Instant::now();
        g.commit(Rect { x: 1, y: 1, w: 1, h: 1 }, true);
        assert!(t0.elapsed() < std::time::Duration::from_millis(100), "a dead device is not waited for again");
    }

    #[test]
    fn a_refused_commit_is_reported_once_and_frees_its_slot() {
        let mut g = gpu();
        let mut dev = Dev::of(&g.vq);
        g.commit(Rect { x: 0, y: 0, w: 2, h: 2 }, true);
        dev.step(&|ty| if ty == p::CMD_RESOURCE_FLUSH { 0x1203 } else { p::RESP_OK_NODATA });
        g.reap();
        assert!(g.warned, "the flush was refused");
        assert_eq!(g.busy, 0, "a refused request still frees its slot");
    }

    #[test]
    fn a_start_up_request_is_waited_for_and_judged() {
        let mut g = gpu();
        let dev = Dev::of(&g.vq);
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let mut dev = dev;
            dev.step(&OK)
        });
        assert_eq!(g.command("set_scanout", &p::set_scanout(0, RESOURCE, Rect { x: 0, y: 0, w: 64, h: 32 })), Ok(()));
        let reqs = t.join().unwrap();
        assert_eq!(le32(&reqs[0], 0), p::CMD_SET_SCANOUT);
        assert_eq!(g.busy, 0);
        // A refusal is an error the caller sees.
        let dev = Dev::of(&g.vq);
        let mut dev = Dev { seen: 1, ..dev };
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            dev.step(&|_| 0x1202)
        });
        assert_eq!(g.command("create_2d", &p::resource_create_2d(1, 2, 64, 32)), Err(GpuError::Command("create_2d")));
        t.join().unwrap();
    }
}
