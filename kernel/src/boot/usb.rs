// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! USB host wiring (Kconfig `USB_HOST`, `USB_XHCI`).
//!
//! The host itself is `azos_usb` (crates/drivers/usb), pure and host-tested
//! against a register-level xHCI mock. This file is what only the kernel can
//! do:
//!
//! - the three traits the crate reaches the machine through: [`KRegs`] (the
//!   mapped register window), [`KMem`] (page-allocator memory under the
//!   device's DMA limit, mapped through its `DmaDomain`, cache maintenance for
//!   a non-coherent master) and [`KClock`] (the arch counter);
//! - the probe the hardware bus calls for a controller it bound to the `xhci`
//!   driver: [`attach_pci`] (a function of PCI class 0C0330, from the PCI
//!   bring-up that owns the configuration space and the BAR window) and
//!   [`attach_dt`] (a `generic-xhci` node, or a `snps,dwc3` one whose `dr_mode` is `host`);
//! - the `usb` task, which calls the core's `service` every `USB_POLL_MS` (the
//!   controller is polled: an MSI-X route is a test-week item) and prints
//!   the hot-plug events;
//! - the listing: the lister class driver is registered with the core, and
//!   the introspection tree (`usb/devN`) reads its rows;
//! - the mass-storage class driver (Kconfig `USB_STORAGE`): a stick becomes a
//!   disk behind its own request queue (`azos_drv_block::usb_msc`); the `usb`
//!   task drives it after each turn of the core, and a task reads its sector 0
//!   once it is ready, so the data path is exercised from the first plug;
//! - the network class driver (Kconfig `USB_CDC`): a CDC-ECM or CDC-NCM
//!   function becomes a NIC of the network device table
//!   (`azos_drv_net::usb_cdc`). The `usb` task drives it after each turn of the
//!   core; when the function comes up the NIC is registered and the stack
//!   gets an interface for it (`azos_net::net_nic_added`, and a DHCP exchange
//!   when it is the primary one and CONFIG.INI asks for it), when it goes the
//!   NIC is unregistered, and while frames wait the network poller is woken
//!   (nothing else tells it: the adapter has no interrupt of its own here).
//!   The serial function of the same class driver (CDC-ACM) becomes a port
//!   of the `Uart` table (`azos_syscall::devices::plug_line`, [`serial`]):
//!   offered as `uart.2` when it is ready and withdrawn when it goes. With
//!   Kconfig `USB_CDC_CONSOLE` the kernel then holds that port itself and the
//!   console runs over it ([`console`]).
//! - the video class driver (Kconfig `USB_UVC`): a UVC camera becomes the
//!   producer of the camera frame ring (`tasks::CAM_RING`) while a reader is
//!   attached to it, in the CSI capture task's place. The driver lives behind
//!   a sleeping mutex that the class-driver registry takes per call and the
//!   `usb` task takes for the turn that drives its second half; the task naps
//!   1 ms instead of `USB_POLL_MS` while a stream runs or a step is in
//!   flight, and prints one line per state the camera reaches.
//!
//! One controller is driven: the first the bus binds. A second is refused
//! with a line (the pipe rings and the device table are the host's, not
//! per controller yet).

#[cfg(feature = "usb-xhci")]
pub(crate) use xhci_host::*;

/// The serial function as a `Uart` port (Kconfig `USB_CDC`).
#[cfg(feature = "usb-cdc")]
mod serial;

/// The console over the serial function (Kconfig `USB_CDC_CONSOLE`).
#[cfg(feature = "usb-cdc-console")]
mod console;

/// The lister's rows, behind a spinlock held only for an attach, a detach or
/// a read.
#[cfg(any(feature = "usb-xhci", feature = "inspect"))]
static LISTER: azos_sync::SpinLock<azos_usb::listing::Lister> =
    azos_sync::SpinLock::new(azos_usb::listing::Lister::new());

/// The controller: the traits, the probe, the `usb` task.
#[cfg(feature = "usb-xhci")]
mod xhci_host {
    use azos_dma::{Direction, DmaDomain};
    use azos_rings::{Consumer, Full, Queue};
    use azos_sync::kmutex::Mutex;
    use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
    use azos_usb::hw::{Clock, DmaBuf, Memory, Regs, PAGE};
    use super::LISTER;
    use azos_usb::listing::Lister;
    #[cfg(feature = "usb-storage")]
    use azos_drv_block::usb_msc::{Event, UsbDisk};
    #[cfg(feature = "usb-storage")]
    use azos_usb::class::msc::Msc;
    #[cfg(feature = "usb-cdc")]
    use azos_drv_net::usb_cdc::{Event as NicEvent, UsbNic};
    #[cfg(feature = "usb-cdc")]
    use azos_usb::class::cdc::{CdcAcm, CdcNet};
    #[cfg(feature = "usb-cdc")]
    use super::serial::{Event as SerialEvent, UsbSerial};
    #[cfg(feature = "usb-uvc")]
    use azos_usb::class::uvc::{State as CamState, Uvc, Want};
    #[cfg(feature = "usb-uvc")]
    use crate::tasks::{CamRing, CAM_RING};
    use azos_usb::usbcore::pipe::PipeRings;
    use azos_usb::usbcore::Usb;
    use azos_usb::{EventKind, UsbEvent, EVENT_DEPTH, MAX_PIPES};

    use crate::kprintln;

    // ---- The three traits ----

    /// The controller's register window, mapped.
    pub(crate) struct KRegs {
        base: usize,
    }

    impl Regs for KRegs {
        fn read32(&self, off: usize) -> u32 {
            // SAFETY: `base` is the controller's register window, mapped by the
            // attach before the first access; the driver's offsets come from the
            // controller's own capability registers.
            unsafe { core::ptr::read_volatile((self.base + off) as *const u32) }
        }
        fn write32(&self, off: usize, val: u32) {
            // SAFETY: as for `read32`.
            unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val) }
        }
    }

    /// The page allocator as [`azos_dma::alloc_below`] takes it: runs of
    /// contiguous pages.
    struct Pmm;

    impl azos_dma::PageSource for Pmm {
        fn alloc(&self, len: usize) -> Option<u64> {
            azos_mm::pmm::alloc_contiguous(len / PAGE).ok().map(|p| p.0 as u64)
        }
        fn free(&self, pa: u64, len: usize) {
            for i in 0..len / PAGE {
                let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa as usize + i * PAGE));
            }
        }
    }

    /// Controller memory: pages under the device's DMA limit, mapped for it.
    pub(crate) struct KMem {
        domain: &'static dyn DmaDomain,
    }

    impl Memory for KMem {
        fn alloc_region(&self, len: usize, align: usize, mask: u64) -> Option<DmaBuf> {
            let pa = azos_dma::alloc_below(&Pmm, mask, len).ok()?;
            if pa % align as u64 != 0 {
                azos_dma::PageSource::free(&Pmm, pa, len);
                return None;
            }
            let bus = match self.domain.map(pa, len, Direction::Bidirectional) {
                Ok(b) if b.0.checked_add(len as u64 - 1).is_some_and(|e| e <= mask) => b.0,
                Ok(b) => {
                    let _ = self.domain.unmap(b, len);
                    azos_dma::PageSource::free(&Pmm, pa, len);
                    return None;
                }
                Err(_) => {
                    azos_dma::PageSource::free(&Pmm, pa, len);
                    return None;
                }
            };
            let cpu = azos_mm::addr::phys_to_virt(pa as usize) as *mut u8;
            // SAFETY: `len` bytes of the direct map at `pa`, ours until freed.
            Some(unsafe { DmaBuf::new(cpu, bus, len) })
        }

        fn free_region(&self, b: DmaBuf) {
            let pa = azos_mm::addr::virt_to_phys(b.cpu() as usize) as u64;
            let _ = self.domain.unmap(azos_dma::DmaAddr(b.bus()), b.len());
            azos_dma::PageSource::free(&Pmm, pa, b.len());
        }

        fn enable(&self) -> bool {
            self.domain.enable().is_ok()
        }

        fn to_device(&self, cpu: *const u8, len: usize) {
            // SAFETY: a range of a region `alloc_region` handed out.
            unsafe { azos_dma::cache::sync_for_device(self.domain, cpu as usize, len, Direction::Bidirectional) }
        }

        fn from_device(&self, cpu: *const u8, len: usize) {
            // SAFETY: as for `to_device`.
            unsafe { azos_dma::cache::sync_for_cpu(self.domain, cpu as usize, len, Direction::Bidirectional) }
        }
    }

    /// The arch counter. A wait of a millisecond or more sleeps the task; a
    /// shorter one spins (the counter is the only clock a driver has before the
    /// scheduler exists, and a sleep before then falls back to a spin anyway).
    pub(crate) struct KClock;

    impl Clock for KClock {
        fn now_us(&self) -> u64 {
            azos_drv_sys::timebase::now().saturating_mul(1_000_000) / azos_drv_sys::timebase::TIMER_FREQ
        }
        fn delay_us(&self, us: u32) {
            if us >= 1_000 {
                azos_syscall::sleep::sleep_ms(us.div_ceil(1_000) as u64);
            } else {
                let until = self.now_us() + us as u64;
                while self.now_us() < until {
                    core::hint::spin_loop();
                }
            }
        }
    }

    // ---- The host ----

    type Host = Usb<'static, KRegs, KMem, KClock>;

    pub(crate) static RINGS: [PipeRings; MAX_PIPES] = [const { PipeRings::new() }; MAX_PIPES];
    static EVENTS: Queue<UsbEvent, EVENT_DEPTH> = Queue::new(Full::Backpressure);

    struct State {
        usb: alloc::boxed::Box<Host>,
        events: Consumer<'static, UsbEvent, EVENT_DEPTH>,
        /// What the controller's DMA reaches, for the class drivers' buffers.
        #[cfg(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc"))]
        dma: (&'static dyn DmaDomain, u64),
    }

    /// The mass-storage disk, once the scheduler exists: leaked, because the
    /// block layer holds it as a `&'static dyn HwQueue`.
    #[cfg(feature = "usb-storage")]
    type Disk = UsbDisk<'static, KMem, KClock>;
    #[cfg(feature = "usb-storage")]
    static DISK: azos_sync::SpinLock<Option<&'static Disk>> = azos_sync::SpinLock::new(None);
    /// The USB network function, once the scheduler exists: leaked, because
    /// the device table holds it as a `&'static dyn NetDevice`.
    #[cfg(feature = "usb-cdc")]
    type Nic = UsbNic<'static, KMem, KClock>;
    #[cfg(feature = "usb-cdc")]
    static NIC: azos_sync::SpinLock<Option<&'static Nic>> = azos_sync::SpinLock::new(None);
    /// The USB serial function, leaked for the same reason: the `Uart` table
    /// holds it as a `&'static dyn SerialLine`.
    #[cfg(feature = "usb-cdc")]
    type Serial = UsbSerial<'static, KMem, KClock>;
    #[cfg(feature = "usb-cdc")]
    static SERIAL: azos_sync::SpinLock<Option<&'static Serial>> = azos_sync::SpinLock::new(None);
    /// The `Uart` port the serial function was offered as; 0: it is not offered.
    #[cfg(feature = "usb-cdc")]
    static SERIAL_PORT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    /// The USB camera, once the scheduler exists. The registry takes the lock
    /// per call ([`SharedCamera`]), the `usb` task for its own turn.
    #[cfg(feature = "usb-uvc")]
    type Camera = Uvc<'static, KMem, KClock, CamRing>;
    #[cfg(feature = "usb-uvc")]
    static CAMERA: Mutex<Option<Camera>> = Mutex::new(None);
    /// A camera is the frame source (the CSI capture task stands down), and a
    /// stream or one of its steps is in flight (the `usb` task naps 1 ms).
    #[cfg(feature = "usb-uvc")]
    static CAMERA_SOURCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    #[cfg(feature = "usb-uvc")]
    static CAMERA_BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    /// The stream's first frame was reported.
    #[cfg(feature = "usb-uvc")]
    static CAMERA_FIRST: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    /// The state the last status line was printed for.
    #[cfg(feature = "usb-uvc")]
    static CAMERA_SEEN: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(u8::MAX);
    /// The `usb` task, for [`usb_kick`].
    #[cfg(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc"))]
    static USB_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// Held by the `usb` task for the length of a service call, which sleeps in
    /// enumeration: a sleeping mutex, not a spinlock.
    static STATE: Mutex<Option<State>> = Mutex::new(None);

    /// The lister as the core sees it: a class driver that takes `LISTER`'s lock
    /// per call (the registry holds it for a whole service call, which sleeps).
    struct SharedLister;

    impl UsbClass for SharedLister {
        fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> azos_devif::Out<u32> {
            LISTER.lock_irqsave().attach(claim, vid_pid, triple, speed_port)
        }
        fn detach(&mut self, claim: u32) -> azos_devif::Out<u32> {
            LISTER.lock_irqsave().detach(claim)
        }
    }

    /// The camera as the core sees it: a class driver that takes `CAMERA`'s
    /// lock per call.
    #[cfg(feature = "usb-uvc")]
    struct SharedCamera;

    #[cfg(feature = "usb-uvc")]
    impl UsbClass for SharedCamera {
        fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, speed_port: u32) -> azos_devif::Out<u32> {
            match CAMERA.lock().as_mut() {
                Some(c) => UsbClass::attach(c, claim, vid_pid, triple, speed_port),
                None => azos_devif::Out::new(azos_devif::outcome::UNSUPPORTED, 0),
            }
        }
        fn detach(&mut self, claim: u32) -> azos_devif::Out<u32> {
            match CAMERA.lock().as_mut() {
                Some(c) => UsbClass::detach(c, claim),
                None => azos_devif::Out::new(azos_devif::outcome::OK, 0),
            }
        }
    }

    /// Start the controller whose registers are at `base` and publish the host.
    fn bring_up(base: usize, domain: &'static dyn DmaDomain, dma_mask: u64, what: impl core::fmt::Display) -> Result<(), ()> {
        if STATE.lock().is_some() {
            kprintln!("[USB] {}: a controller is driven already; this one is left alone", what);
            return Err(());
        }
        let (Some(producer), Some(events)) = (EVENTS.producer(), EVENTS.consumer()) else { return Err(()) };
        // Built in the box, the controller too (`Usb::init_controller`): the core
        // with the controller is tens of KB, and `tools/stack_frames.py` holds
        // every function that is not boot-only to 8 KiB on fleet.
        let mut slot = alloc::boxed::Box::<Host>::new_uninit();
        let usb = match Usb::init_controller(&mut slot, KRegs { base }, KMem { domain }, KClock, dma_mask, false, &RINGS, producer) {
            Ok(u) => u,
            Err(e) => {
                azos_drv_sys::kwarn!("[USB] {}: the xHCI controller did not start: {:?}", what, e);
                return Err(());
            }
        };
        let (ports, slots, ac64, csz) = {
            let hc = usb.controller();
            (hc.ports(), hc.max_slots(), hc.caps().ac64, hc.caps().ctx_size())
        };
        kprintln!(
            "[USB] xHCI {}: {} ports, {} slots, {} DMA, {}-byte contexts; polled every {} ms",
            what, ports, slots, if ac64 { "64-bit" } else { "32-bit" }, csz, azos_limits::USB_POLL_MS);
        // SAFETY: `init_controller` returned `Ok`: every field is written.
        let usb = unsafe { slot.assume_init() };
        *STATE.lock() = Some(State {
            usb,
            events,
            #[cfg(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc"))]
            dma: (domain, dma_mask),
        });
        Ok(())
    }

    /// Attach the xHCI function `f` the PCI bring-up found. `dma_mask` is the
    /// hardware bus's record of how high the host bridge lets it DMA.
    #[cfg(feature = "pci")]
    pub(crate) fn attach_pci<C: azos_pci::ConfigSpace>(
        cfg: &mut C,
        f: &azos_pci::FunctionInfo,
        window: &mut azos_pci::BarWindow,
        dma_mask: u64,
    ) -> Result<(), ()> {
        let bars = azos_drv_virtio::virtio::pci::msix_selftest::map_bars(cfg, f, window).map_err(|e| {
            azos_drv_sys::kwarn!("[USB] xHCI {}: BARs not mapped: {:?}", f.bdf, e);
        })?;
        if bars[0] == 0 {
            azos_drv_sys::kwarn!("[USB] xHCI {}: BAR 0 is not a memory window", f.bdf);
            return Err(());
        }
        let rid = (f.bdf.bus as u32) << 8 | (f.bdf.device as u32) << 3 | f.bdf.function as u32;
        let domain = azos_dma::registry::domain_for(Some(rid));
        bring_up(bars[0], domain, dma_mask, f.bdf)
    }

    /// The device tree the firmware handed the kernel (physical address; 0:
    /// none), kept for the one property the probe reads from it.
    static DTB: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// The largest device tree the kernel reads (`azos_dtb`'s own bound).
    const MAX_DTB: usize = 4 * 1024 * 1024;

    /// Remember the device tree, before the hardware bus binds anything.
    pub(crate) fn note_dtb(dtb_ptr: usize) {
        DTB.store(dtb_ptr, core::sync::atomic::Ordering::Relaxed);
    }

    /// Does the device-tree node at `node` say `dr_mode = "host"`? False for
    /// any other value, for a node without the property and for a tree that
    /// cannot be read.
    fn dt_dr_mode_is_host(node: u32) -> bool {
        let ptr = DTB.load(core::sync::atomic::Ordering::Relaxed);
        if ptr == 0 {
            return false;
        }
        let base = azos_mm::addr::phys_to_virt(ptr) as *const u8;
        // SAFETY: the firmware handed the kernel this pointer and `early_main`
        // parsed the header; the size field bounds the slice below.
        let total = unsafe { core::slice::from_raw_parts(base.add(4), 4) };
        let total = u32::from_be_bytes([total[0], total[1], total[2], total[3]]) as usize;
        if !(40..=MAX_DTB).contains(&total) {
            return false;
        }
        // SAFETY: `total` bytes from the header's own size field.
        let blob = unsafe { core::slice::from_raw_parts(base, total) };
        let Some(fdt) = azos_soc::Fdt::parse(blob) else { return false };
        azos_usb::dwc3::is_host_only(fdt.prop(azos_soc::NodeId(node), "dr_mode"))
    }

    /// Attach a device-tree xHCI: a `generic-xhci` node, or a `snps,dwc3` node
    /// whose `dr_mode` is `host`. A DWC3 in `peripheral` or `otg` mode (or
    /// with no `dr_mode`) is a board's gadget port: it is left alone for the
    /// gadget stack. The DWC3's PHY, clocks and resets are the board glue's
    /// (SOC_FRAMEWORKS has no consumer yet): a controller the firmware did not
    /// bring up fails to start here and is reported.
    pub(crate) fn attach_dt(dev: &azos_drv_bus::hwbus::Device) -> Result<(), azos_drv_bus::hwbus::ProbeError> {
        use azos_drv_bus::hwbus::ProbeError;
        let dwc3 = dev.compatible().any(|c| c == "snps,dwc3");
        if dwc3 {
            if !dev.dt_node.is_some_and(dt_dr_mode_is_host) {
                kprintln!("[USB] {}: snps,dwc3 without dr_mode = \"host\": not driven as a host", dev.name.as_str());
                return Err(ProbeError::Failed);
            }
            if dev.size < azos_usb::dwc3::MIN_WINDOW {
                azos_drv_sys::kwarn!("[USB] {}: the snps,dwc3 window is too small for its global registers", dev.name.as_str());
                return Err(ProbeError::Failed);
            }
        }
        if dev.size == 0 || !crate::boot::map_mmio_region(dev.base as usize, dev.size as usize) {
            return Err(ProbeError::Failed);
        }
        {
            use azos_arch::Mmu;
            azos_arch::ARCH.flush_tlb_all();
        }
        if dwc3 {
            azos_usb::dwc3::set_host_mode(&KRegs { base: dev.base as usize });
        }
        let domain = azos_dma::registry::domain_for_mmio(dev.base);
        bring_up(dev.base as usize, domain, dev.dma_mask, dev.name.as_str()).map_err(|_| ProbeError::Failed)
    }

    /// Start the `usb` task, once the scheduler exists. A no-op without a
    /// controller.
    pub(crate) fn start_usb_task() {
        #[cfg(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc"))]
        let Some((domain, mask)) = STATE.lock().as_ref().map(|s| s.dma) else { return };
        #[cfg(feature = "usb-storage")]
        {
            let msc = Msc::new(KMem { domain }, KClock, mask, &RINGS[..]);
            // Built in the box: the disk's request queue is too big for a frame
            // (`tools/stack_frames.py`, fleet).
            let mut slot = alloc::boxed::Box::<Disk>::new_uninit();
            Disk::init(&mut slot, msc);
            // SAFETY: `init` wrote every field.
            let disk: &'static Disk = alloc::boxed::Box::leak(unsafe { slot.assume_init() });
            azos_drv_block::usb_msc::set_hooks(crate::boot::blk_block_until, crate::boot::blk_wake, usb_kick);
            *DISK.lock_irqsave() = Some(disk);
        }
        #[cfg(feature = "usb-cdc")]
        {
            let cdc = CdcNet::new(KMem { domain }, KClock, mask, &RINGS[..]);
            let nic: &'static Nic = alloc::boxed::Box::leak(alloc::boxed::Box::new(UsbNic::new(cdc, usb_kick)));
            *NIC.lock_irqsave() = Some(nic);
            let acm = CdcAcm::new(KMem { domain }, KClock, mask, &RINGS[..]);
            let serial: &'static Serial = alloc::boxed::Box::leak(alloc::boxed::Box::new(UsbSerial::new(acm, usb_kick)));
            *SERIAL.lock_irqsave() = Some(serial);
            // Once, before the boot seals the hooks: it does nothing until a
            // serial function is bound to the console.
            #[cfg(feature = "usb-cdc-console")]
            azos_drv_sys::uart::set_console_tee(super::console::tee);
        }
        #[cfg(feature = "usb-uvc")]
        {
            // The stream the CSI path would have made: its capture size and
            // rate, and a slot of the ring for a frame.
            let want = Want {
                width: azos_drv_sensor::csi::JPEG_CAP_W as u16,
                height: azos_drv_sensor::csi::JPEG_CAP_H as u16,
                fps: (1000 / azos_limits::CAMERA_TX_CAPTURE_PERIOD_MS.max(1)).max(1) as u16,
                max_frame: CamRing::slot_size(),
                max_jpeg: crate::tasks::CAMERA_JPEG_MAX,
            };
            let cam = Uvc::new(KMem { domain }, KClock, mask, &RINGS[..], &CAM_RING, want, camera_stamp);
            *CAMERA.lock() = Some(cam);
        }
        #[cfg(not(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc")))]
        if STATE.lock().is_none() {
            return;
        }
        azos_sched::task_create("usb", usb_task, 0, azos_sched::DEFAULT_PRIORITY);
    }

    /// Wake the `usb` task: a class driver queued a transfer, which the core
    /// moves to the controller on its next turn.
    #[cfg(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc"))]
    fn usb_kick() {
        let tid = USB_TID.load(core::sync::atomic::Ordering::Acquire);
        if tid != 0 {
            crate::boot::blk_wake(tid);
        }
    }

    fn usb_task(_arg: usize) {
        #[cfg(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc"))]
        USB_TID.store(azos_sync::waitqueue::caller_tid(), core::sync::atomic::Ordering::Release);
        loop {
            service_once();
            nap();
        }
    }

    /// Until the next turn of the core is due: `USB_POLL_MS`, or sooner when
    /// a class driver kicks the task.
    fn nap() {
        #[cfg(any(feature = "usb-storage", feature = "usb-cdc", feature = "usb-uvc"))]
        {
            let ticks = azos_syscall::sleep::ms_to_ticks(nap_ms());
            if crate::boot::blk_block_until(azos_drv_sys::timebase::now().saturating_add(ticks)) {
                return;
            }
        }
        azos_syscall::sleep::sleep_ms(nap_ms());
    }

    /// The length of a nap: `USB_POLL_MS`, or a millisecond while a camera
    /// streams (an isochronous camera needs a transfer per service interval
    /// out, and the descriptors it keeps queued last `USB_PIPE_DEPTH`
    /// intervals).
    fn nap_ms() -> u64 {
        #[cfg(feature = "usb-uvc")]
        if CAMERA_BUSY.load(core::sync::atomic::Ordering::Relaxed) {
            return 1;
        }
        azos_limits::USB_POLL_MS as u64
    }

    /// Read sector 0 of the mass-storage disk that just became ready, through its
    /// request queue, and say what is there: the evidence, from the first plug,
    /// that the whole path (CBW, data, CSW over the pipes) moves real bytes. A
    /// task of its own: the `usb` task runs the transfers this one waits for.
    #[cfg(feature = "usb-storage")]
    fn sector0_task(_arg: usize) {
        let Some(disk) = *DISK.lock_irqsave() else { return };
        let mut sector = [0u8; 512];
        match disk.read(azos_devif::block::OWNER_KERNEL, 0, 1, &mut sector) {
            Ok(()) => crate::kprintln!(
                "[USB] mass storage sector 0 read: {}",
                if sector[510] == 0x55 && sector[511] == 0xaa { "boot signature present" } else { "no boot signature" }
            ),
            Err(e) => crate::kprintln!("[USB] mass storage sector 0 read failed: {:?}", e),
        }
    }

    /// What one turn of the core did to the network and serial functions, for
    /// the code that runs once the host's lock is released (the stack and the
    /// `Uart` table take locks of their own).
    #[cfg(feature = "usb-cdc")]
    struct Turn {
        nic: NicEvent,
        serial: SerialEvent,
    }
    #[cfg(not(feature = "usb-cdc"))]
    type Turn = ();
    #[cfg(feature = "usb-cdc")]
    const NO_TURN: Turn = Turn { nic: NicEvent::None, serial: SerialEvent::None };
    #[cfg(not(feature = "usb-cdc"))]
    const NO_TURN: Turn = ();

    fn service_once() {
        let turn = service_core();
        #[cfg(feature = "usb-cdc")]
        {
            nic_turn(turn.nic);
            serial_turn(turn.serial);
        }
        #[cfg(not(feature = "usb-cdc"))]
        let _ = turn;
    }

    /// The serial function after a turn of the core: offer it to the `Uart`
    /// table when it came up, withdraw it when it went away, and put the
    /// console on it when Kconfig `USB_CDC_CONSOLE` says so.
    #[cfg(feature = "usb-cdc")]
    fn serial_turn(turn: SerialEvent) {
        use azos_syscall::devices::{plug_line, unplug_line};
        let Some(line) = *SERIAL.lock_irqsave() else { return };
        match turn {
            SerialEvent::Up => {
                let Some(port) = plug_line(line) else {
                    azos_drv_sys::kwarn!("[USB-CDC] a serial function is up, but the Uart table has no port for it");
                    return;
                };
                SERIAL_PORT.store(port, core::sync::atomic::Ordering::Release);
                kprintln!("[USB-CDC] serial function up: uart.{}", port);
                #[cfg(feature = "usb-cdc-console")]
                bind_console(line, port);
            }
            SerialEvent::Down => {
                #[cfg(feature = "usb-cdc-console")]
                super::console::unbind();
                let port = SERIAL_PORT.swap(0, core::sync::atomic::Ordering::AcqRel);
                if port != 0 {
                    unplug_line(port);
                }
                kprintln!("[USB-CDC] serial function removed");
            }
            SerialEvent::None => {}
        }
    }

    /// Put the console on the serial function that just came up as `port`.
    #[cfg(feature = "usb-cdc-console")]
    fn bind_console(line: &'static Serial, port: u32) {
        use azos_syscall::devices::{attach_client, SerialLine};
        // The line the device is asked to run: a CDC gadget ignores it, a
        // USB-UART bridge in ACM mode uses it, and a device without line coding
        // answers `UNSUPPORTED` and is used as it is.
        let _ = line.configure(azos_limits::USB_CDC_CONSOLE_BAUD as u32, 8, azos_devif::uart::PARITY_NONE, 1);
        super::console::bind();
        let r = attach_client(port, &super::console::CONSOLE);
        if r.code == azos_devif::outcome::OK {
            // After the bind: this line is the first the device shows.
            kprintln!("[USB-CDC] console on uart.{} ({} baud)", port, azos_limits::USB_CDC_CONSOLE_BAUD);
        } else {
            super::console::unbind();
            azos_drv_sys::kwarn!("[USB-CDC] console not put on uart.{}: attach answered {}", port, r.code);
        }
    }

    /// The network function after a turn of the core: tell the device table and
    /// the stack when it came up or went away, and the poller when frames wait.
    #[cfg(feature = "usb-cdc")]
    fn nic_turn(turn: NicEvent) {
        use azos_drv_api::net::NetDevice;
        let Some(nic) = *NIC.lock_irqsave() else { return };
        match turn {
            NicEvent::Up => {
                let mac = nic.mac();
                let Some(n) = azos_drv_net::net_device::register_usb(nic) else {
                    azos_drv_sys::kwarn!("[USB-CDC] a network function is up, but the NIC table has no number for it");
                    return;
                };
                kprintln!(
                    "[USB-CDC] network function up: NIC {}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    n, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                if azos_net::net_nic_added(n) == Some(azos_net::PRIMARY_IF)
                    && azos_config::CFG_NET_DHCP.load(core::sync::atomic::Ordering::Relaxed) != 0
                {
                    azos_sched::task_create("usb-dhcp", dhcp_task, 0, azos_sched::DEFAULT_PRIORITY);
                }
            }
            NicEvent::Down => {
                azos_drv_net::net_device::unregister_usb();
                kprintln!("[USB-CDC] network function removed");
            }
            NicEvent::None => {}
        }
        if nic.is_ready() && nic.rx_pending() {
            crate::net_rx_kick();
        }
    }

    /// The DHCP exchange of a primary interface that came with the adapter: the
    /// one the boot made before any NIC existed could not be answered. A task of
    /// its own, because the exchange waits for the network and the `usb` task
    /// must keep moving the frames it waits for.
    #[cfg(feature = "usb-cdc")]
    fn dhcp_task(_arg: usize) {
        kprintln!("[USB-CDC] running DHCP on the new interface");
        if !azos_net::dhcp::dhcp_start(azos_sched::task_yield) {
            azos_drv_sys::kwarn!("[USB-CDC] DHCP failed: the interface keeps its static configuration");
        }
    }

    /// The camera's second half: its steps and its stream, with the session
    /// of its claim, after the core's turn.
    #[cfg(feature = "usb-uvc")]
    fn camera_turn(usb: &mut Host) {
        use core::sync::atomic::Ordering::Relaxed;
        let mut g = CAMERA.lock();
        let Some(cam) = g.as_mut() else { return };
        let mut session = cam.claim().map(|c| usb.session(c));
        cam.service(session.as_mut().map(|s| s as &mut dyn azos_usb::UsbDevice));
        let st = cam.state();
        CAMERA_SOURCE.store(
            matches!(st, CamState::Negotiating | CamState::Ready | CamState::Starting | CamState::Streaming | CamState::Stopping),
            Relaxed,
        );
        CAMERA_BUSY.store(
            matches!(st, CamState::Negotiating | CamState::Starting | CamState::Streaming | CamState::Stopping),
            Relaxed,
        );
        let code = match st {
            CamState::Idle => 0,
            CamState::Claimed => 1,
            CamState::Negotiating => 2,
            CamState::Ready => 3,
            CamState::Starting => 4,
            CamState::Streaming => 5,
            CamState::Stopping => 6,
            CamState::Failed(_) => 7,
        };
        // A line per state reached, except the steps between: the evidence on
        // a board that the camera was understood, started and stopped.
        let prev = CAMERA_SEEN.swap(code, Relaxed);
        if prev != code {
            let n = cam.stats();
            let streamed = matches!(prev, 5 | 6);
            match (st, cam.stream_choice(), cam.mode()) {
                (CamState::Ready, _, _) if streamed => kprintln!(
                    "[UVC] stream stopped: {} frames, {} dropped, {} intervals lost, {} refused by the ring, {} too big, {} restarts",
                    n.frames, n.dropped, n.lost, n.refused, n.oversize, n.restarts),
                (CamState::Ready, Some(c), Some(m)) => kprintln!(
                    "[UVC] {:?} {}x{} at {} fps, {:?}: ready",
                    c.pixels, c.width, c.height, c.fps(), m),
                (CamState::Failed(f), _, _) => azos_drv_sys::kwarn!("[UVC] camera failed: {:?}", f),
                (CamState::Streaming, _, _) => kprintln!("[UVC] streaming"),
                (CamState::Idle, _, _) => kprintln!(
                    "[UVC] camera removed: {} frames, {} dropped, {} intervals lost, {} declined",
                    n.frames, n.dropped, n.lost, n.declined),
                _ => {}
            }
        }
        // The first frame of a stream, once.
        if st != CamState::Streaming {
            CAMERA_FIRST.store(false, Relaxed);
        } else if cam.stats().frames != 0 && !CAMERA_FIRST.swap(true, Relaxed) {
            kprintln!("[UVC] first frame delivered");
        }
    }

    /// The frame stamp of a camera: the arch counter, as the CSI path's.
    #[cfg(feature = "usb-uvc")]
    fn camera_stamp() -> u64 {
        azos_drv_sys::timebase::now()
    }

    /// A USB camera is the frame source: the CSI capture task stands down.
    #[cfg(feature = "usb-uvc")]
    pub(crate) fn uvc_is_source() -> bool {
        CAMERA_SOURCE.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// A reader attached to the frame ring: the camera starts on the next
    /// turn of the `usb` task, which is woken for it.
    #[cfg(feature = "usb-uvc")]
    pub(crate) fn uvc_kick() {
        if CAMERA_SOURCE.load(core::sync::atomic::Ordering::Relaxed) {
            usb_kick();
        }
    }

    fn service_core() -> Turn {
        let mut g = STATE.lock();
        let Some(st) = g.as_mut() else { return NO_TURN };
        let mut lister = UsbClassDirect(SharedLister);
        #[cfg(feature = "usb-hid")]
        let mut hid = crate::boot::usb_hid::HID.lock();
        #[cfg(feature = "usb-storage")]
        let disk = *DISK.lock_irqsave();
        #[cfg(feature = "usb-storage")]
        let mut storage = disk.map(|d| UsbClassDirect(d.class()));
        #[cfg(feature = "usb-cdc")]
        let nic = *NIC.lock_irqsave();
        #[cfg(feature = "usb-cdc")]
        let serial = *SERIAL.lock_irqsave();
        // The network function is registered twice, once per interface.
        #[cfg(feature = "usb-cdc")]
        let mut nic_comm = nic.map(|n| UsbClassDirect(n.class()));
        #[cfg(feature = "usb-cdc")]
        let mut nic_data = nic.map(|n| UsbClassDirect(n.class()));
        // And the serial function, after the network one: a communications
        // interface of an Ethernet function is the network driver's, of an ACM
        // function this one's.
        #[cfg(feature = "usb-cdc")]
        let mut serial_comm = serial.map(|p| UsbClassDirect(p.class()));
        #[cfg(feature = "usb-cdc")]
        let mut serial_data = serial.map(|p| UsbClassDirect(p.class()));
        #[cfg(feature = "usb-uvc")]
        let mut camera = UsbClassDirect(SharedCamera);
        let mut reg = Registry::new();
        let _ = reg.register(0, Lister::rule(), &mut lister);
        #[cfg(feature = "usb-hid")]
        let _ = reg.register(1, azos_usb_hid::HidClass::rule(), &mut hid.class);
        #[cfg(feature = "usb-storage")]
        if let Some(s) = storage.as_mut() {
            let _ = reg.register(2, Disk::rule(), s);
        }
        #[cfg(feature = "usb-cdc")]
        {
            let [comm, data] = Nic::rules();
            if let Some(c) = nic_comm.as_mut() {
                let _ = reg.register(3, comm, c);
            }
            if let Some(d) = nic_data.as_mut() {
                let _ = reg.register(4, data, d);
            }
            let [comm, data] = Serial::rules();
            if let Some(c) = serial_comm.as_mut() {
                let _ = reg.register(5, comm, c);
            }
            if let Some(d) = serial_data.as_mut() {
                let _ = reg.register(6, data, d);
            }
        }
        #[cfg(feature = "usb-uvc")]
        let _ = reg.register(7, Camera::rule(), &mut camera);
        st.usb.service(&mut reg);
        drop(reg);
        // The class drivers' second half: what needs the core, after its turn.
        #[cfg(feature = "usb-uvc")]
        camera_turn(&mut st.usb);
        #[cfg(feature = "usb-hid")]
        hid.poll(&mut st.usb);
        #[cfg(feature = "usb-storage")]
        if disk.is_some_and(|d| d.drive(&mut st.usb) == Event::Ready) {
            azos_sched::task_create("usb-msc", sector0_task, 0, azos_sched::DEFAULT_PRIORITY);
        }
        #[cfg(feature = "usb-cdc")]
        let turn = Turn {
            nic: nic.map_or(NicEvent::None, |n| n.drive(&mut st.usb)),
            serial: serial.map_or(SerialEvent::None, |p| p.drive(&mut st.usb)),
        };
        #[cfg(not(feature = "usb-cdc"))]
        let turn = ();
        while let Some(ev) = st.events.pop() {
            match ev.kind {
                EventKind::Attached => kprintln!(
                    "[USB] slot {} on root port {}: {:04x}:{:04x} class {:02x}:{:02x}:{:02x} attached",
                    ev.slot, ev.root_port, ev.vid_pid >> 16, ev.vid_pid & 0xffff,
                    ev.class >> 16, (ev.class >> 8) & 0xff, ev.class & 0xff),
                EventKind::Detached => kprintln!(
                    "[USB] slot {} ({:04x}:{:04x}) removed", ev.slot, ev.vid_pid >> 16, ev.vid_pid & 0xffff),
            }
        }
        turn
    }
}

// ---- The introspection tree ----

#[cfg(feature = "inspect")]
static TREE: azos_sync::SpinLock<Option<azos_usb::listing::Ids>> = azos_sync::SpinLock::new(None);

/// Add the `usb` subtree to the public tree.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_build(
    b: &mut azos_inspect::Builder<'_, '_>,
    parent: azos_inspect::NodeId,
) -> Result<(), azos_inspect::Error> {
    let ids = azos_usb::listing::build(b, parent)?;
    *TREE.lock_irqsave() = Some(ids);
    Ok(())
}

/// Rewrite the `usb` values from the lister's rows; the values that were not
/// published.
#[cfg(feature = "inspect")]
pub(crate) fn inspect_refresh(w: &azos_inspect::Writer<'_>) -> u32 {
    let g = TREE.lock_irqsave();
    let Some(ids) = g.as_ref() else { return 0 };
    azos_usb::listing::refresh(w, ids, &LISTER.lock_irqsave())
}
