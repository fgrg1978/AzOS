// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! USB host wiring (Kconfig `USB_HOST`, `USB_XHCI`, `USB_DWC2`).
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
//!   [`attach_dt`] (a `generic-xhci` node, or a `snps,dwc3` one whose `dr_mode` is `host`),
//!   and for a DesignWare USB 2.0 core (the Raspberry Pi's) [`attach_dwc2`];
//! - the `usb` task, which calls the core's `service` every `USB_POLL_MS` (the
//!   controller is polled: an MSI-X route is a test-week item) and prints
//!   the hot-plug events;
//! - the listing: the lister class driver is registered with the core, and
//!   the introspection tree (`usb/devN`) reads its rows;
//! - the mass-storage class driver (Kconfig `USB_STORAGE`): a stick becomes a
//!   disk behind its own request queue (`azos_drv_block::usb_msc`); the `usb`
//!   task drives it after each turn of the core. With Kconfig
//!   `USB_STORAGE_VOLUME` its FAT32 volume is mounted at `/usb` once it is
//!   ready and retired when it goes ([`stick`], `azos_fs::usbvol`), and an
//!   orderly power-off ejects it ([`storage_shutdown`]); without it a task
//!   reads its sector 0, so the data path is exercised from the first plug;
//! - the network class drivers (Kconfig `USB_CDC`, `USB_SMSC95XX`): a CDC-ECM
//!   or CDC-NCM function, or an SMSC LAN95xx one (the Raspberry Pi 3 B's
//!   Ethernet), becomes a NIC of the network device table
//!   (`azos_drv_net::usb_net`). The `usb` task drives it after each turn of the
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

#[cfg(feature = "usb-hc")]
pub(crate) use host::*;

/// The serial function as a `Uart` port (Kconfig `USB_CDC`).
#[cfg(feature = "usb-cdc")]
mod serial;

/// The console over the serial function (Kconfig `USB_CDC_CONSOLE`).
#[cfg(feature = "usb-cdc-console")]
mod console;

/// The lister's rows, behind a spinlock held only for an attach, a detach or
/// a read.
#[cfg(any(feature = "usb-hc", feature = "inspect"))]
static LISTER: azos_sync::SpinLock<azos_usb::listing::Lister> =
    azos_sync::SpinLock::new(azos_usb::listing::Lister::new());

/// The controller: the traits, the probe, the `usb` task.
#[cfg(feature = "usb-hc")]
mod host {
    use azos_dma::{Direction, DmaDomain, DomainKind};
    use azos_rings::{Consumer, Full, Queue};
    use azos_sync::kmutex::Mutex;
    use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
    use azos_usb::hw::{Clock, DmaBuf, Memory, Regs};
    use super::LISTER;
    use azos_usb::listing::Lister;
    #[cfg(feature = "usb-storage")]
    use azos_drv_block::usb_msc::{Event, UsbDisk};
    #[cfg(feature = "usb-storage")]
    use azos_usb::class::msc::Msc;
    #[cfg(feature = "usb-net")]
    use azos_drv_net::usb_net::{Event as NicEvent, UsbNic};
    #[cfg(feature = "usb-net")]
    use azos_usb::class::net::NetFunction;
    #[cfg(feature = "usb-cdc")]
    use azos_usb::class::cdc::{CdcAcm, CdcNet};
    #[cfg(feature = "usb-smsc95xx")]
    use azos_usb::class::smsc95xx::Smsc95xx;
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
    /// contiguous frames. The driver asks in its own 4 KiB pages
    /// (`azos_usb::hw::PAGE`); the allocator counts frames of the kernel's
    /// granule (16 or 64 KiB on aarch64 under Kconfig), so a request is
    /// rounded up to whole frames, the same way when it is freed.
    struct Pmm;

    fn frames(len: usize) -> usize {
        len.div_ceil(azos_arch_api::PAGE_SIZE)
    }

    impl azos_dma::PageSource for Pmm {
        fn alloc(&self, len: usize) -> Option<u64> {
            azos_mm::pmm::alloc_contiguous(frames(len)).ok().map(|p| p.0 as u64)
        }
        fn free(&self, pa: u64, len: usize) {
            for i in 0..frames(len) {
                let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa as usize + i * azos_arch_api::PAGE_SIZE));
            }
        }
    }

    /// Controller memory: pages under the device's DMA limit, mapped for it.
    pub(crate) struct KMem {
        domain: &'static dyn DmaDomain,
    }

    impl Memory for KMem {
        fn alloc_region(&self, len: usize, align: usize, mask: u64) -> Option<DmaBuf> {
            // `mask` is what the controller reaches on its bus; the domain
            // says which CPU addresses map there (a translated bus moves them).
            let pa = azos_dma::alloc_below(&Pmm, self.domain.cpu_limit(mask), len).ok()?;
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
            // The allocator zeroed the block through the CPU's caches: on a
            // controller that does not snoop them, RAM still holds what was
            // there and the dirty lines could be evicted over what it writes.
            // Written back and dropped once, whole, before it is handed out
            // (`Memory::alloc_region` promises zeroes; a coherent domain makes
            // this a no-op).
            // SAFETY: `len` bytes of the direct map at `pa`, ours until freed.
            unsafe { azos_dma::cache::sync_for_device(self.domain, cpu as usize, len, Direction::Bidirectional) };
            // SAFETY: as above.
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

        /// The direct map of a class driver's buffer, where the bus address
        /// names a physical one by arithmetic (a domain that remaps nothing,
        /// on an identity bus or one that moves addresses by an offset:
        /// `DmaDomain::phys_of`) and that is RAM the kernel manages: what a
        /// DWC2 copies the partial last packet of an IN through
        /// (`azos_usb::dwc2`). An IOMMU domain: `None`.
        fn cpu_of(&self, bus: u64, len: usize) -> Option<*mut u8> {
            if len == 0 || !matches!(self.domain.kind(), DomainKind::Identity | DomainKind::Soft) {
                return None;
            }
            let start = usize::try_from(self.domain.phys_of(bus)).ok()?;
            let end = start.checked_add(len - 1)?;
            // The frames the bytes lie in (`frame_index` takes a frame's own,
            // page-aligned, address: a byte address inside it is no frame).
            let page = azos_arch_api::PAGE_SIZE - 1;
            azos_mm::pmm::frame_index(start & !page)?;
            azos_mm::pmm::frame_index(end & !page)?;
            Some(azos_mm::addr::phys_to_virt(start) as *mut u8)
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
        #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
        dma: (&'static dyn DmaDomain, u64),
    }

    /// The mass-storage disk, once the scheduler exists: leaked, because the
    /// block layer holds it as a `&'static dyn HwQueue`.
    #[cfg(feature = "usb-storage")]
    type Disk = UsbDisk<'static, KMem, KClock>;
    #[cfg(feature = "usb-storage")]
    static DISK: azos_sync::SpinLock<Option<&'static Disk>> = azos_sync::SpinLock::new(None);
    /// The USB network functions, once the scheduler exists: leaked, because
    /// the device table holds one as a `&'static dyn NetDevice`. A CDC-ECM/NCM
    /// function, and an SMSC LAN95xx one (the Raspberry Pi 3 B's Ethernet).
    #[cfg(feature = "usb-cdc")]
    type Nic = UsbNic<CdcNet<'static, KMem, KClock>>;
    #[cfg(feature = "usb-cdc")]
    static NIC: azos_sync::SpinLock<Option<&'static Nic>> = azos_sync::SpinLock::new(None);
    #[cfg(feature = "usb-smsc95xx")]
    type SmscNic = UsbNic<Smsc95xx<'static, KMem, KClock>>;
    #[cfg(feature = "usb-smsc95xx")]
    static SMSC: azos_sync::SpinLock<Option<&'static SmscNic>> = azos_sync::SpinLock::new(None);
    /// Which function holds the device table's one USB NIC (`register_usb`):
    /// [`NIC_CDC`], [`NIC_SMSC`], 0 for none. The other one coming up is
    /// told it has no number; its going down must not take the holder's away.
    #[cfg(feature = "usb-net")]
    static NIC_HOLDER: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    #[cfg(feature = "usb-cdc")]
    const NIC_CDC: u8 = 1;
    #[cfg(feature = "usb-smsc95xx")]
    const NIC_SMSC: u8 = 2;
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
    #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
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

    /// Which controller a window holds.
    #[derive(Clone, Copy)]
    enum Kind {
        #[cfg(feature = "usb-xhci")]
        Xhci,
        #[cfg(feature = "usb-dwc2")]
        Dwc2,
    }

    /// The highest bus address a device-tree controller's DMA reaches: its
    /// CPU-side limit (`dma-ranges`) moved by its bus's offset, the same number
    /// on an identity bus.
    fn bus_reach(dev: &azos_drv_bus::hwbus::Device) -> u64 {
        dev.dma_mask.checked_add(dev.dma_offset).unwrap_or(u64::MAX)
    }

    /// Start the controller whose registers are at `base` and publish the host.
    fn bring_up(base: usize, domain: &'static dyn DmaDomain, dma_mask: u64, what: impl core::fmt::Display, kind: Kind) -> Result<(), ()> {
        if STATE.lock().is_some() {
            kprintln!("[USB] {}: a controller is driven already; this one is left alone", what);
            return Err(());
        }
        let (Some(producer), Some(events)) = (EVENTS.producer(), EVENTS.consumer()) else { return Err(()) };
        // Built in the box, the controller too (`Usb::init_controller`): the core
        // with the controller is tens of KB, and `tools/lint/stack_frames.py` holds
        // every function that is not boot-only to 8 KiB on fleet.
        let mut slot = alloc::boxed::Box::<Host>::new_uninit();
        let (regs, mem) = (KRegs { base }, KMem { domain });
        let started = match kind {
            #[cfg(feature = "usb-xhci")]
            Kind::Xhci => Usb::init_controller(&mut slot, regs, mem, KClock, dma_mask, false, &RINGS, producer),
            #[cfg(feature = "usb-dwc2")]
            Kind::Dwc2 => Usb::init_dwc2(&mut slot, regs, mem, KClock, dma_mask, &RINGS, producer),
        };
        let usb = match started {
            Ok(u) => u,
            Err(e) => {
                azos_drv_sys::kwarn!("[USB] {}: the controller did not start: {:?}", what, e);
                return Err(());
            }
        };
        let hc = usb.controller();
        if let Some(x) = hc.as_xhci() {
            kprintln!(
                "[USB] xHCI {}: {} ports, {} slots, {} DMA, {}-byte contexts; polled every {} ms",
                what, x.ports(), x.max_slots(), if x.caps().ac64 { "64-bit" } else { "32-bit" },
                x.caps().ctx_size(), azos_limits::USB_POLL_MS);
        }
        #[cfg(feature = "usb-dwc2")]
        if let Some(d) = hc.as_dwc2() {
            kprintln!("[USB] DWC2 {}: 1 port, {} host channels, 32-bit DMA; polled every {} ms",
                what, d.channels(), azos_limits::USB_POLL_MS);
        }
        // The class drivers' buffers go under what the controller reaches,
        // which may be less than the bus allows (an xHCI without AC64, a DWC2).
        #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
        let reach = hc.dma_mask();
        // SAFETY: the controller started: every field is written.
        let usb = unsafe { slot.assume_init() };
        *STATE.lock() = Some(State {
            usb,
            events,
            #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
            dma: (domain, reach),
        });
        Ok(())
    }

    /// Attach the xHCI function `f` the PCI bring-up found. `dma_mask` is the
    /// hardware bus's record of how high the host bridge lets it DMA.
    #[cfg(all(feature = "pci", feature = "usb-xhci"))]
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
        bring_up(bars[0], domain, dma_mask, f.bdf, Kind::Xhci)
    }

    /// The device tree the firmware handed the kernel (physical address; 0:
    /// none), kept for the one property the probes read from it.
    static DTB: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// The largest device tree the kernel reads (`azos_dtb`'s own bound).
    const MAX_DTB: usize = 4 * 1024 * 1024;

    /// Remember the device tree, before the hardware bus binds anything.
    pub(crate) fn note_dtb(dtb_ptr: usize) {
        DTB.store(dtb_ptr, core::sync::atomic::Ordering::Relaxed);
    }

    /// What `f` makes of the device tree the firmware handed the kernel;
    /// `None` for a tree that cannot be read.
    fn dt_blob<T>(f: impl FnOnce(&azos_soc::Fdt<'_>) -> T) -> Option<T> {
        let ptr = DTB.load(core::sync::atomic::Ordering::Relaxed);
        if ptr == 0 {
            return None;
        }
        let base = azos_mm::addr::phys_to_virt(ptr) as *const u8;
        // SAFETY: the firmware handed the kernel this pointer and `early_main`
        // parsed the header; the size field bounds the slice below.
        let total = unsafe { core::slice::from_raw_parts(base.add(4), 4) };
        let total = u32::from_be_bytes([total[0], total[1], total[2], total[3]]) as usize;
        if !(40..=MAX_DTB).contains(&total) {
            return None;
        }
        // SAFETY: `total` bytes from the header's own size field.
        let blob = unsafe { core::slice::from_raw_parts(base, total) };
        Some(f(&azos_soc::Fdt::parse(blob)?))
    }

    /// What `f` makes of the `dr_mode` property of the device-tree node at
    /// `node` (`None` when the node has none); `None` for a tree that cannot
    /// be read.
    fn dt_dr_mode<T>(node: u32, f: impl FnOnce(Option<&[u8]>) -> T) -> Option<T> {
        dt_blob(|fdt| f(fdt.prop(azos_soc::NodeId(node), "dr_mode")))
    }

    /// Map a device-tree controller's window: `false` when it has none or the
    /// mapping failed.
    fn map_dt_window(dev: &azos_drv_bus::hwbus::Device) -> bool {
        if dev.size == 0 || !crate::boot::map_mmio_region(dev.base as usize, dev.size as usize) {
            return false;
        }
        use azos_arch::Mmu;
        azos_arch::ARCH.flush_tlb_all();
        true
    }

    /// Attach a device-tree xHCI: a `generic-xhci` node, or a `snps,dwc3` node
    /// whose `dr_mode` is `host`. A DWC3 in `peripheral` or `otg` mode (or
    /// with no `dr_mode`) is a board's gadget port: it is left alone for the
    /// gadget stack. The DWC3's PHY, clocks and resets are the board glue's
    /// (SOC_FRAMEWORKS has no consumer yet): a controller the firmware did not
    /// bring up fails to start here and is reported.
    #[cfg(feature = "usb-xhci")]
    pub(crate) fn attach_dt(dev: &azos_drv_bus::hwbus::Device) -> Result<(), azos_drv_bus::hwbus::ProbeError> {
        use azos_drv_bus::hwbus::ProbeError;
        let dwc3 = dev.compatible().any(|c| c == "snps,dwc3");
        if dwc3 {
            let host = dev.dt_node.and_then(|n| dt_dr_mode(n, azos_usb::dwc3::is_host_only)).unwrap_or(false);
            if !host {
                kprintln!("[USB] {}: snps,dwc3 without dr_mode = \"host\": not driven as a host", dev.name.as_str());
                return Err(ProbeError::Failed);
            }
            if dev.size < azos_usb::dwc3::MIN_WINDOW {
                azos_drv_sys::kwarn!("[USB] {}: the snps,dwc3 window is too small for its global registers", dev.name.as_str());
                return Err(ProbeError::Failed);
            }
        }
        if !map_dt_window(dev) {
            return Err(ProbeError::Failed);
        }
        if dwc3 {
            azos_usb::dwc3::set_host_mode(&KRegs { base: dev.base as usize });
        }
        let domain = azos_dma::registry::domain_for_mmio(dev.base);
        bring_up(dev.base as usize, domain, bus_reach(dev), dev.name.as_str(), Kind::Xhci).map_err(|_| ProbeError::Failed)
    }

    /// Attach a DesignWare USB 2.0 core (`brcm,bcm2835-usb`, the Raspberry
    /// Pi's; `brcm,bcm2708-usb`, the same core in the Pi firmware's own tree;
    /// `snps,dwc2`) as a host, unless its `dr_mode` makes it a gadget port
    /// (`azos_usb::dwc2::may_host`). Its PHY and clocks are the firmware's on
    /// a Pi, which leaves them running.
    #[cfg(feature = "usb-dwc2")]
    pub(crate) fn attach_dwc2(dev: &azos_drv_bus::hwbus::Device) -> Result<(), azos_drv_bus::hwbus::ProbeError> {
        use azos_drv_bus::hwbus::ProbeError;
        // A tree that cannot be read names no gadget port.
        let host = dev.dt_node.and_then(|n| dt_dr_mode(n, azos_usb::dwc2::may_host)).unwrap_or(true);
        if !host {
            kprintln!("[USB] {}: DWC2 with dr_mode = \"peripheral\": not driven as a host", dev.name.as_str());
            return Err(ProbeError::Failed);
        }
        if dev.size < azos_usb::dwc2::MIN_WINDOW {
            azos_drv_sys::kwarn!("[USB] {}: the DWC2 window is too small for its host registers", dev.name.as_str());
            return Err(ProbeError::Failed);
        }
        if !map_dt_window(dev) {
            return Err(ProbeError::Failed);
        }
        // arch-only: the Raspberry Pi's firmware power domains are aarch64's.
        #[cfg(all(feature = "rpi-firmware", target_arch = "aarch64"))]
        if let Some(node) = dev.dt_node {
            if !rpi_power_domains_on(node, dev.name.as_str()) {
                return Err(ProbeError::Failed);
            }
        }
        let domain = azos_dma::registry::domain_for_mmio(dev.base);
        bring_up(dev.base as usize, domain, bus_reach(dev), dev.name.as_str(), Kind::Dwc2).map_err(|_| ProbeError::Failed)
    }

    /// Switch on every `power-domains` entry of the node at `node` that the
    /// Raspberry Pi firmware provides (`raspberrypi,bcm2835-power`: the
    /// VideoCore powers the block, `rpi_mbox::power_on`), before the device's
    /// registers are touched: the Pi's USB host is off until then (Linux's
    /// raspberrypi-power driver does the same through the genpd attach). An
    /// entry of another provider is not this function's (the SoC frameworks
    /// own those). `false`, said on the console, when the firmware cannot
    /// power a domain the device needs.
    // arch-only: the Raspberry Pi firmware is aarch64's.
    #[cfg(all(feature = "rpi-firmware", target_arch = "aarch64"))]
    fn rpi_power_domains_on(node: u32, what: &str) -> bool {
        use azos_soc::consumer;
        const PROVIDER: &str = "raspberrypi,bcm2835-power";
        let mut domains = [0u32; 4];
        let mut n = 0usize;
        let mut root = [0u8; 64];
        let mut root_len = 0usize;
        let ok = dt_blob(|fdt| {
            let me = azos_soc::NodeId(node);
            let count = consumer::count(fdt, me, "power-domains", "#power-domain-cells").unwrap_or(0);
            for i in 0..count {
                let Ok(e) = consumer::entry(fdt, me, "power-domains", "#power-domain-cells", i) else { return false };
                if !fdt.is_compatible(e.provider, PROVIDER) {
                    continue;
                }
                let Ok(id) = e.id() else { return false };
                if n == domains.len() {
                    return false;
                }
                domains[n] = id;
                n += 1;
            }
            if let Some(c) = fdt.prop(azos_soc::NodeId(0), "compatible") {
                root_len = c.len().min(root.len());
                root[..root_len].copy_from_slice(&c[..root_len]);
            }
            true
        })
        .unwrap_or(true);
        if !ok {
            azos_drv_sys::kwarn!("[USB] {}: its power-domains cannot be read", what);
            return false;
        }
        for &id in &domains[..n] {
            let Some(device) = azos_firmware::power_device_for_domain(id) else {
                azos_drv_sys::kwarn!("[USB] {}: firmware power domain {} has no device this kernel knows", what, id);
                return false;
            };
            match crate::entry::aarch64::ext::rpi_mbox::power_on(&root[..root_len], device) {
                Ok(()) => kprintln!("[USB] {}: firmware power domain {} (device {}) on", what, id, device),
                Err(e) => {
                    azos_drv_sys::kwarn!("[USB] {}: the firmware did not power domain {} (device {}): {:?}", what, id, device, e);
                    return false;
                }
            }
        }
        true
    }

    /// Start the `usb` task, once the scheduler exists. A no-op without a
    /// controller.
    pub(crate) fn start_usb_task() {
        #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
        let Some((domain, mask)) = STATE.lock().as_ref().map(|s| s.dma) else { return };
        #[cfg(feature = "usb-storage")]
        {
            let msc = Msc::new(KMem { domain }, KClock, mask, &RINGS[..]);
            // Built in the box: the disk's request queue is too big for a frame
            // (`tools/lint/stack_frames.py`, fleet).
            let mut slot = alloc::boxed::Box::<Disk>::new_uninit();
            Disk::init(&mut slot, msc);
            // SAFETY: `init` wrote every field.
            let disk: &'static Disk = alloc::boxed::Box::leak(unsafe { slot.assume_init() });
            azos_drv_block::usb_msc::set_hooks(crate::boot::blk_block_until, crate::boot::blk_wake, usb_kick);
            *DISK.lock_irqsave() = Some(disk);
            #[cfg(feature = "usb-storage-volume")]
            stick::start();
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
        #[cfg(feature = "usb-smsc95xx")]
        {
            let f = Smsc95xx::new(KMem { domain }, KClock, mask, &RINGS[..], smsc_mac());
            let nic: &'static SmscNic = alloc::boxed::Box::leak(alloc::boxed::Box::new(UsbNic::new(f, usb_kick)));
            *SMSC.lock_irqsave() = Some(nic);
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
        #[cfg(not(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc")))]
        if STATE.lock().is_none() {
            return;
        }
        azos_sched::task_create("usb", usb_task, 0, azos_sched::DEFAULT_PRIORITY);
    }

    /// Wake the `usb` task: a class driver queued a transfer, which the core
    /// moves to the controller on its next turn.
    #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
    fn usb_kick() {
        let tid = USB_TID.load(core::sync::atomic::Ordering::Acquire);
        if tid != 0 {
            crate::boot::blk_wake(tid);
        }
    }

    fn usb_task(_arg: usize) {
        #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
        USB_TID.store(azos_sync::waitqueue::caller_tid(), core::sync::atomic::Ordering::Release);
        loop {
            service_once();
            nap();
        }
    }

    /// Until the next turn of the core is due: `USB_POLL_MS`, or sooner when
    /// a class driver kicks the task.
    fn nap() {
        #[cfg(any(feature = "usb-storage", feature = "usb-net", feature = "usb-uvc"))]
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
    /// With `USB_STORAGE_VOLUME` the mount reads the disk instead ([`stick`]).
    #[cfg(all(feature = "usb-storage", not(feature = "usb-storage-volume")))]
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

    /// Orderly power-off or reboot (`azos_syscall::handlers`, through the
    /// devices hook): the stick's volume ejected (written back,
    /// marked clean, SYNCHRONIZE CACHE), else SYNCHRONIZE CACHE on a disk that
    /// is ready, through its request queue (the `usb` task moves the
    /// transfers). Bounded by Kconfig `USB_MSC_TIMEOUT_MS` per command;
    /// nothing when no disk is plugged. Runs on the task that asked for the
    /// power-off, never on the `usb` task.
    #[cfg(feature = "usb-storage")]
    pub(crate) fn storage_shutdown() {
        #[cfg(feature = "usb-storage-volume")]
        match azos_fs::usbvol::eject() {
            Some(Ok(())) => {
                crate::kprintln!("[ORDERLY] usb volume: written back, marked clean, synchronize cache ok");
                return;
            }
            Some(Err(())) => {
                azos_drv_sys::kwarn!("[ORDERLY] usb volume: eject FAILED (the stick may be left dirty)");
                return;
            }
            None => {}
        }
        let Some(disk) = *DISK.lock_irqsave() else { return };
        if !disk.ready() {
            return;
        }
        match disk.flush(azos_devif::block::OWNER_KERNEL) {
            Ok(()) => crate::kprintln!("[ORDERLY] usb disk: synchronize cache ok"),
            Err(e) => azos_drv_sys::kwarn!("[ORDERLY] usb disk: synchronize cache FAILED ({:?})", e),
        }
    }

    /// The stick's FAT32 volume (Kconfig `USB_STORAGE_VOLUME`), mounted at
    /// [`azos_topology::USB_VOLUME_PATH`] when the disk becomes ready and
    /// retired when it goes. A task of its own, `usb-vol`: the mount and the
    /// retirement do disk I/O and take the volume's locks, which a task doing
    /// I/O on the stick may hold while the `usb` task serves that I/O, so the
    /// `usb` task only notes what happened ([`stick::note`]). One task, so a
    /// plug and an unplug are handled in the order they happened.
    #[cfg(feature = "usb-storage-volume")]
    pub(crate) mod stick {
        use core::sync::atomic::{AtomicU8, Ordering};

        use azos_drv_api::block::{DeviceWait, FlushError};
        use azos_drv_block::queue::{Failure, HwQueue, Outcome};
        use azos_fs::usbvol;

        use super::{Disk, DISK};

        /// The disk became ready.
        pub(crate) const READY: u8 = 1;
        /// The disk went away.
        pub(crate) const GONE: u8 = 2;
        static PENDING: AtomicU8 = AtomicU8::new(0);
        static WAITER: DeviceWait = DeviceWait::new();

        /// The disk as the volume reads and writes it: the kernel's own
        /// requests (`OWNER_KERNEL`) through its request queue.
        struct Volume(&'static Disk);

        impl usbvol::Disk for Volume {
            fn sectors(&self) -> u64 {
                HwQueue::caps(self.0).sectors
            }
            fn read(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
                self.0.read(azos_devif::block::OWNER_KERNEL, sector, count, buf).map_err(|_| ())
            }
            fn write(&self, sector: u64, count: u32, buf: &[u8], preflush: bool) -> Result<(), ()> {
                let flags = if preflush { azos_devif::block::FLAG_PREFLUSH } else { 0 };
                self.0.write(azos_devif::block::OWNER_KERNEL, sector, count, flags, buf).map_err(|_| ())
            }
            fn flush(&self) -> Result<(), FlushError> {
                match self.0.flush(azos_devif::block::OWNER_KERNEL) {
                    Ok(()) => Ok(()),
                    Err(Failure::Ended(Outcome::Unsupported)) => Err(FlushError::Unsupported),
                    Err(_) => Err(FlushError::Io),
                }
            }
        }

        /// Start the `usb-vol` task: once, with the disk.
        pub(crate) fn start() {
            azos_sched::task_create("usb-vol", task, 0, azos_sched::DEFAULT_PRIORITY);
        }

        /// The `usb` task saw `what` ([`READY`], [`GONE`]) happen to the disk.
        pub(crate) fn note(what: u8) {
            // The event first, then the look at who is listed (`DeviceWait`).
            PENDING.fetch_or(what, Ordering::SeqCst);
            let tid = WAITER.sleeper();
            if tid != 0 {
                crate::boot::blk_wake(tid);
            }
        }

        fn task(_arg: usize) {
            let Some(disk) = *DISK.lock_irqsave() else { return };
            let vol: &'static Volume = alloc::boxed::Box::leak(alloc::boxed::Box::new(Volume(disk)));
            let tid = azos_sync::waitqueue::caller_tid();
            loop {
                let what = PENDING.swap(0, Ordering::SeqCst);
                // An unplug before a plug noted in the same look: the old
                // stick goes first.
                if what & GONE != 0 && usbvol::mounted() {
                    usbvol::unplugged();
                    crate::kprintln!("[USB] volume at {} retired: the stick is gone",
                        core::str::from_utf8(azos_topology::USB_VOLUME_PATH).unwrap_or("?"));
                }
                if what & READY != 0 {
                    mount(vol);
                }
                if what == 0 {
                    // Until the `usb` task notes something; the re-check
                    // after listing keeps a note made just before from
                    // being slept through.
                    let until = azos_drv_sys::timebase::now()
                        .saturating_add(azos_syscall::sleep::ms_to_ticks(60_000));
                    WAITER.park(tid, || PENDING.load(Ordering::SeqCst) != 0, || crate::boot::blk_block_until(until));
                }
            }
        }

        fn mount(vol: &'static Volume) {
            let at = azos_topology::USB_VOLUME_PATH;
            let at_s = core::str::from_utf8(at).unwrap_or("?");
            match usbvol::mount(vol, at) {
                Ok(m) if m.partitions == 0 => {
                    crate::kprintln!("[USB] volume mounted at {}: FAT32 on the whole medium", at_s)
                }
                Ok(m) => crate::kprintln!(
                    "[USB] volume mounted at {}: FAT32 at LBA {} ({} partition(s))", at_s, m.base, m.partitions
                ),
                Err(why) => crate::kprintln!("[USB] volume not mounted at {}: {:?}", at_s, why),
            }
        }
    }

    /// What one turn of the core did to the network and serial functions, for
    /// the code that runs once the host's lock is released (the stack and the
    /// `Uart` table take locks of their own).
    #[derive(Default)]
    struct Turn {
        #[cfg(feature = "usb-cdc")]
        nic: Option<NicEvent>,
        #[cfg(feature = "usb-cdc")]
        serial: Option<SerialEvent>,
        #[cfg(feature = "usb-smsc95xx")]
        smsc: Option<NicEvent>,
    }

    fn service_once() {
        let turn = service_core();
        #[cfg(feature = "usb-cdc")]
        {
            if let (Some(nic), Some(t)) = (*NIC.lock_irqsave(), turn.nic) {
                nic_turn(nic, t, NIC_CDC);
            }
            if let Some(t) = turn.serial {
                serial_turn(t);
            }
        }
        #[cfg(feature = "usb-smsc95xx")]
        if let (Some(nic), Some(t)) = (*SMSC.lock_irqsave(), turn.smsc) {
            nic_turn(nic, t, NIC_SMSC);
        }
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

    /// A network function after a turn of the core: tell the device table and
    /// the stack when it came up or went away, and the poller when frames wait.
    /// `who` is the function's [`NIC_HOLDER`] value.
    #[cfg(feature = "usb-net")]
    fn nic_turn<F: NetFunction + Send>(nic: &'static UsbNic<F>, turn: NicEvent, who: u8) {
        use azos_drv_api::net::NetDevice;
        use core::sync::atomic::Ordering;
        match turn {
            NicEvent::Up => {
                let mac = nic.mac();
                if NIC_HOLDER.compare_exchange(0, who, Ordering::AcqRel, Ordering::Acquire).is_err() {
                    azos_drv_sys::kwarn!("[USB-NET] a network function is up, but another holds the USB NIC");
                    return;
                }
                let Some(n) = azos_drv_net::net_device::register_usb(nic) else {
                    NIC_HOLDER.store(0, Ordering::Release);
                    azos_drv_sys::kwarn!("[USB-NET] a network function is up, but the NIC table has no number for it");
                    return;
                };
                kprintln!(
                    "[USB-NET] network function up: NIC {}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    n, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                // Kconfig NET: the first NIC of the boot gets its poller here.
                #[cfg(feature = "net")]
                crate::start_net_poll();
                if azos_net::net_nic_added(n) == Some(azos_net::PRIMARY_IF)
                    && azos_config::CFG_NET_DHCP.load(core::sync::atomic::Ordering::Relaxed) != 0
                {
                    azos_sched::task_create("usb-dhcp", dhcp_task, 0, azos_sched::DEFAULT_PRIORITY);
                }
            }
            NicEvent::Down => {
                if NIC_HOLDER.compare_exchange(who, 0, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    azos_drv_net::net_device::unregister_usb();
                    kprintln!("[USB-NET] network function removed");
                }
            }
            NicEvent::None => {}
        }
        if nic.is_ready() && nic.rx_pending() {
            crate::net_rx_kick();
        }
    }

    /// The MAC address of the LAN95xx function: the device tree's
    /// `local-mac-address` (or `mac-address`) of its `usb424,ec00` node, which
    /// the Raspberry Pi firmware fills in from the board's OTP; else a locally
    /// administered one from the entropy pool (the chips on the Pis have no
    /// EEPROM), else a fixed locally administered one, said so.
    #[cfg(feature = "usb-smsc95xx")]
    fn smsc_mac() -> [u8; 6] {
        let from_tree = dt_blob(|fdt| {
            let n = ["usb424,ec00", "usb424,ec01", "usb424,9500", "usb424,9e00"].iter().find_map(|c| fdt.find_compatible(c))?;
            let v = fdt.prop(n, "local-mac-address").or_else(|| fdt.prop(n, "mac-address"))?;
            let m: [u8; 6] = v.get(..6)?.try_into().ok()?;
            // Not all-zero (a tree the firmware did not fill in), not multicast.
            (m != [0; 6] && m[0] & 1 == 0).then_some(m)
        })
        .flatten();
        if let Some(m) = from_tree {
            return m;
        }
        let mut m = [0u8; 6];
        if azos_crypto::entropy::fill(&mut m) {
            // Locally administered, unicast.
            m[0] = (m[0] & !1) | 2;
            return m;
        }
        azos_drv_sys::kwarn!("[USB-NET] no MAC address for the LAN95xx and no entropy: a fixed local one");
        [0x02, 0x41, 0x7a, 0x4f, 0x53, 0x95]
    }

    /// The DHCP exchange of a primary interface that came with the adapter: the
    /// one the boot made before any NIC existed could not be answered. A task of
    /// its own, because the exchange waits for the network and the `usb` task
    /// must keep moving the frames it waits for.
    #[cfg(feature = "usb-net")]
    fn dhcp_task(_arg: usize) {
        kprintln!("[USB-NET] running DHCP on the new interface");
        if !azos_net::dhcp::dhcp_start(azos_sched::task_yield) {
            azos_drv_sys::kwarn!("[USB-NET] DHCP failed: the interface keeps its static configuration");
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
        let Some(st) = g.as_mut() else { return Turn::default() };
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
        #[cfg(feature = "usb-smsc95xx")]
        let smsc = *SMSC.lock_irqsave();
        #[cfg(feature = "usb-smsc95xx")]
        let mut smsc_class = smsc.map(|n| UsbClassDirect(n.class()));
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
            let rules = <CdcNet<'static, KMem, KClock> as NetFunction>::RULES;
            let (comm, data) = (rules[0], rules[1]);
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
        // The LAN95xx function: vendor-class interfaces, its product ids
        // checked at attach.
        #[cfg(feature = "usb-smsc95xx")]
        if let Some(c) = smsc_class.as_mut() {
            let _ = reg.register(8, Smsc95xx::<'static, KMem, KClock>::rule(), c);
        }
        st.usb.service(&mut reg);
        drop(reg);
        // The class drivers' second half: what needs the core, after its turn.
        #[cfg(feature = "usb-uvc")]
        camera_turn(&mut st.usb);
        #[cfg(feature = "usb-hid")]
        hid.poll(&mut st.usb);
        #[cfg(feature = "usb-storage")]
        match disk.map_or(Event::None, |d| d.drive(&mut st.usb)) {
            #[cfg(not(feature = "usb-storage-volume"))]
            Event::Ready => {
                azos_sched::task_create("usb-msc", sector0_task, 0, azos_sched::DEFAULT_PRIORITY);
            }
            #[cfg(feature = "usb-storage-volume")]
            Event::Ready => stick::note(stick::READY),
            #[cfg(feature = "usb-storage-volume")]
            Event::Gone => stick::note(stick::GONE),
            _ => {}
        }
        let turn = Turn {
            #[cfg(feature = "usb-cdc")]
            nic: nic.map(|n| n.drive(&mut st.usb)),
            #[cfg(feature = "usb-cdc")]
            serial: serial.map(|p| p.drive(&mut st.usb)),
            #[cfg(feature = "usb-smsc95xx")]
            smsc: smsc.map(|n| n.drive(&mut st.usb)),
        };
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
