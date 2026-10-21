// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The route of a PCI function's MSI/MSI-X vectors through the GICv3 ITS:
//! `kernel_main` hands one to the virtio-pci, NVMe and Intel NIC drivers.
//! Each vector is an EventID of the function's DeviceID, mapped to an LPI
//! slot from the route's offset; `prepare` issues a fresh MAPD each time.

pub(crate) struct ItsRoute {
    dev: u32,
    lpi_offset: u32,
}
impl ItsRoute {
    /// The route of the PCI function `bdf` onto LPI slots from `lpi_offset`.
    pub(crate) fn new(bdf: azos_pci::Bdf, lpi_offset: u32) -> Self {
        Self { dev: azos_arch::irq::its::device_id(bdf.bus, bdf.device, bdf.function), lpi_offset }
    }
}
impl azos_drv_virtio::virtio::pci::msix_selftest::MsiRoute for ItsRoute {
    fn prepare(&mut self, n: u16) -> bool {
        if !crate::boot_hooks::its_ready() {
            return false;
        }
        let its = crate::boot_hooks::its();
        let Ok(slot) = its.map_device(self.dev) else { return false };
        let off = self.lpi_offset;
        (0..n as u32).all(|ev| its
            .map_vector(slot, ev, azos_arch::irq::gic::LPI_INTID_BASE + off + ev)
            .is_ok())
    }
    fn target(&self, vec: u16) -> (u64, u32) {
        crate::boot_hooks::its().msi_target(vec as u32)
    }
    fn delivered(&self, vec: u16) -> u64 {
        crate::entry::aarch64::LPI_VECTOR_COUNT
            .get((self.lpi_offset + vec as u32) as usize)
            .map_or(0, |c| c.load(core::sync::atomic::Ordering::Acquire))
    }
    fn isr_token(&self, vec: u16) -> u32 {
        self.lpi_offset + vec as u32
    }
}
// The NVMe driver's view of the same route: the admin vector and one
// per I/O queue are EventIDs of the device (an ITT holds
// `MAX_EVENTS_PER_DEVICE`), all in collection 0, the boot CPU's: the
// queues still have a submission queue and a lock each, but their
// interrupts do not yet land on their own CPUs (that needs a
// collection, a pending table and an enabled redistributor per CPU).
#[cfg(feature = "nvme")]
impl azos_drv_block::nvme::QueueRoute for ItsRoute {
    fn prepare(&mut self, queues: u16) -> u16 {
        use azos_drv_virtio::virtio::pci::msix_selftest::MsiRoute;
        let queues = queues.min(azos_arch::irq::its::MAX_EVENTS_PER_DEVICE as u16 - 1);
        if MsiRoute::prepare(self, queues + 1) { queues } else { 0 }
    }
    fn target(&self, vec: u16) -> (u64, u32) {
        azos_drv_virtio::virtio::pci::msix_selftest::MsiRoute::target(self, vec)
    }
    fn isr_token(&self, vec: u16) -> u32 {
        azos_drv_virtio::virtio::pci::msix_selftest::MsiRoute::isr_token(self, vec)
    }
    fn per_cpu(&self) -> bool {
        false
    }
}
