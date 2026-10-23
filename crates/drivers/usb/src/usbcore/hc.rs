// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The controller under the core: an xHCI ([`Xhci`]) or a DesignWare USB 2.0
//! core ([`Dwc2`], Kconfig `USB_DWC2`).
//!
//! Both present the model the core is written against (slots, endpoints with
//! a queue of transfer descriptors, completion events in xHCI's codes, a root
//! hub of ports whose status reads as PORTSC), so one core, one set of class
//! drivers and one `usb` task serve either; which one a machine has is the
//! device tree's (or PCI's) answer at probe time. [`Hc`] dispatches each
//! call to the controller it holds.
//!
//! The controllers are tens of KB, so each is built in place
//! ([`Hc::init_xhci`], [`Hc::init_dwc2`]): the storage is a union of the two,
//! and the tag says which one was built.

use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::addr_of_mut;

#[cfg(feature = "dwc2")]
use crate::dwc2::Dwc2;
use crate::hw::{Clock, DmaBuf, Memory, Regs};
use crate::xhci::context::SlotParams;
use crate::xhci::{EpSpec, Error, HcEvent, PortStatus, TdSpec, Xhci};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Xhci,
    #[cfg(feature = "dwc2")]
    Dwc2,
}

#[repr(C)]
union Store<R: Regs, M: Memory, C: Clock> {
    xhci: ManuallyDrop<MaybeUninit<Xhci<R, M, C>>>,
    #[cfg(feature = "dwc2")]
    dwc2: ManuallyDrop<MaybeUninit<Dwc2<R, M, C>>>,
}

/// One controller, of either kind.
pub struct Hc<R: Regs, M: Memory, C: Clock> {
    kind: Kind,
    store: Store<R, M, C>,
}

/// Call `$call` on whichever controller `$hc` holds: `each!` lends it shared,
/// `each_mut!` exclusively.
macro_rules! each {
    ($hc:expr, $c:ident => $call:expr) => {
        match $hc.kind {
            Kind::Xhci => {
                let $c = $hc.xhci_ref();
                $call
            }
            #[cfg(feature = "dwc2")]
            Kind::Dwc2 => {
                let $c = $hc.dwc2_ref();
                $call
            }
        }
    };
}

macro_rules! each_mut {
    ($hc:expr, $c:ident => $call:expr) => {
        match $hc.kind {
            Kind::Xhci => {
                let $c = $hc.xhci_mut();
                $call
            }
            #[cfg(feature = "dwc2")]
            Kind::Dwc2 => {
                let $c = $hc.dwc2_mut();
                $call
            }
        }
    };
}

impl<R: Regs, M: Memory, C: Clock> Hc<R, M, C> {
    /// A started xHCI as the controller.
    pub fn from_xhci(x: Xhci<R, M, C>) -> Self {
        Hc { kind: Kind::Xhci, store: Store { xhci: ManuallyDrop::new(MaybeUninit::new(x)) } }
    }

    /// Start an xHCI in `slot` ([`Xhci::init`], in place).
    pub fn init_xhci<'a>(
        slot: &'a mut MaybeUninit<Self>,
        regs: R,
        mem: M,
        clock: C,
        dma_mask: u64,
        irq: bool,
    ) -> Result<&'a mut Self, Error> {
        let p = slot.as_mut_ptr();
        // SAFETY: `p` is valid and aligned; the tag is written, and the
        // controller is built in the union's storage, which starts at offset
        // 0 of every field (`repr(C)`), so the cast is the field's place.
        unsafe {
            addr_of_mut!((*p).kind).write(Kind::Xhci);
            let x = &mut *addr_of_mut!((*p).store).cast::<MaybeUninit<Xhci<R, M, C>>>();
            Xhci::init(x, regs, mem, clock, dma_mask, irq)?;
            Ok(&mut *p)
        }
    }

    /// Start a DWC2 in `slot` ([`Dwc2::init`], in place).
    #[cfg(feature = "dwc2")]
    pub fn init_dwc2<'a>(slot: &'a mut MaybeUninit<Self>, regs: R, mem: M, clock: C, dma_mask: u64) -> Result<&'a mut Self, Error> {
        let p = slot.as_mut_ptr();
        // SAFETY: as in `init_xhci`.
        unsafe {
            addr_of_mut!((*p).kind).write(Kind::Dwc2);
            let d = &mut *addr_of_mut!((*p).store).cast::<MaybeUninit<Dwc2<R, M, C>>>();
            Dwc2::init(d, regs, mem, clock, dma_mask)?;
            Ok(&mut *p)
        }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    // SAFETY (the four accessors): each is called only under the tag that
    // names its controller (`each!`, `each_mut!`, `as_*`), and only the
    // constructor of that controller writes that tag, after the controller
    // was built in the store, at offset 0 of the `repr(C)` union.
    fn xhci_ref(&self) -> &Xhci<R, M, C> {
        debug_assert!(self.kind == Kind::Xhci);
        // SAFETY: see above.
        unsafe { &*(core::ptr::addr_of!(self.store) as *const Xhci<R, M, C>) }
    }
    fn xhci_mut(&mut self) -> &mut Xhci<R, M, C> {
        debug_assert!(self.kind == Kind::Xhci);
        // SAFETY: see above.
        unsafe { &mut *(addr_of_mut!(self.store) as *mut Xhci<R, M, C>) }
    }
    #[cfg(feature = "dwc2")]
    fn dwc2_ref(&self) -> &Dwc2<R, M, C> {
        debug_assert!(self.kind == Kind::Dwc2);
        // SAFETY: see above.
        unsafe { &*(core::ptr::addr_of!(self.store) as *const Dwc2<R, M, C>) }
    }
    #[cfg(feature = "dwc2")]
    fn dwc2_mut(&mut self) -> &mut Dwc2<R, M, C> {
        debug_assert!(self.kind == Kind::Dwc2);
        // SAFETY: see above.
        unsafe { &mut *(addr_of_mut!(self.store) as *mut Dwc2<R, M, C>) }
    }

    /// The xHCI, when the controller is one.
    pub fn as_xhci(&self) -> Option<&Xhci<R, M, C>> {
        match self.kind {
            Kind::Xhci => Some(self.xhci_ref()),
            #[cfg(feature = "dwc2")]
            Kind::Dwc2 => None,
        }
    }

    /// The DWC2, when the controller is one.
    #[cfg(feature = "dwc2")]
    pub fn as_dwc2(&self) -> Option<&Dwc2<R, M, C>> {
        match self.kind {
            Kind::Dwc2 => Some(self.dwc2_ref()),
            Kind::Xhci => None,
        }
    }

    pub fn ports(&self) -> u8 {
        each!(self, c => c.ports())
    }
    /// The controller switches port power: the core waits for it to be good.
    pub fn port_power_switched(&self) -> bool {
        match self.kind {
            Kind::Xhci => self.xhci_ref().caps().ppc,
            // The driver powered its one port at start.
            #[cfg(feature = "dwc2")]
            Kind::Dwc2 => true,
        }
    }
    /// The controller was reset under the core's devices ([`Xhci::reset_pending`]).
    /// A DWC2 has no reset path: never.
    pub fn reset_pending(&self) -> bool {
        match self.kind {
            Kind::Xhci => self.xhci_ref().reset_pending(),
            #[cfg(feature = "dwc2")]
            Kind::Dwc2 => false,
        }
    }
    /// The core removed the reset controller's devices ([`Xhci::ack_reset`]).
    pub fn ack_reset(&mut self) {
        match self.kind {
            Kind::Xhci => self.xhci_mut().ack_reset(),
            #[cfg(feature = "dwc2")]
            Kind::Dwc2 => {}
        }
    }
    pub fn dma_mask(&self) -> u64 {
        each!(self, c => c.dma_mask())
    }
    pub fn is_dead(&self) -> bool {
        each!(self, c => c.is_dead())
    }
    pub fn lost_events(&self) -> u32 {
        each!(self, c => c.lost_events())
    }
    pub fn clock(&self) -> &C {
        each!(self, c => c.clock())
    }
    pub fn mem(&self) -> &M {
        each!(self, c => c.mem())
    }
    pub fn take_page(&mut self) -> Option<DmaBuf> {
        each_mut!(self, c => c.take_page())
    }
    pub fn poll(&mut self) {
        each_mut!(self, c => c.poll())
    }
    pub fn next_event(&mut self) -> Option<HcEvent> {
        each_mut!(self, c => c.next_event())
    }
    pub fn port_status(&mut self, port: u8) -> PortStatus {
        each_mut!(self, c => c.port_status(port))
    }
    pub fn port_ack(&mut self, port: u8, changes: u32) {
        each_mut!(self, c => c.port_ack(port, changes))
    }
    pub fn port_reset(&mut self, port: u8) {
        each_mut!(self, c => c.port_reset(port))
    }
    pub fn enable_slot(&mut self) -> Result<u8, Error> {
        each_mut!(self, c => c.enable_slot())
    }
    pub fn address_device(&mut self, slot: u8, params: SlotParams, ep0_mps: u16) -> Result<(), Error> {
        each_mut!(self, c => c.address_device(slot, params, ep0_mps))
    }
    pub fn update_slot(&mut self, slot: u8, params: SlotParams) -> Result<(), Error> {
        each_mut!(self, c => c.update_slot(slot, params))
    }
    pub fn set_ep0_mps(&mut self, slot: u8, mps: u16) -> Result<(), Error> {
        each_mut!(self, c => c.set_ep0_mps(slot, mps))
    }
    pub fn configure_endpoints(&mut self, slot: u8, specs: &[EpSpec]) -> Result<(), Error> {
        each_mut!(self, c => c.configure_endpoints(slot, specs))
    }
    pub fn drop_endpoints(&mut self, slot: u8, dcis: u32) -> Result<(), Error> {
        each_mut!(self, c => c.drop_endpoints(slot, dcis))
    }
    pub fn disable_slot(&mut self, slot: u8) -> Result<(), Error> {
        each_mut!(self, c => c.disable_slot(slot))
    }
    pub fn ep_halted(&self, ep: u16) -> bool {
        each!(self, c => c.ep_halted(ep))
    }
    pub fn queue_td(&mut self, ep: u16, spec: TdSpec) -> Result<(), Error> {
        each_mut!(self, c => c.queue_td(ep, spec))
    }
    pub fn recover_halted(&mut self) -> usize {
        each_mut!(self, c => c.recover_halted())
    }
}
