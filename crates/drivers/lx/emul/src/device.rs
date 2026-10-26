// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Device model: one bus, its devices and drivers, binding and deferred
//! probe.
//!
//! Behaviour reproduced from Linux's driver core (re-implemented, not
//! ported):
//!
//! * `device_add` tries registered drivers in registration order; the first
//!   whose probe returns 0 binds. A probe error other than
//!   `-EPROBE_DEFER` is recorded and the next driver is tried.
//! * `driver_register` tries the new driver on every unbound device, in the
//!   order the devices were added.
//! * A probe returning `-EPROBE_DEFER` stops the search and puts the device
//!   on the deferred list. Every successful bind triggers a retry of the
//!   whole deferred list in the order devices were deferred; retries that
//!   bind trigger another round, until a round binds nothing.
//! * `device_del` calls the driver's `remove` and unbinds;
//!   `driver_unregister` does that for every device bound to the driver.
//!
//! Probes may re-enter the model (a bus driver's probe adds child devices).
//! The model's borrow is released before every callback and every handle is
//! re-validated afterwards. A device being probed is never probed again
//! from inside its own probe, and the deferred-retry pass waits until the
//! outermost probe returns, so a child's successful bind cannot re-probe a
//! parent that is still mid-probe.

use crate::errno::EPROBE_DEFER;
use crate::kref::Refcount;
use core::fmt;

/// What a device declares about itself when added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Device name (platform device name, matched against driver names).
    pub name: &'static str,
    /// Devicetree `compatible` string, if the device has one.
    pub compatible: Option<&'static str>,
}

/// Probe callback: 0 on success, a negative errno otherwise.
pub type ProbeFn<C> = fn(&mut C, DeviceHandle) -> i32;
/// Remove callback.
pub type RemoveFn<C> = fn(&mut C, DeviceHandle);
/// Bus match function.
pub type MatchFn<C> = fn(&DeviceInfo, &Driver<C>) -> bool;

/// `struct device_driver` (with the bus-specific match table inlined).
pub struct Driver<C> {
    /// Driver name; matches devices with the same name.
    pub name: &'static str,
    /// `of_match_table` compatible strings.
    pub compatible: &'static [&'static str],
    /// `probe`.
    pub probe: ProbeFn<C>,
    /// `remove`, if the driver has one.
    pub remove: Option<RemoveFn<C>>,
}

impl<C> Clone for Driver<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for Driver<C> {}

impl<C> fmt::Debug for Driver<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Driver").field("name", &self.name).field("compatible", &self.compatible).finish()
    }
}

/// Default bus match, as the platform bus: a devicetree compatible string
/// in the driver's table, otherwise equal names.
pub fn default_match<C>(dev: &DeviceInfo, drv: &Driver<C>) -> bool {
    if let Some(c) = dev.compatible {
        if drv.compatible.contains(&c) {
            return true;
        }
    }
    dev.name == drv.name
}

/// Device handle (generation-checked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceHandle {
    idx: u16,
    gen: u16,
}

/// Driver handle (generation-checked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverHandle {
    idx: u16,
    gen: u16,
}

/// Device-model misuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevError {
    /// No free device or driver slot.
    Full,
    /// Stale or foreign handle, or a device already deleted.
    BadHandle,
    /// The operation is not allowed while the device is being probed, or
    /// would drop the reference `device_add` owns.
    Busy,
}

/// Binding state of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevState {
    /// No driver.
    Unbound,
    /// A probe call is in progress.
    Probing,
    /// Bound to a driver.
    Bound(DriverHandle),
    /// Waiting on the deferred list.
    Deferred,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DevStats {
    /// Probe calls made.
    pub probes: u64,
    /// Successful binds.
    pub binds: u64,
    /// `-EPROBE_DEFER` results.
    pub defers: u64,
    /// Other probe errors.
    pub failures: u64,
    /// Deferred-retry rounds run.
    pub retry_rounds: u64,
    /// Adds/registrations refused for lack of a slot.
    pub full: u32,
}

struct DevSlot {
    info: DeviceInfo,
    used: bool,
    present: bool,
    gen: u16,
    seq: u64,
    state: DevState,
    refs: Refcount,
    drvdata: usize,
    last_error: i32,
}

struct DrvSlot<C> {
    drv: Option<Driver<C>>,
    gen: u16,
    seq: u64,
}

impl<C> Clone for DrvSlot<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for DrvSlot<C> {}

enum Outcome {
    Bound,
    Deferred,
    Other,
}

/// One bus with up to `D` devices and `R` drivers.
pub struct DeviceModel<C, const D: usize, const R: usize> {
    devs: [DevSlot; D],
    drvs: [DrvSlot<C>; R],
    deferred: [Option<DeviceHandle>; D],
    ndeferred: usize,
    match_fn: MatchFn<C>,
    next_seq: u64,
    depth: u32,
    retry_pending: bool,
    stats: DevStats,
}

impl<C, const D: usize, const R: usize> fmt::Debug for DeviceModel<C, D, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceModel").field("stats", &self.stats).field("deferred", &self.ndeferred).finish()
    }
}

impl<C, const D: usize, const R: usize> Default for DeviceModel<C, D, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, const D: usize, const R: usize> DeviceModel<C, D, R> {
    // A const (not a static) so the array repeat below builds D fresh
    // slots; the interior `Cell` of `Refcount` is never shared.
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY_DEV: DevSlot = DevSlot {
        info: DeviceInfo { name: "", compatible: None },
        used: false,
        present: false,
        gen: 0,
        seq: 0,
        state: DevState::Unbound,
        refs: Refcount::new(0),
        drvdata: 0,
        last_error: 0,
    };
    const EMPTY_DRV: DrvSlot<C> = DrvSlot { drv: None, gen: 0, seq: 0 };

    /// Empty bus with the default (platform-style) match.
    pub const fn new() -> Self {
        Self::with_match(default_match::<C>)
    }

    /// Empty bus with a custom match function.
    pub const fn with_match(match_fn: MatchFn<C>) -> Self {
        assert!(D <= u16::MAX as usize && R <= u16::MAX as usize);
        DeviceModel {
            devs: [Self::EMPTY_DEV; D],
            drvs: [Self::EMPTY_DRV; R],
            deferred: [None; D],
            ndeferred: 0,
            match_fn,
            next_seq: 0,
            depth: 0,
            retry_pending: false,
            stats: DevStats { probes: 0, binds: 0, defers: 0, failures: 0, retry_rounds: 0, full: 0 },
        }
    }

    fn dev(&self, h: DeviceHandle) -> Option<&DevSlot> {
        self.devs.get(h.idx as usize).filter(|d| d.used && d.gen == h.gen)
    }

    fn dev_mut(&mut self, h: DeviceHandle) -> Option<&mut DevSlot> {
        self.devs.get_mut(h.idx as usize).filter(|d| d.used && d.gen == h.gen)
    }

    fn drv(&self, h: DriverHandle) -> Option<&Driver<C>> {
        self.drvs.get(h.idx as usize).filter(|d| d.gen == h.gen).and_then(|d| d.drv.as_ref())
    }

    /// Counters.
    pub fn stats(&self) -> DevStats {
        self.stats
    }

    /// Binding state (None for a stale handle).
    pub fn state(&self, h: DeviceHandle) -> Option<DevState> {
        self.dev(h).map(|d| d.state)
    }

    /// Driver bound to the device.
    pub fn bound_driver(&self, h: DeviceHandle) -> Option<DriverHandle> {
        match self.dev(h)?.state {
            DevState::Bound(d) => Some(d),
            _ => None,
        }
    }

    /// The device's description.
    pub fn info(&self, h: DeviceHandle) -> Option<DeviceInfo> {
        self.dev(h).map(|d| d.info)
    }

    /// Name of a registered driver.
    pub fn driver_name(&self, h: DriverHandle) -> Option<&'static str> {
        self.drv(h).map(|d| d.name)
    }

    /// Last probe error recorded for the device (0 if none).
    pub fn last_error(&self, h: DeviceHandle) -> Option<i32> {
        self.dev(h).map(|d| d.last_error)
    }

    /// `dev_set_drvdata`.
    pub fn set_drvdata(&mut self, h: DeviceHandle, data: usize) -> Result<(), DevError> {
        self.dev_mut(h).ok_or(DevError::BadHandle)?.drvdata = data;
        Ok(())
    }

    /// `dev_get_drvdata`.
    pub fn drvdata(&self, h: DeviceHandle) -> Option<usize> {
        self.dev(h).map(|d| d.drvdata)
    }

    /// Deferred devices in retry order.
    pub fn deferred(&self) -> impl Iterator<Item = DeviceHandle> + '_ {
        self.deferred[..self.ndeferred].iter().flatten().copied()
    }

    /// `get_device`.
    pub fn get_device(&mut self, h: DeviceHandle) -> Result<(), DevError> {
        self.dev(h).ok_or(DevError::BadHandle)?.refs.inc();
        Ok(())
    }

    /// `put_device`. The slot is reclaimed when the last reference goes
    /// after `device_del`. Dropping the reference `device_add` holds while
    /// the device is still present is refused: that one belongs to
    /// `device_del`.
    pub fn put_device(&mut self, h: DeviceHandle) -> Result<(), DevError> {
        let d = self.dev_mut(h).ok_or(DevError::BadHandle)?;
        if d.present && d.refs.read() == 1 {
            return Err(DevError::Busy);
        }
        if d.refs.dec_and_test() {
            d.used = false;
            d.gen = d.gen.wrapping_add(1);
        }
        Ok(())
    }

    /// Reference count of a device.
    pub fn refcount(&self, h: DeviceHandle) -> Option<i32> {
        self.dev(h).map(|d| d.refs.read())
    }

    fn remove_deferred(&mut self, h: DeviceHandle) {
        let mut w = 0;
        for r in 0..self.ndeferred {
            if self.deferred[r] != Some(h) {
                self.deferred[w] = self.deferred[r];
                w += 1;
            }
        }
        for slot in &mut self.deferred[w..self.ndeferred] {
            *slot = None;
        }
        self.ndeferred = w;
    }

    fn push_deferred(&mut self, h: DeviceHandle) {
        if self.deferred[..self.ndeferred].contains(&Some(h)) {
            return;
        }
        // Cannot overflow: at most D devices exist and each appears once.
        self.deferred[self.ndeferred] = Some(h);
        self.ndeferred += 1;
    }

    /// Driver handles in registration order.
    fn drivers_in_order(&self) -> ([Option<DriverHandle>; R], usize) {
        let mut out = [None; R];
        let mut n = 0;
        let mut last: Option<u64> = None;
        loop {
            let mut best: Option<(usize, u64)> = None;
            for (i, s) in self.drvs.iter().enumerate() {
                if s.drv.is_some()
                    && last.is_none_or(|l| s.seq > l)
                    && best.is_none_or(|(_, b)| s.seq < b)
                {
                    best = Some((i, s.seq));
                }
            }
            let Some((i, seq)) = best else { break };
            out[n] = Some(DriverHandle { idx: i as u16, gen: self.drvs[i].gen });
            n += 1;
            last = Some(seq);
        }
        (out, n)
    }

    /// Present devices in add order.
    fn devices_in_order(&self) -> ([Option<DeviceHandle>; D], usize) {
        let mut out = [None; D];
        let mut n = 0;
        let mut last: Option<u64> = None;
        loop {
            let mut best: Option<(usize, u64)> = None;
            for (i, s) in self.devs.iter().enumerate() {
                if s.used
                    && s.present
                    && last.is_none_or(|l| s.seq > l)
                    && best.is_none_or(|(_, b)| s.seq < b)
                {
                    best = Some((i, s.seq));
                }
            }
            let Some((i, seq)) = best else { break };
            out[n] = Some(DeviceHandle { idx: i as u16, gen: self.devs[i].gen });
            n += 1;
            last = Some(seq);
        }
        (out, n)
    }

    fn matches(&self, dev: DeviceHandle, drv: DriverHandle) -> bool {
        match (self.dev(dev), self.drv(drv)) {
            (Some(d), Some(r)) => (self.match_fn)(&d.info, r),
            _ => false,
        }
    }

    fn probeable(&self, h: DeviceHandle) -> bool {
        self.dev(h).is_some_and(|d| d.present && matches!(d.state, DevState::Unbound | DevState::Deferred))
    }
}

/// Probe `dev` with one driver. Releases the model borrow around the call.
fn probe_one<C, const D: usize, const R: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut DeviceModel<C, D, R>,
    dev: DeviceHandle,
    drv: DriverHandle,
) -> Outcome {
    let m = get(ctx);
    let Some(probe) = m.drv(drv).map(|d| d.probe) else { return Outcome::Other };
    let Some(slot) = m.dev_mut(dev) else { return Outcome::Other };
    slot.state = DevState::Probing;
    m.stats.probes += 1;
    m.depth += 1;
    let ret = probe(ctx, dev);
    let m = get(ctx);
    m.depth -= 1;
    let driver_alive = m.drv(drv).is_some();
    let Some(slot) = m.dev_mut(dev) else { return Outcome::Other };
    match ret {
        0 if driver_alive => {
            slot.state = DevState::Bound(drv);
            slot.last_error = 0;
            m.stats.binds += 1;
            m.remove_deferred(dev);
            Outcome::Bound
        }
        e if e == -EPROBE_DEFER => {
            slot.state = DevState::Deferred;
            slot.last_error = e;
            m.stats.defers += 1;
            m.push_deferred(dev);
            Outcome::Deferred
        }
        e => {
            slot.state = DevState::Unbound;
            slot.last_error = e;
            m.stats.failures += 1;
            Outcome::Other
        }
    }
}

/// Try every registered driver on `dev` in registration order.
fn attach<C, const D: usize, const R: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut DeviceModel<C, D, R>,
    dev: DeviceHandle,
) -> Outcome {
    let (order, n) = get(ctx).drivers_in_order();
    for drv in order[..n].iter().flatten().copied() {
        let m = get(ctx);
        if !m.probeable(dev) {
            break;
        }
        if !m.matches(dev, drv) {
            continue;
        }
        match probe_one(ctx, get, dev, drv) {
            Outcome::Other => continue,
            o => return o,
        }
    }
    Outcome::Other
}

/// The deferred-probe trigger: retry the deferred list until a round binds
/// nothing. Postponed while a probe is running (see the module docs).
fn trigger_deferred<C, const D: usize, const R: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut DeviceModel<C, D, R>,
) {
    if get(ctx).depth != 0 {
        get(ctx).retry_pending = true;
        return;
    }
    // Each productive round binds at least one of at most D devices.
    for _ in 0..=D {
        let m = get(ctx);
        m.retry_pending = false;
        if m.ndeferred == 0 {
            return;
        }
        m.stats.retry_rounds += 1;
        let snapshot = m.deferred;
        let n = m.ndeferred;
        m.deferred = [None; D];
        m.ndeferred = 0;
        let mut bound = false;
        for dev in snapshot[..n].iter().flatten().copied() {
            let m = get(ctx);
            if m.state(dev) != Some(DevState::Deferred) {
                continue;
            }
            // Re-queued (at the tail, preserving order) unless it binds or
            // fails for good.
            match attach(ctx, get, dev) {
                Outcome::Bound => bound = true,
                Outcome::Deferred => {}
                Outcome::Other => {
                    if let Some(s) = get(ctx).dev_mut(dev) {
                        if s.state == DevState::Deferred {
                            s.state = DevState::Unbound;
                        }
                    }
                }
            }
        }
        if !bound && !get(ctx).retry_pending {
            return;
        }
    }
}

/// `device_add`: register a device and probe it. The device holds one
/// reference until `device_del`.
pub fn device_add<C, const D: usize, const R: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut DeviceModel<C, D, R>,
    info: DeviceInfo,
) -> Result<DeviceHandle, DevError> {
    let m = get(ctx);
    let Some(i) = m.devs.iter().position(|d| !d.used) else {
        m.stats.full += 1;
        return Err(DevError::Full);
    };
    let seq = m.next_seq;
    m.next_seq += 1;
    let s = &mut m.devs[i];
    s.info = info;
    s.used = true;
    s.present = true;
    s.seq = seq;
    s.state = DevState::Unbound;
    s.refs.set(1);
    s.drvdata = 0;
    s.last_error = 0;
    let h = DeviceHandle { idx: i as u16, gen: s.gen };
    if let Outcome::Bound = attach(ctx, get, h) {
        trigger_deferred(ctx, get);
    } else if get(ctx).retry_pending {
        trigger_deferred(ctx, get);
    }
    Ok(h)
}

/// `device_del`: unbind (calling `remove`), drop from the deferred list and
/// release the reference taken by `device_add`.
pub fn device_del<C, const D: usize, const R: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut DeviceModel<C, D, R>,
    h: DeviceHandle,
) -> Result<(), DevError> {
    let m = get(ctx);
    let d = m.dev(h).filter(|d| d.present).ok_or(DevError::BadHandle)?;
    match d.state {
        DevState::Probing => return Err(DevError::Busy),
        DevState::Bound(drv) => {
            let remove = m.drv(drv).and_then(|r| r.remove);
            if let Some(slot) = m.dev_mut(h) {
                slot.state = DevState::Unbound;
            }
            if let Some(f) = remove {
                f(ctx, h);
            }
        }
        DevState::Deferred | DevState::Unbound => {}
    }
    let m = get(ctx);
    m.remove_deferred(h);
    let slot = m.dev_mut(h).ok_or(DevError::BadHandle)?;
    slot.state = DevState::Unbound;
    slot.present = false;
    if slot.refs.dec_and_test() {
        slot.used = false;
        slot.gen = slot.gen.wrapping_add(1);
    }
    Ok(())
}

/// `driver_register`: add the driver and try it on every unbound device in
/// add order.
pub fn driver_register<C, const D: usize, const R: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut DeviceModel<C, D, R>,
    drv: Driver<C>,
) -> Result<DriverHandle, DevError> {
    let m = get(ctx);
    let Some(i) = m.drvs.iter().position(|d| d.drv.is_none()) else {
        m.stats.full += 1;
        return Err(DevError::Full);
    };
    let seq = m.next_seq;
    m.next_seq += 1;
    m.drvs[i].drv = Some(drv);
    m.drvs[i].seq = seq;
    let dh = DriverHandle { idx: i as u16, gen: m.drvs[i].gen };
    let (order, n) = m.devices_in_order();
    let mut bound = false;
    for dev in order[..n].iter().flatten().copied() {
        let m = get(ctx);
        if m.drv(dh).is_none() {
            break;
        }
        if m.probeable(dev) && m.matches(dev, dh) {
            if let Outcome::Bound = probe_one(ctx, get, dev, dh) {
                bound = true;
            }
        }
    }
    if bound || get(ctx).retry_pending {
        trigger_deferred(ctx, get);
    }
    Ok(dh)
}

/// `driver_unregister`: unbind every device bound to the driver (calling
/// `remove`, in device add order) and release the driver slot. Unbound
/// devices are not re-probed against other drivers, as on Linux.
pub fn driver_unregister<C, const D: usize, const R: usize>(
    ctx: &mut C,
    get: fn(&mut C) -> &mut DeviceModel<C, D, R>,
    h: DriverHandle,
) -> Result<(), DevError> {
    let m = get(ctx);
    let remove = m.drv(h).ok_or(DevError::BadHandle)?.remove;
    let (order, n) = m.devices_in_order();
    for dev in order[..n].iter().flatten().copied() {
        let m = get(ctx);
        if m.bound_driver(dev) != Some(h) {
            continue;
        }
        if let Some(s) = m.dev_mut(dev) {
            s.state = DevState::Unbound;
        }
        if let Some(f) = remove {
            f(ctx, dev);
        }
    }
    let m = get(ctx);
    let s = &mut m.drvs[h.idx as usize];
    s.drv = None;
    s.gen = s.gen.wrapping_add(1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::{ENODEV, ENOMEM};

    /// Test context: the model plus a script of probe results and a log.
    struct Ctx {
        bus: DeviceModel<Ctx, 8, 4>,
        log: Vec<String>,
        /// Names of devices whose dependencies are "ready".
        ready: Vec<&'static str>,
        /// Device a probe should add as a child.
        child: Option<DeviceInfo>,
    }

    fn ctx() -> Ctx {
        Ctx { bus: DeviceModel::new(), log: Vec::new(), ready: Vec::new(), child: None }
    }

    fn bus(c: &mut Ctx) -> &mut DeviceModel<Ctx, 8, 4> {
        &mut c.bus
    }

    fn name(c: &Ctx, h: DeviceHandle) -> &'static str {
        c.bus.info(h).unwrap().name
    }

    /// Binds if the device is in `ready`, defers otherwise; becoming bound
    /// makes "dep:<name>" ready for others.
    fn probe_dep(c: &mut Ctx, h: DeviceHandle) -> i32 {
        let n = name(c, h);
        c.log.push(format!("probe {}", n));
        if c.ready.contains(&n) {
            0
        } else {
            -EPROBE_DEFER
        }
    }

    fn probe_ok(c: &mut Ctx, h: DeviceHandle) -> i32 {
        let n = name(c, h);
        c.log.push(format!("ok {}", n));
        if n == "provider" {
            // Its consumers can now probe.
            c.ready.extend(["consumer-a", "consumer-b", "consumer-c"]);
        }
        0
    }

    fn probe_nodev(c: &mut Ctx, h: DeviceHandle) -> i32 {
        let n = name(c, h);
        c.log.push(format!("nodev {}", n));
        -ENODEV
    }

    fn probe_add_child(c: &mut Ctx, h: DeviceHandle) -> i32 {
        let n = name(c, h);
        c.log.push(format!("parent {}", n));
        if let Some(info) = c.child.take() {
            device_add(c, bus, info).unwrap();
        }
        // The parent itself must not be re-probed from inside this call.
        assert_eq!(c.bus.state(h), Some(DevState::Probing));
        c.log.push(format!("parent {} done", n));
        0
    }

    fn remove_log(c: &mut Ctx, h: DeviceHandle) {
        let n = name(c, h);
        c.log.push(format!("remove {}", n));
    }

    fn drv(name: &'static str, compatible: &'static [&'static str], probe: ProbeFn<Ctx>) -> Driver<Ctx> {
        Driver { name, compatible, probe, remove: Some(remove_log) }
    }

    fn dev(name: &'static str, compatible: Option<&'static str>) -> DeviceInfo {
        DeviceInfo { name, compatible }
    }

    #[test]
    fn default_match_by_compatible_then_name() {
        let d = drv("uart", &["acme,uart"], probe_ok);
        assert!(default_match(&dev("x", Some("acme,uart")), &d));
        assert!(default_match(&dev("uart", Some("other")), &d));
        assert!(!default_match(&dev("x", Some("other")), &d));
        assert!(!default_match(&dev("x", None), &d));
    }

    #[test]
    fn device_add_binds_first_matching_driver_in_registration_order() {
        let mut c = ctx();
        driver_register(&mut c, bus, drv("a", &["x"], probe_nodev)).unwrap();
        let b = driver_register(&mut c, bus, drv("b", &["x"], probe_ok)).unwrap();
        driver_register(&mut c, bus, drv("c", &["x"], probe_ok)).unwrap();
        let d = device_add(&mut c, bus, dev("d0", Some("x"))).unwrap();
        assert_eq!(c.bus.bound_driver(d), Some(b));
        assert_eq!(c.log, vec!["nodev d0", "ok d0"]);
        assert_eq!(c.bus.stats().failures, 1);
    }

    #[test]
    fn driver_register_probes_unbound_devices_in_add_order() {
        let mut c = ctx();
        let d1 = device_add(&mut c, bus, dev("one", Some("x"))).unwrap();
        let _o = device_add(&mut c, bus, dev("other", Some("y"))).unwrap();
        let d2 = device_add(&mut c, bus, dev("two", Some("x"))).unwrap();
        assert_eq!(c.bus.state(d1), Some(DevState::Unbound));
        let h = driver_register(&mut c, bus, drv("drv", &["x"], probe_ok)).unwrap();
        assert_eq!(c.log, vec!["ok one", "ok two"]);
        assert_eq!(c.bus.bound_driver(d1), Some(h));
        assert_eq!(c.bus.bound_driver(d2), Some(h));
        // A second driver does not steal bound devices.
        driver_register(&mut c, bus, drv("drv2", &["x"], probe_ok)).unwrap();
        assert_eq!(c.log.len(), 2);
    }

    #[test]
    fn deferred_devices_retry_in_deferral_order_after_a_bind() {
        let mut c = ctx();
        driver_register(&mut c, bus, drv("consumer", &["cons"], probe_dep)).unwrap();
        driver_register(&mut c, bus, drv("provider", &["prov"], probe_ok)).unwrap();
        let b = device_add(&mut c, bus, dev("consumer-b", Some("cons"))).unwrap();
        let a = device_add(&mut c, bus, dev("consumer-a", Some("cons"))).unwrap();
        let cc = device_add(&mut c, bus, dev("consumer-c", Some("cons"))).unwrap();
        assert_eq!(c.bus.deferred().collect::<Vec<_>>(), vec![b, a, cc]);
        assert_eq!(c.bus.last_error(a), Some(-EPROBE_DEFER));
        c.log.clear();
        device_add(&mut c, bus, dev("provider", Some("prov"))).unwrap();
        assert_eq!(
            c.log,
            vec!["ok provider", "probe consumer-b", "probe consumer-a", "probe consumer-c"]
        );
        assert_eq!(c.bus.deferred().count(), 0);
        for h in [a, b, cc] {
            assert!(matches!(c.bus.state(h), Some(DevState::Bound(_))));
        }
        assert_eq!(c.bus.stats().defers, 3);
    }

    #[test]
    fn deferred_retry_without_a_bind_does_not_run() {
        let mut c = ctx();
        driver_register(&mut c, bus, drv("consumer", &["cons"], probe_dep)).unwrap();
        device_add(&mut c, bus, dev("consumer-a", Some("cons"))).unwrap();
        c.log.clear();
        // A device that binds to nothing is not a trigger.
        device_add(&mut c, bus, dev("lonely", Some("none"))).unwrap();
        assert!(c.log.is_empty());
        assert_eq!(c.bus.stats().retry_rounds, 0);
    }

    #[test]
    fn chained_dependencies_resolve_over_several_rounds() {
        // c2 needs c1 bound, c1 needs the provider: two retry rounds.
        fn probe_chain(c: &mut Ctx, h: DeviceHandle) -> i32 {
            let n = name(c, h);
            c.log.push(format!("try {}", n));
            let ok = match n {
                "c1" => c.ready.contains(&"provider"),
                "c2" => c.ready.contains(&"c1"),
                _ => true,
            };
            if ok {
                c.ready.push(n);
                0
            } else {
                -EPROBE_DEFER
            }
        }
        let mut c = ctx();
        driver_register(&mut c, bus, drv("chain", &["chain"], probe_chain)).unwrap();
        let c2 = device_add(&mut c, bus, dev("c2", Some("chain"))).unwrap();
        let c1 = device_add(&mut c, bus, dev("c1", Some("chain"))).unwrap();
        c.log.clear();
        device_add(&mut c, bus, dev("provider", Some("chain"))).unwrap();
        // Round 1: c2 defers again, c1 binds; round 2: c2 binds.
        assert_eq!(c.log, vec!["try provider", "try c2", "try c1", "try c2"]);
        assert!(matches!(c.bus.state(c1), Some(DevState::Bound(_))));
        assert!(matches!(c.bus.state(c2), Some(DevState::Bound(_))));
        assert_eq!(c.bus.stats().retry_rounds, 2);
    }

    #[test]
    fn driver_registration_binds_a_deferred_device_and_removes_it_from_the_list() {
        let mut c = ctx();
        driver_register(&mut c, bus, drv("consumer", &["cons"], probe_dep)).unwrap();
        let a = device_add(&mut c, bus, dev("consumer-a", Some("cons"))).unwrap();
        let h = driver_register(&mut c, bus, drv("consumer-a", &[], probe_ok)).unwrap();
        assert_eq!(c.bus.bound_driver(a), Some(h));
        assert_eq!(c.bus.deferred().count(), 0);
    }

    #[test]
    fn child_added_from_probe_does_not_reprobe_the_parent() {
        let mut c = ctx();
        driver_register(&mut c, bus, drv("consumer", &["cons"], probe_dep)).unwrap();
        driver_register(&mut c, bus, drv("bus", &["bus"], probe_add_child)).unwrap();
        driver_register(&mut c, bus, drv("leaf", &["leaf"], probe_ok)).unwrap();
        device_add(&mut c, bus, dev("consumer-a", Some("cons"))).unwrap();
        c.ready.push("consumer-a");
        c.child = Some(dev("kid", Some("leaf")));
        c.log.clear();
        let p = device_add(&mut c, bus, dev("parent", Some("bus"))).unwrap();
        // The child binds inside the parent's probe; the retry its bind
        // triggers waits for the parent's probe to return, then runs.
        assert_eq!(c.log, vec!["parent parent", "ok kid", "parent parent done", "probe consumer-a"]);
        assert!(matches!(c.bus.state(p), Some(DevState::Bound(_))));
        assert_eq!(c.bus.deferred().count(), 0);
    }

    #[test]
    fn device_del_calls_remove_and_reclaims_the_slot() {
        let mut c = ctx();
        driver_register(&mut c, bus, drv("d", &["x"], probe_ok)).unwrap();
        let h = device_add(&mut c, bus, dev("dev", Some("x"))).unwrap();
        c.bus.get_device(h).unwrap();
        assert_eq!(c.bus.refcount(h), Some(2));
        device_del(&mut c, bus, h).unwrap();
        assert_eq!(c.log, vec!["ok dev", "remove dev"]);
        assert_eq!(c.bus.state(h), Some(DevState::Unbound), "still referenced");
        assert_eq!(device_del(&mut c, bus, h), Err(DevError::BadHandle));
        c.bus.put_device(h).unwrap();
        assert_eq!(c.bus.state(h), None, "slot reclaimed on the last put");
        assert_eq!(c.bus.put_device(h), Err(DevError::BadHandle));
    }

    #[test]
    fn put_device_cannot_drop_the_registration_reference() {
        let mut c = ctx();
        let h = device_add(&mut c, bus, dev("dev", None)).unwrap();
        assert_eq!(c.bus.put_device(h), Err(DevError::Busy));
        assert_eq!(c.bus.refcount(h), Some(1));
    }

    #[test]
    fn deleting_a_deferred_device_drops_it_from_the_list() {
        let mut c = ctx();
        driver_register(&mut c, bus, drv("consumer", &["cons"], probe_dep)).unwrap();
        let a = device_add(&mut c, bus, dev("consumer-a", Some("cons"))).unwrap();
        device_del(&mut c, bus, a).unwrap();
        assert_eq!(c.bus.deferred().count(), 0);
        assert!(!c.log.contains(&"remove consumer-a".to_string()), "never bound, no remove");
    }

    #[test]
    fn driver_unregister_unbinds_its_devices_only() {
        let mut c = ctx();
        let dx = driver_register(&mut c, bus, drv("dx", &["x"], probe_ok)).unwrap();
        let dy = driver_register(&mut c, bus, drv("dy", &["y"], probe_ok)).unwrap();
        let a = device_add(&mut c, bus, dev("a", Some("x"))).unwrap();
        let b = device_add(&mut c, bus, dev("b", Some("y"))).unwrap();
        let cdev = device_add(&mut c, bus, dev("c", Some("x"))).unwrap();
        c.log.clear();
        driver_unregister(&mut c, bus, dx).unwrap();
        assert_eq!(c.log, vec!["remove a", "remove c"]);
        assert_eq!(c.bus.state(a), Some(DevState::Unbound));
        assert_eq!(c.bus.state(cdev), Some(DevState::Unbound));
        assert_eq!(c.bus.bound_driver(b), Some(dy));
        assert_eq!(driver_unregister(&mut c, bus, dx), Err(DevError::BadHandle));
        // The slot is reusable and the stale handle stays dead.
        let dz = driver_register(&mut c, bus, drv("dz", &["z"], probe_ok)).unwrap();
        assert_eq!(dz.idx, dx.idx);
        assert_eq!(c.bus.driver_name(dx), None);
    }

    #[test]
    fn probe_failure_is_recorded_and_capacity_is_reported() {
        fn probe_enomem(_: &mut Ctx, _: DeviceHandle) -> i32 {
            -ENOMEM
        }
        let mut c = ctx();
        driver_register(&mut c, bus, drv("bad", &["x"], probe_enomem)).unwrap();
        let h = device_add(&mut c, bus, dev("d", Some("x"))).unwrap();
        assert_eq!(c.bus.state(h), Some(DevState::Unbound));
        assert_eq!(c.bus.last_error(h), Some(-ENOMEM));
        for i in 0..3 {
            let n: &'static str = ["e0", "e1", "e2"][i];
            driver_register(&mut c, bus, drv(n, &[], probe_ok)).unwrap();
        }
        assert_eq!(driver_register(&mut c, bus, drv("full", &[], probe_ok)).err(), Some(DevError::Full));
        for _ in 0..7 {
            device_add(&mut c, bus, dev("n", None)).unwrap();
        }
        assert_eq!(device_add(&mut c, bus, dev("n", None)).err(), Some(DevError::Full));
        assert_eq!(c.bus.stats().full, 2);
    }

    #[test]
    fn drvdata_round_trips() {
        let mut c = ctx();
        let h = device_add(&mut c, bus, dev("d", None)).unwrap();
        c.bus.set_drvdata(h, 0xdead).unwrap();
        assert_eq!(c.bus.drvdata(h), Some(0xdead));
    }
}
