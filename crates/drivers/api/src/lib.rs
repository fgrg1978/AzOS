// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AZOS Driver API surface — pure `no_std`, host-compatible.
//!
//! This crate contains the **stable** Driver-framework surface
//! (RFC-0002 modular pattern): the [`Driver`] trait, the
//! [`DriverIsolation`] / [`DriverManifest`] / [`DriverError`]
//! types, [`MmioRange`], and the *lockless* [`Registry`] struct.
//!
//! It has zero RISC-V dependencies so it compiles and runs unit
//! tests on the host (`cargo test --target aarch64-apple-darwin`).
//!
//! # Crate split rationale
//!
//! - `azos_drv_api` (this crate) — types and class traits only.
//!   Host-testable.
//! - `azos_drv_<class>` (`crates/drivers/<class>`) — the in-kernel driver
//!   impls, one crate per driver class, and (in `azos_drv_base`) the
//!   production `SpinLock<Registry>` static. They cannot compile for the
//!   host because they pull RISC-V asm via `azos_arch`.
//!
//! The split lets the framework surface evolve under host
//! coverage while the impls stay no-std and target-specific.
//!
//! # Class traits
//!
//! One module per driver class that has a trait today: [`block`],
//! [`console`], [`net`], [`usb`]. The other classes (sensors, actuators,
//! buses, timers, interrupt controllers) have no class trait; their drivers
//! register through [`Driver`] where they register at all.

#![no_std]

pub mod block;
pub mod console;
pub mod net;
pub mod usb;

use azos_abi::cap::CapPerms;

// ──────────────────────────────────────────────────────────────────────────
// Resource description
// ──────────────────────────────────────────────────────────────────────────

/// A physical MMIO region claimed by a driver. Wire-stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioRange {
    /// Physical base address of the region.
    pub phys_base: u64,
    /// Size of the region in bytes.
    pub size: u64,
}

impl MmioRange {
    /// `const` constructor so manifests can be declared at compile time.
    pub const fn new(phys_base: u64, size: u64) -> Self {
        Self { phys_base, size }
    }

    /// `true` iff `addr` is within `[phys_base, phys_base + size)`.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.phys_base && addr < self.phys_base.saturating_add(self.size)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Isolation level
// ──────────────────────────────────────────────────────────────────────────

/// Where a driver's *code* executes. Selected by the manifest.
///
/// | Variant         | Where the code runs          | Stage     |
/// |-----------------|------------------------------|-----------|
/// | `InKernel`      | Kernel binary, direct call   | Phase 1 ✓ |
/// | `UserProcess`   | User-mode task via syscalls  | Phase 1 ✓ |
/// | `Hypervisor`    | VM-isolated component        | Phase 3   |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverIsolation {
    /// Linked into the kernel; direct Rust calls. No fault isolation.
    InKernel,
    /// Runs as a user-mode process. Calls routed through the
    /// kernel-side proxy (`UserDriverProxy` in `azos_drv_sys`).
    UserProcess {
        /// Task id of the user process serving this driver.
        tid: u32,
    },
    /// Reserved for a future VM-isolated path (RFC-0008 / Phase 3).
    Hypervisor,
}

impl DriverIsolation {
    /// `true` iff the driver runs outside the kernel binary.
    /// Used by the safety case (RFC-0017): only `InKernel` drivers
    /// contribute to the kernel safety scope.
    pub const fn is_isolated(&self) -> bool {
        matches!(self, Self::UserProcess { .. } | Self::Hypervisor)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Manifest
// ──────────────────────────────────────────────────────────────────────────

/// Stable manifest format version. Bump on breaking field changes.
pub const DRIVER_MANIFEST_VERSION: u16 = 1;

/// Static declaration of *what a driver is* and *what it needs*.
#[derive(Clone, Copy, Debug)]
pub struct DriverManifest {
    /// Subsystem kind. Matches `azos_driver_server::DRV_KIND_*`.
    pub kind: u32,
    /// Human-readable identifier (debug + tracing only).
    pub name: &'static str,
    /// Format version; must equal [`DRIVER_MANIFEST_VERSION`] at
    /// register time.
    pub version: u16,
    /// Where this driver's code executes.
    pub isolation: DriverIsolation,
    /// MMIO region the driver owns, if any.
    pub mmio: Option<MmioRange>,
    /// PLIC IRQ number the driver handles, if any.
    pub irq: Option<u32>,
    /// Cap-table permissions a client must hold to call this driver
    /// (RFC-0003 bridge).
    pub required_perms: CapPerms,
}

impl DriverManifest {
    /// Compile-time-checkable constructor.
    pub const fn new(
        kind: u32,
        name: &'static str,
        isolation: DriverIsolation,
        required_perms: CapPerms,
    ) -> Self {
        Self {
            kind,
            name,
            version: DRIVER_MANIFEST_VERSION,
            isolation,
            mmio: None,
            irq: None,
            required_perms,
        }
    }

    /// Builder: attach an MMIO range.
    pub const fn with_mmio(mut self, range: MmioRange) -> Self {
        self.mmio = Some(range);
        self
    }

    /// Builder: attach an IRQ.
    pub const fn with_irq(mut self, irq: u32) -> Self {
        self.irq = Some(irq);
        self
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────

/// Errors any driver may return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverError {
    NotInitialized,
    BadOp,
    BadInput,
    BadOutput,
    Busy,
    IoFault,
    Unsupported,
    NoMem,
    /// Driver-specific status code, opaque to the framework.
    Other(i32),
}

// ──────────────────────────────────────────────────────────────────────────
// Driver trait
// ──────────────────────────────────────────────────────────────────────────

/// The canonical AZOS driver interface. Implementors:
/// - In-kernel drivers implement this directly on their state
///   struct (e.g. `impl Driver for UartDriver`).
/// - Userspace drivers don't implement it themselves; the
///   `UserDriverProxy` in `azos_drv_sys` implements it by
///   forwarding through the `driver_server` syscalls.
///
/// # Why all methods take `&self`
///
/// The framework hands out `&'static dyn Driver` from
/// [`Registry::find_by_kind`] — there is no way for a caller to
/// upgrade that to `&mut`. Drivers therefore manage their own
/// internal mutability with the appropriate primitive: `AtomicBool`
/// for one-shot init flags, `SpinLock` for per-driver mutable
/// state, etc. This matches the way real hardware drivers behave
/// anyway (shared device registers + atomic / locked access).
pub trait Driver: Send + Sync {
    fn manifest(&self) -> &DriverManifest;
    fn init(&self) -> Result<(), DriverError>;
    fn handle_request(
        &self,
        op: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, DriverError>;
    fn handle_irq(&self, _irq: u32) {}
    fn shutdown(&self) -> Result<(), DriverError>;

    /// Which resource does `(op, input)` actually reach — the pin, the
    /// channel, the bus — or `None` if this call names none?
    ///
    /// # The hole this closes
    ///
    /// `SYS_DRV_INVOKE` authorised a caller with
    /// `CapTable::holds_kind_with`, which compares the KIND and the
    /// permissions and **never the resource index**. Its own doc called that
    /// "right for `SYS_DRV_INVOKE` (one manifest, one permission mask, no
    /// per-resource distinction)" — an assumption that stops being true the
    /// moment a driver's op decodes a resource out of the caller's payload,
    /// which `GpioDriver` does: `decode_pin_payload(input)`.
    ///
    /// So a task holding `Cap<Gpio>(5)` could write pin 40 through this
    /// syscall, while `sys_gpio_write` next door checked the pin correctly.
    /// `GpioDriver` is registered at boot, so that one was live, not latent.
    ///
    /// # Why there is no default implementation
    ///
    /// A `None` default would be fail-open by omission: a driver added later
    /// that decodes a resource would silently inherit "names nothing" and be
    /// authorised kind-wide. Requiring an answer makes a new driver a BUILD
    /// FAILURE until someone decides, which is the same reasoning as
    /// `HandleKind::code`'s exhaustive match.
    ///
    /// # What an implementation must return
    ///
    /// The resource the hardware write LANDS ON, not the one the caller
    /// named — those differ wherever a register is shared. `pwm_domain`'s
    /// `pwm_control_reach` is the worked example: on vf2 the enable bit and
    /// the scale field are instance-wide, so an op naming channel 2 reaches
    /// 0, 1 and 3 as well. Where a call reaches more than one resource and
    /// cannot be expressed as a single index, return `None` and gate it
    /// separately — an answer that is merely plausible is worse here than no
    /// answer, because this one authorises.
    fn request_resource(&self, op: u32, input: &[u8]) -> Option<u32>;
}

// ──────────────────────────────────────────────────────────────────────────
// Registry (lock-free struct; the lock lives in azos_drv_base)
// ──────────────────────────────────────────────────────────────────────────

/// Upper bound on simultaneously-registered drivers. Stays as a
/// constant rather than a `Vec` capacity so the production static
/// is fully no-heap.
pub const REGISTRY_MAX_DRIVERS: usize = 32;

/// Errors returned by [`Registry::register`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// Registry already holds [`REGISTRY_MAX_DRIVERS`] entries.
    Full,
    /// A driver with the same `kind` is already registered.
    DuplicateKind,
}

/// The driver table — a fixed-size array of `Option<&'static dyn
/// Driver>` slots. Not internally locked; consumers wrap it in
/// whatever sync primitive their context provides (the kernel
/// uses a `SpinLock` static; tests use a local owned value).
pub struct Registry {
    drivers: [Option<&'static dyn Driver>; REGISTRY_MAX_DRIVERS],
    count: usize,
}

impl Registry {
    /// Construct an empty registry. `const` so a static can be
    /// initialised without a runtime hook.
    pub const fn empty() -> Self {
        Self {
            drivers: [None; REGISTRY_MAX_DRIVERS],
            count: 0,
        }
    }

    /// Number of currently-registered drivers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` if no drivers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Register `driver`. Fails on `DuplicateKind` (same `kind`
    /// already present) or `Full` (table at capacity).
    pub fn register(
        &mut self,
        driver: &'static dyn Driver,
    ) -> Result<(), RegistryError> {
        let kind = driver.manifest().kind;
        if self.find_by_kind_impl(kind).is_some() {
            return Err(RegistryError::DuplicateKind);
        }
        let slot = self
            .drivers
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(RegistryError::Full)?;
        *slot = Some(driver);
        self.count += 1;
        Ok(())
    }

    /// Look up the driver registered for `kind`, if any.
    pub fn find_by_kind(&self, kind: u32) -> Option<&'static dyn Driver> {
        self.find_by_kind_impl(kind)
    }

    fn find_by_kind_impl(&self, kind: u32) -> Option<&'static dyn Driver> {
        for slot in self.drivers.iter() {
            if let Some(d) = slot {
                if d.manifest().kind == kind {
                    return Some(*d);
                }
            }
        }
        None
    }
}
