// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! UART as a [`Driver`] impl — first migration to the RFC-0002 API.
//!
//! This is **a thin wrapper** over the existing free-function UART
//! API (`crate::uart::*`). The legacy API stays in place because:
//!
//! - The `kprint!`/`kprintln!` macros and the kernel panic path
//!   need a zero-overhead synchronous putc that exists from very
//!   early boot — before the registry is alive.
//! - Moving every caller to `dyn Driver` dispatch is a separate,
//!   larger refactor that follow-up RFCs will cover.
//!
//! What this module *does* prove: a real hardware driver fits the
//! [`Driver`] trait shape cleanly, and a single static instance can
//! be registered into [`runtime::REGISTRY`] for client tasks that
//! want the unified API.

use azos_drv_api::{
    Driver, DriverError, DriverIsolation, DriverManifest, MmioRange,
};
use crate::uart;
use core::sync::atomic::{AtomicBool, Ordering};
use azos_abi::cap::CapPerms;

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

// The `drivers → driver_server` cycle that forced a duplicate here is gone:
// the `DRV_KIND_*` constants moved to `crates/core/abi` on 2026-09-06 (they are
// ABI — ring 3 passes them in `a0`), and this crate already depends on it.
// One source of truth, so "the two must stay numerically equal" is no longer
// a rule anyone has to remember.
use azos_abi::drv_kind::DRV_KIND_UART;

/// MMIO window claimed by the UART driver. NS16550A exposes 8 1-byte
/// registers; PL011 exposes its registers out to offset 0x048 (`DMACR`).
/// Either way a full 256-byte page for alignment is more than enough.
const UART_MMIO_BYTES: u64 = 0x100;

/// Manifest name — names the real hardware, not just "the UART", since it
/// differs by ISA (see `crate::uart`'s module doc: 16550-family on RISC-V,
/// PL011 on aarch64 QEMU `virt`). A `#[cfg]`'d fn body call site would tie
/// itself in knots (`cfg` doesn't apply directly to a call argument
/// expression); a `cfg`'d const does not.
#[cfg(target_arch = "riscv64")]
const UART_DRIVER_NAME: &str = "ns16550a-uart";
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const UART_DRIVER_NAME: &str = "pl011-uart";
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
const UART_DRIVER_NAME: &str = "com16550-pio-uart";

/// UART driver ops. Stable wire numbers — bump
/// [`super::api::DRIVER_MANIFEST_VERSION`] on any breaking change.
pub const UART_OP_WRITE: u32 = 0;
/// Non-blocking read of one byte into `output[0]`. Returns 1 on
/// success, 0 (with `Ok`) if no byte is available.
pub const UART_OP_READ_NB: u32 = 1;
/// Switch the UART to IRQ-driven RX mode.
pub const UART_OP_ENABLE_IRQ: u32 = 2;

// ──────────────────────────────────────────────────────────────────────────
// Driver state
// ──────────────────────────────────────────────────────────────────────────

/// Stateful wrapper over the free-function NS16550A driver. The
/// actual hardware state lives in the static globals in
/// [`crate::uart`]; this struct only carries the manifest and a
/// single atomic init flag. All `Driver` methods take `&self` so a
/// `static UART_DRIVER: UartDriver` can be safely shared through
/// the registry from any CPU.
pub struct UartDriver {
    initialized: AtomicBool,
    manifest: DriverManifest,
}

impl UartDriver {
    /// Construct an uninitialised UART driver. `const` so a static
    /// instance can be created without a runtime hook.
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            manifest: DriverManifest::new(
                DRV_KIND_UART,
                UART_DRIVER_NAME,
                DriverIsolation::InKernel,
                CapPerms::RW,
            )
            .with_mmio(MmioRange::new(
                azos_drv_base::platform::hw::UART_BASE as u64,
                UART_MMIO_BYTES,
            ))
            .with_irq(uart::UART_IRQ),
        }
    }
}

impl Default for UartDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Driver impl
// ──────────────────────────────────────────────────────────────────────────

impl Driver for UartDriver {
    fn manifest(&self) -> &DriverManifest {
        &self.manifest
    }

    fn init(&self) -> Result<(), DriverError> {
        // `initialized` starts `false`, so the FIRST trait-level init()
        // does call `uart::init()` — even though the boot path already
        // ran it long before the registry was alive. This flag only
        // stops a second trait-level call. What keeps the hardware from
        // being reprogrammed (and the RX interrupt the boot hook enabled
        // from being masked again) is `uart::init()`'s own once-guard.
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            uart::init();
        }
        Ok(())
    }

    fn handle_request(
        &self,
        op: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, DriverError> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err(DriverError::NotInitialized);
        }
        match op {
            UART_OP_WRITE => {
                // One kernel line (`uart::write_locked`): never spliced into
                // another writer's line, deferred while ring 3 owns the
                // console. Not `console_write_ring3`: this op is also
                // reached from `kernel_main`'s registry smoke, before any
                // task exists to hold its line lock.
                uart::write_locked(input);
                Ok(0)
            }
            UART_OP_READ_NB => {
                if output.is_empty() {
                    return Err(DriverError::BadOutput);
                }
                match uart::try_getc() {
                    Some(c) => {
                        output[0] = c;
                        Ok(1)
                    }
                    None => Ok(0),
                }
            }
            UART_OP_ENABLE_IRQ => {
                uart::enable_irq();
                Ok(0)
            }
            _ => Err(DriverError::BadOp),
        }
    }

    fn handle_irq(&self, _irq: u32) {
        uart::irq_handler();
    }

    /// The UART has one instance and its ops name no sub-resource: a write
    /// is a write to the console. `None` here is a statement, not a default —
    /// the trait has no default precisely so this had to be decided.
    fn request_resource(&self, _op: u32, _input: &[u8]) -> Option<u32> {
        None
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        // NS16550A has no power-down sequence in our usage. Clearing
        // the init flag is enough so a subsequent `init()` is a
        // no-op-aware reinit.
        self.initialized.store(false, Ordering::Release);
        Ok(())
    }
}
