// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`UserDriverProxy`] — kernel-side proxy that implements
//! [`Driver`] by forwarding requests through the
//! `azos_driver_server` registry to a userspace driver process
//! (E11.AQ3).
//!
//! # Why
//!
//! The whole point of [`azos_drv_api::DriverIsolation`] is that
//! consumers should not care whether a driver runs in the kernel or
//! in a user process. The kernel-side [`Driver`] trait is uniform;
//! what differs is **who runs the code**.
//!
//! - In-kernel: e.g. [`crate::uart_driver::UartDriver`] — methods
//!   compile to direct Rust calls.
//! - User-process: [`UserDriverProxy`] — methods serialize the call
//!   into a [`driver_server::DriverRequest`], enqueue it, block until
//!   the matching [`driver_server::DriverReply`] is published, copy the
//!   payload back. The actual hardware logic lives in a user task that
//!   previously called `sys_driver_register`.
//!
//! # Waiting for the reply
//!
//! The caller BLOCKS (`azos_driver_server::reply_wait`): the request is
//! queued with the caller armed as its waiter, the reply path wakes it by TID,
//! and [`PROXY_REPLY_TIMEOUT_MS`] bounds the wait. This replaced a
//! million-iteration `spin_loop()` that, with strict-priority dispatch and no
//! aging, starved every lower-priority task on the caller's hart for the whole
//! wait — and deadlocked outright when the driver shared that hart at a lower
//! priority, because the driver never ran to answer.
//!
//! Before each block, while the driver is running on ANOTHER hart, the caller
//! first polls for the reply for [`PROXY_SPIN_US`] (`reply_wait`'s bounded
//! spin): a driver already executing usually answers in less time than the
//! block, the wake IPI and the switch back cost.
//!
//! # Priority donation
//!
//! Blocking alone does not make the driver run: a task between the client's
//! priority and the driver's, on the driver's hart, still starves it. So for
//! the span of the wait the client donates its live priority to the driver
//! (`azos_sched::donate_priority`, the same mechanism lease priority
//! inheritance uses), and returns it when the wait ends, reply or timeout. One
//! edge, made once and undone once — see `crates/core/sched/src/donation.rs` for why
//! that cannot loop.
//!
//! # Caller identity
//!
//! `client_tid` in the request stays [`PROXY_CALLER_TID_KERNEL`]: the ring-3
//! driver sees "the kernel asked". The waiter and the donor are the calling
//! task itself, read from the scheduler.

use azos_drv_api::{Driver, DriverError, DriverIsolation, DriverManifest};
use azos_driver_server as ds;
use ds::reply_wait::{ProxyHooks, ReplyWaitEnv, WaitOutcome};

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

/// How long a caller waits for the ring-3 driver's reply before
/// `handle_request` returns [`DriverError::Busy`].
///
/// The same budget the old spin was sized for ("a worst-case userspace
/// turnaround of ~100ms"), now spent blocked: the caller's hart runs other
/// work meanwhile. Kconfig `PROXY_REPLY_TIMEOUT_MS` (default 100).
pub const PROXY_REPLY_TIMEOUT_MS: u64 = azos_limits::PROXY_REPLY_TIMEOUT_MS;

/// Sentinel client_tid used while the trait does not carry caller
/// identity. The userspace driver sees this as "the kernel asked".
pub const PROXY_CALLER_TID_KERNEL: u32 = u32::MAX;

// ──────────────────────────────────────────────────────────────────────────
// Errors specific to the proxy plumbing (mapped to DriverError)
// ──────────────────────────────────────────────────────────────────────────

/// Why a proxied call failed. Public so a caller that must tell a timeout
/// from a full queue can call [`UserDriverProxy::call`]; the [`Driver`]
/// trait folds both into [`DriverError::Busy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// No reply within [`PROXY_REPLY_TIMEOUT_MS`].
    Timeout,
    /// `driver_submit_request_armed` refused — kind not registered, queue
    /// full, or every waiter row taken.
    SubmitFailed,
    /// Reply `out_len` exceeded the caller-supplied output buffer.
    OutputTooLarge,
    /// The kernel has not installed [`ProxyHooks`], or the scheduler refused
    /// to block (K-C29: called inside a critical section). Never a spin.
    CannotBlock,
}

impl From<ProxyError> for DriverError {
    fn from(e: ProxyError) -> Self {
        match e {
            ProxyError::Timeout => DriverError::Busy,
            ProxyError::SubmitFailed => DriverError::Busy,
            ProxyError::OutputTooLarge => DriverError::BadOutput,
            ProxyError::CannotBlock => DriverError::Busy,
        }
    }
}

/// How long a caller polls for the reply before it blocks, while the driver
/// is running on another hart (owner round 22-23: ~20 µs). Below the cost of
/// a block + cross-hart wake + switch back, so a reply that lands inside it
/// saves that round trip; a driver that is not running is never spun on.
///
/// Per board since 2026-09-28: Kconfig `PROXY_SPIN_US` (`config/Kconfig.drivers`,
/// default 20, set explicitly in the board and QEMU defconfigs; its help says
/// how to measure it on a board). 0 turns the spin off.
pub const PROXY_SPIN_US: u64 = azos_limits::PROXY_SPIN_US as u64;

/// [`ReplyWaitEnv`] over the installed hooks and this crate's timebase.
struct HookEnv {
    hooks: &'static ProxyHooks,
    driver_tid: u32,
}

impl ReplyWaitEnv for HookEnv {
    fn now(&self) -> u64 {
        crate::timebase::now()
    }
    fn block(&self, deadline: u64) -> bool {
        (self.hooks.block)(deadline)
    }
    fn peer_running(&self) -> bool {
        (self.hooks.peer_running)(self.driver_tid)
    }
    fn spin_ticks(&self) -> u64 {
        crate::timebase::TIMER_FREQ.saturating_mul(PROXY_SPIN_US) / 1_000_000
    }
    fn note_spin_hit(&self) {
        PROXY_SPIN_REPLIES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Proxy
// ──────────────────────────────────────────────────────────────────────────

/// Kernel-side proxy for a userspace driver. Constructed once per
/// (kind, manifest) and registered into [`azos_drv_base::runtime::REGISTRY`].
pub struct UserDriverProxy {
    manifest: DriverManifest,
}

impl UserDriverProxy {
    /// Construct a proxy for the userspace driver described by
    /// `manifest`. Panics in debug builds if the manifest's
    /// isolation is not [`DriverIsolation::UserProcess`] — using
    /// a proxy for an in-kernel driver is a programming error.
    pub const fn new(manifest: DriverManifest) -> Self {
        debug_assert!(matches!(
            manifest.isolation,
            DriverIsolation::UserProcess { .. }
        ));
        Self { manifest }
    }

    /// Returns the user task id that handles this proxy, or `None`
    /// if the manifest's isolation has been changed at runtime.
    pub fn target_tid(&self) -> Option<u32> {
        match self.manifest.isolation {
            DriverIsolation::UserProcess { tid } => Some(tid),
            _ => None,
        }
    }

    /// One synchronous request → reply cycle, keeping why it failed.
    ///
    /// Blocks the caller (see the module doc): must not be called from an
    /// interrupt handler or while holding a lock. Inside a critical section
    /// the scheduler refuses the block and this returns
    /// [`ProxyError::CannotBlock`] without waiting.
    pub fn call(
        &self,
        op: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ProxyError> {
        self.call_timeout_us(op, input, output, PROXY_REPLY_TIMEOUT_MS * 1000)
    }

    /// [`call`](Self::call) with the caller's own reply budget, in
    /// microseconds, instead of [`PROXY_REPLY_TIMEOUT_MS`]. For a client
    /// whose own deadline is shorter than the default — a control loop that
    /// must decide something every period whether the driver answered or not.
    pub fn call_timeout_us(
        &self,
        op: u32,
        input: &[u8],
        output: &mut [u8],
        timeout_us: u64,
    ) -> Result<usize, ProxyError> {
        let hooks = ds::reply_wait::proxy_hooks().ok_or(ProxyError::CannotBlock)?;
        let kind = self.manifest.kind;
        let me = (hooks.current_tid)();
        let deadline = crate::timebase::now().saturating_add(
            crate::timebase::TIMER_FREQ.saturating_mul(timeout_us) / 1_000_000,
        );
        let armed = ds::driver_submit_request_armed(
            kind,
            PROXY_CALLER_TID_KERNEL,
            op,
            input,
            output.len().min(ds::DRIVER_REPLY_PAYLOAD_BYTES) as u16,
            me,
            deadline,
        )
        .ok_or(ProxyError::SubmitFailed)?;
        let (token, driver_tid) = (armed.token, armed.driver_tid);

        // For the span of the wait the driver runs at least at the caller's
        // priority. Made after the submit, so the TID is the driver that was
        // registered when the request was queued; returned below on every
        // way out, reply or not.
        let donated = (hooks.donate)(me, driver_tid);
        if donated {
            PROXY_DONATIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }

        // The reply lands in this request's own waiter row; `reply_posted` is
        // the lock-free flag for it, and the withdraw on the way out takes the
        // reply (or finds none) under `REGISTRY`.
        let got: core::cell::Cell<Option<ds::DriverReply>> = core::cell::Cell::new(None);
        let outcome = ds::reply_wait::wait_for_reply(
            &HookEnv { hooks, driver_tid },
            deadline,
            || got.get().is_some() || ds::reply_posted(armed.slot, armed.row, token),
            || {
                if let ds::reply_wait::Withdrawn::Replied(r) =
                    ds::driver_withdraw_waiter(kind, me, token)
                {
                    got.set(Some(r));
                }
            },
        );

        if donated {
            (hooks.undonate)(driver_tid);
        }

        // Posted but gone at the withdraw: the kind was released between the
        // two (its rows are cleared). No reply reached this caller.
        let outcome = match (outcome, got.get()) {
            (WaitOutcome::Replied, None) => WaitOutcome::TimedOut,
            (o, _) => o,
        };
        let reply = got.get().unwrap_or(ds::DriverReply::zeroed());

        match outcome {
            WaitOutcome::Replied => {
                // **Bound against the reply payload as well as the caller's
                // buffer.** `out_len` is a u16 a RING-3 driver writes, and
                // `sys_driver_reply` copies the struct in without validating
                // it. Checking only `output.len()` protects the destination
                // and leaves the source: with a caller buffer larger than
                // `DRIVER_REPLY_PAYLOAD_BYTES` (64), an `out_len` between 65
                // and that size passes the check and then indexes
                // `reply.output[..len]` out of bounds -- a panic, and
                // `panic = "abort"` makes it a board reset a userspace driver
                // can trigger deliberately.
                //
                // Not reachable today only because the one caller passes an
                // 8-byte buffer: safe by the caller's choice, not by this
                // code's own bound. Same class as the MACB receive length and
                // as the VirtIO net path that was hardened first.
                let len = reply.out_len as usize;
                if len > output.len() || len > reply.output.len() {
                    return Err(ProxyError::OutputTooLarge);
                }
                output[..len].copy_from_slice(&reply.output[..len]);
                Ok(len)
            }
            WaitOutcome::TimedOut => {
                let n = PROXY_TIMEOUTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
                // Named on the console (first 8): a timeout answers the caller
                // like an empty reply, and the guest clock is the host's on
                // QEMU, so a descheduled vCPU can end the wait (wave 13).
                if n <= 8 {
                    crate::kwarn!("[PROXY] kind {:#x}: no reply within {} us (timeout #{})",
                                     self.manifest.kind, timeout_us, n);
                }
                Err(ProxyError::Timeout)
            }
            WaitOutcome::Refused => Err(ProxyError::CannotBlock),
        }
    }
}

/// Donations the proxy has made (a caller more urgent than the driver).
/// Telemetry; the `proxy-pi-smoke` row reads it across one call.
pub static PROXY_DONATIONS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Calls whose reply was found by the bounded spin, before any block.
pub static PROXY_SPIN_REPLIES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Calls that ended at [`PROXY_REPLY_TIMEOUT_MS`] with no reply.
pub static PROXY_TIMEOUTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// ──────────────────────────────────────────────────────────────────────────
// Driver impl
// ──────────────────────────────────────────────────────────────────────────

impl Driver for UserDriverProxy {
    fn manifest(&self) -> &DriverManifest {
        &self.manifest
    }

    fn init(&self) -> Result<(), DriverError> {
        // No-op: a userspace driver self-initialises during its
        // own `sys_driver_register` call. The proxy has no
        // hardware state of its own.
        Ok(())
    }

    fn handle_request(
        &self,
        op: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, DriverError> {
        self.call(op, input, output).map_err(Into::into)
    }

    fn handle_irq(&self, irq: u32) {
        // For a userspace-isolated driver, the kernel IRQ path
        // wakes the user task — it does not handle the IRQ inline.
        // `driver_signal_irq` latches the IRQ flag; the user task
        // observes it on its next `sys_driver_wait`.
        let _ = ds::driver_signal_irq(irq);
    }

    /// A ring-3 driver defines its own op space, so the kernel cannot decode
    /// a resource out of its payload without trusting the very program the
    /// capability is meant to constrain.
    ///
    /// `None` keeps the kind-wide check, which is why `DriverRegistry` is
    /// parameterised by kind: the authority granted is "be the driver for
    /// this device family", and it is checked at registration.
    fn request_resource(&self, _op: u32, _input: &[u8]) -> Option<u32> {
        None
    }

    fn shutdown(&self) -> Result<(), DriverError> {
        // Cooperative: the userspace driver tears down when its
        // process exits or when it calls `sys_driver_unregister`.
        // The proxy itself owns no resources.
        Ok(())
    }
}
