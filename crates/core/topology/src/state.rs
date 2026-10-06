// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel-global topology storage.
//!
//! `Topology<'static>` lives in a single static slot, set once during
//! boot via [`init`] and accessed read-only thereafter via [`get`].
//!
//! # Concurrency
//!
//! `Topology` is `Sync` (all fields are `Copy` and free of interior
//! mutability). Once `init` returns successfully, the slot is **immutable**;
//! repeated `init` calls return `Err(InitError::AlreadyInit)` so a buggy
//! caller cannot replace a loaded topology mid-run.
//!
//! On hardware with multiple CPUs, the BootCpu writes the slot before
//! AP CPUs come online; AP CPUs only read.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::types::Topology;

/// State of the topology slot.
const STATE_EMPTY: u8 = 0;
const STATE_INITIALISING: u8 = 1;
const STATE_READY: u8 = 2;

/// Errors that can occur during [`init`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InitError {
    /// `init` was called more than once.
    AlreadyInit,
    /// The provided topology failed admission_check.
    Admission(crate::AdmissionError),
}

impl From<crate::AdmissionError> for InitError {
    fn from(e: crate::AdmissionError) -> Self {
        InitError::Admission(e)
    }
}

// SAFETY: see `Sync` impl below. The slot uses an atomic state byte to
// publish writes; readers are gated through `get()` which observes the
// state with `Acquire` ordering.
struct TopologySlot {
    state: AtomicU8,
    /// Holds an empty topology until [`init`] or [`init_with`] fills it.
    /// Readers only see it at `STATE_READY`.
    cell: UnsafeCell<Topology<'static>>,
}

// SAFETY: All access is synchronised through `state` (acquire/release).
// The `UnsafeCell` is written exactly once, by the BootCpu, before any
// AP CPU is allowed to read; readers see `STATE_READY` only with an
// `Acquire` load, which establishes the happens-before edge.
unsafe impl Sync for TopologySlot {}

static SLOT: TopologySlot = TopologySlot {
    state: AtomicU8::new(STATE_EMPTY),
    cell: UnsafeCell::new(Topology::empty()),
};

/// Claim the slot for writing: EMPTY → INITIALISING.
fn claim() -> Result<(), InitError> {
    SLOT.state
        .compare_exchange(
            STATE_EMPTY,
            STATE_INITIALISING,
            Ordering::Acquire,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|_| InitError::AlreadyInit)
}

/// Install the topology. Must be called exactly once, before any
/// task is spawned. Returns `Err` on a second call.
///
/// The value exists once on the caller's stack before it is copied in. A
/// `Topology` is sized by the limits (`MAX_TASKS`, `MAX_CAPS_TOTAL`) and is
/// megabytes on the fleet profile, so the kernel installs through
/// [`init_with`] instead.
pub fn init(topology: Topology<'static>) -> Result<(), InitError> {
    claim()?;
    // Validate before publishing.
    if let Err(e) = topology.admission_check() {
        // Roll the state back so the caller can panic / halt cleanly.
        SLOT.state.store(STATE_EMPTY, Ordering::Release);
        return Err(InitError::Admission(e));
    }
    // SAFETY: we hold the INITIALISING state exclusively (CAS above).
    unsafe {
        *SLOT.cell.get() = topology;
    }
    SLOT.state.store(STATE_READY, Ordering::Release);
    Ok(())
}

/// Install a topology that `fill` writes directly into the slot, so no
/// `Topology`-sized value is ever on a stack. Same rules as [`init`]: once,
/// before any task is spawned, and published only if it passes admission.
pub fn init_with(fill: impl FnOnce(&mut Topology<'static>)) -> Result<(), InitError> {
    claim()?;
    // SAFETY: we hold the INITIALISING state exclusively (CAS above), and
    // `get` hands out no reference before READY.
    let topology = unsafe { &mut *SLOT.cell.get() };
    topology.clear();
    fill(topology);
    if let Err(e) = topology.admission_check() {
        topology.clear();
        SLOT.state.store(STATE_EMPTY, Ordering::Release);
        return Err(InitError::Admission(e));
    }
    SLOT.state.store(STATE_READY, Ordering::Release);
    Ok(())
}

/// Why [`try_init_with`] did not publish a topology.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TryInitError<E> {
    /// The slot was already claimed.
    AlreadyInit,
    /// `fill` refused (for the signed topology: a file that does not verify
    /// or does not parse).
    Fill(E),
    /// The filled topology failed `admission_check`.
    Admission(crate::AdmissionError),
    /// `check` refused the admitted topology (the kernel's boot admission:
    /// deadlines, the real-time band, memory).
    Check(E),
}

/// [`init_with`] for a topology that may be refused: `fill` writes it into
/// the slot, `admission_check` runs, then `check`; it is published only if
/// all three succeed. On any refusal the slot is emptied and left
/// claimable, so the caller can install another topology instead (the
/// kernel falls back to the built-in one, Kconfig `TOPOLOGY_SOURCE`).
/// Nothing reads the slot before READY, so a refused topology is never seen.
pub fn try_init_with<E>(
    fill: impl FnOnce(&mut Topology<'static>) -> Result<(), E>,
    check: impl FnOnce(&Topology<'static>) -> Result<(), E>,
) -> Result<(), TryInitError<E>> {
    claim().map_err(|_| TryInitError::AlreadyInit)?;
    // SAFETY: we hold the INITIALISING state exclusively (CAS above), and
    // `get` hands out no reference before READY.
    let topology = unsafe { &mut *SLOT.cell.get() };
    topology.clear();
    let outcome = match fill(topology) {
        Err(e) => Err(TryInitError::Fill(e)),
        Ok(()) => match topology.admission_check() {
            Err(e) => Err(TryInitError::Admission(e)),
            Ok(()) => check(topology).map_err(TryInitError::Check),
        },
    };
    if outcome.is_err() {
        topology.clear();
        SLOT.state.store(STATE_EMPTY, Ordering::Release);
        return outcome;
    }
    SLOT.state.store(STATE_READY, Ordering::Release);
    Ok(())
}

/// Borrow the loaded topology. Returns `None` until [`init`] or
/// [`init_with`] succeeds.
pub fn get() -> Option<&'static Topology<'static>> {
    if SLOT.state.load(Ordering::Acquire) != STATE_READY {
        return None;
    }
    // SAFETY: state == READY ⇒ the cell was written before the Release in
    // `init` / `init_with`. We hand out a shared reference; the cell is
    // never written again.
    unsafe { Some(&*SLOT.cell.get()) }
}

/// Returns `true` once the topology has been initialised.
pub fn is_ready() -> bool {
    SLOT.state.load(Ordering::Acquire) == STATE_READY
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────
//
// Unit tests for the slot behaviour live in the host-side
// `topology-tests` crate because the `static SLOT` is global and we
// cannot exercise its CAS path twice in a single test binary without
// process restart. The host-side suite includes a single
// `init_then_get_then_double_init_fails` test.
