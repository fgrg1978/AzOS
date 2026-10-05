// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Power management — idle/suspend states with WFI.
///
/// QEMU/VF2/K1: WFI instruction for low-power idle.
/// VF2: clock gating skeleton via JH7110 CRG (Clock Reset Generator).


use core::sync::atomic::{AtomicU8, Ordering};

/// Power management state.
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PmState {
    Active  = 0,
    Idle    = 1,
    Suspend = 2,
}

impl PmState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => PmState::Idle,
            2 => PmState::Suspend,
            _ => PmState::Active,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            PmState::Active  => "Active",
            PmState::Idle    => "Idle",
            PmState::Suspend => "Suspend",
        }
    }
}

static PM_STATE: AtomicU8 = AtomicU8::new(PmState::Active as u8);

/// Initialise power management (set state to Active).
pub fn pm_init() {
    PM_STATE.store(PmState::Active as u8, Ordering::Release);
    azos_drv_sys::kprintln!("[PM] Initialized — state: Active");
}

/// Enter idle state — executes WFI to save power until next interrupt.
///
/// Returns immediately after an interrupt wakes the hart.
pub fn pm_idle() {
    PM_STATE.store(PmState::Idle as u8, Ordering::Release);
    unsafe { core::arch::asm!("wfi") };
    PM_STATE.store(PmState::Active as u8, Ordering::Release);
}

/// Suspend the system — enters a deep WFI loop.
///
/// On QEMU this is effectively the same as idle (WFI), since QEMU virt
/// does not model true suspend states.  The hart will wake on any interrupt.
pub fn pm_suspend() {
    PM_STATE.store(PmState::Suspend as u8, Ordering::Release);
    azos_drv_sys::kprintln!("[PM] System suspended -- WFI");
    unsafe { core::arch::asm!("wfi") };
    // Woken by interrupt
    PM_STATE.store(PmState::Active as u8, Ordering::Release);
    azos_drv_sys::kprintln!("[PM] Resumed from suspend");
}

/// Resume to active state (called from interrupt handler or explicit wake).
pub fn pm_resume() {
    PM_STATE.store(PmState::Active as u8, Ordering::Release);
}

/// Get current power management state.
pub fn pm_get_state() -> PmState {
    PmState::from_u8(PM_STATE.load(Ordering::Acquire))
}

/// Print power management status.
pub fn pm_info() {
    let state = pm_get_state();
    azos_drv_sys::kconsoleln!("[PM] State: {}", state.as_str());
    // Read mtime for uptime estimate
    let mtime: u64 = azos_drv_sys::timebase::now();
    azos_drv_sys::kconsoleln!("[PM] Uptime: {} ticks (mtime)", mtime);
}


// ---------------------------------------------------------------------------
// pm_clock_gate / DVFS (F09) / Thermal (F23) — DELETED 2026-09-26 (U05-7)
// ---------------------------------------------------------------------------
//
// `pm_clock_gate`, `dvfs_set_freq`/`dvfs_get_freq`/`dvfs_power_budget`/
// `dvfs_info` (`CpuFreqLevel`), and `thermal_read_temp_mdeg`/
// `thermal_check`/`thermal_get_temp_c`/`thermal_info` (`ThermalState`) had
// zero callers anywhere in kernel/crates/tests — confirmed by grep before
// deletion (unlike `pm_idle`/`pm_suspend` above, which `crates/core/shell/src/
// lib.rs` calls for real, and which is why this file was not deleted
// wholesale). Their `#[cfg(feature = "vf2")]` bodies wrote invented
// register layouts at `platform::hw`-adjacent addresses that were also
// dead — see U05-10: "drop the syscrg write until the CRG layout is
// sourced" and this crate's per-axis 8d assessment. `thermal_read_temp_mdeg`
// additionally had a base-address fix landed this same pass (U05-1: was
// reading the PMU as a temperature sensor) that is now moot along with the
// function. If DVFS/thermal throttling is wanted again, it needs a real
// caller (a periodic task, or wiring into `domains/robot/safety-core`'s thermal
// story) from day one, not a parallel API surface with none — the same
// rule `optical_flow.rs`'s deletion note in `lib.rs` states.
