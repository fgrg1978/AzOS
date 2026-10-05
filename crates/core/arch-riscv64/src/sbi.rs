// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// RISC-V SBI (Supervisor Binary Interface) wrappers.
///
/// SBI provides a standardized interface between S-mode (our kernel)
/// and M-mode firmware (OpenSBI). All calls are made via `ecall`.
///
/// Ported from kernel/arch/riscv64/sbi/sbi.h

/// SBI return value: error code + value.
#[repr(C)]
pub struct SbiRet {
    pub error: isize,
    pub value: isize,
}

// ---- SBI Extension IDs ----

pub const EXT_BASE: usize = 0x10;
pub const EXT_TIME: usize = 0x5449_4D45; // "TIME"
pub const EXT_IPI: usize = 0x0073_5049; // "sPI"
pub const EXT_RFENCE: usize = 0x5246_4E43; // "RFNC"
pub const EXT_HSM: usize = 0x0048_534D; // "HSM"
pub const EXT_SRST: usize = 0x5352_5354; // "SRST"

// ---- Base Extension Function IDs ----

pub const BASE_GET_SPEC_VERSION: usize = 0;
pub const BASE_GET_IMPL_ID: usize = 1;
pub const BASE_GET_IMPL_VERSION: usize = 2;
pub const BASE_PROBE_EXTENSION: usize = 3;

// ---- Timer Extension ----

pub const TIME_SET_TIMER: usize = 0;

// ---- IPI Extension ----

pub const IPI_SEND: usize = 0;

// ---- RFENCE Extension ----

pub const RFENCE_I: usize = 0;
pub const RFENCE_SFENCE_VMA: usize = 1;

// ---- HSM Extension ----

pub const HSM_HART_START: usize = 0;
pub const HSM_HART_STOP: usize = 1;
pub const HSM_HART_GET_STATUS: usize = 2;

// ---- SRST Extension ----

pub const SRST_SYSTEM_RESET: usize = 0;
pub const SRST_TYPE_SHUTDOWN: usize = 0;
pub const SRST_TYPE_COLD_REBOOT: usize = 1;

/// Low-level SBI ecall with up to 6 arguments.
#[inline(always)]
pub fn sbi_call(ext: usize, fid: usize, args: [usize; 6]) -> SbiRet {
    let error: isize;
    let value: isize;

    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") args[0] as isize => error,
            inlateout("a1") args[1] as isize => value,
            in("a2") args[2],
            in("a3") args[3],
            in("a4") args[4],
            in("a5") args[5],
            in("a6") fid,
            in("a7") ext,
        );
    }

    SbiRet { error, value }
}

/// Simplified SBI call with 0-3 arguments.
#[inline(always)]
fn call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> SbiRet {
    sbi_call(ext, fid, [a0, a1, a2, 0, 0, 0])
}

// ---- Base Extension APIs ----

/// Get SBI specification version.
pub fn get_spec_version() -> usize {
    let ret = call(EXT_BASE, BASE_GET_SPEC_VERSION, 0, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

/// Get SBI implementation ID.
pub fn get_impl_id() -> usize {
    let ret = call(EXT_BASE, BASE_GET_IMPL_ID, 0, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

/// Get SBI implementation version.
pub fn get_impl_version() -> usize {
    let ret = call(EXT_BASE, BASE_GET_IMPL_VERSION, 0, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

/// Probe if an extension is available (returns non-zero if available).
pub fn probe_extension(ext_id: usize) -> usize {
    let ret = call(EXT_BASE, BASE_PROBE_EXTENSION, ext_id, 0, 0);
    if ret.error == 0 { ret.value as usize } else { 0 }
}

// ---- Timer Extension ----

/// Set the timer for the current hart.
#[inline(always)]
pub fn set_timer(stime_value: u64) {
    call(EXT_TIME, TIME_SET_TIMER, stime_value as usize, 0, 0);
}

// ---- IPI Extension ----

/// Send IPI to specified harts.
pub fn send_ipi(hart_mask: usize, hart_mask_base: usize) -> isize {
    call(EXT_IPI, IPI_SEND, hart_mask, hart_mask_base, 0).error
}

// ---- RFENCE Extension ----

/// Remote fence.i on specified harts.
pub fn remote_fence_i(hart_mask: usize, hart_mask_base: usize) -> isize {
    call(EXT_RFENCE, RFENCE_I, hart_mask, hart_mask_base, 0).error
}

/// Remote sfence.vma on specified harts.
pub fn remote_sfence_vma(
    hart_mask: usize,
    hart_mask_base: usize,
    start_addr: usize,
    size: usize,
) -> isize {
    sbi_call(EXT_RFENCE, RFENCE_SFENCE_VMA,
        [hart_mask, hart_mask_base, start_addr, size, 0, 0]).error
}

// ---- HSM Extension ----

/// Start a hart at the given address.
pub fn hart_start(hartid: usize, start_addr: usize, opaque: usize) -> isize {
    call(EXT_HSM, HSM_HART_START, hartid, start_addr, opaque).error
}

/// Stop the current hart.
pub fn hart_stop() -> isize {
    call(EXT_HSM, HSM_HART_STOP, 0, 0, 0).error
}

/// Get hart status.
pub fn hart_get_status(hartid: usize) -> isize {
    let ret = call(EXT_HSM, HSM_HART_GET_STATUS, hartid, 0, 0);
    if ret.error == 0 { ret.value } else { ret.error }
}

// ---- SRST Extension ----

/// System reset (shutdown or reboot).
pub fn system_reset(reset_type: usize, reset_reason: usize) -> isize {
    call(EXT_SRST, SRST_SYSTEM_RESET, reset_type, reset_reason, 0).error
}

/// Shutdown the system.
pub fn shutdown() -> ! {
    system_reset(SRST_TYPE_SHUTDOWN, 0);
    // Should not return, but just in case:
    loop { crate::cpu::wfi(); }
}

/// Reboot the system.
pub fn reboot() -> ! {
    system_reset(SRST_TYPE_COLD_REBOOT, 0);
    loop { crate::cpu::wfi(); }
}
