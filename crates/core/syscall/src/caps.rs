// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The handle family (D6): the calls that act on a capability itself rather
//! than on the object it names. `SYS_CAP_INFO` reads what the caller holds,
//! `SYS_CAP_CLOSE` ends a handle's life and releases what it names,
//! `SYS_CAP_DERIVE` mints a narrowed (badged, dated) copy of an endpoint
//! capability, `SYS_CAP_REVOKE` revokes everything derived from a handle. The
//! wire formats are `azos_abi::syscall_nr`'s.

use azos_abi::cap::{ty, CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::syscall_nr::{CAP_INFO_LOOKUP, CAP_INFO_QUERY};

use crate::dispatch::SyscallOut;
use crate::invoke::errno_cap;

/// `SYS_CAP_INFO`: see the number's doc.
pub(crate) fn sys_cap_info(h: u64, query: u64, a2: u64, a3: u64, out: &mut SyscallOut) -> i64 {
    match query {
        CAP_INFO_LOOKUP => crate::handlers::sys_cap_lookup(a2, a3),
        CAP_INFO_QUERY => {
            let Ok(raw) = u32::try_from(h) else { return Errno::ECAPSTALE.to_syscall_ret() };
            let handle = CapHandle::from_raw(raw);
            let tid = azos_sched::current_task_tid();
            let got = azos_ipc::cap_store::read_table(tid, |t| {
                let (ty, perms, _) = t.peek_raw(handle)?;
                let badge = t.ext_of(handle).map_or(0, |e| e.badge);
                let expiry = t.warrant_of(handle).map_or(0, |w| w.expiry_ns);
                Some((ty, perms, badge, expiry))
            })
            .flatten();
            match got {
                Some((ty, perms, badge, expiry)) => {
                    out.set_no_cap([badge as u64, expiry, 0, 0, 0]);
                    (ty.raw() as i64) | ((perms.bits() as i64) << 8)
                }
                None => Errno::ECAPSTALE.to_syscall_ret(),
            }
        }
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// `SYS_CAP_CLOSE`: release what the handle names, by its type, and revoke it.
pub(crate) fn sys_cap_close(h: u64) -> i64 {
    let Ok(raw) = u32::try_from(h) else { return Errno::ECAPSTALE.to_syscall_ret() };
    match azos_abi::cap::CapType::from_raw(CapHandle::from_raw(raw).kind()) {
        Some(ty::PIPE) => crate::ushell::sys_pipe_close(h),
        Some(ty::IORING) => crate::ipc_handlers::sys_ioring_destroy_typed(h),
        Some(ty::PORT) => crate::ipc_handlers::sys_port_destroy_typed(h),
        Some(ty::SHM) => crate::ipc_handlers::sys_shm_release_typed(h),
        _ => crate::handlers::sys_close_typed(h),
    }
}

/// `SYS_CAP_DERIVE`: see the number's doc.
pub(crate) fn sys_cap_derive(ep_raw: u64, rights: u64, badge: u64, expiry_ns: u64) -> i64 {
    let (Ok(raw), Ok(badge)) = (u32::try_from(ep_raw), u32::try_from(badge)) else {
        return Errno::EINVAL.to_syscall_ret();
    };
    if rights & !(CapPerms::ALL.bits() as u64) != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let tid = azos_sched::current_task_tid();
    // A copy born expired is refused before anything is minted (the rule of a
    // capability entry of a message: `ipc_deadline::check_caps`).
    let now = azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ);
    if expiry_ns != 0 && expiry_ns <= now {
        azos_decision::record(
            azos_decision::Rule::DeadlineExpired,
            azos_decision::Verdict::Refuse,
            tid,
            [expiry_ns, now, ep_raw],
        );
        return Errno::EDEADLINE.to_syscall_ret();
    }
    let rights = CapPerms::from_bits_truncate(rights as u8);
    match crate::handlers::mint_badged_recording(tid, raw, badge, rights, expiry_ns) {
        Ok(h) => h.0 as i64,
        Err(e) => errno_cap(e),
    }
}

/// `SYS_CAP_REVOKE`: see the number's doc.
pub(crate) fn sys_cap_revoke(h: u64) -> i64 {
    let Ok(raw) = u32::try_from(h) else { return Errno::ECAPSTALE.to_syscall_ret() };
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::revoke_derived(tid, CapHandle::from_raw(raw)) {
        Ok(new) => new.0 as i64,
        Err(e) => errno_cap(e),
    }
}
