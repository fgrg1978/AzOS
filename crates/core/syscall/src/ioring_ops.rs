// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's `io_ring` op table.
//!
//! Each entry calls what the matching typed syscall calls once that call has
//! resolved its capability: the sensor read is `handlers::sensor_read_into`,
//! a wheel is `motor_set_reporting` / `motor_stop_reporting`, a PWM duty or
//! GPIO pin goes through the same motor-binding guard and driver call. There
//! is no second implementation of any operation. What the typed call's
//! resolution decides is decided per entry by `io_ring::dispatch_sqe` instead:
//! the submitter's seccomp verdict (`syscall_allowed` below), its Domain's
//! pledge mask (`pledge_allowed`), the capability
//! of the ring's owner, and containment for a write (`write_contained`).
//!
//! The kernel registers the table once at boot, before any task runs:
//! `azos_ipc::io_ring::io_ring_register_ops(&KERNEL_IORING_OPS)`.
//!
//! Every entry receives a window of the ring's data buffer that
//! `dispatch_sqe` has bounded, on a page its in-flight claim keeps alive, and
//! runs with no lock of the ring table held.

use azos_abi::cap::ty;
#[cfg(not(feature = "use-robot"))]
use crate::no_robot::{robot as azos_robot};
use azos_abi::error::Errno;
use azos_ipc::io_ring::{BlockStart, IoRingOps, OpResult, PinnedBuf, IO_ERR_INVALID_PARAM};
use azos_robot::{motor_set_reporting, motor_stop_reporting, MotorDir, MOTOR_REFUSED_HALTED};

/// The table `io_ring_register_ops` installs.
pub static KERNEL_IORING_OPS: IoRingOps = KERNEL_IORING_OPS_TABLE;

/// [`KERNEL_IORING_OPS`] as a constant, for a table that replaces a few
/// entries with struct-update syntax (the K1 ktest's file stand-in).
pub const KERNEL_IORING_OPS_TABLE: IoRingOps = IoRingOps {
    syscall_allowed,
    iface_allowed,
    op_allowed,
    pledge_allowed,
    write_contained,
    read_sensor,
    write_gpio,
    read_gpio,
    i2c_read,
    i2c_write,
    pwm_set,
    motor_wheel,
    net_send,
    net_recv,
    note_denial,
    file_io,
    block_io: crate::block_host::block_io,
    block_start,
    block_poll,
    block_orphan,
    block_service,
    deadline_reached,
    notify_word,
    file_fsync,
    fsync_done,
    may_block,
    file_inline,
    handoff_kick: if azos_limits::IORING_WORKER { Some(handoff_kick) } else { None },
    buf_pin,
    buf_unpin,
    buf_usable,
};

azos_common::ro_hook! {
    /// The io_ring worker's waker, registered by the kernel when it creates the
    /// worker task (Kconfig `IORING_WORKER`); 0 until then.
    static WORKER_WAKE: fn();
}
/// Runtime canary `ioring-rt-inline` (set by the kernel at boot): an RT
/// submitter's file entries run inline again, so the RT block-I/O check
/// fires.
pub static RT_INLINE_CANARY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Register the io_ring worker's waker (the kernel, once its task exists).
pub fn set_worker_wake(f: fn()) {
    WORKER_WAKE.set(f);
}

/// May the running task wait for the block layer? Not a real-time one (its
/// own base priority in the RT band; a donation does not count).
fn may_block() -> bool {
    azos_sched::scheduler::current_task_base_priority() >= azos_sched::RT_PRIORITY_THRESHOLD
        || RT_INLINE_CANARY.load(core::sync::atomic::Ordering::Relaxed)
}

/// May a task that may block run a file entry in its own pass? Not under
/// Kconfig `IORING_ASYNC`, where the worker is the file seam's queue for every
/// submitter; the runtime canary `ioring-rt-inline` puts the inline run back.
fn file_inline() -> bool {
    !azos_limits::IORING_ASYNC || RT_INLINE_CANARY.load(core::sync::atomic::Ordering::Relaxed)
}

/// Wake the worker. Before it exists the hand-off waits for its first pass,
/// which runs every hand-off marked so far.
fn handoff_kick() {
    if let Some(f) = WORKER_WAKE.get() {
        f();
    }
}

#[inline]
const fn errno(e: Errno) -> i32 {
    e.to_syscall_ret() as i32
}

/// The seccomp question `syscall_dispatch_out` asks of a trap, asked of one
/// ring entry: `Allow` runs it, `Audit` runs it and records it the way the
/// dispatcher records an audited call, `Deny` refuses it.
///
/// **The profile is always the ring OWNER's**, the task whose capabilities
/// authorize the entry, so a capability and a profile of two different tasks
/// never combine to admit one:
///  * inline, in the owner's own `SYS_RING_ENTER`, the owner is the
///    current task and its verdict is read as the dispatcher reads it
///    (`io_ring_submit_ref` refuses a submitter that is not the owner before
///    any entry is dispatched);
///  * from the SQ poller, a kernel task running the owner's ring, the verdict
///    is read from the owner's slot (`task_syscall_verdict`), and an owner
///    that is no longer a live task refuses every entry.
///
/// An audited entry is recorded against the owner's per-task bound.
fn syscall_allowed(owner_tid: u32, nr: u64) -> bool {
    use azos_sched::filter::FilterVerdict;
    let verdict = if azos_sched::current_proc_tid() == owner_tid {
        azos_sched::scheduler::current_syscall_verdict(nr)
    } else {
        match azos_sched::scheduler::task_syscall_verdict(owner_tid, nr) {
            Some(v) => v,
            None => return false,
        }
    };
    match verdict {
        FilterVerdict::Allow => true,
        // `Audit` is only answered for `nr <= u16::MAX`, so the narrowing is
        // exact, as in the dispatcher.
        FilterVerdict::Audit => {
            crate::handlers::record_seccomp_audit_for(owner_tid, nr as u16);
            true
        }
        // `task_syscall_verdict` reads the filter itself, never the Linux
        // tag; refused all the same if a later change routes it here.
        FilterVerdict::Deny | FilterVerdict::Linux => false,
    }
}

/// degraded-mode containment, the test `CapTable::get` applies to a WRITE.
/// [`syscall_allowed`] for an interface op: the owner's profile lists the
/// kernel-hosted interface `key` (`ImageProfile::ifaces`), or audits it.
fn iface_allowed(owner_tid: u32, key: u16) -> bool {
    use azos_sched::filter::FilterVerdict;
    let verdict = if azos_sched::current_proc_tid() == owner_tid {
        azos_sched::scheduler::current_iface_verdict(key)
    } else {
        match azos_sched::scheduler::task_iface_verdict(owner_tid, key) {
            Some(v) => v,
            None => return false,
        }
    };
    match verdict {
        FilterVerdict::Allow => true,
        FilterVerdict::Audit => {
            crate::handlers::record_seccomp_audit_for(owner_tid, azos_abi::syscall_nr::SYS_IPC_CALL_V2 as u16);
            true
        }
        FilterVerdict::Deny | FilterVerdict::Linux => false,
    }
}

/// [`syscall_allowed`] for an op of a handle: the owner's profile lists the
/// class of the `invoke` op on its kind (`ImageProfile::ops`), or audits it.
fn op_allowed(owner_tid: u32, op: u16) -> bool {
    use azos_abi::invoke::{op_class, op_kind};
    use azos_sched::filter::FilterVerdict;
    let (kind, class) = (op_kind(op), op_class(op));
    let verdict = if azos_sched::current_proc_tid() == owner_tid {
        azos_sched::scheduler::current_op_verdict(kind, class)
    } else {
        match azos_sched::scheduler::task_op_verdict(owner_tid, kind, class) {
            Some(v) => v,
            None => return false,
        }
    };
    match verdict {
        FilterVerdict::Allow => true,
        FilterVerdict::Audit => {
            crate::handlers::record_seccomp_audit_for(owner_tid, azos_abi::syscall_nr::SYS_INVOKE as u16);
            true
        }
        FilterVerdict::Deny | FilterVerdict::Linux => false,
    }
}

/// The pledge question of a trap's prologue, asked of one ring entry: the
/// mask of the Domain the ring's OWNER is in (never the current task's: the SQ
/// poller is a kernel task, in none), for the call the entry stands for.
/// `false` refuses the entry and writes the `pledge` receipt (door: ring). An owner
/// that is no longer a live task has no Domain, and `syscall_allowed` already
/// refuses it.
fn pledge_allowed(owner_tid: u32, nr: u64, bit: u8) -> bool {
    let key = azos_sched::idx_for_tid(owner_tid).map_or(azos_sched::domain::NONE, azos_sched::task_domain);
    azos_sched::domain::admit(key, owner_tid, nr, bit)
}

fn write_contained() -> bool {
    azos_ipc::cap::degraded_active()
}

/// The `Sensor` interface's read (with no size limit but the window's), into
/// the ring's buffer. The answer is the
/// typed call's: the byte count, 0 when a scan or frame is not ready, -1 for a
/// buffer too small or a sensor not ready.
fn read_sensor(sensor_type: u32, buf: *mut u8, len: usize) -> OpResult {
    // SAFETY: `dispatch_sqe` bounded `[buf, buf + len)` inside the ring's data
    // buffer. That buffer is NOT private to the pass: the whole ring page is
    // mapped user RW (`sys_ioring_create_typed`), so ring 3 can write it while
    // this runs (OVSwrap review F4; this comment used to claim nothing else
    // writes it). Every op on the window treats it as payload: a read lands
    // bytes in it, a write copies bytes out of it once, and nothing here reads
    // a byte back to decide anything — the one op that interprets its payload,
    // `i2c_write`, copies it to the stack first. Ring 3 racing its own buffer
    // can corrupt only its own data.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let n = crate::handlers::sensor_read_into(sensor_type as u64, len as u64, |data, _| {
        match out.get_mut(..data.len()) {
            Some(dst) => {
                dst.copy_from_slice(data);
                data.len() as i64
            }
            None => -1,
        }
    });
    Ok(n.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
}

/// `SYS_GPIO_WRITE_TYPED` below its capability: a pin bound to a motor's
/// H-bridge is refused with the typed call's `E_PERM`, then the level's low
/// bit is written.
fn write_gpio(pin: u32, value: u32) -> OpResult {
    if crate::handlers::gpio_pin_is_motor_bound(pin) {
        return Err(crate::handlers::E_PERM as i32);
    }
    let rc = azos_drv_gpio::gpio::gpio_write(pin, value & 1);
    Ok(if rc == 0 { 0 } else { errno(Errno::EIO) })
}

/// `SYS_GPIO_READ_TYPED` below its capability: 0 or 1, `-EIO` for a driver
/// fault.
fn read_gpio(pin: u32) -> OpResult {
    let v = azos_drv_gpio::gpio::gpio_read(pin);
    if v < 0 {
        Ok(errno(Errno::EIO))
    } else {
        Ok(v)
    }
}

/// Largest I2C transfer one ring entry carries: the ring's own bound (its
/// data buffer is a page), not the interface's inline one
/// (`azos_devif::i2c::MAX_BYTES`).
const I2C_RING_MAX_BYTES: usize = 256;

/// An I2C read below its capability: the length bound, the driver read into
/// the ring's buffer, `-EIO` for a driver fault.
fn i2c_read(bus: u32, addr: u32, reg: u32, buf: *mut u8, len: usize) -> OpResult {
    if len == 0 || len > I2C_RING_MAX_BYTES {
        return Err(errno(Errno::EINVAL));
    }
    // SAFETY: bounded by `dispatch_sqe`, as in `read_sensor`.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    // `dispatch_sqe` narrowed all three to `u8` before the capability check.
    let n = azos_drv_bus::i2c::i2c_read(bus as u8, addr as u8, reg as u8, dst);
    Ok(if n < 0 { errno(Errno::EIO) } else { n })
}

/// `SYS_I2C_WRITE_TYPED` below its capability: the same length bound,
/// `data[0]` the register, `-EIO` for a driver fault.
fn i2c_write(bus: u32, addr: u32, data: *const u8, len: usize) -> OpResult {
    if len == 0 || len > I2C_RING_MAX_BYTES {
        return Err(errno(Errno::EINVAL));
    }
    // `data[0]` is the register and the driver may read it more than once;
    // ring 3 can rewrite the window during the pass (see `read_sensor`), so
    // the payload is copied to the stack ONCE and the driver sees only the
    // copy (OVSwrap review F4): one register, one value, whatever ring 3 does.
    let mut bounce = [0u8; I2C_RING_MAX_BYTES];
    // SAFETY: bounded by `dispatch_sqe`, as in `read_sensor`; `len` is at most
    // `I2C_RING_MAX_BYTES` (checked above). A raw copy, never a slice over
    // the shared window.
    unsafe { core::ptr::copy_nonoverlapping(data, bounce.as_mut_ptr(), len) };
    let rc = azos_drv_bus::i2c::i2c_write(bus as u8, addr as u8, &bounce[..len]);
    Ok(if rc == 0 { 0 } else { errno(Errno::EIO) })
}

/// `SYS_PWM_SET_DUTY_PCT_TYPED` below its capability: a channel bound to a
/// motor is refused with the typed call's `E_PERM` (the raw interface never
/// reaches a wheel past its gate), then the duty is written.
fn pwm_set(channel: u32, duty_pct: u32) -> OpResult {
    if crate::handlers::pwm_channel_is_motor_bound(channel) {
        return Err(crate::handlers::E_PERM as i32);
    }
    let rc = azos_drv_actuator::pwm::pwm_set_duty_pct(channel, duty_pct);
    Ok(if rc == 0 { 0 } else { errno(Errno::EIO) })
}

/// One wheel, as `motor.speed` commands it: 0 coasts, anything else
/// drives forward. The halt rule, the e-stop latch and the envelope are the
/// motor layer's and apply here unchanged; a command the halt rule refuses has
/// still written duty 0, and answers the typed call's `-EAGAIN` as a refusal.
fn motor_wheel(id: u32, speed_pct: u32) -> OpResult {
    let (rc, applied) = if speed_pct == 0 {
        motor_stop_reporting(id)
    } else {
        motor_set_reporting(id, MotorDir::Forward, speed_pct)
    };
    // The applied duty comes out of the write itself; see the marker in
    // `MotorServer::speed` for why it is not read back afterwards.
    #[cfg(feature = "actuation-smoke")]
    {
        let duty = applied.map(|d| d as i64).unwrap_or(-1);
        azos_drv_sys::kprintln!(
            "[ACTSMOKE] ioring motor id={} ask={} duty={} rc={}",
            id, speed_pct, duty, rc);
    }
    #[cfg(not(feature = "actuation-smoke"))]
    let _ = applied;
    if rc == MOTOR_REFUSED_HALTED {
        Err(crate::handlers::E_CONTAINED as i32)
    } else {
        Ok(rc)
    }
}

/// `NODE_SEND` on a ring (K1): the `Cap<Socket>` handle resolved in the
/// OWNER's table with `WRITE` and containment, a refusal recorded as the typed
/// call records it, the socket's owner stamp checked as `socket_access_ok`
/// checks it, then the bytes QUEUED with `socket_send`: one segment (at most
/// 1460 bytes, the typed call's clamp) into the TCP send ring or a UDP
/// datagram onto the NIC's TX queue, never waiting (no ARP or window wait:
/// the typed call's yield loop is not taken). `Ok(bytes queued)`, `Ok(0)` for
/// a closed window, `Ok(-1)` for a socket that cannot send.
fn net_send(owner_tid: u32, cap_raw: u32, data: *const u8, len: usize) -> OpResult {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_ipc::cap::{targets::Socket, Cap};
    let cap: Cap<Socket> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    let fd = match azos_ipc::cap_store::with_table(owner_tid, |t| t.get_op(cap, CapPerms::WRITE, azos_abi::invoke::NODE_SEND)) {
        Some(Ok(fd)) => fd as i32,
        Some(Err(e)) => return refuse(owner_tid, ty::SOCKET, e),
        None => return Err(errno(Errno::EINVAL)),
    };
    if azos_net::socket_owner(fd) != Some(owner_tid) {
        crate::handlers::note_typed_denial_for(owner_tid, ty::SOCKET, azos_ipc::cap::CapError::MissingPerms);
        return Err(crate::handlers::E_PERM as i32);
    }
    // SAFETY: `dispatch_sqe` bounded the window inside the ring's buffer.
    let src = unsafe { core::slice::from_raw_parts(data, len.min(1460)) };
    Ok(azos_net::socket::socket_send(fd, src))
}

/// `NODE_RECV` on a ring: the `Cap<Socket>` handle resolved in the OWNER's table
/// with `READ`, a refusal recorded as the typed call records it, the socket's
/// owner stamp checked as `socket_access_ok` checks it, then the bytes taken
/// off the socket with `socket_recv` straight into the window the dispatcher
/// bounded: no bounce buffer and no `copy_to_user`, because the window is
/// kernel memory (the ring's data buffer, or a registered buffer). Never waits.
///
/// The answers are the typed call's: the byte count, `0` with nothing queued,
/// `-1` for a socket that cannot receive, `-EEOF` once a stream has ended.
/// Like the typed call it drains the NIC itself when no net-poll task runs.
fn net_recv(owner_tid: u32, cap_raw: u32, buf: *mut u8, len: usize) -> OpResult {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_ipc::cap::{targets::Socket, Cap};
    let cap: Cap<Socket> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    let fd = match azos_ipc::cap_store::with_table(owner_tid, |t| t.get_op(cap, CapPerms::READ, azos_abi::invoke::NODE_RECV)) {
        Some(Ok(fd)) => fd as i32,
        Some(Err(e)) => return refuse(owner_tid, ty::SOCKET, e),
        None => return Err(errno(Errno::EINVAL)),
    };
    if azos_net::socket_owner(fd) != Some(owner_tid) {
        crate::handlers::note_typed_denial_for(owner_tid, ty::SOCKET, azos_ipc::cap::CapError::MissingPerms);
        return Err(crate::handlers::E_PERM as i32);
    }
    if len == 0 {
        return Ok(-1);
    }
    // N8: only when no net-poll task runs, as the typed call does.
    if !azos_net::poller_running() {
        azos_net::net_poll();
    }
    // SAFETY: `dispatch_sqe` bounded `buf..buf + len` inside the ring's data
    // buffer or a registered buffer, both kernel memory its claim keeps alive.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf, len.min(i32::MAX as usize)) };
    let n = azos_net::socket::socket_recv(fd, dst);
    if n == -1 && azos_net::socket::socket_stream_ended(fd) {
        return Ok(Errno::EEOF.to_syscall_ret() as i32);
    }
    Ok(n)
}

/// The typed calls' errno for a capability refusal (`errno_for_file_err`).
fn cap_errno(e: azos_ipc::cap::CapError) -> i32 {
    use azos_ipc::cap::CapError;
    errno(match e {
        CapError::Stale | CapError::Revoked => Errno::ECAPSTALE,
        CapError::WrongKind => Errno::ECAPKIND,
        CapError::MissingPerms => Errno::ECAPPERMS,
        CapError::Contained => Errno::EAGAIN,
        CapError::NoSpace => Errno::EMFILE,
    })
}

/// A capability refusal of the ring's owner: recorded as the typed call
/// records it, charged to the owner's bound, and answered with its errno.
fn refuse(owner_tid: u32, kind: azos_abi::cap::CapType, e: azos_ipc::cap::CapError) -> OpResult {
    crate::handlers::note_typed_denial_for(owner_tid, kind, e);
    Err(cap_errno(e))
}

/// A device entry the ring refused for want of the owner's capability. The
/// ring asks "does the owner hold this kind for this resource", so the reason
/// is the one a typed call gives a handle without the permission.
fn note_denial(owner_tid: u32, kind: azos_abi::cap::CapType) {
    crate::handlers::note_typed_denial_for(owner_tid, kind, azos_ipc::cap::CapError::MissingPerms);
}

/// `NODE_READ` / `NODE_WRITE` on a ring: the handle is
/// resolved in the OWNER's table with `CapTable::get` — `READ`, or `WRITE`
/// with containment — as `file_fd_for` resolves it, then the descriptor is
/// read or written through the same `FileOps` seam `sys_read`/`sys_write`
/// reach. The window is the ring's buffer, so there is no user copy.
fn file_io(owner_tid: u32, cap_raw: u32, write: bool, buf: *mut u8, len: usize) -> OpResult {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_ipc::cap::{targets::File, Cap};
    let (need, op) = if write {
        (CapPerms::WRITE, azos_abi::invoke::NODE_WRITE)
    } else {
        (CapPerms::READ, azos_abi::invoke::NODE_READ)
    };
    let cap: Cap<File> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    let fd = match azos_ipc::cap_store::with_table(owner_tid, |t| t.get_op(cap, need, op)) {
        // A directory-tree `Cap<File>` names no descriptor (wave 10).
        Some(Ok(fd)) if azos_ipc::file_cap::is_tree_resource(fd) => {
            return refuse(owner_tid, ty::FILE, azos_ipc::cap::CapError::WrongKind)
        }
        Some(Ok(fd)) => fd as i32,
        Some(Err(e)) => return refuse(owner_tid, ty::FILE, e),
        None => return Err(errno(Errno::EINVAL)),
    };
    let Some(ops) = crate::file_ops::file_ops() else { return Ok(-1) };
    // `read_as`/`write_as`, not `read`/`write`: the descriptor must be the
    // OWNER's. `read`/`write` ask about the running task, and from the SQ
    // poller that is a kernel task every descriptor admits, so a gifted or
    // stale `Cap<File>` (a bare number, reused after its opener closed it)
    // reached whichever task's file now held the number (OVSwrap review F1).
    let n = if write {
        // SAFETY: `dispatch_sqe` bounded `[buf, buf + len)` inside the ring's
        // data buffer, which the in-flight claim keeps allocated. Ring 3 maps
        // that page RW and may write it during the pass, so the slice is not
        // kept past the call: the filesystem copies each byte once, as payload.
        ops.write_as(owner_tid, fd, unsafe { core::slice::from_raw_parts(buf, len) })
    } else {
        // SAFETY: the same bound and claim as the write arm; the filesystem
        // fills the slice once and keeps no reference to it.
        ops.read_as(owner_tid, fd, unsafe { core::slice::from_raw_parts_mut(buf, len) })
    };
    Ok(n.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
}

/// `OP_FSYNC` (K1): the handle resolved in the OWNER's table as
/// `NODE_FSYNC` resolves it (any permission; a directory-tree handle is
/// the wrong kind), then a flush is ASKED for the owner's descriptor. The
/// submitter never waits on the device: the flusher (`fs-wb`) does the I/O
/// and `io_ring_flush_posted` completes the entry.
fn file_fsync(owner_tid: u32, cap_raw: u32) -> azos_ipc::io_ring::OpResult64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_ipc::cap::{targets::File, Cap};
    let cap: Cap<File> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    let fd = match azos_ipc::cap_store::with_table(owner_tid, |t| t.get_op(cap, CapPerms::NONE, azos_abi::invoke::NODE_FSYNC)) {
        Some(Ok(fd)) if azos_ipc::file_cap::is_tree_resource(fd) => {
            return refuse(owner_tid, ty::FILE, azos_ipc::cap::CapError::WrongKind).map(|_| 0)
        }
        Some(Ok(fd)) => fd as i32,
        Some(Err(e)) => return refuse(owner_tid, ty::FILE, e).map(|_| 0),
        None => return Err(errno(Errno::EINVAL)),
    };
    let Some(ops) = crate::file_ops::file_ops() else { return Err(-1) };
    ops.fsync_request_as(owner_tid, fd).map_err(|e| e.clamp(i32::MIN as i64, -1) as i32)
}

/// Has flush `ticket` completed (`FileOps::fsync_done`)?
fn fsync_done(ticket: u64) -> Option<i32> {
    match crate::file_ops::file_ops() {
        Some(ops) => ops.fsync_done(ticket).map(|r| r.clamp(i32::MIN as i64, 0) as i32),
        None => Some(-1),
    }
}

/// `OP_TIMER`'s clock: the deadline rounded up to a tick, as
/// `sys_sleep_until` rounds it.
fn deadline_reached(deadline_ns: u64) -> bool {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    now() >= azos_abi::time::ns_to_ticks_ceil(deadline_ns, TIMER_FREQ)
}

/// `OP_NOTIFY_WAIT`'s look at its word: the `Cap<Shm>` handle resolved in the
/// owner's table (`READ`), the offset 4-aligned and inside the region, the
/// word read through the kernel's view of its page.
///
/// **The page is pinned across the read** (OVSwrap review F5):
/// `memobj_with_word_ref` loads the word with the region table locked, and a
/// region's frames go back to the PMM only under that lock. This used to take
/// the page address under the lock and load after releasing it, so a
/// last-holder release on another hart in between left the load on a freed —
/// possibly reissued — frame, and the completion (`word == expected`) became an
/// equality oracle on someone else's memory.
fn notify_word(owner_tid: u32, shm_cap: u32, offset: u32) -> Result<u32, i32> {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_ipc::cap::{targets::Shm, Cap};
    if offset % 4 != 0 {
        return Err(errno(Errno::EINVAL));
    }
    let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(shm_cap));
    let r = match azos_ipc::cap_store::with_table(owner_tid, |t| {
        t.get_op(cap, CapPerms::READ, crate::invoke::class_op(ty::SHM, azos_abi::invoke::CLASS_WAIT))
    }) {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            crate::handlers::note_typed_denial_for(owner_tid, ty::SHM, e);
            return Err(cap_errno(e));
        }
        None => return Err(errno(Errno::EINVAL)),
    };
    match azos_ipc::memobj::memobj_with_word_ref(r, offset as usize, |w| {
        w.load(core::sync::atomic::Ordering::Acquire)
    }) {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err(errno(Errno::EINVAL)),
        Err(_) => Err(errno(Errno::ECAPSTALE)),
    }
}

// ── Registered buffers (OP_BUF_REGISTER) ─────────────────────────────────
//
// A registered buffer is a range of a `MemObj` the ring's owner already maps,
// pinned with a kernel reference (`memobj_frames_pin`: a reference of the
// object, not a slot of the object table, so `MAX_MEMOBJS` is not touched) and
// reached afterwards through the direct map. The refusals, in order: the
// owner's capability (`READ | MAP`, and `WRITE` on a read-write object: the
// kernel writes into it), an object the kernel can reach (anonymous or
// contiguous, not `ATTR_NO_KERNEL_MAP`, not purged), a mapping of the owner's
// (so the bytes the kernel leaves are bytes the owner can read), a range inside
// the object and inside ONE physically contiguous run of its frames (a single
// kernel pointer must cover it), and no frame a clone shares (a write would
// show in the clone). A pin taken and then refused is given back at once.

/// The errno of a `MemObjError`: a capability refusal is recorded for the
/// ring's owner as a typed call records its own.
fn memobj_errno(owner_tid: u32, e: azos_ipc::memobj::MemObjError) -> i32 {
    use azos_ipc::memobj::MemObjError;
    match e {
        MemObjError::Cap(c) => shm_refusal(owner_tid, c),
        other => crate::ipc_handlers::errno_for_memobj_err(other) as i32,
    }
}

/// A capability refusal on a `Cap<Shm>` of `owner_tid`, recorded as the typed
/// calls record theirs, and its errno.
fn shm_refusal(owner_tid: u32, c: azos_ipc::cap::CapError) -> i32 {
    crate::handlers::note_typed_denial_for(owner_tid, ty::SHM, c);
    cap_errno(c)
}

fn buf_pin(owner_tid: u32, shm_cap: u32, offset: u32, len: u32) -> Result<PinnedBuf, i32> {
    use azos_abi::cap::CapHandle;
    use azos_ipc::cap::{targets::Shm, Cap, CapError};
    use azos_ipc::memobj::{self, MemKind, ATTR_NO_KERNEL_MAP, MAX_MEMOBJ_PAGES};
    let page = azos_arch::PAGE_SIZE;
    let Some(end) = (offset as usize).checked_add(len as usize).filter(|_| len != 0) else {
        return Err(IO_ERR_INVALID_PARAM);
    };
    let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(shm_cap));
    let grant = match azos_ipc::cap_store::with_table(owner_tid, |t| {
        memobj::memobj_resolve_map(t, cap, azos_abi::invoke::MEMOBJ_ACQUIRE)
    }) {
        Some(Ok(g)) => g,
        Some(Err(e)) => return Err(memobj_errno(owner_tid, e)),
        None => return Err(errno(Errno::EINVAL)),
    };
    // The kernel writes into the buffer: the object must be writable and the
    // capability must say so (an attenuated READ capability maps read-only).
    if !grant.writable {
        return Err(shm_refusal(owner_tid, CapError::MissingPerms));
    }
    let d = grant.desc;
    if !matches!(d.kind, MemKind::Anon | MemKind::Contig) || d.attrs & ATTR_NO_KERNEL_MAP != 0 || end > d.page_count * page {
        return Err(IO_ERR_INVALID_PARAM);
    }
    match memobj::memobj_mapping_of_ref(owner_tid, grant.r) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(IO_ERR_INVALID_PARAM),
        Err(e) => return Err(memobj_errno(owner_tid, e)),
    }
    let mut frames = [0usize; MAX_MEMOBJ_PAGES];
    if let Err(e) = memobj::memobj_frames_pin(grant.r, &mut frames) {
        return Err(memobj_errno(owner_tid, e));
    }
    let (first, last) = (offset as usize / page, (end - 1) / page);
    // Read after the pin, so a share taken since the capability check is seen.
    let cow = azos_ipc::memobj::memobj_describe_ref(grant.r).map_or(u64::MAX, |d| d.cow_shared);
    let shared = (first..=last).any(|k| cow & (1u64 << k) != 0);
    let contiguous = (first..=last).all(|k| frames[k] == frames[first] + (k - first) * page);
    if shared || !contiguous {
        memobj::memobj_frames_unpin(grant.r);
        return Err(if shared { errno(Errno::EBUSY) } else { IO_ERR_INVALID_PARAM });
    }
    Ok(PinnedBuf { r: grant.r, kva: frames[first] + offset as usize % page })
}

fn buf_unpin(r: u32) {
    azos_ipc::memobj::memobj_frames_unpin(r);
}

/// May the kernel reach the pin on `r` for `owner_tid` now: the owner still
/// maps the object (released, or MOVEd away, the frames are somebody else's and
/// a use would leak them or overwrite them), the object is not purged, and for
/// a sink it is still read-write with no frame a clone shares.
fn buf_usable(owner_tid: u32, r: u32, sink: bool) -> bool {
    use azos_ipc::memobj::{self, MemPerms, PurgeState};
    if !matches!(memobj::memobj_mapping_of_ref(owner_tid, r), Ok(Some(_))) {
        return false;
    }
    memobj::memobj_describe_ref(r).is_ok_and(|d| {
        d.purge != PurgeState::Purged && (!sink || (d.perms == MemPerms::ReadWrite && d.cow_shared == 0))
    })
}

// ── Queued block requests (Kconfig IORING_ASYNC) ──────────────────────────
//
// An `OP_BLOCK_READ` / `OP_BLOCK_WRITE` is put on the block request layer by
// the submit, which starts no device command and sleeps for nothing; the
// io_ring worker (`io_ring_worker_pass` -> [`block_service`]) starts the queue,
// sleeps until the oldest request is over and collects it, and the ring's
// parked entry is completed from the answer ([`block_poll`]).
//
// **The table owns the request.** What the request layer lends the device is a
// kernel bounce buffer, which this table keeps from the submit to the
// collection; the ring holds only a token. So a ring destroyed with a request
// in flight cannot hand the device a freed page, and the one task that
// collects tickets, the worker, is the only one that does (a ticket is
// collected once; two collectors would make the second read "not live").
// A vacated ring orphans its tokens ([`block_orphan`]) and the worker frees
// them: that path runs under the ring table's lock with interrupts off, where
// nothing may be freed or waited for.

use alloc::vec::Vec;
use azos_drv_block::blkdev::{self, RawTicket};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicU32, Ordering};

/// Requests the table holds at once: as many as the request layer can hold
/// (`NR_CPUS` queues of `BLK_QUEUE_DEPTH` slots) and no more than every ring
/// can park. Nothing with `IORING_ASYNC` off.
const PENDING_SLOTS: usize = if azos_limits::IORING_ASYNC {
    let layer = azos_limits::NR_CPUS * azos_limits::BLK_QUEUE_DEPTH as usize;
    let rings = azos_limits::MAX_IO_RINGS * azos_limits::IORING_MAX_PARKED;
    if layer < rings { layer } else { rings }
} else {
    0
};
// A token is `generation << 16 | slot`.
const _: () = assert!(PENDING_SLOTS <= u16::MAX as usize);

#[derive(Clone, Copy, PartialEq, Eq)]
enum PState {
    Free,
    /// On the request layer, not yet awaited by the worker.
    Queued,
    /// The worker sleeps for it.
    Waiting,
    /// Over; the ring has not asked yet.
    Done,
}

struct Pending {
    state: PState,
    /// The ring that parked it is gone: free it when it is over.
    orphan: bool,
    write: bool,
    /// Never 0, so a token is never 0.
    gen: u16,
    /// Arrival order (wrapping): the worker awaits the oldest.
    seq: u32,
    /// The absolute run, for the write observer.
    lba: u64,
    count: u32,
    /// `len` or a negative errno, once `Done`.
    result: i32,
    ticket: Option<RawTicket>,
    /// The request layer's buffer: a write's source, a read's destination.
    kbuf: Vec<u8>,
}

impl Pending {
    const FREE: Pending = Pending {
        state: PState::Free,
        orphan: false,
        write: false,
        gen: 0,
        seq: 0,
        lba: 0,
        count: 0,
        result: 0,
        ticket: None,
        kbuf: Vec::new(),
    };
}

// Held for a scan and a field store; never across an allocation, a wait or a
// device call (the buffers are moved out and dropped after the unlock). Taken
// with interrupts off because `block_orphan` runs under the ring table's lock.
static PENDING: SpinLock<[Pending; PENDING_SLOTS]> = SpinLock::new([const { Pending::FREE }; PENDING_SLOTS]);
/// Slots not `Free`: the worker's whole cost when no block entry is in flight.
static LIVE: AtomicU32 = AtomicU32::new(0);
static SEQ: AtomicU32 = AtomicU32::new(0);

const fn token_of(idx: usize, gen: u16) -> u32 {
    (gen as u32) << 16 | idx as u32
}

/// The Domain a request is made for: the ring owner's, or the kernel's where
/// the owner has none (a dead task, a kernel ring).
fn owner_key(owner_tid: u32) -> u32 {
    let key = azos_sched::idx_for_tid(owner_tid).map_or(azos_sched::domain::NONE, azos_sched::task_domain);
    if key == azos_sched::domain::NONE { azos_devif::block::OWNER_KERNEL } else { key }
}

/// `IoRingOps::block_start`: queue the run, start nothing.
fn block_start(owner_tid: u32, badge: u32, write: bool, sector: u64, buf: *const u8, len: usize) -> BlockStart {
    let max = match blkdev::raw_max_sectors() {
        Some(m) if PENDING_SLOTS != 0 => m,
        _ => return BlockStart::Unqueueable,
    };
    let (lba, count) = match crate::block_host::scope(badge, write, sector, len) {
        Ok(run) => run,
        Err(e) => return BlockStart::Refused(e),
    };
    if count > max {
        return BlockStart::Unqueueable;
    }
    if !write && blkdev::read_would_wait(lba, count) {
        // FAT32's write-back cache holds a write of this range that has not
        // reached the device: it must go out before the read starts, and that
        // waits for the device. Not in a submit: the entry goes to the worker,
        // whose `block_io` writes it back (`note_external_read`) and reads.
        return BlockStart::Dirty;
    }
    let Some(mut kbuf) = crate::block_host::bounce(len) else {
        return BlockStart::Refused(errno(Errno::ENOMEM));
    };
    if write {
        // SAFETY: `dispatch_block` bounded `[buf, buf + len)` inside the
        // ring's data buffer, which ring 3 maps RW: copied once, as payload.
        unsafe { core::ptr::copy_nonoverlapping(buf, kbuf.as_mut_ptr(), len) };
    }
    let owner = owner_key(owner_tid);
    let queued = {
        let mut t = PENDING.lock_irqsave();
        match t.iter().position(|p| p.state == PState::Free) {
            None => Err(kbuf),
            Some(i) => {
                // SAFETY: the buffer is `count * 512` bytes and moves into the
                // slot below, where it stays until the request is collected;
                // moving a `Vec` does not move its heap block.
                match unsafe { blkdev::submit_raw(owner, write, lba, count, kbuf.as_mut_ptr()) } {
                    Err(()) => Err(kbuf),
                    Ok(ticket) => {
                        let p = &mut t[i];
                        p.gen = p.gen.wrapping_add(1).max(1);
                        *p = Pending {
                            state: PState::Queued,
                            orphan: false,
                            write,
                            gen: p.gen,
                            seq: SEQ.fetch_add(1, Ordering::Relaxed),
                            lba,
                            count,
                            result: 0,
                            ticket: Some(ticket),
                            kbuf,
                        };
                        LIVE.fetch_add(1, Ordering::AcqRel);
                        Ok(token_of(i, p.gen))
                    }
                }
            }
        }
    };
    match queued {
        Ok(token) => BlockStart::Queued(token),
        // Nothing took the buffer: freed here, outside the lock.
        Err(_unused) => BlockStart::Unqueueable,
    }
}

/// `IoRingOps::block_poll`: the answer of a request that is over; its slot is
/// freed and a read's bytes are in `out`.
fn block_poll(token: u32, out: *mut u8, len: usize) -> Option<i32> {
    let (idx, gen) = ((token & 0xFFFF) as usize, (token >> 16) as u16);
    let (result, write, kbuf) = {
        let mut t = PENDING.lock_irqsave();
        let Some(p) = t.get_mut(idx).filter(|p| p.gen == gen && p.state != PState::Free) else {
            // Not a live request: nothing will ever complete it. The entry
            // fails instead of waiting for good.
            return Some(errno(Errno::EIO));
        };
        match p.state {
            PState::Done => {}
            _ => return None,
        }
        let r = (p.result, p.write, core::mem::take(&mut p.kbuf));
        p.state = PState::Free;
        p.ticket = None;
        LIVE.fetch_sub(1, Ordering::AcqRel);
        r
    };
    if result > 0 && !write {
        let n = kbuf.len().min(len);
        // SAFETY: `out` is the entry's window of the ring page, bounded when
        // the entry parked, and the pass that asks holds the ring's claim.
        unsafe { core::ptr::copy_nonoverlapping(kbuf.as_ptr(), out, n) };
    }
    Some(result)
}

/// `IoRingOps::block_orphan`: the ring that parked `token` is gone. Flags the
/// slot; the worker frees it.
fn block_orphan(token: u32) {
    let (idx, gen) = ((token & 0xFFFF) as usize, (token >> 16) as u16);
    let mut t = PENDING.lock_irqsave();
    if let Some(p) = t.get_mut(idx).filter(|p| p.gen == gen && p.state != PState::Free) {
        p.orphan = true;
    }
}

/// `IoRingOps::block_service`, run by the worker: free what orphaned requests
/// held, then sleep until the oldest queued request is over and record its
/// outcome. Answers whether any request remains.
fn block_service() -> bool {
    if PENDING_SLOTS == 0 || LIVE.load(Ordering::Acquire) == 0 {
        return false;
    }
    // Orphans that are over: freed here, one buffer per unlock.
    loop {
        let garbage = {
            let mut t = PENDING.lock_irqsave();
            t.iter_mut().find(|p| p.state == PState::Done && p.orphan).map(|p| {
                p.state = PState::Free;
                p.orphan = false;
                p.ticket = None;
                LIVE.fetch_sub(1, Ordering::AcqRel);
                core::mem::take(&mut p.kbuf)
            })
        };
        if garbage.is_none() {
            break;
        }
    }
    // The oldest request nobody awaits yet.
    let next = {
        let mut t = PENDING.lock_irqsave();
        let mut oldest: Option<usize> = None;
        for (i, p) in t.iter().enumerate() {
            if p.state == PState::Queued
                && oldest.map_or(true, |o| (p.seq.wrapping_sub(t[o].seq) as i32) < 0)
            {
                oldest = Some(i);
            }
        }
        oldest.and_then(|i| {
            let p = &mut t[i];
            p.state = PState::Waiting;
            p.ticket.map(|ticket| (i, p.gen, ticket, p.write, p.lba, p.count))
        })
    };
    let Some((idx, gen, ticket, write, lba, count)) = next else {
        return PENDING.lock_irqsave().iter().any(|p| matches!(p.state, PState::Queued | PState::Waiting));
    };
    // Starts every queued request, then sleeps for this one.
    let r = blkdev::wait_raw(ticket);
    if write {
        // After the device answered, whatever it answered: the FAT32 block
        // cache may hold these sectors.
        blkdev::note_external_write(lba, count);
    }
    let (garbage, more) = {
        let mut t = PENDING.lock_irqsave();
        let p = &mut t[idx];
        let mut garbage = Vec::new();
        if p.gen == gen {
            if p.orphan {
                p.state = PState::Free;
                p.orphan = false;
                p.ticket = None;
                LIVE.fetch_sub(1, Ordering::AcqRel);
                garbage = core::mem::take(&mut p.kbuf);
            } else {
                p.result = if r.is_ok() { (count as usize * azos_devif::block::SECTOR_BYTES) as i32 } else { errno(Errno::EIO) };
                p.state = PState::Done;
            }
        }
        (garbage, t.iter().any(|p| matches!(p.state, PState::Queued | PState::Waiting)))
    };
    drop(garbage);
    more
}

#[cfg(test)]
mod size_tests {
    use super::*;

    /// The bytes per queued request that Kconfig `IORING_ASYNC` quotes. The
    /// table is not all zero (an empty `Vec` points at its alignment), so it
    /// is `.data`, not `.bss`.
    #[test]
    fn a_pending_slot_is_the_size_the_kconfig_help_quotes() {
        if usize::BITS == 64 {
            assert_eq!(core::mem::size_of::<Pending>(), 64, "update the Kconfig help");
        }
    }
}
