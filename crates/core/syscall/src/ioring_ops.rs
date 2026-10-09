// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's `io_ring` op table (RFC-0041 §E).
//!
//! Each entry calls what the matching typed syscall calls once that call has
//! resolved its capability: the sensor read is `handlers::sensor_read_into`,
//! a wheel is `motor_set_reporting` / `motor_stop_reporting`, a PWM duty or
//! GPIO pin goes through the same motor-binding guard and driver call. There
//! is no second implementation of any operation. What the typed call's
//! resolution decides is decided per entry by `io_ring::dispatch_sqe` instead:
//! the submitter's seccomp verdict (`syscall_allowed` below), the capability
//! of the ring's owner, and containment for a write (`write_contained`).
//!
//! The kernel registers the table once at boot, before any task runs:
//! `azos_ipc::io_ring::io_ring_register_ops(&KERNEL_IORING_OPS)`.
//!
//! Every entry receives a window of the ring's data buffer that
//! `dispatch_sqe` has bounded, on a page its in-flight claim keeps alive, and
//! runs with no lock of the ring table held.

#[cfg(not(feature = "domain-robot"))]
use crate::no_robot::{robot as azos_robot};
use azos_abi::error::Errno;
use azos_ipc::io_ring::{IoRingOps, OpResult, IO_ERR_INVALID_OP};
use azos_robot::{motor_set_reporting, motor_stop_reporting, MotorDir, MOTOR_REFUSED_HALTED};

/// The table `io_ring_register_ops` installs.
pub static KERNEL_IORING_OPS: IoRingOps = KERNEL_IORING_OPS_TABLE;

/// [`KERNEL_IORING_OPS`] as a constant, for a table that replaces a few
/// entries with struct-update syntax (the K1 ktest's file stand-in).
pub const KERNEL_IORING_OPS_TABLE: IoRingOps = IoRingOps {
    syscall_allowed,
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
    net_owner,
    note_denial,
    file_io,
    chan_send,
    chan_recv,
    deadline_reached,
    // The seam to the notify primitive: its WAIT syscall is what an
    // `OP_NOTIFY_WAIT` entry is seccomp-checked against. This was behind the
    // `ioring-notify-wait` feature only while SYS_NOTIFY_WAIT did not exist yet
    // (wave 6 built the ring and the primitive in parallel); off, the opcode
    // answered `-ENOSYS` on a kernel that had the syscall.
    notify_wait_nr: Some(azos_abi::syscall_nr::SYS_NOTIFY_WAIT),
    notify_word,
    file_fsync,
    fsync_done,
};

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
///  * inline, in the owner's own `SYS_IORING_SUBMIT_TYPED`, the owner is the
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

/// RFC-0036 containment, the test `CapTable::get` applies to a WRITE.
fn write_contained() -> bool {
    azos_ipc::cap::degraded_active()
}

/// `SYS_SENSOR_READ_TYPED`'s read, into the ring's buffer. The answer is the
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
    Ok(match crate::handlers::gpio_rc_to_result(rc) {
        Ok(()) => 0,
        Err(e) => crate::handlers::errno_for_gpio_err(e) as i32,
    })
}

/// `SYS_GPIO_READ_TYPED` below its capability: 0 or 1, `-EIO` for a driver
/// fault.
fn read_gpio(pin: u32) -> OpResult {
    let v = azos_drv_gpio::gpio::gpio_read(pin);
    if v < 0 {
        Ok(crate::handlers::errno_for_gpio_err(azos_ipc::gpio_cap::GpioCapError::DriverFault) as i32)
    } else {
        Ok(v)
    }
}

/// `SYS_I2C_READ_TYPED` below its capability: the same length bound, the
/// driver read into the ring's buffer, `-EIO` for a driver fault.
fn i2c_read(bus: u32, addr: u32, reg: u32, buf: *mut u8, len: usize) -> OpResult {
    if len == 0 || len > azos_abi::syscall_nr::I2C_TYPED_MAX_BYTES {
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
    if len == 0 || len > azos_abi::syscall_nr::I2C_TYPED_MAX_BYTES {
        return Err(errno(Errno::EINVAL));
    }
    // `data[0]` is the register and the driver may read it more than once;
    // ring 3 can rewrite the window during the pass (see `read_sensor`), so
    // the payload is copied to the stack ONCE and the driver sees only the
    // copy (OVSwrap review F4): one register, one value, whatever ring 3 does.
    let mut bounce = [0u8; azos_abi::syscall_nr::I2C_TYPED_MAX_BYTES];
    // SAFETY: bounded by `dispatch_sqe`, as in `read_sensor`; `len` is at most
    // `I2C_TYPED_MAX_BYTES` (checked above). A raw copy, never a slice over
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

/// One wheel, as `SYS_MOTOR_SPEED_TYPED` commands it: 0 coasts, anything else
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
    // `sys_motor_speed_typed` for why it is not read back afterwards.
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

/// Not executed through a ring: sockets are named by `Cap<Socket>` since
/// 567-570, which an SQE's descriptor number does not carry. `-ENOSYS` for the
/// socket's owner; `dispatch_sqe` refuses anyone else first.
fn net_send(_fd: u32, _data: *const u8, _len: usize) -> OpResult {
    Err(IO_ERR_INVALID_OP)
}

/// See [`net_send`].
fn net_recv(_fd: u32, _buf: *mut u8, _len: usize) -> OpResult {
    Err(IO_ERR_INVALID_OP)
}

/// The socket's owner stamp, as `socket_access_ok` reads it.
fn net_owner(fd: u32) -> Option<u32> {
    i32::try_from(fd).ok().and_then(azos_net::socket_owner)
}

/// The typed calls' errno for a capability refusal (`errno_for_file_err`).
fn cap_errno(e: azos_ipc::cap::CapError) -> i32 {
    use azos_ipc::cap::CapError;
    errno(match e {
        CapError::Stale => Errno::ECAPSTALE,
        CapError::WrongKind => Errno::ECAPKIND,
        CapError::MissingPerms => Errno::ECAPPERMS,
        CapError::Contained => Errno::EAGAIN,
        CapError::NoSpace => Errno::EMFILE,
    })
}

/// A capability refusal of the ring's owner: recorded as the typed call
/// records it, charged to the owner's bound, and answered with its errno.
fn refuse(owner_tid: u32, kind: azos_abi::cap::CapKind, e: azos_ipc::cap::CapError) -> OpResult {
    crate::handlers::note_typed_denial_for(owner_tid, kind, e);
    Err(cap_errno(e))
}

/// A device entry the ring refused for want of the owner's capability. The
/// ring asks "does the owner hold this kind for this resource", so the reason
/// is the one a typed call gives a handle without the permission.
fn note_denial(owner_tid: u32, kind: azos_abi::cap::CapKind) {
    crate::handlers::note_typed_denial_for(owner_tid, kind, azos_ipc::cap::CapError::MissingPerms);
}

/// `SYS_FILE_READ_TYPED` / `SYS_FILE_WRITE_TYPED` on a ring: the handle is
/// resolved in the OWNER's table with `CapTable::get` — `READ`, or `WRITE`
/// with containment — as `file_fd_for` resolves it, then the descriptor is
/// read or written through the same `FileOps` seam `sys_read`/`sys_write`
/// reach. The window is the ring's buffer, so there is no user copy.
fn file_io(owner_tid: u32, cap_raw: u32, write: bool, buf: *mut u8, len: usize) -> OpResult {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms};
    use azos_ipc::cap::{targets::File, Cap};
    let need = if write { CapPerms::WRITE } else { CapPerms::READ };
    let cap: Cap<File> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    let fd = match azos_ipc::cap_store::with_table(owner_tid, |t| t.get(cap, need)) {
        // A directory-tree `Cap<File>` names no descriptor (wave 10).
        Some(Ok(fd)) if azos_ipc::file_cap::is_tree_resource(fd) => {
            return refuse(owner_tid, CapKind::File, azos_ipc::cap::CapError::WrongKind)
        }
        Some(Ok(fd)) => fd as i32,
        Some(Err(e)) => return refuse(owner_tid, CapKind::File, e),
        None => return Err(errno(Errno::EINVAL)),
    };
    let Some(ops) = crate::file_ops::file_ops() else { return Ok(-1) };
    // `read_as`/`write_as`, not `read`/`write`: the descriptor must be the
    // OWNER's. `read`/`write` ask about the running task, and from the SQ
    // poller that is a kernel task every descriptor admits, so a gifted or
    // stale `Cap<File>` (a bare number, reused after its opener closed it)
    // reached whichever task's file now held the number (OVSwrap review F1).
    //
    // SAFETY: `dispatch_sqe` bounded `[buf, buf + len)` inside the ring's data
    // buffer. Ring 3 maps that page RW and may write it during the pass; the
    // filesystem copies each byte once, as payload.
    let n = if write {
        ops.write_as(owner_tid, fd, unsafe { core::slice::from_raw_parts(buf, len) })
    } else {
        ops.read_as(owner_tid, fd, unsafe { core::slice::from_raw_parts_mut(buf, len) })
    };
    Ok(n.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
}

/// `OP_FSYNC` (K1): the handle resolved in the OWNER's table as
/// `SYS_FSYNC_TYPED` resolves it (any permission; a directory-tree handle is
/// the wrong kind), then a flush is ASKED for the owner's descriptor. The
/// submitter never waits on the device: the flusher (`fs-wb`) does the I/O
/// and `io_ring_flush_posted` completes the entry.
fn file_fsync(owner_tid: u32, cap_raw: u32) -> azos_ipc::io_ring::OpResult64 {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms};
    use azos_ipc::cap::{targets::File, Cap};
    let cap: Cap<File> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    let fd = match azos_ipc::cap_store::with_table(owner_tid, |t| t.get(cap, CapPerms::NONE)) {
        Some(Ok(fd)) if azos_ipc::file_cap::is_tree_resource(fd) => {
            return refuse(owner_tid, CapKind::File, azos_ipc::cap::CapError::WrongKind).map(|_| 0)
        }
        Some(Ok(fd)) => fd as i32,
        Some(Err(e)) => return refuse(owner_tid, CapKind::File, e).map(|_| 0),
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

/// A channel call's answer: a capability refusal is refused and recorded, the
/// channel's own state (closed, full, empty) is the operation's answer, with
/// the typed call's codes.
fn chan_answer(owner_tid: u32, e: azos_ipc::channel::ChannelCapError) -> OpResult {
    use azos_ipc::channel::ChannelCapError;
    match e {
        ChannelCapError::Cap(c) => refuse(owner_tid, azos_abi::cap::CapKind::Channel, c),
        ChannelCapError::Closed => Ok(errno(Errno::EBADF)),
        ChannelCapError::Full | ChannelCapError::Empty => Ok(errno(Errno::EAGAIN)),
        ChannelCapError::BadArg => Err(errno(Errno::EINVAL)),
    }
}

/// `SYS_CHAN_WRITE_TYPED` on a ring, with the owner's table: 0 once queued.
fn chan_send(owner_tid: u32, cap_raw: u32, data: *const u8, len: usize) -> OpResult {
    use azos_abi::cap::CapHandle;
    use azos_ipc::cap::{targets::Channel, Cap};
    let cap: Cap<Channel> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    // SAFETY: bounded by `dispatch_sqe`, as in `read_sensor`.
    let src = unsafe { core::slice::from_raw_parts(data, len) };
    match azos_ipc::cap_store::with_table(owner_tid, |t| {
        azos_ipc::channel::channel_send_cap(t, cap, src)
    }) {
        Some(Ok(())) => Ok(0),
        Some(Err(e)) => chan_answer(owner_tid, e),
        None => Err(errno(Errno::EINVAL)),
    }
}

/// `SYS_CHAN_READ_TYPED` on a ring: the byte count of the message dequeued
/// into the window.
fn chan_recv(owner_tid: u32, cap_raw: u32, buf: *mut u8, len: usize) -> OpResult {
    use azos_abi::cap::CapHandle;
    use azos_ipc::cap::{targets::Channel, Cap};
    let cap: Cap<Channel> = Cap::from_raw(CapHandle::from_raw(cap_raw));
    // SAFETY: bounded by `dispatch_sqe`, as in `read_sensor`.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    match azos_ipc::cap_store::with_table(owner_tid, |t| {
        azos_ipc::channel::channel_recv_cap(t, cap, dst)
    }) {
        Some(Ok(n)) => Ok(n as i32),
        Some(Err(e)) => chan_answer(owner_tid, e),
        None => Err(errno(Errno::EINVAL)),
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
/// `shm_with_word_ref` loads the word with the region table locked, and a
/// region's frames go back to the PMM only under that lock. This used to take
/// the page address under the lock and load after releasing it, so a
/// last-holder release on another hart in between left the load on a freed —
/// possibly reissued — frame, and the completion (`word == expected`) became an
/// equality oracle on someone else's memory.
fn notify_word(owner_tid: u32, shm_cap: u32, offset: u32) -> Result<u32, i32> {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms};
    use azos_ipc::cap::{targets::Shm, Cap};
    if offset % 4 != 0 {
        return Err(errno(Errno::EINVAL));
    }
    let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(shm_cap));
    let r = match azos_ipc::cap_store::with_table(owner_tid, |t| t.get(cap, CapPerms::READ)) {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            crate::handlers::note_typed_denial_for(owner_tid, CapKind::Shm, e);
            return Err(cap_errno(e));
        }
        None => return Err(errno(Errno::EINVAL)),
    };
    match azos_ipc::shm::shm_with_word_ref(r, offset as usize, |w| {
        w.load(core::sync::atomic::Ordering::Acquire)
    }) {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err(errno(Errno::EINVAL)),
        Err(_) => Err(errno(Errno::ECAPSTALE)),
    }
}
