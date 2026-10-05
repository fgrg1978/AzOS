// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `errno_for_*_err` functions in
// `crates/core/syscall/src/handlers.rs` (target 1). Each is a pure match from a
// capability/driver error enum to a AZOS errno via `Errno::to_syscall_ret`.
// Zero host coverage before this crate; a wrong arm silently hands ring 3
// the wrong errno (e.g. "retry me" instead of "this cap is dead"), which a
// caller cannot distinguish from a correct answer without reading kernel
// source.
//
// `errno_for_ioring_err` is covered here too, since 2026-09-03: the real
// `crates/core/ipc/src/io_ring.rs` is now `#[path]`-pulled into the ipc shim.
// The previously-reported blocker (its embedded test module wanting
// `azos_mm::shim_*` / `azos_sched::shim_set_current`) does not
// apply -- that module is `#[cfg(test)]`, and Cargo sets `--cfg test` only
// for the crate under test, never for its dependencies. `syscall_test_ipc`
// is a dependency here, so the module is not compiled at all.

use azos_abi::error::Errno;
use azos_ipc::cap::CapError;
use crate::ipc_handlers::*;

/// Every `errno_for_*_err` function maps `CapError::{Stale, WrongKind,
/// MissingPerms, Contained}` through its own `CapError` variant identically
/// — this is the shared prefix every one of the eight matches starts with.
/// Table-driven so the property reads as one statement instead of eight
/// copy-pasted match arms.
#[test]
fn every_cap_error_prefix_maps_to_the_same_four_errnos() {
    assert_eq!(
        errno_for_channel_err(azos_ipc::channel::ChannelCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_channel_err(azos_ipc::channel::ChannelCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_channel_err(azos_ipc::channel::ChannelCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_channel_err(azos_ipc::channel::ChannelCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );

    assert_eq!(
        errno_for_port_err(azos_ipc::port::PortCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_port_err(azos_ipc::port::PortCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_port_err(azos_ipc::port::PortCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_port_err(azos_ipc::port::PortCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );

    assert_eq!(
        errno_for_shm_err(azos_ipc::shm::ShmCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_shm_err(azos_ipc::shm::ShmCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_shm_err(azos_ipc::shm::ShmCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_shm_err(azos_ipc::shm::ShmCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );

    assert_eq!(
        errno_for_gpio_err(azos_ipc::gpio_cap::GpioCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_gpio_err(azos_ipc::gpio_cap::GpioCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_gpio_err(azos_ipc::gpio_cap::GpioCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_gpio_err(azos_ipc::gpio_cap::GpioCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );

    assert_eq!(
        errno_for_i2c_err(azos_ipc::i2c_cap::I2cCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_i2c_err(azos_ipc::i2c_cap::I2cCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_i2c_err(azos_ipc::i2c_cap::I2cCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_i2c_err(azos_ipc::i2c_cap::I2cCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );

    assert_eq!(
        errno_for_pwm_err(azos_ipc::pwm_cap::PwmCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_pwm_err(azos_ipc::pwm_cap::PwmCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_pwm_err(azos_ipc::pwm_cap::PwmCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_pwm_err(azos_ipc::pwm_cap::PwmCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );

    assert_eq!(
        errno_for_motor_err(azos_ipc::motor_cap::MotorCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_motor_err(azos_ipc::motor_cap::MotorCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_motor_err(azos_ipc::motor_cap::MotorCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_motor_err(azos_ipc::motor_cap::MotorCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );
}

/// `MotorCapError` has exactly one variant (`Cap`) — asserted so the "shared
/// prefix" test above is not silently incomplete for this type the way it
/// would be for the other seven, which have kind-specific arms tested below.
#[test]
fn motor_cap_error_has_no_kind_specific_variant() {
    // If this ever grows a second variant, `every_cap_error_prefix_maps_to_
    // the_same_four_errnos` no longer exhaustively covers `errno_for_motor_
    // err`, and a new arm belongs in a dedicated test the way the other
    // seven have one below.
    fn assert_only_cap_variant(e: azos_ipc::motor_cap::MotorCapError) -> i64 {
        match e {
            azos_ipc::motor_cap::MotorCapError::Cap(inner) => errno_for_motor_err(
                azos_ipc::motor_cap::MotorCapError::Cap(inner),
            ),
        }
    }
    assert_eq!(
        assert_only_cap_variant(azos_ipc::motor_cap::MotorCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
}

/// `ChannelCapError`'s kind-specific arms: `Closed`/`Full`/`Empty`/`BadArg`.
#[test]
fn channel_error_kind_specific_arms_map_correctly() {
    use azos_ipc::channel::ChannelCapError;
    assert_eq!(errno_for_channel_err(ChannelCapError::Closed), Errno::EBADF.to_syscall_ret());
    assert_eq!(errno_for_channel_err(ChannelCapError::Full), Errno::EAGAIN.to_syscall_ret());
    assert_eq!(errno_for_channel_err(ChannelCapError::Empty), Errno::EAGAIN.to_syscall_ret());
    assert_eq!(errno_for_channel_err(ChannelCapError::BadArg), Errno::EINVAL.to_syscall_ret());
}

/// `PortCapError`'s kind-specific arms: `Full`/`Empty`/`Closed`.
///
/// **WHY this one matters more than it looks.** `Full` maps to `EMFILE`
/// here (port table exhausted -- "too many open"), but `ChannelCapError::
/// Full` above maps to `EAGAIN` (channel ring buffer full -- "try again").
/// Same variant name, two different subsystems, two different correct
/// answers. A refactor that unified these error enums or copy-pasted one
/// match into the other would silently swap the errno ring 3 sees for
/// "port table full" to "retry", which looks like a transient condition
/// instead of the permanent one it is.
#[test]
fn port_error_kind_specific_arms_map_correctly() {
    use azos_ipc::port::PortCapError;
    assert_eq!(errno_for_port_err(PortCapError::Full), Errno::EMFILE.to_syscall_ret());
    assert_eq!(errno_for_port_err(PortCapError::Empty), Errno::EAGAIN.to_syscall_ret());
    assert_eq!(errno_for_port_err(PortCapError::Closed), Errno::EBADF.to_syscall_ret());
}

/// `ShmCapError`'s kind-specific arms: `NoMem`/`BadArg`/`Closed`/`Full`.
#[test]
fn shm_error_kind_specific_arms_map_correctly() {
    use azos_ipc::shm::ShmCapError;
    assert_eq!(errno_for_shm_err(ShmCapError::NoMem), Errno::ENOMEM.to_syscall_ret());
    assert_eq!(errno_for_shm_err(ShmCapError::BadArg), Errno::EINVAL.to_syscall_ret());
    assert_eq!(errno_for_shm_err(ShmCapError::Closed), Errno::EBADF.to_syscall_ret());
    assert_eq!(errno_for_shm_err(ShmCapError::Full), Errno::EMFILE.to_syscall_ret());
}

/// `GpioCapError`'s kind-specific arms: `BadPin`/`BadDirValue`/`DriverFault`.
#[test]
fn gpio_error_kind_specific_arms_map_correctly() {
    use azos_ipc::gpio_cap::GpioCapError;
    assert_eq!(errno_for_gpio_err(GpioCapError::BadPin), Errno::EINVAL.to_syscall_ret());
    assert_eq!(errno_for_gpio_err(GpioCapError::BadDirValue), Errno::EINVAL.to_syscall_ret());
    assert_eq!(errno_for_gpio_err(GpioCapError::DriverFault), Errno::EIO.to_syscall_ret());
}

/// `I2cCapError`'s kind-specific arms: `BadLen`/`DriverFault`.
#[test]
fn i2c_error_kind_specific_arms_map_correctly() {
    use azos_ipc::i2c_cap::I2cCapError;
    assert_eq!(errno_for_i2c_err(I2cCapError::BadLen), Errno::EINVAL.to_syscall_ret());
    assert_eq!(errno_for_i2c_err(I2cCapError::DriverFault), Errno::EIO.to_syscall_ret());
}

/// `PwmCapError`'s kind-specific arms: `BadChannel`/`DriverFault`.
#[test]
fn pwm_error_kind_specific_arms_map_correctly() {
    use azos_ipc::pwm_cap::PwmCapError;
    assert_eq!(errno_for_pwm_err(PwmCapError::BadChannel), Errno::EINVAL.to_syscall_ret());
    assert_eq!(errno_for_pwm_err(PwmCapError::DriverFault), Errno::EIO.to_syscall_ret());
}

/// `errno_for_driver_err` (`azos_drv_api::DriverError`, the real
/// `azos_drv_api::DriverError` -- not a `Cap`-wrapping enum, no
/// shared prefix with the seven above). Every variant, including the
/// integer-carrying `Other(_)`.
#[test]
fn driver_error_every_variant_maps_correctly() {
    use azos_drv_api::DriverError;
    assert_eq!(errno_for_driver_err(DriverError::NotInitialized), Errno::ENODEV.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::BadOp), Errno::ENOSYS.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::BadInput), Errno::EINVAL.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::BadOutput), Errno::EINVAL.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::Busy), Errno::EAGAIN.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::IoFault), Errno::EIO.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::Unsupported), Errno::ENOSYS.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::NoMem), Errno::ENOMEM.to_syscall_ret());
    // Two different opaque codes must not accidentally compare unequal to
    // the mapping (i.e. the match arm must ignore the payload, not key on
    // it) -- both still land on EIO.
    assert_eq!(errno_for_driver_err(DriverError::Other(1)), Errno::EIO.to_syscall_ret());
    assert_eq!(errno_for_driver_err(DriverError::Other(-7)), Errno::EIO.to_syscall_ret());
}

/// `errno_for_ioring_err` (`azos_ipc::io_ring::IoRingCapError`) -- the
/// eighth `Cap`-wrapping enum, and the last syscall errno mapper to get a
/// test (it lives in `crates/core/syscall/src/ipc_handlers.rs`). Its four `Cap`
/// arms are the shared prefix; asserted here
/// rather than folded into `every_cap_error_prefix_maps_to_the_same_four_
/// errnos` because a mutation confined to *this* function's arms would not
/// change any of the other seven, so the assertion has to name this one.
#[test]
fn ioring_cap_error_prefix_maps_to_the_same_four_errnos() {
    use azos_ipc::io_ring::IoRingCapError;
    assert_eq!(
        errno_for_ioring_err(IoRingCapError::Cap(CapError::Stale)),
        Errno::ECAPSTALE.to_syscall_ret()
    );
    assert_eq!(
        errno_for_ioring_err(IoRingCapError::Cap(CapError::WrongKind)),
        Errno::ECAPKIND.to_syscall_ret()
    );
    assert_eq!(
        errno_for_ioring_err(IoRingCapError::Cap(CapError::MissingPerms)),
        Errno::ECAPPERMS.to_syscall_ret()
    );
    assert_eq!(
        errno_for_ioring_err(IoRingCapError::Cap(CapError::Contained)),
        Errno::EAGAIN.to_syscall_ret()
    );
}

/// `IoRingCapError`'s kind-specific arms: `NoMem`/`Closed`/`Full`/
/// `SubmitError(_)`.
///
/// **`Full` is the arm worth naming.** It means "the caller's cap-table has
/// no free slot -- the ring was rolled back" (`io_ring.rs`'s own doc), and
/// maps to `EMFILE`. `ChannelCapError::Full` -- same variant name, one
/// subsystem over -- maps to `EAGAIN`. `EAGAIN` would tell ring 3 to retry a
/// condition that will never clear on its own, which is the same
/// same-name/different-answer trap `port_error_kind_specific_arms_map_
/// correctly` documents.
#[test]
fn ioring_error_kind_specific_arms_map_correctly() {
    use azos_ipc::io_ring::IoRingCapError;
    assert_eq!(errno_for_ioring_err(IoRingCapError::NoMem), Errno::ENOMEM.to_syscall_ret());
    assert_eq!(errno_for_ioring_err(IoRingCapError::Closed), Errno::EBADF.to_syscall_ret());
    assert_eq!(errno_for_ioring_err(IoRingCapError::Full), Errno::EMFILE.to_syscall_ret());
    // The payload must be ignored, not keyed on: both land on EIO. The
    // per-op status is surfaced through the CQ, not through errno.
    assert_eq!(errno_for_ioring_err(IoRingCapError::SubmitError(0)), Errno::EIO.to_syscall_ret());
    assert_eq!(
        errno_for_ioring_err(IoRingCapError::SubmitError(i32::MIN)),
        Errno::EIO.to_syscall_ret()
    );
    // A submit that ran nothing because the CQ was full: retry after a drain.
    assert_eq!(errno_for_ioring_err(IoRingCapError::CqFull), Errno::EBUSY.to_syscall_ret());
}
