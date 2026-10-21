// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

//! Linux errno values used by the emulation layer.
//!
//! The numbers are part of the Linux kernel ABI that drivers compare
//! against (`if (ret == -EPROBE_DEFER)`), so they must match Linux exactly.
//! Kernel functions return them negated; these constants are positive.

/// Operation not permitted.
pub const EPERM: i32 = 1;
/// No such file or directory (also "no such entry" in lookups).
pub const ENOENT: i32 = 2;
/// I/O error.
pub const EIO: i32 = 5;
/// Try again (also `EWOULDBLOCK`).
pub const EAGAIN: i32 = 11;
/// Out of memory.
pub const ENOMEM: i32 = 12;
/// Device or resource busy.
pub const EBUSY: i32 = 16;
/// No such device (probe: "not mine", try the next driver).
pub const ENODEV: i32 = 19;
/// Invalid argument.
pub const EINVAL: i32 = 22;
/// Connection timed out (used by timed waits).
pub const ETIMEDOUT: i32 = 110;
/// Driver requests probe retry. Kernel-internal, never returned to user space.
pub const EPROBE_DEFER: i32 = 517;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_the_linux_abi() {
        assert_eq!(
            [EPERM, ENOENT, EIO, EAGAIN, ENOMEM, EBUSY, ENODEV, EINVAL, ETIMEDOUT, EPROBE_DEFER],
            [1, 2, 5, 11, 12, 16, 19, 22, 110, 517]
        );
    }
}
