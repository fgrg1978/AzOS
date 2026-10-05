// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Unified kernel error type.
/// Converted to negative errno at the syscall boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    /// Out of memory (physical pages or heap)
    OutOfMemory,
    /// Invalid argument
    InvalidArg,
    /// Address not page-aligned
    NotAligned,
    /// Page already mapped
    AlreadyMapped,
    /// Page not mapped
    NotMapped,
    /// Resource not found
    NotFound,
    /// Double free detected
    DoubleFree,
    /// Capacity exceeded (e.g., PT metadata array full)
    CapacityFull,
    /// Permission denied
    PermissionDenied,
    /// Generic I/O error
    IoError,
    /// An architecture-level PTE encode call rejected inputs the kernel
    /// itself constructed (e.g. `ArchApi::pte_make_leaf` on a COW break,
    /// `mm::cow::handle_cow_fault`) — never a consequence of anything the
    /// faulting task did. Kept distinct from `InvalidArg` (U09-11): a
    /// caller that logs "the program did something wrong" for `InvalidArg`
    /// must not say that here, the same way `kernel/src/trap/exception.rs`'s COW-fault arm
    /// already carves `OutOfMemory` out for the same reason. Added instead
    /// of reusing `IoError` because this is not I/O and a reader searching
    /// for "why did the kernel say EncodeFailed" should find exactly the
    /// encode call, not a grep full of unrelated I/O failures.
    EncodeFailed,
}

/// Kernel-wide Result type alias.
pub type KResult<T> = Result<T, KernelError>;
