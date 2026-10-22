// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Where the runtime is linked: the runtime window, `azos_abi::foreign::RUNTIME_BASE`
//! (the page after the vDSO's two, inside the vDSO's 2 MiB slot), where
//! `azos_sched::foreign::attach_runtime` maps each segment with exactly the
//! permissions of its PT_LOAD. Its entry is `_start` itself: the kernel starts
//! a Linux process there with the Linux stack, which a trampoline must not touch.
//!
//! On riscv64 the runtime is built for the native target spec
//! (sdk/targets/riscv64imac-unknown-azos.json, no FP in RV64IMAC), which
//! carries the rest of the layout. On aarch64 and x86_64 it is built for
//! rustc's own soft-float targets (the runtime runs between two of the Linux
//! program's instructions and shares its FP/vector registers; the native
//! targets are hard-float, and rustc refuses to drop the FP registers from a
//! hard-float ABI), so the layout flags the native spec carries are given here.

fn main() {
    println!("cargo:rustc-link-arg-bins=--image-base={:#x}", azos_abi::foreign::RUNTIME_BASE);
    println!("cargo:rustc-link-arg-bins=-e_start");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        for arg in ["-zmax-page-size=4096", "--no-eh-frame-hdr", "-znorelro"] {
            println!("cargo:rustc-link-arg-bins={arg}");
        }
    }
}
