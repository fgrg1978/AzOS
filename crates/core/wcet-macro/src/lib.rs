// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0027: `#[wcet(N_us)]` proc-macro for per-function WCET budget annotations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use wcet_macro::wcet;
//!
//! #[wcet(50_us)]
//! pub fn motor_pid_step(motor: &mut Motor, dt: u32) -> i16 {
//!     // ... body unchanged ...
//! }
//! ```
//!
//! Supported suffixes: `_us` (microseconds, default), `_ns` (nanoseconds),
//! `_cycles` (CPU cycles, converted via 1 cycle ≈ 0.1 µs on QEMU virt).
//!
//! # Expansion
//!
//! The macro wraps the function body:
//!
//! ```rust,ignore
//! pub fn motor_pid_step(motor: &mut Motor, dt: u32) -> i16 {
//!     let __wcet_start = ::azos_drv_sys::wcet::wcet_begin();
//!     let __wcet_point = ::azos_drv_sys::wcet::POINT_MOTOR_PID_STEP;
//!     let __wcet_result = (|| -> i16 { /* original body */ })();
//!     ::azos_drv_sys::wcet::wcet_end(__wcet_point, __wcet_start);
//!     __wcet_result
//! }
//! ```
//!
//! The `(|| -> R { ... })()` closure preserves `?` early-return semantics
//! because the closure bubbles the result up; `wcet_end` always executes.
//!
//! # Side-channel markers (none emitted)
//!
//! The original RFC-0027 design proposed emitting a hidden `__WCET_DECL_*`
//! const to let the build script discover annotations. In practice, such
//! constants live in compiled IR, not in `.rs` source text; a build script
//! (host-only, runs before the crate compiles) cannot read compiled IR.
//! Therefore `crates/drivers/sys/build.rs` scans the source text directly for
//! `#[wcet(` patterns — no side-channel constant is needed or emitted.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, ItemFn, LitInt};
use syn::parse::{Parse, ParseStream};

// ── Attribute argument parser ─────────────────────────────────────────────────

/// Parsed argument of `#[wcet(N_us)]` / `#[wcet(N_ns)]` / `#[wcet(N_cycles)]`.
/// Stores the budget normalised to microseconds.
struct WcetArg {
    /// Budget in microseconds (converted from whatever unit was written).
    budget_us: u32,
}

/// Allowed suffixes for `#[wcet(...)]`.
const SUFFIX_US:     &str = "us";
const SUFFIX_NS:     &str = "ns";
const SUFFIX_CYCLES: &str = "cycles";

/// Cycles-to-µs ratio for QEMU virt (1 cycle ≈ 0.1 µs at 10 MHz TIMER_FREQ).
const QEMU_CYCLES_PER_US: u32 = 10;

impl Parse for WcetArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Accept integer literal with optional suffix token: `50_us`, `100`, `200_ns`.
        // In syn, a literal like `50_us` is parsed as a single integer literal whose
        // `suffix()` is "us".  A bare `50` has an empty suffix.
        let lit: LitInt = input.parse()?;
        let raw: u32 = lit.base10_parse()?;
        let suffix = lit.suffix().to_string();

        let budget_us = match suffix.as_str() {
            "" | SUFFIX_US => raw,
            SUFFIX_NS => {
                // Round up nanoseconds → microseconds (never under-declare).
                raw.saturating_add(999) / 1000
            },
            SUFFIX_CYCLES => {
                // Default: QEMU virt 10 MHz → 1 cycle = 0.1 µs → divide by 10.
                raw.saturating_add(QEMU_CYCLES_PER_US - 1) / QEMU_CYCLES_PER_US
            },
            other => {
                return Err(syn::Error::new(
                    lit.span(),
                    format!(
                        "#[wcet]: unknown unit suffix \"{other}\". \
                         Use `_us` (microseconds, default), `_ns`, or `_cycles`."
                    ),
                ));
            }
        };

        Ok(WcetArg { budget_us })
    }
}

// ── Main proc-macro entry point ───────────────────────────────────────────────

/// `#[wcet(N_us)]` — wrap a function with WCET begin/end instrumentation.
///
/// Emits a side-channel `__WCET_DECL_<name>` const so `crates/drivers/sys/build.rs`
/// can discover all annotated functions and assign stable point IDs.
#[proc_macro_attribute]
pub fn wcet(attr: TokenStream, item: TokenStream) -> TokenStream {
    let arg = parse_macro_input!(attr as WcetArg);
    let func = parse_macro_input!(item as ItemFn);

    let budget_us = arg.budget_us;

    // ── Function components ───────────────────────────────────────────────
    let vis      = &func.vis;
    let sig      = &func.sig;
    let attrs    = &func.attrs;
    let body     = &func.block;
    let fn_name  = &sig.ident;
    let ret_type = &sig.output;

    // ── UPPER_SNAKE identifier for the POINT_* const ─────────────────────
    // e.g.  `wrap`  →  `POINT_WRAP`
    let point_const_name = {
        let upper = fn_name.to_string().to_uppercase();
        syn::Ident::new(&format!("POINT_{upper}"), Span::call_site())
    };

    // ── Side-channel marker const name ───────────────────────────────────
    // e.g.  `wrap`  →  `__WCET_DECL_wrap`
    let decl_const_name = {
        let name_str = fn_name.to_string();
        syn::Ident::new(&format!("__WCET_DECL_{name_str}"), Span::call_site())
    };

    let fn_name_str = fn_name.to_string();

    // ── Return type for the closure ──────────────────────────────────────
    // If the function has `-> R`, the closure needs `-> R`.
    // If no return annotation, the closure returns `()` which matches.
    let closure_ret = match ret_type {
        syn::ReturnType::Default => quote! { () },
        syn::ReturnType::Type(_, ty) => quote! { #ty },
    };

    // ── Emit expanded function + side-channel marker ──────────────────────
    //
    // Instrumentation is gated `cfg(target_os = "none")` so the macro can
    // safely annotate functions that also get host-compiled (e.g.
    // `brain_protocol::parse_packet`, pulled into `regression-tests` via
    // `#[path = ...]` for property-based testing).  Host targets are macos
    // / linux; kernel targets are baremetal (`target_os = "none"`), so the
    // gate cleanly partitions the two cases.  On host the closure body
    // runs unmeasured — the absolute path `::azos_drv_sys::wcet::*`
    // would otherwise fail to resolve in the host-compiled crate.
    let expanded = quote! {
        // Preserve all original attributes (e.g. #[inline(always)], #[cfg(...)]).
        #(#attrs)*
        #vis #sig {
            // Calls the feature-gated per-function wrappers (RFC-0027). With
            // `azos_drv_sys/wcet` OFF (default) these are no-ops the
            // optimiser strips; the per-function WCET CI gate was rejected
            // (KILL2 — QEMU TCG rdcycle confound). Enable on real hardware.
            #[cfg(target_os = "none")]
            let __wcet_start: u64 = ::azos_drv_sys::wcet::wcet_begin_fn();
            #[cfg(target_os = "none")]
            let __wcet_point: u8 = ::azos_drv_sys::wcet::#point_const_name;
            let __wcet_result = (|| -> #closure_ret { #body })();
            #[cfg(target_os = "none")]
            ::azos_drv_sys::wcet::wcet_end_fn(__wcet_point, __wcet_start);
            __wcet_result
        }

        // Side-channel marker — discovered by crates/drivers/sys/build.rs
        // to enumerate annotated functions and assign stable point IDs.
        // Format: (fn_name_str, budget_us_u32).  Pure data — works on any
        // target, including host.
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        pub const #decl_const_name: (&str, u32) = (#fn_name_str, #budget_us);
    };

    TokenStream::from(expanded)
}

// ── Unit tests (host-side) ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_arg(s: &str) -> syn::Result<WcetArg> {
        syn::parse_str::<WcetArg>(s)
    }

    #[test]
    fn test_bare_number_defaults_to_us() {
        let arg = parse_arg("50").unwrap();
        assert_eq!(arg.budget_us, 50);
    }

    #[test]
    fn test_explicit_us_suffix() {
        let arg = parse_arg("100us").unwrap();
        assert_eq!(arg.budget_us, 100);
    }

    #[test]
    fn test_ns_rounds_up() {
        // 999 ns → 1 µs
        let arg = parse_arg("999ns").unwrap();
        assert_eq!(arg.budget_us, 1);
        // 1000 ns → 1 µs
        let arg = parse_arg("1000ns").unwrap();
        assert_eq!(arg.budget_us, 1);
        // 1001 ns → 2 µs
        let arg = parse_arg("1001ns").unwrap();
        assert_eq!(arg.budget_us, 2);
    }

    #[test]
    fn test_cycles_rounds_up() {
        // 10 cycles → 1 µs
        let arg = parse_arg("10cycles").unwrap();
        assert_eq!(arg.budget_us, 1);
        // 11 cycles → 2 µs
        let arg = parse_arg("11cycles").unwrap();
        assert_eq!(arg.budget_us, 2);
    }

    #[test]
    fn test_unknown_suffix_error() {
        assert!(parse_arg("50ms").is_err());
    }
}
