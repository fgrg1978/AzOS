// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `#[main]` and `#[test]` of `azos_libsys` (the SDK's proc-macros). Use them
//! through the crate, under whatever name it is imported (`use azos_libsys as
//! azos;` gives `#[azos::main]`); the expansions name `::azos_libsys`, the
//! crate's own name, so the dependency must be declared by it.
//!
//! The expansions are plain functions over `proc_macro2` tokens, so the unit
//! tests below check the exact output and the exact error of every refusal.
//!
//! ## `#[main]`
//!
//! The entry and, if asked, the panic handler of a `#![no_std] #![no_main]`
//! ring-3 program:
//!
//! ```ignore
//! #[azos::main(panic_exit = 70)]
//! fn main() -> i32 { /* ... */ 0 }
//! ```
//!
//! generates `_start(_a0, a1)`, which reads the startup block
//! (`azos_libsys::startup_init(a1)`), calls `main` and ends the process with its
//! value (`()` is 0; `-> !` never returns), and, with `panic_exit = N`, a
//! `#[panic_handler]` that ends the process with `N`. Without `panic_exit` the
//! program writes its own handler. A program on `std` does not use it: `std`
//! has its own entry (`fn main` is enough).
//!
//! ## `#[test]`
//!
//! A test of the user-code harness (`azos_libsys::utest`, the ring-3 form of
//! the kernel's `ktest!`): `fn name()` or `fn name() -> Result<(), &'static
//! str>`, registered in the `.azos_ktest` link section, run in name order by
//! `azos_libsys::utest::run`, which prints TAP. A program that links one needs
//! the section bracketed in its linker script (the SDK's scripts do).
#![forbid(unsafe_code)]

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    parse::Parser, punctuated::Punctuated, spanned::Spanned, Expr, ExprLit, ItemFn, Lit, MetaNameValue, ReturnType, Token,
    Type,
};

/// The entry (and panic handler) of a ring-3 program. See the crate docs.
#[proc_macro_attribute]
pub fn main(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    finish(expand_main(attr.into(), item.into()))
}

/// A test of the user-code harness. See the crate docs.
#[proc_macro_attribute]
pub fn test(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    finish(expand_test(attr.into(), item.into()))
}

fn finish(r: syn::Result<TokenStream>) -> proc_macro::TokenStream {
    match r {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// What a function returns, as far as the expansions care.
#[derive(Debug, PartialEq, Eq)]
enum Ret {
    Unit,
    I32,
    Never,
    TestResult,
    Other,
}

fn ret_of(f: &ItemFn) -> Ret {
    match &f.sig.output {
        ReturnType::Default => Ret::Unit,
        ReturnType::Type(_, t) => match &**t {
            Type::Never(_) => Ret::Never,
            Type::Tuple(t) if t.elems.is_empty() => Ret::Unit,
            Type::Path(p) if p.qself.is_none() && p.path.is_ident("i32") => Ret::I32,
            Type::Path(p) if p.qself.is_none() => {
                // `Result<(), &'static str>`, however the path is spelled.
                let last = p.path.segments.last().unwrap();
                if last.ident == "Result" { Ret::TestResult } else { Ret::Other }
            }
            _ => Ret::Other,
        },
    }
}

fn no_params_no_async(f: &ItemFn, what: &str) -> syn::Result<()> {
    if !f.sig.inputs.is_empty() {
        return Err(syn::Error::new(f.sig.inputs.span(), format!("azos {what}: the function takes no arguments")));
    }
    if f.sig.asyncness.is_some() || f.sig.unsafety.is_some() || !f.sig.generics.params.is_empty() {
        return Err(syn::Error::new(f.sig.span(), format!("azos {what}: the function is a plain `fn`")));
    }
    if f.sig.abi.is_some() {
        return Err(syn::Error::new(f.sig.span(), format!("azos {what}: the function has the Rust ABI")));
    }
    Ok(())
}

pub(crate) fn expand_main(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let list = Punctuated::<MetaNameValue, Token![,]>::parse_terminated
        .parse2(attr)
        .map_err(|e| syn::Error::new(e.span(), format!("azos main: expected `panic_exit = N`: {e}")))?;
    let mut panic_exit: Option<i32> = None;
    for nv in &list {
        if !nv.path.is_ident("panic_exit") {
            return Err(syn::Error::new_spanned(&nv.path, "azos main: the only argument is `panic_exit = N`"));
        }
        if panic_exit.is_some() {
            return Err(syn::Error::new_spanned(&nv.path, "azos main: `panic_exit` given twice"));
        }
        panic_exit = Some(match &nv.value {
            Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) => i.base10_parse::<i32>()?,
            other => return Err(syn::Error::new(other.span(), "azos main: `panic_exit` must be an integer literal")),
        });
    }
    let f: ItemFn = syn::parse2(item)?;
    no_params_no_async(&f, "main")?;
    let name = &f.sig.ident;
    let call = match ret_of(&f) {
        Ret::Unit => quote! { #name(); ::azos_libsys::exit(0) },
        Ret::I32 => quote! { ::azos_libsys::exit(#name()) },
        Ret::Never => quote! { #name() },
        _ => {
            return Err(syn::Error::new(
                f.sig.output.span(),
                "azos main: the function returns `()`, `i32` (the exit status) or `!`",
            ))
        }
    };
    let panic = panic_exit.map(|n| {
        quote! {
            #[panic_handler]
            fn __azos_panic(_info: &::core::panic::PanicInfo) -> ! {
                ::azos_libsys::exit(#n)
            }
        }
    });
    Ok(quote! {
        #f

        #[no_mangle]
        pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
            ::azos_libsys::startup_init(a1);
            #call
        }

        #panic
    })
}

pub(crate) fn expand_test(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    if !attr.is_empty() {
        return Err(syn::Error::new(Span::call_site(), "azos test: takes no arguments"));
    }
    let f: ItemFn = syn::parse2(item)?;
    no_params_no_async(&f, "test")?;
    let name = &f.sig.ident;
    let label = name.to_string();
    // A test that returns `()` passes unless it panics; the registry's
    // function type is `fn() -> Result<(), &'static str>`.
    let (wrapper, run) = match ret_of(&f) {
        Ret::TestResult => (quote! {}, quote! { #name }),
        Ret::Unit => {
            let w = quote::format_ident!("__azos_test_{}", name);
            (quote! { fn #w() -> ::core::result::Result<(), &'static str> { #name(); Ok(()) } }, quote! { #w })
        }
        _ => {
            return Err(syn::Error::new(
                f.sig.output.span(),
                "azos test: the function returns `()` or `Result<(), &'static str>`",
            ))
        }
    };
    Ok(quote! {
        #f

        #wrapper

        const _: () = {
            #[used]
            #[link_section = ".azos_ktest"]
            static ENTRY: ::azos_libsys::utest::KTest = ::azos_libsys::utest::KTest {
                name: #label,
                run: #run,
                phase: ::azos_libsys::utest::EARLY,
            };
        };
    })
}

#[cfg(test)]
mod tests;
