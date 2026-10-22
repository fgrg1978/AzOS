// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez

use super::{expand_main, expand_test, TokenStream};
use quote::quote;

fn text(r: syn::Result<TokenStream>) -> String {
    r.expect("expansion").to_string()
}

fn err(r: syn::Result<TokenStream>) -> String {
    r.expect_err("a refusal").to_string()
}

#[test]
fn main_returning_i32_exits_with_its_value() {
    let out = text(expand_main(quote! {}, quote! { fn main() -> i32 { 3 } }));
    assert!(out.contains("fn main () -> i32"), "{out}");
    assert!(out.contains("pub extern \"C\" fn _start (_a0 : usize , a1 : usize) -> !"), "{out}");
    assert!(out.contains(":: azos_libsys :: startup_init (a1)"), "{out}");
    assert!(out.contains(":: azos_libsys :: exit (main ())"), "{out}");
    assert!(!out.contains("panic_handler"), "{out}");
}

#[test]
fn main_returning_unit_exits_zero() {
    let out = text(expand_main(quote! {}, quote! { fn main() { } }));
    assert!(out.contains("main () ; :: azos_libsys :: exit (0)"), "{out}");
}

#[test]
fn main_returning_never_just_calls() {
    let out = text(expand_main(quote! {}, quote! { fn main() -> ! { loop {} } }));
    assert!(out.contains("{ :: azos_libsys :: startup_init (a1) ; main () }"), "{out}");
}

#[test]
fn panic_exit_makes_the_handler() {
    let out = text(expand_main(quote! { panic_exit = 70 }, quote! { fn main() -> i32 { 0 } }));
    assert!(out.contains("# [panic_handler]"), "{out}");
    assert!(out.contains(":: azos_libsys :: exit (70i32)"), "{out}");
}

#[test]
fn main_refusals() {
    assert!(err(expand_main(quote! { panic_exit = "x" }, quote! { fn main() {} })).contains("integer literal"));
    assert!(err(expand_main(quote! { panic = 1 }, quote! { fn main() {} })).contains("only argument"));
    assert!(err(expand_main(quote! { panic_exit = 1, panic_exit = 2 }, quote! { fn main() {} })).contains("twice"));
    assert!(err(expand_main(quote! {}, quote! { fn main(x: u32) {} })).contains("no arguments"));
    assert!(err(expand_main(quote! {}, quote! { async fn main() {} })).contains("plain `fn`"));
    assert!(err(expand_main(quote! {}, quote! { fn main() -> u8 { 0 } })).contains("`()`, `i32`"));
}

#[test]
fn a_test_returning_result_registers_itself() {
    let out = text(expand_test(quote! {}, quote! { fn adds() -> Result<(), &'static str> { Ok(()) } }));
    assert!(out.contains("link_section = \"azos_ktest\""), "{out}");
    assert!(out.contains("name : \"adds\""), "{out}");
    assert!(out.contains("run : adds"), "{out}");
    assert!(out.contains("phase : :: azos_libsys :: utest :: EARLY"), "{out}");
    assert!(!out.contains("__azos_test_"), "{out}");
}

#[test]
fn a_test_returning_unit_is_wrapped() {
    let out = text(expand_test(quote! {}, quote! { fn adds() { assert!(true) } }));
    assert!(out.contains("fn __azos_test_adds () -> :: core :: result :: Result < () , & 'static str >"), "{out}");
    assert!(out.contains("run : __azos_test_adds"), "{out}");
}

#[test]
fn test_refusals() {
    assert!(err(expand_test(quote! { x }, quote! { fn t() {} })).contains("no arguments"));
    assert!(err(expand_test(quote! {}, quote! { fn t() -> i32 { 0 } })).contains("returns `()`"));
    assert!(err(expand_test(quote! {}, quote! { fn t(a: u8) {} })).contains("no arguments"));
}
