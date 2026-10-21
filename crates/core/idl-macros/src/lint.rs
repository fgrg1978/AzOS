// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The anti-Unix lint of `#[azos_interface]` (owner rule, strategic plan L13).
//!
//! The macro cannot know what a value *means*; it sees names and types. The
//! rules below approximate the owner's three prohibitions with both, and
//! every one is a compile error with the offending span:
//!
//! 1. **No raw integer fds.** A parameter whose name is an fd (a `_`-separated
//!    segment `fd`, `fds` or `fildes`) and whose type is an integer
//!    (`i8..i64`, `u8..u64`, `isize`, `usize`, `c_int`, `RawFd`, or an array of
//!    them); a method named like an fd that returns an integer; and any use of
//!    the types `RawFd` or `Fd`. A `Cap<T>` named `fd` is typed authority and
//!    passes.
//! 2. **No errno.** A method, parameter or return type named `errno`/`Errno`,
//!    and any return type `Result<..>` (transport failure is [`IdlError`] on
//!    the stub; an op's own outcomes are values of the interface).
//! 3. **No text or path as authority.** Any `str`, `String`, `Path`,
//!    `PathBuf`, `OsStr`, `OsString`, `CStr` or `CString` anywhere in a type
//!    (so `&str`, `Box<str>`, `Option<String>` too); any reference or raw
//!    pointer (nothing crosses a call by address); and a parameter named like a
//!    path (segment `path`, `paths`, `pathname`, `filename`, `fname`, `dirname`)
//!    unless it is a float or an array of floats (a trajectory is not a name).
//! 4. **No ioctl.** A method named `ioctl` or `fcntl`: a device is an endpoint
//!    with typed ops.
//!
//! 5. **An irreversible op names its failure.** An op marked `#[once_only]`
//!    (the marker of an effect that cannot be taken back: an actuation, a
//!    power-off, an install) must carry `#[on_failure(..)]`: when the service
//!    that runs it fails, what the system does is part of the interface, not
//!    left to the caller to guess.
//! 6. **No address as an integer** (CHERI-clean wire; strategic plan, CHERI
//!    row: the ABI passes handles and explicit `(base, len, perms)` extents,
//!    never a pointer). The integer types whose width is the machine's address
//!    width (`usize`, `isize`, `uintptr_t`, `intptr_t`, `ptrdiff_t`) anywhere
//!    in a type; a 64-bit integer (or array of them) parameter named like an
//!    address (a segment `addr`, `addrs`, `address`, `addresses`, `vaddr`,
//!    `paddr`, `ptr`, `ptrs`, `pointer`, `pointers`, `va` or `pa`); a method
//!    named like one that returns a 64-bit integer; and the pointers in
//!    disguise `NonNull<T>` and `fn(..)`. What names memory is a `Cap<T>`; a
//!    range inside it is explicit scalar parameters (`offset`, `len`, rights
//!    as a `CapPerms` word), the `(base, len, perms)` triple. `base` and
//!    `len` are not address names: an extent is what the rule asks for, and a
//!    guest-physical or bus address is a value in another address space, not a
//!    pointer of this one. Integers narrower than 64 bits (a 7-bit bus
//!    address) pass.
//!
//! Names are matched case-insensitively. These are approximations: a path
//! carried as `[u8; 64]` named `p` passes. The lint catches the habit, not the
//! determined; review catches the rest.
//!
//! [`IdlError`]: ../../azos_idl/enum.IdlError.html

use syn::{GenericArgument, PathArguments, ReturnType, Type};

const INT_TYPES: &[&str] = &[
    "i8", "i16", "i32", "i64", "isize", "u8", "u16", "u32", "u64", "usize", "c_int", "c_uint", "c_long", "c_ulong", "RawFd",
];
const TEXT_TYPES: &[&str] = &["str", "String", "Path", "PathBuf", "OsStr", "OsString", "CStr", "CString"];
const FD_TYPES: &[&str] = &["RawFd", "Fd"];
/// Integer types whose width is the machine's address width.
const ADDR_WIDTH_TYPES: &[&str] = &["usize", "isize", "uintptr_t", "intptr_t", "ptrdiff_t"];
/// Integers that hold a pointer on every ISA AzOS targets (64-bit).
const WIDE_INT_TYPES: &[&str] = &["u64", "i64", "usize", "isize", "uintptr_t", "intptr_t", "ptrdiff_t"];
/// Pointers in disguise.
const POINTER_TYPES: &[&str] = &["NonNull"];

fn segments(name: &str) -> impl Iterator<Item = String> + '_ {
    name.split('_').map(|s| s.to_ascii_lowercase())
}
fn has_segment(name: &str, set: &[&str]) -> bool {
    segments(name).any(|s| set.contains(&s.as_str()))
}

pub(crate) fn is_fd_name(name: &str) -> bool {
    has_segment(name, &["fd", "fds", "fildes"])
}
pub(crate) fn is_path_name(name: &str) -> bool {
    has_segment(name, &["path", "paths", "pathname", "filename", "fname", "dirname"])
}
pub(crate) fn is_addr_name(name: &str) -> bool {
    has_segment(
        name,
        &["addr", "addrs", "address", "addresses", "vaddr", "paddr", "ptr", "ptrs", "pointer", "pointers", "va", "pa"],
    )
}
pub(crate) fn is_errno_name(name: &str) -> bool {
    has_segment(name, &["errno"])
}

fn last_ident(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        Type::Group(g) => last_ident(&g.elem),
        Type::Paren(g) => last_ident(&g.elem),
        _ => None,
    }
}

/// The element type under arrays.
fn base(ty: &Type) -> &Type {
    match ty {
        Type::Array(a) => base(&a.elem),
        Type::Group(g) => base(&g.elem),
        Type::Paren(g) => base(&g.elem),
        t => t,
    }
}

fn is_int(ty: &Type) -> bool {
    last_ident(base(ty)).map_or(false, |n| INT_TYPES.contains(&n.as_str()))
}
/// A 64-bit (pointer-wide) integer, or an array of them.
fn is_wide_int(ty: &Type) -> bool {
    last_ident(base(ty)).map_or(false, |n| WIDE_INT_TYPES.contains(&n.as_str()))
}
fn is_float(ty: &Type) -> bool {
    last_ident(base(ty)).map_or(false, |n| n == "f32" || n == "f64")
}

/// What kind of by-name or by-address thing a type contains, if any.
fn forbidden_in(ty: &Type) -> Option<String> {
    match ty {
        Type::Reference(r) => {
            if last_ident(&r.elem).as_deref() == Some("str") {
                Some("a `&str`".into())
            } else {
                Some("a reference (nothing crosses a call by address)".into())
            }
        }
        Type::Ptr(_) => Some("a raw pointer (nothing crosses a call by address)".into()),
        Type::BareFn(_) => Some("a function pointer (a code address does not cross a call)".into()),
        Type::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                let n = seg.ident.to_string();
                if TEXT_TYPES.contains(&n.as_str()) {
                    return Some(format!("a `{n}`"));
                }
                if POINTER_TYPES.contains(&n.as_str()) {
                    return Some(format!("a `{n}` (a pointer; nothing crosses a call by address)"));
                }
                if let PathArguments::AngleBracketed(a) = &seg.arguments {
                    for g in &a.args {
                        if let GenericArgument::Type(t) = g {
                            if let Some(f) = forbidden_in(t) {
                                return Some(f);
                            }
                        }
                    }
                }
            }
            None
        }
        Type::Array(a) => forbidden_in(&a.elem),
        Type::Slice(s) => forbidden_in(&s.elem),
        Type::Tuple(t) => t.elems.iter().find_map(forbidden_in),
        Type::Group(g) => forbidden_in(&g.elem),
        Type::Paren(g) => forbidden_in(&g.elem),
        _ => None,
    }
}

/// The first address-width integer type anywhere in `ty`.
fn addr_width_in(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(p) => {
            let seg = p.path.segments.last()?;
            let n = seg.ident.to_string();
            if ADDR_WIDTH_TYPES.contains(&n.as_str()) {
                return Some(n);
            }
            if let PathArguments::AngleBracketed(a) = &seg.arguments {
                return a.args.iter().find_map(|g| match g {
                    GenericArgument::Type(t) => addr_width_in(t),
                    _ => None,
                });
            }
            None
        }
        Type::Reference(r) => addr_width_in(&r.elem),
        Type::Ptr(p) => addr_width_in(&p.elem),
        Type::Array(a) => addr_width_in(&a.elem),
        Type::Slice(s) => addr_width_in(&s.elem),
        Type::Tuple(t) => t.elems.iter().find_map(addr_width_in),
        Type::Group(g) => addr_width_in(&g.elem),
        Type::Paren(g) => addr_width_in(&g.elem),
        _ => None,
    }
}

fn err(span: impl quote::ToTokens, msg: String) -> syn::Error {
    syn::Error::new_spanned(span, format!("azos_interface (anti-Unix lint): {msg}"))
}

/// The lint on a method's name.
pub(crate) fn check_method_name(ident: &syn::Ident, ret: &ReturnType) -> Vec<syn::Error> {
    let n = ident.to_string();
    let mut e = Vec::new();
    if is_errno_name(&n) {
        e.push(err(ident, format!("method `{n}` is an errno accessor; an op's outcomes are typed values of the interface, transport failures are IdlError")));
    }
    if n.eq_ignore_ascii_case("ioctl") || n.eq_ignore_ascii_case("fcntl") {
        e.push(err(ident, format!("method `{n}` is an ioctl; a device is an endpoint with typed ops, give each operation its own method")));
    }
    if is_fd_name(&n) {
        if let ReturnType::Type(_, t) = ret {
            if is_int(t) {
                e.push(err(ident, format!("method `{n}` returns a raw integer fd; return a `Cap<T>` (a typed handle)")));
            }
        }
    }
    if is_addr_name(&n) {
        if let ReturnType::Type(_, t) = ret {
            if is_wide_int(t) {
                e.push(err(ident, format!("method `{n}` returns an address as an integer; return a `Cap<T>` naming the memory (or an offset into one the caller holds)")));
            }
        }
    }
    e
}

/// The failure-contract lint: an op that cannot be undone (`#[once_only]`)
/// declares `#[on_failure(..)]`.
pub(crate) fn check_contract(ident: &syn::Ident, once_only: bool, has_on_failure: bool) -> Vec<syn::Error> {
    if once_only && !has_on_failure {
        return vec![syn::Error::new_spanned(
            ident,
            format!("azos_interface (failure-contract lint): method `{ident}` is #[once_only] (irreversible) and declares no #[on_failure(degrade|safe_state|restart|escalate)]; say what happens when its service fails"),
        )];
    }
    Vec::new()
}

/// The lint on one parameter.
pub(crate) fn check_param(name: &syn::Ident, ty: &Type) -> Vec<syn::Error> {
    let n = name.to_string();
    let mut e = Vec::new();
    if is_fd_name(&n) && is_int(ty) {
        e.push(err(name, format!("parameter `{n}` is a raw integer fd; take a `Cap<T>` (a typed handle) instead")));
    }
    if is_errno_name(&n) {
        e.push(err(name, format!("parameter `{n}` is an errno; an op's outcomes are typed values of the interface")));
    }
    if is_addr_name(&n) && is_wide_int(ty) {
        e.push(err(name, format!("parameter `{n}` is an address as an integer; take a `Cap<T>` naming the memory plus explicit `offset` and `len` parameters (a (base, len, perms) extent), never a pointer as a number")));
    }
    if is_path_name(&n) && !is_float(ty) {
        e.push(err(name, format!("parameter `{n}` is a path used as authority; take a `Cap<T>` (a warrant to the object), not a name")));
    }
    e.extend(check_type(ty, &format!("parameter `{n}`")));
    e
}

/// The lint on a type (a parameter's, or the return's).
pub(crate) fn check_type(ty: &Type, what: &str) -> Vec<syn::Error> {
    let mut e = Vec::new();
    if let Some(f) = forbidden_in(ty) {
        e.push(err(ty, format!("{what} contains {f}: text, paths and addresses are not authority; pass a `Cap<T>` or plain scalars")));
    }
    if let Some(n) = addr_width_in(ty) {
        e.push(err(ty, format!("{what} uses `{n}`, whose width is the machine's address width and which holds addresses; a count or an offset is a fixed-width `u32`/`u64`, and memory is named by a `Cap<T>` with explicit `offset`/`len`")));
    }
    if let Some(n) = last_ident(ty) {
        if FD_TYPES.contains(&n.as_str()) {
            e.push(err(ty, format!("{what} has type `{n}`, a raw fd; use a `Cap<T>`")));
        }
        if n.eq_ignore_ascii_case("errno") {
            e.push(err(ty, format!("{what} has type `{n}`; an op's outcomes are typed values of the interface")));
        }
    }
    e
}

/// The lint on the return type.
pub(crate) fn check_return(ret: &ReturnType) -> Vec<syn::Error> {
    let ReturnType::Type(_, ty) = ret else { return Vec::new() };
    let mut e = check_type(ty, "the return type");
    if last_ident(ty).as_deref() == Some("Result") {
        e.push(err(ty, "the return type is a `Result`: an op returns a plain value (the stub adds the transport failure as IdlError); no errno-style status".into()));
    }
    e
}
