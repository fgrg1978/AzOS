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
        Type::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                let n = seg.ident.to_string();
                if TEXT_TYPES.contains(&n.as_str()) {
                    return Some(format!("a `{n}`"));
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
    e
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
