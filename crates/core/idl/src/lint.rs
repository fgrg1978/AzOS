// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The anti-Unix lint, end to end through rustc.
//!
//! The rules are in `azos_idl_macros` (`lint.rs`, with exact-message unit
//! tests); this module documents them and pins, with `compile_fail` doctests,
//! that the macro's refusal reaches the compiler. Each refusal has a twin that
//! compiles, differing only in the offending item.
//!
//! Which of these discriminate the lint: `fd: i32` and `errno` are valid
//! scalar types, so only the lint refuses them (the canary of switching the
//! rule off turns the doctest red). A `&str` is also not a [`Wire`] type, so
//! rustc would refuse it without the lint; the exact-message unit tests in
//! `azos_idl_macros` are what pin the lint's own refusal there.
//!
//! [`Wire`]: crate::Wire
//!
//! | Refused | Why | Use instead |
//! |---|---|---|
//! | `fd: i32` (a parameter named `fd`, `src_fd`, `fd_in`; integer type) | an integer into a global table is ambient authority | `Cap<T>` |
//! | a method `errno`, a parameter `errno`, a type `Errno`, a `Result` return | errno is a global side channel | a typed value; `IdlError` for the transport |
//! | `&str`, `String`, `Path`, `PathBuf`, `CStr`..., any reference or pointer | a name is not authority; nothing crosses a call by address | `Cap<T>` |
//! | a parameter named `path`, `filename`... (not a float) | same, by name | `Cap<T>` |
//! | a method `ioctl`, `fcntl` | magic-number control | one typed method per operation |
//!
//! ```compile_fail
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 2, level = 1)]
//! pub trait Files { fn read(&mut self, fd: i32) -> u32; }
//! ```
//!
//! ```
//! use azos_idl::{azos_interface, Cap};
//! pub struct File;
//! #[azos_interface(id = 2, level = 1)]
//! pub trait Files { fn read(&mut self, fd: Cap<File>) -> u32; }
//! ```
//!
//! ```compile_fail
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 3, level = 1)]
//! pub trait Files { fn open(&mut self, name: &str) -> u32; }
//! ```
//!
//! ```compile_fail
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 4, level = 1)]
//! pub trait Files { fn errno(&mut self) -> i32; }
//! ```
//!
//! ```
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 4, level = 1)]
//! pub trait Files { fn status(&mut self) -> i32; }
//! ```
//!
//! The size check is also a compile error. Seven `u64` arguments and the
//! header are eight words, the ABI ceiling; an eighth argument is a ninth:
//!
//! ```
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 5, level = 1)]
//! pub trait Wide { fn f(&mut self, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64); }
//! ```
//!
//! ```compile_fail
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 5, level = 1)]
//! pub trait Wide { fn f(&mut self, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64); }
//! ```
//!
//! A narrower `words = 4` (the register-only fast path) bounds the same check:
//!
//! ```compile_fail
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 6, level = 1, words = 4)]
//! pub trait Narrow { fn f(&mut self, a: u64, b: u64, c: u64, d: u64); }
//! ```
//!
//! ```
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 6, level = 1, words = 4)]
//! pub trait Narrow { fn f(&mut self, a: u64, b: u64, c: u64) -> u64; }
//! ```
//!
//! A reply is bounded too (status + return):
//!
//! ```compile_fail
//! use azos_idl::azos_interface;
//! #[azos_interface(id = 7, level = 1, words = 4)]
//! pub trait Reply { fn f(&mut self) -> [u64; 4]; }
//! ```
//!
//! Capability entries are bounded by the ABI (eight):
//!
//! ```compile_fail
//! use azos_idl::{azos_interface, Cap};
//! pub struct K;
//! #[azos_interface(id = 8, level = 1)]
//! pub trait Caps { fn f(&mut self, a: [Cap<K>; 9]); }
//! ```
//!
//! ```
//! use azos_idl::{azos_interface, Cap};
//! pub struct K;
//! #[azos_interface(id = 8, level = 1)]
//! pub trait Caps { fn f(&mut self, a: [Cap<K>; 8]); }
//! ```
//!
//! A type that is not a plain scalar, array or capability is not an interface
//! type:
//!
//! ```compile_fail
//! use azos_idl::azos_interface;
//! pub struct NotWire;
//! #[azos_interface(id = 9, level = 1)]
//! pub trait Bad { fn f(&mut self, a: NotWire); }
//! ```
