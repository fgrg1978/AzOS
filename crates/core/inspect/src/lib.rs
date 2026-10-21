// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The introspection tree: what the kernel knows about itself, as data a
//! program reads without asking.
//!
//! # Shape
//!
//! A region is a block of memory (a MemObj the kernel created and alone
//! writes) holding one tree of typed nodes: a directory, a `u64`, an `i64`, a
//! string or a histogram. A reader maps the region read-only and walks it
//! with loads: no system call, no copy, no lock. The same layout serves two
//! regions: the **public** one, any task that holds the MemObj reads, and the
//! **admin** one, which carries the subtrees that name other tasks or
//! otherwise reveal what a task may not know, and which is handed out only
//! against an admin warrant. The two share no byte: the admin region is not
//! a flag on public nodes, so a reader that maps the public MemObj has
//! nothing to be refused, and a corrupt reader has nothing to leak.
//!
//! # Consistency
//!
//! Two seqlocks, because there are two rates of change.
//!
//! * The **epoch** (header word 2) covers the tree's shape: the nodes, their
//!   names and where their values live. A shape change is a *rebuild*; the
//!   epoch is odd while it runs. A reader holds the epoch it opened under
//!   and every operation ends by checking it: a changed epoch is
//!   [`Error::Restructured`] (reopen with [`Reader::refresh`], look the node
//!   up again; node ids belong to one epoch).
//! * Each node has its own **seq** covering its value, so a histogram or a
//!   string is read whole. A writer claims it with a compare-exchange (the
//!   same claim `azos_mm::vdso::vdso_update` makes), so two writers of one
//!   node cannot interleave; a reader that finds it odd for
//!   [`SPIN_MAX`] reads gets [`Error::Contended`] instead of spinning on a
//!   writer that was preempted.
//!
//! Every access to a region is an atomic access of an aligned 64-bit word, on
//! both sides: nothing here is a data race, and a reader of a read-only
//! mapping never stores (it only loads).
//!
//! # Versioning
//!
//! The header carries [`FORMAT_VERSION`]. [`Reader::open`] refuses any other
//! version with [`Error::VersionMismatch`] rather than guess at a layout.
//!
//! The layout is in [`format`]; the kernel side is [`Writer`], the reading
//! side [`Reader`].
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod format;
mod reader;
mod region;
mod writer;

pub use format::{Class, Error, Kind, NodeId, FORMAT_VERSION, HIST_MAX, NAME_MAX, SPIN_MAX, STR_MAX};
pub use reader::{Hist, Name, NodeInfo, Reader, Str, Value};
pub use region::Region;
pub use writer::{Builder, Writer};
