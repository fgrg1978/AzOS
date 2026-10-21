// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
//! The inference service's broker, apart from the program that hosts it.
//!
//! `infsrv` is the ring-3 task behind the `Infer` interface
//! (`azos_devif::infer`). Everything that decides something is in this
//! library and touches no system call, so `tests/host/infsrv-tests` drives it
//! on the host with real bundles, real signatures and the real generated
//! dispatcher; `main.rs` is the glue that gives it a clock, memory objects
//! and a file system.
//!
//! * [`load`]: stream a signed `.MBL` bundle into the blob arena. The
//!   signature is checked before any field is read, the blobs against the
//!   digests in the manifest, and only variants of a backend this machine has
//!   are kept.
//! * [`broker`]: the models held, the per-context energy account and the
//!   admission (Rule `accel-admission`, a receipt for every refusal).
//! * [`exec`]: the backends, `cpu-ggml` (the sequential dot product of
//!   `azos_ml`) and `rvv` (the same layers over the vector unit).
//! * [`verdict`]: the latest verdict of a context, a `Log<Verdict, 1>` in a
//!   memory object of that context's own, which a real-time reader polls with
//!   no call.
//! * [`service`]: the three interfaces one endpoint serves (`Infer`,
//!   `Decisions` for the receipts, [`service::InferLog`] for the verdict log)
//!   over a [`service::Platform`].

pub mod broker;
pub mod config;
pub mod exec;
pub mod load;
pub mod service;
pub mod verdict;
