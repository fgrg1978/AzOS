// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 CPU identification and the speculation-mitigation decision
//! (`crates/core/arch-x86_64/src/{features,mitigations}.rs`). Both files
//! carry their own tests; they are included under one parent because
//! `mitigations.rs` names `super::features`.

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/features.rs"]
pub mod features;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/mitigations.rs"]
pub mod mitigations;
