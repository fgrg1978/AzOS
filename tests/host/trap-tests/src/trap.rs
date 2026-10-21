// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's generic trap layer, pulled in unmodified (the module tree
//! `kernel/src/trap/mod.rs` declares, without `kernel.rs`, which names the
//! kernel's own types).

#[path = "../../../../kernel/src/trap/frame.rs"]
pub mod frame;
#[path = "../../../../kernel/src/trap/fault.rs"]
pub mod fault;
#[path = "../../../../kernel/src/trap/irq.rs"]
pub mod irq;
#[path = "../../../../kernel/src/trap/syscall.rs"]
pub mod syscall;
