// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `userspace/lib/srv`, the ring-3 server runtime.
//!
//! The calls are the kernel's own: `crates/core/ipc/src/ep_queue.rs`, pulled
//! with `#[path]` (it carries its host substitutes), queues them, hands back
//! the port link when a call finds the queue empty, and answers the poll
//! accept and `MSG_MORE`. The port is a stand-in with the kernel port's two
//! classes, alternated as `port.rs` alternates them: the queued events
//! (interrupts) and the table sources (the calls bit, timers, doorbells). A
//! wait with no deadline that finds nothing would sleep in the kernel; here
//! it returns and counts, and a test's bounded number of turns is its
//! timeout.

#[path = "../../../../crates/core/ipc/src/ep_queue.rs"]
#[allow(dead_code)]
pub mod ep_queue;

#[path = "../../../../crates/core/ipc/src/port_link.rs"]
pub mod port_link;
