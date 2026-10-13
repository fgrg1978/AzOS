// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Buzzer` interface: a piezo buzzer on one PWM channel.
//!
//! The one interface of a driver that has two hosts from one source
//! (`crates/drivers/buzzer`): the kernel host is called directly
//! (`BuzzerDirect`), the ring-3 host (`userspace/drivers/buzz_drv`) serves the
//! same trait from the endpoint [`ENDPOINT`] its topology row declares and is
//! called through `BuzzerClient`; `BuzzerPlaced` is the value a caller holds
//! when it must not know which. Which host runs is the row's placement
//! (`azos_topology::placement`), and it can change while the system runs.
//!
//! This is a task-hosted endpoint, not a kernel-hosted interface: it is not in
//! [`crate::IFACES`] and no host key stands for it.
//!
//! Every op starts a sound and answers once it has started, never after it
//! ends: a tone returns when the first step is playing. A request replaces
//! whatever is playing. Every op is idempotent (a repeat starts the same sound
//! again), which is what lets a caller whose call was lost to a move between
//! hosts ask once more.
//!
//! Register-form interface (`words = 4`).

use crate::outcome::Out;
use azos_idl::azos_interface;

/// The interface id (ASCII "BUZZ").
pub const BUZZER_ID: u32 = 0x4255_5A5A;

/// The endpoint a topology row declares for this object.
pub const ENDPOINT: &str = "endpoint.buzzer";

/// The name that endpoint has in the kernel's pool: a topology grant
/// `endpoint.<name>` names `<name>` there, which is how the kernel finds it
/// to mint its own tasks a capability on it.
pub const ENDPOINT_NAME: &str = "buzzer";

#[azos_interface(id = 0x4255_5A5A, level = 1, words = 4)]
pub trait Buzzer {
    /// Play `freq_hz` for `ms` milliseconds (clamped to 20 kHz and 10 s; 0 for
    /// either stops the sound). Answers when the tone has started.
    #[idempotent]
    fn tone(&mut self, freq_hz: u32, ms: u32) -> Out<()>;
    /// Play `freq_hz` until replaced (0 stops).
    #[idempotent]
    fn on(&mut self, freq_hz: u32) -> Out<()>;
    /// Stop whatever is playing.
    #[idempotent]
    fn off(&mut self) -> Out<()>;
    /// A 100 ms acknowledgment beep.
    #[idempotent]
    fn beep(&mut self) -> Out<()>;
    /// Three short alert beeps.
    #[idempotent]
    fn alert(&mut self) -> Out<()>;
    /// The start-up arpeggio.
    #[idempotent]
    fn startup(&mut self) -> Out<()>;
}
