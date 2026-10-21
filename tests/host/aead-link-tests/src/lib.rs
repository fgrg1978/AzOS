// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests of the brain link's Noise secure channel
//! (`azos_crypto::secure_channel`). Everything lives in `tests/`:
//!
//! * `link.rs` -- both handshakes against a Noise responder built straight on
//!   `azos_crypto::noise` (the brain's role), the framed transport, rekey,
//!   the violations, and the vectors `AzOSRobotBrain/tests/test_secure_channel.py`
//!   asserts too.
//! * `link_policy.rs` -- the K-C5 policy gate and the session registry, in a
//!   process of its own because the registry is process-global.
