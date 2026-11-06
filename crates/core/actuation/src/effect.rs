// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The effect interface every profile has: an effect of a kind that an
//! extension's provider owns (`azos_ext_api::Provider::kinds`) is refused,
//! with a receipt, when no installed provider owns it, because the image has
//! no such device. An effect of a served kind goes on to its device, through
//! the write-ahead gate where the image has one (`effect_gate`, Kconfig
//! `EFFECT_WRITE_AHEAD`), which admits or refuses it with a receipt of its own.

use azos_decision::{record_receipt, Rule, Verdict};

use crate::kind::Class;

/// Does an installed provider own `kind`? `Err` with the refusal's receipt
/// (`Rule::EffectUnserved`; 0 when decision records are off in this build)
/// when none does. `device` is the effect's subject.
pub fn admit_kind(kind: u8, class: Class, device: u32, tid: u32) -> Result<(), u64> {
    if crate::providers::serves(kind) {
        return Ok(());
    }
    let effect = (kind as u64) << 8 | class as u64;
    Err(record_receipt(Rule::EffectUnserved, Verdict::Refuse, tid, [effect, device as u64, 0]))
}
