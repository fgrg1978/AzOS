// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The source fingerprint both hosts carry (`crates/drivers/chip_source.rs`).

include!("../chip_source.rs");

fn main() {
    chip_source_fingerprint("buzzer");
}
