// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! G1 (2026-10-11): where the e-stop release key may come from
//! (`estop::operator_key_source`, the decision `kernel/src/main.rs` applies
//! at boot). The loose `/fat/OPERATOR.PUB` is unsigned: anyone who can write
//! the FAT could install a key and release a latched e-stop. A release build
//! must never read it.

use super::estop::{operator_key_source, OperatorKeySource};

#[test]
fn a_signed_key_wins_in_every_build() {
    assert_eq!(operator_key_source(true, false), OperatorKeySource::SignedTopology);
    assert_eq!(operator_key_source(true, true), OperatorKeySource::SignedTopology);
}

#[test]
fn a_release_build_never_reads_the_unsigned_fat_key() {
    assert_eq!(operator_key_source(false, false), OperatorKeySource::None);
}

#[test]
fn a_dev_build_without_a_signed_key_may_read_the_fat_key() {
    assert_eq!(operator_key_source(false, true), OperatorKeySource::UnsignedFatDevOnly);
}
