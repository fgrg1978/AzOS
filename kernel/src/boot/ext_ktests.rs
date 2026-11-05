// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The extension contract in a booted image (Kconfig `EXT_ROBOT`): what the
//! robot extension's manifest declares is what the actuation core holds.

use azos_actuation::{gate, providers};
use azos_safety_core::actuation::ROBOT;

azos_ktest::ktest! {
    fn ext_robot_providers_are_installed() {
        if providers::count() != ROBOT.providers.len() {
            return Err("the provider table does not hold the robot manifest's providers");
        }
        Ok(())
    }
}

azos_ktest::ktest! {
    fn ext_gate_follows_the_providers_readiness() {
        let ready = ROBOT.providers.iter().all(|p| p.ready.is_none_or(|r| r()));
        if gate::gate_installed() != ready {
            return Err("the actuation gate does not follow the robot provider's readiness");
        }
        if !ready {
            return Err("the robot provider is not ready after boot");
        }
        Ok(())
    }
}
