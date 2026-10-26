// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The guest's `HVC` and `SMC`, served: [`super::psci`] answers from the
//! state of the VM's vCPUs, and this layer puts the answer where the guest
//! reads it and carries out what the call asked of the VM.
//!
//! `Hypervisor::hypercall` runs on the vCPU thread that made the call, with
//! the VM as a [`HypercallHost`]. The VM's power state is not kept here: a
//! vCPU that runs is `On`, one that does not is `Off` (`CPU_ON` was accepted
//! when its thread was made, so `AFFINITY_INFO` never answers `ON_PENDING`).
//!
//! | `psci` effect | here |
//! |---------------|------|
//! | none | `x0` = the answer |
//! | `Start` | [`HypercallHost::start_vcpu`] makes the thread; `x0` = the answer, or the code its failure maps to |
//! | `Standby` | `x0` = success and the guest runs on: a standby `CPU_SUSPEND` that returns at once is a `wfi` that woke early, which the architecture allows |
//! | `CpuOff` | the vCPU ends ([`HypercallOutcome::StopVcpu`]); the call does not return |
//! | `SystemOff`, `SystemReset` | the guest ends the machine ([`HypercallOutcome::EndGuest`], kind 0 and 1) |

use azos_arch_api::{HypercallHost, HypercallOutcome, VcpuStartError};

use super::psci::{self, Effect, CpuSet};
use super::world::is_smc;

const EC_HVC64: u64 = 0x16;

/// A result code in the width of the calling convention (`int32` in `w0` for
/// an SMC32 function, `int64` in `x0` for SMC64), as `psci` words its own.
const fn code(c: i32, wide: bool) -> u64 {
    if wide { c as i64 as u64 } else { c as u32 as u64 }
}

/// Serve the call the guest vCPU `vcpu` made: `esr` is the `ESR_EL2` of the
/// trap, `gpr` the guest's registers and `pc` its resume address. An `SMC`
/// leaves `ELR_EL2` on the instruction, which is stepped over here; an `HVC`
/// already returns after it.
pub fn hypercall(
    gpr: &mut [u64; 32],
    pc: &mut u64,
    esr: u64,
    vcpu: usize,
    host: &mut dyn HypercallHost,
) -> HypercallOutcome {
    let smc = is_smc(esr);
    if !smc && (esr >> 26) & 0x3F != EC_HVC64 {
        return HypercallOutcome::Unserved;
    }
    if smc {
        *pc = pc.wrapping_add(4);
    }
    let mut set = CpuSet::new(host.vcpus());
    for i in 0..set.count() {
        if i == vcpu || host.vcpu_running(i) {
            set.boot(i);
        }
    }
    let fid = gpr[0] as u32;
    let wide = fid & (1 << 30) != 0;
    let reply = psci::call(&mut set, vcpu, fid, [gpr[1], gpr[2], gpr[3]]);
    match reply.effect {
        Effect::None | Effect::Standby => gpr[0] = reply.x0,
        Effect::Start { index, entry, context } => {
            gpr[0] = match host.start_vcpu(index as usize, entry, context) {
                Ok(()) => reply.x0,
                Err(VcpuStartError::BadAddress) => code(psci::ret::INVALID_ADDRESS, wide),
                Err(VcpuStartError::AlreadyRunning) => code(psci::ret::ALREADY_ON, wide),
                Err(VcpuStartError::Failed) => code(psci::ret::INTERNAL_FAILURE, wide),
            };
        }
        Effect::CpuOff => return HypercallOutcome::StopVcpu,
        Effect::SystemOff => return HypercallOutcome::EndGuest { kind: 0, reason: 0 },
        Effect::SystemReset => return HypercallOutcome::EndGuest { kind: 1, reason: 0 },
    }
    HypercallOutcome::Served
}
