// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PSCI and SMCCC as a guest sees them: emulated, never re-issued.
//!
//! Two PSCI paths exist on aarch64 and they must not be mixed up:
//!
//! * [`super::stub`] (the **host's**): the kernel itself, running at EL1 over
//!   the resident EL2 stub, calls PSCI with `HVC` and the stub forwards the
//!   call as `SMC #0` to the firmware. That is how the host powers its own
//!   CPUs on and off. It stays as it is.
//! * this module (the **guest's**): a guest's `HVC` or `SMC` is a trap taken
//!   while its vCPU ran ([`super::decode_esr`] says `Hypercall`), and it is
//!   answered here from the state of the VM's vCPUs. It never reaches the
//!   firmware: forwarding it would power physical CPUs on behalf of a guest
//!   that only owns virtual ones, and `SYSTEM_OFF` would power the machine
//!   off.
//!
//! [`call`] takes the function id and `x1`-`x3` of the trap, the vCPU that
//! made it and the VM's [`CpuSet`] (shared by the VM's vCPU threads: the VM
//! holds it under one lock), and answers with the value for the guest's `x0`
//! and an [`Effect`] for the vCPU loop to carry out:
//!
//! | effect | the loop |
//! |--------|----------|
//! | [`Effect::Start`] | creates the target's `GuestCtx` (`entry_pc` = `entry`, `entry_arg` = `context`: the guest sees it in `x0`), starts its thread, and calls [`CpuSet::entered`] on its first entry; a start that fails calls [`CpuSet::ended`] and replaces `x0` with [`ret::INTERNAL_FAILURE`] |
//! | [`Effect::Standby`] | parks like a `wfi` exit, then returns to the guest |
//! | [`Effect::CpuOff`] | ends the caller's thread (`Stopped`); the call does not return |
//! | [`Effect::SystemOff`], [`Effect::SystemReset`] | ends the guest through the monitor (`fault::SHUTDOWN`'s path: vmmd tears the VM down, or builds it again for a reset) |
//!
//! For an `SMC` trapped to EL2 `ELR_EL2` still points at the `SMC`: the
//! entry steps the guest past it (4 bytes) before it resumes; for an `HVC` the
//! preferred return address is already the next instruction.
//!
//! # Contract with the entry code and the guest's device tree
//!
//! A vCPU's MPIDR is [`mpidr_of`]`(index)`: `VMPIDR_EL2` is programmed with it
//! before the first entry, the guest's device tree names the CPUs by it
//! (`reg = <index>`), and `CPU_ON` / `AFFINITY_INFO` take it back with
//! [`index_of`]. The device tree's PSCI node says `method = "hvc"` (or
//! `"smc"`: both reach [`call`]) and `compatible = "arm,psci-1.0"`.
//!
//! # What is answered
//!
//! PSCI 1.1 over SMCCC 1.1, a flat set of single-thread CPUs (affinity level
//! 0 only, no clusters). `PSCI_VERSION`, `CPU_SUSPEND` (the standby state
//! only: it behaves as `wfi`; a power-down state is refused), `CPU_OFF`,
//! `CPU_ON`, `AFFINITY_INFO`, `MIGRATE_INFO_TYPE` (2: no Trusted OS to
//! migrate), `SYSTEM_OFF`, `SYSTEM_RESET`, `PSCI_FEATURES`, `SMCCC_VERSION`
//! and `SMCCC_ARCH_FEATURES`. Everything else is `NOT_SUPPORTED`, and
//! `PSCI_FEATURES` / `SMCCC_ARCH_FEATURES` say so for it, so a guest probes
//! instead of guessing (no vulnerability workaround is offered: the host's
//! own mitigations are not the guest's to configure).

/// Most vCPUs one VM can have here: the MPIDR carries the index in `Aff0`,
/// and the GICv3 range-selector form of an SGI target list covers 16 CPUs of
/// an `Aff0` group.
pub const MAX_VCPUS: usize = 16;

/// `SMCCC_VERSION` (SMC32 fast call, owner 0, function 0).
pub const SMCCC_VERSION: u32 = 0x8000_0000;
/// `SMCCC_ARCH_FEATURES` (owner 0, function 1).
pub const SMCCC_ARCH_FEATURES: u32 = 0x8000_0001;
/// The SMCCC version answered: 1.1.
pub const SMCCC_VERSION_1_1: u64 = 0x0001_0001;
/// The PSCI version answered: 1.1.
pub const PSCI_VERSION_1_1: u64 = 0x0001_0001;

/// PSCI function numbers (the low bits of a fid of owner 4).
pub mod func {
    pub const VERSION: u32 = 0;
    pub const CPU_SUSPEND: u32 = 1;
    pub const CPU_OFF: u32 = 2;
    pub const CPU_ON: u32 = 3;
    pub const AFFINITY_INFO: u32 = 4;
    pub const MIGRATE_INFO_TYPE: u32 = 6;
    pub const SYSTEM_OFF: u32 = 8;
    pub const SYSTEM_RESET: u32 = 9;
    pub const FEATURES: u32 = 10;
}

/// PSCI return codes (`int32`; for an SMC64 function `int64`, sign-extended).
pub mod ret {
    pub const SUCCESS: i32 = 0;
    pub const NOT_SUPPORTED: i32 = -1;
    pub const INVALID_PARAMETERS: i32 = -2;
    pub const DENIED: i32 = -3;
    pub const ALREADY_ON: i32 = -4;
    pub const ON_PENDING: i32 = -5;
    pub const INTERNAL_FAILURE: i32 = -6;
    pub const INVALID_ADDRESS: i32 = -9;
}

/// What `AFFINITY_INFO` returns for a CPU that is on / off / being turned on.
pub mod affinity {
    pub const ON: u64 = 0;
    pub const OFF: u64 = 1;
    pub const ON_PENDING: u64 = 2;
}

/// `MIGRATE_INFO_TYPE`: the Trusted OS is absent or needs no migration.
const MIGRATE_NOT_REQUIRED: u64 = 2;

/// `CPU_SUSPEND`'s `power_state` bit 16: set for a power-down state.
const POWER_STATE_TYPE_DOWN: u64 = 1 << 16;
/// `MPIDR_EL1` bit 31 reads as one.
const MPIDR_RES1: u64 = 1 << 31;
/// `MPIDR` affinity fields `Aff3` and `Aff2:Aff1:Aff0`; the flag bits (31, 30
/// `U`, 24 `MT`) are not part of the address.
const MPIDR_AFF: u64 = 0xFF_00FF_FFFF;

/// The MPIDR of vCPU `index`: `Aff0` is the index, bit 31 reads as one.
pub const fn mpidr_of(index: usize) -> u64 {
    MPIDR_RES1 | index as u64
}

/// The vCPU an MPIDR names among `count`: only `Aff0` may be non-zero.
pub const fn index_of(mpidr: u64, count: usize) -> Option<usize> {
    let aff = mpidr & MPIDR_AFF;
    if aff >> 8 != 0 || aff as usize >= count {
        return None;
    }
    Some(aff as usize)
}

/// Where one vCPU is in its power life.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuState {
    /// No thread runs it: never started, `CPU_OFF`, ended, or the VM shut down.
    Off,
    /// `CPU_ON` accepted, its thread has not entered the guest yet.
    OnPending,
    On,
}

/// The power state of a VM's vCPUs: what `CPU_ON`, `CPU_OFF` and
/// `AFFINITY_INFO` read and change. Pure; the VM keeps it under a lock.
#[derive(Copy, Clone, Debug)]
pub struct CpuSet {
    n: u8,
    st: [CpuState; MAX_VCPUS],
}

impl CpuSet {
    /// `n` vCPUs (clamped to 1..=[`MAX_VCPUS`]), all off: the boot vCPU is
    /// marked with [`CpuSet::boot`] when the monitor starts it.
    pub const fn new(n: usize) -> CpuSet {
        let n = if n < 1 { 1 } else if n > MAX_VCPUS { MAX_VCPUS } else { n };
        CpuSet { n: n as u8, st: [CpuState::Off; MAX_VCPUS] }
    }

    pub const fn count(&self) -> usize {
        self.n as usize
    }

    pub const fn state(&self, index: usize) -> Option<CpuState> {
        if index < self.n as usize { Some(self.st[index]) } else { None }
    }

    /// The monitor started vCPU `index` itself (the boot CPU), not through
    /// `CPU_ON`.
    pub fn boot(&mut self, index: usize) {
        if index < self.count() {
            self.st[index] = CpuState::On;
        }
    }

    /// The thread of vCPU `index` made its first entry after a `CPU_ON`.
    pub fn entered(&mut self, index: usize) {
        if index < self.count() && self.st[index] == CpuState::OnPending {
            self.st[index] = CpuState::On;
        }
    }

    /// The thread of vCPU `index` ended, whatever the cause (a stop, a
    /// fault, a start that failed).
    pub fn ended(&mut self, index: usize) {
        if index < self.count() {
            self.st[index] = CpuState::Off;
        }
    }

    fn all_off(&mut self) {
        self.st = [CpuState::Off; MAX_VCPUS];
    }
}

/// What the vCPU loop does besides putting [`Reply::x0`] in the guest's `x0`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    /// Start vCPU `index` at `entry` with `context` in `x0` (`CPU_ON`).
    Start { index: u8, entry: u64, context: u64 },
    /// Wait for an interrupt like a `wfi`, then return (`CPU_SUSPEND`, standby).
    Standby,
    /// End the calling vCPU (`CPU_OFF`).
    CpuOff,
    /// End the guest (`SYSTEM_OFF`).
    SystemOff,
    /// End the guest to build it again (`SYSTEM_RESET`).
    SystemReset,
}

/// The answer to one call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub x0: u64,
    pub effect: Effect,
}

impl Reply {
    const fn value(x0: u64) -> Reply {
        Reply { x0, effect: Effect::None }
    }
}

/// A result code in the width of the calling convention: `int32` in `w0` for
/// an SMC32 function, `int64` in `x0` for SMC64.
const fn code(c: i32, wide: bool) -> u64 {
    if wide { c as i64 as u64 } else { c as u32 as u64 }
}

/// What a function id names.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Fid {
    /// Owner 0 (Arm architecture), function number.
    Arch(u32),
    /// Owner 4 (standard secure service) function number below 32: PSCI.
    Psci { num: u32, wide: bool },
    /// Not a fast call of either, or with the must-be-zero bits set.
    Unknown { wide: bool },
}

const fn parse(fid: u32) -> Fid {
    let wide = fid & (1 << 30) != 0;
    let fast = fid & (1 << 31) != 0;
    let owner = (fid >> 24) & 0x3F;
    let num = fid & 0xFFFF;
    if !fast || fid & 0x00FF_0000 != 0 {
        return Fid::Unknown { wide };
    }
    match owner {
        0 if !wide => Fid::Arch(num),
        4 if num < 32 => Fid::Psci { num, wide },
        _ => Fid::Unknown { wide },
    }
}

/// Does this ISA's guest PSCI answer `fid` (what `PSCI_FEATURES` and
/// `SMCCC_ARCH_FEATURES` report)? The SMC64 forms exist for the functions
/// that carry an address or a register-wide argument.
const fn psci_implemented(num: u32, wide: bool) -> bool {
    match num {
        func::CPU_SUSPEND | func::CPU_ON | func::AFFINITY_INFO => true,
        func::VERSION
        | func::CPU_OFF
        | func::MIGRATE_INFO_TYPE
        | func::SYSTEM_OFF
        | func::SYSTEM_RESET
        | func::FEATURES => !wide,
        _ => false,
    }
}

/// Answer the `HVC`/`SMC` of vCPU `caller` with function id `fid` and
/// arguments `x[0..3] = x1..x3`.
pub fn call(set: &mut CpuSet, caller: usize, fid: u32, x: [u64; 3]) -> Reply {
    match parse(fid) {
        Fid::Arch(n) => Reply::value(arch(n, x[0] as u32)),
        Fid::Psci { num, wide } => psci(set, caller, num, wide, x),
        Fid::Unknown { wide } => Reply::value(code(ret::NOT_SUPPORTED, wide)),
    }
}

fn arch(num: u32, query: u32) -> u64 {
    match 0x8000_0000 | num {
        SMCCC_VERSION => SMCCC_VERSION_1_1,
        SMCCC_ARCH_FEATURES => match query {
            SMCCC_VERSION | SMCCC_ARCH_FEATURES => code(ret::SUCCESS, false),
            _ => code(ret::NOT_SUPPORTED, false),
        },
        _ => code(ret::NOT_SUPPORTED, false),
    }
}

fn psci(set: &mut CpuSet, caller: usize, num: u32, wide: bool, x: [u64; 3]) -> Reply {
    if !psci_implemented(num, wide) {
        return Reply::value(code(ret::NOT_SUPPORTED, wide));
    }
    // Canary: the call goes to the firmware as the host's own SMC would; the
    // monitor sees no effect, so no vCPU starts and no guest ends.
    if cfg!(feature = "canary-psci-forwarded") && matches!(num, func::CPU_ON | func::SYSTEM_OFF) {
        return Reply::value(code(ret::SUCCESS, wide));
    }
    // An SMC32 call passes 32-bit registers: the upper halves are not arguments.
    let arg = |i: usize| if wide { x[i] } else { x[i] & 0xFFFF_FFFF };
    match num {
        func::VERSION => Reply::value(PSCI_VERSION_1_1),
        func::MIGRATE_INFO_TYPE => Reply::value(MIGRATE_NOT_REQUIRED),
        func::FEATURES => Reply::value(features(arg(0) as u32)),
        func::CPU_SUSPEND => {
            // Standby behaves as `wfi`; a power-down state would lose the
            // vCPU's context and resume it at an entry point, which this does not offer.
            if arg(0) & POWER_STATE_TYPE_DOWN != 0 {
                Reply::value(code(ret::INVALID_PARAMETERS, wide))
            } else {
                Reply { x0: code(ret::SUCCESS, wide), effect: Effect::Standby }
            }
        }
        func::CPU_OFF => {
            if set.state(caller) == Some(CpuState::On) {
                set.st[caller] = CpuState::Off;
                Reply { x0: code(ret::SUCCESS, wide), effect: Effect::CpuOff }
            } else {
                Reply::value(code(ret::DENIED, wide))
            }
        }
        func::CPU_ON => cpu_on(set, wide, arg(0), arg(1), arg(2)),
        func::AFFINITY_INFO => {
            let Some(i) = index_of(arg(0), set.count()) else {
                return Reply::value(code(ret::INVALID_PARAMETERS, wide));
            };
            // Level 0 is the CPU itself; the set has no clusters above it.
            if arg(1) != 0 {
                return Reply::value(code(ret::INVALID_PARAMETERS, wide));
            }
            Reply::value(match set.st[i] {
                CpuState::On => affinity::ON,
                CpuState::Off => affinity::OFF,
                CpuState::OnPending => affinity::ON_PENDING,
            })
        }
        func::SYSTEM_OFF => {
            set.all_off();
            Reply { x0: code(ret::SUCCESS, wide), effect: Effect::SystemOff }
        }
        func::SYSTEM_RESET => {
            set.all_off();
            Reply { x0: code(ret::SUCCESS, wide), effect: Effect::SystemReset }
        }
        _ => Reply::value(code(ret::NOT_SUPPORTED, wide)),
    }
}

fn cpu_on(set: &mut CpuSet, wide: bool, target: u64, entry: u64, context: u64) -> Reply {
    let Some(i) = index_of(target, set.count()) else {
        return Reply::value(code(ret::INVALID_PARAMETERS, wide));
    };
    // The guest is AArch64: an entry point is a 4-byte aligned instruction.
    if entry & 3 != 0 {
        return Reply::value(code(ret::INVALID_ADDRESS, wide));
    }
    match set.st[i] {
        CpuState::On => Reply::value(code(ret::ALREADY_ON, wide)),
        CpuState::OnPending => Reply::value(code(ret::ON_PENDING, wide)),
        CpuState::Off => {
            set.st[i] = CpuState::OnPending;
            Reply { x0: code(ret::SUCCESS, wide), effect: Effect::Start { index: i as u8, entry, context } }
        }
    }
}

/// `PSCI_FEATURES(fid)`: 0 for a function answered here (a feature-flags
/// word of zero: `CPU_SUSPEND` uses the original `power_state` format and no
/// OS-initiated mode), `SMCCC_VERSION` included since a guest finds SMCCC
/// through it; `NOT_SUPPORTED` for the rest.
fn features(fid: u32) -> u64 {
    let ok = match parse(fid) {
        Fid::Psci { num, wide } => psci_implemented(num, wide),
        Fid::Arch(n) => 0x8000_0000 | n == SMCCC_VERSION,
        Fid::Unknown { .. } => false,
    };
    if ok { code(ret::SUCCESS, false) } else { code(ret::NOT_SUPPORTED, false) }
}
