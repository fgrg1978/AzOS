// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The privileged families the kernel hosts (wave 12, RFC-0055 S5; endpoint
//! interfaces since D6 part A): `Flight`, `Behavior`, `Config` and `Ota`, the
//! ring-3 forms of the recovery console's `flight`, `behavior`, `config` and
//! `ota` commands, for the `FLIGHT.ELF`, `BEHAVIOR.ELF`, `CONFIG.ELF` and
//! `OTA.ELF` tools.
//!
//! As `power`: the right an op needs is its class (`READ` observes, `WRITE`
//! changes), checked FIRST, over the CALLING image's capability, on every call;
//! a refusal is recorded and does nothing. The console's table
//! (`azos_ipc::authority_policy`) names the same commands.
//!
//! **The operations are the console's own code**, reached through
//! [`FamilyOps`], which the kernel installs at boot over
//! `crates/core/shell`'s family functions -- the same functions the
//! console's commands call. This crate is core and cannot name the shell.
//! Without an installed implementation (a kernel built without the Robot
//! domain for flight/behavior) an op answers `UNSUPPORTED` after the right
//! check.

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_abi::families::*;
use azos_devif::families::{BEHAVIOR_LAYERS, KEY_MAX, KEY_WORDS, VALUE_MAX, VALUE_WORDS};
use azos_devif::{outcome, Out};
use azos_sync::SpinLock;

use crate::khost::Caller;

/// The family operations, implemented by the kernel over the console's code.
/// Each answers as the syscall does: 0 or a value, or a negative errno. The
/// capability has been checked before any of these runs.
pub trait FamilyOps: Sync {
    /// `FLIGHT_OP_ARM` / `FLIGHT_OP_DISARM`. `-ENOSYS` without the Robot domain.
    fn flight(&self, op: u64) -> i64;
    /// `BEHAVIOR_OP_*` on a validated `layer` (0 for the status read).
    fn behavior(&self, op: u64, layer: u64) -> i64;
    /// `config get`: the value of `key` into `out`; its length.
    fn config_get(&self, key: &[u8], out: &mut [u8]) -> i64;
    /// `config set` + apply.
    fn config_set(&self, key: &[u8], val: &[u8]) -> i64;
    /// `OTA_OP_STATUS` (the packed word) / `OTA_OP_ROLLBACK`.
    fn ota(&self, op: u64) -> i64;
}

static FAMILY_OPS: SpinLock<Option<&'static dyn FamilyOps>> = SpinLock::new(None);

/// Install the family operations (kernel boot, `boot/seams.rs`).
pub fn set_family_ops(ops: &'static dyn FamilyOps) {
    *FAMILY_OPS.lock() = Some(ops);
}

/// Back to "nothing installed". Host tests only.
#[cfg(test)]
pub fn __family_ops_clear_for_tests() {
    *FAMILY_OPS.lock() = None;
}

fn family_ops() -> Option<&'static dyn FamilyOps> {
    *FAMILY_OPS.lock()
}

fn errno(e: Errno) -> i64 {
    e.to_syscall_ret()
}

/// The outcome an op's family answer means: 0 and positive values are served,
/// `-ENOSYS` is a build without the domain, `-ENOENT` an unset key, the rest
/// a failure of the operation.
fn outcome_of(r: i64) -> u32 {
    if r >= 0 {
        outcome::OK
    } else if r == errno(Errno::ENOSYS) {
        outcome::UNSUPPORTED
    } else if r == errno(Errno::ENOENT) {
        outcome::NO_RESOURCE
    } else if r == errno(Errno::EINVAL) {
        outcome::BAD_ARGUMENT
    } else if r == errno(Errno::EACCES) {
        outcome::REFUSED
    } else {
        outcome::FAULT
    }
}

/// The class check of every op: `Ok`, or the refusal answer (recorded, and
/// printed as the console prints it).
fn gate<T: Default>(who: &Caller, class: CapPerms, cmd: &'static str) -> Result<(), Out<T>> {
    if who.allows(class) {
        return Ok(());
    }
    who.deny_cmd(class, cmd);
    Err(Out::err(outcome::DENIED))
}

/// The bytes of NUL-padded little-endian words, up to the first NUL.
fn unpack<'a>(words: &[u64], buf: &'a mut [u8]) -> &'a [u8] {
    for (i, w) in words.iter().enumerate() {
        buf[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..n]
}

/// The `Flight` interface served for one caller.
pub struct FlightServer(pub Caller);

impl FlightServer {
    fn run(&self, op: u64, cmd: &'static str) -> Out<()> {
        if let Err(o) = gate(&self.0, CapPerms::WRITE, cmd) {
            return o;
        }
        match family_ops() {
            Some(ops) => {
                azos_drv_sys::kprintln!("[FLIGHT] {} by tid {} (ring 3)", cmd, self.0.tid);
                Out::new(outcome_of(ops.flight(op)), ())
            }
            None => Out::err(outcome::UNSUPPORTED),
        }
    }
}

impl azos_devif::Flight for FlightServer {
    fn arm(&mut self) -> Out<()> {
        self.run(FLIGHT_OP_ARM, "flight arm")
    }
    fn disarm(&mut self) -> Out<()> {
        self.run(FLIGHT_OP_DISARM, "flight disarm")
    }
}

/// The `Behavior` interface served for one caller.
pub struct BehaviorServer(pub Caller);

impl BehaviorServer {
    fn switch(&self, op: u64, layer: u32, cmd: &'static str) -> Out<()> {
        if let Err(o) = gate(&self.0, CapPerms::WRITE, cmd) {
            return o;
        }
        if !(1..BEHAVIOR_LAYERS).contains(&layer) {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        match family_ops() {
            Some(ops) => Out::new(outcome_of(ops.behavior(op, layer as u64)), ()),
            None => Out::err(outcome::UNSUPPORTED),
        }
    }
}

impl azos_devif::Behavior for BehaviorServer {
    fn enable(&mut self, layer: u32) -> Out<()> {
        self.switch(BEHAVIOR_OP_ENABLE, layer, "behavior enable")
    }
    fn disable(&mut self, layer: u32) -> Out<()> {
        self.switch(BEHAVIOR_OP_DISABLE, layer, "behavior disable")
    }
    fn status(&self) -> Out<u64> {
        if let Err(o) = gate(&self.0, CapPerms::READ, "behavior status") {
            return o;
        }
        match family_ops() {
            Some(ops) => {
                let r = ops.behavior(BEHAVIOR_OP_STATUS, 0);
                if r < 0 { Out::err(outcome_of(r)) } else { Out::ok(r as u64) }
            }
            None => Out::err(outcome::UNSUPPORTED),
        }
    }
}

/// The `Config` interface served for one caller.
pub struct ConfigServer(pub Caller);

impl azos_devif::Config for ConfigServer {
    fn get(&self, key: [u64; KEY_WORDS]) -> Out<[u64; VALUE_WORDS]> {
        if let Err(o) = gate(&self.0, CapPerms::READ, "config get") {
            return o;
        }
        let mut kb = [0u8; KEY_MAX];
        let k = unpack(&key, &mut kb);
        if k.is_empty() {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let Some(ops) = family_ops() else { return Out::err(outcome::UNSUPPORTED) };
        let mut val = [0u8; CONFIG_VAL_MAX as usize];
        let n = ops.config_get(k, &mut val);
        if n < 0 {
            return Out::err(outcome_of(n));
        }
        let n = n as usize;
        if n > VALUE_MAX {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        // Bytes past the value are zero, so the NUL padding is the length.
        let mut bytes = [0u8; VALUE_MAX];
        bytes[..n].copy_from_slice(&val[..n]);
        let mut out = [0u64; VALUE_WORDS];
        for (o, c) in out.iter_mut().zip(bytes.chunks_exact(8)) {
            *o = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
        }
        Out::ok(out)
    }

    fn set(&mut self, key: [u64; KEY_WORDS], value: [u64; VALUE_WORDS]) -> Out<()> {
        if let Err(o) = gate(&self.0, CapPerms::WRITE, "config set") {
            return o;
        }
        let mut kb = [0u8; KEY_MAX];
        let k = unpack(&key, &mut kb);
        let mut vb = [0u8; VALUE_MAX];
        let v = unpack(&value, &mut vb);
        if k.is_empty() || v.is_empty() {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let Some(ops) = family_ops() else { return Out::err(outcome::UNSUPPORTED) };
        let r = ops.config_set(k, v);
        if r == 0 {
            azos_drv_sys::kprintln!("[CFG] set by tid {} (ring 3)", self.0.tid);
        }
        Out::new(outcome_of(r), ())
    }
}

/// The `Ota` interface served for one caller.
pub struct OtaServer(pub Caller);

impl azos_devif::Ota for OtaServer {
    fn status(&self) -> Out<u64> {
        if let Err(o) = gate(&self.0, CapPerms::READ, "ota status") {
            return o;
        }
        match family_ops() {
            Some(ops) => {
                let r = ops.ota(OTA_OP_STATUS);
                if r < 0 { Out::err(outcome_of(r)) } else { Out::ok(r as u64) }
            }
            None => Out::err(outcome::UNSUPPORTED),
        }
    }

    fn rollback(&mut self) -> Out<u32> {
        if let Err(o) = gate(&self.0, CapPerms::WRITE, "ota rollback") {
            return o;
        }
        match family_ops() {
            Some(ops) => {
                let r = ops.ota(OTA_OP_ROLLBACK);
                if r < 0 { Out::err(outcome_of(r)) } else { Out::ok(r as u32) }
            }
            None => Out::err(outcome::UNSUPPORTED),
        }
    }
}
