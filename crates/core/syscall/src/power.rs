// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Power` interface the kernel hosts: the power family, the
//! ring-3 form of the recovery console's `pm suspend`, `reboot`, `shutdown` and
//! `sched_hz`, and the energy policy, served on the `power` endpoint
//! (`azos_devif::Power`) to the `POWER.ELF` tool.
//!
//! Which right an op needs is the op's class (`READ` observes, `WRITE`
//! changes); the console's table (`azos_ipc::authority_policy`) names the same
//! commands. What changes is the table the right is read from: the CALLING
//! image's, whose topology row is the whole of its authority. The check is made
//! on every call, not only under the console lockdown.
//!
//! On a refusal nothing of the operation happens, a `SAFETY_CAP_DENIED_TYPED`
//! record is made (bounded per task, as every typed denial), and the kernel
//! prints the console's refusal line, `[AUTHORITY] <cmd> REFUSED`, only when
//! that record was actually handed to the recorder.

use azos_abi::cap::CapPerms;
use azos_abi::power::*;
use azos_devif::{outcome, Out};

use crate::khost::Caller;

/// The `Power` interface served for one caller.
pub struct Server(pub Caller);

impl Server {
    /// The caller may use op class `class` for the command `cmd`, else the
    /// refusal is recorded (and printed once handed to the recorder).
    fn gate<T: Default>(&self, class: CapPerms, cmd: &'static str) -> Result<(), Out<T>> {
        if self.0.allows(class) {
            return Ok(());
        }
        self.0.deny_cmd(class, cmd);
        Err(Out::err(outcome::DENIED))
    }
}

#[cfg(feature = "energy")]
impl Server {
    /// A setter's answer: applied, or refused by a kernel limit with its
    /// reason (recorded by the policy itself; the console line says so too).
    fn verdict(&self, op: u64, arg: u64, r: Result<(), u32>) -> Out<u32> {
        match r {
            Ok(()) => Out::ok(0),
            Err(why) => {
                azos_drv_sys::kwarn!(
                    "[ENERGY] policy op {} arg {:#x} REFUSED: reason {} (tid {}, recorded)",
                    op, arg, why, self.0.tid);
                Out::new(outcome::REFUSED, why)
            }
        }
    }
}

impl azos_devif::Power for Server {
    fn shutdown(&mut self) -> Out<()> {
        if let Err(o) = self.gate(CapPerms::WRITE, "shutdown") {
            return o;
        }
        azos_drv_sys::kprintln!("[POWER] shutdown by tid {} (ring 3)", self.0.tid);
        crate::handlers::power_off_orderly()
    }

    fn reboot(&mut self) -> Out<()> {
        if let Err(o) = self.gate(CapPerms::WRITE, "reboot") {
            return o;
        }
        azos_drv_sys::kprintln!("[POWER] reboot by tid {} (ring 3)", self.0.tid);
        crate::handlers::reboot_orderly()
    }

    fn suspend(&mut self) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "pm suspend") {
            return o;
        }
        azos_drv_sys::kprintln!("[PM] Entering suspend... (tid {}, ring 3)", self.0.tid);
        let domain = azos_ipc::cap_store::domain_key_of(self.0.tid);
        match azos_drv_power::pm::pm_suspend(self.0.tid, domain) {
            0 => {
                azos_drv_sys::kprintln!("[PM] Resumed from suspend (tid {})", self.0.tid);
                Out::ok(0)
            }
            why => {
                azos_drv_sys::kwarn!("[PM] suspend REFUSED: reason {} (tid {}, recorded)", why, self.0.tid);
                // The caller gets the reason too (`Reason::code`), as the setters do.
                Out::new(outcome::REFUSED, why)
            }
        }
    }

    fn sched_hz(&self) -> Out<u64> {
        if let Err(o) = self.gate(CapPerms::READ, "sched_hz") {
            return o;
        }
        Out::ok(azos_drv_sys::timebase::sched_hz_get() as u64)
    }

    fn set_sched_hz(&mut self, hz: u64) -> Out<()> {
        if let Err(o) = self.gate(CapPerms::WRITE, "sched_hz set") {
            return o;
        }
        if !(POWER_SCHED_HZ_MIN..=POWER_SCHED_HZ_MAX).contains(&hz) {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        azos_drv_sys::timebase::sched_hz_set(hz);
        azos_drv_sys::kprintln!("[SCHED] Scheduler rate set to {} Hz (tid {}, ring 3)", hz, self.0.tid);
        Out::ok(())
    }

    fn set_governor(&mut self, gov: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            self.verdict(POWER_OP_POLICY_GOVERNOR, gov as u64, azos_sched::energy::policy_set_governor(gov).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = gov;
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn set_opp_range(&mut self, domain: u32, min: u32, max: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        if domain > 0xFF || min > 0xFF || max > 0xFF {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        #[cfg(feature = "energy")]
        {
            let arg = domain as u64 | (min as u64) << 8 | (max as u64) << 16;
            self.verdict(POWER_OP_POLICY_OPP_RANGE, arg, azos_sched::energy::policy_set_opp_range(domain, min, max).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        Out::err(outcome::UNSUPPORTED)
    }

    fn set_headroom(&mut self, pct: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            self.verdict(POWER_OP_POLICY_HEADROOM, pct as u64, azos_sched::energy::policy_set_headroom(pct).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = pct;
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn set_rate_limit(&mut self, us: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            self.verdict(POWER_OP_POLICY_RATE_LIMIT, us as u64, azos_sched::energy::policy_set_rate_limit(us).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = us;
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn set_idle_depth(&mut self, depth: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            self.verdict(POWER_OP_POLICY_IDLE_DEPTH, depth as u64, azos_sched::energy::policy_set_idle_depth(depth).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = depth;
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn set_power_cap(&mut self, domain: u32, mw: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        if domain > 0xFF || mw > 0xFF_FFFF {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        #[cfg(feature = "energy")]
        {
            let arg = domain as u64 | (mw as u64) << 8;
            self.verdict(POWER_OP_POLICY_POWER_CAP, arg, azos_sched::energy::policy_set_power_cap(domain, mw).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        Out::err(outcome::UNSUPPORTED)
    }

    fn set_parked(&mut self, mask: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            self.verdict(POWER_OP_POLICY_PARK, mask as u64, azos_sched::energy::policy_set_parked(mask).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = mask;
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn set_qos_domains(&mut self, class: u32, domains: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        if class > 0xFF || domains > 0xFF_FFFF {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        #[cfg(feature = "energy")]
        {
            let arg = class as u64 | (domains as u64) << 8;
            self.verdict(POWER_OP_POLICY_QOS_DOMAINS, arg, azos_sched::energy::policy_set_qos_domains(class, domains).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        Out::err(outcome::UNSUPPORTED)
    }

    fn report_battery(&mut self, soc_pct: u32, level: u32) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        if soc_pct > 0xFF || level > 0xFF {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        #[cfg(feature = "energy")]
        {
            let arg = soc_pct as u64 | (level as u64) << 8;
            self.verdict(POWER_OP_POLICY_BATTERY, arg, azos_sched::energy::policy_report_battery(soc_pct, level).map_err(|w| w.code() as u32))
        }
        #[cfg(not(feature = "energy"))]
        Out::err(outcome::UNSUPPORTED)
    }

    fn cpu_online(&mut self, cpu: u32, on: u32) -> Out<u32> {
        // A power-policy setter as far as the right goes (`WRITE`, the console's
        // `power policy set`).
        if let Err(o) = self.gate(CapPerms::WRITE, "power policy set") {
            return o;
        }
        if on > 1 {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if !azos_limits::CPU_HOTPLUG {
            return Out::err(outcome::UNSUPPORTED);
        }
        // The change is recorded (rule `cpu-hotplug`) and printed by the
        // scheduler's hotplug path, refusal included.
        let r = if on == 0 {
            azos_sched::smp::cpu_offline(cpu as usize)
        } else {
            azos_sched::smp::cpu_online(cpu as usize)
        };
        match r {
            Ok(n) => Out::ok(n as u32),
            Err(why) => Out::new(outcome::REFUSED, why.code()),
        }
    }

    fn sync(&mut self) -> Out<u32> {
        if let Err(o) = self.gate(CapPerms::WRITE, "sync") {
            return o;
        }
        // The same sync the orderly power-off runs (`FileOps::sync_all`).
        let r = crate::file_ops::file_ops().map(|o| o.sync_all()).unwrap_or_default();
        azos_drv_sys::kprintln!("[POWER] sync by tid {}: {} volume(s) synced, {} failed, {} timed out",
            self.0.tid, r.volumes, r.failed, r.timed_out);
        match r.failed + r.timed_out {
            0 => Out::ok(r.volumes),
            bad => Out::new(outcome::FAULT, bad),
        }
    }

    fn state(&self, sel: u32) -> Out<u64> {
        if let Err(o) = self.gate(CapPerms::READ, "power policy get") {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            azos_sched::energy::policy_state(sel as u64).map_or(Out::err(outcome::BAD_ARGUMENT), Out::ok)
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = sel;
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn stats(&self, sel: u32) -> Out<u64> {
        if let Err(o) = self.gate(CapPerms::READ, "power policy get") {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            azos_sched::energy::policy_stats(sel as u64).map_or(Out::err(outcome::BAD_ARGUMENT), Out::ok)
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = sel;
            Out::err(outcome::UNSUPPORTED)
        }
    }
}
