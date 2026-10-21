// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hypervisor's boot step (Kconfig `VIRT`, hypervisor plan step H1).
//!
//! The CPU's extension was probed earlier, by the ISA's own boot hooks (the
//! `[HV]` line says what each found); here the *role* meets the topology:
//! the signed file's `[guest.NAME]` rows are admitted (`azos_hv::admit`)
//! against this machine's harts, free memory and backends, and the accepted
//! ones become the monitor's VMs (`azos_syscall::vm::install`). Nothing is
//! created: a VM owns no memory until its owner calls `create` on its
//! endpoint, and no guest runs before the guest-boot step.
//!
//! A rejection is a boot line, not a halt, unless Kconfig `HV_REQUIRE` says
//! the image is useless without its hypervisor (a static partition): then a
//! CPU that cannot host guests stops the boot, like any `require` extension.
//! No decision record is written for an admission: no rule is reserved for
//! one.

use core::fmt::Write;

use azos_arch::HvImpl;
use azos_arch_api::{HvStatus, Hypervisor};
use azos_drv_sys::kprintln;
use azos_hv::admit::{admit, HostFacts, VirtRole};

static HV: HvImpl = HvImpl;

/// The role Kconfig `VIRT` chose.
const fn role() -> VirtRole {
    if azos_limits::VIRT_STATIC {
        VirtRole::Static
    } else if azos_limits::VIRT_SPLIT {
        VirtRole::Split
    } else if azos_limits::VIRT_HOSTED {
        VirtRole::Hosted
    } else {
        VirtRole::None
    }
}

/// Bit `n`: hart `n` of `num_cpus`.
fn online_mask(num_cpus: usize) -> u64 {
    if num_cpus >= 64 { u64::MAX } else { (1u64 << num_cpus) - 1 }
}

/// The harts the topology's deadline reservations were placed on.
fn rt_mask(topo: &azos_topology::Topology<'static>, num_cpus: usize) -> u64 {
    match topo.deadline_admission(num_cpus) {
        Ok(r) => r.placement[..(r.placed as usize).min(r.placement.len())]
            .iter()
            .fold(0u64, |m, &(_, cpu)| m | 1u64.checked_shl(cpu as u32).unwrap_or(0)),
        // The topology was admitted already; an error here is a CPU count that
        // changed under it. Treat every hart as reserved: no guest runs.
        Err(_) => online_mask(num_cpus),
    }
}

/// MiB the guests may have: what is free, less the kernel's reserve and what
/// the topology's ring-3 rows will need (counting every row as one that
/// forks, the larger estimate: the guests must not take what a task was
/// admitted to), plus the guests' own RAM, which the row of `VMMD.ELF`
/// budgets (`rows`; `VMMD.ELF` does not fork) and the need counted.
fn free_mib(topo: &azos_topology::Topology<'static>, rows: &[azos_topology::GuestSpec<'_>]) -> u64 {
    let page = azos_arch_api::PAGE_SIZE as u64;
    let free = azos_topology::units_for(azos_mm::pmm::free_pages() as u64, page);
    let reserve = (azos_limits::MEM_KERNEL_RESERVE_KB as u64).div_ceil(4)
        + azos_topology::units_for(azos_limits::MAX_TASKS as u64, page);
    let is_vmmd = |t: &azos_topology::TaskSpec<'_>| t.name.as_bytes() == azos_topology::builder::TASK_VMMD_IMAGE;
    let need = match topo.memory_admission(free, reserve, azos_topology::RING3_DEFAULT_PAGES, &|t| !is_vmmd(t)) {
        Ok(m) => m.need,
        Err(_) => free,
    };
    let guests = azos_topology::builder::vmmd_pages(rows) - azos_topology::builder::VMMD_MEM_PAGES as u64;
    // Topology pages are 4 KiB.
    free.saturating_sub(need).saturating_add(guests) / 256
}

/// MiB of guest RAM the memory-object table can describe. Guest RAM is MemObj
/// frames `VMMD.ELF` creates and charges to its own Domain (the kernel pins
/// them and holds a reference until `destroy`, `azos_hv::stage2` maps them):
/// `MAX_MEMOBJ_PAGES` pages an object, and the guests may take half of the
/// table's `MAX_MEMOBJS` slots (the rest is the tracer's, the introspection
/// tree's and the tasks'). The hypervisor defconfigs raise `MAX_MEMOBJS` so
/// that a row can ask for a useful guest.
fn max_guest_mib() -> u64 {
    let objects = (azos_limits::MAX_MEMOBJS as u64) / 2;
    (objects * azos_ipc::MAX_MEMOBJ_PAGES as u64 * azos_arch_api::PAGE_SIZE as u64) >> 20
}

/// Admit the topology's guest rows and install the monitor.
pub(crate) fn install_hv(num_cpus: usize) {
    let role = role();
    let status = HV.status();
    if let HvStatus::Absent(why) = status {
        if azos_limits::HV_REQUIRE {
            super::isa::refuse(|w| write!(w, "[HV] role {}: no hypervisor ({}) and HV_REQUIRE is set", role.name(), why));
        }
    }
    let Some(topo) = azos_topology::get() else { return };
    let rows = topo.guests();
    if rows.is_empty() {
        kprintln!("[HV] role {}: {}; no [guest.*] row declared", role.name(), describe(status));
        return;
    }
    // The guests' RAM is made by `VMMD.ELF` and charged to its Domain: its row
    // has to budget it, or the guest would end with a RAM that is partial.
    let need = azos_topology::builder::vmmd_pages(rows);
    let have = topo
        .row_mem(azos_topology::builder::TASK_VMMD_IMAGE, None, azos_topology::RING3_DEFAULT_PAGES)
        .map_or(0, |m| m.limit as u64);
    if have < need {
        kprintln!(
            "[HV] role {}: guests NOT admitted ({} row(s)): the VMMD.ELF row budgets {} pages and its own frames plus the guests' RAM are {}",
            role.name(), rows.len(), have, need
        );
        return;
    }
    let (online, rt) = (online_mask(num_cpus), rt_mask(topo, num_cpus));
    let facts = HostFacts { role, hv: status, online, rt, free_mib: free_mib(topo, rows), max_guest_mib: max_guest_mib() };
    match admit(rows, &facts) {
        Ok(plan) => match azos_syscall::vm::install(&HV, rows, &plan, online, rt) {
            Ok(()) => {
                kprintln!(
                    "[HV] role {}: {} guest(s) admitted: {} vCPU(s) on harts {:#x} (real-time harts {:#x} excluded), {} MiB",
                    role.name(), plan.guests, plan.vcpus, online & !rt, rt, plan.mem_mib
                );
                for (i, g) in rows.iter().enumerate() {
                    kprintln!(
                        "[HV] guest {} ({}): {} cpus, {} MiB, envelope {}, {} backend(s); endpoint vm.{}",
                        i, g.name.as_str(), g.cpus, g.mem_mib, g.envelope.as_str(), g.devices_len, i
                    );
                }
            }
            Err(e) => kprintln!("[HV] role {}: guests admitted but the monitor refused them: {:?}", role.name(), e),
        },
        Err(r) => kprintln!("[HV] role {}: guests NOT admitted ({} row(s)): {:?}", role.name(), rows.len(), r),
    }
}

fn describe(s: HvStatus) -> &'static str {
    match s {
        HvStatus::Usable(k) => k.name(),
        HvStatus::Absent(why) => why,
    }
}
