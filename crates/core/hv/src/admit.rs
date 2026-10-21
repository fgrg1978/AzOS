// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot admission of the topology's guest rows.
//!
//! The rows are parsed and verified by the topology (names unique, CPUs and
//! memory present, an envelope on every row); what is left is whether *this
//! machine, in this role* can host them. [`admit`] answers once, before any
//! VM exists, from facts the boot hands it ([`HostFacts`]):
//!
//! * the role (Kconfig `VIRT`): a `none` kernel hosts nothing, so rows are
//!   refused as a set rather than half-run;
//! * the hardware ([`HvStatus`]): no extension, no guests (a boot line says
//!   why; the kernel boots on unless Kconfig `HV_REQUIRE` says otherwise);
//! * the harts: vCPUs may use the harts that hold no deadline reservation
//!   ([`crate::vcpu::allowed`]); a static partition pins each vCPU to a hart
//!   of its own, hosted and split share them;
//! * the memory the rows ask for against what the host has free, and against
//!   what the memory-object table can describe (guest RAM is MemObj frames,
//!   [`HostFacts::max_guest_mib`]);
//! * the backends the rows list, against those someone serves.
//!
//! It records nothing in the decision ring: no admission rule is reserved
//! for guests, and an admission is a boot line, not a runtime refusal.

use azos_arch_api::HvStatus;
use azos_topology::GuestSpec;

use crate::backend::Backend;
use crate::vm::{MAX_VCPUS, MAX_VMS};

/// Does a device model exist for backend `name`? The names are
/// [`crate::backend::Backend`]'s; a name outside it is a device nobody will
/// serve and the row is refused at admission.
pub fn is_known_device(name: &[u8]) -> bool {
    Backend::from_name(name).is_some()
}

/// The hypervisor role of the image (Kconfig `VIRT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtRole {
    /// The kernel hosts no guest.
    None,
    /// Guests run beside the kernel; vCPUs share harts.
    Hosted,
    /// A resident monitor under the kernel; vCPUs share harts.
    Split,
    /// Pinned guests fixed at build time: a hart per vCPU.
    Static,
}

impl VirtRole {
    pub const fn name(self) -> &'static str {
        match self {
            VirtRole::None => "none",
            VirtRole::Hosted => "hosted",
            VirtRole::Split => "split",
            VirtRole::Static => "static",
        }
    }
}

/// What the machine offers.
#[derive(Clone, Copy, Debug)]
pub struct HostFacts {
    pub role: VirtRole,
    pub hv: HvStatus,
    /// Bit `n`: hart `n` is online.
    pub online: u64,
    /// Bit `n`: hart `n` holds a deadline reservation (the topology's real-time rows).
    pub rt: u64,
    /// MiB the host can give to guests now (free memory net of the kernel's reserve).
    pub free_mib: u64,
    /// MiB of guest RAM the memory-object table can describe: guest RAM is
    /// MemObj frames, a MemObj holds a bounded number of pages and the table
    /// a bounded number of objects, shared with everything else that has one.
    pub max_guest_mib: u64,
}

/// Why the rows were not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The image's role is `none`.
    RoleNone,
    /// The CPU has no usable extension (the reason as the probe words it).
    NoHypervisor(&'static str),
    /// More VMs than the table.
    TooManyVms { rows: usize, room: usize },
    /// More vCPUs than the pool (Kconfig `HV_MAX_VCPUS`).
    TooManyVcpus { need: u32, room: usize },
    /// Every online hart holds a deadline reservation.
    NoHart,
    /// A static partition wants a hart per vCPU and there are fewer.
    NotEnoughHarts { need: u32, have: u32 },
    /// The rows ask for more memory than the host has.
    Memory { need_mib: u64, free_mib: u64 },
    /// The rows' RAM is more than the memory-object table can describe.
    RamCeiling { need_mib: u64, max_mib: u64 },
    /// A row lists a backend nobody serves.
    UnknownDevice { guest: u8, device: u8 },
}

/// A plan the table installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub guests: u8,
    /// vCPUs over all rows.
    pub vcpus: u16,
    /// MiB over all rows.
    pub mem_mib: u64,
    /// Harts each guest's vCPUs may run on: the non-real-time online harts
    /// for hosted and split, the guest's own for static.
    pub affinity: [u64; MAX_VMS],
    /// Static: vCPU `n` of a guest is pinned to the `n`-th hart of its mask,
    /// not free to take any of them.
    pub pinned: bool,
}

/// Admit `rows` on a machine described by `facts`. No rows is always an
/// empty plan: a kernel with the hypervisor built in and no guest declared
/// has nothing to refuse.
pub fn admit(rows: &[GuestSpec<'_>], facts: &HostFacts) -> Result<Admitted, Refusal> {
    let mut plan = Admitted { guests: 0, vcpus: 0, mem_mib: 0, affinity: [0; MAX_VMS], pinned: false };
    if rows.is_empty() {
        return Ok(plan);
    }
    if facts.role == VirtRole::None {
        return Err(Refusal::RoleNone);
    }
    if let HvStatus::Absent(why) = facts.hv {
        return Err(Refusal::NoHypervisor(why));
    }
    if rows.len() > MAX_VMS {
        return Err(Refusal::TooManyVms { rows: rows.len(), room: MAX_VMS });
    }
    let usable = facts.online & !facts.rt;
    if usable == 0 {
        return Err(Refusal::NoHart);
    }
    let vcpus: u32 = rows.iter().map(|r| r.cpus as u32).sum();
    if vcpus as usize > MAX_VCPUS {
        return Err(Refusal::TooManyVcpus { need: vcpus, room: MAX_VCPUS });
    }
    let mem: u64 = rows.iter().map(|r| r.mem_mib as u64).sum();
    if mem > facts.free_mib {
        return Err(Refusal::Memory { need_mib: mem, free_mib: facts.free_mib });
    }
    if mem > facts.max_guest_mib {
        return Err(Refusal::RamCeiling { need_mib: mem, max_mib: facts.max_guest_mib });
    }
    for (g, r) in rows.iter().enumerate() {
        for (d, name) in r.devices().iter().enumerate() {
            if !is_known_device(name.as_bytes()) {
                return Err(Refusal::UnknownDevice { guest: g as u8, device: d as u8 });
            }
        }
    }
    if facts.role == VirtRole::Static {
        let have = usable.count_ones();
        if vcpus > have {
            return Err(Refusal::NotEnoughHarts { need: vcpus, have });
        }
        plan.pinned = true;
        // Each guest takes the next free harts, lowest first.
        let mut free = usable;
        for (g, r) in rows.iter().enumerate() {
            for _ in 0..r.cpus {
                let h = free.trailing_zeros();
                free &= !(1u64 << h);
                plan.affinity[g] |= 1u64 << h;
            }
        }
    } else {
        for a in plan.affinity.iter_mut().take(rows.len()) {
            *a = usable;
        }
    }
    plan.guests = rows.len() as u8;
    plan.vcpus = vcpus as u16;
    plan.mem_mib = mem;
    Ok(plan)
}
