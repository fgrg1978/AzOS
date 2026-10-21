// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! The hypervisor core (hypervisor plan step H1: admission, VM objects, guest
//! memory, and the vCPU loop that serves a guest's device accesses).
//!
//! A guest is a virtual machine the signed topology declares (`[guest.NAME]`,
//! CAPS.TOML format 7). The monitor here is what is the same on the three
//! ISAs; what differs is behind [`azos_arch_api::Hypervisor`] (RISC-V H, ARM
//! EL2, AMD SVM), and the kernel objects it uses (MemObjs, the event port, the
//! thread of a vCPU) are the callers'. Nothing here touches hardware or the
//! scheduler, so the whole core runs under the host tests
//! (`tests/host/hv-tests`, and `tests/host/vmmd-tests` for the far end of the
//! trap ring).
//!
//! | module        | what it holds |
//! |---------------|---------------|
//! | [`admit`]     | the boot admission of the guest rows: role, hardware, harts, memory, backends |
//! | [`vm`]        | [`Vm`] and the table of them: lifecycle, stage-2 root, RAM and trap page attached, device windows, start / stop of the vCPUs |
//! | [`vcpu`]      | [`Vcpu`]: its hart set, pending interrupt lines and run state; the rule that keeps real-time harts clear of it |
//! | [`backend`]   | the backends a row names, and the envelope's ceiling on their reach |
//! | [`run`]       | the vCPU loop: enter, route the exit, post a trap to the device model, wait for its answer |
//! | [`ring`]      | the monitor's end of the trap and completion rings |
//! | [`trapwire`]  | the wire form of those rings, shared with `VMMD.ELF` |
//! | [`stage2`]    | guest-physical mapping over the frames of a MemObj (a [`stage2::FrameSource`]) |
//! | [`vlapic`]    | the virtual local APIC of an x86 guest vCPU: x2APIC / xAPIC registers, priority and EOI, the timer, IPIs |
//! | [`vioapic`]   | the virtual IOAPIC of an x86 guest: redirection table, edge / level lines, EOI broadcast |
//! | [`vplic`]     | the virtual PLIC of a RISC-V guest: priorities, enables, thresholds, claim / complete, one external line per vCPU |
//!
//! # What is still the guest-boot step's (S6)
//!
//! * The ISAs' entry primitive behind [`azos_arch_api::Hypervisor::enter`]:
//!   riscv64's is wired (`can_enter` is true where H is usable; its CSR half
//!   awaits a hart with H, the S6 QEMU row); aarch64's and x86_64's are not
//!   (`can_enter` is false), so a vCPU is refused, not started. The loop, the
//!   routing and the rings are tested here against an ISA that scripts its
//!   exits.
//! * Serving the exits a booting guest causes besides device accesses
//!   (hypercalls, CPUID, system registers, port I/O): [`run`] faults the vCPU
//!   on them, visibly.
//!
//! # Placement of a guest's pieces
//!
//! * A **vCPU may use** the harts that hold no deadline reservation
//!   ([`vcpu::allowed`]): a guest is untrusted code, and a deadline task's CPU
//!   is spoken for by its reservation. Admission applies the rule to the
//!   topology's placement, `Vcpu::set_affinity` to every mask a caller asks
//!   for and [`vcpu::pick_hart`] to the hart a started vCPU's thread is
//!   created on.
//! * A **guest holds no warrant.** The device models that serve its devices
//!   are a ring-3 task and hold theirs; what the guest causes through them is
//!   held to the VM's envelope at the trap ([`backend::allows`]).
//! * Data moves through rings ([`trapwire`]); the calls are authority
//!   (attach, start, stop) and the sleep on the event port.

pub mod admit;
pub mod backend;
pub mod ring;
pub mod run;
pub mod stage2;
pub mod trapwire;
pub mod vcpu;
pub mod vioapic;
pub mod vlapic;
pub mod vplic;
pub mod vm;

pub use admit::{Admitted, HostFacts, Refusal, VirtRole};
pub use vcpu::Vcpu;
pub use vm::{Vm, VmState, VmTable};
