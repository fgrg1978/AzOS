// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86_64 thermal board object's hardware (kernel feature `thermal`):
//! CPUID, `rdmsr`/`wrmsr` and the legacy PCI config port pair, handed to
//! `azos_thermal::x86_sensor` (the temperature) and `azos_thermal::x86` (the
//! level request and the energy meter), which decide what to read and write
//! from them. x86_64 only: the other ISAs have no MSRs and no CPUID.
//!
//! The SMN window of an AMD part is the index/data pair at config offsets
//! 0x60 / 0x64 of the root complex, reached through the same legacy port pair
//! (0xCF8/0xCFC) the PCI bring-up uses. Both pairs are shared: a hart that
//! rewrites 0xCF8 between this task's two port writes would send them to
//! another function's register. `boot_hooks::pci_port_*` therefore take one
//! lock around each access, and `pci_port_indirect_read32` holds it across the
//! SMN index write and the data read; every SMN user must go through it. A
//! build without the `pci` feature has no config-space access, so an AMD part
//! reads as having no root complex and no sensor.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch::cpu::features::{decode_ident, read_cpuid, Vendor as ArchVendor};
use azos_arch::cpu::pstate;
use azos_arch::irq::{apic, encode};
use azos_arch::platform_impl::cpuid;
use azos_thermal::x86 as pc;
#[cfg(feature = "pci")]
use azos_thermal::x86_sensor::{SMN_DATA, SMN_INDEX};
use azos_thermal::x86_sensor::{self, brand_from_leaves, Kind, MsrBus, Refused, RootComplex, Vendor, X86Board, X86Cpu, X86Sensor};

/// `rdmsr` on the executing CPU.
pub(crate) struct Msr;

impl MsrBus for Msr {
    fn rdmsr(&mut self, msr: u32) -> u64 {
        azos_arch::cpu::rdmsr(msr)
    }
}

/// The root complex at `00:00.0`, over the legacy port pair.
pub(crate) struct Root;

#[cfg(feature = "pci")]
impl RootComplex for Root {
    fn vendor_id(&self) -> u16 {
        crate::boot_hooks::pci_port_read32(0, 0, 0, 0) as u16
    }
    fn smn_read(&mut self, addr: u32) -> u32 {
        // Index write and data read under the lock of the port pair: the
        // other harts' config accesses (driver enable, MSI setup, hotplug)
        // take the same lock, so neither the 0xCF8/0xCFC pair nor the SMN
        // pair is ever split by another access.
        crate::boot_hooks::pci_port_indirect_read32(0, 0, 0, SMN_INDEX, SMN_DATA, addr)
    }
}

/// No config-space access in this build (no `pci`): no root complex, so an
/// AMD part is refused with `NoRoot`.
#[cfg(not(feature = "pci"))]
impl RootComplex for Root {
    fn vendor_id(&self) -> u16 {
        u16::MAX
    }
    fn smn_read(&mut self, _addr: u32) -> u32 {
        u32::MAX
    }
}

/// The brand string, CPUID.0x80000002..4 (zeros when the CPU has none).
fn brand() -> [u8; 48] {
    if cpuid(0x8000_0000, 0).0 < 0x8000_0004 {
        return [0; 48];
    }
    let leaf = |l| {
        let (a, b, c, d) = cpuid(l, 0);
        [a, b, c, d]
    };
    brand_from_leaves([leaf(0x8000_0002), leaf(0x8000_0003), leaf(0x8000_0004)])
}

/// What the probe reads of this CPU.
fn this_cpu() -> X86Cpu {
    let leaves = read_cpuid();
    let id = decode_ident(&leaves);
    let max = cpuid(0, 0).0;
    let vendor = match id.vendor {
        ArchVendor::Intel => Vendor::Intel,
        ArchVendor::Amd => Vendor::Amd,
        ArchVendor::Hygon => Vendor::Hygon,
        ArchVendor::Unknown => Vendor::Other,
    };
    let l6_eax = if max >= 6 { cpuid(6, 0).0 } else { 0 };
    X86Cpu::from_cpuid(vendor, id.family, id.model, leaves.l1_ecx, max, l6_eax, brand())
}

/// Which sensor this machine has, or why none. CPUID first, so no MSR the CPU
/// lacks is ever read (QEMU TCG has none of them).
pub(crate) fn probe() -> Result<Kind, Refused> {
    x86_sensor::probe(&this_cpu(), &mut Msr, &Root)
}

/// The board object for one tick: the sensor `kind` over the real MSRs and
/// root complex, paired with `actuator` (`azos_thermal::x86::X86Pstate::actuator`
/// over [`KernelPlatform`]).
pub(crate) fn board<A>(kind: Kind, actuator: A) -> X86Board<Msr, Root, A> {
    X86Board { sensor: X86Sensor::new(kind, Msr, Root), actuator }
}

// ── The level request and the energy meter ──────────────────────────────────

/// What the CPU offers for moving its clock and measuring its energy
/// (`azos_arch::cpu::pstate`'s CPUID decision, never under a hypervisor), as
/// `azos_thermal::x86` names it.
pub(crate) fn pstate_hw() -> pc::Hw {
    let caps = pstate::detect();
    pc::Hw {
        perf: match caps.perf {
            pstate::Perf::None => pc::Perf::None,
            pstate::Perf::Hwp => pc::Perf::Hwp,
            pstate::Perf::Cppc => pc::Perf::Cppc,
        },
        meter: match caps.meter {
            pstate::Meter::None => pc::Meter::None,
            pstate::Meter::Intel => pc::Meter::Intel,
            pstate::Meter::Amd => pc::Meter::Amd,
        },
    }
}

/// The access to the CPU the PC board gets each tick: the register of this
/// CPU directly, another CPU's through the function-call IPI.
///
/// # Another CPU's MSR
///
/// HWP and CPPC level requests are per logical CPU, and the thermal task is
/// pinned to one. A register of another CPU is reached through
/// `encode::CALL_VECTOR`, the function-call IPI: the sender (the thermal tick,
/// which holds the board's state lock, so one at a time) posts the access,
/// sends the vector, and waits for the target's handler ([`call_ipi`], from
/// `entry/x86_64/irq.rs`) to run it and post the answer. Only the registers
/// the actuator drives may be asked this way
/// (`azos_thermal::x86::is_remote_msr`), so the handler is not a way to run an
/// arbitrary `wrmsr` on a CPU. A round trip to a CPU that takes interrupts is
/// a few microseconds; a target that does not answer within
/// [`CALL_TIMEOUT_US`] (interrupts masked on a lock, a CPU that is stopping)
/// makes the access fail; a request that was posted and not yet taken is
/// withdrawn first, so a late handler cannot run it.
///
/// The IPI interrupts the CPU for the access, a few microseconds, on a
/// request that exists only when the clock changes. A real-time CPU takes it
/// as it takes a TLB shootdown.
pub(crate) struct KernelPlatform;

impl pc::Platform for KernelPlatform {
    fn this_cpu(&self) -> usize {
        azos_sched::smp::current_cpu_id()
    }

    fn cpu_online(&self, cpu: usize) -> bool {
        azos_percpu::cpu_online(cpu)
    }

    fn rdmsr(&mut self, cpu: usize, msr: u32) -> Option<u64> {
        if cpu == self.this_cpu() {
            return Some(azos_arch::cpu::rdmsr(msr));
        }
        remote(cpu, false, msr, 0)
    }

    fn wrmsr(&mut self, cpu: usize, msr: u32, v: u64) -> bool {
        if cpu == self.this_cpu() {
            azos_arch::cpu::wrmsr(msr, v);
            return true;
        }
        remote(cpu, true, msr, v).is_some()
    }
}

/// How long a sender waits for another CPU to take its register access.
const CALL_TIMEOUT_US: u64 = 250;

/// A posted access: free, posted and not yet taken, being run, done.
const FREE: u32 = 0;
const POSTED: u32 = 1;
const RUNNING: u32 = 2;
const DONE: u32 = 3;

/// The one access in flight.
struct Call {
    state: AtomicU32,
    target: AtomicUsize,
    write: AtomicBool,
    msr: AtomicU32,
    value: AtomicU64,
    result: AtomicU64,
}

static CALL: Call = Call {
    state: AtomicU32::new(FREE),
    target: AtomicUsize::new(0),
    write: AtomicBool::new(false),
    msr: AtomicU32::new(0),
    value: AtomicU64::new(0),
    result: AtomicU64::new(0),
};

/// Run a register access on `cpu` and bring the answer back (a write answers
/// 1).
fn remote(cpu: usize, write: bool, msr: u32, value: u64) -> Option<u64> {
    if !pc::is_remote_msr(msr) || !azos_percpu::cpu_online(cpu) {
        return None;
    }
    // One sender: the thermal tick, which holds the board's `STATE` lock.
    debug_assert_eq!(CALL.state.load(Ordering::Relaxed), FREE, "one access in flight");
    CALL.target.store(cpu, Ordering::Relaxed);
    CALL.write.store(write, Ordering::Relaxed);
    CALL.msr.store(msr, Ordering::Relaxed);
    CALL.value.store(value, Ordering::Relaxed);
    CALL.state.store(POSTED, Ordering::Release);
    if !apic::send_ipi(cpu, encode::CALL_VECTOR) {
        CALL.state.store(FREE, Ordering::Release);
        return None;
    }
    let end = azos_drv_sys::timebase::now()
        .saturating_add(CALL_TIMEOUT_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000);
    loop {
        match CALL.state.load(Ordering::Acquire) {
            DONE => {
                let r = CALL.result.load(Ordering::Relaxed);
                CALL.state.store(FREE, Ordering::Release);
                return Some(r);
            }
            // Past the deadline, withdraw a request nobody took. One that is
            // being run is waited for: it is on its way out.
            POSTED if azos_drv_sys::timebase::now() >= end => {
                if CALL.state.compare_exchange(POSTED, FREE, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    return None;
                }
            }
            _ => core::hint::spin_loop(),
        }
    }
}

/// The function-call IPI's handler (`entry/x86_64/irq.rs`): take the access
/// posted for this CPU, if there is one, and answer it. Interrupt context.
pub(crate) fn call_ipi() {
    if CALL.state.load(Ordering::Acquire) != POSTED || CALL.target.load(Ordering::Relaxed) != azos_sched::smp::current_cpu_id() {
        return;
    }
    if CALL.state.compare_exchange(POSTED, RUNNING, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    let msr = CALL.msr.load(Ordering::Relaxed);
    let result = if !pc::is_remote_msr(msr) {
        0
    } else if CALL.write.load(Ordering::Relaxed) {
        azos_arch::cpu::wrmsr(msr, CALL.value.load(Ordering::Relaxed));
        1
    } else {
        azos_arch::cpu::rdmsr(msr)
    };
    CALL.result.store(result, Ordering::Relaxed);
    CALL.state.store(DONE, Ordering::Release);
}
