// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The three ISAs' guest traps decoded into one `Exit` (the decode is the
//! arch glue's; the routing of an exit to the monitor, a device model or a
//! fault comes with the guest-entry loop), and the device windows a VM keeps
//! for that routing.
//!
//! The expected values are written out from the architecture manuals (RISC-V
//! privileged spec 1.12 `htinst`, Arm ARM `ESR_ELx`, AMD APM vol. 2 appendix C
//! `EXITINFO`), not derived from the constants under test.

use crate::glue;
use azos_arch_api::{Exit, Hypervisor, MmioAccess, PioAccess, RawExit, StageAccess, RAW_ARM_IRQ};
use azos_hv::vm::{Space, VmTable};
use azos_hv::{admit, HostFacts, VirtRole};
use azos_arch_api::{HvKind, HvStatus};
use azos_topology::{parse_caps, parse_sched, Topology};

fn raw(code: u64, info: [u64; 4]) -> RawExit {
    RawExit { code, info }
}

// ── riscv64 ─────────────────────────────────────────────────────────────

const RV_EXC_INST_GPF: u64 = 20;
const RV_EXC_LOAD_GPF: u64 = 21;
const RV_EXC_STORE_GPF: u64 = 23;
const RV_EXC_ECALL_VS: u64 = 10;
const RV_EXC_VIRTUAL_INSN: u64 = 22;
const RV_INTERRUPT: u64 = 1 << 63;

/// `sw a0, 0(a1)` as the hardware transforms it for `htinst`: the opcode,
/// `funct3 = 2` (word), `rs2 = x10`, the address-offset field in place of
/// `rs1` (0: the fault is at the base address), bits 1:0 = 0b11 (32-bit).
const RV_SW_A0: u64 = (10 << 20) | (2 << 12) | 0x23;
/// `lw a2, 0(a1)`: `rd = x12`, `funct3 = 2`, opcode `0x03`.
const RV_LW_A2: u64 = (12 << 7) | (2 << 12) | 0x03;
/// `fld fa0, 0(a1)`: a floating-point load, not one a device model serves.
const RV_FLD: u64 = (10 << 7) | (3 << 12) | 0x07;

fn rv_fault(cause: u64, gpa: u64, htinst: u64) -> RawExit {
    // htval holds the guest-physical address shifted right by 2; the two
    // low bits come from stval.
    raw(cause, [gpa & 3, gpa >> 2, htinst, 0])
}

#[test]
fn riscv_a_decoded_store_is_an_mmio_access_with_the_register_it_names() {
    let hv = glue::rv::HvImpl;
    assert_eq!(
        hv.decode_exit(&rv_fault(RV_EXC_STORE_GPF, 0x1000_1050, RV_SW_A0)),
        Exit::Mmio(MmioAccess { gpa: 0x1000_1050, size: 4, write: true, reg: 10, insn_len: 4 })
    );
    assert_eq!(
        hv.decode_exit(&rv_fault(RV_EXC_LOAD_GPF, 0x1000_1000, RV_LW_A2)),
        Exit::Mmio(MmioAccess { gpa: 0x1000_1000, size: 4, write: false, reg: 12, insn_len: 4 })
    );
}

#[test]
fn riscv_what_the_hardware_did_not_decode_stays_a_fault() {
    let hv = glue::rv::HvImpl;
    // htinst = 0: the hardware gave nothing.
    assert_eq!(
        hv.decode_exit(&rv_fault(RV_EXC_STORE_GPF, 0x8000_0000, 0)),
        Exit::Fault { gpa: 0x8000_0000, access: StageAccess::Write }
    );
    // A floating-point access, and a fetch: not for a device model.
    assert_eq!(
        hv.decode_exit(&rv_fault(RV_EXC_LOAD_GPF, 0x1000_0000, RV_FLD)),
        Exit::Fault { gpa: 0x1000_0000, access: StageAccess::Read }
    );
    assert_eq!(
        hv.decode_exit(&rv_fault(RV_EXC_INST_GPF, 0x9000_0000, 0)),
        Exit::Fault { gpa: 0x9000_0000, access: StageAccess::Exec }
    );
}

#[test]
fn riscv_the_other_traps() {
    let hv = glue::rv::HvImpl;
    assert_eq!(hv.decode_exit(&raw(RV_EXC_ECALL_VS, [0; 4])), Exit::Hypercall);
    assert_eq!(hv.decode_exit(&raw(RV_INTERRUPT | 5, [0; 4])), Exit::HostInterrupt);
    // A trapped `wfi` (stval holds the instruction), and some other instruction.
    assert_eq!(hv.decode_exit(&raw(RV_EXC_VIRTUAL_INSN, [0x1050_0073, 0, 0, 0])), Exit::Wait);
    assert_eq!(hv.decode_exit(&raw(RV_EXC_VIRTUAL_INSN, [0x1800_2073, 0, 0, 0])), Exit::Other(RV_EXC_VIRTUAL_INSN));
    assert_eq!(hv.decode_exit(&raw(2, [0; 4])), Exit::Other(2));
}

// ── aarch64 ─────────────────────────────────────────────────────────────

const A64_EC_WFX: u64 = 0x01;
const A64_EC_HVC: u64 = 0x16;
const A64_EC_SYSREG: u64 = 0x18;
const A64_EC_IABT_LOWER: u64 = 0x20;
const A64_EC_DABT_LOWER: u64 = 0x24;

fn esr(ec: u64, il: u64, iss: u64) -> u64 {
    ec << 26 | il << 25 | iss
}

/// ISS of a data abort with a valid syndrome: `ISV`, `SAS` (log2 of the
/// size), `SRT`, `WnR`, and the fault status code.
fn dabt_iss(sas: u64, srt: u64, write: bool, dfsc: u64) -> u64 {
    1 << 24 | sas << 22 | srt << 16 | (write as u64) << 6 | dfsc
}

/// `FAR_EL2` carries the page offset (and junk above), `HPFAR_EL2.FIPA` the
/// page frame of the IPA in bits 43:4.
fn a64_addr(gpa: u64) -> [u64; 4] {
    [0xFFFF_0000_0000_0000 | (gpa & 0xFFF), (gpa >> 12) << 4, 0, 0]
}

#[test]
fn aarch64_a_data_abort_with_a_syndrome_is_an_mmio_access() {
    let hv = glue::arm::HvImpl;
    // Translation fault level 1 (DFSC 0b000101), a 4-byte store from x3.
    let e = raw(esr(A64_EC_DABT_LOWER, 1, dabt_iss(2, 3, true, 0b000101)), a64_addr(0x0a00_0010));
    assert_eq!(hv.decode_exit(&e), Exit::Mmio(MmioAccess { gpa: 0x0a00_0010, size: 4, write: true, reg: 3, insn_len: 4 }));
    // A byte load into x30, permission fault (DFSC 0b001111), 16-bit instruction (IL 0).
    let e = raw(esr(A64_EC_DABT_LOWER, 0, dabt_iss(0, 30, false, 0b001111)), a64_addr(0x0a00_0200));
    assert_eq!(hv.decode_exit(&e), Exit::Mmio(MmioAccess { gpa: 0x0a00_0200, size: 1, write: false, reg: 30, insn_len: 2 }));
    // 8 bytes.
    let e = raw(esr(A64_EC_DABT_LOWER, 1, dabt_iss(3, 0, true, 0b000100)), a64_addr(0x0a00_0000));
    assert!(matches!(hv.decode_exit(&e), Exit::Mmio(m) if m.size == 8));
}

#[test]
fn aarch64_without_a_syndrome_or_in_a_page_walk_it_is_a_plain_fault() {
    let hv = glue::arm::HvImpl;
    // ISV clear: the instruction was not decodable.
    let e = raw(esr(A64_EC_DABT_LOWER, 1, 1 << 6 | 0b000101), a64_addr(0x0a00_0010));
    assert_eq!(hv.decode_exit(&e), Exit::Fault { gpa: 0x0a00_0010, access: StageAccess::Write });
    // S1PTW (bit 7): the fault was on the guest's own table walk.
    let e = raw(esr(A64_EC_DABT_LOWER, 1, dabt_iss(2, 1, false, 0b000101) | 1 << 7), a64_addr(0x4000_0000));
    assert_eq!(hv.decode_exit(&e), Exit::Fault { gpa: 0x4000_0000, access: StageAccess::Read });
    // An instruction abort is a fetch.
    let e = raw(esr(A64_EC_IABT_LOWER, 1, 0b000111), a64_addr(0x4000_8000));
    assert_eq!(hv.decode_exit(&e), Exit::Fault { gpa: 0x4000_8000, access: StageAccess::Exec });
}

#[test]
fn aarch64_an_abort_that_is_not_a_stage_2_miss_is_not_decoded_as_one() {
    let hv = glue::arm::HvImpl;
    // Alignment fault (0b100001) and synchronous external abort (0b010000).
    for fsc in [0b100001u64, 0b010000] {
        let e = raw(esr(A64_EC_DABT_LOWER, 1, dabt_iss(2, 1, true, fsc)), a64_addr(0x0a00_0000));
        assert_eq!(hv.decode_exit(&e), Exit::Other(esr(A64_EC_DABT_LOWER, 1, dabt_iss(2, 1, true, fsc))), "fsc {fsc:#b}");
    }
}

#[test]
fn aarch64_the_other_traps() {
    let hv = glue::arm::HvImpl;
    assert_eq!(hv.decode_exit(&raw(esr(A64_EC_HVC, 1, 0), [0; 4])), Exit::Hypercall);
    assert_eq!(hv.decode_exit(&raw(esr(0x17, 1, 0), [0; 4])), Exit::Hypercall, "SMC");
    assert_eq!(hv.decode_exit(&raw(esr(A64_EC_WFX, 1, 0), [0; 4])), Exit::Wait);
    // ISS bit 0 is the direction: 0 is MSR (a write), 1 is MRS (a read).
    assert_eq!(hv.decode_exit(&raw(esr(A64_EC_SYSREG, 1, 0), [0; 4])), Exit::SysReg { write: true });
    assert_eq!(hv.decode_exit(&raw(esr(A64_EC_SYSREG, 1, 1), [0; 4])), Exit::SysReg { write: false });
    assert_eq!(hv.decode_exit(&raw(RAW_ARM_IRQ, [0; 4])), Exit::HostInterrupt);
    let unknown = esr(0x2F, 1, 0);
    assert_eq!(hv.decode_exit(&raw(unknown, [0; 4])), Exit::Other(unknown));
}

// ── x86_64 ──────────────────────────────────────────────────────────────

const SVM_INTR: u64 = 0x60;
const SVM_NMI: u64 = 0x61;
const SVM_CPUID: u64 = 0x72;
const SVM_HLT: u64 = 0x78;
const SVM_IOIO: u64 = 0x7B;
const SVM_MSR: u64 = 0x7C;
const SVM_SHUTDOWN: u64 = 0x7F;
const SVM_VMMCALL: u64 = 0x81;
const SVM_NPF: u64 = 0x400;

#[test]
fn x86_the_nested_fault_names_the_access() {
    let hv = glue::x86::HvImpl;
    // EXITINFO1: bit 0 present, bit 1 write, bit 4 instruction fetch.
    for (info1, access) in [(0b00u64, StageAccess::Read), (0b10, StageAccess::Write), (1 << 4, StageAccess::Exec)] {
        assert_eq!(
            hv.decode_exit(&raw(SVM_NPF, [info1, 0xFEE0_0000, 0, 0])),
            Exit::Fault { gpa: 0xFEE0_0000, access },
            "info1 {info1:#x}"
        );
    }
}

#[test]
fn x86_port_io_and_the_rest() {
    let hv = glue::x86::HvImpl;
    // EXITINFO1 of IOIO: bit 0 is 1 for IN, bit 2 string, bit 3 rep, bits 4/5/6
    // the size (1, 2, 4 bytes), port in 31:16.
    let out_byte = 0x3F8 << 16 | 1 << 4;
    assert_eq!(
        hv.decode_exit(&raw(SVM_IOIO, [out_byte, 0, 0, 0])),
        Exit::Pio(PioAccess { port: 0x3F8, size: 1, write: true, string: false, rep: false })
    );
    let in_dword_rep = 0x60 << 16 | 1 | 1 << 3 | 1 << 2 | 1 << 6;
    assert_eq!(
        hv.decode_exit(&raw(SVM_IOIO, [in_dword_rep, 0, 0, 0])),
        Exit::Pio(PioAccess { port: 0x60, size: 4, write: false, string: true, rep: true })
    );
    assert_eq!(hv.decode_exit(&raw(SVM_CPUID, [0; 4])), Exit::Cpuid);
    assert_eq!(hv.decode_exit(&raw(SVM_HLT, [0; 4])), Exit::Wait);
    assert_eq!(hv.decode_exit(&raw(SVM_VMMCALL, [0; 4])), Exit::Hypercall);
    assert_eq!(hv.decode_exit(&raw(SVM_INTR, [0; 4])), Exit::HostInterrupt);
    assert_eq!(hv.decode_exit(&raw(SVM_NMI, [0; 4])), Exit::HostInterrupt);
    assert_eq!(hv.decode_exit(&raw(SVM_SHUTDOWN, [0; 4])), Exit::Shutdown);
    assert_eq!(hv.decode_exit(&raw(u64::MAX, [0; 4])), Exit::InvalidState);
    // RDMSR is EXITINFO1 = 0, WRMSR 1.
    assert_eq!(hv.decode_exit(&raw(SVM_MSR, [0, 0, 0, 0])), Exit::SysReg { write: false });
    assert_eq!(hv.decode_exit(&raw(SVM_MSR, [1, 0, 0, 0])), Exit::SysReg { write: true });
    assert_eq!(hv.decode_exit(&raw(0x1234, [0; 4])), Exit::Other(0x1234));
}

// ── routing ─────────────────────────────────────────────────────────────

fn topology(body: &str) -> Box<Topology<'static>> {
    let sched: &'static str = "[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"cfs\"\n";
    let caps: &'static str = Box::leak(format!("format = 7\n{body}").into_boxed_str());
    let mut t = Box::new(Topology::empty());
    parse_sched(sched.as_bytes(), &mut t).unwrap();
    parse_caps(caps.as_bytes(), &mut t).unwrap_or_else(|e| panic!("{e:?}\n{body}"));
    t
}

/// A table with one admitted guest `g` (2 CPUs, 16 MiB, three backends) whose
/// first backend has an MMIO window and a port window, and whose second has
/// a port window.
fn table() -> VmTable {
    let t = topology("[guest.g]\ncpus = 2\nmem_mib = 16\nenvelope = \"full\"\ndevices = [\"virtio-blk\", \"virtio-console\", \"virtio-rng\"]\n");
    let facts = HostFacts {
        role: VirtRole::Hosted,
        hv: HvStatus::Usable(HvKind::RiscvH),
        online: 0b1111,
        rt: 0,
        free_mib: 1024,
        max_guest_mib: 1024,
    };
    let plan = admit::admit(t.guests(), &facts).unwrap();
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    let vm = vms.vm_mut(0).unwrap();
    vm.add_window(Space::Mmio, 0x1000_1000, 0x1000, 0).unwrap();
    vm.add_window(Space::Pio, 0x3F8, 8, 1).unwrap();
    vm.add_window(Space::Pio, 0x60, 4, 0).unwrap();
    vms
}

#[test]
fn windows_cannot_overlap_cover_ram_or_name_a_device_the_row_lacks() {
    use azos_hv::vm::WindowError;
    let mut vms = table();
    let vm = vms.vm_mut(0).unwrap();
    assert_eq!(vm.add_window(Space::Mmio, 0x1000_1800, 0x1000, 1), Err(WindowError::Overlap));
    assert_eq!(vm.add_window(Space::Mmio, 0x1000_0000, 0x1000_1001 - 0x1000_0000, 1), Err(WindowError::Overlap));
    // The same range in the other space is another range.
    vm.add_window(Space::Pio, 0x1000, 0x10, 2).unwrap();
    let ram = vm.ram_base;
    assert_eq!(vm.add_window(Space::Mmio, ram, 0x1000, 1), Err(WindowError::InRam));
    assert_eq!(vm.add_window(Space::Mmio, ram - 0x800, 0x1000, 1), Err(WindowError::InRam), "straddling the RAM base");
    assert_eq!(vm.add_window(Space::Mmio, 0x2000_0000, 0x1000, 3), Err(WindowError::NoSuchDevice));
    assert_eq!(vm.add_window(Space::Mmio, 0x2000_0000, 0, 1), Err(WindowError::BadRange));
    assert_eq!(vm.add_window(Space::Pio, 0xFFF0, 0x20, 1), Err(WindowError::BadRange));
}
