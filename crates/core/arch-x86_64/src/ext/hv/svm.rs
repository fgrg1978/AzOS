// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AMD SVM: the VMCB and its encoders (AMD APM vol. 2, chapter 15 and
//! appendix B; the offsets are Linux's `struct vmcb_control_area` and
//! `vmcb_save_area` from `arch/x86/include/asm/svm.h`, each pinned by a host
//! test).
//!
//! A VMCB is one 4 KiB page: the control area in bytes `0..0x400`, the state
//! save area from `0x400`. The accessors read and write little-endian
//! fields at fixed offsets ([`off`]); a typed `struct` would only repeat
//! the table and hide which offset a bug is at.
//!
//! What `VMRUN` checks before it enters the guest, plus this port's policy
//! (a guest never gets the host's I/O ports or MSRs by default), is
//! [`Vmcb::check`]: the hardware answer to a violation is `VMEXIT_INVALID`
//! with no hint, so the monitor asks first.

/// Page size of a VMCB, a VM_HSAVE area and a nested-page-table page.
pub const PAGE: usize = 4096;
/// The I/O permission map: one bit per port, 64 Ki ports plus the spill page.
pub const IOPM_BYTES: usize = 3 * PAGE;
/// The MSR permission map: two bits (read, write) per MSR in three ranges.
pub const MSRPM_BYTES: usize = 2 * PAGE;

/// Field offsets, bytes from the start of the VMCB.
pub mod off {
    /// Intercepts: CR reads (15:0) and writes (31:16).
    pub const INTERCEPT_CR: usize = 0x00;
    /// Intercepts: DR reads and writes.
    pub const INTERCEPT_DR: usize = 0x04;
    /// Intercepts: exception vectors 0..31.
    pub const INTERCEPT_EXCEPTIONS: usize = 0x08;
    /// Intercepts, word 3: INTR, NMI, CPUID, HLT, IOIO, MSR, SHUTDOWN, ...
    pub const INTERCEPT_W3: usize = 0x0C;
    /// Intercepts, word 4: VMRUN (mandatory), VMMCALL, VMLOAD, ...
    pub const INTERCEPT_W4: usize = 0x10;
    /// Intercepts, word 5.
    pub const INTERCEPT_W5: usize = 0x14;
    /// PAUSE filter threshold (u16).
    pub const PAUSE_FILTER_THRESH: usize = 0x3C;
    /// PAUSE filter count (u16).
    pub const PAUSE_FILTER_COUNT: usize = 0x3E;
    /// Physical address of the I/O permission map.
    pub const IOPM_BASE_PA: usize = 0x40;
    /// Physical address of the MSR permission map.
    pub const MSRPM_BASE_PA: usize = 0x48;
    /// Added to the guest's RDTSC.
    pub const TSC_OFFSET: usize = 0x50;
    /// Guest address space id (u32); 0 is the host's and is invalid for a guest.
    pub const GUEST_ASID: usize = 0x58;
    /// TLB control (u8).
    pub const TLB_CTL: usize = 0x5C;
    /// Virtual interrupt control (u32).
    pub const INT_CTL: usize = 0x60;
    /// Virtual interrupt vector.
    pub const INT_VECTOR: usize = 0x64;
    /// Interrupt shadow and GIF (u32).
    pub const INT_STATE: usize = 0x68;
    /// Why the guest exited.
    pub const EXIT_CODE: usize = 0x70;
    /// Exit information 1.
    pub const EXIT_INFO_1: usize = 0x78;
    /// Exit information 2.
    pub const EXIT_INFO_2: usize = 0x80;
    /// Event being delivered when the exit happened (u32).
    pub const EXIT_INT_INFO: usize = 0x88;
    /// Its error code (u32).
    pub const EXIT_INT_INFO_ERR: usize = 0x8C;
    /// Nested paging enable (bit 0).
    pub const NESTED_CTL: usize = 0x90;
    /// Event to inject on the next entry (u32).
    pub const EVENT_INJ: usize = 0xA8;
    /// Its error code (u32).
    pub const EVENT_INJ_ERR: usize = 0xAC;
    /// The nested page table root (`N_CR3`).
    pub const NESTED_CR3: usize = 0xB0;
    /// Virtual-extension control (LBR virtualization, virtual VMLOAD/VMSAVE).
    pub const VIRT_EXT: usize = 0xB8;
    /// VMCB clean bits (u32); zero means "reload everything".
    pub const CLEAN: usize = 0xC0;
    /// RIP of the instruction after the intercepted one (with NRIPS).
    pub const NEXT_RIP: usize = 0xC8;

    /// Start of the state save area.
    pub const SAVE: usize = 0x400;
    /// ES: selector (u16), attributes (u16), limit (u32), base (u64).
    pub const ES: usize = 0x400;
    /// CS.
    pub const CS: usize = 0x410;
    /// SS.
    pub const SS: usize = 0x420;
    /// DS.
    pub const DS: usize = 0x430;
    /// FS.
    pub const FS: usize = 0x440;
    /// GS.
    pub const GS: usize = 0x450;
    /// GDTR (limit and base only).
    pub const GDTR: usize = 0x460;
    /// LDTR.
    pub const LDTR: usize = 0x470;
    /// IDTR (limit and base only).
    pub const IDTR: usize = 0x480;
    /// TR.
    pub const TR: usize = 0x490;
    /// Current privilege level (u8).
    pub const CPL: usize = 0x4CB;
    /// EFER; `SVME` must be set.
    pub const EFER: usize = 0x4D0;
    /// CR4.
    pub const CR4: usize = 0x548;
    /// CR3.
    pub const CR3: usize = 0x550;
    /// CR0.
    pub const CR0: usize = 0x558;
    /// DR7.
    pub const DR7: usize = 0x560;
    /// DR6.
    pub const DR6: usize = 0x568;
    /// RFLAGS.
    pub const RFLAGS: usize = 0x570;
    /// RIP.
    pub const RIP: usize = 0x578;
    /// RSP.
    pub const RSP: usize = 0x5D8;
    /// RAX (the one general register the VMCB holds).
    pub const RAX: usize = 0x5F8;
    /// STAR.
    pub const STAR: usize = 0x600;
    /// LSTAR.
    pub const LSTAR: usize = 0x608;
    /// CSTAR.
    pub const CSTAR: usize = 0x610;
    /// SFMASK.
    pub const SFMASK: usize = 0x618;
    /// KernelGSBase.
    pub const KERNEL_GS_BASE: usize = 0x620;
    /// SYSENTER_CS.
    pub const SYSENTER_CS: usize = 0x628;
    /// SYSENTER_ESP.
    pub const SYSENTER_ESP: usize = 0x630;
    /// SYSENTER_EIP.
    pub const SYSENTER_EIP: usize = 0x638;
    /// CR2.
    pub const CR2: usize = 0x640;
    /// The guest's PAT (used with nested paging).
    pub const G_PAT: usize = 0x668;
}

/// Intercept bits, by the word they sit in.
pub mod icpt {
    /// Word 3: a physical interrupt.
    pub const INTR: u32 = 1 << 0;
    /// Word 3: NMI.
    pub const NMI: u32 = 1 << 1;
    /// Word 3: SMI.
    pub const SMI: u32 = 1 << 2;
    /// Word 3: INIT.
    pub const INIT: u32 = 1 << 3;
    /// Word 3: a virtual interrupt is pending and the guest can take it
    /// (the interrupt window: `V_IRQ` set in `INT_CTL`).
    pub const VINTR: u32 = 1 << 4;
    /// Word 3: IRET (the exit comes before the instruction runs).
    pub const IRET: u32 = 1 << 20;
    /// Word 3: INVD.
    pub const INVD: u32 = 1 << 22;
    /// Word 3: CPUID.
    pub const CPUID: u32 = 1 << 18;
    /// Word 3: HLT.
    pub const HLT: u32 = 1 << 24;
    /// Word 3: IN/OUT, per the I/O permission map.
    pub const IOIO_PROT: u32 = 1 << 27;
    /// Word 3: RDMSR/WRMSR, per the MSR permission map.
    pub const MSR_PROT: u32 = 1 << 28;
    /// Word 3: shutdown (triple fault).
    pub const SHUTDOWN: u32 = 1 << 31;
    /// Word 4: VMRUN. Mandatory: a VMCB without it fails the VMRUN checks.
    pub const VMRUN: u32 = 1 << 0;
    /// Word 4: VMMCALL (the hypercall instruction).
    pub const VMMCALL: u32 = 1 << 1;
    /// Word 4: VMLOAD.
    pub const VMLOAD: u32 = 1 << 2;
    /// Word 4: VMSAVE.
    pub const VMSAVE: u32 = 1 << 3;
    /// Word 4: STGI.
    pub const STGI: u32 = 1 << 4;
    /// Word 4: CLGI.
    pub const CLGI: u32 = 1 << 5;
    /// Word 4: SKINIT.
    pub const SKINIT: u32 = 1 << 6;
    /// Word 4: RDTSCP.
    pub const RDTSCP: u32 = 1 << 7;
    /// Word 4: WBINVD.
    pub const WBINVD: u32 = 1 << 9;
    /// Word 4: MONITOR / MONITORX.
    pub const MONITOR: u32 = 1 << 10;
    /// Word 4: MWAIT / MWAITX.
    pub const MWAIT: u32 = 1 << 11;
    /// Word 4: XSETBV.
    pub const XSETBV: u32 = 1 << 13;
}

/// Control bits.
pub mod ctl {
    /// `NESTED_CTL`: nested paging on.
    pub const NP_ENABLE: u64 = 1;
    /// `INT_CTL`: a virtual interrupt is pending (the guest takes it as soon as
    /// it can; with the `VINTR` intercept that is an exit).
    pub const V_IRQ: u32 = 1 << 8;
    /// `INT_CTL`: `V_IRQ` is taken whatever the guest's TPR says (the vLAPIC
    /// did the priority check).
    pub const V_IGN_TPR: u32 = 1 << 20;
    /// `INT_CTL`: the host's EFLAGS.IF, not the guest's, masks physical
    /// interrupts while the guest runs (so a guest `cli` cannot hold off the
    /// host's timer).
    pub const V_INTR_MASKING: u32 = 1 << 24;
    /// `INT_STATE`: the guest is in the shadow of `sti` / `mov ss`.
    pub const INT_SHADOW: u32 = 1;
    /// `EVENT_INJ`: the entry is valid.
    pub const EVENT_VALID: u32 = 1 << 31;
    /// `EVENT_INJ`: the error code field is valid.
    pub const EVENT_ERR: u32 = 1 << 11;
    /// `EVENT_INJ` type: an external interrupt.
    pub const EVENT_INTR: u32 = 0 << 8;
    /// `EVENT_INJ` type: an NMI.
    pub const EVENT_NMI: u32 = 2 << 8;
    /// `EVENT_INJ` type: a hardware exception.
    pub const EVENT_EXCEPTION: u32 = 3 << 8;
    /// `TLB_CTL`: no flush.
    pub const TLB_DO_NOTHING: u8 = 0;
    /// `TLB_CTL`: flush all ASIDs.
    pub const TLB_FLUSH_ALL: u8 = 1;
    /// `TLB_CTL`: flush this ASID.
    pub const TLB_FLUSH_ASID: u8 = 3;
    /// `TLB_CTL`: flush this ASID's non-global entries.
    pub const TLB_FLUSH_ASID_LOCAL: u8 = 7;
}

/// `EXITCODE` values.
pub mod code {
    /// A physical interrupt arrived.
    pub const INTR: u64 = 0x60;
    /// NMI.
    pub const NMI: u64 = 0x61;
    /// The interrupt window (`V_IRQ` pending and the guest can take it).
    pub const VINTR: u64 = 0x64;
    /// CPUID.
    pub const CPUID: u64 = 0x72;
    /// PAUSE.
    pub const PAUSE: u64 = 0x77;
    /// IRET.
    pub const IRET: u64 = 0x7A;
    /// HLT.
    pub const HLT: u64 = 0x78;
    /// IN/OUT/INS/OUTS.
    pub const IOIO: u64 = 0x7B;
    /// RDMSR/WRMSR.
    pub const MSR: u64 = 0x7C;
    /// SMI.
    pub const SMI: u64 = 0x62;
    /// INIT.
    pub const INIT: u64 = 0x63;
    /// INVD.
    pub const INVD: u64 = 0x76;
    /// WBINVD.
    pub const WBINVD: u64 = 0x89;
    /// Shutdown (triple fault).
    pub const SHUTDOWN: u64 = 0x7F;
    /// VMRUN in the guest.
    pub const VMRUN: u64 = 0x80;
    /// VMMCALL.
    pub const VMMCALL: u64 = 0x81;
    /// VMLOAD.
    pub const VMLOAD: u64 = 0x82;
    /// VMSAVE.
    pub const VMSAVE: u64 = 0x83;
    /// STGI.
    pub const STGI: u64 = 0x84;
    /// CLGI.
    pub const CLGI: u64 = 0x85;
    /// SKINIT.
    pub const SKINIT: u64 = 0x86;
    /// RDTSCP.
    pub const RDTSCP: u64 = 0x87;
    /// MONITOR / MONITORX.
    pub const MONITOR: u64 = 0x8A;
    /// MWAIT / MWAITX.
    pub const MWAIT: u64 = 0x8B;
    /// XSETBV.
    pub const XSETBV: u64 = 0x8D;
    /// A nested page fault.
    pub const NPF: u64 = 0x400;
    /// The VMCB failed the VMRUN consistency checks.
    pub const INVALID: u64 = u64::MAX;
}

/// `EFER` bits a VMCB's guest state uses.
pub mod efer {
    /// Long mode enable.
    pub const LME: u64 = 1 << 8;
    /// Long mode active.
    pub const LMA: u64 = 1 << 10;
    /// SVM enable: must be set in the guest's EFER.
    pub const SVME: u64 = 1 << 12;
}

/// `CR0` bits the checks read.
pub mod cr0 {
    /// Protected mode.
    pub const PE: u64 = 1 << 0;
    /// Not write-through.
    pub const NW: u64 = 1 << 29;
    /// Cache disable.
    pub const CD: u64 = 1 << 30;
    /// Paging.
    pub const PG: u64 = 1 << 31;
}

/// `CR4` bits the checks read.
pub mod cr4 {
    /// Physical address extension.
    pub const PAE: u64 = 1 << 5;
}

/// `RFLAGS` bit 1 is always set.
pub const RFLAGS_RESERVED1: u64 = 1 << 1;

/// A segment's attribute word from a GDT descriptor: the access byte
/// (descriptor bits 47:40) in bits 7:0 and the flags nibble (55:52) in
/// bits 11:8.
pub const fn attrib_from_descriptor(desc: u64) -> u16 {
    (((desc >> 40) & 0xFF) | ((desc >> 44) & 0xF00)) as u16
}

/// Attributes of a real-mode code segment (present, readable, accessed).
pub const ATTR_REAL_CODE: u16 = 0x9B;
/// Attributes of a real-mode data segment (present, writable, accessed).
pub const ATTR_REAL_DATA: u16 = 0x93;
/// Attributes of a busy 64-bit TSS.
pub const ATTR_TSS_BUSY: u16 = 0x8B;
/// Attributes of an LDT.
pub const ATTR_LDT: u16 = 0x82;

/// The guest general registers the VMCB does not hold (RAX it does):
/// `VMRUN` swaps nothing else, so the run stub loads them before entering
/// and stores them back on the exit. The order is the stub's offsets.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct GuestRegs {
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// One VMCB page.
#[derive(Clone)]
#[repr(C, align(4096))]
pub struct Vmcb {
    bytes: [u8; PAGE],
}

impl Default for Vmcb {
    fn default() -> Self {
        Self::new()
    }
}

/// Why `VMRUN` would refuse this VMCB (AMD APM vol. 2, 15.5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Invalid {
    /// Guest `EFER.SVME` is clear.
    GuestEferSvme,
    /// The VMRUN intercept is not set.
    NoVmrunIntercept,
    /// `GUEST_ASID` is 0 (the host's).
    AsidZero,
    /// `CR0.CD` clear with `CR0.NW` set.
    Cr0CdNw,
    /// `CR0` bits 63:32 are not zero.
    Cr0High,
    /// `EFER.LME` with `CR0.PG` but not `CR4.PAE` and `CR0.PE`.
    LongModeWithoutPae,
    /// `EFER` has `LMA` without `LME`, or a reserved bit set.
    EferReserved,
    /// `DR6` or `DR7` bits 63:32 are not zero.
    DrHigh,
    /// `GUEST_ASID` is not below the CPU's ASID count (`SvmCaps::nasid`).
    AsidAboveCount,
    /// Policy: the I/O or MSR intercept is clear, which would hand the guest
    /// the host's ports or MSRs (`VM_HSAVE_PA`, `APIC_BASE`, `SPEC_CTRL`, ...).
    NoProtIntercepts,
    /// The I/O or MSR permission map is not page-aligned or unset.
    BadPermissionMap,
    /// Nested paging is on and `N_CR3` is not page-aligned.
    BadNestedCr3,
}

impl Vmcb {
    /// A zeroed VMCB.
    pub const fn new() -> Self {
        Self { bytes: [0; PAGE] }
    }

    /// The page, to hand to `VMRUN` by address.
    pub fn as_bytes(&self) -> &[u8; PAGE] {
        &self.bytes
    }

    /// 8-bit field.
    pub fn rd8(&self, at: usize) -> u8 {
        self.bytes[at]
    }

    /// Write an 8-bit field.
    pub fn wr8(&mut self, at: usize, v: u8) {
        self.bytes[at] = v;
    }

    /// 16-bit field.
    pub fn rd16(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.bytes[at], self.bytes[at + 1]])
    }

    /// 32-bit field.
    pub fn rd32(&self, at: usize) -> u32 {
        let mut b = [0; 4];
        b.copy_from_slice(&self.bytes[at..at + 4]);
        u32::from_le_bytes(b)
    }

    /// 64-bit field.
    pub fn rd64(&self, at: usize) -> u64 {
        let mut b = [0; 8];
        b.copy_from_slice(&self.bytes[at..at + 8]);
        u64::from_le_bytes(b)
    }

    /// Write a 16-bit field.
    pub fn wr16(&mut self, at: usize, v: u16) {
        self.bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    /// Write a 32-bit field.
    pub fn wr32(&mut self, at: usize, v: u32) {
        self.bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Write a 64-bit field.
    pub fn wr64(&mut self, at: usize, v: u64) {
        self.bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Set bits in a 32-bit field.
    pub fn or32(&mut self, at: usize, bits: u32) {
        let v = self.rd32(at) | bits;
        self.wr32(at, v);
    }

    /// Write one segment register's four fields.
    pub fn set_segment(&mut self, at: usize, selector: u16, attrib: u16, limit: u32, base: u64) {
        self.wr16(at, selector);
        self.wr16(at + 2, attrib);
        self.wr32(at + 4, limit);
        self.wr64(at + 8, base);
    }

    /// Read one segment register back as `(selector, attrib, limit, base)`.
    pub fn segment(&self, at: usize) -> (u16, u16, u32, u64) {
        (self.rd16(at), self.rd16(at + 2), self.rd32(at + 4), self.rd64(at + 8))
    }

    /// The intercepts every guest needs, and [`Vmcb::check`] requires:
    ///
    /// * `VMRUN` (mandatory), and the instructions that would let the guest
    ///   touch the host's SVM state (`VMLOAD`, `VMSAVE`, `STGI`, `CLGI`);
    ///   `VMMCALL` stays an exit so a guest can ask the monitor for something.
    /// * `IOIO_PROT` and `MSR_PROT`: without them the guest's `IN`/`OUT` reach
    ///   the host's ports and its `RDMSR`/`WRMSR` the host's MSRs. They
    ///   consult the permission maps, so [`Vmcb::set_iopm`] and
    ///   [`Vmcb::set_msrpm`] are part of the setup (a map of all ones
    ///   intercepts everything).
    /// * `INVD` and `WBINVD`: both write back or drop the host's caches and
    ///   have no business in a guest. `SMI` and `INIT`: a physical SMI or INIT
    ///   would otherwise run the firmware's handler or reset the CPU under the
    ///   guest. (KVM intercepts the same four.) Their exits decode as
    ///   `Exit::Other`: the monitor treats them as a guest it kills.
    /// * `HLT`: an idle guest must put its vCPU thread to sleep, not the
    ///   physical CPU (`Exit::Halt` is `Exit::Wait` above).
    /// * `XSETBV`: `XCR0` is not in the VMCB, so a guest's write would land in
    ///   the host's register; the monitor keeps the guest's value and loads it
    ///   around `VMRUN` ([`super::serve`]).
    /// * `MONITOR`, `MWAIT`, `RDTSCP` and `SKINIT`: CPUID does not offer
    ///   them ([`super::cpuid`]), so the guest that runs one gets the `#UD` it
    ///   would on a CPU without them. (`RDTSCP` reads `TSC_AUX`, which the
    ///   VMCB does not hold either.)
    pub fn intercept_minimum(&mut self) {
        self.or32(off::INTERCEPT_W4,
            icpt::VMRUN | icpt::VMMCALL | icpt::VMLOAD | icpt::VMSAVE | icpt::STGI | icpt::CLGI
                | icpt::WBINVD | icpt::XSETBV | icpt::MONITOR | icpt::MWAIT | icpt::RDTSCP | icpt::SKINIT);
        self.or32(off::INTERCEPT_W3,
            icpt::SHUTDOWN | icpt::INTR | icpt::IOIO_PROT | icpt::MSR_PROT | icpt::INVD | icpt::SMI | icpt::INIT
                | icpt::HLT);
    }

    /// Turn nested paging on with root `n_cr3` (a physical address).
    pub fn enable_nested_paging(&mut self, n_cr3: u64) {
        self.wr64(off::NESTED_CTL, self.rd64(off::NESTED_CTL) | ctl::NP_ENABLE);
        self.wr64(off::NESTED_CR3, n_cr3);
    }

    /// Point the I/O permission map ([`IOPM_BYTES`], page-aligned) at `pa`;
    /// the ports whose bit is set exit. Required: [`Vmcb::check`] refuses a
    /// VMCB without it.
    pub fn set_iopm(&mut self, pa: u64) {
        self.wr64(off::IOPM_BASE_PA, pa);
    }

    /// Point the MSR permission map ([`MSRPM_BYTES`], page-aligned) at `pa`;
    /// the MSRs whose read or write bit is set exit. Required, as
    /// [`Vmcb::set_iopm`].
    pub fn set_msrpm(&mut self, pa: u64) {
        self.wr64(off::MSRPM_BASE_PA, pa);
    }

    /// The architectural state of a guest that starts in 16-bit real mode
    /// with every segment flat at base 0 and limit 64 KiB, at `rip`
    /// (`< 0x10000`), no paging, interrupts off, `asid` as its address space
    /// and `EFER.SVME` set as `VMRUN` requires. The smallest guest that can
    /// run a few instructions with nested paging providing its memory. It
    /// carries [`Vmcb::intercept_minimum`]; the caller still sets the two
    /// permission maps and nested paging before [`Vmcb::check`] passes.
    pub fn init_real_mode(&mut self, rip: u16, asid: u32) {
        for seg in [off::ES, off::SS, off::DS, off::FS, off::GS] {
            self.set_segment(seg, 0, ATTR_REAL_DATA, 0xFFFF, 0);
        }
        self.set_segment(off::CS, 0, ATTR_REAL_CODE, 0xFFFF, 0);
        self.set_segment(off::LDTR, 0, ATTR_LDT, 0xFFFF, 0);
        self.set_segment(off::TR, 0, ATTR_TSS_BUSY, 0xFFFF, 0);
        self.set_segment(off::GDTR, 0, 0, 0xFFFF, 0);
        self.set_segment(off::IDTR, 0, 0, 0xFFFF, 0);
        self.wr64(off::EFER, efer::SVME);
        // ET (bit 4) is the reset value's always-one bit; CD/NW stay clear.
        self.wr64(off::CR0, 1 << 4);
        self.wr64(off::RFLAGS, RFLAGS_RESERVED1);
        self.wr64(off::RIP, rip as u64);
        self.wr64(off::DR6, 0xFFFF_0FF0);
        self.wr64(off::DR7, 0x400);
        // The architectural PAT reset value.
        self.wr64(off::G_PAT, 0x0007_0406_0007_0406);
        self.wr32(off::GUEST_ASID, asid);
        self.intercept_minimum();
        // The state a start or an INIT leaves, whatever the VMCB held before:
        // no paging structures, no event queued for injection, no interrupt
        // shadow, no interrupt window, and the ASID's old translations stale.
        for f in [off::CR2, off::CR3, off::CR4] {
            self.wr64(f, 0);
        }
        for f in [off::EVENT_INJ, off::EVENT_INJ_ERR, off::INT_STATE, off::EXIT_INT_INFO, off::EXIT_INT_INFO_ERR] {
            self.wr32(f, 0);
        }
        self.wr32(off::INT_CTL, ctl::V_INTR_MASKING);
        self.wr32(off::INTERCEPT_W3, self.rd32(off::INTERCEPT_W3) & !icpt::VINTR);
        self.wr32(off::TLB_CTL, ctl::TLB_FLUSH_ALL as u32);
    }

    /// What `VMRUN` would object to, plus this port's policy
    /// ([`Invalid::NoProtIntercepts`]); first violation only (the order is the
    /// APM's list, so a test pins one violation at a time). `nasid` is the
    /// CPU's ASID count (`SvmCaps::nasid`): an ASID at or above it is a
    /// `VMEXIT_INVALID` on hardware.
    pub fn check(&self, nasid: u32) -> Result<(), Invalid> {
        let efer = self.rd64(off::EFER);
        if efer & efer::SVME == 0 {
            return Err(Invalid::GuestEferSvme);
        }
        if self.rd32(off::INTERCEPT_W4) & icpt::VMRUN == 0 {
            return Err(Invalid::NoVmrunIntercept);
        }
        let asid = self.rd32(off::GUEST_ASID);
        if asid == 0 {
            return Err(Invalid::AsidZero);
        }
        if asid >= nasid {
            return Err(Invalid::AsidAboveCount);
        }
        let cr0 = self.rd64(off::CR0);
        if cr0 >> 32 != 0 {
            return Err(Invalid::Cr0High);
        }
        if cr0 & cr0::CD == 0 && cr0 & cr0::NW != 0 {
            return Err(Invalid::Cr0CdNw);
        }
        // Defined EFER bits: SCE 0, LME 8, LMA 10, NXE 11, SVME 12, LMSLE 13,
        // FFXSR 14, TCE 15, AIBRSE 21 (this port sets none beyond SVME).
        const EFER_DEFINED: u64 = 1 | 1 << 8 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 13 | 1 << 14 | 1 << 15 | 1 << 21;
        if efer & !EFER_DEFINED != 0 || (efer & efer::LMA != 0 && efer & efer::LME == 0) {
            return Err(Invalid::EferReserved);
        }
        if efer & efer::LME != 0 && cr0 & cr0::PG != 0
            && (self.rd64(off::CR4) & cr4::PAE == 0 || cr0 & cr0::PE == 0)
        {
            return Err(Invalid::LongModeWithoutPae);
        }
        if self.rd64(off::DR6) >> 32 != 0 || self.rd64(off::DR7) >> 32 != 0 {
            return Err(Invalid::DrHigh);
        }
        let w3 = self.rd32(off::INTERCEPT_W3);
        if w3 & (icpt::IOIO_PROT | icpt::MSR_PROT) != icpt::IOIO_PROT | icpt::MSR_PROT {
            return Err(Invalid::NoProtIntercepts);
        }
        let bad = |pa: u64| pa == 0 || pa & (PAGE as u64 - 1) != 0;
        if bad(self.rd64(off::IOPM_BASE_PA)) || bad(self.rd64(off::MSRPM_BASE_PA)) {
            return Err(Invalid::BadPermissionMap);
        }
        if self.rd64(off::NESTED_CTL) & ctl::NP_ENABLE != 0 && self.rd64(off::NESTED_CR3) & (PAGE as u64 - 1) != 0 {
            return Err(Invalid::BadNestedCr3);
        }
        Ok(())
    }
}
