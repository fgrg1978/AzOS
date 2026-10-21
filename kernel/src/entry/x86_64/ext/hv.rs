// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hardware virtualization at boot (Kconfig `X86_SVM`, `X86_VMX`): the probe
//! and its record, and the in-kernel test that runs a real guest.
//!
//! The probe is read-only (CPUID, and the two MSRs firmware can lock) and
//! runs on the boot CPU from `cpu_features`, next to the other extensions'
//! rows. A CPU whose firmware turned virtualization off is "no hypervisor,
//! with a record": the `[HV]` line says why, `azos_arch::hv::probe::record`
//! keeps it for whoever asks later, and the boot goes on. Only the Kconfig
//! choice `require` stops it (the `[ISA]` report does that, as for any
//! extension).
//!
//! Nothing here enables SVM or VMX outside a guest run: `EFER.SVME`, or
//! `CR4.VMXE` and `VMXON`, are set per CPU by whoever starts a guest, with
//! preemption off (`azos_arch::hv::hw`, `azos_arch::hv::vmx_hw`).

use azos_arch::hv::probe::{self, Kind, Probe};
use azos_drv_sys::kprintln;

/// The probe, honouring the Kconfig choices (`n` reads nothing).
pub(crate) fn probe() -> Probe {
    use azos_arch_api::isa::x86_64 as p;
    probe::probe(p::SVM.allowed(), p::VMX.allowed())
}

/// Keep the verdict and print the `[HV]` line.
pub(crate) fn record(p: &Probe) {
    let c = p.choice();
    probe::record_set(c);
    #[cfg(feature = "hv")]
    if matches!(c.kind, Kind::Svm | Kind::Vmx) {
        host::register();
    }
    match c.kind {
        Kind::Svm => {
            let s = &p.svm_caps;
            kprintln!("[HV] svm rev {}: nested paging, {} ASIDs{}{}{}{}", s.revision, s.nasid,
                if s.nrips { ", nrip" } else { "" },
                if s.decode_assists { ", decode-assists" } else { "" },
                if s.flush_by_asid { ", flush-by-asid" } else { "" },
                if s.vmcb_clean { ", vmcb-clean" } else { "" });
        }
        Kind::Vmx => {
            let v = &p.vmx_caps;
            kprintln!("[HV] vmx rev {:#x}: EPT 4-level wb{}{}{}{}", v.revision,
                if v.ept_2m { ", 2M" } else { "" },
                if v.ept_1g { ", 1G" } else { "" },
                if v.unrestricted_guest { ", unrestricted-guest" } else { "" },
                if v.invept { ", invept" } else { "" });
        }
        Kind::None => {
            kprintln!("[HV] none: svm {}, vmx {} (no guests; the boot continues)", p.svm.name(), p.vmx.name());
        }
    }
}

/// What the guest entry (`azos_arch::hv::vcpu`) needs of the kernel: page
/// frames, and the virtual APICs of each VM. The arch crate sits below the
/// page allocator and the monitor, so this is the one place that joins them.
///
/// A VM's interrupt controllers are one local APIC per vCPU and an IOAPIC
/// (`azos_hv::{vlapic, vioapic}`, pure models) behind one lock: a vCPU's
/// entry holds it for the time of a `serve` or a `before_entry`, never across
/// a `VMRUN`. What a write to one vCPU's APIC asks of another (an IPI, a
/// released level interrupt) lands in that vCPU's APIC; the vCPU notices at
/// its next entry, which for a sleeping one is within the monitor's bounded
/// wait (`azos_syscall::vm`'s slice), since the kick mask the models return is
/// not turned into a wake-up here.
#[cfg(feature = "hv")]
mod host {
    use alloc::vec::Vec;

    use azos_arch::hv::apic::{ApicEvent, Gp, LocalApic};
    use azos_arch::hv::vcpu::{register_host, VmHost, VmInfo};
    use azos_hv::vioapic::{deliver_all, deliver_effect, pulse_lines, Vioapic, IOAPIC_DEFAULT_BASE, IOAPIC_WINDOW};
    use azos_hv::vlapic::{timer_clock, Event, Mode, Vlapic, APIC_PAGE};
    use azos_mm::addr::{phys_to_virt, PhysAddr};
    use azos_mm::pmm;
    use azos_sync::SpinLock;

    /// The rate of the virtual APIC timer's undivided clock the guest is told
    /// (CPUID leaf `0x4000_0010`): the nearest the TSC divides into.
    const APIC_KHZ: u32 = 100_000;

    /// One VM's interrupt controllers.
    struct Controllers {
        apics: Vec<Vlapic>,
        io: Vioapic,
    }

    struct Kernel;

    static VMS: SpinLock<[Option<Controllers>; azos_hv::vm::MAX_VMS]> =
        SpinLock::new([const { None }; azos_hv::vm::MAX_VMS]);
    static KERNEL: Kernel = Kernel;
    static KERNEL_REF: &dyn VmHost = &KERNEL;

    pub(super) fn register() {
        register_host(&KERNEL_REF);
    }

    fn tsc_khz() -> u32 {
        (azos_arch::timer::tsc_hz() / 1000).min(u32::MAX as u64) as u32
    }

    fn info(vmid: u16) -> Option<VmInfo> {
        let vcpus = azos_syscall::vm::vcpus_of(vmid)?;
        let tsc = tsc_khz();
        Some(VmInfo { vcpus, tsc_khz: tsc, apic_khz: timer_clock(tsc, APIC_KHZ).1 })
    }

    fn controllers(i: &VmInfo) -> Controllers {
        let per_tick = timer_clock(i.tsc_khz, APIC_KHZ).0;
        Controllers {
            apics: (0..i.vcpus as u32).map(|k| Vlapic::new(k, k == 0, per_tick)).collect(),
            io: Vioapic::new(0, IOAPIC_DEFAULT_BASE),
        }
    }

    fn slot(vmid: u16) -> Option<usize> {
        (vmid as usize).checked_sub(1).filter(|&i| i < azos_hv::vm::MAX_VMS)
    }

    impl VmHost for Kernel {
        fn alloc_pages(&self, pages: usize) -> Option<u64> {
            let frames = (pages * 4096).div_ceil(azos_arch::PAGE_SIZE);
            let pa = pmm::alloc_contiguous_aligned(frames, azos_arch::PAGE_SIZE.max(4096)).ok()?;
            // SAFETY: frames the allocator just gave: RAM in the direct map.
            unsafe { core::ptr::write_bytes(phys_to_virt(pa.as_usize()) as *mut u8, 0, frames * azos_arch::PAGE_SIZE) };
            Some(pa.as_usize() as u64)
        }

        fn free_pages(&self, pa: u64, pages: usize) {
            for i in 0..(pages * 4096).div_ceil(azos_arch::PAGE_SIZE) {
                let _ = pmm::free_page(PhysAddr::new(pa as usize + i * azos_arch::PAGE_SIZE));
            }
        }

        fn vm_info(&self, vmid: u16) -> Option<VmInfo> {
            let i = info(vmid)?;
            let s = slot(vmid)?;
            let mut g = VMS.lock();
            g[s].get_or_insert_with(|| controllers(&i));
            Some(i)
        }

        fn reset_vm(&self, vmid: u16) -> Option<VmInfo> {
            let i = info(vmid)?;
            let s = slot(vmid)?;
            VMS.lock()[s] = Some(controllers(&i));
            Some(i)
        }

        fn with_apic(&self, vmid: u16, vcpu: u8, f: &mut dyn FnMut(&mut dyn LocalApic)) -> bool {
            let Some(s) = slot(vmid) else { return false };
            let mut g = VMS.lock();
            let Some(c) = g[s].as_mut() else { return false };
            if vcpu as usize >= c.apics.len() {
                return false;
            }
            f(&mut Port { c, idx: vcpu as usize });
            true
        }

        fn raise_lines(&self, vmid: u16, lines: u64) {
            let Some(s) = slot(vmid) else { return };
            if let Some(c) = VMS.lock()[s].as_mut() {
                pulse_lines(&mut c.apics, &mut c.io, lines);
            }
        }

        fn release_vm(&self, vmid: u16) {
            if let Some(s) = slot(vmid) {
                VMS.lock()[s] = None;
            }
        }
    }

    /// vCPU `idx`'s window onto the VM's interrupt controllers.
    struct Port<'a> {
        c: &'a mut Controllers,
        idx: usize,
    }

    impl LocalApic for Port<'_> {
        fn msr_read(&mut self, m: u32, tsc: u64) -> Result<u64, Gp> {
            self.c.apics[self.idx].msr_read(m, tsc).map_err(|_| Gp)
        }
        fn msr_write(&mut self, m: u32, v: u64, tsc: u64) -> Result<(), Gp> {
            let e = self.c.apics[self.idx].msr_write(m, v, tsc).map_err(|_| Gp)?;
            deliver_effect(&mut self.c.apics, &mut self.c.io, self.idx, e);
            Ok(())
        }
        fn tick(&mut self, tsc: u64) {
            self.c.apics[self.idx].tick(tsc)
        }
        fn pending(&self) -> Option<u8> {
            self.c.apics[self.idx].pending()
        }
        fn ack(&mut self) -> Option<u8> {
            self.c.apics[self.idx].ack()
        }
        fn take_event(&mut self) -> Option<ApicEvent> {
            self.c.apics[self.idx].take_event().map(|e| match e {
                Event::Init => ApicEvent::Init,
                Event::Startup(v) => ApicEvent::Startup(v),
                Event::Smi => ApicEvent::Smi,
                Event::Nmi => ApicEvent::Nmi,
                Event::ExtInt => ApicEvent::ExtInt,
            })
        }
        fn has_work(&self) -> bool {
            self.c.apics[self.idx].has_work()
        }
        fn next_deadline(&self) -> Option<u64> {
            self.c.apics[self.idx].next_deadline()
        }
        fn init_reset(&mut self) {
            self.c.apics[self.idx].init_reset()
        }
        fn owns_mmio(&self, gpa: u64) -> bool {
            let a = &self.c.apics[self.idx];
            let io = self.c.io.mmio_base();
            (a.mode() == Mode::XApic && gpa >= a.mmio_base() && gpa < a.mmio_base() + APIC_PAGE)
                || (gpa >= io && gpa < io + IOAPIC_WINDOW)
        }
        fn mmio_read(&mut self, gpa: u64, size: u8, tsc: u64) -> u32 {
            let io = self.c.io.mmio_base();
            if gpa >= io && gpa < io + IOAPIC_WINDOW {
                self.c.io.mmio_read(gpa, size).unwrap_or(0)
            } else {
                self.c.apics[self.idx].mmio_read(gpa, size, tsc).unwrap_or(0)
            }
        }
        fn mmio_write(&mut self, gpa: u64, size: u8, val: u32, tsc: u64) {
            let io = self.c.io.mmio_base();
            if gpa >= io && gpa < io + IOAPIC_WINDOW {
                if let Ok(msgs) = self.c.io.mmio_write(gpa, size, val) {
                    deliver_all(&mut self.c.apics, &msgs);
                }
            } else if let Ok(e) = self.c.apics[self.idx].mmio_write(gpa, size, val, tsc) {
                deliver_effect(&mut self.c.apics, &mut self.c.io, self.idx, e);
            }
        }
    }
}

/// A guest in 16-bit real mode, one VMRUN per intercepted event:
///
/// ```text
/// 0x1000  cpuid                 -> Cpuid
///         mov al, 'A'
///         mov dx, 0x3f8
///         out dx, al            -> Io(port 0x3f8, write, 1 byte), RAX and RDX through the save paths
///         mov al, [0x5000]      -> NestedFault(gpa 0x5000, not present): the host maps the page
///         mov cx, 0x10
///         rdmsr                 -> Msr(read): the MSR permission map, not the host's TSC MSR
///         hlt                   -> Halt
/// ```
///
/// The pieces it exercises are the ones a monitor needs and that only hardware
/// can confirm: EFER.SVME and VM_HSAVE_PA, the VMCB the host built passing
/// VMRUN's checks (including the policy that a guest has both permission
/// maps), nested paging built with the x86 PTE builder (a missing U/S bit is
/// a #VMEXIT on the first fetch), the I/O and MSR permission maps (every
/// port and MSR intercepted), the general registers across the stub, and the
/// exit decode. Needs QEMU TCG with
/// `-cpu max,+svm` (or any SVM machine); on a CPU without usable SVM it
/// passes without running (the `[HV]` line says why).
#[cfg(feature = "ktest")]
mod guest_test {
    use azos_arch::hv::exit::{self, Exit, IoAccess};
    use azos_arch::hv::npt::{self, GuestAccess};
    use azos_arch::hv::probe::{self, Kind};
    use azos_arch::hv::svm::{self, code, ctl, off, GuestRegs, Vmcb, IOPM_BYTES, MSRPM_BYTES};
    use azos_arch::mmu::TableMem;
    use azos_mm::addr::{phys_to_virt, PhysAddr};
    use azos_mm::pmm;

    /// The guest's program, at guest-physical 0x1000.
    const PROGRAM: [u8; 17] = [
        0x0F, 0xA2, // cpuid
        0xB0, 0x41, // mov al, 'A'
        0xBA, 0xF8, 0x03, // mov dx, 0x3f8
        0xEE, // out dx, al
        0xA0, 0x00, 0x50, // mov al, [0x5000]
        0xB9, 0x10, 0x00, // mov cx, 0x10
        0x0F, 0x32, // rdmsr
        0xF4, // hlt
    ];
    const CODE_GPA: usize = 0x1000;
    const DATA_GPA: usize = 0x5000;

    /// Frames the test owns, returned to the PMM on drop.
    struct Frames {
        list: [usize; 24],
        n: usize,
    }

    impl Frames {
        fn page(&mut self) -> Result<usize, &'static str> {
            let pa = pmm::alloc_page().map_err(|_| "out of frames")?.as_usize();
            self.push(pa)?;
            Ok(pa)
        }
        fn push(&mut self, pa: usize) -> Result<(), &'static str> {
            *self.list.get_mut(self.n).ok_or("frame list full")? = pa;
            self.n += 1;
            Ok(())
        }
    }

    impl Drop for Frames {
        fn drop(&mut self) {
            for &pa in &self.list[..self.n] {
                let _ = pmm::free_page(PhysAddr(pa));
            }
        }
    }

    /// Nested page tables in the direct map, frames from [`Frames`].
    struct Tables<'a>(&'a mut Frames);

    impl TableMem for Tables<'_> {
        fn read(&self, table: usize, idx: usize) -> u64 {
            // SAFETY: a table frame this test allocated: RAM in the direct map.
            unsafe { core::ptr::read_volatile((phys_to_virt(table) + idx * 8) as *const u64) }
        }
        fn write(&mut self, table: usize, idx: usize, word: u64) {
            // SAFETY: as `read`; nothing else uses these frames.
            unsafe { core::ptr::write_volatile((phys_to_virt(table) + idx * 8) as *mut u64, word) }
        }
        fn alloc_table(&mut self) -> Option<usize> {
            self.0.page().ok()
        }
    }

    fn vmcb(pa: usize) -> &'static mut Vmcb {
        // SAFETY: `pa` is a page this test allocated and nothing else maps; a
        // fresh reference per phase, so no value is cached across a VMRUN.
        unsafe { &mut *(phys_to_virt(pa) as *mut Vmcb) }
    }

    /// One VMRUN that ends in an exit the guest caused; the decoded exit. A
    /// physical interrupt (the LAPIC timer in the early phase) ends a run too:
    /// by the time `svm_run` returns, GIF is set again and the host took it,
    /// so the guest is simply entered again.
    fn run(vmcb_pa: usize, host_pa: usize, nasid: u32, regs: &mut GuestRegs) -> Result<Exit, &'static str> {
        loop {
            vmcb(vmcb_pa).check(nasid).map_err(|_| "the VMCB fails the VMRUN checks")?;
            // SAFETY: SVM is enabled on this CPU by the caller; both pages are owned
            // and distinct; the test does not migrate (early phase, one CPU).
            unsafe { azos_arch::hv::hw::svm_run(vmcb_pa as u64, host_pa as u64, regs) };
            let v = vmcb(vmcb_pa);
            match exit::svm(v.rd64(off::EXIT_CODE), v.rd64(off::EXIT_INFO_1), v.rd64(off::EXIT_INFO_2)) {
                Exit::Interrupt => continue,
                e => return Ok(e),
            }
        }
    }

    fn body() -> Result<(), &'static str> {
        let rec = probe::record();
        if rec.kind != Kind::Svm {
            return Ok(());
        }
        let mut fr = Frames { list: [0; 24], n: 0 };
        let (vmcb_pa, host_pa) = (fr.page()?, fr.page()?);
        let (code_pa, data_pa) = (fr.page()?, fr.page()?);
        let npt_root = fr.page()?;
        // SAFETY: a page this test owns.
        unsafe { core::ptr::copy_nonoverlapping(PROGRAM.as_ptr(), phys_to_virt(code_pa) as *mut u8, PROGRAM.len()) };
        // The permission maps: every port and every MSR intercepted.
        let iopm = pmm::alloc_contiguous(IOPM_BYTES / 4096).map_err(|_| "no IOPM")?.as_usize();
        for i in 0..IOPM_BYTES / 4096 {
            fr.push(iopm + i * 4096)?;
        }
        // SAFETY: the run just allocated.
        unsafe { core::ptr::write_bytes(phys_to_virt(iopm) as *mut u8, 0xFF, IOPM_BYTES) };
        let msrpm = pmm::alloc_contiguous(MSRPM_BYTES / 4096).map_err(|_| "no MSRPM")?.as_usize();
        for i in 0..MSRPM_BYTES / 4096 {
            fr.push(msrpm + i * 4096)?;
        }
        // SAFETY: as above.
        unsafe { core::ptr::write_bytes(phys_to_virt(msrpm) as *mut u8, 0xFF, MSRPM_BYTES) };
        let nasid = super::probe().svm_caps.nasid;

        let levels = azos_arch::mmu::levels();
        npt::map(&mut Tables(&mut fr), npt_root, levels, CODE_GPA, code_pa, 0, GuestAccess::RX, false)
            .map_err(|_| "NPT map of the code page")?;

        let v = vmcb(vmcb_pa);
        v.init_real_mode(CODE_GPA as u16, 1);
        v.enable_nested_paging(npt_root as u64);
        v.set_iopm(iopm as u64);
        v.set_msrpm(msrpm as u64);
        v.or32(off::INTERCEPT_W3, svm::icpt::CPUID | svm::icpt::HLT);
        v.wr32(off::TLB_CTL, ctl::TLB_FLUSH_ALL as u32);

        azos_arch::hv::hw::svm_enable_this_cpu(host_pa as u64);
        let r = steps(vmcb_pa, host_pa, data_pa, npt_root, levels, nasid, &mut fr);
        azos_arch::hv::hw::svm_disable_this_cpu();
        r
    }

    fn steps(vmcb_pa: usize, host_pa: usize, data_pa: usize, npt_root: usize, levels: usize, nasid: u32,
             fr: &mut Frames)
        -> Result<(), &'static str>
    {
        if !azos_arch::hv::hw::svm_enabled_this_cpu() {
            return Err("EFER.SVME did not stick");
        }
        let mut regs = GuestRegs::default();

        if run(vmcb_pa, host_pa, nasid, &mut regs)? != Exit::Cpuid {
            return Err("step 1: expected a CPUID exit");
        }
        vmcb(vmcb_pa).wr64(off::RIP, (CODE_GPA + 2) as u64);

        match run(vmcb_pa, host_pa, nasid, &mut regs)? {
            Exit::Io(IoAccess { port: 0x3F8, write: true, size: 1, next_rip: n, .. }) if n == (CODE_GPA + 8) as u64 => {}
            _ => return Err("step 2: expected OUT 0x3f8, 1 byte, next RIP 0x1008"),
        }
        let v = vmcb(vmcb_pa);
        if v.rd64(off::RAX) & 0xFF != 0x41 {
            return Err("step 2: guest RAX did not reach the VMCB");
        }
        if regs.rdx != 0x3F8 {
            return Err("step 2: guest RDX did not reach the register block");
        }
        v.wr64(off::RIP, (CODE_GPA + 8) as u64);

        match run(vmcb_pa, host_pa, nasid, &mut regs)? {
            Exit::NestedFault(f) if f.gpa == DATA_GPA as u64 && !f.present && !f.write && f.final_translation => {}
            _ => return Err("step 3: expected a nested fault on 0x5000, page absent"),
        }
        npt::map(&mut Tables(fr), npt_root, levels, DATA_GPA, data_pa, 0, GuestAccess::RW, false)
            .map_err(|_| "NPT map of the data page")?;
        vmcb(vmcb_pa).wr32(off::TLB_CTL, ctl::TLB_DO_NOTHING as u32);

        // RDMSR is intercepted by the permission map; without MSR_PROT it would
        // have read the host's TSC MSR and gone on to the HLT. The exit leaves
        // RIP at the instruction: step over its two bytes.
        if run(vmcb_pa, host_pa, nasid, &mut regs)? != (Exit::Msr { write: false }) {
            return Err("step 4: expected an RDMSR exit");
        }
        vmcb(vmcb_pa).wr64(off::RIP, (CODE_GPA + 16) as u64);

        if run(vmcb_pa, host_pa, nasid, &mut regs)? != Exit::Halt {
            return Err("step 5: expected HLT");
        }
        if vmcb(vmcb_pa).rd64(off::EXIT_CODE) != code::HLT {
            return Err("step 5: exit code is not HLT");
        }
        Ok(())
    }

    azos_ktest::ktest! {
        fn hv_svm_guest_exits() {
            body()
        }
    }
}

/// The production entry (`azos_arch::hv::vcpu::enter`, the function behind
/// `Hypervisor::enter`) on a real CPU: a PVH guest of one vCPU in 32-bit
/// protected mode whose program asks for what the monitor's loop and the guest
/// OS depend on, one `VMRUN` per step:
///
/// ```text
/// 0x10000  mov eax, 0x40000000
///          cpuid                 served inside enter: EBX = "AzOS"
///          mov edi, 0xD0000000
///          mov [edi], ebx        -> Exit::Mmio, value "AzOS" (the instruction is read from guest memory through the nested tables)
///          xor eax, eax
///          mov edx, 0x3f8
///          in al, dx             served inside enter: an empty bus reads 0xFF
///          mov [edi+4], eax      -> Exit::Mmio, value 0xFF
///          hlt                   -> Exit::Wait
/// ```
///
/// What only hardware confirms: `EFER.SVME` and the host-save page enabled by
/// the entry itself, the PVH start state and the intercept list passing
/// `VMRUN`, the XSAVE swap with `XCR0` around it, the register file across the
/// stub, and the nested-table walk that reads the faulting instruction. Needs
/// QEMU TCG with `-cpu EPYC-Rome,svm=on` (gate row `ktest hv enter (x86 svm)`);
/// on a CPU without usable SVM it passes without running.
#[cfg(feature = "ktest")]
mod enter_test {
    use azos_arch::hv::apic::{ApicEvent, Gp, LocalApic};
    use azos_arch::hv::probe::{self, Kind};
    use azos_arch::hv::vcpu::{self, VmHost, VmInfo};
    use azos_arch::HvImpl;
    use azos_arch_api::{Exit, GuestCtx, Hypervisor, MmioDone, StagePerms, StageTableMem};
    use azos_mm::addr::{phys_to_virt, PhysAddr};
    use azos_mm::pmm;

    const CODE_GPA: u64 = 0x1_0000;
    const DEVICE: u64 = 0xD000_0000;
    const PROGRAM: [u8; 26] = [
        0xB8, 0x00, 0x00, 0x00, 0x40, // mov eax, 0x40000000
        0x0F, 0xA2, // cpuid
        0xBF, 0x00, 0x00, 0x00, 0xD0, // mov edi, 0xD0000000
        0x89, 0x1F, // mov [edi], ebx
        0x31, 0xC0, // xor eax, eax
        0xBA, 0xF8, 0x03, 0x00, 0x00, // mov edx, 0x3f8
        0xEC, // in al, dx
        0x89, 0x47, 0x04, // mov [edi+4], eax
        0xF4, // hlt
    ];

    /// Frames from the page allocator, zeroed, read through the direct map.
    struct Frames;

    impl StageTableMem for Frames {
        fn alloc(&mut self, pages: usize) -> Option<u64> {
            KernelPages.alloc_pages(pages)
        }
        fn free(&mut self, pa: u64, pages: usize) {
            KernelPages.free_pages(pa, pages)
        }
        fn read(&self, pa: u64) -> u64 {
            // SAFETY: a table frame this test allocated: RAM in the direct map.
            unsafe { core::ptr::read_volatile(phys_to_virt(pa as usize) as *const u64) }
        }
        fn write(&mut self, pa: u64, word: u64) {
            // SAFETY: as `read`; nothing else uses these frames.
            unsafe { core::ptr::write_volatile(phys_to_virt(pa as usize) as *mut u64, word) }
        }
    }

    /// The host of the test: frames, one vCPU, and an APIC that refuses everything.
    struct KernelPages;

    impl VmHost for KernelPages {
        fn alloc_pages(&self, pages: usize) -> Option<u64> {
            let pa = pmm::alloc_contiguous_aligned(pages, 4096).ok()?;
            // SAFETY: frames just allocated, in the direct map.
            unsafe { core::ptr::write_bytes(phys_to_virt(pa.as_usize()) as *mut u8, 0, pages * 4096) };
            Some(pa.as_usize() as u64)
        }
        fn free_pages(&self, pa: u64, pages: usize) {
            for i in 0..pages {
                let _ = pmm::free_page(PhysAddr::new(pa as usize + i * 4096));
            }
        }
        fn vm_info(&self, _vmid: u16) -> Option<VmInfo> {
            Some(VmInfo { vcpus: 1, tsc_khz: 0, apic_khz: 0 })
        }
        fn reset_vm(&self, vmid: u16) -> Option<VmInfo> {
            self.vm_info(vmid)
        }
        fn with_apic(&self, _vmid: u16, vcpu: u8, f: &mut dyn FnMut(&mut dyn LocalApic)) -> bool {
            f(&mut NoApic);
            vcpu == 0
        }
        fn raise_lines(&self, _vmid: u16, _lines: u64) {}
        fn release_vm(&self, _vmid: u16) {}
    }

    struct NoApic;

    impl LocalApic for NoApic {
        fn msr_read(&mut self, _: u32, _: u64) -> Result<u64, Gp> {
            Err(Gp)
        }
        fn msr_write(&mut self, _: u32, _: u64, _: u64) -> Result<(), Gp> {
            Err(Gp)
        }
        fn tick(&mut self, _: u64) {}
        fn pending(&self) -> Option<u8> {
            None
        }
        fn ack(&mut self) -> Option<u8> {
            None
        }
        fn take_event(&mut self) -> Option<ApicEvent> {
            None
        }
        fn has_work(&self) -> bool {
            false
        }
        fn next_deadline(&self) -> Option<u64> {
            None
        }
        fn init_reset(&mut self) {}
        fn owns_mmio(&self, _: u64) -> bool {
            false
        }
        fn mmio_read(&mut self, _: u64, _: u8, _: u64) -> u32 {
            0
        }
        fn mmio_write(&mut self, _: u64, _: u8, _: u32, _: u64) {}
    }

    fn body() -> Result<(), &'static str> {
        if probe::record().kind != Kind::Svm {
            return Ok(());
        }
        let hv = HvImpl;
        let mut mem = Frames;
        let s2 = hv.stage2_create(&mut mem).map_err(|_| "stage2_create")?;
        let code = mem.alloc(1).ok_or("no code frame")?;
        // SAFETY: a page this test owns.
        unsafe { core::ptr::copy_nonoverlapping(PROGRAM.as_ptr(), phys_to_virt(code as usize) as *mut u8, PROGRAM.len()) };
        hv.stage2_map(&s2, &mut mem, CODE_GPA, code, StagePerms::RX).map_err(|_| "stage2_map")?;

        let host = KernelPages;
        let mut ctx = GuestCtx::new(s2, 1, 0, CODE_GPA, 0);
        let mut cpu = azos_arch::hv::hw::Hw(&host);
        let mut run = |ctx: &mut GuestCtx| vcpu::enter(&mut cpu, &host, ctx);

        let r = (|| {
            let Exit::Mmio(a) = run(&mut ctx) else { return Err("step 1: expected a device store") };
            if a.gpa != DEVICE || !a.write || a.size != 4 || ctx.mmio_value != 0x534F_7A41 {
                return Err("step 1: the store is not [0xD0000000] <- \"AzOS\" (CPUID leaf 0x40000000, EBX)");
            }
            ctx.completed = Some(MmioDone { access: a, value: 0 });
            let Exit::Mmio(a) = run(&mut ctx) else { return Err("step 2: expected a device store") };
            if a.gpa != DEVICE + 4 || !a.write || ctx.mmio_value != 0xFF {
                return Err("step 2: the store is not [0xD0000004] <- 0xFF (an IN on an empty bus)");
            }
            ctx.completed = Some(MmioDone { access: a, value: 0 });
            if run(&mut ctx) != Exit::Wait {
                return Err("step 3: expected HLT to be a wait");
            }
            Ok(())
        })();
        vcpu::slots_release(&host, s2.root);
        hv.stage2_destroy(s2, &mut mem);
        mem.free(code, 1);
        r
    }

    azos_ktest::ktest! {
        fn hv_enter_guest() {
            body()
        }
    }
}
