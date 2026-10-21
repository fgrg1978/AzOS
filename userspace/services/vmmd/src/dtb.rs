// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device tree of a riscv64 or aarch64 guest: a flattened device tree
//! (FDT, devicetree specification v0.4) built from what the row declares, to
//! be placed in the guest's RAM with its address in the boot register.
//!
//! A guest has no firmware that could describe its machine, so this is the
//! whole description. It says:
//!
//! * `/memory`: the guest's RAM, `ram_base` for `ram_bytes`;
//! * `/cpus`: one `cpu@k` per vCPU, with the way the guest brings a secondary
//!   one up: riscv64 `sbi` (the SBI HSM extension: `hart_start`), aarch64
//!   `psci` (and a `/psci` node, method `hvc`: `CPU_ON` is an `hvc` to the
//!   hypervisor). riscv64 also gives `timebase-frequency`; aarch64 has the
//!   generic timer node instead (`arm,armv8-timer`, the architectural PPIs);
//! * the interrupt controller the monitor presents to the guest: a PLIC on
//!   riscv64 (`sifive,plic-1.0.0`; context `k` is hart `k`'s supervisor
//!   external interrupt, there is no machine mode in a guest) and a GICv3 on
//!   aarch64 (distributor, then one redistributor frame per vCPU);
//! * `/soc/virtio_mmio@…`: a `virtio,mmio` node with `reg` and `interrupts`
//!   for each device of the row the monitor has a model for, at the window
//!   and line `model` gives it;
//! * `/chosen`: `bootargs` (the owner's command line) and `stdout-path`, the
//!   guest's virtio-console when the row has one.
//!
//! The tree is built into the caller's buffer, no allocation: the strings
//! block is a small table of its own, written after the structure block when
//! the tree is finished. Every `put` checks the buffer, so a tree that does
//! not fit is an error, not a short write.

use crate::loader::Isa;
use crate::mmio::WINDOW;
use crate::model::Kind;
use core::fmt::Write;

/// The most bytes a tree takes: the buffer the monitor builds into. 16 vCPUs
/// and 16 devices come to under 6 KiB.
pub const MAX_BYTES: usize = 8192;
/// vCPUs a tree describes (`life::VCPUS`).
pub const MAX_CPUS: usize = 16;

/// Where the platform puts the guest's devices: the machine model a guest
/// kernel is built for. One table per ISA, here so the interrupt controller's
/// emulation and the tree read the same addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    /// The first virtio-mmio window (`model::MMIO_BASE` is the host ISA's).
    pub mmio_base: u64,
    /// The first device's interrupt line (`model::irq_line` reads the host ISA's): a PLIC source
    /// on riscv64, a GIC interrupt id on aarch64 (SPIs start at 32).
    pub irq_base: u32,
    /// riscv64: the PLIC; aarch64: the GICv3 distributor.
    pub intc_base: u64,
    pub intc_len: u64,
    /// aarch64: the first redistributor frame, one `redist_stride` per vCPU.
    pub redist_base: u64,
    pub redist_stride: u64,
    /// riscv64: the PLIC's `riscv,ndev`.
    pub plic_sources: u32,
}

/// The platform of `isa` (RISC-V `virt`, ARM `virt`; x86 has no tree, only
/// the window and line of its devices).
pub const fn platform(isa: Isa) -> Platform {
    match isa {
        Isa::Riscv64 => Platform {
            mmio_base: 0x1000_1000,
            irq_base: 1,
            intc_base: 0x0c00_0000,
            intc_len: 0x60_0000,
            redist_base: 0,
            redist_stride: 0,
            plic_sources: 63,
        },
        Isa::Aarch64 => Platform {
            mmio_base: 0x0a00_0000,
            irq_base: 48,
            intc_base: 0x0800_0000,
            intc_len: 0x1_0000,
            redist_base: 0x080a_0000,
            redist_stride: 0x2_0000,
            plic_sources: 0,
        },
        Isa::X86_64 => Platform {
            mmio_base: 0xd000_0000,
            irq_base: 5,
            intc_base: 0,
            intc_len: 0,
            redist_base: 0,
            redist_stride: 0,
            plic_sources: 0,
        },
    }
}

/// What the tree is built from.
pub struct Config<'a> {
    pub isa: Isa,
    pub ram_base: u64,
    pub ram_bytes: u64,
    /// The row's vCPUs.
    pub cpus: usize,
    /// The guest's timer frequency (riscv64: the host's `time` counter, which
    /// a guest reads directly).
    pub timebase_hz: u32,
    /// The kind of backend at each device index of the row (`None`: the
    /// monitor has no model, so no node).
    pub devices: &'a [Option<Kind>],
    /// The owner's command line.
    pub args: &'a [u8],
}

/// Why no tree was built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtbError {
    /// The ISA has no device tree (x86_64 boots by PVH, `pvh`), or the
    /// configuration is empty or too large: no vCPU, more than [`MAX_CPUS`],
    /// no RAM.
    BadConfig,
    /// The tree does not fit the buffer (or its strings table).
    Full,
}

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;
const HEADER: usize = 40;
/// The memory reservation block: its terminating entry only.
const RSVMAP: usize = 16;
const STRINGS: usize = 512;

/// Interrupt-type cells of the GIC binding.
const GIC_SPI: u32 = 0;
const GIC_PPI: u32 = 1;
const IRQ_LEVEL_HIGH: u32 = 4;
/// `S-mode external interrupt` in the CPU interrupt controller's numbering.
const RISCV_IRQ_S_EXT: u32 = 9;

/// A small `fmt::Write` target for node names and paths.
struct Name {
    b: [u8; 64],
    n: usize,
}

impl Name {
    fn new() -> Name {
        Name { b: [0; 64], n: 0 }
    }

    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

impl Write for Name {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.n + s.len();
        if end > self.b.len() {
            return Err(core::fmt::Error);
        }
        self.b[self.n..end].copy_from_slice(s.as_bytes());
        self.n = end;
        Ok(())
    }
}

/// `prefix@hex`.
fn unit(prefix: &str, addr: u64) -> Name {
    let mut n = Name::new();
    // Cannot overflow 64 bytes: the prefixes are short and the address has 16 digits.
    let _ = write!(n, "{prefix}@{addr:x}");
    n
}

/// The flattened tree under construction.
struct Fdt<'a> {
    out: &'a mut [u8],
    /// Next byte of the structure block.
    at: usize,
    strs: [u8; STRINGS],
    nstr: usize,
    full: bool,
}

impl<'a> Fdt<'a> {
    fn new(out: &'a mut [u8]) -> Fdt<'a> {
        Fdt { out, at: HEADER + RSVMAP, strs: [0; STRINGS], nstr: 0, full: false }
    }

    fn put(&mut self, bytes: &[u8]) {
        match self.at.checked_add(bytes.len()).filter(|&e| e <= self.out.len()) {
            Some(end) => {
                self.out[self.at..end].copy_from_slice(bytes);
                self.at = end;
            }
            None => self.full = true,
        }
    }

    fn pad(&mut self) {
        while self.at % 4 != 0 && !self.full {
            self.put(&[0]);
        }
    }

    fn token(&mut self, t: u32) {
        self.put(&t.to_be_bytes());
    }

    fn begin(&mut self, name: &[u8]) {
        self.token(FDT_BEGIN_NODE);
        self.put(name);
        self.put(&[0]);
        self.pad();
    }

    fn end(&mut self) {
        self.token(FDT_END_NODE);
    }

    /// Offset of `name` in the strings block, adding it if it is new.
    fn string(&mut self, name: &str) -> u32 {
        let name = name.as_bytes();
        let mut at = 0;
        while at < self.nstr {
            let len = self.strs[at..self.nstr].iter().position(|&c| c == 0).unwrap_or(0);
            if &self.strs[at..at + len] == name {
                return at as u32;
            }
            at += len + 1;
        }
        let end = self.nstr + name.len() + 1;
        if end > STRINGS {
            self.full = true;
            return 0;
        }
        self.strs[self.nstr..end - 1].copy_from_slice(name);
        self.strs[end - 1] = 0;
        let off = self.nstr;
        self.nstr = end;
        off as u32
    }

    fn prop(&mut self, name: &str, data: &[u8]) {
        let off = self.string(name);
        self.token(FDT_PROP);
        self.put(&(data.len() as u32).to_be_bytes());
        self.put(&off.to_be_bytes());
        self.put(data);
        self.pad();
    }

    fn flag(&mut self, name: &str) {
        self.prop(name, &[]);
    }

    fn u32(&mut self, name: &str, v: u32) {
        self.prop(name, &v.to_be_bytes());
    }

    /// A NUL-terminated string (`strs` several: a string list).
    fn strings(&mut self, name: &str, strs: &[&[u8]]) {
        let off = self.string(name);
        let len: usize = strs.iter().map(|s| s.len() + 1).sum();
        self.token(FDT_PROP);
        self.put(&(len as u32).to_be_bytes());
        self.put(&off.to_be_bytes());
        for s in strs {
            self.put(s);
            self.put(&[0]);
        }
        self.pad();
    }

    fn str(&mut self, name: &str, s: &[u8]) {
        self.strings(name, &[s]);
    }

    /// A list of 32-bit cells.
    fn cells(&mut self, name: &str, cells: &[u32]) {
        let off = self.string(name);
        self.token(FDT_PROP);
        self.put(&(cells.len() as u32 * 4).to_be_bytes());
        self.put(&off.to_be_bytes());
        for c in cells {
            self.put(&c.to_be_bytes());
        }
    }

    /// `reg` of a parent with two address and two size cells.
    fn reg(&mut self, base: u64, len: u64) {
        self.cells("reg", &[(base >> 32) as u32, base as u32, (len >> 32) as u32, len as u32]);
    }

    /// Close the tree: the header, the memory reservation block (empty) and
    /// the strings after the structure block. The tree's size.
    fn finish(mut self) -> Result<usize, DtbError> {
        self.token(FDT_END);
        let off_strings = self.at;
        let nstr = self.nstr;
        let strs = self.strs;
        self.put(&strs[..nstr]);
        self.pad();
        if self.full {
            return Err(DtbError::Full);
        }
        let total = self.at;
        let o = &mut *self.out;
        o[..HEADER + RSVMAP].fill(0);
        let header = [
            FDT_MAGIC,
            total as u32,
            (HEADER + RSVMAP) as u32,
            off_strings as u32,
            HEADER as u32,
            17, // version
            16, // last compatible version
            0,  // boot cpu
            nstr as u32,
            (off_strings - HEADER - RSVMAP) as u32,
        ];
        for (i, w) in header.iter().enumerate() {
            o[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        Ok(total)
    }
}

/// Build the tree of the guest `c` describes into `out` ([`MAX_BYTES`] is
/// enough for any row). The tree's length.
pub fn build(c: &Config, out: &mut [u8]) -> Result<usize, DtbError> {
    if c.isa == Isa::X86_64 || c.cpus == 0 || c.cpus > MAX_CPUS || c.ram_bytes == 0 || c.devices.len() > crate::model::MAX_DEVICES
    {
        return Err(DtbError::BadConfig);
    }
    let rv = c.isa == Isa::Riscv64;
    let p = platform(c.isa);
    // The interrupt controller's phandle: after the cpu interrupt controllers on riscv64.
    let intc = if rv { c.cpus as u32 + 1 } else { 1 };

    let mut f = Fdt::new(out);
    f.begin(b"");
    f.str("compatible", if rv { b"azos,vm-riscv64" } else { b"azos,vm-aarch64" });
    f.str("model", b"AzOS guest");
    f.u32("#address-cells", 2);
    f.u32("#size-cells", 2);
    f.u32("interrupt-parent", intc);

    f.begin(b"chosen");
    if !c.args.is_empty() {
        f.str("bootargs", c.args);
    }
    let console = c.devices.iter().position(|k| *k == Some(Kind::Console));
    if let Some(i) = console {
        let mut path = Name::new();
        let _ = write!(path, "/soc/virtio_mmio@{:x}", device_base(&p, i));
        f.str("stdout-path", path.bytes());
    }
    f.end();

    f.begin(unit("memory", c.ram_base).bytes());
    f.str("device_type", b"memory");
    f.reg(c.ram_base, c.ram_bytes);
    f.end();

    f.begin(b"cpus");
    f.u32("#address-cells", 1);
    f.u32("#size-cells", 0);
    if rv {
        f.u32("timebase-frequency", c.timebase_hz);
    }
    for k in 0..c.cpus {
        f.begin(unit("cpu", k as u64).bytes());
        f.str("device_type", b"cpu");
        f.u32("reg", k as u32);
        f.str("status", b"okay");
        if rv {
            f.str("compatible", b"riscv");
            f.str("riscv,isa", b"rv64imac");
            f.str("mmu-type", b"riscv,sv39");
            f.str("enable-method", b"sbi");
            f.begin(b"interrupt-controller");
            f.u32("#interrupt-cells", 1);
            f.str("compatible", b"riscv,cpu-intc");
            f.flag("interrupt-controller");
            f.u32("phandle", k as u32 + 1);
            f.end();
        } else {
            f.str("compatible", b"arm,armv8");
            f.str("enable-method", b"psci");
        }
        f.end();
    }
    f.end();

    if !rv {
        f.begin(b"psci");
        f.strings("compatible", &[b"arm,psci-1.0", b"arm,psci-0.2", b"arm,psci"]);
        f.str("method", b"hvc");
        f.end();

        f.begin(b"timer");
        f.str("compatible", b"arm,armv8-timer");
        f.flag("always-on");
        // Secure physical, non-secure physical, virtual, hypervisor: PPIs 13, 14, 11, 10.
        let ppi = |n| [GIC_PPI, n, IRQ_LEVEL_HIGH];
        let mut irqs = [0u32; 12];
        for (i, n) in [13, 14, 11, 10].into_iter().enumerate() {
            irqs[i * 3..i * 3 + 3].copy_from_slice(&ppi(n));
        }
        f.cells("interrupts", &irqs);
        f.end();
    }

    f.begin(b"soc");
    f.strings("compatible", &[b"simple-bus"]);
    f.u32("#address-cells", 2);
    f.u32("#size-cells", 2);
    f.flag("ranges");

    if rv {
        f.begin(unit("plic", p.intc_base).bytes());
        f.strings("compatible", &[b"sifive,plic-1.0.0", b"riscv,plic0"]);
        f.reg(p.intc_base, p.intc_len);
        f.u32("riscv,ndev", p.plic_sources);
        let mut ext = [0u32; 2 * MAX_CPUS];
        for k in 0..c.cpus {
            ext[2 * k] = k as u32 + 1;
            ext[2 * k + 1] = RISCV_IRQ_S_EXT;
        }
        f.cells("interrupts-extended", &ext[..2 * c.cpus]);
        f.u32("phandle", intc);
        f.flag("interrupt-controller");
        f.u32("#interrupt-cells", 1);
        // Last: the kernel's parser (azos_dtb) reads a node's `reg` with the
        // `#address-cells` in scope, so a node's own cells must come after it
        // (as QEMU writes this node).
        f.u32("#address-cells", 0);
        f.end();
    } else {
        f.begin(unit("interrupt-controller", p.intc_base).bytes());
        f.str("compatible", b"arm,gic-v3");
        f.u32("#interrupt-cells", 3);
        f.flag("interrupt-controller");
        let redist = p.redist_stride * c.cpus as u64;
        f.cells(
            "reg",
            &[
                (p.intc_base >> 32) as u32,
                p.intc_base as u32,
                (p.intc_len >> 32) as u32,
                p.intc_len as u32,
                (p.redist_base >> 32) as u32,
                p.redist_base as u32,
                (redist >> 32) as u32,
                redist as u32,
            ],
        );
        f.u32("phandle", intc);
        f.end();
    }

    for (i, k) in c.devices.iter().enumerate() {
        if k.is_none() {
            continue;
        }
        let line = device_line(&p, i);
        f.begin(unit("virtio_mmio", device_base(&p, i)).bytes());
        f.str("compatible", b"virtio,mmio");
        f.reg(device_base(&p, i), WINDOW);
        if rv {
            f.cells("interrupts", &[line]);
        } else {
            // A GIC interrupt id from 32 up is SPI `id - 32`.
            f.cells("interrupts", &[GIC_SPI, line.saturating_sub(32), IRQ_LEVEL_HIGH]);
            // The device model reads and writes the guest's RAM through the same
            // cache as the guest does.
            f.flag("dma-coherent");
        }
        f.end();
    }
    f.end(); // soc
    f.end(); // root
    f.finish()
}

/// Where device `index`'s window starts on `p`.
pub const fn device_base(p: &Platform, index: usize) -> u64 {
    p.mmio_base + index as u64 * WINDOW
}

/// The interrupt line of device `index` on `p`.
pub const fn device_line(p: &Platform, index: usize) -> u32 {
    p.irq_base + index as u32
}
