// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The life of a guest's vCPUs, as the monitor drives it: put the kernel and
//! its boot information in RAM, start the boot CPU, notice that the guest is
//! over, stop what still runs, wait for the threads to end.
//!
//! Pure over [`Cpu`] (one `vcpu.<n>.<k>` endpoint), so the host tests run
//! the same code `VMMD.ELF` runs against a model of the kernel's threads
//! (`tests/host/vmmd-tests/src/life_tests.rs`, `guest_boot.rs`).
//!
//! # The boot protocol
//!
//! A guest is an AzOS (or any) kernel ELF read from the volume
//! (`loader`) with the machine it will find described to it ([`prepare`]):
//!
//! | ISA | description | `Vcpu::start(pc, arg)` |
//! |-----|-------------|------------------------|
//! | riscv64 | flattened device tree (`dtb`) | `pc` the ELF entry, `arg` the tree's address, which the entry puts in `a1` (`a0` is the hart id, 0) |
//! | aarch64 | flattened device tree (`dtb`) | `pc` the ELF entry, `arg` the tree's address, in `x0` |
//! | x86_64 | PVH `hvm_start_info` (`pvh`) | `pc` the kernel's 32-bit entry, `arg` the start_info's address, in `ebx`, in 32-bit protected mode with paging off |
//!
//! Only vCPU 0 starts. The others stay stopped until the guest asks for them
//! the way its ISA does (SBI HSM `hart_start`, PSCI `CPU_ON`, an INIT-SIPI),
//! which the monitor serves by starting that vCPU at the address the guest
//! gave: [`boot`] starts the boot CPU, [`watch`] looks at the ones that have
//! been started.
//!
//! # When the guest is over
//!
//! A vCPU thread ends on `stop` or on an exit nothing serves (a shutdown, a
//! fault), and until the guest can take a CPU offline by itself a vCPU that
//! left ends the guest: [`watch`] says so, the monitor [`halt`]s the rest and
//! gives the VM back.

use crate::dtb;
use crate::guest::GuestMem;
use crate::loader::{self, Isa, LoadError, Source};
use crate::model::{self, Kind};
use crate::pvh;

/// vCPUs this program serves: a trap names its vCPU in a byte and the kick
/// mask has a bit for each. The built-in row grants this many endpoints at
/// most (`azos_topology::builder`).
pub const VCPUS: usize = 16;

/// `Vcpu::state`, low byte: a thread runs the vCPU
/// (`azos_devif::vm::RUN_RUNNING`; the monitor checks the value at build time).
pub const RUN_RUNNING: u64 = 1;
/// `Vcpu::state`, low byte: the thread ended on an exit nothing serves, and
/// bits 8..64 say which (`azos_devif::vm::RUN_FAULTED`).
pub const RUN_FAULTED: u64 = 2;

/// One vCPU endpoint (`Vcpu`), as far as the life of a guest goes.
pub trait Cpu {
    /// `Vcpu::start(pc, arg)`: `Err` carries the outcome.
    fn launch(&mut self, pc: u64, arg: u64) -> Result<(), u32>;
    /// `Vcpu::stop`. Refused (`BUSY`) when the vCPU does not run: the answer
    /// is not needed, the state tells.
    fn request_stop(&mut self);
    /// `Vcpu::state`: `None` when the call did not reach the interface.
    fn run_state(&mut self) -> Option<u64>;
}

/// Where a vCPU starts: `Vcpu::start`'s arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub pc: u64,
    pub arg: u64,
}

/// What [`boot`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boot {
    /// The boot CPU runs.
    Started,
    /// The row has more vCPUs than this program serves ([`VCPUS`]).
    TooMany,
    /// The row grants no endpoint for this vCPU: nothing was started. A guest
    /// whose secondary CPUs could never be started is not the guest the row
    /// declares.
    NoEndpoint(usize),
    /// The boot CPU refused to start (the outcome).
    Refused(u32),
}

/// Start vCPU 0 at `entry`; vCPUs `1..count` wait for the guest to ask.
pub fn boot<C: Cpu>(cpus: &mut [Option<C>], count: usize, entry: Entry) -> Boot {
    if count == 0 || count > VCPUS || count > cpus.len() {
        return Boot::TooMany;
    }
    if let Some(k) = cpus[..count].iter().position(Option::is_none) {
        return Boot::NoEndpoint(k);
    }
    let Some(c) = cpus[0].as_mut() else { return Boot::NoEndpoint(0) };
    match c.launch(entry.pc, entry.arg) {
        Ok(()) => Boot::Started,
        Err(code) => Boot::Refused(code),
    }
}

/// What the guest is made of, for [`prepare`].
pub struct Setup<'a> {
    pub isa: Isa,
    /// The row's vCPUs.
    pub cpus: usize,
    /// The guest's timer frequency (`dtb::Config::timebase_hz`).
    pub timebase_hz: u32,
    /// The backend at each device index of the row.
    pub devices: &'a [Option<Kind>],
    /// The kernel's command line.
    pub args: &'a [u8],
}

/// Why a guest could not be prepared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// The kernel was refused.
    Kernel(LoadError),
    /// No device tree could be built.
    Tree(dtb::DtbError),
    /// No boot information could be built.
    Pvh(pvh::PvhError),
    /// The boot information has no place in RAM: it would overlap the kernel
    /// or leave RAM.
    NoRoom,
}

impl PrepareError {
    /// For the monitor's log.
    pub fn reason(&self) -> &'static [u8] {
        match self {
            PrepareError::Kernel(LoadError::Read) => b"reading the kernel failed",
            PrepareError::Kernel(LoadError::Truncated) => b"the kernel file ends early",
            PrepareError::Kernel(LoadError::NotElf) => b"the kernel is not an ELF64 executable",
            PrepareError::Kernel(LoadError::Machine) => b"the kernel is for another ISA",
            PrepareError::Kernel(LoadError::Phdrs) => b"the kernel's program headers are malformed",
            PrepareError::Kernel(LoadError::Loads) => b"the kernel has no loadable segment, or too many",
            PrepareError::Kernel(LoadError::BadSegment) => b"a kernel segment is malformed",
            PrepareError::Kernel(LoadError::OutOfRam) => b"a kernel segment lies outside the guest's RAM",
            PrepareError::Kernel(LoadError::Overlap) => b"two kernel segments overlap",
            PrepareError::Kernel(LoadError::BadEntry) => b"the kernel's entry lies in no segment",
            PrepareError::Kernel(LoadError::NoPvhEntry) => b"the kernel has no PVH entry note",
            PrepareError::Tree(_) => b"the device tree could not be built",
            PrepareError::Pvh(_) => b"the PVH boot information could not be built",
            PrepareError::NoRoom => b"the boot information has no room in the guest's RAM",
        }
    }
}

/// The scratch [`prepare`] needs: the chunk the kernel is read through, then
/// the room the description is built in. Lent by the caller: the task's stack
/// is small.
pub const SCRATCH_BYTES: usize = dtb::MAX_BYTES;
const _: () = assert!(pvh::MAX_BYTES <= SCRATCH_BYTES);

/// Load the kernel from `src` into `ram` and put the description of the
/// machine next to it; the boot CPU's [`Entry`].
///
/// riscv64 and aarch64 have no firmware below the kernel, so the tree goes
/// where firmware would be (the start of RAM) when it fits under the image,
/// else right above it. x86_64's start_info has a fixed place ([`pvh::BASE`],
/// below the kernel at 1 MiB), and the guest's RAM starts at 0.
pub fn prepare(
    src: &mut dyn Source,
    ram: &mut dyn GuestMem,
    s: &Setup,
    scratch: &mut [u8],
) -> Result<Entry, PrepareError> {
    let (ram_base, ram_bytes) = ram.range();
    let image = loader::load(src, ram, s.isa, scratch).map_err(PrepareError::Kernel)?;
    let p = dtb::platform(s.isa);
    if s.isa == Isa::X86_64 {
        if ram_base != 0 {
            return Err(PrepareError::NoRoom);
        }
        let mut devices = [(0u64, 0u64, 0u32); model::MAX_DEVICES];
        let mut n = 0;
        for (i, k) in s.devices.iter().enumerate().take(model::MAX_DEVICES) {
            if k.is_some() {
                devices[n] = (dtb::device_base(&p, i), crate::mmio::WINDOW, dtb::device_line(&p, i));
                n += 1;
            }
        }
        let info = pvh::Info { ram_bytes, devices: &devices[..n], args: s.args };
        let len = pvh::build(&info, scratch).map_err(PrepareError::Pvh)?;
        if image.low < pvh::BASE + len as u64 {
            return Err(PrepareError::NoRoom);
        }
        ram.write(pvh::BASE, &scratch[..len]).map_err(|_| PrepareError::NoRoom)?;
        return Ok(Entry { pc: image.entry, arg: pvh::BASE });
    }
    let cfg = dtb::Config {
        isa: s.isa,
        ram_base,
        ram_bytes,
        cpus: s.cpus,
        timebase_hz: s.timebase_hz,
        devices: s.devices,
        args: s.args,
    };
    let len = dtb::build(&cfg, scratch).map_err(PrepareError::Tree)? as u64;
    let at = if ram_base + len <= image.low { ram_base } else { (image.high + 0xFFF) & !0xFFF };
    if !ram.contains(at, len) {
        return Err(PrepareError::NoRoom);
    }
    ram.write(at, &scratch[..len as usize]).map_err(|_| PrepareError::NoRoom)?;
    Ok(Entry { pc: image.entry, arg: at })
}

/// What [`watch`] saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Watch {
    /// Every vCPU runs.
    Running,
    /// A vCPU left. `fault` is the state word of the first one that ended on
    /// an exit nothing serves (`None` when it was stopped).
    Over { fault: Option<u64> },
}

/// Look at the vCPUs of `0..count` that were started (bit `k` of `started`
/// for vCPU `k`: [`boot`] started vCPU 0, the monitor adds the ones the guest
/// asked for).
pub fn watch<C: Cpu>(cpus: &mut [Option<C>], count: usize, started: u64) -> Watch {
    let mut over = false;
    let mut fault = None;
    for (k, c) in cpus.iter_mut().enumerate().take(count) {
        let Some(c) = c.as_mut().filter(|_| started >> k & 1 != 0) else { continue };
        match c.run_state() {
            Some(s) if s & 0xFF == RUN_RUNNING => {}
            Some(s) if s & 0xFF == RUN_FAULTED => {
                over = true;
                fault = fault.or(Some(s));
            }
            _ => over = true,
        }
    }
    if over {
        Watch::Over { fault }
    } else {
        Watch::Running
    }
}

/// Ask every vCPU of `0..count` that still runs to stop, and wait for the
/// threads to end: `pause` sleeps one slice (it is the port wait of the
/// monitor), at most `slices` times. `true` when none runs any more, which
/// is what `Vm::destroy` needs.
pub fn halt<C: Cpu>(cpus: &mut [Option<C>], count: usize, slices: u32, pause: &mut dyn FnMut()) -> bool {
    for left in (0..=slices).rev() {
        let mut running = false;
        for c in cpus.iter_mut().take(count).flatten() {
            if matches!(c.run_state(), Some(s) if s & 0xFF == RUN_RUNNING) {
                c.request_stop();
                running = true;
            }
        }
        if !running {
            return true;
        }
        if left > 0 {
            pause();
        }
    }
    false
}
