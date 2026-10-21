// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `VmCtl` interface: how a task launches and ends a guest.
//!
//! `Vm` and `Vcpu` (module `vm`) are the kernel's side of a guest and only the
//! guest's monitor holds them. `VmCtl` is the monitor's own front: the
//! interface `VMMD.ELF` serves on `endpoint.vmctl`, which the name server
//! lends to the rows that import `vmctl` (the user shell's tools). **The
//! caller's authority is its warrant for that endpoint, and nothing more**:
//! what a guest may do is what the signed `[guest.NAME]` row and the
//! monitor's own row allow, so a caller can name a smaller guest than the row
//! declares, never a larger one, and can name a kernel only beneath the one
//! directory the monitor holds.
//!
//! A guest is a *row* of the signed topology (its CPUs, memory, devices and
//! envelope); the monitor builds a virtual machine from one, loads a kernel
//! into it and starts it:
//!
//! * [`VmCtl::create`] builds the machine of row `row` and loads the kernel
//!   `image` into it, beneath the monitor's guest directory (`/fat/VM`). The
//!   guest sees `cpus` CPUs and `mem_mib` MiB of RAM, 0 for what the row
//!   declares; more than the row is refused. Nothing runs yet.
//! * [`VmCtl::start`] starts the boot CPU. [`VmCtl::stop`] ends the guest and
//!   gives the machine back; the row can then be created again.
//! * [`VmCtl::console`] lends the caller the guest's console output: a ring
//!   (one producer, the monitor) in a region the caller maps and drains. The
//!   bytes pass the monitor's console filter and volume limit as they do on
//!   the operator's console.
//! * [`VmCtl::pause`] holds a running guest: every vCPU stops entering guest
//!   mode, keeps its registers and the interrupt lines raised meanwhile, and
//!   the guest's clock does not count the time held. The hold is taken within
//!   a timer tick (or when a device model's answer lands): until every vCPU
//!   took it the entry reads [`STATE_PAUSING`], then [`STATE_PAUSED`].
//!   [`VmCtl::resume`] lets it run on, and [`VmCtl::stop`] ends a held guest
//!   like any other. The monitor's device models keep running while the guest
//!   is held: a request already in flight completes, and the console ring
//!   keeps what the guest wrote before.
//! * [`VmCtl::list`] reads the table: one entry per row the monitor serves.
//!
//! # Refusals
//!
//! Every refusal answers a [`Receipt`]: the cause ([`cause`]), the number
//! that explains it (the ceiling a request exceeded, the loader's error) and
//! a serial that counts the refusals the monitor has made. The monitor logs
//! the same line. A caller without the warrant never reaches the monitor:
//! that refusal is the kernel's capability denial, in the decision journal.

use crate::outcome::Out;
use azos_idl::{azos_interface, Lent, Reader, Wire, Writer};

/// The `VmCtl` interface id (ASCII "VM", then 0003).
pub const VMCTL_ID: u32 = 0x564D_0003;

/// The name the monitor's endpoint is lent by (`endpoint.vmctl`; a row's
/// `imports` entry).
pub const NAME: &[u8] = b"vmctl";

/// What a `Lent<ConsoleRing>` names: the region of a guest's console output,
/// an `azos_rings` byte ring of [`CONSOLE_RING_CAP`] data bytes at its start,
/// [`CONSOLE_RING_PAGES`] pages in all. The monitor is the producer; the
/// holder is the consumer and moves the tail.
///
/// The ring ends when the monitor stops writing to it: the guest is over, or
/// another tool took the console and got a ring of its own. The monitor says
/// so with [`ConsoleRing::close`], a word in the ring's head line that the
/// ring protocol does not use; the holder reads it with
/// [`ConsoleRing::closed`], drains what is left, and ends. (The ring is
/// otherwise silent when nobody writes: an empty ring cannot tell "the guest
/// is quiet" from "nobody will ever write".)
pub struct ConsoleRing;

/// Offset of the closed word in the ring region: the head line's second word
/// (the first is the head index).
const CLOSED_OFF: usize = 8;

impl ConsoleRing {
    fn closed_word(base: usize) -> &'static core::sync::atomic::AtomicU32 {
        // SAFETY: `base` is the start of a console ring's region (2 pages,
        // 64-byte aligned, zero when made), shared by the monitor and its one
        // holder; the word lies inside the head line.
        unsafe { &*((base + CLOSED_OFF) as *const core::sync::atomic::AtomicU32) }
    }

    /// Monitor: the ring at `base` is not written any more. Call it after the
    /// last byte was published and before the region is released.
    pub fn close(base: usize) {
        Self::closed_word(base).store(1, core::sync::atomic::Ordering::Release);
    }

    /// Holder: has the monitor stopped writing the ring at `base`? Bytes
    /// published before the close are visible once this answers `true`, so a
    /// last drain after it takes everything.
    pub fn closed(base: usize) -> bool {
        Self::closed_word(base).load(core::sync::atomic::Ordering::Acquire) != 0
    }
}

/// Data bytes of the console ring (a power of two).
pub const CONSOLE_RING_CAP: u32 = 4096;
/// Pages of the console ring's region: the ring's header lines and its data.
pub const CONSOLE_RING_PAGES: u64 = 2;

/// Bytes of an image name: a path beneath the monitor's guest directory.
pub const IMAGE_MAX: usize = 32;
/// Words of a packed image name.
pub const IMAGE_WORDS: usize = IMAGE_MAX / 8;

/// An image name on the wire: up to [`IMAGE_MAX`] bytes, zero-padded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImageName(pub [u64; IMAGE_WORDS]);

impl ImageName {
    /// `name` packed; `None` for an empty or over-long one (refused, never
    /// truncated).
    pub fn pack(name: &[u8]) -> Option<ImageName> {
        if name.is_empty() || name.len() > IMAGE_MAX {
            return None;
        }
        let mut b = [0u8; IMAGE_MAX];
        b[..name.len()].copy_from_slice(name);
        Some(ImageName(core::array::from_fn(|i| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i * 8..i * 8 + 8]);
            u64::from_le_bytes(w)
        })))
    }

    /// The bytes up to the first zero: copied into `out`, and how many.
    pub fn unpack(&self, out: &mut [u8; IMAGE_MAX]) -> usize {
        for (i, w) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out.iter().position(|&c| c == 0).unwrap_or(IMAGE_MAX)
    }
}

impl Wire for ImageName {
    const WORDS: usize = IMAGE_WORDS;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.0.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        ImageName(<[u64; IMAGE_WORDS]>::get(r))
    }
}

/// [`Info::state`]: the row is declared and no machine is built.
pub const STATE_FREE: u32 = 0;
/// [`Info::state`]: the machine is built and holds its kernel; no CPU runs.
pub const STATE_CREATED: u32 = 1;
/// [`Info::state`]: the guest runs.
pub const STATE_RUNNING: u32 = 2;

/// [`Info::state`]: a pause was asked and some vCPU still enters the guest.
pub const STATE_PAUSING: u32 = 3;
/// [`Info::state`]: every vCPU holds the guest; nothing of it runs.
pub const STATE_PAUSED: u32 = 4;

/// [`Info::ended`]: the row has not run since the monitor started.
pub const ENDED_NEVER: u32 = 0;
/// [`Info::ended`]: the last run was stopped (by a caller, or a CPU stopped).
pub const ENDED_STOPPED: u32 = 1;
/// [`Info::ended`]: the last run ended on an exit nothing serves.
pub const ENDED_FAULTED: u32 = 2;

/// One entry of the table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    /// The VM's id: the row's position (`vm.<id>`).
    pub id: u32,
    /// [`STATE_FREE`], [`STATE_CREATED`], [`STATE_RUNNING`], [`STATE_PAUSING`]
    /// or [`STATE_PAUSED`].
    pub state: u32,
    /// CPUs the guest sees (the row's, while free).
    pub cpus: u32,
    /// MiB of RAM the guest sees (the row's, while free).
    pub mem_mib: u32,
    /// How the last run ended: `ENDED_*`.
    pub ended: u32,
}

impl Wire for Info {
    const WORDS: usize = 5;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        for v in [self.id, self.state, self.cpus, self.mem_mib, self.ended] {
            v.put(w);
        }
    }
    fn get(r: &mut Reader<'_>) -> Self {
        Info { id: u32::get(r), state: u32::get(r), cpus: u32::get(r), mem_mib: u32::get(r), ended: u32::get(r) }
    }
}

/// Why a request was refused ([`Receipt::cause`]); 0 is served.
pub mod cause {
    /// Served.
    pub const NONE: u32 = 0;
    /// The monitor serves no VM for this row (`arg`: how many rows it serves).
    pub const NO_SUCH_ROW: u32 = 1;
    /// More CPUs than the row declares (`arg`: the row's).
    pub const OVER_CPUS: u32 = 2;
    /// More memory than the row declares (`arg`: the row's MiB).
    pub const OVER_MEM: u32 = 3;
    /// The row's machine is already built or running.
    pub const NOT_FREE: u32 = 4;
    /// The id names no VM.
    pub const NO_SUCH_VM: u32 = 5;
    /// The image name is not a plain relative path: empty, absolute, with an
    /// empty or `..` component, or with a byte outside the printable set.
    pub const IMAGE_NAME: u32 = 6;
    /// The image cannot be opened beneath the monitor's guest directory.
    pub const IMAGE_OPEN: u32 = 7;
    /// The image is not a kernel the guest can run (`arg`: the loader's error
    /// number, 1 read, 2 truncated, 3 not ELF, 4 machine, 5 headers, 6 loads,
    /// 7 segment, 8 out of RAM, 9 overlap, 10 entry, 11 no PVH entry, 12 the
    /// description, 13 no room for it).
    pub const IMAGE_REFUSED: u32 = 8;
    /// The machine could not be built (`arg`: the step, 1 the VM, 2 RAM, 3
    /// the trap page, 4 the monitor's own memory budget).
    pub const BUILD: u32 = 9;
    /// The VM holds no kernel to start: it is not created.
    pub const NOT_CREATED: u32 = 10;
    /// The guest already runs.
    pub const RUNNING: u32 = 11;
    /// The kernel refused to start the boot CPU (`arg`: the outcome).
    pub const START_REFUSED: u32 = 12;
    /// The machine could not be given back in time (`arg`: 0 from `stop`; from
    /// a `create` whose load failed, the cause of that failure. The row stays
    /// built: `stop` retries the give-back).
    pub const STOP_FAILED: u32 = 13;
    /// No console ring could be made (the monitor's memory budget).
    pub const NO_CONSOLE: u32 = 14;
    /// The guest does not run (created, nothing started): there is nothing to
    /// hold.
    pub const NOT_RUNNING: u32 = 15;
    /// A pause is already asked (or taken).
    pub const ALREADY_PAUSED: u32 = 16;
    /// The guest is not held: there is nothing to resume.
    pub const NOT_PAUSED: u32 = 17;
    /// The kernel refused to hold or release a vCPU (`arg`: the outcome). The
    /// vCPUs it had already held are released again.
    pub const PAUSE_REFUSED: u32 = 18;

    /// What a cause says, for the monitor's log and a tool's message.
    pub const fn text(c: u32) -> &'static [u8] {
        match c {
            NO_SUCH_ROW => b"the monitor serves no VM for that row",
            OVER_CPUS => b"more CPUs than the row declares",
            OVER_MEM => b"more memory than the row declares",
            NOT_FREE => b"the machine is already built",
            NO_SUCH_VM => b"no such VM",
            IMAGE_NAME => b"the image name is not a plain relative path",
            IMAGE_OPEN => b"the image cannot be opened beneath the guest directory",
            IMAGE_REFUSED => b"the image is not a kernel this guest can run",
            BUILD => b"the machine could not be built",
            NOT_CREATED => b"the VM holds no kernel",
            RUNNING => b"the guest already runs",
            START_REFUSED => b"the kernel refused to start the boot CPU",
            STOP_FAILED => b"the machine could not be given back",
            NO_CONSOLE => b"no console ring could be made",
            NOT_RUNNING => b"the guest does not run",
            ALREADY_PAUSED => b"the guest is already paused",
            NOT_PAUSED => b"the guest is not paused",
            PAUSE_REFUSED => b"the kernel refused to hold a vCPU",
            _ => b"refused",
        }
    }
}

/// What a request answers besides its outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    /// The VM the request named.
    pub id: u32,
    /// [`cause`]: why it was refused, [`cause::NONE`] when it was served.
    pub cause: u32,
    /// The number that explains the cause (a ceiling, an error).
    pub arg: u64,
    /// Refusals the monitor has made so far, this one included when it is one.
    pub serial: u32,
}

impl Wire for Receipt {
    const WORDS: usize = 4;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.id.put(w);
        self.cause.put(w);
        self.arg.put(w);
        self.serial.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        Receipt { id: u32::get(r), cause: u32::get(r), arg: u64::get(r), serial: u32::get(r) }
    }
}

/// [`VmCtl::console`]'s answer: the receipt, and the ring when it was served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleLease {
    pub receipt: Receipt,
    pub ring: Lent<ConsoleRing>,
}

impl Default for ConsoleLease {
    fn default() -> Self {
        ConsoleLease { receipt: Receipt::default(), ring: Lent::none() }
    }
}

impl Wire for ConsoleLease {
    const WORDS: usize = Receipt::WORDS + <Lent<ConsoleRing> as Wire>::WORDS;
    const CAPS: usize = <Lent<ConsoleRing> as Wire>::CAPS;
    fn put(&self, w: &mut Writer<'_>) {
        self.receipt.put(w);
        self.ring.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        ConsoleLease { receipt: Receipt::get(r), ring: <Lent<ConsoleRing> as Wire>::get(r) }
    }
}

#[azos_interface(id = 0x564D_0003, level = 1)]
pub trait VmCtl {
    /// Entry `index` of the table (`NO_RESOURCE` past its end).
    #[idempotent]
    fn list(&self, index: u32) -> Out<Info>;
    /// Build the machine of row `row` with `cpus` CPUs and `mem_mib` MiB (0:
    /// the row's) and load the kernel `image` into it. `REFUSED` with a
    /// [`Receipt`] when the row is unknown, the request exceeds the row, the
    /// machine is not free, or the image is refused.
    fn create(&mut self, row: u32, cpus: u32, mem_mib: u32, image: ImageName) -> Out<Receipt>;
    /// Start VM `id`'s boot CPU.
    fn start(&mut self, id: u32) -> Out<Receipt>;
    /// End VM `id` and give its machine back; created or running alike.
    fn stop(&mut self, id: u32) -> Out<Receipt>;
    /// Lend the caller VM `id`'s console output ([`ConsoleRing`]): replaces an
    /// earlier ring, which is closed (its holder drains it and ends).
    fn console(&mut self, id: u32) -> Out<ConsoleLease>;
    /// Hold VM `id`'s guest: see the module docs. `REFUSED` with a [`Receipt`]
    /// when the guest does not run, is already held, or the kernel refused.
    fn pause(&mut self, id: u32) -> Out<Receipt>;
    /// Let VM `id`'s held guest run on. `REFUSED` with a [`Receipt`] when it
    /// is not held.
    fn resume(&mut self, id: u32) -> Out<Receipt>;
}
