// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the virtual-machine monitor's device models.
//!
//! The code under test is `userspace/services/vmmd/src/*.rs`, pulled in by
//! path so it is the code `VMMD.ELF` is built from. Guest RAM is a `Vec` that
//! checks every access ([`harness::Ram`]); the guest's driver is played by
//! [`harness`] writing the registers and the rings the way a virtio driver
//! does.
//!
//! * `queue` — the split virtqueue refuses what a hostile guest can write.
//! * `transport` — the virtio-mmio register file and its failure handling.
//! * `blk`, `net`, `console` — the backends, through the transport.
//! * `proto` — the trap records and rings, the NIC ring pair, the disk over a
//!   file with no seek and its work budget.
//! * `ctl` — the `VmCtl` state machine over a model of the monitor's loop: the
//!   ceiling, the image name, the receipts, the mailbox between threads, the
//!   console ring.
//! * `life` — starting the boot CPU of a guest, noticing it is over, stopping
//!   what runs and waiting for the threads.
//! * `guest_boot` — a kernel ELF into guest RAM, and the description of the
//!   machine it finds: the device tree read back with `azos_dtb`, the PVH
//!   start_info.
//! * `machine` — the per-VM loop on recorded MMIO traps.
//! * `segram` — the guest's RAM as memory objects attached one at a time.
//! * `monitor` — the kernel's end of the rings (`crates/core/hv`) driving
//!   these device models: attach, a device access through the event port, the
//!   answer back in the guest's register.

#![allow(dead_code)]

#[path = "../../../../userspace/services/vmmd/src/blk.rs"]
pub mod blk;
#[path = "../../../../userspace/services/vmmd/src/console.rs"]
pub mod console;
#[path = "../../../../userspace/services/vmmd/src/ctl.rs"]
pub mod ctl;
#[path = "../../../../userspace/services/vmmd/src/dtb.rs"]
pub mod dtb;
#[path = "../../../../userspace/services/vmmd/src/guest.rs"]
pub mod guest;
#[path = "../../../../userspace/services/vmmd/src/life.rs"]
pub mod life;
#[path = "../../../../userspace/services/vmmd/src/loader.rs"]
pub mod loader;
#[path = "../../../../userspace/services/vmmd/src/mmio.rs"]
pub mod mmio;
#[path = "../../../../userspace/services/vmmd/src/model.rs"]
pub mod model;
#[path = "../../../../userspace/services/vmmd/src/net.rs"]
pub mod net;
#[path = "../../../../userspace/services/vmmd/src/pvh.rs"]
pub mod pvh;
#[path = "../../../../userspace/services/vmmd/src/ringlink.rs"]
pub mod ringlink;
#[path = "../../../../userspace/services/vmmd/src/store.rs"]
pub mod store;
#[path = "../../../../userspace/services/vmmd/src/trap.rs"]
pub mod trap;
#[path = "../../../../userspace/services/vmmd/src/virtq.rs"]
pub mod virtq;
#[path = "../../../../crates/core/hv/src/trapwire.rs"]
pub mod wire;

#[cfg(test)]
#[path = "../../hv-tests/src/fakes.rs"]
mod fakes;
#[cfg(test)]
mod guest_boot;
#[cfg(test)]
mod harness;
#[cfg(test)]
mod blk_tests;
#[cfg(test)]
mod console_tests;
#[cfg(test)]
mod ctl_tests;
#[cfg(test)]
mod life_tests;
#[cfg(test)]
mod machine_tests;
#[cfg(test)]
mod monitor_tests;
#[cfg(test)]
mod net_tests;
#[cfg(test)]
mod proto_tests;
#[cfg(test)]
mod queue_tests;
#[cfg(test)]
mod segram_tests;
#[cfg(test)]
mod transport_tests;
