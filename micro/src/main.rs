// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AzOS-micro's image: verify the topology the build embedded, build the
//! task table from it, and run the first task.

#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::Write;

use azos_micro::hw::{self, Machine};
use azos_micro::kernel::BootInfo;
use azos_micro::trap;
use azos_topology::signed::{load_signed, DeviceContext, SignedFiles};
use azos_topology::verify::TRUSTED_PUBKEY;
use azos_topology::Topology;

mod tasks;

static CAPS: &[u8] = include_bytes!(concat!(env!("MICRO_TOPOLOGY_DIR"), "/CAPS.TOM"));
static CAPS_SIG: &[u8] = include_bytes!(concat!(env!("MICRO_TOPOLOGY_DIR"), "/CAPS.SIG"));
static SCHED: &[u8] = include_bytes!(concat!(env!("MICRO_TOPOLOGY_DIR"), "/SCHED.TOM"));

static mut TOPOLOGY: Topology<'static> = Topology::empty();

extern "C" {
    static __code_start: u8;
    static __code_end: u8;
    static __pool_start: u8;
    static __pool_end: u8;
    static __contig_start: u8;
    static __contig_end: u8;
}

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        hw::uart_write(s.as_bytes());
        Ok(())
    }
}

fn halt() -> ! {
    loop {
        // SAFETY: M-mode; nothing is left to run.
        unsafe { asm!("wfi") };
    }
}

/// Reached from the reset vector with the stack set and `.bss` cleared.
#[no_mangle]
pub extern "C" fn micro_main() -> ! {
    let _ = writeln!(Console, "[MICRO] AzOS-micro, riscv32 M-mode, PMP");
    // SAFETY: the one hart, before any task: nothing else touches the
    // topology, and the shared reference below is taken after the last write.
    let topo = unsafe { &mut *core::ptr::addr_of_mut!(TOPOLOGY) };
    // A micro part has no device record and no counter store yet (a flash
    // store is a later item), so the signed topology is checked for its
    // signature and the hash of SCHED.TOM, and a device or counter it
    // carries is not enforced.
    let ctx = DeviceContext { device_id: None, floor: 0, bind_device: false, enforce_floor: false };
    let files = SignedFiles { caps: CAPS, caps_sig: CAPS_SIG, sched: SCHED };
    if let Err(e) = load_signed(topo, &files, &TRUSTED_PUBKEY, &ctx) {
        let _ = writeln!(Console, "[MICRO] topology refused: {:?}", e);
        halt();
    }
    let _ = writeln!(Console, "[MICRO] topology verified: {} rows", topo.tasks_len());
    // SAFETY: `TOPOLOGY` is complete and never written again.
    let topo: &'static Topology<'static> = unsafe { &*core::ptr::addr_of!(TOPOLOGY) };
    let range = |a: &u8, b: &u8| (a as *const u8 as usize, b as *const u8 as usize);
    // SAFETY: linker symbols; only their addresses are taken.
    let info = unsafe {
        let gp: usize;
        asm!("mv {0}, gp", out(reg) gp);
        BootInfo {
            code: range(&__code_start, &__code_end),
            pool: range(&__pool_start, &__pool_end),
            contig: range(&__contig_start, &__contig_end),
            gp,
        }
    };
    // SAFETY: before the first trap; the only reference to the kernel.
    let k = unsafe { trap::kernel() };
    if let Err(e) = k.boot(&mut Machine, topo, &tasks::IMAGES, info) {
        let _ = writeln!(Console, "[MICRO] boot refused: {:?}", e);
        halt();
    }
    // SAFETY: booted, M-mode, interrupts off.
    unsafe { trap::enter() }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // In a task this first UART write is refused by the PMP and the kernel
    // ends the task; in the kernel it prints and stops.
    let _ = writeln!(Console, "[MICRO] PANIC: {}", info);
    halt()
}
