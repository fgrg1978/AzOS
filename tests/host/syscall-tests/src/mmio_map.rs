// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `DOMAIN_MMIO_MAP` (509, RFC-0043): the one way ring 3 maps device registers.
//
// Real on this path: the handler (`crates/core/syscall/src/mmio.rs`), the argument
// check (`crates/core/ipc/src/mmio_cap.rs`), the capability table, the hardware
// bus (`crates/drivers/hwbus`, `crates/drivers/bus/src/hwbus.rs`) and the Sv39
// walker. Transcribed: `process::mmio_map_user` (see `shims/sched`), whose PTEs
// are read back here through the real `translate_user`.
//
// What a refusal must leave behind is nothing: every refused call below is
// followed by a check that the task's MMIO window is still empty.

use super::harness::serial;
use azos_abi::cap::{CapPerms, ty};
use azos_abi::error::Errno;
use azos_drv_bus::hwbus;
use std::sync::OnceLock;

/// The cap-store pool slot this file binds its caller to (unused elsewhere).
const SLOT: usize = 30;
const TID: u32 = 0x5100_0001;

const READ: u64 = CapPerms::READ.bits() as u64;
const RW: u64 = CapPerms::RW.bits() as u64;

struct Quiet;
impl hwbus::Sink for Quiet {
    fn event(&mut self, _: &hwbus::Event<'_>) {}
}

struct Accepting;
impl hwbus::Drivers for Accepting {
    fn probe(&mut self, _: &str, _: hwbus::Handle, _: &hwbus::Device) -> Result<(), hwbus::ProbeError> {
        Ok(())
    }
    fn remove(&mut self, _: &str, _: hwbus::Handle, _: &hwbus::Device) -> Result<(), hwbus::ProbeError> {
        Err(hwbus::ProbeError::Busy)
    }
}

/// The handles of the machine: a goldfish RTC, a page of the platform bus (both
/// nothing drives), and a UART the kernel drives.
struct Machine {
    rtc: u32,
    bus: u32,
    uart: u32,
}

fn machine() -> &'static Machine {
    static M: OnceLock<Machine> = OnceLock::new();
    M.get_or_init(|| {
        hwbus::with(|b| {
            let mut q = Quiet;
            let rtc = b.add(hwbus::Device::dt("rtc@101000", b"google,goldfish-rtc\0", 0x0010_1000, 0x1000, 11), &mut q).unwrap();
            let bus = b.add(hwbus::Device::dt("page@4000000", b"vendor,page\0", 0x0400_0000, 0x1000, 0), &mut q).unwrap();
            let uart = b.add(hwbus::Device::dt("uart@10000000", b"ns16550a\0", 0x1000_0000, 0x100, 10), &mut q).unwrap();
            let rules = hwbus::Rules {
                native: &[hwbus::NativeEntry { pattern: hwbus::Pattern::Dt("ns16550a"), driver: "uart", boot: true }],
                linux: &[],
                rows: &[],
                policy: hwbus::Policy::Auto,
            };
            b.bind_all(&rules, &mut Accepting, &mut q);
            Machine { rtc: rtc.0, bus: bus.0, uart: uart.0 }
        })
    })
}

/// Ring 3, an empty capability table and a real user page table.
fn ring3() -> usize {
    machine();
    ipc_task_pool::shim_bind(TID, SLOT);
    azos_ipc::cap_store::reset(TID);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(TID);
    pt
}

fn hold(handle: u32, perms: CapPerms) {
    assert!(
        azos_ipc::cap_store::with_table(TID, |t| t.grant_raw(ty::MMIO, perms, handle))
            .flatten()
            .is_some(),
        "could not grant mmio {handle:#x}"
    );
}

/// The first page of the MMIO window: where the first mapping lands.
fn window_base() -> usize {
    azos_sched::user_shm_window().0
}

fn window_is_empty(pt: usize) -> bool {
    azos_mm::vmm::translate_user(pt, window_base(), false).is_none()
}

fn map(handle: u64, access: u64) -> i64 {
    crate::mmio::sys_mmio_map(handle, access)
}

fn einval() -> i64 { Errno::EINVAL.to_syscall_ret() }

/// Admitted: a READ capability on the RTC maps exactly the RTC's frame,
/// readable and NOT writable.
#[test]
fn a_read_capability_maps_the_window_read_only() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    hold(m.rtc, CapPerms::READ);
    let va = map(m.rtc as u64, READ);
    assert_eq!(va, window_base() as i64, "did not map at the window");
    let va = va as usize;
    assert_eq!(azos_mm::vmm::translate_user(pt, va, false), Some(0x0010_1000), "wrong frame");
    assert_eq!(azos_mm::vmm::user_write_would_be_permitted(pt, va), false, "RTC mapped writable");
    assert!(azos_mm::vmm::translate_user(pt, va + 0x1000, false).is_none(), "mapped past the window");
}

/// Admitted: RW with an RW capability is writable.
#[test]
fn a_read_write_capability_maps_the_window_writable() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    hold(m.bus, CapPerms::RW);
    let va = map(m.bus as u64, RW) as usize;
    assert_eq!(azos_mm::vmm::translate_user(pt, va, false), Some(0x0400_0000));
    assert!(azos_mm::vmm::user_write_would_be_permitted(pt, va), "RW mapping is not writable");
}

/// Refusal: no capability. `-1` (the dispatch-level `E_PERM`), nothing mapped.
#[test]
fn no_capability_is_refused_and_maps_nothing() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    assert_eq!(map(m.rtc as u64, READ), -1);
    assert_eq!(map(m.bus as u64, RW), -1);
    assert!(window_is_empty(pt));
}

/// Refusal: a capability for ANOTHER device, or a READ capability asked for
/// RW (WRITE is the capability's to allow), does not admit.
#[test]
fn a_capability_admits_only_its_own_device_and_access() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    hold(m.bus, CapPerms::READ);
    assert_eq!(map(m.rtc as u64, READ), -1, "a Cap for the page mapped the RTC");
    assert_eq!(map(m.bus as u64, RW), -1, "a READ Cap mapped RW");
    assert!(window_is_empty(pt));
}

/// Refusal before the capability check: an access word other than READ or
/// READ|WRITE is `EINVAL` even while holding RW on the device.
#[test]
fn an_access_word_other_than_read_or_read_write_is_einval() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    hold(m.bus, CapPerms::RW);
    for access in [0u64, CapPerms::WRITE.bits() as u64, 4, RW | 4, u64::MAX, 1 << 32 | READ] {
        assert_eq!(map(m.bus as u64, access), einval(), "access {access:#x}");
    }
    assert!(window_is_empty(pt));
}

/// Refusal: a handle that names no device, and one wider than `u32` that would
/// NARROW to a held handle, are `EINVAL`: the holder of the RTC must not reach
/// it through a wide register.
#[test]
fn a_handle_that_names_no_device_or_is_wider_than_u32_is_einval() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    hold(m.rtc, CapPerms::READ);
    for handle in [hwbus::MAX_DEVICES as u64, 0x7fff, u32::MAX as u64, (m.rtc as u64) | (1 << 32), 1 << 32, u64::MAX] {
        assert_eq!(map(handle, READ), einval(), "handle {handle:#x}");
    }
    assert!(window_is_empty(pt));
}

/// Refusal: a device a kernel driver owns is not ring 3's, whatever the table
/// holds (`grant_raw` bypasses the minter's rule): `EINVAL`.
#[test]
fn a_device_the_kernel_drives_is_einval_whatever_is_held() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    hold(m.uart, CapPerms::RW);
    assert_eq!(map(m.uart as u64, READ), einval());
    assert_eq!(map(m.uart as u64, RW), einval());
    assert!(window_is_empty(pt));
}

/// Refusal: a device still `Detected` (its stage has not run: a kernel driver
/// may take it) or whose probe failed (it may be half set up) is not ring 3's.
#[test]
fn a_device_not_yet_decided_or_whose_probe_failed_is_einval() {
    let _g = serial();
    let pt = ring3();
    let (waiting, failed) = hwbus::with(|b| {
        let mut q = Quiet;
        let waiting = b.add(hwbus::Device::dt("wait@6000000", b"vendor,wait\0", 0x0600_0000, 0x1000, 0), &mut q).unwrap();
        let failed = b.add(hwbus::Device::dt("fail@6001000", b"vendor,fail\0", 0x0600_1000, 0x1000, 0), &mut q).unwrap();
        struct Refusing;
        impl hwbus::Drivers for Refusing {
            fn probe(&mut self, _: &str, _: hwbus::Handle, _: &hwbus::Device) -> Result<(), hwbus::ProbeError> {
                Err(hwbus::ProbeError::Failed)
            }
            fn remove(&mut self, _: &str, _: hwbus::Handle, _: &hwbus::Device) -> Result<(), hwbus::ProbeError> {
                Ok(())
            }
        }
        let rules = hwbus::Rules {
            native: &[hwbus::NativeEntry { pattern: hwbus::Pattern::Dt("vendor,fail"), driver: "faildrv", boot: false }],
            linux: &[],
            rows: &[],
            policy: hwbus::Policy::Auto,
        };
        b.bind(failed, &rules, &mut Refusing, &mut q);
        (waiting.0, failed.0)
    });
    hold(waiting, CapPerms::RW);
    hold(failed, CapPerms::RW);
    assert_eq!(map(waiting as u64, READ), einval());
    assert_eq!(map(failed as u64, RW), einval());
    assert!(window_is_empty(pt));
}

/// A mapping books the device: a kernel driver the rules later choose for it
/// is not asked, because the task's mapping cannot be taken back.
#[test]
fn a_mapped_device_is_never_bound_to_a_kernel_driver_afterwards() {
    let _g = serial();
    let _pt = ring3();
    let h = hwbus::with(|b| {
        let mut q = Quiet;
        let h = b.add(hwbus::Device::dt("book@7000000", b"vendor,book\0", 0x0700_0000, 0x1000, 0), &mut q).unwrap();
        let none = hwbus::Rules { native: &[], linux: &[], rows: &[], policy: hwbus::Policy::Auto };
        b.bind(h, &none, &mut Accepting, &mut q);
        h
    });
    hold(h.0, CapPerms::RW);
    assert!(map(h.0 as u64, RW) > 0, "an undriven device maps");
    let rules = hwbus::Rules {
        native: &[hwbus::NativeEntry { pattern: hwbus::Pattern::Dt("vendor,book"), driver: "bookdrv", boot: false }],
        linux: &[],
        rows: &[],
        policy: hwbus::Policy::Auto,
    };
    let state = hwbus::with(|b| {
        b.bind(h, &rules, &mut Accepting, &mut Quiet);
        b.get(h).unwrap().state
    });
    assert_eq!(state, hwbus::State::ProbeFailed);
}

/// A kernel caller has no user page table: admitted by `cap_check`, refused
/// by the mapper, `-1`.
#[test]
fn a_kernel_caller_gets_minus_one() {
    let _g = serial();
    let m = machine();
    assert_eq!(map(m.rtc as u64, READ), -1);
}
