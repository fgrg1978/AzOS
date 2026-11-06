// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `DOMAIN_MMIO_MAP` (509): the one way ring 3 maps device registers.
//
// Real on this path: the handler (`crates/core/syscall/src/mmio.rs`), the argument
// check (`crates/core/ipc/src/mmio_cap.rs`), the capability table, the hardware
// bus (`crates/drivers/hwbus`, `crates/drivers/bus/src/hwbus.rs`) and the Sv39
// walker. Transcribed: `process::mmio_map_user` (see `shims/sched`), whose PTEs
// are read back here by a walk of the table ([`leaf`]). Not through
// `translate_user`: that one is the kernel's own access to user memory, and it
// refuses a device window (front uaccess-mmio-buffer, `uaccess_mmio.rs`).
//
// What a refusal must leave behind is nothing: every refused call below is
// followed by a check that the task's MMIO window is still empty.

use super::harness::serial;
use azos_abi::cap::{CapPerms, ty};
use azos_abi::error::Errno;
use azos_drv_bus::hwbus::{self, Access as _};
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
    leaf(pt, window_base()).is_none()
}

/// The frame and permissions of the leaf mapping `va` in `pt`, read from the
/// table words (on the host a physical address is a pointer).
fn leaf(pt: usize, va: usize) -> Option<(usize, azos_arch_api::PagePerms)> {
    use azos_arch_api::Mmu as _;
    use azos_arch::ARCH;
    let mut t = pt;
    for level in (0..3).rev() {
        let w = unsafe { core::ptr::read_volatile((t + ARCH.vpn(va, level) * 8) as *const u64) };
        if !ARCH.pte_is_valid(w) {
            return None;
        }
        if ARCH.pte_is_leaf(w, level) {
            let span = 1usize << (12 + 9 * level);
            return Some((ARCH.pte_phys(w) + (va & (span - 1)), ARCH.pte_perms(w)));
        }
        t = ARCH.pte_phys(w);
    }
    None
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
    let (pa, perms) = leaf(pt, va).expect("window not mapped");
    assert_eq!(pa, 0x0010_1000, "wrong frame");
    assert!(perms.user && !perms.write, "RTC mapped writable");
    assert!(leaf(pt, va + 0x1000).is_none(), "mapped past the window");
}

/// Admitted: RW with an RW capability is writable.
#[test]
fn a_read_write_capability_maps_the_window_writable() {
    let _g = serial();
    let pt = ring3();
    let m = machine();
    hold(m.bus, CapPerms::RW);
    let va = map(m.bus as u64, RW) as usize;
    let (pa, perms) = leaf(pt, va).expect("window not mapped");
    assert_eq!(pa, 0x0400_0000);
    assert!(perms.user && perms.write, "RW mapping is not writable");
    // A kernel copy into the window is refused (front uaccess-mmio-buffer).
    assert!(azos_mm::vmm::translate_user(pt, va, false).is_none(), "the user walk accepted a device window");
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

// ── `DEVICE_DMA_MAP` / `DEVICE_DMA_UNMAP`: the memory a device reaches ──────
//
// Real: the op (`mmio.rs` `device_op`), the binding table and its teardown
// (`azos_ipc::dma_bind`, `azos_dma::bind`), the memory objects. The device's
// domain is the recording one below, installed as the kernel installs its
// own (`dma_bind::set_hooks`): it logs what happened in which order, and
// whether the object still had its frames when it happened.

mod dma {
    use super::*;
    use azos_abi::invoke::{DEVICE_DMA_MAP, DEVICE_DMA_UNMAP, DMA_BIDIRECTIONAL, DMA_TO_DEVICE, INVOKE_REGS};
    use azos_abi::syscall_nr::{SHM_CREATE_KIND_SHIFT, SHM_KIND_CONTIG};
    use azos_dma::{Direction, DmaAddr, DmaDomain, DmaError, DomainKind};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex;

    /// What the domain and the quiesce saw: (what, did the object still have
    /// its frames).
    static EVENTS: Mutex<Vec<(&'static str, bool)>> = Mutex::new(Vec::new());
    /// The object under test (its slot index), for the frames check.
    static OBJ: AtomicU32 = AtomicU32::new(u32::MAX);
    static QUIESCE_OK: AtomicBool = AtomicBool::new(true);
    /// What the domain adds to a physical address: a bus address is not one.
    const BUS_OFFSET: u64 = 0x10_0000_0000;

    fn alive() -> bool {
        azos_ipc::memobj::memobj_info(OBJ.load(Ordering::SeqCst)).is_some()
    }

    struct Rec;
    impl DmaDomain for Rec {
        fn map(&self, pa: u64, _len: usize, _dir: Direction) -> Result<DmaAddr, DmaError> {
            EVENTS.lock().unwrap().push(("map", alive()));
            Ok(DmaAddr(pa + BUS_OFFSET))
        }
        fn unmap(&self, _bus: DmaAddr, _len: usize) -> Result<(), DmaError> {
            EVENTS.lock().unwrap().push(("unmap", alive()));
            Ok(())
        }
        fn coherent(&self) -> bool {
            true
        }
        fn kind(&self) -> DomainKind {
            DomainKind::Soft
        }
        fn enable(&self) -> Result<(), DmaError> {
            Ok(())
        }
        fn allow_msi(&self, _: u64) -> Result<(), DmaError> {
            Ok(())
        }
    }
    static REC: Rec = Rec;

    fn domain(_dev: u32) -> Option<&'static dyn DmaDomain> {
        Some(&REC)
    }
    fn quiesce(_dev: u32) -> bool {
        EVENTS.lock().unwrap().push(("quiesce", alive()));
        QUIESCE_OK.load(Ordering::SeqCst)
    }

    fn setup() -> usize {
        azos_ipc::dma_bind::set_hooks(azos_ipc::dma_bind::Hooks { domain, quiesce });
        EVENTS.lock().unwrap().clear();
        QUIESCE_OK.store(true, Ordering::SeqCst);
        ring3()
    }

    /// The handle of a capability on device `dev` with `perms`.
    fn device(dev: u32, perms: CapPerms) -> u64 {
        azos_ipc::cap_store::grant::<azos_ipc::cap::targets::MmioRegion>(TID, perms, dev)
            .expect("cap table full")
            .raw()
            .as_raw() as u64
    }

    /// A `pages`-page object of `kind`, its slot index and its reference.
    fn object(pages: u64, kind: u64) -> (u64, u32, u32) {
        let h = crate::ipc_handlers::sys_shm_create_typed(pages, 1 | kind << SHM_CREATE_KIND_SHIFT);
        assert!(h > 0, "create: {h}");
        let r = azos_ipc::cap_store::get(
            TID,
            azos_ipc::cap::Cap::<azos_ipc::cap::targets::Shm>::from_raw(azos_abi::cap::CapHandle::from_raw(h as u32)),
            CapPerms::NONE,
        )
        .unwrap();
        (h as u64, azos_common::slot_ref::SHM.idx(r), r)
    }

    fn op(dev: u64, op: u16, obj: u64, dir: u64) -> (i64, [u64; 6]) {
        let mut out = crate::dispatch::SyscallOut::new();
        let rc = crate::invoke::sys_invoke(dev, INVOKE_REGS | op as u64, obj, dir, 0, 0, &mut out);
        (rc, out.regs)
    }

    /// **Only a read-write Contig object ring 3 made reaches a device, and only
    /// a device no kernel driver owns, through a capability that carries
    /// `WRITE`; the binding keeps the frames past the task's own release, and
    /// the unmap takes the object out of the domain while it still has them,
    /// then gives them back.**
    ///
    /// **Canary.** Unpin before the domain's unmap in `bind::release`: the
    /// unmap finds the object gone.
    #[test]
    fn a_bound_object_keeps_its_frames_until_it_is_out_of_the_domain() {
        let _g = serial();
        setup();
        let m = machine();
        let dev = device(m.bus, CapPerms::RW);
        let (anon, ..) = object(1, 0);
        assert_eq!(op(dev, DEVICE_DMA_MAP, anon, DMA_BIDIRECTIONAL).0, Errno::EINVAL.to_syscall_ret(), "an Anon object");
        assert_eq!(crate::ipc_handlers::sys_shm_release_typed(anon), 0);
        let (obj, idx, _) = object(2, SHM_KIND_CONTIG);
        OBJ.store(idx, Ordering::SeqCst);
        assert_eq!(op(dev, DEVICE_DMA_MAP, obj, 7).0, Errno::EINVAL.to_syscall_ret(), "an unknown direction");
        let ro = device(m.rtc, CapPerms::READ);
        assert_eq!(op(ro, DEVICE_DMA_MAP, obj, DMA_TO_DEVICE).0, Errno::ECAPPERMS.to_syscall_ret(), "a READ-only device");
        let uart = device(m.uart, CapPerms::RW);
        assert_eq!(op(uart, DEVICE_DMA_MAP, obj, DMA_TO_DEVICE).0, Errno::ENODEV.to_syscall_ret(), "the kernel's device");
        assert!(EVENTS.lock().unwrap().is_empty(), "a refused map reached the domain");

        let (rc, regs) = op(dev, DEVICE_DMA_MAP, obj, DMA_BIDIRECTIONAL);
        assert_eq!(rc, 0);
        assert_eq!(regs[0] & BUS_OFFSET, BUS_OFFSET, "the reply is the domain's bus address");
        assert_eq!(regs[1], 2 * azos_arch::PAGE_SIZE as u64, "and the object's length");
        assert_eq!(op(dev, DEVICE_DMA_MAP, obj, DMA_BIDIRECTIONAL).0, Errno::EBUSY.to_syscall_ret(), "bound twice");

        assert_eq!(crate::ipc_handlers::sys_shm_release_typed(obj), 0);
        assert!(alive(), "the task's release freed frames a device can reach");
        assert_eq!(op(dev, DEVICE_DMA_UNMAP, obj, 0).0, Errno::ECAPSTALE.to_syscall_ret(), "the released handle");
        // The binding is the process's: the exit path ends it (the device
        // stopped first).
        azos_ipc::dma_bind::release_all(azos_sched::group::proc_tid(TID));
        assert_eq!(
            *EVENTS.lock().unwrap(),
            vec![("map", true), ("quiesce", true), ("unmap", true)],
            "stopped, out of the domain, then the frames"
        );
        assert!(!alive(), "the frames stayed after the unmap");
    }

    /// **The driver's unmap ends its binding, once; a second one finds none.**
    #[test]
    fn the_unmap_ends_the_binding_once() {
        let _g = serial();
        setup();
        let m = machine();
        let dev = device(m.bus, CapPerms::RW);
        let (obj, idx, _) = object(1, SHM_KIND_CONTIG);
        OBJ.store(idx, Ordering::SeqCst);
        assert_eq!(op(dev, DEVICE_DMA_MAP, obj, DMA_TO_DEVICE).0, 0);
        assert_eq!(op(dev, DEVICE_DMA_UNMAP, obj, 0).0, 0);
        assert_eq!(op(dev, DEVICE_DMA_UNMAP, obj, 0).0, Errno::ENOENT.to_syscall_ret());
        assert_eq!(*EVENTS.lock().unwrap(), vec![("map", true), ("unmap", true)], "no quiesce: the driver stopped it");
        assert!(alive(), "the task still holds the object");
        assert_eq!(crate::ipc_handlers::sys_shm_release_typed(obj), 0);
        assert!(!alive());
    }

    /// **A device given memory is booked with the bus as a mapped window is: a
    /// kernel driver is not asked to bind it while the binding lives, whether
    /// or not ring 3 mapped its registers.**
    ///
    /// **Canary.** Check `user_window` instead of `claim_user_window` in
    /// `dma_bind::map`: the driver binds a device whose pages it does not know
    /// a ring-3 task still has in its domain.
    #[test]
    fn a_device_given_memory_is_not_handed_to_a_kernel_driver() {
        let _g = serial();
        setup();
        let h = hwbus::with(|b| {
            let mut q = Quiet;
            let h = b.add(hwbus::Device::dt("dma@7200000", b"vendor,dmadev\0", 0x0720_0000, 0x1000, 0), &mut q).unwrap();
            let none = hwbus::Rules { native: &[], linux: &[], rows: &[], policy: hwbus::Policy::Auto };
            b.bind(h, &none, &mut Accepting, &mut q);
            h
        });
        let dev = device(h.0, CapPerms::RW);
        let (obj, idx, _) = object(1, SHM_KIND_CONTIG);
        OBJ.store(idx, Ordering::SeqCst);
        assert_eq!(op(dev, DEVICE_DMA_MAP, obj, DMA_TO_DEVICE).0, 0);
        let rules = hwbus::Rules {
            native: &[hwbus::NativeEntry { pattern: hwbus::Pattern::Dt("vendor,dmadev"), driver: "dmadrv", boot: false }],
            linux: &[],
            rows: &[],
            policy: hwbus::Policy::Auto,
        };
        let state = hwbus::with(|b| {
            b.bind(h, &rules, &mut Accepting, &mut Quiet);
            b.get(h).unwrap().state
        });
        assert_eq!(state, hwbus::State::ProbeFailed, "a kernel driver took a device ring 3 gave memory to");
        assert_eq!(op(dev, DEVICE_DMA_UNMAP, obj, 0).0, 0);
        assert_eq!(crate::ipc_handlers::sys_shm_release_typed(obj), 0);
        assert!(!alive());
    }

    /// **At the exit, a device that cannot be shown stopped keeps the frames
    /// it was given out of the allocator, counted.**
    ///
    /// **Canary.** Ignore the quiesce's answer in `dma_bind::release_all`:
    /// the frames go while the device may still write them.
    #[test]
    fn a_device_not_shown_stopped_keeps_its_frames() {
        let _g = serial();
        setup();
        let m = machine();
        let dev = device(m.bus, CapPerms::RW);
        let (obj, idx, r) = object(1, SHM_KIND_CONTIG);
        OBJ.store(idx, Ordering::SeqCst);
        assert_eq!(op(dev, DEVICE_DMA_MAP, obj, DMA_TO_DEVICE).0, 0);
        assert_eq!(crate::ipc_handlers::sys_shm_release_typed(obj), 0);
        QUIESCE_OK.store(false, Ordering::SeqCst);
        let kept = azos_dma::leaked_bytes();
        azos_ipc::dma_bind::release_all(azos_sched::group::proc_tid(TID));
        assert_eq!(*EVENTS.lock().unwrap(), vec![("map", true), ("quiesce", true)], "unmapped though not stopped");
        assert!(alive(), "the frames went while the device may still write them");
        assert_eq!(azos_dma::leaked_bytes(), kept + azos_arch::PAGE_SIZE as u64, "the kept page is not counted");
        // The suite shares one object table: the kept reference goes here, as
        // nothing in the kernel ever gives it back.
        azos_ipc::memobj::memobj_frames_unpin(r);
        assert!(!alive());
    }
}
