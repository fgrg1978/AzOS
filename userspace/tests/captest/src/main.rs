// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Capability + syscall ABI test for a ring-3 process.
//!
//! A ring-3 program reaches hardware only through the capabilities the
//! topology seeds into its table. Without them `reflex` and `brain_client`
//! load, exec, and sit forever doing nothing — reflex reads a failed
//! rangefinder as "no obstacle", because `obstacle_front()` guards the
//! comparison with `range_front > 0`. A blind daemon and a daemon on a clear
//! road print exactly the same thing: nothing.
//!
//! This binary makes that state observable. It asserts BOTH halves:
//!
//!   POSITIVE — a granted resource is usable. Every sensor read and motor
//!   write through a looked-up `Cap<Sensor>` / `Cap<Motor>` must be admitted.
//!   A read may still return -1 ("sensor not ready"): QEMU has no IMU, and -1
//!   means the capability was accepted and the driver had nothing to give,
//!   which is a pass for this test. A capability error is a failure.
//!
//!   NEGATIVE — an ungranted resource is still refused. No table holds an ADC
//!   channel, so `adc_read` must come back E_PERM; a resource the topology
//!   does not grant has no handle to look up; a forged handle is stale.
//!   Without this half the test would pass just as happily if the checks were
//!   deleted altogether, which is the opposite of what it is meant to prove.

#![no_std]
#![no_main]

use azos_abi::cap::CapPerms;
use azos_abi::syscall_nr::{SYS_CLOSE, SYS_MMIO_MAP};
use azos_libsys as sys;

mod stream;

/// Permission denied, from `crates/core/syscall/src/handlers.rs`.
const E_PERM: isize = -99;

static mut FAILURES: u32 = 0;

/// Raw `ecall`, bypassing every `libsys` wrapper.
///
/// Written out here rather than exposed from `libsys` for two reasons. A raw
/// syscall escape hatch does not belong in the shipped userspace ABI, and more
/// to the point: the thing under test is the KERNEL's dispatch boundary, so
/// going through a library wrapper would let a wrapper-side change (a deleted
/// function, a renumbering) mask what the kernel actually does with the number.
unsafe fn raw_syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 as isize => ret,
            in("a1") a1,
            in("a2") a2,
            options(nostack),
        );
        // aarch64 twin (phase 6 prep — see
        // `crates/core/abi/src/syscall_nr.rs`'s "Register convention"). x8/x0..x2
        // mirror a7/a0..a2.
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 as isize => ret,
            in("x1") a1,
            in("x2") a2,
            options(nostack),
        );
    }
    ret
}

/// `SYS_MMIO_MAP(index, access)`, issued raw for the same reason as the call
/// above: libsys has no wrapper, and the kernel's answer is what is under test.
///
/// Its own `ecall` naming the ABI constant, because `tests/host/seccomp-tests`
/// derives this image's profile from this file and resolves a call through
/// the three-argument helper only when its number is a literal.
unsafe fn mmio_map(index: u64, access: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "ecall",
            in("a7") SYS_MMIO_MAP,
            inlateout("a0") index as isize => ret,
            in("a1") access,
            options(nostack),
        );
        // aarch64 twin — see `raw_syscall3`.
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_MMIO_MAP,
            inlateout("x0") index as isize => ret,
            in("x1") access,
            options(nostack),
        );
    }
    ret
}

/// The untyped `SYS_CLOSE(fd)`, issued raw. libsys `close` takes a capability
/// handle and issues `SYS_CLOSE_TYPED`, so the kernel's refusal of the untyped
/// close behind a live `Cap<File>` has no wrapper left to reach it. Its own
/// `ecall` naming the constant, like [`mmio_map`], so the seccomp derivation
/// resolves it.
unsafe fn untyped_close(fd: u64) -> isize {
    let ret: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "ecall",
            in("a7") SYS_CLOSE,
            inlateout("a0") fd as isize => ret,
            options(nostack),
        );
        // aarch64 twin — see `raw_syscall3`.
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_CLOSE,
            inlateout("x0") fd as isize => ret,
            options(nostack),
        );
    }
    ret
}

fn report(name: &[u8], ok: bool, rc: isize) {
    sys::print(if ok { b"[CAPTEST]   ok   " } else { b"[CAPTEST]  FAIL  " });
    sys::print(name);
    sys::print(b" rc=");
    print_i(rc);
    sys::print(b"\n");
    if !ok {
        unsafe { FAILURES += 1; }
    }
}

/// Minimal signed-decimal print — no core::fmt in a no_std ring-3 binary.
fn print_i(v: isize) {
    if v < 0 {
        sys::print(b"-");
    }
    let mut n = if v < 0 { (-(v as i64)) as u64 } else { v as u64 };
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    sys::print(&buf[i..]);
}

/// Granted → must NOT be E_PERM. -1 (driver has nothing) still counts.
fn expect_allowed(name: &[u8], rc: isize) {
    report(name, rc != E_PERM, rc);
}

/// Not granted → must be exactly E_PERM.
fn expect_denied(name: &[u8], rc: isize) {
    report(name, rc == E_PERM, rc);
}

/// Refused with one SPECIFIC errno, not merely refused.
///
/// The typed capability path does not answer `E_PERM`: it distinguishes
/// "you hold no such capability" (`-ENOENT`) from "that handle names nothing"
/// (`-ECAPSTALE`), and collapsing them into "some negative number" would let
/// a handler that failed for an unrelated reason — a bad argument, an
/// unimplemented syscall — pass as a capability refusal. The first draft of
/// these three assertions used `expect_denied` and would have done exactly
/// that, since `expect_denied` demands E_PERM and none of them returns it.
fn expect_errno(name: &[u8], rc: isize, want: isize) {
    report(name, rc == want, rc);
}

/// From `azos_abi::error::Errno`, as returned by the typed path.
const E_NOENT: isize = -2;
/// `Errno::ECAPSTALE` — the handle names an empty or recycled slot.
const E_CAPSTALE: isize = -202;

/// Granted → admitted: a byte count, 0, or the driver's -1 ("nothing to
/// report"). Every refusal on the typed path is another negative value
/// (`-ENOENT` from the lookup, `-ECAPSTALE`, `-ECAPKIND`, `-ECAPPERMS`), and
/// `expect_allowed`'s `!= E_PERM` would pass all of them.
fn expect_admitted(name: &[u8], rc: isize) {
    report(name, rc >= 0 || rc == -1, rc);
}

/// Look up the `Cap<Sensor>` for `sensor_type` and read it. A failed lookup
/// is returned as it came (`-ENOENT`), so the check names the missing grant.
fn read_sensor(sensor_type: u64, buf: &mut [u8]) -> isize {
    let cap = sys::cap_lookup(sys::CapKind::Sensor as u8, sensor_type as u32);
    if cap < 0 {
        return cap;
    }
    sys::sensor_read_typed(cap as u32, buf)
}

/// Bound on the age of a CACHED sample (odometry, integrated by the kernel's
/// 50 Hz `odom` task) when it is read: fifty of its periods.
const CACHED_MAX_AGE_NS: u64 = 1_000_000_000;

/// Each granted sensor through `SYS_SENSOR_READ_TS`, between two reads of the
/// vDSO clock: the header is version 1 with the payload 561 returns for the
/// type, and the acquisition stamp is on the same clock as the reader's —
/// inside the call for a value the kernel reads during it (IMU, encoder,
/// rangefinder, battery), at most [`CACHED_MAX_AGE_NS`] before it for
/// odometry — and never goes backwards across two reads.
///
/// The summary line is printed only when every check held; the gate row
/// greps it on both ISAs. Canary: the `sensor-ts-freeze` kernel feature (the
/// IMU driver reports its first stamp forever) fails `IMU acquired inside the
/// call`.
fn stamped_reads() {
    // (type, payload bytes, read during the call)
    const TYPES: [(u64, usize, bool, &[u8]); 5] = [
        (sys::SENSOR_TYPE_IMU, 24, true, b"IMU"),
        (sys::SENSOR_TYPE_ODOM, 16, false, b"ODOM"),
        (sys::SENSOR_TYPE_ENCODER, 16, true, b"ENCODER"),
        (sys::SENSOR_TYPE_RANGE, 4, true, b"RANGE"),
        (sys::SENSOR_TYPE_BATTERY, 2, true, b"BATTERY"),
    ];
    let before = unsafe { FAILURES };
    for &(ty, plen, during, name) in TYPES.iter() {
        let cap = sys::cap_lookup(sys::CapKind::Sensor as u8, ty as u32);
        if cap < 0 {
            report(b"sensor_read_ts: Cap<Sensor> lookup", false, cap);
            continue;
        }
        let mut prev = 0u64;
        for round in 0..2 {
            let mut buf = [0u8; 64];
            let t0 = sys::vdso_now_ns();
            let n = sys::sensor_read_ts(cap as u32, &mut buf);
            let t1 = sys::vdso_now_ns();
            let hdr = sys::SensorSampleHdr::from_bytes(&buf);
            let ok_len = n == (sys::SENSOR_SAMPLE_HDR_LEN + plen) as isize;
            let ok_hdr = matches!(hdr, Some(h) if h.version == 1
                && h.hdr_len as usize == sys::SENSOR_SAMPLE_HDR_LEN
                && h.payload_len as usize == plen);
            let acq = hdr.map(|h| h.acq_ns).unwrap_or(0);
            let ok_time = acq != 0 && acq <= t1
                && if during { acq >= t0 } else { t1 - acq < CACHED_MAX_AGE_NS };
            let ok_mono = acq >= prev;
            prev = acq;
            if round == 0 {
                sys::print(b"[CAPTEST] sensorts: ");
                sys::print(name);
                sys::print(b" acq_ns=");
                print_i(acq as isize);
                sys::print(b" read in [");
                print_i(t0 as isize);
                sys::print(b", ");
                print_i(t1 as isize);
                sys::print(b"]\n");
            }
            if !(ok_len && ok_hdr) {
                stamped_fail(name, b"length/header", n);
            }
            if !ok_time {
                stamped_fail(name, if during { b"acquired inside the call" as &[u8] }
                                   else { b"acquired within 1 s before the call" }, acq as isize);
            }
            if !ok_mono {
                stamped_fail(name, b"stamp went backwards", acq as isize);
            }
        }
    }
    // A buffer that holds the header but not the payload: refused, as 561
    // refuses a short buffer.
    let imu = sys::cap_lookup(sys::CapKind::Sensor as u8, sys::SENSOR_TYPE_IMU as u32);
    let mut short = [0u8; sys::SENSOR_SAMPLE_HDR_LEN + 23];
    report(b"sensor_read_ts(IMU, header + 23 bytes) -> refused",
           sys::sensor_read_ts(imu as u32, &mut short) == -1, 0);
    if unsafe { FAILURES } == before {
        sys::println(b"[CAPTEST] sensorts: 5 sensors stamped on the vDSO clock, inside the call (IMU ENCODER RANGE BATTERY) or < 1 s before it (ODOM), monotonic");
    }
}

/// One `[CAPTEST]  FAIL  sensor_read_ts(<name>): <what> rc=<rc>` line.
fn stamped_fail(name: &[u8], what: &[u8], rc: isize) {
    sys::print(b"[CAPTEST]  FAIL  sensor_read_ts(");
    sys::print(name);
    sys::print(b"): ");
    sys::print(what);
    sys::print(b" rc=");
    print_i(rc);
    sys::print(b"\n");
    unsafe { FAILURES += 1; }
}

/// Stop the wheel behind a looked-up `Cap<Motor>`. A failed lookup is
/// returned as it came.
fn speed_zero(cap: isize) -> isize {
    if cap < 0 {
        return cap;
    }
    sys::motor_speed_typed(cap as u32, 0)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[CAPTEST] Starting...");

    // ── Cap<Disk> scoped to ONE partition (RFC-0048 P3, owner round 23) ──
    //
    // Only where the topology grants it: the `disk-part-row` kernel feature
    // gives the autorun row `disk.part.1` read/write, and only the gate's
    // partitioned image (`build/disk-parted.img`) has a partition 1 for it to
    // name — a 64-sector raw partition after the FAT32 one. Everywhere else
    // the lookup finds nothing and this block issues no disk call at all (a
    // miss is not a recorded denial). First in the run on purpose: its
    // refusal is the denial record the kernel's `disk-part-row` probe reads
    // back, and denial records are bounded per task.
    //
    // Sectors are RELATIVE to the partition: 0 is its first sector and 63 its
    // last. The gate reads the image back after the boot and finds these two
    // patterns at the partition's ABSOLUTE start and start + 63 — which is
    // what proves the kernel added the start rather than writing LBA 0 (the
    // MBR) and LBA 63.
    //
    // Wave 10: the same row also grants `disk.part.0` READ-only (the FAT32
    // volume), so this task holds TWO readable partitions. The writes below
    // still name partition 1 through the sentinel (only it is writable, so
    // the sentinel is unambiguous for a write); every read names its
    // partition by handle (`*_on`), and a read through the sentinel is
    // refused as ambiguous — the owner's 4th-argument decision, end to end.
    let part1 = sys::cap_lookup(sys::CapKind::Disk as u8, 2);
    if part1 >= 0 {
        let part1 = part1 as u32;
        const PART1_SECTORS: u64 = 64;
        let mut first = [0xA5u8; 512];
        first[..14].copy_from_slice(b"AZOS-P3-REL000");
        let mut last = [0x5Au8; 512];
        last[..14].copy_from_slice(b"AZOS-P3-REL063");
        expect_errno(b"disk_write(rel 0) [inside partition 1]", sys::disk_write(0, &first), 0);
        expect_errno(b"disk_write(rel 63) [its last sector]",
                     sys::disk_write(PART1_SECTORS - 1, &last), 0);
        let mut back = [0u8; 512];
        let rc = sys::disk_read_on(part1, 0, &mut back);
        report(b"disk_read(rel 0) returns what was written", rc == 0 && back == first, rc);
        let mut two = [0u8; 1024];
        expect_denied(b"disk_read(rel 63, 2 sectors) [crosses the end]",
                      sys::disk_read_on(part1, PART1_SECTORS - 1, &mut two));
        // The one the gate row pins: `[DISK] scope: ... refused write LBA 64+1`.
        expect_denied(b"disk_write(rel 64) [one past the end]",
                      sys::disk_write(PART1_SECTORS, &first));
        sys::println(b"[CAPTEST] partition checks done");

        // ── Wave 10: the partition selector and SYS_DISK_SIZE ──
        let part0 = sys::cap_lookup(sys::CapKind::Disk as u8, 1);
        report(b"cap_lookup(disk.part.0) [granted READ]", part0 >= 0, part0);
        if part0 >= 0 {
            const E_CAPPERMS: isize = -201;
            let part0 = part0 as u32;
            // Pinned by the gate row: `holds partitions 0 and 1: refused
            // ambiguous read LBA 0+1`.
            expect_denied(b"disk_read(rel 0) [sentinel, two readable partitions: ambiguous]",
                          sys::disk_read(0, &mut back));
            let rc = sys::disk_read_on(part0, 0, &mut back);
            report(b"disk_read_on(part 0, rel 0) is the FAT32 boot sector",
                   rc == 0 && back[510] == 0x55 && back[511] == 0xAA && &back[82..87] == b"FAT32",
                   rc);
            expect_errno(b"disk_write_on(part 0) [READ-only handle] -> -ECAPPERMS",
                         sys::disk_write_on(part0, 0, &first), E_CAPPERMS);
            expect_errno(b"disk_read_on(forged handle) -> -ECAPSTALE",
                         sys::disk_read_on(0x7FFF_FFF1, 0, &mut back), E_CAPSTALE);
            expect_errno(b"disk_size_on(part 1) is its 64 sectors",
                         sys::disk_size_on(part1), PART1_SECTORS as isize);
            let n0 = sys::disk_size_on(part0);
            report(b"disk_size_on(part 0) is the FAT32 partition, not the medium",
                   n0 > 0 && n0 != PART1_SECTORS as isize && n0 < 1 << 20, n0);
            expect_denied(b"disk_size() [sentinel, two partitions: ambiguous]", sys::disk_size());
        }
        sys::println(b"[CAPTEST] partition selector checks done");
    }

    // ── POSITIVE: granted sensors are reachable ──────────────────────────
    // Each read goes through the `Cap<Sensor>` the topology grants for that
    // type (`sensor.0`..`sensor.9`, read-only), looked up first.
    let mut imu = [0u8; 24];
    expect_admitted(b"sensor_read_typed(IMU)", read_sensor(sys::SENSOR_TYPE_IMU, &mut imu));
    let mut odom = [0u8; 16];
    expect_admitted(b"sensor_read_typed(ODOM)", read_sensor(sys::SENSOR_TYPE_ODOM, &mut odom));
    let mut enc = [0u8; 16];
    expect_admitted(b"sensor_read_typed(ENCODER)", read_sensor(sys::SENSOR_TYPE_ENCODER, &mut enc));
    let mut range = [0u8; 4];
    expect_admitted(b"sensor_read_typed(RANGE)", read_sensor(sys::SENSOR_TYPE_RANGE, &mut range));
    let mut batt = [0u8; 2];
    expect_admitted(b"sensor_read_typed(BATTERY)", read_sensor(sys::SENSOR_TYPE_BATTERY, &mut batt));

    // ── Wave 11 (SENSORTS): the stamped read, SYS_SENSOR_READ_TS (606) ───
    stamped_reads();

    // ── POSITIVE: granted motors accept a write ──────────────────────────
    // Speed 0 on purpose: this asserts the capability, and must not move a
    // real robot if the same image is ever booted on hardware.
    let motor0 = sys::cap_lookup(sys::CapKind::Motor as u8, 0);
    let motor1 = sys::cap_lookup(sys::CapKind::Motor as u8, 1);
    expect_admitted(b"motor_speed_typed(L,0)", speed_zero(motor0));
    expect_admitted(b"motor_speed_typed(R,0)", speed_zero(motor1));

    // ── NEGATIVE: ungranted resources stay refused ───────────────────────
    //
    // No capability table can hold an ADC channel (`CapKind::Adc` has no
    // minter), so this is refused whatever the topology grants. It is the
    // untyped refusal the kernel's `cap-deny-smoke` task reads back off the
    // disk, and it stays ahead of the other refusals: denial records are
    // bounded per task, and the forged GPIO handle below has to land inside
    // the same budget.
    expect_denied(b"adc_read(0) [ungranted]", sys::adc_read(0));
    // A wheel the topology does not grant has no handle to look up (asserted
    // below). What ring 3 can still send is a handle it made up.
    expect_errno(b"motor_speed_typed(0,0) [forged cap]",
                 sys::motor_speed_typed(0, 0), E_CAPSTALE);

    // ── NEGATIVE, TYPED: the same refusal through Cap<T> ─────────────────
    //
    // Two properties, and the second is the one with no other coverage on a
    // booted machine.
    //
    // First: `cap_lookup` for a capability this task does not hold must
    // return nothing. A lookup that answered here would BE a mint — it would
    // hand out authority the boot never granted — so this is the security
    // assertion for the whole discovery primitive, not a smoke test.
    //
    // This used to ask for `Gpio(0)`, back when the topology granted no GPIO
    // at all. It grants `gpio.0` deliberately now — that grant is what makes
    // the drivetrain guard observable, see the hardware-families block below —
    // so the question moved to a pin that is in range and belongs to nobody.
    // Picking an ungranted resource is the whole content of this check: an
    // ungranted resource that later becomes granted turns it into a tautology.
    expect_errno(b"cap_lookup(Gpio,63) [ungranted pin]",
                 sys::cap_lookup(sys::CapKind::Gpio as u8, 63), E_NOENT);
    expect_errno(b"cap_lookup(Pwm,7) [ungranted channel]",
                 sys::cap_lookup(sys::CapKind::Pwm as u8, 7), E_NOENT);
    expect_errno(b"cap_lookup(Motor,9) [ungranted id]",
                 sys::cap_lookup(sys::CapKind::Motor as u8, 9), E_NOENT);

    // Second: a forged handle into the typed GPIO path is refused, and that
    // refusal reaches the flight recorder as `SAFETY_CAP_DENIED_TYPED`.
    // When this was written no ring-3 program called a typed hardware syscall
    // at all, so the typed recorder was wired and host-tested but had never
    // fired on a real boot. The hardware-families block below now calls
    // plenty; this stays because a FORGED handle is a different event from a
    // refused real one, and only this line produces it. Handle 0 is `Cap::NULL`, the cheapest possible
    // forgery and the one a caller passing an uninitialised variable sends.
    expect_errno(b"gpio_read_typed(0) [forged cap]",
                 sys::gpio_read_typed(0), E_CAPSTALE);

    // And the positive control for the primitive itself, on a capability the
    // topology DOES grant this task: without it, every assertion above is
    // satisfied by a `cap_lookup` that always fails.
    // A handle is a non-negative value, so "not refused" is `>= 0` — the
    // same trap the socket-fd assertion hit: fd 0 and cap slot 0 are both
    // valid, and `> 0` would have failed on the very first capability minted.
    report(b"cap_lookup(Motor,0) [granted]", motor0 >= 0, motor0);

    // ── Cap<File>: a file as a capability, from ring 3 ──────────────────
    //
    // `HELLO.TXT` is on every image the gate builds, so the read-back carries
    // content only the real filesystem can supply.
    {
        const HELLO: &[u8] = b"Hello from AzOS FAT32!\n";
        const E_CAPPERMS: isize = -201;
        const E_INVAL: isize = -22;

        let f = sys::file_open_typed(sys::cstr!(b"/fat/HELLO.TXT"), 0);
        report(b"file_open_typed(HELLO.TXT, O_RDONLY)", f >= 0, f);
        if f >= 0 {
            let c = f as u32;
            let mut buf = [0u8; 64];
            let n = sys::file_read_typed(c, &mut buf);
            report(b"file_read_typed returns the file's own bytes",
                   n == HELLO.len() as isize && &buf[..HELLO.len()] == HELLO, n);
            expect_errno(b"file_write_typed on a READ-only cap",
                         sys::file_write_typed(c, b"x"), E_CAPPERMS);

            // The descriptor behind the capability, found the way a task finds
            // anything it holds. While the capability is live the untyped close
            // must refuse it: otherwise the next open reuses the number and
            // this handle names a different file. The read that follows is
            // what tells a refusal from a close — both return -1, but only
            // after a refusal does the descriptor still answer (0, at EOF).
            let mut fd: isize = -1;
            for i in 3..32u32 {
                if sys::cap_lookup(sys::CapKind::File as u8, i) == f {
                    fd = i as isize;
                    break;
                }
            }
            report(b"cap_lookup(File, fd) finds the minted cap", fd >= 3, fd);
            if fd >= 3 {
                expect_errno(b"close(fd) refused behind a live Cap<File>",
                             unsafe { untyped_close(fd as u64) }, -1);
                expect_errno(b"file_read_typed still reads after the refused close",
                             sys::file_read_typed(c, &mut buf), 0);
            }

            expect_errno(b"close_typed(file cap)", sys::close_typed(c), 0);
            expect_errno(b"file_read_typed after close_typed [stale]",
                         sys::file_read_typed(c, &mut buf), E_CAPSTALE);
            expect_errno(b"close_typed twice [stale]", sys::close_typed(c), E_CAPSTALE);
        }
        expect_errno(b"file_open_typed access mode 3",
                     sys::file_open_typed(sys::cstr!(b"/fat/HELLO.TXT"), 3), E_INVAL);
        let mut scratch = [0u8; 4];
        expect_errno(b"file_read_typed(0) [forged cap]",
                     sys::file_read_typed(0, &mut scratch), E_CAPSTALE);
    }

    // ── The owner-round-23 file calls (597-601), from ring 3 ────────────
    //
    // Non-destructive on `/fat`: every image the gate builds is shared by
    // other rows, so the mutating FAT32 paths are covered by `tests/host/fs-tests`
    // on an in-memory volume, and here only what cannot change the image runs
    // against it. The positive mkdir/rmdir work on the ramfs `/tmp` instead.
    {
        const E_NOTEMPTY: isize = -39;
        const E_INVAL: isize = -22;
        let mut st = [0u8; 48];
        let rc = sys::statfs(sys::cstr!(b"/fat"), &mut st);
        report(b"statfs(/fat) -> 0", rc == 0, rc);
        let u32_at = |o: usize| u32::from_le_bytes([st[o], st[o + 1], st[o + 2], st[o + 3]]);
        let u64_at = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&st[o..o + 8]);
            u64::from_le_bytes(b)
        };
        report(b"statfs(/fat) is FAT32 (type 1)", u32_at(0) == 1, u32_at(0) as isize);
        report(b"statfs(/fat) has blocks, free <= total",
               u64_at(8) > 0 && u64_at(16) <= u64_at(8), u64_at(16) as isize);
        let mut short = [0u8; 47];
        expect_errno(b"statfs(short buffer) -> -EINVAL", sys::statfs(sys::cstr!(b"/fat"), &mut short), E_INVAL);

        let f = sys::file_open_typed(sys::cstr!(b"/fat/HELLO.TXT"), 0);
        if f >= 0 {
            expect_errno(b"fsync_typed(READ-only file cap) -> 0", sys::fsync_typed(f as u32), 0);
            let _ = sys::close_typed(f as u32);
        } else {
            report(b"file_open_typed(HELLO.TXT) for fsync", false, f);
        }
        expect_errno(b"fsync_typed(0) [forged cap]", sys::fsync_typed(0), E_CAPSTALE);

        // Wave 10: these five need a `Cap<File>` WRITE tree covering the
        // path. The QEMU topology grants autorun `/fat` and `/tmp` (a ramfs
        // directory); everything else is refused with -EACCES before the
        // filesystem is asked, so the refusal says nothing about existence.
        const E_ACCES: isize = -13;
        expect_errno(b"truncate(/fat/NOSUCH.TXT) -> -ENOENT [tree /fat]",
                     sys::truncate(sys::cstr!(b"/fat/NOSUCH.TXT"), 0), E_NOENT);
        // Admitted, and answered by FAT32 itself: the target is no 8.3 name.
        // (Not a missing source: that is -ENOENT now, asserted below, but
        // this one names the FAT32 name check itself.)
        expect_errno(b"rename(/fat/NOSUCH.TXT -> /fat/not-an-8.3-name) -> -EINVAL [tree /fat]",
                     sys::rename(sys::cstr!(b"/fat/NOSUCH.TXT"), sys::cstr!(b"/fat/not-an-8.3-name")), E_INVAL);
        expect_errno(b"rename(/fat/HELLO.TXT -> /nomount/X) -> -EACCES [no tree on /nomount]",
                     sys::rename(sys::cstr!(b"/fat/HELLO.TXT"), sys::cstr!(b"/nomount/X")), E_ACCES);
        expect_errno(b"rmdir(/tmp/nosuchdir) -> -ENOENT", sys::rmdir(sys::cstr!(b"/tmp/nosuchdir")), E_NOENT);
        expect_errno(b"rmdir(/dev) -> -EACCES [no tree on /]", sys::rmdir(sys::cstr!(b"/dev")), E_ACCES);
        expect_errno(b"unlink(/dev/stdin) -> -EACCES [no tree on /dev]",
                     sys::unlink(sys::cstr!(b"/dev/stdin")), E_ACCES);
        expect_errno(b"mkdir(/captest.d) -> -EACCES [no tree on /]",
                     sys::mkdir(sys::cstr!(b"/captest.d")), E_ACCES);
        expect_errno(b"rmdir(/tmp/../dev) -> -EINVAL [.. is not resolved]",
                     sys::rmdir(sys::cstr!(b"/tmp/../dev")), E_INVAL);
        expect_errno(b"mkdir(/tmp/captest.d)", sys::mkdir(sys::cstr!(b"/tmp/captest.d")), 0);
        expect_errno(b"mkdir(/tmp/captest.d/x)", sys::mkdir(sys::cstr!(b"/tmp/captest.d/x")), 0);
        expect_errno(b"rmdir(/tmp/captest.d) [not empty] -> -ENOTEMPTY",
                     sys::rmdir(sys::cstr!(b"/tmp/captest.d")), E_NOTEMPTY);
        expect_errno(b"rmdir(/tmp/captest.d/x) -> 0", sys::rmdir(sys::cstr!(b"/tmp/captest.d/x")), 0);
        expect_errno(b"rmdir(/tmp/captest.d) -> 0", sys::rmdir(sys::cstr!(b"/tmp/captest.d")), 0);
        expect_errno(b"rmdir(/tmp/captest.d) again -> -ENOENT",
                     sys::rmdir(sys::cstr!(b"/tmp/captest.d")), E_NOENT);

        // Wave 11 (HERM): `mkdir` and `unlink` reach FAT32 under `/fat` (they
        // used to know only the ramfs, so `mkdir /fat/X` answered -1), and
        // `rename` answers with the real errno instead of -EIO. Everything
        // created here is removed again: this image is private to the row.
        const E_EXIST: isize = -17;
        const E_ISDIR: isize = -21;
        expect_errno(b"mkdir(/fat/HERMD) -> 0 [FAT32]",
                     sys::mkdir(sys::cstr!(b"/fat/HERMD")), 0);
        expect_errno(b"mkdir(/fat/HERMD) again -> -EEXIST",
                     sys::mkdir(sys::cstr!(b"/fat/HERMD")), E_EXIST);
        expect_errno(b"unlink(/fat/HERMD) [a directory] -> -EISDIR",
                     sys::unlink(sys::cstr!(b"/fat/HERMD")), E_ISDIR);
        expect_errno(b"unlink(/fat/NOSUCH.TXT) -> -ENOENT [FAT32]",
                     sys::unlink(sys::cstr!(b"/fat/NOSUCH.TXT")), E_NOENT);
        expect_errno(b"rename(/fat/NOSUCH.TXT -> /fat/NEWNAME.TXT) -> -ENOENT [real errno]",
                     sys::rename(sys::cstr!(b"/fat/NOSUCH.TXT"), sys::cstr!(b"/fat/NEWNAME.TXT")), E_NOENT);
        // O_WRONLY | O_CREAT = 0x41.
        let hf = sys::file_open_typed(sys::cstr!(b"/fat/HERMF.TXT"), 0x41);
        report(b"file_open_typed(/fat/HERMF.TXT, O_CREAT) [tree /fat]", hf >= 0, hf);
        if hf >= 0 {
            expect_errno(b"file_write_typed(HERMF.TXT, 1 byte)", sys::file_write_typed(hf as u32, b"x"), 1);
            expect_errno(b"close_typed(HERMF.TXT)", sys::close_typed(hf as u32), 0);
        }
        expect_errno(b"unlink(/fat/HERMF.TXT) -> 0 [FAT32]",
                     sys::unlink(sys::cstr!(b"/fat/HERMF.TXT")), 0);
        expect_errno(b"unlink(/fat/HERMF.TXT) again -> -ENOENT",
                     sys::unlink(sys::cstr!(b"/fat/HERMF.TXT")), E_NOENT);
        expect_errno(b"rmdir(/fat/HERMD) -> 0 [FAT32]",
                     sys::rmdir(sys::cstr!(b"/fat/HERMD")), 0);
    }

    // ── THE THREE HARDWARE FAMILIES, from ring 3 ────────────────────
    //
    // Gpio, I2c and Pwm had no ring-3 caller because NOTHING GRANTED THEM:
    // `default_minimal()` seeded motors, the GPIO driver registry and sensors,
    // and nothing else, so the eleven typed syscalls behind these three were
    // unreachable and the guards protecting the drivetrain from them had no
    // exercise on a booted machine. The topology now names one free resource
    // per family — and, deliberately, two resources that BELONG TO A MOTOR so
    // the refusal can be observed.
    {
        // `bus.0/0x68` — the simulated MPU-6050. The resource is
        // `(bus << 8) | addr`, the packing in `crates/core/ipc/src/i2c_cap.rs`.
        const I2C_IMU_RES: u32 = (0u32 << 8) | 0x68;

        let pwm_free   = sys::cap_lookup(sys::CapKind::Pwm as u8, 4);
        let pwm_motor  = sys::cap_lookup(sys::CapKind::Pwm as u8, 0);
        let gpio_free  = sys::cap_lookup(sys::CapKind::Gpio as u8, 20);
        let gpio_motor = sys::cap_lookup(sys::CapKind::Gpio as u8, 0);
        let i2c_imu    = sys::cap_lookup(sys::CapKind::I2c as u8, I2C_IMU_RES);
        report(b"cap_lookup(Pwm,4) [granted]",   pwm_free   >= 0, pwm_free);
        report(b"cap_lookup(Pwm,0) [granted]",   pwm_motor  >= 0, pwm_motor);
        report(b"cap_lookup(Gpio,20) [granted]", gpio_free  >= 0, gpio_free);
        report(b"cap_lookup(Gpio,0) [granted]",  gpio_motor >= 0, gpio_motor);
        report(b"cap_lookup(I2c,bus0/0x68) [granted]", i2c_imu >= 0, i2c_imu);

        // GPIO: a WRITE-then-READ round trip through two different syscalls,
        // so a handler stubbed to return 0 is caught by the read-back rather
        // than believed. Pin 20 belongs to nothing else on this machine.
        if gpio_free >= 0 {
            let g = gpio_free as u32;
            expect_allowed(b"gpio_set_dir_typed(20, output)", sys::gpio_set_dir_typed(g, 1));
            expect_allowed(b"gpio_write_typed(20, 1)", sys::gpio_write_typed(g, 1));
            expect_errno(b"gpio_read_typed(20) -> 1", sys::gpio_read_typed(g), 1);
            expect_allowed(b"gpio_write_typed(20, 0)", sys::gpio_write_typed(g, 0));
            expect_errno(b"gpio_read_typed(20) -> 0", sys::gpio_read_typed(g), 0);
        }

        // I2C: the read-back carries a value only the real device can supply.
        // WHO_AM_I on an MPU-6050 is register 0x75 and reads 0x68 — its own
        // address. A stubbed handler cannot produce it, and unlike an rc of 0
        // it is not a value that appears by accident.
        if i2c_imu >= 0 {
            let c = i2c_imu as u32;
            expect_allowed(b"i2c_detect_typed(bus0/0x68) [simulated IMU acks]",
                           sys::i2c_detect_typed(c));
            let mut who = [0u8; 1];
            expect_errno(b"i2c_read_typed WHO_AM_I -> 1 byte",
                         sys::i2c_read_typed(c, 0x75, &mut who), 1);
            report(b"WHO_AM_I reads 0x68 (only the real device says this)",
                   who[0] == 0x68, who[0] as isize);
        }

        // PWM on a free channel. Asserted on the return code alone, and that
        // is a stated limit rather than an oversight: ring 3 has no
        // `pwm_get_typed`, so there is nothing to read back — the one
        // observable this family offers is the refusal below.
        if pwm_free >= 0 {
            let p = pwm_free as u32;
            expect_allowed(b"pwm_set_period_typed(ch4)", sys::pwm_set_period_typed(p, 20_000_000));
            expect_allowed(b"pwm_enable_typed(ch4)", sys::pwm_enable_typed(p));
            expect_allowed(b"pwm_set_duty_pct_typed(ch4, 40)", sys::pwm_set_duty_pct_typed(p, 40));
            expect_allowed(b"pwm_disable_typed(ch4)", sys::pwm_disable_typed(p));
        }

        // ── THE SECURITY HALF: a capability is not enough ──────────
        //
        // These five hold a VALID, GRANTED capability for a resource the
        // drivetrain owns, and the kernel must refuse every one. PWM channel 0
        // is motor 0's duty; GPIO 0 is one of its H-bridge direction pins.
        // Reaching either below `motor_set` bypasses the e-stop latch and the
        // motor envelope together — the duty route decides how FAST a wheel
        // turns, the direction route decides which WAY, and the second guard
        // did not exist until 2026-09-10.
        //
        // The distinction that makes these worth writing: E_PERM here means
        // "you hold it and you still may not", which is a different claim from
        // the E_NOENT a missing grant would give. Without the grants above,
        // deleting both guards would leave this file passing.
        if pwm_motor >= 0 {
            let p = pwm_motor as u32;
            expect_errno(b"pwm_set_duty_pct_typed(MOTOR ch0) refused",
                         sys::pwm_set_duty_pct_typed(p, 50), E_PERM);
            expect_errno(b"pwm_enable_typed(MOTOR ch0) refused",
                         sys::pwm_enable_typed(p), E_PERM);
        }
        if gpio_motor >= 0 {
            let g = gpio_motor as u32;
            expect_errno(b"gpio_write_typed(MOTOR dir pin 0) refused",
                         sys::gpio_write_typed(g, 1), E_PERM);
            expect_errno(b"gpio_set_dir_typed(MOTOR dir pin 0) refused",
                         sys::gpio_set_dir_typed(g, 0), E_PERM);
        }
    }

    // ── THE TYPED PID FAMILY (550-555): the first ring-3 caller ──────
    //
    // All six were reachable and had ZERO ring-3 callers. That is a different
    // gap from "no possible caller" (closed 2026-09-06 with `SYS_CAP_LOOKUP`):
    // autorun holds `Motor(0)` and `Motor(1)` RW, so these calls were
    // available and simply never made from a booted machine. Their host tests
    // exercise `motor_cap`, not the syscall boundary.
    //
    // The pair rule matters here and is why the negative half uses a forged
    // handle rather than a wheel this task lacks: these five demand WRITE on
    // BOTH wheels because they command the drivetrain in one operation, and
    // autorun holds both, so there is no "one wheel only" state to reach from
    // ring 3.
    if motor0 >= 0 {
        let cap = motor0 as u32;

        // NEGATIVE, on every one of the six. `Cap::NULL` is handle 0 — the
        // cheapest forgery, and what an uninitialised variable sends. A
        // handler stubbed to return 0 fails all six of these.
        let mut tick_out = [0u8; sys::MOTOR_TICK_BYTES];
        expect_errno(b"motor_set_target_typed(0) [forged cap]",
                     sys::motor_set_target_typed(0, 0, 0), E_CAPSTALE);
        expect_errno(b"motor_tick_typed(0) [forged cap]",
                     sys::motor_tick_typed(0, 0, 0, 0, &mut tick_out), E_CAPSTALE);
        expect_errno(b"motor_enable_typed(0) [forged cap]",
                     sys::motor_enable_typed(0, 1), E_CAPSTALE);
        expect_errno(b"motor_enabled_typed(0) [forged cap]",
                     sys::motor_enabled_typed(0), E_CAPSTALE);
        expect_errno(b"motor_set_gains_typed(0) [forged cap]",
                     sys::motor_set_gains_typed(0, 1, 0, 0), E_CAPSTALE);
        expect_errno(b"motor_reset_typed(0) [forged cap]",
                     sys::motor_reset_typed(0), E_CAPSTALE);

        // POSITIVE, and the enable/enabled pair is the one that discriminates:
        // it writes through one syscall and reads back through ANOTHER, so a
        // handler stubbed to return success is caught by the read-back rather
        // than believed. `PID_ENABLED` has exactly one writer (this program)
        // and `rt_motor_task` only reads it, so the round trip is not a race.
        //
        // Target stays 0 throughout ON PURPOSE: the PID is enabled from boot,
        // so `rt_motor_task` is ALREADY taking the PID branch and driving the
        // wheels from its output. A non-zero target here would spin the
        // drivetrain of a machine running a capability test.
        // The boot state is NOT assumed. It is `true` today —
        // `motor_pid_init()` enables closed-loop control at startup, so
        // `rt_motor_task` runs the PID branch for the whole boot — but that is
        // a kernel boot policy, and pinning it from a capability test would
        // make this program fail for a reason that has nothing to do with
        // capabilities. Recorded as a diagnostic, asserted as a round trip
        // from whatever it is, and put back at the end.
        let pid_boot = sys::motor_enabled_typed(cap);
        report(b"motor_enabled_typed [boot state is a clean bool]",
               pid_boot == 0 || pid_boot == 1, pid_boot);
        sys::print(b"[CAPTEST] PID enabled at boot = ");
        print_i(pid_boot);
        sys::print(b"\n");

        expect_allowed(b"motor_enable_typed(0)", sys::motor_enable_typed(cap, 0));
        expect_errno(b"motor_enabled_typed -> 0 after disable",
                     sys::motor_enabled_typed(cap), 0);
        expect_allowed(b"motor_enable_typed(1)", sys::motor_enable_typed(cap, 1));
        expect_errno(b"motor_enabled_typed -> 1 after enable",
                     sys::motor_enabled_typed(cap), 1);
        // Back to the boot state, whatever it was.
        expect_allowed(b"motor_enable_typed [restore boot state]",
                       sys::motor_enable_typed(cap, pid_boot as u64));

        // The gains echo is a DIAGNOSTIC, not the assertion — said plainly
        // because it looks like one. `motor_pid_set_gains` prints
        // "[MOTOR-PID] Gains updated: Kp=4242 Ki=137 Kd=9" from inside the
        // call, with values only this caller could have supplied, so a human
        // reading the log can see the arguments reached the driver. But the
        // scenario's success marker is `[CAPTEST] ALL PASSED` and `qemu_run`
        // deletes the log on success, so nothing greps that line.
        //
        // What actually discriminates for this family is the enable/enabled
        // round trip above: it writes through one syscall and reads back
        // through another, so a handler stubbed to return 0 is caught.
        expect_allowed(b"motor_set_gains_typed(4242,137,9)",
                       sys::motor_set_gains_typed(cap, 4242, 137, 9));
        // Put the boot defaults back: the gains are global to the PID and a
        // capability test must not leave the controller misconfigured for
        // whatever runs next in this boot.
        expect_allowed(b"motor_set_gains_typed [restore 1,0,0]",
                       sys::motor_set_gains_typed(cap, 1, 0, 0));

        // Target 0, not a live setpoint. The PID runs from boot, so a
        // non-zero target here would set `rt_motor_task` driving the wheels of
        // a machine running a capability test — and it would buy no assertion,
        // because the resulting PWM is not observable from ring 3 (see the
        // tick note below).
        expect_allowed(b"motor_set_target_typed(0,0)",
                       sys::motor_set_target_typed(cap, 0, 0));

        // The tick is asserted on its ABI SHAPE only, and that is a limit
        // worth stating rather than hiding. `motor_pid_tick` returns (0,0)
        // while PID is disabled, so the value here is a constant; and the
        // moment PID is ENABLED, `rt_motor_task` ticks the same controller and
        // the same `TICK_STATE` on its own cadence, so a PWM read back from
        // ring 3 would be a race in both directions. What can be pinned
        // soundly is that the call reaches the handler and returns the
        // documented byte count.
        //
        // The same reason keeps the OVERFLOW GUARD out of here.
        // `motor_pid_tick` saturates `elapsed * 1000` and the encoder deltas
        // deliberately — its own comment calls that "a security bound, not a
        // robustness nicety", because `now` and `ticks` come straight from
        // ring 3 and this kernel is `panic = "abort"`. Exercising it from here
        // would mean writing hostile values into the LIVE controller state
        // `rt_motor_task` shares, and leaving the drivetrain being driven from
        // poisoned velocity until the next reset. It is pinned on the host
        // instead — `tests/host/drivers-tests`, `mod motor_pid_tick_bounds`.
        expect_errno(b"motor_tick_typed -> MOTOR_TICK_BYTES",
                     sys::motor_tick_typed(cap, 0, 0, sys::vdso_uptime_ticks(),
                                           &mut tick_out),
                     sys::MOTOR_TICK_BYTES as isize);
        // Leave the controller as it was found: state cleared and target 0.
        expect_allowed(b"motor_reset_typed", sys::motor_reset_typed(cap));
    }

    // ── DIAGNOSTIC: what the sensors actually reported ───────────────────
    // Not assertions — QEMU has no ultrasonic rangefinder, no IMU and no ADC,
    // so there are no correct values to assert against. They are printed
    // because the alternative is inferring them, and inferring is what cost
    // time here: `reflex` sat silent and it was not possible to tell from its
    // output whether it was reading a clear road or reading nothing at all.
    //
    // On the RANGE line: under QEMU the driver IS initialised and serves the
    // simulated distance array, so these are real numbers (1500/800 mm at
    // boot), not zeros — `reflex-smoke` drives them to force a decision.
    //
    // The ABI still has a latent ambiguity worth recording. `sensor_read_dispatch`
    // computes the value as `us_read_mm(0).unwrap_or(0)`, so an
    // *uninitialised or absent* sensor would reach userspace as 0 mm, which
    // is also what an obstacle pressed against the bumper reads. reflex
    // guards its comparison with `range_front > 0`, so that case becomes "no
    // obstacle" — a safety daemon failing silent-open. It does not arise in
    // QEMU and is not patched from userspace: it is a decision about what the
    // sensor ABI should say when there is nothing to report.
    sys::print(b"[CAPTEST] RANGE front_mm=");
    print_i(u16::from_le_bytes([range[0], range[1]]) as isize);
    sys::print(b" right_mm=");
    print_i(u16::from_le_bytes([range[2], range[3]]) as isize);
    sys::print(b"  (0 = no sensor OR touching; the ABI cannot say which)\n");
    sys::print(b"[CAPTEST] BATTERY mv=");
    print_i(u16::from_le_bytes([batt[0], batt[1]]) as isize);
    sys::print(b"\n");

    // ── RETIRED — a syscall number that must no longer answer ───────────
    //
    // 116 was `SYS_CAP_GRANT`: it let a ring-3 task hand one of its
    // capabilities to another task. RFC-0003 says capabilities are granted at
    // boot and not allocated dynamically -- that is what makes the set of
    // rights a robot holds a static, auditable fact -- and the gate the RFC's
    // own design requires for dynamic delegation was never built. So the call
    // was removed on 2026-09-03.
    //
    // Removing a syscall from the source is not the same as it being refused
    // at the boundary, and only the second one is a security property. A stale
    // dispatch arm, a fallthrough, or a number quietly reassigned to something
    // else would all leave the source looking clean. So ask the kernel, from
    // ring 3, the way an old binary or an attacker would, and require a
    // refusal.
    //
    // Deliberately called with plausible arguments -- a live TID, a handle
    // shape, a permission mask -- rather than zeros, so that a handler which
    // survived somewhere cannot pass this by rejecting nonsense input.
    let rc = unsafe { raw_syscall3(116, 1, 0x0001_0001, 0x3) };
    report(b"SYS_CAP_GRANT (116) is refused", rc < 0, rc);

    // ── The kernel's own mappings must not be reachable from ring 3 ─────
    //
    // Every user page table carries the kernel's mappings, merged in at exec
    // and fork. The merge copies the kernel's PTE -- which is a POINTER to the
    // kernel's own next-level table -- so a walk down a user page table to any
    // address in the shared region lands on the kernel's table, not on a copy
    // of it. `munmap` walks and clears.
    //
    // `SYS_MUNMAP` has no capability check, and every image profile that lists
    // it lets it through (`crates/core/sched/src/seccomp.rs`: CAPTEST.ELF and
    // VSBENCH.ELF), so for those programs this is one unprivileged call. It
    // was any ring-3 task before seccomp was installed at exec, and a task
    // under no filter still reaches it. Clearing the UART's PTE kills
    // `kprintln!`; the next one takes a fatal S-mode store fault, and with
    // `panic = "abort"` that is a board reset. On a robot that is the machine
    // stopping mid-motion because a userspace program made one syscall.
    //
    // Three addresses, all below the old `USER_VA_TOP` ceiling and therefore
    // all accepted by the guard that was meant to prevent exactly this.
    // Asking for a refusal, not for a return code -- if this ever returns 0
    // again the board may not survive to print the failure.
    //
    // The property is ISA-neutral (the kernel's own console + interrupt
    // controller must never be unmappable from ring 3) but the addresses are
    // not: riscv64's are CLINT/PLIC/UART; aarch64 has no CLINT/PLIC — its
    // interrupt controller is the GICv3 distributor + redistributor. Each
    // side's literals match the SAME addresses `kernel/src/main.rs` maps with
    // `map_mmio_region` on that ISA (`crates/drivers/base/src/platform.rs`'s
    // `hw::UART_BASE`, `crates/core/arch-aarch64/src/gic.rs`'s `GICD_BASE`/
    // `GICR_BASE`, and riscv64's own CLINT/PLIC literals) — restated here
    // rather than imported, the same tradeoff `platform.rs`'s own vDSO
    // const-check makes: this crate is `no_std`/`no_main` userspace and does
    // not link the kernel's drivers or arch crates, and the two builds are
    // separate ELFs per ISA, so a `#[cfg(target_arch)]` table is not a twin
    // in the sense the kernel-side rule means — it is the same pattern
    // `userspace/tests/ipctest`'s `spawn()` already uses for its per-ISA register
    // names.
    #[cfg(target_arch = "riscv64")]
    let kernel_critical: [(&[u8], u64); 3] = [
        (b"munmap(CLINT) is refused", 0x0200_0000u64),
        (b"munmap(PLIC) is refused",  0x0C00_0000u64),
        (b"munmap(UART) is refused",  0x1000_0000u64),
    ];
    #[cfg(target_arch = "aarch64")]
    let kernel_critical: [(&[u8], u64); 3] = [
        (b"munmap(GICD) is refused", 0x0800_0000u64),
        (b"munmap(GICR) is refused", 0x080A_0000u64),
        (b"munmap(UART) is refused", 0x0900_0000u64),
    ];
    for (name, addr) in kernel_critical {
        let rc = sys::munmap(addr, 4096);
        report(name, rc < 0, rc);
    }

    // The other half of the same property, and the one that would catch an
    // over-broad fix: a task must still be able to unmap its OWN memory.
    // Refusing everything would make the check above pass while breaking the
    // syscall, and nothing else here would notice.
    // The other half of the same property, and the half that catches an
    // over-broad fix: refusing the kernel's pages must not mean refusing
    // everything. "return -1 always" satisfies the three checks above and
    // breaks the syscall, and nothing else in the gate would notice.
    //
    // `fd` must be -1. `sys_mmap` accepts only anonymous mappings and rejects
    // any other fd on its first line, which is a refusal that looks exactly
    // like the guard failing -- worth stating here because passing 0 cost an
    // investigation into a kernel bug that did not exist.
    const MAP_ANON_FD: u64 = u64::MAX;
    let p = sys::mmap(0, 4096, sys::PROT_READ | sys::PROT_WRITE, 0, MAP_ANON_FD, 0);
    if p > 0 {
        let rc = sys::munmap(p as u64, 4096);
        report(b"a task can still unmap its OWN page", rc >= 0, rc);
    } else {
        report(b"mmap for the own-page check", false, p);
    }

    // Both ISAs: a ring-3 interrupt, delivered mask-until-ACK. Before the
    // MMIO section, whose refusals must stay last (bounded denial records).
    irq_section();

    // ── MMIO by region index (RFC-0043) ─────────────────────────────────
    //
    // `SYS_MMIO_MAP` takes an index into the board's MMIO region table, never
    // an address, and the table decides the range and whether it may be
    // written — ISA-neutral by construction (`crates/core/topology`'s `mmio.<N>`
    // resource names an index, not an address; see `cap_seed.rs`). The
    // topology grants this program `mmio.0` READ: on QEMU `virt` the board's
    // RTC, read-only in the table — goldfish RTC on riscv64, PL031 on
    // aarch64, a different IP with a different register layout on each ISA,
    // but `crates/drivers/base/src/platform.rs`'s `hw::MMIO_REGIONS[0]` names
    // whichever one the board has, and this file never needs to know which.
    // Index 1 is a writable region granted to nobody.
    //
    // Last on purpose: the refusal of index 1 is a capability denial, and
    // denial records are bounded per task (see the ADC refusal above).
    {
        const ACCESS_READ: u64 = CapPerms::READ.bits() as u64;
        const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;
        const E_ACCES: isize = -13;
        const E_INVAL: isize = -22;
        // A refusal written at dispatch level, `dispatch.rs`'s `E_PERM`, not
        // the handlers' -99 this file calls `E_PERM`.
        const E_PERM_DISPATCH: isize = -1;

        let va = unsafe { mmio_map(0, ACCESS_READ) };
        report(b"mmio_map(0, READ) [granted, read-only RTC]", va > 0, va);
        if va > 0 {
            // Offset 0x00: goldfish RTC's TIME_LOW (latches TIME_HIGH at
            // 0x04) on riscv64; PL031's RTCDR — the live seconds-since-epoch
            // value — on aarch64. Both are non-zero the moment QEMU boots
            // with a real host clock, so the SAME two-word read proves the
            // mapping reaches a live register on either ISA: a zero page or
            // a mapping of the wrong frame returns 0|0.
            let reg = va as usize as *const u32;
            let low = unsafe { core::ptr::read_volatile(reg) };
            let high = unsafe { core::ptr::read_volatile(reg.add(1)) };
            report(b"RTC time reads non-zero through the mapping",
                   (low | high) != 0, high as isize);
        }
        expect_errno(b"mmio_map(0, READ|WRITE) [read-only region]",
                     unsafe { mmio_map(0, ACCESS_RW) }, E_ACCES);
        expect_errno(b"mmio_map(1, READ) [ungranted index]",
                     unsafe { mmio_map(1, ACCESS_READ) }, E_PERM_DISPATCH);
        // 4 GiB above the granted index. The call used to take a physical
        // base and compare it narrowed to 32 bits; an index is range-checked
        // whole.
        expect_errno(b"mmio_map(1 << 32, READ) [no alias of index 0]",
                     unsafe { mmio_map(1 << 32, ACCESS_READ) }, E_INVAL);
    }

    // ── Wave 11 (SHMRING): the kernel sensor streams, or the path that
    //    answers without them. Last, so no earlier check's timing moves.
    stream::run();

    let failed = unsafe { FAILURES };
    if failed == 0 {
        sys::println(b"[CAPTEST] ALL PASSED");
        sys::exit(0);
    } else {
        sys::print(b"[CAPTEST] FAILED: ");
        print_i(failed as isize);
        sys::println(b" check(s)");
        sys::exit(1);
    }
}

// ── Ring-3 interrupt delivery, mask-until-ACK (wave 8 aarch64, wave 9 both) ──
//
// The qemu topology grants this image the board RTC's interrupt line and the
// RTC writable as `mmio.2`: aarch64 the PL031 (`irq.34`, SPI 2), riscv64 the
// goldfish RTC (`irq.11`, PLIC/APLIC source 11). Each is a device ring 3 can
// make interrupt on demand — the alarm set to "now" fires at once — and each
// holds its line HIGH (level) until the interrupt is cleared. That is what
// makes it a test of the mask: the first delivery leaves the device
// asserting, and the kernel must hold the line masked until this program
// ACKs; the second delivery happens only if the ACK unmasked it.
#[cfg(target_arch = "aarch64")]
mod rtc {
    const DR: usize = 0x00;
    const MR: usize = 0x04;
    const IMSC: usize = 0x10;
    const RIS: usize = 0x14;
    const MIS: usize = 0x18;
    const ICR: usize = 0x1C;
    /// `hw::RTC_IRQ`: `pl031@9010000`'s `interrupts = <0 2 4>`, SPI 2.
    pub const LINE: u32 = 34;
    pub const NAME: &[u8] = b"PL031";

    fn rd(va: usize, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((va + off) as *const u32) }
    }
    fn wr(va: usize, off: usize, v: u32) {
        unsafe { core::ptr::write_volatile((va + off) as *mut u32, v) }
    }
    /// No alarm latched, none enabled.
    pub fn quiet(va: usize) {
        wr(va, IMSC, 0);
        wr(va, ICR, 1);
    }
    /// Raise the alarm now: RTCMR = RTCDR. A second boundary between the
    /// read and the write makes the match lie ~136 years ahead (the count
    /// wraps), so retry until RTCRIS shows the alarm.
    pub fn fire(va: usize) -> bool {
        wr(va, IMSC, 1);
        for _ in 0..8 {
            let now = rd(va, DR);
            wr(va, MR, now);
            if rd(va, RIS) & 1 != 0 {
                return true;
            }
        }
        false
    }
    /// Clear the alarm interrupt (the line drops).
    pub fn clear(va: usize) {
        wr(va, ICR, 1);
    }
    /// Drive the (still asserted) line again. A GIC level SPI needs nothing.
    pub fn reassert(va: usize) {
        wr(va, IMSC, 1);
    }
    /// Whether the device still asserts its line (RTCMIS).
    pub fn asserted(va: usize) -> bool {
        rd(va, MIS) & 1 != 0
    }
}

#[cfg(target_arch = "riscv64")]
mod rtc {
    // QEMU `hw/rtc/goldfish_rtc.c`. Time in nanoseconds; reading TIME_LOW
    // latches TIME_HIGH; a write of ALARM_LOW arms the alarm and fires it at
    // once when it is not in the future; the line is
    // `irq_pending & irq_enabled`, re-driven on every register write that
    // calls `goldfish_rtc_update`.
    const TIME_LOW: usize = 0x00;
    const TIME_HIGH: usize = 0x04;
    const ALARM_LOW: usize = 0x08;
    const ALARM_HIGH: usize = 0x0c;
    const IRQ_ENABLED: usize = 0x10;
    const CLEAR_ALARM: usize = 0x14;
    const CLEAR_INTERRUPT: usize = 0x1c;
    /// `rtc@101000`'s `interrupts = <0x0b>` (PLIC) / `<0x0b 0x04>` (APLIC).
    pub const LINE: u32 = 11;
    pub const NAME: &[u8] = b"goldfish RTC";

    fn rd(va: usize, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((va + off) as *const u32) }
    }
    fn wr(va: usize, off: usize, v: u32) {
        unsafe { core::ptr::write_volatile((va + off) as *mut u32, v) }
    }
    pub fn quiet(va: usize) {
        wr(va, IRQ_ENABLED, 0);
        wr(va, CLEAR_ALARM, 1);
        wr(va, CLEAR_INTERRUPT, 1);
    }
    /// Arm the alarm at the current time: it fires on the ALARM_LOW write.
    /// The device has no readable "interrupt pending" bit, so this cannot
    /// confirm it; the delivery is the proof.
    pub fn fire(va: usize) -> bool {
        wr(va, IRQ_ENABLED, 1);
        let lo = rd(va, TIME_LOW);
        let hi = rd(va, TIME_HIGH);
        wr(va, ALARM_HIGH, hi);
        wr(va, ALARM_LOW, lo);
        true
    }
    pub fn clear(va: usize) {
        wr(va, CLEAR_INTERRUPT, 1);
    }
    /// Drive the still-asserted line again. Needed on QEMU's PLIC: a claim
    /// clears the source's pending bit and a level that merely stays high
    /// does not set it again; the device re-driving it does. Without this
    /// the "held masked" check below could not tell a mask from no mask.
    pub fn reassert(va: usize) {
        wr(va, IRQ_ENABLED, 1);
    }
    /// Asserting by construction: nothing cleared the interrupt.
    pub fn asserted(_va: usize) -> bool {
        true
    }
}

const IRQ_KEY: u64 = 0x1_2034;

/// Poll the port for up to `ms` (10 ms steps). The event's
/// `(source type, source id, key)`, or `None` if nothing arrived.
/// `port_wait_typed` is not the timeout: its own give-up is eight empty
/// blocks, not a clock this test controls.
fn poll_event(port: u32, ms: u64) -> Option<(u8, u32, u64)> {
    let mut ev = [0u8; sys::PORT_EVENT_BYTES];
    let mut waited = 0;
    loop {
        if sys::port_poll_typed(port, &mut ev) == sys::PORT_EVENT_BYTES as isize {
            let key = u64::from_le_bytes([ev[0], ev[1], ev[2], ev[3], ev[4], ev[5], ev[6], ev[7]]);
            let id = u32::from_le_bytes([ev[12], ev[13], ev[14], ev[15]]);
            return Some((ev[8], id, key));
        }
        if waited >= ms {
            return None;
        }
        sys::sleep(10);
        waited += 10;
    }
}

fn print_line_msg(msg: &[u8]) {
    sys::print(b"[CAPTEST] irq: line ");
    print_i(rtc::LINE as isize);
    sys::println(msg);
}

fn irq_section() {
    const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;
    /// `PortEvent::source_type` of an IRQ (`crates/core/ipc/src/irq_bind.rs`).
    const SRC_IRQ: u8 = 3;
    let line = rtc::LINE;
    let want = Some((SRC_IRQ, line, IRQ_KEY));

    let irq_cap = sys::cap_lookup(sys::CapKind::Irq as u8, line);
    report(b"irq: cap_lookup(Irq, RTC line) [granted]", irq_cap > 0, irq_cap);
    let va = unsafe { mmio_map(2, ACCESS_RW) };
    report(b"irq: mmio_map(2, READ|WRITE) [RTC, writable]", va > 0, va);
    let port = sys::port_create_typed();
    report(b"irq: port_create_typed", port > 0, port);
    if irq_cap <= 0 || va <= 0 || port <= 0 {
        return;
    }
    let (va, port) = (va as usize, port as u32);
    sys::print(b"[CAPTEST] irq: device ");
    sys::print(rtc::NAME);
    sys::print(b", line ");
    print_i(line as isize);
    sys::println(b"");
    rtc::quiet(va);

    let rc = sys::port_bind_typed(port, sys::PORT_SRC_IRQ, irq_cap as u32, IRQ_KEY);
    report(b"irq: port_bind_typed(port, RTC line)", rc == 0, rc);
    if rc != 0 {
        return;
    }

    // 1. First interrupt.
    report(b"irq: RTC alarm raised", rtc::fire(va), 0);
    let first = poll_event(port, 2000);
    report(b"irq: first interrupt delivered to the port (RTC line, our key)",
           first == want, first.map(|e| e.1 as isize).unwrap_or(-1));

    // 2. Not ACKed, device still asserting (and driven again): the line must
    //    stay masked. A level line that was only completed/EOId would be
    //    taken again at once and queue more events.
    let asserted = rtc::asserted(va);
    rtc::reassert(va);
    let extra = poll_event(port, 100);
    report(b"irq: line held masked until ACK (still asserted, no event in 100 ms)",
           asserted && extra.is_none(), asserted as isize);

    // 3. Quieten the device, then ACK: the kernel unmasks the line.
    rtc::clear(va);
    let rc = sys::drv_irq_ack(line as u64);
    report(b"irq: drv_irq_ack(RTC line) -> 0", rc == 0, rc);

    // 4. Second interrupt: arrives only if the ACK unmasked the line.
    report(b"irq: RTC alarm raised again", rtc::fire(va), 0);
    let second = poll_event(port, 2000);
    if second == want {
        print_line_msg(b" delivered twice, masked in between, re-armed by ACK");
    }
    report(b"irq: second interrupt delivered after ACK",
           second == want, second.map(|e| e.1 as isize).unwrap_or(-1));
    rtc::clear(va);
    let _ = sys::drv_irq_ack(line as u64);
    // A driving the device did while the line was masked is delivered on the
    // unmask (riscv64: the re-assert above). Drain it and ACK it.
    let _ = poll_event(port, 50);
    let _ = sys::drv_irq_ack(line as u64);
    rtc::quiet(va);

    // 5. Wave 9: the same line bound to this task (`SYS_IRQ_BIND` type 0),
    //    and an interrupt that arrives BEFORE `SYS_DRV_IRQ_WAIT` blocks. The
    //    kernel keeps it pending on the binding; without that the delivery
    //    is lost, the line stays masked, and the wait below never returns
    //    (the marker printed before it names the hang).
    let rc = sys::irq_bind(line, 0, 0, 0);
    report(b"irq: irq_bind(RTC line, wake this task)", rc == 0, rc);
    if rc != 0 {
        return;
    }
    report(b"irq: RTC alarm raised before the wait", rtc::fire(va), 0);
    sys::sleep(50);
    print_line_msg(b": waiting for an interrupt delivered before the wait (a hang here = it was lost)");
    let rc = sys::drv_irq_wait(line as u64);
    if rc == 0 {
        print_line_msg(b" delivered before SYS_DRV_IRQ_WAIT was kept pending");
    }
    report(b"irq: interrupt before the wait kept pending (drv_irq_wait -> 0)", rc == 0, rc);
    rtc::quiet(va);
    let _ = sys::drv_irq_ack(line as u64);

    // 6. Wave 10 IRQ5: a line the capability range admits and the interrupt
    //    controller does not implement (`ABSENT_IRQ`, granted by the qemu
    //    topology). Both binds must answer -ENODEV — they used to answer 0
    //    with a binding no interrupt could reach — and the kernel prints how
    //    many bindings of the line are left after its undo (the row wants 0).
    const E_NODEV: isize = -19;
    let absent_cap = sys::cap_lookup(sys::CapKind::Irq as u8, ABSENT_IRQ);
    report(b"irq: cap_lookup(Irq, absent line) [granted]", absent_cap > 0, absent_cap);
    if absent_cap <= 0 {
        return;
    }
    expect_errno(b"irq: irq_bind(absent line) -> -ENODEV",
                 sys::irq_bind(ABSENT_IRQ, 0, 0, 0), E_NODEV);
    expect_errno(b"irq: port_bind_typed(port, absent line) -> -ENODEV",
                 sys::port_bind_typed(port, sys::PORT_SRC_IRQ, absent_cap as u32, IRQ_KEY), E_NODEV);
}

/// A line inside the capability range that QEMU `virt`'s interrupt controller
/// does not implement: PLIC source 100 (it has 1..=95; the APLIC 1..=96).
#[cfg(target_arch = "riscv64")]
const ABSENT_IRQ: u32 = 100;
/// SPI 1000: past the GICv3 distributor's `ITLinesNumber`.
#[cfg(target_arch = "aarch64")]
const ABSENT_IRQ: u32 = 1000;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    sys::println(b"[CAPTEST] PANIC");
    sys::exit(2);
}
