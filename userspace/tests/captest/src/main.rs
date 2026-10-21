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
//!   write through a looked-up `sensor` / `motor` endpoint must be admitted.
//!   A read may still return -1 ("sensor not ready"): QEMU has no IMU, and -1
//!   means the capability was accepted and the driver had nothing to give,
//!   which is a pass for this test. A capability error is a failure.
//!
//!   NEGATIVE — an ungranted resource is still refused. A resource the
//!   topology does not grant has no handle to look up; a forged handle is
//!   stale.
//!   Without this half the test would pass just as happily if the checks were
//!   deleted altogether, which is the opposite of what it is meant to prove.

#![no_std]
#![no_main]

use azos_abi::cap::CapPerms;
use azos_inspect_lib::{str_in, Inspector, Source};
use azos_libsys as sys;
use sys::dev::{Bytes, BlockCall, BlockClient, Ep, GpioCall, GpioClient, I2cCall, I2cClient, MotorCall, MotorClient, PwmCall, PwmClient, Regs};

mod abi_cases;

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
            lateout("t0") _, lateout("t1") _, lateout("t2") _, lateout("t3") _,
            lateout("t4") _, lateout("t5") _, lateout("t6") _, lateout("a7") _,
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
            lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _,
            lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
            lateout("x15") _, lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
    }
    ret
}

/// The main kernel's side of the cases shared with the micro kernel's captest
/// (`abi_cases.rs`): each operation is the libsys wrapper of its call.
struct RingThree;

impl abi_cases::Env for RingThree {
    fn close_typed(&mut self, handle: usize) -> isize {
        sys::close_typed(handle as u32)
    }
    fn cap_lookup(&mut self, kind: usize, resource: usize) -> isize {
        sys::cap_lookup(kind as u8, resource as u32)
    }
    fn fast_call(&mut self, endpoint: usize, words: [usize; 4]) -> isize {
        let w = words.map(|v| v as u64);
        match sys::fast_ipc_call_ep_status(endpoint as u32, w, sys::NO_CAP_TO_MOVE) {
            Ok(r) => r[0] as isize,
            Err(e) => e,
        }
    }
    fn fast_reply(&mut self, handle: usize, words: [usize; 4]) -> isize {
        sys::fast_ipc_reply(handle as u64, words.map(|v| v as u64))
    }
    fn uptime(&mut self) -> usize {
        sys::uptime() as usize
    }
    fn report(&mut self, name: &[u8], ok: bool, rc: isize) {
        report(name, ok, rc);
    }
}

fn report(name: &[u8], ok: bool, rc: isize) {
    Line::new()
        .s(if ok { b"[CAPTEST]   ok   " } else { b"[CAPTEST]  FAIL  " })
        .s(name).s(b" rc=").i(rc)
        .flush();
    if !ok {
        unsafe { FAILURES += 1; }
    }
}

/// One output line, built in a buffer and written with ONE `write`.
///
/// Each `sys::print` is atomic at the console, a line of several is not:
/// gate 253d5b8d's `disk: partition cap refused from ring 3` read
/// `[CAPTEST]   ok   [BENCH-RES] mm.kheap_used ...` and then
/// `disk_write(rel 0) [inside partition 1] rc=0` on the next line, the
/// kernel's boot-bench sweep spliced between this program's prefix and its
/// label, and the row missed a check that had passed. The same struct, and
/// the same lesson, as ipctest's `Line`.
struct Line {
    buf: [u8; 256],
    n: usize,
}

impl Line {
    fn new() -> Self {
        Line { buf: [0u8; 256], n: 0 }
    }

    /// Appends `b`, truncated at the buffer's end.
    fn s(&mut self, b: &[u8]) -> &mut Self {
        let room = self.buf.len() - self.n;
        let take = if b.len() < room { b.len() } else { room };
        self.buf[self.n..self.n + take].copy_from_slice(&b[..take]);
        self.n += take;
        self
    }

    /// Signed decimal (no core::fmt in a no_std ring-3 binary). The `i64`
    /// widening keeps `isize::MIN` from overflowing on negation.
    fn i(&mut self, v: isize) -> &mut Self {
        if v < 0 {
            self.s(b"-");
        }
        let mut n = if v < 0 { (v as i64).unsigned_abs() } else { v as u64 };
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        if n == 0 {
            i -= 1;
            tmp[i] = b'0';
        }
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        self.s(&tmp[i..])
    }

    /// Ends the line and writes it, in one `sys::print`.
    fn flush(&mut self) {
        self.s(b"\n");
        sys::print(&self.buf[..self.n]);
        self.n = 0;
    }
}

/// Granted → must NOT be E_PERM. -1 (driver has nothing) still counts.
fn expect_allowed(name: &[u8], rc: isize) {
    report(name, rc != E_PERM, rc);
}

/// Refused with one SPECIFIC errno, not merely refused.
///
/// The typed capability path does not answer `E_PERM`: it distinguishes
/// "you hold no such capability" (`-ENOENT`) from "that handle names nothing"
/// (`-ECAPSTALE`), and collapsing them into "some negative number" would let
/// a handler that failed for an unrelated reason — a bad argument, an
/// unimplemented syscall — pass as a capability refusal. The first draft of
/// these three assertions used `expect_denied` and would have done exactly
/// that, since an E_PERM check would pass none of them.
fn expect_errno(name: &[u8], rc: isize, want: isize) {
    report(name, rc == want, rc);
}

/// From `azos_abi::error::Errno`, as returned by the typed path.
const E_NOENT: isize = -2;
/// `Errno::ECAPPERMS` — the capability lacks the permission (or none is held).
const E_CAPPERMS: isize = -201;
/// `Errno::ECAPSTALE` — the handle names an empty or recycled slot.
const E_CAPSTALE: isize = -202;

/// The outcome of a device-interface call as the number the helpers above
/// judge: 0 when the op was served, `-(outcome code)` when the interface
/// refused it (`DENIED` 1, `BAD_ARGUMENT` 2, `REFUSED` 8, ...), and
/// [`O_NO_SERVER`] when the call did not reach the interface.
fn oc<T>(r: sys::dev::IdlResult<sys::dev::Out<T>>) -> isize {
    match r {
        Ok(o) if o.is_ok() => 0,
        Ok(o) => -(o.code as isize),
        Err(_) => O_NO_SERVER,
    }
}

/// The value of a device-interface call (a level, a count), or the negative
/// outcome as [`oc`] reports it.
fn val<T: Into<i64>>(r: sys::dev::IdlResult<sys::dev::Out<T>>) -> isize {
    match r {
        Ok(o) if o.is_ok() => o.value.into() as isize,
        Ok(o) => -(o.code as isize),
        Err(_) => O_NO_SERVER,
    }
}

/// [`val`] for a boolean answer: 1 for true, 0 for false.
fn flag(r: sys::dev::IdlResult<sys::dev::Out<bool>>) -> isize {
    match r {
        Ok(o) if o.is_ok() => o.value as isize,
        Ok(o) => -(o.code as isize),
        Err(_) => O_NO_SERVER,
    }
}

/// `-outcome::DENIED`: the capability lacks the op class (or containment).
const O_DENIED: isize = -(sys::dev::outcome::DENIED as isize);
/// `-outcome::REFUSED`: the op is not available on this resource (a motor's
/// pin or channel).
const O_REFUSED: isize = -(sys::dev::outcome::REFUSED as isize);
/// The call did not reach the interface (a stale or forged handle).
const O_NO_SERVER: isize = -1000;

/// Granted → admitted: a byte count, 0, or the driver's -1 ("nothing to
/// report"). Every refusal on the typed path is another negative value
/// (`-ENOENT` from the lookup, `-ECAPSTALE`, `-ECAPKIND`, `-ECAPPERMS`), and
/// `expect_allowed`'s `!= E_PERM` would pass all of them.
fn expect_admitted(name: &[u8], rc: isize) {
    report(name, rc >= 0 || rc == -1, rc);
}

/// Look up the `sensor` endpoint for `sensor_type` and read it: the record's
/// length, `-1` when the driver has nothing to report, `-2` for a sensor the
/// topology does not grant (so the check names the missing grant), any other
/// refusal as `-outcome`.
fn read_sensor(sensor_type: u64, buf: &mut [u8]) -> isize {
    let Some(ep) = sys::dev::lookup(sys::dev::key::SENSOR, sensor_type as u32) else {
        return -2;
    };
    match sys::dev::sensor_read(ep, buf) {
        Ok(smp) => smp.len as isize,
        Err(sys::dev::outcome::NOT_READY) => -1,
        Err(c) => -(c as isize),
    }
}

/// Bound on the age of a CACHED sample (odometry, integrated by the kernel's
/// 50 Hz `odom` task) when it is read: fifty of its periods.
const CACHED_MAX_AGE_NS: u64 = 1_000_000_000;

/// Each granted sensor read through its `sensor` endpoint, between two reads
/// of the vDSO clock: the record has the length of the type, and the
/// acquisition stamp is on the same clock as the reader's —
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
        let Some(cap) = sys::dev::lookup(sys::dev::key::SENSOR, ty as u32) else {
            report(b"sensor_read_ts: sensor endpoint lookup", false, -2);
            continue;
        };
        let mut prev = 0u64;
        for round in 0..2 {
            let mut buf = [0u8; 64];
            let t0 = sys::vdso_now_ns();
            let r = sys::dev::sensor_read(cap, &mut buf);
            let t1 = sys::vdso_now_ns();
            let n = match r { Ok(smp) => smp.len as isize, Err(c) => -(c as isize) };
            let ok_len = n == plen as isize;
            let ok_hdr = r.is_ok();
            let acq = r.map(|smp| smp.acq_ns).unwrap_or(0);
            let ok_time = acq != 0 && acq <= t1
                && if during { acq >= t0 } else { t1 - acq < CACHED_MAX_AGE_NS };
            let ok_mono = acq >= prev;
            prev = acq;
            if round == 0 {
                Line::new()
                    .s(b"[CAPTEST] sensorts: ").s(name)
                    .s(b" acq_ns=").i(acq as isize)
                    .s(b" read in [").i(t0 as isize)
                    .s(b", ").i(t1 as isize).s(b"]")
                    .flush();
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
    // A buffer too short for the record: the reply still carries the whole
    // record and its length, and the client copies what fits, so the
    // truncation is visible, never silent.
    let imu = sys::dev::lookup(sys::dev::key::SENSOR, sys::SENSOR_TYPE_IMU as u32);
    let mut short = [0u8; 23];
    report(b"sensor read(IMU, 23-byte buffer) reports the 24-byte record",
           matches!(imu.map(|e| sys::dev::sensor_read(e, &mut short)), Some(Ok(smp)) if smp.len == 24), 0);
    if unsafe { FAILURES } == before {
        sys::println(b"[CAPTEST] sensorts: 5 sensors stamped on the vDSO clock, inside the call (IMU ENCODER RANGE BATTERY) or < 1 s before it (ODOM), monotonic");
    }
}

/// One `[CAPTEST]  FAIL  sensor_read_ts(<name>): <what> rc=<rc>` line.
fn stamped_fail(name: &[u8], what: &[u8], rc: isize) {
    Line::new()
        .s(b"[CAPTEST]  FAIL  sensor_read_ts(").s(name)
        .s(b"): ").s(what).s(b" rc=").i(rc)
        .flush();
    unsafe { FAILURES += 1; }
}

/// A private io_ring for block entries (`OP_BLOCK_READ` / `OP_BLOCK_WRITE`).
struct BlockRing {
    cap: u32,
    ring: sys::ioring::Ring,
}

impl BlockRing {
    fn open() -> Option<BlockRing> {
        let mut out = [0u8; 8];
        let cap = sys::ioring_create_typed(&mut out);
        if cap <= 0 {
            return None;
        }
        match sys::ioring::Ring::open(cap as u32, out) {
            Ok(ring) => Some(BlockRing { cap: cap as u32, ring }),
            Err(_) => {
                sys::ioring_destroy_typed(cap as u32);
                None
            }
        }
    }

    /// One entry: `len` bytes (whole sectors) of the partition the badge
    /// names, at the partition-relative `sector`, through the ring's data
    /// buffer. `0` when every byte moved, else the completion's refusal (a
    /// negative errno) or what the submit answered.
    fn io(&self, write: bool, badge: u32, sector: u32, buf: &mut [u8]) -> isize {
        let len = buf.len();
        if write {
            // SAFETY: the data buffer is `DATA_SIZE` bytes and `len` is at most
            // that (the callers pass one or two sectors).
            unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), self.ring.data(), len) };
        }
        if !self.ring.push_block(write, badge, 0, len as u32, sector, 1) {
            return -1;
        }
        let n = sys::ioring_submit_typed(self.cap);
        if n != 1 {
            return n;
        }
        let Some((_, result, _)) = self.ring.pop() else { return -3 };
        if result as isize != len as isize {
            return result as isize;
        }
        if !write {
            // SAFETY: as above.
            unsafe { core::ptr::copy_nonoverlapping(self.ring.data(), buf.as_mut_ptr(), len) };
        }
        0
    }

    fn close(self) {
        sys::ioring_destroy_typed(self.cap);
    }
}

/// Stop the wheel behind a looked-up `motor` endpoint. A failed lookup is
/// [`O_NO_SERVER`].
fn speed_zero(ep: Option<u32>) -> isize {
    match ep {
        Some(ep) => oc(MotorClient::new(Regs(ep)).speed(0)),
        None => O_NO_SERVER,
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::println(b"[CAPTEST] Starting...");

    // ── The `block` endpoint scoped to ONE partition (owner round 23) ──
    //
    // Only where the topology grants it: the `disk-part-row` kernel feature
    // gives the autorun row `block.part.1` read/write, and only the gate's
    // partitioned image (`$AZOS_OUT/build/disk-parted.img`) has a partition 1 for it to
    // name — a 64-sector raw partition after the FAT32 one. Everywhere else
    // the lookup finds nothing and this block issues no block entry at all (a
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
    // The row also grants `block.part.0` READ-only (the FAT32 volume): this
    // task holds an endpoint per partition, and each entry names its partition
    // by the endpoint's badge (partition `n` is badge `n + 1`), so there is no
    // ambiguity to refuse.
    if let Some(part1) = sys::dev::lookup(sys::dev::key::BLOCK, 2) {
        const PART1_SECTORS: u64 = 64;
        let Some(br) = BlockRing::open() else {
            report(b"block: create the io_ring", false, -1);
            sys::exit(1);
        };
        let mut first = [0xA5u8; 512];
        first[..14].copy_from_slice(b"AZOS-P3-REL000");
        let mut last = [0x5Au8; 512];
        last[..14].copy_from_slice(b"AZOS-P3-REL063");
        expect_errno(b"block write(rel 0) [inside partition 1]", br.io(true, 2, 0, &mut first), 0);
        expect_errno(b"block write(rel 63) [its last sector]",
                     br.io(true, 2, PART1_SECTORS as u32 - 1, &mut last), 0);
        let mut back = [0u8; 512];
        let rc = br.io(false, 2, 0, &mut back);
        report(b"block read(rel 0) returns what was written", rc == 0 && back == first, rc);
        let mut two = [0u8; 1024];
        expect_errno(b"block read(rel 63, 2 sectors) [crosses the end]",
                     br.io(false, 2, PART1_SECTORS as u32 - 1, &mut two), E_CAPPERMS);
        // The one the gate row pins: `[BLOCK] scope: ... refused write sector 64+1`.
        expect_errno(b"block write(rel 64) [one past the end]",
                     br.io(true, 2, PART1_SECTORS as u32, &mut first), E_CAPPERMS);
        sys::println(b"[CAPTEST] partition checks done");

        // ── Wave 10: the second partition, a READ-only endpoint, the length ──
        let part0 = sys::dev::lookup(sys::dev::key::BLOCK, 1);
        report(b"lookup(block.part.0) [granted READ]", part0.is_some(), 0);
        if let Some(part0) = part0 {
            let rc = br.io(false, 1, 0, &mut back);
            report(b"block read(part 0, rel 0) is the FAT32 boot sector",
                   rc == 0 && back[510] == 0x55 && back[511] == 0xAA && &back[82..87] == b"FAT32",
                   rc);
            expect_errno(b"block write(part 0) [READ-only endpoint] -> refused",
                         br.io(true, 1, 0, &mut first), E_CAPPERMS);
            expect_errno(b"block read(part 2) [no such endpoint held] -> refused",
                         br.io(false, 3, 0, &mut back), E_CAPPERMS);
            let sectors = |ep: u32| sys::dev::value(BlockClient::new(Ep(ep)).sectors());
            report(b"sectors(part 1) is its 64 sectors", sectors(part1) == Ok(PART1_SECTORS), 0);
            let n0 = sectors(part0).unwrap_or(0) as isize;
            report(b"sectors(part 0) is the FAT32 partition, not the medium",
                   n0 > 0 && n0 != PART1_SECTORS as isize && n0 < 1 << 20, n0);
        }
        br.close();
        sys::println(b"[CAPTEST] block endpoint checks done");
    }

    // ── POSITIVE: granted sensors are reachable ──────────────────────────
    // Each read goes through the `sensor` endpoint the topology grants for
    // that type (`sensor.0`..`sensor.9`, read-only), looked up first.
    let mut imu = [0u8; 24];
    expect_admitted(b"sensor read(IMU)", read_sensor(sys::SENSOR_TYPE_IMU, &mut imu));
    let mut odom = [0u8; 16];
    expect_admitted(b"sensor read(ODOM)", read_sensor(sys::SENSOR_TYPE_ODOM, &mut odom));
    let mut enc = [0u8; 16];
    expect_admitted(b"sensor read(ENCODER)", read_sensor(sys::SENSOR_TYPE_ENCODER, &mut enc));
    let mut range = [0u8; 4];
    expect_admitted(b"sensor read(RANGE)", read_sensor(sys::SENSOR_TYPE_RANGE, &mut range));
    let mut batt = [0u8; 2];
    expect_admitted(b"sensor read(BATTERY)", read_sensor(sys::SENSOR_TYPE_BATTERY, &mut batt));

    // ── Wave 11 (SENSORTS): the reading's acquisition stamp ──────────────
    stamped_reads();

    // ── POSITIVE: granted motors accept a write ──────────────────────────
    // Speed 0 on purpose: this asserts the capability, and must not move a
    // real robot if the same image is ever booted on hardware.
    let motor0 = sys::dev::lookup(sys::dev::key::MOTOR, 0);
    let motor1 = sys::dev::lookup(sys::dev::key::MOTOR, 1);
    expect_admitted(b"motor speed(L,0)", speed_zero(motor0));
    expect_admitted(b"motor speed(R,0)", speed_zero(motor1));

    // ── NEGATIVE: ungranted resources stay refused ───────────────────────
    //
    // A wheel the topology does not grant has no handle to look up (asserted
    // below). What ring 3 can still send is a handle it made up.
    expect_errno(b"motor speed(0) through handle 0 [forged cap]",
                 oc(MotorClient::new(Regs(0)).speed(0)), O_NO_SERVER);

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
    report(b"lookup(gpio.63) [ungranted pin]",
           sys::dev::lookup(sys::dev::key::GPIO, 63).is_none(), 0);
    report(b"lookup(pwm.7) [ungranted channel]",
           sys::dev::lookup(sys::dev::key::PWM, 7).is_none(), 0);
    report(b"lookup(motor.9) [no such wheel]",
           sys::dev::lookup(sys::dev::key::MOTOR, 9).is_none(), 0);

    // Second: a call through an endpoint holding only the op class `READ`
    // that asks for `WRITE` is refused, and that refusal reaches the flight
    // recorder as `SAFETY_CAP_DENIED_TYPED` (under the endpoint kind: the
    // kernel's `cap-deny-smoke` reads it back off the disk). The IMU's i2c
    // endpoint is granted READ only on purpose (a write could put the sensor
    // that feeds the L0 reflexes to sleep), so this is the strongest refusal
    // the topology offers: a real capability, the wrong class.
    if let Some(imu) = sys::dev::lookup(sys::dev::key::I2C, sys::dev::i2c::badge(0, 0x68)) {
        let mut i2c = I2cClient::new(Ep(imu));
        expect_errno(b"i2c write(IMU PWR_MGMT_1) [read-only endpoint]",
                     oc(i2c.write(Bytes::from_slice(&[0x6B, 0x40]))), O_DENIED);
    } else {
        report(b"lookup(i2c.0.0x68) [granted READ]", false, 0);
    }
    // A handle that names nothing never reaches an interface: the kernel's
    // call refuses it. Handle 0 is `Cap::NULL`, the cheapest possible forgery
    // and the one a caller passing an uninitialised variable sends.
    {
        let forged = GpioClient::new(Regs(0));
        expect_errno(b"gpio read through handle 0 [forged cap]", val(forged.read()), O_NO_SERVER);
    }

    // And the positive control for the primitive itself, on a capability the
    // topology DOES grant this task: without it, every assertion above is
    // satisfied by a `cap_lookup` that always fails.
    // A handle is a non-negative value, so "not refused" is `>= 0` — the
    // same trap the socket-fd assertion hit: fd 0 and cap slot 0 are both
    // valid, and `> 0` would have failed on the very first capability minted.
    report(b"lookup(motor.0) [granted]", motor0.is_some(), 0);

    // ── Cap<File>: a file as a capability, from ring 3 ──────────────────
    //
    // `HELLO.TXT` is on every image the gate builds, so the read-back carries
    // content only the real filesystem can supply.
    {
        const HELLO: &[u8] = b"Hello from AzOS FAT32!\n";
        const E_CAPPERMS: isize = -201;
        const E_INVAL: isize = -22;

        let f = sys::open_root(sys::cstr!(b"/fat/HELLO.TXT"), 0);
        report(b"file_open_typed(HELLO.TXT, O_RDONLY)", f >= 0, f);
        if f >= 0 {
            let c = f as u32;
            let mut buf = [0u8; 64];
            let n = sys::file_read_typed(c, &mut buf);
            report(b"file_read_typed returns the file's own bytes",
                   n == HELLO.len() as isize && &buf[..HELLO.len()] == HELLO, n);
            expect_errno(b"file_write_typed on a READ-only cap",
                         sys::file_write_typed(c, b"x"), E_CAPPERMS);

            expect_errno(b"close_typed(file cap)", sys::close_typed(c), 0);
            expect_errno(b"file_read_typed after close_typed [stale]",
                         sys::file_read_typed(c, &mut buf), E_CAPSTALE);
            expect_errno(b"close_typed twice [stale]", sys::close_typed(c), E_CAPSTALE);
        }
        expect_errno(b"file_open_typed access mode 3",
                     sys::open_root(sys::cstr!(b"/fat/HELLO.TXT"), 3), E_INVAL);
        let mut scratch = [0u8; 4];
        // Handle 0 names no kind at all: `SYS_INVOKE` refuses it as a malformed
        // call (-EINVAL, as `send_typed(0)` in abitest), not as a stale slot.
        expect_errno(b"file_read_typed(0) [forged cap]",
                     sys::file_read_typed(0, &mut scratch), E_INVAL);
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

        let f = sys::open_root(sys::cstr!(b"/fat/HELLO.TXT"), 0);
        if f >= 0 {
            expect_errno(b"fsync_typed(READ-only file cap) -> 0", sys::fsync_typed(f as u32), 0);
            let _ = sys::close_typed(f as u32);
        } else {
            report(b"file_open_typed(HELLO.TXT) for fsync", false, f);
        }
        expect_errno(b"fsync_typed(0) [forged cap]", sys::fsync_typed(0), -22);

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
        let hf = sys::open_root(sys::cstr!(b"/fat/HERMF.TXT"), 0x41);
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
    // Gpio, I2c and Pwm are interfaces the kernel hosts; a task reaches one
    // through the endpoint capability its topology row grants, the badge of
    // which is the resource. The topology names one free resource per family
    // — and, deliberately, two resources that BELONG TO A MOTOR so the
    // refusal can be observed.
    {
        const GPIO: u16 = sys::dev::key::GPIO;
        const PWM: u16 = sys::dev::key::PWM;
        const I2C: u16 = sys::dev::key::I2C;
        // `i2c.0.0x68` — the simulated MPU-6050.
        let imu_badge = sys::dev::i2c::badge(0, 0x68);

        let pwm_free   = sys::dev::lookup(PWM, 4);
        let pwm_motor  = sys::dev::lookup(PWM, 0);
        let gpio_free  = sys::dev::lookup(GPIO, 20);
        let gpio_motor = sys::dev::lookup(GPIO, 0);
        let i2c_imu    = sys::dev::lookup(I2C, imu_badge);
        report(b"lookup(pwm.4) [granted]",       pwm_free.is_some(),   0);
        report(b"lookup(pwm.0) [granted]",       pwm_motor.is_some(),  0);
        report(b"lookup(gpio.20) [granted]",     gpio_free.is_some(),  0);
        report(b"lookup(gpio.0) [granted]",      gpio_motor.is_some(), 0);
        report(b"lookup(i2c.0.0x68) [granted]",  i2c_imu.is_some(),    0);

        // GPIO: a WRITE-then-READ round trip through two different ops, so a
        // handler stubbed to return 0 is caught by the read-back rather than
        // believed. Pin 20 belongs to nothing else on this machine.
        if let Some(ep) = gpio_free {
            let mut g = GpioClient::new(Regs(ep));
            expect_allowed(b"gpio set_dir(20, output)", oc(g.set_dir(sys::dev::gpio::DIR_OUTPUT)));
            expect_allowed(b"gpio write(20, 1)", oc(g.write(1)));
            expect_errno(b"gpio read(20) -> 1", val(g.read()), 1);
            expect_allowed(b"gpio write(20, 0)", oc(g.write(0)));
            expect_errno(b"gpio read(20) -> 0", val(g.read()), 0);
        }

        // I2C: the read-back carries a value only the real device can supply.
        // WHO_AM_I on an MPU-6050 is register 0x75 and reads 0x68 — its own
        // address. A stubbed handler cannot produce it, and unlike an rc of 0
        // it is not a value that appears by accident.
        if let Some(ep) = i2c_imu {
            let mut i2c = I2cClient::new(Ep(ep));
            expect_errno(b"i2c detect(0.0x68) [simulated IMU acks]", val(i2c.detect()), 1);
            let mut who = [0u8; 1];
            let got = match sys::dev::value(i2c.read(0x75, 1)) {
                Ok(b) => b.copy_to(&mut who) as isize,
                Err(c) => -(c as isize),
            };
            expect_errno(b"i2c read WHO_AM_I -> 1 byte", got, 1);
            report(b"WHO_AM_I reads 0x68 (only the real device says this)",
                   who[0] == 0x68, who[0] as isize);
        }

        // PWM on a free channel. Asserted on the outcome alone, and that
        // is a stated limit rather than an oversight: the interface has no
        // read-back, so there is nothing to read — the one observable this
        // family offers is the refusal below.
        if let Some(ep) = pwm_free {
            let mut p = PwmClient::new(Regs(ep));
            expect_allowed(b"pwm set_period(ch4)", oc(p.set_period(20_000_000)));
            expect_allowed(b"pwm enable(ch4)", oc(p.enable()));
            expect_allowed(b"pwm set_duty_pct(ch4, 40)", oc(p.set_duty_pct(40)));
            expect_allowed(b"pwm disable(ch4)", oc(p.disable()));
        }

        // ── THE SECURITY HALF: a capability is not enough ──────────
        //
        // These four hold a VALID, GRANTED capability for a resource the
        // drivetrain owns, and the kernel must refuse every one. PWM channel 0
        // is motor 0's duty; GPIO 0 is one of its H-bridge direction pins.
        // Reaching either below `motor_set` bypasses the e-stop latch and the
        // motor envelope together — the duty route decides how FAST a wheel
        // turns, the direction route decides which WAY, and the second guard
        // did not exist until 2026-09-10.
        //
        // The distinction that makes these worth writing: REFUSED here means
        // "you hold it and you still may not", which is a different claim
        // from the DENIED a capability without the op class gives. Without the
        // grants above, deleting both guards would leave this file passing.
        if let Some(ep) = pwm_motor {
            let mut p = PwmClient::new(Regs(ep));
            expect_errno(b"pwm set_duty_pct(MOTOR ch0) refused", oc(p.set_duty_pct(50)), O_REFUSED);
            expect_errno(b"pwm enable(MOTOR ch0) refused", oc(p.enable()), O_REFUSED);
        }
        if let Some(ep) = gpio_motor {
            let mut g = GpioClient::new(Regs(ep));
            expect_errno(b"gpio write(MOTOR dir pin 0) refused", oc(g.write(1)), O_REFUSED);
            expect_errno(b"gpio set_dir(MOTOR dir pin 0) refused",
                         oc(g.set_dir(sys::dev::gpio::DIR_INPUT)), O_REFUSED);
        }
    }

    // ── THE PID FAMILY of the `Motor` interface: the first ring-3 caller ──
    //
    // The PID ops were reachable and had ZERO ring-3 callers: autorun holds
    // `motor.0` and `motor.1` RW, so they were available and simply never made
    // from a booted machine. Their host tests exercise the server, not the
    // boundary.
    //
    // The pair rule matters here: these ops demand WRITE on BOTH wheels'
    // endpoints because they command the drivetrain in one operation, and
    // autorun holds both, so there is no "one wheel only" state to reach from
    // ring 3 (the host tests state it).
    if let Some(ep) = motor0 {
        let mut m = MotorClient::new(Regs(ep));

        // NEGATIVE: a handle that names nothing never reaches the interface.
        // A handler stubbed to return 0 fails all six of these.
        let mut forged = MotorClient::new(Regs(0));
        expect_errno(b"motor pid_target through handle 0 [forged cap]",
                     oc(forged.pid_target(0, 0)), O_NO_SERVER);
        expect_errno(b"motor pid_tick through handle 0 [forged cap]",
                     oc(forged.pid_tick(0, 0, 0)), O_NO_SERVER);
        expect_errno(b"motor pid_enable through handle 0 [forged cap]",
                     oc(forged.pid_enable(true)), O_NO_SERVER);
        expect_errno(b"motor pid_enabled through handle 0 [forged cap]",
                     flag(forged.pid_enabled()), O_NO_SERVER);
        expect_errno(b"motor pid_gains through handle 0 [forged cap]",
                     oc(forged.pid_gains(1, 0, 0)), O_NO_SERVER);
        expect_errno(b"motor pid_reset through handle 0 [forged cap]",
                     oc(forged.pid_reset()), O_NO_SERVER);

        // POSITIVE, and the enable/enabled pair is the one that discriminates:
        // it writes through one op and reads back through ANOTHER, so a
        // handler stubbed to return success is caught by the read-back rather
        // than believed. `PID_ENABLED` has exactly one writer (this program)
        // and `rt_motor_task` only reads it, so the round trip is not a race.
        //
        // Target stays 0 throughout ON PURPOSE: the PID is enabled from boot,
        // so `rt_motor_task` is ALREADY taking the PID branch and driving the
        // wheels from its output. A non-zero target here would spin the
        // drivetrain of a machine running a capability test.
        // The boot state is NOT assumed. It is `true` today --
        // `motor_pid_init()` enables closed-loop control at startup, so
        // `rt_motor_task` runs the PID branch for the whole boot -- but that is
        // a kernel boot policy, and pinning it from a capability test would
        // make this program fail for a reason that has nothing to do with
        // capabilities. Recorded as a diagnostic, asserted as a round trip
        // from whatever it is, and put back at the end.
        let pid_boot = flag(m.pid_enabled());
        report(b"motor pid_enabled [boot state is a clean bool]",
               pid_boot == 0 || pid_boot == 1, pid_boot);
        Line::new().s(b"[CAPTEST] PID enabled at boot = ").i(pid_boot).flush();

        expect_allowed(b"motor pid_enable(false)", oc(m.pid_enable(false)));
        expect_errno(b"motor pid_enabled -> 0 after disable", flag(m.pid_enabled()), 0);
        expect_allowed(b"motor pid_enable(true)", oc(m.pid_enable(true)));
        expect_errno(b"motor pid_enabled -> 1 after enable", flag(m.pid_enabled()), 1);
        // Back to the boot state, whatever it was.
        expect_allowed(b"motor pid_enable [restore boot state]", oc(m.pid_enable(pid_boot == 1)));

        // The gains echo is a DIAGNOSTIC, not the assertion -- said plainly
        // because it looks like one. `motor_pid_set_gains` prints
        // "[MOTOR-PID] Gains updated: Kp=4242 Ki=137 Kd=9" from inside the
        // call, with values only this caller could have supplied, so a human
        // reading the log can see the arguments reached the driver. What
        // actually discriminates for this family is the enable/enabled round
        // trip above.
        expect_allowed(b"motor pid_gains(4242,137,9)", oc(m.pid_gains(4242, 137, 9)));
        // Put the boot defaults back: the gains are global to the PID and a
        // capability test must not leave the controller misconfigured for
        // whatever runs next in this boot.
        expect_allowed(b"motor pid_gains [restore 1,0,0]", oc(m.pid_gains(1, 0, 0)));

        // Target 0, not a live setpoint. The PID runs from boot, so a
        // non-zero target here would set `rt_motor_task` driving the wheels of
        // a machine running a capability test -- and it would buy no
        // assertion, because the resulting PWM is not observable from ring 3.
        expect_allowed(b"motor pid_target(0,0)", oc(m.pid_target(0, 0)));
        // A target past the loop's `i16` is refused, not truncated.
        expect_errno(b"motor pid_target(70000,0) [past i16]",
                     oc(m.pid_target(70_000, 0)), -(sys::dev::outcome::BAD_ARGUMENT as isize));

        // The tick is asserted on its ABI SHAPE only, and that is a limit
        // worth stating rather than hiding. `motor_pid_tick` returns (0,0)
        // while PID is disabled, so the value here is a constant; and the
        // moment PID is ENABLED, `rt_motor_task` ticks the same controller and
        // the same `TICK_STATE` on its own cadence, so a PWM read back from
        // ring 3 would be a race in both directions. What can be pinned
        // soundly is that the call reaches the interface and answers.
        //
        // The same reason keeps the OVERFLOW GUARD out of here.
        // `motor_pid_tick` saturates `elapsed * 1000` and the encoder deltas
        // deliberately -- its own comment calls that "a security bound, not a
        // robustness nicety", because `now` and `ticks` come straight from
        // ring 3 and this kernel is `panic = "abort"`. Exercising it from here
        // would mean writing hostile values into the LIVE controller state
        // `rt_motor_task` shares. It is pinned on the host instead --
        // `tests/host/drivers-tests`, `mod motor_pid_tick_bounds`.
        expect_allowed(b"motor pid_tick answers",
                       oc(m.pid_tick(0, 0, sys::vdso_uptime_ticks())));
        // Leave the controller as it was found: state cleared and target 0.
        expect_allowed(b"motor pid_reset", oc(m.pid_reset()));
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
    Line::new()
        .s(b"[CAPTEST] RANGE front_mm=").i(u16::from_le_bytes([range[0], range[1]]) as isize)
        .s(b" right_mm=").i(u16::from_le_bytes([range[2], range[3]]) as isize)
        .s(b"  (0 = no sensor OR touching; the ABI cannot say which)")
        .flush();
    Line::new()
        .s(b"[CAPTEST] BATTERY mv=").i(u16::from_le_bytes([batt[0], batt[1]]) as isize)
        .flush();

    // ── RETIRED — a syscall number that must no longer answer ───────────
    //
    // 116 was `SYS_CAP_GRANT`: it let a ring-3 task hand one of its
    // capabilities to another task. The capability model has them granted at
    // boot and not allocated dynamically -- that is what makes the set of
    // rights a robot holds a static, auditable fact -- and the gate its own design
    // requires for dynamic delegation was never built. So the call
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
    report(b"SYS_CAP_GRANT is refused", rc < 0, rc);

    // ── The kernel's own mappings must not be reachable from ring 3 ─────
    //
    // Every user page table carries the kernel's mappings, merged in at exec
    // and fork. The merge copies the kernel's PTE -- which is a POINTER to the
    // kernel's own next-level table -- so a walk down a user page table to any
    // address in the shared region lands on the kernel's table, not on a copy
    // of it. `munmap` walks and clears.
    //
    // `SYS_MO_UNMAP` has no capability check, and every image profile that lists
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

    // ── MMIO by device handle ────────────────────────────────
    //
    // `DOMAIN_MMIO_MAP` takes the handle of a device of the hardware bus,
    // never an address, and the capability decides whether it may be
    // written — ISA-neutral by construction (`crates/core/topology`'s
    // `mmio.<selector>` names a device by what it is, see `cap_seed.rs`). The
    // topology grants this program READ on a device nothing drives (riscv64
    // the `sifive,test1` finisher, aarch64 the PL061 GPIO) and READ|WRITE on
    // the board's RTC (the IRQ section below needs it writable). Each
    // device's handle is its directory in the introspection tree's
    // `devices/`, whose `identity` says what the device is.
    //
    // Last on purpose: the refusals are capability denials, and denial
    // records are bounded per task.
    {
        const ACCESS_READ: u64 = CapPerms::READ.bits() as u64;
        const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;
        const E_INVAL: isize = -22;
        // A refusal written at dispatch level, `dispatch.rs`'s `E_PERM`, not
        // the handlers' -99 this file calls `E_PERM`.
        const E_PERM_DISPATCH: isize = -1;

        let ro = device_handle(rtc::RO_DEVICE);
        let rw = device_handle(rtc::DEVICE);
        report(b"devices/ lists the granted read-only device", ro.is_some(), ro.unwrap_or(0) as isize);
        report(b"devices/ lists the RTC", rw.is_some(), rw.unwrap_or(0) as isize);
        if let (Some(ro), Some(rw)) = (ro, rw) {
            let va = sys::mmio_map(ro, ACCESS_READ);
            report(b"mmio_map(device, READ) [granted, read-only]", va > 0, va);
            expect_errno(b"mmio_map(device, READ|WRITE) [capability carries READ only]",
                         sys::mmio_map(ro, ACCESS_RW), E_PERM_DISPATCH);
            let va = sys::mmio_map(rw, ACCESS_READ);
            report(b"mmio_map(RTC, READ) [granted READ|WRITE]", va > 0, va);
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
            // A device on the bus this program holds no capability for.
            if let Some(other) = device_handle_not(&[rtc::DEVICE, rtc::RO_DEVICE]) {
                expect_errno(b"mmio_map(ungranted device, READ)",
                             sys::mmio_map(other, ACCESS_READ), E_PERM_DISPATCH);
            }
            // 4 GiB above a granted handle. The handle is range-checked
            // whole, so it cannot alias a smaller one.
            expect_errno(b"mmio_map(handle + 2^32, READ) [no alias]",
                         sys::mmio_map(rw + (1 << 32), ACCESS_READ), E_INVAL);
        }
    }

    // ── ABI-level cases shared with the micro kernel's captest ──
    abi_cases::run(&mut RingThree);

    let failed = unsafe { FAILURES };
    if failed == 0 {
        sys::println(b"[CAPTEST] ALL PASSED");
        sys::exit(0);
    } else {
        Line::new().s(b"[CAPTEST] FAILED: ").i(failed as isize).s(b" check(s)").flush();
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
    /// What `devices/<handle>/identity` calls it, and the read-only device the topology
    /// grants beside it (a PL061 GPIO nothing drives).
    pub const DEVICE: &[u8] = b"dt:arm,pl031";
    pub const RO_DEVICE: &[u8] = b"dt:arm,pl061";

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
    /// What `devices/<handle>/identity` calls it, and the read-only device the topology
    /// grants beside it (the `sifive,test1` finisher, which nothing drives).
    pub const DEVICE: &[u8] = b"dt:google,goldfish-rtc";
    pub const RO_DEVICE: &[u8] = b"dt:sifive,test1";

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

/// The first device of the introspection tree's `devices/` (the public region
/// this program's row grants) whose identity and state satisfy `want`: its
/// handle, the directory's name.
fn find_device(want: &dyn Fn(&[u8], &[u8]) -> bool) -> Option<u64> {
    let m = sys::inspect_map(azos_abi::cap::SHM_INSPECT_PUBLIC).ok()?;
    // SAFETY: the mapping lives as long as the task, read-only, and the kernel
    // writes it only with aligned 64-bit stores.
    let mut tree = unsafe { Inspector::from_mapped(m, None) }.ok()?;
    tree.with(Source::Public, |r| {
        let mut found = None;
        let Some(dir) = r.lookup("devices")? else { return Ok(None) };
        r.children(dir, &mut |info, _| {
            if found.is_some() {
                return;
            }
            let (Ok(Some(id)), Ok(Some(st))) = (str_in(r, info.id, "identity"), str_in(r, info.id, "state")) else { return };
            if want(id.as_bytes(), st.as_bytes()) {
                found = info.name.as_str().parse().ok();
            }
        })?;
        Ok(found)
    })
    .ok()
    .flatten()
}

/// The handle of the first device whose identity is `identity`
/// (`dt:google,goldfish-rtc`).
fn device_handle(identity: &[u8]) -> Option<u64> {
    find_device(&|id, _| id == identity)
}

/// A device nothing owns (unmatched) that is none of `except`.
fn device_handle_not(except: &[&[u8]]) -> Option<u64> {
    find_device(&|id, st| st == b"unmatched" && !except.contains(&id))
}

fn print_line_msg(msg: &[u8]) {
    Line::new().s(b"[CAPTEST] irq: line ").i(rtc::LINE as isize).s(msg).flush();
}

fn irq_section() {
    const ACCESS_RW: u64 = CapPerms::RW.bits() as u64;
    /// `PortEvent::source_type` of an IRQ.
    const SRC_IRQ: u8 = sys::PORT_EVENT_IRQ;
    let line = rtc::LINE;
    let want = Some((SRC_IRQ, line, IRQ_KEY));

    let irq_cap = sys::cap_lookup(sys::ty::IRQ.raw(), line);
    report(b"irq: cap_lookup(Irq, RTC line) [granted]", irq_cap > 0, irq_cap);
    let va = match device_handle(rtc::DEVICE) {
        Some(h) => sys::mmio_map(h, ACCESS_RW),
        None => -1,
    };
    report(b"irq: mmio_map(RTC, READ|WRITE) [writable]", va > 0, va);
    let port = sys::port_create_typed();
    report(b"irq: port_create_typed", port > 0, port);
    if irq_cap <= 0 || va <= 0 || port <= 0 {
        return;
    }
    let (va, port) = (va as usize, port as u32);
    Line::new().s(b"[CAPTEST] irq: device ").s(rtc::NAME).s(b", line ").i(line as isize).flush();
    rtc::quiet(va);

    // Bound by an op of the line's own capability; the value is the CPU the
    // line was routed to.
    let rc = sys::irq_bind(irq_cap as u32, port, IRQ_KEY, sys::DEVICE_IRQ_CPU_ANY);
    report(b"irq: irq_bind(RTC line, port) -> CPU", rc >= 0, rc);
    if rc < 0 {
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
    let rc = sys::irq_ack(irq_cap as u32);
    report(b"irq: irq_ack(RTC line) -> 0", rc == 0, rc);

    // 4. Second interrupt: arrives only if the ACK unmasked the line.
    report(b"irq: RTC alarm raised again", rtc::fire(va), 0);
    let second = poll_event(port, 2000);
    if second == want {
        print_line_msg(b" delivered twice, masked in between, re-armed by ACK");
    }
    report(b"irq: second interrupt delivered after ACK",
           second == want, second.map(|e| e.1 as isize).unwrap_or(-1));
    rtc::clear(va);
    let _ = sys::irq_ack(irq_cap as u32);
    // A driving the device did while the line was masked is delivered on the
    // unmask (riscv64: the re-assert above). Drain it and ACK it.
    let _ = poll_event(port, 50);
    let _ = sys::irq_ack(irq_cap as u32);
    rtc::quiet(va);

    // 5. An interrupt that arrives BEFORE anyone polls is queued on the port,
    //    not lost: the event waits there for the handler (a binding to a
    //    task, with its pending bit, is gone with the wake-task target).
    report(b"irq: RTC alarm raised before the poll", rtc::fire(va), 0);
    sys::sleep(50);
    let kept = poll_event(port, 0);
    if kept == want {
        print_line_msg(b" delivered before the poll was kept on the port");
    }
    report(b"irq: interrupt before the poll kept on the port", kept == want, kept.map(|e| e.1 as isize).unwrap_or(-1));
    rtc::quiet(va);
    let _ = sys::irq_ack(irq_cap as u32);

    // 6. Wave 10 IRQ5: a line the capability range admits and the interrupt
    //    controller does not implement (`ABSENT_IRQ`, granted by the qemu
    //    topology). The bind must answer -ENODEV — it used to answer 0 with a
    //    binding no interrupt could reach — and the kernel prints how many
    //    bindings of the line are left after its undo (the row wants 0).
    const E_NODEV: isize = -19;
    let absent_cap = sys::cap_lookup(sys::ty::IRQ.raw(), ABSENT_IRQ);
    report(b"irq: cap_lookup(Irq, absent line) [granted]", absent_cap > 0, absent_cap);
    if absent_cap <= 0 {
        return;
    }
    expect_errno(b"irq: irq_bind(absent line) -> -ENODEV",
                 sys::irq_bind(absent_cap as u32, port, IRQ_KEY, sys::DEVICE_IRQ_CPU_ANY), E_NODEV);
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
