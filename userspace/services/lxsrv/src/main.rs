// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `LXSRV.ELF`: the Linux driver server skeleton (RFC-0053 stages L0/L0b).
//!
//! In the finished layer one such process runs per driver class, hosting
//! unmodified Linux modules over the `lx/` base. At this stage it links **no
//! Linux object and no `lx/` code** (the first Linux object is stage L1,
//! after the owner's sign-off), so this image stays
//! "Apache-2.0 OR GPL-2.0-only". What it does run is the whole module path:
//!
//! 1. read `/fat/LXTEST.KO` (a relocatable object compiled from this
//!    project's own C, `userspace/tests/lxmod/lxtest.c`);
//! 2. check its `.modinfo` (GPL-compatible licence tag, exact `vermagic`);
//! 3. `SYS_MODULE_VERIFY`: the kernel hashes the file bytes against the
//!    digest table built into the kernel image and grants a one-shot token;
//! 4. lay the module out in two anonymous regions (text, data), resolve its
//!    imports against this server's export table and relocate it
//!    (`crates/core/lx-loader`);
//! 5. `SYS_MODULE_MAP_X`: the kernel flips the text region read-write to
//!    read-execute (never both);
//! 6. call the module's `lxtest_init` and compare its result with the value
//!    computed here independently, then idle.
//!
//! Around the real path it probes the token rules the kernel must enforce: a
//! forged token, a range larger than the verified module, and a token used
//! twice are each refused. Every outcome prints one `[LXSRV]` line the gate
//! rows key on.
//!
//! Stage L1 (RFC-0053) adds the first Linux modules, built by Linux's own
//! Kbuild from the pinned tree (`make lx-kbuild`, in a container): when the
//! volume carries them, the server loads `LXBASE.KO` (the GPL glue in
//! `lx/glue`, resolved against this server's host ABI) and then the
//! unmodified upstream `XZ_DEC.KO` (resolved against `LXBASE.KO`'s
//! `__ksymtab`, as the Linux loader resolves against exports), each through
//! the same verify/map-X path, and makes `xz_dec` decompress `XZTEST.XZ`.
//! This image still links no Linux object: the GPL code exists only inside
//! those `.ko` files, mapped at run time (`tools/lx_license_lint.py`).
//!
//! Its topology row (`lx-server` kernels only) grants no capability: a Linux
//! server never holds an actuator, and the skeleton needs nothing else.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use azos_libsys as sys;
use azos_lx_loader::{admit, Isa, Module};

/// `vermagic` this server accepts (the test module's `.modinfo`). A Linux
/// module's is the kernel release string; L1 sets it from the pinned tag.
const VERMAGIC: &[u8] = b"azos-lx0";
const MODULE_PATH: &[u8] = b"/fat/LXTEST.KO\0";
const MODULE_NAME: &[u8] = b"LXTEST.KO";
/// The module file buffer. 64 KiB is the topology row's budget for it; the
/// test module is about 3 KiB.
const KO_MAX: usize = 64 * 1024;
const PAGE: u64 = 4096;

struct Buf(UnsafeCell<[u8; KO_MAX]>);
// SAFETY: single-threaded process; the buffer is only touched from `run`.
unsafe impl Sync for Buf {}
static KO: Buf = Buf(UnsafeCell::new([0; KO_MAX]));

// ── the server's exports (what the module imports) ──────────────────────────

fn mix(acc: u64, v: u64) -> u64 {
    acc.rotate_left(5) ^ v.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Exported to the module: print a NUL-terminated string from its .rodata.
#[no_mangle]
pub extern "C" fn lx_test_log(msg: *const u8) {
    let mut line = [0u8; 96];
    let pre = b"[LXSRV] module says: ";
    line[..pre.len()].copy_from_slice(pre);
    let mut n = pre.len();
    // SAFETY: the module passes pointers into its own relocated .rodata,
    // NUL-terminated; the read is bounded by the line buffer.
    unsafe {
        let mut p = msg;
        while n < line.len() && *p != 0 {
            line[n] = *p;
            n += 1;
            p = p.add(1);
        }
    }
    sys::println(&line[..n]);
}

/// Exported to the module: the mixing step both sides compute.
#[no_mangle]
pub extern "C" fn lx_test_mix(acc: u64, v: u64) -> u64 {
    mix(acc, v)
}

/// The export table the loader resolves imports against. Sorted by name;
/// L1 replaces it with the generated `EXPORT_SYMBOL` table of the base.
fn export(name: &[u8]) -> Option<u64> {
    match name {
        b"lx_test_log" => Some(lx_test_log as extern "C" fn(*const u8) as usize as u64),
        b"lx_test_mix" => Some(lx_test_mix as extern "C" fn(u64, u64) -> u64 as usize as u64),
        _ => None,
    }
}

/// `lxtest_init`'s result, recomputed from `lxtest.c`'s definition. A
/// relocation that lands on the wrong address changes the module's answer.
fn expected_init() -> u64 {
    fn step(x: u64) -> u64 {
        let mut acc = x;
        for _ in 0..5 {
            acc = if acc & 1 != 0 { acc.wrapping_mul(3).wrapping_add(1) } else { acc >> 1 };
        }
        acc
    }
    let mut counter = 7u64;
    let mut acc = mix(0x4c58, counter);
    counter += 1;
    for i in 0..4u64 {
        acc = mix(acc, step(acc.wrapping_add(i)));
    }
    acc = mix(acc, b'l' as u64); // strings[1][0]
    mix(acc, counter)
}

// ── output ──────────────────────────────────────────────────────────────────

fn line(parts: &[&[u8]]) {
    let mut b = [0u8; 256];
    let mut n = 0;
    let mut cut = false;
    for p in parts {
        let take = p.len().min(b.len() - n);
        cut |= take < p.len();
        b[n..n + take].copy_from_slice(&p[..take]);
        n += take;
    }
    // A cut line says so: a silently truncated number reads as a wrong one
    // (wave 13: "counter hz 1000000000" printed as "10000000").
    if cut {
        b[n - 3..n].copy_from_slice(b"...");
    }
    sys::println(&b[..n]);
}

fn hex(v: u64, out: &mut [u8; 18]) -> &[u8] {
    out[0] = b'0';
    out[1] = b'x';
    for i in 0..16 {
        let d = ((v >> (60 - 4 * i)) & 0xf) as u8;
        out[2 + i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
    }
    &out[..]
}

fn dec(v: i64, out: &mut [u8; 21]) -> &[u8] {
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        out[i] = b'-';
    }
    &out[i..]
}

fn idle() -> ! {
    loop {
        sys::sleep(1000);
    }
}

fn mmap_pages(bytes: u64) -> Option<u64> {
    let len = bytes.div_ceil(PAGE).max(1) * PAGE;
    let r = sys::mmap(0, len, 3, 0, sys::MAP_ANON_FD, 0);
    if r <= 0 {
        None
    } else {
        Some(r as u64)
    }
}

// ── the module path ─────────────────────────────────────────────────────────

fn read_module(buf: &mut [u8]) -> Option<usize> {
    let h = sys::file_open_typed(MODULE_PATH, 0);
    if h < 0 {
        return None;
    }
    let mut n = 0;
    loop {
        if n == buf.len() {
            break;
        }
        let r = sys::file_read_typed(h as u32, &mut buf[n..]);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    sys::close_typed(h as u32);
    Some(n)
}

// ── RFC-0053 L1: Linux modules built by Kbuild ──────────────────────────────

/// The Linux release the modules must be built from: `lx/LINUX_PIN`'s tag,
/// passed by the Makefile. The rest of `vermagic` is fixed by
/// `tools/lx_kbuild/common.config` (`SMP`, the default preemption model) and
/// the ISA, so a module built from another tree or config is refused.
const LX_RELEASE: &[u8] = match option_env!("LX_LINUX_RELEASE") {
    Some(v) => v.as_bytes(),
    None => b"unset",
};
#[cfg(target_arch = "riscv64")]
const LX_ARCH: &[u8] = b"riscv";
#[cfg(target_arch = "aarch64")]
const LX_ARCH: &[u8] = b"aarch64";

/// The host allocator behind `lxh_alloc`: a bump arena (memory is never
/// reused, so it is always zero) with a table of live blocks, so `lxh_free`
/// can tell a real free from a double or foreign one.
const ARENA: usize = 96 * 1024;
const LIVE: usize = 32;
struct Heap {
    base: u64,
    used: usize,
    allocs: u32,
    frees: u32,
    bad_frees: u32,
    live: [u64; LIVE],
}
struct HeapCell(UnsafeCell<Heap>);
// SAFETY: single-threaded process; module code runs on this thread only.
unsafe impl Sync for HeapCell {}
static HEAP: HeapCell = HeapCell(UnsafeCell::new(Heap { base: 0, used: 0, allocs: 0, frees: 0, bad_frees: 0, live: [0; LIVE] }));

/// Host ABI: `size` bytes aligned to `align` (a power of two), zeroed, or NULL.
#[no_mangle]
pub extern "C" fn lxh_alloc(size: usize, align: usize) -> *mut u8 {
    // SAFETY: see `HeapCell`.
    let h = unsafe { &mut *HEAP.0.get() };
    if h.base == 0 {
        match mmap_pages(ARENA as u64) {
            Some(b) => h.base = b,
            None => return core::ptr::null_mut(),
        }
    }
    if align == 0 || !align.is_power_of_two() || align > PAGE as usize {
        return core::ptr::null_mut();
    }
    let at = (h.base as usize + h.used).next_multiple_of(align);
    let Some(end) = at.checked_add(size) else { return core::ptr::null_mut() };
    let Some(slot) = h.live.iter().position(|&p| p == 0) else { return core::ptr::null_mut() };
    if end > h.base as usize + ARENA {
        return core::ptr::null_mut();
    }
    h.used = end - h.base as usize;
    h.live[slot] = at as u64;
    h.allocs += 1;
    at as *mut u8
}

/// Host ABI: release a block `lxh_alloc` returned.
#[no_mangle]
pub extern "C" fn lxh_free(p: *const u8) {
    // SAFETY: see `HeapCell`.
    let h = unsafe { &mut *HEAP.0.get() };
    match h.live.iter().position(|&q| q != 0 && q == p as u64) {
        Some(i) => {
            h.live[i] = 0;
            h.frees += 1;
        }
        None => h.bad_frees += 1,
    }
}

/// Host ABI: the kernel's vDSO hwcap word (`azos_abi::vdso::HWCAP_*`).
#[no_mangle]
pub extern "C" fn lxh_hwcap() -> u64 {
    sys::vdso_hwcap()
}

extern "C" {
    fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8;
    fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8;
    fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8;
    fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32;
}

/// The host ABI (`lx/HOST_ABI`): all a module may import from this
/// server. Linux symbols come from `LXBASE.KO`'s exports, never from here.
fn host_abi(name: &[u8]) -> Option<u64> {
    Some(match name {
        b"lxh_alloc" => lxh_alloc as extern "C" fn(usize, usize) -> *mut u8 as usize as u64,
        b"lxh_free" => lxh_free as extern "C" fn(*const u8) as usize as u64,
        b"lxh_hwcap" => lxh_hwcap as extern "C" fn() -> u64 as usize as u64,
        b"memcmp" => memcmp as unsafe extern "C" fn(*const u8, *const u8, usize) -> i32 as usize as u64,
        b"memcpy" => memcpy as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 as usize as u64,
        b"memmove" => memmove as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 as usize as u64,
        b"memset" => memset as unsafe extern "C" fn(*mut u8, i32, usize) -> *mut u8 as usize as u64,
        _ => return None,
    })
}

/// A file from `/fat`, copied into its own mapping (never unmapped, hence
/// `'static`), so a loaded module can keep borrowing its object bytes.
fn read_static(path: &[u8]) -> Option<&'static [u8]> {
    // SAFETY: `KO` is only touched from this thread, and the LXTEST path
    // that used it before is finished.
    let ko: &mut [u8; KO_MAX] = unsafe { &mut *KO.0.get() };
    let len = read_file(path, ko)?;
    let at = mmap_pages(len as u64)?;
    // SAFETY: freshly mapped, `len` bytes, read-write, never unmapped.
    let dst = unsafe { core::slice::from_raw_parts_mut(at as *mut u8, len) };
    dst.copy_from_slice(&ko[..len]);
    Some(dst)
}

fn read_file(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    let h = sys::file_open_typed(path, 0);
    if h < 0 {
        return None;
    }
    let mut n = 0;
    while n < buf.len() {
        let r = sys::file_read_typed(h as u32, &mut buf[n..]);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    sys::close_typed(h as u32);
    Some(n)
}

/// The counter both sides of the Linux comparison read (riscv `time`, 10 MHz
/// on QEMU virt; aarch64 `cntvct_el0`), the one `userspace/bench/latbench`
/// uses. Under `-icount shift=0` one virtual ns is one instruction.
fn counter() -> u64 {
    let t: u64;
    #[cfg(target_arch = "riscv64")]
    // SAFETY: reads the time CSR, which AzOS exposes to U-mode.
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: reads the virtual counter, readable at EL0 on AzOS.
    unsafe { core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack)) };
    t
}

/// Calibration: a loop of exactly 2 x 4,000,000 instructions (decrement and
/// branch). Under -icount its ticks show what the machine adds around a
/// running task (timer interrupts, the scheduler, other tasks).
fn calibrate() -> u64 {
    let t0 = counter();
    #[cfg(target_arch = "riscv64")]
    // SAFETY: a register-only loop.
    unsafe { core::arch::asm!("li {n}, 4000000", "2:", "addi {n}, {n}, -1", "bnez {n}, 2b", n = out(reg) _, options(nomem, nostack)) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a register-only loop.
    unsafe { core::arch::asm!("movz {n}, #0x3d, lsl #16", "movk {n}, #0x0900", "2:", "subs {n}, {n}, #1", "b.ne 2b", n = out(reg) _, options(nomem, nostack)) };
    counter() - t0
}

fn counter_hz() -> u64 {
    // riscv64: the `time` CSR's frequency is the device tree's
    // timebase-frequency, which the kernel publishes in the vDSO.
    #[cfg(target_arch = "riscv64")]
    return sys::vdso_timebase_hz();
    #[cfg(target_arch = "aarch64")]
    {
        let f: u64;
        // SAFETY: CNTFRQ_EL0 is readable wherever CNTVCT_EL0 is.
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
        f
    }
}

/// A Linux module loaded and mapped: the object (for its tables) and its
/// data region (where its relocated `__ksymtab` lives).
struct LxModule {
    loaded: azos_lx_loader::Loaded<'static>,
    data: &'static [u8],
}

impl LxModule {
    fn export(&self, name: &[u8]) -> Option<u64> {
        self.loaded.export(self.data, name)
    }
}

/// Read, admit, verify, place, resolve, relocate and map one module. Prints
/// one `[LX] module` line on success, one `FAIL`/`REFUSED` line otherwise.
fn lx_load(path: &[u8], name: &[u8], resolve: &mut dyn FnMut(&[u8]) -> Option<u64>) -> Option<LxModule> {
    let mut d = [0u8; 21];
    let Some(file) = read_static(path) else {
        line(&[b"[LX] module ", name, b" FAIL: not readable"]);
        return None;
    };
    let mut vm = [0u8; 64];
    let mut n = 0;
    for p in [LX_RELEASE, b" SMP preempt ", LX_ARCH] {
        vm[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let vermagic = &vm[..n];
    // Timed from here (the file is in memory, as for Linux `init_module`).
    let t0 = counter();
    let Ok(m) = Module::parse(file, Isa::native()) else {
        line(&[b"[LX] module ", name, b" FAIL: not a relocatable object for this ISA"]);
        return None;
    };
    if admit(&m, vermagic).is_err() {
        line(&[b"[LX] module ", name, b" REFUSED: licence or vermagic (want '", vermagic, b"', module has '",
               m.modinfo(b"vermagic").unwrap_or(b"?"), b"')"]);
        return None;
    }
    let t_admit = counter();
    let token = sys::module_verify(file, name);
    if token <= 0 {
        line(&[b"[LX] module ", name, b" verify REFUSED by the kernel: rc ", dec(token as i64, &mut d)]);
        return None;
    }
    let t_verify = counter();
    let layout = m.layout().ok()?;
    let (Some(tb), Some(db)) = (mmap_pages(layout.text_size), mmap_pages(layout.data_size)) else {
        line(&[b"[LX] module ", name, b" FAIL: no memory for the regions"]);
        return None;
    };
    let tl = layout.text_size.div_ceil(PAGE).max(1) * PAGE;
    let dl = layout.data_size.div_ceil(PAGE).max(1) * PAGE;
    // SAFETY: both regions were just mapped read-write for this process,
    // with these lengths, and are never unmapped.
    let text = unsafe { core::slice::from_raw_parts_mut(tb as *mut u8, tl as usize) };
    let data = unsafe { core::slice::from_raw_parts_mut(db as *mut u8, dl as usize) };
    // First touch of the fresh mappings, timed apart: demand paging is the
    // kernel's cost, not the loader's.
    let t_map0 = counter();
    for pg in text.chunks_mut(PAGE as usize).chain(data.chunks_mut(PAGE as usize)) {
        // SAFETY: a byte inside a mapping this function owns.
        unsafe { core::ptr::write_volatile(pg.as_mut_ptr(), 0) };
    }
    let t_touch = counter();
    let mut missing: &[u8] = b"";
    let loaded = match m.load(text, tb, data, db, &mut |s: &[u8]| {
        let r = resolve(s);
        if r.is_none() && missing.is_empty() {
            // SAFETY: `s` borrows the module file, which is 'static.
            missing = unsafe { core::slice::from_raw_parts(s.as_ptr(), s.len()) };
        }
        r
    }) {
        Ok(l) => l,
        Err(_) => {
            line(&[b"[LX] module ", name, b" FAIL: relocation refused; first unresolved import: '", missing, b"'"]);
            return None;
        }
    };
    let t_reloc = counter();
    let r = sys::module_map_x(token as u64, tb, tl);
    if r != 0 {
        line(&[b"[LX] module ", name, b" FAIL: map_x refused, rc ", dec(r as i64, &mut d)]);
        return None;
    }
    // The module's init (`module_init`, aliased `init_module` by Linux's
    // headers), as Linux's loader runs it: a non-zero return refuses the
    // module.
    if let Some(init) = loaded.symbol(b"init_module") {
        // SAFETY: the relocated, kernel-verified, read-execute
        // `int init_module(void)` of this module.
        let f: extern "C" fn() -> i32 = unsafe { core::mem::transmute(init as usize) };
        let rc = f();
        if rc != 0 {
            line(&[b"[LX] module ", name, b" FAIL: init returned ", dec(rc as i64, &mut d)]);
            return None;
        }
    }
    let t_map = counter();
    let mut dd = [[0u8; 21]; 7];
    let [d0, d1, d2, d3, d4, d5, d6] = &mut dd;
    line(&[b"[LX] timing ", name, b": parse+admit ", dec((t_admit - t0) as i64, d0), b", verify ",
           dec((t_verify - t_admit) as i64, d1), b", mmap ", dec((t_map0 - t_verify) as i64, d5),
           b", first touch ", dec((t_touch - t_map0) as i64, d6), b", place+relocate ", dec((t_reloc - t_touch) as i64, d2),
           b", map_x+init ", dec((t_map - t_reloc) as i64, d3), b", total ", dec((t_map - t0) as i64, d4), b" ticks"]);
    let data: &'static [u8] = data;
    let imports = m.for_each_import(|_| {}).unwrap_or(0);
    let exports = loaded.for_each_export(data, |_, _| {}).unwrap_or(0);
    line(&[b"[LX] module ", name, b" license=", m.modinfo(b"license").unwrap_or(b"?"), b" vermagic='", vermagic,
           b"' imports ", dec(imports as i64, &mut d), b" exports ", dec(exports as i64, &mut [0u8; 21]),
           b": kernel-verified, mapped RX"]);
    Some(LxModule { loaded, data })
}

/// The plaintext of `XZTEST.XZ`, regenerated here independently of the
/// build (`tools/lx_kbuild/xz_fixture.py` is the other copy): words picked
/// by xorshift64, each followed by a newline or a space.
const XZ_PATTERN_SIZE: usize = 49152;
const XZ_WORDS: [&[u8]; 16] = [b"azos", b"linux", b"module", b"driver", b"server", b"ring", b"three", b"xz",
                                b"decode", b"stream", b"block", b"page", b"token", b"verify", b"map", b"exec"];

fn xz_pattern_eq(out: &[u8]) -> bool {
    let mut x: u64 = 0x4C58_585A_5445_5354;
    let mut i = 0;
    while i < XZ_PATTERN_SIZE {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let sep = if (x >> 56) & 7 == 0 { b'\n' } else { b' ' };
        for &b in XZ_WORDS[(x >> 60) as usize].iter().chain(core::iter::once(&sep)) {
            if i == XZ_PATTERN_SIZE {
                break;
            }
            if out.get(i) != Some(&b) {
                return false;
            }
            i += 1;
        }
    }
    out.len() == XZ_PATTERN_SIZE
}

/// `struct xz_buf` (`include/linux/xz.h`, 0BSD).
#[repr(C)]
struct XzBuf {
    input: *const u8,
    in_pos: usize,
    in_size: usize,
    out: *mut u8,
    out_pos: usize,
    out_size: usize,
}
const XZ_SINGLE: u32 = 0;
const XZ_STREAM_END: u32 = 1;

fn run_linux() {
    let Some(_) = read_file(b"/fat/LXBASE.KO\0", &mut [0u8; 1]) else {
        line(&[b"[LX] no Kbuild modules on the volume (make lx-kbuild): Linux path skipped"]);
        return;
    };
    let Some(base) = lx_load(b"/fat/LXBASE.KO\0", b"LXBASE.KO", &mut host_abi) else { return };
    {
        let mut h = [0u8; 18];
        // SAFETY: `lxbase_crc32_impl` is an exported `int` in the base's
        // data region, written only by its init, which has returned.
        let imp = base.export(b"lxbase_crc32_impl").map(|a| unsafe { core::ptr::read_volatile(a as *const i32) });
        let what: &[u8] = match imp {
            Some(1) => b"arm64 CRC32 instructions",
            Some(2) => b"riscv64 Zbc carry-less multiply",
            Some(0) => b"slice-by-8 tables (fallback)",
            _ => b"unknown",
        };
        line(&[b"[LX] vdso hwcap ", hex(sys::vdso_hwcap(), &mut h), b"; lxbase crc32_le: ", what]);
    }
    let Some(xz) = lx_load(b"/fat/XZ_DEC.KO\0", b"XZ_DEC.KO", &mut |n: &[u8]| base.export(n).or_else(|| host_abi(n))) else {
        return;
    };
    let (Some(init), Some(run), Some(end)) = (xz.export(b"xz_dec_init"), xz.export(b"xz_dec_run"), xz.export(b"xz_dec_end")) else {
        line(&[b"[LX] XZ_DEC.KO FAIL: xz_dec_init/run/end not exported"]);
        return;
    };
    // SAFETY: the three addresses are the relocated, kernel-verified,
    // read-execute exports of xz_dec.ko with the prototypes of
    // include/linux/xz.h.
    let (init, run, end): (extern "C" fn(u32, u32) -> *mut u8, extern "C" fn(*mut u8, *mut XzBuf) -> u32, extern "C" fn(*mut u8)) =
        unsafe { (core::mem::transmute(init as usize), core::mem::transmute(run as usize), core::mem::transmute(end as usize)) };
    let Some(input) = read_static(b"/fat/XZTEST.XZ\0") else {
        line(&[b"[LX] XZ_DEC.KO FAIL: no /fat/XZTEST.XZ"]);
        return;
    };
    let Some(out_at) = mmap_pages(XZ_PATTERN_SIZE as u64 + PAGE) else { return };
    let out_cap = XZ_PATTERN_SIZE + PAGE as usize;
    // One decode of `src` into the output mapping: (xz_ret, bytes out).
    let decode = |src: &[u8]| -> (u32, usize) {
        let s = init(XZ_SINGLE, 0);
        if s.is_null() {
            return (u32::MAX, 0);
        }
        let mut b = XzBuf { input: src.as_ptr(), in_pos: 0, in_size: src.len(), out: out_at as *mut u8, out_pos: 0, out_size: out_cap };
        let ret = run(s, &mut b);
        end(s);
        (ret, b.out_pos)
    };
    let t0 = counter();
    let (ret, n) = decode(input);
    let t_decode = counter() - t0;
    // A second, warm decode: the first one also pays the first-touch page
    // faults of the output mapping and the allocator arena (demand paging);
    // Linux's vmalloc/kmalloc memory is populated when it is allocated.
    let t0 = counter();
    let (ret2, n2) = decode(input);
    let t_warm = counter() - t0;
    let warm_ok = ret2 == ret && n2 == n;
    // The request floor a client pays before any driver work: one trapping
    // syscall (SYS_UPTIME), 1000 times; Linux's twin is getppid x1000.
    let t1 = counter();
    for _ in 0..1000 {
        sys::uptime_ecall();
    }
    let t_sys = counter() - t1;
    // crc32_le alone over the decoded 48 KiB: the part of the decode that is
    // lxbase's, not xz_dec's (lxbench.ko times Linux's the same way).
    let t_crc = match base.export(b"crc32_le") {
        Some(f) => {
            // SAFETY: lxbase's exported `u32 crc32_le(u32, const void *, size_t)`.
            let f: extern "C" fn(u32, *const u8, usize) -> u32 = unsafe { core::mem::transmute(f as usize) };
            let t0 = counter();
            let c = f(!0, out_at as *const u8, n.min(out_cap));
            let t = counter() - t0;
            core::hint::black_box(c);
            t
        }
        None => 0,
    };
    let t_cal = calibrate();
    let mut dt = [[0u8; 21]; 6];
    let [e0, e1, e2, e3, e4, e5] = &mut dt;
    line(&[b"[LX] timing xz decode (init+run+end) cold ", dec(t_decode as i64, e0), b", warm ", dec(t_warm as i64, e3),
           b" ticks; crc32_le 48K ", dec(t_crc as i64, e5),
           b" ticks; uptime syscall x1000 ", dec(t_sys as i64, e1), b" ticks; 8M-instruction loop ", dec(t_cal as i64, e4),
           b" ticks; counter hz ", dec(counter_hz() as i64, e2)]);
    // SAFETY: `out_at` maps `out_cap` bytes; `n <= out_cap` (xz_buf contract).
    let out = unsafe { core::slice::from_raw_parts(out_at as *const u8, n.min(out_cap)) };
    let same = ret == XZ_STREAM_END && xz_pattern_eq(out);
    // The negative probe: one flipped bit in the middle of the compressed
    // payload must not decode (the stream's CRC32, computed by LXBASE.KO's
    // crc32_le, or LZMA2 itself, catches it).
    let bad_ret = match mmap_pages(input.len() as u64) {
        Some(at) => {
            // SAFETY: freshly mapped, `input.len()` bytes.
            let bad = unsafe { core::slice::from_raw_parts_mut(at as *mut u8, input.len()) };
            bad.copy_from_slice(input);
            bad[input.len() / 2] ^= 0x10;
            decode(bad).0
        }
        None => u32::MAX,
    };
    // SAFETY: see `HeapCell`; the module code has returned.
    let h = unsafe { &*HEAP.0.get() };
    let ok = same && warm_ok && (2..=8).contains(&bad_ret) && h.allocs > 0 && h.allocs == h.frees && h.bad_frees == 0;
    let mut d = [[0u8; 21]; 6];
    let [d0, d1, d2, d3, d4, d5] = &mut d;
    line(&[b"[LX] xz_dec.ko decompressed XZTEST.XZ: ", dec(input.len() as i64, d0), b" -> ", dec(n as i64, d1),
           b" bytes, ret ", dec(ret as i64, d2), if same { b", equal to the pattern" } else { b", NOT the pattern" },
           b"; corrupted copy ret ", dec(bad_ret as i64, d3), b"; kmalloc/kfree ", dec(h.allocs as i64, d4), b"/",
           dec(h.frees as i64, d5), if ok { b": PASS" } else { b": FAIL" }]);
}

fn run() {
    line(&[b"[LXSRV] up: Linux driver server skeleton (RFC-0053 L0), no Linux object linked"]);
    // SAFETY: `KO` is used only here, and this process is single-threaded.
    let ko: &mut [u8; KO_MAX] = unsafe { &mut *KO.0.get() };
    let Some(len) = read_module(ko) else {
        line(&[b"[LXSRV] no /fat/LXTEST.KO on the volume: idle"]);
        return;
    };
    let file = &ko[..len];
    let (mut h, mut d) = ([0u8; 18], [0u8; 21]);
    let isa = Isa::native();
    let module = match Module::parse(file, isa) {
        Ok(m) => m,
        Err(_) => {
            line(&[b"[LXSRV] module LXTEST.KO FAIL: not a relocatable object for this ISA"]);
            return;
        }
    };
    if admit(&module, VERMAGIC).is_err() {
        line(&[b"[LXSRV] module LXTEST.KO FAIL: licence or vermagic refused"]);
        return;
    }
    let license = module.modinfo(b"license").unwrap_or(b"?");
    let imports = module.for_each_import(|_| {}).unwrap_or(0);
    line(&[b"[LXSRV] module LXTEST.KO: ", dec(len as i64, &mut d), b" bytes, license=", license,
           b", imports ", dec(imports as i64, &mut [0u8; 21])]);

    // Probe 1: a token the kernel never issued.
    let probe = mmap_pages(PAGE).unwrap_or(0);
    let r = sys::module_map_x(0x0000_0001_4c58_0001, probe, PAGE);
    line(&[b"[LXSRV] probe forged token: rc ", dec(r as i64, &mut d)]);
    let forged_ok = r < 0;

    // The kernel's verdict on the file bytes. The tamper row keys on this.
    let token = sys::module_verify(file, MODULE_NAME);
    if token <= 0 {
        line(&[b"[LXSRV] module LXTEST.KO verify REFUSED by the kernel: rc ", dec(token as i64, &mut d)]);
        return;
    }

    let Ok(layout) = module.layout() else {
        line(&[b"[LXSRV] module LXTEST.KO FAIL: layout"]);
        return;
    };
    let (Some(text_base), Some(data_base)) = (mmap_pages(layout.text_size), mmap_pages(layout.data_size)) else {
        line(&[b"[LXSRV] module LXTEST.KO FAIL: no memory for the regions"]);
        return;
    };
    let text_len = layout.text_size.div_ceil(PAGE) * PAGE;
    let data_len = layout.data_size.div_ceil(PAGE).max(1) * PAGE;
    // SAFETY: both regions were just mapped read-write for this process,
    // with these lengths, and nothing else refers to them.
    let text = unsafe { core::slice::from_raw_parts_mut(text_base as *mut u8, text_len as usize) };
    let data = unsafe { core::slice::from_raw_parts_mut(data_base as *mut u8, data_len as usize) };
    let loaded = match module.load(text, text_base, data, data_base, &mut export) {
        Ok(l) => l,
        Err(_) => {
            line(&[b"[LXSRV] module LXTEST.KO FAIL: relocation refused"]);
            return;
        }
    };

    // Probe 2: more pages than the verified module may make executable. The
    // token is consumed by the attempt, so verify again for the real call.
    let r = sys::module_map_x(token as u64, text_base, text_len + 64 * PAGE);
    line(&[b"[LXSRV] probe oversized range: rc ", dec(r as i64, &mut d)]);
    let oversized_ok = r < 0;
    let token = sys::module_verify(file, MODULE_NAME);
    if token <= 0 {
        line(&[b"[LXSRV] module LXTEST.KO verify REFUSED by the kernel: rc ", dec(token as i64, &mut d)]);
        return;
    }
    let r = sys::module_map_x(token as u64, text_base, text_len);
    if r != 0 {
        line(&[b"[LXSRV] module LXTEST.KO FAIL: map_x refused, rc ", dec(r as i64, &mut d)]);
        return;
    }
    // Probe 3: the same token twice.
    let r = sys::module_map_x(token as u64, text_base, text_len);
    line(&[b"[LXSRV] probe token reuse: rc ", dec(r as i64, &mut d)]);
    let reuse_ok = r < 0;

    let Some(init) = loaded.symbol(b"lxtest_init") else {
        line(&[b"[LXSRV] module LXTEST.KO FAIL: no lxtest_init"]);
        return;
    };
    // SAFETY: `init` is the relocated, kernel-verified, now read-execute
    // entry of a C function `u64 lxtest_init(void)`.
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(init as usize) };
    let got = f();
    let want = expected_init();
    let (mut h2, mut h3) = ([0u8; 18], [0u8; 18]);
    let verdict: &[u8] = if got == want && forged_ok && oversized_ok && reuse_ok { b"PASS" } else { b"FAIL" };
    line(&[b"[LXSRV] module lxtest init=", hex(got, &mut h), b" expected=", hex(want, &mut h2),
           b" at ", hex(init, &mut h3), b" probes forged/oversized/reuse refused: ", verdict]);
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    run();
    run_linux();
    line(&[b"[LXSRV] idle"]);
    idle()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::println(b"[LXSRV] FAIL: panic");
    sys::exit(70);
}
