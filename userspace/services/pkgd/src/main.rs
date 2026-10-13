// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `PKGD.ELF`: the AzOS package installer.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `endpoint.packages` (it serves it) and a read-write tree on `/fat/PKG`
//! (where it stages; the directory is provisioned with the volume, as a tree
//! cannot create its own root). It answers the `Packages` object
//! (`userspace/lib/packages`) to whoever holds a call capability on that
//! endpoint, copying the package out of the memory object the request carries.
//!
//! Everything it decides is `azos_pkg`'s and the library's; this file is the
//! volume (libsys over the FAT32 mount) and the loop. What it stages is not
//! applied by anything yet (the kernel's boot-time application is not built),
//! and its verdict is not a trust anchor: whoever can write `/fat/PKG` can
//! stage a file without it, so the application must verify again.

#![no_std]
#![no_main]

use azos_idl::Cap;
use azos_libsys as sys;
use azos_packages::{PackagesIdl, PkgMem, Read, Service, VolErr, Volume, Work};
use azos_pkg::Device;

/// The one working set: a megabyte of package buffer (`.bss`) and, beside it,
/// the topology it is judged against.
static mut WORK: Work = Work::new();
static mut TOPOLOGY: azos_topology::Topology<'static> = azos_topology::Topology::empty();

/// O_WRONLY, O_CREAT, O_TRUNC, O_APPEND (`azos_fs` values).
const O_WRONLY: u64 = 0x1;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
/// A path longer than this is not one the installer builds.
const PATH_MAX: usize = 64;

/// The interfaces this device serves and their levels: what a package's
/// `[api]` is held to. Read off the interfaces' own definitions.
fn api() -> [(&'static str, u32); 17] {
    use azos_devif as d;
    [
        ("Block", d::BlockIdl::LEVEL as u32),
        ("Behavior", d::families::BehaviorIdl::LEVEL as u32),
        ("Config", d::families::ConfigIdl::LEVEL as u32),
        ("Decisions", azos_decisions::DecisionsIdl::LEVEL as u32),
        ("Entropy", d::EntropyIdl::LEVEL as u32),
        ("Flight", d::families::FlightIdl::LEVEL as u32),
        ("Gpio", d::GpioIdl::LEVEL as u32),
        ("I2c", d::I2cIdl::LEVEL as u32),
        ("LinkKey", d::LinkKeyIdl::LEVEL as u32),
        ("Motor", d::MotorIdl::LEVEL as u32),
        ("Names", azos_names::NamesIdl::LEVEL as u32),
        ("Ota", d::families::OtaIdl::LEVEL as u32),
        ("Packages", PackagesIdl::LEVEL as u32),
        ("Power", d::PowerIdl::LEVEL as u32),
        ("Pwm", d::PwmIdl::LEVEL as u32),
        ("Sensor", d::SensorIdl::LEVEL as u32),
        ("Terminal", azos_term::TerminalIdl::LEVEL as u32),
    ]
}

/// `path` with the NUL the kernel scans for.
fn cpath(path: &[u8], out: &mut [u8; PATH_MAX]) -> bool {
    if path.len() >= PATH_MAX {
        return false;
    }
    out[..path.len()].copy_from_slice(path);
    out[path.len()] = 0;
    true
}

/// Fill `buf` from handle `h`; `more` says the file goes on past it.
fn read_all(h: u32, buf: &mut [u8]) -> Result<Read, VolErr> {
    let mut n = 0;
    while n < buf.len() {
        let r = sys::file_read_typed(h, &mut buf[n..]);
        if r < 0 {
            return Err(VolErr::Io);
        }
        if r == 0 {
            return Ok(Read { n, more: false });
        }
        n += r as usize;
    }
    // The buffer is full: is there a byte after it?
    let mut probe = [0u8; 1];
    match sys::file_read_typed(h, &mut probe) {
        r if r < 0 => Err(VolErr::Io),
        0 => Ok(Read { n, more: false }),
        _ => Ok(Read { n, more: true }),
    }
}

fn write_all(h: u32, data: &[u8]) -> Result<(), VolErr> {
    let mut at = 0;
    while at < data.len() {
        let r = sys::file_write_typed(h, &data[at..]);
        if r <= 0 {
            return Err(VolErr::Io);
        }
        at += r as usize;
    }
    Ok(())
}

/// The first `len` bytes of the memory object `cap` names, into `buf`. The
/// client keeps its own mapping of the object and can change it under us, so the
/// bytes are copied once, here, and everything after works on the copy.
fn copy_region(cap: u32, len: usize, buf: &mut [u8]) -> Result<usize, VolErr> {
    if len > buf.len() {
        return Err(VolErr::TooLarge);
    }
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    if sys::shm_acquire_typed(cap, &mut info) < 0 {
        return Err(VolErr::Io);
    }
    // The geometry counts pages of at least 4 KiB: the object holds at least
    // this many bytes, and a client that asked for fewer than `len` is lying.
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    if pages.saturating_mul(4096) < len {
        return Err(VolErr::Io);
    }
    let va = sys::shm_map_typed(cap);
    if va <= 0 {
        return Err(VolErr::Io);
    }
    // SAFETY: the kernel mapped the object at `va` for at least `pages` pages,
    // readable, and `len <= pages * 4096`; the mapping lasts until the release
    // that follows, and the slice is dropped before it.
    let src = unsafe { core::slice::from_raw_parts(va as *const u8, len) };
    buf[..len].copy_from_slice(src);
    Ok(len)
}

/// The volume: libsys over the FAT32 mount.
struct Fat;

impl Fat {
    fn open(path: &[u8], flags: u64) -> Result<u32, VolErr> {
        let mut p = [0u8; PATH_MAX];
        if !cpath(path, &mut p) {
            return Err(VolErr::Io);
        }
        match sys::file_open_typed(&p[..path.len() + 1], flags) {
            h if h >= 0 => Ok(h as u32),
            _ => Err(VolErr::Missing),
        }
    }

    fn written(path: &[u8], flags: u64, data: &[u8]) -> Result<(), VolErr> {
        let h = Self::open(path, flags).map_err(|_| VolErr::Io)?;
        let r = write_all(h, data);
        let _ = sys::close_typed(h);
        r
    }
}

impl Volume for Fat {
    fn read_file(&mut self, path: &[u8], buf: &mut [u8]) -> Result<Read, VolErr> {
        let h = Self::open(path, 0)?;
        let r = read_all(h, buf);
        let _ = sys::close_typed(h);
        r
    }

    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr> {
        let r = copy_region(cap.raw(), len, buf);
        // The object is the installer's now: unmapped and released whatever
        // happened, so a client cannot fill the capability table.
        let _ = sys::shm_release_typed(cap.raw());
        r
    }

    fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        Self::written(path, O_WRONLY | O_CREAT | O_TRUNC, data)
    }

    fn append(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        Self::written(path, O_WRONLY | O_CREAT | O_APPEND, data)
    }

    fn remove(&mut self, path: &[u8]) -> Result<(), VolErr> {
        let mut p = [0u8; PATH_MAX];
        if !cpath(path, &mut p) {
            return Err(VolErr::Io);
        }
        if sys::unlink(&p[..path.len() + 1]) == 0 { Ok(()) } else { Err(VolErr::Io) }
    }

    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; 64]) -> Option<usize> {
        let mut p = [0u8; PATH_MAX];
        if !cpath(dir, &mut p) {
            return None;
        }
        let (mut size, mut is_dir) = (0u32, 0u32);
        if sys::readdir(&p[..dir.len() + 1], index as u64, name, &mut size, &mut is_dir) != 0 {
            return None;
        }
        Some(name.iter().position(|&b| b == 0).unwrap_or(name.len()))
    }

    fn dir_exists(&mut self, dir: &[u8]) -> bool {
        let mut p = [0u8; PATH_MAX];
        if !cpath(dir, &mut p) {
            return false;
        }
        let mut st = [0u8; azos_abi::syscall_nr::STAT_BYTES];
        sys::stat(&p[..dir.len() + 1], &mut st) == 0
    }

    fn now_ns(&mut self) -> u64 {
        sys::clock_now(sys::ClockId::MONO).unwrap_or(0)
    }
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    let _ = sys::console_write(sys::STDOUT, b"[pkgd] AzOS package installer (Packages on endpoint.packages)\n");
    let table = api();
    // SAFETY: the one reference to each, for the life of the program.
    let (work, topo) = unsafe { (&mut *core::ptr::addr_of_mut!(WORK), &mut *core::ptr::addr_of_mut!(TOPOLOGY)) };
    let mut svc = Service::new(Fat, work, topo, azos_topology::TRUSTED_PUBKEY, Device::this(&table));

    loop {
        let mut req = sys::MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        let mut rep = sys::MsgDesc::default();
        let _ = PackagesIdl::dispatch(&mut svc, &req, &mut rep);
        // A request that carried a memory object the installer did not read (a
        // malformed one, a refused level) leaves it in the table: release what
        // came in. The ones it did read are released already; releasing a stale
        // handle is harmless (`-ECAPSTALE`).
        for c in &req.caps[..(req.n_caps as usize).min(req.caps.len())] {
            let _ = sys::shm_release_typed(c.handle);
        }
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}
