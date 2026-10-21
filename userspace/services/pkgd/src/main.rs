// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `PKGD.ELF`: the AzOS package installer.
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on
//! `endpoint.packages` (it serves it), a read-write tree on `/fat/PKG` (the
//! slot directories of a whole-system update; the directory is provisioned
//! with the volume, as a tree cannot create its own root) and, where the
//! topology declares a native volume for it, a read-write tree on that
//! volume's mount (`stage::STAGE_MOUNT`), where it stages packages and keeps
//! its journal. It answers the `Packages` object (`userspace/lib/packages`) to
//! whoever holds a call capability on that endpoint, copying the package out
//! of the memory object the request carries. A package is staged on that native
//! volume only: it is the kernel that applies it, at the next boot, and it applies
//! from there (`kernel/src/boot/pkg_apply.rs`).
//!
//! Everything it decides is `azos_pkg`'s and the library's; this file is the
//! ring-3 half of the volume (libsys calls, the shared memory of a request, the
//! OTA endpoint) and the loop; `stage.rs` is where the staged files live and
//! the order they are written in (a staged package and its journal record
//! become durable together or not at all). What it stages is applied by the
//! kernel at the next boot, which verifies again (its verdict is not a trust
//! anchor: whoever can write the staging volume can stage a file without it);
//! `snap.rs` keeps the restore points that apply leaves to the retention.
//!
//! It also stages the whole-system update (`Packages::update`): a signed
//! manifest and the kernel, userspace images, topology and configuration it
//! covers, streamed out of the client's memory object into the inactive slot's
//! directory under `/fat/PKG` (on the boot volume, where the kernel-side switch
//! reads it) and read back before the stage is reported. The switch of the boot
//! record is not here: this program holds no authority over it, and the
//! kernel-side switch verifies the staged set again.
//!
//! **A std program.** The installer fetches a package from a pinned HTTPS
//! source when the operator asks (`pkg fetch`, `Packages::fetch`), and TLS
//! (`userspace/lib/tls`: rustls with the rustls-rustcrypto provider) needs the
//! std port, so `pkgd` is built like `rpcquic` is: `-Zbuild-std` for
//! `<isa>-unknown-azos`, the crates.io tree `third_party/vendor`
//! (`tools/sdk_cargo.py --vendored`). Its loop and its files are still the
//! native calls of `azos_libsys`; `std` is what the dial and the handshake run
//! on (`std::net`, the clock, the heap). The package source decides nothing: a
//! fetched package is verified, admitted and staged exactly as one a client
//! handed over. Its row adds `READ` on `entropy` (the handshake's keys, the
//! allocator's seed) and its seccomp profile the TCP socket ops; the file
//! authority is unchanged.
//!
//! In a development build (`PKG_FETCH_TFTP`) `SOURCE.CFG` may name a TFTP
//! server on the development host instead (`tftp.rs`): the same fetch, the same
//! verification, a different transport, over the UDP ops the profile already
//! has. Nothing about the package is trusted for having come from there.

#![cfg_attr(target_os = "azos", feature(random))]

use std::process::ExitCode;

mod snap;
mod stage;
mod tftp;

use azos_idl::Cap;
use azos_libsys as sys;
use azos_packages::update::{IoErr, Source, NAME_BUF};
use azos_packages::{PackagesIdl, PkgMem, Service, VolErr, Work};
use azos_tls::remote::HttpsRemote;
use stage::{Files, Paths, Platform, Stage, Unlinked, PATH_MAX};
use tftp::Sources;
use sys::dev::OtaCall;
use azos_pkg::Device;

#[cfg(target_os = "azos")]
mod azos_random {
    use std::random::{DefaultRandomSource, RandomSource};

    /// getrandom 0.2's custom backend (rand_core 0.6, the TLS provider's keys): the std port's random source, the kernel pool behind the `entropy` capability.
    fn kernel_pool(buf: &mut [u8]) -> Result<(), getrandom02::Error> {
        DefaultRandomSource.fill_bytes(buf);
        Ok(())
    }
    getrandom02::register_custom_getrandom!(kernel_pool);
}

/// The one working set: a megabyte of package buffer (`.bss`) and, beside it,
/// the topology it is judged against.
/// The key the signed topology is checked with, as one 32-byte object in the
/// image. Passed straight to `Service::new` the constant is split by the
/// compiler into the immediates of the code that builds the argument, and
/// `tools/check_board_keys.py elf` (a board image embeds its own key and not the
/// test one) cannot find the key's 32 bytes in the ELF; a read through
/// `black_box` of this `#[used]` static cannot be folded away.
#[used]
static TRUSTED_PUBKEY: [u8; 32] = azos_topology::TRUSTED_PUBKEY;

/// A development build may fetch from the development host over TFTP (Kconfig
/// `PKG_FETCH_TFTP`, which depends on `BUILD_TYPE_DEV`). The Kconfig dependency
/// keeps a release `.config` from setting it; this keeps a hand-edited one from
/// compiling it in.
const FETCH_TFTP: bool = azos_limits::PKG_FETCH_TFTP;
const _: () = assert!(!FETCH_TFTP || azos_limits::BUILD_TYPE_DEV, "PKG_FETCH_TFTP is for development builds only");

static mut WORK: Work = Work::new();
static mut TOPOLOGY: azos_topology::Topology<'static> = azos_topology::Topology::empty();
/// The table and the requests the restore points are read into (`.bss`).
static mut SNAP_BUF: [u8; snap::BUF] = [0; snap::BUF];

/// The levels the shared table (`azos_pkg::api`) restates for the interfaces
/// this program's own libraries serve: a drift between the restatement and the
/// libraries is a build error here, and the kernel's boot-time apply reads the
/// same table.
const _: () = {
    let u = azos_pkg::api::USER_SERVED;
    assert!(u.decisions == azos_decisions::DecisionsIdl::LEVEL as u32);
    assert!(u.names == azos_names::NamesIdl::LEVEL as u32);
    assert!(u.packages == PackagesIdl::LEVEL as u32);
    assert!(u.terminal == azos_term::TerminalIdl::LEVEL as u32);
};

/// Map the memory object `cap` names and check it holds at least `len` bytes:
/// the address it is mapped at. The mapping lasts until the capability is
/// released.
fn map_region(cap: u32, len: usize) -> Result<usize, VolErr> {
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
    Ok(va as usize)
}

/// The first `len` bytes of the memory object `cap` names, into `buf`. The
/// client keeps its own mapping of the object and can change it under us, so the
/// bytes are copied once, here, and everything after works on the copy.
fn copy_region(cap: u32, len: usize, buf: &mut [u8]) -> Result<usize, VolErr> {
    if len > buf.len() {
        return Err(VolErr::TooLarge);
    }
    let va = map_region(cap, len)?;
    // SAFETY: the kernel mapped the object at `va` for at least `len` bytes,
    // readable (`map_region` checked the geometry); the mapping lasts until the
    // release that follows, and the slice is dropped before it.
    let src = unsafe { core::slice::from_raw_parts(va as *const u8, len) };
    buf[..len].copy_from_slice(src);
    Ok(len)
}

/// An update bundle: the client's memory object, mapped, read in place. The
/// installer owns the capability and releases it (which unmaps it) when this is
/// dropped.
struct Mapped {
    cap: u32,
    va: usize,
    len: usize,
}

impl Source for Mapped {
    fn len(&self) -> u64 {
        self.len as u64
    }

    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, IoErr> {
        let off = usize::try_from(off).map_err(|_| IoErr::Io)?;
        if off > self.len {
            return Err(IoErr::Io);
        }
        let n = buf.len().min(self.len - off);
        // SAFETY: `va..va+len` is mapped readable for as long as `self` lives
        // (`map_region`). The client can write the same pages while we read, so
        // the bytes are copied through raw pointers, never viewed as a slice,
        // and the stager hashes the copy, not the object.
        unsafe { core::ptr::copy_nonoverlapping((self.va + off) as *const u8, buf.as_mut_ptr(), n) };
        Ok(n)
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        let _ = sys::shm_release_typed(self.cap);
    }
}

/// The file calls, over libsys. The installer library names its files by
/// absolute path; an open is `NODE_OPENAT` beneath the root `Cap<Dir>` this
/// holds, on the name without its leading `/`, and a change to the tree is
/// authorised by the write trees its row grants. The calls with no `_at` form
/// (`unlink`, `stat`, `mkdir`, `readdir`) still take the path.
#[derive(Clone, Copy)]
struct SysFiles {
    /// The task's root directory, which every open is beneath.
    root: u32,
}

impl SysFiles {
    /// The files of the task's root directory; `None` when its row grants none.
    fn new() -> Option<SysFiles> {
        Some(SysFiles { root: u32::try_from(sys::root_dir()).ok()? })
    }

    /// `path` with the NUL the kernel scans for.
    fn cstr(path: &[u8]) -> Option<([u8; PATH_MAX], usize)> {
        if path.len() >= PATH_MAX {
            return None;
        }
        let mut out = [0u8; PATH_MAX];
        out[..path.len()].copy_from_slice(path);
        Some((out, path.len() + 1))
    }
}

impl Files for SysFiles {
    fn open(&mut self, path: &[u8], flags: u64) -> Option<u32> {
        let (p, n) = Self::cstr(path)?;
        match sys::open_at(self.root, sys::below_root(&p[..n]), flags) {
            h if h >= 0 => Some(h as u32),
            _ => None,
        }
    }

    fn read(&mut self, h: u32, buf: &mut [u8]) -> Result<usize, ()> {
        match sys::file_read_typed(h, buf) {
            r if r < 0 => Err(()),
            r => Ok(r as usize),
        }
    }

    fn write(&mut self, h: u32, data: &[u8]) -> Result<usize, ()> {
        match sys::file_write_typed(h, data) {
            r if r <= 0 => Err(()),
            r => Ok(r as usize),
        }
    }

    fn sync(&mut self, h: u32) -> Result<(), ()> {
        if sys::fsync_typed(h) < 0 { Err(()) } else { Ok(()) }
    }

    fn close(&mut self, h: u32) -> Result<(), ()> {
        if sys::close_typed(h) < 0 { Err(()) } else { Ok(()) }
    }

    fn unlink(&mut self, path: &[u8]) -> Unlinked {
        let Some((p, n)) = Self::cstr(path) else { return Unlinked::Failed };
        if sys::unlink(&p[..n]) == 0 {
            return Unlinked::Done;
        }
        // Say "missing" only when the file is not there.
        if self.exists(path) { Unlinked::Failed } else { Unlinked::Missing }
    }

    fn exists(&mut self, path: &[u8]) -> bool {
        let Some((p, n)) = Self::cstr(path) else { return false };
        let mut st = [0u8; azos_abi::syscall_nr::STAT_BYTES];
        sys::stat(&p[..n], &mut st) == 0
    }

    fn mkdir(&mut self, path: &[u8]) -> bool {
        let Some((p, n)) = Self::cstr(path) else { return false };
        sys::mkdir(&p[..n]) == 0
    }

    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; NAME_BUF]) -> Option<usize> {
        let (p, n) = Self::cstr(dir)?;
        let (mut size, mut is_dir) = (0u32, 0u32);
        if sys::readdir(&p[..n], index as u64, name, &mut size, &mut is_dir) != 0 {
            return None;
        }
        Some(name.iter().position(|&b| b == 0).unwrap_or(name.len()))
    }
}

/// The request's memory objects, the OTA endpoint and the clock.
struct SysPlatform;

impl Platform for SysPlatform {
    type Bundle = Mapped;

    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr> {
        let r = copy_region(cap.raw(), len, buf);
        // The object is the installer's now: unmapped and released whatever
        // happened, so a client cannot fill the capability table.
        let _ = sys::shm_release_typed(cap.raw());
        r
    }

    fn open_bundle(&mut self, cap: Cap<PkgMem>, len: usize) -> Result<Mapped, VolErr> {
        match map_region(cap.raw(), len) {
            Ok(va) => Ok(Mapped { cap: cap.raw(), va, len }),
            Err(e) => {
                let _ = sys::shm_release_typed(cap.raw());
                Err(e)
            }
        }
    }

    fn boot_slots(&mut self) -> Option<(u8, u8)> {
        // The kernel-hosted `ota` endpoint this program's row grants, if it does.
        let ep = sys::dev::lookup(sys::dev::key::OTA, 0)?;
        let c = sys::dev::OtaClient::new(sys::dev::Ep(ep));
        match c.status() {
            Ok(o) if o.is_ok() => {
                let (active, last_good, _, _) = sys::families::ota_status_unpack(o.value);
                Some((active, last_good))
            }
            _ => None,
        }
    }

    fn now_ns(&mut self) -> u64 {
        sys::clock_now(sys::ClockId::MONO).unwrap_or(0)
    }
}

fn main() -> ExitCode {
    println!("[pkgd] AzOS package installer (Packages on endpoint.packages)");
    let table = azos_pkg::api::device_api();
    // SAFETY: the one reference to each, for the life of the program.
    let (work, topo) = unsafe { (&mut *core::ptr::addr_of_mut!(WORK), &mut *core::ptr::addr_of_mut!(TOPOLOGY)) };
    // Staged packages and the journal go to the native volume when the
    // topology mounts one for them, else to the boot volume.
    let Some(files) = SysFiles::new() else {
        println!("[pkgd] no root directory granted");
        return ExitCode::from(1);
    };
    let paths = Paths::new(files);
    println!("[pkgd] staging on the {} volume", if paths.on_volume() { "native" } else { "boot" });
    // The restore points the kernel keeps for the staged packages: kept to the
    // retention, the rest asked to be dropped at the next boot (`snap`).
    let mut snaps = paths.clone();
    let vol = Stage { paths, plat: SysPlatform };
    let mut svc = Service::new(vol, Sources::<_, FETCH_TFTP>::new(HttpsRemote::device()), work, topo, *core::hint::black_box(&TRUSTED_PUBKEY), Device::this(&table));

    // SAFETY: the one reference to it, for the life of the program.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(SNAP_BUF) };
    match snap::list(&mut snaps, buf) {
        Ok(p) if p.kept != 0 || p.trial => {
            println!("[pkgd] restore points kept{}", if p.trial { ", a trial on probation" } else { "" });
        }
        _ => {}
    }
    let _ = snap::prune(&mut snaps, snap::KEPT, buf);

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
        // An install or a removal changes what the next boot applies: keep the
        // restore points to the retention.
        let _ = snap::prune(&mut snaps, snap::KEPT, buf);
    }
}
