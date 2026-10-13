// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `PKG.ELF`: install signed application packages.
//!
//! The ring-3 face of the package installer. Its topology row is its whole
//! authority: a call capability (`WRITE`) on `endpoint.packages`, the endpoint
//! `PKGD.ELF` serves the `Packages` object on (`userspace/lib/packages`). It
//! reads the package file it is told to into a memory object and hands the
//! installer THAT capability and the length; it decides nothing, and prints
//! what the installer answered.
//!
//! ```text
//! pkg admit FILE     would the device take the package in FILE? changes nothing
//! pkg install FILE   admit it, stage it and journal the decision
//! pkg list           the staged packages, by id
//! pkg remove ID      unstage the package whose id is ID (64 hex digits)
//! ```
//! Exit 0, 1 when the installer refused, 2 on a usage error, no endpoint or
//! no such file, 3 when the installer failed.

#![no_std]
#![no_main]

use azos_libsys as sys;
use azos_packages::cli::{self, Fail, Opener};
use azos_packages::{Cap, IdlError, MsgDesc, PackagesClient, PkgMem, Transport};

/// The transport: the v2 call on the endpoint capability.
struct Ep(u32);

impl Transport for Ep {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        match sys::ipc_call_v2(self.0, msg) {
            0 => Ok(()),
            rc => Err(IdlError::Transport(rc)),
        }
    }
}

/// Reads the file into a new memory object. The object's capability goes to
/// the installer in the call (a MOVE: this program keeps its mapping and no
/// handle), and the installer releases it.
struct Files;

impl Opener for Files {
    fn open(&mut self, path: &[u8]) -> Option<(Cap<PkgMem>, u32)> {
        let mut p = [0u8; 128];
        if path.len() >= p.len() {
            return None;
        }
        p[..path.len()].copy_from_slice(path);
        let cpath = &p[..path.len() + 1];
        let mut st = [0u8; azos_abi::syscall_nr::STAT_BYTES];
        if sys::stat(cpath, &mut st) != 0 {
            return None;
        }
        let size = u64::from_le_bytes([st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]]);
        let len = u32::try_from(size).ok().filter(|&n| n != 0)?;
        let h = sys::file_open_typed(cpath, 0);
        if h < 0 {
            return None;
        }
        let h = h as u32;
        // Pages of 4 KiB at least: a larger base page only makes it roomier.
        let obj = sys::shm_create_typed((len as u64).div_ceil(4096), sys::SHM_RW);
        let va = if obj > 0 { sys::shm_map_typed(obj as u32) } else { -1 };
        let mut ok = va > 0;
        if ok {
            // SAFETY: the kernel mapped `ceil(len / 4096)` pages at `va`,
            // read-write, for this task; the slice ends before the call
            // that hands the object on.
            let dst = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len as usize) };
            let mut at = 0;
            while at < dst.len() {
                let r = sys::file_read_typed(h, &mut dst[at..]);
                if r <= 0 {
                    ok = false;
                    break;
                }
                at += r as usize;
            }
        }
        let _ = sys::close_typed(h);
        if !ok {
            if obj > 0 {
                let _ = sys::shm_release_typed(obj as u32);
            }
            return None;
        }
        Some((Cap::from_raw(obj as u32), len))
    }
}

/// Output, written in whole pieces: a line is one `write`, so another task's
/// output does not land in the middle of it.
struct Out {
    b: [u8; 256],
    n: usize,
    fd: u64,
}

impl Out {
    fn flush(&mut self) {
        let mut done = 0;
        while done < self.n {
            let r = sys::write(self.fd, &self.b[done..self.n]);
            if r <= 0 {
                break;
            }
            done += r as usize;
        }
        self.n = 0;
    }
}

impl core::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &c in s.as_bytes() {
            if self.n == self.b.len() {
                self.flush();
            }
            self.b[self.n] = c;
            self.n += 1;
            if c == b'\n' {
                self.flush();
            }
        }
        Ok(())
    }
}

/// The `Cap<Endpoint>` this row holds (its only endpoint; the topology
/// declares which). Ring 3 has no by-name lookup, so scan the pool indexes.
fn find_endpoint() -> Option<u32> {
    (0..16u32).find_map(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        (h > 0).then_some(h as u32)
    })
}

fn run() -> i32 {
    use core::fmt::Write;
    let mut out = Out { b: [0; 256], n: 0, fd: 1 };
    let mut err = Out { b: [0; 256], n: 0, fd: 2 };
    let mut args: [&[u8]; 4] = [b""; 4];
    let argc = sys::argc().saturating_sub(1).min(args.len());
    for (i, a) in args.iter_mut().enumerate().take(argc) {
        *a = sys::arg(i + 1).unwrap_or(b"");
    }
    let cmd = match cli::parse(&args[..argc]) {
        Ok(c) => c,
        Err(why) => {
            let _ = write!(err, "pkg: {}\n{}", why, cli::USAGE);
            return 2;
        }
    };
    let Some(ep) = find_endpoint() else {
        let _ = write!(err, "pkg: no packages endpoint (the row holds no call capability on endpoint.packages)\n");
        return 2;
    };
    let mut client = PackagesClient::new(Ep(ep));
    let code = match cli::run(&cmd, &mut client, &mut Files, &mut out) {
        Ok(code) => code,
        Err(Fail::Call(e)) => {
            let _ = write!(err, "pkg: the installer did not answer: {:?}\n", e);
            3
        }
        Err(Fail::Open) => {
            let _ = write!(err, "pkg: cannot open the package file\n");
            2
        }
        Err(Fail::Out) => 3,
    };
    out.flush();
    err.flush();
    code
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    let code = run();
    sys::exit(code)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}
