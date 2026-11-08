// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `EXT4D.ELF`: a read-only ext4 volume served in ring 3.
//!
//! The parser (`azos_ext4`) reads an untrusted image, so it runs here, in a
//! row of its own whose whole authority is three grants: `READ` on the one
//! partition it serves (`block.part.<n>`, read through the io_ring's block
//! entries), its endpoint (`endpoint.ext4`, `READ` to serve and `WRITE` with
//! `transfer` to lend each open file a right of its own) and the region it
//! shares with the kernel (`MemObj fs.share`), where names and data cross.
//! The kernel mounts the volume through `azos_fs::endpoint::EndpointFs`, so a
//! client of the mount cannot tell it from a volume the kernel parses.
//!
//! The protocol is `service.rs`, pure and host-tested
//! (`tests/host/ext4-tests`); this file is the host it runs in: the block
//! source and the calls.
//!
//! A volume it will not serve (no partition granted, a refused mount) ends
//! the task with code 0 and the reason on the console: the verdict is final,
//! so nothing restarts it. A panic is a failure, and its row restarts it.

#![no_std]
#![no_main]

mod service;

use azos_abi::cap::{CapPerms, SHM_FS_SHARE};
use azos_devif::fs::{DirIdl, NodeIdl, DIR_ID};
use azos_devif::BlockCall;
use azos_ext4::{BlockSource, IoError, Volume};
use azos_libsys as sys;
use azos_srv::sys::Calls;
use azos_srv::{Handler, Server};
use azos_abi::ipc_msg::{MsgDesc, MSG_BADGED};
use service::{Host, Service};

fn log(line: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, line);
}

/// Bytes of one cached metadata window (the largest block the parser reads).
const WINDOW: usize = azos_ext4::MAX_BLOCK;
/// Windows kept: the superblock, a descriptor block, inode table blocks and
/// the directory being walked.
const WINDOWS: usize = 16;
const SECTOR: u64 = 512;
/// How long one block entry may take before the read fails: Kconfig
/// `FS_EXT4_RING3_REPLY_MS`, the kernel's wait for one answer.
const BLOCK_WAIT_MS: u64 = azos_limits::FS_EXT4_RING3_REPLY_MS as u64;

/// The partition through the io_ring.
struct Dev {
    ring: sys::ioring::Ring,
    ring_cap: u32,
    badge: u32,
    bytes: u64,
    tag: u64,
}

/// The partition, metadata through a small cache. File data is not kept:
/// the kernel's page cache holds what a client read.
struct Disk {
    dev: Dev,
    cache: [(u64, u64); WINDOWS],
    data: &'static mut [[u8; WINDOW]; WINDOWS],
    clock: u64,
}

impl Dev {
    /// Read whole sectors at `sector` into `buf` (at most the ring's data window).
    fn sectors(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let sector = u32::try_from(sector).map_err(|_| IoError)?;
        self.tag += 1;
        if !self.ring.push_block(false, self.badge, 0, buf.len() as u32, sector, self.tag) {
            return Err(IoError);
        }
        if sys::ioring_submit_typed(self.ring_cap) < 0 {
            return Err(IoError);
        }
        let mut waited = 0;
        loop {
            match self.ring.pop() {
                Some((t, r, _)) if t == self.tag => {
                    if r as isize != buf.len() as isize {
                        return Err(IoError);
                    }
                    break;
                }
                Some(_) => return Err(IoError),
                None if waited >= BLOCK_WAIT_MS => return Err(IoError),
                None => {
                    sys::sleep(1);
                    waited += 1;
                }
            }
        }
        // SAFETY: the ring's data window is `DATA_SIZE` bytes and `buf` is at
        // most that (the callers split by it); the kernel finished writing it.
        unsafe { core::ptr::copy_nonoverlapping(self.ring.data(), buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    /// `buf` from byte `off`, through sector-aligned reads.
    fn raw(&mut self, off: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let end = off.checked_add(buf.len() as u64).ok_or(IoError)?;
        if end > self.bytes {
            return Err(IoError);
        }
        let mut bounce = [0u8; sys::ioring::DATA_SIZE];
        let mut at = off;
        while at < end {
            let first = at / SECTOR;
            let skip = (at % SECTOR) as usize;
            let want = ((end - at) as usize + skip).div_ceil(SECTOR as usize) * SECTOR as usize;
            let chunk = want.min(bounce.len());
            self.sectors(first, &mut bounce[..chunk])?;
            let n = (chunk - skip).min((end - at) as usize);
            let o = (at - off) as usize;
            buf[o..o + n].copy_from_slice(&bounce[skip..skip + n]);
            at += n as u64;
        }
        Ok(())
    }
}

impl BlockSource for Disk {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let base = off / WINDOW as u64 * WINDOW as u64;
        let inner = (off - base) as usize;
        if inner + buf.len() > WINDOW {
            return self.dev.raw(off, buf);
        }
        self.clock += 1;
        let slot = match self.cache.iter().position(|&(b, used)| used != 0 && b == base) {
            Some(s) => s,
            None => {
                let s = (0..WINDOWS).min_by_key(|&i| self.cache[i].1).unwrap_or(0);
                let n = (self.dev.bytes - base).min(WINDOW as u64) as usize;
                // The slot names nothing while it is read: a failed read
                // leaves no window that claims the bytes.
                self.cache[s] = (0, 0);
                self.dev.raw(base, &mut self.data[s][..n])?;
                s
            }
        };
        self.cache[slot] = (base, self.clock);
        buf.copy_from_slice(&self.data[slot][inner..inner + buf.len()]);
        Ok(())
    }

    fn read_data(&mut self, off: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.dev.raw(off, buf)
    }

    fn len(&self) -> u64 {
        self.dev.bytes
    }
}

/// The region and the endpoint, as the service needs them.
struct Kernel {
    region: &'static mut [u8],
    /// `READ` + the lendable call right on `endpoint.ext4`.
    source: u32,
}

impl Host for Kernel {
    fn region(&mut self) -> &mut [u8] {
        self.region
    }
    fn derive(&mut self, badge: u32) -> Option<u32> {
        // The server's copy keeps `DELEGATE`, which lending it needs; the
        // opener gets the call right alone (`NODE_RIGHTS`).
        let rights = CapPerms::WRITE.union(CapPerms::DELEGATE).bits();
        let h = sys::endpoint_derive(self.source, rights, badge, 0, &[]);
        (h > 0).then_some(h as u32)
    }
    fn revoke(&mut self, handle: u32) {
        let r = sys::cap_revoke(handle);
        let _ = sys::close_typed(if r > 0 { r as u32 } else { handle });
    }
}

/// The partition this row was granted: the first `block.part.<n>` it holds.
fn partition() -> Option<(u32, u32)> {
    (1..=azos_devif::block::PARTS).find_map(|b| sys::dev::lookup(sys::dev::key::BLOCK, b).map(|h| (h, b)))
}

fn map_share() -> Option<&'static mut [u8]> {
    let cap = sys::cap_lookup(sys::ty::SHM.raw(), SHM_FS_SHARE);
    if cap < 0 {
        return None;
    }
    let mut info = [0u8; sys::SHM_INFO_BYTES];
    if sys::shm_acquire_typed(cap as u32, &mut info) < 0 {
        return None;
    }
    let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        return None;
    }
    // SAFETY: the kernel mapped `pages` pages read-write at `va` for the life
    // of the task; the kernel reads what this task writes there only between
    // a call and its reply, and copies it before it checks it.
    Some(unsafe { core::slice::from_raw_parts_mut(va as *mut u8, pages * sys::PAGE_SIZE) })
}

/// The metadata windows and the service: statics, past the stack.
static WINDOWS_MEM: sys::Lock<[[u8; WINDOW]; WINDOWS]> = sys::Lock::new([[0; WINDOW]; WINDOWS]);
static SERVICE: sys::Lock<Option<Service<Disk, Kernel>>> = sys::Lock::new(None);

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    let Some((part, badge)) = partition() else {
        log(b"[EXT4D] no partition granted: nothing to serve\n");
        sys::exit(0);
    };
    let sectors = match sys::dev::value(sys::dev::BlockClient::new(sys::dev::Ep(part)).sectors()) {
        Ok(n) => n,
        Err(_) => {
            log(b"[EXT4D] the partition's length is not known\n");
            sys::exit(0);
        }
    };
    let mut out = [0u8; 8];
    let cap = sys::ioring_create_typed(&mut out);
    let ring = if cap > 0 { sys::ioring::Ring::open(cap as u32, out).ok() } else { None };
    let Some(ring) = ring else {
        log(b"[EXT4D] no io_ring\n");
        sys::exit(0);
    };
    let disk = Disk {
        dev: Dev { ring, ring_cap: cap as u32, badge, bytes: sectors * SECTOR, tag: 0 },
        cache: [(0, 0); WINDOWS],
        data: WINDOWS_MEM.lock().leak(),
        clock: 0,
    };
    let source = sys::cap_lookup_endpoint(b"ext4", CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::DELEGATE).bits(), 0);
    let Some(region) = map_share() else {
        log(b"[EXT4D] no shared region: nothing to serve\n");
        sys::exit(0);
    };
    if source <= 0 {
        log(b"[EXT4D] no endpoint to serve\n");
        sys::exit(0);
    }
    let vol = match Volume::mount(disk) {
        Ok(v) => v,
        Err(e) => {
            let mut line = [0u8; 96];
            let n = refusal(&mut line, e);
            log(&line[..n]);
            sys::exit(0);
        }
    };
    log(b"[EXT4D] serving a read-only ext4 volume on endpoint.ext4\n");
    let svc = SERVICE.lock().leak();
    *svc = Some(Service::new(vol, Kernel { region, source: source as u32 }));
    let Some(svc) = svc.as_mut() else { sys::exit(1) };
    Server::calls_only(Calls).run(&mut Fs(svc))
}

/// `[EXT4D] refused: <reason>`.
fn refusal(out: &mut [u8; 96], e: azos_ext4::MountError) -> usize {
    use azos_ext4::MountError as M;
    let why: &[u8] = match e {
        M::Io => b"the partition could not be read",
        M::BadMagic => b"not an ext2/3/4 volume",
        M::BlockSize(_) => b"block size",
        M::InodeSize(_) => b"inode size",
        M::DescSize(_) => b"descriptor size",
        M::Geometry => b"geometry",
        M::Incompat(_) => b"an incompatible feature it does not read",
        M::RoCompat(_) => b"bigalloc",
        M::NeedsRecovery => b"the journal needs recovery",
        M::ChecksumType(_) => b"checksum type",
        M::SuperChecksum => b"superblock checksum",
        M::Group(_) => b"group descriptor",
        M::Root => b"root directory",
    };
    let head = b"[EXT4D] refused: ";
    let n = head.len() + why.len();
    out[..head.len()].copy_from_slice(head);
    out[head.len()..n].copy_from_slice(why);
    out[n] = b'\n';
    n + 1
}

struct Fs(&'static mut Service<Disk, Kernel>);

impl Handler<Calls> for Fs {
    fn call(&mut self, _k: &mut Calls, _handle: u64, req: &MsgDesc, rep: &mut MsgDesc) {
        self.0.badge = if req.flags & MSG_BADGED != 0 { req.badge as u32 } else { 0 };
        if (req.words[0] >> 32) as u32 == DIR_ID {
            let _ = DirIdl::dispatch(self.0, req, rep);
        } else {
            let _ = NodeIdl::dispatch(self.0, req, rep);
        }
    }
}
