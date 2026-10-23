// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The removable volume (`crates/fs/fs/src/usbvol.rs`): a FAT32 on a fake USB
//! stick, mounted at `/usb` beside the shim disk's `/fat`.
//!
//! The stick is [`Stick`], an in-memory [`usbvol::Disk`] that can be pulled
//! out. The volume code is the real `fat32.rs`, compiled a second time inside
//! `usbvol`, so every row here is also a row about the seam: the two volumes
//! must not share a byte of state.

use super::{fat32, image::*, serial, usbvol, vfs, vfs_open_close::fresh_volume};
use azos_drv_api::block::FlushError;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use vfs::FileSystem as _;

const AT: &[u8] = b"/usb";

/// A USB stick: sectors in memory, a flush counter, and a plug.
struct Stick {
    img: Mutex<Vec<u8>>,
    pulled: AtomicBool,
    flushes: AtomicU32,
    writes: AtomicU32,
}

impl Stick {
    fn leak(img: Vec<u8>) -> &'static Stick {
        Box::leak(Box::new(Stick {
            img: Mutex::new(img),
            pulled: AtomicBool::new(false),
            flushes: AtomicU32::new(0),
            writes: AtomicU32::new(0),
        }))
    }
    fn image(&self) -> Vec<u8> {
        self.img.lock().unwrap().clone()
    }
}

impl usbvol::Disk for Stick {
    fn sectors(&self) -> u64 {
        (self.img.lock().unwrap().len() / SECTOR) as u64
    }
    fn read(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        if self.pulled.load(Ordering::SeqCst) {
            return Err(());
        }
        let img = self.img.lock().unwrap();
        let (o, n) = (sector as usize * SECTOR, count as usize * SECTOR);
        buf[..n].copy_from_slice(img.get(o..o + n).ok_or(())?);
        Ok(())
    }
    fn write(&self, sector: u64, count: u32, buf: &[u8], _preflush: bool) -> Result<(), ()> {
        if self.pulled.load(Ordering::SeqCst) {
            return Err(());
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        let mut img = self.img.lock().unwrap();
        let (o, n) = (sector as usize * SECTOR, count as usize * SECTOR);
        img.get_mut(o..o + n).ok_or(())?.copy_from_slice(&buf[..n]);
        Ok(())
    }
    fn flush(&self) -> Result<(), FlushError> {
        if self.pulled.load(Ordering::SeqCst) {
            return Err(FlushError::Io);
        }
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// An MBR stick: one FAT32 partition (type 0x0C) at LBA 2048, the default
/// fixture volume in it, `marker` in the root's first entry name so two
/// sticks tell apart.
fn stick_image() -> Vec<u8> {
    const BASE: usize = 2048;
    let g = Geom::default();
    let mut vol = build(&g);
    set_fat(&mut vol, &g, 2, 0x0FFF_FFFF);
    let mut m = vec![0u8; BASE * SECTOR];
    let o = 446;
    m[o + 4] = 0x0C;
    m[o + 8..o + 12].copy_from_slice(&(BASE as u32).to_le_bytes());
    m[o + 12..o + 16].copy_from_slice(&((vol.len() / SECTOR) as u32).to_le_bytes());
    m[510] = 0x55;
    m[511] = 0xAA;
    m.extend_from_slice(&vol);
    m
}

/// The FAT[1] "shut down cleanly" bit of the stick's volume (first FAT copy).
fn clean_bit(img: &[u8]) -> bool {
    let fat = (2048 + Geom::default().rsvd as usize) * SECTOR;
    u32::from_le_bytes(img[fat + 4..fat + 8].try_into().unwrap()) & 0x0800_0000 != 0
}

fn write_file(path: &[u8], data: &[u8]) {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path, vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
    assert!(fd >= 0, "create {:?}", std::str::from_utf8(path));
    assert_eq!(vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), data.len() as i32);
    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
}

fn read_file(path: &[u8]) -> Option<Vec<u8>> {
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, path, vfs::O_RDONLY);
    if fd < 0 {
        return None;
    }
    let mut buf = vec![0u8; 4096];
    let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len());
    vfs::vfs_close(&mut t, fd);
    buf.truncate(n.max(0) as usize);
    Some(buf)
}

/// Whatever a failed row left mounted goes: every row starts with no stick.
fn no_stick() {
    usbvol::unplugged();
    assert!(!usbvol::mounted());
}

/// **The stick is a second volume, not `/fat`.** Mounted from its MBR
/// partition at `/usb`; a file written there lands on the stick past LBA
/// 2048 and never on the boot disk, a file of the same name on `/fat` keeps
/// its own bytes, and the two backends are two values (the VFS tells them
/// apart by address: a shared one would merge their page caches and skip one
/// in a sync of every volume).
///
/// **Canary, does not discriminate here.** Make `Fat32Fs` zero-sized again
/// (`pub struct Fat32Fs;`): the host build still places the two statics at
/// two addresses, so the row stays green. Nothing guarantees that for a
/// zero-sized static (the kernel's linker may fold them); the `addr_eq`
/// assertion is the property, kept for the build that would break it.
#[test]
fn a_stick_mounts_beside_fat_as_a_volume_of_its_own() {
    let _g = serial();
    fresh_volume();
    no_stick();
    let s = Stick::leak(stick_image());
    let m = usbvol::mount(s, AT).expect("the stick's FAT32 mounts");
    assert_eq!(m, usbvol::Mounted { base: 2048, partitions: 1 });
    assert!(usbvol::mounted());
    assert!(
        !core::ptr::addr_eq(
            &fat32::FAT32_FS as &dyn vfs::FileSystem as *const dyn vfs::FileSystem,
            &usbvol::fat32::FAT32_FS as &dyn vfs::FileSystem as *const dyn vfs::FileSystem,
        ),
        "the boot volume and the stick are one backend to the VFS"
    );
    assert_eq!(usbvol::fat32::FAT32_FS.fs_type(), vfs::FS_TYPE_FAT32_REMOVABLE);

    write_file(b"/fat/SAME.TXT", b"boot volume");
    let boot_with_file = fs_test_drivers::disk_image();
    write_file(b"/usb/SAME.TXT", b"on the stick");
    assert_eq!(read_file(b"/usb/SAME.TXT").as_deref(), Some(&b"on the stick"[..]));
    assert_eq!(read_file(b"/fat/SAME.TXT").as_deref(), Some(&b"boot volume"[..]));
    assert_eq!(fs_test_drivers::disk_image(), boot_with_file, "a write to /usb reached the boot disk");
    let img = s.image();
    assert!(img[2048 * SECTOR..].windows(12).any(|w| w == b"on the stick"), "the bytes are on the stick");
    assert!(!img[..2048 * SECTOR].windows(12).any(|w| w == b"on the stick"), "never before the partition");
    // The page cache and the spawn cache key by stamp: never the same.
    let k = usbvol::fat32::FAT32_FS.key_for(b"SAME.TXT").unwrap();
    let st = usbvol::fat32::FAT32_FS.content_stamp(&k).expect("a stamp");
    assert_eq!(st.fs, vfs::STAMP_FS_FAT32_REMOVABLE);
    // Only the boot volume's tickets are served (by `fs-wb`): an fsync of a
    // stick file syncs inline.
    assert!(usbvol::fat32::FAT32_FS.flush_request().is_none());
    assert!(fat32::FAT32_FS.flush_request().is_some());
    no_stick();
}

/// **Pulling the stick out retires the volume, typed, and the next stick is
/// not the last one's.** With a file open on `/usb`, the stick goes: the
/// read fails (-1, not a silent end of file) and so does a write; the path
/// opens nothing. A second stick holding a file of the same name mounts at
/// the same path, and the descriptor opened on the first stick still fails:
/// it does not read the new stick's file.
///
/// **Canary.** In `vfs_unmount`, leave the inodes on the backend (drop the
/// `GONE_FS` hand-over): the old descriptor reads the second stick's bytes.
/// **Canary.** Drop the `is_gone` check in `vfs_read_inner`: the read
/// returns 0 (an end of file) instead of -1.
#[test]
fn a_pulled_stick_fails_its_open_files_and_the_next_stick_is_its_own() {
    let _g = serial();
    fresh_volume();
    no_stick();
    let a = Stick::leak(stick_image());
    usbvol::mount(a, AT).expect("stick A mounts");
    write_file(b"/usb/DATA.BIN", b"stick A data");
    let mut t = vfs::ScratchFds::new();
    let fd = vfs::vfs_open(&mut t, b"/usb/DATA.BIN", vfs::O_RDWR);
    assert!(fd >= 0);

    a.pulled.store(true, Ordering::SeqCst);
    usbvol::unplugged();
    assert!(!usbvol::mounted());
    let mut buf = [0u8; 64];
    assert_eq!(vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len()), -1, "a read on a pulled stick");
    assert_eq!(vfs::vfs_write(&mut t, fd, b"x".as_ptr(), 1), -1, "a write on a pulled stick");
    assert!(read_file(b"/usb/DATA.BIN").is_none(), "the path names nothing once the stick is gone");

    // Stick B, the same name with other bytes.
    let b = Stick::leak(stick_image());
    usbvol::mount(b, AT).expect("stick B mounts at the same path");
    write_file(b"/usb/DATA.BIN", b"stick B data");
    vfs::vfs_lseek(&mut t, fd, 0, vfs::SEEK_SET);
    let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len());
    assert_eq!(n, -1, "the descriptor of stick A read {:?}", &buf[..n.max(0) as usize]);
    vfs::vfs_close(&mut t, fd);
    assert_eq!(read_file(b"/usb/DATA.BIN").as_deref(), Some(&b"stick B data"[..]));
    no_stick();
}

/// **An eject leaves the stick clean and flushed; an unplug never writes.**
/// Mounting marks the volume dirty (FAT[1] bit 27 clear); an eject writes it
/// back, sets the bit again and sends at least one flush. A stick that is
/// pulled instead is left dirty (its next mount checks it) and is not asked
/// for anything once gone.
///
/// **Canary.** In `usbvol::eject`, retire with `writeback: false` and skip the
/// unmount's sync: the clean bit stays clear and the file never reaches the
/// stick.
#[test]
fn an_eject_writes_back_marks_clean_and_flushes() {
    let _g = serial();
    fresh_volume();
    no_stick();
    let s = Stick::leak(stick_image());
    assert!(clean_bit(&s.image()), "the fixture is clean");
    usbvol::mount(s, AT).expect("mounts");
    assert!(!clean_bit(&s.image()), "a mounted volume is marked dirty");
    write_file(b"/usb/CRASH.LOG", b"panic: test record\n");
    let flushes = s.flushes.load(Ordering::SeqCst);
    assert_eq!(usbvol::eject(), Some(Ok(())));
    assert!(!usbvol::mounted());
    assert!(clean_bit(&s.image()), "an ejected volume is clean");
    assert!(s.flushes.load(Ordering::SeqCst) > flushes, "an eject flushes the stick");
    assert!(s.image().windows(19).any(|w| w == b"panic: test record\n"));
    assert_eq!(usbvol::eject(), None, "nothing is mounted any more");

    // Pulled instead: nothing reaches it after.
    let p = Stick::leak(stick_image());
    usbvol::mount(p, AT).expect("mounts");
    p.pulled.store(true, Ordering::SeqCst);
    let writes = p.writes.load(Ordering::SeqCst);
    usbvol::unplugged();
    assert_eq!(p.writes.load(Ordering::SeqCst), writes);
    assert!(!clean_bit(&p.image()), "a pulled stick stays dirty");
}

/// **Plugging in and out does not run the mount table out.** Twice
/// `VFS_MAX_MOUNTS` cycles of mount and unplug at `/usb`, each stick
/// readable while it is in.
///
/// **Canary.** Make `vfs_mount_inner` always append (no reuse of a retired
/// slot): the mount fails after a few cycles.
#[test]
fn plug_cycles_reuse_the_mount_slot() {
    let _g = serial();
    fresh_volume();
    no_stick();
    for i in 0..2 * azos_limits::VFS_MAX_MOUNTS {
        let s = Stick::leak(stick_image());
        usbvol::mount(s, AT).unwrap_or_else(|e| panic!("cycle {i}: {e:?}"));
        write_file(b"/usb/CYCLE.TXT", format!("cycle {i}").as_bytes());
        assert_eq!(read_file(b"/usb/CYCLE.TXT"), Some(format!("cycle {i}").into_bytes()));
        usbvol::unplugged();
    }
}

/// **What is not a FAT32 stick is refused, and leaves nothing mounted.** A
/// blank stick (no table, no boot sector) and a stick whose MBR entry runs
/// past the medium.
#[test]
fn a_stick_without_a_fat32_volume_is_not_mounted() {
    let _g = serial();
    fresh_volume();
    no_stick();
    let blank = Stick::leak(vec![0u8; 4096 * SECTOR]);
    assert_eq!(usbvol::mount(blank, AT), Err(usbvol::Why::NoFat32));
    assert!(!usbvol::mounted());
    let mut img = stick_image();
    img[446 + 12..446 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    let bad = Stick::leak(img);
    assert!(matches!(usbvol::mount(bad, AT), Err(usbvol::Why::Table(_))));
    assert!(read_file(b"/usb/ANY.TXT").is_none());
    // And a good one still mounts after both.
    let good = Stick::leak(stick_image());
    assert!(usbvol::mount(good, AT).is_ok());
    no_stick();
}
