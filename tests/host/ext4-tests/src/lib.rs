// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Images for the ext4 tests, made by the host's `mke2fs` from a fixture tree,
//! and the walk that reads a whole volume back.
//!
//! Each image names its feature list in full (`-O none,...`), so the host's
//! `mke2fs.conf` cannot change what is tested; the UUID, the hash seed and
//! the clock are fixed, so an image is the same bytes on every run.

use azos_ext4::{BlockSource, DirEntry, Error, Inode, IoError, Volume};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A partition in memory.
pub struct Mem(pub Vec<u8>);

impl BlockSource for Mem {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), IoError> {
        let off = usize::try_from(off).map_err(|_| IoError)?;
        let src = self.0.get(off..off.checked_add(buf.len()).ok_or(IoError)?).ok_or(IoError)?;
        buf.copy_from_slice(src);
        Ok(())
    }
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
}

/// The ext4 feature set `mke2fs -t ext4` makes today, in full.
pub const EXT4: &str = "has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum";

/// One image to make.
pub struct Spec {
    pub name: &'static str,
    pub block: u32,
    pub inode: u32,
    pub features: &'static str,
    /// Extra `-E` options (comma-joined after the fixed ones).
    pub extended: &'static str,
    pub mib: u32,
    /// Index the directories afterwards (`e2fsck -fD`): `mke2fs -d` writes
    /// them linear.
    pub htree: bool,
}

/// The long directory name a slow symlink's target goes through.
pub fn long_dir() -> String {
    "x".repeat(60)
}

/// Contents of `big.bin`: no two blocks alike.
pub fn big() -> Vec<u8> {
    (0..300 * 1024 + 123u32).map(|i| (i.wrapping_mul(7) ^ (i >> 10)) as u8).collect()
}

/// Lay the fixture tree out under `root`.
pub fn fixture(root: &Path) {
    use std::fs;
    use std::os::unix::fs::symlink;
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root.join("deep/a/b/c")).unwrap();
    fs::create_dir_all(root.join("deep").join(long_dir())).unwrap();
    fs::create_dir_all(root.join("many")).unwrap();
    fs::write(root.join("hello.txt"), b"hello ext4\n").unwrap();
    fs::write(root.join("empty.txt"), b"").unwrap();
    fs::write(root.join("big.bin"), big()).unwrap();
    let mut sparse = vec![0u8; 64 * 1024];
    sparse.extend_from_slice(b"tail");
    fs::write(root.join("sparse.bin"), sparse).unwrap();
    fs::write(root.join("deep/a/b/c/leaf.txt"), b"leaf\n").unwrap();
    fs::write(root.join("deep").join(long_dir()).join("f"), b"slow target\n").unwrap();
    for i in 0..300 {
        fs::write(root.join("many").join(format!("an-entry-with-a-rather-long-name-{i:04}")), format!("{i}\n")).unwrap();
    }
    symlink("hello.txt", root.join("fast")).unwrap();
    symlink(format!("deep/{}/f", long_dir()), root.join("slow")).unwrap();
    symlink("/hello.txt", root.join("abs")).unwrap();
    symlink("../../../hello.txt", root.join("esc")).unwrap();
    symlink("deep/a", root.join("dirlink")).unwrap();
    fs::create_dir_all(root.join("jail/sub")).unwrap();
    fs::write(root.join("jail/data.txt"), b"jail data\n").unwrap();
    symlink("data.txt", root.join("jail/in")).unwrap();
    symlink("../data.txt", root.join("jail/sub/up_in")).unwrap();
    symlink("../hello.txt", root.join("jail/out")).unwrap();
    symlink("../../hello.txt", root.join("jail/sub/out2")).unwrap();
    symlink("/hello.txt", root.join("jail/abs")).unwrap();
    symlink("../deep/a", root.join("jail/outdir")).unwrap();
    symlink("sub", root.join("jail/indir")).unwrap();
    fs::create_dir_all(root.join("private")).unwrap();
    fs::write(root.join("private/secret.txt"), b"private\n").unwrap();
    symlink("private", root.join("grant")).unwrap();
    symlink("loop2", root.join("loop1")).unwrap();
    symlink("loop1", root.join("loop2")).unwrap();
}

/// Where e2fsprogs is: the first directory on PATH that has both `mke2fs`
/// and `e2fsck`, else Homebrew's keg (`brew --prefix e2fsprogs`), which is
/// not linked onto PATH.
fn e2fsprogs() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let has = |d: &Path| d.join("mke2fs").is_file() && d.join("e2fsck").is_file();
    if let Some(d) = std::env::split_paths(&path).find(|d| has(d)) {
        return d;
    }
    let brew = Command::new("brew").args(["--prefix", "e2fsprogs"]).output().ok();
    if let Some(o) = brew.filter(|o| o.status.success()) {
        let d = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()).join("sbin");
        if has(&d) {
            return d;
        }
    }
    panic!("e2fsprogs (mke2fs and e2fsck) is neither on PATH nor a Homebrew keg: these tests make their images with it")
}

/// Make `spec`'s image from the fixture tree under `dir` (built once per
/// directory) and read it into memory.
pub fn image(dir: &Path, spec: &Spec) -> Vec<u8> {
    // Tests run on threads of one process and share the fixture tree.
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    let root = dir.join("fixture");
    if !root.join("hello.txt").exists() {
        fixture(&root);
    }
    let img = dir.join(format!("{}.img", spec.name));
    let mut ext = String::from("hash_seed=01234567-89ab-cdef-0123-456789abcdef,lazy_itable_init=1");
    if !spec.extended.is_empty() {
        ext.push(',');
        ext.push_str(spec.extended);
    }
    let tools = e2fsprogs();
    let out = Command::new(tools.join("mke2fs"))
        .env("E2FSPROGS_FAKE_TIME", "1700000000")
        .env("MKE2FS_CONFIG", "/dev/null")
        .args(["-q", "-F", "-T", "default"])
        .args(["-b", &spec.block.to_string(), "-I", &spec.inode.to_string()])
        .args(["-O", &format!("none,{}", spec.features)])
        .args(["-U", "01234567-89ab-cdef-0123-456789abcdef", "-E", &ext])
        .arg("-d")
        .arg(&root)
        .arg(&img)
        .arg(format!("{}M", spec.mib))
        .output()
        .expect("run mke2fs");
    assert!(out.status.success(), "mke2fs {}: {}", spec.name, String::from_utf8_lossy(&out.stderr));
    if spec.htree {
        let out = Command::new(tools.join("e2fsck"))
            .env("E2FSPROGS_FAKE_TIME", "1700000000")
            .env("E2FSCK_CONFIG", "/dev/null")
            .args(["-f", "-y", "-D"])
            .arg(&img)
            .output()
            .expect("run e2fsck");
        // 0: nothing changed, 1: the directories were rewritten.
        assert!(matches!(out.status.code(), Some(0 | 1)), "e2fsck -D {}: {}", spec.name, String::from_utf8_lossy(&out.stdout));
    }
    std::fs::read(&img).unwrap()
}

/// Mount `bytes`.
pub fn mount(bytes: Vec<u8>) -> Result<Volume<Mem>, azos_ext4::MountError> {
    Volume::mount(Mem(bytes))
}

/// The entries of `dir`, in the order read.
pub fn list(v: &mut Volume<Mem>, dir: &Inode) -> Result<Vec<(Vec<u8>, u32)>, Error> {
    let mut out = Vec::new();
    let mut e = DirEntry::new();
    let mut pos = 0;
    while let Some(next) = v.readdir(dir, pos, &mut e)? {
        out.push((e.name().to_vec(), e.ino));
        pos = next;
        assert!(out.len() <= 1 << 16, "a directory listing that does not end");
    }
    Ok(out)
}

/// Read a whole file through a 1000-byte window (no read lines up with a
/// block, so every run and hole boundary is crossed somewhere).
pub fn read_all(v: &mut Volume<Mem>, ino: &Inode) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = [0u8; 1000];
    loop {
        let n = v.read(ino, out.len() as u64, &mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
        assert!(out.len() as u64 <= ino.size, "read past the file's size");
    }
}

/// Everything a walk of the whole volume reached, or the first refusal: the
/// walk a client of the volume makes, used on damaged images where only
/// "no panic, a typed answer" is asked.
pub fn walk(v: &mut Volume<Mem>) -> Result<usize, Error> {
    let mut seen = 0usize;
    let mut stack = vec![(v.inode(azos_ext4::ROOT_INO)?, 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        for (_, ino) in list(v, &dir)? {
            seen += 1;
            let i = v.inode(ino)?;
            if i.is_dir() && depth < 8 {
                stack.push((i, depth + 1));
            } else if i.is_file() {
                read_all(v, &i)?;
            } else if i.is_symlink() {
                let mut t = [0u8; azos_ext4::PATH_MAX];
                v.readlink(&i, &mut t)?;
            }
            if seen > 4096 {
                return Ok(seen);
            }
        }
    }
    Ok(seen)
}
