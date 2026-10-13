// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Linux runtime (`userspace/lib/linux_rt`) over a model of the native
//! calls. The runtime answers through raw pointers into the program's own
//! memory, which here is the test's: every buffer below is a host buffer.

#[cfg(test)]
mod tests {
    use azos_abi::foreign::{ForeignFrame, REG_NUMBER, REG_RESULT};
    use azos_abi::syscall_nr::{STAT_BYTES, STAT_OFF_MODE, STAT_OFF_NLINK, STAT_OFF_SIZE, STAT_S_IFDIR, STAT_S_IFREG};
    use azos_linux_abi as lx;
    use azos_linux_abi::errno as le;
    use azos_linux_abi::nr;
    use azos_abi::cap::{CapHandle, CapPerms, ty, CapType};
    use azos_abi::ushell::{StartupFd, FD_CONSOLE, FD_HANDLE, STARTUP_FDS};
    use azos_linux_rt::{Native, Runtime, Startup, NAME_BYTES};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// A model of the native calls: a tiny file system, pipes, a clock.
    #[derive(Default)]
    struct Model {
        files: BTreeMap<Vec<u8>, Vec<u8>>,
        dirs: Vec<Vec<u8>>,
        /// handle -> (path or pipe id, offset, is_pipe)
        handles: BTreeMap<u32, (Vec<u8>, usize, Option<usize>)>,
        pipes: Vec<Vec<u8>>,
        next_handle: u32,
        console: Vec<u8>,
        closed: Vec<u32>,
        now: u64,
        slept_until: Option<u64>,
        denied_prefix: Vec<u8>,
        exited: Option<i32>,
        /// What the next fork answers; the pid a thread asks for after it.
        fork_result: i64,
        pid: i64,
        child_pid_after_fork: i64,
        /// tid -> exit code, for the children that have ended.
        ended: BTreeMap<u32, i32>,
        /// children the model knows (a waitpid on another is -ECHILD)
        kids: Vec<u32>,
    }

    struct Mock(RefCell<Model>);

    fn trim(p: &[u8]) -> &[u8] {
        p.strip_suffix(&[0]).unwrap_or(p)
    }

    impl Native for Mock {
        fn getpid(&self) -> i64 {
            self.0.borrow().pid
        }
        fn now_ns(&self) -> u64 {
            let mut m = self.0.borrow_mut();
            m.now += 1000;
            m.now
        }
        fn console_write(&self, buf: &[u8]) -> i64 {
            self.0.borrow_mut().console.extend_from_slice(buf);
            buf.len() as i64
        }
        fn file_open(&self, path: &[u8], flags: u64) -> i64 {
            let mut m = self.0.borrow_mut();
            let p = trim(path).to_vec();
            if !m.denied_prefix.is_empty() && p.starts_with(&m.denied_prefix) && flags & 0x40 != 0 {
                return -13;
            }
            if !m.files.contains_key(&p) {
                if flags & 0x40 == 0 {
                    return -1;
                }
                m.files.insert(p.clone(), Vec::new());
            }
            m.next_handle += 1;
            let h = m.next_handle;
            m.handles.insert(h, (p, 0, None));
            h as i64
        }
        fn handle_read(&self, h: u32, buf: &mut [u8]) -> i64 {
            let mut m = self.0.borrow_mut();
            let Some((path, off, pipe)) = m.handles.get(&h).cloned() else { return -100 };
            match pipe {
                Some(id) => {
                    let n = buf.len().min(m.pipes[id].len());
                    buf[..n].copy_from_slice(&m.pipes[id][..n]);
                    m.pipes[id].drain(..n);
                    n as i64
                }
                None => {
                    let data = m.files[&path].clone();
                    let n = buf.len().min(data.len().saturating_sub(off));
                    buf[..n].copy_from_slice(&data[off..off + n]);
                    m.handles.get_mut(&h).unwrap().1 += n;
                    n as i64
                }
            }
        }
        fn handle_write(&self, h: u32, buf: &[u8]) -> i64 {
            let mut m = self.0.borrow_mut();
            let Some((path, _, pipe)) = m.handles.get(&h).cloned() else { return -100 };
            match pipe {
                Some(id) => m.pipes[id].extend_from_slice(buf),
                None => m.files.get_mut(&path).unwrap().extend_from_slice(buf),
            }
            buf.len() as i64
        }
        fn handle_close(&self, h: u32) -> i64 {
            let mut m = self.0.borrow_mut();
            m.closed.push(h);
            m.handles.remove(&h);
            0
        }
        fn pipe(&self, ends: &mut [u32; 2], _nonblock: bool) -> i64 {
            let mut m = self.0.borrow_mut();
            m.pipes.push(Vec::new());
            let id = m.pipes.len() - 1;
            for e in ends.iter_mut() {
                m.next_handle += 1;
                *e = m.next_handle;
                let h = m.next_handle;
                m.handles.insert(h, (Vec::new(), 0, Some(id)));
            }
            0
        }
        fn stat(&self, path: &[u8], out: &mut [u8; STAT_BYTES]) -> i64 {
            let m = self.0.borrow();
            let p = trim(path);
            *out = [0; STAT_BYTES];
            if let Some(d) = m.files.get(p) {
                out[STAT_OFF_SIZE..STAT_OFF_SIZE + 8].copy_from_slice(&(d.len() as u64).to_le_bytes());
                out[STAT_OFF_MODE..STAT_OFF_MODE + 4].copy_from_slice(&(STAT_S_IFREG | 0o644).to_le_bytes());
                out[STAT_OFF_NLINK..STAT_OFF_NLINK + 4].copy_from_slice(&1u32.to_le_bytes());
                return 0;
            }
            if p == b"/" || m.dirs.iter().any(|d| d == p) {
                out[STAT_OFF_MODE..STAT_OFF_MODE + 4].copy_from_slice(&(STAT_S_IFDIR | 0o755).to_le_bytes());
                return 0;
            }
            -1
        }
        fn readdir(&self, dir: &[u8], idx: u64, name: &mut [u8; NAME_BYTES], size: &mut u32, is_dir: &mut u32) -> i64 {
            let m = self.0.borrow();
            let d = trim(dir);
            let mut entries: Vec<(Vec<u8>, u32, u32)> = Vec::new();
            let prefix = if d == b"/" { b"/".to_vec() } else { [d, b"/"].concat() };
            for (p, data) in &m.files {
                if let Some(rest) = p.strip_prefix(prefix.as_slice()) {
                    if !rest.contains(&b'/') {
                        entries.push((rest.to_vec(), data.len() as u32, 0));
                    }
                }
            }
            match entries.get(idx as usize) {
                Some((n, s, dd)) => {
                    *name = [0; NAME_BYTES];
                    name[..n.len()].copy_from_slice(n);
                    *size = *s;
                    *is_dir = *dd;
                    0
                }
                None => -1,
            }
        }
        fn brk(&self, addr: u64) -> i64 {
            addr as i64
        }
        fn mmap(&self, _addr: u64, len: u64, _prot: u64, _flags: u64) -> i64 {
            0x4000_0000 + len as i64
        }
        fn munmap(&self, _addr: u64, _len: u64) -> i64 {
            0
        }
        fn sleep_until_ns(&self, deadline_ns: u64) {
            self.0.borrow_mut().slept_until = Some(deadline_ns);
        }
        fn yield_now(&self) {}
        fn fork(&self) -> i64 {
            let mut m = self.0.borrow_mut();
            let r = m.fork_result;
            if r > 0 {
                m.kids.push(r as u32);
            } else if r == 0 {
                m.pid = m.child_pid_after_fork;
            }
            r
        }
        fn waitpid(&self, tid: u32, code: &mut i32) -> i64 {
            let mut m = self.0.borrow_mut();
            if !m.kids.contains(&tid) {
                return -10;
            }
            match m.ended.remove(&tid) {
                Some(c) => {
                    *code = c;
                    m.kids.retain(|k| *k != tid);
                    tid as i64
                }
                None => -1,
            }
        }
        fn exit(&self, code: i32) -> ! {
            self.0.borrow_mut().exited = Some(code);
            panic!("exit({code})");
        }
    }

    fn model() -> Model {
        let mut m = Model::default();
        m.files.insert(b"/fat/HELLO.ELF".to_vec(), b"\x7fELF-and-more-bytes".to_vec());
        m.files.insert(b"/fat/OTHER.TXT".to_vec(), b"abc".to_vec());
        m.dirs.push(b"/fat".to_vec());
        m.denied_prefix = b"/fat/NEW".to_vec();
        m.pid = 42;
        m
    }

    /// A process a spawn with no request started: the console, and `/`.
    fn rt() -> Runtime<Mock> {
        let r = Runtime::new(Mock(RefCell::new(model())));
        r.init(b"/fat/HELLO.ELF", None);
        r
    }

    /// A native handle of kind `kind`, as the kernel packs them (the runtime
    /// reads the kind from the handle's own bits).
    fn handle(kind: CapType, slot: u16) -> u32 {
        CapHandle::pack(kind, CapPerms::READ.union(CapPerms::WRITE), 1, slot).as_raw()
    }

    /// A process a `SYS_SPAWN_EX` request started: `fds` and `cwd` arrive in
    /// the startup block.
    fn rt_spawned(fds: &[StartupFd; STARTUP_FDS], cwd: &[u8]) -> Runtime<Mock> {
        let r = Runtime::new(Mock(RefCell::new(model())));
        r.init(b"/fat/HELLO.ELF", Some(&Startup { fds, cwd }));
        r
    }

    fn call(r: &Runtime<Mock>, num: u64, a: [u64; 6]) -> i64 {
        let mut f = ForeignFrame::ZERO;
        f.gpr[REG_NUMBER] = num;
        for (i, v) in a.iter().enumerate() {
            f.gpr[REG_RESULT + i] = *v;
        }
        r.dispatch(&mut f);
        f.gpr[REG_RESULT] as i64
    }

    fn c(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    fn p(v: &[u8]) -> u64 {
        v.as_ptr() as u64
    }

    #[test]
    fn a_spawn_request_hands_over_its_descriptors_and_working_directory() {
        // `cat < in > out 2>&1`-shaped: 0 a pipe's read end, 1 and 2 one
        // file handle (aliased), 3.. closed.
        let (pipe_h, file_h) = (handle(ty::PIPE, 5), handle(ty::FILE, 6));
        let mut fds = [StartupFd::default(); STARTUP_FDS];
        fds[0] = StartupFd { kind: FD_HANDLE, handle: pipe_h };
        fds[1] = StartupFd { kind: FD_HANDLE, handle: file_h };
        fds[2] = StartupFd { kind: FD_HANDLE, handle: file_h };
        let r = rt_spawned(&fds, b"/fat");
        // The handles the kernel moved into the process: open in the model.
        r.native().0.borrow_mut().pipes.push(b"from the pipe".to_vec());
        r.native().0.borrow_mut().handles.insert(pipe_h, (Vec::new(), 0, Some(0)));
        r.native().0.borrow_mut().handles.insert(file_h, (b"/fat/OTHER.TXT".to_vec(), 3, None));

        // The working directory is the request's, not `/`.
        let mut cwd = [0u8; 16];
        assert_eq!(call(&r, nr::GETCWD, [cwd.as_mut_ptr() as u64, 16, 0, 0, 0, 0]), 5);
        assert_eq!(&cwd[..5], b"/fat\0");
        let rel = c("OTHER.TXT");
        let fd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&rel), 0, 0, 0, 0]);
        assert_eq!(fd, 3, "a relative name resolves against the spawn's directory, and the lowest free fd is 3");

        // Descriptor 0 reads the pipe, 1 and 2 write the file.
        let mut buf = [0u8; 8];
        assert_eq!(call(&r, nr::READ, [0, buf.as_mut_ptr() as u64, 8, 0, 0, 0]), 8);
        assert_eq!(&buf, b"from the");
        assert_eq!(call(&r, nr::WRITE, [1, p(b"xy"), 2, 0, 0, 0]), 2);
        assert_eq!(call(&r, nr::WRITE, [2, p(b"z"), 1, 0, 0, 0]), 1);
        assert_eq!(r.native().0.borrow().files[&b"/fat/OTHER.TXT".to_vec()], b"abcxyz");
        assert!(r.native().0.borrow().console.is_empty(), "nothing went to the console");
        // The kinds come from the handles: a pipe is a FIFO, a file a regular file.
        let mut st = [0u8; lx::STAT_SIZE];
        assert_eq!(call(&r, nr::FSTAT, [0, st.as_mut_ptr() as u64, 0, 0, 0, 0]), 0);
        assert_eq!(u32::from_le_bytes(st[16..20].try_into().unwrap()) & lx::mode::S_IFMT, lx::mode::S_IFIFO);
        assert_eq!(call(&r, nr::FSTAT, [1, st.as_mut_ptr() as u64, 0, 0, 0, 0]), 0);
        assert_eq!(u32::from_le_bytes(st[16..20].try_into().unwrap()) & lx::mode::S_IFMT, lx::mode::S_IFREG);
        // 3 is the file the test opened; 4 and up were closed by the request.
        assert_eq!(call(&r, nr::WRITE, [5, p(b"x"), 1, 0, 0, 0]), -le::EBADF);
        // `2>&1`: one handle on two descriptors is closed once, with the last.
        assert_eq!(call(&r, nr::CLOSE, [1, 0, 0, 0, 0, 0]), 0);
        assert!(!r.native().0.borrow().closed.contains(&file_h));
        assert_eq!(call(&r, nr::CLOSE, [2, 0, 0, 0, 0, 0]), 0);
        assert!(r.native().0.borrow().closed.contains(&file_h));
    }

    #[test]
    fn a_request_may_leave_descriptors_closed_and_name_the_console() {
        let mut fds = [StartupFd::default(); STARTUP_FDS];
        fds[1] = StartupFd { kind: FD_CONSOLE, handle: 0 };
        let r = rt_spawned(&fds, b"");
        // 0 and 2 are closed (the request said so), 1 is the console; an
        // empty working directory leaves `/`.
        assert_eq!(call(&r, nr::WRITE, [1, p(b"ok"), 2, 0, 0, 0]), 2);
        assert_eq!(r.native().0.borrow().console, b"ok");
        assert_eq!(call(&r, nr::WRITE, [2, p(b"no"), 2, 0, 0, 0]), -le::EBADF);
        let mut buf = [0u8; 1];
        assert_eq!(call(&r, nr::READ, [0, buf.as_mut_ptr() as u64, 1, 0, 0, 0]), -le::EBADF);
        let mut cwd = [0u8; 4];
        assert_eq!(call(&r, nr::GETCWD, [cwd.as_mut_ptr() as u64, 4, 0, 0, 0, 0]), 2);
        assert_eq!(&cwd[..2], b"/\0");
    }

    #[test]
    fn a_working_directory_that_is_not_absolute_or_too_long_keeps_root() {
        let fds = [StartupFd::default(); STARTUP_FDS];
        for bad in [&b"fat"[..], &[b'/'; 200][..]] {
            let r = rt_spawned(&fds, bad);
            let mut cwd = [0u8; 4];
            assert_eq!(call(&r, nr::GETCWD, [cwd.as_mut_ptr() as u64, 4, 0, 0, 0, 0]), 2);
        }
    }

    #[test]
    fn identity_is_answered_without_a_native_call() {
        let r = rt();
        assert_eq!(call(&r, nr::GETPID, [0; 6]), 42);
        assert_eq!(call(&r, nr::GETTID, [0; 6]), 42);
        assert_eq!(call(&r, nr::SET_TID_ADDRESS, [0; 6]), 42);
        assert_eq!(call(&r, nr::GETUID, [0; 6]), 0);
        assert_eq!(call(&r, nr::GETEGID, [0; 6]), 0);
    }

    #[test]
    fn umask_returns_the_old_one() {
        let r = rt();
        assert_eq!(call(&r, nr::UMASK, [0o077, 0, 0, 0, 0, 0]), 0o022);
        assert_eq!(call(&r, nr::UMASK, [0o022, 0, 0, 0, 0, 0]), 0o077);
    }

    #[test]
    fn uname_names_linux_and_the_machine() {
        let r = rt();
        let mut u = [0u8; 390];
        assert_eq!(call(&r, nr::UNAME, [u.as_mut_ptr() as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(&u[..5], b"Linux");
        assert_eq!(&u[65..69], b"azos");
    }

    #[test]
    fn the_console_is_open_on_0_1_2_and_writes_go_to_it() {
        let r = rt();
        let msg = b"hello";
        assert_eq!(call(&r, nr::WRITE, [1, p(msg), 5, 0, 0, 0]), 5);
        assert_eq!(call(&r, nr::WRITE, [2, p(msg), 5, 0, 0, 0]), 5);
        assert_eq!(r.native().0.borrow().console, b"hellohello");
        assert_eq!(call(&r, nr::WRITE, [3, p(msg), 5, 0, 0, 0]), -le::EBADF);
        // Console input is not offered yet: end of file, not a hang.
        let mut buf = [0u8; 4];
        assert_eq!(call(&r, nr::READ, [0, buf.as_mut_ptr() as u64, 4, 0, 0, 0]), 0);
    }

    #[test]
    fn a_file_is_opened_read_stat_ed_and_closed() {
        let r = rt();
        let path = c("/fat/HELLO.ELF");
        let fd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&path), 0, 0, 0, 0]);
        assert_eq!(fd, 3);
        let mut buf = [0u8; 4];
        assert_eq!(call(&r, nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 4, 0, 0, 0]), 4);
        assert_eq!(&buf, b"\x7fELF");
        let mut st = [0u8; lx::STAT_SIZE];
        assert_eq!(call(&r, nr::FSTAT, [fd as u64, st.as_mut_ptr() as u64, 0, 0, 0, 0]), 0);
        let size = i64::from_le_bytes(st[48..56].try_into().unwrap());
        assert_eq!(size, 19);
        assert_eq!(u32::from_le_bytes(st[16..20].try_into().unwrap()) & lx::mode::S_IFMT, lx::mode::S_IFREG);
        assert_eq!(call(&r, nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(call(&r, nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]), -le::EBADF);
        // The lowest closed descriptor is the next one.
        assert_eq!(call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&path), 0, 0, 0, 0]), 3);
    }

    #[test]
    fn a_missing_file_is_enoent_and_a_refused_create_is_eacces() {
        let r = rt();
        let missing = c("/fat/NOSUCH.TXT");
        assert_eq!(call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&missing), 0, 0, 0, 0]), -le::ENOENT);
        let denied = c("/fat/NEWFILE.TXT");
        assert_eq!(
            call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&denied), lx::oflag::O_CREAT | 1, 0, 0, 0]),
            -le::EACCES
        );
    }

    #[test]
    fn a_relative_path_resolves_against_the_working_directory() {
        let r = rt();
        let dir = c("/fat");
        assert_eq!(call(&r, nr::CHDIR, [p(&dir), 0, 0, 0, 0, 0]), 0);
        let mut cwd = [0u8; 64];
        assert_eq!(call(&r, nr::GETCWD, [cwd.as_mut_ptr() as u64, 64, 0, 0, 0, 0]), 5);
        assert_eq!(&cwd[..5], b"/fat\0");
        let rel = c("OTHER.TXT");
        let fd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&rel), 0, 0, 0, 0]);
        assert!(fd >= 3);
        let mut buf = [0u8; 8];
        assert_eq!(call(&r, nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 8, 0, 0, 0]), 3);
        assert_eq!(&buf[..3], b"abc");
        // chdir to a file, or to nothing, is refused.
        let file = c("/fat/OTHER.TXT");
        assert_eq!(call(&r, nr::CHDIR, [p(&file), 0, 0, 0, 0, 0]), -le::ENOTDIR);
        let none = c("/nowhere");
        assert_eq!(call(&r, nr::CHDIR, [p(&none), 0, 0, 0, 0, 0]), -le::ENOENT);
    }

    #[test]
    fn getdents64_lists_a_directory_in_one_or_more_calls() {
        let r = rt();
        let dir = c("/fat");
        let fd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&dir), lx::oflag::o_directory(lx::Arch::native()), 0, 0, 0]);
        assert!(fd >= 3);
        let mut buf = [0u8; 512];
        let n = call(&r, nr::GETDENTS64, [fd as u64, buf.as_mut_ptr() as u64, 512, 0, 0, 0]);
        assert!(n > 0);
        let mut names = Vec::new();
        let mut off = 0usize;
        while off < n as usize {
            let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let end = buf[off + 19..].iter().position(|&b| b == 0).unwrap();
            names.push(String::from_utf8(buf[off + 19..off + 19 + end].to_vec()).unwrap());
            off += reclen;
        }
        assert_eq!(names, ["HELLO.ELF", "OTHER.TXT"]);
        assert_eq!(call(&r, nr::GETDENTS64, [fd as u64, buf.as_mut_ptr() as u64, 512, 0, 0, 0]), 0);
        // A file is not a directory.
        let file = c("/fat/HELLO.ELF");
        let ffd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&file), 0, 0, 0, 0]);
        assert_eq!(call(&r, nr::GETDENTS64, [ffd as u64, buf.as_mut_ptr() as u64, 512, 0, 0, 0]), -le::ENOTDIR);
    }

    #[test]
    fn a_pipe_moves_bytes_and_dup3_aliases_one_handle() {
        let r = rt();
        let mut fds = [0u32; 2];
        assert_eq!(call(&r, nr::PIPE2, [fds.as_mut_ptr() as u64, lx::oflag::O_CLOEXEC, 0, 0, 0, 0]), 0);
        let (rd, wr) = (fds[0] as u64, fds[1] as u64);
        assert_eq!(call(&r, nr::DUP3, [wr, 9, 0, 0, 0, 0]), 9);
        // Closing the original write end leaves the alias, and the handle.
        assert_eq!(call(&r, nr::CLOSE, [wr, 0, 0, 0, 0, 0]), 0);
        assert!(r.native().0.borrow().closed.is_empty());
        assert_eq!(call(&r, nr::WRITE, [9, p(b"pipe-bytes"), 10, 0, 0, 0]), 10);
        let mut buf = [0u8; 16];
        assert_eq!(call(&r, nr::READ, [rd, buf.as_mut_ptr() as u64, 16, 0, 0, 0]), 10);
        assert_eq!(&buf[..10], b"pipe-bytes");
        // The last alias closes the native handle.
        assert_eq!(call(&r, nr::CLOSE, [9, 0, 0, 0, 0, 0]), 0);
        assert_eq!(r.native().0.borrow().closed.len(), 1);
        // fcntl: the descriptor flags are per descriptor.
        assert_eq!(call(&r, nr::FCNTL, [rd, lx::fcntl::F_GETFD, 0, 0, 0, 0]), 1);
        assert_eq!(call(&r, nr::FCNTL, [rd, lx::fcntl::F_SETFD, 0, 0, 0, 0]), 0);
        assert_eq!(call(&r, nr::FCNTL, [rd, lx::fcntl::F_GETFD, 0, 0, 0, 0]), 0);
        // dup picks the lowest free descriptor; F_DUPFD at or above its argument.
        assert_eq!(call(&r, nr::DUP, [rd, 0, 0, 0, 0, 0]), 4);
        assert_eq!(call(&r, nr::FCNTL, [rd, lx::fcntl::F_DUPFD, 10, 0, 0, 0]), 10);
    }

    #[test]
    fn writev_gathers_into_one_write() {
        let r = rt();
        let iov: [(u64, u64); 2] = [(p(b"lx: writev "), 11), (p(b"ok\n"), 3)];
        assert_eq!(call(&r, nr::WRITEV, [1, iov.as_ptr() as u64, 2, 0, 0, 0]), 14);
        assert_eq!(r.native().0.borrow().console, b"lx: writev ok\n");
    }

    #[test]
    fn the_tty_ioctls_answer_on_the_console_only() {
        let r = rt();
        let mut ws = [0u16; 4];
        assert_eq!(call(&r, nr::IOCTL, [1, 0x5413, ws.as_mut_ptr() as u64, 0, 0, 0]), 0);
        assert_eq!((ws[0], ws[1]), (24, 80));
        let path = c("/fat/HELLO.ELF");
        let fd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&path), 0, 0, 0, 0]);
        assert_eq!(call(&r, nr::IOCTL, [fd as u64, 0x5413, ws.as_mut_ptr() as u64, 0, 0, 0]), -le::ENOTTY);
    }

    #[test]
    fn signal_state_is_kept_and_sigkill_cannot_be_caught_or_blocked() {
        let r = rt();
        let act = [1u64, 0, 0, 0];
        let mut old = [0u64; 4];
        let size = lx::KSigaction::size(lx::Arch::native());
        assert_eq!(call(&r, nr::RT_SIGACTION, [2, act.as_ptr() as u64, 0, 8, 0, 0]), 0);
        assert_eq!(call(&r, nr::RT_SIGACTION, [2, 0, old.as_mut_ptr() as u64, 8, 0, 0]), 0);
        assert_eq!(old[0], 1);
        let _ = size;
        assert_eq!(call(&r, nr::RT_SIGACTION, [9, act.as_ptr() as u64, 0, 8, 0, 0]), -le::EINVAL);
        let set = (1u64 << 16) | (1u64 << 8);
        let mut got = 0u64;
        assert_eq!(call(&r, nr::RT_SIGPROCMASK, [0, &set as *const u64 as u64, 0, 8, 0, 0]), 0);
        assert_eq!(call(&r, nr::RT_SIGPROCMASK, [0, 0, &mut got as *mut u64 as u64, 8, 0, 0]), 0);
        assert_eq!(got, set & !(1u64 << 8));
        assert_eq!(call(&r, nr::RT_SIGPROCMASK, [7, &set as *const u64 as u64, 0, 8, 0, 0]), -le::EINVAL);
    }

    #[test]
    fn time_and_sleep_use_the_native_clock() {
        let r = rt();
        let mut ts = [0u8; 16];
        assert_eq!(call(&r, nr::CLOCK_GETTIME, [1, ts.as_mut_ptr() as u64, 0, 0, 0, 0]), 0);
        assert_eq!(call(&r, nr::CLOCK_GETTIME, [99, ts.as_mut_ptr() as u64, 0, 0, 0, 0]), -le::EINVAL);
        let req = lx::timespec_bytes(20_000_000);
        assert_eq!(call(&r, nr::NANOSLEEP, [req.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
        let slept = r.native().0.borrow().slept_until.unwrap();
        assert!(slept >= 20_000_000);
    }

    #[test]
    fn memory_calls_pass_through_with_the_linux_rules() {
        let r = rt();
        use lx::mman::*;
        assert_eq!(call(&r, nr::BRK, [0x10000, 0, 0, 0, 0, 0]), 0x10000);
        let ok = call(&r, nr::MMAP, [0, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0]);
        assert!(ok > 0);
        assert_eq!(call(&r, nr::MUNMAP, [ok as u64, 16384, 0, 0, 0, 0]), 0);
        // Executable and fixed mappings are refused; file mappings are not answered.
        let x = call(&r, nr::MMAP, [0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0]);
        assert_eq!(x, -le::EINVAL);
        let f = call(&r, nr::MMAP, [0, 4096, PROT_READ, MAP_PRIVATE, 3, 0]);
        assert_eq!(f, -le::ENOSYS);
    }

    #[test]
    fn what_needs_the_abi_cut_answers_enosys_and_is_reported_once_per_call() {
        let r = rt();
        assert_eq!(call(&r, nr::LSEEK, [3, 0, 0, 0, 0, 0]), -le::ENOSYS);
        assert_eq!(call(&r, nr::MPROTECT, [0, 4096, 1, 0, 0, 0]), -le::ENOSYS);
        // A thread (CLONE_THREAD and friends) is not answered.
        assert_eq!(call(&r, nr::CLONE, [0x7d0f00, 0x1000, 0, 0, 0, 0]), -le::ENOSYS);
        let console = String::from_utf8(r.native().0.borrow().console.clone()).unwrap();
        assert_eq!(console.matches("not answered by the personality: -ENOSYS").count(), 3);
        assert!(console.contains("syscall 62 "));
        // With no child to wait for, wait4 says so.
        assert_eq!(call(&r, nr::WAIT4, [u64::MAX, 0, 0, 0, 0, 0]), -le::ECHILD);
    }

    #[test]
    fn fork_gives_the_parent_a_child_it_can_wait_for() {
        let r = rt();
        r.native().0.borrow_mut().fork_result = 77;
        // fork: exit signal SIGCHLD in the low byte.
        assert_eq!(call(&r, nr::CLONE, [17, 0, 0, 0, 0, 0]), 77);
        let mut st = -1i32;
        // Still running: WNOHANG says 0, a pid that is not ours says ECHILD.
        assert_eq!(call(&r, nr::WAIT4, [77, &mut st as *mut i32 as u64, 1, 0, 0, 0]), 0);
        assert_eq!(call(&r, nr::WAIT4, [78, &mut st as *mut i32 as u64, 1, 0, 0, 0]), -le::ECHILD);
        // It exits 5: wait4(-1) reaps it with the Linux status for an exit.
        r.native().0.borrow_mut().ended.insert(77, 5);
        assert_eq!(call(&r, nr::WAIT4, [u64::MAX, &mut st as *mut i32 as u64, 0, 0, 0, 0]), 77);
        assert_eq!(st, 5 << 8);
        // And it is gone: nothing left to wait for.
        assert_eq!(call(&r, nr::WAIT4, [u64::MAX, &mut st as *mut i32 as u64, 0, 0, 0, 0]), -le::ECHILD);
    }

    #[test]
    fn a_vfork_with_no_new_stack_is_a_fork_and_one_with_a_stack_is_not_answered() {
        use lx::clone::*;
        let r = rt();
        r.native().0.borrow_mut().fork_result = 9;
        assert_eq!(call(&r, nr::CLONE, [CLONE_VM | CLONE_VFORK | 17, 0, 0, 0, 0, 0]), 9);
        assert_eq!(call(&r, nr::CLONE, [CLONE_VM | CLONE_VFORK | 17, 0x1000, 0, 0, 0, 0]), -le::ENOSYS);
    }

    #[test]
    fn the_forked_child_has_its_own_id_its_parents_as_ppid_and_no_children() {
        let r = rt();
        assert_eq!(call(&r, nr::GETPPID, [0; 6]), 1, "a process the shell started");
        r.native().0.borrow_mut().fork_result = 0;
        r.native().0.borrow_mut().child_pid_after_fork = 43;
        // A child of its own, forked earlier in the parent, is not the new child's.
        assert_eq!(call(&r, nr::CLONE, [17, 0, 0, 0, 0, 0]), 0);
        assert_eq!(call(&r, nr::GETPID, [0; 6]), 43);
        assert_eq!(call(&r, nr::GETPPID, [0; 6]), 42);
        assert_eq!(call(&r, nr::WAIT4, [u64::MAX, 0, 1, 0, 0, 0]), -le::ECHILD);
    }

    #[test]
    fn a_descriptor_survives_the_fork_the_native_fork_keeps_the_handle() {
        let r = rt();
        let path = c("/fat/HELLO.ELF");
        let fd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&path), 0, 0, 0, 0]);
        r.native().0.borrow_mut().fork_result = 0;
        r.native().0.borrow_mut().child_pid_after_fork = 50;
        assert_eq!(call(&r, nr::CLONE, [17, 0, 0, 0, 0, 0]), 0);
        // The same descriptor, the same handle: the child reads where it is.
        let mut buf = [0u8; 4];
        assert_eq!(call(&r, nr::READ, [fd as u64, buf.as_mut_ptr() as u64, 4, 0, 0, 0]), 4);
        assert_eq!(&buf, b"\x7fELF");
    }

    #[test]
    fn exit_ends_the_process_with_the_low_byte() {
        let r = rt();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            call(&r, nr::EXIT_GROUP, [0x1ff, 0, 0, 0, 0, 0])
        }));
        assert!(res.is_err());
        assert_eq!(r.native().0.borrow().exited, Some(0xff));
    }

    #[test]
    fn the_runtime_lists_its_own_native_calls() {
        use azos_abi::syscall_nr::*;
        for n in [SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME, SYS_FOREIGN_FORK, SYS_GETPID, SYS_INVOKE] {
            assert!(azos_linux_rt::RUNTIME_NATIVE.contains(&(n as u16)), "{n}");
        }
    }

    /// The runtime image is linked where the kernel maps it: the linker
    /// scripts' load address is `azos_abi::foreign::RUNTIME_BASE`, on both ISAs
    /// that host the personality. A drift would load the image nowhere and
    /// fail every Linux spawn.
    #[test]
    fn the_linker_scripts_load_the_runtime_where_the_kernel_maps_it() {
        use azos_abi::foreign::{RUNTIME_BASE, RUNTIME_LIMIT};
        for (name, src) in [
            ("user.ld", include_str!("../../../../userspace/services/lxrt/user.ld")),
            ("user_aarch64.ld", include_str!("../../../../userspace/services/lxrt/user_aarch64.ld")),
        ] {
            let at = src
                .lines()
                .find_map(|l| l.trim().strip_prefix(". = 0x").and_then(|r| r.split(';').next()))
                .unwrap_or_else(|| panic!("{name}: no `. = 0x...;` load address"));
            assert_eq!(usize::from_str_radix(at, 16).unwrap(), RUNTIME_BASE, "{name}");
        }
        assert!(RUNTIME_LIMIT > RUNTIME_BASE);
        assert_eq!(RUNTIME_BASE % 4096, 0);
    }
}
