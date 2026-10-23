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
        /// The offsets the kernel publishes (the vDSO's clock words).
        offsets: azos_abi::time::ClockOffsets,
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
        /// Where the next anonymous mapping goes (the kernel places them one
        /// after the other); the lengths unmapped.
        map_next: u64,
        unmapped: Vec<(u64, u64)>,
        /// A write to a pipe answers `-EPIPE` (no reader left).
        broken_pipes: bool,
        /// `handle_set_nonblock` calls, in order.
        nonblock: Vec<(u32, bool)>,
        /// `resume_with_thread_pointer`: what a failed create answers (0: the
        /// resume happens, modelled as a panic, the call not returning), and
        /// each call's (thread pointer, result register of the frame).
        resume_fails: i64,
        resumed: Vec<(u64, u64)>,
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
        fn clock_ns(&self, id: azos_abi::time::ClockId) -> Result<u64, azos_abi::time::ClockError> {
            let offsets = self.0.borrow().offsets;
            azos_abi::time::clock_now_with(id, || self.now_ns(), || offsets)
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
            if pipe.is_some() && m.broken_pipes {
                return -32;
            }
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
        fn handle_is_pipe(&self, h: u32) -> bool {
            // The model names a pipe end by the kind of its handle (a pipe is a
            // shared region; the runtime's tokens are not capabilities).
            CapHandle::from_raw(h).kind() == ty::SHM.raw()
        }
        fn handle_set_nonblock(&self, h: u32, on: bool) {
            self.0.borrow_mut().nonblock.push((h, on));
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
        fn page_size(&self) -> u64 {
            4096
        }
        fn mmap(&self, _addr: u64, len: u64, _prot: u64, _flags: u64) -> i64 {
            let mut m = self.0.borrow_mut();
            let at = m.map_next;
            m.map_next += (len + 4095) & !4095;
            at as i64
        }
        fn munmap(&self, addr: u64, len: u64) -> i64 {
            self.0.borrow_mut().unmapped.push((addr, len));
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
        fn resume_with_thread_pointer(&self, frame: &ForeignFrame, tp: u64) -> i64 {
            let fails = {
                let mut m = self.0.borrow_mut();
                m.resumed.push((tp, frame.gpr[0]));
                m.resume_fails
            };
            if fails != 0 {
                return fails;
            }
            panic!("resumed on a thread with fs {tp:#x}");
        }
    }

    fn model() -> Model {
        let mut m = Model::default();
        m.files.insert(b"/fat/HELLO.ELF".to_vec(), b"\x7fELF-and-more-bytes".to_vec());
        m.files.insert(b"/fat/OTHER.TXT".to_vec(), b"abc".to_vec());
        m.dirs.push(b"/fat".to_vec());
        m.denied_prefix = b"/fat/NEW".to_vec();
        m.pid = 42;
        m.map_next = 0x4000_0000;
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
        let (pipe_h, file_h) = (handle(ty::SHM, 5), handle(ty::FILE, 6));
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
        let fd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&dir), lx::oflag::o_directory(lx::Arch::native().unwrap()), 0, 0, 0]);
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

    /// A write to a pipe with no reader left (`-EPIPE` from the native pipe):
    /// the SIGPIPE default ends the writer with 128 + 13, as the kernel's own
    /// personality did; ignored or blocked, the call only fails.
    #[test]
    fn a_write_to_a_broken_pipe_raises_sigpipe_by_default() {
        let r = rt();
        let mut fds = [0u32; 2];
        assert_eq!(call(&r, nr::PIPE2, [fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0]), 0);
        r.native().0.borrow_mut().broken_pipes = true;
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            call(&r, nr::WRITE, [fds[1] as u64, p(b"x"), 1, 0, 0, 0])
        }));
        assert!(res.is_err(), "the default action ended the process");
        assert_eq!(r.native().0.borrow().exited, Some(128 + 13));
    }

    #[test]
    fn sigpipe_ignored_or_blocked_leaves_epipe() {
        let r = rt();
        let mut fds = [0u32; 2];
        assert_eq!(call(&r, nr::PIPE2, [fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0]), 0);
        r.native().0.borrow_mut().broken_pipes = true;
        // SIG_IGN.
        let act = [1u64, 0, 0, 0];
        assert_eq!(call(&r, nr::RT_SIGACTION, [13, act.as_ptr() as u64, 0, 8, 0, 0]), 0);
        assert_eq!(call(&r, nr::WRITE, [fds[1] as u64, p(b"x"), 1, 0, 0, 0]), -le::EPIPE);
        assert_eq!(r.native().0.borrow().exited, None);
        // Back to the default, but blocked.
        let dfl = [0u64, 0, 0, 0];
        assert_eq!(call(&r, nr::RT_SIGACTION, [13, dfl.as_ptr() as u64, 0, 8, 0, 0]), 0);
        let set = 1u64 << 12;
        assert_eq!(call(&r, nr::RT_SIGPROCMASK, [0, &set as *const u64 as u64, 0, 8, 0, 0]), 0);
        assert_eq!(call(&r, nr::WRITE, [fds[1] as u64, p(b"x"), 1, 0, 0, 0]), -le::EPIPE);
        assert_eq!(r.native().0.borrow().exited, None);
    }

    #[test]
    fn setfl_on_a_pipe_end_reaches_the_native_pipe() {
        let r = rt();
        let mut fds = [0u32; 2];
        assert_eq!(call(&r, nr::PIPE2, [fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0]), 0);
        let rd = fds[0] as u64;
        assert_eq!(call(&r, nr::FCNTL, [rd, lx::fcntl::F_SETFL, lx::oflag::O_NONBLOCK, 0, 0, 0]), 0);
        assert_eq!(call(&r, nr::FCNTL, [rd, lx::fcntl::F_GETFL, 0, 0, 0, 0]) as u64 & lx::oflag::O_NONBLOCK, lx::oflag::O_NONBLOCK);
        let n = r.native().0.borrow().nonblock.clone();
        assert_eq!(n.len(), 1, "one description changed");
        assert!(n[0].1);
        // A file is not a pipe: nothing reaches the pipe.
        let file = c("/fat/HELLO.ELF");
        let ffd = call(&r, nr::OPENAT, [lx::AT_FDCWD, p(&file), 0, 0, 0, 0]);
        assert_eq!(call(&r, nr::FCNTL, [ffd as u64, lx::fcntl::F_SETFL, lx::oflag::O_NONBLOCK, 0, 0, 0]), 0);
        assert_eq!(r.native().0.borrow().nonblock.len(), 1);
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
        let size = lx::KSigaction::size(lx::Arch::native().unwrap());
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

    /// Every Linux clock id the personality answers reads its native clock:
    /// CLOCK_TAI and CLOCK_BOOTTIME add the offsets the kernel published to
    /// the monotonic reading, the others do not move. An id nothing serves
    /// (CPU time, unknown) is -EINVAL. **Canary:** serving TAI as MONO fails
    /// the `tai` row; an unknown id answering 0 fails the last two.
    #[test]
    fn clock_ids_read_their_native_clock() {
        let r = rt();
        r.native().0.borrow_mut().offsets =
            azos_abi::time::ClockOffsets { real: 5_000_000_000, tai: 5_000_000_000 + 37_000_000_000, boot: 3_000_000_000 };
        let read = |id: u64| {
            let mut ts = [0u8; 16];
            let rc = call(&r, nr::CLOCK_GETTIME, [id, ts.as_mut_ptr() as u64, 0, 0, 0, 0]);
            (rc, lx::timespec_ns(&ts))
        };
        let sec = |ns: Option<u64>| ns.unwrap() / 1_000_000_000;
        assert_eq!(sec(read(1).1), 0, "monotonic");
        assert_eq!(sec(read(4).1), 0, "monotonic raw");
        assert_eq!(sec(read(6).1), 0, "monotonic coarse");
        assert_eq!(sec(read(0).1), 5, "realtime");
        assert_eq!(sec(read(5).1), 5, "realtime coarse");
        assert_eq!(sec(read(7).1), 3, "boottime includes the suspended time");
        assert_eq!(sec(read(11).1), 42, "tai is realtime plus the leap offset");
        for id in [2u64, 3, 8, 9, 10, 12, 99] {
            assert_eq!(read(id).0, -le::EINVAL, "clock {id}");
        }
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
        // The break: asked, it is where the first page was mapped; it grows
        // by mapping what is missing next to the run; it never shrinks.
        let base = call(&r, nr::BRK, [0, 0, 0, 0, 0, 0]);
        assert_eq!(base, 0x4000_0000);
        assert_eq!(call(&r, nr::BRK, [base as u64 + 10_000, 0, 0, 0, 0, 0]), base + 10_000);
        assert_eq!(call(&r, nr::BRK, [base as u64 + 100, 0, 0, 0, 0, 0]), base + 10_000);
        assert_eq!(call(&r, nr::BRK, [0, 0, 0, 0, 0, 0]), base + 10_000);
        let ok = call(&r, nr::MMAP, [0, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0]);
        assert!(ok > 0);
        // A mapping of the program's own now sits where the break would grow:
        // the break stays, and the pages the attempt mapped are given back.
        assert_eq!(call(&r, nr::BRK, [base as u64 + 40_000, 0, 0, 0, 0, 0]), base + 10_000);
        assert_eq!(r.native().0.borrow().unmapped.len(), 1);
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
        for n in [SYS_FOREIGN_ENTRY, SYS_FOREIGN_RESUME, SYS_FOREIGN_FORK, SYS_GETPID, SYS_INVOKE, SYS_CAP_INFO] {
            assert!(azos_linux_rt::RUNTIME_NATIVE.contains(&(n as u16)), "{n}");
        }
    }

    /// The runtime image is linked where the kernel maps it: lxrt's build
    /// script hands the linker `azos_abi::foreign::RUNTIME_BASE` itself as the
    /// image base, on every ISA that hosts the personality (no linker script
    /// carries a copy of it). A drift would load the image nowhere and fail
    /// every Linux spawn.
    #[test]
    fn the_runtime_is_linked_where_the_kernel_maps_it() {
        use azos_abi::foreign::{RUNTIME_BASE, RUNTIME_LIMIT};
        let build = include_str!("../../../../userspace/services/lxrt/build.rs");
        assert!(
            build.contains(r#"--image-base={:#x}", azos_abi::foreign::RUNTIME_BASE"#),
            "lxrt/build.rs does not link the runtime at azos_abi::foreign::RUNTIME_BASE"
        );
        assert!(RUNTIME_LIMIT > RUNTIME_BASE);
        assert_eq!(RUNTIME_BASE % 4096, 0);
    }

    // ── x86_64: the runtime's x86-64 face (`Runtime::dispatch_x86_64`) ──────
    //
    // Canaries (by hand, 2026-10-17, each reverted): `REG_ARGS[3]` = 1 (rcx
    // for r10): the run dies on a wild pointer (a fourth argument read as
    // 0xdead0001 by the openat row);
    // `stat_from_generic` unshuffled: the stat rows red; the `Post::DupSame`
    // answer dropped: the dup2 row red; the `Sigaction` arm calling the
    // riscv64 layout: the restorer row red. Does not discriminate: which
    // descriptor number a pipe gets (the model hands out the lowest free).

    /// One x86-64 call as a program's `syscall` makes it: the number in rax,
    /// the arguments in rdi rsi rdx r10 r8 r9 (`ForeignFrame` x86_64 order).
    fn xcall(r: &Runtime<Mock>, num: u64, a: [u64; 6]) -> i64 {
        let mut f = ForeignFrame::ZERO;
        f.gpr[0] = num;
        for (i, v) in a.iter().enumerate() {
            f.gpr[[7, 6, 2, 10, 8, 9][i]] = *v;
        }
        // The registers `syscall` clobbers and the unused ones carry noise a
        // wrong register choice would read.
        f.gpr[1] = 0xdead_0001;
        f.gpr[11] = 0xdead_0002;
        r.dispatch_x86_64(&mut f);
        assert_eq!(f.gpr[1], 0xdead_0001, "only rax is written");
        f.gpr[0] as i64
    }

    use lx::x86_64::nr as xnr;

    #[test]
    fn x86_open_fstat_read_close_with_the_x86_struct_stat() {
        let r = rt();
        let path = c("/fat/HELLO.ELF");
        // open(path, O_RDONLY, 0): the older call, no dirfd.
        let fd = xcall(&r, xnr::OPEN, [p(&path), 0, 0, 0, 0, 0]);
        assert_eq!(fd, 3);
        let mut buf = [0u8; 4];
        assert_eq!(xcall(&r, xnr::READ, [fd as u64, buf.as_mut_ptr() as u64, 4, 0, 0, 0]), 4);
        assert_eq!(&buf, b"\x7fELF");
        let mut st = [0xAAu8; 144];
        assert_eq!(xcall(&r, xnr::FSTAT, [fd as u64, st.as_mut_ptr() as u64, 0, 0, 0, 0]), 0);
        // x86-64 `struct stat`: st_nlink@16 (64 bits), st_mode@24, st_size@48.
        assert_eq!(u64::from_le_bytes(st[16..24].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(st[24..28].try_into().unwrap()) & lx::mode::S_IFMT, lx::mode::S_IFREG);
        assert_eq!(i64::from_le_bytes(st[48..56].try_into().unwrap()), 19);
        assert!(st[120..].iter().all(|&b| b == 0), "the 144 bytes are all written");
        assert_eq!(xcall(&r, xnr::CLOSE, [fd as u64, 0, 0, 0, 0, 0]), 0);
        // stat and lstat by path; a missing one is -ENOENT with the buffer untouched.
        for n in [xnr::STAT, xnr::LSTAT] {
            let mut st = [0xAAu8; 144];
            assert_eq!(xcall(&r, n, [p(&path), st.as_mut_ptr() as u64, 0, 0, 0, 0]), 0);
            assert_eq!(i64::from_le_bytes(st[48..56].try_into().unwrap()), 19, "{n}");
            let none = c("/fat/NONE");
            let mut un = [0xAAu8; 144];
            assert_eq!(xcall(&r, n, [p(&none), un.as_mut_ptr() as u64, 0, 0, 0, 0]), -le::ENOENT);
            assert!(un.iter().all(|&b| b == 0xAA), "a failed stat writes nothing");
        }
        // newfstatat(AT_FDCWD, path, buf, 0): the buffer is the third argument.
        let mut st = [0u8; 144];
        assert_eq!(xcall(&r, xnr::NEWFSTATAT, [lx::AT_FDCWD, p(&path), st.as_mut_ptr() as u64, 0, 0, 0]), 0);
        assert_eq!(i64::from_le_bytes(st[48..56].try_into().unwrap()), 19);
    }

    #[test]
    fn x86_openat_and_mmap_read_their_fourth_and_fifth_arguments_from_r10_and_r8() {
        let r = rt();
        let path = c("/fat/NEWFILE");
        // O_CREAT under a denied prefix: the flags (rdx) and the call both arrive.
        assert_eq!(xcall(&r, xnr::OPENAT, [lx::AT_FDCWD, p(&path), lx::oflag::O_CREAT | 1, 0o644, 0, 0]), -le::EACCES);
        // mmap(0, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0):
        // the flags are r10; executable memory is refused, a file mapping is not answered.
        use lx::mman::*;
        let x = xcall(&r, xnr::MMAP, [0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0]);
        assert_eq!(x, -le::EINVAL);
        let ok = xcall(&r, xnr::MMAP, [0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0]);
        assert!(ok > 0);
        assert_eq!(xcall(&r, xnr::MUNMAP, [ok as u64, 8192, 0, 0, 0, 0]), 0);
    }

    #[test]
    fn x86_pipe_dup2_and_the_dup2_onto_itself() {
        let r = rt();
        let mut fds = [0i32; 2];
        assert_eq!(xcall(&r, xnr::PIPE, [fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0]), 0);
        assert!(fds[0] >= 3 && fds[1] >= 3 && fds[0] != fds[1]);
        assert_eq!(xcall(&r, xnr::WRITE, [fds[1] as u64, p(b"ping"), 4, 0, 0, 0]), 4);
        // dup2(read end, 9) then read from 9.
        assert_eq!(xcall(&r, xnr::DUP2, [fds[0] as u64, 9, 0, 0, 0, 0]), 9);
        let mut b = [0u8; 4];
        assert_eq!(xcall(&r, xnr::READ, [9, b.as_mut_ptr() as u64, 4, 0, 0, 0]), 4);
        assert_eq!(&b, b"ping");
        // dup2(fd, fd) is `fd` when open (dup3 would say -EINVAL), -EBADF when not.
        assert_eq!(xcall(&r, xnr::DUP2, [9, 9, 0, 0, 0, 0]), 9);
        assert_eq!(xcall(&r, xnr::DUP2, [12, 12, 0, 0, 0, 0]), -le::EBADF);
        // dup(fd) is the lowest free descriptor.
        let used = [0, 1, 2, fds[0] as i64, fds[1] as i64, 9];
        let lowest = (0..).find(|n| !used.contains(n)).unwrap();
        assert_eq!(xcall(&r, xnr::DUP, [fds[0] as u64, 0, 0, 0, 0, 0]), lowest);
    }

    #[test]
    fn x86_uname_says_x86_64() {
        let r = rt();
        let mut u = [0u8; lx::UTSNAME_SIZE];
        assert_eq!(xcall(&r, xnr::UNAME, [u.as_mut_ptr() as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(&u[..5], b"Linux");
        assert_eq!(&u[4 * 65..4 * 65 + 7], b"x86_64\0");
    }

    #[test]
    fn x86_fork_vfork_and_wait4() {
        let r = rt();
        r.native().0.borrow_mut().fork_result = 77;
        assert_eq!(xcall(&r, xnr::FORK, [0; 6]), 77);
        r.native().0.borrow_mut().fork_result = 78;
        assert_eq!(xcall(&r, xnr::VFORK, [0; 6]), 78);
        let mut st = -1i32;
        r.native().0.borrow_mut().ended.insert(77, 5);
        assert_eq!(xcall(&r, xnr::WAIT4, [77, &mut st as *mut i32 as u64, 0, 0, 0, 0]), 77);
        assert_eq!(st, 5 << 8);
        // x86-64 `clone` with a thread's flags is not answered, as on the other ISAs.
        assert_eq!(xcall(&r, xnr::CLONE, [0x7d0f00, 0x1000, 0, 0, 0, 0]), -le::ENOSYS);
    }

    #[test]
    fn x86_rt_sigaction_keeps_the_restorer_in_the_x86_layout() {
        let r = rt();
        // struct sigaction on x86-64: handler@0 flags@8 restorer@16 mask@24.
        let mut act = [0u8; 32];
        act[0..8].copy_from_slice(&0x4000_1000u64.to_le_bytes());
        act[8..16].copy_from_slice(&0x0400_0000u64.to_le_bytes()); // SA_RESTORER
        act[16..24].copy_from_slice(&0x4000_2000u64.to_le_bytes());
        act[24..32].copy_from_slice(&0x8u64.to_le_bytes());
        assert_eq!(xcall(&r, xnr::RT_SIGACTION, [2, act.as_ptr() as u64, 0, 8, 0, 0]), 0);
        let mut old = [0u8; 32];
        assert_eq!(xcall(&r, xnr::RT_SIGACTION, [2, 0, old.as_mut_ptr() as u64, 8, 0, 0]), 0);
        assert_eq!(old, act);
        // The wrong set size is refused.
        assert_eq!(xcall(&r, xnr::RT_SIGACTION, [2, 0, old.as_mut_ptr() as u64, 4, 0, 0]), -le::EINVAL);
    }

    #[test]
    fn x86_unanswered_calls_are_enosys_under_their_own_number() {
        let r = rt();
        // lseek is 8 here (62 is kill in the asm-generic table and lseek's number there).
        assert_eq!(xcall(&r, xnr::LSEEK, [3, 0, 0, 0, 0, 0]), -le::ENOSYS);
        let console = String::from_utf8(r.native().0.borrow().console.clone()).unwrap();
        assert!(console.contains("syscall 8 not answered"), "{console}");
    }

    /// `arch_prctl(ARCH_SET_FS)` resumes the program on a thread started with
    /// the base, the frame already carrying the call's 0; the call does not
    /// come back, and `ARCH_GET_FS` then answers the base.
    ///
    /// **Canary.** Write the result after the resume (or not at all): the
    /// recorded result register is the call number, red.
    #[test]
    fn x86_arch_prctl_set_fs_resumes_on_a_thread_with_the_base() {
        let r = rt();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            xcall(&r, xnr::ARCH_PRCTL, [0x1002, 0x7f00_1000, 0, 0, 0, 0])
        }));
        assert!(res.is_err(), "a set that worked must not return to the trapping thread");
        assert_eq!(r.native().0.borrow().resumed, vec![(0x7f00_1000, 0)]);
        let mut base = 0u64;
        assert_eq!(xcall(&r, xnr::ARCH_PRCTL, [0x1003, &mut base as *mut u64 as u64, 0, 0, 0, 0]), 0);
        assert_eq!(base, 0x7f00_1000);
    }

    /// A set no thread could be made for answers the native error, and the
    /// old base stays; a non-canonical base is `-EPERM` without a create, an
    /// unknown code `-EINVAL`.
    #[test]
    fn x86_arch_prctl_refusals() {
        let r = rt();
        r.native().0.borrow_mut().resume_fails = -11;
        assert_eq!(xcall(&r, xnr::ARCH_PRCTL, [0x1002, 0x7f00_1000, 0, 0, 0, 0]), -le::EAGAIN);
        let mut base = 1u64;
        assert_eq!(xcall(&r, xnr::ARCH_PRCTL, [0x1003, &mut base as *mut u64 as u64, 0, 0, 0, 0]), 0);
        assert_eq!(base, 0, "a failed set left the base it replaced");
        assert_eq!(xcall(&r, xnr::ARCH_PRCTL, [0x1002, 1 << 47, 0, 0, 0, 0]), -le::EPERM);
        assert_eq!(r.native().0.borrow().resumed.len(), 1, "a refused base made a thread");
        assert_eq!(xcall(&r, xnr::ARCH_PRCTL, [0x1001, 0, 0, 0, 0, 0]), -le::EINVAL);
        assert_eq!(xcall(&r, xnr::ARCH_PRCTL, [0x1003, 0, 0, 0, 0, 0]), -le::EFAULT);
    }

    #[test]
    fn x86_every_translated_call_is_answered_by_the_runtime() {
        // A translated number the runtime's own match does not know would
        // fall to its `unanswered` and print a report: none may, at any argument.
        for n in 0..1024u64 {
            if lx::x86_64::translate(n, [0; 6]).is_none() || n == xnr::EXIT || n == xnr::EXIT_GROUP {
                continue;
            }
            let r = rt();
            let _ = xcall(&r, n, [0; 6]);
            let console = String::from_utf8(r.native().0.borrow().console.clone()).unwrap();
            assert!(!console.contains("not answered"), "x86-64 call {n} reached the runtime's unanswered path: {console}");
        }
    }

    #[test]
    fn x86_identity_and_exit() {
        let r = rt();
        assert_eq!(xcall(&r, xnr::GETPID, [0; 6]), 42);
        assert_eq!(xcall(&r, xnr::GETTID, [0; 6]), 42);
        assert_eq!(xcall(&r, xnr::GETUID, [0; 6]), 0);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| xcall(&r, xnr::EXIT_GROUP, [3, 0, 0, 0, 0, 0])));
        assert!(res.is_err());
        assert_eq!(r.native().0.borrow().exited, Some(3));
    }
}
