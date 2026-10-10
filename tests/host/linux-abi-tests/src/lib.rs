// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `crates/core/linux-abi` (RFC-0047): the layouts the
//! Linux personality writes into a Linux task's memory, read back the way a
//! static musl binary reads them, and the translation table's invariants.

#[cfg(test)]
mod tests {
    use azos_linux_abi::*;

    fn u64_at(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }

    /// Read the initial stack back as musl's `__init_libc`/`_start_c` does:
    /// argc, argv until NULL, envp until NULL, then auxv pairs to AT_NULL.
    #[test]
    fn initial_stack_reads_back_as_musl_reads_it() {
        let base = 0x7fff_0000u64;
        let mut buf = [0u8; 1024];
        let aux = ImageAux { phdr: 0x10040, phent: 56, phnum: 4, entry: 0x10100, pagesz: 4096 };
        let random = [7u8; 16];
        let sp = layout_initial_stack(&mut buf, base, b"lxhello\0one\0", 2, b"PATH=/fat\0", 1, &random, &aux)
            .expect("fits");
        assert_eq!(sp % 16, 0, "sp is 16-byte aligned at _start");
        let at = |addr: u64| (addr - base) as usize;
        let cstr = |addr: u64| {
            let s = &buf[at(addr)..];
            &s[..s.iter().position(|&b| b == 0).unwrap()]
        };
        let mut p = at(sp);
        assert_eq!(u64_at(&buf, p), 2);
        p += 8;
        assert_eq!(cstr(u64_at(&buf, p)), b"lxhello");
        assert_eq!(cstr(u64_at(&buf, p + 8)), b"one");
        assert_eq!(u64_at(&buf, p + 16), 0);
        p += 24;
        assert_eq!(cstr(u64_at(&buf, p)), b"PATH=/fat");
        assert_eq!(u64_at(&buf, p + 8), 0);
        p += 16;
        let mut seen = std::collections::HashMap::new();
        loop {
            let (k, v) = (u64_at(&buf, p), u64_at(&buf, p + 8));
            p += 16;
            if k == at::NULL {
                break;
            }
            seen.insert(k, v);
        }
        assert_eq!(seen[&at::PHDR], 0x10040);
        assert_eq!(seen[&at::PHNUM], 4);
        assert_eq!(seen[&at::PHENT], 56);
        assert_eq!(seen[&at::PAGESZ], 4096);
        assert_eq!(seen[&at::ENTRY], 0x10100);
        assert_eq!(seen[&at::SECURE], 0);
        let r = seen[&at::RANDOM];
        assert_eq!(&buf[at(r)..at(r) + 16], &random);
        assert_eq!(cstr(seen[&at::EXECFN]), b"lxhello");
        // Everything the block names lies inside the buffer, above sp.
        assert!(p <= at(r), "pointer block does not run into the random bytes");
    }

    /// No program header address is reported when no `PT_LOAD` maps the
    /// headers: musl would read unmapped memory through `AT_PHDR`.
    #[test]
    fn at_phdr_is_left_out_when_it_is_zero() {
        let mut buf = [0u8; 512];
        let aux = ImageAux { phdr: 0, phent: 56, phnum: 1, entry: 0x10000, pagesz: 4096 };
        let sp = layout_initial_stack(&mut buf, 0x1000, b"a\0", 1, b"", 0, &[0; 16], &aux).unwrap();
        let mut p = (sp - 0x1000) as usize + 8 + 16 + 8;
        loop {
            let k = u64_at(&buf, p);
            assert_ne!(k, at::PHDR);
            if k == at::NULL {
                break;
            }
            p += 16;
        }
    }

    #[test]
    fn initial_stack_refuses_a_bad_blob_or_too_little_room() {
        let aux = ImageAux::default();
        let mut buf = [0u8; 1024];
        assert!(layout_initial_stack(&mut buf, 0x1000, b"a\0b", 2, b"", 0, &[0; 16], &aux).is_none());
        assert!(layout_initial_stack(&mut buf, 0x1000, b"a\0", 2, b"", 0, &[0; 16], &aux).is_none());
        assert!(layout_initial_stack(&mut buf, 0x1008, b"a\0", 1, b"", 0, &[0; 16], &aux).is_none());
        let mut small = [0u8; 64];
        assert!(layout_initial_stack(&mut small, 0x1000, b"a\0", 1, b"", 0, &[0; 16], &aux).is_none());
    }

    fn elf_with(phoff: u64, loads: &[(u32, u64, u64, u64)]) -> Vec<u8> {
        let mut e = vec![0u8; 4096];
        e[0..4].copy_from_slice(b"\x7fELF");
        e[4] = 2;
        e[5] = 1;
        e[24..32].copy_from_slice(&0x10100u64.to_le_bytes());
        e[32..40].copy_from_slice(&phoff.to_le_bytes());
        e[54..56].copy_from_slice(&56u16.to_le_bytes());
        e[56..58].copy_from_slice(&(loads.len() as u16).to_le_bytes());
        for (i, &(t, off, va, filesz)) in loads.iter().enumerate() {
            let at = phoff as usize + i * 56;
            e[at..at + 4].copy_from_slice(&t.to_le_bytes());
            e[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            e[at + 16..at + 24].copy_from_slice(&va.to_le_bytes());
            e[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
        }
        e
    }

    #[test]
    fn at_phdr_comes_from_the_load_segment_that_maps_the_headers() {
        // Headers at file offset 64, inside a PT_LOAD of offset 0 at 0x10000.
        let e = elf_with(64, &[(1, 0, 0x10000, 0x800), (1, 0x1000, 0x11000, 0x100)]);
        let a = image_aux(&e, 4096).unwrap();
        assert_eq!(a.phdr, 0x10040);
        assert_eq!((a.phnum, a.phent, a.entry), (2, 56, 0x10100));
        // Headers outside every PT_LOAD: 0, never a guess.
        let e = elf_with(64, &[(1, 0x1000, 0x11000, 0x100)]);
        assert_eq!(image_aux(&e, 4096).unwrap().phdr, 0);
        // A PT_PHDR alone does not count: nothing maps it.
        let e = elf_with(64, &[(6, 64, 0x10040, 112), (1, 0x1000, 0x11000, 0x100)]);
        assert_eq!(image_aux(&e, 4096).unwrap().phdr, 0);
    }

    #[test]
    fn stat_layout_matches_the_asm_generic_offsets() {
        let s = Stat { dev: 1, ino: 2, mode: mode::S_IFREG | 0o644, nlink: 1, size: 1234, blksize: 512,
            blocks: 3, atime: 10, mtime: 11, ctime: 12, rdev: 0 };
        let b = s.to_bytes();
        assert_eq!(b.len(), 128);
        assert_eq!(u64_at(&b, 8), 2);
        assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), mode::S_IFREG | 0o644);
        assert_eq!(u64_at(&b, 48), 1234);
        assert_eq!(u64_at(&b, 64), 3);
        assert_eq!(u64_at(&b, 88), 11);
    }

    #[test]
    fn dirent64_records_are_8_aligned_and_nul_terminated() {
        let mut b = [0xffu8; 64];
        let n = encode_dirent64(&mut b, 5, 1, DT_REG, b"HELLO.TXT").unwrap();
        assert_eq!(n, 32); // 19 + 9 + 1 = 29 -> 32
        assert_eq!(u16::from_le_bytes([b[16], b[17]]) as usize, n);
        assert_eq!(b[18], DT_REG);
        assert_eq!(&b[19..28], b"HELLO.TXT");
        assert_eq!(b[28], 0);
        let mut tiny = [0u8; 16];
        assert!(encode_dirent64(&mut tiny, 1, 1, DT_DIR, b"X").is_none());
    }

    #[test]
    fn open_flags_differ_per_isa_only_where_musl_says() {
        // O_DIRECTORY: 0o200000 generic, 0o40000 aarch64.
        let rv = open_flags(0o200000, Arch::Riscv64).unwrap();
        assert!(rv.directory);
        let arm = open_flags(0o40000, Arch::Aarch64).unwrap();
        assert!(arm.directory);
        // On riscv64 0o40000 is O_DIRECT, which the personality refuses.
        assert!(open_flags(0o40000, Arch::Riscv64).is_none());
        let w = open_flags(1 | oflag::O_CREAT | oflag::O_TRUNC | oflag::O_CLOEXEC, Arch::Riscv64).unwrap();
        assert_eq!(w.native, 1 | 0x40 | 0x200);
        assert!(open_flags(3, Arch::Riscv64).is_none());
        assert!(open_flags(oflag::O_CREAT | oflag::O_EXCL, Arch::Aarch64).is_none());
    }

    #[test]
    fn native_errnos_map_to_linux_ones() {
        use azos_abi::error::Errno as N;
        assert_eq!(errno_from_native(5, errno::EIO), 5);
        assert_eq!(errno_from_native(-1, errno::ENOENT), -errno::ENOENT);
        assert_eq!(errno_from_native(-(N::EACCES as i64), errno::EIO), -errno::EACCES);
        assert_eq!(errno_from_native(-(N::ECAPSTALE as i64), errno::EIO), -errno::EBADF);
        assert_eq!(errno_from_native(-(N::ECAPPERMS as i64), errno::EIO), -errno::EACCES);
        assert_eq!(errno_from_native(-(N::ENOTOWNER as i64), errno::EIO), -errno::EPERM);
        assert_eq!(errno_from_native(-250, errno::EIO), -errno::EIO);
    }

    #[test]
    fn the_table_has_one_row_per_number_and_reaches_no_retired_call() {
        let mut seen = std::collections::HashSet::new();
        for &(n, name, reach) in TABLE {
            assert!(seen.insert(n), "{name} ({n}) listed twice");
            assert_eq!(number_of(name), Some(n));
            for &r in reach {
                assert!(!azos_abi::syscall_nr::RETIRED_SYSCALLS.contains(&(r as u64)),
                    "{name} reaches retired native call {r}");
            }
        }
        // The numbers the brief names (RFC-0047 stage 1 + the BusyBox set).
        for n in [nr::READ, nr::WRITE, nr::OPENAT, nr::CLOSE, nr::FSTAT, nr::LSEEK, nr::MMAP,
                  nr::MUNMAP, nr::BRK, nr::EXIT_GROUP, nr::WAIT4, nr::PIPE2, nr::DUP3,
                  nr::GETDENTS64, nr::IOCTL, nr::RT_SIGACTION, nr::RT_SIGPROCMASK, nr::UNAME,
                  nr::GETPID, nr::CLOCK_GETTIME, nr::NANOSLEEP] {
            assert!(native_reach(n).is_some(), "{n} not answered");
        }
        // The canary the RFC names: 17 is SYS_SPAWN natively and getcwd here.
        assert_eq!(nr::GETCWD, azos_abi::syscall_nr::SYS_SPAWN);
        assert_eq!(native_reach(17), Some(&[][..]));
    }

    #[test]
    fn sigaction_layout_has_a_restorer_only_on_aarch64() {
        let s = KSigaction { handler: 0x1234, flags: 0x0400_0000, restorer: 0x5678, mask: 1 << 1 };
        let rv = s.to_bytes(Arch::Riscv64);
        assert_eq!(u64_at(&rv, 16), 2);
        let back = KSigaction::from_bytes(&rv[..24], Arch::Riscv64).unwrap();
        assert_eq!((back.handler, back.mask, back.restorer), (0x1234, 2, 0));
        let arm = s.to_bytes(Arch::Aarch64);
        assert_eq!(u64_at(&arm, 16), 0x5678);
        assert_eq!(KSigaction::from_bytes(&arm, Arch::Aarch64).unwrap(), s);
        assert!(KSigaction::from_bytes(&arm[..24], Arch::Aarch64).is_none());
    }

    #[test]
    fn paths_join_lexically() {
        let mut o = [0u8; 64];
        let n = join_path(b"/fat", b"X.TXT", &mut o).unwrap();
        assert_eq!(&o[..n], b"/fat/X.TXT");
        let n = join_path(b"/fat/sub", b"../Y", &mut o).unwrap();
        assert_eq!(&o[..n], b"/fat/Y");
        let n = join_path(b"/fat", b"/tmp/./a", &mut o).unwrap();
        assert_eq!(&o[..n], b"/tmp/a");
        let n = join_path(b"/", b"..", &mut o).unwrap();
        assert_eq!(&o[..n], b"/");
        let n = join_path(b"/fat", b".", &mut o).unwrap();
        assert_eq!(&o[..n], b"/fat");
        assert!(join_path(b"/fat", b"", &mut o).is_none());
        let mut tiny = [0u8; 4];
        assert!(join_path(b"/fat", b"LONGNAME", &mut tiny).is_none());
    }

    #[test]
    fn timespecs_round_trip_and_refuse_bad_nanoseconds() {
        let b = timespec_bytes(3_000_000_007);
        assert_eq!(timespec_ns(&b), Some(3_000_000_007));
        let mut bad = timespec_bytes(0);
        bad[8..16].copy_from_slice(&1_000_000_000i64.to_le_bytes());
        assert_eq!(timespec_ns(&bad), None);
        assert_eq!(wait_status(3), 0x300);
        assert_eq!(wait_status(130), 130 << 8);
    }

    #[test]
    fn utsname_and_tty_layouts() {
        let u = utsname_bytes(Arch::Aarch64, b"azos");
        assert_eq!(&u[0..5], b"Linux");
        assert_eq!(&u[65..70], b"azos\0");
        assert_eq!(&u[4 * 65..4 * 65 + 7], b"aarch64");
        let w = winsize_bytes(24, 80);
        assert_eq!(u16::from_le_bytes([w[2], w[3]]), 80);
        let t = termios_bytes();
        assert_eq!(t[17], 3, "VINTR is ^C");
    }

    // ── Wave 13: signal frames, default actions, the line discipline ────────

    use azos_linux_abi::signal as sg;

    fn ctx_with() -> sg::Context {
        let mut gpr = [0u64; 32];
        for (i, g) in gpr.iter_mut().enumerate() {
            *g = 0x1000 + i as u64;
        }
        sg::Context { gpr, pc: 0x40_1234, pstate: 0x6000_0000 }
    }

    fn bytes(w: &[u64]) -> Vec<u8> {
        w.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// musl's layouts, measured with the toolchain BusyBox is built with
    /// (`zig cc` for riscv64/aarch64-linux-musl): `ucontext_t` 960 / 4560
    /// bytes, `uc_sigmask` at 40, `uc_mcontext` at 176; riscv64's FP state
    /// at 256 into `mcontext_t`; aarch64's `pc` at 264 and `__reserved` at
    /// 288 into it. A handler reads these offsets; a kernel that writes
    /// others hands it garbage.
    #[test]
    fn frame_layout_is_musls() {
        assert_eq!(sg::SIGINFO_SIZE, 128);
        assert_eq!(sg::UC_SIGMASK, 40);
        assert_eq!(sg::UC_MCONTEXT, 176);
        assert_eq!(sg::RV_UC_SIZE, 960);
        assert_eq!(sg::RV_MC_FP, 256);
        assert_eq!(sg::A64_UC_SIZE, 4560);
        assert_eq!(sg::A64_MC_PC, 264);
        assert_eq!(sg::A64_MC_RESERVED, 288);
        assert_eq!(sg::frame_size(Arch::Riscv64), 128 + 960);
        assert_eq!(sg::frame_size(Arch::Aarch64), 128 + 4560 + 16);
        assert_eq!(sg::frame_words(Arch::Riscv64) * 8, 128 + 176 + 256 + 264, "through fcsr");
        assert_eq!(sg::head_words(Arch::Riscv64) * 8, 128 + 176 + 256, "through __gregs");
        assert_eq!(sg::frame_words(Arch::Aarch64) * 8, 128 + 176 + 288 + 528 + 8, "through the null record");
        assert_eq!(sg::head_words(Arch::Aarch64) * 8, 128 + 176 + 288 + 8, "through the first record head");
        assert!(sg::frame_words(Arch::Aarch64) <= sg::FRAME_WORDS_MAX);
        assert_eq!(sg::a64_frame_record_word() * 8, 128 + 4560);
        assert_eq!(sg::fp_words(Arch::Riscv64).start * 8, 128 + 176 + 256);
        assert_eq!(sg::fp_words(Arch::Riscv64).len(), 33);
        assert_eq!(sg::fp_words(Arch::Aarch64).start * 8, 128 + 176 + 288 + 8, "after the record head");
        assert_eq!(sg::fp_words(Arch::Aarch64).len(), 65);
        for a in [Arch::Riscv64, Arch::Aarch64] {
            let b = sg::frame_base(a, 0x7fff_f00c);
            assert_eq!(b % 16, 0);
            assert!(b + sg::frame_size(a) as u64 <= 0x7fff_f00c);
        }
    }

    /// What a handler reads: `si_signo`, `si_pid`, the saved mask, and on
    /// riscv64 `__gregs[0]` = pc, `__gregs[n]` = xn; on aarch64 `regs[n]`,
    /// `sp`, `pc`, `pstate` and an `fpsimd_context` head.
    #[test]
    fn frame_reads_back_where_musl_looks() {
        let info = sg::Info { signo: 10, code: sg::si::USER, pid: 42, status: 0 };
        let c = ctx_with();
        let mask = 0x8000_0000_0000_0201u64;
        let mut w = vec![0xAAAA_AAAA_AAAA_AAAAu64; 1024];
        assert_eq!(sg::write_frame(Arch::Riscv64, &mut w, &c, mask, &info, false), Some(sg::head_words(Arch::Riscv64)));
        let n = sg::head_words(Arch::Riscv64);
        assert!(w[..n].iter().all(|&x| x != 0xAAAA_AAAA_AAAA_AAAA), "every word copied out is written");
        assert!(w[n..].iter().all(|&x| x == 0xAAAA_AAAA_AAAA_AAAA), "nothing past the head without FP");
        assert_eq!(w[16] & sg::RV_UC_FP, 0, "uc_flags: no FP");
        let b = bytes(&w);
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 42);
        let uc = 128;
        assert_eq!(u64_at(&b, uc + 40), mask);
        assert_eq!(u64_at(&b, uc + 176), c.pc, "__gregs[0] is the pc");
        assert_eq!(u64_at(&b, uc + 176 + 8 * 10), c.gpr[10], "__gregs[10] is a0");
        let mut w = vec![0xAAAA_AAAA_AAAA_AAAAu64; 1024];
        assert_eq!(sg::write_frame(Arch::Riscv64, &mut w, &c, mask, &info, true), Some(sg::frame_words(Arch::Riscv64)));
        assert_eq!(w[16] & sg::RV_UC_FP, sg::RV_UC_FP, "uc_flags: FP follows");
        assert!(w[sg::fp_words(Arch::Riscv64)].iter().all(|&x| x == 0xAAAA_AAAA_AAAA_AAAA), "FP words are the caller's");

        let mut w = vec![0xAAAA_AAAA_AAAA_AAAAu64; 1024];
        assert_eq!(sg::write_frame(Arch::Aarch64, &mut w, &c, mask, &info, true), Some(sg::frame_words(Arch::Aarch64)));
        let b = bytes(&w);
        let mc = uc + 176;
        assert_eq!(u64_at(&b, mc + 8 + 8 * 30), c.gpr[30], "regs[30]");
        assert_eq!(u64_at(&b, mc + 256), c.gpr[31], "sp");
        assert_eq!(u64_at(&b, mc + 264), c.pc);
        assert_eq!(u64_at(&b, mc + 272), c.pstate);
        let r = mc + 288;
        assert_eq!(u32::from_le_bytes(b[r..r + 4].try_into().unwrap()), 0x4650_8001, "FPSIMD_MAGIC");
        assert_eq!(u32::from_le_bytes(b[r + 4..r + 8].try_into().unwrap()), 528);
        assert_eq!(u64_at(&b, r + 528), 0, "a null record ends the list");
        assert!(sg::read_frame(Arch::Aarch64, &w).unwrap().2, "the record is read back");
        w[r / 8] = 0;
        assert!(!sg::read_frame(Arch::Aarch64, &w).unwrap().2, "a broken record head is not read");
        let mut w = vec![0xAAAA_AAAA_AAAA_AAAAu64; 1024];
        assert_eq!(sg::write_frame(Arch::Aarch64, &mut w, &c, mask, &info, false), Some(sg::head_words(Arch::Aarch64)));
        assert_eq!(w[r / 8], 0, "without FP the first record is the null one");
        assert!(w[..sg::head_words(Arch::Aarch64)].iter().all(|&x| x != 0xAAAA_AAAA_AAAA_AAAA));
    }

    /// A frame read back is the context written, on both ISAs; the mask
    /// never comes back with SIGKILL/SIGSTOP blocked.
    #[test]
    fn frame_round_trips() {
        for a in [Arch::Riscv64, Arch::Aarch64] {
            let c = ctx_with();
            let mask = u64::MAX;
            let mut w = vec![0u64; sg::frame_words(a)];
            assert!(sg::write_frame(a, &mut w, &c, mask, &sg::Info::default(), true).is_some());
            let (r, m, fp) = sg::read_frame(a, &w).expect("reads");
            assert!(fp);
            let from = if a == Arch::Riscv64 { 1 } else { 0 };
            assert_eq!(&r.gpr[from..], &c.gpr[from..], "{a:?}");
            assert_eq!(r.pc, c.pc);
            assert_eq!(m, mask & !sg::UNBLOCKABLE);
            assert!(sg::read_frame(a, &w[..sg::head_words(a) - 1]).is_none(), "a short frame is refused");
        }
    }

    /// aarch64's PSTATE comes back as N, Z, C, V only (a frame naming EL1 or
    /// masking interrupts is not obeyed). **Canary:** drop the
    /// `& A64_PSTATE_USER_MASK` in `read_frame`: red.
    #[test]
    fn pstate_from_a_frame_is_flags_only() {
        let mut c = ctx_with();
        c.pstate = 0xF000_0000 | 0x3c5; // NZCV + DAIF masked + EL1h
        let mut w = vec![0u64; sg::frame_words(Arch::Aarch64)];
        assert!(sg::write_frame(Arch::Aarch64, &mut w, &c, 0, &sg::Info::default(), false).is_some());
        assert_eq!(sg::read_frame(Arch::Aarch64, &w).unwrap().0.pstate, 0xF000_0000);
    }

    /// The riscv64 trampoline is `li a7, 139; ecall`.
    #[test]
    fn rv_trampoline_encodes_rt_sigreturn() {
        let [li, ecall] = sg::RV_SIGRETURN_CODE;
        assert_eq!(li & 0x7f, 0x13, "OP-IMM");
        assert_eq!((li >> 7) & 0x1f, 17, "rd = a7");
        assert_eq!((li >> 15) & 0x1f, 0, "rs1 = zero");
        assert_eq!(li >> 20, nr::RT_SIGRETURN as u32);
        assert_eq!(ecall, 0x73);
    }

    /// Linux's defaults, with stop and continue discarded (no job control).
    #[test]
    fn default_actions() {
        use sg::DefaultAction::*;
        for s in [1u64, 2, 3, 9, 11, 13, 14, 15, 10, 12, 31, 34, 64] {
            assert_eq!(sg::default_action(s), Terminate, "signal {s}");
        }
        for s in [17u64, 23, 28] {
            assert_eq!(sg::default_action(s), Ignore, "signal {s}");
        }
        for s in [18u64, 19, 20, 21, 22] {
            assert_eq!(sg::default_action(s), StopIgnored, "signal {s}");
        }
        assert_eq!(sg::bit(1), 1);
        assert_eq!(sg::bit(64), 1 << 63);
        assert_eq!(sg::bit(0), 0);
        assert_eq!(sg::bit(65), 0);
    }

    fn feed_all(ld: &mut sg::LineDisc, bytes: &[u8], echo: &mut Vec<u8>) -> Vec<sg::Feed> {
        bytes.iter().map(|&c| ld.feed(c, &mut |e: &[u8]| echo.extend_from_slice(e))).collect()
    }

    /// A line is handed out once complete; CR is NL; DEL and ^U edit; echo
    /// shows what was typed; a short read leaves the rest of the line.
    #[test]
    fn line_discipline_cooks_a_line() {
        let mut ld = sg::LineDisc::new();
        let mut echo = Vec::new();
        let mut out = [0u8; 64];
        feed_all(&mut ld, b"ls", &mut echo);
        assert_eq!(ld.take(&mut out), None, "no line yet");
        feed_all(&mut ld, b"x\x7f /fat\r", &mut echo);
        assert_eq!(ld.take(&mut out), Some(8));
        assert_eq!(&out[..8], b"ls /fat\n");
        assert_eq!(echo, b"lsx\x08 \x08 /fat\n");
        feed_all(&mut ld, b"junk\x15echo hi\n", &mut echo);
        let mut two = [0u8; 4];
        assert_eq!(ld.take(&mut two), Some(4));
        assert_eq!(&two, b"echo");
        assert_eq!(ld.take(&mut out), Some(4));
        assert_eq!(&out[..4], b" hi\n");
        assert_eq!(ld.take(&mut out), None);
    }

    /// ^D on an empty line is end of file (once); after text it ends the
    /// line without a byte. ^C drops the partial line and asks for SIGINT.
    #[test]
    fn line_discipline_eof_and_interrupt() {
        let mut ld = sg::LineDisc::new();
        let mut echo = Vec::new();
        let mut out = [0u8; 64];
        feed_all(&mut ld, b"\x04", &mut echo);
        assert_eq!(ld.take(&mut out), Some(0));
        assert_eq!(ld.take(&mut out), None);
        feed_all(&mut ld, b"ab\x04", &mut echo);
        assert_eq!(ld.take(&mut out), Some(2));
        let f = feed_all(&mut ld, b"half\x03", &mut echo);
        assert_eq!(*f.last().unwrap(), sg::Feed::Signal(2));
        assert_eq!(ld.take(&mut out), None, "the partial line is gone");
        feed_all(&mut ld, b"ok\r", &mut echo);
        assert_eq!(ld.take(&mut out), Some(3));
        assert_eq!(&out[..3], b"ok\n");
    }

    /// A full line still ends at its newline: a reader is never stuck.
    #[test]
    fn line_discipline_full_line_still_ends() {
        let mut ld = sg::LineDisc::new();
        let mut echo = Vec::new();
        let long = vec![b'a'; sg::LINE_MAX + 50];
        feed_all(&mut ld, &long, &mut echo);
        feed_all(&mut ld, b"\r", &mut echo);
        let mut out = vec![0u8; 1024];
        let n = ld.take(&mut out).expect("a line");
        assert_eq!(n, sg::LINE_MAX);
        assert_eq!(out[n - 1], b'\n');
    }

    /// The signal calls a Linux image reaches: `kill`/`tkill`/`tgkill` the
    /// native stop call (its ancestry), `read` the console input call.
    #[test]
    fn signal_calls_reach_the_stop_call() {
        use azos_abi::syscall_nr as k;
        for n in [nr::KILL, nr::TKILL, nr::TGKILL] {
            assert_eq!(native_reach(n), Some(&[k::SYS_TASK_KILL as u16][..]));
        }
        for n in [nr::RT_SIGRETURN, nr::RT_SIGPENDING, nr::SIGALTSTACK] {
            assert_eq!(native_reach(n), Some(&[][..]));
        }
        assert!(native_reach(nr::READ).unwrap().contains(&(k::SYS_CONSOLE_WAIT as u16)));
    }

    /// Wave 13: a child a signal ended reads back as glibc/musl's macros read
    /// it: `WIFSIGNALED`, `WTERMSIG` = the signal; an exit with 128 + n stays
    /// `WIFEXITED` with that code (what a native-style exit looks like).
    #[test]
    fn wait_status_tells_killed_from_exited() {
        let wifexited = |s: i32| s & 0x7f == 0;
        let wexitstatus = |s: i32| (s >> 8) & 0xff;
        let wifsignaled = |s: i32| ((s & 0x7f) + 1) as i8 >> 1 > 0;
        let wtermsig = |s: i32| s & 0x7f;
        let k = wait_status_signalled(15);
        assert!(wifsignaled(k) && !wifexited(k) && wtermsig(k) == 15);
        let e = wait_status(128 + 15);
        assert!(wifexited(e) && !wifsignaled(e) && wexitstatus(e) == 143);
        assert!(wifexited(wait_status(0)) && wexitstatus(wait_status(0)) == 0);
    }
}

/// Wave 15: the robust futex list walked at a Linux thread's exit
/// (`crates/core/linux-abi/src/robust.rs`), over a sparse fake memory.
#[cfg(test)]
mod robust_list {
    use azos_linux_abi::robust::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Mem {
        bytes: BTreeMap<u64, u8>,
        woken: Vec<u64>,
        /// One CAS on this word sees FUTEX_WAITERS set first (a racing waiter).
        race_waiter_on: Option<u64>,
        /// N10: what the PI futex hook answers (`None`: PI futexes off).
        pi_hook: Option<bool>,
        pi_calls: Vec<u64>,
    }
    impl Mem {
        fn put64(&mut self, a: u64, v: u64) {
            for (i, b) in v.to_le_bytes().iter().enumerate() {
                self.bytes.insert(a + i as u64, *b);
            }
        }
        fn put32(&mut self, a: u64, v: u32) {
            for (i, b) in v.to_le_bytes().iter().enumerate() {
                self.bytes.insert(a + i as u64, *b);
            }
        }
        fn get32(&self, a: u64) -> Option<u32> {
            let mut b = [0u8; 4];
            for (i, x) in b.iter_mut().enumerate() {
                *x = *self.bytes.get(&(a + i as u64))?;
            }
            Some(u32::from_le_bytes(b))
        }
    }
    impl RobustMem for Mem {
        fn read_u64(&mut self, a: u64) -> Option<u64> {
            let mut b = [0u8; 8];
            for (i, x) in b.iter_mut().enumerate() {
                *x = *self.bytes.get(&(a.checked_add(i as u64)?))?;
            }
            Some(u64::from_le_bytes(b))
        }
        fn read_u32(&mut self, a: u64) -> Option<u32> {
            self.get32(a)
        }
        fn cas_u32(&mut self, a: u64, old: u32, new: u32) -> Result<(), Option<u32>> {
            let cur = self.get32(a).ok_or(None)?;
            if self.race_waiter_on == Some(a) {
                self.race_waiter_on = None;
                self.put32(a, cur | FUTEX_WAITERS);
                return Err(Some(cur | FUTEX_WAITERS));
            }
            if cur != old {
                return Err(Some(cur));
            }
            self.put32(a, new);
            Ok(())
        }
        fn wake_one(&mut self, a: u64) {
            self.woken.push(a);
        }
        fn pi_owner_died(&mut self, a: u64) -> Option<bool> {
            self.pi_calls.push(a);
            self.pi_hook
        }
    }

    const HEAD: u64 = 0x1000;
    const TID: u32 = 42;
    /// Lock word at entry + OFF (musl's `_m_lock` sits before `_m_next`).
    const OFF: i64 = -8;

    /// head -> entries... -> head, pending as given; word of entry e at e-8.
    fn list(m: &mut Mem, entries: &[u64], pending: u64) {
        let mut prev = HEAD;
        for &e in entries {
            m.put64(prev, e);
            prev = e;
        }
        m.put64(prev, HEAD);
        m.put64(HEAD + 8, OFF as u64);
        m.put64(HEAD + 16, pending);
    }

    /// N10: a held PI word goes to the PI futex code, which writes it and
    /// wakes its new owner; the walk neither writes nor wakes. A PI word of
    /// another owner never reaches the hook; with the hook off (FUTEX_PI n)
    /// the walk marks the word itself and wakes nobody (no PI sleeper).
    #[test]
    fn a_held_pi_word_is_handed_to_the_pi_futex_code() {
        let mut m = Mem { pi_hook: Some(true), ..Default::default() };
        // head -> 0x2008 (PI) -> 0x3008 (PI) -> head; bit 0 marks PI.
        list(&mut m, &[0x2008, 0x3008], 0);
        m.put64(HEAD, 0x2008 | 1);
        m.put64(0x2008, 0x3008 | 1);
        m.put32(0x2000, TID | FUTEX_WAITERS);
        m.put32(0x3000, 77 | FUTEX_WAITERS);
        let w = exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.pi_calls, vec![0x2000]);
        assert_eq!(m.get32(0x2000), Some(TID | FUTEX_WAITERS), "the hook owns the write");
        assert_eq!(m.get32(0x3000), Some(77 | FUTEX_WAITERS));
        assert!(m.woken.is_empty());
        assert_eq!((w.entries, w.owner_died, w.woken), (2, 1, 1));

        let mut m = Mem::default();
        list(&mut m, &[0x2008], 0);
        m.put64(HEAD, 0x2008 | 1);
        m.put32(0x2000, TID | FUTEX_WAITERS);
        let w = exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.pi_calls, vec![0x2000]);
        assert_eq!(m.get32(0x2000), Some(FUTEX_OWNER_DIED | FUTEX_WAITERS));
        assert!(m.woken.is_empty());
        assert_eq!((w.entries, w.owner_died, w.woken), (1, 1, 0));
    }

    #[test]
    fn a_held_contended_word_becomes_owner_died_and_wakes_one() {
        let mut m = Mem::default();
        list(&mut m, &[0x2008], 0);
        m.put32(0x2000, TID | FUTEX_WAITERS);
        let w = exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x2000), Some(FUTEX_OWNER_DIED | FUTEX_WAITERS));
        assert_eq!(m.woken, vec![0x2000]);
        assert_eq!((w.entries, w.owner_died, w.woken), (1, 1, 1));
    }

    #[test]
    fn an_uncontended_word_is_marked_and_wakes_nobody() {
        let mut m = Mem::default();
        list(&mut m, &[0x2008], 0);
        m.put32(0x2000, TID);
        exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x2000), Some(FUTEX_OWNER_DIED));
        assert!(m.woken.is_empty());
    }

    #[test]
    fn a_word_another_thread_holds_is_left_alone() {
        let mut m = Mem::default();
        list(&mut m, &[0x2008, 0x3008], 0);
        m.put32(0x2000, 7 | FUTEX_WAITERS);
        m.put32(0x3000, TID);
        let w = exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x2000), Some(7 | FUTEX_WAITERS));
        assert_eq!(m.get32(0x3000), Some(FUTEX_OWNER_DIED));
        assert_eq!(w.owner_died, 1);
    }

    #[test]
    fn a_waiter_racing_the_cas_is_seen_and_woken() {
        let mut m = Mem::default();
        list(&mut m, &[0x2008], 0);
        m.put32(0x2000, TID);
        m.race_waiter_on = Some(0x2000);
        exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x2000), Some(FUTEX_OWNER_DIED | FUTEX_WAITERS));
        assert_eq!(m.woken, vec![0x2000]);
    }

    #[test]
    fn a_cyclic_list_ends_at_the_limit_and_the_pending_word_is_still_handled() {
        let mut m = Mem::default();
        // head -> A -> A -> A ... never back to head.
        m.put64(HEAD, 0x2008);
        m.put64(0x2008, 0x2008);
        m.put64(HEAD + 8, OFF as u64);
        m.put64(HEAD + 16, 0x4008);
        m.put32(0x2000, TID);
        m.put32(0x4000, TID | FUTEX_WAITERS);
        let w = exit_robust_list(&mut m, HEAD, TID, 16);
        assert_eq!(w.entries, 16 + 1, "the limit, then the pending entry");
        assert_eq!(w.owner_died, 2, "the cycled word once, then the pending one");
        assert_eq!(m.get32(0x4000), Some(FUTEX_OWNER_DIED | FUTEX_WAITERS));
    }

    #[test]
    fn the_pending_entry_is_not_handled_twice_when_it_is_also_listed() {
        let mut m = Mem::default();
        list(&mut m, &[0x2008], 0x2008);
        m.put32(0x2000, TID | FUTEX_WAITERS);
        let w = exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(w.entries, 1);
        assert_eq!(m.woken, vec![0x2000]);
    }

    #[test]
    fn a_pending_word_left_zero_still_wakes_one() {
        let mut m = Mem::default();
        list(&mut m, &[], 0x5008);
        m.put32(0x5000, 0);
        exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x5000), Some(0));
        assert_eq!(m.woken, vec![0x5000]);
    }

    #[test]
    fn an_unreadable_next_stops_the_walk_without_the_pending_word() {
        let mut m = Mem::default();
        m.put64(HEAD, 0x2008);
        m.put64(HEAD + 8, OFF as u64);
        m.put64(HEAD + 16, 0x4008);
        m.put32(0x2000, TID);
        m.put32(0x4000, TID);
        // 0x2008 (the entry's own `next`) is not mapped.
        exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x2000), Some(FUTEX_OWNER_DIED), "the entry itself is handled");
        assert_eq!(m.get32(0x4000), Some(TID), "Linux returns before the pending word");
    }

    #[test]
    fn an_unreadable_or_absent_head_does_nothing() {
        let mut m = Mem::default();
        assert_eq!(exit_robust_list(&mut m, 0, TID, 2048), Walked::default());
        assert_eq!(exit_robust_list(&mut m, HEAD, TID, 2048), Walked::default());
    }

    #[test]
    fn the_pi_bit_is_masked_and_a_pi_word_wakes_nobody() {
        let mut m = Mem::default();
        list(&mut m, &[0x2008 | 1], 0);
        m.put32(0x2000, TID | FUTEX_WAITERS);
        exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x2000), Some(FUTEX_OWNER_DIED | FUTEX_WAITERS));
        assert!(m.woken.is_empty());
    }

    #[test]
    fn an_unaligned_word_or_a_tid_wider_than_the_mask_is_refused() {
        let mut m = Mem::default();
        list(&mut m, &[0x2009], 0);
        m.put32(0x2001, TID);
        exit_robust_list(&mut m, HEAD, TID, 2048);
        assert_eq!(m.get32(0x2001), Some(TID));
        let mut m = Mem::default();
        list(&mut m, &[0x2008], 0);
        m.put32(0x2000, 5);
        assert_eq!(exit_robust_list(&mut m, HEAD, (1 << 30) | 5, 2048), Walked::default());
    }
}

/// Wave 15 (K2): `readv`/`writev` as ONE transfer each
/// (`crates/core/linux-abi/src/iov.rs`), over a sparse fake memory.
#[cfg(test)]
mod iov_walk {
    use azos_linux_abi::errno as le;
    use azos_linux_abi::iov::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Mem {
        bytes: BTreeMap<u64, u8>,
    }
    impl Mem {
        fn put(&mut self, at: u64, b: &[u8]) {
            for (i, &x) in b.iter().enumerate() {
                self.bytes.insert(at + i as u64, x);
            }
        }
        /// An iovec array at `at` naming `segs` (base, len).
        fn iovs(&mut self, at: u64, segs: &[(u64, u64)]) {
            for (i, &(b, l)) in segs.iter().enumerate() {
                self.put(at + 16 * i as u64, &b.to_le_bytes());
                self.put(at + 16 * i as u64 + 8, &l.to_le_bytes());
            }
        }
        /// `len` writable zero bytes at `at`.
        fn room(&mut self, at: u64, len: usize) {
            self.put(at, &vec![0; len]);
        }
        fn get(&self, at: u64, len: usize) -> Vec<u8> {
            (0..len as u64).map(|i| self.bytes[&(at + i)]).collect()
        }
    }
    impl IovMem for Mem {
        fn word(&mut self, addr: u64) -> Option<u64> {
            let mut w = [0u8; 8];
            for (i, b) in w.iter_mut().enumerate() {
                *b = *self.bytes.get(&(addr + i as u64))?;
            }
            Some(u64::from_le_bytes(w))
        }
        fn copy_in(&mut self, dst: &mut [u8], base: u64) -> bool {
            for (i, d) in dst.iter_mut().enumerate() {
                match self.bytes.get(&(base + i as u64)) {
                    Some(&b) => *d = b,
                    None => return false,
                }
            }
            true
        }
        fn copy_out(&mut self, base: u64, src: &[u8]) -> bool {
            if !self.writable(base, src.len()) {
                return false;
            }
            self.put(base, src);
            true
        }
        fn writable(&mut self, base: u64, len: usize) -> bool {
            (0..len as u64).all(|i| self.bytes.contains_key(&(base + i)))
        }
    }

    const IOV_A: u64 = 0x1000;
    const IOV_B: u64 = 0x2000;

    /// One writer's memory: three segments "<tag>1-" "<tag>2-" "<tag>3\n".
    fn writer(tag: u8, data_at: u64, iov_at: u64) -> Mem {
        let mut m = Mem::default();
        let segs: Vec<Vec<u8>> = (1..=3u8)
            .map(|k| vec![tag, b'0' + k, if k == 3 { b'\n' } else { b'-' }])
            .collect();
        let mut table = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            let at = data_at + 0x100 * i as u64;
            m.put(at, s);
            table.push((at, s.len() as u64));
        }
        m.iovs(iov_at, &table);
        m
    }

    /// The property: writer B runs (here: re-entered from inside A's write,
    /// the instant A's first transfer is on the shared description) and
    /// still never lands between two of A's segments. Today's code makes
    /// ONE write per writev; the per-segment loop it replaced (the canary
    /// `writev-per-segment-canary`) lets B in after "A1-".
    #[test]
    fn a_writev_is_one_transfer_no_other_writer_between_its_segments() {
        let stream = std::cell::RefCell::new(Vec::<u8>::new());
        let mut b_ran = false;
        let mut a = writer(b'A', 0x10_000, IOV_A);
        let mut buf_a = [0u8; 4096];
        let r = writev(&mut a, IOV_A, 3, &mut buf_a, |bytes| {
            stream.borrow_mut().extend_from_slice(bytes);
            if !b_ran {
                b_ran = true;
                let mut b = writer(b'B', 0x20_000, IOV_B);
                let mut buf_b = [0u8; 4096];
                let rb = writev(&mut b, IOV_B, 3, &mut buf_b, |bb| {
                    stream.borrow_mut().extend_from_slice(bb);
                    bb.len() as i64
                });
                assert_eq!(rb, 9);
            }
            bytes.len() as i64
        });
        assert_eq!(r, 9);
        let s = String::from_utf8(stream.into_inner()).unwrap();
        assert!(s == "A1-A2-A3\nB1-B2-B3\n", "segments interleaved: {s:?}");
    }

    #[test]
    fn writev_checks_every_entry_before_the_transfer() {
        let mut m = writer(b'A', 0x10_000, IOV_A);
        let mut buf = [0u8; 64];
        let mut calls = 0;
        // More than UIO_MAXIOV entries.
        assert_eq!(writev(&mut m, IOV_A, UIO_MAXIOV + 1, &mut buf, |_| { calls += 1; 0 }), -le::EINVAL);
        // A length negative as ssize_t in the LAST entry, after the gather
        // filled the buffer: still EINVAL, nothing written.
        m.iovs(IOV_A + 3 * 16, &[(0x10_000, u64::MAX)]);
        assert_eq!(writev(&mut m, IOV_A, 4, &mut buf[..3], |_| { calls += 1; 0 }), -le::EINVAL);
        // The array itself unreadable.
        assert_eq!(writev(&mut m, 0xdead_0000, 1, &mut buf, |_| { calls += 1; 0 }), -le::EFAULT);
        assert_eq!(calls, 0);
        // No entries, or only empty ones: 0, no write.
        m.iovs(IOV_B, &[(0x10_000, 0), (0, 0)]);
        assert_eq!(writev(&mut m, IOV_B, 2, &mut buf, |_| { calls += 1; 0 }), 0);
        assert_eq!(writev(&mut m, IOV_B, 0, &mut buf, |_| { calls += 1; 0 }), 0);
        assert_eq!(calls, 0);
    }

    #[test]
    fn writev_cut_at_the_bounce_and_short_at_a_faulting_segment() {
        let mut m = writer(b'A', 0x10_000, IOV_A);
        let mut got = Vec::new();
        let mut buf = [0u8; 7];
        // 9 bytes into a 7-byte bounce: one write of the first 7.
        assert_eq!(writev(&mut m, IOV_A, 3, &mut buf, |b| { got.push(b.to_vec()); b.len() as i64 }), 7);
        assert_eq!(got, vec![b"A1-A2-A".to_vec()]);
        // Segment 2 unmapped: what came before it, in one write.
        m.iovs(IOV_A + 16, &[(0xbad_0000, 3)]);
        got.clear();
        let mut buf = [0u8; 64];
        assert_eq!(writev(&mut m, IOV_A, 3, &mut buf, |b| { got.push(b.to_vec()); b.len() as i64 }), 3);
        assert_eq!(got, vec![b"A1-".to_vec()]);
        // Segment 1 unmapped: EFAULT, nothing written.
        m.iovs(IOV_A, &[(0xbad_0000, 3)]);
        got.clear();
        assert_eq!(writev(&mut m, IOV_A, 3, &mut buf, |b| { got.push(b.to_vec()); 0 }), -le::EFAULT);
        assert!(got.is_empty());
    }

    #[test]
    fn readv_is_one_read_scattered_in_order() {
        let mut m = Mem::default();
        m.room(0x30_000, 2);
        m.room(0x31_000, 0);
        m.room(0x32_000, 5);
        m.iovs(IOV_A, &[(0x30_000, 2), (0x31_000, 0), (0x32_000, 5)]);
        let mut buf = [0u8; 4096];
        let mut reads = Vec::new();
        let r = readv(&mut m, IOV_A, 3, &mut buf, |b| {
            reads.push(b.len());
            b[..6].copy_from_slice(b"hello\n");
            6
        });
        assert_eq!(r, 6);
        assert_eq!(reads, vec![7], "one read, of the segments' total");
        assert_eq!(m.get(0x30_000, 2), b"he");
        assert_eq!(m.get(0x32_000, 5), b"llo\n\0");
    }

    #[test]
    fn readv_checks_destinations_before_the_destructive_read() {
        let mut m = Mem::default();
        m.room(0x30_000, 4);
        let mut buf = [0u8; 64];
        let mut reads = 0;
        // First destination unmapped: EFAULT, the read never happens.
        m.iovs(IOV_A, &[(0xbad_0000, 4), (0x30_000, 4)]);
        assert_eq!(readv(&mut m, IOV_A, 2, &mut buf, |_| { reads += 1; 4 }), -le::EFAULT);
        assert_eq!(reads, 0);
        // Second unmapped: the read is cut to the first (nothing consumed
        // that could not be delivered).
        m.iovs(IOV_A, &[(0x30_000, 4), (0xbad_0000, 4)]);
        let r = readv(&mut m, IOV_A, 2, &mut buf, |b| {
            reads += 1;
            assert_eq!(b.len(), 4);
            b.copy_from_slice(b"abcd");
            4
        });
        assert_eq!((r, reads), (4, 1));
        assert_eq!(m.get(0x30_000, 4), b"abcd");
        // A read error passes through.
        m.iovs(IOV_A, &[(0x30_000, 4)]);
        assert_eq!(readv(&mut m, IOV_A, 1, &mut buf, |_| -le::EAGAIN), -le::EAGAIN);
    }
}
