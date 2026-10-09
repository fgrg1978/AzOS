// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side checks for the Linux+seccomp column of vsbench.
//!
//! The launcher's `allow.rs` and `bpf.rs` are included by path, so these tests
//! exercise the exact list and program the guest binary is built from.
//!
//! Two kinds of check:
//!
//!  * **The list against the program under test.** The allow-list must equal
//!    what `userspace/bench/vsbench` issues with `--features linux`, read straight
//!    from its source. A syscall added there and not here would kill the
//!    benchmark under the filter; one listed here and no longer issued there
//!    would widen the filter past parity.
//!  * **The program against the kernel's rules.** A classic-BPF interpreter
//!    with the semantics seccomp gives each opcode, refusing any opcode it does
//!    not model, plus the kernel's validity checks and a port of the seccomp
//!    action-cache emulation (`seccomp_is_const_allow`).

#[cfg(test)]
#[path = "../../src/allow.rs"]
mod allow;
#[cfg(test)]
#[path = "../../src/bpf.rs"]
mod bpf;

#[cfg(test)]
mod tests {
    use super::allow::{By, ALLOWED, VDSO_FALLBACKS};
    use super::bpf::*;
    use std::collections::{BTreeMap, BTreeSet};

    const ABI_LINUX: &str = include_str!("../../../../userspace/bench/vsbench/src/abi_linux.rs");
    const MAIN_RS: &str = include_str!("../../../../userspace/bench/vsbench/src/main.rs");
    const BENCH_CORE: &str = include_str!("../../../../userspace/bench/vsbench/src/bench_core.rs");
    /// The wire protocol shared with `userspace/bench/vssrv` through `#[path]`
    /// (RFC-0040 gap 2 stage 4). One constant, no syscalls — and scanned
    /// below rather than merely allowed, so "it only holds a constant" stays
    /// a checked fact instead of a claim in this comment.
    const IPC_PROTO: &str = include_str!("../../../../userspace/bench/vsbench/src/ipc_proto.rs");

    // ── The list against vsbench's Linux source ─────────────────────────────

    /// `SYS_NAME -> number` for every `const SYS_*: usize = N;` in the file.
    fn source_consts(src: &str) -> BTreeMap<String, u32> {
        let mut out = BTreeMap::new();
        for line in src.lines() {
            let t = line.trim_start();
            let t = t.strip_prefix("pub ").unwrap_or(t);
            let Some(rest) = t.strip_prefix("const SYS_") else { continue };
            let (name, value) = rest.split_once(':').expect("const without a type");
            let value = value
                .split_once('=')
                .expect("const without a value")
                .1
                .trim()
                .trim_end_matches(';')
                .trim();
            let nr: u32 = value
                .parse()
                .unwrap_or_else(|_| panic!("SYS_{name} is not a decimal literal: {value:?}"));
            assert!(out.insert(format!("SYS_{}", name.trim()), nr).is_none(), "SYS_{name} twice");
        }
        out
    }

    /// The first argument of every `syscallN(` call site, excluding the helper
    /// definitions themselves.
    fn call_site_names(src: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut rest = src;
        while let Some(at) = rest.find("syscall") {
            let before = &rest[..at];
            let after = &rest[at + "syscall".len()..];
            rest = after;
            let mut chars = after.chars();
            let (Some(d), Some('(')) = (chars.next(), chars.next()) else { continue };
            if !d.is_ascii_digit() {
                continue;
            }
            if before.trim_end().ends_with("fn") {
                continue; // `unsafe fn syscallN(` — the helper itself
            }
            let arg: String = after[2..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            assert!(
                arg.starts_with("SYS_"),
                "a syscall{d}( call site whose number is not a named SYS_ constant \
                 ({arg:?}); the allow-list cannot be checked against it"
            );
            names.insert(arg);
        }
        names
    }

    #[test]
    fn the_allow_list_is_sorted_and_names_each_number_once() {
        for w in ALLOWED.windows(2) {
            assert!(w[0].nr < w[1].nr, "{} ({}) before {} ({})", w[0].name, w[0].nr, w[1].name, w[1].nr);
        }
        let names: BTreeSet<_> = ALLOWED.iter().map(|s| s.name).collect();
        assert_eq!(names.len(), ALLOWED.len(), "a name is listed twice");
    }

    #[test]
    fn the_allow_list_is_exactly_what_vsbench_linux_issues_including_the_launchers_execve() {
        let consts = source_consts(ABI_LINUX);
        let used = call_site_names(ABI_LINUX);

        // Every constant is called, and every call names a constant.
        let const_names: BTreeSet<String> = consts.keys().cloned().collect();
        assert_eq!(const_names, used, "abi_linux.rs: constants and call sites differ");

        let listed: BTreeMap<String, u32> = ALLOWED
            .iter()
            .filter(|s| s.by == By::Vsbench)
            .map(|s| (s.name.to_string(), s.nr))
            .collect();
        assert_eq!(
            listed, consts,
            "allow.rs (By::Vsbench) and userspace/bench/vsbench/src/abi_linux.rs differ"
        );

        // The launcher's one call after the install is `execve`, which
        // vsbench issues too since wave 12 (`spawn+wait`), so the entry is
        // vsbench's and no launcher-only entry is left.
        let launcher: Vec<_> = ALLOWED.iter().filter(|s| s.by == By::Launcher).collect();
        assert!(launcher.is_empty(), "a launcher-only entry: {launcher:?}");
        assert_eq!(consts.get("SYS_EXECVE"), Some(&221), "the launcher's execve must stay listed");
    }

    #[test]
    fn every_ecall_in_the_linux_build_goes_through_a_named_helper() {
        // The helpers are `syscall0` .. `syscall6`, and `syscall7` (wave 13:
        // the thread-shaped clone, whose child must leave the asm itself);
        // each holds one `ecall` and one `in("a7")`. Any other `ecall` would
        // issue a number the call site scan above never sees.
        let helpers = ABI_LINUX.matches("unsafe fn syscall").count();
        assert_eq!(helpers, 8, "abi_linux.rs helper count changed");
        assert_eq!(ABI_LINUX.matches("\"ecall\"").count(), helpers, "an ecall outside the helpers");
        assert_eq!(ABI_LINUX.matches("in(\"a7\")").count(), helpers, "an a7 load outside the helpers");
        // The code, not the prose: bench_core.rs mentions `ecall` in comments.
        //
        // aarch64 parity (phase 6 prep): `"svc #0"`/`in("x8")` are the
        // register-convention analogue of `"ecall"`/`in("a7")` — see
        // `crates/core/abi/src/syscall_nr.rs`'s "Register convention". This
        // launcher never runs an aarch64 build (vsbench's Linux column is
        // riscv64-only; only its `--features azos` build targets aarch64,
        // and that is not what these three files compile for), so the
        // invariant is the same one stated above, for the other ISA: none of
        // these three shared files may issue a raw trap of their own, on
        // either ISA. `bench_core.rs`'s `rdtime()` reads `cntvct_el0`
        // directly on aarch64 — a register read, not a trap — so this holds
        // today; it exists to catch a future raw `svc` the same way the
        // `ecall` check above does.
        for (file, src) in [
            ("main.rs", MAIN_RS),
            ("bench_core.rs", BENCH_CORE),
            ("ipc_proto.rs", IPC_PROTO),
        ] {
            assert!(!src.contains("\"ecall\""), "{file} issues an ecall of its own");
            assert!(!src.contains("\"a7\""), "{file} loads a7");
            assert!(!src.contains("\"svc #0\""), "{file} issues an aarch64 svc of its own");
            assert!(!src.contains("in(\"x8\")"), "{file} loads x8");
        }
        // The Linux build compiles exactly these files. `ipc_proto` joined on
        // 2026-09-21: the server LOOP moved to `userspace/bench/vssrv` and only the
        // protocol constant stayed shared, so the client stopped compiling
        // `SYS_IPC_FAST_ACCEPT`/`_REPLY`/`_REPLY_ACCEPT` at all.
        for m in MAIN_RS.lines().map(str::trim).filter(|l| l.starts_with("mod ")) {
            assert!(
                ["mod bench_core;", "mod abi_linux;", "mod abi_azos;", "mod ipc_proto;"]
                    .contains(&m),
                "main.rs declares an unscanned module: {m}"
            );
        }
    }

    #[test]
    fn the_vdso_functions_vsbench_calls_fall_back_to_listed_syscalls() {
        let mut resolved: Vec<&str> = Vec::new();
        let mut rest = ABI_LINUX;
        while let Some(at) = rest.find("b\"__vdso_") {
            let s = &rest[at + 2..];
            let end = s.find('"').unwrap();
            resolved.push(&s[..end]);
            rest = &s[end..];
        }
        resolved.sort();
        let mut known: Vec<&str> = VDSO_FALLBACKS.iter().map(|(f, _)| *f).collect();
        known.sort();
        assert_eq!(resolved, known, "vsbench resolves a vDSO function allow.rs has not accounted for");
        for (f, nr) in VDSO_FALLBACKS {
            assert!(ALLOWED.iter().any(|s| s.nr == nr), "{f} falls back to {nr}, which is not allowed");
        }
    }

    // ── The program against the kernel's rules ──────────────────────────────

    const SECCOMP_DATA_LEN: u32 = 64;
    const AUDIT_ARCH_RISCV32: u32 = 0x4000_00F3;
    const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

    fn data(nr: u32, arch: u32) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[0..4].copy_from_slice(&nr.to_le_bytes());
        d[4..8].copy_from_slice(&arch.to_le_bytes());
        // Arguments that would change a decision if the program read them.
        for i in 16..64 {
            d[i] = 0xA5;
        }
        d
    }

    /// Classic BPF with seccomp's semantics for the opcodes this program may
    /// use. Anything else panics rather than being guessed at.
    fn run(prog: &[SockFilter], d: &[u8; 64]) -> u32 {
        let mut acc: u32 = 0;
        let mut pc = 0usize;
        loop {
            let i = prog.get(pc).expect("ran off the end of the program");
            match i.code {
                BPF_LD_W_ABS => {
                    let k = i.k as usize;
                    acc = u32::from_le_bytes(d[k..k + 4].try_into().unwrap());
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    pc += 1 + if acc == i.k { i.jt as usize } else { i.jf as usize };
                }
                BPF_RET_K => return i.k,
                other => panic!("opcode {other:#x} is not modelled by this checker"),
            }
        }
    }

    /// Port of `seccomp_is_const_allow` (kernel/seccomp.c, 5.11+): the
    /// emulation that decides, per syscall number, whether the filter can be
    /// skipped. Only `nr` and `arch` loads are constant; anything else makes
    /// the number non-cacheable.
    fn const_allow(prog: &[SockFilter], nr: u32, arch: u32) -> bool {
        let mut reg: u32 = 0;
        let mut pc = 0usize;
        while pc < prog.len() {
            let i = prog[pc];
            match i.code {
                BPF_LD_W_ABS => match i.k {
                    SECCOMP_DATA_NR => reg = nr,
                    SECCOMP_DATA_ARCH => reg = arch,
                    _ => return false,
                },
                BPF_RET_K => return i.k == SECCOMP_RET_ALLOW,
                BPF_JMP_JEQ_K => {
                    pc += if reg == i.k { i.jt as usize } else { i.jf as usize };
                }
                _ => return false,
            }
            pc += 1;
        }
        false
    }

    fn listed(nr: u32) -> bool {
        ALLOWED.iter().any(|s| s.nr == nr)
    }

    #[test]
    fn the_program_passes_the_kernels_classic_bpf_checks() {
        let p = program();
        // bpf_check_classic + seccomp_check_filter.
        assert!(!p.is_empty() && p.len() <= 4096, "BPF_MAXINSNS");
        assert_eq!(p.last().unwrap().code, BPF_RET_K, "the last instruction must return");
        for (pc, i) in p.iter().enumerate() {
            match i.code {
                BPF_LD_W_ABS => {
                    assert!(i.k % 4 == 0 && i.k < SECCOMP_DATA_LEN, "pc {pc}: load outside seccomp_data");
                }
                BPF_JMP_JEQ_K => {
                    assert!(pc + 1 + (i.jt as usize) < p.len(), "pc {pc}: jt out of range");
                    assert!(pc + 1 + (i.jf as usize) < p.len(), "pc {pc}: jf out of range");
                }
                BPF_RET_K => {
                    assert!(
                        i.k == SECCOMP_RET_ALLOW || i.k == SECCOMP_RET_KILL_PROCESS,
                        "pc {pc}: unexpected action {:#x}", i.k
                    );
                }
                other => panic!("pc {pc}: opcode {other:#x} not expected in this program"),
            }
        }
    }

    #[test]
    fn the_structs_have_the_kernel_layout() {
        // `struct sock_filter` is 8 bytes; `struct sock_fprog` on LP64 is a
        // u16, padding, and a pointer at offset 8. The host is LP64 like the
        // guest, so the layout checked here is the one the launcher passes.
        assert_eq!(std::mem::size_of::<SockFilter>(), 8);
        assert_eq!(std::mem::offset_of!(SockFilter, k), 4);
        let p = program();
        let f = SockFprog { len: LEN as u16, filter: p.as_ptr() };
        assert_eq!(std::mem::size_of::<SockFprog>(), 16);
        assert_eq!(std::mem::offset_of!(SockFprog, filter), 8);
        assert_eq!(f.len as usize, p.len());
        assert_eq!(f.filter, p.as_ptr());
    }

    #[test]
    fn the_program_is_the_list_plus_five_instructions() {
        // The vsbench method quotes these two numbers.
        assert_eq!(ALLOWED.len(), 33);
        assert_eq!(LEN, ALLOWED.len() + 5);
        assert_eq!(program().len(), 38);
    }

    #[test]
    fn every_listed_syscall_is_allowed_and_every_other_number_is_killed() {
        let p = program();
        let extra = [u32::MAX, 0x4000_0000, 0x8000_0000 | 64, 1024, 4096];
        for nr in (0..1024).chain(extra) {
            let want = if listed(nr) { SECCOMP_RET_ALLOW } else { SECCOMP_RET_KILL_PROCESS };
            assert_eq!(run(&p, &data(nr, AUDIT_ARCH_RISCV64)), want, "nr {nr}");
        }
    }

    #[test]
    fn a_foreign_arch_is_killed_even_for_a_listed_syscall() {
        let p = program();
        for arch in [AUDIT_ARCH_RISCV32, AUDIT_ARCH_AARCH64, 0] {
            for s in ALLOWED {
                assert_eq!(
                    run(&p, &data(s.nr, arch)),
                    SECCOMP_RET_KILL_PROCESS,
                    "{} under arch {arch:#x}", s.name
                );
            }
        }
    }

    #[test]
    fn every_allowed_syscall_is_constant_for_the_kernels_action_cache() {
        // If this goes red, allowed syscalls stop being cacheable and pay the
        // BPF interpreter on every call (the reference kernel has no JIT):
        // the column's cost model changes, not only its code.
        let p = program();
        for nr in 0..1024u32 {
            assert_eq!(const_allow(&p, nr, AUDIT_ARCH_RISCV64), listed(nr), "nr {nr}");
        }
    }
}
